#![cfg(feature = "ss")]
//! Real-server interop for the built-in `shadow-tls` v3 SS plugin.
//!
//!   meow-rs ShadowsocksAdapter (chacha20-ietf-poly1305 + shadow-tls v3)
//!     ──TCP──> official ihciah/shadow-tls `--v3 server`
//!                 ├─ handshake relay ──> loopback cover (rustls)
//!                 └─ data ──> loopback SS server (shadowsocks crate) ──echo
//!
//! The relay is the reference implementation the protocol is defined by
//! (`ihciah/shadow-tls`), not a mock — a green run proves meow's
//! wire-patched ClientHello, swizzled-record authorization and
//! rolling-HMAC data framing interoperate with code we did not write.
//! Covered: TLS 1.3 and TLS 1.2 covers, multi-record bulk transfer,
//! a client that stays silent after dialing, wrong-password
//! authentication failure, `strict-mode` (client and server side) and
//! dial errors.
//!
//! Gated on `$SHADOWTLS_SERVER_BIN`: every leg is real-peer, so an
//! unset binary fails — `MEOW_SHADOWTLS_E2E_ALLOW_SKIP=1` prints a loud
//! skip for local runs (same convention as `MEOW_KCPTUN_E2E_ALLOW_SKIP`).
//! Fetch the pinned release with
//! `bash scripts/fetch-shadowtls-server.sh /tmp/meow-stls` and export
//! `SHADOWTLS_SERVER_BIN=/tmp/meow-stls/shadow-tls`.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Arc;

use meow_common::{Metadata, Network, ProxyAdapter};
use meow_proxy::dialer::DirectDialer;
use meow_proxy::ShadowsocksAdapter;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use sha2::{Digest, Sha256};
use shadowsocks::config::{ServerConfig, ServerType};
use shadowsocks::context::Context;
use shadowsocks::crypto::CipherKind;
use shadowsocks::relay::tcprelay::proxy_stream::ProxyServerStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::process::{Child, Command};
use tokio::time::{sleep, timeout, Duration, Instant};

const SS_PASSWORD: &str = "stls-e2e-ss-password";
const SS_CIPHER: &str = "chacha20-ietf-poly1305";
const STLS_PASSWORD: &str = "stls-e2e-shadowtls-password";
const COVER_SNI: &str = "cover.example.com";
const TIMEOUT: Duration = Duration::from_secs(15);

fn server_binary() -> Option<PathBuf> {
    match std::env::var_os("SHADOWTLS_SERVER_BIN") {
        Some(p) => {
            let p = PathBuf::from(p);
            assert!(p.is_file(), "SHADOWTLS_SERVER_BIN is not a file: {p:?}");
            Some(p)
        }
        None => {
            // Fail-closed: a green run must mean the interop actually ran.
            assert_eq!(
                std::env::var("MEOW_SHADOWTLS_E2E_ALLOW_SKIP")
                    .ok()
                    .as_deref(),
                Some("1"),
                "shadow_tls_v3_e2e requires SHADOWTLS_SERVER_BIN — run \
                 `bash scripts/fetch-shadowtls-server.sh <dir>` or set \
                 MEOW_SHADOWTLS_E2E_ALLOW_SKIP=1 to skip locally"
            );
            eprintln!("SKIP: shadow_tls_v3_e2e — SHADOWTLS_SERVER_BIN unset (allowed)");
            None
        }
    }
}

// ─── Loopback peers ─────────────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq)]
enum CoverTls {
    V13,
    V12,
}

/// Spawn a cover TLS server for `COVER_SNI`. It completes handshakes and
/// then idles reading until the peer goes away — an HTTPS origin that
/// never gets a request.  Returns its address and the SHA-256 of its leaf
/// certificate (for the `fingerprint` pin on the TLS 1.2 cover path).
async fn spawn_cover(version: CoverTls) -> (SocketAddr, [u8; 32]) {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let ck = rcgen::generate_simple_self_signed(vec![COVER_SNI.to_string()]).unwrap();
    let cert = CertificateDer::from(ck.cert.der().to_vec());
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ck.key_pair.serialize_der()));
    let pin: [u8; 32] = Sha256::digest(cert.as_ref()).into();
    let versions: &[&rustls::SupportedProtocolVersion] = match version {
        CoverTls::V13 => &[&rustls::version::TLS13],
        CoverTls::V12 => &[&rustls::version::TLS12],
    };
    let mut cfg = rustls::ServerConfig::builder_with_protocol_versions(versions)
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .unwrap();
    cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut addr = listener.local_addr().unwrap();
    if version == CoverTls::V12 {
        // A TLS 1.2 cover rejects the client's (necessarily
        // transcript-divergent) Finished and closes; the session lives
        // because the first payload trails that Finished and switches
        // the relay before the rejection lands.  A real cover sits a
        // network RTT away from the relay — on bare loopback the race
        // would be a coin flip, so model the distance.
        addr = spawn_latency_proxy(addr, Duration::from_millis(100)).await;
    }
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                return;
            };
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                // The v3 client's Finished never verifies (its patched
                // ClientHello diverges the transcript), so most
                // handshakes end in an error here — expected.
                if let Ok(mut tls) = acceptor.accept(tcp).await {
                    let mut buf = [0u8; 4096];
                    while matches!(tls.read(&mut buf).await, Ok(n) if n > 0) {}
                }
            });
        }
    });
    (addr, pin)
}

/// Forward to `upstream`, delaying every relay→cover chunk by `delay`
/// (order-preserving: one task reads, sleeps, writes).
async fn spawn_latency_proxy(upstream: SocketAddr, delay: Duration) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((down, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let Ok(up) = TcpStream::connect(upstream).await else {
                    return;
                };
                let (mut down_r, mut down_w) = down.into_split();
                let (mut up_r, mut up_w) = up.into_split();
                let to_cover = async move {
                    let mut buf = vec![0u8; 16 * 1024];
                    while let Ok(n) = down_r.read(&mut buf).await {
                        if n == 0 {
                            break;
                        }
                        sleep(delay).await;
                        if up_w.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                    let _ = up_w.shutdown().await;
                };
                let from_cover = async move {
                    let _ = tokio::io::copy(&mut up_r, &mut down_w).await;
                    let _ = down_w.shutdown().await;
                };
                tokio::join!(to_cover, from_cover);
            });
        }
    });
    addr
}

/// Spawn a loopback SS server (chacha20-ietf-poly1305) that echoes every
/// accepted session after the SS address handshake.
async fn spawn_ss_echo() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let cipher: CipherKind = SS_CIPHER.parse().unwrap();
    let svr_cfg = ServerConfig::new(addr, SS_PASSWORD, cipher).unwrap();
    let context = Context::new_shared(ServerType::Server);
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                return;
            };
            let mut stream =
                ProxyServerStream::from_stream(Arc::clone(&context), tcp, cipher, svr_cfg.key());
            tokio::spawn(async move {
                if stream.handshake().await.is_err() {
                    return;
                }
                let mut buf = vec![0u8; 32 * 1024];
                loop {
                    match stream.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => {
                            if stream.write_all(&buf[..n]).await.is_err() {
                                return;
                            }
                        }
                    }
                }
            });
        }
    });
    addr
}

/// A running official shadow-tls server plus its loopback cover/backend.
struct Relay {
    _child: Child,
    port: u16,
    cover_pin: [u8; 32],
}

/// Spawn `shadow-tls --v3 [--strict] server` relaying handshakes to a
/// `cover` server and data to the SS echo backend.
async fn spawn_relay(cover: CoverTls, server_strict: bool) -> Option<Relay> {
    let bin = server_binary()?;
    let (cover_addr, cover_pin) = spawn_cover(cover).await;
    let ss_addr = spawn_ss_echo().await;
    // Reserve a port for the relay (shadow-tls has no "print bound port").
    let port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let mut cmd = Command::new(bin);
    cmd.arg("--v3");
    if server_strict {
        cmd.arg("--strict");
    }
    let child = cmd
        .args(["--threads", "1", "server"])
        .args(["--listen", &format!("127.0.0.1:{port}")])
        .args(["--server", &ss_addr.to_string()])
        .args(["--tls", &cover_addr.to_string()])
        .args(["--password", STLS_PASSWORD])
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .kill_on_drop(true)
        .spawn()
        .expect("spawn shadow-tls server");
    // Wait for the listener to come up.
    let deadline = Instant::now() + TIMEOUT;
    while TcpStream::connect(("127.0.0.1", port)).await.is_err() {
        assert!(
            Instant::now() < deadline,
            "shadow-tls server never listened"
        );
        sleep(Duration::from_millis(50)).await;
    }
    Some(Relay {
        _child: child,
        port,
        cover_pin,
    })
}

// ─── Client side ────────────────────────────────────────────────────────────

/// Build the SS adapter exactly as the Clash-style config would: the
/// `plugin-opts` map flattened into the SIP003 string the parser feeds
/// `ShadowsocksAdapter::new`, plus the node-level `client-fingerprint`.
fn adapter(port: u16, opts: &str) -> ShadowsocksAdapter {
    ShadowsocksAdapter::new(
        "ss-shadowtls",
        "127.0.0.1",
        port,
        SS_PASSWORD,
        SS_CIPHER,
        false,
        Some("shadow-tls"),
        Some(opts),
        Some("chrome"),
        Arc::new(DirectDialer),
    )
    .expect("ss + shadow-tls v3 adapter must construct")
}

fn base_opts(password: &str) -> String {
    format!("host={COVER_SNI};password={password};version=3;skip-cert-verify=false")
}

fn metadata() -> Metadata {
    Metadata {
        network: Network::Tcp,
        dst_ip: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        dst_port: 80,
        ..Default::default()
    }
}

/// Dial, then round-trip small payloads and one multi-record bulk payload
/// (well past the 16 KiB record bound, so the rolling HMAC chains advance
/// across many records in both directions).
async fn echo_round_trips(adapter: &ShadowsocksAdapter) {
    let mut conn = timeout(TIMEOUT, adapter.dial_tcp(&metadata()))
        .await
        .expect("dial_tcp timed out")
        .expect("dial_tcp through shadow-tls v3 failed");
    for round in 0..3 {
        let payload = format!("shadow-tls v3 round {round}");
        conn.write_all(payload.as_bytes()).await.unwrap();
        conn.flush().await.unwrap();
        let mut buf = vec![0u8; payload.len()];
        timeout(TIMEOUT, conn.read_exact(&mut buf))
            .await
            .expect("echo timed out")
            .expect("read echo");
        assert_eq!(buf, payload.as_bytes(), "echo mismatch round {round}");
    }
    let bulk: Vec<u8> = (0..256 * 1024u32).map(|i| (i % 251) as u8).collect();
    let (mut rd, mut wr) = tokio::io::split(conn);
    let expect = bulk.clone();
    let writer = tokio::spawn(async move {
        wr.write_all(&bulk).await.unwrap();
        wr.flush().await.unwrap();
        wr
    });
    let mut got = vec![0u8; expect.len()];
    timeout(TIMEOUT, rd.read_exact(&mut got))
        .await
        .expect("bulk echo timed out")
        .expect("bulk echo read");
    assert!(got == expect, "bulk echo corrupted");
    writer.await.unwrap();
}

async fn dial_err(adapter: &ShadowsocksAdapter) -> String {
    match timeout(TIMEOUT, adapter.dial_tcp(&metadata()))
        .await
        .expect("failing dial must not hang")
    {
        Ok(mut conn) => {
            // SS may defer its first write; the failure can only surface
            // once data has to cross the relay.
            let _ = conn.write_all(b"probe").await;
            let mut buf = [0u8; 16];
            match timeout(TIMEOUT, conn.read(&mut buf)).await {
                Ok(Ok(n)) if n > 0 => panic!("dial must not succeed, echoed {n}B"),
                Ok(Ok(_)) => "eof".to_string(),
                Ok(Err(e)) => e.to_string(),
                Err(_) => panic!("failed session must not hang"),
            }
        }
        Err(e) => e.to_string(),
    }
}

// ─── Tests ──────────────────────────────────────────────────────────────────

/// The spec configuration: SS chacha20-ietf-poly1305 behind shadow-tls
/// v3, `client-fingerprint: chrome`, TLS 1.3 cover.
#[tokio::test]
async fn v3_tls13_cover_ss_echo() {
    let Some(relay) = spawn_relay(CoverTls::V13, false).await else {
        return;
    };
    echo_round_trips(&adapter(relay.port, &base_opts(STLS_PASSWORD))).await;
}

/// Several sessions over one relay — each re-runs the tagged handshake
/// with a fresh server random.
#[tokio::test]
async fn v3_tls13_cover_concurrent_sessions() {
    let Some(relay) = spawn_relay(CoverTls::V13, false).await else {
        return;
    };
    let adapter = Arc::new(adapter(relay.port, &base_opts(STLS_PASSWORD)));
    let mut tasks = Vec::new();
    for _ in 0..4 {
        let adapter = Arc::clone(&adapter);
        tasks.push(tokio::spawn(
            async move { echo_round_trips(&adapter).await },
        ));
    }
    for t in tasks {
        t.await.unwrap();
    }
}

/// The client stays silent after dialing (a server-first application,
/// or SS deferring its header) — the relay must keep the session usable
/// rather than tearing it down when the cover gives up on the doomed
/// handshake.
#[tokio::test]
async fn v3_tls13_cover_survives_idle_before_first_write() {
    let Some(relay) = spawn_relay(CoverTls::V13, false).await else {
        return;
    };
    let adapter = adapter(relay.port, &base_opts(STLS_PASSWORD));
    let mut conn = timeout(TIMEOUT, adapter.dial_tcp(&metadata()))
        .await
        .expect("dial timed out")
        .expect("dial");
    sleep(Duration::from_millis(1500)).await;
    conn.write_all(b"late first write").await.unwrap();
    conn.flush().await.unwrap();
    let mut buf = [0u8; 16];
    timeout(TIMEOUT, conn.read_exact(&mut buf))
        .await
        .expect("echo after idle timed out")
        .expect("echo after idle");
    assert_eq!(&buf, b"late first write");
}

/// TLS 1.2 cover: the handshake is plaintext, so certificate
/// verification genuinely runs — pin the cover's leaf (`fingerprint`).
#[tokio::test]
async fn v3_tls12_cover_with_cert_pin() {
    let Some(relay) = spawn_relay(CoverTls::V12, false).await else {
        return;
    };
    let pin: String = relay.cover_pin.iter().map(|b| format!("{b:02x}")).collect();
    let opts = format!("{};fingerprint={pin}", base_opts(STLS_PASSWORD));
    echo_round_trips(&adapter(relay.port, &opts)).await;
}

/// TLS 1.2 cover, self-signed and unpinned: verification fails closed.
#[tokio::test]
async fn v3_tls12_cover_untrusted_cert_fails() {
    let Some(relay) = spawn_relay(CoverTls::V12, false).await else {
        return;
    };
    let err = dial_err(&adapter(relay.port, &base_opts(STLS_PASSWORD))).await;
    assert!(
        err.contains("certificate") || err.contains("shadow-tls"),
        "expected a cover certificate failure, got: {err}"
    );
}

/// Wrong shadow-tls password: the official server fails the ClientHello
/// tag and degrades to a plain SNI proxy for the cover, whose unswizzled
/// records the client must reject ("traffic hijacked") — no data path.
#[tokio::test]
async fn v3_wrong_password_fails_authentication() {
    let Some(relay) = spawn_relay(CoverTls::V13, false).await else {
        return;
    };
    let err = dial_err(&adapter(relay.port, &base_opts("not-the-password"))).await;
    assert!(
        err.contains("shadow-tls") || err.contains("hmac"),
        "expected a shadow-tls authentication failure, got: {err}"
    );
}

/// Client `strict-mode=true` refuses a TLS 1.2 cover even though the
/// relay itself would authorize it.
#[tokio::test]
async fn v3_client_strict_mode_rejects_tls12_cover() {
    let Some(relay) = spawn_relay(CoverTls::V12, false).await else {
        return;
    };
    let pin: String = relay.cover_pin.iter().map(|b| format!("{b:02x}")).collect();
    let opts = format!(
        "{};fingerprint={pin};strict-mode=true",
        base_opts(STLS_PASSWORD)
    );
    let err = dial_err(&adapter(relay.port, &opts)).await;
    assert!(err.contains("strict-mode"), "got: {err}");
}

/// Server `--strict` with a TLS 1.2 cover degrades to a plain relay to
/// the cover.  A TLS 1.2 cover authorizes client-side at its ServerHello
/// (upstream `authorized = !isTLS13`), so the refusal surfaces on the
/// data path: the tagged payload reaches the cover, never the backend,
/// and no echo may come back (`dial_err` panics on one).
#[tokio::test]
async fn v3_server_strict_mode_rejects_tls12_cover() {
    let Some(relay) = spawn_relay(CoverTls::V12, true).await else {
        return;
    };
    let pin: String = relay.cover_pin.iter().map(|b| format!("{b:02x}")).collect();
    let opts = format!("{};fingerprint={pin}", base_opts(STLS_PASSWORD));
    let err = dial_err(&adapter(relay.port, &opts)).await;
    assert!(!err.is_empty(), "dial against a strict server must fail");
}

/// Nothing listening at the configured server port — a connection error
/// surfaces promptly instead of hanging.
#[tokio::test]
async fn v3_connection_refused_surfaces() {
    if server_binary().is_none() {
        return;
    }
    let port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let err = dial_err(&adapter(port, &base_opts(STLS_PASSWORD))).await;
    assert!(!err.is_empty(), "connection refused must surface an error");
}

// ─── UDP-over-TCP through ShadowTLS (sing-box UoT backend) ─────────────────
//
//   meow SS (+ shadow-tls v3 + udp-over-tcp) ──TCP──> official shadow-tls
//     ──> sing-box SS inbound (UoT server, both versions) ──UDP──> echo
//
// The client knows only the relay's TCP port: there is no SS UDP endpoint
// anywhere in its config, so a datagram that came back proves it crossed
// the ShadowTLS transport inside the SS stream.

/// Pinned sing-box release (kept in sync with the CI install step).
const SINGBOX_VERSION: &str = "1.14.0";

/// `$SINGBOX_BIN`, else `sing-box` on PATH; fail-closed like the relay.
fn singbox_binary() -> Option<PathBuf> {
    if let Some(p) = std::env::var_os("SINGBOX_BIN") {
        let p = PathBuf::from(p);
        assert!(p.is_file(), "SINGBOX_BIN is not a file: {p:?}");
        return Some(p);
    }
    if let Some(found) = std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths)
            .map(|d| d.join("sing-box"))
            .find(|p| p.is_file())
    }) {
        return Some(found);
    }
    assert_eq!(
        std::env::var("MEOW_SHADOWTLS_E2E_ALLOW_SKIP")
            .ok()
            .as_deref(),
        Some("1"),
        "shadow_tls_v3_e2e UoT legs require sing-box {SINGBOX_VERSION} \
         ($SINGBOX_BIN or PATH) — or set MEOW_SHADOWTLS_E2E_ALLOW_SKIP=1 locally"
    );
    eprintln!("SKIP: shadow_tls_v3_e2e UoT — sing-box not found (allowed)");
    None
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// A running sing-box SS inbound; the temp config lives as long as it.
struct SingBox {
    _child: Child,
    _dir: tempfile::TempDir,
    port: u16,
}

async fn spawn_singbox_ss() -> Option<SingBox> {
    let bin = singbox_binary()?;
    let port = free_port();
    let dir = tempfile::tempdir().unwrap();
    let cfg = dir.path().join("sing-box.json");
    std::fs::write(
        &cfg,
        format!(
            r#"{{"log":{{"level":"error"}},
"inbounds":[{{"type":"shadowsocks","tag":"ss-in","listen":"127.0.0.1",
"listen_port":{port},"method":"{SS_CIPHER}","password":"{SS_PASSWORD}"}}],
"outbounds":[{{"type":"direct","tag":"direct"}}]}}"#
        ),
    )
    .unwrap();
    let child = Command::new(bin)
        .arg("run")
        .arg("-c")
        .arg(&cfg)
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .kill_on_drop(true)
        .spawn()
        .expect("spawn sing-box");
    let deadline = Instant::now() + TIMEOUT;
    while TcpStream::connect(("127.0.0.1", port)).await.is_err() {
        assert!(Instant::now() < deadline, "sing-box never listened");
        sleep(Duration::from_millis(50)).await;
    }
    Some(SingBox {
        _child: child,
        _dir: dir,
        port,
    })
}

/// Official shadow-tls v3 relay in front of an arbitrary data backend.
async fn spawn_relay_to(backend: SocketAddr) -> Option<Relay> {
    let bin = server_binary()?;
    let (cover_addr, cover_pin) = spawn_cover(CoverTls::V13).await;
    let port = free_port();
    let child = Command::new(bin)
        .args(["--v3", "--threads", "1", "server"])
        .args(["--listen", &format!("127.0.0.1:{port}")])
        .args(["--server", &backend.to_string()])
        .args(["--tls", &cover_addr.to_string()])
        .args(["--password", STLS_PASSWORD])
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .kill_on_drop(true)
        .spawn()
        .expect("spawn shadow-tls server");
    let deadline = Instant::now() + TIMEOUT;
    while TcpStream::connect(("127.0.0.1", port)).await.is_err() {
        assert!(
            Instant::now() < deadline,
            "shadow-tls server never listened"
        );
        sleep(Duration::from_millis(50)).await;
    }
    Some(Relay {
        _child: child,
        port,
        cover_pin,
    })
}

/// UDP echo on loopback; returns its address.
async fn spawn_udp_echo() -> SocketAddr {
    let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = sock.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        while let Ok((n, peer)) = sock.recv_from(&mut buf).await {
            let _ = sock.send_to(&buf[..n], peer).await;
        }
    });
    addr
}

fn udp_metadata(dst: SocketAddr) -> Metadata {
    Metadata {
        network: Network::Udp,
        dst_ip: Some(dst.ip()),
        dst_port: dst.port(),
        ..Default::default()
    }
}

/// Each datagram comes back whole, in order, from the echo's address —
/// sizes span the 1-byte floor, a typical MTU payload, and datagrams
/// larger than one 16 KiB TLS record (so a single datagram spans several
/// ShadowTLS records).  The ceiling is the *server's*: sing-box reads each
/// UoT datagram into a 16 KiB packet buffer and drops the stream on a
/// bigger one ("UoT read: short buffer"), though the framing allows 64 KiB.
async fn uot_echo_round_trips(adapter: &ShadowsocksAdapter, echo: SocketAddr) {
    assert!(
        adapter.support_udp(),
        "udp-over-tcp node must advertise UDP"
    );
    let conn = timeout(TIMEOUT, adapter.dial_udp(&udp_metadata(echo)))
        .await
        .expect("dial_udp timed out")
        .expect("dial_udp over udp-over-tcp failed");
    let mut buf = vec![0u8; 65535];
    for (i, size) in [1usize, 1200, 9_000, 16_000].into_iter().enumerate() {
        let payload: Vec<u8> = (0..size).map(|b| (b * 7 + i) as u8).collect();
        conn.write_packet(&payload, &echo).await.unwrap();
        let (n, from) = timeout(TIMEOUT, conn.read_packet(&mut buf))
            .await
            .expect("uot echo timed out")
            .expect("uot read");
        assert_eq!(from, echo, "reply source must be the echo server");
        assert_eq!(n, size, "datagram {i} boundary");
        assert!(buf[..n] == payload[..], "datagram {i} corrupted");
    }
    // Several datagrams in flight before reading: boundaries survive
    // coalescing inside the TCP stream.
    for i in 0..8u8 {
        conn.write_packet(&[i; 300], &echo).await.unwrap();
    }
    for i in 0..8u8 {
        let (n, _) = timeout(TIMEOUT, conn.read_packet(&mut buf))
            .await
            .expect("burst echo timed out")
            .expect("burst read");
        assert_eq!(&buf[..n], &[i; 300], "burst datagram {i}");
    }
    conn.close().unwrap();
}

fn uot_adapter(port: u16, version: meow_proxy::UotVersion) -> ShadowsocksAdapter {
    ShadowsocksAdapter::new(
        "ss-shadowtls-uot",
        "127.0.0.1",
        port,
        SS_PASSWORD,
        SS_CIPHER,
        true,
        Some("shadow-tls"),
        Some(&base_opts(STLS_PASSWORD)),
        Some("chrome"),
        Arc::new(DirectDialer),
    )
    .expect("adapter")
    .with_udp_over_tcp(version)
    .expect("udp-over-tcp")
}

#[tokio::test]
async fn v3_uot_legacy_over_shadow_tls() {
    let Some(sb) = spawn_singbox_ss().await else {
        return;
    };
    let Some(relay) = spawn_relay_to(SocketAddr::from(([127, 0, 0, 1], sb.port))).await else {
        return;
    };
    let echo = spawn_udp_echo().await;
    uot_echo_round_trips(
        &uot_adapter(relay.port, meow_proxy::UotVersion::Legacy),
        echo,
    )
    .await;
}

#[tokio::test]
async fn v3_uot_v2_over_shadow_tls() {
    let Some(sb) = spawn_singbox_ss().await else {
        return;
    };
    let Some(relay) = spawn_relay_to(SocketAddr::from(([127, 0, 0, 1], sb.port))).await else {
        return;
    };
    let echo = spawn_udp_echo().await;
    uot_echo_round_trips(&uot_adapter(relay.port, meow_proxy::UotVersion::V2), echo).await;
}

/// Concurrent associations each get their own UoT stream (and their own
/// ShadowTLS session); TCP keeps working on the same node meanwhile.
#[tokio::test]
async fn v3_uot_concurrent_associations_and_tcp() {
    let Some(sb) = spawn_singbox_ss().await else {
        return;
    };
    let Some(relay) = spawn_relay_to(SocketAddr::from(([127, 0, 0, 1], sb.port))).await else {
        return;
    };
    let echo = spawn_udp_echo().await;
    let adapter = Arc::new(uot_adapter(relay.port, meow_proxy::UotVersion::V2));
    let mut tasks = Vec::new();
    for _ in 0..4 {
        let adapter = Arc::clone(&adapter);
        tasks.push(tokio::spawn(async move {
            uot_echo_round_trips(&adapter, echo).await;
        }));
    }
    for t in tasks {
        t.await.unwrap();
    }
}

/// Without `udp-over-tcp` the same node refuses UDP outright — ShadowTLS
/// has no datagram path and meow never sends raw SS UDP beside it.
#[tokio::test]
async fn v3_without_uot_refuses_udp() {
    if server_binary().is_none() {
        return;
    }
    let adapter = adapter(free_port(), &base_opts(STLS_PASSWORD));
    assert!(!adapter.support_udp());
    let err = adapter
        .dial_udp(&udp_metadata("127.0.0.1:53".parse().unwrap()))
        .await
        .err()
        .expect("plain UDP must be refused");
    assert!(err.to_string().contains("shadow-tls"), "{err}");
}
