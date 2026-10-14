#![cfg(feature = "ss")]
//! Opt-in interop against a **real, externally deployed** ShadowTLS v3 +
//! Shadowsocks server (e.g. the official `ihciah/shadow-tls` in front of
//! `ssserver`/sing-box on a VPS, with a public cover site).
//!
//! Ordinary CI never depends on a public server: unless
//! `MEOW_SHADOWTLS_EXTERNAL=1` is set, every test here prints a skip line
//! and passes. The hermetic interop suite is `shadow_tls_v3_e2e`.
//!
//! ```sh
//! MEOW_SHADOWTLS_EXTERNAL=1 \
//! MEOW_STLS_SERVER=203.0.113.10 MEOW_STLS_PORT=6443 \
//! MEOW_STLS_HOST=www.example.com MEOW_STLS_PASSWORD=… \
//! MEOW_STLS_SS_CIPHER=chacha20-ietf-poly1305 MEOW_STLS_SS_PASSWORD=… \
//! MEOW_STLS_UOT=2   # optional: also query DNS over udp-over-tcp v1|v2
//! cargo test -p meow-proxy --test shadow_tls_external_interop -- --nocapture
//! ```
//!
//! Optional: `MEOW_STLS_VERSION` (default 3), `MEOW_STLS_FINGERPRINT`
//! (`client-fingerprint`, default chrome), `MEOW_STLS_TARGET`
//! (`host:port` for the TCP probe, default `example.com:80`).

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use meow_common::{Metadata, Network, ProxyAdapter};
use meow_proxy::dialer::DirectDialer;
use meow_proxy::{ShadowsocksAdapter, UotVersion};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::{timeout, Duration};

const TIMEOUT: Duration = Duration::from_secs(20);

struct External {
    server: String,
    port: u16,
    opts: String,
    cipher: String,
    ss_password: String,
    fingerprint: String,
    target: (String, u16),
    uot: Option<UotVersion>,
}

fn external() -> Option<External> {
    if std::env::var("MEOW_SHADOWTLS_EXTERNAL").ok().as_deref() != Some("1") {
        eprintln!("SKIP: shadow_tls_external_interop — MEOW_SHADOWTLS_EXTERNAL unset (opt-in)");
        return None;
    }
    let var = |k: &str| std::env::var(k).unwrap_or_else(|_| panic!("{k} must be set"));
    let opt = |k: &str, d: &str| std::env::var(k).unwrap_or_else(|_| d.to_string());
    let target = opt("MEOW_STLS_TARGET", "example.com:80");
    let (host, port) = target
        .rsplit_once(':')
        .expect("MEOW_STLS_TARGET is host:port");
    Some(External {
        server: var("MEOW_STLS_SERVER"),
        port: var("MEOW_STLS_PORT").parse().expect("MEOW_STLS_PORT"),
        opts: format!(
            "host={};password={};version={}",
            var("MEOW_STLS_HOST"),
            var("MEOW_STLS_PASSWORD"),
            opt("MEOW_STLS_VERSION", "3")
        ),
        cipher: opt("MEOW_STLS_SS_CIPHER", "chacha20-ietf-poly1305"),
        ss_password: var("MEOW_STLS_SS_PASSWORD"),
        fingerprint: opt("MEOW_STLS_FINGERPRINT", "chrome"),
        target: (host.to_string(), port.parse().expect("target port")),
        uot: std::env::var("MEOW_STLS_UOT").ok().map(|v| {
            UotVersion::from_config(v.parse().expect("MEOW_STLS_UOT is 1 or 2"))
                .expect("MEOW_STLS_UOT is 1 or 2")
        }),
    })
}

fn adapter(e: &External) -> ShadowsocksAdapter {
    let a = ShadowsocksAdapter::new(
        "external-ss-shadowtls",
        &e.server,
        e.port,
        &e.ss_password,
        &e.cipher,
        e.uot.is_some(),
        Some("shadow-tls"),
        Some(&e.opts),
        Some(&e.fingerprint),
        Arc::new(DirectDialer),
    )
    .expect("adapter");
    match e.uot {
        Some(v) => a.with_udp_over_tcp(v).expect("udp-over-tcp"),
        None => a,
    }
}

/// TCP: an HTTP HEAD through SS + ShadowTLS v3 gets an HTTP status line.
#[tokio::test]
async fn external_tcp_http_probe() {
    let Some(e) = external() else {
        return;
    };
    let metadata = Metadata {
        network: Network::Tcp,
        host: e.target.0.as_str().into(),
        dst_port: e.target.1,
        ..Default::default()
    };
    let mut conn = timeout(TIMEOUT, adapter(&e).dial_tcp(&metadata))
        .await
        .expect("dial timed out")
        .expect("dial through external shadow-tls");
    let req = format!(
        "HEAD / HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
        e.target.0
    );
    conn.write_all(req.as_bytes()).await.unwrap();
    conn.flush().await.unwrap();
    let mut buf = vec![0u8; 512];
    let n = timeout(TIMEOUT, conn.read(&mut buf))
        .await
        .expect("response timed out")
        .expect("response");
    let head = String::from_utf8_lossy(&buf[..n]);
    eprintln!("external tcp: {}", head.lines().next().unwrap_or(""));
    assert!(head.starts_with("HTTP/1."), "unexpected response: {head:?}");
}

/// UDP-over-TCP: a DNS query for example.com to 1.1.1.1 gets an answer
/// with the query's id (requires `MEOW_STLS_UOT` and a UoT-capable server).
#[tokio::test]
async fn external_uot_dns_probe() {
    let Some(e) = external() else {
        return;
    };
    if e.uot.is_none() {
        eprintln!("SKIP: external_uot_dns_probe — MEOW_STLS_UOT unset");
        return;
    }
    let dns = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 53);
    let metadata = Metadata {
        network: Network::Udp,
        dst_ip: Some(dns.ip()),
        dst_port: 53,
        ..Default::default()
    };
    let pc = timeout(TIMEOUT, adapter(&e).dial_udp(&metadata))
        .await
        .expect("dial_udp timed out")
        .expect("udp-over-tcp through external shadow-tls");
    // Minimal DNS query: id 0x4d45, RD, one question example.com A IN.
    let mut q = vec![0x4d, 0x45, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    for label in ["example", "com"] {
        q.push(label.len() as u8);
        q.extend_from_slice(label.as_bytes());
    }
    q.extend_from_slice(&[0, 0, 1, 0, 1]);
    pc.write_packet(&q, &dns).await.unwrap();
    let mut buf = [0u8; 1500];
    let (n, from) = timeout(TIMEOUT, pc.read_packet(&mut buf))
        .await
        .expect("dns answer timed out")
        .expect("dns answer");
    eprintln!("external uot: {n}B answer from {from}");
    assert!(n >= 12 && buf[..2] == [0x4d, 0x45], "not our DNS answer");
}
