//! shadow-tls end-to-end tests — a fake shadow-tls server (fused
//! cover-TLS terminator + relay) on loopback exercises the real wire
//! protocol for v1/v2/v3 against a BoringSSL client.

mod support;

use hmac::{Hmac, Mac};
use meow_transport::tls::{TlsConfig, TlsLayer, TlsVersion};
use rustls::ServerConnection;
use sha1::Sha1;
use sha2::{Digest, Sha256};
use std::io;
use std::sync::Arc;
use support::loopback::{gen_cert, install_crypto_provider};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

type HmacSha1 = Hmac<Sha1>;

const PASSWORD: &[u8] = b"e2e-psk";
const RECORD_HDR: usize = 5;
const SERVER_RANDOM_INDEX: usize = RECORD_HDR + 4 + 2; // hdr + hs-hdr + version

fn sha1_hmac(key: &[u8]) -> HmacSha1 {
    HmacSha1::new_from_slice(key).unwrap()
}

fn kdf(password: &[u8], server_random: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(password);
    h.update(server_random);
    h.finalize().into()
}

fn xor_in_place(data: &mut [u8], key: &[u8; 32]) {
    for (i, b) in data.iter_mut().enumerate() {
        *b ^= key[i % 32];
    }
}

/// Read exactly one TLS record from the wire.
async fn read_record(tcp: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut hdr = [0u8; RECORD_HDR];
    tcp.read_exact(&mut hdr).await?;
    let len = u16::from_be_bytes([hdr[3], hdr[4]]) as usize;
    let mut rec = hdr.to_vec();
    rec.resize(RECORD_HDR + len, 0);
    tcp.read_exact(&mut rec[RECORD_HDR..]).await?;
    Ok(rec)
}

/// rustls `write_tls` output → wire bytes, applying the v3 relay swizzle
/// to `application_data` records once `server_random` has been captured.
struct OutAssembler {
    rec: Vec<u8>,
    want: usize,
    server_random: Option<[u8; 32]>,
    write_hmac: Option<HmacSha1>,
    xor_key: Option<[u8; 32]>,
    password: Vec<u8>,
    version: u8,
}

impl OutAssembler {
    fn new(version: u8, password: &[u8]) -> Self {
        Self {
            rec: Vec::new(),
            want: 0,
            server_random: None,
            write_hmac: None,
            xor_key: None,
            password: password.to_vec(),
            version,
        }
    }

    /// Feed produced TLS bytes; returns wire bytes (records may be
    /// withheld until complete).
    fn feed(&mut self, bytes: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        self.rec.extend_from_slice(bytes);
        loop {
            if self.want == 0 {
                if self.rec.len() < RECORD_HDR {
                    break;
                }
                self.want = RECORD_HDR + u16::from_be_bytes([self.rec[3], self.rec[4]]) as usize;
            }
            if self.rec.len() < self.want {
                break;
            }
            let record: Vec<u8> = self.rec.drain(..self.want).collect();
            self.want = 0;
            out.extend(self.emit(record));
        }
        out
    }

    fn emit(&mut self, mut record: Vec<u8>) -> Vec<u8> {
        // Capture the server random out of the ServerHello record.
        if record[0] == 22 && record.len() >= SERVER_RANDOM_INDEX + 32 && record[RECORD_HDR] == 2 {
            let mut rand = [0u8; 32];
            rand.copy_from_slice(&record[SERVER_RANDOM_INDEX..SERVER_RANDOM_INDEX + 32]);
            self.server_random = Some(rand);
            if self.version == 3 {
                let mut chain = sha1_hmac(&self.password);
                chain.update(&rand);
                self.write_hmac = Some(chain);
                self.xor_key = Some(kdf(&self.password, &rand));
            }
            return record;
        }
        // v3: swizzle cover appdata — tag(4) over the xor'd payload under
        // the handshake chain, then xor the payload.
        if self.version == 3 && record[0] == 23 && record.len() > 9 {
            if let (Some(chain), Some(key)) = (&mut self.write_hmac, &self.xor_key) {
                xor_in_place(&mut record[RECORD_HDR..], key);
                chain.update(&record[RECORD_HDR..]);
                let tag = chain.clone().finalize().into_bytes();
                let mut out = record[..RECORD_HDR].to_vec();
                out[3..5].copy_from_slice(&((record.len() - RECORD_HDR + 4) as u16).to_be_bytes());
                out.extend(&tag[..4]);
                out.extend(&record[RECORD_HDR..]);
                return out;
            }
        }
        record
    }
}

/// Group ids for the hybrid-PQ key shares the vendored BoringSSL offers by
/// default via boring-sys's boring-pq.patch (`X25519MLKEM768`,
/// `P256Kyber768Draft00`).  The v2 pin must strip both; the ML-KEM one is
/// the load-bearing assert (upstream's strip targets it by name).
const GROUP_X25519_MLKEM768: u16 = 0x11ec;
const GROUP_P256_KYBER768_DRAFT00: u16 = 0xfe32;

/// Whether the ClientHello's `supported_groups` extension offers `group`.
/// v2 asserts `false` for the hybrid-PQ groups (upstream strips them —
/// `BuildRemovedX25519MLKEM768HandshakeState`; a hybrid-PQ share breaks
/// v2 servers, and the production pin in `tls_config_for` is what keeps
/// this green), while v3 asserts `true` for ML-KEM to keep the v2 check
/// non-vacuous: a boring default flip shows up in the *positive* v3
/// assertion as well.
fn ch_offers_group(record: &[u8], group: u16) -> bool {
    assert!(record.len() >= 6, "record too short for a handshake header");
    assert_eq!(record[0], 22, "expected a TLS handshake record");
    assert_eq!(record[5], 1, "expected a ClientHello handshake message");
    let sid_len_index = SERVER_RANDOM_INDEX + 32;
    assert!(
        record.len() > sid_len_index,
        "record too short for session-id length"
    );
    let mut i = sid_len_index + 1 + record[sid_len_index] as usize;
    assert!(record.len() >= i + 2, "record too short for cipher-suites");
    let cs_len = u16::from_be_bytes([record[i], record[i + 1]]) as usize;
    i += 2 + cs_len;
    assert!(record.len() > i, "record too short for compression methods");
    i += 1 + record[i] as usize; // compression methods
    assert!(record.len() >= i + 2, "record too short for extensions");
    let ext_len = u16::from_be_bytes([record[i], record[i + 1]]) as usize;
    let ext_end = i + 2 + ext_len;
    i += 2;
    while i + 4 <= ext_end && i + 4 <= record.len() {
        let ty = u16::from_be_bytes([record[i], record[i + 1]]);
        let el = u16::from_be_bytes([record[i + 2], record[i + 3]]) as usize;
        if ty == 0x000a {
            // supported_groups
            let end = (i + 4 + el).min(record.len());
            let [hi, lo] = group.to_be_bytes();
            return record[i + 4..end].as_chunks::<2>().0.contains(&[hi, lo]);
        }
        i += 4 + el;
    }
    false
}

/// Verify the v3 ClientHello's embedded session-id tag
/// (upstream `verifyClientHello`).
fn verify_ch_tag(record: &[u8], password: &[u8]) {
    assert_eq!(record[0], 22, "first client record must be handshake");
    assert_eq!(record[RECORD_HDR], 1, "must be a ClientHello");
    let sid_len_index = SERVER_RANDOM_INDEX + 32;
    assert_eq!(record[sid_len_index], 32, "compat session id must be 32B");
    let sid_start = sid_len_index + 1;
    let sid_end = sid_start + 32;
    let mut chain = sha1_hmac(password);
    chain.update(&record[RECORD_HDR..sid_end - 4]);
    chain.update(&[0u8; 4]);
    chain.update(&record[sid_end..]);
    let tag = chain.finalize().into_bytes();
    assert_eq!(
        &record[sid_end - 4..sid_end],
        &tag[..4],
        "v3 ClientHello session-id tag"
    );
}

/// Run the cover handshake over `tcp` (rustls terminator + relay
/// mutations), returning the raw stream, the full inbound transcript,
/// and the captured server random.
async fn cover_handshake(
    mut tcp: TcpStream,
    conn: &mut ServerConnection,
    version: u8,
    password: &[u8],
) -> io::Result<(TcpStream, Vec<u8>, [u8; 32])> {
    let mut asm = OutAssembler::new(version, password);
    let mut inbound = Vec::new();
    let mut first_checked = false;
    loop {
        while conn.wants_write() {
            let mut produced = Vec::new();
            conn.write_tls(&mut produced)?;
            let wire = asm.feed(&produced);
            tcp.write_all(&wire).await?;
        }
        if !conn.is_handshaking() && !conn.wants_write() {
            break;
        }
        let rec = read_record(&mut tcp).await?;
        if version == 3 && !first_checked {
            verify_ch_tag(&rec, password);
            first_checked = true;
        }
        inbound.extend_from_slice(&rec);
        conn.read_tls(&mut &rec[..])?;
        conn.process_new_packets()
            .map_err(|e| io::Error::other(format!("cover TLS: {e}")))?;
    }
    // Flush any trailing writes.
    while conn.wants_write() {
        let mut produced = Vec::new();
        conn.write_tls(&mut produced)?;
        let wire = asm.feed(&produced);
        tcp.write_all(&wire).await?;
    }
    Ok((tcp, inbound, asm.server_random.unwrap_or([0u8; 32])))
}

fn server_conn() -> (ServerConnection, rustls::pki_types::CertificateDer<'static>) {
    let (cert_der, key_der, _, _) = gen_cert(&["cover.example.com"]);
    let mut cfg = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der.clone()], key_der)
        .expect("server config");
    // No session tickets: a ticket that races in after Finished is hashed
    // by the server but may never be pulled by the client's TLS stack —
    // a nondeterministic transcript for the v2 handshake tag.
    cfg.send_tls13_tickets = 0;
    (
        ServerConnection::new(Arc::new(cfg)).expect("server conn"),
        cert_der,
    )
}

fn client_layer(version: u8, cert_der: &rustls::pki_types::CertificateDer<'static>) -> TlsLayer {
    let mut cfg = TlsConfig::new("cover.example.com");
    cfg.additional_roots = vec![cert_der.as_ref().to_vec()];
    cfg.alpn = vec!["h2".to_string(), "http/1.1".to_string()];
    // Upstream floors at TLS 1.2 for every version; v1 caps at 1.2.
    cfg.min_version = Some(TlsVersion::Tls12);
    if version == 1 {
        cfg.max_version = Some(TlsVersion::Tls12);
    }
    // Mirror the production `tls_config_for` pin: v2 never offers
    // X25519MLKEM768 (boring ≥5.x would offer it by default).
    if version == 2 {
        cfg.curves = Some("X25519:P-256:P-384".to_string());
    }
    TlsLayer::new(&cfg).expect("tls layer")
}

/// A rustls cover pinned to TLS 1.2 — the plaintext-cover path where
/// certificate verification genuinely runs before the doomed Finished.
fn server_conn_tls12() -> (ServerConnection, rustls::pki_types::CertificateDer<'static>) {
    let (cert_der, key_der, _, _) = gen_cert(&["cover.example.com"]);
    let cfg = rustls::ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS12])
        .with_no_client_auth()
        .with_single_cert(vec![cert_der.clone()], key_der)
        .expect("server config");
    (
        ServerConnection::new(Arc::new(cfg)).expect("server conn"),
        cert_der,
    )
}

/// The v3 relay half of the mock server: verify the tagged ClientHello,
/// pump the doomed cover flight (swizzling post-SH appdata), then switch
/// on the first client record whose "C"-chain tag verifies and echo one
/// payload back under the "S" chain.
async fn v3_relay_server(mut tcp: TcpStream, conn: &mut ServerConnection, password: &[u8]) {
    let mut asm = OutAssembler::new(3, password);
    let mut verify: Option<HmacSha1> = None;
    let mut add: Option<HmacSha1> = None;

    // First client record must be the tagged ClientHello.
    let ch = read_record(&mut tcp).await.unwrap();
    // v3 carries no curves pin — the default BoringSSL hello must still
    // offer ML-KEM, which keeps the v2 `!ch_offers_group` assertion
    // meaningful (it would also pass vacuously if the default stopped
    // offering it).
    assert!(
        ch_offers_group(&ch, GROUP_X25519_MLKEM768),
        "unpinned v3 ClientHello should offer X25519MLKEM768 by default"
    );
    verify_ch_tag(&ch, password);
    conn.read_tls(&mut &ch[..]).unwrap();
    conn.process_new_packets().expect("cover TLS");

    // Set once the cover rejects the client's (transcript-divergent)
    // flight.  Its rejection alert is never pumped: a real cover sits a
    // network hop from the relay, so the client's first data record —
    // which trails its Finished immediately — switches the relay before
    // the rejection lands (`shadow_tls_v3_e2e` exercises that race
    // against the official server with a latency-modelled cover).
    let mut cover_dead = false;
    let payload = 'switch: loop {
        // Pump whatever the cover wants to say, swizzling post-SH
        // appdata (SH random seeds the chains on first sight).
        while !cover_dead && conn.wants_write() {
            let mut produced = Vec::new();
            conn.write_tls(&mut produced).unwrap();
            let wire = asm.feed(&produced);
            if verify.is_none() {
                if let Some(sr) = asm.server_random {
                    let mut v = sha1_hmac(password);
                    v.update(&sr);
                    v.update(b"C");
                    verify = Some(v);
                    let mut a = sha1_hmac(password);
                    a.update(&sr);
                    a.update(b"S");
                    add = Some(a);
                }
            }
            tcp.write_all(&wire).await.unwrap();
        }
        // A rejected dial drops the conn mid-flight — die quietly.
        let Ok(rec) = read_record(&mut tcp).await else {
            return;
        };
        if let Some(v) = &verify {
            if rec[0] == 23 && rec.len() > RECORD_HDR + 4 {
                // Upstream `copyByFrameUntilHMACMatches` — a record
                // verifying under the "C" chain is the data switch.
                let mut probe = v.clone();
                probe.update(&rec[RECORD_HDR + 4..]);
                let tag = probe.finalize().into_bytes();
                if rec[RECORD_HDR..RECORD_HDR + 4] == tag[..4] {
                    break 'switch rec[RECORD_HDR + 4..].to_vec();
                }
            }
        }
        // Untagged record — relay into the (doomed) cover conn;
        // the client Finished never verifies server-side either.
        // The v3 client never relays an alert (it swallows its own
        // abort alert), so any record reaching the cover is flight.
        assert_ne!(rec[0], 21, "v3 client must not send an alert to the cover");
        assert_ne!(
            rec[0], 23,
            "untagged appdata from a v3 client is its (encrypted) abort alert"
        );
        if !cover_dead {
            let _ = conn.read_tls(&mut &rec[..]);
            cover_dead = conn.process_new_packets().is_err();
        }
    };

    // Echo the payload back under the "S" chain.
    let add = add.as_mut().expect("S chain seeded");
    add.update(&payload);
    let etag = add.clone().finalize().into_bytes();
    add.update(&etag[..4]);
    let mut out = vec![23u8, 3, 3];
    out.extend(((payload.len() + 4) as u16).to_be_bytes());
    out.extend(&etag[..4]);
    out.extend(&payload);
    tcp.write_all(&out).await.unwrap();
}

// ─── v1 ─────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn v1_end_to_end() {
    install_crypto_provider();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (mut conn, cert) = server_conn();

    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let (mut tcp, _in, _rand) = cover_handshake(tcp, &mut conn, 1, PASSWORD)
            .await
            .expect("cover handshake");
        drop(conn);
        // v1 data path: raw echo.
        let mut buf = [0u8; 1024];
        let n = tcp.read(&mut buf).await.unwrap();
        tcp.write_all(&buf[..n]).await.unwrap();
    });

    let tcp = TcpStream::connect(addr).await.unwrap();
    let layer = client_layer(1, &cert);
    let mut s = meow_transport::shadow_tls::dial(Box::new(tcp), &layer, 1, PASSWORD, false)
        .await
        .expect("v1 dial");
    s.write_all(b"v1-payload").await.unwrap();
    let mut out = [0u8; 32];
    let n = s.read(&mut out).await.unwrap();
    assert_eq!(&out[..n], b"v1-payload");
    server.await.unwrap();
}

// ─── v2 ─────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn v2_end_to_end() {
    install_crypto_provider();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (mut conn, cert) = server_conn();
    let password = PASSWORD.to_vec();

    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        // The server hashes everything it *sent* during the handshake —
        // the mirror of the client hashing everything it received.
        let mut out_chain = sha1_hmac(&password);
        let mut asm = OutAssembler::new(2, &password);
        let mut first_rec = Some(());
        let mut tcp = tcp;
        loop {
            while conn.wants_write() {
                let mut produced = Vec::new();
                conn.write_tls(&mut produced).unwrap();
                let wire = asm.feed(&produced);
                out_chain.update(&wire);
                tcp.write_all(&wire).await.unwrap();
            }
            if !conn.is_handshaking() && !conn.wants_write() {
                break;
            }
            let rec = read_record(&mut tcp).await.unwrap();
            if first_rec.take().is_some() {
                assert!(
                    !ch_offers_group(&rec, GROUP_X25519_MLKEM768),
                    "v2 ClientHello must not offer X25519MLKEM768"
                );
                assert!(
                    !ch_offers_group(&rec, GROUP_P256_KYBER768_DRAFT00),
                    "v2 ClientHello must not offer P256Kyber768Draft00"
                );
            }
            conn.read_tls(&mut &rec[..]).unwrap();
            conn.process_new_packets().expect("cover TLS");
        }
        drop(conn);
        // First framed record must carry the 8-byte transcript tag.
        let first = read_record(&mut tcp).await.unwrap();
        assert_eq!(first[0], 23, "data must be framed as appdata");
        let payload = &first[RECORD_HDR..];
        let expect = out_chain.finalize().into_bytes();
        assert_eq!(&payload[..8], &expect[..8], "v2 first-write transcript tag");
        // Echo the payload back framed.
        let body = &payload[8..];
        let mut rec = vec![23u8, 3, 3];
        rec.extend((body.len() as u16).to_be_bytes());
        rec.extend(body);
        tcp.write_all(&rec).await.unwrap();
    });

    let tcp = TcpStream::connect(addr).await.unwrap();
    let layer = client_layer(2, &cert);
    let mut s = meow_transport::shadow_tls::dial(Box::new(tcp), &layer, 2, PASSWORD, false)
        .await
        .expect("v2 dial");
    s.write_all(b"v2-payload").await.unwrap();
    let mut out = [0u8; 32];
    let n = s.read(&mut out).await.unwrap();
    assert_eq!(&out[..n], b"v2-payload");
    server.await.unwrap();
}

// ─── v3 ─────────────────────────────────────────────────────────────────────

/// The v3 cover handshake never completes on the client side — the
/// wire-patched ClientHello diverges the transcript, so the cover's
/// Finished always fails verification.  The relay is therefore modelled
/// faithfully: the patched CH and the client's CCS are relayed into
/// rustls (the cover), cover output is swizzled once the ServerHello's
/// random is captured, and the first client record carrying a valid
/// "C"-chain tag switches the mock into echo mode.
#[tokio::test]
async fn v3_end_to_end() {
    install_crypto_provider();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (mut conn, cert) = server_conn();
    let password = PASSWORD.to_vec();

    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        v3_relay_server(tcp, &mut conn, &password).await;
    });

    let tcp = TcpStream::connect(addr).await.unwrap();
    let layer = client_layer(3, &cert);
    let mut s = meow_transport::shadow_tls::dial(Box::new(tcp), &layer, 3, PASSWORD, false)
        .await
        .expect("v3 dial — cover Finished fails but the relay authorized");
    s.write_all(b"v3-payload").await.unwrap();
    let mut out = [0u8; 32];
    let n = s.read(&mut out).await.unwrap();
    assert_eq!(&out[..n], b"v3-payload");
    server.await.unwrap();
}

/// TLS 1.2 cover: the whole server flight rides plaintext handshake
/// records, so certificate verification genuinely runs before the
/// doomed Finished — making `cert_ok` the operative accept gate
/// (`(authorized, !is_tls13)` arm).  Pin all four combinations.
#[tokio::test]
async fn v3_tls12_cover_cert_gate() {
    install_crypto_provider();

    // (client trust tweak, expect dial ok, err substring on failure)
    let cases: &[(&str, bool)] = &[
        ("trusted", true),
        ("untrusted", false),
        ("pin-mismatch", false),
        ("skip-verify", true),
    ];
    for (kind, expect_ok) in cases {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (mut conn, cert) = server_conn_tls12();
        let password = PASSWORD.to_vec();
        let kind = kind.to_string();
        let expect_ok = *expect_ok;

        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            // Rejected dials may never reach the switch — let the relay
            // mock die on the dropped socket instead of hanging the test.
            let _ = tokio::time::timeout(
                std::time::Duration::from_secs(10),
                v3_relay_server(tcp, &mut conn, &password),
            )
            .await;
        });

        let mut cfg = TlsConfig::new("cover.example.com");
        cfg.alpn = vec!["h2".to_string(), "http/1.1".to_string()];
        // Client still offers 1.3 (that is what emits the 32-byte compat
        // session id v3 patches); the SERVER is pinned to 1.2, so the
        // cover negotiates 1.2 and its post-SH flight stays plaintext.
        cfg.min_version = Some(TlsVersion::Tls12);
        match kind.as_str() {
            "trusted" => cfg.additional_roots = vec![cert.as_ref().to_vec()],
            "untrusted" => {
                // A different self-signed CA — the cover cert won't verify.
                let (rogue, _, _, _) = gen_cert(&["rogue.example.com"]);
                cfg.additional_roots = vec![rogue.as_ref().to_vec()];
            }
            "pin-mismatch" => {
                cfg.cert_pin = Some([0xAA; 32]); // wrong pin → custom-verify fails
            }
            "skip-verify" => cfg.skip_cert_verify = true,
            _ => unreachable!(),
        }
        let layer = TlsLayer::new(&cfg).expect("tls layer");
        let tcp = TcpStream::connect(addr).await.unwrap();
        let dial =
            meow_transport::shadow_tls::dial(Box::new(tcp), &layer, 3, PASSWORD, false).await;
        match (dial, expect_ok) {
            (Ok(mut s), true) => {
                s.write_all(b"v3-tls12").await.unwrap();
                let mut out = [0u8; 32];
                let n = s.read(&mut out).await.unwrap();
                assert_eq!(&out[..n], b"v3-tls12", "{kind}");
            }
            (Err(e), false) => {
                assert!(
                    e.to_string().contains("shadow-tls"),
                    "{kind}: expected shadow-tls failure, got {e}"
                );
            }
            (Ok(_), false) => panic!("{kind}: dial must fail closed"),
            (Err(e), true) => panic!("{kind}: dial must succeed, got {e}"),
        }
        server.await.unwrap();
    }
}

/// `strict-mode` refuses a cover that negotiates below TLS 1.3 — even
/// when the TLS 1.2 cover would otherwise authorize (upstream
/// `ClientConfig.StrictMode`, checked before `authorized`).
#[tokio::test]
async fn v3_strict_mode_rejects_tls12_cover() {
    install_crypto_provider();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (mut conn, cert) = server_conn_tls12();
    let password = PASSWORD.to_vec();

    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let _ = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            v3_relay_server(tcp, &mut conn, &password),
        )
        .await;
    });

    let mut cfg = TlsConfig::new("cover.example.com");
    cfg.alpn = vec!["h2".to_string(), "http/1.1".to_string()];
    cfg.min_version = Some(TlsVersion::Tls12);
    cfg.additional_roots = vec![cert.as_ref().to_vec()]; // trusted 1.2 cover
    let layer = TlsLayer::new(&cfg).expect("tls layer");
    let tcp = TcpStream::connect(addr).await.unwrap();
    let err = meow_transport::shadow_tls::dial(Box::new(tcp), &layer, 3, PASSWORD, true)
        .await
        .err()
        .map(|e| e.to_string())
        .unwrap_or_default();
    assert!(
        err.contains("strict-mode"),
        "strict-mode must refuse the 1.2 cover, got {err}"
    );
    server.await.unwrap();
}

/// A plain-TLS peer (no shadow-tls relay) must fail closed: its unswizzled
/// appdata records fail the embedded-tag check, so the cover handshake
/// errors before any authorization — and even the transcript-divergent
/// Finished would never let it complete.
#[tokio::test]
async fn v3_hijacked_cover_fails() {
    install_crypto_provider();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (mut conn, cert) = server_conn();

    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        // Plain TLS termination — no swizzle, no tag check.  The client
        // aborts on the first unswizzled record; the server just relays
        // until the connection dies.
        let _ = cover_handshake(tcp, &mut conn, 1, PASSWORD).await;
    });

    let tcp = TcpStream::connect(addr).await.unwrap();
    let layer = client_layer(3, &cert);
    let err = meow_transport::shadow_tls::dial(Box::new(tcp), &layer, 3, PASSWORD, false)
        .await
        .err()
        .map(|e| e.to_string())
        .unwrap_or_default();
    assert!(
        err.contains("shadow-tls") || err.contains("handshake") || err.contains("hmac"),
        "expected a shadow-tls handshake failure, got: {err}"
    );
    let _ = server.await;
}

// ─── v3 failure modes ───────────────────────────────────────────────────────

/// Authentication failure: the relay holds a different password, so its
/// swizzled cover records carry tags the client cannot verify — the dial
/// must fail closed before any data path exists.
#[tokio::test]
async fn v3_wrong_password_fails_closed() {
    install_crypto_provider();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (mut conn, cert) = server_conn();

    let server = tokio::spawn(async move {
        let (mut tcp, _) = listener.accept().await.unwrap();
        // A relay with the wrong key: swizzle cover output under it
        // (skipping the ClientHello tag check, which it would fail).
        let mut asm = OutAssembler::new(3, b"some-other-password");
        let ch = read_record(&mut tcp).await.unwrap();
        conn.read_tls(&mut &ch[..]).unwrap();
        conn.process_new_packets().expect("cover TLS");
        while conn.wants_write() {
            let mut produced = Vec::new();
            conn.write_tls(&mut produced).unwrap();
            let wire = asm.feed(&produced);
            if tcp.write_all(&wire).await.is_err() {
                return;
            }
        }
        // Drain until the client hangs up.
        let mut sink = [0u8; 1024];
        while matches!(tcp.read(&mut sink).await, Ok(n) if n > 0) {}
    });

    let tcp = TcpStream::connect(addr).await.unwrap();
    let layer = client_layer(3, &cert);
    let err = meow_transport::shadow_tls::dial(Box::new(tcp), &layer, 3, PASSWORD, false)
        .await
        .err()
        .map(|e| e.to_string())
        .unwrap_or_default();
    assert!(
        err.contains("hmac mismatch"),
        "wrong relay password must fail the record tag check, got: {err}"
    );
    server.await.unwrap();
}

/// A data record whose "S"-chain tag does not verify (tampered or forged
/// after the switch) is rejected by the reader — never surfaced as data.
#[tokio::test]
async fn v3_tampered_server_record_rejected() {
    install_crypto_provider();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (mut conn, cert) = server_conn();
    let password = PASSWORD.to_vec();

    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        // Run the honest relay into a pipe so its single echoed record can
        // be corrupted on the way out.
        let (relay_side, mut tap) = {
            let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let a = l.local_addr().unwrap();
            let c = TcpStream::connect(a).await.unwrap();
            let (s, _) = l.accept().await.unwrap();
            (s, c)
        };
        let relay = tokio::spawn(async move {
            v3_relay_server(relay_side, &mut conn, &password).await;
        });
        let (mut tcp_r, mut tcp_w) = tcp.into_split();
        let (mut tap_r, mut tap_w) = tap.split();
        // Client → relay verbatim.
        let up = async {
            let mut buf = [0u8; 4096];
            while let Ok(n) = tcp_r.read(&mut buf).await {
                if n == 0 || tap_w.write_all(&buf[..n]).await.is_err() {
                    break;
                }
            }
        };
        // Relay → client verbatim until the switch; flip one payload bit
        // of the first post-switch record (the echo).
        let down = async {
            let mut tampered = false;
            let mut hdr = [0u8; RECORD_HDR];
            while tap_r.read_exact(&mut hdr).await.is_ok() {
                let len = u16::from_be_bytes([hdr[3], hdr[4]]) as usize;
                let mut body = vec![0u8; len];
                if tap_r.read_exact(&mut body).await.is_err() {
                    break;
                }
                // The echo is the only appdata record whose body ends in
                // the plaintext payload.
                if !tampered && hdr[0] == 23 && body.ends_with(b"v3-tamper") {
                    let last = body.len() - 1;
                    body[last] ^= 0x01;
                    tampered = true;
                }
                if tcp_w.write_all(&hdr).await.is_err() || tcp_w.write_all(&body).await.is_err() {
                    break;
                }
            }
        };
        tokio::select! {
            () = up => {}
            () = down => {}
        }
        let _ = relay.await;
    });

    let tcp = TcpStream::connect(addr).await.unwrap();
    let layer = client_layer(3, &cert);
    let mut s = meow_transport::shadow_tls::dial(Box::new(tcp), &layer, 3, PASSWORD, false)
        .await
        .expect("v3 dial");
    s.write_all(b"v3-tamper").await.unwrap();
    let mut out = [0u8; 32];
    let res = tokio::time::timeout(std::time::Duration::from_secs(10), s.read(&mut out))
        .await
        .expect("tampered record must not hang the reader");
    match res {
        Ok(n) => assert_eq!(n, 0, "tampered record surfaced as data: {:?}", &out[..n]),
        Err(e) => assert!(
            e.to_string().contains("shadow-tls") || e.to_string().contains("verif"),
            "unexpected error: {e}"
        ),
    }
    drop(s);
    let _ = server.await;
}

/// Connection errors mid-handshake surface as dial errors, never hangs:
/// the peer hangs up right after the ClientHello, or answers with
/// non-TLS garbage.
#[tokio::test]
async fn v3_connection_errors_mid_handshake() {
    install_crypto_provider();
    for (case, reply) in [
        ("eof", None),
        ("garbage", Some(&b"HTTP/1.1 400 Bad\r\n\r\n"[..])),
    ] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut tcp, _) = listener.accept().await.unwrap();
            let ch = read_record(&mut tcp).await.unwrap();
            verify_ch_tag(&ch, PASSWORD);
            if let Some(reply) = reply {
                let _ = tcp.write_all(reply).await;
            }
            // Dropping `tcp` closes the connection.
        });
        let (_, cert) = server_conn();
        let tcp = TcpStream::connect(addr).await.unwrap();
        let layer = client_layer(3, &cert);
        let res = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            meow_transport::shadow_tls::dial(Box::new(tcp), &layer, 3, PASSWORD, false),
        )
        .await
        .unwrap_or_else(|_| panic!("{case}: dial must not hang"));
        let err = res.err().map(|e| e.to_string()).unwrap_or_default();
        assert!(!err.is_empty(), "{case}: dial must fail");
        server.await.unwrap();
    }
}

// ─── v3 robustness: fragmentation, partial IO, cancellation, timeouts ───────

/// Wraps a stream so every read returns at most a few bytes and every
/// write accepts at most a few — TLS records then arrive split across
/// many reads (record reassembly) and the TLS stack's writes are partial
/// (the ClientHello patcher's write-side assembly).
struct Choppy<S> {
    inner: S,
    tick: usize,
}

impl<S> Choppy<S> {
    fn new(inner: S) -> Self {
        Self { inner, tick: 0 }
    }
    /// Deterministic 1..=7 chunk size.
    fn next_len(&mut self) -> usize {
        self.tick = self.tick.wrapping_mul(31).wrapping_add(7);
        1 + self.tick % 7
    }
}

impl<S: tokio::io::AsyncRead + Unpin> tokio::io::AsyncRead for Choppy<S> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        let cap = self.next_len().min(buf.remaining());
        let mut tmp = [0u8; 8];
        let mut small = tokio::io::ReadBuf::new(&mut tmp[..cap]);
        match std::pin::Pin::new(&mut self.inner).poll_read(cx, &mut small) {
            std::task::Poll::Ready(Ok(())) => {
                buf.put_slice(small.filled());
                std::task::Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}

impl<S: tokio::io::AsyncWrite + Unpin> tokio::io::AsyncWrite for Choppy<S> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        let cap = self.next_len().min(5).min(buf.len());
        std::pin::Pin::new(&mut self.inner).poll_write(cx, &buf[..cap])
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Mock v3 relay that, after the switch, echoes every verified client
/// record back under the "S" chain until the client hangs up — a
/// multi-record data phase (the single-shot `v3_relay_server` stops
/// after one payload).
async fn v3_echo_relay(mut tcp: TcpStream, conn: &mut ServerConnection, password: &[u8]) {
    let mut asm = OutAssembler::new(3, password);
    let mut chains: Option<(HmacSha1, HmacSha1)> = None; // (verify "C", add "S")
    let ch = read_record(&mut tcp).await.unwrap();
    verify_ch_tag(&ch, password);
    conn.read_tls(&mut &ch[..]).unwrap();
    conn.process_new_packets().expect("cover TLS");
    let mut cover_dead = false;
    let first = loop {
        while !cover_dead && conn.wants_write() {
            let mut produced = Vec::new();
            conn.write_tls(&mut produced).unwrap();
            let wire = asm.feed(&produced);
            if chains.is_none() {
                if let Some(sr) = asm.server_random {
                    let mut v = sha1_hmac(password);
                    v.update(&sr);
                    v.update(b"C");
                    let mut a = sha1_hmac(password);
                    a.update(&sr);
                    a.update(b"S");
                    chains = Some((v, a));
                }
            }
            tcp.write_all(&wire).await.unwrap();
        }
        let Ok(rec) = read_record(&mut tcp).await else {
            return;
        };
        if let Some((v, _)) = &chains {
            if rec[0] == 23 && rec.len() > RECORD_HDR + 4 {
                let mut probe = v.clone();
                probe.update(&rec[RECORD_HDR + 4..]);
                if rec[RECORD_HDR..RECORD_HDR + 4] == probe.finalize().into_bytes()[..4] {
                    break rec;
                }
            }
        }
        if !cover_dead {
            let _ = conn.read_tls(&mut &rec[..]);
            cover_dead = conn.process_new_packets().is_err();
        }
    };
    let (mut verify, mut add) = chains.expect("chains seeded");
    let mut rec = first;
    loop {
        // Verify under the rolling "C" chain (upstream `verifiedRelay`).
        let payload = rec[RECORD_HDR + 4..].to_vec();
        verify.update(&payload);
        let tag = verify.clone().finalize().into_bytes();
        assert_eq!(
            &rec[RECORD_HDR..RECORD_HDR + 4],
            &tag[..4],
            "client C-chain tag"
        );
        verify.update(&tag[..4]);
        // Echo under the rolling "S" chain.
        add.update(&payload);
        let etag = add.clone().finalize().into_bytes();
        add.update(&etag[..4]);
        let mut out = vec![23u8, 3, 3];
        out.extend(((payload.len() + 4) as u16).to_be_bytes());
        out.extend(&etag[..4]);
        out.extend(&payload);
        if tcp.write_all(&out).await.is_err() {
            return;
        }
        rec = match read_record(&mut tcp).await {
            Ok(r) if r[0] == 23 => r,
            _ => return, // EOF / alert: the client hung up
        };
    }
}

async fn spawn_v3_echo_relay() -> (std::net::SocketAddr, tokio::task::JoinHandle<()>, TlsLayer) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (mut conn, cert) = server_conn();
    let handle = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        v3_echo_relay(tcp, &mut conn, PASSWORD).await;
    });
    (addr, handle, client_layer(3, &cert))
}

/// Full v3 handshake + multi-record data with every read returning 1–7
/// bytes and every write accepting ≤5: record reassembly, the patcher's
/// write-side buffering and the framed reader all see maximal
/// fragmentation; the payload must still round-trip intact.
#[tokio::test]
async fn v3_survives_fragmented_reads_and_partial_writes() {
    install_crypto_provider();
    let (addr, server, layer) = spawn_v3_echo_relay().await;
    let tcp = TcpStream::connect(addr).await.unwrap();
    let mut s =
        meow_transport::shadow_tls::dial(Box::new(Choppy::new(tcp)), &layer, 3, PASSWORD, false)
            .await
            .expect("v3 dial over a fragmenting stream");
    // > one 16 KiB record each way, written in odd-sized pieces.
    let payload: Vec<u8> = (0..40_000u32).map(|i| (i % 253) as u8).collect();
    let mut got = Vec::with_capacity(payload.len());
    for chunk in payload.chunks(9_973) {
        s.write_all(chunk).await.unwrap();
        s.flush().await.unwrap();
        let mut buf = vec![0u8; chunk.len()];
        tokio::time::timeout(std::time::Duration::from_secs(10), s.read_exact(&mut buf))
            .await
            .expect("fragmented echo timed out")
            .unwrap();
        got.extend(buf);
    }
    assert!(got == payload, "payload corrupted under fragmentation");
    drop(s);
    tokio::time::timeout(std::time::Duration::from_secs(10), server)
        .await
        .expect("relay must see the hang-up")
        .unwrap();
}

/// Cancelling a dial mid-handshake (caller dropped the future) releases
/// the socket: the peer observes EOF promptly instead of a leaked conn.
#[tokio::test]
async fn v3_cancelled_dial_releases_connection() {
    install_crypto_provider();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (_, cert) = server_conn();
    let server = tokio::spawn(async move {
        let (mut tcp, _) = listener.accept().await.unwrap();
        let ch = read_record(&mut tcp).await.unwrap();
        verify_ch_tag(&ch, PASSWORD);
        // Never answer; wait for the client side to go away.
        let mut b = [0u8; 64];
        loop {
            match tcp.read(&mut b).await {
                Ok(0) | Err(_) => return,
                Ok(_) => {}
            }
        }
    });
    let layer = client_layer(3, &cert);
    let tcp = TcpStream::connect(addr).await.unwrap();
    let dial = meow_transport::shadow_tls::dial(Box::new(tcp), &layer, 3, PASSWORD, false);
    let res = tokio::time::timeout(std::time::Duration::from_millis(200), dial).await;
    assert!(
        res.is_err(),
        "dial against a silent relay must not complete"
    );
    // The timeout dropped the dial future (and its socket).
    tokio::time::timeout(std::time::Duration::from_secs(5), server)
        .await
        .expect("relay must observe the cancelled client's EOF")
        .unwrap();
}

/// A relay that stalls after its ServerHello (half a handshake) cannot
/// wedge the caller: an outer timeout bounds the dial and nothing on the
/// client side blocks past it.
#[tokio::test]
async fn v3_stalled_relay_is_bounded_by_caller_timeout() {
    install_crypto_provider();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (mut conn, cert) = server_conn();
    let server = tokio::spawn(async move {
        let (mut tcp, _) = listener.accept().await.unwrap();
        let ch = read_record(&mut tcp).await.unwrap();
        conn.read_tls(&mut &ch[..]).unwrap();
        conn.process_new_packets().unwrap();
        // Forward only the ServerHello record, then go silent.
        let mut produced = Vec::new();
        while conn.wants_write() {
            conn.write_tls(&mut produced).unwrap();
        }
        let sh_len = RECORD_HDR + u16::from_be_bytes([produced[3], produced[4]]) as usize;
        tcp.write_all(&produced[..sh_len]).await.unwrap();
        let mut b = [0u8; 64];
        while matches!(tcp.read(&mut b).await, Ok(n) if n > 0) {}
    });
    let layer = client_layer(3, &cert);
    let tcp = TcpStream::connect(addr).await.unwrap();
    let started = std::time::Instant::now();
    let res = tokio::time::timeout(
        std::time::Duration::from_millis(300),
        meow_transport::shadow_tls::dial(Box::new(tcp), &layer, 3, PASSWORD, false),
    )
    .await;
    assert!(res.is_err(), "half a handshake must not authorize");
    assert!(started.elapsed() < std::time::Duration::from_secs(2));
    tokio::time::timeout(std::time::Duration::from_secs(5), server)
        .await
        .expect("stalled relay must see the client go away")
        .unwrap();
}

/// Independent concurrent sessions (each its own server random and
/// rolling chains) neither cross-talk nor leak: every relay task ends
/// once its client hangs up.
#[tokio::test]
async fn v3_concurrent_sessions_are_isolated_and_cleaned_up() {
    install_crypto_provider();
    let mut tasks = Vec::new();
    for i in 0..8u8 {
        tasks.push(tokio::spawn(async move {
            let (addr, server, layer) = spawn_v3_echo_relay().await;
            let tcp = TcpStream::connect(addr).await.unwrap();
            let mut s = meow_transport::shadow_tls::dial(Box::new(tcp), &layer, 3, PASSWORD, false)
                .await
                .expect("concurrent v3 dial");
            for round in 0..3u8 {
                let msg = vec![i ^ round; 3000 + usize::from(i) * 100];
                s.write_all(&msg).await.unwrap();
                s.flush().await.unwrap();
                let mut buf = vec![0u8; msg.len()];
                s.read_exact(&mut buf).await.unwrap();
                assert_eq!(buf, msg, "session {i} round {round}");
            }
            s.shutdown().await.unwrap();
            drop(s);
            tokio::time::timeout(std::time::Duration::from_secs(10), server)
                .await
                .expect("relay task must finish after client shutdown")
                .unwrap();
        }));
    }
    for t in tasks {
        t.await.unwrap();
    }
}
