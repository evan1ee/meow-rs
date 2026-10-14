//! In-process ShadowTLS client options + dial (mihomo `transport/shadowtls`
//! parity — the record layer lives in [`meow_transport::shadow_tls`]).
//!
//! Shared by the Shadowsocks `plugin: shadow-tls` SIP003 plugin and Snell's
//! `obfs-opts.mode: shadow-tls` (both mihomo surfaces decode the same
//! `shadowTLSOption`), so the option parser, the cover-handshake shaping and
//! the handshake itself exist exactly once.
//!
//! Option keys (`plugin-opts` for SS, `obfs-opts` for Snell):
//!
//! | opt | meaning | default |
//! |-----|---------|---------|
//! | `host` | cover server name — TLS SNI of the relayed handshake | *(required)* |
//! | `password` | per-user PSK (v2 handshake HMAC / v3 session-id tag) | `""` |
//! | `version` | protocol version 1, 2 or 3 | `2` (upstream default) |
//! | `alpn` | comma-separated ALPN list for the cover handshake | `h2,http/1.1` |
//! | `skip-cert-verify` | disable cover cert verification | `false` |
//! | `name-cert-verify` | cert-verify hostname when it differs from SNI (upstream `NameCertVerify`) | `host` |
//! | `fingerprint` | SHA-256 **certificate pin** (upstream
//!   `FingerprintVerifier`), *not* a uTLS profile | — |
//! | `certificate` / `private-key` | mTLS pair — inline PEM or file path | — |
//! | `strict-mode` | v3 only: refuse a cover that negotiates below TLS 1.3 (upstream `ClientConfig.StrictMode`) | `false` |
//!
//! The node-level `client-fingerprint` option shapes the cover
//! ClientHello (uTLS profile → `TlsConfig::fingerprint`), matching
//! upstream's `ShadowTLSOption.ClientFingerprint`.
//!
//! Version bounds on the cover handshake mirror upstream
//! (`MinVersion = TLS 1.2`, `v1` caps at TLS 1.2).  v3 keeps the 1.2
//! floor: the ClientHello still offers TLS 1.3 (so the compat session id
//! the HMAC patch needs is emitted), and a TLS 1.2 cover authorizes at
//! its ServerHello exactly as upstream (`authorized = !isTLS13`).

use meow_common::error::{MeowError, Result};
use meow_transport::{
    shadow_tls,
    tls::{ClientCert, TlsConfig, TlsLayer, TlsVersion},
    Stream,
};
use tracing::{debug, warn};

use crate::plugin_util::{load_pem_or_path, parse_bool_strict, parse_cert_pin, sip003_opts};
use crate::transport_to_proxy_err;

const PLUGIN: &str = "shadow-tls";

/// Protocol version used when `plugin-opts.version` is omitted — mihomo
/// pre-seeds its option struct with `Version: 2` before decoding.
pub const DEFAULT_VERSION: u8 = 2;

/// Parsed `shadow-tls` client options.
///
/// `Debug` is hand-written so the PSK and client key never reach a log
/// line or error message.
#[derive(Clone)]
pub struct ShadowTlsConfig {
    /// Cover server name — the TLS handshake's SNI; the shadow-tls server
    /// relays the handshake to this host.
    pub host: String,
    /// Per-user PSK (ignored by v1, matching upstream).
    pub password: String,
    /// Protocol version 1, 2 or 3 — defaults to [`DEFAULT_VERSION`] when
    /// omitted, like upstream (`shadowTLSOption{Version: 2}` before decode).
    pub version: u8,
    /// ALPN for the cover handshake (upstream default `h2,http/1.1`).
    pub alpn: Vec<String>,
    pub skip_cert_verify: bool,
    /// Cert-verify hostname when it differs from `host`/SNI
    /// (`name-cert-verify`, upstream `shadowTLSOption.NameCertVerify`).
    pub verify_name: Option<String>,
    /// SHA-256 certificate pin (`fingerprint` — SSL pinning per upstream
    /// `ca.NewFingerprintVerifier`, *not* a uTLS ClientHello profile).
    pub cert_pin: Option<[u8; 32]>,
    /// mTLS client certificate (`certificate` + `private-key`, PEM or path).
    pub client_cert: Option<ClientCert>,
    /// `strict-mode` — v3 only: refuse a cover that negotiates below
    /// TLS 1.3 (upstream `ClientConfig.StrictMode`; v1/v2 ignore it,
    /// matching upstream where the check lives in the v3 arm).
    pub strict_mode: bool,
}

impl std::fmt::Debug for ShadowTlsConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ShadowTlsConfig")
            .field("host", &self.host)
            .field("password", &"<redacted>")
            .field("version", &self.version)
            .field("alpn", &self.alpn)
            .field("skip_cert_verify", &self.skip_cert_verify)
            .field("verify_name", &self.verify_name)
            .field("cert_pin", &self.cert_pin.is_some())
            .field("client_cert", &self.client_cert.is_some())
            .field("strict_mode", &self.strict_mode)
            .finish()
    }
}

/// Parse a flattened SIP003 opts string for `shadow-tls`
/// (`host=cover.example.com;password=…;version=3;alpn=h2,http/1.1`).
///
/// - `host` is required (upstream `obfs:"host"` has no `omitempty`).
/// - `version` accepts `1`/`2`/`3` and defaults to [`DEFAULT_VERSION`]
///   when omitted; anything else (incl. an explicit empty value) is a
///   config error.
/// - Unknown keys are logged at `warn` level and ignored.
pub fn parse_opts(s: &str) -> Result<ShadowTlsConfig> {
    let mut cfg = ShadowTlsConfig {
        host: String::new(),
        password: String::new(),
        version: DEFAULT_VERSION,
        alpn: Vec::new(),
        skip_cert_verify: false,
        verify_name: None,
        cert_pin: None,
        client_cert: None,
        strict_mode: false,
    };
    let mut alpn_seen = false;
    let mut cert_pem: Option<Vec<u8>> = None;
    let mut key_pem: Option<Vec<u8>> = None;

    for (key, value) in sip003_opts(s) {
        match key.as_str() {
            "host" => cfg.host = value,
            "password" => cfg.password = value,
            "version" => {
                cfg.version = value
                    .parse::<u8>()
                    .ok()
                    .filter(|v| (1..=3).contains(v))
                    .ok_or_else(|| {
                        MeowError::Config(format!(
                            "{PLUGIN}: 'version' must be 1, 2 or 3, got '{value}'"
                        ))
                    })?;
            }
            "alpn" => {
                alpn_seen = true;
                cfg.alpn = value
                    .split(',')
                    .map(str::trim)
                    .filter(|p| !p.is_empty())
                    .map(str::to_string)
                    .collect();
            }
            "skip-cert-verify" => {
                cfg.skip_cert_verify = parse_bool_strict(&value, PLUGIN, "skip-cert-verify")?;
            }
            "name-cert-verify" if !value.is_empty() => cfg.verify_name = Some(value),
            "fingerprint" if !value.is_empty() => {
                cfg.cert_pin = Some(parse_cert_pin(&value, PLUGIN)?);
            }
            // Explicit-empty value clears the opt — same as absent.
            "name-cert-verify" | "fingerprint" => {}
            "strict-mode" => {
                cfg.strict_mode = parse_bool_strict(&value, PLUGIN, "strict-mode")?;
            }
            "certificate" => cert_pem = Some(load_pem_or_path(&value, "certificate", PLUGIN)?),
            "private-key" => key_pem = Some(load_pem_or_path(&value, "private-key", PLUGIN)?),
            other => warn!("{PLUGIN}: ignoring unknown opt '{other}'"),
        }
    }

    if cfg.host.is_empty() {
        return Err(MeowError::Config(format!(
            "{PLUGIN}: missing required 'host' opt (cover server name)"
        )));
    }
    // Absent `alpn` → upstream DefaultALPN; `alpn=` (explicit empty) is
    // honored as no-ALPN, matching upstream's `opt.ALPN != nil` check.
    if !alpn_seen {
        cfg.alpn = shadow_tls::DEFAULT_ALPN
            .iter()
            .map(ToString::to_string)
            .collect();
    }
    // mTLS: both halves or none — a lone cert or key is a config error.
    match (cert_pem, key_pem) {
        (Some(cert_pem), Some(key_pem)) => {
            cfg.client_cert = Some(ClientCert { cert_pem, key_pem });
        }
        (None, None) => {}
        _ => {
            return Err(MeowError::Config(format!(
                "{PLUGIN}: 'certificate' and 'private-key' must both be set"
            )));
        }
    }
    if cfg.version != 1 && cfg.password.is_empty() {
        warn!(
            "{PLUGIN}: empty password — v{} authentication will fail",
            cfg.version
        );
    }
    Ok(cfg)
}

/// Build the cover-handshake `TlsLayer`.  `client_fingerprint` is the
/// node-level `client-fingerprint` option (uTLS profile shaping).
///
/// Version bounds mirror upstream: TLS 1.2 floor for every version, TLS
/// 1.2 cap for v1.  v3 needs no 1.3 floor — the compat session id is
/// emitted whenever 1.3 is *offered* (the floor does not remove it), and
/// a TLS 1.2 cover still authorizes the session at its ServerHello.
/// Upstream also drops `client-fingerprint` when the cap is 1.2
/// (`uTLSHandshakeFunc` forces `""`) — a 1.2-only ClientHello should not
/// carry a 1.3-shaped profile.
pub fn build_tls_layer(
    cfg: &ShadowTlsConfig,
    client_fingerprint: Option<&str>,
) -> Result<TlsLayer> {
    if cfg.version == 3
        && (cfg.cert_pin.is_some() || cfg.verify_name.is_some() || cfg.skip_cert_verify)
    {
        warn!(
            "{PLUGIN}: 'fingerprint'/'name-cert-verify'/'skip-cert-verify' only \
             take effect on a TLS 1.2 cover — on a 1.3 cover the post-ServerHello \
             flight is undecryptable, so the embedded record tags are the only \
             authenticator"
        );
    }
    let tls_config = tls_config_for(cfg, client_fingerprint);
    TlsLayer::new(&tls_config).map_err(transport_to_proxy_err)
}

/// Build the [`TlsConfig`] for the cover handshake. Split out from
/// [`build_tls_layer`] so tests can pin the per-version shaping matrix
/// (v1 fingerprint drop, v1 max-version cap, v2 ML-KEM strip).
fn tls_config_for(cfg: &ShadowTlsConfig, client_fingerprint: Option<&str>) -> TlsConfig {
    let fingerprint = client_fingerprint
        .filter(|_| cfg.version != 1)
        .map(str::to_string);
    TlsConfig {
        alpn: cfg.alpn.clone(),
        skip_cert_verify: cfg.skip_cert_verify,
        verify_name: cfg.verify_name.clone(),
        cert_pin: cfg.cert_pin,
        client_cert: cfg.client_cert.clone(),
        // Upstream removes X25519MLKEM768 from the v2 ClientHello after
        // uTLS shaping (`BuildRemovedX25519MLKEM768HandshakeState` — a
        // hybrid-PQ keyshare breaks v2 servers). The strip is surgical:
        // it must not clobber a resolved profile's own group list
        // (firefox advertises P-521, android orders P-256 first), and
        // every shipped profile already excludes ML-KEM — so the classic
        // pin is needed only when no profile shapes the hello and the
        // vendored BoringSSL default (which does offer ML-KEM) applies.
        curves: (cfg.version == 2
            && client_fingerprint
                .is_none_or(|fp| !meow_transport::tls::is_supported_fingerprint(fp)))
        .then(|| "X25519:P-256:P-384".to_string()),
        fingerprint,
        min_version: Some(TlsVersion::Tls12),
        max_version: (cfg.version == 1).then_some(TlsVersion::Tls12),
        ..TlsConfig::new(&cfg.host)
    }
}

/// Run the ShadowTLS handshake over an already-connected stream (a fresh
/// TCP dial, or a relay-supplied stream on a `relay` chain hop) and return
/// the authenticated data stream ready for the SS/Snell codec.
///
/// Fails closed: an unauthenticated relay, a strict-mode violation or a
/// cover-certificate failure is an error — never a fallback to plain data.
pub async fn handshake_over(
    cfg: &ShadowTlsConfig,
    tls: &TlsLayer,
    stream: Box<dyn Stream>,
) -> Result<Box<dyn Stream>> {
    shadow_tls::dial(
        stream,
        tls,
        cfg.version,
        cfg.password.as_bytes(),
        cfg.strict_mode,
    )
    .await
    .map_err(transport_to_proxy_err)
}

/// Dial a TCP + shadow-tls connection to `server_host:server_port` and
/// return the framed stream ready to be wrapped by the SS/Snell codec.
pub async fn dial(
    cfg: &ShadowTlsConfig,
    tls: &TlsLayer,
    server_host: &str,
    server_port: u16,
    dialer: &dyn crate::dialer::TcpDialer,
    internal: bool,
) -> Result<Box<dyn Stream>> {
    debug!(
        "{PLUGIN}: dialing {server_host}:{server_port} via cover={} version={}",
        cfg.host, cfg.version
    );
    let tcp = dialer
        .dial(server_host, server_port, internal)
        .await
        .map_err(MeowError::Io)?;
    handshake_over(cfg, tls, Box::new(tcp)).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_opts_cases() {
        let cases: &[(&str, bool)] = &[
            // version omitted → upstream default 2
            ("host=cover.example.com", true),
            ("host=cover.example.com;password=psk", true),
            ("host=h;version=", false), // explicit empty is not "omitted"
            // every version accepted
            ("host=h;version=1;password=p", true),
            ("host=h;version=2;password=p", true),
            ("host=h;version=3;password=p", true),
            // upstream option surface
            ("host=h;version=2;password=p;alpn=h2,http/1.1", true),
            ("host=h;version=2;alpn=", true), // explicit empty = no ALPN
            ("host=h;version=2;skip-cert-verify=true", true),
            ("host=h;version=2;name-cert-verify=real.example.com", true),
            (
                "host=h;version=2;fingerprint=aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:\
                 88:99:aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99",
                true,
            ),
            ("host=h;version=0", false),
            ("host=h;version=4", false),
            ("host=h;version=three", false),
            ("version=2;password=psk", false), // host required
            ("", false),                       // empty → no host
            ("host=h;version=2;fingerprint=chrome", false), // uTLS name rejected
            ("host=h;version=2;fingerprint=zz", false), // bad hex
            // Security-relevant booleans parse strictly — a typo is a
            // config error, not a silent downgrade.
            ("host=h;version=2;skip-cert-verify=bogus", false),
            ("host=h;version=3;strict-mode=bogus", false),
            ("host=h;version=3;strict-mode=true", true),
            // Explicit-empty value clears the opt — same as absent.
            ("host=h;version=2;fingerprint=", true),
            ("host=h;version=2;name-cert-verify=", true),
            ("host=h;version=2;certificate=nonexistent.pem", false), // path missing
            ("host=h;version=2;certificate=-----BEGIN X-----\nPEM", false), // key missing
        ];
        for (opts, ok) in cases {
            assert_eq!(
                parse_opts(opts).is_ok(),
                *ok,
                "opts {opts:?} expected ok={ok}"
            );
        }
    }

    /// Upstream removes the hybrid-PQ `X25519MLKEM768` key share from the
    /// v2 ClientHello after uTLS shaping — the strip never replaces the
    /// shaped group list. Every shipped profile already excludes ML-KEM,
    /// so the classic pin applies only when no profile resolves and the
    /// vendored-BoringSSL default hello (which offers ML-KEM) would run.
    #[test]
    fn tls_config_for_pins_v2_classic_curves() {
        for (version, want) in [(1u8, None), (2, Some("X25519:P-256:P-384")), (3, None)] {
            let cfg = parse_opts(&format!("host=h;version={version};password=p")).unwrap();
            let tls = tls_config_for(&cfg, None);
            assert_eq!(
                tls.curves.as_deref(),
                want,
                "version {version} curves pin mismatch"
            );
        }
        // A resolved fingerprint lifts the pin — its own group list is
        // already ML-KEM-free, and overriding it would break the profile
        // (firefox's P-521, android's P-256-first ordering).
        let cfg = parse_opts("host=h;version=2;password=p").unwrap();
        for fp in ["chrome", "firefox", "android", "random"] {
            let tls = tls_config_for(&cfg, Some(fp));
            assert_eq!(tls.curves.as_deref(), None, "{fp} must keep its own list");
            assert_eq!(tls.fingerprint.as_deref(), Some(fp));
        }
        // A deferred/unknown fingerprint resolves to nothing — the
        // default hello offers ML-KEM, so the pin must hold.
        let tls = tls_config_for(&cfg, Some("randomized"));
        assert_eq!(tls.curves.as_deref(), Some("X25519:P-256:P-384"));
        assert_eq!(tls.fingerprint.as_deref(), Some("randomized"));
    }

    /// mihomo seeds `Version: 2` before decoding `plugin-opts`, so an
    /// omitted `version` is v2; explicit values are kept verbatim and
    /// anything outside 1..=3 is refused with the offending value named.
    #[test]
    fn version_defaults_to_two_and_validates() {
        let cfg = parse_opts("host=cover.example.com;password=p").unwrap();
        assert_eq!(cfg.version, DEFAULT_VERSION);
        assert_eq!(cfg.version, 2);
        for v in 1..=3u8 {
            let cfg = parse_opts(&format!("host=h;password=p;version={v}")).unwrap();
            assert_eq!(cfg.version, v, "explicit version {v} kept");
        }
        for bad in ["0", "4", "-1", "three", ""] {
            let err = parse_opts(&format!("host=h;password=p;version={bad}"))
                .expect_err("invalid version must fail")
                .to_string();
            assert!(
                err.contains("'version' must be 1, 2 or 3") && err.contains(bad),
                "version={bad:?}: {err}"
            );
        }
    }

    /// Neither the PSK nor key material may leak through `Debug`.
    #[test]
    fn debug_redacts_password() {
        let cfg = parse_opts("host=h;password=hunter2-secret;version=3").unwrap();
        let shown = format!("{cfg:?}");
        assert!(!shown.contains("hunter2-secret"), "{shown}");
        assert!(shown.contains("<redacted>"), "{shown}");
    }

    #[test]
    fn parse_opts_defaults() {
        let cfg = parse_opts("host=cover.example.com;version=2").unwrap();
        assert_eq!(cfg.alpn, ["h2", "http/1.1"], "upstream DefaultALPN");
        assert!(cfg.password.is_empty());
        assert!(cfg.verify_name.is_none());
        assert!(cfg.cert_pin.is_none());

        // `alpn=` explicit-empty suppresses the extension entirely —
        // upstream `opt.ALPN != nil` distinguishes it from "absent".
        let cfg = parse_opts("host=cover.example.com;version=2;alpn=").unwrap();
        assert!(cfg.alpn.is_empty(), "explicit alpn= must not re-default");
    }

    #[test]
    fn parse_opts_full() {
        let cfg = parse_opts(
            "host=cover.example.com;password=psk;version=3;alpn=h3,h2;\
             skip-cert-verify=true;name-cert-verify=real.example.com;\
             fingerprint=AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899",
        )
        .unwrap();
        assert_eq!(cfg.version, 3);
        assert_eq!(cfg.alpn, ["h3", "h2"]);
        assert!(cfg.skip_cert_verify);
        assert_eq!(cfg.verify_name.as_deref(), Some("real.example.com"));
        assert!(cfg.cert_pin.is_some());
    }

    #[test]
    fn build_tls_layer_bounds() {
        // Construction succeeds for every version with a valid host —
        // bounds (v1 → max 1.2, all → min 1.2) are enforced inside
        // TlsConfig; invalid combos would error here.
        for v in 1..=3u8 {
            let cfg = parse_opts(&format!("host=cover.example.com;version={v}")).unwrap();
            build_tls_layer(&cfg, None).unwrap_or_else(|e| panic!("v{v}: {e}"));
        }
        // client-fingerprint is forwarded into the cover handshake —
        // except under v1, whose TLS 1.2 cap drops it (upstream parity).
        let cfg = parse_opts("host=cover.example.com;version=3").unwrap();
        build_tls_layer(&cfg, Some("chrome")).unwrap();
        let cfg = parse_opts("host=cover.example.com;version=1").unwrap();
        build_tls_layer(&cfg, Some("chrome")).unwrap();
    }

    /// The version-dependent TlsConfig shaping, asserted field by field:
    /// a dropped `max_version` would send a TLS 1.3 ClientHello for v1;
    /// a dropped `curves` pin reintroduces X25519MLKEM768 into v2.
    #[test]
    fn tls_config_for_shapes_per_version() {
        use meow_transport::tls::TlsVersion;
        for v in 1..=3u8 {
            let cfg = parse_opts(&format!("host=cover.example.com;version={v}")).unwrap();
            let c = tls_config_for(&cfg, None);
            assert_eq!(c.min_version, Some(TlsVersion::Tls12), "v{v} floor");
            assert_eq!(
                c.max_version,
                (v == 1).then_some(TlsVersion::Tls12),
                "v{v} cap"
            );
            assert_eq!(c.curves.is_some(), v == 2, "v{v} MLKEM drop applies to v2");
        }
        // A resolved v2 fingerprint keeps its own (ML-KEM-free) group
        // list — the pin lifts — while v1 drops the fingerprint entirely
        // (upstream parity).
        let cfg = parse_opts("host=cover.example.com;version=2").unwrap();
        let c = tls_config_for(&cfg, Some("chrome"));
        assert!(c.curves.is_none() && c.fingerprint.is_some());
        let cfg = parse_opts("host=cover.example.com;version=1").unwrap();
        let c = tls_config_for(&cfg, Some("chrome"));
        assert!(
            c.fingerprint.is_none(),
            "v1 must not carry a 1.3-shaped profile"
        );
    }

    /// `strict-mode` is parsed strictly and threaded to the transport
    /// dial (the wire-level gate itself is e2e'd in meow-transport's
    /// `v3_strict_mode_rejects_tls12_cover`).
    #[test]
    fn strict_mode_parses() {
        let cfg = parse_opts("host=h;version=3;strict-mode=true").unwrap();
        assert!(cfg.strict_mode);
        let cfg = parse_opts("host=h;version=3").unwrap();
        assert!(!cfg.strict_mode);
    }
}
