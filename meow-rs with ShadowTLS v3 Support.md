# meow-rs with ShadowTLS v3 Support

A fork of [meow-rs](https://github.com/meow-rs/meow-rs) aimed at adding native ShadowTLS v3 support for Shadowsocks outbound connections.

## Goals

- Add native ShadowTLS v3 support.
- Support Shadowsocks with `chacha20-ietf-poly1305`.
- Support Clash-style YAML configuration.
- Preserve compatibility with existing Shadowsocks configurations.
- Add tests for TLS handshakes, TCP transmission, authentication failures, and connection errors.

## Example Configuration

```yaml
proxies:
  - name: ss-shadowtls
    type: ss
    server: YOUR_SERVER_IP
    port: 6443
    cipher: chacha20-ietf-poly1305
    password: YOUR_SS_PASSWORD
    udp: true
    plugin: shadow-tls
    client-fingerprint: chrome
    plugin-opts:
      host: pubilc.webiste
      password: YOUR_SHADOWTLS_PASSWORD
      version: 3
      skip-cert-verify: false
```

Replace the placeholder values with your actual server settings.

## Development Plan

1. Inspect the existing Shadowsocks outbound and TLS transport implementations.
2. Implement the ShadowTLS v3 handshake and stream transport.
3. Integrate the adapter with the existing configuration parser.
4. Add unit tests and integration tests.
5. Verify compatibility with an official ShadowTLS v3 server.
6. Document UDP support and any remaining limitations.

## Dependencies

- [meow-rs](https://github.com/meow-rs/meow-rs)
- [ShadowTLS](https://github.com/ihciah/shadow-tls) — protocol reference and interoperability testing.
- Existing TLS and Shadowsocks dependencies from meow-rs.

No additional forks are planned unless changes to an upstream dependency prove necessary.

## Status

**Functional — interoperability tests pass against the official ShadowTLS v3 server.**

| Plan step | Where |
|-----------|-------|
| 1. Inspect SS outbound + TLS transport | `plugin: shadow-tls` on `type: ss` (`crates/meow-proxy/src/shadowsocks_adapter.rs`) over the BoringSSL `TlsLayer` |
| 2. v3 handshake + stream transport | `crates/meow-transport/src/shadow_tls.rs`: tagged ClientHello session id, swizzled-record authorization, rolling-HMAC data framing |
| 3. Config parser integration | `crates/meow-proxy/src/shadow_tls_plugin.rs` (`plugin-opts`), `crates/meow-config/src/proxy_parser.rs`; the example above is pinned by `test_shadow_tls_v3_documented_node` |
| 4. Unit + integration tests | `crates/meow-transport/tests/shadow_tls_test.rs` (handshakes, TCP transfer, wrong password, tampered records, mid-handshake EOF/garbage, strict mode) plus unit tests in the modules above |
| 5. Official-server interop | `crates/meow-proxy/tests/shadow_tls_v3_e2e.rs`, SS `chacha20-ietf-poly1305` through `ihciah/shadow-tls` v0.2.25 (`scripts/fetch-shadowtls-server.sh`), wired into CI |
| 6. UDP + limitations | [docs/plugins/shadow-tls.md](docs/plugins/shadow-tls.md): a shadow-tls node carries no UDP (`udp: true` is accepted and UDP flows fall through to another rule); TLS 1.3 covers are recommended |

Interop testing found and fixed one real incompatibility. The client's
local TLS stack sent an abort alert to the cover after its (expected)
handshake failure. That made the cover hang up, and the official server
then tore down the session before the first payload. The alert is now
swallowed. On TLS 1.2 covers the client ends the handshake as soon as its
Finished is sent, so the first payload switches the relay in time.

## License

Follow the original meow-rs license and comply with the licenses of all dependencies.
