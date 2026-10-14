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

**In development.** ShadowTLS v3 support is a development goal and should not be considered functional until implementation and interoperability tests pass.

## License

Follow the original meow-rs license and comply with the licenses of all dependencies.
