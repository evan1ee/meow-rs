# `shadow-tls` — native client transport (v3)

meow-rs ships a built-in (no-subprocess) client for
[ShadowTLS](https://github.com/ihciah/shadow-tls) as a Shadowsocks
`plugin: shadow-tls`. The connection starts with a **real** TLS handshake
against a public *cover* site, relayed byte-for-byte by the ShadowTLS
server. An observer sees a genuine handshake with that site (its real
certificate, real ServerHello). After the handshake the Shadowsocks
stream continues inside TLS `application_data` records that are
authenticated per record.

Protocol versions 1, 2 and 3 are implemented
(`crates/meow-transport/src/shadow_tls.rs`). **Use v3**: v1 has no
authentication, and v2 authenticates only the first data record. v3
authenticates the ClientHello (an HMAC in its session id) and every
record in both directions, and it detects a relay that is not a
ShadowTLS server ("traffic hijacked").

## Client configuration

Clash-style YAML, compatible with existing `type: ss` nodes. Only
`plugin`, `plugin-opts` and (optionally) `client-fingerprint` are added:

```yaml
proxies:
  - name: ss-shadowtls
    type: ss
    server: 203.0.113.10        # the ShadowTLS server
    port: 6443                  # its listen port
    cipher: chacha20-ietf-poly1305
    password: YOUR_SS_PASSWORD
    udp: true                   # accepted; see "UDP" below
    plugin: shadow-tls
    client-fingerprint: chrome  # shapes the cover ClientHello
    plugin-opts:
      host: www.example.com     # cover site (TLS SNI) — must match the server's --tls
      password: YOUR_SHADOWTLS_PASSWORD
      version: 3
      skip-cert-verify: false
```

The plugin wraps the TCP stream underneath the Shadowsocks layer, so any
SS cipher works unchanged. `chacha20-ietf-poly1305` is the cipher the
interop suite runs end to end against the official server.

### `plugin-opts`

| opt | meaning | default |
|-----|---------|---------|
| `host` | cover server name: the TLS SNI of the relayed handshake | *(required)* |
| `password` | ShadowTLS password (the server's `--password`) | `""` |
| `version` | `1`, `2` or `3` (integer or string) | *(required)* |
| `alpn` | ALPN list for the cover handshake (YAML list or comma string) | `h2,http/1.1` |
| `skip-cert-verify` | disable cover certificate verification (strict boolean) | `false` |
| `strict-mode` | v3: refuse a cover that negotiates below TLS 1.3 | `false` |
| `fingerprint` | SHA-256 pin of the cover certificate (hex), *not* a uTLS profile | — |
| `name-cert-verify` | hostname for certificate verification when it differs from `host` (meow extension) | `host` |
| `certificate` / `private-key` | mTLS pair, inline PEM or file path | — |

The node-level `client-fingerprint` (`chrome`, `firefox`, `safari`,
`ios`, `android`, `edge`, `random`, …) shapes the cover ClientHello the
same way mihomo's does.

Booleans parse strictly: a typo such as `skip-cert-verify: flase` is a
config error, never a silent downgrade.

## Server setup (official ShadowTLS)

Run the official server in front of a Shadowsocks server. The SS server
listens on loopback; ShadowTLS owns the public port:

```sh
ssserver -s 127.0.0.1:8388 -m chacha20-ietf-poly1305 -k 'YOUR_SS_PASSWORD'

shadow-tls --v3 --strict server \
    --listen 0.0.0.0:6443 \
    --server 127.0.0.1:8388 \
    --tls www.example.com:443 \
    --password 'YOUR_SHADOWTLS_PASSWORD'
```

Choose a cover (`--tls` / `host`) that serves **TLS 1.3**, is reachable
from the server with low latency, and is plausible for your network.
`--strict` (server) and `strict-mode: true` (client) refuse TLS 1.2
covers outright.

## Interoperability status

Verified against the official `ihciah/shadow-tls` server (v0.2.25, and
`master` at the time of writing) by
`crates/meow-proxy/tests/shadow_tls_v3_e2e.rs`. The suite drives the full
client stack (SS `chacha20-ietf-poly1305` + shadow-tls v3 +
`client-fingerprint: chrome`) through the real server binary to a loopback
SS backend and covers:

- TLS 1.3 cover: echo round trips, a 256 KiB multi-record bulk transfer,
  concurrent sessions, and a client that stays idle before its first write;
- TLS 1.2 cover with a `fingerprint` pin; an unpinned self-signed cover
  fails closed;
- a wrong ShadowTLS password: the server falls back to a plain SNI proxy
  and the client refuses the unauthenticated cover;
- client `strict-mode` and server `--strict` against a TLS 1.2 cover;
- connection refused.

The wire mechanics (ClientHello tag, swizzled-record authorization,
rolling HMAC framing, tampered-record rejection, mid-handshake EOF and
garbage) are also covered against an in-process mock by
`crates/meow-transport/tests/shadow_tls_test.rs`. To run the interop
suite locally:

```sh
bash scripts/fetch-shadowtls-server.sh /tmp/meow-stls
SHADOWTLS_SERVER_BIN=/tmp/meow-stls/shadow-tls \
  cargo test -p meow-proxy --test shadow_tls_v3_e2e
```

## Limitations

### UDP

ShadowTLS carries TCP only. The server has no datagram path, so a
`shadow-tls` node **does not advertise UDP**, even with `udp: true`. For a
UDP flow, rule matching skips such a node and falls through to the next
rule whose target can carry UDP, so route UDP to another proxy or to
`DIRECT` explicitly. mihomo behaves differently: it sends raw
Shadowsocks UDP straight to `server:port`, outside the TLS disguise. That
only works if the SS server's UDP port is publicly exposed, and it reveals
plain SS traffic next to the cover. meow refuses that leak rather than
emulate it. This is a Class A (evasion) divergence under
[ADR-0002](../adr/0002-upstream-divergence-policy.md).

### Cover handshake

BoringSSL has no hook for choosing the session id, so the client patches
the authenticated session id into the serialized ClientHello. The
cover's transcript then differs from the client's, and the cover
handshake can never complete locally. Authentication still holds,
because it rests on the per-record HMACs, which is the point of the
protocol. Consequences:

- **TLS 1.3 cover (recommended).** The cover's certificate arrives
  encrypted and cannot be verified by the client. `skip-cert-verify`,
  `fingerprint` and `name-cert-verify` have no effect there. The relay's
  correctly tagged records are the only authenticator, as in upstream.
  The client never sends an alert to the cover, so an idle client keeps
  its session as long as the cover would wait for a handshake to finish
  (typically tens of seconds).
- **TLS 1.2 cover.** Certificate verification runs on the plaintext
  server flight and is enforced, including `fingerprint` pinning. The
  cover rejects the client's Finished, so the client ends the handshake
  right after sending it, and the first payload must reach the relay
  before the cover's rejection does (about one relay↔cover round trip).
  Client-first protocols (HTTP, TLS) meet this naturally. A
  server-first application that waits more than a round trip before
  the client speaks can lose the session. Prefer TLS 1.3 covers, or use
  `strict-mode`.

### Other

- A `shadow-tls` node cannot be a **non-first hop** of a `relay` group:
  the plugin owns its TCP dial, so a relay-supplied stream fails loudly
  instead of carrying unwrapped traffic. `dialer-proxy` on the node itself
  works, because the plugin's TCP dial goes through the node's dialer.
- `version: 1` is unauthenticated and kept only for parity. `version: 2`
  strips hybrid post-quantum key shares from the ClientHello (upstream
  parity).
