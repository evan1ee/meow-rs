# `shadow-tls` — native client transport (v3)

meow-rs ships a built-in (no-subprocess) client for
[ShadowTLS](https://github.com/ihciah/shadow-tls). It is available on two
outbound types:

- **Shadowsocks:** `type: ss` with `plugin: shadow-tls`.
- **Snell:** `type: snell` with `obfs-opts.mode: shadow-tls` (v3–v5 only;
  Snell v6 has no obfs).

The connection starts with a **real** TLS handshake against a public
*cover* site, which the ShadowTLS server relays byte for byte. An observer
sees a genuine handshake with that site: its real certificate and its real
ServerHello. After the handshake, the proxy stream continues inside TLS
`application_data` records that are authenticated one by one.

Protocol versions 1, 2 and 3 are implemented
(`crates/meow-transport/src/shadow_tls.rs`). **Use v3.** v1 has no
authentication, and v2 authenticates only the first data record. v3
authenticates the ClientHello (an HMAC in its session id) and every record
in both directions. It also detects a relay that is not a ShadowTLS server
("traffic hijacked"). Both outbound types share one options parser and one
handshake implementation (`crates/meow-proxy/src/shadow_tls_plugin.rs`).

## Shadowsocks

The configuration is Clash-style YAML and works with existing `type: ss`
nodes. It adds only `plugin`, `plugin-opts` and, optionally,
`client-fingerprint` and `udp-over-tcp`:

```yaml
proxies:
  - name: ss-shadowtls
    type: ss
    server: 203.0.113.10        # the ShadowTLS server
    port: 6443                  # its listen port
    cipher: chacha20-ietf-poly1305
    password: YOUR_SS_PASSWORD
    udp: true
    udp-over-tcp: true          # optional: carry UDP through ShadowTLS (see "UDP")
    plugin: shadow-tls
    client-fingerprint: chrome  # shapes the cover ClientHello
    plugin-opts:
      host: www.example.com     # cover site (TLS SNI); must match the server's --tls
      password: YOUR_SHADOWTLS_PASSWORD
      version: 3
      skip-cert-verify: false
```

The plugin wraps the TCP stream underneath the Shadowsocks layer, so any SS
cipher works unchanged. `chacha20-ietf-poly1305` is the cipher the interop
suite runs end to end against the official server.

## Snell

```yaml
proxies:
  - name: snell-shadowtls
    type: snell
    server: 203.0.113.10
    port: 6443
    psk: YOUR_SNELL_PSK
    version: 4
    udp: true                   # Snell's own UDP rides the same ShadowTLS stream
    client-fingerprint: chrome
    obfs-opts:
      mode: shadow-tls
      host: www.example.com
      password: YOUR_SHADOWTLS_PASSWORD
      version: 3
```

`obfs-opts` takes the same keys as the SS `plugin-opts` below, plus
`mode`. Unlike the `http`/`tls` modes, `host` is required here and never
defaults to `server`: it is the cover SNI. Snell's UDP command and the
reuse pool open connections through the same step, so they always cross
ShadowTLS.

## Options (`plugin-opts` / `obfs-opts`)

| opt | meaning | default |
|-----|---------|---------|
| `host` | cover server name: the TLS SNI of the relayed handshake | *(required)* |
| `password` | ShadowTLS password (the server's `--password`) | `""` |
| `version` | `1`, `2` or `3` (integer or string) | `2` (as mihomo) |
| `alpn` | ALPN list for the cover handshake (YAML list or comma string) | `h2,http/1.1` |
| `skip-cert-verify` | disable cover certificate verification (strict boolean) | `false` |
| `fingerprint` | SHA-256 pin of the cover certificate (hex), *not* a uTLS profile | — |
| `name-cert-verify` | hostname to verify the certificate against, when it differs from `host` | `host` |
| `certificate` / `private-key` | mTLS pair, inline PEM or file path | — |
| `strict-mode` | v3: refuse a cover that negotiates below TLS 1.3 (meow extension) | `false` |

An omitted `version` means **2**, matching mihomo, which pre-sets
`Version: 2` before decoding. Set `version: 3` explicitly for v3 servers;
the official server only speaks v3 when started with `--v3`. Any value
other than 1, 2 or 3, including an empty one, is a configuration error that
names the value.

The node-level `client-fingerprint` (`chrome`, `firefox`, `safari`, `ios`,
`android`, `edge`, `random`, …) shapes the cover ClientHello the same way
mihomo's does. v1 drops it because its handshake is capped at TLS 1.2.

Booleans parse strictly. A typo such as `skip-cert-verify: flase` is a
config error, never a silent downgrade. The ShadowTLS password never
appears in logs or `Debug` output.

## UDP

ShadowTLS itself carries TCP only, and its server has no datagram path.

- **SS without `udp-over-tcp`.** The node **does not advertise UDP**, even
  with `udp: true`. For a UDP flow, rule matching skips the node and falls
  through to the next rule whose target can carry UDP. mihomo instead sends
  raw Shadowsocks UDP straight to `server:port`, outside the TLS disguise.
  That works only if the SS server's UDP port is publicly exposed, and it
  puts plain SS traffic next to the cover. meow refuses that leak: a
  Class A (evasion) divergence under
  [ADR-0002](../adr/0002-upstream-divergence-policy.md).
- **SS with `udp-over-tcp: true`.** This is mihomo's `UDPOverTCP`. Each UDP
  association opens one SS TCP stream to the UoT magic destination. That
  stream is dialed through the node's plugin transport, so datagrams travel
  inside authenticated ShadowTLS records. The client never sends SS UDP,
  and its config contains no UDP endpoint at all.
  - `udp-over-tcp-version`: `1` is legacy (`sp.udp-over-tcp.arpa`, the
    default; `0` also maps here). `2` is v2 (`sp.v2.udp-over-tcp.arpa`,
    with a request header first). Any other value is rejected, even when
    `udp-over-tcp` is off (upstream parity).
  - The **server** must speak UoT. sing-box and mihomo SS inbounds do.
    Plain `ssserver` (shadowsocks-rust) does not. sing-box 1.14 reads each
    UoT datagram into a 16 KiB buffer and closes the stream on a larger one,
    although the framing itself allows 64 KiB. Real UDP traffic (DNS, QUIC,
    games) stays far below that.
  - `udp-over-tcp` works on any SS node (plain, other plugins, ShadowTLS).
    kcptun nodes already relay UDP over legacy UoT, so `udp-over-tcp-version:
    2` on a kcptun node is rejected rather than ignored.
  - With `udp: false`, `udp-over-tcp` has no effect. meow logs a warning.
- **Snell.** Snell's own UDP-over-TCP command rides the ShadowTLS stream
  like its TCP sessions do.

## Rejected (fail at config load)

These mihomo options name a security or transport mode that meow does not
implement for the node's type. meow rejects them before any connection is
made rather than ignore them:

| option | on | why it is rejected, not ignored |
|--------|----|------|
| `shadow-tls-opts` | `trojan`, `vless`, `vmess` (any type) | Ignored, the node would speak plain TLS to a ShadowTLS relay. The relay forwards it to the real cover, and trojan's password hash goes with it. Use `type: ss` or `type: snell`. |
| `restls-opts`, `jls-opts` | any type | Same reason. These transports exist only as SS plugins (`plugin: restls` / `plugin: jls`). |
| `obfs-opts.mode: restls` / `jls` | `snell` | Named explicitly instead of reported as an "invalid mode". |
| `udp-over-tcp: true` | any non-SS type | It's a Shadowsocks option. Dropping it would change how UDP leaves the host. |

`shadow-tls-opts: {}` and `udp-over-tcp: false` stay accepted, because they
enable nothing.

## Server setup (official ShadowTLS)

Run the official server in front of the proxy server. The proxy server
listens on loopback; ShadowTLS owns the public port:

```sh
# Shadowsocks (UoT needs a UoT-capable server such as sing-box; ssserver works for TCP)
ssserver -s 127.0.0.1:8388 -m chacha20-ietf-poly1305 -k 'YOUR_SS_PASSWORD'

shadow-tls --v3 --strict server \
    --listen 0.0.0.0:6443 \
    --server 127.0.0.1:8388 \
    --tls www.example.com:443 \
    --password 'YOUR_SHADOWTLS_PASSWORD'
```

Choose a cover (`--tls` / `host`) that serves **TLS 1.3**, is reachable
from the server with low latency, and is plausible for your network.
`--strict` on the server and `strict-mode: true` on the client both refuse
TLS 1.2 covers outright.

## Interoperability status

Verified against the official `ihciah/shadow-tls` server (release v0.2.25,
and `master` at the time of writing) by
`crates/meow-proxy/tests/shadow_tls_v3_e2e.rs`. It drives the real server
binary and covers:

- **SS (`chacha20-ietf-poly1305`, `client-fingerprint: chrome`) on a TLS
  1.3 cover:** echo round trips, a 256 KiB multi-record transfer,
  concurrent sessions, an idle-before-first-write client, and a relay-chain
  hop (handshake over a relay-supplied stream).
- **SS + `udp-over-tcp` v1 and v2 through the relay into a sing-box 1.14
  SS inbound:** datagram boundaries and integrity from 1 B to 16 KB (one
  datagram spanning several ShadowTLS records), bursts, the reply source
  address, and concurrent associations. Without UoT, UDP is refused.
- **Snell v4 with `obfs-opts.mode: shadow-tls`:** TCP echo with a 200 KiB
  transfer, Snell UDP, and a relay-chain hop.
- **TLS 1.2 cover:** passes with a `fingerprint` pin; an unpinned
  self-signed cover fails closed.
- **Failure cases:** a wrong ShadowTLS password (SS and Snell; the server
  degrades to an SNI proxy and the client refuses it), client
  `strict-mode` and server `--strict`, and connection refused.

`crates/meow-transport/tests/shadow_tls_test.rs` tests the wire mechanics
against an in-process mock relay:
- ClientHello tag, swizzled-record authorization, rolling HMAC framing,
  tampered records, mid-handshake EOF and garbage;
- fragmented reads (1–7 bytes) and partial writes (≤5 bytes) across a full
  handshake;
- cancellation, a stalled relay, and concurrent sessions.

```sh
bash scripts/fetch-shadowtls-server.sh /tmp/meow-stls
SHADOWTLS_SERVER_BIN=/tmp/meow-stls/shadow-tls SINGBOX_BIN=$(command -v sing-box) \
  cargo test -p meow-proxy --test shadow_tls_v3_e2e
```

To test against a **real deployed** server (opt-in, never run by CI), use
`crates/meow-proxy/tests/shadow_tls_external_interop.rs`. With
`MEOW_SHADOWTLS_EXTERNAL=1` set, it sends an HTTP request through SS +
ShadowTLS, and with `MEOW_STLS_UOT=1|2` also a DNS query over
`udp-over-tcp`. The file header lists the variables. It was validated
against an OpenSSL `s_server` TLS 1.3 cover behind a `--strict` official
relay.

## Limitations and differences from mihomo

### Cover handshake

BoringSSL has no hook for choosing the session id, so the client patches
the authenticated session id into the serialized ClientHello. The cover's
transcript then differs from the client's, and the cover handshake can
never complete locally. Authentication still holds, because it rests on
the per-record HMACs, which is the point of the protocol. mihomo uses
uTLS's `SessionIDGenerator` and completes the handshake. Consequences:

- **TLS 1.3 cover (recommended).** The cover's certificate arrives
  encrypted and cannot be verified by the client, so `skip-cert-verify`,
  `fingerprint` and `name-cert-verify` have no effect there; meow logs a
  warning about this. mihomo verifies the cover certificate on this path.
  Here the relay's correctly tagged records are the only authenticator.
  The client never sends an alert to the cover, so an idle client keeps its
  session as long as the cover waits for a handshake to finish (typically
  tens of seconds).
- **TLS 1.2 cover.** Certificate verification runs on the plaintext server
  flight and is enforced, including `fingerprint` pinning. The cover
  rejects the client's Finished, so the client ends the handshake right
  after sending it. The first payload must then reach the relay before the
  cover's rejection does, about one relay↔cover round trip. Client-first
  protocols (HTTP, TLS) meet this naturally. A server-first application that
  waits longer than a round trip before the client speaks can lose the
  session. Prefer TLS 1.3 covers, or use `strict-mode`.

### Other

- **ShadowTLS is supported for `ss` and `snell` only.** The Trojan, VLESS
  and VMess `shadow-tls-opts` are rejected (see above).
- **`client-fingerprint`** profiles are meow's BoringSSL-shaped ClientHellos
  (`chrome`, `firefox`, `safari`, `ios`, `android`, `edge`, `random`), not
  uTLS byte-for-byte copies. An unknown name falls back to the default
  hello. When `alpn` is exactly `[http/1.1]`, mihomo applies uTLS's
  WebSocket handshake shaping; meow does not.
- **Relay chains and `dialer-proxy` both work.** A non-first `relay` hop
  runs the handshake over the relay-supplied stream, and `dialer-proxy` on
  the node dials through the front proxy.
- **Version caveats.** `version: 1` is unauthenticated and kept only for
  parity. `version: 2` strips hybrid post-quantum key shares from the
  ClientHello (upstream parity).
