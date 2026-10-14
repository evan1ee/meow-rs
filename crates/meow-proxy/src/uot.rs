//! UDP-over-TCP (sing `common/uot`, mihomo `udp-over-tcp`) — the datagram
//! framing inside a proxy stream opened to a magic destination.  Shared by
//! the Shadowsocks `udp-over-tcp` option (which rides whatever TCP
//! transport the node uses, ShadowTLS included), kcptun's forced legacy
//! relay, and the anytls uot reader.
//!
//! Two versions exist:
//!
//! - **legacy (v1)** — destination `sp.udp-over-tcp.arpa:0`; the stream is
//!   a bare datagram pipe from the first byte.
//! - **v2** — destination `sp.v2.udp-over-tcp.arpa:0`; a one-shot request
//!   header (`isConnect ‖ SOCKS5 addr`) precedes the datagrams.  meow runs
//!   non-connect mode like mihomo, so every datagram carries its own
//!   address in both versions.
//!
//! Per-packet layout (both directions):
//!
//! ```text
//! | ATYP | Address | Port  |
//! | u8   | var     | u16be |
//! ```
//!
//! ATYP is the uot family table (NOT the SOCKS5 one): 0=IPv4, 1=IPv6,
//! 2=len-prefixed domain.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use meow_common::error::{MeowError, Result};
use meow_common::Metadata;
use tokio::io::{AsyncRead, AsyncReadExt};
#[cfg(feature = "ss")]
use {
    async_trait::async_trait,
    meow_common::ProxyPacketConn,
    meow_transport::Stream,
    smol_str::SmolStr,
    tokio::io::{AsyncWriteExt, ReadHalf, WriteHalf},
};

/// Legacy (v1) magic destination.
#[cfg(feature = "ss")]
pub(crate) const UOT_LEGACY_MAGIC_HOST: &str = "sp.udp-over-tcp.arpa";
/// v2 magic destination.
#[cfg(feature = "ss")]
pub(crate) const UOT_V2_MAGIC_HOST: &str = "sp.v2.udp-over-tcp.arpa";
/// Both magic destinations use port 0.
#[cfg(feature = "ss")]
pub(crate) const UOT_MAGIC_PORT: u16 = 0;

/// UDP-over-TCP protocol version (`udp-over-tcp-version`).
#[cfg(feature = "ss")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UotVersion {
    /// v1, `sp.udp-over-tcp.arpa` — mihomo's default (`0` maps here).
    Legacy,
    /// v2, `sp.v2.udp-over-tcp.arpa` — request header first.
    V2,
}

#[cfg(feature = "ss")]
impl UotVersion {
    /// mihomo `udp-over-tcp-version`: `0`/absent → legacy, `1`, `2`;
    /// anything else is an unknown version.
    pub fn from_config(version: u64) -> Option<Self> {
        match version {
            0 | 1 => Some(UotVersion::Legacy),
            2 => Some(UotVersion::V2),
            _ => None,
        }
    }

    /// The magic destination a UoT stream is opened to.
    pub(crate) fn magic_host(self) -> &'static str {
        match self {
            UotVersion::Legacy => UOT_LEGACY_MAGIC_HOST,
            UotVersion::V2 => UOT_V2_MAGIC_HOST,
        }
    }
}

/// SOCKS5 address-family bytes — the v2 **request** header only.  Upstream
/// serializes the request address with `M.SocksaddrSerializer` (SOCKS5
/// 0x01/0x03/0x04) but every per-packet address with `uot.AddrParser`
/// (0x00/0x01/0x02); reusing one table for both is silently wrong.
pub(crate) const SOCKS5_ATYP_IPV4: u8 = 0x01;
pub(crate) const SOCKS5_ATYP_DOMAIN: u8 = 0x03;
pub(crate) const SOCKS5_ATYP_IPV6: u8 = 0x04;

/// Encode the one-shot v2 request: `isConnect = 0` followed by the
/// session's nominal destination in SOCKS5 form. In non-connect mode the
/// server ignores this address (it routes per packet), but upstream still
/// sends it and its serializer rejects an empty address, so mirror mihomo
/// and send the resolved destination — falling back to the hostname when
/// the metadata has no IP yet.
pub(crate) fn encode_uot_request(metadata: &Metadata) -> Vec<u8> {
    let mut buf = Vec::with_capacity(24);
    buf.push(0); // isConnect = false
    match metadata.dst_ip {
        Some(IpAddr::V4(v4)) => {
            buf.push(SOCKS5_ATYP_IPV4);
            buf.extend_from_slice(&v4.octets());
        }
        Some(IpAddr::V6(v6)) => match v6.to_ipv4_mapped() {
            Some(v4) => {
                buf.push(SOCKS5_ATYP_IPV4);
                buf.extend_from_slice(&v4.octets());
            }
            None => {
                buf.push(SOCKS5_ATYP_IPV6);
                buf.extend_from_slice(&v6.octets());
            }
        },
        None => {
            // No resolved IP: send the hostname, truncated to the 255-byte
            // ceiling the length prefix allows. An empty host degrades to
            // 0.0.0.0 rather than an unencodable address.
            let host = metadata.host.as_bytes();
            if host.is_empty() || host.len() > 255 {
                buf.push(SOCKS5_ATYP_IPV4);
                buf.extend_from_slice(&Ipv4Addr::UNSPECIFIED.octets());
            } else {
                buf.push(SOCKS5_ATYP_DOMAIN);
                buf.push(host.len() as u8);
                buf.extend_from_slice(host);
            }
        }
    }
    buf.extend_from_slice(&metadata.dst_port.to_be_bytes());
    buf
}

/// `uot.AddrParser` address-family bytes — every **per-packet** header.
pub(crate) const UOT_ATYP_IPV4: u8 = 0x00;
pub(crate) const UOT_ATYP_IPV6: u8 = 0x01;
pub(crate) const UOT_ATYP_DOMAIN: u8 = 0x02;

/// Append a per-packet uot address header (`uot.AddrParser` bytes).
pub(crate) fn encode_uot_addr(buf: &mut Vec<u8>, addr: &SocketAddr) {
    match addr.ip() {
        IpAddr::V4(v4) => {
            buf.push(UOT_ATYP_IPV4);
            buf.extend_from_slice(&v4.octets());
        }
        // Upstream unmaps before serializing, so a `::ffff:a.b.c.d` peer goes
        // out as plain IPv4 rather than as an IPv6 address the server would
        // then have to unmap itself.
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => {
                buf.push(UOT_ATYP_IPV4);
                buf.extend_from_slice(&v4.octets());
            }
            None => {
                buf.push(UOT_ATYP_IPV6);
                buf.extend_from_slice(&v6.octets());
            }
        },
    }
    buf.extend_from_slice(&addr.port().to_be_bytes());
}

/// Append a per-packet uot domain address header — the form a chained
/// `UdpTarget::Name` stamps so the server resolves the name (issue #657).
/// `host` must be ≤255 bytes (the length prefix is a u8).
///
pub(crate) fn encode_uot_addr_domain(buf: &mut Vec<u8>, host: &str, port: u16) {
    let host_bytes = host.as_bytes();
    debug_assert!(
        host_bytes.len() <= u8::MAX as usize,
        "domain length checked by caller"
    );
    buf.push(UOT_ATYP_DOMAIN);
    buf.push(u8::try_from(host_bytes.len()).expect("domain length checked by caller"));
    buf.extend_from_slice(host_bytes);
    buf.extend_from_slice(&port.to_be_bytes());
}

/// Read a per-packet uot address header.
///
/// Domain-form replies are best-effort, matching `trojan.rs`: an IP literal is
/// parsed, anything else degrades to `0.0.0.0:<port>`. Servers echo the IP
/// form here — the FQDN branch exists because the serializer allows it.
pub(crate) async fn read_uot_addr<R: AsyncRead + Unpin>(reader: &mut R) -> Result<SocketAddr> {
    let mut atyp = [0u8; 1];
    reader.read_exact(&mut atyp).await.map_err(MeowError::Io)?;
    let ip = match atyp[0] {
        UOT_ATYP_IPV4 => {
            let mut octets = [0u8; 4];
            reader
                .read_exact(&mut octets)
                .await
                .map_err(MeowError::Io)?;
            IpAddr::V4(Ipv4Addr::from(octets))
        }
        UOT_ATYP_IPV6 => {
            let mut octets = [0u8; 16];
            reader
                .read_exact(&mut octets)
                .await
                .map_err(MeowError::Io)?;
            IpAddr::V6(Ipv6Addr::from(octets))
        }
        UOT_ATYP_DOMAIN => {
            let mut len = [0u8; 1];
            reader.read_exact(&mut len).await.map_err(MeowError::Io)?;
            let mut domain = vec![0u8; len[0] as usize];
            reader
                .read_exact(&mut domain)
                .await
                .map_err(MeowError::Io)?;
            std::str::from_utf8(&domain)
                .ok()
                .and_then(|d| d.parse::<IpAddr>().ok())
                .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED))
        }
        other => {
            return Err(MeowError::Proxy(format!(
                "uot: unknown address type {other:#x}"
            )));
        }
    };
    let mut port = [0u8; 2];
    reader.read_exact(&mut port).await.map_err(MeowError::Io)?;
    Ok(SocketAddr::new(ip, u16::from_be_bytes(port)))
}

/// A `ProxyPacketConn` speaking UoT framing (either version — the
/// per-packet layout is identical) over one proxy stream.  Datagram layout
/// per packet, both directions:
///
/// ```text
/// | ATYP | Address | Port  | Length | Payload |
/// | u8   | var     | u16be | u16be  | var     |   ← uot.AddrParser bytes
/// ```
///
/// Split halves behind mutexes because `ProxyPacketConn` takes `&self`:
/// a blocked `read_packet` must never hold up `write_packet`.
#[cfg(feature = "ss")]
pub(crate) struct UotPacketConn {
    reader: tokio::sync::Mutex<ReadHalf<Box<dyn Stream>>>,
    writer: tokio::sync::Mutex<WriteHalf<Box<dyn Stream>>>,
    /// Set once any frame op is torn by cancellation — after a partial
    /// read or write the stream's framing is unrecoverable, so every
    /// later packet op must fail fast rather than misdeliver (issue #514).
    poisoned: std::sync::atomic::AtomicBool,
    /// A chained `UdpTarget::Name` binds every datagram's address to the
    /// domain so the server resolves it (issue #657); `None` stamps each
    /// datagram's `SocketAddr`.
    write_target: Option<(SmolStr, u16)>,
}

#[cfg(feature = "ss")]
impl UotPacketConn {
    /// Wrap a stream already opened to the legacy magic destination.
    pub(crate) fn new(stream: Box<dyn Stream>) -> Self {
        let (reader, writer) = tokio::io::split(stream);
        Self {
            reader: tokio::sync::Mutex::new(reader),
            writer: tokio::sync::Mutex::new(writer),
            poisoned: std::sync::atomic::AtomicBool::new(false),
            write_target: None,
        }
    }

    /// Open a UoT packet conn over `stream` (already opened to
    /// `version.magic_host()`): v2 writes its request header before
    /// returning, so a server that rejects it fails the dial rather than
    /// the first datagram.
    pub(crate) async fn open(
        mut stream: Box<dyn Stream>,
        version: UotVersion,
        metadata: &Metadata,
        write_target: Option<(SmolStr, u16)>,
    ) -> Result<Self> {
        if version == UotVersion::V2 {
            stream
                .write_all(&encode_uot_request(metadata))
                .await
                .map_err(|e| MeowError::io_with("uot v2 request", e))?;
            stream
                .flush()
                .await
                .map_err(|e| MeowError::io_with("uot v2 request", e))?;
        }
        let mut conn = Self::new(stream);
        conn.write_target = write_target;
        Ok(conn)
    }
}

#[cfg(feature = "ss")]
#[async_trait]
impl ProxyPacketConn for UotPacketConn {
    async fn read_packet(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr)> {
        crate::check_not_desynced(&self.poisoned)?;
        let mut reader = self.reader.lock().await;
        // Re-check post-lock: a read parked behind a cancelled mid-frame
        // read must not consume the torn remainder.
        crate::check_not_desynced(&self.poisoned)?;
        // Declared after `reader` so the poison store runs while the
        // mutex is still held (locals drop in reverse order).
        let mut guard = crate::PoisonOnIncomplete::new(&self.poisoned);
        let addr = read_uot_addr(&mut *reader).await?;
        let mut lenb = [0u8; 2];
        reader.read_exact(&mut lenb).await.map_err(MeowError::Io)?;
        let len = u16::from_be_bytes(lenb) as usize;
        // Datagram truncation semantics: serve what fits, then drain the
        // rest of the (u16-bounded) frame through a fixed stack scratch so
        // the stream stays aligned without a per-read heap allocation.
        let to_copy = len.min(buf.len());
        reader
            .read_exact(&mut buf[..to_copy])
            .await
            .map_err(MeowError::Io)?;
        let mut remaining = len - to_copy;
        let mut sink = [0u8; 4096];
        while remaining > 0 {
            let chunk = remaining.min(sink.len());
            reader
                .read_exact(&mut sink[..chunk])
                .await
                .map_err(MeowError::Io)?;
            remaining -= chunk;
        }
        guard.complete = true;
        Ok((to_copy, addr))
    }

    async fn write_packet(&self, buf: &[u8], addr: &SocketAddr) -> Result<usize> {
        crate::check_not_desynced(&self.poisoned)?;
        let Ok(len) = u16::try_from(buf.len()) else {
            return Err(MeowError::Proxy(format!(
                "uot: datagram too large ({} > {})",
                buf.len(),
                u16::MAX
            )));
        };
        let mut frame = Vec::with_capacity(buf.len() + 24);
        match &self.write_target {
            Some((host, port)) => encode_uot_addr_domain(&mut frame, host, *port),
            None => encode_uot_addr(&mut frame, addr),
        }
        frame.extend_from_slice(&len.to_be_bytes());
        frame.extend_from_slice(buf);
        let mut writer = self.writer.lock().await;
        crate::check_not_desynced(&self.poisoned)?;
        let mut guard = crate::PoisonOnIncomplete::new(&self.poisoned);
        writer.write_all(&frame).await.map_err(MeowError::Io)?;
        // The whole frame is in the stream's buffers; a cancelled flush
        // cannot tear the framing.
        guard.complete = true;
        writer.flush().await.map_err(MeowError::Io)?;
        Ok(buf.len())
    }

    fn local_addr(&self) -> Result<SocketAddr> {
        // Tunneled — no meaningful local UDP address exists.
        Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0))
    }

    fn close(&self) -> Result<()> {
        // UoT framing has no close handshake — upstream `uot.Conn.Close`
        // likewise just releases the stream.  Dropping the halves closes
        // the underlying proxy stream.
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packet_header_encodes_uot_family_bytes() {
        let mut buf = Vec::new();
        encode_uot_addr(&mut buf, &"1.2.3.4:80".parse().unwrap());
        assert_eq!(buf, vec![UOT_ATYP_IPV4, 1, 2, 3, 4, 0, 80]);

        let mut buf = Vec::new();
        encode_uot_addr(&mut buf, &"[::1]:80".parse().unwrap());
        assert_eq!(buf[0], UOT_ATYP_IPV6);
        assert_eq!(buf.len(), 1 + 16 + 2);

        // v4-mapped peers are unmapped, as upstream does before serializing.
        let mut buf = Vec::new();
        encode_uot_addr(&mut buf, &"[::ffff:1.2.3.4]:80".parse().unwrap());
        assert_eq!(buf, vec![UOT_ATYP_IPV4, 1, 2, 3, 4, 0, 80]);
    }

    #[tokio::test]
    async fn read_uot_addr_round_trips_encode() {
        for addr in ["1.2.3.4:53", "[2001:db8::1]:443"] {
            let addr: SocketAddr = addr.parse().unwrap();
            let mut buf = Vec::new();
            encode_uot_addr(&mut buf, &addr);
            let mut reader: &[u8] = &buf;
            assert_eq!(read_uot_addr(&mut reader).await.unwrap(), addr);
        }
    }

    /// The domain write form (`UdpTarget::Name`, issue #657) round-trips
    /// through the parser's FQDN branch — which degrades a non-literal to
    /// `0.0.0.0:<port>` — and an IP-literal host survives as an address.
    #[tokio::test]
    async fn encode_uot_addr_domain_wire_layout() {
        let mut buf = Vec::new();
        encode_uot_addr_domain(&mut buf, "back.internal", 8388);
        assert_eq!(
            buf[..2],
            [UOT_ATYP_DOMAIN, 13],
            "atyp + one-byte host length"
        );
        assert_eq!(&buf[2..15], b"back.internal");
        assert_eq!(&buf[15..], &8388u16.to_be_bytes());

        // Parser accepts the form (degrades non-literal to unspecified+port).
        let mut reader: &[u8] = &buf;
        assert_eq!(
            read_uot_addr(&mut reader).await.unwrap(),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 8388)
        );

        let mut buf = Vec::new();
        encode_uot_addr_domain(&mut buf, "203.0.113.9", 5300);
        let mut reader: &[u8] = &buf;
        assert_eq!(
            read_uot_addr(&mut reader).await.unwrap(),
            "203.0.113.9:5300".parse().unwrap(),
            "IP-literal domain form round-trips to the literal"
        );
    }

    /// Domain-form replies degrade to `0.0.0.0:<port>` unless the "domain" is
    /// an IP literal — same best-effort rule as `trojan.rs`.
    #[tokio::test]
    async fn read_uot_addr_handles_domain_form() {
        let mut wire = vec![UOT_ATYP_DOMAIN, 11];
        wire.extend_from_slice(b"example.com");
        wire.extend_from_slice(&443u16.to_be_bytes());
        let mut reader: &[u8] = &wire;
        assert_eq!(
            read_uot_addr(&mut reader).await.unwrap(),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 443)
        );

        let mut wire = vec![UOT_ATYP_DOMAIN, 7];
        wire.extend_from_slice(b"1.2.3.4");
        wire.extend_from_slice(&53u16.to_be_bytes());
        let mut reader: &[u8] = &wire;
        assert_eq!(
            read_uot_addr(&mut reader).await.unwrap(),
            "1.2.3.4:53".parse::<SocketAddr>().unwrap()
        );
    }

    #[cfg(feature = "ss")]
    mod packet_conn {
        use super::super::*;
        use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

        fn md(dst: SocketAddr) -> Metadata {
            Metadata {
                network: meow_common::Network::Udp,
                dst_ip: Some(dst.ip()),
                dst_port: dst.port(),
                ..Default::default()
            }
        }

        async fn pair(
            version: UotVersion,
            write_target: Option<(SmolStr, u16)>,
        ) -> (UotPacketConn, DuplexStream) {
            let (client, peer) = tokio::io::duplex(1 << 20);
            let dst: SocketAddr = "1.2.3.4:53".parse().unwrap();
            let conn = UotPacketConn::open(Box::new(client), version, &md(dst), write_target)
                .await
                .unwrap();
            (conn, peer)
        }

        fn frame(addr: &SocketAddr, payload: &[u8]) -> Vec<u8> {
            let mut f = Vec::new();
            encode_uot_addr(&mut f, addr);
            f.extend_from_slice(&(payload.len() as u16).to_be_bytes());
            f.extend_from_slice(payload);
            f
        }

        /// Legacy is a bare datagram pipe; v2 puts its request header
        /// (`isConnect=0 ‖ SOCKS5 addr`) on the wire at open, before any
        /// datagram — sing `uot.Request` byte layout.
        #[tokio::test]
        async fn wire_layout_per_version() {
            let dst: SocketAddr = "1.2.3.4:53".parse().unwrap();
            let (conn, mut peer) = pair(UotVersion::Legacy, None).await;
            conn.write_packet(b"abc", &dst).await.unwrap();
            let want = frame(&dst, b"abc");
            let mut got = vec![0u8; want.len()];
            peer.read_exact(&mut got).await.unwrap();
            assert_eq!(got, want);

            let (conn, mut peer) = pair(UotVersion::V2, None).await;
            let mut req = [0u8; 8];
            peer.read_exact(&mut req).await.unwrap();
            assert_eq!(req, [0, SOCKS5_ATYP_IPV4, 1, 2, 3, 4, 0, 53]);
            conn.write_packet(b"abc", &dst).await.unwrap();
            let mut got = vec![0u8; want.len()];
            peer.read_exact(&mut got).await.unwrap();
            assert_eq!(got, want, "v2 datagrams use the same per-packet frame");
        }

        #[test]
        fn version_from_config() {
            assert_eq!(UotVersion::from_config(0), Some(UotVersion::Legacy));
            assert_eq!(UotVersion::from_config(1), Some(UotVersion::Legacy));
            assert_eq!(UotVersion::from_config(2), Some(UotVersion::V2));
            assert_eq!(UotVersion::from_config(3), None);
            assert_eq!(UotVersion::Legacy.magic_host(), "sp.udp-over-tcp.arpa");
            assert_eq!(UotVersion::V2.magic_host(), "sp.v2.udp-over-tcp.arpa");
        }

        /// A chained domain target stamps every datagram with the name.
        #[tokio::test]
        async fn domain_write_target() {
            let (conn, mut peer) =
                pair(UotVersion::Legacy, Some((SmolStr::from("dns.example"), 53))).await;
            conn.write_packet(b"q", &"9.9.9.9:53".parse().unwrap())
                .await
                .unwrap();
            let mut want = Vec::new();
            encode_uot_addr_domain(&mut want, "dns.example", 53);
            want.extend_from_slice(&1u16.to_be_bytes());
            want.push(b'q');
            let mut got = vec![0u8; want.len()];
            peer.read_exact(&mut got).await.unwrap();
            assert_eq!(got, want);
        }

        /// Boundaries hold when the peer dribbles bytes (partial reads),
        /// and a datagram larger than the caller's buffer is truncated
        /// without desynchronizing the next one.
        #[tokio::test]
        async fn partial_reads_and_truncation_keep_alignment() {
            let (conn, mut peer) = pair(UotVersion::Legacy, None).await;
            let src: SocketAddr = "[2001:db8::1]:443".parse().unwrap();
            let mut wire = frame(&src, &[0xAB; 5000]);
            wire.extend(frame(&src, b"next"));
            let writer = tokio::spawn(async move {
                for b in wire {
                    peer.write_all(&[b]).await.unwrap();
                }
                peer
            });
            let mut small = [0u8; 100];
            let (n, from) = conn.read_packet(&mut small).await.unwrap();
            assert_eq!((n, from), (100, src), "truncated to the caller buffer");
            assert!(small.iter().all(|&b| b == 0xAB));
            let mut buf = [0u8; 64];
            let (n, from) = conn.read_packet(&mut buf).await.unwrap();
            assert_eq!(
                (&buf[..n], from),
                (&b"next"[..], src),
                "stream stayed aligned"
            );
            drop(writer.await.unwrap());
        }

        #[tokio::test]
        async fn oversized_datagram_rejected_before_write() {
            let (conn, mut peer) = pair(UotVersion::Legacy, None).await;
            let err = conn
                .write_packet(&vec![0u8; 65_536], &"1.2.3.4:53".parse().unwrap())
                .await
                .unwrap_err();
            assert!(err.to_string().contains("too large"), "{err}");
            drop(conn);
            let mut rest = Vec::new();
            peer.read_to_end(&mut rest).await.unwrap();
            assert!(rest.is_empty(), "nothing may reach the wire");
        }

        /// A read cancelled mid-frame poisons the conn: later ops fail
        /// fast instead of parsing the torn remainder as a new datagram.
        #[tokio::test]
        async fn cancelled_mid_frame_read_poisons() {
            let (conn, mut peer) = pair(UotVersion::Legacy, None).await;
            let full = frame(&"1.2.3.4:53".parse().unwrap(), b"hello");
            peer.write_all(&full[..full.len() - 2]).await.unwrap();
            let mut buf = [0u8; 64];
            let res = tokio::time::timeout(
                std::time::Duration::from_millis(50),
                conn.read_packet(&mut buf),
            )
            .await;
            assert!(res.is_err(), "read must still be waiting on the tail");
            peer.write_all(&full[full.len() - 2..]).await.unwrap();
            let err = conn.read_packet(&mut buf).await.unwrap_err();
            assert!(err.to_string().contains("desynced"), "{err}");
            let err = conn
                .write_packet(b"x", &"1.2.3.4:53".parse().unwrap())
                .await
                .unwrap_err();
            assert!(err.to_string().contains("desynced"), "{err}");
        }

        /// The server hanging up mid-frame is an error, not a datagram.
        #[tokio::test]
        async fn eof_mid_frame_is_error() {
            let (conn, mut peer) = pair(UotVersion::Legacy, None).await;
            let full = frame(&"1.2.3.4:53".parse().unwrap(), b"hello");
            peer.write_all(&full[..full.len() - 3]).await.unwrap();
            drop(peer);
            let mut buf = [0u8; 64];
            assert!(conn.read_packet(&mut buf).await.is_err());
        }
    }

    #[tokio::test]
    async fn read_uot_addr_rejects_unknown_family() {
        let mut reader: &[u8] = &[0x09, 0, 0, 0, 0, 0, 0];
        let Err(err) = read_uot_addr(&mut reader).await else {
            panic!("unknown address family must error");
        };
        assert!(err.to_string().contains("unknown address type"), "{err}");
    }
}
