//! PROXY protocol v2 (receiving side), for the layer-4 deployment: a TCP
//! passthrough on the same host (nginx `stream`, HAProxy `mode tcp`,
//! caddy-l4) forwards raw bytes to the relay, which still terminates TLS
//! itself, and prefixes each connection with a PROXY v2 header naming the
//! client's address. The relay uses that address only for its per-source
//! fair shares.
//!
//! The parser is strict and bounded: the 12-byte signature, version 2,
//! commands LOCAL and PROXY, families TCP over IPv4 / IPv6 (UNSPEC and
//! LOCAL mean "use the peer address"), and an address block of at most
//! [`MAX_ADDRESS_BLOCK`] bytes, TLVs included and skipped. It reads exactly
//! the header's bytes (never anything past it, so the TLS handshake that
//! follows is untouched) into a fixed buffer: nothing the sender writes
//! decides how much is allocated. The whole header must arrive within the
//! caller's timeout.
//!
//! Reference: <https://www.haproxy.org/download/2.9/doc/proxy-protocol.txt>.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt};

/// The v2 signature: `\r\n\r\n\0\r\nQUIT\n`.
pub const SIGNATURE: [u8; 12] = [
    0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
];

/// Fixed part: signature, version/command, family/transport, length.
pub const FIXED_LEN: usize = 16;

/// Largest address block accepted (the size of the AF_UNIX block, the
/// largest the specification defines). TCP4 needs 12 bytes and TCP6 36;
/// the rest of the block is TLVs, which are skipped.
pub const MAX_ADDRESS_BLOCK: usize = 216;

/// How long a front end has to deliver the whole header.
pub const HEADER_TIMEOUT: Duration = Duration::from_secs(5);

const CMD_LOCAL: u8 = 0x0;
const CMD_PROXY: u8 = 0x1;
const FAM_UNSPEC: u8 = 0x00;
const FAM_TCP4: u8 = 0x11;
const FAM_TCP6: u8 = 0x21;
const TCP4_LEN: usize = 12;
const TCP6_LEN: usize = 36;

/// Why a header was refused. Carries no addresses (safe to log).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeaderError {
    /// The first 12 bytes are not the v2 signature.
    BadSignature,
    /// A text (version 1) header: `PROXY TCP4 ...`. Only v2 is accepted.
    Version1,
    /// The signature matched but the version nibble is not 2.
    UnsupportedVersion,
    /// A command other than LOCAL or PROXY.
    UnsupportedCommand,
    /// PROXY over a family other than TCP4, TCP6 or UNSPEC.
    UnsupportedFamily,
    /// The declared address block is longer than [`MAX_ADDRESS_BLOCK`].
    TooLong,
    /// The declared address block is shorter than its family needs.
    TooShort,
    /// The stream ended inside the header.
    Truncated,
    /// The header did not arrive within the timeout.
    TimedOut,
    /// A socket error while reading the header.
    Io,
}

impl fmt::Display for HeaderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::BadSignature => "no PROXY protocol v2 signature",
            Self::Version1 => "PROXY protocol v1 (text) header; only v2 is accepted",
            Self::UnsupportedVersion => "unsupported PROXY protocol version",
            Self::UnsupportedCommand => "unsupported PROXY protocol command",
            Self::UnsupportedFamily => "unsupported PROXY protocol address family",
            Self::TooLong => "PROXY protocol header too long",
            Self::TooShort => "PROXY protocol address block too short for its family",
            Self::Truncated => "connection ended inside the PROXY protocol header",
            Self::TimedOut => "PROXY protocol header not received in time",
            Self::Io => "read error in the PROXY protocol header",
        })
    }
}

impl std::error::Error for HeaderError {}

/// What the fixed part says about the address block that follows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Fixed {
    /// TCP4 / TCP6 with the PROXY command; `None`: use the peer address.
    family: Option<u8>,
    /// Bytes of address block (addresses plus TLVs) that follow.
    len: usize,
}

fn parse_fixed(h: &[u8; FIXED_LEN]) -> Result<Fixed, HeaderError> {
    if h[..12] != SIGNATURE {
        return Err(if h.starts_with(b"PROXY ") {
            HeaderError::Version1
        } else {
            HeaderError::BadSignature
        });
    }
    if h[12] >> 4 != 2 {
        return Err(HeaderError::UnsupportedVersion);
    }
    let len = usize::from(u16::from_be_bytes([h[14], h[15]]));
    if len > MAX_ADDRESS_BLOCK {
        return Err(HeaderError::TooLong);
    }
    let family = match (h[12] & 0x0F, h[13]) {
        // LOCAL: the front end's own connection (a health check); the
        // address block, whatever it holds, is skipped.
        (CMD_LOCAL, _) => None,
        (CMD_PROXY, FAM_UNSPEC) => None,
        (CMD_PROXY, fam @ (FAM_TCP4 | FAM_TCP6)) => Some(fam),
        (CMD_PROXY, _) => return Err(HeaderError::UnsupportedFamily),
        _ => return Err(HeaderError::UnsupportedCommand),
    };
    let needed = match family {
        Some(FAM_TCP4) => TCP4_LEN,
        Some(_) => TCP6_LEN,
        None => 0,
    };
    if len < needed {
        return Err(HeaderError::TooShort);
    }
    Ok(Fixed { family, len })
}

/// The source address in an address block of `family` (lengths already
/// checked by `parse_fixed`).
fn source_of(family: u8, block: &[u8]) -> IpAddr {
    if family == FAM_TCP4 {
        let mut a = [0u8; 4];
        a.copy_from_slice(&block[..4]);
        IpAddr::V4(Ipv4Addr::from(a))
    } else {
        let mut a = [0u8; 16];
        a.copy_from_slice(&block[..16]);
        IpAddr::V6(Ipv6Addr::from(a))
    }
}

async fn read_inner<S: AsyncRead + Unpin>(stream: &mut S) -> Result<Option<IpAddr>, HeaderError> {
    let io = |e: std::io::Error| {
        if e.kind() == std::io::ErrorKind::UnexpectedEof {
            HeaderError::Truncated
        } else {
            HeaderError::Io
        }
    };
    let mut fixed = [0u8; FIXED_LEN];
    stream.read_exact(&mut fixed).await.map_err(io)?;
    let Fixed { family, len } = parse_fixed(&fixed)?;
    let mut block = [0u8; MAX_ADDRESS_BLOCK];
    stream.read_exact(&mut block[..len]).await.map_err(io)?;
    Ok(family.map(|fam| source_of(fam, &block[..len])))
}

/// Read one PROXY v2 header from the start of `stream`, consuming exactly
/// its bytes. `Ok(Some(addr))`: the client's source address (PROXY over
/// TCP4/TCP6). `Ok(None)`: LOCAL or UNSPEC - the caller uses the peer
/// address. Anything else, or no complete header within `timeout`, is an
/// error and the connection must be closed.
pub async fn read_header<S: AsyncRead + Unpin>(
    stream: &mut S,
    timeout: Duration,
) -> Result<Option<IpAddr>, HeaderError> {
    match tokio::time::timeout(timeout, read_inner(stream)).await {
        Ok(result) => result,
        Err(_) => Err(HeaderError::TimedOut),
    }
}

/// Encode a PROXY v2 header (tests and the end-to-end check).
#[cfg(test)]
pub fn encode(source: Option<(std::net::SocketAddr, std::net::SocketAddr)>) -> Vec<u8> {
    let mut out = SIGNATURE.to_vec();
    match source {
        None => out.extend_from_slice(&[0x20, FAM_UNSPEC, 0, 0]),
        Some((src, dst)) => {
            let (fam, mut block) = match (src.ip(), dst.ip()) {
                (IpAddr::V4(s), IpAddr::V4(d)) => (FAM_TCP4, [s.octets(), d.octets()].concat()),
                (s, d) => {
                    let v6 = |ip: IpAddr| match ip {
                        IpAddr::V4(v4) => v4.to_ipv6_mapped().octets(),
                        IpAddr::V6(v6) => v6.octets(),
                    };
                    (FAM_TCP6, [v6(s), v6(d)].concat())
                }
            };
            block.extend_from_slice(&src.port().to_be_bytes());
            block.extend_from_slice(&dst.port().to_be_bytes());
            out.extend_from_slice(&[0x21, fam]);
            out.extend_from_slice(&(block.len() as u16).to_be_bytes());
            out.extend_from_slice(&block);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use tokio::io::AsyncWriteExt;

    const T: Duration = Duration::from_secs(1);

    async fn parse(bytes: &[u8]) -> Result<Option<IpAddr>, HeaderError> {
        let mut cursor = std::io::Cursor::new(bytes.to_vec());
        read_header(&mut cursor, T).await
    }

    fn addr(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[tokio::test]
    async fn a_valid_tcp4_header_gives_the_source_and_consumes_only_the_header() {
        let mut bytes = encode(Some((addr("203.0.113.7:51000"), addr("127.0.0.1:8443"))));
        assert_eq!(bytes.len(), FIXED_LEN + TCP4_LEN);
        bytes.extend_from_slice(b"\x16\x03\x01rest");
        let mut cursor = std::io::Cursor::new(bytes);
        let src = read_header(&mut cursor, T).await.unwrap();
        assert_eq!(src, Some("203.0.113.7".parse().unwrap()));
        let mut rest = Vec::new();
        cursor.read_to_end(&mut rest).await.unwrap();
        assert_eq!(rest, b"\x16\x03\x01rest", "the TLS bytes are left alone");
    }

    #[tokio::test]
    async fn a_valid_tcp6_header_gives_the_source() {
        let bytes = encode(Some((addr("[2001:db8::7]:51000"), addr("[::1]:8443"))));
        assert_eq!(bytes.len(), FIXED_LEN + TCP6_LEN);
        assert_eq!(
            parse(&bytes).await.unwrap(),
            Some("2001:db8::7".parse().unwrap())
        );
    }

    #[tokio::test]
    async fn tlvs_within_the_bound_are_skipped() {
        let mut bytes = encode(Some((addr("198.51.100.4:1"), addr("127.0.0.1:2"))));
        let extra = MAX_ADDRESS_BLOCK - TCP4_LEN;
        bytes[14..16].copy_from_slice(&(MAX_ADDRESS_BLOCK as u16).to_be_bytes());
        bytes.extend(std::iter::repeat(0xAB).take(extra));
        bytes.extend_from_slice(b"after");
        let mut cursor = std::io::Cursor::new(bytes);
        let src = read_header(&mut cursor, T).await.unwrap();
        assert_eq!(src, Some("198.51.100.4".parse().unwrap()));
        let mut rest = Vec::new();
        cursor.read_to_end(&mut rest).await.unwrap();
        assert_eq!(rest, b"after");
    }

    #[tokio::test]
    async fn local_and_unspec_fall_back_to_the_peer() {
        // LOCAL with no address block (a front end's health check).
        let mut local = SIGNATURE.to_vec();
        local.extend_from_slice(&[0x20, 0x00, 0, 0]);
        assert_eq!(parse(&local).await, Ok(None));
        // LOCAL carrying a TCP4 block: the block is ignored.
        let mut local4 = encode(Some((addr("203.0.113.7:1"), addr("127.0.0.1:2"))));
        local4[12] = 0x20;
        assert_eq!(parse(&local4).await, Ok(None));
        // PROXY over UNSPEC.
        let mut unspec = SIGNATURE.to_vec();
        unspec.extend_from_slice(&[0x21, 0x00, 0, 0]);
        assert_eq!(parse(&unspec).await, Ok(None));
    }

    #[tokio::test]
    async fn a_bad_signature_is_refused() {
        let mut bytes = encode(Some((addr("203.0.113.7:1"), addr("127.0.0.1:2"))));
        bytes[3] ^= 0xFF;
        assert_eq!(parse(&bytes).await, Err(HeaderError::BadSignature));
        // A TLS ClientHello straight away (front end not sending PROXY).
        let hello = [
            0x16u8, 0x03, 0x01, 0x02, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        assert_eq!(parse(&hello).await, Err(HeaderError::BadSignature));
    }

    #[tokio::test]
    async fn a_version_1_text_header_is_refused() {
        let v1 = b"PROXY TCP4 203.0.113.7 127.0.0.1 51000 8443\r\n";
        assert_eq!(parse(v1).await, Err(HeaderError::Version1));
    }

    #[tokio::test]
    async fn other_versions_commands_and_families_are_refused() {
        let base = encode(Some((addr("203.0.113.7:1"), addr("127.0.0.1:2"))));
        let with = |i: usize, b: u8| {
            let mut v = base.clone();
            v[i] = b;
            v
        };
        assert_eq!(
            parse(&with(12, 0x11)).await,
            Err(HeaderError::UnsupportedVersion)
        );
        assert_eq!(
            parse(&with(12, 0x22)).await,
            Err(HeaderError::UnsupportedCommand)
        );
        for fam in [0x12, 0x22, 0x31, 0x32, 0x10, 0x41] {
            assert_eq!(
                parse(&with(13, fam)).await,
                Err(HeaderError::UnsupportedFamily),
                "family {fam:#x}"
            );
        }
    }

    #[tokio::test]
    async fn an_over_long_or_too_short_length_is_refused() {
        let mut long = encode(Some((addr("203.0.113.7:1"), addr("127.0.0.1:2"))));
        long[14..16].copy_from_slice(&((MAX_ADDRESS_BLOCK + 1) as u16).to_be_bytes());
        assert_eq!(parse(&long).await, Err(HeaderError::TooLong));
        long[14..16].copy_from_slice(&u16::MAX.to_be_bytes());
        assert_eq!(parse(&long).await, Err(HeaderError::TooLong));

        let mut short6 = encode(Some((addr("[2001:db8::7]:1"), addr("[::1]:2"))));
        short6[14..16].copy_from_slice(&(TCP4_LEN as u16).to_be_bytes());
        assert_eq!(parse(&short6).await, Err(HeaderError::TooShort));
    }

    #[tokio::test]
    async fn a_truncated_header_is_refused() {
        let full = encode(Some((addr("203.0.113.7:1"), addr("127.0.0.1:2"))));
        for cut in [0, 5, FIXED_LEN - 1, FIXED_LEN, full.len() - 1] {
            assert_eq!(
                parse(&full[..cut]).await,
                Err(HeaderError::Truncated),
                "cut at {cut}"
            );
        }
    }

    #[tokio::test]
    async fn a_stalled_header_times_out() {
        let (mut client, mut server) = tokio::io::duplex(64);
        let full = encode(Some((addr("203.0.113.7:1"), addr("127.0.0.1:2"))));
        client.write_all(&full[..10]).await.unwrap();
        let started = std::time::Instant::now();
        let r = read_header(&mut server, Duration::from_millis(200)).await;
        assert_eq!(r, Err(HeaderError::TimedOut));
        assert!(started.elapsed() < Duration::from_secs(2));
        drop(client);
    }
}
