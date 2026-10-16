//! Relay invites (protocol v3 §6c, Part J): one link that carries a relay's
//! WebSocket URL and its identity pin, shown as a QR code.
//!
//! `rchat://relay?u=<percent-encoded wss URL>&pin=<rk:1:… relay pin>`
//!
//! The one implementation: the relay's `--print-invite` calls
//! [`format_invite`], and the app parses through the FFI
//! (`rchat_parse_relay_invite`). An invite is sensitive but not a key: it
//! names the relay's secret WebSocket path, so it lets the holder reach the
//! relay, never read messages.

/// Longest invite link accepted or made, in bytes.
pub const MAX_INVITE_LEN: usize = 2048;

const SCHEME: &str = "rchat://";
const HOST: &str = "relay";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invite {
    /// The relay's WebSocket URL (`wss://host[:port]/path`).
    pub url: String,
    /// The relay identity pin, canonical (`rk:1:` + 52 lowercase base32).
    pub pin: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum InviteError {
    #[error("invite is longer than 2048 bytes")]
    TooLong,
    #[error("not an rchat://relay link")]
    NotAnInvite,
    #[error("invite is malformed")]
    Malformed,
    #[error("invite repeats a parameter")]
    DuplicateParameter,
    #[error("invite has no relay address")]
    MissingUrl,
    #[error("invite has no relay identity")]
    MissingPin,
    #[error("invite's relay identity is not a valid pin")]
    BadPin,
    #[error("invite's relay address is not a valid wss:// URL")]
    BadUrl,
}

/// Which plain `ws://` addresses a parse accepts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WsPolicy {
    /// `wss://` only: every release path.
    WssOnly,
    /// Also `ws://` to this device (`127.0.0.1`, `::1`, `localhost`): the
    /// app's debug builds only, for a local test relay.
    AllowLoopbackWs,
}

/// The invite link for `url` and `pin`. The URL must be `wss://` and pass
/// the same checks a parse applies; the pin must parse as a relay pin and is
/// written in its canonical (lowercase) form.
pub fn format_invite(url: &str, pin: &str) -> Result<String, InviteError> {
    check_url(url, WsPolicy::WssOnly)?;
    let pin = canonical_pin(pin)?;
    let mut link = String::with_capacity(SCHEME.len() + HOST.len() + url.len() * 3 + 64);
    link.push_str(SCHEME);
    link.push_str(HOST);
    link.push_str("?u=");
    for &b in url.as_bytes() {
        if is_unreserved(b) {
            link.push(b as char);
        } else {
            link.push('%');
            link.push(HEX[usize::from(b >> 4)] as char);
            link.push(HEX[usize::from(b & 0xf)] as char);
        }
    }
    link.push_str("&pin=");
    link.push_str(&pin);
    if link.len() > MAX_INVITE_LEN {
        return Err(InviteError::TooLong);
    }
    Ok(link)
}

/// Parse an invite link. Refuses anything but `rchat://relay?…`, a URL that
/// is not `wss://` (or has userinfo, a query, a fragment, or a host that is
/// not a DNS name or IP address), a missing or malformed pin, a repeated
/// parameter, and a link over [`MAX_INVITE_LEN`] bytes. Unknown parameters
/// are ignored. Surrounding whitespace is ignored.
pub fn parse_invite(link: &str) -> Result<Invite, InviteError> {
    parse_with(link, WsPolicy::WssOnly)
}

/// [`parse_invite`], but also accepts `ws://` to this device. For the app's
/// debug builds only (a local test relay); release builds never call it.
pub fn parse_invite_allowing_loopback_ws(link: &str) -> Result<Invite, InviteError> {
    parse_with(link, WsPolicy::AllowLoopbackWs)
}

const HEX: &[u8; 16] = b"0123456789ABCDEF";

/// RFC 3986 unreserved: the only bytes a formatted invite leaves unencoded.
fn is_unreserved(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~')
}

fn canonical_pin(pin: &str) -> Result<String, InviteError> {
    crate::relay_pin::parse_pin(pin).map_err(|_| InviteError::BadPin)?;
    // `parse_pin` checked the exact `rk:1:` prefix and a canonical body
    // once lowercased.
    Ok(format!(
        "rk:1:{}",
        pin["rk:1:".len()..].to_ascii_lowercase()
    ))
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Strict percent-decoding: every `%` starts two hex digits, the result is
/// UTF-8. `+` stays `+`.
fn percent_decode(s: &str) -> Result<String, InviteError> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            let hi = b.get(i + 1).copied().and_then(hex_val);
            let lo = b.get(i + 2).copied().and_then(hex_val);
            let (Some(hi), Some(lo)) = (hi, lo) else {
                return Err(InviteError::Malformed);
            };
            out.push(hi << 4 | lo);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8(out).map_err(|_| InviteError::Malformed)
}

fn parse_with(link: &str, policy: WsPolicy) -> Result<Invite, InviteError> {
    if link.len() > MAX_INVITE_LEN {
        return Err(InviteError::TooLong);
    }
    let link = link.trim_matches(|c: char| c.is_ascii_whitespace());
    // Printable ASCII only: a link is percent-encoded throughout.
    if !link.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(InviteError::Malformed);
    }
    let scheme = link.get(..SCHEME.len()).ok_or(InviteError::NotAnInvite)?;
    if !scheme.eq_ignore_ascii_case(SCHEME) {
        return Err(InviteError::NotAnInvite);
    }
    let rest = &link[SCHEME.len()..];
    let (host, query) = match rest.split_once('?') {
        Some((h, q)) => (h, Some(q)),
        None => (rest, None),
    };
    if !host.eq_ignore_ascii_case(HOST) {
        return Err(InviteError::NotAnInvite);
    }
    let query = query.ok_or(InviteError::MissingUrl)?;
    if query.contains('#') {
        return Err(InviteError::Malformed);
    }
    let mut seen: Vec<&str> = Vec::new();
    let (mut url, mut pin) = (None, None);
    for pair in query.split('&') {
        let (name, value) = pair.split_once('=').ok_or(InviteError::Malformed)?;
        // Names are taken as written: no `%` escapes, and no known
        // name in another case (`U`, `PIN`), which a looser reader might
        // take for the real one.
        if name.is_empty()
            || name.contains('%')
            || (name != "u" && name.eq_ignore_ascii_case("u"))
            || (name != "pin" && name.eq_ignore_ascii_case("pin"))
        {
            return Err(InviteError::Malformed);
        }
        if seen.contains(&name) {
            return Err(InviteError::DuplicateParameter);
        }
        seen.push(name);
        match name {
            "u" => url = Some(percent_decode(value)?),
            "pin" => pin = Some(percent_decode(value)?),
            // Unknown parameters are ignored (spec §6c), but must still be
            // well formed.
            _ => {
                percent_decode(value)?;
            }
        }
    }
    let url = url.ok_or(InviteError::MissingUrl)?;
    let pin = pin.ok_or(InviteError::MissingPin)?;
    check_url(&url, policy)?;
    let pin = canonical_pin(&pin)?;
    Ok(Invite { url, pin })
}

/// `wss://host[:port][/path]`: no userinfo, query or fragment; the host a
/// DNS name, an IPv4 address or a bracketed IPv6 address; the path RFC 3986
/// path characters with valid percent escapes. `ws://` only to this device,
/// and only under `AllowLoopbackWs`.
fn check_url(url: &str, policy: WsPolicy) -> Result<(), InviteError> {
    let bad = InviteError::BadUrl;
    if url.len() > MAX_INVITE_LEN {
        return Err(InviteError::TooLong);
    }
    let (rest, plain) = if let Some(r) = url.strip_prefix("wss://") {
        (r, false)
    } else if let Some(r) = url.strip_prefix("ws://") {
        (r, true)
    } else {
        return Err(bad);
    };
    let (authority, path) = match rest.find('/') {
        Some(i) => rest.split_at(i),
        None => (rest, ""),
    };
    let (host, port) = split_host_port(authority).ok_or(bad)?;
    if let Some(port) = port {
        if port.is_empty()
            || port.len() > 5
            || port.starts_with('0')
            || !port.bytes().all(|b| b.is_ascii_digit())
            || !matches!(port.parse::<u32>(), Ok(1..=65535))
        {
            return Err(bad);
        }
    }
    let loopback = match host {
        Host::V6(a) => a.is_loopback(),
        Host::V4(a) => a == std::net::Ipv4Addr::LOCALHOST,
        Host::Name(n) => n.eq_ignore_ascii_case("localhost"),
    };
    if plain && !(policy == WsPolicy::AllowLoopbackWs && loopback) {
        return Err(bad);
    }
    check_path(path).ok_or(bad)?;
    // The core's connect parser reads the same address (Task 20e).
    crate::relay_pin::canonical_origin(url).map_err(|_| bad)?;
    Ok(())
}

enum Host<'a> {
    V4(std::net::Ipv4Addr),
    V6(std::net::Ipv6Addr),
    Name(&'a str),
}

fn split_host_port(authority: &str) -> Option<(Host<'_>, Option<&str>)> {
    if let Some(v6) = authority.strip_prefix('[') {
        let (addr, after) = v6.split_once(']')?;
        let addr: std::net::Ipv6Addr = addr.parse().ok()?;
        let port = match after {
            "" => None,
            p => Some(p.strip_prefix(':')?),
        };
        return Some((Host::V6(addr), port));
    }
    let (host, port) = match authority.split_once(':') {
        Some((h, p)) => (h, Some(p)),
        None => (authority, None),
    };
    if !host.is_empty() && host.bytes().all(|b| b.is_ascii_digit() || b == b'.') {
        return Some((Host::V4(host.parse().ok()?), port));
    }
    is_dns_name(host).then_some((Host::Name(host), port))
}

/// LDH labels of 1 to 63 bytes, not starting or ending with '-', at most
/// 253 bytes in all, no trailing dot, and a last label that is not all
/// digits (that would be a malformed IPv4 address).
fn is_dns_name(host: &str) -> bool {
    if host.is_empty() || host.len() > 253 {
        return false;
    }
    let labels_ok = host.split('.').all(|l| {
        !l.is_empty()
            && l.len() <= 63
            && !l.starts_with('-')
            && !l.ends_with('-')
            && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
    });
    let last_ok = host
        .rsplit('.')
        .next()
        .is_some_and(|l| !l.bytes().all(|b| b.is_ascii_digit()));
    labels_ok && last_ok
}

/// Empty, or '/' then RFC 3986 path characters (pchar and '/'), every '%'
/// starting two hex digits.
fn check_path(path: &str) -> Option<()> {
    if path.is_empty() {
        return Some(());
    }
    let b = path.as_bytes();
    if b[0] != b'/' {
        return None;
    }
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'%' => {
                hex_val(*b.get(i + 1)?)?;
                hex_val(*b.get(i + 2)?)?;
                i += 3;
                continue;
            }
            c if is_unreserved(c) => {}
            b'!' | b'$' | b'&' | b'\'' | b'(' | b')' | b'*' | b'+' | b',' | b';' | b'=' | b':'
            | b'@' | b'/' => {}
            _ => return None,
        }
        i += 1;
    }
    Some(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const PIN: &str = "rk:1:mc7qpreivliy7wrttxyh4t54i62pac7hc4izg3yy2bgtkkwqdcia";
    const URL: &str = "wss://relay.example.com/Zk3qA9-x_y~z.long-random-path";

    fn link(u: &str, pin: &str) -> String {
        format!("rchat://relay?u={u}&pin={pin}")
    }

    fn enc(s: &str) -> String {
        s.bytes()
            .map(|b| {
                if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
                    (b as char).to_string()
                } else {
                    format!("%{b:02X}")
                }
            })
            .collect()
    }

    /// The golden link (also pinned by the relay's cross-crate test).
    #[test]
    fn golden_format() {
        assert_eq!(
            format_invite(URL, PIN).unwrap(),
            "rchat://relay?u=wss%3A%2F%2Frelay.example.com%2FZk3qA9-x_y~z.long-random-path\
             &pin=rk:1:mc7qpreivliy7wrttxyh4t54i62pac7hc4izg3yy2bgtkkwqdcia"
        );
    }

    #[test]
    fn round_trip() {
        for url in [
            URL,
            "wss://relay.example.com",
            "wss://relay.example.com:8443/p",
            "wss://203.0.113.7/ws",
            "wss://[2001:db8::1]:443/ws",
            "wss://relay.example.com/a/b%20c/!$&'()*+,;=:@",
        ] {
            let l = format_invite(url, PIN).unwrap();
            assert_eq!(
                parse_invite(&l).unwrap(),
                Invite {
                    url: url.into(),
                    pin: PIN.into()
                },
                "{url}"
            );
        }
    }

    #[test]
    fn path_is_percent_encoded() {
        let l = format_invite("wss://h.example/a&pin=x?#%20+", PIN);
        // '?' and '#' are refused in the URL itself; the rest is encoded.
        assert_eq!(l, Err(InviteError::BadUrl));
        let l = format_invite("wss://h.example/a&pin=x%20+=", PIN).unwrap();
        assert_eq!(
            l,
            format!("rchat://relay?u=wss%3A%2F%2Fh.example%2Fa%26pin%3Dx%2520%2B%3D&pin={PIN}")
        );
        assert_eq!(
            parse_invite(&l).unwrap().url,
            "wss://h.example/a&pin=x%20+="
        );
        // Only unreserved bytes are left as they are.
        let u = &l["rchat://relay?u=".len()..l.find("&pin=").unwrap()];
        assert!(u
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-._~%".contains(&b)));
    }

    #[test]
    fn pin_is_canonical_and_order_free() {
        let upper = PIN.to_uppercase().replacen("RK:", "rk:", 1);
        assert_eq!(parse_invite(&link(&enc(URL), &upper)).unwrap().pin, PIN);
        assert_eq!(
            format_invite(URL, &upper).unwrap(),
            format_invite(URL, PIN).unwrap()
        );
        let swapped = format!("rchat://relay?pin={PIN}&u={}", enc(URL));
        assert_eq!(parse_invite(&swapped).unwrap().url, URL);
        let pin_encoded = link(&enc(URL), &PIN.replace(':', "%3A"));
        assert_eq!(parse_invite(&pin_encoded).unwrap().pin, PIN);
    }

    #[test]
    fn unknown_parameters_and_whitespace_are_ignored() {
        let l = format!("  {}&x=1&note=hi%20there\n", link(&enc(URL), PIN));
        assert_eq!(parse_invite(&l).unwrap().url, URL);
        let l = format!("RChat://Relay?u={}&pin={PIN}", enc(URL));
        assert_eq!(parse_invite(&l).unwrap().url, URL, "scheme and host case");
    }

    #[test]
    fn refuses_other_schemes_and_hosts() {
        let good = link(&enc(URL), PIN);
        for bad in [
            good.replacen("rchat://", "https://", 1),
            good.replacen("rchat://", "rchatx://", 1),
            good.replacen("rchat://", "rchat:", 1),
            good.replacen("rchat://", "", 1),
            good.replacen("relay?", "contact?", 1),
            good.replacen("relay?", "relay/?", 1),
            good.replacen("relay?", "relay:1?", 1),
            good.replacen("relay?", "x@relay?", 1),
            good.replacen("relay?", "relay.example.com?", 1),
            "rchat://relay".to_string(),
        ] {
            assert!(
                matches!(
                    parse_invite(&bad),
                    Err(InviteError::NotAnInvite | InviteError::MissingUrl)
                ),
                "{bad}: {:?}",
                parse_invite(&bad)
            );
        }
        assert_eq!(
            parse_invite(&good.replacen("rchat://", "https://", 1)),
            Err(InviteError::NotAnInvite)
        );
    }

    #[test]
    fn refuses_missing_or_garbled_pin() {
        assert_eq!(
            parse_invite(&format!("rchat://relay?u={}", enc(URL))),
            Err(InviteError::MissingPin)
        );
        assert_eq!(
            parse_invite(&format!("rchat://relay?pin={PIN}")),
            Err(InviteError::MissingUrl)
        );
        for bad in [
            "",
            "rk:1:short",
            "rk:2:mc7qpreivliy7wrttxyh4t54i62pac7hc4izg3yy2bgtkkwqdcia",
            "rk:1:mc7qpreivliy7wrttxyh4t54i62pac7hc4izg3yy2bgtkkwqdcib",
            "rk:1:mc7qpreivliy7wrttxyh4t54i62pac7hc4izg3yy2bgtkkwqdci1",
            "rk:1:mc7qpreivliy7wrttxyh4t54i62pac7hc4izg3yy2bgtkkwqdciaa",
            "mc7qpreivliy7wrttxyh4t54i62pac7hc4izg3yy2bgtkkwqdcia",
        ] {
            assert_eq!(
                parse_invite(&link(&enc(URL), bad)),
                Err(InviteError::BadPin),
                "{bad}"
            );
            assert_eq!(format_invite(URL, bad), Err(InviteError::BadPin), "{bad}");
        }
    }

    #[test]
    fn refuses_non_wss_urls() {
        for bad in [
            "ws://relay.example.com/p",
            "https://relay.example.com/p",
            "http://relay.example.com/p",
            "WSS://relay.example.com/p",
            "wss:relay.example.com/p",
            "wss:///p",
            "ftp://relay.example.com",
            "relay.example.com/p",
        ] {
            assert_eq!(
                parse_invite(&link(&enc(bad), PIN)),
                Err(InviteError::BadUrl),
                "{bad}"
            );
            assert_eq!(format_invite(bad, PIN), Err(InviteError::BadUrl), "{bad}");
        }
    }

    #[test]
    fn refuses_userinfo_fragment_query_and_bad_hosts() {
        for bad in [
            "wss://user@relay.example.com/p",
            "wss://user:pw@relay.example.com/p",
            "wss://relay.example.com/p#frag",
            "wss://relay.example.com/p?x=1",
            "wss://relay.example.com/p\\q",
            "wss://relay.example.com/p q",
            "wss://relay.example.com/p\u{7f}",
            "wss://relay.example.com/caf\u{e9}",
            "wss://relay.example.com/p%zz",
            "wss://relay.example.com/p%2",
            "wss://bücher.example/p",
            "wss://relay_x.example.com/p",
            "wss://-relay.example.com/p",
            "wss://relay-.example.com/p",
            "wss://relay..example.com/p",
            "wss://.relay.example.com/p",
            "wss://relay.example.com./p",
            "wss://999.1.1.1/p",
            "wss://1.2.3/p",
            "wss://[::1/p",
            "wss://[nothex]/p",
            "wss://[::1]x/p",
            "wss://relay.example.com:/p",
            "wss://relay.example.com:0/p",
            "wss://relay.example.com:65536/p",
            "wss://relay.example.com:+443/p",
            "wss://relay.example.com:44a/p",
            "wss://relay.example.com/p\r\n",
        ] {
            assert_eq!(
                parse_invite(&link(&enc(bad), PIN)),
                Err(InviteError::BadUrl),
                "{bad:?}"
            );
            assert_eq!(format_invite(bad, PIN), Err(InviteError::BadUrl), "{bad:?}");
        }
        let long_label = format!("wss://{}.example.com/p", "a".repeat(64));
        assert_eq!(format_invite(&long_label, PIN), Err(InviteError::BadUrl));
        let long_name = format!("wss://{}example.com/p", "abcdefghi.".repeat(25));
        assert_eq!(format_invite(&long_name, PIN), Err(InviteError::BadUrl));
    }

    #[test]
    fn refuses_more_than_2048_bytes() {
        let base = link(&enc(URL), PIN);
        let pad = |n: usize| format!("{base}&x={}", "a".repeat(n));
        let exact = pad(MAX_INVITE_LEN - base.len() - "&x=".len());
        assert_eq!(exact.len(), MAX_INVITE_LEN);
        assert!(parse_invite(&exact).is_ok());
        let over = pad(MAX_INVITE_LEN - base.len() - "&x=".len() + 1);
        assert_eq!(parse_invite(&over), Err(InviteError::TooLong));
        // Whitespace around a link counts too: nothing over the limit is read.
        assert_eq!(
            parse_invite(&format!(" {exact}")),
            Err(InviteError::TooLong)
        );
        let long_url = format!("wss://relay.example.com/{}", "p".repeat(2000));
        assert_eq!(format_invite(&long_url, PIN), Err(InviteError::TooLong));
    }

    #[test]
    fn refuses_duplicate_parameters() {
        let u = enc(URL);
        for bad in [
            format!("rchat://relay?u={u}&pin={PIN}&pin={PIN}"),
            format!("rchat://relay?u={u}&u={u}&pin={PIN}"),
            format!("rchat://relay?u={u}&pin={PIN}&x=1&x=2"),
        ] {
            assert_eq!(
                parse_invite(&bad),
                Err(InviteError::DuplicateParameter),
                "{bad}"
            );
        }
    }

    #[test]
    fn refuses_malformed_queries_and_fragments() {
        let u = enc(URL);
        for bad in [
            format!("rchat://relay?u={u}&pin={PIN}#x"),
            format!("rchat://relay?u={u}&&pin={PIN}"),
            format!("rchat://relay?u={u}&pin={PIN}&"),
            format!("rchat://relay?u={u}&pin"),
            format!("rchat://relay?u={u}&={PIN}"),
            format!("rchat://relay?u={u}%zz&pin={PIN}"),
            format!("rchat://relay?u={u}%E9&pin={PIN}"),
            format!("rchat://relay?u={u}&pin={PIN} x"),
            format!("rchat://relay?u={u}&pin={PIN}\u{0}"),
            format!("rchat://relay?u={u}&x=%&pin={PIN}"),
        ] {
            assert!(parse_invite(&bad).is_err(), "{bad:?}");
        }
        assert_eq!(
            parse_invite(&format!("rchat://relay?u={u}&pin={PIN}#x")),
            Err(InviteError::Malformed)
        );
        assert_eq!(
            parse_invite(&format!("rchat://relay?u={u}%zz&pin={PIN}")),
            Err(InviteError::Malformed)
        );
    }

    /// Round 1 M-4: a port with a leading zero, and a parameter name with a
    /// `%` or that is a known name in another case, are refused.
    #[test]
    fn refuses_leading_zero_ports_and_lookalike_names() {
        for bad in [
            "wss://relay.example.com:0443/p",
            "wss://relay.example.com:00/p",
            "wss://[2001:db8::1]:08443/p",
        ] {
            assert_eq!(format_invite(bad, PIN), Err(InviteError::BadUrl), "{bad}");
            assert_eq!(
                parse_invite(&link(&enc(bad), PIN)),
                Err(InviteError::BadUrl),
                "{bad}"
            );
        }
        let u = enc(URL);
        for bad in [
            format!("rchat://relay?U={u}&pin={PIN}"),
            format!("rchat://relay?u={u}&PIN={PIN}"),
            format!("rchat://relay?u={u}&Pin={PIN}&pin={PIN}"),
            format!("rchat://relay?u={u}&pin={PIN}&%75=x"),
            format!("rchat://relay?%75={u}&pin={PIN}"),
            format!("rchat://relay?u={u}&pin={PIN}&x%20y=1"),
        ] {
            assert_eq!(parse_invite(&bad), Err(InviteError::Malformed), "{bad}");
        }
        assert!(parse_invite(&format!("rchat://relay?u={u}&pin={PIN}&note=1")).is_ok());
    }

    #[test]
    fn loopback_ws_only_through_the_dev_parse() {
        for ok in [
            "ws://127.0.0.1:18443",
            "ws://127.0.0.1:18443/p",
            "ws://[::1]:18443/p",
            "ws://localhost:18443/p",
        ] {
            let l = link(&enc(ok), PIN);
            assert_eq!(parse_invite(&l), Err(InviteError::BadUrl), "{ok}");
            assert_eq!(parse_invite_allowing_loopback_ws(&l).unwrap().url, ok);
            assert_eq!(format_invite(ok, PIN), Err(InviteError::BadUrl), "{ok}");
        }
        for bad in [
            "ws://relay.example.com/p",
            "ws://192.168.1.10:8443/p",
            "ws://localhost.example.com/p",
            "ws://127.0.0.2/p",
            "http://127.0.0.1/p",
        ] {
            assert_eq!(
                parse_invite_allowing_loopback_ws(&link(&enc(bad), PIN)),
                Err(InviteError::BadUrl),
                "{bad}"
            );
        }
        assert!(parse_invite_allowing_loopback_ws(&link(&enc(URL), PIN)).is_ok());
    }

    /// Every URL a parse accepts reads the same through the core's connect
    /// parser (no second reading of an address, Task 20e).
    #[test]
    fn accepted_urls_have_a_canonical_origin() {
        let origin = |u: &str| crate::relay_pin::canonical_origin(u).unwrap();
        assert_eq!(origin(URL), "wss://relay.example.com:443");
        for url in [
            "wss://[2001:db8::1]:443/ws",
            "wss://203.0.113.7/ws",
            "wss://Relay.Example.com:8443",
        ] {
            let inv = parse_invite(&format_invite(url, PIN).unwrap()).unwrap();
            assert!(
                crate::relay_pin::canonical_origin(&inv.url).is_ok(),
                "{url}"
            );
        }
    }
}
