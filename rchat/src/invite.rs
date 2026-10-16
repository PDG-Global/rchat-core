//! `rchat-server --print-invite` (protocol v3 §6c, Part J): this relay's
//! invite link and its QR code, drawn in the terminal.
//!
//! The link is made by the core's formatter (`rchat_core::invite`), the one
//! the app parses with. It carries the secret WebSocket path, so it is only
//! ever printed to stdout by this explicit command: never logged.

use crate::config::ServerConfig;
use anyhow::{bail, Result};

/// The one-line sensitivity note (spec §6c), word for word as in the app.
pub const SENSITIVITY: &str =
    "Anyone with this invite can reach your relay. They can't read messages.";

/// What `--print-invite` says when the config names no public host.
pub const NO_HOST: &str = "--print-invite needs this relay's public host name: set `host` under \
     [server.decoy] in the config file (for example host = \"chat.example.com\"), or list the \
     domain under [server.acme] domains";

/// The URL clients dial: `wss://` + [`dialled_host`] + `[server]
/// websocket_path`.
pub fn relay_url(config: &ServerConfig) -> Result<String> {
    let host = dialled_host(config)?;
    if config
        .websocket_path
        .contains(crate::config::WEBSOCKET_PATH_PLACEHOLDER)
    {
        bail!("websocket_path still holds the template placeholder: set it first (see the config template)");
    }
    Ok(format!("wss://{host}{}", config.websocket_path))
}

/// The host clients dial, with `:port` unless it is 443. The host is
/// `[server.decoy] host`, else the first `[server.acme]` domain. The port is
/// `[server] public_port` (or `--public-port`) when set: behind NAT, a
/// FreeBSD `rdr` rule or a jail the relay's own port isn't the public one.
/// Otherwise it is guessed: 443 behind a PROXY-protocol front end, else the
/// port of `bind_addr`.
pub fn dialled_host(config: &ServerConfig) -> Result<String> {
    let Some(host) = config.decoy_host() else {
        bail!(NO_HOST);
    };
    let port = match config.public_port {
        Some(0) => bail!("public_port must be between 1 and 65535"),
        Some(p) => p,
        None if config.proxy_protocol => 443,
        None => config.bind_addr.port(),
    };
    Ok(if port == 443 {
        host
    } else {
        format!("{host}:{port}")
    })
}

/// The invite link for this relay and its pin.
pub fn invite_link(config: &ServerConfig, pin: &str) -> Result<String> {
    let url = relay_url(config)?;
    // The error names the problem, never the URL (it holds the secret path).
    rchat_core::invite::format_invite(&url, pin).map_err(|e| {
        anyhow::anyhow!(
            "cannot make an invite: {e} (check [server.decoy] host and [server] websocket_path)"
        )
    })
}

/// The QR code for `text` at error correction M, as Unicode half blocks
/// (two modules per character cell) with a 4-module quiet zone. With
/// `ansi`, dark modules are drawn black on a white background whatever the
/// terminal's colours; without, light modules are drawn as blocks, for a
/// terminal with a dark background.
pub fn render_qr(text: &str, ansi: bool) -> Result<String> {
    const QUIET: i32 = 4;
    let qr = qrcodegen::QrCode::encode_text(text, qrcodegen::QrCodeEcc::Medium)
        .map_err(|_| anyhow::anyhow!("the invite is too long for a QR code"))?;
    let (lo, hi) = (-QUIET, qr.size() + QUIET);
    let mut out = String::new();
    let mut y = lo;
    while y < hi {
        if ansi {
            out.push_str("\x1b[30;107m");
        }
        for x in lo..hi {
            // Outside the symbol `get_module` is false: the quiet zone.
            let (top, bottom) = (qr.get_module(x, y), qr.get_module(x, y + 1));
            // With ANSI the foreground is black (dark); without, the
            // terminal's light text stands for light modules.
            let (t, b) = if ansi { (top, bottom) } else { (!top, !bottom) };
            out.push(match (t, b) {
                (true, true) => '█',
                (true, false) => '▀',
                (false, true) => '▄',
                (false, false) => ' ',
            });
        }
        if ansi {
            out.push_str("\x1b[0m");
        }
        out.push('\n');
        y += 2;
    }
    Ok(out)
}

/// Everything `--print-invite` prints.
pub fn print_invite_output(config: &ServerConfig, pin: &str, ansi: bool) -> Result<String> {
    let link = invite_link(config, pin)?;
    let qr = render_qr(&link, ansi)?;
    let host = dialled_host(config)?;
    Ok(format!(
        "Invite for the rChat relay at {host}\n\n{link}\n\n{qr}\n{SENSITIVITY}\n\
         In rChat: Connect > Scan relay invite, or Paste invite with the link above.\n"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    const PIN: &str = "rk:1:mc7qpreivliy7wrttxyh4t54i62pac7hc4izg3yy2bgtkkwqdcia";
    const PATH: &str = "/Zk3qA9-dummy-path-for-tests-only";

    fn config(decoy: Option<&str>, acme: &[&str]) -> ServerConfig {
        let mut c = ServerConfig {
            bind_addr: "0.0.0.0:443".parse().unwrap(),
            websocket_path: PATH.into(),
            ..ServerConfig::default()
        };
        c.decoy.host = decoy.map(str::to_string);
        c.acme.domains = acme.iter().map(|d| d.to_string()).collect();
        c
    }

    #[test]
    fn host_from_decoy_then_first_acme_domain() {
        let both = config(Some("Chat.Example.com."), &["acme.example.com"]);
        assert_eq!(
            relay_url(&both).unwrap(),
            format!("wss://chat.example.com{PATH}")
        );
        let acme = config(None, &["first.example.com", "second.example.com"]);
        assert_eq!(
            relay_url(&acme).unwrap(),
            format!("wss://first.example.com{PATH}")
        );
    }

    #[test]
    fn without_a_host_refuses_and_says_to_set_it() {
        let e = relay_url(&config(None, &[])).unwrap_err().to_string();
        assert_eq!(e, NO_HOST);
        assert!(e.contains("[server.decoy]") && e.contains("host"), "{e}");
        assert!(invite_link(&config(None, &[]), PIN).is_err());
        assert!(print_invite_output(&config(None, &[]), PIN, false).is_err());
    }

    #[test]
    fn port_only_when_the_public_port_is_not_443() {
        let mut c = config(Some("chat.example.com"), &[]);
        c.bind_addr = "0.0.0.0:8443".parse().unwrap();
        assert_eq!(
            relay_url(&c).unwrap(),
            format!("wss://chat.example.com:8443{PATH}")
        );
        // Behind a PROXY-protocol front end clients dial the front end's 443.
        c.bind_addr = "127.0.0.1:8443".parse().unwrap();
        c.proxy_protocol = true;
        assert_eq!(
            relay_url(&c).unwrap(),
            format!("wss://chat.example.com{PATH}")
        );
    }

    /// Round 1 I-2: `public_port` (or `--public-port`) wins over the
    /// bind-port guess, e.g. behind FreeBSD rdr, NAT or a jail.
    #[test]
    fn public_port_wins_over_the_bind_port() {
        let mut c = config(Some("chat.example.com"), &[]);
        c.bind_addr = "127.0.1.1:8443".parse().unwrap();
        c.public_port = Some(443);
        assert_eq!(
            relay_url(&c).unwrap(),
            format!("wss://chat.example.com{PATH}")
        );
        assert_eq!(dialled_host(&c).unwrap(), "chat.example.com");
        c.public_port = Some(8443);
        c.bind_addr = "0.0.0.0:443".parse().unwrap();
        c.proxy_protocol = true;
        assert_eq!(
            relay_url(&c).unwrap(),
            format!("wss://chat.example.com:8443{PATH}")
        );
        assert_eq!(dialled_host(&c).unwrap(), "chat.example.com:8443");
        c.public_port = Some(0);
        assert!(relay_url(&c).is_err());
    }

    /// The header names the dialled host and port, never the path.
    #[test]
    fn header_shows_host_and_port_without_the_path() {
        let mut c = config(Some("chat.example.com"), &[]);
        c.public_port = Some(8443);
        let out = print_invite_output(&c, PIN, false).unwrap();
        let first = out.lines().next().unwrap();
        assert_eq!(first, "Invite for the rChat relay at chat.example.com:8443");
        assert!(!first.contains(&PATH[1..]));
    }

    #[test]
    fn refuses_a_placeholder_path_or_bad_host() {
        let mut c = config(Some("chat.example.com"), &[]);
        c.websocket_path = "/CHANGE-ME-to-a-long-random-path".into();
        assert!(relay_url(&c)
            .unwrap_err()
            .to_string()
            .contains("websocket_path"));
        let c = config(Some("not a host"), &[]);
        assert!(invite_link(&c, PIN).is_err());
    }

    /// The relay calls the core's formatter: the same golden link as the
    /// core's own test (cross-crate golden).
    #[test]
    fn link_is_the_cores_golden_format() {
        let mut c = config(Some("relay.example.com"), &[]);
        c.websocket_path = "/Zk3qA9-x_y~z.long-random-path".into();
        assert_eq!(
            invite_link(&c, PIN).unwrap(),
            "rchat://relay?u=wss%3A%2F%2Frelay.example.com%2FZk3qA9-x_y~z.long-random-path\
             &pin=rk:1:mc7qpreivliy7wrttxyh4t54i62pac7hc4izg3yy2bgtkkwqdcia"
        );
        let parsed = rchat_core::invite::parse_invite(&invite_link(&c, PIN).unwrap()).unwrap();
        assert_eq!(
            parsed.url,
            "wss://relay.example.com/Zk3qA9-x_y~z.long-random-path"
        );
        assert_eq!(parsed.pin, PIN);
        assert!(invite_link(&c, "rk:1:short").is_err());
    }

    /// Read the half blocks back into modules: the drawing is the symbol.
    fn modules_from(drawing: &str, ansi: bool) -> Vec<Vec<bool>> {
        let mut rows = Vec::new();
        for line in drawing.lines() {
            let line = line.replace("\x1b[30;107m", "").replace("\x1b[0m", "");
            let (mut top, mut bottom) = (Vec::new(), Vec::new());
            for ch in line.chars() {
                // (top dark, bottom dark)
                let (t, b) = match (ch, ansi) {
                    ('█', true) | (' ', false) => (true, true),
                    ('▀', true) | ('▄', false) => (true, false),
                    ('▄', true) | ('▀', false) => (false, true),
                    (' ', true) | ('█', false) => (false, false),
                    _ => panic!("unexpected {ch:?}"),
                };
                top.push(t);
                bottom.push(b);
            }
            rows.push(top);
            rows.push(bottom);
        }
        rows
    }

    #[test]
    fn qr_drawing_is_the_symbol_at_ecc_m_with_a_quiet_zone() {
        let link = invite_link(&config(Some("chat.example.com"), &[]), PIN).unwrap();
        let qr = qrcodegen::QrCode::encode_text(&link, qrcodegen::QrCodeEcc::Medium).unwrap();
        assert_eq!(qr.error_correction_level(), qrcodegen::QrCodeEcc::Medium);
        let n = qr.size();
        for ansi in [true, false] {
            let drawing = render_qr(&link, ansi).unwrap();
            let m = modules_from(&drawing, ansi);
            let side = (n + 8) as usize;
            assert_eq!(m[0].len(), side);
            assert!(m.len() == side || m.len() == side + 1, "{} rows", m.len());
            for (y, row) in m.iter().enumerate() {
                for (x, &dark) in row.iter().enumerate() {
                    let (qx, qy) = (x as i32 - 4, y as i32 - 4);
                    // get_module is false outside the symbol: the quiet zone.
                    assert_eq!(dark, qr.get_module(qx, qy), "({x},{y}) ansi={ansi}");
                }
            }
        }
    }

    #[test]
    fn output_has_the_link_the_qr_and_the_note() {
        let c = config(Some("chat.example.com"), &[]);
        let out = print_invite_output(&c, PIN, false).unwrap();
        let link = invite_link(&c, PIN).unwrap();
        assert!(out.lines().any(|l| l == link), "{out}");
        assert!(out.contains(&render_qr(&link, false).unwrap()));
        assert!(out.contains(SENSITIVITY));
        assert!(out.contains("chat.example.com"));
        assert_eq!(
            SENSITIVITY,
            "Anyone with this invite can reach your relay. They can't read messages."
        );
    }

    /// The invite is never logged: building and printing it emits no log
    /// line at any level (the path is secret).
    #[test]
    fn printing_an_invite_logs_nothing() {
        use std::sync::{Arc, Mutex};
        #[derive(Clone, Default)]
        struct Buf(Arc<Mutex<Vec<u8>>>);
        impl std::io::Write for Buf {
            fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(b);
                Ok(b.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let buf = Buf::default();
        let sink = buf.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .with_writer(move || sink.clone())
            .finish();
        tracing::subscriber::with_default(subscriber, || {
            tracing::trace!("capture-check");
            let c = config(Some("chat.example.com"), &[]);
            print_invite_output(&c, PIN, true).unwrap();
            let _ = relay_url(&config(None, &[]));
        });
        let logs = String::from_utf8(buf.0.lock().unwrap().clone()).unwrap();
        assert!(logs.contains("capture-check"), "capture not wired up");
        assert!(!logs.contains(&PATH[1..]), "{logs}");
        assert!(!logs.contains("rchat://"), "{logs}");
        assert_eq!(logs.lines().count(), 1, "{logs}");
    }
}
