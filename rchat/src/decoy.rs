//! Decoy static website for non-WebSocket HTTP requests.
//!
//! A scanner or censor's probe that sends a plain HTTP request to the
//! server should see an ordinary website. When `[server.decoy] root` is
//! set, real files are served from that directory; otherwise a small
//! generic default page is used. Nothing here mentions the real service.
//!
//! Only requests that are valid WebSocket upgrades to the configured
//! `websocket_path` reach the relay; everything else, including garbage
//! bytes, is answered here. One request per connection (`Connection:
//! close`); keep-alive and Range are known differences from nginx.
//! Request paths are never logged.

use std::path::{Component, Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};

use crate::config::DecoyConfig as DecoySettings;

const DEFAULT_SERVER: &str = "nginx/1.24.0";

/// Runtime decoy configuration (validated; root canonicalised).
#[derive(Debug, Clone)]
pub struct DecoyConfig {
    /// Enable decoy responses.
    pub enabled: bool,
    /// Canonical site root, if configured.
    root: Option<PathBuf>,
    /// Value of the `Server` header.
    server: String,
    /// Exact request path that may upgrade to the relay.
    ws_path: String,
    /// Timeout for writing a whole response.
    write_timeout: Duration,
}

impl Default for DecoyConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            root: None,
            server: DEFAULT_SERVER.to_string(),
            ws_path: "/".to_string(),
            write_timeout: Duration::from_secs(30),
        }
    }
}

impl DecoyConfig {
    /// Validate settings. Fails closed: a configured root that is relative,
    /// missing, or not a directory, or a bad websocket path, is a startup
    /// error.
    pub fn from_settings(s: &DecoySettings, websocket_path: &str) -> anyhow::Result<Self> {
        if !websocket_path.starts_with('/')
            || websocket_path.contains(['?', '#', ' '])
            || websocket_path
                .chars()
                .any(|c| c.is_control() || !c.is_ascii())
        {
            anyhow::bail!("[server] websocket_path must start with '/' and be plain ASCII without '?', '#' or spaces");
        }
        let root = match &s.root {
            None => None,
            Some(p) => {
                if !p.is_absolute() {
                    anyhow::bail!(
                        "[server.decoy] root must be an absolute path: {}",
                        p.display()
                    );
                }
                let canon = std::fs::canonicalize(p).map_err(|e| {
                    anyhow::anyhow!("[server.decoy] root {} unusable: {}", p.display(), e)
                })?;
                if !canon.is_dir() {
                    anyhow::bail!("[server.decoy] root {} is not a directory", p.display());
                }
                Some(canon)
            }
        };
        let server = s.server_header.trim().to_string();
        if server.is_empty() || server.bytes().any(|b| !(0x20..0x7f).contains(&b)) {
            anyhow::bail!("[server.decoy] server_header must be non-empty printable ASCII");
        }
        if s.write_timeout_secs == 0 {
            anyhow::bail!("[server.decoy] write_timeout_secs must be > 0");
        }
        Ok(Self {
            enabled: s.enabled,
            root,
            server,
            ws_path: websocket_path.to_string(),
            write_timeout: Duration::from_secs(s.write_timeout_secs),
        })
    }

    /// True only for a well-formed WebSocket upgrade to exactly the
    /// configured path. Everything else belongs to the decoy.
    pub fn is_relay_upgrade(&self, buf: &[u8]) -> bool {
        match parse_request(buf) {
            Some(r) => r.is_ws_upgrade && strip_query(&r.target) == self.ws_path,
            None => false,
        }
    }
}

/// Whether `buf` could still be the start of an HTTP request head (it
/// begins with an uppercase letter). Anything else, such as a TLS
/// ClientHello on a plain port, is answered immediately with a 400.
pub fn may_be_http_head(buf: &[u8]) -> bool {
    buf.first().is_some_and(|b| b.is_ascii_uppercase())
}

struct Request {
    method: String,
    target: String,
    http11: bool,
    has_host: bool,
    is_ws_upgrade: bool,
    if_none_match: Option<String>,
    if_modified_since: Option<String>,
}

/// Parse a complete request head. `None` means malformed or incomplete.
fn parse_request(buf: &[u8]) -> Option<Request> {
    let end = buf.windows(4).position(|w| w == b"\r\n\r\n")?;
    let text = std::str::from_utf8(&buf[..end]).ok()?;
    let mut lines = text.split("\r\n");
    let mut parts = lines.next()?.split(' ');
    let method = parts.next()?.to_string();
    let target = parts.next()?.to_string();
    let version = parts.next()?;
    if parts.next().is_some()
        || method.is_empty()
        || !method.bytes().all(|b| b.is_ascii_uppercase())
        || target.is_empty()
    {
        return None;
    }
    let http11 = match version {
        "HTTP/1.1" => true,
        "HTTP/1.0" => false,
        _ => return None,
    };
    let mut req = Request {
        method,
        target,
        http11,
        has_host: false,
        is_ws_upgrade: false,
        if_none_match: None,
        if_modified_since: None,
    };
    let (mut upgrade, mut conn_upgrade, mut key) = (false, false, false);
    for line in lines {
        let (k, v) = line.split_once(':')?;
        let v = v.trim();
        let tok = |name: &str| v.split(',').any(|t| t.trim().eq_ignore_ascii_case(name));
        if k.eq_ignore_ascii_case("host") {
            req.has_host = !v.is_empty();
        } else if k.eq_ignore_ascii_case("upgrade") {
            upgrade |= tok("websocket");
        } else if k.eq_ignore_ascii_case("connection") {
            conn_upgrade |= tok("upgrade");
        } else if k.eq_ignore_ascii_case("sec-websocket-key") {
            key = !v.is_empty();
        } else if k.eq_ignore_ascii_case("if-none-match") {
            req.if_none_match = Some(v.to_string());
        } else if k.eq_ignore_ascii_case("if-modified-since") {
            req.if_modified_since = Some(v.to_string());
        }
    }
    req.is_ws_upgrade = req.method == "GET" && http11 && upgrade && conn_upgrade && key;
    Some(req)
}

fn strip_query(target: &str) -> &str {
    target.split(['?', '#']).next().unwrap_or("")
}

/// Response body source.
enum Body {
    None,
    Bytes(Vec<u8>),
    File(tokio::fs::File, u64),
}

struct Response {
    head: Vec<u8>,
    body: Body,
}

/// Answer one HTTP request (the already-peeked bytes) and flush. The whole
/// write is bounded by the configured timeout; files are streamed through a
/// fixed-size buffer.
pub async fn serve_decoy(
    mut stream: impl AsyncWrite + Unpin + Send,
    request: &[u8],
    config: &DecoyConfig,
) -> anyhow::Result<()> {
    let resp = respond(request, config).await;
    let write = async {
        stream.write_all(&resp.head).await?;
        match resp.body {
            Body::None => {}
            Body::Bytes(b) => stream.write_all(&b).await?,
            Body::File(f, len) => {
                let mut r = BufReader::with_capacity(32 * 1024, f).take(len);
                copy_bounded(&mut r, &mut stream).await?;
            }
        }
        stream.flush().await
    };
    match tokio::time::timeout(config.write_timeout, write).await {
        Ok(r) => r?,
        Err(_) => anyhow::bail!("decoy write timed out"),
    }
    tracing::debug!("decoy response served");
    Ok(())
}

/// Handle any connection that is not a valid relay upgrade: the decoy site
/// when enabled, otherwise a plain nginx-style 404 (the relay is never
/// reachable except through the configured path).
pub async fn serve_non_relay(
    stream: impl AsyncWrite + Unpin + Send,
    request: &[u8],
    config: &DecoyConfig,
) -> anyhow::Result<()> {
    if config.enabled {
        return serve_decoy(stream, request, config).await;
    }
    let mut stream = stream;
    let resp = error_response(404, config, false);
    let write = async {
        stream.write_all(&resp.head).await?;
        if let Body::Bytes(b) = resp.body {
            stream.write_all(&b).await?;
        }
        stream.flush().await
    };
    match tokio::time::timeout(config.write_timeout, write).await {
        Ok(r) => r?,
        Err(_) => anyhow::bail!("write timed out"),
    }
    Ok(())
}

async fn copy_bounded<R, W>(r: &mut R, w: &mut W) -> std::io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; 32 * 1024];
    loop {
        let n = r.read(&mut buf).await?;
        if n == 0 {
            return Ok(());
        }
        w.write_all(&buf[..n]).await?;
    }
}

async fn respond(request: &[u8], config: &DecoyConfig) -> Response {
    let Some(req) = parse_request(request) else {
        return error_response(400, config, false);
    };
    let head = req.method == "HEAD";
    if req.http11 && !req.has_host {
        return error_response(400, config, head);
    }
    if req.method != "GET" && !head {
        return error_response(405, config, false);
    }
    let rel = match sanitize_target(&req.target) {
        Ok(r) => r,
        Err(Reject::Bad) => return error_response(400, config, head),
        Err(Reject::Hidden) => return error_response(404, config, head),
    };
    let at_root = rel.as_os_str().is_empty();

    let Some(root) = &config.root else {
        // Built-in default page: only the site root exists.
        if at_root || rel == Path::new("index.html") {
            return full(
                200,
                config,
                "text/html",
                DEFAULT_PAGE.as_bytes().to_vec(),
                head,
            );
        }
        return error_response(404, config, head);
    };

    let mut path = root.join(&rel);
    let is_dir = at_root
        || tokio::fs::metadata(&path)
            .await
            .map(|m| m.is_dir())
            .unwrap_or(false);
    if is_dir {
        if !at_root && !strip_query(&req.target).ends_with('/') {
            return redirect(&rel, config, head);
        }
        path = path.join("index.html");
    }

    // Symlink-escape guard: the canonical file must live under the root.
    let Ok(canon) = tokio::fs::canonicalize(&path).await else {
        // A directory without an index is 403 in nginx.
        return error_response(if is_dir { 403 } else { 404 }, config, head);
    };
    if !canon.starts_with(root) {
        return error_response(404, config, head);
    }
    let Ok(file) = tokio::fs::File::open(&canon).await else {
        return error_response(404, config, head);
    };
    let Ok(meta) = file.metadata().await else {
        return error_response(404, config, head);
    };
    if !meta.is_file() {
        return error_response(404, config, head);
    }
    let mtime = meta.modified().unwrap_or(UNIX_EPOCH);
    let etag = format!(
        "\"{:x}-{:x}\"",
        mtime
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
        meta.len()
    );
    let lm = http_date(mtime);

    let not_modified = match (&req.if_none_match, &req.if_modified_since) {
        (Some(inm), _) => inm == &etag,
        (None, Some(ims)) => ims == &lm,
        _ => false,
    };
    let hdr = Headers {
        ctype: if not_modified {
            None
        } else {
            Some(content_type(&canon))
        },
        len: if not_modified { None } else { Some(meta.len()) },
        last_modified: Some(&lm),
        etag: Some(&etag),
        location: None,
    };
    if not_modified {
        return Response {
            head: build_head(304, config, &hdr),
            body: Body::None,
        };
    }
    Response {
        head: build_head(200, config, &hdr),
        body: if head {
            Body::None
        } else {
            Body::File(file, meta.len())
        },
    }
}

/// Why a request target was refused.
#[derive(Debug, PartialEq, Eq)]
pub enum Reject {
    /// Malformed or hostile (traversal, bad escape, NUL, backslash): 400.
    Bad,
    /// Dotfile: looks like a plain miss (404).
    Hidden,
}

/// Map a request target to a safe relative path. Each segment is
/// percent-decoded exactly once; the target is rejected for `..`, NUL and
/// control characters, backslash, an encoded `/` (`%2f`), or a malformed
/// escape. Dotfiles are refused too. A leading `/` is required (no
/// absolute-form, no authority-form).
pub fn sanitize_target(target: &str) -> Result<PathBuf, Reject> {
    let path = strip_query(target);
    if !path.starts_with('/') {
        return Err(Reject::Bad);
    }
    let mut rel = PathBuf::new();
    let mut hidden = false;
    for raw in path.split('/') {
        if raw.is_empty() {
            continue;
        }
        let decoded = percent_decode(raw.as_bytes()).ok_or(Reject::Bad)?;
        let seg = String::from_utf8(decoded).map_err(|_| Reject::Bad)?;
        if seg == ".." || seg.contains(['/', '\\']) || seg.chars().any(|c| c.is_control()) {
            return Err(Reject::Bad);
        }
        if seg.starts_with('.') {
            hidden = true;
            continue;
        }
        rel.push(seg);
    }
    if hidden {
        return Err(Reject::Hidden);
    }
    // Defence in depth: only plain components may remain.
    if rel.components().all(|c| matches!(c, Component::Normal(_))) {
        Ok(rel)
    } else {
        Err(Reject::Bad)
    }
}

fn percent_decode(input: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        if input[i] == b'%' {
            let hi = (*input.get(i + 1)? as char).to_digit(16)?;
            let lo = (*input.get(i + 2)? as char).to_digit(16)?;
            out.push((hi * 16 + lo) as u8);
            i += 3;
        } else {
            out.push(input[i]);
            i += 1;
        }
    }
    Some(out)
}

fn percent_encode(seg: &str) -> String {
    let mut o = String::new();
    for b in seg.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
            o.push(b as char);
        } else {
            o.push_str(&format!("%{b:02X}"));
        }
    }
    o
}

/// Content-Type by extension (no charset, like a default nginx).
pub fn content_type(path: &Path) -> &'static str {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .map(|s| s.to_ascii_lowercase());
    match ext.as_deref() {
        Some("html") | Some("htm") => "text/html",
        Some("css") => "text/css",
        Some("js") | Some("mjs") => "application/javascript",
        Some("json") => "application/json",
        Some("txt") => "text/plain",
        Some("xml") => "application/xml",
        Some("png") => "image/png",
        Some("jpg") | Some("jpeg") => "image/jpeg",
        Some("gif") => "image/gif",
        Some("svg") => "image/svg+xml",
        Some("ico") => "image/x-icon",
        Some("webp") => "image/webp",
        Some("woff") => "font/woff",
        Some("woff2") => "font/woff2",
        Some("ttf") => "font/ttf",
        Some("otf") => "font/otf",
        Some("pdf") => "application/pdf",
        Some("wasm") => "application/wasm",
        Some("mp3") => "audio/mpeg",
        Some("mp4") => "video/mp4",
        Some("webm") => "video/webm",
        _ => "application/octet-stream",
    }
}

/// RFC 7231 date. Never panics: a time chrono cannot represent (a decoy
/// file with an extreme mtime) is shown as the Unix epoch instead of going
/// through chrono's panicking `From<SystemTime>` (R-6).
fn http_date(t: SystemTime) -> String {
    let secs = match t.duration_since(UNIX_EPOCH) {
        Ok(d) => i64::try_from(d.as_secs()).ok(),
        Err(e) => i64::try_from(e.duration().as_secs()).ok().map(|s| -s),
    };
    let dt = secs
        .and_then(|s| chrono::DateTime::<chrono::Utc>::from_timestamp(s, 0))
        .unwrap_or(chrono::DateTime::UNIX_EPOCH);
    dt.format("%a, %d %b %Y %H:%M:%S GMT").to_string()
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        301 => "Moved Permanently",
        304 => "Not Modified",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Not Allowed",
        _ => "Error",
    }
}

fn error_page(status: u16, config: &DecoyConfig) -> Vec<u8> {
    let r = reason(status);
    format!(
        "<html>\r\n<head><title>{status} {r}</title></head>\r\n<body>\r\n<center><h1>{status} {r}</h1></center>\r\n<hr><center>{}</center>\r\n</body>\r\n</html>\r\n",
        config.server
    )
    .into_bytes()
}

fn error_response(status: u16, config: &DecoyConfig, head: bool) -> Response {
    full(
        status,
        config,
        "text/html",
        error_page(status, config),
        head,
    )
}

fn redirect(rel: &Path, config: &DecoyConfig, head: bool) -> Response {
    // Built only from the sanitised path: never from the raw target.
    let mut loc = String::from("/");
    for c in rel.components() {
        if let Component::Normal(s) = c {
            loc.push_str(&percent_encode(&s.to_string_lossy()));
            loc.push('/');
        }
    }
    let body = error_page(301, config);
    let hdr = Headers {
        ctype: Some("text/html"),
        len: Some(body.len() as u64),
        last_modified: None,
        etag: None,
        location: Some(&loc),
    };
    Response {
        head: build_head(301, config, &hdr),
        body: if head { Body::None } else { Body::Bytes(body) },
    }
}

fn full(status: u16, config: &DecoyConfig, ctype: &str, body: Vec<u8>, head: bool) -> Response {
    let hdr = Headers {
        ctype: Some(ctype),
        len: Some(body.len() as u64),
        last_modified: None,
        etag: None,
        location: None,
    };
    Response {
        head: build_head(status, config, &hdr),
        body: if head { Body::None } else { Body::Bytes(body) },
    }
}

struct Headers<'a> {
    ctype: Option<&'a str>,
    len: Option<u64>,
    last_modified: Option<&'a str>,
    etag: Option<&'a str>,
    location: Option<&'a str>,
}

/// Serialise the status line and headers in nginx's order: Server, Date,
/// Content-Type, Content-Length, Location, Last-Modified, Connection, ETag.
fn build_head(status: u16, config: &DecoyConfig, h: &Headers) -> Vec<u8> {
    let mut o = format!(
        "HTTP/1.1 {} {}\r\nServer: {}\r\nDate: {}\r\n",
        status,
        reason(status),
        config.server,
        http_date(SystemTime::now())
    );
    if let Some(ct) = h.ctype {
        o.push_str(&format!("Content-Type: {ct}\r\n"));
    }
    if let Some(l) = h.len {
        o.push_str(&format!("Content-Length: {l}\r\n"));
    }
    if let Some(l) = h.location {
        o.push_str(&format!("Location: {l}\r\n"));
    }
    if let Some(l) = h.last_modified {
        o.push_str(&format!("Last-Modified: {l}\r\n"));
    }
    o.push_str("Connection: close\r\n");
    if let Some(e) = h.etag {
        o.push_str(&format!("ETag: {e}\r\n"));
    }
    o.push_str("\r\n");
    o.into_bytes()
}

const DEFAULT_PAGE: &str = "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n<title>Welcome</title>\n<style>body{font-family:sans-serif;max-width:40em;margin:4em auto;color:#333}</style>\n</head>\n<body>\n<h1>Welcome</h1>\n<p>This site is currently being set up. Please check back soon.</p>\n</body>\n</html>\n";

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    static N: AtomicU32 = AtomicU32::new(0);

    #[test]
    fn http_date_of_an_unrepresentable_mtime_does_not_panic() {
        // Far beyond chrono's ±262,143-year range (R-6).
        let far = UNIX_EPOCH + Duration::from_secs(1 << 60);
        assert_eq!(http_date(far), "Thu, 01 Jan 1970 00:00:00 GMT");
        if let Some(before) = UNIX_EPOCH.checked_sub(Duration::from_secs(1 << 60)) {
            assert_eq!(http_date(before), "Thu, 01 Jan 1970 00:00:00 GMT");
        }
        assert_eq!(
            http_date(UNIX_EPOCH + Duration::from_secs(784_111_777)),
            "Sun, 06 Nov 1994 08:49:37 GMT"
        );
    }

    struct Tmp(PathBuf);
    impl Tmp {
        fn new() -> Self {
            let p = std::env::temp_dir().join(format!(
                "decoy-test-{}-{}",
                std::process::id(),
                N.fetch_add(1, Ordering::SeqCst)
            ));
            std::fs::create_dir_all(&p).unwrap();
            Tmp(std::fs::canonicalize(p).unwrap())
        }
    }
    impl Drop for Tmp {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn cfg(root: Option<&Path>) -> DecoyConfig {
        DecoyConfig {
            root: root.map(|p| p.to_path_buf()),
            ..DecoyConfig::default()
        }
    }

    async fn raw(c: &DecoyConfig, req: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        serve_decoy(&mut out, req, c).await.unwrap();
        out
    }

    async fn send(c: &DecoyConfig, req: &str) -> String {
        String::from_utf8_lossy(&raw(c, req.as_bytes()).await).into_owned()
    }

    async fn get(c: &DecoyConfig, method: &str, target: &str) -> String {
        send(c, &format!("{method} {target} HTTP/1.1\r\nHost: x\r\n\r\n")).await
    }

    #[test]
    fn rejects_traversal_and_encodings() {
        for t in [
            "/../etc/passwd",
            "/a/../../etc/passwd",
            "/%2e%2e/etc/passwd",
            "/%2E%2E/etc/passwd",
            "/a/%2e%2e/%2e%2e/x",
            "/..%2fetc/passwd",
            "/a%2fb",
            "/a%2Fb",
            "/%5c..%5cx",
            "/a\\b",
            "/a%00b",
            "/a\0b",
            "/%",
            "/%zz",
            "etc/passwd",
            "http://h/x",
        ] {
            assert_eq!(sanitize_target(t), Err(Reject::Bad), "should reject {t:?}");
        }
        for t in ["/.git/config", "/.env", "/a/.hidden"] {
            assert_eq!(sanitize_target(t), Err(Reject::Hidden), "{t:?}");
        }
    }

    #[test]
    fn accepts_normal_paths() {
        assert_eq!(sanitize_target("/").unwrap(), PathBuf::new());
        assert_eq!(
            sanitize_target("/a/b.css?v=1").unwrap(),
            PathBuf::from("a/b.css")
        );
        assert_eq!(
            sanitize_target("//etc/passwd").unwrap(),
            PathBuf::from("etc/passwd")
        );
        assert_eq!(sanitize_target("/a%20b").unwrap(), PathBuf::from("a b"));
        // double-encoded stays literal
        assert_eq!(
            sanitize_target("/%252e%252e").unwrap(),
            PathBuf::from("%2e%2e")
        );
    }

    #[tokio::test]
    async fn serves_files_and_index() {
        let t = Tmp::new();
        std::fs::write(t.0.join("index.html"), "<h1>hi</h1>").unwrap();
        std::fs::write(t.0.join("a.css"), "x{}").unwrap();
        std::fs::create_dir(t.0.join("sub")).unwrap();
        std::fs::write(t.0.join("sub/index.html"), "sub").unwrap();
        let c = cfg(Some(&t.0));
        let r = get(&c, "GET", "/").await;
        assert!(r.starts_with("HTTP/1.1 200 OK\r\n") && r.ends_with("<h1>hi</h1>"));
        assert!(r.contains("Content-Length: 11\r\n") && r.contains("Server: nginx/1.24.0\r\n"));
        assert!(r.contains("Content-Type: text/html\r\n"));
        assert!(r.contains("Date: ") && r.contains("Last-Modified: ") && r.contains("ETag: \""));
        assert!(!r.to_lowercase().contains("\r\nx-"));
        assert!(get(&c, "GET", "/a.css")
            .await
            .contains("Content-Type: text/css\r\n"));
        assert!(get(&c, "GET", "/sub/").await.ends_with("sub"));
        let r = get(&c, "GET", "/sub").await;
        assert!(r.starts_with("HTTP/1.1 301") && r.contains("Location: /sub/\r\n"));
    }

    #[tokio::test]
    async fn redirect_never_uses_raw_target() {
        let t = Tmp::new();
        std::fs::create_dir(t.0.join("foo")).unwrap();
        let c = cfg(Some(&t.0));
        // //foo must not become the protocol-relative Location //foo/
        let r = get(&c, "GET", "//foo").await;
        assert!(r.starts_with("HTTP/1.1 301"), "{r}");
        assert!(r.contains("Location: /foo/\r\n"), "{r}");
        assert!(!r.contains("Location: //"));
    }

    #[tokio::test]
    async fn header_order_is_nginx_like() {
        let t = Tmp::new();
        std::fs::write(t.0.join("index.html"), "x").unwrap();
        let c = cfg(Some(&t.0));
        let r = get(&c, "GET", "/").await;
        let names: Vec<&str> = r
            .split("\r\n\r\n")
            .next()
            .unwrap()
            .split("\r\n")
            .skip(1)
            .map(|l| l.split(':').next().unwrap())
            .collect();
        assert_eq!(
            names,
            [
                "Server",
                "Date",
                "Content-Type",
                "Content-Length",
                "Last-Modified",
                "Connection",
                "ETag"
            ]
        );
    }

    #[tokio::test]
    async fn traversal_requests_get_400() {
        let t = Tmp::new();
        let root = t.0.join("root");
        std::fs::create_dir(&root).unwrap();
        std::fs::write(t.0.join("secret.txt"), "secret").unwrap();
        let c = cfg(Some(&root));
        for p in [
            "/../secret.txt",
            "/%2e%2e/secret.txt",
            "/..%2fsecret.txt",
            "/a%00",
            "/../",
        ] {
            let r = get(&c, "GET", p).await;
            assert!(r.starts_with("HTTP/1.1 400"), "{p}: {r}");
            assert!(!r.contains("secret."));
        }
        assert!(get(&c, "GET", "/.env").await.starts_with("HTTP/1.1 404"));
    }

    #[tokio::test]
    async fn directory_without_index_is_403() {
        let t = Tmp::new();
        std::fs::create_dir(t.0.join("empty")).unwrap();
        let c = cfg(Some(&t.0));
        assert!(get(&c, "GET", "/empty/")
            .await
            .starts_with("HTTP/1.1 403 Forbidden"));
        assert!(get(&c, "GET", "/")
            .await
            .starts_with("HTTP/1.1 403 Forbidden"));
        assert!(get(&c, "GET", "/missing").await.starts_with("HTTP/1.1 404"));
    }

    #[tokio::test]
    async fn http11_requires_host() {
        let t = Tmp::new();
        let c = cfg(Some(&t.0));
        assert!(send(&c, "GET / HTTP/1.1\r\n\r\n")
            .await
            .starts_with("HTTP/1.1 400"));
        // HTTP/1.0 does not need one
        let c = cfg(None);
        assert!(send(&c, "GET / HTTP/1.0\r\n\r\n")
            .await
            .starts_with("HTTP/1.1 200"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn symlink_escape_blocked_inside_allowed() {
        let t = Tmp::new();
        let root = t.0.join("root");
        std::fs::create_dir(&root).unwrap();
        std::fs::write(t.0.join("secret.txt"), "secret").unwrap();
        std::fs::write(root.join("ok.txt"), "fine").unwrap();
        std::os::unix::fs::symlink(t.0.join("secret.txt"), root.join("leak.txt")).unwrap();
        std::os::unix::fs::symlink(&t.0, root.join("dirleak")).unwrap();
        std::os::unix::fs::symlink(root.join("ok.txt"), root.join("alias.txt")).unwrap();
        let c = cfg(Some(&root));
        assert!(get(&c, "GET", "/leak.txt")
            .await
            .starts_with("HTTP/1.1 404"));
        assert!(get(&c, "GET", "/dirleak/secret.txt")
            .await
            .starts_with("HTTP/1.1 404"));
        assert!(get(&c, "GET", "/alias.txt").await.ends_with("fine"));
    }

    #[test]
    fn content_types() {
        for (f, ct) in [
            ("a.html", "text/html"),
            ("a.HTM", "text/html"),
            ("a.css", "text/css"),
            ("a.js", "application/javascript"),
            ("a.json", "application/json"),
            ("a.png", "image/png"),
            ("a.jpeg", "image/jpeg"),
            ("a.svg", "image/svg+xml"),
            ("a.woff2", "font/woff2"),
            ("a.ico", "image/x-icon"),
            ("a.unknown", "application/octet-stream"),
            ("noext", "application/octet-stream"),
        ] {
            assert_eq!(content_type(Path::new(f)), ct, "{f}");
        }
    }

    #[tokio::test]
    async fn not_found_and_method_not_allowed() {
        let t = Tmp::new();
        let c = cfg(Some(&t.0));
        let r = get(&c, "GET", "/nope").await;
        assert!(
            r.starts_with("HTTP/1.1 404 Not Found\r\n")
                && r.contains("<center>nginx/1.24.0</center>")
        );
        assert!(r.contains("Content-Type: text/html\r\n"));
        for m in ["POST", "PUT", "DELETE", "OPTIONS", "PATCH"] {
            let r = get(&c, m, "/").await;
            assert!(r.starts_with("HTTP/1.1 405 Not Allowed\r\n"), "{m}");
            assert!(!r.contains("Allow:") && r.contains("Server: nginx/1.24.0"));
        }
    }

    #[tokio::test]
    async fn garbage_gets_400() {
        let c = cfg(None);
        for req in [
            &b"garbage\r\n\r\n"[..],
            b"get / HTTP/1.1\r\nHost: x\r\n\r\n",
            b"GET / HTTP/9.9\r\nHost: x\r\n\r\n",
            b"\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03",
            b"",
            b"GET /",
        ] {
            let r = String::from_utf8_lossy(&raw(&c, req).await).into_owned();
            assert!(
                r.starts_with("HTTP/1.1 400 Bad Request\r\n"),
                "{req:?}: {r}"
            );
            assert!(r.contains("Server: nginx/1.24.0"));
        }
        assert!(!may_be_http_head(b"\x16\x03\x01"));
        assert!(!may_be_http_head(b"get /"));
        assert!(may_be_http_head(b"GE"));
    }

    #[tokio::test]
    async fn head_has_headers_no_body() {
        let t = Tmp::new();
        std::fs::write(t.0.join("index.html"), "0123456789").unwrap();
        let c = cfg(Some(&t.0));
        let r = get(&c, "HEAD", "/").await;
        assert!(r.starts_with("HTTP/1.1 200 OK\r\n") && r.contains("Content-Length: 10\r\n"));
        assert!(r.ends_with("\r\n\r\n"));
        let r = get(&c, "HEAD", "/missing").await;
        assert!(r.starts_with("HTTP/1.1 404") && r.ends_with("\r\n\r\n"));
    }

    #[tokio::test]
    async fn streams_large_file() {
        let t = Tmp::new();
        let size = 20 * 1024 * 1024usize; // above the old 16 MiB in-memory cap
        let data: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
        std::fs::write(t.0.join("big.bin"), &data).unwrap();
        let c = cfg(Some(&t.0));
        let out = raw(&c, b"GET /big.bin HTTP/1.1\r\nHost: x\r\n\r\n").await;
        let split = out.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
        assert!(
            String::from_utf8_lossy(&out[..split]).contains(&format!("Content-Length: {size}\r\n"))
        );
        assert_eq!(out.len() - split, size);
        assert_eq!(&out[split..], &data[..]);
    }

    #[tokio::test]
    async fn conditional_get() {
        let t = Tmp::new();
        std::fs::write(t.0.join("index.html"), "x").unwrap();
        let c = cfg(Some(&t.0));
        let r = get(&c, "GET", "/").await;
        let etag = r.lines().find(|l| l.starts_with("ETag: ")).unwrap()[6..].to_string();
        let r = send(
            &c,
            &format!("GET / HTTP/1.1\r\nHost: x\r\nIf-None-Match: {etag}\r\n\r\n"),
        )
        .await;
        assert!(r.starts_with("HTTP/1.1 304") && r.ends_with("\r\n\r\n"));
    }

    #[tokio::test]
    async fn default_page_is_generic() {
        let c = cfg(None);
        let r = get(&c, "GET", "/").await;
        assert!(r.starts_with("HTTP/1.1 200 OK"));
        let lower = r.to_lowercase();
        for w in ["rchat", "relay", "chat", "messag"] {
            assert!(!lower.contains(w), "default page leaks {w}");
        }
        assert!(get(&c, "GET", "/other").await.starts_with("HTTP/1.1 404"));
        assert!(get(&c, "GET", "/index.html")
            .await
            .starts_with("HTTP/1.1 200"));
    }

    fn upgrade(path: &str) -> Vec<u8> {
        format!(
            "GET {path} HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: keep-alive, Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"
        )
        .into_bytes()
    }

    #[tokio::test]
    async fn websocket_path_routing() {
        let s = DecoySettings {
            write_timeout_secs: 5,
            ..DecoySettings::default()
        };
        let c = DecoyConfig::from_settings(&s, "/s3cr3t-path").unwrap();
        // exact match (query allowed) goes to the relay
        assert!(c.is_relay_upgrade(&upgrade("/s3cr3t-path")));
        assert!(c.is_relay_upgrade(&upgrade("/s3cr3t-path?x=1")));
        // upgrades elsewhere are decoy traffic
        for p in [
            "/",
            "/ws",
            "/s3cr3t-path/",
            "/S3CR3T-PATH",
            "/s3cr3t-path%2f",
        ] {
            assert!(!c.is_relay_upgrade(&upgrade(p)), "{p}");
        }
        let r = String::from_utf8_lossy(&raw(&c, &upgrade("/ws")).await).into_owned();
        assert!(r.starts_with("HTTP/1.1 404") && !r.contains("101"), "{r}");
        // plain GET to the secret path is not an upgrade -> decoy
        assert!(!c.is_relay_upgrade(b"GET /s3cr3t-path HTTP/1.1\r\nHost: x\r\n\r\n"));
        // incomplete upgrade headers -> decoy
        let no_key = b"GET /s3cr3t-path HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n";
        assert!(!c.is_relay_upgrade(no_key));
        let no_conn = b"GET /s3cr3t-path HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nSec-WebSocket-Key: a\r\n\r\n";
        assert!(!c.is_relay_upgrade(no_conn));
        // substring tricks do not count as an upgrade
        let tricky = b"GET /s3cr3t-path?upgrade:%20websocket HTTP/1.1\r\nHost: x\r\nX-A: upgrade: websocket sec-websocket-key\r\n\r\n";
        assert!(!c.is_relay_upgrade(tricky));
    }

    #[tokio::test]
    async fn disabled_decoy_still_enforces_path() {
        let s = DecoySettings {
            enabled: false,
            ..DecoySettings::default()
        };
        let c = DecoyConfig::from_settings(&s, "/s3cr3t-path").unwrap();
        assert!(c.is_relay_upgrade(&upgrade("/s3cr3t-path")));
        for req in [upgrade("/"), upgrade("/ws"), b"garbage".to_vec()] {
            assert!(!c.is_relay_upgrade(&req));
            let mut out = Vec::new();
            serve_non_relay(&mut out, &req, &c).await.unwrap();
            let r = String::from_utf8_lossy(&out).into_owned();
            assert!(r.starts_with("HTTP/1.1 404 Not Found\r\n"), "{r}");
            assert!(r.contains("<center>nginx/1.24.0</center>") && !r.contains("101"));
        }
    }

    #[test]
    fn default_websocket_path_is_root() {
        let c = DecoyConfig::from_settings(&DecoySettings::default(), "/").unwrap();
        assert!(c.is_relay_upgrade(&upgrade("/")));
        assert!(!c.is_relay_upgrade(&upgrade("/x")));
    }

    #[test]
    fn settings_validation() {
        let mut s = DecoySettings::default();
        assert!(DecoyConfig::from_settings(&s, "/").is_ok());
        assert!(DecoyConfig::from_settings(&s, "ws").is_err());
        assert!(DecoyConfig::from_settings(&s, "").is_err());
        assert!(DecoyConfig::from_settings(&s, "/a b").is_err());
        assert!(DecoyConfig::from_settings(&s, "/a?b").is_err());
        s.root = Some(PathBuf::from("relative/dir"));
        assert!(DecoyConfig::from_settings(&s, "/").is_err());
        s.root = Some(PathBuf::from("/definitely/not/here/xyz"));
        assert!(DecoyConfig::from_settings(&s, "/").is_err());
        let t = Tmp::new();
        s.root = Some(t.0.clone());
        assert!(DecoyConfig::from_settings(&s, "/").is_ok());
        s.write_timeout_secs = 0;
        assert!(DecoyConfig::from_settings(&s, "/").is_err());
        s.write_timeout_secs = 5;
        s.server_header = "bad\r\nX: y".into();
        assert!(DecoyConfig::from_settings(&s, "/").is_err());
    }

    #[tokio::test]
    async fn write_timeout_applies() {
        // A writer that never accepts data: the serve must time out, not hang.
        struct Stuck;
        impl AsyncWrite for Stuck {
            fn poll_write(
                self: std::pin::Pin<&mut Self>,
                _: &mut std::task::Context<'_>,
                _: &[u8],
            ) -> std::task::Poll<std::io::Result<usize>> {
                std::task::Poll::Pending
            }
            fn poll_flush(
                self: std::pin::Pin<&mut Self>,
                _: &mut std::task::Context<'_>,
            ) -> std::task::Poll<std::io::Result<()>> {
                std::task::Poll::Pending
            }
            fn poll_shutdown(
                self: std::pin::Pin<&mut Self>,
                _: &mut std::task::Context<'_>,
            ) -> std::task::Poll<std::io::Result<()>> {
                std::task::Poll::Pending
            }
        }
        let mut c = cfg(None);
        c.write_timeout = Duration::from_millis(50);
        let r = serve_decoy(Stuck, b"GET / HTTP/1.1\r\nHost: x\r\n\r\n", &c).await;
        assert!(r.is_err());
    }
}
