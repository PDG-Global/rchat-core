//! Decoy static website for non-WebSocket HTTP requests.
//!
//! A scanner or censor's probe that sends a plain HTTP request to the
//! server should see an ordinary website. When `[server.decoy] root` is
//! set, real files are served from that directory; otherwise the built-in
//! site is used, a login page for an invented product that varies with the
//! relay's host name (see `decoy_render`). Nothing here mentions the real
//! service.
//!
//! Only requests that are valid WebSocket upgrades to the configured
//! `websocket_path` reach the relay; everything else, including garbage
//! bytes, is answered here. One request per connection (`Connection:
//! close`); keep-alive is a known difference from nginx. Range follows nginx 1.24:
//! one range is a 206, several a multipart/byteranges 206, none satisfiable a
//! 416.
//! Request paths are never logged.

use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncSeekExt, AsyncWrite, AsyncWriteExt, BufReader};

use crate::config::DecoyConfig as DecoySettings;
use crate::decoy_render::{render_site_for_seed, Site};

#[cfg(test)]
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
    /// The built-in site, rendered from the relay's decoy seed (used when no
    /// `root` is configured).
    builtin: Arc<Site>,
}

/// Tests only: production always builds the config with `from_settings`
/// and the relay's secret-derived seed.
#[cfg(test)]
impl Default for DecoyConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            root: None,
            server: DEFAULT_SERVER.to_string(),
            ws_path: "/".to_string(),
            write_timeout: Duration::from_secs(30),
            builtin: Arc::new(render_site_for_seed(crate::decoy_render::seed_for(
                "localhost",
            ))),
        }
    }
}

impl DecoyConfig {
    /// Validate settings. Fails closed: a configured root that is relative,
    /// missing, or not a directory, or a bad websocket path, is a startup
    /// error.
    ///
    /// `seed` picks the built-in site (see `decoy_render`): the relay
    /// identity's decoy seed, `HKDF(identity secret, salt = host)` (final
    /// review M2), so the design can't be computed without the secret.
    pub fn from_settings(
        s: &DecoySettings,
        websocket_path: &str,
        seed: [u8; 32],
    ) -> anyhow::Result<Self> {
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
            builtin: Arc::new(render_site_for_seed(seed)),
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
    range: Option<String>,
    if_range: Option<String>,
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
        range: None,
        if_range: None,
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
        } else if k.eq_ignore_ascii_case("range") {
            req.range = Some(v.to_string());
        } else if k.eq_ignore_ascii_case("if-range") {
            req.if_range = Some(v.to_string());
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
    /// A file slice: start offset and length.
    FileAt(tokio::fs::File, u64, u64),
    /// A multipart/byteranges body: each part's header and slice of the
    /// source, then the closing boundary (final review L2).
    Parts(PartSource, Vec<Part>, Vec<u8>),
}

/// Where a multipart body's slices come from.
enum PartSource {
    Bytes(Vec<u8>),
    File(tokio::fs::File),
}

/// One part of a multipart/byteranges body: its boundary and headers, then
/// `len` bytes of the source from `start`.
struct Part {
    head: Vec<u8>,
    start: u64,
    len: u64,
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
            Body::FileAt(mut f, start, len) => {
                f.seek(std::io::SeekFrom::Start(start)).await?;
                let mut r = BufReader::with_capacity(32 * 1024, f).take(len);
                copy_bounded(&mut r, &mut stream).await?;
            }
            Body::Parts(source, parts, trailer) => {
                let mut source = source;
                for part in parts {
                    stream.write_all(&part.head).await?;
                    match &mut source {
                        PartSource::Bytes(v) => {
                            let (a, n) = (part.start as usize, part.len as usize);
                            stream.write_all(&v[a..a + n]).await?;
                        }
                        PartSource::File(f) => {
                            f.seek(std::io::SeekFrom::Start(part.start)).await?;
                            let mut r = BufReader::with_capacity(32 * 1024, &mut *f).take(part.len);
                            copy_bounded(&mut r, &mut stream).await?;
                        }
                    }
                }
                stream.write_all(&trailer).await?;
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
        Err(Reject::Hidden) => return not_found(config, head).await,
    };
    let at_root = rel.as_os_str().is_empty();
    let slash = strip_query(&req.target).ends_with('/');

    let Some(root) = &config.root else {
        // Built-in site, served from memory: only the fixed set of rendered
        // files exists, looked up by name (never a filesystem path).
        let name = if at_root {
            "index.html".to_string()
        } else {
            rel.components()
                .filter_map(|c| match c {
                    Component::Normal(s) => s.to_str(),
                    _ => None,
                })
                .collect::<Vec<_>>()
                .join("/")
        };
        let prefix = format!("{name}/");
        let is_dir = !at_root
            && config
                .builtin
                .files
                .iter()
                .any(|(p, _)| p.starts_with(&prefix));
        if is_dir {
            // As in root mode: a directory without its slash redirects, and
            // one without an index is 403 (as nginx).
            return if slash {
                error_response(403, config, head)
            } else {
                redirect(&rel, config, head)
            };
        }
        if slash && !at_root {
            return not_found(config, head).await;
        }
        if let Some(bytes) = config.builtin.get(&name) {
            let mtime = UNIX_EPOCH + Duration::from_secs(config.builtin.mtime);
            return finish_static(
                config,
                &req,
                head,
                content_type(Path::new(&name)),
                mtime,
                Body::Bytes(bytes.to_vec()),
                bytes.len() as u64,
            );
        }
        return not_found(config, head).await;
    };

    let mut path = root.join(&rel);
    let is_dir = at_root
        || tokio::fs::metadata(&path)
            .await
            .map(|m| m.is_dir())
            .unwrap_or(false);
    if is_dir {
        if !at_root && !slash {
            return redirect(&rel, config, head);
        }
        path = path.join("index.html");
    } else if slash {
        // `/file.html/` is not a file (nginx: 404).
        return not_found(config, head).await;
    }

    // Symlink-escape guard: the canonical file must live under the root.
    let Ok(canon) = tokio::fs::canonicalize(&path).await else {
        // A directory without an index is 403 in nginx.
        return if is_dir {
            error_response(403, config, head)
        } else {
            not_found(config, head).await
        };
    };
    if !canon.starts_with(root) {
        return not_found(config, head).await;
    }
    let Ok(file) = tokio::fs::File::open(&canon).await else {
        return not_found(config, head).await;
    };
    let Ok(meta) = file.metadata().await else {
        return not_found(config, head).await;
    };
    if !meta.is_file() {
        return not_found(config, head).await;
    }
    let mtime = meta.modified().unwrap_or(UNIX_EPOCH);
    finish_static(
        config,
        &req,
        head,
        content_type(&canon),
        mtime,
        Body::File(file, meta.len()),
        meta.len(),
    )
}

/// A found file (from disk or from the built-in site): `ETag` and
/// `Last-Modified` from `mtime` and `len`, conditional requests, and nginx's
/// header order. `body` is dropped for HEAD and 304.
fn finish_static(
    config: &DecoyConfig,
    req: &Request,
    head: bool,
    ctype: &str,
    mtime: SystemTime,
    body: Body,
    len: u64,
) -> Response {
    let etag = format!(
        "\"{:x}-{:x}\"",
        mtime
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
        len
    );
    let lm = http_date(mtime);
    let not_modified = match (&req.if_none_match, &req.if_modified_since) {
        (Some(inm), _) => inm == &etag,
        (None, Some(ims)) => ims == &lm,
        _ => false,
    };
    let hdr = Headers {
        ctype: if not_modified { None } else { Some(ctype) },
        len: if not_modified { None } else { Some(len) },
        last_modified: Some(&lm),
        etag: Some(&etag),
        location: None,
        accept_ranges: true,
        content_range: None,
    };
    if not_modified {
        return Response {
            head: build_head(304, config, &hdr),
            body: Body::None,
        };
    }
    // Range, as nginx 1.24's range filter (final review L2): one satisfiable
    // range is a single-part 206, several a multipart/byteranges 206, none
    // (or a malformed set) a 416; a failing If-Range, another unit, or
    // ranges adding up to more than the file get the whole file (200). A
    // 206 carries no Accept-Ranges header, as nginx's.
    let range_applies = match &req.if_range {
        None => true,
        Some(v) if v.starts_with('"') || v.starts_with("W/") => v == &etag,
        Some(v) => v == &lm,
    };
    let parsed = req
        .range
        .as_deref()
        .filter(|_| range_applies)
        .and_then(|r| parse_range(r, len));
    match parsed {
        Some(RangeSpec::Unsatisfiable) => {
            let cr = format!("bytes */{len}");
            let page = error_page(416, config);
            let h = Headers {
                ctype: Some("text/html"),
                len: Some(page.len() as u64),
                last_modified: None,
                etag: None,
                location: None,
                accept_ranges: false,
                content_range: Some(&cr),
            };
            Response {
                head: build_head(416, config, &h),
                body: if head { Body::None } else { Body::Bytes(page) },
            }
        }
        Some(RangeSpec::Ranges(ranges)) if ranges.len() == 1 => {
            let (a, end) = ranges[0];
            let b = end - 1;
            let cr = format!("bytes {a}-{b}/{len}");
            let n = end - a;
            let h = Headers {
                len: Some(n),
                accept_ranges: false,
                content_range: Some(&cr),
                ..hdr
            };
            let body = match body {
                Body::Bytes(v) => Body::Bytes(v[a as usize..end as usize].to_vec()),
                Body::File(f, _) | Body::FileAt(f, _, _) => Body::FileAt(f, a, n),
                other => other,
            };
            Response {
                head: build_head(206, config, &h),
                body: if head { Body::None } else { body },
            }
        }
        Some(RangeSpec::Ranges(ranges)) => {
            let boundary = next_boundary();
            let (parts, trailer) = multipart_parts(&boundary, ctype, &ranges, len);
            let total = parts
                .iter()
                .map(|p| p.head.len() as u64 + p.len)
                .sum::<u64>()
                + trailer.len() as u64;
            let mtype = format!("multipart/byteranges; boundary={boundary}");
            let h = Headers {
                ctype: Some(&mtype),
                len: Some(total),
                accept_ranges: false,
                ..hdr
            };
            let source = match body {
                Body::Bytes(v) => Some(PartSource::Bytes(v)),
                Body::File(f, _) | Body::FileAt(f, _, _) => Some(PartSource::File(f)),
                _ => None,
            };
            Response {
                head: build_head(206, config, &h),
                body: match source {
                    Some(source) if !head => Body::Parts(source, parts, trailer),
                    _ => Body::None,
                },
            }
        }
        None => Response {
            head: build_head(200, config, &hdr),
            body: if head { Body::None } else { body },
        },
    }
}

/// What a `Range` header asks of a file, decided as nginx 1.24's range
/// filter does (`ngx_http_range_parse`, default `max_ranges`: no limit).
#[derive(Debug, PartialEq, Eq)]
enum RangeSpec {
    /// Satisfiable ranges in request order, as half-open `[start, end)`
    /// offsets clamped to the file (overlaps and repeats kept, as nginx).
    Ranges(Vec<(u64, u64)>),
    /// No satisfiable range, or a malformed range set: 416.
    Unsatisfiable,
}

/// Parse `h` against a file of `len` bytes, porting `ngx_http_range_parse`.
/// `None` (send the whole file with 200): not a `bytes=` header (prefix
/// matched case-insensitively, at least one character after it), a range
/// starting at 0 that selects nothing (an empty file), or ranges adding up
/// to more than the file. A malformed range anywhere in the set is a 416,
/// as are only-unsatisfiable ranges.
fn parse_range(h: &str, len: u64) -> Option<RangeSpec> {
    let b = h.as_bytes();
    if b.len() < 7 || !b[..6].eq_ignore_ascii_case(b"bytes=") {
        return None;
    }
    // A NUL ends the value, as at the end of nginx's C string.
    let at = |i: usize| b.get(i).copied().unwrap_or(0);
    let mut p = 6;
    let digits = |p: &mut usize| -> Option<u64> {
        let mut n: u64 = 0;
        while at(*p).is_ascii_digit() {
            // nginx refuses values past off_t's maximum (as unsatisfiable).
            n = n
                .checked_mul(10)?
                .checked_add(u64::from(at(*p) - b'0'))
                .filter(|v| *v <= i64::MAX as u64)?;
            *p += 1;
        }
        Some(n)
    };
    let skip_spaces = |p: &mut usize| {
        while at(*p) == b' ' {
            *p += 1;
        }
    };
    let mut ranges = Vec::new();
    let mut size: u64 = 0;
    loop {
        let (start, end);
        skip_spaces(&mut p);
        let mut open_end = false;
        let mut suffix = false;
        let mut first: u64 = 0;
        if at(p) != b'-' {
            if !at(p).is_ascii_digit() {
                return Some(RangeSpec::Unsatisfiable);
            }
            let Some(s) = digits(&mut p) else {
                return Some(RangeSpec::Unsatisfiable);
            };
            first = s;
            skip_spaces(&mut p);
            if at(p) != b'-' {
                return Some(RangeSpec::Unsatisfiable);
            }
            p += 1;
            skip_spaces(&mut p);
            if at(p) == b',' || at(p) == 0 {
                open_end = true;
            }
        } else {
            suffix = true;
            p += 1;
        }
        if open_end {
            start = first;
            end = len;
        } else {
            if !at(p).is_ascii_digit() {
                return Some(RangeSpec::Unsatisfiable);
            }
            let Some(last) = digits(&mut p) else {
                return Some(RangeSpec::Unsatisfiable);
            };
            skip_spaces(&mut p);
            if at(p) != b',' && at(p) != 0 {
                return Some(RangeSpec::Unsatisfiable);
            }
            let (s, e) = if suffix {
                // `-n`: the last n bytes (nginx: end = len - 1, so -1 for
                // an empty file, then the end++ below makes it 0).
                (len.saturating_sub(last), len.checked_sub(1))
            } else {
                (first, Some(last))
            };
            start = s;
            end = match e {
                Some(e) if e < len => e + 1,
                Some(_) => len,
                None => 0,
            };
        }
        if start < end {
            ranges.push((start, end));
            size = match size.checked_add(end - start) {
                Some(s) if s <= i64::MAX as u64 => s,
                _ => return Some(RangeSpec::Unsatisfiable),
            };
        } else if start == 0 {
            return None;
        }
        if at(p) != b',' {
            break;
        }
        p += 1;
    }
    if ranges.is_empty() {
        return Some(RangeSpec::Unsatisfiable);
    }
    if size > len {
        return None;
    }
    Some(RangeSpec::Ranges(ranges))
}

/// The next multipart boundary: nginx's `ngx_next_temp_number(0)` printed
/// as `%0muA` (zero-padded to 20 digits on 64-bit), a process-wide counter
/// that steps by one per boundary (nginx's starts at 0 and also steps for
/// temporary files; this one starts at a random point below a million).
fn next_boundary() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: std::sync::OnceLock<AtomicU64> = std::sync::OnceLock::new();
    let c = COUNTER.get_or_init(|| AtomicU64::new(rand::random::<u64>() % 1_000_000));
    format!("{:020}", c.fetch_add(1, Ordering::Relaxed) + 1)
}

/// The body of a multipart/byteranges answer, as nginx's range body filter
/// writes it: per range `CRLF "--" boundary CRLF "Content-Type: " type CRLF
/// "Content-Range: bytes " start "-" last "/" total CRLF CRLF` and the
/// bytes, then `CRLF "--" boundary "--" CRLF`.
fn multipart_parts(
    boundary: &str,
    ctype: &str,
    ranges: &[(u64, u64)],
    total: u64,
) -> (Vec<Part>, Vec<u8>) {
    let parts = ranges
        .iter()
        .map(|&(start, end)| Part {
            head: format!(
                "\r\n--{boundary}\r\nContent-Type: {ctype}\r\nContent-Range: bytes {start}-{}/{total}\r\n\r\n",
                end - 1
            )
            .into_bytes(),
            start,
            len: end - start,
        })
        .collect();
    (parts, format!("\r\n--{boundary}--\r\n").into_bytes())
}

/// The 404 answer: the site's own branded `404.html` body (the built-in one,
/// or `<root>/404.html` when it is a regular file under the root) with
/// status 404 and the usual `Server` header; the plain nginx page when
/// there is none. A direct request for `/404.html` is an ordinary 200.
async fn not_found(config: &DecoyConfig, head: bool) -> Response {
    const MAX_404: u64 = 256 * 1024;
    let body: Option<Vec<u8>> = match &config.root {
        None => config.builtin.get("404.html").map(<[u8]>::to_vec),
        Some(root) => {
            async {
                let canon = tokio::fs::canonicalize(root.join("404.html")).await.ok()?;
                if !canon.starts_with(root) {
                    return None;
                }
                let meta = tokio::fs::metadata(&canon).await.ok()?;
                if !meta.is_file() || meta.len() > MAX_404 {
                    return None;
                }
                tokio::fs::read(&canon).await.ok()
            }
            .await
        }
    };
    match body {
        Some(b) => full(404, config, "text/html", b, head),
        None => error_response(404, config, head),
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
        206 => "Partial Content",
        301 => "Moved Permanently",
        304 => "Not Modified",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Not Allowed",
        416 => "Requested Range Not Satisfiable",
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
        accept_ranges: false,
        content_range: None,
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
        accept_ranges: false,
        content_range: None,
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
    accept_ranges: bool,
    content_range: Option<&'a str>,
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
    if h.accept_ranges {
        o.push_str("Accept-Ranges: bytes\r\n");
    }
    if let Some(r) = h.content_range {
        o.push_str(&format!("Content-Range: {r}\r\n"));
    }
    o.push_str("\r\n");
    o.into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decoy_render::seed_for;
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
                "ETag",
                "Accept-Ranges"
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

    fn host_cfg(host: &str) -> DecoyConfig {
        DecoyConfig::from_settings(&DecoySettings::default(), "/s3cr3t-path", seed_for(host))
            .unwrap()
    }

    #[tokio::test]
    async fn builtin_decoy_varies_by_host_and_serves_its_assets() {
        let (a, b) = (host_cfg("one.example.com"), host_cfg("two.example.com"));
        let (ra, rb) = (get(&a, "GET", "/").await, get(&b, "GET", "/").await);
        assert!(ra.starts_with("HTTP/1.1 200 OK\r\n"), "{ra}");
        assert_ne!(ra, rb, "two hosts must not serve identical pages");
        // Same host, same body (headers carry a Date).
        let body = |r: &str| r.split_once("\r\n\r\n").unwrap().1.to_string();
        assert_eq!(
            body(&ra),
            body(&get(&host_cfg("ONE.example.com."), "GET", "/").await)
        );
        let css = get(&a, "GET", "/assets/style.css").await;
        assert!(
            css.contains("Content-Type: text/css") && css.contains("--accent"),
            "{css}"
        );
        assert!(get(&a, "GET", "/index.html")
            .await
            .starts_with("HTTP/1.1 200"));
        assert!(get(&a, "HEAD", "/favicon.svg")
            .await
            .contains("image/svg+xml"));
        // Unknown paths and traversal stay refused; nothing leaks.
        assert!(get(&a, "GET", "/nope").await.starts_with("HTTP/1.1 404"));
        assert!(get(&a, "GET", "/assets/").await.starts_with("HTTP/1.1 403"));
        assert!(get(&a, "GET", "/assets/../index.html")
            .await
            .starts_with("HTTP/1.1 400"));
        assert!(get(&a, "GET", "/%2e%2e/etc/passwd")
            .await
            .starts_with("HTTP/1.1 400"));
        assert!(!ra.contains("s3cr3t-path") && !ra.to_lowercase().contains("rchat"));
    }

    #[tokio::test]
    async fn no_host_relays_with_different_seeds_serve_different_pages() {
        let mk = |seed: [u8; 32]| {
            DecoyConfig::from_settings(&DecoySettings::default(), "/s", seed).unwrap()
        };
        let body = |r: String| r.split_once("\r\n\r\n").unwrap().1.to_string();
        let a = body(get(&mk([1; 32]), "GET", "/").await);
        assert_ne!(a, body(get(&mk([2; 32]), "GET", "/").await));
        assert_eq!(a, body(get(&mk([1; 32]), "GET", "/").await));
    }

    fn header<'a>(r: &'a str, name: &str) -> Option<&'a str> {
        r.split("\r\n\r\n")
            .next()
            .unwrap()
            .split("\r\n")
            .find_map(|l| {
                l.split_once(": ")
                    .filter(|(k, _)| k.eq_ignore_ascii_case(name))
                    .map(|(_, v)| v)
            })
    }

    #[tokio::test]
    async fn unknown_paths_get_the_branded_404_with_status_404() {
        let c = host_cfg("one.example.com");
        let direct = get(&c, "GET", "/404.html").await;
        assert!(
            direct.starts_with("HTTP/1.1 200 OK"),
            "direct request is a plain 200"
        );
        let want = direct.split_once("\r\n\r\n").unwrap().1.to_string();
        for t in ["/nope", "/assets/nope.css", "/.env", "/index.html/"] {
            let r = get(&c, "GET", t).await;
            assert!(r.starts_with("HTTP/1.1 404 Not Found\r\n"), "{t}: {r}");
            assert_eq!(r.split_once("\r\n\r\n").unwrap().1, want, "{t}");
            assert_eq!(header(&r, "Server"), Some("nginx/1.24.0"));
            assert_eq!(header(&r, "Content-Type"), Some("text/html"));
        }
        let h = get(&c, "HEAD", "/nope").await;
        assert!(h.starts_with("HTTP/1.1 404") && h.ends_with("\r\n\r\n"));
        // Not 404 for other errors: bad requests keep the nginx page.
        assert!(get(&c, "GET", "/../x")
            .await
            .contains("<center>nginx/1.24.0</center>"));
    }

    #[tokio::test]
    async fn root_mode_serves_its_own_404_html_with_status_404() {
        let t = Tmp::new();
        std::fs::write(t.0.join("index.html"), b"home").unwrap();
        std::fs::write(t.0.join("404.html"), b"custom missing").unwrap();
        let s = DecoySettings {
            root: Some(t.0.clone()),
            ..DecoySettings::default()
        };
        let c = DecoyConfig::from_settings(&s, "/s", [0; 32]).unwrap();
        let r = get(&c, "GET", "/missing").await;
        assert!(
            r.starts_with("HTTP/1.1 404 Not Found") && r.ends_with("custom missing"),
            "{r}"
        );
        assert!(get(&c, "GET", "/index.html/")
            .await
            .starts_with("HTTP/1.1 404"));
        assert!(get(&c, "GET", "/404.html")
            .await
            .starts_with("HTTP/1.1 200"));
        // A symlinked 404.html pointing outside the root is not used.
        #[cfg(unix)]
        {
            let o = Tmp::new();
            std::fs::write(o.0.join("secret"), b"outside").unwrap();
            std::fs::remove_file(t.0.join("404.html")).unwrap();
            std::os::unix::fs::symlink(o.0.join("secret"), t.0.join("404.html")).unwrap();
            let r = get(&c, "GET", "/missing").await;
            assert!(
                r.starts_with("HTTP/1.1 404") && !r.contains("outside"),
                "{r}"
            );
            assert!(r.contains("<center>nginx/1.24.0</center>"));
        }
        // Without a 404.html: the plain nginx page.
        let t2 = Tmp::new();
        let s2 = DecoySettings {
            root: Some(t2.0.clone()),
            ..DecoySettings::default()
        };
        let c2 = DecoyConfig::from_settings(&s2, "/s", [0; 32]).unwrap();
        assert!(get(&c2, "GET", "/x")
            .await
            .contains("<center>nginx/1.24.0</center>"));
    }

    /// The range set as nginx 1.24's `ngx_http_range_parse` decides it
    /// (final review L2).
    #[test]
    fn range_header_parsing() {
        use RangeSpec::*;
        let one = |a, b| Some(Ranges(vec![(a, b)]));
        assert_eq!(parse_range("bytes=0-9", 100), one(0, 10));
        assert_eq!(parse_range("bytes=90-", 100), one(90, 100));
        assert_eq!(parse_range("bytes=-5", 100), one(95, 100));
        assert_eq!(parse_range("bytes=-500", 100), one(0, 100));
        assert_eq!(parse_range("bytes=5-500", 100), one(5, 100));
        assert_eq!(parse_range("BYTES=1-2", 100), one(1, 3));
        assert_eq!(parse_range("bytes= 1 - 2 ", 100), one(1, 3));
        // Several ranges, in request order, overlaps and repeats kept.
        assert_eq!(
            parse_range("bytes=0-1,3-4", 100),
            Some(Ranges(vec![(0, 2), (3, 5)]))
        );
        assert_eq!(
            parse_range("bytes=50-59, -10,0-0", 100),
            Some(Ranges(vec![(50, 60), (90, 100), (0, 1)]))
        );
        assert_eq!(
            parse_range("bytes=0-1,0-1", 100),
            Some(Ranges(vec![(0, 2), (0, 2)]))
        );
        // Unsatisfiable ranges are skipped; one left is a single range.
        assert_eq!(parse_range("bytes=200-300,5-6", 100), one(5, 7));
        assert_eq!(parse_range("bytes=5-3,1-1", 100), one(1, 2));
        // Nothing satisfiable, or anything malformed in the set: 416.
        for bad in [
            "bytes=100-",
            "bytes=-0",
            "bytes=5-3",
            "bytes=200-300,400-",
            "bytes=abc",
            "bytes=-",
            "bytes=1-2-3",
            "bytes=+1-2",
            "bytes=0-1,abc",
            "bytes=0-1,",
            "bytes=0-1;3-4",
            "bytes=99999999999999999999-",
        ] {
            assert_eq!(parse_range(bad, 100), Some(Unsatisfiable), "{bad}");
        }
        // The whole file: other units, a bare prefix, an empty file, or
        // ranges adding up to more than the file.
        for whole in [
            "items=0-1",
            "bytes=",
            "0-5",
            "bytes =0-1",
            "bytes=0-,0-",
            "bytes=0-59,40-99",
        ] {
            assert_eq!(parse_range(whole, 100), None, "{whole}");
        }
        assert_eq!(parse_range("bytes=0-1", 0), None);
        assert_eq!(parse_range("bytes=-5", 0), None);
        assert_eq!(parse_range("bytes=3-4", 0), Some(Unsatisfiable));
    }

    /// Final review L2: several satisfiable ranges get a 206
    /// `multipart/byteranges` answer laid out byte for byte as nginx 1.24's,
    /// in built-in and root mode alike; HEAD gets the same head.
    #[tokio::test]
    async fn several_ranges_get_a_multipart_byteranges_206() {
        let seed = seed_for("multi.example.com");
        let t = Tmp::new();
        crate::decoy_render::render_decoy_seeded(seed, &t.0.join("site")).unwrap();
        let s = DecoySettings {
            root: Some(t.0.join("site")),
            ..DecoySettings::default()
        };
        let root_c = DecoyConfig::from_settings(&s, "/s", seed).unwrap();
        let built = DecoyConfig::from_settings(&DecoySettings::default(), "/s", seed).unwrap();
        for c in [&built, &root_c] {
            let full = get(c, "GET", "/assets/style.css").await;
            let body = full.split_once("\r\n\r\n").unwrap().1.as_bytes().to_vec();
            let n = body.len();
            let req = |method: &str| {
                format!(
                    "{method} /assets/style.css HTTP/1.1\r\nHost: x\r\nRange: bytes=0-1, 10-19,-5\r\n\r\n"
                )
            };
            let r = send(c, &req("GET")).await;
            let (h, b) = r.split_once("\r\n\r\n").unwrap();
            assert!(h.starts_with("HTTP/1.1 206 Partial Content\r\n"), "{h}");
            let ct = header(&r, "Content-Type").unwrap();
            let boundary = ct
                .strip_prefix("multipart/byteranges; boundary=")
                .unwrap_or_else(|| panic!("{ct}"));
            assert_eq!(boundary.len(), 20, "nginx pads the boundary to 20 digits");
            assert!(boundary.bytes().all(|c| c.is_ascii_digit()));
            let part = |a: usize, z: usize| {
                let mut p = format!(
                    "\r\n--{boundary}\r\nContent-Type: text/css\r\nContent-Range: bytes {a}-{z}/{n}\r\n\r\n"
                )
                .into_bytes();
                p.extend_from_slice(&body[a..=z]);
                p
            };
            let mut want = Vec::new();
            want.extend(part(0, 1));
            want.extend(part(10, 19));
            want.extend(part(n - 5, n - 1));
            want.extend(format!("\r\n--{boundary}--\r\n").into_bytes());
            assert_eq!(b.as_bytes(), &want[..]);
            assert_eq!(
                header(&r, "Content-Length").unwrap(),
                want.len().to_string()
            );
            assert!(header(&r, "Content-Range").is_none());
            assert!(header(&r, "Accept-Ranges").is_none());
            assert!(header(&r, "ETag").is_some() && header(&r, "Last-Modified").is_some());
            // Header order as nginx: Content-Type, Content-Length,
            // Last-Modified, Connection, ETag.
            let names: Vec<&str> = h
                .split("\r\n")
                .skip(1)
                .filter_map(|l| l.split_once(':').map(|(k, _)| k))
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
            // HEAD: the same head (a fresh boundary), no body.
            let hr = send(c, &req("HEAD")).await;
            assert!(
                hr.starts_with("HTTP/1.1 206 Partial Content\r\n") && hr.ends_with("\r\n\r\n"),
                "{hr}"
            );
            assert_eq!(
                header(&hr, "Content-Length").unwrap(),
                want.len().to_string()
            );
            assert_ne!(header(&hr, "Content-Type").unwrap(), ct, "next boundary");
            // Unsatisfiable ranges are left out; none left is a 416.
            let r = send(
                c,
                "GET /assets/style.css HTTP/1.1\r\nHost: x\r\nRange: bytes=999999-,9999999-\r\n\r\n",
            )
            .await;
            assert!(r.starts_with("HTTP/1.1 416 "), "{r}");
            assert_eq!(header(&r, "Content-Range").unwrap(), format!("bytes */{n}"));
        }
    }

    /// Range answers are identical in built-in and root mode.
    #[tokio::test]
    async fn range_requests_206_416_and_ignored_cases() {
        let seed = seed_for("range.example.com");
        let t = Tmp::new();
        crate::decoy_render::render_decoy_seeded(seed, &t.0.join("site")).unwrap();
        let s = DecoySettings {
            root: Some(t.0.join("site")),
            ..DecoySettings::default()
        };
        let root_c = DecoyConfig::from_settings(&s, "/s", seed).unwrap();
        let built = DecoyConfig::from_settings(&DecoySettings::default(), "/s", seed).unwrap();
        for c in [&built, &root_c] {
            let full = get(c, "GET", "/assets/style.css").await;
            let body = full.split_once("\r\n\r\n").unwrap().1.to_string();
            let n = body.len();
            assert!(n > 100);
            let req = |method: &str, extra: &str| {
                format!("{method} /assets/style.css HTTP/1.1\r\nHost: x\r\n{extra}\r\n")
            };
            let split = |r: &str| {
                let (h, b) = r.split_once("\r\n\r\n").unwrap();
                (h.to_string(), b.to_string())
            };
            // Satisfiable single ranges.
            for (hdr, a, b) in [
                ("bytes=0-9", 0, 9),
                ("bytes=10-", 10, n - 1),
                ("bytes=-5", n - 5, n - 1),
                ("bytes=5-999999", 5, n - 1),
                ("bytes=-999999", 0, n - 1),
            ] {
                let r = send(c, &req("GET", &format!("Range: {hdr}\r\n"))).await;
                let (h, b_) = split(&r);
                assert!(
                    h.starts_with("HTTP/1.1 206 Partial Content\r\n"),
                    "{hdr}: {h}"
                );
                assert_eq!(
                    header(&r, "Content-Range").unwrap(),
                    format!("bytes {a}-{b}/{n}")
                );
                assert_eq!(
                    header(&r, "Content-Length").unwrap(),
                    (b - a + 1).to_string()
                );
                assert_eq!(b_, body[a..=b], "{hdr}");
                // nginx adds Accept-Ranges only when it sends the whole file.
                assert_eq!(header(&r, "Accept-Ranges"), None);
                assert!(header(&r, "ETag").is_some() && header(&r, "Last-Modified").is_some());
            }
            // HEAD: same head, no body.
            let r = send(c, &req("HEAD", "Range: bytes=0-9\r\n")).await;
            assert!(
                r.starts_with("HTTP/1.1 206 ") && r.ends_with("\r\n\r\n"),
                "{r}"
            );
            assert_eq!(header(&r, "Content-Length"), Some("10"));
            // Unsatisfiable or malformed (as nginx): 416 with the nginx page.
            for hdr in [
                format!("bytes={n}-"),
                "bytes=999999-".to_string(),
                "bytes=-0".to_string(),
                "bytes=abc".to_string(),
                "bytes=5-3".to_string(),
            ] {
                let r = send(c, &req("GET", &format!("Range: {hdr}\r\n"))).await;
                assert!(
                    r.starts_with("HTTP/1.1 416 Requested Range Not Satisfiable\r\n"),
                    "{hdr}: {r}"
                );
                assert_eq!(header(&r, "Content-Range").unwrap(), format!("bytes */{n}"));
                assert!(r.contains("<center>nginx/1.24.0</center>"));
            }
            // Other units, a bare prefix, garbage, and ranges adding up to
            // more than the file: the whole file.
            for hdr in ["items=0-1", "bytes=", "garbage", "bytes=0-,0-"] {
                let r = send(c, &req("GET", &format!("Range: {hdr}\r\n"))).await;
                let (h, b_) = split(&r);
                assert!(h.starts_with("HTTP/1.1 200 "), "{hdr}: {h}");
                assert_eq!(b_, body, "{hdr}");
                assert!(header(&r, "Content-Range").is_none());
            }
            // If-Range: a matching validator keeps the range, a mismatch sends all.
            let etag = header(&full, "ETag").unwrap().to_string();
            let lm = header(&full, "Last-Modified").unwrap().to_string();
            for ir in [&etag, &lm] {
                let r = send(
                    c,
                    &req("GET", &format!("Range: bytes=0-9\r\nIf-Range: {ir}\r\n")),
                )
                .await;
                assert!(r.starts_with("HTTP/1.1 206 "), "{ir}: {r}");
            }
            for ir in ["\"nope\"", "Mon, 01 Jan 2001 00:00:00 GMT"] {
                let r = send(
                    c,
                    &req("GET", &format!("Range: bytes=0-9\r\nIf-Range: {ir}\r\n")),
                )
                .await;
                let (h, b_) = split(&r);
                assert!(h.starts_with("HTTP/1.1 200 "), "{ir}: {h}");
                assert_eq!(b_, body);
            }
        }
    }

    #[tokio::test]
    async fn builtin_and_root_modes_answer_alike() {
        // Same site both ways: render to disk, serve it as a root.
        let seed = seed_for("parity.example.com");
        let site = render_site_for_seed(seed);
        let t = Tmp::new();
        crate::decoy_render::render_decoy_seeded(seed, &t.0.join("site")).unwrap();
        let s = DecoySettings {
            root: Some(t.0.join("site")),
            ..DecoySettings::default()
        };
        let root_c = DecoyConfig::from_settings(&s, "/s", seed).unwrap();
        let built = DecoyConfig::from_settings(&DecoySettings::default(), "/s", seed).unwrap();
        let status = |r: &str| r.lines().next().unwrap().to_string();
        for t in [
            "/",
            "/index.html",
            "/assets",
            "/assets/",
            "/assets/style.css",
            "/nope",
            "/index.html/",
            "/favicon.svg",
        ] {
            let (a, b) = (get(&built, "GET", t).await, get(&root_c, "GET", t).await);
            assert_eq!(status(&a), status(&b), "{t}");
            assert_eq!(header(&a, "Location"), header(&b, "Location"), "{t}");
            assert_eq!(
                header(&a, "Content-Type"),
                header(&b, "Content-Type"),
                "{t}"
            );
            assert_eq!(
                a.split_once("\r\n\r\n").unwrap().1,
                b.split_once("\r\n\r\n").unwrap().1,
                "{t}"
            );
        }
        assert!(get(&built, "GET", "/assets")
            .await
            .contains("Location: /assets/\r\n"));
        assert!(get(&built, "GET", "/assets/")
            .await
            .starts_with("HTTP/1.1 403"));
        // Built-in validators: stable, seed-derived, nginx-shaped, no wall clock.
        let r1 = get(&built, "GET", "/").await;
        let r2 = get(&built, "GET", "/").await;
        for h in ["Last-Modified", "ETag", "Accept-Ranges"] {
            assert!(header(&r1, h).is_some(), "{h}");
            assert_eq!(header(&r1, h), header(&r2, h));
        }
        assert_eq!(header(&r1, "Accept-Ranges"), Some("bytes"));
        assert_eq!(
            header(&r1, "Last-Modified"),
            Some(http_date(UNIX_EPOCH + Duration::from_secs(site.mtime)).as_str())
        );
        let etag = header(&r1, "ETag").unwrap().to_string();
        let r = send(
            &built,
            &format!("GET / HTTP/1.1\r\nHost: x\r\nIf-None-Match: {etag}\r\n\r\n"),
        )
        .await;
        assert!(r.starts_with("HTTP/1.1 304"), "{r}");
        let other = DecoyConfig::from_settings(
            &DecoySettings::default(),
            "/s",
            seed_for("other.example.com"),
        )
        .unwrap();
        assert_ne!(
            header(&get(&other, "GET", "/").await, "Last-Modified"),
            header(&r1, "Last-Modified")
        );
    }

    #[tokio::test]
    async fn configured_root_wins_over_the_builtin_site() {
        let t = Tmp::new();
        std::fs::write(t.0.join("index.html"), b"custom site").unwrap();
        let s = DecoySettings {
            root: Some(t.0.clone()),
            ..DecoySettings::default()
        };
        let c = DecoyConfig::from_settings(&s, "/s", seed_for("one.example.com")).unwrap();
        assert!(get(&c, "GET", "/").await.ends_with("custom site"));
    }

    #[tokio::test]
    async fn websocket_path_routing() {
        let s = DecoySettings {
            write_timeout_secs: 5,
            ..DecoySettings::default()
        };
        let c = DecoyConfig::from_settings(&s, "/s3cr3t-path", [0u8; 32]).unwrap();
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
        let c = DecoyConfig::from_settings(&s, "/s3cr3t-path", [0u8; 32]).unwrap();
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
        let c = DecoyConfig::from_settings(&DecoySettings::default(), "/", [0u8; 32]).unwrap();
        assert!(c.is_relay_upgrade(&upgrade("/")));
        assert!(!c.is_relay_upgrade(&upgrade("/x")));
    }

    #[test]
    fn settings_validation() {
        let mut s = DecoySettings::default();
        assert!(DecoyConfig::from_settings(&s, "/", [0u8; 32]).is_ok());
        assert!(DecoyConfig::from_settings(&s, "ws", [0u8; 32]).is_err());
        assert!(DecoyConfig::from_settings(&s, "", [0u8; 32]).is_err());
        assert!(DecoyConfig::from_settings(&s, "/a b", [0u8; 32]).is_err());
        assert!(DecoyConfig::from_settings(&s, "/a?b", [0u8; 32]).is_err());
        s.root = Some(PathBuf::from("relative/dir"));
        assert!(DecoyConfig::from_settings(&s, "/", [0u8; 32]).is_err());
        s.root = Some(PathBuf::from("/definitely/not/here/xyz"));
        assert!(DecoyConfig::from_settings(&s, "/", [0u8; 32]).is_err());
        let t = Tmp::new();
        s.root = Some(t.0.clone());
        assert!(DecoyConfig::from_settings(&s, "/", [0u8; 32]).is_ok());
        s.write_timeout_secs = 0;
        assert!(DecoyConfig::from_settings(&s, "/", [0u8; 32]).is_err());
        s.write_timeout_secs = 5;
        s.server_header = "bad\r\nX: y".into();
        assert!(DecoyConfig::from_settings(&s, "/", [0u8; 32]).is_err());
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
