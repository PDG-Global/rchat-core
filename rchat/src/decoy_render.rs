//! Per-relay decoy sites (spec §D.2), ported from rVPN's `render_decoy.py`.
//!
//! Every relay shows a plausible, self-contained product login page to
//! anything that is not a WebSocket upgrade to the secret path. The product
//! (webmail, NAS, photo library, cloud drive, code hosting), the brand, the
//! accent colour and the logo are derived from a 32-byte seed, so
//! re-provisioning the same relay reproduces the same site and no two relays
//! serve the same bytes.
//!
//! # Seeding
//!
//! The seed is the relay identity's decoy seed (final review M2):
//! `HKDF-SHA256(ikm = identity secret key, salt = normalised host bytes,
//! empty with no host, info = "rchat/decoy-seed/v3")`, the same for the
//! built-in page and `--render-decoy` (`RelayIdentity::decoy_seed`). It
//! can't be computed from public data: knowing a relay's host and pin does
//! not reveal its design. The host is normalised first: trimmed,
//! lower-cased, and every trailing dot removed (`Chat.Example.COM.` and
//! `chat.example.com` are one host). A deterministic stream is drawn from
//! the seed in counter mode (`SHA-256(seed || counter_be64)`), so the output
//! does not depend on any third-party PRNG version. Output carries no
//! timestamps.
//!
//! # What the pages never contain
//!
//! Nothing identifying: no WebSocket path, relay pin, version string or
//! project name. All CSS, JS and SVG is inline or a local file. Forms never
//! submit (`onsubmit="return false"`, no `action`); the script shows a
//! generic "incorrect username or password" message. Brand names are
//! invented.

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

/// Marker file written into every rendered directory. A non-empty `out`
/// without it is refused. Deliberately says nothing about its origin.
pub const MARKER: &str = ".decoy-rendered";

const BASE_CSS: &str = include_str!("decoy_templates/base.css");
const LOGIN_JS: &str = include_str!("decoy_templates/login.js");
const FAVICON: &str = include_str!("decoy_templates/favicon.svg");
const ROBOTS: &str = include_str!("decoy_templates/robots.txt");
const NOT_FOUND: &str = include_str!("decoy_templates/404.html");

/// The product a decoy site imitates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Product {
    Webmail,
    Nas,
    Photos,
    Cloud,
    Code,
}

impl Product {
    pub const ALL: [Product; 5] = [
        Product::Webmail,
        Product::Nas,
        Product::Photos,
        Product::Cloud,
        Product::Code,
    ];

    fn index_template(self) -> &'static str {
        match self {
            Product::Webmail => include_str!("decoy_templates/webmail.html"),
            Product::Nas => include_str!("decoy_templates/nas.html"),
            Product::Photos => include_str!("decoy_templates/photos.html"),
            Product::Cloud => include_str!("decoy_templates/cloud.html"),
            Product::Code => include_str!("decoy_templates/code.html"),
        }
    }

    fn css(self) -> &'static str {
        match self {
            Product::Webmail => include_str!("decoy_templates/webmail.css"),
            Product::Nas => include_str!("decoy_templates/nas.css"),
            Product::Photos => include_str!("decoy_templates/photos.css"),
            Product::Cloud => include_str!("decoy_templates/cloud.css"),
            Product::Code => include_str!("decoy_templates/code.css"),
        }
    }

    fn brands(self) -> &'static [&'static str] {
        match self {
            Product::Webmail => &[
                "Postwick Mail",
                "Larkspur Mail",
                "Inkwell Mail",
                "Tallow Mail",
                "Marrow Post",
                "Sundial Mail",
                "Quillfeather Mail",
                "Brindle Mail",
                "Fenwick Post",
                "Wickerlane Mail",
                "Hollin Mail",
                "Pennant Post",
            ],
            Product::Nas => &[
                "Kelvane Storage",
                "Ostrel Vault",
                "Brackwater NAS",
                "Tessarok Systems",
                "Hobnail Storage",
                "Variel Disk",
                "Dunmore Stor",
                "Cindra NAS",
                "Pellam Systems",
                "Orrin Station",
                "Gantry Storage",
                "Marlow Vault",
            ],
            Product::Photos => &[
                "Foxglove Photos",
                "Tumble Gallery",
                "Thistle Album",
                "Lantern Roll",
                "Pebbleframe",
                "Moth Gallery",
                "Orchard Photos",
                "Kiln Album",
                "Tarn Photos",
                "Fieldnote Photos",
                "Quarry Gallery",
                "Wren Album",
            ],
            Product::Cloud => &[
                "Skerry Drive",
                "Cobalt Meadow",
                "Hearth Sync",
                "Plover Cloud",
                "Driftwood Files",
                "Anvilbox",
                "Tamarind Drive",
                "Ketch Cloud",
                "Burrow Files",
                "Saltmarsh Sync",
                "Rookery Drive",
                "Gable Cloud",
            ],
            Product::Code => &[
                "Cairnforge",
                "Tinderbox Git",
                "Lathe Code",
                "Bramble Forge",
                "Pylon Git",
                "Hasp Code",
                "Oxbow Git",
                "Wattle Forge",
                "Ferrule Code",
                "Anneal Git",
                "Rivet Forge",
                "Mortise Code",
            ],
        }
    }

    fn taglines(self) -> &'static [&'static str] {
        match self {
            Product::Webmail => &[
                "Email that stays out of your way.",
                "Your inbox, wherever you are.",
                "Simple, dependable email.",
                "All your mail in one place.",
                "Fast email for busy people.",
            ],
            Product::Nas => &[
                "Your data on your own hardware.",
                "Storage you control.",
                "Network storage, simplified.",
                "All your files, always at hand.",
                "Reliable storage for home and office.",
            ],
            Product::Photos => &[
                "Every photo in one home.",
                "Keep the moments that matter.",
                "Your library, neatly organised.",
                "A quiet place for your pictures.",
                "Albums for the whole family.",
            ],
            Product::Cloud => &[
                "Files that follow you.",
                "Work from anywhere.",
                "One drive for everything.",
                "Sync, share, done.",
                "Your files, always in reach.",
            ],
            Product::Code => &[
                "Git hosting without the noise.",
                "Where your team builds.",
                "Review, merge, repeat.",
                "Plain tooling for small teams.",
                "Issues and code in one place.",
            ],
        }
    }
}

/// Accent colours: dark enough for white label text.
const ACCENTS: [&str; 14] = [
    "#2563eb", "#1d4ed8", "#0d9488", "#0e7490", "#059669", "#4d7c0f", "#b45309", "#c2410c",
    "#b91c1c", "#be185d", "#7c3aed", "#4f46e5", "#475569", "#0f766e",
];

const DISALLOW: [&str; 4] = ["/admin/", "/internal/", "/settings/", ""];
// Chosen so no model reads as a real vendor SKU (avoid DS/RS/TS/TVS/DX).
const NAS_PREFIX: [&str; 5] = ["KV", "VZ", "NB", "ZR", "HX"];
const NAS_SUFFIX: [&str; 5] = ["+", "j", "se", " II", ""];
const NAS_BAYS: [&str; 4] = ["2-bay", "4-bay", "5-bay", "8-bay"];

/// A fully rendered site, in memory.
#[derive(Debug, Clone)]
pub struct Site {
    pub product: Product,
    /// Relative path (always `/`-separated, never absolute or `..`) and bytes.
    pub files: Vec<(&'static str, Vec<u8>)>,
    /// Synthetic, stable modification time (Unix seconds) drawn from the
    /// seed, for `Last-Modified` and `ETag` (never the wall clock).
    pub mtime: u64,
}

impl Site {
    pub fn get(&self, rel: &str) -> Option<&[u8]> {
        self.files
            .iter()
            .find(|(p, _)| *p == rel)
            .map(|(_, b)| b.as_slice())
    }
}

/// Normalise a host name for seeding: trim, lower-case, strip all trailing
/// dots. `Chat.Example.COM.` and `chat.example.com` seed identically.
pub fn normalize_host(host: &str) -> String {
    host.trim()
        .to_ascii_lowercase()
        .trim_end_matches('.')
        .to_string()
}

/// Tests only: a seed from a label, `SHA-256(normalised label)`, so tests can
/// render distinct sites without a relay identity. Never a relay's seed: that
/// one is secret-derived (final review M2, `RelayIdentity::decoy_seed`).
#[cfg(test)]
pub fn seed_for(host: &str) -> [u8; 32] {
    Sha256::digest(normalize_host(host).as_bytes()).into()
}

/// Deterministic stream: `SHA-256(seed || counter)` blocks.
struct Stream {
    seed: [u8; 32],
    counter: u64,
    buf: [u8; 32],
    pos: usize,
}

impl Stream {
    fn new(seed: [u8; 32]) -> Self {
        Self {
            seed,
            counter: 0,
            buf: [0; 32],
            pos: 32,
        }
    }

    fn next_u64(&mut self) -> u64 {
        if self.pos + 8 > 32 {
            let mut h = Sha256::new();
            h.update(self.seed);
            h.update(self.counter.to_be_bytes());
            self.buf = h.finalize().into();
            self.counter += 1;
            self.pos = 0;
        }
        let mut b = [0u8; 8];
        b.copy_from_slice(&self.buf[self.pos..self.pos + 8]);
        self.pos += 8;
        u64::from_be_bytes(b)
    }

    /// Uniform-enough value in `lo..=hi` (bias below 2^-50 for these ranges).
    fn range(&mut self, lo: u32, hi: u32) -> u32 {
        lo + (self.next_u64() % u64::from(hi - lo + 1)) as u32
    }

    fn pick<'a, T: ?Sized>(&mut self, items: &'a [&'a T]) -> &'a T {
        items[(self.next_u64() % items.len() as u64) as usize]
    }
}

fn logo(s: &mut Stream, brand: &str, accent: &str) -> String {
    let letter = brand.chars().next().unwrap_or('A').to_ascii_uppercase();
    let font = "-apple-system,Segoe UI,Helvetica,Arial,sans-serif";
    // No xmlns: inline SVG in HTML needs none, and the page then has no URL
    // string at all.
    let marks = [
        format!(
            "<svg width=\"40\" height=\"40\" viewBox=\"0 0 40 40\" aria-hidden=\"true\"><rect width=\"40\" height=\"40\" rx=\"10\" fill=\"{accent}\"/><text x=\"20\" y=\"27\" font-family=\"{font}\" font-size=\"20\" font-weight=\"700\" fill=\"#fff\" text-anchor=\"middle\">{letter}</text></svg>"
        ),
        format!(
            "<svg width=\"40\" height=\"40\" viewBox=\"0 0 40 40\" aria-hidden=\"true\"><circle cx=\"20\" cy=\"20\" r=\"18\" fill=\"none\" stroke=\"{accent}\" stroke-width=\"4\"/><text x=\"20\" y=\"26\" font-family=\"{font}\" font-size=\"17\" font-weight=\"700\" fill=\"{accent}\" text-anchor=\"middle\">{letter}</text></svg>"
        ),
        format!(
            "<svg width=\"40\" height=\"40\" viewBox=\"0 0 40 40\" aria-hidden=\"true\"><polygon points=\"20,3 35,11.5 35,28.5 20,37 5,28.5 5,11.5\" fill=\"{accent}\"/><text x=\"20\" y=\"26\" font-family=\"{font}\" font-size=\"16\" font-weight=\"700\" fill=\"#fff\" text-anchor=\"middle\">{letter}</text></svg>"
        ),
        format!(
            "<svg width=\"40\" height=\"40\" viewBox=\"0 0 40 40\" aria-hidden=\"true\"><rect width=\"40\" height=\"40\" rx=\"8\" fill=\"{accent}\"/><rect x=\"9\" y=\"10\" width=\"22\" height=\"5\" rx=\"2.5\" fill=\"#fff\"/><rect x=\"9\" y=\"18\" width=\"16\" height=\"5\" rx=\"2.5\" fill=\"#fff\" opacity=\".8\"/><rect x=\"9\" y=\"26\" width=\"10\" height=\"5\" rx=\"2.5\" fill=\"#fff\" opacity=\".6\"/></svg>"
        ),
    ];
    let i = (s.next_u64() % marks.len() as u64) as usize;
    marks[i].clone()
}

/// Draw until the text does not contain the crate version, so a generated
/// version string can never equal the relay's own.
fn without_crate_version(mut make: impl FnMut() -> String) -> String {
    loop {
        let s = make();
        if !s.contains(env!("CARGO_PKG_VERSION")) {
            return s;
        }
    }
}

fn substitute(text: &str, ctx: &[(&str, String)]) -> String {
    let mut out = text.to_string();
    for (k, v) in ctx {
        out = out.replace(&format!("{{{{{k}}}}}"), v);
    }
    out
}

/// Render the site for `host`, optionally forcing the product (tests).
#[cfg(test)]
pub fn render_site_with(host: &str, forced: Option<Product>) -> Site {
    render_site_seeded(seed_for(host), forced)
}

/// Render from a 32-byte seed: the relay identity's decoy seed (derived from
/// its secret key and host, never from anything public alone).
pub fn render_site_seeded(seed: [u8; 32], forced: Option<Product>) -> Site {
    let mut s = Stream::new(seed);
    let drawn = Product::ALL[(s.next_u64() % Product::ALL.len() as u64) as usize];
    let product = forced.unwrap_or(drawn);
    let brand = s.pick(product.brands());
    let tagline = s.pick(product.taglines());
    let accent = s.pick(&ACCENTS);
    let logo_svg = logo(&mut s, brand, accent);
    let year = s.range(2022, 2026);
    let footer = match s.range(0, 2) {
        0 => format!("&copy; {year} {brand}. All rights reserved."),
        1 => format!("&copy; {year} {brand} Ltd."),
        _ => format!("&copy; {year} {brand} &middot; Privacy &middot; Terms"),
    };
    let disallow = s.pick(&DISALLOW);

    let mut ctx: Vec<(&str, String)> = vec![
        ("LOGIN_JS", LOGIN_JS.trim_end().to_string()),
        ("BRAND", brand.to_string()),
        ("TAGLINE", tagline.to_string()),
        ("ACCENT", accent.to_string()),
        ("LOGO_SVG", logo_svg),
        (
            "LETTER",
            brand
                .chars()
                .next()
                .unwrap_or('A')
                .to_ascii_uppercase()
                .to_string(),
        ),
        ("FOOTER", footer),
        ("DISALLOW", disallow.to_string()),
    ];
    match product {
        Product::Nas => {
            let model = format!(
                "{}{}{}",
                s.pick(&NAS_PREFIX),
                s.range(100, 999),
                s.pick(&NAS_SUFFIX)
            );
            let bays = s.pick(&NAS_BAYS).to_string();
            let firmware = without_crate_version(|| {
                format!(
                    "Firmware {}.{}.{}-{}",
                    s.range(4, 7),
                    s.range(0, 9),
                    s.range(0, 9),
                    s.range(10000, 99999)
                )
            });
            ctx.push(("MODEL", model));
            ctx.push(("BAYS", bays));
            ctx.push(("FIRMWARE", firmware));
        }
        Product::Code => {
            let v = without_crate_version(|| {
                format!("v{}.{}.{}", s.range(1, 3), s.range(0, 49), s.range(0, 9))
            });
            ctx.push(("VERSION", v));
        }
        Product::Cloud => {
            let gb = [5u32, 10, 15, 20][s.range(0, 3) as usize];
            ctx.push(("FREE_GB", gb.to_string()));
        }
        _ => {}
    }
    let css = format!("{BASE_CSS}{}", product.css());
    let files = vec![
        ("index.html", substitute(product.index_template(), &ctx)),
        ("assets/style.css", substitute(&css, &ctx)),
        ("favicon.svg", substitute(FAVICON, &ctx)),
        ("404.html", substitute(NOT_FOUND, &ctx)),
        ("robots.txt", substitute(ROBOTS, &ctx)),
    ]
    .into_iter()
    .map(|(p, t)| (p, t.into_bytes()))
    .collect();
    // Last: appended draws never change the pages above.
    let mtime = 1_700_000_000 + u64::from(s.range(0, 60_000_000));
    Site {
        product,
        files,
        mtime,
    }
}

/// Render for a seed (see [`render_site_seeded`]).
pub fn render_site_for_seed(seed: [u8; 32]) -> Site {
    render_site_seeded(seed, None)
}

/// Render the site for `host` (product chosen from the seed).
#[cfg(test)]
pub fn render_site(host: &str) -> Site {
    render_site_with(host, None)
}

fn refuse(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, msg.into())
}

/// Write `bytes` to `dir/name` through a temp file and a rename. The temp
/// file is created exclusively (never follows a symlink at that name); the
/// rename replaces a pre-existing symlink at `name` itself rather than
/// writing through it.
fn write_atomic(dir: &Path, name: &str, bytes: &[u8]) -> io::Result<()> {
    let tmp = dir.join(format!(".{name}.tmp{}", std::process::id()));
    let _ = fs::remove_file(&tmp);
    let result = (|| {
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        fs::rename(&tmp, dir.join(name))
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

/// Make sure `dir` is a real directory (not a symlink), creating it if
/// absent.
fn ensure_real_dir(dir: &Path) -> io::Result<()> {
    match fs::symlink_metadata(dir) {
        Ok(m) if m.is_dir() => Ok(()),
        Ok(_) => Err(refuse(format!(
            "{} is not a plain directory (symlinks are not followed)",
            dir.display()
        ))),
        Err(e) if e.kind() == io::ErrorKind::NotFound => fs::create_dir(dir),
        Err(e) => Err(e),
    }
}

/// Tests only: [`render_decoy_seeded`] with the test seed of `host`.
#[cfg(test)]
pub fn render_decoy(host: &str, out: &Path) -> io::Result<()> {
    if normalize_host(host).is_empty() {
        return Err(refuse("the host name is empty"));
    }
    render_decoy_seeded(seed_for(host), out)
}

/// Render the decoy site for `seed` (the relay identity's decoy seed) into
/// `out`.
///
/// `out` must be missing, empty, or a directory this function rendered
/// earlier (it holds [`MARKER`]). Anything else is refused and left alone.
/// Symlinks are never followed out of `out`; every file is written through
/// a temp file and a rename.
pub fn render_decoy_seeded(seed: [u8; 32], out: &Path) -> io::Result<()> {
    match fs::symlink_metadata(out) {
        Ok(m) if m.file_type().is_symlink() => {
            return Err(refuse(format!(
                "{} is a symlink; give the real directory",
                out.display()
            )))
        }
        Ok(m) if !m.is_dir() => {
            return Err(refuse(format!("{} is not a directory", out.display())))
        }
        Ok(_) => {
            let marker_ok = fs::symlink_metadata(out.join(MARKER))
                .map(|m| m.is_file())
                .unwrap_or(false);
            let empty = fs::read_dir(out)?.next().is_none();
            if !marker_ok && !empty {
                return Err(refuse(format!(
                    "{} is not empty and was not rendered by --render-decoy; \
                     refusing to touch it",
                    out.display()
                )));
            }
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => fs::create_dir_all(out)?,
        Err(e) => return Err(e),
    }
    let site = render_site_for_seed(seed);
    // The marker goes first: an interrupted run can be repeated.
    write_atomic(out, MARKER, b"1\n")?;
    for (rel, bytes) in &site.files {
        let mut dir: PathBuf = out.to_path_buf();
        let mut parts: Vec<&str> = rel.split('/').collect();
        let name = parts.pop().unwrap_or_default();
        for part in parts {
            dir.push(part);
            ensure_real_dir(&dir)?;
        }
        write_atomic(&dir, name, bytes)?;
    }
    Ok(())
}
