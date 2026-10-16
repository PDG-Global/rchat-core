//! Tests for per-relay decoy sites (spec §D.2).

use crate::decoy_render::*;
use std::collections::HashSet;
use std::fs;
use std::path::Path;

fn tree(dir: &Path) -> Vec<(String, Vec<u8>)> {
    fn walk(base: &Path, dir: &Path, out: &mut Vec<(String, Vec<u8>)>) {
        for e in fs::read_dir(dir).unwrap() {
            let e = e.unwrap();
            let p = e.path();
            if e.file_type().unwrap().is_dir() {
                walk(base, &p, out);
            } else {
                out.push((
                    p.strip_prefix(base).unwrap().to_string_lossy().into_owned(),
                    fs::read(&p).unwrap(),
                ));
            }
        }
    }
    let mut v = Vec::new();
    walk(dir, dir, &mut v);
    v.sort();
    v
}

fn all_text(site: &Site) -> Vec<(&'static str, String)> {
    site.files
        .iter()
        .map(|(p, b)| (*p, String::from_utf8(b.clone()).unwrap()))
        .collect()
}

#[test]
fn same_host_twice_is_byte_identical_and_host_is_normalised() {
    let t = crate::ScratchDir::new("decoy-det");
    render_decoy("chat.example.com", &t.join("a")).unwrap();
    render_decoy("chat.example.com", &t.join("b")).unwrap();
    render_decoy("  Chat.Example.COM.. ", &t.join("c")).unwrap();
    let a = tree(&t.join("a"));
    assert_eq!(a, tree(&t.join("b")));
    assert_eq!(
        a,
        tree(&t.join("c")),
        "case and trailing dots are normalised"
    );
    // Re-rendering in place is also identical.
    render_decoy("chat.example.com", &t.join("a")).unwrap();
    assert_eq!(a, tree(&t.join("a")));
    assert!(a.iter().any(|(p, _)| p == "index.html"));
    assert!(a.iter().any(|(p, _)| p == "assets/style.css"));
}

#[test]
fn different_hosts_differ_and_cover_every_product() {
    let a = render_site("one.example.com");
    let b = render_site("two.example.com");
    assert_ne!(a.files, b.files);
    let mut products = HashSet::new();
    let mut brands = HashSet::new();
    let mut bytes = HashSet::new();
    for i in 0..200 {
        let s = render_site(&format!("relay-{i}.example.net"));
        products.insert(s.product);
        let html = String::from_utf8(s.get("index.html").unwrap().to_vec()).unwrap();
        brands.insert(
            html.split("<h1>")
                .nth(1)
                .unwrap()
                .split("</h1>")
                .next()
                .unwrap()
                .to_string(),
        );
        bytes.insert(s.files.clone());
    }
    assert_eq!(products.len(), 5, "all five products appear");
    assert!(brands.len() >= 30, "brands vary: {}", brands.len());
    assert_eq!(bytes.len(), 200, "no two hosts serve identical bytes");
}

#[test]
fn seed_is_sha256_of_the_normalised_host() {
    use sha2::{Digest, Sha256};
    let want: [u8; 32] = Sha256::digest(b"chat.example.com").into();
    assert_eq!(seed_for("Chat.Example.com."), want);
    assert_eq!(normalize_host(" A.B. "), "a.b");
}

fn every_site() -> Vec<Site> {
    let mut v = Vec::new();
    for h in ["a.example.com", "b.example.org", "c.example.net"] {
        for p in Product::ALL {
            v.push(render_site_with(h, Some(p)));
        }
    }
    v
}

#[test]
fn no_unreplaced_placeholders() {
    for site in every_site() {
        for (p, t) in all_text(&site) {
            assert!(
                !t.contains("{{"),
                "{:?} {p} has a placeholder",
                site.product
            );
        }
    }
}

#[test]
fn no_external_fetches() {
    for site in every_site() {
        for (p, t) in all_text(&site) {
            // The SVG namespace is an identifier, not a fetch. Case-insensitive.
            let t = t
                .to_ascii_lowercase()
                .replace("xmlns=\"http://www.w3.org/2000/svg\"", "");
            for bad in [
                "http://", "https://", "//cdn", "@import", "src=\"//", "url(//",
            ] {
                assert!(!t.contains(bad), "{:?} {p} contains {bad}", site.product);
            }
            // Every src/href is a local path or a fragment.
            for attr in ["src=\"", "href=\""] {
                for part in t.split(attr).skip(1) {
                    let v = part.split('"').next().unwrap();
                    assert!(
                        v.starts_with('/') || v == "#",
                        "{:?} {p}: {attr}{v}",
                        site.product
                    );
                    assert!(!v.starts_with("//"));
                }
            }
        }
    }
}

#[test]
fn forms_never_submit_and_show_a_generic_error() {
    for site in every_site() {
        let html = String::from_utf8(site.get("index.html").unwrap().to_vec()).unwrap();
        let forms: Vec<&str> = html.split("<form").skip(1).collect();
        assert!(!forms.is_empty(), "{:?} has a login form", site.product);
        for f in forms {
            let tag = f.split('>').next().unwrap();
            assert!(tag.contains("onsubmit=\"return false\""), "{tag}");
            assert!(!tag.contains("action="), "{tag}");
        }
        assert!(html
            .to_ascii_lowercase()
            .contains("incorrect username or password"));
        assert!(html.contains("<input type=\"password\""));
    }
}

#[test]
fn contains_no_secret_or_identifying_text() {
    let ws_path = "/s3cr3t-LONG-random-path-9f8e7d";
    let version = env!("CARGO_PKG_VERSION");
    let t = crate::ScratchDir::new("decoy-secret");
    for i in 0..120 {
        let host = format!("relay-{i}.example.com");
        for site in [render_site(&host)]
            .into_iter()
            .chain(Product::ALL.map(|p| render_site_with(&host, Some(p))))
        {
            for (p, text) in all_text(&site) {
                let low = text.to_ascii_lowercase();
                assert!(!text.contains(ws_path), "{p}");
                assert!(!low.contains("rchat"), "{p}");
                assert!(
                    !text.contains(version),
                    "{:?} {p} contains the crate version",
                    site.product
                );
                assert!(!low.contains(&host), "{p} contains the host name");
            }
        }
    }
    render_decoy("x.example.com", &t.join("o")).unwrap();
    for (p, b) in tree(&t.join("o")) {
        let low = String::from_utf8_lossy(&b).to_ascii_lowercase();
        assert!(!low.contains("rchat"), "{p}");
    }
    let marker = fs::read_to_string(t.join("o").join(MARKER)).unwrap();
    assert!(!marker.to_ascii_lowercase().contains("rchat"));
}

#[test]
fn refuses_a_non_empty_directory_that_was_not_rendered_by_us() {
    let t = crate::ScratchDir::new("decoy-refuse");
    let d = t.join("data");
    fs::create_dir(&d).unwrap();
    fs::write(d.join("precious.txt"), b"keep me").unwrap();
    fs::write(d.join("index.html"), b"mine").unwrap();
    let err = render_decoy("h.example.com", &d).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    assert_eq!(fs::read(d.join("precious.txt")).unwrap(), b"keep me");
    assert_eq!(fs::read(d.join("index.html")).unwrap(), b"mine");
    assert!(!d.join(MARKER).exists());
    // A regular file, an empty host, and a symlinked out are refused.
    fs::write(t.join("file"), b"x").unwrap();
    assert!(render_decoy("h.example.com", &t.join("file")).is_err());
    assert!(render_decoy("  . ", &t.join("fresh")).is_err());
    assert!(!t.join("fresh").exists());
}

#[test]
fn accepts_empty_and_missing_and_previously_rendered_directories() {
    let t = crate::ScratchDir::new("decoy-ok");
    let e = t.join("empty");
    fs::create_dir(&e).unwrap();
    render_decoy("one.example.com", &e).unwrap();
    render_decoy("two.example.com", &e).unwrap();
    render_decoy("two.example.com", &t.join("deep").join("er")).unwrap();
    assert_eq!(tree(&e), tree(&t.join("deep").join("er")));
    // No temp files are left behind.
    assert!(tree(&e).iter().all(|(p, _)| !p.contains(".tmp")));
}

#[cfg(unix)]
#[test]
fn never_follows_symlinks_out_of_the_output_directory() {
    use std::os::unix::fs::symlink;
    let t = crate::ScratchDir::new("decoy-symlink");
    let outside = t.join("outside");
    fs::create_dir(&outside).unwrap();
    fs::write(outside.join("target"), b"untouched").unwrap();

    // `out` itself a symlink.
    symlink(&outside, t.join("link")).unwrap();
    assert!(render_decoy("h.example.com", &t.join("link")).is_err());
    assert_eq!(fs::read_dir(&outside).unwrap().count(), 1);

    // `assets` a symlink to elsewhere.
    let o = t.join("o");
    render_decoy("h.example.com", &o).unwrap();
    fs::remove_dir_all(o.join("assets")).unwrap();
    symlink(&outside, o.join("assets")).unwrap();
    assert!(render_decoy("h.example.com", &o).is_err());
    assert_eq!(fs::read_dir(&outside).unwrap().count(), 1);

    // A file that is a symlink is replaced, not written through.
    let o2 = t.join("o2");
    render_decoy("h.example.com", &o2).unwrap();
    fs::remove_file(o2.join("index.html")).unwrap();
    symlink(outside.join("target"), o2.join("index.html")).unwrap();
    render_decoy("h.example.com", &o2).unwrap();
    assert_eq!(fs::read(outside.join("target")).unwrap(), b"untouched");
    assert!(!fs::symlink_metadata(o2.join("index.html"))
        .unwrap()
        .file_type()
        .is_symlink());

    // A marker that is a symlink does not make a directory ours.
    let o3 = t.join("o3");
    fs::create_dir(&o3).unwrap();
    fs::write(o3.join("x"), b"x").unwrap();
    symlink(outside.join("target"), o3.join(MARKER)).unwrap();
    assert!(render_decoy("h.example.com", &o3).is_err());
}

#[cfg(unix)]
#[test]
fn a_symlink_to_an_empty_directory_is_refused() {
    let t = crate::ScratchDir::new("decoy-emptylink");
    let real = t.join("real");
    fs::create_dir(&real).unwrap();
    std::os::unix::fs::symlink(&real, t.join("link")).unwrap();
    assert!(render_decoy("h.example.com", &t.join("link")).is_err());
    assert_eq!(fs::read_dir(&real).unwrap().count(), 0);
}

#[test]
fn seeded_rendering_is_deterministic_and_seed_dependent() {
    let (a, b) = (render_site_for_seed([1; 32]), render_site_for_seed([2; 32]));
    assert_eq!(a.files, render_site_for_seed([1; 32]).files);
    assert_eq!(a.mtime, render_site_for_seed([1; 32]).mtime);
    assert_ne!(a.files, b.files);
    // The host path is the seed path with SHA-256(host).
    assert_eq!(
        render_site("x.example.com").files,
        render_site_for_seed(seed_for("x.example.com")).files
    );
    let t = crate::ScratchDir::new("decoy-seeded");
    render_decoy_seeded([1; 32], &t.join("o")).unwrap();
    assert_eq!(
        tree(&t.join("o"))
            .iter()
            .find(|(p, _)| p == "index.html")
            .unwrap()
            .1,
        a.get("index.html").unwrap()
    );
}

#[test]
fn nas_models_never_look_like_vendor_skus() {
    for i in 0..400 {
        let s = render_site_with(&format!("n{i}.example.com"), Some(Product::Nas));
        let html = String::from_utf8(s.get("index.html").unwrap().to_vec()).unwrap();
        let model = html
            .split("<dd>")
            .nth(1)
            .unwrap()
            .split("</dd>")
            .next()
            .unwrap();
        for bad in ["DS", "RS", "TS", "TVS", "DX", "QX", "VS", "NS", "TX"] {
            assert!(!model.starts_with(bad), "{model}");
        }
    }
    for p in Product::ALL {
        let html = String::from_utf8(
            render_site_with("a.example.com", Some(p))
                .get("index.html")
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        assert!(!html.contains("Snapdragon") && !html.contains("Smithy"));
    }
}
