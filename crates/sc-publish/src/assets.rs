//! Content-hashed asset names. GitHub Pages sets its own cache headers, so
//! the site makes caching safe by naming each script, stylesheet and WASM
//! module after its contents (`js/site.3f9a2c1b0d.js`): a changed file gets
//! a new name, and a cached one is never stale.
//!
//! [`fingerprint`] renames the assets and rewrites the references between
//! them (module imports and `new URL("…", import.meta.url)` in scripts);
//! [`rewrite_page`] rewrites a generated page's references. A file's hash
//! covers its rewritten text, so a change in a module it imports renames it
//! too. No I/O: the caller reads and writes the files.

use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// Extensions that get a content-hashed name.
const HASHED: &[&str] = &[".js", ".css", ".wasm"];

/// Hex digits of the SHA-256 kept in a name.
const HASH_LEN: usize = 10;

fn is_hashed(path: &str) -> bool {
    HASHED.iter().any(|e| path.ends_with(e))
}

/// `js/lib/dom.js` with `abc` as `js/lib/dom.abc.js`.
fn hashed_name(path: &str, hash: &str) -> String {
    match path.rfind('.') {
        Some(i) if !path[i..].contains('/') => format!("{}.{hash}{}", &path[..i], &path[i..]),
        _ => format!("{path}.{hash}"),
    }
}

/// `base` (a file's directory, `a/b/`) joined with a relative reference,
/// `.` and `..` resolved; `None` when it climbs above the root or is not
/// relative.
fn resolve(dir: &str, rel: &str) -> Option<String> {
    if rel.starts_with('/') || rel.contains("://") || rel.contains(':') {
        return None;
    }
    let mut parts: Vec<&str> = dir.split('/').filter(|s| !s.is_empty()).collect();
    for seg in rel.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                parts.pop()?;
            }
            s => parts.push(s),
        }
    }
    Some(parts.join("/"))
}

fn dir_of(path: &str) -> &str {
    path.rfind('/').map_or("", |i| &path[..=i])
}

/// Every quoted string in `text` that names a hashed asset relative to
/// `path`, as (byte range of the string's contents, asset path).
fn references(
    path: &str,
    text: &str,
    assets: &BTreeMap<String, Vec<u8>>,
) -> Vec<(std::ops::Range<usize>, String)> {
    let mut out = Vec::new();
    let b = text.as_bytes();
    let mut i = 0;
    while i < b.len() {
        let q = b[i];
        if q == b'"' || q == b'\'' {
            let start = i + 1;
            let mut j = start;
            while j < b.len() && b[j] != q && b[j] != b'\n' {
                j += 1;
            }
            if j < b.len() && b[j] == q {
                let lit = &text[start..j];
                if is_hashed(lit)
                    && let Some(target) = resolve(dir_of(path), lit)
                    && assets.contains_key(&target)
                {
                    out.push((start..j, target));
                }
                i = j + 1;
                continue;
            }
        }
        i += 1;
    }
    out
}

/// Files as (path under the site root, contents).
pub type Files = Vec<(String, Vec<u8>)>;

/// Rename every script, stylesheet and WASM module among `files` to its
/// content-hashed name, rewriting the references scripts make to each
/// other. Other files pass through. Returns the renamed set and the map
/// from old path to new.
pub fn fingerprint(files: Files) -> (Files, BTreeMap<String, String>) {
    let mut assets: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    let mut out = Vec::new();
    for (p, bytes) in files {
        if is_hashed(&p) {
            assets.insert(p, bytes);
        } else {
            out.push((p, bytes));
        }
    }
    let mut names: BTreeMap<String, String> = BTreeMap::new();
    let mut done: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    let keys: Vec<String> = assets.keys().cloned().collect();
    for k in &keys {
        visit(k, &assets, &mut names, &mut done, &mut Vec::new());
    }
    for (old, bytes) in done {
        out.push((names[&old].clone(), bytes));
    }
    (out, names)
}

/// Hash `path` after its dependencies, depth first. A reference cycle is
/// left unrewritten at the point it closes.
fn visit(
    path: &str,
    assets: &BTreeMap<String, Vec<u8>>,
    names: &mut BTreeMap<String, String>,
    done: &mut BTreeMap<String, Vec<u8>>,
    stack: &mut Vec<String>,
) {
    if names.contains_key(path) || stack.iter().any(|s| s == path) {
        return;
    }
    stack.push(path.to_string());
    let bytes = &assets[path];
    let rewritten = if path.ends_with(".js") || path.ends_with(".css") {
        match std::str::from_utf8(bytes) {
            Ok(text) => {
                let refs = references(path, text, assets);
                for (_, dep) in &refs {
                    visit(dep, assets, names, done, stack);
                }
                let mut s = String::with_capacity(text.len() + 64);
                let mut last = 0;
                for (range, dep) in refs {
                    let Some(new) = names.get(&dep) else { continue };
                    let lit = &text[range.clone()];
                    // Keep the reference's own directory part; swap the name.
                    let base = &new[new.rfind('/').map_or(0, |i| i + 1)..];
                    s.push_str(&text[last..range.start]);
                    s.push_str(dir_of(lit));
                    s.push_str(base);
                    last = range.end;
                }
                s.push_str(&text[last..]);
                s.into_bytes()
            }
            Err(_) => bytes.clone(),
        }
    } else {
        bytes.clone()
    };
    let digest = Sha256::digest(&rewritten);
    let hash: String = digest
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>()[..HASH_LEN]
        .to_string();
    names.insert(path.to_string(), hashed_name(path, &hash));
    done.insert(path.to_string(), rewritten);
    stack.pop();
}

/// A generated page with its asset references (`…/css/site.css"`, written
/// from the page's root prefix) pointed at the hashed names.
pub fn rewrite_page(html: &str, names: &BTreeMap<String, String>) -> String {
    let mut s = html.to_string();
    for (old, new) in names {
        // A doc's link to the source file on GitHub keeps its name.
        let source = format!("/blob/main/site/{old}\"");
        let kept = "\u{0}source-link\u{0}";
        s = s
            .replace(&source, kept)
            .replace(&format!("/{old}\""), &format!("/{new}\""))
            .replace(kept, &source);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn files() -> Vec<(String, Vec<u8>)> {
        [
            ("css/site.css", "body{}"),
            ("js/lib/dom.js", "export const x = 1;"),
            (
                "js/pages/a.js",
                "import { x } from \"../lib/dom.js\";\nconst m = new URL('../../pkg/m.js', import.meta.url);\nconst s = \"not/a/file.js\";",
            ),
            ("pkg/m.js", "new URL('m_bg.wasm', import.meta.url)"),
            ("pkg/m_bg.wasm", "\0asm"),
            ("favicon.svg", "<svg/>"),
        ]
        .iter()
        .map(|(p, t)| (p.to_string(), t.as_bytes().to_vec()))
        .collect()
    }

    #[test]
    fn assets_get_hashed_names_and_references_follow() {
        let (out, names) = fingerprint(files());
        let get = |p: &str| {
            let n = names.get(p).map_or(p, String::as_str);
            String::from_utf8(out.iter().find(|(q, _)| q == n).unwrap().1.clone()).unwrap()
        };
        assert_eq!(names.len(), 5);
        assert!(!names.contains_key("favicon.svg"));
        let dom = &names["js/lib/dom.js"];
        assert!(
            dom.starts_with("js/lib/dom.")
                && dom.ends_with(".js")
                && dom.len() == "js/lib/dom..js".len() + HASH_LEN,
            "{dom}"
        );
        let a = get("js/pages/a.js");
        assert!(
            a.contains(&format!("\"../lib/{}\"", &dom["js/lib/".len()..])),
            "{a}"
        );
        assert!(a.contains(&format!("'../../{}'", names["pkg/m.js"])), "{a}");
        assert!(a.contains("\"not/a/file.js\""), "{a}");
        let m = get("pkg/m.js");
        assert!(
            m.contains(&format!("'{}'", &names["pkg/m_bg.wasm"]["pkg/".len()..])),
            "{m}"
        );

        // A change in a dependency renames its importers too.
        let mut changed = files();
        changed[1].1 = b"export const x = 2;".to_vec();
        let (_, again) = fingerprint(changed);
        assert_ne!(again["js/lib/dom.js"], names["js/lib/dom.js"]);
        assert_ne!(again["js/pages/a.js"], names["js/pages/a.js"]);
        assert_eq!(again["pkg/m.js"], names["pkg/m.js"]);

        let page = "<link rel=\"stylesheet\" href=\"../css/site.css\"><script src=\"/base/js/pages/a.js\"></script>";
        let html = rewrite_page(page, &names);
        assert!(
            html.contains(&format!("\"../{}\"", names["css/site.css"])),
            "{html}"
        );
        assert!(
            html.contains(&format!("\"/base/{}\"", names["js/pages/a.js"])),
            "{html}"
        );
    }

    #[test]
    fn references_resolve_within_the_root() {
        assert_eq!(
            resolve("js/pages/", "../lib/dom.js").as_deref(),
            Some("js/lib/dom.js")
        );
        assert_eq!(resolve("", "../x.js"), None);
        assert_eq!(resolve("js/", "https://x/y.js"), None);
        assert_eq!(hashed_name("js/site.js", "ab"), "js/site.ab.js");
    }
}
