//! Content-hashed asset names. GitHub Pages sets its own cache headers, so
//! the site makes caching safe by naming each script, stylesheet and WASM
//! module after its contents (`js/site.3f9a2c1b0d.js`): a changed file gets
//! a new name, and a cached one is never stale.
//!
//! [`fingerprint`] renames the assets and rewrites the references between
//! them (module imports and `new URL("…", import.meta.url)` in scripts);
//! [`rewrite_page`] rewrites a generated page's references. A file's hash
//! covers its rewritten text, so a change in a module it imports renames it
//! too. [`module_preloads`] adds a `modulepreload` link to a page for every
//! module its scripts import, so the browser fetches them in parallel
//! instead of one import level at a time. No I/O: the caller reads and
//! writes the files.

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

/// Each script's static imports (`import … from "…"`, `import "…"`), as
/// paths under the site root, for the scripts among `files`. Dynamic
/// `import()` and `new URL(…)` references are left out: they load on
/// demand.
pub fn module_imports(files: &Files) -> BTreeMap<String, Vec<String>> {
    let mut out = BTreeMap::new();
    for (path, bytes) in files {
        if !path.ends_with(".js") {
            continue;
        }
        let Ok(text) = std::str::from_utf8(bytes) else {
            continue;
        };
        let mut deps = Vec::new();
        let mut rest = text;
        while let Some(i) = rest.find("import") {
            let at_line_start = rest[..i]
                .rsplit('\n')
                .next()
                .is_some_and(|l| l.trim().is_empty());
            let after = &rest[i + "import".len()..];
            rest = after;
            let next = after.chars().next();
            if !at_line_start || !matches!(next, Some(' ' | '{' | '"' | '\'' | '*')) {
                continue;
            }
            // The statement runs to its semicolon; its last string literal
            // is the module.
            let stmt = &after[..after.find(';').unwrap_or(after.len())];
            let lit = stmt
                .rsplit(['"', '\''])
                .nth(1)
                .filter(|l| l.ends_with(".js"));
            if let Some(dep) = lit.and_then(|l| resolve(dir_of(path), l)) {
                deps.push(dep);
            }
        }
        out.insert(path.clone(), deps);
    }
    out
}

/// A generated page with a `modulepreload` link for every module its
/// module scripts import, directly or through other modules, written with
/// the same root prefix as the script that needs it. A module the page
/// already loads by its own script tag is not preloaded again. Run before
/// [`rewrite_page`], which hashes the new links' names too.
pub fn module_preloads(html: &str, imports: &BTreeMap<String, Vec<String>>) -> String {
    const TAG: &str = "<script type=\"module\" src=\"";
    let mut scripts: Vec<(String, String)> = Vec::new();
    let mut rest = html;
    while let Some(i) = rest.find(TAG) {
        let after = &rest[i + TAG.len()..];
        let Some(end) = after.find('"') else { break };
        let src = &after[..end];
        if let Some(j) = src.find("js/") {
            scripts.push((src[..j].to_string(), src[j..].to_string()));
        }
        rest = &after[end..];
    }
    let Some((prefix, _)) = scripts.first().cloned() else {
        return html.to_string();
    };
    let own: std::collections::BTreeSet<&str> = scripts.iter().map(|(_, p)| p.as_str()).collect();
    let mut seen = std::collections::BTreeSet::new();
    let mut stack: Vec<String> = scripts.iter().map(|(_, p)| p.clone()).collect();
    while let Some(m) = stack.pop() {
        for dep in imports.get(&m).into_iter().flatten() {
            if seen.insert(dep.clone()) {
                stack.push(dep.clone());
            }
        }
    }
    let links: String = seen
        .iter()
        .filter(|d| !own.contains(d.as_str()))
        .map(|d| format!("<link rel=\"modulepreload\" href=\"{prefix}{d}\">\n"))
        .collect();
    if links.is_empty() {
        return html.to_string();
    }
    match html.find(TAG) {
        Some(i) => format!("{}{links}{}", &html[..i], &html[i..]),
        None => html.to_string(),
    }
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
    fn pages_preload_every_module_their_scripts_import() {
        let files: Files = [
            ("js/site.js", "import { store } from \"./lib/dom.js\";\n"),
            ("js/lib/dom.js", "export const x = 1;\n"),
            ("js/lib/fmt.js", "export const y = 1;\n"),
            (
                "js/lib/charts.js",
                "import { el } from \"./dom.js\";\nimport {\n  fmt,\n} from './fmt.js';\n",
            ),
            (
                "js/pages/a.js",
                "// import nothing from \"x.js\" here\nimport { c } from \"../lib/charts.js\";\nconst m = await import(\"../../pkg/m.js\");\n",
            ),
        ]
        .iter()
        .map(|(p, t)| (p.to_string(), t.as_bytes().to_vec()))
        .collect();
        let imports = module_imports(&files);
        assert_eq!(
            imports["js/pages/a.js"],
            vec!["js/lib/charts.js".to_string()]
        );
        assert_eq!(
            imports["js/lib/charts.js"],
            vec!["js/lib/dom.js".to_string(), "js/lib/fmt.js".to_string()]
        );
        let page = "<head>\n<script type=\"module\" src=\"../js/site.js\"></script>\n<script type=\"module\" src=\"../js/pages/a.js\"></script>\n</head>";
        let html = module_preloads(page, &imports);
        for m in ["js/lib/charts.js", "js/lib/dom.js", "js/lib/fmt.js"] {
            assert_eq!(
                html.matches(&format!("<link rel=\"modulepreload\" href=\"../{m}\">"))
                    .count(),
                1,
                "{html}"
            );
        }
        assert!(
            !html.contains("pkg/m.js") && !html.contains("modulepreload\" href=\"../js/site.js")
        );
        assert!(html.find("modulepreload") < html.find("<script"));
        // Hashing renames the preloads with the scripts.
        let (_, names) = fingerprint(files);
        let out = rewrite_page(&html, &names);
        assert!(
            out.contains(&format!("href=\"../{}\"", names["js/lib/fmt.js"])),
            "{out}"
        );
        assert_eq!(
            module_preloads("<p>no scripts</p>", &imports),
            "<p>no scripts</p>"
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
