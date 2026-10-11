//! Building the public site into a directory: the one entry both `sc-site`
//! and `swarmchase site build` call.
//!
//! Reads only `notices/*.md`, `docs/**/*.md`, `rules/default.toml`,
//! `samples/eval/*.ndjson`, `samples/eval/coverage-allow.txt`,
//! `samples/showcase/*.ndjson` and the static files in `site/` (with the
//! WASM modules `scripts/ci/build-site.sh` builds into `site/pkg`). It refuses any path under `data/` or
//! `$SWARMCHASE_DATA`: watch data and case files never reach the site.
//! Unlike the rest of this crate it reads and writes files; it never touches
//! the network.

use crate::{SiteInputs, build_pages, check_notice, parse_notice};
use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

/// What to build, and where.
#[derive(Debug, Clone)]
pub struct BuildOptions {
    /// The output directory. Replaced if it holds an earlier build.
    pub out: PathBuf,
    pub base_url: String,
    /// The repository root.
    pub root: PathBuf,
    /// Write the list of every file read here, for
    /// `scripts/ci/check-site.py --inputs`.
    pub inputs_log: Option<PathBuf>,
    /// Notice files from another directory (the XSS check's hostile
    /// fixture). A deploy never sets it.
    pub extra_notices: Option<PathBuf>,
}

impl Default for BuildOptions {
    fn default() -> Self {
        Self {
            out: PathBuf::from("_site"),
            base_url: "http://localhost:8080/".into(),
            root: PathBuf::from("."),
            inputs_log: None,
            extra_notices: None,
        }
    }
}

/// What a build wrote.
#[derive(Debug, Clone)]
pub struct Built {
    pub generated: usize,
    pub copied: usize,
    pub notices: usize,
    pub out: PathBuf,
    pub warnings: Vec<String>,
}

/// Repository paths the build may read: a prefix and the extension its
/// files must have.
const INPUTS: &[(&str, &str)] = &[
    ("notices/", ".md"),
    ("docs/", ".md"),
    ("rules/default.toml", ".toml"),
    ("samples/eval/", ".ndjson"),
    ("samples/eval/coverage-allow.txt", ".txt"),
    ("samples/showcase/", ".ndjson"),
    ("site/", ""),
];

struct Reader {
    root: PathBuf,
    data_dirs: Vec<PathBuf>,
    /// Files git tracks, when the root is a checkout. Content listings skip
    /// anything else, so ignored local files never become pages.
    tracked: Option<HashSet<String>>,
    log: Vec<String>,
}

impl Reader {
    fn new(root: &Path) -> Result<Self, String> {
        let root = root
            .canonicalize()
            .map_err(|e| format!("{}: {e}", root.display()))?;
        let mut data_dirs = vec![root.join("data")];
        if let Ok(d) = std::env::var("SWARMCHASE_DATA") {
            let p = PathBuf::from(&d);
            let p = if p.is_absolute() { p } else { root.join(p) };
            data_dirs.push(p.canonicalize().unwrap_or(p));
        }
        let tracked = git_tracked(&root);
        Ok(Self {
            root,
            data_dirs,
            tracked,
            log: Vec::new(),
        })
    }

    /// Refuse anything outside the allowed inputs or inside a data directory.
    fn allow(&self, rel: &str, abs: &Path) -> Result<(), String> {
        let canon = abs.canonicalize().unwrap_or_else(|_| abs.to_path_buf());
        if self.data_dirs.iter().any(|d| canon.starts_with(d)) {
            return Err(format!(
                "{rel}: inside a data directory; the site reads committed inputs only"
            ));
        }
        if !canon.starts_with(&self.root) {
            return Err(format!("{rel}: outside the repository"));
        }
        let ok = INPUTS.iter().any(|(prefix, ext)| {
            (rel == *prefix || rel.starts_with(prefix)) && (ext.is_empty() || rel.ends_with(ext))
        });
        if !ok || rel.split('/').any(|s| s == "..") {
            return Err(format!("{rel}: not a site input"));
        }
        Ok(())
    }

    fn read(&mut self, rel: &str) -> Result<String, String> {
        let abs = self.root.join(rel);
        self.allow(rel, &abs)?;
        let text = fs::read_to_string(&abs).map_err(|e| format!("{rel}: {e}"))?;
        self.log.push(rel.to_string());
        Ok(text)
    }

    /// Files under `dir` (repository-relative) with `ext`, sorted;
    /// recursive when `deep`; only files git tracks when `tracked_only`.
    fn list(&self, dir: &str, ext: &str, deep: bool, tracked_only: bool) -> Vec<String> {
        let mut out = Vec::new();
        let mut stack = vec![dir.trim_end_matches('/').to_string()];
        while let Some(d) = stack.pop() {
            let Ok(entries) = fs::read_dir(self.root.join(&d)) else {
                continue;
            };
            for e in entries.flatten() {
                let name = e.file_name().to_string_lossy().to_string();
                let rel = format!("{d}/{name}");
                let Ok(ft) = e.file_type() else { continue };
                if ft.is_dir() && deep && !name.starts_with('.') {
                    stack.push(rel);
                } else if ft.is_file()
                    && name.ends_with(ext)
                    && (!tracked_only || self.tracked.as_ref().is_none_or(|t| t.contains(&rel)))
                {
                    out.push(rel);
                }
            }
        }
        out.sort();
        out
    }
}

/// Repository-relative paths git tracks under `root`, or `None` when `root`
/// is not a checkout or git is unavailable.
fn git_tracked(root: &Path) -> Option<HashSet<String>> {
    let out = std::process::Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["ls-files", "-z"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    Some(
        String::from_utf8_lossy(&out.stdout)
            .split('\0')
            .filter(|p| !p.is_empty())
            .map(str::to_string)
            .collect(),
    )
}

/// Copy `site/` into the output with content-hashed script, style and WASM
/// names ([`crate::assets`]); returns the file count and the renames.
fn copy_static(r: &mut Reader, out: &Path) -> Result<(usize, BTreeMap<String, String>), String> {
    let mut files = Vec::new();
    for rel in r.list("site", "", true, false) {
        let sub = rel["site/".len()..].to_string();
        // Notice files from an older `notice build --out site/notices`.
        if sub.starts_with("notices/") {
            continue;
        }
        let abs = r.root.join(&rel);
        r.allow(&rel, &abs)?;
        files.push((sub, fs::read(&abs).map_err(|e| format!("{rel}: {e}"))?));
        r.log.push(rel);
    }
    let (files, names) = crate::assets::fingerprint(files);
    for (sub, bytes) in &files {
        let dest = out.join(sub);
        if let Some(p) = dest.parent() {
            fs::create_dir_all(p).map_err(|e| format!("{}: {e}", p.display()))?;
        }
        fs::write(&dest, bytes).map_err(|e| format!("{}: {e}", dest.display()))?;
    }
    Ok((files.len(), names))
}

/// Build the site from the committed inputs under `o.root` into `o.out`.
pub fn build_site_dir(o: &BuildOptions) -> Result<Built, String> {
    let mut r = Reader::new(&o.root)?;
    if !r.root.join("rules/default.toml").is_file() {
        return Err(format!("{} is not the repository root", r.root.display()));
    }

    let mut notices = Vec::new();
    let rules_toml = r.read("rules/default.toml")?;
    let rules = sc_core::Rules::from_toml(&rules_toml)?;
    for rel in r.list("notices", ".md", false, true) {
        if rel.eq_ignore_ascii_case("notices/README.md") {
            continue;
        }
        let n = parse_notice(&r.read(&rel)?).map_err(|e| format!("{rel}: {e}"))?;
        let stem = rel.trim_start_matches("notices/").trim_end_matches(".md");
        if stem != n.meta.id {
            return Err(format!(
                "{rel}: file name does not match id `{}`",
                n.meta.id
            ));
        }
        let problems = check_notice(&n, &rules);
        if !problems.is_empty() {
            return Err(format!("{rel}: {}", problems.join("; ")));
        }
        notices.push(n);
    }
    if let Some(dir) = &o.extra_notices {
        for e in fs::read_dir(dir).map_err(|e| format!("{}: {e}", dir.display()))? {
            let p = e.map_err(|e| e.to_string())?.path();
            if p.extension().is_some_and(|x| x == "md") {
                let text = fs::read_to_string(&p).map_err(|e| format!("{}: {e}", p.display()))?;
                notices.push(parse_notice(&text).map_err(|e| format!("{}: {e}", p.display()))?);
            }
        }
    }
    let mut docs = Vec::new();
    for rel in r.list("docs", ".md", true, true) {
        let text = r.read(&rel)?;
        docs.push((rel, text));
    }
    let mut eval_set = Vec::new();
    for rel in r.list("samples/eval", ".ndjson", false, true) {
        let text = r.read(&rel)?;
        eval_set.push((rel.trim_start_matches("samples/eval/").to_string(), text));
    }
    let coverage_allow = if r.root.join("samples/eval/coverage-allow.txt").is_file() {
        r.read("samples/eval/coverage-allow.txt")?
    } else {
        String::new()
    };
    let showcase = r.read("samples/showcase/showcase.ndjson")?;
    // A module's download size: the host serves it gzip-compressed.
    let size = |p: &str| fs::read(r.root.join(p)).ok().map(|b| gzip_len(&b));
    let engine_bytes = size("site/pkg/sc_wasm_bg.wasm");
    let tools_bytes = size("site/pkg/tools/sc_tools_bg.wasm");
    let mut inputs = SiteInputs {
        notices,
        docs,
        rules_toml,
        eval_set,
        coverage_allow,
        showcase,
        base_url: o.base_url.clone(),
        repo: env!("CARGO_PKG_REPOSITORY").to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        engine_bytes,
        tools_bytes,
    };
    let files = build_pages(&mut inputs)?;

    // Start from an empty output directory, but never delete one this tool
    // did not write.
    let out = if o.out.is_absolute() {
        o.out.clone()
    } else {
        std::env::current_dir()
            .map_err(|e| e.to_string())?
            .join(&o.out)
    };
    let out_canon = out.canonicalize().unwrap_or_else(|_| out.clone());
    if out_canon == r.root
        || out_canon.starts_with(r.root.join("site"))
        || r.data_dirs.iter().any(|d| out_canon.starts_with(d))
    {
        return Err(format!("--out {} would overwrite inputs", out.display()));
    }
    if out.exists() {
        let ours = out.join("sitemap.xml").is_file();
        let empty = fs::read_dir(&out)
            .map(|mut d| d.next().is_none())
            .unwrap_or(false);
        if !ours && !empty {
            return Err(format!(
                "{} exists and is not a site build; remove it or pick another --out",
                out.display()
            ));
        }
        fs::remove_dir_all(&out).map_err(|e| format!("{}: {e}", out.display()))?;
    }
    fs::create_dir_all(&out).map_err(|e| format!("{}: {e}", out.display()))?;
    let (copied, names) = copy_static(&mut r, &out)?;
    for (path, text) in &files {
        let dest = out.join(path);
        if let Some(p) = dest.parent() {
            fs::create_dir_all(p).map_err(|e| format!("{}: {e}", p.display()))?;
        }
        let text = if path.ends_with(".html") {
            crate::assets::rewrite_page(text, &names)
        } else {
            text.clone()
        };
        fs::write(&dest, text).map_err(|e| format!("{}: {e}", dest.display()))?;
    }
    let mut warnings = Vec::new();
    if !r.root.join("site/pkg/sc_wasm.js").is_file() {
        warnings.push(
            "site/pkg is missing; run scripts/ci/build-site.sh for the analysis pages".to_string(),
        );
    }
    if let Some(log) = &o.inputs_log {
        let mut text = r.log.join("\n");
        text.push('\n');
        fs::write(log, text).map_err(|e| format!("{}: {e}", log.display()))?;
    }
    Ok(Built {
        generated: files.len(),
        copied,
        notices: inputs.notices.len(),
        out,
        warnings,
    })
}

/// The length of `bytes` gzip-compressed at the default level.
fn gzip_len(bytes: &[u8]) -> u64 {
    use std::io::Write;
    let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    let _ = e.write_all(bytes);
    e.finish().map_or(bytes.len(), |v| v.len()) as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    fn repo() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
    }

    #[test]
    fn builds_the_checkout_and_refuses_to_overwrite_inputs() {
        let out = std::env::temp_dir().join(format!("sc-publish-build-{}", std::process::id()));
        let _ = fs::remove_dir_all(&out);
        let o = BuildOptions {
            out: out.clone(),
            root: repo(),
            ..Default::default()
        };
        let built = build_site_dir(&o).unwrap();
        assert!(built.generated > 0 && out.join("sitemap.xml").is_file());
        // A rebuild replaces its own earlier output.
        build_site_dir(&o).unwrap();
        // Never into the inputs, never over a directory it did not write.
        let into_site = BuildOptions {
            out: repo().join("site"),
            ..o.clone()
        };
        assert!(build_site_dir(&into_site).is_err());
        fs::remove_file(out.join("sitemap.xml")).unwrap();
        assert!(build_site_dir(&o).is_err());
        fs::remove_dir_all(&out).unwrap();
    }
}
