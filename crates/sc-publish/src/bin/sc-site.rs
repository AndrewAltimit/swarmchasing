//! `sc-site`: build the public site from committed inputs.
//!
//! ```text
//! sc-site [--out _site] [--base-url URL] [--root .] [--inputs-log FILE]
//!         [--extra-notices DIR]
//! ```
//!
//! Reads only `notices/*.md`, `docs/**/*.md`, `rules/default.toml`,
//! `samples/eval/*.ndjson`, `samples/eval/coverage-allow.txt` and the static files in `site/` (with the WASM
//! package `scripts/ci/build-site.sh` builds into `site/pkg`). It refuses any
//! path under `data/` or `$SWARMCHASE_DATA`: watch data and case files never
//! reach the site. `--inputs-log` lists every file read, for
//! `scripts/ci/check-site.py --inputs` to check against git.
//! `--extra-notices` adds notice files from another directory; the XSS check
//! uses it for a hostile fixture, and a deploy never passes it.

use sc_publish::{SiteInputs, build_pages, check_notice, parse_notice};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

/// Repository paths the build may read: a prefix and the extension its
/// files must have.
const INPUTS: &[(&str, &str)] = &[
    ("notices/", ".md"),
    ("docs/", ".md"),
    ("rules/default.toml", ".toml"),
    ("samples/eval/", ".ndjson"),
    ("samples/eval/coverage-allow.txt", ".txt"),
    ("site/", ""),
];

struct Reader {
    root: PathBuf,
    data_dirs: Vec<PathBuf>,
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
        Ok(Self {
            root,
            data_dirs,
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
    /// recursive when `deep`.
    fn list(&self, dir: &str, ext: &str, deep: bool) -> Vec<String> {
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
                } else if ft.is_file() && name.ends_with(ext) {
                    out.push(rel);
                }
            }
        }
        out.sort();
        out
    }
}

fn copy_static(r: &mut Reader, out: &Path) -> Result<usize, String> {
    let mut n = 0;
    for rel in r.list("site", "", true) {
        let sub = &rel["site/".len()..];
        // Notice files from an older `notice build --out site/notices`.
        if sub.starts_with("notices/") {
            continue;
        }
        let abs = r.root.join(&rel);
        r.allow(&rel, &abs)?;
        let dest = out.join(sub);
        if let Some(p) = dest.parent() {
            fs::create_dir_all(p).map_err(|e| format!("{}: {e}", p.display()))?;
        }
        fs::copy(&abs, &dest).map_err(|e| format!("{rel}: {e}"))?;
        r.log.push(rel);
        n += 1;
    }
    Ok(n)
}

fn run() -> Result<(), String> {
    let mut out = PathBuf::from("_site");
    let mut base = "http://localhost:8080/".to_string();
    let mut root = PathBuf::from(".");
    let mut inputs_log: Option<PathBuf> = None;
    let mut extra: Option<PathBuf> = None;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        let mut val = || args.next().ok_or(format!("{a} needs a value"));
        match a.as_str() {
            "--out" => out = PathBuf::from(val()?),
            "--base-url" => base = val()?,
            "--root" => root = PathBuf::from(val()?),
            "--inputs-log" => inputs_log = Some(PathBuf::from(val()?)),
            "--extra-notices" => extra = Some(PathBuf::from(val()?)),
            "-h" | "--help" => {
                println!(
                    "sc-site [--out _site] [--base-url URL] [--root .] [--inputs-log FILE] [--extra-notices DIR]"
                );
                return Ok(());
            }
            _ => return Err(format!("unknown argument {a}")),
        }
    }
    let mut r = Reader::new(&root)?;
    if !r.root.join("rules/default.toml").is_file() {
        return Err(format!("{} is not the repository root", r.root.display()));
    }

    let mut notices = Vec::new();
    let rules_toml = r.read("rules/default.toml")?;
    let rules = sc_core::Rules::from_toml(&rules_toml)?;
    for rel in r.list("notices", ".md", false) {
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
    if let Some(dir) = &extra {
        for e in fs::read_dir(dir).map_err(|e| format!("{}: {e}", dir.display()))? {
            let p = e.map_err(|e| e.to_string())?.path();
            if p.extension().is_some_and(|x| x == "md") {
                let text = fs::read_to_string(&p).map_err(|e| format!("{}: {e}", p.display()))?;
                notices.push(parse_notice(&text).map_err(|e| format!("{}: {e}", p.display()))?);
            }
        }
    }
    let mut docs = Vec::new();
    for rel in r.list("docs", ".md", true) {
        let text = r.read(&rel)?;
        docs.push((rel, text));
    }
    let mut eval_set = Vec::new();
    for rel in r.list("samples/eval", ".ndjson", false) {
        let text = r.read(&rel)?;
        eval_set.push((rel.trim_start_matches("samples/eval/").to_string(), text));
    }
    let coverage_allow = if r.root.join("samples/eval/coverage-allow.txt").is_file() {
        r.read("samples/eval/coverage-allow.txt")?
    } else {
        String::new()
    };
    let engine_bytes = fs::metadata(r.root.join("site/pkg/sc_wasm_bg.wasm"))
        .ok()
        .map(|m| m.len());
    let mut inputs = SiteInputs {
        notices,
        docs,
        rules_toml,
        eval_set,
        coverage_allow,
        base_url: base,
        repo: env!("CARGO_PKG_REPOSITORY").to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        engine_bytes,
    };
    let files = build_pages(&mut inputs)?;

    // Start from an empty output directory, but never delete one this tool
    // did not write.
    let out = if out.is_absolute() {
        out
    } else {
        std::env::current_dir()
            .map_err(|e| e.to_string())?
            .join(out)
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
    let copied = copy_static(&mut r, &out)?;
    for (path, text) in &files {
        let dest = out.join(path);
        if let Some(p) = dest.parent() {
            fs::create_dir_all(p).map_err(|e| format!("{}: {e}", p.display()))?;
        }
        fs::write(&dest, text).map_err(|e| format!("{}: {e}", dest.display()))?;
    }
    if !r.root.join("site/pkg/sc_wasm.js").is_file() {
        eprintln!(
            "sc-site: warning: site/pkg is missing; run scripts/ci/build-site.sh for the analysis pages"
        );
    }
    if let Some(log) = inputs_log {
        let mut text = r.log.join("\n");
        text.push('\n');
        fs::write(&log, text).map_err(|e| format!("{}: {e}", log.display()))?;
    }
    println!(
        "sc-site: {} generated files, {} static files, {} notices -> {}",
        files.len(),
        copied,
        inputs.notices.len(),
        out.display()
    );
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("sc-site: {e}");
            ExitCode::FAILURE
        }
    }
}
