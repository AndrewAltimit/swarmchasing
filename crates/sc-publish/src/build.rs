//! Building the public site into a directory: the one entry both `sc-site`
//! and `swarmchase site build` call.
//!
//! Reads only `notices/*.md`, `docs/**/*.md`, `rules/default.toml`,
//! `samples/eval/*.ndjson`, `samples/eval/coverage-allow.txt`,
//! `samples/showcase/*.ndjson`, `schemas/**/*.json` (published as they
//! are, under `schemas/`), `keys/bundle-signing.pub` when it is
//! committed, and the static files in `site/` (with the
//! WASM modules `scripts/ci/build-site.sh` builds into `site/pkg`). It refuses any path under `data/` or
//! `$SWARMCHASE_DATA`: watch data and case files never reach the site.
//! Unlike the rest of this crate it reads and writes files; it never touches
//! the network.
//!
//! One input is not committed: with `identity_snapshot` set, the providers'
//! range files and key directories `swarmchase identity refresh` holds, for
//! the identity page ([`crate::identity`]). Only `fetched.json` and the files
//! the catalog names are read, and each is embedded only when it parses and
//! matches its recorded SHA-256. They are the providers' public documents,
//! never watch data.
//!
//! It adds the agent-facing files ([`crate::agents`]). When
//! `SWARMCHASE_CANARY_SEED` holds the secret seed, every page and agent
//! file carries its own canary token for the build's month
//! ([`sc_core::canary`]); unset or empty, none does. The seed is read from
//! the environment and never written anywhere.
//!
//! A committed bundle signing key is published at its own path, and the
//! providers page, `security.txt` and `swarm-report.json` name it
//! ([`crate::agents::signing_key_md`]). The build never reads the secret.

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
    /// A directory `swarmchase identity refresh` wrote (`<data>/identity`):
    /// the providers' files the identity page starts with. Unset or without
    /// `fetched.json`, the page has the catalog alone.
    pub identity_snapshot: Option<PathBuf>,
}

impl Default for BuildOptions {
    fn default() -> Self {
        Self {
            out: PathBuf::from("_site"),
            base_url: "http://localhost:8080/".into(),
            root: PathBuf::from("."),
            inputs_log: None,
            extra_notices: None,
            identity_snapshot: None,
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
    /// The canary period (`YYMM`) when tokens were embedded.
    pub canary_period: Option<String>,
    /// The providers' files embedded for the identity page: (catalog id,
    /// fetch date).
    pub identity_files: Vec<(String, String)>,
}

/// The build's time: `SOURCE_DATE_EPOCH` when set (reproducible builds),
/// else the clock.
fn build_time() -> i64 {
    std::env::var("SOURCE_DATE_EPOCH")
        .ok()
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or_else(|| {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_secs() as i64)
        })
}

/// The seed and period when canary tokens are on: whenever
/// `SWARMCHASE_CANARY_SEED` is set and not empty. A seed too short to use
/// is an error.
fn canary_setting(now: i64) -> Result<Option<(String, String)>, String> {
    let seed = std::env::var("SWARMCHASE_CANARY_SEED").unwrap_or_default();
    if seed.trim().is_empty() {
        return Ok(None);
    }
    sc_core::canary::check_seed(&seed).map_err(|e| format!("SWARMCHASE_CANARY_SEED: {e}"))?;
    Ok(Some((
        seed.trim().to_string(),
        sc_core::canary::period_of(now),
    )))
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
    ("keys/bundle-signing.pub", ".pub"),
    ("schemas/", ".json"),
    ("site/", ""),
];

/// Where the providers guide marks the paragraph on the signing key.
const SIGNING_MARK: &str = "<!-- bundle-signing-key -->";

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

/// The date (`YYYY-MM-DD`) of the last commit to each file under `paths`,
/// by repository path. Empty in a shallow clone, where every file would
/// carry the one commit's date, and without git: commit dates keep the
/// build reproducible, where file times or the clock would not.
fn git_dates(root: &Path, paths: &[&str]) -> BTreeMap<String, String> {
    let git = |args: &[&str]| {
        std::process::Command::new("git")
            .arg("-C")
            .arg(root)
            .args(args)
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
    };
    let mut out = BTreeMap::new();
    match git(&["rev-parse", "--is-shallow-repository"]) {
        Some(s) if s.trim() == "false" => {}
        _ => return out,
    }
    let mut args = vec!["log", "--format=%x00%cs", "--name-only", "--"];
    args.extend_from_slice(paths);
    let Some(log) = git(&args) else { return out };
    let mut date = String::new();
    for line in log.lines() {
        if let Some(d) = line.strip_prefix('\0') {
            date = d.trim().to_string();
        } else if !line.trim().is_empty() && !date.is_empty() {
            out.entry(line.trim().to_string())
                .or_insert_with(|| date.clone());
        }
    }
    out
}

/// The build's commit date (`YYYY-MM-DD`): `HEAD`'s, which a shallow clone
/// knows too, else the day of `now` (the build's time) without git.
fn commit_date(root: &Path, now: i64) -> String {
    std::process::Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["log", "-1", "--format=%cs"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .filter(|d| d.len() == 10)
        .unwrap_or_else(|| {
            chrono::DateTime::from_timestamp(now, 0)
                .unwrap_or_default()
                .format("%Y-%m-%d")
                .to_string()
        })
}

/// What [`copy_static`] wrote: the file count, the renames, and each
/// script's static imports, for the pages' module preloads.
struct Copied {
    count: usize,
    names: BTreeMap<String, String>,
    imports: BTreeMap<String, Vec<String>>,
}

/// Copy `site/` into the output with content-hashed script, style and WASM
/// names ([`crate::assets`]).
fn copy_static(r: &mut Reader, out: &Path) -> Result<Copied, String> {
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
    let imports = crate::assets::module_imports(&files);
    let (files, names) = crate::assets::fingerprint(files);
    for (sub, bytes) in &files {
        let dest = out.join(sub);
        if let Some(p) = dest.parent() {
            fs::create_dir_all(p).map_err(|e| format!("{}: {e}", p.display()))?;
        }
        fs::write(&dest, bytes).map_err(|e| format!("{}: {e}", dest.display()))?;
    }
    Ok(Copied {
        count: files.len(),
        names,
        imports,
    })
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
    let base = if o.base_url.ends_with('/') {
        o.base_url.clone()
    } else {
        format!("{}/", o.base_url)
    };
    let signing_keys = read_signing_keys(&mut r)?;
    let mut docs = Vec::new();
    for rel in r.list("docs", ".md", true, true) {
        let mut text = r.read(&rel)?;
        if rel == "docs/guides/for-providers.md" {
            text = text.replace(SIGNING_MARK, &crate::agents::signing_key_md(&signing_keys));
        }
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
    let mut schemas = Vec::new();
    for rel in r.list("schemas", ".json", true, true) {
        let text = r.read(&rel)?;
        schemas.push((rel, text));
    }
    let lastmod = git_dates(&r.root, &["docs", "rules/default.toml", "site/js/pages"]);
    let now = build_time();
    let dated = commit_date(&r.root, now);
    // A module's download size: the host serves it gzip-compressed.
    let size = |p: &str| fs::read(r.root.join(p)).ok().map(|b| gzip_len(&b));
    let engine_bytes = size("site/pkg/sc_wasm_bg.wasm");
    let tools_bytes = size("site/pkg/tools/sc_tools_bg.wasm");
    let mut warnings = Vec::new();
    let identity = match &o.identity_snapshot {
        Some(dir) => read_identity_snapshot(dir, &mut warnings)?,
        None => None,
    };
    let identity_files: Vec<(String, String)> = identity
        .as_ref()
        .map(|s| {
            s.files
                .iter()
                .map(|f| (f.id.clone(), f.fetched.clone()))
                .collect()
        })
        .unwrap_or_default();
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
        identity,
        lastmod,
        dated,
    };
    let mut files = build_pages(&mut inputs)?;
    let schema_paths: Vec<String> = schemas.iter().map(|(p, _)| p.clone()).collect();
    files.extend(schemas);
    files.extend(crate::agents::files(&crate::agents::AgentInputs {
        base: &base,
        repo: &inputs.repo,
        now,
        docs: &inputs.docs,
        signing_keys: &signing_keys,
        schemas: &schema_paths,
    }));
    if !signing_keys.is_empty() {
        files.push((
            sc_case::signing::PUBLIC_KEY_PATH.to_string(),
            sc_case::signing::public_key_file(&signing_keys),
        ));
    }
    let canary = canary_setting(now)?;
    for (path, text) in files.iter_mut() {
        if crate::agents::is_surface(path) {
            let token = canary
                .as_ref()
                .map(|(seed, period)| sc_core::canary::derive(seed.as_bytes(), path, period));
            *text = crate::agents::apply_canary(path, text, token.as_deref());
        }
    }

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
    let copied = copy_static(&mut r, &out)?;
    for (path, text) in &files {
        let dest = out.join(path);
        if let Some(p) = dest.parent() {
            fs::create_dir_all(p).map_err(|e| format!("{}: {e}", p.display()))?;
        }
        let text = if path.ends_with(".html") {
            let text = crate::assets::module_preloads(text, &copied.imports);
            crate::assets::rewrite_page(&text, &copied.names)
        } else {
            text.clone()
        };
        fs::write(&dest, text).map_err(|e| format!("{}: {e}", dest.display()))?;
    }
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
        copied: copied.count,
        notices: inputs.notices.len(),
        out,
        warnings,
        canary_period: canary.map(|(_, p)| p),
        identity_files,
    })
}

/// The committed bundle signing keys: none when `keys/bundle-signing.pub`
/// is absent or not tracked by git (a key on disk only is never published).
/// A file that does not parse fails the build.
fn read_signing_keys(r: &mut Reader) -> Result<Vec<sc_case::signing::PublicKey>, String> {
    let rel = sc_case::signing::PUBLIC_KEY_PATH;
    let tracked = r.tracked.as_ref().is_none_or(|t| t.contains(rel));
    if !tracked || !r.root.join(rel).is_file() {
        return Ok(Vec::new());
    }
    let text = r.read(rel)?;
    sc_case::signing::parse_public_keys(&text).map_err(|e| format!("{rel}: {e}"))
}

/// The providers' files in `dir` (as `identity refresh` writes them), for
/// the identity page. `None` when `dir` holds no `fetched.json`. Reads only
/// `fetched.json` and `<id>.json` for each catalog id; a file over the size
/// `identity refresh` accepts is left out.
fn read_identity_snapshot(
    dir: &Path,
    warnings: &mut Vec<String>,
) -> Result<Option<crate::identity::Snapshot>, String> {
    const MAX: u64 = 4 << 20;
    let index = dir.join("fetched.json");
    if !index.is_file() {
        warnings.push(format!(
            "identity snapshot: {} has no fetched.json; the identity page has the catalog only",
            dir.display()
        ));
        return Ok(None);
    }
    let catalog = sc_core::identity::Catalog::bundled();
    let read = |p: &Path| -> Result<String, String> {
        let len = fs::metadata(p)
            .map_err(|e| format!("{}: {e}", p.display()))?
            .len();
        if len > MAX {
            return Err(format!("{}: over {MAX} bytes", p.display()));
        }
        fs::read_to_string(p).map_err(|e| format!("{}: {e}", p.display()))
    };
    let mut files = BTreeMap::new();
    let ids = catalog
        .range_files
        .iter()
        .map(|f| f.id.clone())
        .chain(catalog.directories.iter().map(|d| d.id.clone()));
    for id in ids {
        let p = dir.join(format!("{id}.json"));
        if !p.is_file() {
            continue;
        }
        match read(&p) {
            Ok(t) => {
                files.insert(id, t);
            }
            Err(e) => warnings.push(format!("identity snapshot: {e}; left out")),
        }
    }
    let (snap, w) = crate::identity::snapshot(catalog, &read(&index)?, &files)
        .map_err(|e| format!("identity snapshot: {e}"))?;
    warnings.extend(w.into_iter().map(|w| format!("identity snapshot: {w}")));
    Ok(Some(snap))
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
        // The agent files, with no canary placeholder left behind.
        for f in [
            "llms.txt",
            "llms-full.txt",
            ".well-known/security.txt",
            ".well-known/swarm-report.json",
            "index.html",
        ] {
            let text = fs::read_to_string(out.join(f)).unwrap();
            assert!(!text.contains(sc_core::canary::PLACEHOLDER), "{f}");
        }
        // The providers page says what the checkout says of signing.
        let providers = fs::read_to_string(out.join("providers/index.html")).unwrap();
        let committed = repo().join(sc_case::signing::PUBLIC_KEY_PATH).is_file();
        assert_eq!(
            out.join(sc_case::signing::PUBLIC_KEY_PATH).is_file(),
            committed
        );
        assert!(
            providers.contains(if committed {
                "The signing key this site publishes"
            } else {
                "This site publishes no signing key yet"
            }),
            "providers page"
        );
        // The schemas are published, and the agent files point at them.
        assert!(out.join("schemas/sc-submission-v1.json").is_file());
        let llms = fs::read_to_string(out.join("llms.txt")).unwrap();
        assert!(
            llms.contains("localhost:8080/schemas/sc-submission-v1.json"),
            "{llms}"
        );
        // Each page preloads the modules its scripts import, by hashed name.
        let wb = fs::read_to_string(out.join("analyze/index.html")).unwrap();
        assert!(
            wb.contains("<link rel=\"modulepreload\" href=\"../js/lib/charts."),
            "{wb}"
        );
        assert!(!wb.contains("modulepreload\" href=\"../js/lib/charts.js\""));
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
