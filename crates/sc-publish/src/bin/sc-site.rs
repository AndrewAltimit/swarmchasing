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

use sc_publish::build::{BuildOptions, build_site_dir};
use std::path::PathBuf;
use std::process::ExitCode;

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
    let built = build_site_dir(&BuildOptions {
        out,
        base_url: base,
        root,
        inputs_log,
        extra_notices: extra,
    })?;
    for w in &built.warnings {
        eprintln!("sc-site: warning: {w}");
    }
    println!(
        "sc-site: {} generated files, {} static files, {} notices -> {}",
        built.generated,
        built.copied,
        built.notices,
        built.out.display()
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
