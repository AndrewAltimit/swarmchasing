//! The full `Analysis` JSON and every audience's report over the labelled
//! evaluation set, compared with the files in `tests/snapshots/`.
//!
//! The JSON is what the browser toolkit and `swarmchase analyze` read, so a
//! change to its shape or content shows here as a diff. All sample files are
//! analysed together (as the eval gate does) and each alone; a lone file's
//! analysis is pinned by its digest. Only the committed synthetic samples
//! are read.
//!
//! After an intended change, regenerate with
//! `UPDATE_SNAPSHOTS=1 cargo test -p sc-core --test integration snapshot::`
//! and review the diff.

use sc_core::{
    Audience, FieldMap, Format, ReportOptions, Rules, analyze, parse_input, render_markdown,
    render_notice,
};
use std::path::{Path, PathBuf};

/// The snapshot stem for every sample file analysed together.
const ALL: &str = "all";

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn sample_files() -> Vec<PathBuf> {
    let dir = root().join("../../samples/eval");
    let mut files: Vec<PathBuf> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|x| x == "ndjson"))
        .collect();
    files.sort();
    assert!(!files.is_empty(), "no samples in {}", dir.display());
    files
}

/// Compares `got` with the snapshot `name`, or writes it when
/// `UPDATE_SNAPSHOTS` is set. Returns a mismatch description.
fn check(name: &str, got: &str) -> Option<String> {
    let path = root().join("tests/snapshots").join(name);
    if std::env::var_os("UPDATE_SNAPSHOTS").is_some() {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, got).unwrap();
        return None;
    }
    let want = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("{}: {e} (set UPDATE_SNAPSHOTS=1)", path.display()))
        .replace("\r\n", "\n");
    if want == got {
        return None;
    }
    let line = want
        .lines()
        .zip(got.lines())
        .position(|(a, b)| a != b)
        .unwrap_or_else(|| want.lines().count().min(got.lines().count()));
    Some(format!(
        "{name}: differs from line {}\n  want: {}\n  got:  {}",
        line + 1,
        want.lines().nth(line).unwrap_or("<end>"),
        got.lines().nth(line).unwrap_or("<end>")
    ))
}

/// The first path at which `a` and `b` differ, reading numbers as `f64` to
/// within parse rounding.
fn differ(a: &serde_json::Value, b: &serde_json::Value, at: &str) -> Option<String> {
    use serde_json::Value::*;
    match (a, b) {
        (Number(x), Number(y)) => {
            let (x, y) = (x.as_f64().unwrap(), y.as_f64().unwrap());
            ((x - y).abs() > 1e-9 * x.abs().max(1.0)).then(|| format!("{at}: {x} != {y}"))
        }
        (Array(x), Array(y)) if x.len() == y.len() => x
            .iter()
            .zip(y)
            .enumerate()
            .find_map(|(i, (x, y))| differ(x, y, &format!("{at}[{i}]"))),
        (Object(x), Object(y)) if x.keys().eq(y.keys()) => x
            .iter()
            .find_map(|(k, v)| differ(v, &y[k], &format!("{at}.{k}"))),
        _ => (a != b).then(|| at.to_string()),
    }
}

fn snapshot(stem: &str, text: &str, failures: &mut Vec<String>) {
    let rules = Rules::default_rules();
    let parsed = parse_input(text, Format::Ndjson, &FieldMap::default());
    let a = analyze(parsed.observations, &rules);
    let mut json = serde_json::to_string_pretty(&a).unwrap();
    json.push('\n');
    if stem == ALL {
        failures.extend(check(&format!("{stem}.analysis.snap.json"), &json));
    } else {
        // One file's analysis is pinned by its digest, to keep the snapshots
        // small; the combined analysis above shows the diff.
        use sha2::Digest;
        let digest: String = sha2::Sha256::digest(json.as_bytes())
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        failures.extend(check(&format!("{stem}.analysis.sha256"), &(digest + "\n")));
    }

    // The JSON reads back into the same analysis (floats to parse precision).
    let back: sc_core::Analysis = serde_json::from_str(&json).unwrap();
    let want: serde_json::Value = serde_json::from_str(&json).unwrap();
    if let Some(path) = differ(&want, &serde_json::to_value(&back).unwrap(), "") {
        failures.push(format!(
            "{stem}: analysis JSON does not round-trip at {path}"
        ));
    }

    for audience in [Audience::Internal, Audience::Provider, Audience::Affected] {
        let opts = ReportOptions {
            audience,
            generated: Some("2000-01-01".into()),
            ..Default::default()
        };
        let md = render_markdown(&a, &opts);
        let name = format!(
            "{stem}.report-{}.md",
            format!("{audience:?}").to_lowercase()
        );
        failures.extend(check(&name, &md));
    }
    let notice = render_notice(
        &a,
        &ReportOptions {
            generated: Some("2000-01-01".into()),
            ..Default::default()
        },
    );
    let mut json = serde_json::to_string_pretty(&notice).unwrap();
    json.push('\n');
    failures.extend(check(&format!("{stem}.notice.json"), &json));
}

fn stem(p: &Path) -> String {
    p.file_stem().unwrap().to_string_lossy().into_owned()
}

#[test]
fn analysis_and_reports_match_snapshots() {
    let files = sample_files();
    let mut failures = Vec::new();
    let mut all = Vec::new();
    for f in &files {
        let text = std::fs::read_to_string(f).unwrap();
        snapshot(&stem(f), &text, &mut failures);
        all.push(text);
    }
    snapshot(ALL, &all.join("\n"), &mut failures);
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
