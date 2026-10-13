//! `eval repro` and `eval check-results`: a saved result is only worth
//! quoting if it can be measured again.
//!
//! `repro` finds the result's inputs (at the recorded paths, or among
//! `--input` files with the same SHA-256), checks the rules are the ones it
//! names, measures again, and diffs every number the result holds against
//! the new measurement. `check-results` checks what can be checked without
//! the inputs, for CI: each result's rules version is not newer than the
//! bundled rules, a held-out or prospective result has a benign record (or
//! was saved with `--allow-no-benign`), it was measured from committed code,
//! and it holds no URL.

use super::{FileHash, hash_file, load_labels, restrict, rules_sha256};
use crate::commands::eval::ReproArgs;
use crate::input::{InputArgs, read_records};
use anyhow::{Context, Result, bail};
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Summary keys compared by `repro`: the numbers, not the rule and
/// coverage listing (which depends on the allow-list given at the time).
const COMPARED: &[&str] = &[
    "labelled",
    "agents",
    "benign",
    "unlabelled",
    "missing_records",
    "tiers",
    "cluster_tiers",
    "non_synthetic",
    "agent_classes",
    "benign_classes",
    "tactics",
    "calibration",
];

fn file_hashes(v: &Value, key: &str) -> Result<Vec<FileHash>> {
    match v.get(key) {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::Array(_)) => Ok(serde_json::from_value(v[key].clone())?),
        Some(one) => Ok(vec![serde_json::from_value(one.clone())?]),
    }
}

/// The file for `want`: its recorded path when the hash matches there,
/// else the candidate with its hash.
fn locate(want: &FileHash, candidates: &[(PathBuf, String)]) -> Result<PathBuf> {
    if let Some(p) = &want.path {
        let p = PathBuf::from(p);
        if p.is_file() && hash_file(&p)?.sha256 == want.sha256 {
            return Ok(p);
        }
    }
    if let Some((p, _)) = candidates.iter().find(|(_, h)| *h == want.sha256) {
        return Ok(p.clone());
    }
    bail!(
        "no file with SHA-256 {} ({} bytes{}); pass it with --input",
        want.sha256,
        want.bytes,
        want.path
            .as_deref()
            .map(|p| format!(", recorded at {p}"))
            .unwrap_or_default()
    )
}

/// Every number in `v`, by path (`tiers[0].precision.k`).
fn leaves(prefix: &str, v: &Value, out: &mut BTreeMap<String, Value>) {
    match v {
        Value::Object(m) => {
            for (k, x) in m {
                let p = if prefix.is_empty() {
                    k.clone()
                } else {
                    format!("{prefix}.{k}")
                };
                leaves(&p, x, out);
            }
        }
        Value::Array(a) => {
            for (i, x) in a.iter().enumerate() {
                // Rows named by `name` or `tier` are keyed by it, so a new
                // class does not shift every row after it.
                let key = x
                    .get("name")
                    .or_else(|| x.get("tier"))
                    .and_then(Value::as_str)
                    .map_or(i.to_string(), str::to_string);
                leaves(&format!("{prefix}[{key}]"), x, out);
            }
        }
        _ => {
            out.insert(prefix.to_string(), v.clone());
        }
    }
}

fn same(a: &Value, b: &Value) -> bool {
    match (a.as_f64(), b.as_f64()) {
        (Some(x), Some(y)) => (x - y).abs() < 1e-9,
        _ => a == b,
    }
}

/// Differences between the saved summary and a new one, over [`COMPARED`]
/// keys the saved one has. `(path, saved, now)`.
pub fn diff(saved: &Value, now: &Value) -> Vec<(String, String, String)> {
    let mut out = Vec::new();
    for k in COMPARED {
        let Some(s) = saved.get(*k) else { continue };
        let (mut a, mut b) = (BTreeMap::new(), BTreeMap::new());
        leaves(k, s, &mut a);
        leaves(k, now.get(*k).unwrap_or(&Value::Null), &mut b);
        for (p, x) in &a {
            match b.get(p) {
                Some(y) if same(x, y) => {}
                Some(y) => out.push((p.clone(), x.to_string(), y.to_string())),
                None => out.push((p.clone(), x.to_string(), "absent".into())),
            }
        }
        for (p, y) in &b {
            if !a.contains_key(p) && !s.is_null() {
                out.push((p.clone(), "absent".into(), y.to_string()));
            }
        }
    }
    out
}

pub fn run(args: &ReproArgs) -> Result<()> {
    let text = std::fs::read_to_string(&args.result)
        .with_context(|| format!("reading {}", args.result.display()))?;
    let v: Value = serde_json::from_str(&text)
        .with_context(|| format!("parsing {}", args.result.display()))?;
    let candidates: Vec<(PathBuf, String)> = args
        .candidates
        .iter()
        .map(|p| Ok((p.clone(), hash_file(p)?.sha256)))
        .collect::<Result<_>>()?;
    let find = |key: &str| -> Result<Vec<PathBuf>> {
        file_hashes(&v, key)?
            .iter()
            .map(|h| locate(h, &candidates).with_context(|| key.to_string()))
            .collect()
    };
    let records = find("records")?;
    let labels = find("labels")?;
    let only = find("only_ids")?;
    let exclude = find("exclude_ids")?;
    if records.is_empty() {
        bail!("{} names no record files", args.result.display());
    }

    let rules_path = args
        .rules
        .clone()
        .or_else(|| v["rules_file"].as_str().map(PathBuf::from));
    let rules = crate::pinning::RulesText::load(rules_path.as_deref())?;
    let mut problems = Vec::new();
    let want_version = v["rules_version"].as_str().unwrap_or_default();
    if rules.version() != want_version {
        problems.push(format!(
            "rules version: saved {want_version}, now {}",
            rules.version()
        ));
    }
    if let Some(h) = v["rules_sha256"].as_str()
        && h != rules_sha256(&rules.text)
    {
        problems.push("rules SHA-256 differs from the saved one".to_string());
    }

    let mut l = load_labels(&labels, &records)?;
    let ids = |ps: &[PathBuf]| -> Result<Option<Vec<String>>> {
        match ps.first() {
            None => Ok(None),
            Some(p) => Ok(Some(sc_core::eval::split::parse_id_list(
                &std::fs::read_to_string(p)?,
            ))),
        }
    };
    restrict(&mut l, ids(&only)?.as_deref(), ids(&exclude)?.as_deref());
    let a = sc_core::analyze(read_records(&InputArgs::files(records))?, &rules.rules);
    if let Some(want) = v["scored_ids"]["sha256"].as_str() {
        let now = super::scored_ids(&a, &l);
        if now.sha256 != want {
            problems.push(format!(
                "the labelled records scored changed: saved sha256:{want} over {} ids, now sha256:{} over {}",
                v["scored_ids"]["count"].as_u64().unwrap_or(0),
                now.sha256,
                now.count
            ));
        }
    }
    let (_, _, s) = sc_core::summarize(&a, &l, &rules.text, "").map_err(anyhow::Error::msg)?;
    let now = serde_json::to_value(&s)?;
    let d = diff(&v["summary"], &now);
    println!(
        "{} · {} · rules {} · {} record file(s), {} label file(s) found by hash",
        args.result.display(),
        v["kind"].as_str().unwrap_or("?"),
        rules.version(),
        file_hashes(&v, "records")?.len(),
        file_hashes(&v, "labels")?.len()
    );
    for p in &problems {
        println!("  {p}");
    }
    if d.is_empty() {
        println!("  every saved number measured again the same");
    } else {
        println!("  {} number(s) differ:", d.len());
        for (p, a, b) in d.iter().take(60) {
            println!("    {p}: saved {a}, now {b}");
        }
    }
    if !problems.is_empty() || !d.is_empty() {
        bail!("the result does not reproduce");
    }
    Ok(())
}

/// What `check-results` finds wrong with one result.
pub fn result_problems(v: &Value, text: &str, bundled_version: &str) -> Vec<String> {
    let mut out = Vec::new();
    let version = v["rules_version"].as_str().unwrap_or_default();
    if version.is_empty() {
        out.push("no rules_version".into());
    } else if version > bundled_version {
        out.push(format!(
            "rules_version {version} is newer than the bundled rules ({bundled_version}): it cannot be measured again from this checkout"
        ));
    }
    let kind = v["kind"].as_str().unwrap_or_default();
    let benign = v["summary"]["benign"].as_u64().unwrap_or(0);
    let allowed = v["allow_no_benign"].as_bool().unwrap_or(false);
    if kind != "regression" && benign == 0 && !allowed {
        out.push(format!(
            "a {kind} result with no benign record, not saved with --allow-no-benign: its precision says nothing"
        ));
    }
    if v["toolkit"]["commit"]
        .as_str()
        .is_none_or(|c| c.ends_with("-dirty") || c == "unknown")
    {
        out.push("measured from uncommitted or unknown code (toolkit.commit)".into());
    }
    if text.contains("://") {
        out.push("holds a URL; a result holds numbers and hashes only".into());
    }
    out
}

pub fn check_results(dir: &Path) -> Result<()> {
    let bundled = crate::pinning::RulesText::load(None)?;
    let mut paths: Vec<PathBuf> = std::fs::read_dir(dir)
        .with_context(|| format!("reading {}", dir.display()))?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("json"))
        .collect();
    paths.sort();
    let mut bad = 0;
    for p in &paths {
        let text = std::fs::read_to_string(p)?;
        let problems = match serde_json::from_str::<Value>(&text) {
            Ok(v) => result_problems(&v, &text, bundled.version()),
            Err(e) => vec![format!("not JSON: {e}")],
        };
        if problems.is_empty() {
            println!("ok   {}", p.display());
        } else {
            bad += 1;
            for x in problems {
                eprintln!("FAIL {}: {x}", p.display());
            }
        }
    }
    println!(
        "{} result(s) checked against rules {}",
        paths.len(),
        bundled.version()
    );
    if bad > 0 {
        bail!("{bad} saved result(s) fail the check");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn diff_keys_rows_by_name_and_ignores_unsaved_keys() {
        let saved = json!({
            "labelled": 3,
            "tiers": [{"tier": "suggestive", "tp": 2}],
            "agent_classes": [{"name": "a", "n": 1}, {"name": "b", "n": 2}],
        });
        let now = json!({
            "labelled": 3,
            "tiers": [{"tier": "suggestive", "tp": 1}],
            "agent_classes": [{"name": "0", "n": 9}, {"name": "a", "n": 1}, {"name": "b", "n": 2}],
            "non_synthetic": {"labelled": 1},
        });
        let d = diff(&saved, &now);
        // The changed tp, and the new row's two numbers.
        assert_eq!(d.len(), 3, "{d:?}");
        assert_eq!(d[0].0, "tiers[suggestive].tp");
        assert!(d[1].0.starts_with("agent_classes[0]"), "{d:?}");
    }

    #[test]
    fn check_results_rejects_future_rules_and_vacuous_precision() {
        let v = json!({
            "kind": "held_out",
            "rules_version": "2026-10-15",
            "toolkit": {"commit": "abc"},
            "summary": {"benign": 0},
        });
        let p = result_problems(&v, "{}", "2026-10-10");
        assert_eq!(p.len(), 2, "{p:?}");
        let ok = json!({
            "kind": "held_out",
            "rules_version": "2026-10-10",
            "allow_no_benign": true,
            "toolkit": {"commit": "abc"},
            "summary": {"benign": 0},
        });
        assert!(result_problems(&ok, "{}", "2026-10-10").is_empty());
        let dirty = json!({"kind": "regression", "rules_version": "2026-01-01", "toolkit": {"commit": "abc-dirty"}});
        assert_eq!(result_problems(&dirty, "x://y", "2026-10-10").len(), 2);
    }
}
