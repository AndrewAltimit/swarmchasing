//! Digests that were never mailed. The watch workflow's mail step writes
//! `runs/<stamp>/mailed` once a digest is sent (`scripts/ci/send-mail.sh`).
//! A changed run newer than the newest mailed one, with no marker of its
//! own, had its digest written but not delivered (no SMTP that run, a relay
//! that refused it, a cancelled job): its leads would be lost to the admin.
//! The next digest lists those runs with their reasons and leads, and the
//! dashboard lists them too.
//!
//! A data directory with no marker at all is one whose digests are not
//! mailed (a local watch), and nothing is listed.

use super::priority::Level;
use serde_json::Value;
use std::fmt::Write as _;
use std::path::Path;

/// The marker's file name, in the run directory.
pub const MARKER: &str = "mailed";

/// Runs listed at most; the oldest beyond this are counted only.
const MAX_RUNS: usize = 12;
/// Reason and lead lines kept per run.
const LINES: usize = 6;

/// One changed run whose digest was never mailed.
#[derive(Debug, Clone, PartialEq)]
pub struct Unmailed {
    pub stamp: String,
    /// `high`, `medium` or `low`, from its `run.json`.
    pub priority: String,
    /// Its priority reasons, as the digest showed them (already defanged).
    pub reasons: Vec<String>,
    /// Its leads: name, tier, grade, records and targets (defanged).
    pub leads: Vec<String>,
}

impl Unmailed {
    pub fn level(&self) -> Level {
        match self.priority.as_str() {
            "high" => Level::High,
            "medium" => Level::Medium,
            _ => Level::Low,
        }
    }
}

/// Changed runs before `current` that were never mailed, oldest first.
pub fn unmailed(out: &Path, current: &str) -> Vec<Unmailed> {
    list(out, Some(current))
}

/// Every changed run never mailed, the newest included (the dashboard).
pub fn unmailed_all(out: &Path) -> Vec<Unmailed> {
    list(out, None)
}

fn list(out: &Path, current: Option<&str>) -> Vec<Unmailed> {
    let runs = out.join("runs");
    let Ok(entries) = std::fs::read_dir(&runs) else {
        return Vec::new();
    };
    let mut stamps: Vec<String> = entries
        .filter_map(|e| e.ok())
        .filter(|e| e.path().is_dir())
        .filter_map(|e| e.file_name().to_str().map(str::to_string))
        .filter(|s| {
            current.is_none_or(|c| s.as_str() < c)
                && chrono::NaiveDateTime::parse_from_str(s, "%Y%m%dT%H%M%SZ").is_ok()
        })
        .collect();
    stamps.sort();
    let Some(last_mailed) = stamps
        .iter()
        .rposition(|s| runs.join(s).join(MARKER).exists())
    else {
        return Vec::new();
    };
    let mut out: Vec<Unmailed> = stamps[last_mailed + 1..]
        .iter()
        .filter_map(|s| read(&runs.join(s).join(super::run_summary::FILE), s))
        .collect();
    if out.len() > MAX_RUNS {
        out.drain(..out.len() - MAX_RUNS);
    }
    out
}

/// A run's `run.json`, when it says the run changed.
fn read(p: &Path, stamp: &str) -> Option<Unmailed> {
    let v: Value = serde_json::from_str(&std::fs::read_to_string(p).ok()?).ok()?;
    if v["changed"] != Value::Bool(true) {
        return None;
    }
    let s = |x: &Value| x.as_str().unwrap_or("").to_string();
    let reasons = v["reasons"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|r| format!("{}: {}", s(&r["level"]), s(&r["text"])))
        .collect();
    let leads = v["leads"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|l| {
            let name = match l["key"].as_str() {
                Some(k) if !k.is_empty() => format!("{} {k}", s(&l["id"])),
                _ => s(&l["id"]),
            };
            let targets: Vec<String> = l["targets"]
                .as_array()
                .into_iter()
                .flatten()
                .take(3)
                .map(|t| format!("`{}`", s(t)))
                .collect();
            format!(
                "{} {name} [{}, {}], {} record(s){}",
                s(&l["change"]),
                s(&l["tier"]),
                s(&l["grade"]),
                l["records"].as_u64().unwrap_or(0),
                if targets.is_empty() {
                    String::new()
                } else {
                    format!(", targets {}", targets.join(", "))
                }
            )
        })
        .collect();
    Some(Unmailed {
        stamp: stamp.to_string(),
        priority: s(&v["priority"]),
        reasons,
        leads,
    })
}

/// The digest section: each run never mailed, with its reasons and leads.
/// Empty when there is none.
pub fn section(runs: &[Unmailed]) -> String {
    if runs.is_empty() {
        return String::new();
    }
    let mut t = String::new();
    let _ = writeln!(t, "## Digests not mailed ({})\n", runs.len());
    let _ = writeln!(
        t,
        "These runs found something, but their digest was never mailed; what they reported is folded in here. Each digest is in `runs/<stamp>/digest.md`.\n"
    );
    for r in runs {
        let _ = writeln!(t, "- `{}`, priority {}:", r.stamp, r.priority);
        let lines: Vec<&String> = r.reasons.iter().chain(&r.leads).collect();
        if lines.is_empty() {
            let _ = writeln!(t, "  - health or case lines only; see its digest");
        }
        for l in lines.iter().take(LINES) {
            let _ = writeln!(t, "  - {l}");
        }
        if lines.len() > LINES {
            let _ = writeln!(t, "  - … {} more in its digest", lines.len() - LINES);
        }
    }
    t.push('\n');
    t
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(out: &Path, stamp: &str, changed: bool, mailed: bool) {
        let d = out.join("runs").join(stamp);
        std::fs::create_dir_all(&d).unwrap();
        let json = serde_json::json!({
            "changed": changed,
            "priority": "high",
            "reasons": [{"level": "high", "kind": "lead", "text": "new significant cluster C1"}],
            "leads": [{"change": "new", "id": "C1", "key": "k-1234abcd", "tier": "significant",
                       "grade": "L3", "records": 4, "targets": ["a[.]example"]}],
        });
        std::fs::write(d.join("run.json"), json.to_string()).unwrap();
        if mailed {
            std::fs::write(d.join(MARKER), "").unwrap();
        }
    }

    #[test]
    fn lists_changed_runs_after_the_last_mailed_one() {
        let out = std::env::temp_dir().join(format!("swarmchase-mailed-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&out);
        // No marker anywhere: mail is not in use, nothing is listed.
        run(&out, "20261010T000000Z", true, false);
        assert!(unmailed(&out, "20261013T000000Z").is_empty());

        run(&out, "20261011T000000Z", true, true);
        run(&out, "20261011T060000Z", false, false);
        run(&out, "20261011T120000Z", true, false);
        let got = unmailed(&out, "20261013T000000Z");
        // The run before the mailed one is not listed again; the unchanged
        // run never needed mail.
        assert_eq!(got.len(), 1, "{got:?}");
        assert_eq!(got[0].stamp, "20261011T120000Z");
        assert_eq!(got[0].level(), Level::High);
        let s = section(&got);
        assert!(s.contains("## Digests not mailed (1)"), "{s}");
        assert!(
            s.contains("new C1 k-1234abcd [significant, L3], 4 record(s), targets `a[.]example`"),
            "{s}"
        );
        assert!(s.contains("high: new significant cluster C1"), "{s}");
        // The current run is never its own unmailed run; the dashboard
        // counts the newest run too.
        assert!(unmailed(&out, "20261011T120000Z").is_empty());
        assert_eq!(unmailed_all(&out), got);
        // Once a later digest is mailed, they are covered.
        run(&out, "20261012T000000Z", true, true);
        assert!(unmailed(&out, "20261013T000000Z").is_empty());
        std::fs::remove_dir_all(&out).unwrap();
    }
}
