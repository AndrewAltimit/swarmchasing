//! Digests that were never mailed. The watch workflow's mail step writes
//! `runs/<stamp>/mailed` once a digest is sent (`scripts/ci/send-mail.sh`).
//! A changed run newer than the newest mailed one, with no marker of its
//! own, had its digest written but not delivered (no SMTP that run, a relay
//! that refused it, a cancelled job): its leads would be lost to the admin.
//! The next digest lists those runs with their reasons and leads, and the
//! dashboard lists them too.
//!
//! A data directory with no marker at all is one whose digests are not
//! mailed (a local watch), and nothing is listed. Each run keeps the newest
//! marked stamp in `state.json` (`last_mailed`, [`newest_marked`]), so
//! retention deleting the run that held the marker does not make the runs
//! after it look like a directory that never mails.

use super::priority::Level;
use serde_json::Value;
use std::fmt::Write as _;
use std::path::Path;

/// The marker's file name, in the run directory.
pub const MARKER: &str = "mailed";

/// Runs listed at most; the oldest beyond this are counted only
/// ([`Listed::older`]).
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

/// The changed runs never mailed: the newest [`MAX_RUNS`] listed, oldest
/// first, and how many older ones are counted only.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Listed {
    pub runs: Vec<Unmailed>,
    /// Older runs never mailed, beyond the listed ones.
    pub older: usize,
}

impl Listed {
    /// Every run never mailed, listed or not.
    pub fn total(&self) -> usize {
        self.runs.len() + self.older
    }

    pub fn is_empty(&self) -> bool {
        self.total() == 0
    }
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
/// `last_mailed` is the newest mailed stamp `state.json` remembers, read
/// when no run directory holds a marker newer than it.
pub fn unmailed(out: &Path, current: &str, last_mailed: Option<&str>) -> Listed {
    list(out, Some(current), last_mailed)
}

/// Every changed run never mailed, the newest included (the dashboard).
pub fn unmailed_all(out: &Path, last_mailed: Option<&str>) -> Listed {
    list(out, None, last_mailed)
}

/// The newest run directory holding a marker, if any.
pub fn newest_marked(out: &Path) -> Option<String> {
    let runs = out.join("runs");
    stamps(&runs, None)
        .into_iter()
        .rev()
        .find(|s| runs.join(s).join(MARKER).exists())
}

/// Run stamps under `runs`, before `current` when given, oldest first.
fn stamps(runs: &Path, current: Option<&str>) -> Vec<String> {
    let Ok(entries) = std::fs::read_dir(runs) else {
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
    stamps
}

fn list(out: &Path, current: Option<&str>, remembered: Option<&str>) -> Listed {
    let runs = out.join("runs");
    let stamps = stamps(&runs, current);
    let marked = stamps
        .iter()
        .rposition(|s| runs.join(s).join(MARKER).exists())
        .map(|i| stamps[i].as_str());
    let Some(last_mailed) = marked.max(remembered) else {
        return Listed::default();
    };
    let mut out: Vec<Unmailed> = stamps
        .iter()
        .filter(|s| s.as_str() > last_mailed)
        .filter_map(|s| read(&runs.join(s).join(super::run_summary::FILE), s))
        .collect();
    let older = out.len().saturating_sub(MAX_RUNS);
    out.drain(..older);
    Listed { runs: out, older }
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
pub fn section(listed: &Listed) -> String {
    if listed.is_empty() {
        return String::new();
    }
    let mut t = String::new();
    let _ = writeln!(t, "## Digests not mailed ({})\n", listed.total());
    let _ = writeln!(
        t,
        "These runs found something, but their digest was never mailed; what they reported is folded in here. Each digest is in `runs/<stamp>/digest.md`.\n"
    );
    if listed.older > 0 {
        let _ = writeln!(
            t,
            "- and {} older run(s) not listed; their digests are in `runs/` until retention deletes them",
            listed.older
        );
    }
    for r in &listed.runs {
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
        assert!(unmailed(&out, "20261013T000000Z", None).is_empty());

        run(&out, "20261011T000000Z", true, true);
        run(&out, "20261011T060000Z", false, false);
        run(&out, "20261011T120000Z", true, false);
        let got = unmailed(&out, "20261013T000000Z", None);
        // The run before the mailed one is not listed again; the unchanged
        // run never needed mail.
        assert_eq!(got.total(), 1, "{got:?}");
        assert_eq!(got.runs[0].stamp, "20261011T120000Z");
        assert_eq!(got.runs[0].level(), Level::High);
        let s = section(&got);
        assert!(s.contains("## Digests not mailed (1)"), "{s}");
        assert!(
            s.contains("new C1 k-1234abcd [significant, L3], 4 record(s), targets `a[.]example`"),
            "{s}"
        );
        assert!(s.contains("high: new significant cluster C1"), "{s}");
        // The current run is never its own unmailed run; the dashboard
        // counts the newest run too.
        assert!(unmailed(&out, "20261011T120000Z", None).is_empty());
        assert_eq!(unmailed_all(&out, None), got);
        // Once a later digest is mailed, they are covered.
        run(&out, "20261012T000000Z", true, true);
        assert!(unmailed(&out, "20261013T000000Z", None).is_empty());
        assert_eq!(newest_marked(&out).as_deref(), Some("20261012T000000Z"));
        std::fs::remove_dir_all(&out).unwrap();
    }

    #[test]
    fn a_pruned_marker_is_remembered() {
        let out =
            std::env::temp_dir().join(format!("swarmchase-mailed-pruned-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&out);
        // Retention deleted the run holding the marker; a later run was
        // never mailed.
        run(&out, "20261011T060000Z", true, false);
        run(&out, "20261011T120000Z", true, false);
        assert_eq!(newest_marked(&out), None);
        assert!(unmailed(&out, "20261013T000000Z", None).is_empty());
        let got = unmailed(&out, "20261013T000000Z", Some("20261011T000000Z"));
        assert_eq!(got.total(), 2, "{got:?}");
        assert_eq!(unmailed_all(&out, Some("20261011T060000Z")).total(), 1);
        // A newer marker on disk wins over an older remembered stamp.
        run(&out, "20261011T120000Z", true, true);
        assert!(unmailed(&out, "20261013T000000Z", Some("20261011T000000Z")).is_empty());
        std::fs::remove_dir_all(&out).unwrap();
    }

    #[test]
    fn runs_beyond_the_list_are_counted() {
        let out =
            std::env::temp_dir().join(format!("swarmchase-mailed-older-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&out);
        run(&out, "20261001T000000Z", true, true);
        for h in 0..MAX_RUNS + 3 {
            run(&out, &format!("20261002T{h:02}0000Z"), true, false);
        }
        let got = unmailed(&out, "20261013T000000Z", None);
        assert_eq!(got.runs.len(), MAX_RUNS);
        assert_eq!(got.older, 3);
        assert_eq!(got.total(), MAX_RUNS + 3);
        // The newest are the ones listed.
        assert_eq!(got.runs[0].stamp, "20261002T030000Z");
        let s = section(&got);
        assert!(
            s.contains(&format!("## Digests not mailed ({})", MAX_RUNS + 3)),
            "{s}"
        );
        assert!(s.contains("and 3 older run(s) not listed"), "{s}");
        std::fs::remove_dir_all(&out).unwrap();
    }
}
