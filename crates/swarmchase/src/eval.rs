//! `swarmchase eval`: precision and recall of the rules on labelled records,
//! optionally as a gate that fails below set floors (CI runs it on
//! `samples/eval/`).
//!
//! Besides the tables it can check rule coverage against an allow-list,
//! write a frozen held-out split, write the summary JSON the site renders,
//! and save a result file of numbers only (no record content) for
//! `samples/eval/results/`.

use anyhow::{Context, Result, bail};
use sc_core::eval::coverage::{AllowList, Coverage, coverage_failures};
use sc_core::eval::grades::{COLUMNS, GradeTable};
use sc_core::eval::stats::Proportion;
use sc_core::eval::summary::Summary;
use sc_core::eval::{EvalReport, LabelSet, Threshold};
use sc_core::{Tier, parse_labels};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

/// Floors for the gate. A floor on a threshold that flagged nothing fails:
/// a precision of "n/a" must not pass as 100%.
#[derive(Debug, Default, Clone, clap::Args)]
pub struct Floors {
    /// Fail if precision at the significant tier is below this (0..1).
    #[arg(long)]
    pub min_significant_precision: Option<f64>,
    /// Fail if precision at suggestive-or-above is below this.
    #[arg(long)]
    pub min_suggestive_precision: Option<f64>,
    /// Fail if recall at the significant tier is below this.
    #[arg(long)]
    pub min_significant_recall: Option<f64>,
    /// Fail if recall at suggestive-or-above is below this.
    #[arg(long)]
    pub min_suggestive_recall: Option<f64>,
    /// Fail if the lower end of the 95% Wilson interval for precision at the
    /// significant tier is below this.
    #[arg(long)]
    pub min_significant_precision_lower: Option<f64>,
    /// Fail if the Wilson lower bound for suggestive-or-above precision is
    /// below this.
    #[arg(long)]
    pub min_suggestive_precision_lower: Option<f64>,
}

/// Labels from `--labels` files, or, when none are given, from the inputs
/// themselves (NDJSON records carrying `label`).
pub fn load_labels(labels: &[PathBuf], inputs: &[PathBuf]) -> Result<LabelSet> {
    let files = if labels.is_empty() { inputs } else { labels };
    let mut all = LabelSet::default();
    for p in files {
        let text =
            std::fs::read_to_string(p).with_context(|| format!("reading {}", p.display()))?;
        let l = parse_labels(&text);
        for w in l.warnings.iter().take(5) {
            eprintln!("warning: {}: {w}", p.display());
        }
        all.skipped += l.skipped;
        all.labels.extend(l.labels);
        all.actors.extend(l.actors);
    }
    if all.labels.is_empty() {
        bail!(
            "no labels found in {}",
            files
                .iter()
                .map(|p| p.display().to_string())
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    Ok(all)
}

/// Keep only labels whose id is in `only`, then drop those in `exclude`.
pub fn restrict(labels: &mut LabelSet, only: Option<&[String]>, exclude: Option<&[String]>) {
    if let Some(only) = only {
        let keep: std::collections::HashSet<&str> = only.iter().map(String::as_str).collect();
        labels.labels.retain(|k, _| keep.contains(k.as_str()));
        labels.actors.retain(|k, _| keep.contains(k.as_str()));
    }
    if let Some(ex) = exclude {
        for id in ex {
            labels.labels.remove(id);
            labels.actors.remove(id);
        }
    }
}

fn pct(x: Option<f64>) -> String {
    x.map_or("n/a".into(), |v| format!("{:.1}%", v * 100.0))
}

/// `87.8% [75.8–94.3]`, or `n/a`.
fn ci(p: &Proportion) -> String {
    match (p.value, p.lo, p.hi) {
        (Some(v), Some(lo), Some(hi)) => {
            format!("{:.1}% [{:.1}–{:.1}]", v * 100.0, lo * 100.0, hi * 100.0)
        }
        _ => "n/a".into(),
    }
}

pub fn print(r: &EvalReport, s: &Summary, labels: &LabelSet, show_fp: usize) {
    println!(
        "rules {} · {} labelled records ({} agent, {} benign) · {} unlabelled · {} labels without a record · {} rows skipped",
        r.rules_version,
        r.labelled,
        r.agents,
        r.benign,
        r.unlabelled,
        r.missing_records,
        labels.skipped
    );
    println!("intervals are 95% Wilson score intervals; n is the denominator");
    println!(
        "\n{:<22} {:>5} {:>5} {:>5} {:>5}  {:>24} {:>5}  {:>24} {:>5}",
        "threshold", "tp", "fp", "fn", "tn", "precision", "n", "recall", "n"
    );
    for t in &s.tiers {
        println!(
            "{:<22} {:>5} {:>5} {:>5} {:>5}  {:>24} {:>5}  {:>24} {:>5}",
            format!("{} or above", t.tier.label()),
            t.tp,
            t.fp,
            t.fn_,
            t.tn,
            ci(&t.precision),
            t.precision.n,
            ci(&t.recall),
            t.recall.n
        );
    }
    let recall_table = |title: &str, rows: &[sc_core::eval::summary::RecallRow]| {
        if rows.is_empty() {
            return;
        }
        println!(
            "\n{:<22} {:>5}  {:>24}  {:>24}",
            title, "n", "recall (suggestive+)", "recall (significant)"
        );
        for c in rows {
            println!(
                "{:<22} {:>5}  {:>24}  {:>24}",
                c.name,
                c.n,
                ci(&c.suggestive),
                ci(&c.significant)
            );
        }
    };
    recall_table("agent class", &s.agent_classes);
    recall_table("tactic (rules fired)", &s.tactics);
    if !s.benign_classes.is_empty() {
        println!(
            "\n{:<22} {:>5}  {:>24}  {:>24}",
            "benign class", "n", "FP rate (suggestive+)", "FP rate (significant)"
        );
        for c in &s.benign_classes {
            println!(
                "{:<22} {:>5}  {:>24}  {:>24}",
                c.name,
                c.n,
                ci(&c.suggestive),
                ci(&c.significant)
            );
        }
    }
    if !r.agreement.is_empty() {
        println!("\nlabeller tier → our tier");
        for (theirs, ours) in &r.agreement {
            let row: Vec<String> = ours.iter().map(|(k, v)| format!("{k} {v}")).collect();
            println!("  {theirs:<12} {}", row.join(" · "));
        }
    }
    println!(
        "\n{:<32} {:>6} {:>7} {:>9} {:>6}",
        "rule", "agent", "benign", "precision", "hardneg"
    );
    for x in &r.rules {
        let hn = r
            .hard_negatives
            .get(&x.rule_id)
            .copied()
            .unwrap_or_default();
        println!(
            "{:<32} {:>6} {:>7} {:>9} {:>6}",
            x.rule_id,
            x.on_agent,
            x.on_benign,
            pct(x.precision),
            if hn.records > 0 {
                format!("{}/{}", hn.fired, hn.records)
            } else {
                "-".into()
            }
        );
    }
    print_clusters(s);
    print_grades(&r.grades, "actor");
    print_swarm(&r.swarm);
    println!(
        "\ncoverage: {}/{} rules have a positive · {} allow-listed · {} uncovered · {} with hard negatives",
        s.coverage.covered,
        s.coverage.rules,
        s.coverage.allowed,
        s.coverage.uncovered.len(),
        s.coverage.with_hard_negatives
    );
    if !r.false_positives.is_empty() && show_fp > 0 {
        println!("\nfalse positives (benign records flagged):");
        for m in r.false_positives.iter().take(show_fp) {
            println!(
                "  {:<11} score {:>2}  {}  [{}]
              {}",
                m.tier.label(),
                m.score,
                m.id,
                m.rules.join(", "),
                crate::util::truncate(&m.url, 140)
            );
        }
    }
}

/// Interaction edges against `swarm` group labels. Report only.
fn print_swarm(w: &sc_core::swarm::SwarmEval) {
    if w.edges == 0 && w.groups.is_empty() {
        return;
    }
    let kinds = |m: &[usize; 5]| {
        sc_core::SwarmEdgeKind::ALL
            .iter()
            .zip(m)
            .filter(|(_, n)| **n > 0)
            .map(|(k, n)| format!("{} {n}", k.id()))
            .collect::<Vec<_>>()
            .join(", ")
    };
    println!(
        "\ninteraction edges (report only): {} ({}) · swarm groups with an edge inside {}/{} · edges inside a group {} · across groups {} · on runs labelled none {}{}",
        w.edges,
        kinds(&w.by_kind),
        w.found.len(),
        w.groups.len(),
        w.on_groups,
        w.across_groups,
        w.on_non_swarm.iter().sum::<usize>(),
        if w.on_non_swarm.iter().all(|n| *n == 0) {
            String::new()
        } else {
            format!(" ({})", kinds(&w.on_non_swarm))
        }
    );
    let missed: Vec<&String> = w.groups.iter().filter(|g| !w.found.contains(g)).collect();
    if !missed.is_empty() {
        println!(
            "  groups with no edge: {}",
            missed
                .iter()
                .map(|s| s.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
}

fn print_clusters(s: &Summary) {
    let c = &s.clusters;
    if c.run_labelled == 0 && c.false_merges.is_empty() {
        return;
    }
    let f = |x: Option<f64>| x.map_or("n/a".into(), |v| format!("{v:.3}"));
    println!(
        "\nlinking (report only): {} run-labelled records in {} runs · B-cubed precision {} recall {} F1 {}",
        c.run_labelled,
        c.runs,
        f(c.bcubed_precision),
        f(c.bcubed_recall),
        f(c.bcubed_f1)
    );
    println!(
        "  false merges {}/{} clusters ({}) · runs split over several groups {}",
        c.false_merges.len(),
        c.clusters_checked,
        pct(c.false_merge_rate),
        c.false_splits.len()
    );
    for m in &c.false_merges {
        println!(
            "  false merge {} ({} records): runs [{}]{}",
            m.cluster,
            m.members,
            m.runs.join(", "),
            if m.mixes_labels {
                " · mixes agent and benign"
            } else {
                ""
            }
        );
    }
    if !c.false_splits.is_empty() {
        println!("  split runs: {}", c.false_splits.join(", "));
    }
}

/// The agent-grade confusion table: rows by actor (or the control), columns
/// by grade. Report only.
pub fn print_grades(t: &GradeTable, rows: &str) {
    if t.is_empty() {
        return;
    }
    println!("\nagent grade by {rows} (report only, not gated; records, graded by their cluster)");
    print!("  {:<22}", rows);
    for c in COLUMNS {
        print!(" {c:>11}");
    }
    println!();
    for (name, cols) in &t.rows {
        print!("  {name:<22}");
        for c in COLUMNS {
            print!(" {:>11}", cols.get(c).copied().unwrap_or(0));
        }
        println!();
    }
}

/// The per-rule coverage table (`--coverage`).
pub fn print_coverage(c: &Coverage) {
    println!(
        "\n{:<32} {:<8} {:>9} {:>7} {:>9}  allow-list",
        "rule", "tactic", "positives", "benign", "hard neg"
    );
    for r in &c.rules {
        println!(
            "{:<32} {:<8} {:>9} {:>7} {:>9}  {}",
            r.rule_id,
            match (r.artifact, r.tactics.as_slice()) {
                (true, [t]) if t == sc_core::eval::coverage::UNTAGGED => "artifact".to_string(),
                (true, t) => format!("{},art", t.join(",")),
                (false, t) => t.join(","),
            },
            r.positives,
            r.on_benign,
            if r.hard_negatives > 0 {
                format!("{}/{}", r.hard_negatives_fired, r.hard_negatives)
            } else {
                "-".into()
            },
            r.allowed.as_deref().unwrap_or("")
        );
    }
    if !c.unknown_hard_negative_ids.is_empty() {
        println!(
            "hard_negative_for names no such rule: {}",
            c.unknown_hard_negative_ids.join(", ")
        );
    }
}

/// Check the floors. Returns the failures, empty when the gate passes.
pub fn check(r: &EvalReport, f: &Floors) -> Vec<String> {
    let mut out = Vec::new();
    let mut need = |t: Option<&Threshold>,
                    what: &str,
                    floor: Option<f64>,
                    get: fn(&Threshold) -> Option<f64>| {
        let Some(floor) = floor else { return };
        let Some(t) = t else { return };
        match get(t) {
            Some(v) if v + 1e-9 >= floor => {}
            Some(v) => out.push(format!(
                "{} {what} {:.1}% < floor {:.1}%",
                t.tier.label(),
                v * 100.0,
                floor * 100.0
            )),
            None => out.push(format!(
                "{} {what} undefined (nothing to measure) - floor {:.1}% not met",
                t.tier.label(),
                floor * 100.0
            )),
        }
    };
    let sig = r.threshold(Tier::Significant);
    let sug = r.threshold(Tier::Suggestive);
    need(sig, "precision", f.min_significant_precision, |t| {
        t.precision
    });
    need(sug, "precision", f.min_suggestive_precision, |t| {
        t.precision
    });
    need(sig, "recall", f.min_significant_recall, |t| t.recall);
    need(sug, "recall", f.min_suggestive_recall, |t| t.recall);
    need(
        sig,
        "precision lower bound (95% Wilson)",
        f.min_significant_precision_lower,
        |t| t.precision_ci.map(|c| c.0),
    );
    need(
        sug,
        "precision lower bound (95% Wilson)",
        f.min_suggestive_precision_lower,
        |t| t.precision_ci.map(|c| c.0),
    );
    out
}

/// A file named by hash and size, never by content.
#[derive(Debug, Serialize)]
pub struct FileHash {
    pub sha256: String,
    pub bytes: u64,
}

pub fn hash_file(p: &Path) -> Result<FileHash> {
    let b = std::fs::read(p).with_context(|| format!("reading {}", p.display()))?;
    Ok(FileHash {
        sha256: Sha256::digest(&b)
            .iter()
            .map(|x| format!("{x:02x}"))
            .collect(),
        bytes: b.len() as u64,
    })
}

/// A saved result: numbers, hashes and the summary. No record content.
#[derive(Debug, Serialize)]
pub struct SavedResult<'a> {
    /// `regression`, `held_out` or `prospective` (manual FM-9.1).
    pub kind: &'a str,
    pub description: &'a str,
    pub rules_version: &'a str,
    pub toolkit: Toolkit,
    pub records: Vec<FileHash>,
    pub labels: Vec<FileHash>,
    /// The id list scored, when restricted with `--only-ids`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub only_ids: Option<FileHash>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exclude_ids: Option<FileHash>,
    pub summary: &'a Summary,
}

#[derive(Debug, Serialize)]
pub struct Toolkit {
    pub version: &'static str,
    /// `git rev-parse HEAD` of the checkout, `-dirty` when it has changes.
    pub commit: String,
}

pub fn toolkit() -> Toolkit {
    let git = |args: &[&str]| {
        std::process::Command::new("git")
            .args(args)
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
    };
    let commit = match git(&["rev-parse", "HEAD"]) {
        Some(c) => {
            let dirty = git(&["status", "--porcelain", "--untracked-files=no"])
                .is_some_and(|s| !s.is_empty());
            if dirty { format!("{c}-dirty") } else { c }
        }
        None => "unknown".into(),
    };
    Toolkit {
        version: env!("CARGO_PKG_VERSION"),
        commit,
    }
}

/// Fail on the coverage gate's findings.
pub fn check_coverage(c: &Coverage, allow: &AllowList) -> Vec<String> {
    coverage_failures(c, allow)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wilson_floor_fails_below_the_lower_bound() {
        let labels = parse_labels(
            "{\"id\":\"x:1\",\"label\":\"agent\"}\n{\"id\":\"x:2\",\"label\":\"benign\"}\n",
        );
        let a = sc_core::analyze(
            vec![
                sc_core::Observation {
                    id: "x:1".into(),
                    url: "https://t.example/?id=1%20OR%201=1".into(),
                    ..Default::default()
                },
                sc_core::Observation {
                    id: "x:2".into(),
                    url: "https://t.example/".into(),
                    ..Default::default()
                },
            ],
            &sc_core::Rules::default_rules(),
        );
        let r = sc_core::evaluate(&a, &labels);
        // 1/1 precision: the point estimate is 100%, the lower bound ~20.7%.
        let f = Floors {
            min_significant_precision: Some(0.9),
            min_significant_precision_lower: Some(0.5),
            ..Default::default()
        };
        let fails = check(&r, &f);
        assert_eq!(fails.len(), 1, "{fails:?}");
        assert!(fails[0].contains("lower bound"), "{fails:?}");
    }
}
