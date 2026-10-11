//! `swarmchase eval`: precision and recall of the rules on labelled records,
//! optionally as a gate that fails below set floors (CI runs it on
//! `samples/eval/`).
//!
//! Besides the tables it can check rule coverage against an allow-list,
//! write a frozen held-out split, write the summary JSON the site renders,
//! and save a result file of numbers only (no record content) for
//! `samples/eval/results/`. [`repro`] measures a saved result again and
//! checks the committed ones; [`bench`] writes and scores SC-Bench files;
//! [`control`] collects and measures the pre-era negative control.

pub mod bench;
pub mod control;
pub mod repro;

use anyhow::{Context, Result, bail};
use sc_core::eval::baseline::Baseline;
use sc_core::eval::control::{ControlRow, ControlSummary};
use sc_core::eval::coverage::{AllowList, Coverage, coverage_failures};
use sc_core::eval::grades::{COLUMNS, GradeTable};
use sc_core::eval::stats::Proportion;
use sc_core::eval::summary::{Summary, TierSummary};
use sc_core::eval::units::{Calibration, Slice};
use sc_core::eval::{EvalReport, LabelSet};
use sc_core::{Tier, parse_labels};
use serde::{Deserialize, Serialize};
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
    /// The same six floors over the records not marked `synthetic`.
    #[arg(long)]
    pub min_nonsynthetic_significant_precision: Option<f64>,
    #[arg(long)]
    pub min_nonsynthetic_suggestive_precision: Option<f64>,
    #[arg(long)]
    pub min_nonsynthetic_significant_recall: Option<f64>,
    #[arg(long)]
    pub min_nonsynthetic_suggestive_recall: Option<f64>,
    #[arg(long)]
    pub min_nonsynthetic_significant_precision_lower: Option<f64>,
    #[arg(long)]
    pub min_nonsynthetic_suggestive_precision_lower: Option<f64>,
}

/// Labels from `--labels` files, or, when none are given, from the inputs
/// themselves (NDJSON records carrying `label`).
pub fn load_labels(labels: &[PathBuf], inputs: &[PathBuf]) -> Result<LabelSet> {
    let files = if labels.is_empty() { inputs } else { labels };
    let mut all = LabelSet::default();
    for p in files {
        let text =
            std::fs::read_to_string(p).with_context(|| format!("reading {}", p.display()))?;
        let mut l = parse_labels(&text);
        for w in l.warnings.iter().take(5) {
            eprintln!("warning: {}: {w}", p.display());
        }
        // The file name only: a full path would say where the reader keeps
        // their data.
        let origin = p
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .filter(|n| n != "-");
        for v in l.labels.values_mut() {
            v.origin = origin.clone();
        }
        all.skipped += l.skipped;
        all.labels.extend(l.labels);
        all.actors.extend(l.actors);
        all.provenance.extend(l.provenance);
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
    print_tiers("all records · record unit", &s.tiers);
    print_tiers(
        "all records · cluster unit (a cluster, or an unclustered record, counts once)",
        &s.cluster_tiers,
    );
    let ns = &s.non_synthetic;
    println!(
        "\nnon-synthetic: {} labelled records ({} agent, {} benign) not marked synthetic",
        ns.labelled, ns.agents, ns.benign
    );
    print_tiers("non-synthetic · record unit", &ns.tiers);
    print_tiers("non-synthetic · cluster unit", &ns.cluster_tiers);
    print_slices("provenance", &s.by_provenance);
    print_slices("source", &s.by_source);
    print_slices("file", &s.by_file);
    print_calibration(&s.calibration);
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
    if let Some(b) = &s.baseline {
        print_baseline(b);
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

/// The reviewed benign baseline: progress toward its target, and the
/// false-positive rate with its 95% upper bound per tier.
pub fn print_baseline(b: &Baseline) {
    println!(
        "\nreviewed benign baseline (review sample labels, not synthetic, not tuned): {} benign of the {} target ({:.1}%) · {} agent (misses) · {} left out as tuned or synthetic",
        b.benign,
        b.target,
        100.0 * b.benign as f64 / b.target.max(1) as f64,
        b.agents,
        b.excluded
    );
    for t in &b.tiers {
        let upper = match (t.upper, t.method.as_str()) {
            (Some(u), "rule_of_three") => {
                format!("{:.2}% (rule of three, none flagged)", u * 100.0)
            }
            (Some(u), _) => format!("{:.2}% (Wilson)", u * 100.0),
            (None, _) => "n/a".into(),
        };
        println!(
            "  {:<22} flagged {:>5} of {:>5}  FP rate {:>22}  95% upper bound {upper}",
            format!("{} or above", t.tier.label()),
            t.fp_rate.k,
            t.fp_rate.n,
            ci(&t.fp_rate)
        );
    }
}

/// The negative control's false-alarm rates.
pub fn print_control(c: &ControlSummary, all: usize, date: &str, rules: &str) {
    println!(
        "negative control: {} of {all} records before {date} · {} clusters · rules {rules}",
        c.records, c.clusters
    );
    println!(
        "every flag, grade above L1 and plant signal here is a false alarm; rates are 95% Wilson intervals"
    );
    let rows = |title: &str, rows: &[ControlRow]| {
        println!("\n{title:<26} {:>7} {:>7}  {:>24}", "k", "n", "rate");
        for r in rows {
            println!(
                "{:<26} {:>7} {:>7}  {:>24}",
                r.name,
                r.rate.k,
                r.rate.n,
                ci(&r.rate)
            );
        }
    };
    rows("records flagged", &c.by_tier);
    rows("records by agent grade", &c.by_agent_level);
    println!(
        "\nclusters graded L2 or above: {} of {} · {}",
        c.clusters_l2_or_above.k,
        c.clusters_l2_or_above.n,
        ci(&c.clusters_l2_or_above)
    );
    println!(
        "records graded above L0: {} of {} · {}",
        c.records_above_l0.k,
        c.records_above_l0.n,
        ci(&c.records_above_l0)
    );
    println!(
        "clusters graded above L0: {} of {} · {}",
        c.clusters_above_l0.k,
        c.clusters_above_l0.n,
        ci(&c.clusters_above_l0)
    );
    rows("clusters by plant signal", &c.plant_signals);
    if !c.by_rule.is_empty() {
        println!(
            "\n{:<32} {:>7} {:>24}  {:>7} {:>24}",
            "rule (records fired on)", "fired", "rate", "flagged", "flagged rate (sugg+)"
        );
        for r in &c.by_rule {
            println!(
                "{:<32} {:>7} {:>24}  {:>7} {:>24}",
                r.rule_id,
                r.fired.k,
                ci(&r.fired),
                r.flagged.k,
                ci(&r.flagged)
            );
        }
    }
    let kinds: Vec<String> = c
        .swarm_edges_by_kind
        .iter()
        .filter(|k| k.count > 0)
        .map(|k| format!("{} {}", k.name, k.count))
        .collect();
    println!(
        "\ninteraction edges: {}{}",
        c.swarm_edges,
        if kinds.is_empty() {
            String::new()
        } else {
            format!(" ({})", kinds.join(", "))
        }
    );
    for t in &c.by_tier {
        let (upper, method) = sc_core::eval::baseline::upper_bound(t.rate.k, t.rate.n);
        if let Some(u) = upper {
            println!(
                "95% upper bound on the false-alarm rate, {}: {:.2}% ({})",
                t.name,
                u * 100.0,
                if method == "rule_of_three" {
                    "rule of three, none flagged"
                } else {
                    "Wilson"
                }
            );
        }
    }
}

/// A tp/fp/fn/tn table with precision and recall at each threshold.
pub fn print_tiers(title: &str, tiers: &[TierSummary]) {
    println!("\n{title}");
    println!(
        "{:<22} {:>5} {:>5} {:>5} {:>5}  {:>24} {:>5}  {:>24} {:>5}",
        "threshold", "tp", "fp", "fn", "tn", "precision", "n", "recall", "n"
    );
    for t in tiers {
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
}

/// One line per slice: counts, then precision and recall at both
/// thresholds, record unit.
pub fn print_slices(by: &str, slices: &[Slice]) {
    if slices.is_empty() {
        return;
    }
    println!(
        "\n{:<26} {:>5} {:>5} {:>5}  {:>22} {:>22}  {:>22} {:>22}",
        format!("by {by}"),
        "n",
        "agent",
        "benign",
        "precision (sugg+)",
        "recall (sugg+)",
        "precision (sig)",
        "recall (sig)"
    );
    for s in slices {
        let t = |i: usize| s.tiers.get(i);
        let p = |i: usize| t(i).map_or("n/a".into(), |t| ci(&t.precision));
        let r = |i: usize| t(i).map_or("n/a".into(), |t| ci(&t.recall));
        println!(
            "{:<26} {:>5} {:>5} {:>5}  {:>22} {:>22}  {:>22} {:>22}",
            crate::util::truncate(&s.name, 26),
            s.labelled,
            s.agents,
            s.benign,
            p(0),
            r(0),
            p(1),
            r(1)
        );
    }
}

/// Observed precision per tier and per agent grade.
pub fn print_calibration(c: &Calibration) {
    if c.by_tier.is_empty() && c.by_agent_level.is_empty() {
        return;
    }
    println!("\ncalibration: share of labelled records that are agents (report only)");
    for (title, rows) in [("tier", &c.by_tier), ("agent grade", &c.by_agent_level)] {
        let row: Vec<String> = rows
            .iter()
            .map(|r| format!("{} {} of {}", r.name, ci(&r.precision), r.precision.n))
            .collect();
        if !row.is_empty() {
            println!("  {title:<12} {}", row.join(" · "));
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
pub fn check(s: &Summary, f: &Floors) -> Vec<String> {
    let mut out = Vec::new();
    let mut need = |set: &str,
                    tiers: &[TierSummary],
                    tier: Tier,
                    what: &str,
                    floor: Option<f64>,
                    get: fn(&TierSummary) -> Option<f64>| {
        let Some(floor) = floor else { return };
        let Some(t) = tiers.iter().find(|t| t.tier == tier) else {
            out.push(format!(
                "{set}{} {what}: no such threshold - floor {:.1}% not met",
                tier.label(),
                floor * 100.0
            ));
            return;
        };
        match get(t) {
            Some(v) if v + 1e-9 >= floor => {}
            Some(v) => out.push(format!(
                "{set}{} {what} {:.1}% < floor {:.1}%",
                tier.label(),
                v * 100.0,
                floor * 100.0
            )),
            None => out.push(format!(
                "{set}{} {what} undefined (nothing to measure) - floor {:.1}% not met",
                tier.label(),
                floor * 100.0
            )),
        }
    };
    let lower = "precision lower bound (95% Wilson)";
    let prec: fn(&TierSummary) -> Option<f64> = |t| t.precision.value;
    let rec: fn(&TierSummary) -> Option<f64> = |t| t.recall.value;
    let lo: fn(&TierSummary) -> Option<f64> = |t| t.precision.lo;
    let (sig, sug) = (Tier::Significant, Tier::Suggestive);
    for (set, tiers, floors) in [
        (
            "",
            &s.tiers,
            [
                f.min_significant_precision,
                f.min_suggestive_precision,
                f.min_significant_recall,
                f.min_suggestive_recall,
                f.min_significant_precision_lower,
                f.min_suggestive_precision_lower,
            ],
        ),
        (
            "non-synthetic ",
            &s.non_synthetic.tiers,
            [
                f.min_nonsynthetic_significant_precision,
                f.min_nonsynthetic_suggestive_precision,
                f.min_nonsynthetic_significant_recall,
                f.min_nonsynthetic_suggestive_recall,
                f.min_nonsynthetic_significant_precision_lower,
                f.min_nonsynthetic_suggestive_precision_lower,
            ],
        ),
    ] {
        need(set, tiers, sig, "precision", floors[0], prec);
        need(set, tiers, sug, "precision", floors[1], prec);
        need(set, tiers, sig, "recall", floors[2], rec);
        need(set, tiers, sug, "recall", floors[3], rec);
        need(set, tiers, sig, lower, floors[4], lo);
        need(set, tiers, sug, lower, floors[5], lo);
    }
    out
}

/// A file named by path, hash and size, never by content.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileHash {
    /// The path as given when relative (with `/`), the file name when
    /// absolute: enough to find it again, without saying where a reader
    /// keeps their data.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    pub sha256: String,
    pub bytes: u64,
}

pub fn sha256_hex(b: &[u8]) -> String {
    Sha256::digest(b)
        .iter()
        .map(|x| format!("{x:02x}"))
        .collect()
}

/// The path as a [`FileHash`] records it.
pub fn recorded_path(p: &Path) -> String {
    if p.is_absolute() {
        p.file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default()
    } else {
        p.to_string_lossy().replace('\\', "/")
    }
}

pub fn hash_file(p: &Path) -> Result<FileHash> {
    let b = std::fs::read(p).with_context(|| format!("reading {}", p.display()))?;
    Ok(FileHash {
        path: Some(recorded_path(p)),
        sha256: sha256_hex(&b),
        bytes: b.len() as u64,
    })
}

/// SHA-256 of rules text with line endings made `\n`, so a checkout with
/// CRLF line endings hashes the same rules the same.
pub fn rules_sha256(text: &str) -> String {
    sha256_hex(text.replace("\r\n", "\n").as_bytes())
}

/// The version of the saved-result format [`SavedResult`] writes.
pub const RESULT_SCHEMA: u32 = 2;

/// A saved result: numbers, hashes and the summary. No record content.
#[derive(Debug, Serialize)]
pub struct SavedResult<'a> {
    pub result_schema: u32,
    /// `regression`, `held_out` or `prospective` (manual FM-9.1).
    pub kind: &'a str,
    pub description: &'a str,
    pub rules_version: &'a str,
    /// [`rules_sha256`] of the rules the analysis ran with.
    pub rules_sha256: String,
    /// The rules file given with `--rules`; absent for the bundled rules.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rules_file: Option<String>,
    pub toolkit: Toolkit,
    pub records: Vec<FileHash>,
    pub labels: Vec<FileHash>,
    /// The id list scored, when restricted with `--only-ids`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub only_ids: Option<FileHash>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exclude_ids: Option<FileHash>,
    pub counts: Counts,
    /// Saved with `--allow-no-benign`: a result with no benign record, whose
    /// precision cannot be wrong and so says nothing.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub allow_no_benign: bool,
    pub summary: &'a Summary,
}

/// The counts a reader checks first.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Counts {
    pub labelled: usize,
    pub agents: usize,
    pub benign: usize,
    pub non_synthetic_labelled: usize,
    pub non_synthetic_benign: usize,
}

impl Counts {
    pub fn of(s: &Summary) -> Self {
        Self {
            labelled: s.labelled,
            agents: s.agents,
            benign: s.benign,
            non_synthetic_labelled: s.non_synthetic.labelled,
            non_synthetic_benign: s.non_synthetic.benign,
        }
    }
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
        let (_, _, s) = sc_core::summarize(&a, &labels, sc_core::DEFAULT_RULES, "").unwrap();
        // 1/1 precision: the point estimate is 100%, the lower bound ~20.7%.
        let f = Floors {
            min_significant_precision: Some(0.9),
            min_significant_precision_lower: Some(0.5),
            ..Default::default()
        };
        let fails = check(&s, &f);
        assert_eq!(fails.len(), 1, "{fails:?}");
        assert!(fails[0].contains("lower bound"), "{fails:?}");
    }

    #[test]
    fn non_synthetic_floors_read_the_non_synthetic_slice() {
        let labels = parse_labels(
            "{\"id\":\"x:1\",\"label\":\"agent\",\"synthetic\":true}\n\
             {\"id\":\"x:2\",\"label\":\"agent\"}\n",
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
        let (_, _, s) = sc_core::summarize(&a, &labels, sc_core::DEFAULT_RULES, "").unwrap();
        let f = Floors {
            min_significant_recall: Some(0.5),
            min_nonsynthetic_significant_recall: Some(0.5),
            ..Default::default()
        };
        let fails = check(&s, &f);
        assert_eq!(fails.len(), 1, "{fails:?}");
        assert!(
            fails[0].starts_with("non-synthetic significant recall 0.0%"),
            "{fails:?}"
        );
        assert_eq!(Counts::of(&s).non_synthetic_labelled, 1);
    }
}
