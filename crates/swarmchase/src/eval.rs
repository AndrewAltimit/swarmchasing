//! `swarmchase eval`: precision and recall of the rules on labelled records,
//! optionally as a gate that fails below set floors (CI runs it on
//! `samples/eval/`).

use anyhow::{Context, Result, bail};
use sc_core::eval::{EvalReport, LabelSet, Threshold};
use sc_core::{Analysis, Tier, parse_labels};
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

fn pct(x: Option<f64>) -> String {
    x.map_or("n/a".into(), |v| format!("{:.1}%", v * 100.0))
}

pub fn print(r: &EvalReport, labels: &LabelSet, show_fp: usize) {
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
    println!(
        "\n{:<22} {:>5} {:>5} {:>5} {:>5}  {:>9} {:>9}",
        "threshold", "tp", "fp", "fn", "tn", "precision", "recall"
    );
    for t in &r.thresholds {
        println!(
            "{:<22} {:>5} {:>5} {:>5} {:>5}  {:>9} {:>9}",
            format!("{} or above", t.tier.label()),
            t.tp,
            t.fp,
            t.fn_,
            t.tn,
            pct(t.precision),
            pct(t.recall)
        );
    }
    if !r.classes.is_empty() {
        println!(
            "\n{:<22} {:>6} {:>11} {:>12}",
            "agent class", "n", "flagged", "significant"
        );
        for c in &r.classes {
            println!(
                "{:<22} {:>6} {:>11} {:>12}",
                c.class,
                c.agents,
                pct(Some(c.suggestive_or_above as f64 / c.agents as f64)),
                pct(Some(c.significant as f64 / c.agents as f64)),
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
        "\n{:<32} {:>6} {:>7} {:>9}",
        "rule", "agent", "benign", "precision"
    );
    for s in &r.rules {
        println!(
            "{:<32} {:>6} {:>7} {:>9}",
            s.rule_id,
            s.on_agent,
            s.on_benign,
            pct(s.precision)
        );
    }
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
                crate::truncate(&m.url, 140)
            );
        }
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
    out
}

pub fn run(
    a: &Analysis,
    labels: &LabelSet,
    floors: &Floors,
    json: Option<&Path>,
    show_fp: usize,
) -> Result<()> {
    let r = sc_core::evaluate(a, labels);
    print(&r, labels, show_fp);
    if let Some(p) = json {
        crate::write_out(Some(p), &serde_json::to_string_pretty(&r)?)?;
    }
    let failures = check(&r, floors);
    if !failures.is_empty() {
        for f in &failures {
            eprintln!("eval gate: {f}");
        }
        bail!("eval gate failed ({} floor(s) not met)", failures.len());
    }
    Ok(())
}
