//! `eval export-bench` and `eval --bench`: write an SC-Bench file
//! ([`sc_core::eval::bench`]) and score a detector against one.

use super::{load_labels, print_tiers, rules_sha256};
use crate::commands::eval::BenchArgs;
use crate::input::{InputArgs, read_records};
use anyhow::{Context, Result, bail};
use sc_core::eval::bench::{self, Bench, BenchMeta};
use std::path::Path;

pub fn export(args: &BenchArgs) -> Result<()> {
    match args.split.as_str() {
        "regression" | "held_out" | "prospective" => {}
        s => bail!("unknown --split `{s}` (regression | held_out | prospective)"),
    }
    let labels = load_labels(&args.labels, &args.input)?;
    let rules = crate::pinning::RulesText::load(args.rules.as_deref())?;
    let a = sc_core::analyze(
        read_records(&InputArgs::files(args.input.clone()))?,
        &rules.rules,
    );
    let held_out = match &args.held_out_ids {
        Some(p) => sc_core::eval::split::parse_id_list(
            &std::fs::read_to_string(p).with_context(|| format!("reading {}", p.display()))?,
        ),
        None => Vec::new(),
    };
    let freeze = args
        .freeze_date
        .map_or_else(crate::util::today, |d| d.to_string());
    let sha = rules_sha256(&rules.text);
    let b = bench::build(
        &a,
        &labels,
        &BenchMeta {
            name: &args.name,
            description: &args.describe,
            freeze_date: &freeze,
            rules_sha256: &sha,
            toolkit_version: env!("CARGO_PKG_VERSION"),
            split: &args.split,
            held_out: &held_out,
            default_labeller: &args.labeller,
        },
    );
    let problems = bench::validate(&b);
    if !problems.is_empty() {
        bail!("bench does not validate: {}", problems.join("; "));
    }
    if !bench::reference_matches(&a, &labels, &b) {
        bail!("bench reference tiers do not score as the analysis did");
    }
    let mut json = serde_json::to_value(&b)?;
    if let Some(m) = json.as_object_mut() {
        // Put `$schema` first for editors that validate on it.
        let mut out = serde_json::Map::new();
        out.insert(
            "$schema".into(),
            "https://github.com/AndrewAltimit/swarmchasing/blob/main/schemas/sc-bench-v1.json"
                .into(),
        );
        out.append(m);
        json = serde_json::Value::Object(out);
    }
    crate::util::write_out(
        Some(&args.out),
        &(serde_json::to_string_pretty(&json)? + "\n"),
    )?;
    let labelled = b.records.iter().filter(|r| r.label.is_some()).count();
    eprintln!(
        "{}: {} records ({labelled} labelled), rules {}, frozen {freeze}",
        args.out.display(),
        b.records.len(),
        b.rules_version
    );
    Ok(())
}

pub fn score_file(path: &Path, predictions: Option<&Path>, json: Option<&Path>) -> Result<()> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let b: Bench =
        serde_json::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
    let problems = bench::validate(&b);
    if !problems.is_empty() {
        bail!(
            "{} does not validate: {}",
            path.display(),
            problems.join("; ")
        );
    }
    let preds = match predictions {
        Some(p) => Some(
            bench::parse_predictions(
                &std::fs::read_to_string(p).with_context(|| format!("reading {}", p.display()))?,
            )
            .map_err(anyhow::Error::msg)?,
        ),
        None => None,
    };
    let s = bench::score(&b, preds.as_ref());
    println!(
        "bench {} · frozen {} · reference rules {} · scoring {}{}",
        b.name,
        b.freeze_date,
        b.rules_version,
        s.detector,
        if s.missing_predictions > 0 {
            format!(
                " · {} labelled records without a prediction, scored unflagged",
                s.missing_predictions
            )
        } else {
            String::new()
        }
    );
    println!("intervals are 95% Wilson score intervals; n is the denominator");
    for sp in &s.splits {
        for sl in [&sp.all, &sp.non_synthetic] {
            if sl.labelled == 0 {
                continue;
            }
            let head = format!(
                "split {} · {} · {} labelled ({} agent, {} benign)",
                sp.split, sl.name, sl.labelled, sl.agents, sl.benign
            );
            print_tiers(&format!("{head} · record unit"), &sl.tiers);
            print_tiers(&format!("{head} · cluster unit"), &sl.cluster_tiers);
        }
    }
    if let Some(p) = json {
        crate::util::write_out(Some(p), &serde_json::to_string_pretty(&s)?)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_committed_example_parses_validates_and_holds_no_url() {
        let text = include_str!("../../../../samples/eval/bench/sc-bench-v1-example.json");
        let b: Bench = serde_json::from_str(text).unwrap();
        assert!(bench::validate(&b).is_empty(), "{:?}", bench::validate(&b));
        assert!(
            b.records
                .iter()
                .all(|r| r.provenance != "collected" && r.source == "eval"),
            "the example is built from committed samples only"
        );
        // The only URL is the schema's.
        assert_eq!(text.matches("://").count(), 1);
        let s = bench::score(&b, None);
        assert!(s.splits[0].all.labelled > 0);
    }
}
