//! End to end on the labelled evaluation set (`samples/eval/*.ndjson`):
//! ingest, analyse and score, then compare with the numbers the eval gate
//! last accepted. A change that moves them updates them here and gives the
//! before and after in its commit message.

use sc_core::{
    FieldMap, Format, LabelSet, Rules, Tier, analyze, evaluate, parse_input, parse_labels,
};
use std::path::PathBuf;

fn eval_set() -> String {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../samples/eval");
    let mut files: Vec<PathBuf> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|x| x == "ndjson"))
        .collect();
    files.sort();
    assert!(
        !files.is_empty(),
        "no evaluation records in {}",
        dir.display()
    );
    files
        .iter()
        .map(|p| std::fs::read_to_string(p).unwrap())
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn evaluation_set_numbers_hold() {
    let text = eval_set();
    let rules = Rules::default_rules();
    let mut labels = LabelSet::default();
    labels.labels.extend(parse_labels(&text).labels);
    let parsed = parse_input(&text, Format::Ndjson, &FieldMap::default());
    let a = analyze(parsed.observations, &rules);
    let report = evaluate(&a, &labels);

    // (true positives, false positives, false negatives, true negatives)
    let counts = |t: Tier| {
        let x = report.threshold(t).unwrap();
        (x.tp, x.fp, x.fn_, x.tn)
    };
    assert_eq!(
        counts(Tier::Suggestive),
        (67, 0, 6, 68),
        "suggestive or above"
    );
    assert_eq!(counts(Tier::Significant), (29, 0, 44, 68), "significant");

    let tiers: Vec<usize> = [Tier::Noise, Tier::Suggestive, Tier::Significant]
        .iter()
        .map(|t| a.tier_counts.get(t).copied().unwrap_or(0))
        .collect();
    assert_eq!(a.total, 141);
    assert_eq!(
        tiers,
        [74, 38, 29],
        "records per tier (noise, suggestive, significant)"
    );
    assert_eq!(a.clusters.len(), 17, "clusters");

    // Every benign record says what kind of traffic it is.
    assert!(
        report.benign_classes.iter().all(|c| c.class != "unclassed"),
        "{:?}",
        report.benign_classes
    );
    // The two readers sharing a popular campaign tag months apart are
    // merged: linking's known false merge, reported, not gated.
    let c = &report.clusters;
    assert!(
        c.false_merges
            .iter()
            .any(|m| m.runs == ["benign-tag-reader-1", "benign-tag-reader-2"]),
        "{c:?}"
    );
    assert!(c.run_labelled > 0 && c.bcubed_precision.is_some());
}
