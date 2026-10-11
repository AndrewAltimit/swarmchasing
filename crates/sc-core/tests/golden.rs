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
    let parsed_labels = parse_labels(&text);
    labels.labels.extend(parsed_labels.labels);
    labels.actors.extend(parsed_labels.actors);
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
        (126, 0, 7, 82),
        "suggestive or above"
    );
    assert_eq!(counts(Tier::Significant), (52, 0, 81, 82), "significant");

    let tiers: Vec<usize> = [Tier::Noise, Tier::Suggestive, Tier::Significant]
        .iter()
        .map(|t| a.tier_counts.get(t).copied().unwrap_or(0))
        .collect();
    assert_eq!(a.total, 251);
    assert_eq!(
        tiers,
        [91, 76, 84],
        "records per tier (noise, suggestive, significant)"
    );
    assert_eq!(a.clusters.len(), 33, "clusters");

    // Agent grades by actor: no scanner run and no hand-typed pentest grades
    // above L0; a person pasting chatbot payloads reaches L3, the grade's
    // documented limit.
    let g = &report.grades.rows;
    let above = |actor: &str, from: usize| -> usize {
        sc_core::eval::grades::COLUMNS[from..]
            .iter()
            .map(|c| g[actor].get(*c).copied().unwrap_or(0))
            .sum()
    };
    assert_eq!(above("tool", 3), 0, "tool runs above L0: {g:?}");
    assert_eq!(g["human"].get("L3"), Some(&4), "{g:?}");
    assert_eq!(above("human", 6), 0, "human runs at L4: {g:?}");

    // Every benign record says what kind of traffic it is.
    assert!(
        report.benign_classes.iter().all(|c| c.class != "unclassed"),
        "{:?}",
        report.benign_classes
    );
    // Two readers sharing a popular campaign tag months apart stay apart:
    // a feature links only within the link window.
    let c = &report.clusters;
    assert!(
        !c.false_merges
            .iter()
            .any(|m| m.runs == ["benign-tag-reader-1", "benign-tag-reader-2"]),
        "{c:?}"
    );
    // A record planted beside a run, minutes later on the same host and
    // sharing only a context rule (a relay, a cache buster), stays out of it.
    assert!(
        !c.false_merges
            .iter()
            .any(|m| m.runs.iter().any(|r| r.starts_with("plant-"))),
        "{c:?}"
    );
    assert!(c.run_labelled > 0 && c.bcubed_precision.is_some());

    // Interaction edges: each labelled swarm has one inside it; the sharded
    // scheduler (labelled `none`) gets only a disjoint partition, the fleet
    // signal that one scheduler produces alone.
    let w = &report.swarm;
    assert_eq!(w.found, w.groups, "{w:?}");
    assert_eq!(w.groups.len(), 3, "{w:?}");
    assert_eq!((w.edges, w.on_groups, w.across_groups), (4, 3, 0), "{w:?}");
    assert_eq!(w.on_non_swarm, [0, 0, 0, 0, 1], "S5 only: {w:?}");
}
