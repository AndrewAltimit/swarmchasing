//! `platform-swarms` over the synthetic GH Archive-style fixture: two
//! invented agent swarms among benign floods (a dependency bot, dependency
//! updates under user accounts, a contribution drive, an outage, an issue
//! template filled in over hours) and background comments. Scored like an
//! eval: every agent event found, no benign event reported.

use crate::common::{Scratch, ok};
use std::collections::BTreeSet;
use std::path::Path;

fn fixture() -> String {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/platform/synthetic-events.ndjson")
        .to_string_lossy()
        .into_owned()
}

#[test]
fn the_synthetic_swarms_are_found_and_the_benign_floods_are_not() {
    let s = Scratch::new("platform");
    let f = fixture();
    let r = ok(s.path(), &["platform-swarms", "--gharchive", &f, "--json"]);
    let rep: serde_json::Value = serde_json::from_str(&r.stdout).unwrap();
    let found: BTreeSet<String> = rep["swarms"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|s| s["members"].as_array().unwrap().iter())
        .map(|m| m.as_str().unwrap().to_string())
        .collect();
    let (mut agent, mut benign) = (BTreeSet::new(), BTreeSet::new());
    for line in std::fs::read_to_string(&f).unwrap().lines() {
        let v: serde_json::Value = serde_json::from_str(line).unwrap();
        assert_eq!(v["synthetic"], true);
        let id = format!("gh:{}", v["id"].as_str().unwrap());
        match v["sc_label"].as_str().unwrap() {
            "agent" => agent.insert(id),
            _ => benign.insert(id),
        };
    }
    let tp = found.intersection(&agent).count();
    assert_eq!(
        tp,
        agent.len(),
        "recall: missed {:?}",
        agent.difference(&found)
    );
    assert!(
        found.is_subset(&agent),
        "benign reported: {:?}",
        found.intersection(&benign)
    );
    assert_eq!(rep["swarms"].as_array().unwrap().len(), 2);
    let why: BTreeSet<&str> = rep["suppressed"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["why"].as_str().unwrap())
        .collect();
    assert_eq!(
        why,
        ["contribution drive", "dependency update"]
            .into_iter()
            .collect()
    );
    // No login and no URL from the text reaches the report.
    assert!(!r.stdout.contains("sec-research-"), "{}", r.stdout);
    assert!(!r.stdout.contains("handler_"), "{}", r.stdout);
}

#[test]
fn the_markdown_output_is_defanged() {
    let s = Scratch::new("platform-md");
    let r = ok(s.path(), &["platform-swarms", "--gharchive", &fixture()]);
    assert!(r.stdout.contains("Hints, not findings"), "{}", r.stdout);
    assert!(r.stdout.contains("hxxps://github[.]com/"), "{}", r.stdout);
    assert!(!r.stdout.contains("https://"), "{}", r.stdout);
}
