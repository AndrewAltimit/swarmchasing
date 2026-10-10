//! `eval` over the sample records: summary JSON, coverage gate, splits.

use crate::common::{Scratch, ok, run, samples, with_samples};

#[test]
fn summary_json_carries_numbers_not_records() {
    let s = Scratch::new("eval-summary");
    let files = samples();
    let out = s.path().join("summary.json");
    let out = out.to_str().unwrap();
    let r = ok(
        s.path(),
        &with_samples(&["eval", "--summary-json", out, "--show-fp", "0"], &files),
    );
    assert!(r.stdout.contains("Wilson"), "{}", r.stdout);
    let text = std::fs::read_to_string(out).unwrap();
    let v: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(v["schema"], 1);
    assert_eq!(v["tiers"].as_array().unwrap().len(), 2);
    assert!(v["tiers"][0]["precision"]["lo"].is_number());
    assert!(v["coverage"]["rules"].as_u64().unwrap() > 0);
    assert!(v["clusters"]["bcubed_f1"].is_number());
    assert!(
        !text.contains("eval:") && !text.contains("https://"),
        "record content leaked"
    );
}

#[test]
fn coverage_gate_needs_the_allow_list() {
    let s = Scratch::new("eval-coverage");
    let files = samples();
    let empty = s.path().join("allow.txt");
    std::fs::write(&empty, "# nothing allowed\n").unwrap();
    let r = run(
        s.path(),
        &with_samples(
            &[
                "eval",
                "--require-coverage",
                "--coverage-allow",
                empty.to_str().unwrap(),
            ],
            &files,
        ),
    );
    let allow = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../samples/eval/coverage-allow.txt");
    let listed = std::fs::read_to_string(&allow).unwrap();
    let has_entries = listed
        .lines()
        .any(|l| !l.trim().is_empty() && !l.starts_with('#'));
    assert_eq!(r.ok, !has_entries, "{}", r.stderr);
    ok(
        s.path(),
        &with_samples(
            &[
                "eval",
                "--require-coverage",
                "--coverage-allow",
                allow.to_str().unwrap(),
            ],
            &files,
        ),
    );
}

#[test]
fn split_writes_a_frozen_id_list_that_eval_can_score() {
    let s = Scratch::new("eval-split");
    let files = samples();
    let ids = s.path().join("holdout.txt");
    let ids = ids.to_str().unwrap();
    ok(
        s.path(),
        &with_samples(
            &[
                "eval",
                "--split",
                "cluster",
                "--seed",
                "3",
                "--split-out",
                ids,
            ],
            &files,
        ),
    );
    let text = std::fs::read_to_string(ids).unwrap();
    let held: Vec<&str> = text.lines().filter(|l| !l.starts_with('#')).collect();
    assert!(!held.is_empty());
    let result = s.path().join("result.json");
    let result = result.to_str().unwrap();
    let r = ok(
        s.path(),
        &with_samples(
            &[
                "eval",
                "--only-ids",
                ids,
                "--save-result",
                result,
                "--result-kind",
                "held_out",
                "--describe",
                "test split",
            ],
            &files,
        ),
    );
    assert!(
        r.stdout
            .contains(&format!("{} labelled records", held.len())),
        "{}",
        r.stdout
    );
    let v: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(result).unwrap()).unwrap();
    assert_eq!(v["kind"], "held_out");
    assert_eq!(v["records"].as_array().unwrap().len(), files.len());
    assert_eq!(v["only_ids"]["sha256"].as_str().unwrap().len(), 64);
}
