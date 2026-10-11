//! The SC-Rules v1 conformance vectors
//! ([`docs/specs/conformance/rules-v1.json`]) run through the engine: each
//! URL, analysed alone with the bundled rules, must give the vector's target
//! host, rule-id set, score and tier. A group that writes its own engine
//! checks it against the same file.
//!
//! After an intended scoring change, regenerate the vectors' `score` and
//! `tier` (and the target/rules, if they moved) with
//! `UPDATE_SNAPSHOTS=1 cargo test -p sc-core --test integration conformance::`
//! and review the diff; the `url` and `note` of each vector are authored by
//! hand and never rewritten.

use sc_core::{Rules, Tier, analyze};
use serde_json::Value;
use std::path::PathBuf;

fn spec_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../docs/specs/conformance/rules-v1.json")
}

fn tier_label(t: Tier) -> &'static str {
    match t {
        Tier::Noise => "noise",
        Tier::Suggestive => "suggestive",
        Tier::Significant => "significant",
    }
}

#[test]
fn conformance_vectors_hold() {
    let text = std::fs::read_to_string(spec_path()).unwrap();
    let mut doc: Value = serde_json::from_str(&text).unwrap();
    let rules = Rules::default_rules();
    let update = std::env::var_os("UPDATE_SNAPSHOTS").is_some();

    // The file declares the rules version and thresholds it was built with.
    assert_eq!(
        doc["rules_version"].as_str().unwrap(),
        rules.set.meta.version,
        "conformance rules_version is not the bundled rules version"
    );
    assert_eq!(
        doc["thresholds"]["suggestive"].as_i64().unwrap() as i32,
        rules.set.thresholds.suggestive
    );
    assert_eq!(
        doc["thresholds"]["significant"].as_i64().unwrap() as i32,
        rules.set.thresholds.significant
    );

    let vectors = doc["vectors"].as_array_mut().unwrap();
    let mut failures = Vec::new();
    for v in vectors.iter_mut() {
        let id = v["id"].as_str().unwrap().to_string();
        let url = v["url"].as_str().unwrap().to_string();
        let obs = sc_core::Observation {
            url: url.clone(),
            ts: 1,
            ..Default::default()
        };
        let a = analyze(vec![obs], &rules);
        let r = &a.results[0];
        let target = r.target_host.clone();
        let mut ids: Vec<String> = r.hits.iter().map(|h| h.rule_id.clone()).collect();
        ids.sort();
        ids.dedup();
        let score = r.score;
        let tier = tier_label(r.tier).to_string();

        if update {
            v["target"] = target.clone().map_or(Value::Null, Value::String);
            v["rules"] = Value::from(ids.clone());
            v["score"] = Value::from(score);
            v["tier"] = Value::from(tier.clone());
            continue;
        }

        let want_target = v["target"].as_str().map(str::to_string);
        let want_rules: Vec<String> = v["rules"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| x.as_str().unwrap().to_string())
            .collect();
        let want_score = v["score"].as_i64().unwrap() as i32;
        let want_tier = v["tier"].as_str().unwrap();
        if target != want_target || ids != want_rules || score != want_score || tier != want_tier {
            failures.push(format!(
                "{id}: target {target:?} (want {want_target:?}), rules {ids:?} (want {want_rules:?}), score {score} (want {want_score}), tier {tier} (want {want_tier})"
            ));
        }
    }

    if update {
        let mut out = serde_json::to_string_pretty(&doc).unwrap();
        out.push('\n');
        std::fs::write(spec_path(), out).unwrap();
        return;
    }
    assert!(
        failures.is_empty(),
        "conformance vectors differ (set UPDATE_SNAPSHOTS=1 to regenerate and review):\n{}",
        failures.join("\n")
    );
}
