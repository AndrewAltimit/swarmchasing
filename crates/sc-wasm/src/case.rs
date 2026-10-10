//! Evidence bundle check for the Case tab. The page checks the manifest
//! hashes itself (Web Crypto); this re-runs the analysis and compares it with
//! the stamp, as `swarmchase case verify` does.

use sc_core::{Analysis, Rules, Stamp, analyze};
use wasm_bindgen::prelude::*;

/// Re-run a bundle's analysis and compare it with its stamp. `rules_toml`
/// empty means the bundled rules. Returns `{"stamp": Stamp, "differences":
/// [...], "notes": [...], "rules_version": "...", "analysis": Analysis}`;
/// no differences means the bundle verifies. `analysis` is the re-run, not
/// the bundle's copy.
#[wasm_bindgen]
pub fn verify_bundle(
    records_ndjson: &str,
    analysis_json: &str,
    stamp_json: &str,
    rules_toml: &str,
) -> Result<String, JsError> {
    let rules = super::rules_from(rules_toml)?;
    let out =
        check(records_ndjson, analysis_json, stamp_json, &rules).map_err(|e| JsError::new(&e))?;
    serde_json::to_string(&out).map_err(|e| JsError::new(&e.to_string()))
}

fn check(
    records_ndjson: &str,
    analysis_json: &str,
    stamp_json: &str,
    rules: &Rules,
) -> Result<serde_json::Value, String> {
    let st: Stamp = serde_json::from_str(stamp_json).map_err(|e| format!("stamp.json: {e}"))?;
    let records = sc_core::stamp::parse_records(records_ndjson)
        .map_err(|e| format!("records.ndjson: {e}"))?;
    let mut differences = Vec::new();
    let mut notes = Vec::new();
    if st.rules_version != rules.set.meta.version {
        differences.push(format!(
            "rules version {} differs from the bundle's {}; load the rules it was made with in the Rules tab",
            rules.set.meta.version, st.rules_version
        ));
    }
    let a = analyze(records, rules);
    differences.extend(st.differences(&a));
    // The bundle's own analysis should match its stamp too. A copy this
    // toolkit version cannot read is noted, not failed: the re-run above is
    // what the check rests on.
    if !analysis_json.trim().is_empty() {
        match serde_json::from_str::<Analysis>(analysis_json) {
            Ok(stored) => differences.extend(
                st.differences(&stored)
                    .into_iter()
                    .map(|d| format!("analysis.json: {d}")),
            ),
            Err(e) => notes.push(format!("analysis.json not compared: {e}")),
        }
    }
    if st.toolkit_version != env!("CARGO_PKG_VERSION") {
        notes.push(format!(
            "made with toolkit {}, checked with {}",
            st.toolkit_version,
            env!("CARGO_PKG_VERSION")
        ));
    }
    Ok(serde_json::json!({
        "stamp": st,
        "differences": differences,
        "notes": notes,
        "rules_version": rules.set.meta.version,
        "analysis": a,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sc_core::Observation;

    fn bundle(rules: &Rules) -> (String, String, String) {
        let records: Vec<Observation> = (0..4)
            .map(|i| Observation {
                id: format!("r{i}"),
                ts: 1_791_000_000 + i * 40,
                url: format!(
                    "https://r.jina.ai/https://portal.example.gov/q?id={i}%20UNION%20SELECT%201&uqtag=zz9"
                ),
                ..Default::default()
            })
            .collect();
        let nd: String = records
            .iter()
            .map(|r| serde_json::to_string(r).unwrap() + "\n")
            .collect();
        let a = analyze(records, rules);
        let st = Stamp::new("t-1", "2026-10-12", env!("CARGO_PKG_VERSION"), None, &a);
        (
            nd,
            serde_json::to_string(&a).unwrap(),
            serde_json::to_string(&st).unwrap(),
        )
    }

    fn diffs(v: &serde_json::Value) -> Vec<String> {
        serde_json::from_value(v["differences"].clone()).unwrap()
    }

    #[test]
    fn a_fresh_bundle_verifies() {
        let rules = Rules::default_rules();
        let (nd, a, st) = bundle(&rules);
        let v = check(&nd, &a, &st, &rules).unwrap();
        assert!(diffs(&v).is_empty(), "{v}");
        assert_eq!(v["stamp"]["case"], "t-1");
        assert_eq!(v["analysis"]["total"], 4);
        assert_eq!(v["notes"].as_array().unwrap().len(), 0);
        // The binding's own path, with bundled rules.
        assert!(verify_bundle(&nd, &a, &st, "").is_ok());
    }

    #[test]
    fn dropped_records_and_other_rules_are_differences() {
        let rules = Rules::default_rules();
        let (nd, a, st) = bundle(&rules);
        let fewer: String = nd.lines().skip(1).map(|l| format!("{l}\n")).collect();
        let d = diffs(&check(&fewer, &a, &st, &rules).unwrap());
        assert!(d.iter().any(|x| x == "3 records, stamp says 4"), "{d:?}");
        assert!(!d.iter().any(|x| x.starts_with("analysis.json")), "{d:?}");

        let other = st.replace(&rules.set.meta.version, "0000-00-00");
        let d = diffs(&check(&nd, &a, &other, &rules).unwrap());
        assert!(d[0].starts_with("rules version "), "{d:?}");
    }

    #[test]
    fn analysis_copy_is_compared_or_noted() {
        let rules = Rules::default_rules();
        let (nd, _, st) = bundle(&rules);
        let empty = serde_json::to_string(&analyze(Vec::new(), &rules)).unwrap();
        let d = diffs(&check(&nd, &empty, &st, &rules).unwrap());
        assert!(d.iter().any(|x| x.starts_with("analysis.json: ")), "{d:?}");

        let v = check(&nd, "{}", &st, &rules).unwrap();
        assert!(diffs(&v).is_empty(), "{v}");
        assert!(
            v["notes"][0]
                .as_str()
                .unwrap()
                .starts_with("analysis.json not compared")
        );
    }

    #[test]
    fn bad_input_is_an_error() {
        let rules = Rules::default_rules();
        let (nd, a, st) = bundle(&rules);
        assert!(
            check(&nd, &a, "{", &rules)
                .unwrap_err()
                .starts_with("stamp.json")
        );
        assert!(
            check("{bad", &a, &st, &rules)
                .unwrap_err()
                .starts_with("records.ndjson: line 1")
        );
    }
}
