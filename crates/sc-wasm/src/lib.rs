//! Browser bindings. Everything crosses the boundary as JSON strings so the
//! page needs nothing but `JSON.parse`.

use sc_core::eval::LabelSet;
use sc_core::timing::{DateTagOffset, infer_offset, parse_date_tag};
use sc_core::{Analysis, Claim, Evidence, FieldMap, Format, Label, ReportOptions, Rules, Tier};
use std::collections::{BTreeMap, HashSet};
use wasm_bindgen::prelude::*;

mod case;

/// The labelled evaluation set: `(file name, NDJSON)` for every
/// `samples/eval/*.ndjson`, embedded by `build.rs`.
mod eval_set {
    include!(concat!(env!("OUT_DIR"), "/eval_set.rs"));
}

/// Fully synthetic example records (none were collected), offered by the
/// page's "Try an example" button.
const EXAMPLE: &str = include_str!("../../../samples/eval/llm-residue.ndjson");

/// Fields of the evaluation set that carry the answer, stripped from the example.
const LABEL_FIELDS: [&str; 3] = ["label", "class", "cite"];

/// Longest URL, in characters, an eval result carries.
const SHORT_URL: usize = 120;

fn rules_from(text: &str) -> Result<Rules, JsError> {
    if text.trim().is_empty() {
        Ok(Rules::default_rules())
    } else {
        Rules::from_toml(text).map_err(|e| JsError::new(&e))
    }
}

#[wasm_bindgen]
pub fn version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

#[wasm_bindgen]
pub fn default_rules() -> String {
    sc_core::DEFAULT_RULES.to_string()
}

/// Validate rules; returns `{"rules":n,"asns":n,"version":"..."}`.
#[wasm_bindgen]
pub fn check_rules(rules_toml: &str) -> Result<String, JsError> {
    let r = rules_from(rules_toml)?;
    Ok(serde_json::json!({"rules": r.set.rules.len(), "asns": r.set.asns.len(), "version": r.set.meta.version}).to_string())
}

/// Parse + analyse. `format`: auto|ndjson|json|lines. `map`: `ts=a.b,url=c` or empty.
/// Returns `{"analysis": Analysis, "warnings": [...], "redacted": n,
/// "cluster_date_tags": {"C1": DateTagOffset}}`. Secrets are replaced with
/// hashes before analysis (see `sc_core::redact`).
#[wasm_bindgen]
pub fn analyze(input: &str, format: &str, map: &str, rules_toml: &str) -> Result<String, JsError> {
    let rules = rules_from(rules_toml)?;
    let format: Format = format.parse().map_err(|e: String| JsError::new(&e))?;
    let map = if map.trim().is_empty() {
        FieldMap::default()
    } else {
        FieldMap::parse(map).map_err(|e| JsError::new(&e))?
    };
    let parsed = sc_core::parse_input(input, format, &map);
    let a = sc_core::analyze(parsed.observations, &rules);
    serde_json::to_string(&serde_json::json!({
        "cluster_date_tags": cluster_date_tags(&a),
        "analysis": a,
        "warnings": parsed.warnings,
        "redacted": parsed.redacted,
    }))
    .map_err(|e| JsError::new(&e.to_string()))
}

/// The operator clock offset implied by each cluster's date tags, read the
/// way `analyze` reads them for the whole input. The parameters the tags sit
/// in are not serialised, so this runs on the analysis before it is.
fn cluster_date_tags(a: &Analysis) -> BTreeMap<String, DateTagOffset> {
    a.clusters
        .iter()
        .map(|c| {
            let samples: Vec<_> = c
                .members
                .iter()
                .map(|&m| &a.results[m])
                .filter(|r| r.obs.ts > 0)
                .filter_map(|r| {
                    r.layers
                        .iter()
                        .flat_map(|l| l.params.iter())
                        .find_map(|(_, v)| parse_date_tag(v))
                        .map(|d| (r.obs.ts, d))
                })
                .collect();
            (c.id.clone(), infer_offset(&samples))
        })
        .collect()
}

/// Unwrap a single URL; returns `{"layers": [...], "extracted": {...}}`.
#[wasm_bindgen]
pub fn unwrap(url: &str, rules_toml: &str) -> Result<String, JsError> {
    let rules = rules_from(rules_toml)?;
    let obs = sc_core::Observation {
        url: url.to_string(),
        ..Default::default()
    };
    let x = sc_core::extract(&obs, &rules);
    serde_json::to_string(&x).map_err(|e| JsError::new(&e.to_string()))
}

/// Evidence levels that may name a developer, weakest first, and the default:
/// `{"levels":[{"id":"hosting_asn","label":"..."}],"default":"shared_identifiers"}`.
/// Levels below the floor are left out: self-identification alone names no one.
#[wasm_bindgen]
pub fn evidence_levels() -> String {
    let levels: Vec<_> = Evidence::ALL
        .into_iter()
        .filter(|e| *e >= Evidence::FLOOR)
        .map(|e| serde_json::json!({"id": e.id(), "label": e.describe()}))
        .collect();
    serde_json::json!({"levels": levels, "default": Evidence::default().id()}).to_string()
}

/// Validate claims established by case work (the same JSON array the CLI's
/// `report --claims` reads). Empty input is no claims. Returns the claims
/// re-serialised, so the page passes on exactly what was checked.
#[wasm_bindgen]
pub fn check_claims(claims_json: &str) -> Result<String, JsError> {
    let claims = parse_claims(claims_json).map_err(|e| JsError::new(&e))?;
    serde_json::to_string(&claims).map_err(|e| JsError::new(&e.to_string()))
}

fn parse_claims(text: &str) -> Result<Vec<Claim>, String> {
    if text.trim().is_empty() {
        return Ok(Vec::new());
    }
    serde_json::from_str(text).map_err(|e| format!("claims: {e}"))
}

/// Render a Markdown draft from an analysis JSON (the `analysis` field from `analyze`).
/// `opts` is ReportOptions JSON: `{"audience":"provider","cluster":"C1","reporter":"...",
/// "generated":"2026-10-09","min_named":"shared_identifiers","claims":[...]}`. A developer
/// is named outside case notes only on evidence at or above `min_named`, as in the CLI.
#[wasm_bindgen]
pub fn report(analysis_json: &str, opts_json: &str) -> Result<String, JsError> {
    let a: sc_core::Analysis =
        serde_json::from_str(analysis_json).map_err(|e| JsError::new(&format!("analysis: {e}")))?;
    let opts: ReportOptions = if opts_json.trim().is_empty() {
        ReportOptions::default()
    } else {
        serde_json::from_str(opts_json).map_err(|e| JsError::new(&format!("options: {e}")))?
    };
    Ok(sc_core::render_markdown(&a, &opts))
}

/// Per-host view of an analysis JSON. `opts` is EndpointOptions JSON
/// (`{"min_tier":"suggestive","now":0,"active_days":7}`) or empty for defaults.
#[wasm_bindgen]
pub fn endpoints(analysis_json: &str, opts_json: &str) -> Result<String, JsError> {
    let a: sc_core::Analysis =
        serde_json::from_str(analysis_json).map_err(|e| JsError::new(&format!("analysis: {e}")))?;
    let opts: sc_core::EndpointOptions = if opts_json.trim().is_empty() {
        sc_core::EndpointOptions::default()
    } else {
        serde_json::from_str(opts_json).map_err(|e| JsError::new(&format!("options: {e}")))?
    };
    serde_json::to_string(&sc_core::endpoints(&a, &opts)).map_err(|e| JsError::new(&e.to_string()))
}

#[wasm_bindgen]
pub fn defang(text: &str) -> String {
    sc_core::defang(text)
}

#[wasm_bindgen]
pub fn parse_security_txt(text: &str) -> String {
    serde_json::to_string(&sc_core::parse_security_txt(text)).unwrap_or_default()
}

/// The example records as NDJSON with their label fields removed. They are
/// synthetic: written to exercise the rules, never collected.
#[wasm_bindgen]
pub fn example_records() -> String {
    EXAMPLE
        .lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .filter_map(|mut v| {
            let m = v.as_object_mut()?;
            for k in LABEL_FIELDS {
                m.remove(k);
            }
            Some(v.to_string())
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Score rules against the bundled labelled set, as `swarmchase eval
/// samples/eval/*.ndjson` does. Returns `{"rules_version", "files", "labelled",
/// "agents", "benign", "missing_records", "thresholds": [{"tier", "tp", "fp",
/// "fn", "tn", "precision", "recall"}], "records": [...], "misclassified": [...]}`.
/// `records` holds every labelled record (`id`, `label`, `tier`, `score`,
/// `rules`, `url` defanged and cut short) so the page can compare two rule
/// sets; `misclassified` holds those the suggestive-or-above call gets wrong.
#[wasm_bindgen]
pub fn eval_labelled(rules_toml: &str) -> Result<String, JsError> {
    let rules = rules_from(rules_toml)?;
    serde_json::to_string(&eval_with(&rules)).map_err(|e| JsError::new(&e.to_string()))
}

fn eval_with(rules: &Rules) -> serde_json::Value {
    let mut input = String::new();
    let mut labels = LabelSet::default();
    for (_, text) in eval_set::EVAL_SET {
        input.push_str(text);
        input.push('\n');
        let l = sc_core::parse_labels(text);
        labels.skipped += l.skipped;
        labels.labels.extend(l.labels);
    }
    let parsed = sc_core::parse_input(&input, Format::Ndjson, &FieldMap::default());
    let a = sc_core::analyze(parsed.observations, rules);
    let report = sc_core::evaluate(&a, &labels);

    let mut seen = HashSet::new();
    let mut records = Vec::new();
    let mut misclassified = Vec::new();
    for r in &a.results {
        let Some(l) = labels.labels.get(&r.obs.id) else {
            continue;
        };
        if !seen.insert(r.obs.id.as_str()) {
            continue;
        }
        let mut ids: Vec<&str> = r.hits.iter().map(|h| h.rule_id.as_str()).collect();
        ids.sort_unstable();
        ids.dedup();
        let rec = serde_json::json!({
            "id": r.obs.id,
            "label": l.label,
            "tier": r.tier,
            "score": r.score,
            "rules": ids,
            "url": short_url(&r.obs.url),
        });
        if (l.label == Label::Agent) != (r.tier >= Tier::Suggestive) {
            misclassified.push(rec.clone());
        }
        records.push(rec);
    }
    serde_json::json!({
        "rules_version": report.rules_version,
        "files": eval_set::EVAL_SET.iter().map(|(name, _)| name).collect::<Vec<_>>(),
        "labelled": report.labelled,
        "agents": report.agents,
        "benign": report.benign,
        "missing_records": report.missing_records,
        "thresholds": report.thresholds,
        "records": records,
        "misclassified": misclassified,
    })
}

fn short_url(url: &str) -> String {
    let safe = sc_core::defang(url);
    let cut: String = safe.chars().take(SHORT_URL).collect();
    if cut.len() < safe.len() {
        cut + "…"
    } else {
        cut
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn draft(min_named: &str, evidence: &str) -> String {
        let a = sc_core::analyze(Vec::new(), &Rules::default_rules());
        let opts = serde_json::json!({
            "audience": "provider",
            "min_named": min_named,
            "claims": [{"party": "Example AI", "role": "developer", "evidence": evidence, "details": ["case work"]}],
        });
        let Ok(md) = report(&serde_json::to_string(&a).unwrap(), &opts.to_string()) else {
            panic!("report failed");
        };
        md
    }

    #[test]
    fn report_follows_the_naming_gate() {
        let named = "**Example AI** (developer)";
        assert!(draft("shared_identifiers", "shared_identifiers").contains(named));
        let md = draft("provider_confirmed", "shared_identifiers");
        assert!(!md.contains("Example AI"), "{md}");
        // Below the floor, the floor applies.
        let md = draft("self_id", "self_id");
        assert!(!md.contains("Example AI"), "{md}");
    }

    #[test]
    fn levels_start_at_the_floor() {
        let v: serde_json::Value = serde_json::from_str(&evidence_levels()).unwrap();
        let ids: Vec<&str> = v["levels"]
            .as_array()
            .unwrap()
            .iter()
            .map(|l| l["id"].as_str().unwrap())
            .collect();
        assert_eq!(ids.first(), Some(&Evidence::FLOOR.id()));
        assert!(ids.contains(&v["default"].as_str().unwrap()));
    }

    #[test]
    fn claims_are_checked_against_the_cli_schema() {
        assert_eq!(parse_claims("  ").unwrap(), Vec::new());
        let ok = r#"[{"party":"Example AI","role":"developer","evidence":"provider_confirmed"}]"#;
        assert_eq!(
            parse_claims(ok).unwrap()[0].evidence,
            Evidence::ProviderConfirmed
        );
        assert!(parse_claims(r#"[{"party":"X","role":"developer","evidence":"rumour"}]"#).is_err());
    }

    #[test]
    fn eval_set_is_the_committed_ndjson() {
        let names: Vec<&str> = eval_set::EVAL_SET.iter().map(|(n, _)| *n).collect();
        assert!(names.contains(&"llm-residue.ndjson"), "{names:?}");
        assert!(names.contains(&"published-patterns.ndjson"), "{names:?}");
        assert!(names.iter().all(|n| n.ends_with(".ndjson")));
    }

    // The set grows; assert shape and sanity, not exact counts.
    #[test]
    fn bundled_rules_hold_up_on_the_labelled_set() {
        let v = eval_with(&Rules::default_rules());
        let labelled = v["labelled"].as_u64().unwrap();
        assert!(labelled > 0);
        assert_eq!(v["records"].as_array().unwrap().len() as u64, labelled);
        let tiers: Vec<&str> = v["thresholds"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["tier"].as_str().unwrap())
            .collect();
        assert_eq!(tiers, ["suggestive", "significant"]);
        for t in v["thresholds"].as_array().unwrap() {
            assert!(t["precision"].as_f64().unwrap() > 0.9, "{t}");
            assert!(t["recall"].as_f64().unwrap() > 0.0, "{t}");
            assert!(t.get("fn").is_some());
        }
        let ids: HashSet<&str> = v["records"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["id"].as_str().unwrap())
            .collect();
        for m in v["misclassified"].as_array().unwrap() {
            assert!(ids.contains(m["id"].as_str().unwrap()));
            assert!(m["url"].as_str().unwrap().chars().count() <= SHORT_URL + 1);
            let url = m["url"].as_str().unwrap().to_ascii_lowercase();
            assert!(!url.contains("http://") && !url.contains("https://"), "{m}");
        }
    }

    #[test]
    fn example_is_synthetic_and_unlabelled() {
        assert!(EXAMPLE.lines().all(|l| l.contains(r#""synthetic": true"#)));
        let ex = example_records();
        assert_eq!(ex.lines().count(), EXAMPLE.lines().count());
        for l in ex.lines() {
            let v: serde_json::Value = serde_json::from_str(l).unwrap();
            for k in LABEL_FIELDS {
                assert!(v.get(k).is_none(), "{k} left in {l}");
            }
            assert!(v["url"].is_string() && v["id"].is_string());
        }
    }

    #[test]
    fn analysis_carries_a_date_tag_offset_per_cluster() {
        let Ok(out) = analyze(&example_records(), "ndjson", "", "") else {
            panic!("analyze failed");
        };
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        let ids: Vec<&str> = v["analysis"]["clusters"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| c["id"].as_str().unwrap())
            .collect();
        let keys: Vec<&str> = v["cluster_date_tags"]
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(keys.len(), ids.len());
        assert!(ids.iter().all(|id| keys.contains(id)));
        assert!(v["analysis"]["total"].as_u64().unwrap() > 0);
    }
}
