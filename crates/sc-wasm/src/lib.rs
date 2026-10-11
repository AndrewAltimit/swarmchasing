//! Browser bindings. Everything crosses the boundary as JSON strings so the
//! page needs nothing but `JSON.parse`.
//!
//! Rules arrive as JSON: the bundled rules are converted when the module is
//! built, and edited rules (TOML, as the CLI reads them) by the small
//! `sc-rules-wasm` module, which keeps a TOML parser out of this one.
//!
//! `analyze` keeps its result in this module, and `report` and `endpoints`
//! read it from there, so the page never sends a whole analysis back across
//! the boundary and the module carries no deserialiser for one.

use sc_core::eval::LabelSet;
use sc_core::timing::DateTagOffset;
use sc_core::{
    Analysis, Claim, Evidence, FieldMap, Format, Label, ReportOptions, RuleSet, Rules, Tier,
};
use std::cell::RefCell;
use std::collections::{BTreeMap, HashSet};
use wasm_bindgen::prelude::*;

mod case;

/// Longest URL, in characters, an eval result carries.
const SHORT_URL: usize = 120;

thread_local! {
    /// The most recent `analyze` result.
    static LAST: RefCell<Option<Analysis>> = const { RefCell::new(None) };
}

/// `rules/default.toml` as JSON, converted by `build.rs`.
const DEFAULT_RULES_JSON: &str = include_str!(concat!(env!("OUT_DIR"), "/default_rules.json"));

/// A rule set from its JSON; empty means the bundled rules.
fn parse_rules(json: &str) -> Result<Rules, String> {
    let text = if json.trim().is_empty() {
        DEFAULT_RULES_JSON
    } else {
        json
    };
    let set: RuleSet = serde_json::from_str(text).map_err(|e| format!("rules: {e}"))?;
    Rules::compile(set)
}

fn rules_from(json: &str) -> Result<Rules, JsError> {
    parse_rules(json).map_err(|e| JsError::new(&e))
}

fn json<T: serde::Serialize>(v: &T) -> Result<String, JsError> {
    serde_json::to_string(v).map_err(|e| JsError::new(&e.to_string()))
}

/// Validate rules; returns `{"rules":n,"asns":n,"version":"..."}`.
#[wasm_bindgen]
pub fn check_rules(rules_json: &str) -> Result<String, JsError> {
    let r = rules_from(rules_json)?;
    Ok(serde_json::json!({"rules": r.set.rules.len(), "asns": r.set.asns.len(), "version": r.set.meta.version}).to_string())
}

/// Parse + analyse. `format`: auto|ndjson|json|lines|access_log. `map`:
/// `ts=a.b,url=c` or empty. Returns `{"analysis": Analysis, "warnings":
/// [...], "redacted": n, "cluster_date_tags": {"C1": DateTagOffset}}`.
/// Secrets are replaced with hashes before analysis (see `sc_core::redact`).
/// The analysis is kept for `report` and `endpoints`.
#[wasm_bindgen]
pub fn analyze(input: &str, format: &str, map: &str, rules_json: &str) -> Result<String, JsError> {
    let rules = rules_from(rules_json)?;
    let format: Format = format.parse().map_err(|e: String| JsError::new(&e))?;
    let map = if map.trim().is_empty() {
        FieldMap::default()
    } else {
        FieldMap::parse(map).map_err(|e| JsError::new(&e))?
    };
    let parsed = sc_core::parse_input(input, format, &map);
    let a = sc_core::analyze(parsed.observations, &rules);
    let out = json(&Analyzed {
        cluster_date_tags: a.cluster_date_tags(),
        analysis: &a,
        warnings: &parsed.warnings,
        redacted: parsed.redacted,
    })?;
    LAST.with(|l| *l.borrow_mut() = Some(a));
    Ok(out)
}

/// `analyze`'s result. Structs rather than `json!` throughout: `json!` goes
/// through a `Value`, which doubles the serialisation code in the module.
#[derive(serde::Serialize)]
struct Analyzed<'a> {
    cluster_date_tags: BTreeMap<String, DateTagOffset>,
    analysis: &'a Analysis,
    warnings: &'a [String],
    redacted: usize,
}

fn with_last<T>(f: impl FnOnce(&Analysis) -> Result<T, JsError>) -> Result<T, JsError> {
    LAST.with(|l| match l.borrow().as_ref() {
        Some(a) => f(a),
        None => Err(JsError::new("nothing analysed yet")),
    })
}

/// Unwrap a single URL; returns `{"layers": [...], "extracted": {...}}`.
#[wasm_bindgen]
pub fn unwrap(url: &str, rules_json: &str) -> Result<String, JsError> {
    let rules = rules_from(rules_json)?;
    let obs = sc_core::Observation {
        url: url.to_string(),
        ..Default::default()
    };
    json(&sc_core::extract(&obs, &rules))
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
    json(&claims)
}

fn parse_claims(text: &str) -> Result<Vec<Claim>, String> {
    if text.trim().is_empty() {
        return Ok(Vec::new());
    }
    serde_json::from_str(text).map_err(|e| format!("claims: {e}"))
}

/// A Markdown draft of the most recent `analyze` result. `opts` is
/// ReportOptions JSON: `{"audience":"provider","cluster":"k-3f9a2c1b",
/// "reporter":"...","generated":"2026-10-09","min_named":"shared_identifiers",
/// "claims":[...]}`. A developer is named outside case notes only on evidence
/// at or above `min_named`, as in the CLI.
#[wasm_bindgen]
pub fn report(opts_json: &str) -> Result<String, JsError> {
    let opts: ReportOptions = if opts_json.trim().is_empty() {
        ReportOptions::default()
    } else {
        serde_json::from_str(opts_json).map_err(|e| JsError::new(&format!("options: {e}")))?
    };
    with_last(|a| Ok(sc_core::render_markdown(a, &opts)))
}

/// Flagged activity per target host in the most recent `analyze` result.
/// `opts` is EndpointOptions JSON (`{"min_tier":"suggestive","now":0,
/// "active_days":7}`) or empty for defaults.
#[wasm_bindgen]
pub fn endpoints(opts_json: &str) -> Result<String, JsError> {
    let opts: sc_core::EndpointOptions = if opts_json.trim().is_empty() {
        sc_core::EndpointOptions::default()
    } else {
        serde_json::from_str(opts_json).map_err(|e| JsError::new(&format!("options: {e}")))?
    };
    with_last(|a| json(&sc_core::endpoints(a, &opts)))
}

#[wasm_bindgen]
pub fn defang(text: &str) -> String {
    sc_core::defang(text)
}

#[wasm_bindgen]
pub fn parse_security_txt(text: &str) -> String {
    serde_json::to_string(&sc_core::parse_security_txt(text)).unwrap_or_default()
}

/// Score rules against a labelled set, as `swarmchase eval` does. `set` is
/// the labelled NDJSON (the site serves `samples/eval/*.ndjson` joined).
/// Returns the eval report (`rules_version`, `labelled`, `agents`, `benign`,
/// `thresholds`, `rules`, `classes`, ...) plus `records`, every labelled
/// record (`id`, `label`, `tier`, `score`, `rules`, `url` defanged and cut
/// short), and `misclassified`, those the suggestive-or-above call gets wrong.
#[wasm_bindgen]
pub fn eval_labelled(rules_json: &str, set: &str) -> Result<String, JsError> {
    let rules = rules_from(rules_json)?;
    Ok(eval_with(&rules, set))
}

fn eval_with(rules: &Rules, set: &str) -> String {
    let labels: LabelSet = sc_core::parse_labels(set);
    let parsed = sc_core::parse_input(set, Format::Ndjson, &FieldMap::default());
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
        sc_core::sort::sort(&mut ids);
        ids.dedup();
        let rec = EvalRecord {
            id: &r.obs.id,
            label: l.label,
            class: l.class.as_deref(),
            tier: r.tier,
            score: r.score,
            rules: ids,
            url: short_url(&r.obs.url),
        };
        if (l.label == Label::Agent) != (r.tier >= Tier::Suggestive) {
            misclassified.push(rec.clone());
        }
        records.push(rec);
    }
    serde_json::to_string(&EvalOut {
        rules_version: &report.rules_version,
        labelled: report.labelled,
        unlabelled: report.unlabelled,
        missing_records: report.missing_records,
        agents: report.agents,
        benign: report.benign,
        thresholds: &report.thresholds,
        rules: &report.rules,
        classes: &report.classes,
        records: &records,
        misclassified: &misclassified,
    })
    .unwrap_or_default()
}

#[derive(serde::Serialize, Clone)]
struct EvalRecord<'a> {
    id: &'a str,
    label: Label,
    class: Option<&'a str>,
    tier: Tier,
    score: i32,
    rules: Vec<&'a str>,
    url: String,
}

/// The eval report without its own false-positive list (the page lists
/// misclassified records both ways), plus every labelled record.
#[derive(serde::Serialize)]
struct EvalOut<'a> {
    rules_version: &'a str,
    labelled: usize,
    unlabelled: usize,
    missing_records: usize,
    agents: usize,
    benign: usize,
    thresholds: &'a [sc_core::eval::Threshold],
    rules: &'a [sc_core::eval::RuleStat],
    classes: &'a [sc_core::eval::ClassStat],
    records: &'a [EvalRecord<'a>],
    misclassified: &'a [EvalRecord<'a>],
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

    const SET: &str = concat!(
        include_str!("../../../samples/eval/llm-residue.ndjson"),
        "\n",
        include_str!("../../../samples/eval/published-patterns.ndjson"),
    );

    fn draft(min_named: &str, evidence: &str) -> String {
        LAST.with(|l| {
            *l.borrow_mut() = Some(sc_core::analyze(Vec::new(), &Rules::default_rules()))
        });
        let opts = serde_json::json!({
            "audience": "provider",
            "min_named": min_named,
            "claims": [{"party": "Example AI", "role": "developer", "evidence": evidence, "details": ["case work"]}],
        });
        let Ok(md) = report(&opts.to_string()) else {
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

    // The bundled JSON, and edited TOML through sc-rules-wasm, read as the
    // CLI reads the TOML.
    #[test]
    fn json_rules_match_the_toml() {
        let as_json = |set: &RuleSet| serde_json::to_string(set).unwrap();
        let bundled = parse_rules("").unwrap();
        assert_eq!(as_json(&bundled.set), as_json(&Rules::default_rules().set));
        let edited = sc_core::DEFAULT_RULES.replace("weight = 2\n", "weight = 5\n");
        let via = parse_rules(&sc_rules_wasm::to_json(&edited).unwrap()).unwrap();
        assert_eq!(
            as_json(&via.set),
            as_json(&Rules::from_toml(&edited).unwrap().set)
        );
        assert!(parse_rules("{\"rule\": 3}").is_err_and(|e| e.starts_with("rules: ")));
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

    // The set grows; assert shape and sanity, not exact counts.
    #[test]
    fn bundled_rules_hold_up_on_the_labelled_set() {
        let v: serde_json::Value =
            serde_json::from_str(&eval_with(&Rules::default_rules(), SET)).unwrap();
        let labelled = v["labelled"].as_u64().unwrap();
        assert!(labelled > 0);
        assert_eq!(v["records"].as_array().unwrap().len() as u64, labelled);
        assert!(v.get("false_positives").is_none());
        assert!(!v["rules"].as_array().unwrap().is_empty());
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
    fn analysis_is_kept_for_report_and_endpoints() {
        let Ok(out) = analyze(SET, "ndjson", "", "") else {
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
        let Ok(ep) = endpoints("") else {
            panic!("endpoints failed")
        };
        assert!(ep.starts_with('['));
        let key = v["analysis"]["clusters"][0]["key"].as_str().unwrap();
        let Ok(md) = report(&serde_json::json!({ "cluster": key }).to_string()) else {
            panic!("report failed")
        };
        assert!(!md.is_empty());
    }
}
