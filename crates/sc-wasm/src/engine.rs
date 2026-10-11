//! The engine module: what every analysis page loads on arrival.
//!
//! `analyze` keeps its result in this module, and `endpoints` reads it from
//! there, so the page never sends a whole analysis back across the boundary
//! and the module carries no deserialiser for one.

use super::{json, parse_claims, rules_from};
use sc_core::timing::DateTagOffset;
use sc_core::{Analysis, Evidence, FieldMap, Format};
use std::cell::RefCell;
use std::collections::BTreeMap;
use wasm_bindgen::prelude::*;

thread_local! {
    /// The most recent `analyze` result.
    static LAST: RefCell<Option<Analysis>> = const { RefCell::new(None) };
}

/// Parse + analyse. `format`: auto|ndjson|json|lines|access_log. `map`:
/// `ts=a.b,url=c` or empty. Returns `{"analysis": Analysis, "warnings":
/// [...], "redacted": n, "cluster_date_tags": {"C1": DateTagOffset}}`.
/// Secrets are replaced with hashes before analysis (see `sc_core::redact`).
/// The analysis is kept for `endpoints`.
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

#[cfg(test)]
mod tests {
    use super::*;

    const SET: &str = concat!(
        include_str!("../../../samples/eval/llm-residue.ndjson"),
        "\n",
        include_str!("../../../samples/eval/published-patterns.ndjson"),
    );

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
    fn analysis_is_kept_for_endpoints() {
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
    }
}
