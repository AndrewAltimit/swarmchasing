//! The tools module: loaded only when a visitor asks for a report draft, an
//! evidence bundle check or a labelled-set eval.
//!
//! A report draft needs the analysis the engine module made, which lives in
//! that module's memory. Rather than carry a deserialiser for a whole
//! analysis, `prepare` re-runs it here on the same input: the analysis is
//! deterministic, so cluster ids and keys match the engine's.

use super::{json, rules_from};
use sc_core::eval::LabelSet;
use sc_core::{Analysis, FieldMap, Format, Label, ReportOptions, Rules, Tier};
use std::cell::RefCell;
use std::collections::HashSet;
use wasm_bindgen::prelude::*;

/// Longest URL, in characters, an eval result carries.
const SHORT_URL: usize = 120;

thread_local! {
    /// The analysis `prepare` made, for `report`.
    static PREPARED: RefCell<Option<Analysis>> = const { RefCell::new(None) };
}

/// Analyse the input for `report`, as the engine's `analyze` does (same
/// arguments, same redaction). Returns `{"clusters": n, "total": n}` so the
/// page can check it matches what it shows.
#[wasm_bindgen]
pub fn prepare(input: &str, format: &str, map: &str, rules_json: &str) -> Result<String, JsError> {
    let rules = rules_from(rules_json)?;
    let format: Format = format.parse().map_err(|e: String| JsError::new(&e))?;
    let map = if map.trim().is_empty() {
        FieldMap::default()
    } else {
        FieldMap::parse(map).map_err(|e| JsError::new(&e))?
    };
    let parsed = sc_core::parse_input(input, format, &map);
    let a = sc_core::analyze(parsed.observations, &rules);
    let out = format!(
        "{{\"clusters\":{},\"total\":{}}}",
        a.clusters.len(),
        a.total
    );
    PREPARED.with(|p| *p.borrow_mut() = Some(a));
    Ok(out)
}

/// A Markdown draft of the analysis `prepare` made. `opts` is ReportOptions
/// JSON: `{"audience":"provider","cluster":"k-3f9a2c1b","reporter":"...",
/// "generated":"2026-10-09","min_named":"shared_identifiers","claims":[...]}`.
/// A developer is named outside case notes only on evidence at or above
/// `min_named`, as in the CLI.
#[wasm_bindgen]
pub fn report(opts_json: &str) -> Result<String, JsError> {
    let opts: ReportOptions = if opts_json.trim().is_empty() {
        ReportOptions::default()
    } else {
        serde_json::from_str(opts_json).map_err(|e| JsError::new(&format!("options: {e}")))?
    };
    PREPARED.with(|p| match p.borrow().as_ref() {
        Some(a) => Ok(sc_core::render_markdown(a, &opts)),
        None => Err(JsError::new("nothing prepared yet")),
    })
}

/// The sightings document (SC-Sightings v1) of the analysis `prepare` made,
/// pretty-printed, so the page shows exactly the bytes it would download.
/// `opts` is ExportOptions JSON: `{"include_hosts":false,"operator":null,
/// "cluster":null,"generated":"2026-10-12"}`. Nothing is sent anywhere.
#[wasm_bindgen]
pub fn sightings(opts_json: &str) -> Result<String, JsError> {
    let opts: sc_core::sightings::ExportOptions = if opts_json.trim().is_empty() {
        Default::default()
    } else {
        serde_json::from_str(opts_json).map_err(|e| JsError::new(&format!("options: {e}")))?
    };
    PREPARED.with(|p| match p.borrow().as_ref() {
        Some(a) => {
            let doc = sc_core::sightings::export(a, &opts, &Default::default());
            serde_json::to_string_pretty(&doc).map_err(|e| JsError::new(&e.to_string()))
        }
        None => Err(JsError::new("nothing prepared yet")),
    })
}

/// What `attribution` reads: a cluster id or key, the claims from case work
/// (as `report --claims` reads them) and the naming level.
#[derive(serde::Deserialize)]
struct AttributionOptions {
    cluster: String,
    #[serde(default)]
    claims: Vec<sc_core::Claim>,
    #[serde(default)]
    min_named: sc_core::Evidence,
}

#[derive(serde::Serialize)]
struct Attributed {
    layers: Vec<sc_core::attribution::LayerSummary>,
    /// Developer candidates below the naming level, left out of `layers`.
    withheld: usize,
}

/// The attribution layers of one cluster of the analysis `prepare` made,
/// gated as a report at `min_named` is. `opts`: `{"cluster":"C1","claims":
/// [...],"min_named":"shared_identifiers"}`. Returns `{"layers":
/// [LayerSummary], "withheld": n}`.
#[wasm_bindgen]
pub fn attribution(opts_json: &str) -> Result<String, JsError> {
    let o: AttributionOptions =
        serde_json::from_str(opts_json).map_err(|e| JsError::new(&format!("options: {e}")))?;
    PREPARED.with(|p| {
        let guard = p.borrow();
        let a = guard
            .as_ref()
            .ok_or_else(|| JsError::new("nothing prepared yet"))?;
        let c = a
            .cluster(&o.cluster)
            .ok_or_else(|| JsError::new("no such cluster"))?;
        let claims = sc_core::attribution::merge(o.claims, &sc_core::attribute(a, c));
        let withheld = claims
            .iter()
            .filter(|c| c.role == sc_core::Role::Developer && !c.nameable(o.min_named))
            .count();
        json(&Attributed {
            layers: sc_core::attribution::summaries(&claims, o.min_named),
            withheld,
        })
    })
}

#[wasm_bindgen]
pub fn parse_security_txt(text: &str) -> Result<String, JsError> {
    json(&sc_core::parse_security_txt(text))
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
        PREPARED.with(|p| {
            *p.borrow_mut() = Some(sc_core::analyze(Vec::new(), &Rules::default_rules()))
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
    fn sightings_of_the_showcase_hold_no_host_unless_asked() {
        let input = include_str!("../../../samples/showcase/showcase.ndjson");
        assert!(prepare(input, "ndjson", "", "").is_ok());
        let Ok(doc) = sightings(r#"{"generated":"2026-10-12"}"#) else {
            panic!("sightings failed");
        };
        let s = sc_core::sightings::parse(&doc).unwrap();
        assert!(!s.sightings.is_empty());
        assert!(
            !doc.contains("county-records") && !doc.contains("jina.ai"),
            "{doc}"
        );
        let Ok(doc) = sightings(r#"{"include_hosts":true}"#) else {
            panic!("sightings failed");
        };
        assert!(
            doc.contains("county-records[.]example") && !doc.contains("county-records.example")
        );
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

    // The engine's analysis and the one prepared here agree, so a cluster
    // key the page holds selects the same cluster in a draft.
    #[test]
    fn prepare_matches_the_engine() {
        let engine: serde_json::Value = serde_json::from_str(
            &crate::engine::analyze(SET, "ndjson", "", "").unwrap_or_default(),
        )
        .unwrap();
        let Ok(p) = prepare(SET, "ndjson", "", "") else {
            panic!("prepare failed")
        };
        let p: serde_json::Value = serde_json::from_str(&p).unwrap();
        let clusters = engine["analysis"]["clusters"].as_array().unwrap();
        assert_eq!(p["clusters"].as_u64().unwrap() as usize, clusters.len());
        assert_eq!(p["total"], engine["analysis"]["total"]);
        let key = clusters[0]["key"].as_str().unwrap();
        let Ok(md) = report(&serde_json::json!({ "cluster": key }).to_string()) else {
            panic!("report failed")
        };
        assert!(!md.is_empty());
        let Ok(at) = attribution(&serde_json::json!({ "cluster": key }).to_string()) else {
            panic!("attribution failed")
        };
        let at: serde_json::Value = serde_json::from_str(&at).unwrap();
        assert!(
            at["layers"].is_array() && at["withheld"].is_number(),
            "{at}"
        );
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
}
