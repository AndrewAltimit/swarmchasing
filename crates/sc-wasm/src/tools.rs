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

/// `declared-agents.toml` as JSON, converted by `build.rs`.
const DECLARED_AGENTS_JSON: &str = include_str!(concat!(env!("OUT_DIR"), "/declared_agents.json"));

fn catalog() -> Result<sc_core::identity::Catalog, JsError> {
    serde_json::from_str::<sc_core::identity::Catalog>(DECLARED_AGENTS_JSON)
        .map_err(|e| e.to_string())
        .and_then(sc_core::identity::Catalog::checked)
        .map_err(|e| JsError::new(&e))
}

/// The declared-agent catalog: products, and the range files and key
/// directories with the URLs their providers document, so a page can say
/// which files to download. The module never fetches them.
#[wasm_bindgen]
pub fn identity_catalog() -> Result<String, JsError> {
    json(&catalog()?)
}

/// One record's declared identity, for the page.
#[derive(serde::Serialize)]
struct IdentityRow {
    id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    ip: Option<String>,
    #[serde(flatten)]
    identity: sc_core::RecordIdentity,
}

/// The range files and key directories a visitor supplies, by catalog id.
#[derive(serde::Deserialize, Default)]
struct IdentityFiles {
    #[serde(default)]
    ranges: std::collections::BTreeMap<String, String>,
    #[serde(default)]
    directories: std::collections::BTreeMap<String, String>,
}

/// Class each record's declared identity (verified, spoofed, claimed), as
/// `swarmchase identity check` does. `files_json` holds the range files and
/// key directories the visitor downloaded from the catalog's URLs, by
/// catalog id: `{"ranges": {"openai.chatgpt-user": "<file text>"},
/// "directories": {"openai.chatgpt": "<file text>"}}`; empty checks claims
/// only. Returns `{"records": [...], "counts": {...}, "warnings": [...]}`;
/// records with no declared identity are counted, not listed.
#[wasm_bindgen]
pub fn identity_check(
    input: &str,
    format: &str,
    map: &str,
    files_json: &str,
) -> Result<String, JsError> {
    use sc_core::identity::httpsig::KeyDirectory;
    use sc_core::identity::ranges::RangeTable;
    use sc_core::identity::{IdentityClass, IdentityData, classify};
    use std::collections::BTreeMap;

    let cat = catalog()?;
    let files: IdentityFiles = if files_json.trim().is_empty() {
        IdentityFiles::default()
    } else {
        serde_json::from_str(files_json).map_err(|e| JsError::new(&format!("files: {e}")))?
    };
    let mut data = IdentityData::default();
    let mut warnings = Vec::new();
    for (id, text) in &files.ranges {
        if !cat.range_files.iter().any(|f| &f.id == id) {
            warnings.push(format!("{id}: not a range file in the catalog"));
            continue;
        }
        match RangeTable::parse(id, text) {
            Ok(t) => {
                data.ranges.insert(id.clone(), t);
            }
            Err(e) => warnings.push(e),
        }
    }
    for (id, text) in &files.directories {
        let Some(d) = cat.directories.iter().find(|d| &d.id == id) else {
            warnings.push(format!("{id}: not a directory in the catalog"));
            continue;
        };
        match KeyDirectory::parse(id, &d.signature_agent, text) {
            Ok(k) => {
                data.directories.insert(id.clone(), k);
            }
            Err(e) => warnings.push(e),
        }
    }
    let format: Format = format.parse().map_err(|e: String| JsError::new(&e))?;
    let map = if map.trim().is_empty() {
        FieldMap::default()
    } else {
        FieldMap::parse(map).map_err(|e| JsError::new(&e))?
    };
    let parsed = sc_core::parse_input(input, format, &map);
    let mut counts: BTreeMap<IdentityClass, usize> = BTreeMap::new();
    let mut records = Vec::new();
    for o in parsed.observations {
        let r = classify(&o, &cat, &data);
        *counts.entry(r.class).or_default() += 1;
        if r.class != IdentityClass::None {
            records.push(IdentityRow {
                id: o.id,
                ip: o.ip,
                identity: r,
            });
        }
    }
    json(&serde_json::json!({
        "records": records,
        "counts": counts,
        "warnings": warnings,
    }))
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
    fn identity_check_classes_log_lines() {
        let ua = "Mozilla/5.0 (compatible; ChatGPT-User/1.0; +https://openai.com/bot)";
        let log = format!(
            "192.0.2.9 - - [04/Oct/2026:08:10:00 +0000] \"GET / HTTP/1.1\" 200 5 \"-\" \"{ua}\"\n\
             203.0.113.9 - - [04/Oct/2026:08:10:01 +0000] \"GET / HTTP/1.1\" 200 5 \"-\" \"{ua}\"\n\
             203.0.113.10 - - [04/Oct/2026:08:10:02 +0000] \"GET / HTTP/1.1\" 200 5 \"-\" \"curl/8.5\""
        );
        let files = serde_json::json!({
            "ranges": {
                "openai.chatgpt-user": r#"{"prefixes":[{"ipv4Prefix":"192.0.2.0/28"}]}"#,
                "unknown.file": "192.0.2.0/24",
            }
        });
        let Ok(out) = identity_check(&log, "access_log", "host=shop.example", &files.to_string())
        else {
            panic!("identity_check failed");
        };
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        let classes: Vec<&str> = v["records"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["class"].as_str().unwrap())
            .collect();
        assert_eq!(classes, ["ip_verified", "spoofed"], "{out}");
        assert_eq!(v["counts"]["none"], 1);
        assert_eq!(v["warnings"].as_array().unwrap().len(), 1, "{out}");
        let Ok(c) = identity_catalog() else {
            panic!("catalog")
        };
        assert!(c.contains("ChatGPT-User"));
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
