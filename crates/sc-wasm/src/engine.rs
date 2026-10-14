//! The engine's bindings: `analyze`, `unwrap`, `endpoints` and helpers. The
//! engine module is these alone; the tools module carries them too, so the
//! workbench loads one module for its analysis and its report.
//!
//! `analyze` keeps its result in the module ([`super::hold`]), and
//! `endpoints` (and in the tools module `report`, `sightings` and
//! `attribution`) read it from there, so the page never sends a whole
//! analysis back across the boundary and the engine carries no
//! deserialiser for one.
//!
//! A set of files (a folder, an archive) is one analysis too: the page adds
//! each file with `inputs_add` as it unpacks it, then `inputs_analyze` runs
//! the analysis over every record read ([`inputs_add`]).

use super::{hold, json, parse_claims, rules_from, with_held};
use sc_core::timing::DateTagOffset;
use sc_core::{Analysis, Evidence, FieldMap, Format, Observation, Parsed};
use std::cell::RefCell;
use std::collections::BTreeMap;
use wasm_bindgen::prelude::*;

/// Parse + analyse. `format`: auto|ndjson|json|lines|access_log. `map`:
/// `ts=a.b,url=c` or empty. Returns `{"analysis": Analysis, "warnings":
/// [...], "redacted": n, "cluster_date_tags": {"C1": DateTagOffset}}`.
/// Secrets are replaced with hashes before analysis (see `sc_core::redact`).
/// The analysis is kept for `endpoints` (and the tools module's reports).
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
    hold(a);
    Ok(out)
}

/// A field map from its text; empty is the default map.
fn field_map(map: &str) -> Result<FieldMap, String> {
    if map.trim().is_empty() {
        Ok(FieldMap::default())
    } else {
        FieldMap::parse(map)
    }
}

thread_local! {
    /// The records of the files added since the last `inputs_clear` or
    /// `inputs_analyze`, and how many files they came from.
    static PENDING: RefCell<(Vec<Observation>, usize)> = const { RefCell::new((Vec::new(), 0)) };
}

/// Most warnings `inputs_add` returns for one file; it counts them all.
const FILE_WARNINGS: usize = 5;

/// What `inputs_add` says about one file.
#[derive(serde::Serialize)]
struct FileRead<'a> {
    /// The file's number in the set, from 1: its records' ids start `f<n>:`.
    file: usize,
    /// The format it was read as (`auto` resolved per file).
    format: &'static str,
    /// Lines that are not blank.
    lines: usize,
    records: usize,
    skipped: usize,
    redacted: usize,
    warnings: &'a [String],
    warning_count: usize,
}

/// Parse one file of a set and keep its records for `inputs_analyze`.
/// Each file is read on its own, in `format` (`auto` detects it per file,
/// so a JSON log beside an access log reads as both) with the field `map`
/// (the operator's host applies to every file). Each record's id gets the
/// file's number in front (`f2:log-17`, or `f2:r5` for a record without
/// one), so ids stay unique across files and the page can name a record's
/// file; the file's name never enters the module. Returns `{"file",
/// "format", "lines", "records", "skipped", "redacted", "warnings",
/// "warning_count"}`.
#[wasm_bindgen]
pub fn inputs_add(text: &str, format: &str, map: &str) -> Result<String, JsError> {
    let format: Format = format.parse().map_err(|e: String| JsError::new(&e))?;
    let map = field_map(map).map_err(|e| JsError::new(&e))?;
    let (file, records, parsed) = add_input(text, format, &map);
    json(&FileRead {
        file,
        format: parsed.format.name(),
        lines: text.lines().filter(|l| !l.trim().is_empty()).count(),
        records,
        skipped: parsed.skipped,
        redacted: parsed.redacted,
        warnings: &parsed.warnings[..parsed.warnings.len().min(FILE_WARNINGS)],
        warning_count: parsed.warnings.len(),
    })
}

/// `inputs_add` without the boundary: the file's number, how many records
/// it held, and what else was read (its records moved into the pending set).
fn add_input(text: &str, format: Format, map: &FieldMap) -> (usize, usize, Parsed) {
    let mut parsed = sc_core::parse_input(text, format, map);
    let records = parsed.observations.len();
    PENDING.with(|p| {
        let mut p = p.borrow_mut();
        p.1 += 1;
        let n = p.1;
        for (k, mut o) in parsed.observations.drain(..).enumerate() {
            o.id = if o.id.is_empty() {
                format!("f{n}:r{}", k + 1)
            } else {
                format!("f{n}:{}", o.id)
            };
            p.0.push(o);
        }
        (n, records, parsed)
    })
}

/// Drop the files added so far.
#[wasm_bindgen]
pub fn inputs_clear() {
    PENDING.with(|p| *p.borrow_mut() = (Vec::new(), 0));
}

/// Analyse every record of the files added since the last call (or
/// `inputs_clear`) as one input, so clusters and timing span files, and
/// keep the analysis as `analyze` does. Returns what `analyze` returns,
/// with the warnings left to each file's `inputs_add`. The set is cleared.
#[wasm_bindgen]
pub fn inputs_analyze(rules_json: &str) -> Result<String, JsError> {
    let rules = rules_from(rules_json)?;
    let observations = PENDING.with(|p| std::mem::take(&mut *p.borrow_mut()).0);
    let a = sc_core::analyze(observations, &rules);
    let out = json(&Analyzed {
        cluster_date_tags: a.cluster_date_tags(),
        analysis: &a,
        warnings: &[],
        redacted: 0,
    })?;
    hold(a);
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
    with_held("nothing analysed yet", |a| {
        json(&sc_core::endpoints(a, &opts))
    })
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

    // Files of different formats read as one analysis: each in its own
    // format, ids numbered by file, the set cleared once analysed.
    #[test]
    fn a_set_of_files_is_one_analysis() {
        inputs_clear();
        let log = "203.0.113.9 - - [04/Oct/2026:08:10:00 +0000] \"GET /q?id=1%20UNION%20SELECT%201 HTTP/1.1\" 200 5 \"-\" \"curl/8\"\nnot a line\n203.0.113.9 - - [04/Oct/2026:08:10:30 +0000] \"GET / HTTP/1.1\" 200 5\n";
        let nd = "{\"url\":\"https://b.example/x\",\"ts\":\"2026-10-04T08:11:00Z\"}\n{\"url\":\"https://b.example/y\",\"id\":\"z\"}\n";
        let Ok(first) = inputs_add(log, "auto", "host=www.example.org") else {
            panic!("inputs_add failed")
        };
        let first: serde_json::Value = serde_json::from_str(&first).unwrap();
        assert_eq!(
            first,
            serde_json::json!({"file": 1, "format": "access_log", "lines": 3, "records": 2,
                "skipped": 1, "redacted": 0, "warnings": ["line 2: not an access log line"],
                "warning_count": 1})
        );
        let map = FieldMap::parse("host=www.example.org").unwrap();
        let (n2, records, p2) = add_input(nd, Format::Auto, &map);
        assert_eq!(
            (n2, records, p2.format, p2.skipped),
            (2, 2, Format::Ndjson, 0)
        );
        let Ok(out) = inputs_analyze("") else {
            panic!("inputs_analyze failed")
        };
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        let ids: Vec<&str> = v["analysis"]["results"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["obs"]["id"].as_str().unwrap())
            .collect();
        assert_eq!(ids, ["f1:log-1", "f1:log-3", "f2:r1", "f2:z"]);
        assert_eq!(
            v["analysis"]["results"][0]["obs"]["url"],
            "https://www.example.org/q?id=1%20UNION%20SELECT%201"
        );
        PENDING.with(|p| assert_eq!(p.borrow().1, 0, "cleared"));
    }
}
