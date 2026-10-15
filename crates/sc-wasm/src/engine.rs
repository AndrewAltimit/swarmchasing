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
//!
//! A large analysis stays here. Past [`RESULTS_IN_FULL`] records, the text
//! the page gets carries the records it lists (the flagged ones, at most
//! [`RESULTS_SENT`]) with their indexes,
//! not a result per record: the page lists flagged records only, and a
//! result per record of a large set is more text than a browser holds in
//! one string. `held_results` hands over any record by its index.

use super::{hold, json, parse_claims, rules_from, with_held};
use sc_core::timing::DateTagOffset;
use sc_core::{Analysis, Evidence, FieldMap, Format, ObsResult, Observation, Parsed};
use std::cell::RefCell;
use std::collections::BTreeMap;
use wasm_bindgen::prelude::*;

/// An analysis of more records than this reaches the page with the records
/// it lists only ([`analyzed`]).
pub const RESULTS_IN_FULL: usize = 50_000;

/// The most records a large analysis sends the page.
pub const RESULTS_SENT: usize = 100_000;

/// Most records `held_results` returns at once.
pub const HELD_RESULTS_MAX: usize = 1000;

/// Parse + analyse. `format`: auto|ndjson|json|lines|access_log. `map`:
/// `ts=a.b,url=c` or empty. Returns `{"analysis": Analysis, "warnings":
/// [...], "redacted": n, "cluster_date_tags": {"C1": DateTagOffset}}`,
/// with `result_index` and `results_omitted` for a large input
/// ([`analyzed`]). Secrets are replaced with hashes before analysis (see
/// `sc_core::redact`). The analysis is kept for `endpoints` (and the tools
/// module's reports).
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
    let mut a = sc_core::analyze(parsed.observations, &rules);
    let out = analyzed(&mut a, &parsed.warnings, parsed.redacted)?;
    hold(a);
    Ok(out)
}

/// `analyze`'s result as text: `a` whole up to [`RESULTS_IN_FULL`]
/// records; past that, `analysis.results` holds only the records [`shown`]
/// picks, `result_index` their indexes among every record, and
/// `results_omitted` counts the flagged records left out. `a` is as it was
/// afterwards.
fn analyzed(a: &mut Analysis, warnings: &[String], redacted: usize) -> Result<String, JsError> {
    let cluster_date_tags = a.cluster_date_tags();
    if a.results.len() <= RESULTS_IN_FULL {
        return json(&Analyzed {
            cluster_date_tags,
            analysis: a,
            warnings,
            redacted,
            result_index: None,
            results_omitted: 0,
        });
    }
    let (index, omitted) = shown(a, RESULTS_SENT);
    let all = std::mem::take(&mut a.results);
    a.results = index.iter().map(|&i| all[i].clone()).collect();
    let out = json(&Analyzed {
        cluster_date_tags,
        analysis: a,
        warnings,
        redacted,
        result_index: Some(&index),
        results_omitted: omitted,
    });
    a.results = all;
    out
}

/// The records a large analysis sends the page, by index in order, and how
/// many flagged records that leaves out: its flagged records (score above
/// zero: what the page lists), at most `cap`, highest score and then
/// earliest first. Only flagged records are clustered, so every record a
/// cluster or a probe chain names by its cluster is among them.
fn shown(a: &Analysis, cap: usize) -> (Vec<usize>, usize) {
    let mut flagged: Vec<usize> = (0..a.results.len())
        .filter(|&i| a.results[i].score > 0)
        .collect();
    let omitted = flagged.len().saturating_sub(cap);
    if omitted > 0 {
        sc_core::sort::by_key(&mut flagged, |&i| {
            (std::cmp::Reverse(a.results[i].score), i)
        });
        flagged.truncate(cap);
    }
    flagged.sort_unstable();
    (flagged, omitted)
}

/// Records of the held analysis by index, for a page that holds only those
/// it lists. `indices_json` is a JSON array of indexes, at most
/// [`HELD_RESULTS_MAX`]; returns `[{"i": index, "result": ObsResult}]` for
/// those that exist, in the order asked.
#[wasm_bindgen]
pub fn held_results(indices_json: &str) -> Result<String, JsError> {
    let want = indices(indices_json).map_err(|e| JsError::new(&e))?;
    with_held("nothing analysed yet", |a| {
        let rows: Vec<HeldResult> = want
            .iter()
            .filter_map(|&i| a.results.get(i).map(|result| HeldResult { i, result }))
            .collect();
        json(&rows)
    })
}

/// `held_results`' indexes from their JSON, at most [`HELD_RESULTS_MAX`].
fn indices(text: &str) -> Result<Vec<usize>, String> {
    let want: Vec<usize> = serde_json::from_str(text).map_err(|e| format!("indices: {e}"))?;
    if want.len() > HELD_RESULTS_MAX {
        return Err(format!("indices: at most {HELD_RESULTS_MAX} at a time"));
    }
    Ok(want)
}

#[derive(serde::Serialize)]
struct HeldResult<'a> {
    i: usize,
    result: &'a ObsResult,
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
    /// Lines read that are not blank.
    lines: usize,
    records: usize,
    skipped: usize,
    redacted: usize,
    warnings: &'a [String],
    warning_count: usize,
    /// The file held more than the record limit it was read under, and was
    /// read up to it.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    cut: bool,
}

/// Parse one file of a set and keep its records for `inputs_analyze`.
/// Each file is read on its own, in `format` (`auto` detects it per file,
/// so a JSON log beside an access log reads as both) with the field `map`
/// (the operator's host applies to every file). Each record's id gets the
/// file's number in front (`f2:log-17`, or `f2:r5` for a record without
/// one), so ids stay unique across files and the page can name a record's
/// file; the file's name never enters the module. `limit` is the most
/// records to take from this file, 0 for no limit: a longer file is read
/// up to that many lines (a JSON document, not read by lines, up to that
/// many records) and says `"cut": true`. Returns `{"file", "format",
/// "lines", "records", "skipped", "redacted", "warnings",
/// "warning_count"}`, `lines` counting the lines read.
#[wasm_bindgen]
pub fn inputs_add(text: &str, format: &str, map: &str, limit: usize) -> Result<String, JsError> {
    let format: Format = format.parse().map_err(|e: String| JsError::new(&e))?;
    let map = field_map(map).map_err(|e| JsError::new(&e))?;
    let added = add_input(text, format, &map, limit);
    let parsed = &added.parsed;
    json(&FileRead {
        file: added.file,
        format: parsed.format.name(),
        lines: added.read.lines().filter(|l| !l.trim().is_empty()).count(),
        records: added.records,
        skipped: parsed.skipped,
        redacted: parsed.redacted,
        warnings: &parsed.warnings[..parsed.warnings.len().min(FILE_WARNINGS)],
        warning_count: parsed.warnings.len(),
        cut: added.cut,
    })
}

/// What `add_input` read of one file.
struct Added<'t> {
    /// The file's number in the set.
    file: usize,
    /// Records kept (moved into the pending set).
    records: usize,
    /// The rest of what was parsed.
    parsed: Parsed,
    /// The part of the text read.
    read: &'t str,
    /// Records past the limit were left.
    cut: bool,
}

/// `text` up to the end of its `limit`th line that is not blank, when more
/// text follows it; None when it holds no more than that, or `limit` is 0.
fn first_lines(text: &str, limit: usize) -> Option<&str> {
    if limit == 0 {
        return None;
    }
    let mut seen = 0;
    let mut end = 0;
    for line in text.split_inclusive('\n') {
        end += line.len();
        if !line.trim().is_empty() {
            seen += 1;
            if seen == limit {
                return (!text[end..].trim().is_empty()).then(|| &text[..end]);
            }
        }
    }
    None
}

/// `inputs_add` without the boundary. At most `limit` records are kept (0
/// for no limit).
fn add_input<'t>(text: &'t str, format: Format, map: &FieldMap, limit: usize) -> Added<'t> {
    let resolved = match format {
        Format::Auto => sc_core::detect_format(text),
        f => f,
    };
    // A file in a line format is cut before it is parsed, so one past the
    // limit costs no more than the limit; a JSON document is parsed whole.
    let head = match resolved {
        Format::Json => None,
        _ => first_lines(text, limit),
    };
    let read = head.unwrap_or(text);
    let mut parsed = sc_core::parse_input(read, format, map);
    let mut cut = head.is_some();
    if limit > 0 && parsed.observations.len() > limit {
        parsed.observations.truncate(limit);
        cut = true;
    }
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
        Added {
            file: n,
            records,
            parsed,
            read,
            cut,
        }
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
    // The last analysis goes before the next is made: holding both is
    // twice the memory a large set needs.
    super::release();
    let mut a = sc_core::analyze(observations, &rules);
    let out = analyzed(&mut a, &[], 0)?;
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
    /// Each of `analysis.results`' index among every record, when the
    /// analysis is past [`RESULTS_IN_FULL`] records and sends only some.
    #[serde(skip_serializing_if = "Option::is_none")]
    result_index: Option<&'a [usize]>,
    /// Flagged records left out of `analysis.results`.
    #[serde(skip_serializing_if = "is_zero")]
    results_omitted: usize,
}

fn is_zero(n: &usize) -> bool {
    *n == 0
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
        // A small input is sent whole.
        assert_eq!(
            v["analysis"]["results"].as_array().unwrap().len() as u64,
            v["analysis"]["total"].as_u64().unwrap()
        );
        assert!(v.get("result_index").is_none());
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
        let Ok(first) = inputs_add(log, "auto", "host=www.example.org", 0) else {
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
        let a2 = add_input(nd, Format::Auto, &map, 0);
        assert_eq!(
            (
                a2.file,
                a2.records,
                a2.parsed.format,
                a2.parsed.skipped,
                a2.cut
            ),
            (2, 2, Format::Ndjson, 0, false)
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

    // A file past the record limit is read up to it, by lines for a line
    // format and by records for a JSON document, and says it was cut.
    #[test]
    fn a_file_is_read_up_to_the_limit() {
        inputs_clear();
        let log = "1.2.3.4 - - [04/Oct/2026:08:10:00 +0000] \"GET /a HTTP/1.1\" 200 5\n\n1.2.3.4 - - [04/Oct/2026:08:10:01 +0000] \"GET /b HTTP/1.1\" 200 5\n1.2.3.4 - - [04/Oct/2026:08:10:02 +0000] \"GET /c HTTP/1.1\" 200 5\n";
        let Ok(row) = inputs_add(log, "access_log", "host=h.example", 2) else {
            panic!("inputs_add failed")
        };
        let row: serde_json::Value = serde_json::from_str(&row).unwrap();
        assert_eq!(
            (&row["records"], &row["lines"], &row["cut"]),
            (
                &serde_json::json!(2),
                &serde_json::json!(2),
                &serde_json::json!(true)
            )
        );
        // Exactly the limit is not cut.
        let Ok(row) = inputs_add(log, "access_log", "host=h.example", 3) else {
            panic!("inputs_add failed")
        };
        assert!(!row.contains("\"cut\""));
        let doc = r#"[{"url":"https://a.example/1"},{"url":"https://a.example/2"},{"url":"https://a.example/3"}]"#;
        let map = FieldMap::default();
        let a = add_input(doc, Format::Auto, &map, 2);
        assert_eq!((a.records, a.cut), (2, true));
        inputs_clear();
    }

    fn record(url: &str, n: usize) -> Observation {
        Observation {
            id: format!("r{n}"),
            url: url.to_string(),
            ts: 1_790_000_000 + n as i64,
            ..Default::default()
        }
    }

    // Past RESULTS_IN_FULL records the page gets the flagged ones with
    // their indexes, and the rest by index on request.
    #[test]
    fn a_large_analysis_sends_the_records_it_lists() {
        let n = RESULTS_IN_FULL + 10;
        let mut obs: Vec<Observation> = (0..n)
            .map(|i| record(&format!("https://www.example.org/p/{}", i % 97), i))
            .collect();
        let flagged_at = [7, 40_000, n - 1];
        for &i in &flagged_at {
            obs[i].url =
                "https://www.example.org/q?id=1%20UNION%20SELECT%20null,password%20FROM%20users--"
                    .into();
        }
        let rules = sc_core::Rules::default_rules();
        let mut a = sc_core::analyze(obs, &rules);
        let flagged: Vec<usize> = (0..n).filter(|&i| a.results[i].score > 0).collect();
        assert_eq!(flagged, flagged_at);
        let Ok(out) = analyzed(&mut a, &[], 0) else {
            panic!("analyzed failed")
        };
        assert_eq!(a.results.len(), n, "the held analysis keeps every record");
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["analysis"]["total"], n);
        let index: Vec<usize> = serde_json::from_value(v["result_index"].clone()).unwrap();
        assert_eq!(index, flagged_at);
        let sent = v["analysis"]["results"].as_array().unwrap();
        assert_eq!(sent.len(), index.len());
        assert_eq!(sent[1]["obs"]["id"], "r40000");
        assert!(v.get("results_omitted").is_none());
        assert!(out.len() < 200_000, "{} chars", out.len());
        hold(a);
        let Ok(got) = held_results("[3, 40000, 999999999]") else {
            panic!("held_results failed")
        };
        let got: serde_json::Value = serde_json::from_str(&got).unwrap();
        assert_eq!(got.as_array().unwrap().len(), 2);
        assert_eq!(got[0]["i"], 3);
        assert_eq!(got[0]["result"]["obs"]["id"], "r3");
        assert_eq!(
            got[1]["result"]["score"].as_i64().map(|s| s > 0),
            Some(true)
        );
        let many = format!("[{}]", vec!["0"; HELD_RESULTS_MAX + 1].join(","));
        assert!(indices(&many).is_err());
        assert!(indices("[1, -2]").is_err());
    }

    // Past the cap, the highest-scoring flagged records are sent and the
    // rest counted.
    #[test]
    fn the_records_sent_are_capped_by_score() {
        let mut obs: Vec<Observation> = (0..8)
            .map(|i| record(&format!("https://www.example.org/p/{i}"), i))
            .collect();
        obs[2].url =
            "https://www.example.org/q?id=1%20UNION%20SELECT%20null,password%20FROM%20users--"
                .into();
        obs[5].url = "https://www.example.org/download?file=../../../../etc/passwd".into();
        obs[6].url =
            "https://www.example.org/q?id=1%20UNION%20SELECT%20null,password%20FROM%20users--"
                .into();
        let rules = sc_core::Rules::default_rules();
        let a = sc_core::analyze(obs, &rules);
        let flagged: Vec<usize> = (0..8).filter(|&i| a.results[i].score > 0).collect();
        assert_eq!(flagged, [2, 5, 6]);
        let (all, none) = shown(&a, 10);
        assert_eq!((all, none), (vec![2, 5, 6], 0));
        let (two, left) = shown(&a, 2);
        assert_eq!(left, 1);
        assert_eq!(two.len(), 2);
        let lowest = *flagged
            .iter()
            .min_by_key(|&&i| (a.results[i].score, std::cmp::Reverse(i)))
            .unwrap();
        assert!(!two.contains(&lowest));
    }
}
