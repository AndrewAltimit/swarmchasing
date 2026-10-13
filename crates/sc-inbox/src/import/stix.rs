//! A STIX 2.1 bundle as an SC-Submission.
//!
//! | Object | Becomes |
//! |---|---|
//! | `identity` (the report's or objects' creator) | The submitter. |
//! | `report` | The claim's summary; `published` the stated submission time. |
//! | `indicator` | Indicators from each `=` comparison of its pattern; SC-T kill chain phases as tactics. |
//! | `observed-data` | Log lines (one JSON record per request) from its `url`, `network-traffic` (with `http-request-ext`) and address objects; its first and last observed times widen the claim's span. |
//! | `sighting` | The claim's span. |
//! | `x-sc-agent-run` | Its tactics and span; the rest of its analysis as claims. |
//! | `external_references` | Public-record references when they name a record by id (urlscan, urlquery, Wayback, Arquivo.pt, npm, PyPI); SC-T references as tactics. |
//!
//! Anything else (other object types, fields of mapped objects that carry
//! no mapping, other references) is kept as an unmapped claim. Structural
//! objects (relationships, groupings, marking and extension definitions) are
//! counted in the conversion notes; the stored original keeps them all.

use super::{Builder, Converted, Format, is_ip, text_of, url_host};
use crate::spec::{Caps, IndicatorKind, Role};
use regex::Regex;
use sc_stix::agent_run::TYPE as AGENT_RUN;
use sc_stix::mapping::{SC_T_SOURCE, of as crosswalk};
use serde_json::{Map, Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;

/// Fields every object may carry that say nothing about the activity.
const COMMON: &[&str] = &[
    "type",
    "spec_version",
    "id",
    "created",
    "modified",
    "created_by_ref",
    "object_marking_refs",
    "granular_markings",
    "lang",
    "revoked",
    "external_references",
    "defanged",
];

/// Objects that only structure a bundle.
const STRUCTURAL: &[&str] = &[
    "relationship",
    "grouping",
    "marking-definition",
    "extension-definition",
    "language-content",
];

/// Cyber-observable objects read through `observed-data`.
const OBSERVABLES: &[&str] = &[
    "url",
    "ipv4-addr",
    "ipv6-addr",
    "domain-name",
    "network-traffic",
];

/// Framework references the SC-T crosswalk derives; read as such.
const CROSSWALK_SOURCES: &[&str] = &["mitre-atlas", "mitre-attack", "owasp-agentic-top-10"];

pub fn convert(doc: &Value, caps: &Caps) -> Result<Converted, Vec<String>> {
    let mut b = Builder::new(Format::Stix);
    let objects = doc
        .get("objects")
        .and_then(Value::as_array)
        .ok_or_else(|| vec!["a STIX bundle needs an `objects` array".to_string()])?;
    b.objects = objects.len();
    b.version = objects
        .iter()
        .find_map(|o| o.get("spec_version").and_then(Value::as_str))
        .or_else(|| doc.get("spec_version").and_then(Value::as_str))
        .map(str::to_string);
    if let Some(v) = &b.version
        && !v.starts_with("2.")
    {
        return Err(vec![format!("STIX spec_version {v}; expected 2.1")]);
    }
    let by_id: BTreeMap<&str, &Value> = objects
        .iter()
        .filter_map(|o| Some((o.get("id")?.as_str()?, o)))
        .collect();
    let kind = |o: &Value| {
        o.get("type")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string()
    };

    // The submitter: the identity that created the report, else the one
    // most objects name as creator, else the first.
    let report = objects.iter().find(|o| kind(o) == "report");
    let mut creators: BTreeMap<&str, usize> = BTreeMap::new();
    for o in objects {
        if let Some(c) = o.get("created_by_ref").and_then(Value::as_str) {
            *creators.entry(c).or_default() += 1;
        }
    }
    let submitter_id = report
        .and_then(|r| r.get("created_by_ref").and_then(Value::as_str))
        .or_else(|| creators.iter().max_by_key(|(_, n)| **n).map(|(id, _)| *id))
        .filter(|id| by_id.get(id).is_some_and(|o| kind(o) == "identity"))
        .or_else(|| {
            objects
                .iter()
                .find(|o| kind(o) == "identity")
                .and_then(|o| o.get("id")?.as_str())
        });

    // Observables read through observed-data are not read again alone.
    let mut through: BTreeSet<String> = BTreeSet::new();
    for o in objects.iter().filter(|o| kind(o) == "observed-data") {
        for r in refs(o, "object_refs") {
            through.insert(r.to_string());
            if let Some(t) = by_id.get(r) {
                for k in ["src_ref", "dst_ref"] {
                    if let Some(x) = t.get(k).and_then(Value::as_str) {
                        through.insert(x.to_string());
                    }
                }
            }
        }
    }

    let mut structural: BTreeMap<String, usize> = BTreeMap::new();
    let mut crosswalk_refs = 0usize;
    for o in objects {
        let t = kind(o);
        let id = o.get("id").and_then(Value::as_str).unwrap_or("");
        let path = if id.is_empty() {
            t.clone()
        } else {
            id.to_string()
        };
        let mut used: Vec<&str> = COMMON.to_vec();
        match t.as_str() {
            "identity" if Some(id) == submitter_id => {
                let s = &mut b.submitter;
                s.name = str_of(o, "name");
                s.contact = str_of(o, "contact_information");
                s.ai_agent = str_of(o, "identity_class").as_deref() == Some("system");
                s.role = roles(o);
                used.extend(["name", "contact_information", "identity_class", "roles"]);
            }
            "report" => {
                if let Some(n) = str_of(o, "name") {
                    b.summary(&n);
                }
                if let Some(d) = str_of(o, "description") {
                    b.summary(&d);
                }
                if let Some(p) = str_of(o, "published") {
                    b.submitted = Some(p);
                }
                used.extend([
                    "name",
                    "description",
                    "published",
                    "object_refs",
                    "report_types",
                ]);
                if let Some(rt) = o.get("report_types") {
                    b.unmapped(&format!("{path}.report_types"), &text_of(rt));
                }
            }
            "indicator" => {
                indicator(&mut b, o, &path);
                used.extend([
                    "pattern",
                    "pattern_type",
                    "pattern_version",
                    "name",
                    "description",
                    "indicator_types",
                    "valid_from",
                    "valid_until",
                    "kill_chain_phases",
                ]);
            }
            "observed-data" => {
                observed(&mut b, o, &by_id, &path);
                used.extend([
                    "first_observed",
                    "last_observed",
                    "number_observed",
                    "object_refs",
                    "objects",
                ]);
            }
            "sighting" => {
                for k in ["first_seen", "last_seen"] {
                    if let Some(v) = str_of(o, k) {
                        b.seen(&v);
                    }
                }
                if let Some(n) = o.get("count").and_then(Value::as_u64) {
                    b.note(format!("{path}: sighted {n} time(s)"));
                }
                used.extend([
                    "first_seen",
                    "last_seen",
                    "count",
                    "sighting_of_ref",
                    "observed_data_refs",
                    "where_sighted_refs",
                    "summary",
                ]);
            }
            x if x == AGENT_RUN => {
                for tac in o
                    .get("tactics")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                {
                    if let Some(s) = tac.as_str() {
                        b.tactic(s);
                    }
                }
                for k in ["first_seen", "last_seen"] {
                    if let Some(v) = str_of(o, k) {
                        b.seen(&v);
                    }
                }
                used.extend([
                    "tactics",
                    "first_seen",
                    "last_seen",
                    "observed_data_refs",
                    "extensions",
                    "name",
                ]);
            }
            x if OBSERVABLES.contains(&x) => {
                if through.contains(id) {
                    continue;
                }
                used.push("value");
                match (x, str_of(o, "value")) {
                    ("url", Some(v)) => b.indicator(IndicatorKind::Url, &v, None),
                    ("ipv4-addr" | "ipv6-addr", Some(v)) => {
                        b.indicator(IndicatorKind::Ip, &v, None)
                    }
                    ("domain-name", Some(v)) => b.indicator(
                        IndicatorKind::Other,
                        &v,
                        Some("a domain name in the bundle".into()),
                    ),
                    _ => {}
                }
            }
            x if STRUCTURAL.contains(&x) => {
                *structural.entry(x.to_string()).or_default() += 1;
                continue;
            }
            _ => {
                let what = [str_of(o, "name"), str_of(o, "description")]
                    .into_iter()
                    .flatten()
                    .collect::<Vec<_>>()
                    .join(": ");
                let what = if what.is_empty() {
                    t.clone()
                } else {
                    format!("{t} {what}")
                };
                b.unmapped(&path, &what);
                used.extend(["name", "description"]);
            }
        }
        // External references on any object.
        for (n, r) in o
            .get("external_references")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .enumerate()
        {
            let src = str_of(r, "source_name");
            let eid = str_of(r, "external_id");
            let low = src.as_deref().unwrap_or("").to_ascii_lowercase();
            if low == SC_T_SOURCE {
                if !eid.as_deref().is_some_and(|e| b.tactic(e)) {
                    b.unmapped(&format!("{path}.external_references[{n}]"), &text_of(r));
                }
                continue;
            }
            if CROSSWALK_SOURCES.contains(&low.as_str()) {
                crosswalk_refs += 1;
                continue;
            }
            b.reference(
                &format!("{path}.external_references[{n}]"),
                src.as_deref(),
                eid.as_deref(),
                str_of(r, "url").as_deref(),
                str_of(r, "description").map(|d| super::short(&d, 300)),
            );
        }
        // Fields of a mapped object that carry no mapping.
        if let Some(m) = o.as_object() {
            let rest: Map<String, Value> = m
                .iter()
                .filter(|(k, _)| !used.contains(&k.as_str()))
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();
            if !rest.is_empty() {
                b.unmapped(&path, &Value::Object(rest).to_string());
            }
        }
    }
    if !structural.is_empty() {
        let s: Vec<String> = structural.iter().map(|(k, n)| format!("{n} {k}")).collect();
        b.note(format!(
            "structural objects not mapped (kept in the original): {}",
            s.join(", ")
        ));
    }
    if crosswalk_refs > 0 {
        b.note(format!(
            "{crosswalk_refs} ATLAS, ATT&CK or OWASP reference(s) read as the SC-T crosswalk, not as evidence"
        ));
    }
    if let Some(id) = submitter_id
        && b.submitter.name.is_none()
    {
        b.submitter.name = Some(id.to_string());
    }
    b.finish(caps)
}

fn str_of(o: &Value, k: &str) -> Option<String> {
    o.get(k)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

fn refs<'a>(o: &'a Value, k: &str) -> impl Iterator<Item = &'a str> {
    o.get(k)
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
}

/// The identity's `roles`, as the submission's role, when one fits.
fn roles(o: &Value) -> Option<Role> {
    let rs: Vec<String> = o
        .get("roles")
        .and_then(Value::as_array)?
        .iter()
        .filter_map(|r| r.as_str().map(str::to_ascii_lowercase))
        .collect();
    let has = |w: &str| rs.iter().any(|r| r.contains(w));
    Some(if has("operator") {
        Role::Operator
    } else if has("research") {
        Role::Researcher
    } else if has("provider") {
        Role::Provider
    } else if has("bystander") {
        Role::Bystander
    } else {
        Role::Other
    })
}

/// `object:path = 'value'` comparisons of a STIX pattern.
fn comparisons() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(r"([a-z0-9-]+):([A-Za-z0-9_.'\[\]*-]+)\s*(=|!=|LIKE|MATCHES|IN|<=|>=|<|>)\s*'((?:[^'\\]|\\.)*)'")
            .unwrap()
    })
}

fn indicator(b: &mut Builder, o: &Value, path: &str) {
    let note = [str_of(o, "name"), str_of(o, "description")]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
        .join(": ");
    let note = (!note.is_empty()).then(|| super::short(&note, 1000));
    for p in o
        .get("kill_chain_phases")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let chain = str_of(p, "kill_chain_name").unwrap_or_default();
        let phase = str_of(p, "phase_name").unwrap_or_default();
        let tactic = (chain == SC_T_SOURCE)
            .then(|| {
                (1..=9)
                    .map(|n| format!("SC-T{n}"))
                    .find(|t| crosswalk(t).is_some_and(|c| c.phase == phase))
            })
            .flatten();
        match tactic {
            Some(t) => {
                b.tactic(&t);
            }
            None => b.unmapped(&format!("{path}.kill_chain_phases"), &text_of(p)),
        }
    }
    if let Some(t) = o.get("indicator_types") {
        b.unmapped(&format!("{path}.indicator_types"), &text_of(t));
    }
    let pattern = str_of(o, "pattern").unwrap_or_default();
    let ptype = str_of(o, "pattern_type").unwrap_or_else(|| "stix".into());
    if ptype != "stix" {
        b.unmapped(&format!("{path}.pattern ({ptype})"), &pattern);
        return;
    }
    let mut any = false;
    for c in comparisons().captures_iter(&pattern) {
        let (obj, prop, op) = (&c[1], &c[2], &c[3]);
        let value = c[4].replace("\\'", "'").replace("\\\\", "\\");
        if op != "=" {
            b.unmapped(&format!("{path}.pattern"), &c[0]);
            continue;
        }
        any = true;
        let low = prop.to_ascii_lowercase();
        let kind = match obj {
            "url" if prop == "value" => IndicatorKind::Url,
            "ipv4-addr" | "ipv6-addr" if prop == "value" => IndicatorKind::Ip,
            "network-traffic" if low.contains("user-agent") => IndicatorKind::UserAgent,
            _ => IndicatorKind::Other,
        };
        let value = if kind == IndicatorKind::Other {
            format!("{obj}:{prop} = {value}")
        } else {
            value
        };
        b.indicator(kind, &value, note.clone());
    }
    if !any && !pattern.is_empty() {
        b.unmapped(&format!("{path}.pattern"), &pattern);
    }
}

/// One observed-data object as JSON log records, one per request.
fn observed(b: &mut Builder, o: &Value, by_id: &BTreeMap<&str, &Value>, path: &str) {
    let first = str_of(o, "first_observed");
    let last = str_of(o, "last_observed");
    for t in [&first, &last].into_iter().flatten() {
        b.seen(t);
    }
    // 2.1 refers to objects; 2.0 embedded them under `objects`.
    let mut objs: Vec<(String, Value)> = refs(o, "object_refs")
        .filter_map(|r| by_id.get(r).map(|v| (r.to_string(), (*v).clone())))
        .collect();
    let embedded: BTreeMap<String, Value> = o
        .get("objects")
        .and_then(Value::as_object)
        .map(|m| m.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
        .unwrap_or_default();
    objs.extend(embedded.iter().map(|(k, v)| (k.clone(), v.clone())));
    let lookup = |r: &str| -> Option<Value> {
        by_id
            .get(r)
            .map(|v| (*v).clone())
            .or_else(|| embedded.get(r).cloned())
    };
    let kind = |v: &Value| {
        v.get("type")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string()
    };
    let mut records: Vec<Value> = Vec::new();
    let mut in_traffic: BTreeSet<String> = BTreeSet::new();
    let (mut ips, mut urls) = (Vec::new(), Vec::new());
    for (id, v) in &objs {
        if kind(v) != "network-traffic" {
            continue;
        }
        let side = |k: &str| {
            let r = v.get(k).and_then(Value::as_str)?;
            let x = lookup(r)?;
            Some((r.to_string(), str_of(&x, "value")?))
        };
        let src = side("src_ref");
        let dst = side("dst_ref");
        in_traffic.insert(id.clone());
        for (r, _) in [&src, &dst].into_iter().flatten() {
            in_traffic.insert(r.clone());
        }
        let http = v
            .get("extensions")
            .and_then(|e| e.get("http-request-ext"))
            .cloned()
            .unwrap_or(Value::Null);
        let header = |name: &str| {
            http.get("request_header")
                .and_then(Value::as_object)?
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case(name))
                .and_then(|(_, v)| v.as_str().map(str::to_string))
        };
        let host = header("Host").or_else(|| dst.as_ref().map(|d| d.1.clone()));
        let port = v.get("dst_port").and_then(Value::as_u64);
        let target = str_of(&http, "request_value");
        let url = match (&target, &host) {
            (Some(t), _) if t.starts_with("http://") || t.starts_with("https://") => {
                Some(t.clone())
            }
            (Some(t), Some(h)) => {
                let scheme = if port == Some(80) { "http" } else { "https" };
                let sep = if t.starts_with('/') { "" } else { "/" };
                Some(format!("{scheme}://{h}{sep}{t}"))
            }
            _ => None,
        };
        let ip = src.as_ref().map(|s| s.1.clone()).filter(|s| is_ip(s));
        match url {
            Some(u) => {
                let mut rec = json!({ "url": u });
                if let Some(t) = &first {
                    rec["ts"] = json!(t);
                }
                if let Some(ip) = &ip {
                    rec["ip"] = json!(ip);
                }
                if let Some(ua) = header("User-Agent") {
                    rec["user_agent"] = json!(ua);
                }
                if let Some(m) = str_of(&http, "request_method") {
                    rec["method"] = json!(m);
                }
                records.push(rec);
            }
            None => {
                if let Some(ip) = ip {
                    ips.push(ip);
                }
                b.unmapped(
                    &format!("{path} network-traffic {id}"),
                    &format!(
                        "no request URL; to {}",
                        host.as_deref().unwrap_or("an unnamed host")
                    ),
                );
            }
        }
    }
    for (id, v) in &objs {
        if in_traffic.contains(id) {
            continue;
        }
        match (kind(v).as_str(), str_of(v, "value")) {
            ("url", Some(u)) => urls.push(u),
            ("ipv4-addr" | "ipv6-addr", Some(ip)) => ips.push(ip),
            ("domain-name", Some(d)) => b.target(&d),
            ("network-traffic", _) => {}
            (t, _) => b.unmapped(&format!("{path} {id}"), &format!("{t} {}", v)),
        }
    }
    let one_ip = (ips.len() == 1).then(|| ips[0].clone());
    for u in urls {
        let mut rec = json!({ "url": u });
        if let Some(t) = &first {
            rec["ts"] = json!(t);
        }
        if let Some(ip) = &one_ip {
            rec["ip"] = json!(ip);
        }
        records.push(rec);
    }
    if records.is_empty() {
        for ip in ips {
            b.indicator(IndicatorKind::Ip, &ip, Some(format!("observed in {path}")));
        }
        return;
    }
    for r in &records {
        if let Some(h) = r["url"].as_str().and_then(url_host) {
            b.target(&h);
        }
    }
    let n = o
        .get("number_observed")
        .and_then(Value::as_u64)
        .unwrap_or(1);
    let span = match (&first, &last) {
        (Some(f), Some(l)) if f != l => format!(", {f} to {l}"),
        (Some(f), _) => format!(", {f}"),
        _ => String::new(),
    };
    b.lines(
        records.iter().map(Value::to_string).collect(),
        None,
        Some(format!("STIX {path}: observed {n} time(s){span}")),
    );
}
