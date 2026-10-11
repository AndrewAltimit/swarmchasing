//! The `x-sc-agent-run` STIX Domain Object (SC-FM 12.2): one run of an
//! autonomous agent, defined through an `extension-definition` of type
//! `new-sdo` whose JSON schema is committed at
//! `schemas/stix/x-sc-agent-run.json`.
//!
//! One object per exported cluster: its cluster key, span and timestamp
//! kind, the SC-T tactics its indicators are evidence of (in order of first
//! appearance), the artifact families seen, how wide its parallel batches
//! were, its tier, attribution per layer, and the `observed-data` holding
//! its records.

use crate::Options;
use crate::ids::{sdo_id, stix_ts};
use crate::objects::Head;
use sc_core::attribution::{Claim, Role, merge, summaries};
use sc_core::{Analysis, Cluster, attribute};
use serde_json::{Value, json};
use std::collections::BTreeSet;

/// The object type, and the extension definition's name.
pub const TYPE: &str = "x-sc-agent-run";
/// Where the committed schema is published.
pub const SCHEMA_URL: &str =
    "https://github.com/AndrewAltimit/swarmchasing/blob/main/schemas/stix/x-sc-agent-run.json";
/// The extension's version; bump it with the schema.
pub const VERSION: &str = "1.1.0";

/// The extension definition's id: fixed, so every export refers to the same
/// definition.
pub fn extension_id() -> String {
    sdo_id("extension-definition", &format!("{TYPE}:{VERSION}"))
}

/// The `extension-definition` object, created by the reporter.
pub(crate) fn extension_definition(h: &Head) -> Value {
    json!({
        "type": "extension-definition",
        "spec_version": "2.1",
        "id": extension_id(),
        "created_by_ref": h.identity,
        "created": h.created,
        "modified": h.created,
        "name": TYPE,
        "description": "One run of an autonomous agent: a linked cluster of requests, with its tactics, artifact families, concurrency and attribution per layer (Swarmchasing Field Manual 12.2).",
        "schema": SCHEMA_URL,
        "version": VERSION,
        "extension_types": ["new-sdo"],
        "object_marking_refs": [h.marking.0],
    })
}

/// The artifact family (SC-FM 4.5) a rule's match belongs to.
fn residue_family(rule: &str) -> Option<&'static str> {
    Some(match rule {
        "marker.tool_call_markup" | "marker.tool_call_json" => "tool_call_residue",
        "marker.placeholder_identity" => "fabricated_identifiers",
        "marker.truncated_output" => "cut_lengths",
        "marker.md_link"
        | "marker.md_url_wrapper"
        | "marker.placeholder"
        | "marker.template_unrendered"
        | "marker.chat_opener"
        | "marker.doubled_scheme"
        | "marker.garbled_scheme"
        | "marker.escaped_newline"
        | "marker.json_quote_residue" => "model_output_residue",
        _ => return None,
    })
}

/// The SC-T tactics the members' rule hits carry (each rule's `tactic`), in
/// order of first appearance, members taken in time order. A rule with no
/// tactic adds none.
fn tactics(a: &Analysis, c: &Cluster) -> Vec<String> {
    let mut members = c.members.clone();
    members.sort_by_key(|&m| (a.results[m].obs.ts, m));
    let mut out = Vec::new();
    for m in members {
        let mut hits: Vec<_> = a.results[m].hits.iter().collect();
        hits.sort_by(|x, y| x.rule_id.cmp(&y.rule_id));
        for t in hits
            .into_iter()
            .filter_map(|h| h.tactic.map(|t| format!("SC-{}", t.id())))
        {
            if !out.contains(&t) {
                out.push(t);
            }
        }
    }
    out
}

fn artifact_families(c: &Cluster) -> Vec<&'static str> {
    let mut f: BTreeSet<&str> = c.rules.keys().filter_map(|r| residue_family(r)).collect();
    if !c.dialect.is_empty() {
        f.insert("payload_dialect");
    }
    if !c.cut_lengths.is_empty() {
        f.insert("cut_lengths");
    }
    if !c.encodings.is_empty() {
        f.insert("encodings");
    }
    if c.paths.fabricated_ids > 0 {
        f.insert("fabricated_identifiers");
    }
    f.into_iter().collect()
}

/// The members' timestamp kind, or `mixed`.
fn timestamp_kind(a: &Analysis, c: &Cluster) -> String {
    let kinds: BTreeSet<String> = c
        .members
        .iter()
        .map(|&m| {
            serde_json::to_value(a.results[m].obs.ts_kind)
                .ok()
                .and_then(|v| v.as_str().map(str::to_string))
                .unwrap_or_else(|| "unknown".into())
        })
        .collect();
    match kinds.len() {
        1 => kinds.into_iter().next().unwrap_or_default(),
        _ => "mixed".into(),
    }
}

/// Attribution per layer for one run: the records' own claims and the
/// case's, gated like the report for the audience. A public export carries
/// developers through the naming gate and hosts only.
fn attribution(a: &Analysis, c: &Cluster, o: &Options) -> Vec<Value> {
    let claims: Vec<Claim> = merge(attribute(a, c), o.claims);
    summaries(&claims, o.min_named)
        .into_iter()
        .filter(|s| !o.public() || matches!(s.layer, Role::Developer | Role::Host))
        .filter_map(|s| serde_json::to_value(s).ok())
        .collect()
}

/// The run object for cluster `c`, referring to its `observed-data`.
pub(crate) fn agent_run(h: &Head, a: &Analysis, c: &Cluster, o: &Options, observed: &str) -> Value {
    let first = if c.start > 0 {
        stix_ts(c.start)
    } else {
        h.created.clone()
    };
    let last = if c.end > 0 {
        stix_ts(c.end)
    } else {
        first.clone()
    };
    let tactics = tactics(a, c);
    let mut v = json!({
        "type": TYPE,
        "spec_version": "2.1",
        "id": sdo_id(TYPE, &format!("{}:{}:{}", h.marking.1, o.case_id, c.key)),
        "created_by_ref": h.identity,
        "created": h.created,
        "modified": h.created,
        "name": format!("Agent run {} ({})", c.key, o.case_id),
        "cluster_key": c.key,
        "first_seen": first,
        "last_seen": last,
        "timestamp_kind": timestamp_kind(a, c),
        "tactics": tactics,
        "artifact_families": artifact_families(c),
        "concurrency": {
            "batches": c.fanout.batches,
            "modal_width": c.fanout.modal_width.unwrap_or(1),
            "max_width": c.fanout.widths.keys().max().copied().unwrap_or(1),
            "runs": c.runs.len(),
        },
        "tier": c.tier.label(),
        "record_count": c.members.len(),
        "attribution": attribution(a, c, o),
        "observed_data_refs": [observed],
        "object_marking_refs": [h.marking.0],
        "extensions": { extension_id(): { "extension_type": "new-sdo" } },
    });
    let refs = crate::mapping::external_references(&tactics);
    if !refs.is_empty() {
        v["external_references"] = json!(refs);
    }
    v
}
