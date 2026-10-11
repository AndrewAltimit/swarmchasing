//! The STIX objects of an export, one function per object type.

use crate::Options;
use crate::ids::{STIX_NS, Tlp, sdo_id, stix_ts, uuid5};
use crate::indicators::{Draft, confidence};
use sc_case::text::audience_id;
use serde_json::{Value, json};
use std::collections::BTreeMap;

/// What every object an export creates shares: its creator, creation time
/// and marking.
pub(crate) struct Head {
    pub identity: String,
    pub created: String,
    pub marking: Tlp,
}

/// The reporter.
pub(crate) fn identity(h: &Head, name: &str) -> Value {
    json!({
        "type": "identity",
        "spec_version": "2.1",
        "id": h.identity,
        "created": h.created,
        "modified": h.created,
        "name": name,
    })
}

/// The predefined TLP marking definition.
pub(crate) fn marking(m: Tlp) -> Value {
    json!({
        "type": "marking-definition",
        "spec_version": "2.1",
        "id": m.0,
        "created": "2017-01-20T00:00:00.000Z",
        "definition_type": "tlp",
        "name": m.1,
        "definition": { "tlp": m.2 },
    })
}

/// An indicator's id. Exports under different markings are different objects.
pub(crate) fn indicator_id(h: &Head, pattern: &str) -> String {
    sdo_id("indicator", &format!("{}:{pattern}", h.marking.1))
}

pub(crate) fn indicator(h: &Head, id: &str, pattern: &str, d: &Draft) -> Value {
    let malicious = d.tier == sc_core::Tier::Significant;
    let tactics: Vec<String> = d.tactics.iter().cloned().collect();
    let mut v = json!({
        "type": "indicator",
        "spec_version": "2.1",
        "id": id,
        "created_by_ref": h.identity,
        "created": h.created,
        "modified": h.created,
        "name": d.name,
        "indicator_types": [if malicious { "malicious-activity" } else { "anomalous-activity" }],
        "pattern": pattern,
        "pattern_type": "stix",
        "pattern_version": "2.1",
        "valid_from": if d.valid_from == i64::MAX { h.created.clone() } else { stix_ts(d.valid_from) },
        "confidence": confidence(d.tier),
        "labels": [d.label],
        "object_marking_refs": [h.marking.0],
    });
    if !tactics.is_empty() {
        v["kill_chain_phases"] = json!(crate::mapping::kill_chain_phases(&tactics));
        v["external_references"] = json!(crate::mapping::external_references(&tactics));
    }
    v
}

/// An indicator `based-on` the observed data it came from.
pub(crate) fn based_on(h: &Head, indicator: &str, observed: &str) -> Value {
    json!({
        "type": "relationship",
        "spec_version": "2.1",
        "id": sdo_id("relationship", &format!("{indicator}:based-on:{observed}")),
        "created_by_ref": h.identity,
        "created": h.created,
        "modified": h.created,
        "relationship_type": "based-on",
        "source_ref": indicator,
        "target_ref": observed,
        "object_marking_refs": [h.marking.0],
    })
}

/// One cluster's observations.
pub(crate) fn observed_data(
    h: &Head,
    case_id: &str,
    members: &[&str],
    (first, last): (String, String),
    refs: Vec<String>,
) -> Value {
    json!({
        "type": "observed-data",
        "spec_version": "2.1",
        "id": sdo_id("observed-data", &format!("{}:{}:{}", h.marking.1, case_id, members.join(","))),
        "created_by_ref": h.identity,
        "created": h.created,
        "modified": h.created,
        "first_observed": first,
        "last_observed": last,
        "number_observed": members.len().clamp(1, 999_999_999),
        "object_refs": refs,
        "object_marking_refs": [h.marking.0],
    })
}

/// The report wrapping everything else.
pub(crate) fn report(h: &Head, o: &Options, refs: Vec<String>) -> Value {
    json!({
        "type": "report",
        "spec_version": "2.1",
        "id": sdo_id("report", &format!("{}:{}", o.case_id, audience_id(o.audience))),
        "created_by_ref": h.identity,
        "created": h.created,
        "modified": h.created,
        "name": o.title,
        "description": format!(
            "DRAFT from swarmchasing case {} ({} export). Verify every item against the public records before sharing.",
            o.case_id,
            audience_id(o.audience)
        ),
        "report_types": ["threat-report"],
        "published": h.created,
        "object_refs": refs,
        "object_marking_refs": [h.marking.0],
    })
}

/// The bundle, its id a hash of its objects.
pub(crate) fn bundle(objects: Vec<Value>) -> Result<Value, String> {
    let content = serde_json::to_string(&objects).map_err(|e| e.to_string())?;
    Ok(json!({
        "type": "bundle",
        "id": format!("bundle--{}", uuid5(STIX_NS, &sc_case::bundle::sha256_hex(content.as_bytes()))),
        "objects": objects,
    }))
}

/// Add a cyber-observable once, with its STIX deterministic id (a UUIDv5 of
/// its id-contributing property in the STIX namespace).
pub(crate) fn add_sco(scos: &mut BTreeMap<String, Value>, kind: &str, props: Value) -> String {
    let key = if kind == "autonomous-system" {
        json!({ "number": props["number"] })
    } else {
        json!({ "value": props["value"] })
    };
    let id = format!("{kind}--{}", uuid5(STIX_NS, &key.to_string()));
    scos.entry(id.clone()).or_insert_with(|| {
        let mut v = props;
        v["type"] = json!(kind);
        v["spec_version"] = json!("2.1");
        v["id"] = json!(id);
        v
    });
    id
}
