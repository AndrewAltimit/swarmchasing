//! A STIX bundle from [`crate::build`] as a MISP event (MISP core format,
//! JSON), so it carries exactly what the export for that audience carries,
//! withholding included.
//!
//! - Indicators become attributes: a callback channel's domain as `domain`,
//!   a flagged user agent as `user-agent` (both `to_ids`), and a run tag or
//!   agent marker, a substring of URLs, as `text` (not `to_ids`: an IDS
//!   cannot match a substring pattern as is).
//! - Observables become attributes, not for IDS: `url`, `domain`, the
//!   client address as `ip-src`, the network as `AS`.
//! - Each agent run becomes an object `swarmchasing-agent-run` with its
//!   cluster key, span, tier, record count and tactics.
//! - Tags: the TLP of the export, `swarmchasing:draft`, and per tactic a
//!   `swarmchasing:tactic` machine tag with galaxy-style tags for its MITRE
//!   ATLAS and ATT&CK techniques and OWASP agentic entries
//!   ([`crate::mapping::misp_tags`]).
//!
//! The event is unpublished with distribution "your organisation only":
//! sharing it is the admin's decision in their own MISP. Every uuid is a
//! UUIDv5 of the content, so the same bundle converts byte for byte the same.

use crate::ids::{STIX_NS, uuid5};
use crate::mapping::misp_tags;
use serde_json::{Value, json};

fn uuid(kind: &str, value: &str) -> String {
    uuid5(STIX_NS, &format!("swarmchase:misp:{kind}:{value}"))
}

fn attribute(kind: &str, category: &str, value: &str, to_ids: bool, comment: &str) -> Value {
    json!({
        "uuid": uuid(kind, value),
        "type": kind,
        "category": category,
        "value": value,
        "to_ids": to_ids,
        "comment": comment,
        "disable_correlation": false,
    })
}

/// The value inside a STIX pattern's single quoted literal, unescaped.
fn literal(pattern: &str) -> Option<String> {
    let start = ["= '", "LIKE '"]
        .iter()
        .filter_map(|op| pattern.rfind(op).map(|i| i + op.len()))
        .max()?;
    let end = pattern.rfind('\'')?;
    (end > start).then(|| {
        pattern[start..end]
            .replace("\\'", "'")
            .replace("\\\\", "\\")
    })
}

fn indicator_attribute(v: &Value) -> Option<Value> {
    let pattern = v["pattern"].as_str()?;
    let name = v["name"].as_str().unwrap_or_default();
    let value = literal(pattern)?;
    let mut a = if pattern.starts_with("[domain-name:value =") {
        attribute("domain", "Network activity", &value, true, name)
    } else if pattern.contains("'User-Agent'") {
        attribute("user-agent", "Network activity", &value, true, name)
    } else {
        let value = value.trim_matches('%').to_string();
        attribute(
            "text",
            "Network activity",
            &value,
            false,
            &format!("{name} (a substring of the URLs)"),
        )
    };
    let tactics: Vec<String> = v["external_references"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|r| r["source_name"] == crate::mapping::SC_T_SOURCE)
        .filter_map(|r| r["external_id"].as_str().map(str::to_string))
        .collect();
    if !tactics.is_empty() {
        a["Tag"] = json!(
            misp_tags(&tactics)
                .into_iter()
                .map(|t| json!({ "name": t }))
                .collect::<Vec<_>>()
        );
    }
    Some(a)
}

fn observable_attribute(v: &Value) -> Option<Value> {
    let value = v["value"].as_str();
    Some(match v["type"].as_str()? {
        "url" => attribute("url", "Network activity", value?, false, "observed request"),
        "domain-name" => attribute("domain", "Network activity", value?, false, "target host"),
        "ipv4-addr" | "ipv6-addr" => attribute(
            "ip-src",
            "Network activity",
            value?,
            false,
            "client address",
        ),
        "autonomous-system" => {
            let n = v["number"].as_u64()?;
            let name = v["name"].as_str().unwrap_or_default();
            attribute("AS", "Network activity", &format!("AS{n}"), false, name)
        }
        _ => return None,
    })
}

fn run_object(v: &Value) -> Value {
    let id = v["id"].as_str().unwrap_or_default();
    let field = |kind: &str, relation: &str, value: &str| {
        let mut a = attribute(kind, "Other", value, false, "");
        a["object_relation"] = json!(relation);
        a
    };
    let mut attrs = vec![
        field(
            "text",
            "cluster-key",
            v["cluster_key"].as_str().unwrap_or_default(),
        ),
        field("text", "tier", v["tier"].as_str().unwrap_or_default()),
        field("counter", "record-count", &v["record_count"].to_string()),
    ];
    let tactics: Vec<String> = v["tactics"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|t| t.as_str().map(str::to_string))
        .collect();
    for t in &tactics {
        let mut a = field("text", "tactic", t);
        a["Tag"] = json!(
            misp_tags(std::slice::from_ref(t))
                .into_iter()
                .map(|t| json!({ "name": t }))
                .collect::<Vec<_>>()
        );
        attrs.push(a);
    }
    for a in attrs.iter_mut() {
        let rel = a["object_relation"]
            .as_str()
            .unwrap_or_default()
            .to_string();
        a["uuid"] = json!(uuid("run-attr", &format!("{id}:{rel}:{}", a["value"])));
    }
    json!({
        "uuid": uuid("run", id),
        "name": "swarmchasing-agent-run",
        "meta-category": "network",
        "description": "One run of an autonomous agent: a linked cluster of requests (Swarmchasing Field Manual 12.2).",
        "comment": v["name"],
        "first_seen": v["first_seen"],
        "last_seen": v["last_seen"],
        "Attribute": attrs,
    })
}

/// The MISP event for a STIX bundle built for `title` on `date`.
pub fn event(bundle: &Value, title: &str, date: &str) -> Value {
    let objects: &[Value] = bundle["objects"].as_array().map_or(&[], Vec::as_slice);
    let tlp = objects
        .iter()
        .find(|o| o["type"] == "marking-definition")
        .and_then(|o| o["definition"]["tlp"].as_str())
        .unwrap_or("amber");
    let mut attributes: Vec<Value> = Vec::new();
    let mut push = |a: Value| {
        if !attributes
            .iter()
            .any(|x| x["type"] == a["type"] && x["value"] == a["value"])
        {
            attributes.push(a);
        }
    };
    for o in objects.iter().filter(|o| o["type"] == "indicator") {
        if let Some(a) = indicator_attribute(o) {
            push(a);
        }
    }
    for o in objects {
        if let Some(a) = observable_attribute(o) {
            push(a);
        }
    }
    let runs: Vec<&Value> = objects
        .iter()
        .filter(|o| o["type"] == crate::agent_run::TYPE)
        .collect();
    let mut tactics: Vec<String> = Vec::new();
    for r in &runs {
        for t in r["tactics"].as_array().into_iter().flatten() {
            if let Some(t) = t.as_str()
                && !tactics.iter().any(|x| x == t)
            {
                tactics.push(t.to_string());
            }
        }
    }
    let significant = runs.iter().any(|r| r["tier"] == "significant");
    let mut tags = vec![format!("tlp:{tlp}"), "swarmchasing:draft".to_string()];
    tags.extend(misp_tags(&tactics));
    let report = objects.iter().find(|o| o["type"] == "report");
    json!({
        "Event": {
            "uuid": uuid("event", bundle["id"].as_str().unwrap_or_default()),
            "info": title,
            "date": date,
            "threat_level_id": if significant { "2" } else { "3" },
            "analysis": "1",
            "distribution": "0",
            "published": false,
            "Tag": tags.into_iter().map(|t| json!({ "name": t })).collect::<Vec<_>>(),
            "Attribute": attributes,
            "Object": runs.iter().map(|r| run_object(r)).collect::<Vec<_>>(),
            "EventReport": [{
                "uuid": uuid("report", bundle["id"].as_str().unwrap_or_default()),
                "name": "Swarmchasing export",
                "content": report.and_then(|r| r["description"].as_str()).unwrap_or_default(),
                "distribution": "0",
            }],
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::{analysis, options};
    use sc_core::Audience;

    #[test]
    fn an_event_carries_what_the_bundle_carries() {
        let (a, rules) = analysis();
        let affected = vec!["portal.example.gov".to_string()];
        let b = crate::build(&a, &rules, &options(Audience::Provider, &affected)).unwrap();
        let e = event(&b, "Portal probe", "2026-10-14");
        let ev = &e["Event"];
        assert_eq!(ev["published"], false);
        assert_eq!(ev["distribution"], "0");
        let tags: Vec<&str> = ev["Tag"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["name"].as_str().unwrap())
            .collect();
        assert!(tags.contains(&"tlp:amber") && tags.contains(&"swarmchasing:draft"));
        assert!(tags.contains(&"swarmchasing:tactic=\"SC-T4\""), "{tags:?}");
        assert!(
            tags.contains(&"misp-galaxy:mitre-atlas-attack-pattern=\"AML.T0049\""),
            "{tags:?}"
        );
        let attrs = ev["Attribute"].as_array().unwrap();
        let has = |ty: &str, v: &str| attrs.iter().any(|a| a["type"] == ty && a["value"] == v);
        assert!(has("text", "uqtag=zz9"), "{attrs:#?}");
        assert!(has("user-agent", "python-httpx/0.27"));
        assert!(has("ip-src", "203.0.113.5"));
        assert!(has("AS", "AS132203"));
        assert!(has("domain", "portal.example.gov"));
        let objs = ev["Object"].as_array().unwrap();
        assert!(!objs.is_empty());
        assert!(
            objs[0]["Attribute"]
                .as_array()
                .unwrap()
                .iter()
                .any(|a| a["object_relation"] == "tactic" && a["value"] == "SC-T4")
        );
        let uuids: std::collections::BTreeSet<String> = attrs
            .iter()
            .chain(objs.iter().flat_map(|o| o["Attribute"].as_array().unwrap()))
            .map(|a| a["uuid"].as_str().unwrap().to_string())
            .collect();
        assert_eq!(
            uuids.len(),
            attrs.len()
                + objs
                    .iter()
                    .map(|o| o["Attribute"].as_array().unwrap().len())
                    .sum::<usize>(),
            "uuids are unique"
        );
        assert_eq!(e, event(&b, "Portal probe", "2026-10-14"), "deterministic");

        let public = crate::build(&a, &rules, &options(Audience::Public, &affected)).unwrap();
        let text = event(&public, "Portal probe", "2026-10-14").to_string();
        assert!(text.contains("tlp:white") && !text.contains("203.0.113.5"));
    }
}
