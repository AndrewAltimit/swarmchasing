//! A case fleet as STIX (SC-FM 12.2): a `grouping` with context
//! `suspicious-activity` whose `object_refs` are its exported runs and their
//! `observed-data`, and a `related-to` relationship for each soft link
//! between two of its runs, its description naming the link's kind. Only
//! fleets the admin merged (`case fleet merge`) are exported, never the
//! analysis's candidate fleets.

use crate::ids::sdo_id;
use crate::objects::Head;
use sc_case::Fleet;
use sc_core::Analysis;
use serde_json::{Value, json};
use std::collections::BTreeMap;

/// One exported cluster: its run and observed-data ids, by cluster index.
pub(crate) struct Exported {
    pub run: String,
    pub observed: String,
}

/// The fleet's grouping and its runs' `related-to` relationships, or
/// nothing when fewer than two of its clusters were exported.
pub(crate) fn fleet_objects(
    h: &Head,
    a: &Analysis,
    case_id: &str,
    f: &Fleet,
    exported: &BTreeMap<usize, Exported>,
) -> Vec<Value> {
    let members: Vec<usize> = exported
        .keys()
        .copied()
        .filter(|&ci| f.clusters.contains(&a.clusters[ci].key))
        .collect();
    if members.len() < 2 {
        return Vec::new();
    }
    let mut refs: Vec<String> = Vec::new();
    for ci in &members {
        refs.push(exported[ci].run.clone());
        refs.push(exported[ci].observed.clone());
    }
    let mut out = Vec::new();
    for l in &a.soft_links {
        let (Some(x), Some(y)) = (a.cluster_index(&l.a), a.cluster_index(&l.b)) else {
            continue;
        };
        if !members.contains(&x) || !members.contains(&y) {
            continue;
        }
        let (src, tgt) = (&exported[&x].run, &exported[&y].run);
        let id = sdo_id(
            "relationship",
            &format!("{src}:related-to:{tgt}:{:?}", l.kind),
        );
        refs.push(id.clone());
        out.push(json!({
            "type": "relationship",
            "spec_version": "2.1",
            "id": id,
            "created_by_ref": h.identity,
            "created": h.created,
            "modified": h.created,
            "relationship_type": "related-to",
            "description": format!("soft link: {} (strength {:.2})", l.kind.label(), l.strength),
            "source_ref": src,
            "target_ref": tgt,
            "object_marking_refs": [h.marking.0],
        }));
    }
    let keys: Vec<&str> = members
        .iter()
        .map(|&ci| a.clusters[ci].key.as_str())
        .collect();
    out.insert(
        0,
        json!({
            "type": "grouping",
            "spec_version": "2.1",
            "id": sdo_id("grouping", &format!("{}:{case_id}:{}", h.marking.1, f.id)),
            "created_by_ref": h.identity,
            "created": h.created,
            "modified": h.created,
            "name": format!("{} {} ({case_id})", if f.is_swarm() { "Swarm" } else { "Fleet" }, f.id),
            "description": format!(
                "Agent runs the reporter treats as one fleet, one operator behind several runs: {}. The grouping rests on soft links, which unrelated clients can also share; an inference, not a finding.{}",
                keys.join(", "),
                if f.is_swarm() {
                    let k: std::collections::BTreeSet<&str> =
                        f.swarm_evidence.iter().map(|e| e.kind.label()).collect();
                    format!(
                        " The reporter also reviewed interaction between its runs (SC-T9: {}), so treats it as a swarm; also an inference.",
                        k.into_iter().collect::<Vec<_>>().join(", ")
                    )
                } else {
                    String::new()
                }
            ),
            "context": "suspicious-activity",
            "object_refs": refs,
            "object_marking_refs": [h.marking.0],
        }),
    );
    out
}
