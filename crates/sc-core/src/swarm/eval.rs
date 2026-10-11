//! Interaction edges against labelled swarm groups.

use super::RunRef;
use crate::analyze::Analysis;
use crate::eval::LabelSet;
use serde::{Deserialize, Serialize};

/// Edges against records labelled with a `swarm` group (`none` for runs
/// known not to interact). Counts by kind are indexed `S1` to `S5`. Report
/// only: no gate reads it.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SwarmEval {
    pub edges: usize,
    pub by_kind: [usize; 5],
    /// Interacting groups labelled, and those with an edge inside them.
    pub groups: Vec<String>,
    pub found: Vec<String>,
    /// Edges inside one interacting group.
    pub on_groups: usize,
    /// Edges touching a run labelled `none`, by kind.
    pub on_non_swarm: [usize; 5],
    /// Edges between two different interacting groups.
    pub across_groups: usize,
}

pub fn swarm_eval(a: &Analysis, labels: &LabelSet) -> SwarmEval {
    let group = |r: &RunRef| -> Option<&str> {
        r.records
            .iter()
            .find_map(|id| labels.labels.get(id).and_then(|l| l.swarm.as_deref()))
    };
    let mut groups: Vec<String> = Vec::new();
    for l in labels.labels.values() {
        if let Some(g) = &l.swarm
            && g != "none"
            && !groups.contains(g)
        {
            groups.push(g.clone());
        }
    }
    crate::sort::sort(&mut groups);
    let mut out = SwarmEval {
        edges: a.swarm_edges.len(),
        ..Default::default()
    };
    let mut inside: Vec<&str> = Vec::new();
    for e in &a.swarm_edges {
        let k = e.kind as usize;
        out.by_kind[k] += 1;
        match (group(&e.a), group(&e.b)) {
            (Some("none"), _) | (_, Some("none")) => out.on_non_swarm[k] += 1,
            (Some(x), Some(y)) if x == y => {
                out.on_groups += 1;
                inside.push(x);
            }
            (Some(_), Some(_)) => out.across_groups += 1,
            _ => {}
        }
    }
    out.found = groups
        .iter()
        .filter(|g| inside.contains(&g.as_str()))
        .cloned()
        .collect();
    out.groups = groups;
    out
}
