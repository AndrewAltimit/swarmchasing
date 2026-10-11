//! The few facts the evaluation reads from a cluster, in one place, so the
//! scoring code does not depend on how [`crate::analyze::Cluster`] lays out
//! its fields.

use crate::analyze::Analysis;
use crate::model::Tier;
use crate::plant::PlantSignalKind;

/// The cluster's tier: the strongest member's, raised by corroboration.
pub(crate) fn cluster_tier(a: &Analysis, c: usize) -> Tier {
    a.clusters[c].tier
}

/// The cluster's agent grade code (`L0`..`L4`).
pub(crate) fn cluster_level(a: &Analysis, c: usize) -> &'static str {
    a.clusters[c].agent.level.code()
}

/// The kinds of plant signal the cluster carries, each once.
pub(crate) fn cluster_plant_kinds(a: &Analysis, c: usize) -> Vec<PlantSignalKind> {
    let mut out: Vec<PlantSignalKind> = Vec::new();
    for p in &a.clusters[c].origin.plant_signals {
        if !out.contains(&p.kind) {
            out.push(p.kind);
        }
    }
    out
}

/// The cluster's stable key.
pub(crate) fn cluster_key(a: &Analysis, c: usize) -> &str {
    &a.clusters[c].key
}

/// How many records the cluster holds.
pub(crate) fn cluster_size(a: &Analysis, c: usize) -> usize {
    a.clusters[c].members.len()
}

/// The grade column of record `i`: `unflagged` (no rule fired),
/// `unclustered` (flagged, in no cluster), or its cluster's grade.
pub(crate) fn grade_column(a: &Analysis, i: usize) -> &'static str {
    let r = &a.results[i];
    match (r.score, r.cluster) {
        (0, _) => "unflagged",
        (_, None) => "unclustered",
        (_, Some(c)) => cluster_level(a, c),
    }
}
