//! Possible interaction between runs (SC-T9): hints that agents act on each
//! other's output, not only alongside each other.
//!
//! A fleet is many agents doing the same thing; a swarm is a fleet whose
//! agents interact (SC-FM 1.3). Public records rarely show interaction
//! directly, so each [`SwarmEdge`] is one weak-to-moderate signal between two
//! runs, and a claim of interaction needs several together and the admin's
//! review. Edges are never scored, never link records and never merge
//! clusters. The kinds:
//!
//! - **S1 shared sink**: runs, or strands of one run, that write to the same
//!   inbox or artifact but differ in how they send requests (relay route,
//!   user agent, network, header set, encoding). A shared inbox hard-links
//!   every writer into one cluster, so this also looks inside a cluster.
//! - **S2 hand-off**: an artifact (an inbox, a gist, a paste, a Space, a
//!   static-site subdomain) that one run writes to and a later run fetches.
//! - **S3 synchronized start**: runs of different clients in lockstep,
//!   their requests lined up step by step at one offset, against random
//!   placement and against their own gaps reordered.
//! - **S4 role sequence**: a run that only reads a set of hosts, then a
//!   differently fingerprinted run attacking the same hosts in the same order.
//! - **S5 disjoint partition**: runs started together that split one target
//!   family with almost no overlap. One scheduler sharding a list does the
//!   same, so alone it is a fleet signal.
//!
//! Only identifier strings already in the records are matched; nothing here
//! reads an artifact, an inbox or a callback channel.

mod artifacts;
mod edges;
mod eval;
mod runs;

pub use eval::{SwarmEval, swarm_eval};

use crate::analyze::{Cluster, ObsResult};
use crate::extract::defang;
use crate::model::truncate;
use crate::rules::Rules;
use serde::{Deserialize, Serialize};
use std::fmt::Write;

/// What an edge rests on, `S1` to `S5`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwarmEdgeKind {
    SharedSink,
    Handoff,
    SynchronizedStart,
    RoleSequence,
    DisjointPartition,
}

impl SwarmEdgeKind {
    pub const ALL: [SwarmEdgeKind; 5] = [
        SwarmEdgeKind::SharedSink,
        SwarmEdgeKind::Handoff,
        SwarmEdgeKind::SynchronizedStart,
        SwarmEdgeKind::RoleSequence,
        SwarmEdgeKind::DisjointPartition,
    ];

    /// `S1` to `S5`.
    pub fn id(self) -> &'static str {
        ["S1", "S2", "S3", "S4", "S5"][self as usize]
    }

    pub fn label(self) -> &'static str {
        [
            "shared sink",
            "hand-off",
            "synchronized start",
            "role sequence",
            "disjoint partition",
        ][self as usize]
    }

    /// The name case files and the CLI use (`shared_sink`).
    pub fn name(self) -> &'static str {
        [
            "shared_sink",
            "handoff",
            "synchronized_start",
            "role_sequence",
            "disjoint_partition",
        ][self as usize]
    }
}

impl std::str::FromStr for SwarmEdgeKind {
    type Err = String;
    /// `S2`, `handoff` or `hand-off`, any case.
    fn from_str(s: &str) -> Result<Self, String> {
        let s = s.trim().to_ascii_lowercase().replace('-', "_");
        let s = if s == "hand_off" { "handoff".into() } else { s };
        Self::ALL
            .into_iter()
            .find(|k| k.id().eq_ignore_ascii_case(&s) || k.name() == s)
            .ok_or_else(|| {
                format!("unknown interaction kind `{s}` (S1..S5 or a name such as handoff)")
            })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EdgeStrength {
    Weak,
    Moderate,
    Strong,
}

impl EdgeStrength {
    pub fn label(self) -> &'static str {
        ["weak", "moderate", "strong"][self as usize]
    }
}

/// One run, or one strand of a run (its records sent one way, when the run
/// holds records sent several ways), with the records an edge rests on.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RunRef {
    /// Cluster id (`C3`) and stable key.
    pub cluster: String,
    pub key: String,
    /// The run's number in its cluster, from 1 ([`Cluster::runs`]).
    pub run: usize,
    /// How the strand's records were sent, when the edge is between strands.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub strand: Option<String>,
    /// Ids of the records the edge rests on, earliest first (a few).
    pub records: Vec<String>,
}

impl RunRef {
    /// `C3#2`, with the strand when there is one.
    pub fn label(&self) -> String {
        match &self.strand {
            Some(s) => format!("{}#{} ({s})", self.cluster, self.run),
            None => format!("{}#{}", self.cluster, self.run),
        }
    }

    /// `k-3f9a2c1b#2`: the form case files keep.
    pub fn stable(&self) -> String {
        format!("{}#{}", self.key, self.run)
    }
}

/// A hint that two runs interacted. Never a score, a link or a merge.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SwarmEdge {
    pub kind: SwarmEdgeKind,
    /// For a hand-off, `a` writes and `b` fetches; otherwise `a` starts first.
    pub a: RunRef,
    pub b: RunRef,
    pub strength: EdgeStrength,
    /// The chance of what was seen under the edge's chance model, where it
    /// has one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chance: Option<f64>,
    pub detail: String,
}

/// Interaction edge settings (`[swarm]` in the rules file).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct SwarmOptions {
    /// S3: two requests line up when this close at the pair's offset.
    pub lockstep_tolerance_secs: i64,
    /// S3: requests of the shorter run that must line up.
    pub lockstep_min_events: usize,
    /// S3: share of the shorter run's requests that must line up.
    pub lockstep_min_share: f64,
    /// S3: the offset between the runs is searched up to this either way.
    pub lockstep_max_offset_secs: i64,
    /// S3: permutations of the shorter run's own gaps in the second chance
    /// model. Its smallest chance is `1 / (permutations + 1)`.
    pub lockstep_permutations: usize,
    /// S3: kept when the larger of the two chances is at most this.
    pub lockstep_max_chance: f64,
}

impl Default for SwarmOptions {
    fn default() -> Self {
        Self {
            lockstep_tolerance_secs: 3,
            lockstep_min_events: 4,
            lockstep_min_share: 0.6,
            lockstep_max_offset_secs: 120,
            lockstep_permutations: 199,
            lockstep_max_chance: 0.01,
        }
    }
}

/// Edges kept, strongest first.
const MAX_EDGES: usize = 200;

/// Possible interaction between the runs of clusters above noise, in kind
/// order (`S1` first).
pub(crate) fn swarm_edges(
    clusters: &[Cluster],
    results: &[ObsResult],
    rules: &Rules,
) -> Vec<SwarmEdge> {
    let runs = runs::runs(clusters, results);
    let mut out = edges::detect(&runs, clusters, results, rules);
    out.truncate(MAX_EDGES);
    out
}

/// The "Possible interaction (SC-T9)" block of a report: the edges whose
/// two clusters `shown` allows, or nothing.
pub(crate) fn report_block(
    s: &mut String,
    edges: &[SwarmEdge],
    shown: &dyn Fn(&str, &str) -> bool,
) {
    let edges: Vec<&SwarmEdge> = edges
        .iter()
        .filter(|e| shown(&e.a.cluster, &e.b.cluster))
        .collect();
    if edges.is_empty() {
        return;
    }
    let _ = writeln!(
        s,
        "\n## Possible interaction (SC-T9)\n\nPairs of runs whose records suggest agents acting on each other's output. Each is a weak-to-moderate signal that coincidence, one scheduler or one agent changing route can also produce. None is scored or merges anything; together they are an Inference to review, not a finding. A grouping is called a swarm only once reviewed evidence of interaction is recorded.\n"
    );
    for e in edges.iter().take(12) {
        let recs: Vec<&str> =
            e.a.records
                .iter()
                .chain(&e.b.records)
                .map(String::as_str)
                .collect();
        let _ = writeln!(
            s,
            "- {} {} ({}): {} {} {}: {}. Records: {}",
            e.kind.id(),
            e.kind.label(),
            e.strength.label(),
            e.a.label(),
            if e.kind == SwarmEdgeKind::Handoff {
                "→"
            } else {
                "↔"
            },
            e.b.label(),
            truncate(&e.detail, 240),
            defang(&recs.join(", "))
        );
    }
    if edges.len() > 12 {
        let _ = writeln!(s, "- … and {} more", edges.len() - 12);
    }
}

#[cfg(test)]
mod tests;
