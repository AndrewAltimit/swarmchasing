//! Swarm edges, soft links and candidate fleets against true run pairs, and
//! the agent grade by actor class.
//!
//! The unit is a pair of true runs. An edge side is placed on the run most of
//! its records belong to; a cluster on the run most of its members belong
//! to. Kinds are keyed by their serialised name. Every kind is listed with
//! its recall denominator in every measurement, fired or not, so a sum over
//! seeds and scenarios counts the true pairs a kind missed where it drew
//! nothing.

use crate::truth::Truth;
use sc_core::eval::stats::Proportion;
use sc_core::{Analysis, SoftLinkKind, Tier};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// One kind's pairs. For an edge, `correct` is a pair of distinct runs in one
/// swarm; for a soft link or candidate fleet, a pair with one operator
/// (`same_run` included).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct KindStat {
    /// Distinct run pairs it drew, both sides placed.
    pub pairs: usize,
    pub correct: usize,
    /// Both sides on one true run.
    pub same_run: usize,
    /// Distinct runs, one operator, no interaction (edges only).
    pub same_operator: usize,
    pub unrelated: usize,
    /// True pairs it found, of those it could reach.
    pub found: usize,
    pub of: usize,
}

impl KindStat {
    pub fn precision(&self) -> Proportion {
        Proportion::new(self.correct, self.pairs)
    }

    pub fn recall(&self) -> Proportion {
        Proportion::new(self.found, self.of)
    }

    fn add(&mut self, o: &Self) {
        self.pairs += o.pairs;
        self.correct += o.correct;
        self.same_run += o.same_run;
        self.same_operator += o.same_operator;
        self.unrelated += o.unrelated;
        self.found += o.found;
        self.of += o.of;
    }
}

/// True pairs: all of them, and those both of whose runs reach a cluster
/// above noise (`reachable`). For operator pairs, `joined` are already in
/// one cluster.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct PairCounts {
    pub total: usize,
    pub reachable: usize,
    pub joined: usize,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Measurement {
    /// Records with truth.
    pub records: usize,
    /// Pairs of distinct runs in one swarm.
    pub swarm_pairs: PairCounts,
    /// Pairs of distinct runs with one operator.
    pub operator_pairs: PairCounts,
    /// Edge kind name, then `any`.
    pub edges: BTreeMap<String, KindStat>,
    /// Soft-link kind name, `any`, then `candidate_fleet`.
    pub links: BTreeMap<String, KindStat>,
    /// Edges or links with a side no truth places.
    pub unplaced: usize,
    /// `actor/class` → grade column → records.
    pub grades: BTreeMap<String, BTreeMap<String, usize>>,
}

impl Measurement {
    /// Sum another measurement into this one (seeds, scenarios, files).
    pub fn add(&mut self, o: &Self) {
        self.records += o.records;
        for (a, b) in [
            (&mut self.swarm_pairs, &o.swarm_pairs),
            (&mut self.operator_pairs, &o.operator_pairs),
        ] {
            a.total += b.total;
            a.reachable += b.reachable;
            a.joined += b.joined;
        }
        for (mine, theirs) in [(&mut self.edges, &o.edges), (&mut self.links, &o.links)] {
            for (k, v) in theirs {
                mine.entry(k.clone()).or_default().add(v);
            }
        }
        self.unplaced += o.unplaced;
        for (row, cols) in &o.grades {
            let r = self.grades.entry(row.clone()).or_default();
            for (c, n) in cols {
                *r.entry(c.clone()).or_default() += n;
            }
        }
    }
}

/// The serialised name of a kind (`shared_sink`).
fn kind_name<T: Serialize>(k: &T) -> String {
    serde_json::to_value(k)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_else(|| "unknown".into())
}

/// The run most of `ids` belong to (ties to the smallest name).
fn majority<'a>(truth: &'a Truth, ids: impl Iterator<Item = &'a str>) -> Option<&'a str> {
    let mut n: BTreeMap<&str, usize> = BTreeMap::new();
    for id in ids {
        if let Some(t) = truth.get(id) {
            *n.entry(t.run.as_str()).or_default() += 1;
        }
    }
    let max = *n.values().max()?;
    n.into_iter().find(|x| x.1 == max).map(|x| x.0)
}

fn pair<'a>(a: &'a str, b: &'a str) -> (&'a str, &'a str) {
    if a <= b { (a, b) } else { (b, a) }
}

pub fn measure(a: &Analysis, truth: &Truth) -> Measurement {
    let mut out = Measurement::default();
    // Each run's row (its first record's), clusters above noise, and the
    // cluster holding most of its records.
    let mut run_row = BTreeMap::new();
    let mut run_clusters: BTreeMap<&str, BTreeMap<usize, usize>> = BTreeMap::new();
    let mut seen = BTreeSet::new();
    for r in &a.results {
        let Some(t) = truth.get(&r.obs.id) else {
            continue;
        };
        if !seen.insert(r.obs.id.as_str()) {
            continue;
        }
        out.records += 1;
        run_row.entry(t.run.as_str()).or_insert(t);
        let col = match (r.score, r.cluster) {
            (0, _) => "unflagged".to_string(),
            (_, None) => "unclustered".to_string(),
            (_, Some(c)) => a.clusters[c].agent.level.code().to_string(),
        };
        *out.grades
            .entry(format!("{}/{}", t.actor.id(), t.class))
            .or_default()
            .entry(col)
            .or_default() += 1;
        if let Some(c) = r.cluster.filter(|&c| a.clusters[c].tier > Tier::Noise) {
            *run_clusters
                .entry(t.run.as_str())
                .or_default()
                .entry(c)
                .or_default() += 1;
        }
    }
    let home: BTreeMap<&str, usize> = run_clusters
        .iter()
        .filter_map(|(r, cs)| {
            let max = cs.values().max()?;
            cs.iter().find(|x| x.1 == max).map(|x| (*r, *x.0))
        })
        .collect();

    // True pairs.
    let runs: Vec<&str> = run_row.keys().copied().collect();
    let (mut swarm_pairs, mut op_pairs) = (Vec::new(), Vec::new());
    for (i, &x) in runs.iter().enumerate() {
        for &y in &runs[i + 1..] {
            let (tx, ty) = (run_row[x], run_row[y]);
            let reach = home.contains_key(x) && home.contains_key(y);
            if tx.swarm_id().is_some() && tx.swarm_id() == ty.swarm_id() {
                out.swarm_pairs.total += 1;
                if reach {
                    out.swarm_pairs.reachable += 1;
                    swarm_pairs.push((x, y));
                }
            }
            if tx.operator() == ty.operator() {
                out.operator_pairs.total += 1;
                if reach {
                    out.operator_pairs.reachable += 1;
                    if home[x] == home[y] {
                        out.operator_pairs.joined += 1;
                    } else {
                        op_pairs.push((x, y));
                    }
                }
            }
        }
    }

    // Swarm edges, by kind.
    // Every kind and `any` is listed with its denominator, fired or not, so
    // summed recall counts the seeds where a kind drew nothing.
    let mut drawn: BTreeMap<String, BTreeSet<(&str, &str)>> = BTreeMap::new();
    for k in sc_core::SwarmEdgeKind::ALL {
        drawn.entry(kind_name(&k)).or_default();
    }
    drawn.entry("any".into()).or_default();
    for e in &a.swarm_edges {
        let ra = majority(truth, e.a.records.iter().map(String::as_str));
        let rb = majority(truth, e.b.records.iter().map(String::as_str));
        let (Some(ra), Some(rb)) = (ra, rb) else {
            out.unplaced += 1;
            continue;
        };
        let p = pair(ra, rb);
        drawn.entry(kind_name(&e.kind)).or_default().insert(p);
        drawn.entry("any".into()).or_default().insert(p);
    }
    for (k, ps) in drawn {
        let mut s = KindStat::default();
        for &(x, y) in &ps {
            s.pairs += 1;
            let (tx, ty) = (run_row[x], run_row[y]);
            if x == y {
                s.same_run += 1;
            } else if tx.swarm_id().is_some() && tx.swarm_id() == ty.swarm_id() {
                s.correct += 1;
            } else if tx.operator() == ty.operator() {
                s.same_operator += 1;
            } else {
                s.unrelated += 1;
            }
        }
        s.of = swarm_pairs.len();
        s.found = swarm_pairs.iter().filter(|p| ps.contains(p)).count();
        out.edges.insert(k, s);
    }

    // Soft links and candidate fleets, between clusters.
    let cluster_run: BTreeMap<usize, &str> = (0..a.clusters.len())
        .filter_map(|c| {
            let ids = a.clusters[c]
                .members
                .iter()
                .map(|&m| a.results[m].obs.id.as_str());
            majority(truth, ids).map(|r| (c, r))
        })
        .collect();
    let mut linked: BTreeMap<String, BTreeSet<(usize, usize)>> = BTreeMap::new();
    for k in SOFT_LINK_KINDS {
        linked.entry(kind_name(&k)).or_default();
    }
    for k in ["any", "candidate_fleet"] {
        linked.entry(k.into()).or_default();
    }
    let push = |kind: String, x: usize, y: usize, linked: &mut BTreeMap<_, BTreeSet<_>>| {
        linked.entry(kind).or_default().insert((x.min(y), x.max(y)));
    };
    for l in &a.soft_links {
        let (Some(x), Some(y)) = (a.cluster_index(&l.a), a.cluster_index(&l.b)) else {
            continue;
        };
        push(kind_name(&l.kind), x, y, &mut linked);
        push("any".into(), x, y, &mut linked);
    }
    for f in &a.candidate_fleets {
        let cs: Vec<usize> = f
            .clusters
            .iter()
            .filter_map(|c| a.cluster_index(c))
            .collect();
        for (i, &x) in cs.iter().enumerate() {
            for &y in &cs[i + 1..] {
                push("candidate_fleet".into(), x, y, &mut linked);
            }
        }
    }
    for (k, ps) in linked {
        let mut s = KindStat::default();
        for &(x, y) in &ps {
            let (Some(rx), Some(ry)) = (cluster_run.get(&x), cluster_run.get(&y)) else {
                out.unplaced += 1;
                continue;
            };
            s.pairs += 1;
            if rx == ry {
                s.same_run += 1;
                s.correct += 1;
            } else if run_row[rx].operator() == run_row[ry].operator() {
                s.correct += 1;
            } else {
                s.unrelated += 1;
            }
        }
        s.of = op_pairs.len();
        s.found = op_pairs
            .iter()
            .filter(|(x, y)| {
                let (cx, cy) = (home[x], home[y]);
                ps.contains(&(cx.min(cy), cx.max(cy)))
            })
            .count();
        out.links.insert(k, s);
    }
    out
}

/// Every soft-link kind. The match fails to compile when a kind is added
/// to [`SoftLinkKind`] and not here, so none goes unmeasured.
const SOFT_LINK_KINDS: [SoftLinkKind; 16] = {
    use SoftLinkKind::*;
    const fn listed(k: SoftLinkKind) {
        match k {
            SharedPause | Dialect | Rerun | Preamble | PathSet | Encoding | FanOut | CutLength
            | HeaderSet | Escalation | CommonFeature | SharedSecret | RelayStack
            | CallbackService | Scaffold | CoActivity => {}
        }
    }
    listed(SharedPause);
    [
        SharedPause,
        Dialect,
        Rerun,
        Preamble,
        PathSet,
        Encoding,
        FanOut,
        CutLength,
        HeaderSet,
        Escalation,
        CommonFeature,
        SharedSecret,
        RelayStack,
        CallbackService,
        Scaffold,
        CoActivity,
    ]
};
