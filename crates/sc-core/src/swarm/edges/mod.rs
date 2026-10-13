//! The five edge detectors (`S1` to `S5`), one module each, over the runs
//! of one analysis.

mod handoff;
mod lockstep;
mod partition;
mod role;
mod sink;

use super::artifacts::artifacts;
use super::runs::{Keyed, Run, first_by_key, indexes, sort_keyed};
use super::{EdgeStrength, RunRef, SwarmEdge, SwarmEdgeKind};
use crate::analyze::{Cluster, ObsResult};
use crate::rules::Rules;

/// Edges kept when their chance is at most this (S4).
pub(super) const MAX_CHANCE: f64 = 0.01;
/// Hosts each side needs (S4, S5).
const MIN_HOSTS: usize = 3;
/// A sink or artifact written or read by more runs than this is common.
const MAX_SHARING: usize = 10;
/// Record ids kept per side.
const MAX_RECORDS: usize = 3;

/// Every edge between `runs`, in kind order (`S1` first).
pub(super) fn detect(
    runs: &[Run],
    clusters: &[Cluster],
    results: &[ObsResult],
    rules: &Rules,
) -> Vec<SwarmEdge> {
    // Every artifact each run names, by id; the value indexes `meta`
    // (run, strand, written, record).
    let (mut named, mut meta) = (Keyed::new(), Vec::new());
    let mut found = Vec::new();
    for (ri, run) in runs.iter().enumerate() {
        for (si, s) in run.strands.iter().enumerate() {
            for &m in &s.members {
                found.clear();
                artifacts(&results[m], rules, &mut found);
                for (id, w) in found.drain(..) {
                    named.push((id, meta.len() as i64));
                    meta.push((ri, si, w, m));
                }
            }
        }
    }
    sort_keyed(&mut named);
    let cx = Ctx {
        runs,
        cl: clusters,
        res: results,
        opts: &rules.set.swarm,
    };
    let mut out = Vec::new();
    let groups: Vec<(&str, Vec<Meta>)> = named
        .chunk_by(|a, b| a.0 == b.0)
        .map(|g| {
            (
                g[0].0.as_str(),
                g.iter().map(|x| meta[x.1 as usize]).collect(),
            )
        })
        .collect();
    for (id, g) in &groups {
        cx.shared_sink(id, g, &mut out);
    }
    for (id, g) in &groups {
        cx.handoff(id, g, &mut out);
    }
    cx.lockstep(&mut out);
    cx.role_sequences(&mut out);
    cx.partitions(&mut out);
    out
}

/// Where an artifact was named: (run, strand, written, record).
type Meta = (usize, usize, bool, usize);

struct Ctx<'a> {
    runs: &'a [Run],
    cl: &'a [Cluster],
    res: &'a [ObsResult],
    opts: &'a super::SwarmOptions,
}

/// One side of an edge: the run, its strand label, the records.
type Side<'a> = (&'a Run, Option<&'a String>, &'a [usize]);

impl Ctx<'_> {
    fn side(&self, s: Side) -> RunRef {
        let (run, strand, recs) = s;
        let c = &self.cl[run.ci];
        RunRef {
            cluster: c.id.clone(),
            key: c.key.clone(),
            run: run.n,
            strand: strand.cloned(),
            records: recs
                .iter()
                .take(MAX_RECORDS)
                .map(|&m| self.res[m].obs.id.clone())
                .collect(),
        }
    }

    fn push(
        &self,
        out: &mut Vec<SwarmEdge>,
        kind: SwarmEdgeKind,
        (x, y): (Side, Side),
        strength: EdgeStrength,
        chance: Option<f64>,
        detail: String,
    ) {
        out.push(SwarmEdge {
            kind,
            a: self.side(x),
            b: self.side(y),
            strength,
            chance,
            detail,
        });
    }
}

impl Ctx<'_> {
    /// Indexes of the runs `keep` admits, by start.
    fn by_start(&self, keep: &dyn Fn(&Run) -> bool) -> Vec<usize> {
        let mut v = indexes(self.runs.len(), &|i| keep(&self.runs[i]));
        crate::sort::by_key(&mut v, |&i| self.runs[i].start);
        v
    }
}

impl Ctx<'_> {
    /// Distinct target hosts over all runs, by host.
    fn all_hosts(&self) -> Keyed {
        let mut v = Keyed::new();
        for r in self.runs {
            v.extend(r.hosts.iter().cloned());
        }
        first_by_key(v)
    }
}
