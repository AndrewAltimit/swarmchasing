//! The six edge detectors (`S1` to `S6`), one module each, over the runs
//! of one analysis.

mod dispatch;
mod handoff;
mod lockstep;
mod partition;
mod role;
mod sink;

use super::artifacts::artifacts;
use super::runs::{Keyed, Run, first_by_key, indexes, sort_keyed};
use super::{EdgeStrength, RunRef, SwarmEdge, SwarmEdgeKind};
use crate::analyze::{Cluster, ObsResult};
use crate::chance::TestFamily;
use crate::rules::Rules;

/// Edges kept when their chance is at most this (S4).
pub(super) const MAX_CHANCE: f64 = 0.01;
/// Hosts each side needs (S4, S5).
const MIN_HOSTS: usize = 3;
/// A sink or artifact written or read by more runs than this is common.
const MAX_SHARING: usize = 10;
/// Record ids kept per side.
const MAX_RECORDS: usize = 3;

/// The tests one kind with a chance model read: each passing test's chance
/// (at or under the kind's own limit) with the edges it draws, and how many
/// tests were read in all.
#[derive(Default)]
pub(super) struct Tests {
    pub found: Vec<(f64, Vec<SwarmEdge>)>,
    pub tested: usize,
}

impl Tests {
    /// The edges whose test survives a Benjamini-Hochberg cut at `fdr` over
    /// every test read, each stating the count, and the family's budget.
    fn keep(self, kind: SwarmEdgeKind, fdr: f64, out: &mut Vec<SwarmEdge>) -> TestFamily {
        let ps: Vec<f64> = self.found.iter().map(|f| f.0).collect();
        let family = TestFamily::cut(kind.name(), &ps, self.tested, fdr);
        for (p, edges) in self.found {
            if !family.keeps(p) {
                continue;
            }
            for mut e in edges {
                e.tested = family.tested;
                e.detail.push_str(&format!(
                    "; {:.2} such pairs expected among {} tested",
                    p * family.tested as f64,
                    family.tested
                ));
                out.push(e);
            }
        }
        family
    }
}

/// Every edge between `runs`, in kind order (`S1` first), and the
/// multiplicity budget of S3 to S6.
pub(super) fn detect(
    runs: &[Run],
    clusters: &[Cluster],
    results: &[ObsResult],
    rules: &Rules,
) -> (Vec<SwarmEdge>, Vec<TestFamily>) {
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
        co: &rules.set.co_activity,
        max_shared: rules.set.soft_links.max_shared,
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
    let fdr = rules.set.swarm.fdr;
    let families = vec![
        cx.lockstep()
            .keep(SwarmEdgeKind::SynchronizedStart, fdr, &mut out),
        cx.role_sequences()
            .keep(SwarmEdgeKind::RoleSequence, fdr, &mut out),
        cx.partitions()
            .keep(SwarmEdgeKind::DisjointPartition, fdr, &mut out),
        cx.dispatch_stars()
            .keep(SwarmEdgeKind::DispatchStar, fdr, &mut out),
    ];
    (out, families)
}

/// Where an artifact was named: (run, strand, written, record).
type Meta = (usize, usize, bool, usize);

struct Ctx<'a> {
    runs: &'a [Run],
    cl: &'a [Cluster],
    res: &'a [ObsResult],
    opts: &'a super::SwarmOptions,
    /// Co-activity's bins, lags, shifts and clock weighting (S6).
    co: &'a crate::coactivity::CoActivityOptions,
    /// `soft_links.max_shared`: a bin more clusters share says nothing (S6).
    max_shared: usize,
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
        sides: (Side, Side),
        strength: EdgeStrength,
        chance: Option<f64>,
        detail: String,
    ) {
        out.push(self.edge(kind, sides, strength, chance, detail));
    }

    fn edge(
        &self,
        kind: SwarmEdgeKind,
        (x, y): (Side, Side),
        strength: EdgeStrength,
        chance: Option<f64>,
        detail: String,
    ) -> SwarmEdge {
        SwarmEdge {
            kind,
            a: self.side(x),
            b: self.side(y),
            strength,
            chance,
            tested: 0,
            detail,
        }
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
