//! Swarm edges, soft links and candidate fleets against true run pairs, and
//! the agent grade by actor class.
//!
//! Review hints are measured beside them ([`GROUP_KINDS`]): onset groups as
//! edges are, against true swarm pairs, and seams against false merges, the
//! clusters above noise whose members span more than one operator.
//!
//! The unit is a pair of true runs. An edge side is placed on the run most of
//! its records belong to; a cluster on the run most of its members belong
//! to. Kinds are keyed by their serialised name. Every kind is listed with
//! its recall denominator in every measurement, fired or not, so a sum over
//! seeds and scenarios counts the true pairs a kind missed where it drew
//! nothing.

use crate::truth::Truth;
use sc_core::eval::Label;
use sc_core::eval::grades::Actor;
use sc_core::eval::stats::Proportion;
use sc_core::{AgentLevel, Analysis, PlantSignalKind, SoftLinkKind, Tier};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// One kind's pairs. For an edge, `correct` is a pair of distinct runs in one
/// swarm; for a soft link or candidate fleet, a pair with one operator
/// (`same_run` included, so a run split in two clusters and rejoined counts
/// as right). `cross_correct` counts only right pairs of distinct runs, and
/// [`KindStat::cross_run_precision`] reads it over the pairs of distinct
/// runs.
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
    /// Right pairs of distinct runs.
    #[serde(default)]
    pub cross_correct: usize,
    /// Soft links and candidate fleets: pairs of two clusters above noise
    /// on one run it linked (a split run rejoined), of
    /// [`Measurement::split_pairs`].
    #[serde(default)]
    pub rejoined: usize,
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

    /// Precision over the pairs of distinct runs: same-run pairs left out
    /// of both counts.
    pub fn cross_run_precision(&self) -> Proportion {
        Proportion::new(self.cross_correct, self.pairs - self.same_run)
    }

    fn add(&mut self, o: &Self) {
        self.pairs += o.pairs;
        self.correct += o.correct;
        self.same_run += o.same_run;
        self.same_operator += o.same_operator;
        self.unrelated += o.unrelated;
        self.cross_correct += o.cross_correct;
        self.rejoined += o.rejoined;
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
    /// Pairs of clusters above noise both placed on one run: a run split
    /// across clusters, which soft links may rejoin.
    #[serde(default)]
    pub split_pairs: usize,
    /// `actor/class` → grade column → records. Records with no actor are
    /// left out.
    pub grades: BTreeMap<String, BTreeMap<String, usize>>,
    /// Benign or tool records in clusters graded L2 or above.
    #[serde(default)]
    pub benign_high: usize,
    /// People's records in clusters graded L3 or above.
    #[serde(default)]
    pub human_high: usize,
    /// Agents' records grouped by cluster against their true runs.
    #[serde(default)]
    pub clustering: Clustering,
    /// How soon each true agent run is flagged.
    #[serde(default)]
    pub detection: Detection,
    /// Review hints by [`GROUP_KINDS`] name. `seam`: `pairs` are clusters
    /// above noise with a seam, `correct` and `found` those that are false
    /// merges, `of` the false merges, `unrelated` the clean ones seamed.
    /// `onset_group` (kept) and `onset_trigger` (listed as a common
    /// trigger): pairs of runs in one group, against true swarm pairs, as
    /// edges are.
    #[serde(default)]
    pub groups: BTreeMap<String, KindStat>,
    /// Clusters above noise whose members are one operator's.
    #[serde(default)]
    pub clean_clusters: usize,
}

/// Clusters against true runs, over records labelled agent: each record's
/// predicted group is its cluster, or the record alone when it is in none.
/// B-cubed precision counts a member of another run of the record's swarm
/// as right (a swarm's agents share an inbox or a tag by design); recall
/// and the adjusted Rand index read runs only. Sums, so seeds and scenarios
/// add; the ratios are read off the sums.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Clustering {
    pub records: usize,
    /// B-cubed precision and recall, summed over records.
    pub bcubed_precision_sum: f64,
    pub bcubed_recall_sum: f64,
    /// Pair counts for the adjusted Rand index: pairs of records, pairs in
    /// one group and one run, pairs in one group, pairs in one run.
    pub pairs: f64,
    pub pairs_both: f64,
    pub pairs_group: f64,
    pub pairs_run: f64,
}

impl Clustering {
    pub fn bcubed(&self) -> Option<(f64, f64, f64)> {
        if self.records == 0 {
            return None;
        }
        let n = self.records as f64;
        let (p, r) = (self.bcubed_precision_sum / n, self.bcubed_recall_sum / n);
        let f = if p + r > 0.0 {
            2.0 * p * r / (p + r)
        } else {
            0.0
        };
        Some((p, r, f))
    }

    /// The adjusted Rand index (Hubert and Arabie) from the summed pair
    /// counts: 1 for groups that are the runs, about 0 for chance.
    pub fn ari(&self) -> Option<f64> {
        if self.pairs <= 0.0 {
            return None;
        }
        let expected = self.pairs_group * self.pairs_run / self.pairs;
        let max = (self.pairs_group + self.pairs_run) / 2.0;
        if (max - expected).abs() < 1e-12 {
            return Some(1.0);
        }
        Some((self.pairs_both - expected) / (max - expected))
    }

    fn add(&mut self, o: &Self) {
        self.records += o.records;
        self.bcubed_precision_sum += o.bcubed_precision_sum;
        self.bcubed_recall_sum += o.bcubed_recall_sum;
        self.pairs += o.pairs;
        self.pairs_both += o.pairs_both;
        self.pairs_group += o.pairs_group;
        self.pairs_run += o.pairs_run;
    }
}

/// How soon true agent runs are flagged: from the whole analysis, records
/// and minutes from each run's first record to its first record at
/// suggestive or above; with checkpoints, minutes to the first prefix of
/// the records (cut at evenly spaced record counts, sorted by time) whose
/// analysis grades the run's cluster L2 or above or puts it in a candidate
/// fleet. A checkpoint's time is its last record's, so those minutes are
/// an upper bound at the checkpoints' spacing.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Detection {
    /// True agent runs.
    pub runs: usize,
    /// Per flagged run: its records up to and including the first flagged.
    pub records_to_flag: Vec<usize>,
    pub minutes_to_flag: Vec<f64>,
    /// Checkpoints each analysis was cut at; 0 when none was run.
    #[serde(default)]
    pub checkpoints: usize,
    /// Per run that reached L2 or a candidate fleet at a checkpoint.
    #[serde(default)]
    pub minutes_to_escalate: Vec<f64>,
}

impl Detection {
    fn add(&mut self, o: &Self) {
        self.runs += o.runs;
        self.records_to_flag.extend(&o.records_to_flag);
        self.minutes_to_flag.extend(&o.minutes_to_flag);
        self.checkpoints = self.checkpoints.max(o.checkpoints);
        self.minutes_to_escalate.extend(&o.minutes_to_escalate);
    }
}

/// The `q` quantile (nearest rank) of `xs`, `None` when empty.
pub fn quantile(xs: &[f64], q: f64) -> Option<f64> {
    if xs.is_empty() {
        return None;
    }
    let mut v = xs.to_vec();
    v.sort_by(f64::total_cmp);
    let k = ((q * v.len() as f64).ceil() as usize).clamp(1, v.len());
    Some(v[k - 1])
}

fn choose2(n: usize) -> f64 {
    let n = n as f64;
    n * (n - 1.0) / 2.0
}

/// Agent records' clusters against their runs.
fn clustering(a: &Analysis, truth: &Truth) -> Clustering {
    let mut seen = BTreeSet::new();
    // (group, run) per agent record; a record in no cluster is its own group.
    let mut recs: Vec<((bool, usize), &str)> = Vec::new();
    let mut swarm_of: BTreeMap<&str, &str> = BTreeMap::new();
    for (i, r) in a.results.iter().enumerate() {
        let Some(t) = truth.get(&r.obs.id) else {
            continue;
        };
        if t.label != Some(Label::Agent) || !seen.insert(r.obs.id.as_str()) {
            continue;
        }
        let g = r.cluster.map_or((false, i), |c| (true, c));
        recs.push((g, t.run.as_str()));
        if let Some(sw) = t.swarm_id() {
            swarm_of.insert(t.run.as_str(), sw);
        }
    }
    let mut out = Clustering {
        records: recs.len(),
        pairs: choose2(recs.len()),
        ..Clustering::default()
    };
    let mut group: BTreeMap<(bool, usize), usize> = BTreeMap::new();
    let mut run: BTreeMap<&str, usize> = BTreeMap::new();
    let mut both: BTreeMap<((bool, usize), &str), usize> = BTreeMap::new();
    for &(g, r) in &recs {
        *group.entry(g).or_default() += 1;
        *run.entry(r).or_default() += 1;
        *both.entry((g, r)).or_default() += 1;
    }
    // Precision counts members of the record's swarm's other runs as right,
    // as `eval` does: one swarm's agents share an inbox or a tag by design.
    let mut group_runs: BTreeMap<(bool, usize), Vec<(&str, usize)>> = BTreeMap::new();
    for (&(g, r), &n) in &both {
        group_runs.entry(g).or_default().push((r, n));
    }
    let one_swarm =
        |x: &str, y: &str| x == y || swarm_of.get(x).is_some_and(|s| swarm_of.get(y) == Some(s));
    for &(g, r) in &recs {
        let same = both[&(g, r)] as f64;
        let swarm: usize = group_runs[&g]
            .iter()
            .filter(|(x, _)| one_swarm(x, r))
            .map(|x| x.1)
            .sum();
        out.bcubed_precision_sum += swarm as f64 / group[&g] as f64;
        out.bcubed_recall_sum += same / run[r] as f64;
    }
    out.pairs_both = both.values().map(|&n| choose2(n)).sum();
    out.pairs_group = group.values().map(|&n| choose2(n)).sum();
    out.pairs_run = run.values().map(|&n| choose2(n)).sum();
    out
}

/// Records and minutes to each agent run's first flagged record.
fn detection(a: &Analysis, truth: &Truth) -> Detection {
    let mut seen = BTreeSet::new();
    let mut by_run: BTreeMap<&str, Vec<(i64, bool)>> = BTreeMap::new();
    for r in &a.results {
        let Some(t) = truth.get(&r.obs.id) else {
            continue;
        };
        if t.label != Some(Label::Agent) || !seen.insert(r.obs.id.as_str()) {
            continue;
        }
        by_run
            .entry(t.run.as_str())
            .or_default()
            .push((r.obs.ts, r.tier >= Tier::Suggestive));
    }
    let mut out = Detection {
        runs: by_run.len(),
        ..Detection::default()
    };
    for recs in by_run.values_mut() {
        recs.sort_by_key(|x| (x.0, !x.1));
        if let Some(k) = recs.iter().position(|x| x.1) {
            out.records_to_flag.push(k + 1);
            out.minutes_to_flag
                .push((recs[k].0 - recs[0].0) as f64 / 60.0);
        }
    }
    out
}

/// Minutes from each agent run's first record to the first of
/// `checkpoints` prefixes of `obs` (sorted by time) whose analysis grades
/// the cluster holding most of the run's records so far L2 or above, or
/// puts it in a candidate fleet. Each prefix is analysed afresh.
pub fn escalation_times(
    obs: &[sc_core::Observation],
    truth: &Truth,
    rules: &sc_core::Rules,
    checkpoints: usize,
) -> Vec<f64> {
    let mut sorted: Vec<&sc_core::Observation> = obs.iter().collect();
    sorted.sort_by_key(|o| o.ts);
    let n = sorted.len();
    let mut first: BTreeMap<String, i64> = BTreeMap::new();
    for o in &sorted {
        if let Some(t) = truth.get(&o.id)
            && t.label == Some(Label::Agent)
        {
            first.entry(t.run.clone()).or_insert(o.ts);
        }
    }
    let mut done: BTreeMap<String, f64> = BTreeMap::new();
    for j in 1..=checkpoints.max(1) {
        let m = (n * j).div_ceil(checkpoints.max(1));
        if m == 0 {
            continue;
        }
        let cut = sorted[m - 1].ts;
        let prefix: Vec<sc_core::Observation> = sorted[..m].iter().map(|o| (*o).clone()).collect();
        let a = sc_core::analyze(prefix, rules);
        let fleet: BTreeSet<usize> = a
            .candidate_fleets
            .iter()
            .flat_map(|f| f.clusters.iter().filter_map(|c| a.cluster_index(c)))
            .collect();
        // Each run's cluster holding most of its records so far.
        let mut counts: BTreeMap<&str, BTreeMap<usize, usize>> = BTreeMap::new();
        for r in &a.results {
            let (Some(t), Some(c)) = (truth.get(&r.obs.id), r.cluster) else {
                continue;
            };
            if t.label == Some(Label::Agent) && !done.contains_key(&t.run) {
                *counts
                    .entry(t.run.as_str())
                    .or_default()
                    .entry(c)
                    .or_default() += 1;
            }
        }
        for (run, cs) in counts {
            let Some((&c, _)) = cs.iter().max_by_key(|x| (*x.1, std::cmp::Reverse(*x.0))) else {
                continue;
            };
            if a.clusters[c].agent.level >= AgentLevel::ModelWritten || fleet.contains(&c) {
                let start = first.get(run).copied().unwrap_or(cut);
                done.insert(run.to_string(), (cut - start).max(0) as f64 / 60.0);
            }
        }
    }
    done.into_values().collect()
}

/// The review hints measured per scenario, as `expect` names them.
pub const GROUP_KINDS: [&str; 3] = ["seam", "onset_group", "onset_trigger"];

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
        for (mine, theirs) in [
            (&mut self.edges, &o.edges),
            (&mut self.links, &o.links),
            (&mut self.groups, &o.groups),
        ] {
            for (k, v) in theirs {
                mine.entry(k.clone()).or_default().add(v);
            }
        }
        self.unplaced += o.unplaced;
        self.split_pairs += o.split_pairs;
        self.benign_high += o.benign_high;
        self.human_high += o.human_high;
        self.clustering.add(&o.clustering);
        self.detection.add(&o.detection);
        self.clean_clusters += o.clean_clusters;
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
pub(crate) fn majority<'a>(
    truth: &'a Truth,
    ids: impl Iterator<Item = &'a str>,
) -> Option<&'a str> {
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
    let mut out = Measurement {
        clustering: clustering(a, truth),
        detection: detection(a, truth),
        ..Measurement::default()
    };
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
        let level = match (r.score, r.cluster) {
            (0, _) | (_, None) => None,
            (_, Some(c)) => Some(a.clusters[c].agent.level),
        };
        let col = match (r.score, level) {
            (0, _) => "unflagged".to_string(),
            (_, None) => "unclustered".to_string(),
            (_, Some(l)) => l.code().to_string(),
        };
        if let Some(actor) = t.actor {
            *out.grades
                .entry(format!("{}/{}", actor.id(), t.class))
                .or_default()
                .entry(col)
                .or_default() += 1;
        }
        let benign = t.label == Some(Label::Benign) || t.actor == Some(Actor::Tool);
        if benign && level >= Some(AgentLevel::ModelWritten) {
            out.benign_high += 1;
        }
        if t.actor == Some(Actor::Human) && level >= Some(AgentLevel::Adaptive) {
            out.human_high += 1;
        }
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
    let swarm_stat = |ps: &BTreeSet<(&str, &str)>| {
        let mut s = KindStat::default();
        for &(x, y) in ps {
            s.pairs += 1;
            let (tx, ty) = (run_row[x], run_row[y]);
            if x == y {
                s.same_run += 1;
            } else if tx.swarm_id().is_some() && tx.swarm_id() == ty.swarm_id() {
                s.correct += 1;
                s.cross_correct += 1;
            } else if tx.operator() == ty.operator() {
                s.same_operator += 1;
            } else {
                s.unrelated += 1;
            }
        }
        s.of = swarm_pairs.len();
        s.found = swarm_pairs.iter().filter(|p| ps.contains(p)).count();
        s
    };
    for (k, ps) in drawn {
        out.edges.insert(k, swarm_stat(&ps));
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
    // Clusters above noise on one run: the split runs a link may rejoin.
    let above = |c: usize| a.clusters[c].tier > Tier::Noise;
    let placed_above: Vec<&str> = cluster_run
        .iter()
        .filter(|(c, _)| above(**c))
        .map(|(_, r)| *r)
        .collect();
    for (i, rx) in placed_above.iter().enumerate() {
        out.split_pairs += placed_above[i + 1..].iter().filter(|ry| *ry == rx).count();
    }
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
    // Onset groups: every pair of runs in a group, kept or listed as a
    // common trigger.
    let mut onset: BTreeMap<String, BTreeSet<(&str, &str)>> = BTreeMap::new();
    for k in ["onset_group", "onset_trigger"] {
        onset.entry(k.into()).or_default();
    }
    for g in &a.onset_groups {
        let kind = if g.common_trigger {
            "onset_trigger"
        } else {
            "onset_group"
        };
        let runs: Vec<&str> = g
            .clusters
            .iter()
            .filter_map(|c| a.cluster_index(c))
            .filter_map(|c| cluster_run.get(&c).copied())
            .collect();
        out.unplaced += g.clusters.len() - runs.len();
        for (i, &x) in runs.iter().enumerate() {
            for &y in &runs[i + 1..] {
                onset.entry(kind.into()).or_default().insert(pair(x, y));
            }
        }
    }
    for (k, ps) in onset {
        out.groups.insert(k, swarm_stat(&ps));
    }

    // Seams against false merges.
    let mut seam = KindStat::default();
    for c in a.clusters.iter().filter(|c| c.tier > Tier::Noise) {
        let ops: BTreeSet<String> = c
            .members
            .iter()
            .filter_map(|&m| truth.get(&a.results[m].obs.id))
            .map(|t| t.operator())
            .collect();
        if ops.is_empty() {
            continue;
        }
        let merged = ops.len() > 1;
        let seamed = c
            .origin
            .plant_signals
            .iter()
            .any(|p| p.kind == PlantSignalKind::Seam);
        if merged {
            seam.of += 1;
        } else {
            out.clean_clusters += 1;
        }
        if seamed {
            seam.pairs += 1;
            if merged {
                seam.correct += 1;
                seam.cross_correct += 1;
                seam.found += 1;
            } else {
                seam.unrelated += 1;
            }
        }
    }
    out.groups.insert("seam".into(), seam);

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
                if above(x) && above(y) {
                    s.rejoined += 1;
                }
            } else if run_row[rx].operator() == run_row[ry].operator() {
                s.correct += 1;
                s.cross_correct += 1;
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
const SOFT_LINK_KINDS: [SoftLinkKind; 23] = {
    use SoftLinkKind::*;
    const fn listed(k: SoftLinkKind) {
        match k {
            SharedPause | Dialect | Rerun | Preamble | PathSet | Encoding | FanOut | CutLength
            | HeaderSet | Escalation | CommonFeature | SharedSecret | RelayStack
            | CallbackService | Scaffold | CoActivity | CoTarget | OrderedCoTarget
            | ScaffoldLineage | PromptEcho | CoGroup | Generator | Playbook => {}
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
        CoTarget,
        OrderedCoTarget,
        ScaffoldLineage,
        PromptEcho,
        CoGroup,
        Generator,
        Playbook,
    ]
};
