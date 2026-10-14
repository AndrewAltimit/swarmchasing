//! Recurrent target sets: one task rerun on another day.
//!
//! A fleet that reruns a task works through the same list of target hosts in
//! roughly the same order, even when its run tags change between runs. Two
//! runs match when they share enough hosts, their host sets overlap strongly
//! once hosts common to many runs are down-weighted, and the shared hosts come
//! up in a similar order. A list walked by more than a few runs within a
//! day of each other is a published one (a news story's sites, a directory
//! read top to bottom), not one operator's task, and pairs on it are not
//! matched. Only walkers active within a day less `min_gap_secs` of either
//! run of the pair count: one operator rerunning its task every day, under
//! a new tag each day, walks the list once a day however many days it
//! runs. Matches are leads to review; nothing here merges clusters.

use crate::analyze::{Analysis, Cluster, ObsResult};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

const DAY: i64 = 86_400;

/// One run: a key the caller chooses and the target hosts it hit, with times.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TargetRun {
    pub key: String,
    /// (unix ts, target host). Need not be sorted.
    pub targets: Vec<(i64, String)>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecurrenceOptions {
    /// Shared hosts needed before a pair is considered at all.
    pub min_shared: usize,
    /// Minimum Jaccard of the two host sets, each host weighted by how few
    /// runs it appears in (IDF), so hosts every run touches count for little.
    pub min_weighted_jaccard: f64,
    /// Minimum order agreement on the shared hosts (longest common
    /// subsequence of first-hit order over the shared host count).
    pub min_order: f64,
    /// The later run must start at least this long after the earlier one
    /// ends, as well as on a different UTC day.
    pub min_gap_secs: i64,
    /// A pair is not matched when more than this many walkers (clusters, or
    /// runs when no clusters are given) active within a day less
    /// `min_gap_secs` of either run hold at least half of the shared hosts
    /// (and `min_shared`): the list is common, not one operator's (0: no
    /// limit).
    pub max_walkers: usize,
}

impl Default for RecurrenceOptions {
    fn default() -> Self {
        Self {
            min_shared: 4,
            min_weighted_jaccard: 0.5,
            min_order: 0.7,
            min_gap_secs: 6 * 3600,
            max_walkers: 3,
        }
    }
}

/// A later run whose target sequence matches an earlier one.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Rerun {
    /// Indices into the runs passed to [`reruns`].
    pub earlier: usize,
    pub later: usize,
    /// Shared hosts, in the earlier run's order.
    pub shared: Vec<String>,
    /// Plain Jaccard of the host sets.
    pub jaccard: f64,
    pub weighted_jaccard: f64,
    pub order: f64,
}

struct Seq {
    start: i64,
    end: i64,
    /// Distinct hosts in first-hit order.
    hosts: Vec<String>,
    set: BTreeSet<String>,
}

fn seq(r: &TargetRun) -> Seq {
    let mut t: Vec<&(i64, String)> = r.targets.iter().filter(|(ts, _)| *ts > 0).collect();
    crate::sort::by(&mut t, |a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
    let mut set = BTreeSet::new();
    let mut hosts = Vec::new();
    for (_, h) in &t {
        if set.insert(h.clone()) {
            hosts.push(h.clone());
        }
    }
    Seq {
        start: t.first().map_or(0, |x| x.0),
        end: t.last().map_or(0, |x| x.0),
        hosts,
        set,
    }
}

/// Length of the longest increasing subsequence.
fn lis(v: &[usize]) -> usize {
    let mut tails: Vec<usize> = Vec::new();
    for &x in v {
        let i = tails.partition_point(|&t| t < x);
        if i == tails.len() {
            tails.push(x);
        } else {
            tails[i] = x;
        }
    }
    tails.len()
}

/// Every pair of runs on different days whose target sequences match, earliest
/// pair first.
pub fn reruns(runs: &[TargetRun], opt: &RecurrenceOptions) -> Vec<Rerun> {
    reruns_apart(runs, opt, |_, _| false, |i| i)
}

/// As [`reruns`], without comparing the pairs `skip` names (by index into
/// `runs`), and counting walkers by `walker` (one per distinct value; a
/// cluster's runs are one walker). Skipped runs still count towards every
/// host's weight and as walkers.
fn reruns_apart(
    runs: &[TargetRun],
    opt: &RecurrenceOptions,
    skip: impl Fn(usize, usize) -> bool,
    walker: impl Fn(usize) -> usize,
) -> Vec<Rerun> {
    let seqs: Vec<Seq> = runs.iter().map(seq).collect();
    let n = seqs.iter().filter(|s| !s.hosts.is_empty()).count();
    let mut df: BTreeMap<&str, usize> = BTreeMap::new();
    for s in &seqs {
        for h in &s.set {
            *df.entry(h.as_str()).or_default() += 1;
        }
    }
    // Smoothed IDF: a host in every run still weighs ln 2, a host in one run
    // weighs ln(1 + n).
    let w = |h: &str| (1.0 + n as f64 / df.get(h).copied().unwrap_or(1) as f64).ln();

    let mut order: Vec<usize> = (0..seqs.len())
        .filter(|&i| seqs[i].hosts.len() >= opt.min_shared.max(1))
        .collect();
    crate::sort::by_key(&mut order, |&i| (seqs[i].start, i));

    // Only runs sharing `min_shared` hosts are compared.
    let sets: Vec<Vec<&str>> = order
        .iter()
        .map(|&i| seqs[i].set.iter().map(String::as_str).collect())
        .collect();
    let counts = crate::dialect::SharedCounts::new(&sets);
    // The runs holding each host, for counting a list's walkers.
    let mut holders: BTreeMap<&str, Vec<usize>> = BTreeMap::new();
    for (r, s) in seqs.iter().enumerate() {
        for h in &s.set {
            holders.entry(h.as_str()).or_default().push(r);
        }
    }
    let mut out = Vec::new();
    for (k, &i) in order.iter().enumerate() {
        let later: Vec<usize> = if opt.min_shared == 0 {
            (k + 1..order.len()).collect()
        } else {
            counts
                .later(k, opt.min_shared)
                .into_iter()
                .map(|(kj, _)| kj)
                .collect()
        };
        for kj in later {
            let j = order[kj];
            if skip(i, j) {
                continue;
            }
            let (a, b) = (&seqs[i], &seqs[j]);
            if a.start.div_euclid(DAY) == b.start.div_euclid(DAY)
                || b.start - a.end < opt.min_gap_secs
            {
                continue;
            }
            let shared: Vec<&String> = a.hosts.iter().filter(|h| b.set.contains(*h)).collect();
            if shared.len() < opt.min_shared {
                continue;
            }
            let union = a.set.union(&b.set).count();
            let jaccard = shared.len() as f64 / union as f64;
            let w_shared: f64 = shared.iter().map(|h| w(h)).sum();
            let w_union: f64 = a.set.union(&b.set).map(|h| w(h)).sum();
            let weighted_jaccard = if w_union > 0.0 {
                w_shared / w_union
            } else {
                0.0
            };
            if weighted_jaccard < opt.min_weighted_jaccard {
                continue;
            }
            // Shared hosts in the earlier run's order, ranked by position in the later run.
            let pos: BTreeMap<&str, usize> = b
                .hosts
                .iter()
                .filter(|h| a.set.contains(*h))
                .enumerate()
                .map(|(p, h)| (h.as_str(), p))
                .collect();
            let ranks: Vec<usize> = shared.iter().map(|h| pos[h.as_str()]).collect();
            let order_score = lis(&ranks) as f64 / shared.len() as f64;
            if order_score < opt.min_order {
                continue;
            }
            if opt.max_walkers > 0 {
                let need = opt.min_shared.max(shared.len().div_ceil(2));
                // A day less the gap: one operator's daily reruns fall
                // outside it, other walkers of a published list inside.
                let g = (DAY - opt.min_gap_secs).max(opt.min_gap_secs).max(0);
                let near = |s: &Seq, x: &Seq| s.start <= x.end + g && s.end >= x.start - g;
                // A walker holding `need` of the shared hosts holds one of
                // the first `len - need + 1`; counting stops past the limit.
                let mut walkers: BTreeSet<usize> = BTreeSet::new();
                let mut seen: BTreeSet<usize> = BTreeSet::new();
                'scan: for h in &shared[..shared.len() + 1 - need.min(shared.len())] {
                    for &r in holders.get(h.as_str()).into_iter().flatten() {
                        let s = &seqs[r];
                        if !seen.insert(r)
                            || !(near(s, a) || near(s, b))
                            || walkers.contains(&walker(r))
                            || shared.iter().filter(|h| s.set.contains(**h)).count() < need
                        {
                            continue;
                        }
                        walkers.insert(walker(r));
                        if walkers.len() > opt.max_walkers {
                            break 'scan;
                        }
                    }
                }
                if walkers.len() > opt.max_walkers {
                    continue;
                }
            }
            out.push(Rerun {
                earlier: i,
                later: j,
                shared: shared.into_iter().cloned().collect(),
                jaccard,
                weighted_jaccard,
                order: order_score,
            });
        }
    }
    out
}

/// One run of a cluster (a stretch with no long gap), as
/// [`cluster_reruns`] sees it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ClusterRun {
    /// The cluster's number and key.
    pub cluster: String,
    pub key: String,
    pub start: i64,
    pub records: usize,
    /// Whether the run holds a record in the caller's new set.
    pub new: bool,
}

/// Runs in the analysis whose target sequence repeats an earlier run in a
/// different cluster, where the later run has a record in `new_ids`. The
/// matches index into the returned runs.
pub fn cluster_reruns(a: &Analysis, new_ids: &BTreeSet<String>) -> (Vec<ClusterRun>, Vec<Rerun>) {
    let (infos, matches) = reruns_across(&a.clusters, &a.results, new_ids);
    let matches = matches.into_iter().filter(|m| infos[m.later].new).collect();
    (infos, matches)
}

/// Every run of `clusters` (over `results`) whose target sequence repeats an
/// earlier run in a different cluster. `new` marks runs holding a record in
/// `new_ids`; nothing is filtered on it.
pub(crate) fn reruns_across(
    clusters: &[Cluster],
    results: &[ObsResult],
    new_ids: &BTreeSet<String>,
) -> (Vec<ClusterRun>, Vec<Rerun>) {
    let mut infos = Vec::new();
    let mut runs = Vec::new();
    let mut walker = Vec::new();
    for (ci, c) in clusters.iter().enumerate() {
        for (n, span) in c.runs.iter().enumerate() {
            let members: Vec<&ObsResult> = c
                .members
                .iter()
                .map(|&m| &results[m])
                .filter(|r| r.obs.ts >= span.start && r.obs.ts <= span.end)
                .collect();
            runs.push(TargetRun {
                key: format!("{}#{}", c.id, n + 1),
                targets: members
                    .iter()
                    .filter_map(|r| Some((r.obs.ts, r.target_host.clone()?)))
                    .collect(),
            });
            walker.push(ci);
            infos.push(ClusterRun {
                cluster: c.id.clone(),
                key: c.key.clone(),
                start: span.start,
                records: members.len(),
                new: members.iter().any(|r| new_ids.contains(&r.obs.id)),
            });
        }
    }
    let matches = reruns_apart(
        &runs,
        &RecurrenceOptions::default(),
        |i, j| infos[i].cluster == infos[j].cluster,
        |i| walker[i],
    );
    (infos, matches)
}

#[cfg(test)]
mod tests {
    use super::*;

    const T0: i64 = 1_791_000_000;

    fn run(key: &str, start: i64, hosts: &[&str]) -> TargetRun {
        TargetRun {
            key: key.into(),
            targets: hosts
                .iter()
                .enumerate()
                .map(|(i, h)| (start + i as i64 * 40, h.to_string()))
                .collect(),
        }
    }

    const HOSTS: [&str; 8] = [
        "a.example",
        "b.example",
        "c.example",
        "d.example",
        "e.example",
        "f.example",
        "g.example",
        "h.example",
    ];

    #[test]
    fn rerun_on_another_day_matches() {
        let mut later: Vec<&str> = HOSTS.to_vec();
        later.swap(3, 4); // roughly the same order
        later.push("z.example");
        let runs = [
            run("r1", T0, &HOSTS),
            run(
                "other",
                T0 + DAY / 2,
                &["x.example", "y.example", "q.example", "w.example"],
            ),
            run("r2", T0 + 3 * DAY, &later),
        ];
        let m = reruns(&runs, &RecurrenceOptions::default());
        assert_eq!(m.len(), 1, "{m:?}");
        assert_eq!((m[0].earlier, m[0].later), (0, 2));
        assert_eq!(m[0].shared.len(), 8);
        assert!(m[0].order >= 0.85 && m[0].order < 1.0, "{m:?}");
    }

    #[test]
    fn a_list_many_walk_is_no_ones_rerun() {
        // Five agents walk one published list in one order within an hour
        // of each other, and five more two days later.
        let runs: Vec<TargetRun> = (0..10)
            .map(|k| {
                let day = if k < 5 { 0 } else { 2 * DAY };
                run(&format!("r{k}"), T0 + day + (k % 5) * 600, &HOSTS)
            })
            .collect();
        assert!(reruns(&runs, &RecurrenceOptions::default()).is_empty());
        let all = RecurrenceOptions {
            max_walkers: 0,
            ..Default::default()
        };
        assert_eq!(reruns(&runs, &all).len(), 25);
        // Three walkers at once are still one operator's run and its rerun.
        let few: Vec<TargetRun> = [0, 1, 5].iter().map(|&k| runs[k].clone()).collect();
        assert_eq!(reruns(&few, &RecurrenceOptions::default()).len(), 2);
    }

    #[test]
    fn one_operators_daily_reruns_all_match() {
        // One task rerun every day for a week, a new tag (a new cluster)
        // each day: one walker at a time, however many days.
        let runs: Vec<TargetRun> = (0..7)
            .map(|d| run(&format!("r{d}"), T0 + d * DAY, &HOSTS))
            .collect();
        assert_eq!(reruns(&runs, &RecurrenceOptions::default()).len(), 21);
    }

    #[test]
    fn shuffled_order_does_not_match() {
        let shuffled: Vec<&str> = [5, 2, 7, 0, 3, 6, 1, 4].iter().map(|&i| HOSTS[i]).collect();
        let runs = [run("r1", T0, &HOSTS), run("r2", T0 + 2 * DAY, &shuffled)];
        assert!(reruns(&runs, &RecurrenceOptions::default()).is_empty());
    }

    #[test]
    fn popular_hosts_alone_do_not_match() {
        let popular = [
            "p1.example",
            "p2.example",
            "p3.example",
            "p4.example",
            "p5.example",
        ];
        let runs: Vec<TargetRun> = (0..6)
            .map(|i| {
                let own1 = format!("own{i}a.example");
                let own2 = format!("own{i}b.example");
                let mut hosts: Vec<&str> = popular.to_vec();
                hosts.push(&own1);
                hosts.push(&own2);
                run(&format!("r{i}"), T0 + i * DAY, &hosts)
            })
            .collect();
        // Plain Jaccard alone (5 of 9) would pass; the IDF weighting does not.
        assert!(reruns(&runs, &RecurrenceOptions::default()).is_empty());
    }

    #[test]
    fn same_day_does_not_match() {
        let runs = [run("r1", T0, &HOSTS), run("r2", T0 + 3 * 3600, &HOSTS)];
        assert!(reruns(&runs, &RecurrenceOptions::default()).is_empty());
    }

    #[test]
    fn too_few_shared_hosts() {
        let runs = [run("r1", T0, &HOSTS[..3]), run("r2", T0 + DAY, &HOSTS[..3])];
        assert!(reruns(&runs, &RecurrenceOptions::default()).is_empty());
    }

    #[test]
    fn cluster_runs_rerun_in_another_cluster() {
        let rules = crate::Rules::default_rules();
        let run = |tag: &str, start: i64| -> Vec<crate::Observation> {
            ["a", "b", "c", "d", "e", "f"]
                .iter()
                .enumerate()
                .map(|(i, h)| crate::Observation {
                    id: format!("{tag}-{i}"),
                    ts: start + i as i64 * 40,
                    url: format!(
                        "https://r.jina.ai/https://{h}.portal.example/q?id=1'%20OR%201=1--&uqtag={tag}"
                    ),
                    ..Default::default()
                })
                .collect()
        };
        let mut obs = run("first7", 1_791_000_000);
        obs.extend(run("second9", 1_791_000_000 + 3 * DAY));
        let a = crate::analyze(obs, &rules);
        let new_ids: BTreeSet<String> = (0..6).map(|i| format!("second9-{i}")).collect();
        let (runs, matches) = cluster_reruns(&a, &new_ids);
        assert_eq!(matches.len(), 1, "{matches:?}");
        let (e, l) = (&runs[matches[0].earlier], &runs[matches[0].later]);
        assert!(l.new && !e.new);
        assert_ne!(e.cluster, l.cluster);
        assert!(l.key.starts_with("k-"));
        assert_eq!(matches[0].shared.len(), 6);
        assert!(cluster_reruns(&a, &BTreeSet::new()).1.is_empty());
    }

    /// Every later run compared with every earlier one, as before the host
    /// index.
    fn every_pair(runs: &[TargetRun], opt: &RecurrenceOptions) -> Vec<Rerun> {
        let seqs: Vec<Seq> = runs.iter().map(seq).collect();
        let n = seqs.iter().filter(|s| !s.hosts.is_empty()).count();
        let mut df: BTreeMap<&str, usize> = BTreeMap::new();
        for s in &seqs {
            for h in &s.set {
                *df.entry(h.as_str()).or_default() += 1;
            }
        }
        let w = |h: &str| (1.0 + n as f64 / df.get(h).copied().unwrap_or(1) as f64).ln();
        let mut order: Vec<usize> = (0..seqs.len())
            .filter(|&i| seqs[i].hosts.len() >= opt.min_shared.max(1))
            .collect();
        crate::sort::by_key(&mut order, |&i| (seqs[i].start, i));
        let mut out = Vec::new();
        for (k, &i) in order.iter().enumerate() {
            for &j in &order[k + 1..] {
                let (a, b) = (&seqs[i], &seqs[j]);
                if a.start.div_euclid(DAY) == b.start.div_euclid(DAY)
                    || b.start - a.end < opt.min_gap_secs
                {
                    continue;
                }
                let shared: Vec<&String> = a.hosts.iter().filter(|h| b.set.contains(*h)).collect();
                if shared.len() < opt.min_shared {
                    continue;
                }
                let union = a.set.union(&b.set).count();
                let jaccard = shared.len() as f64 / union as f64;
                let w_shared: f64 = shared.iter().map(|h| w(h)).sum();
                let w_union: f64 = a.set.union(&b.set).map(|h| w(h)).sum();
                let weighted_jaccard = if w_union > 0.0 {
                    w_shared / w_union
                } else {
                    0.0
                };
                if weighted_jaccard < opt.min_weighted_jaccard {
                    continue;
                }
                let pos: BTreeMap<&str, usize> = b
                    .hosts
                    .iter()
                    .filter(|h| a.set.contains(*h))
                    .enumerate()
                    .map(|(p, h)| (h.as_str(), p))
                    .collect();
                let ranks: Vec<usize> = shared.iter().map(|h| pos[h.as_str()]).collect();
                let order_score = lis(&ranks) as f64 / shared.len() as f64;
                if order_score < opt.min_order {
                    continue;
                }
                out.push(Rerun {
                    earlier: i,
                    later: j,
                    shared: shared.into_iter().cloned().collect(),
                    jaccard,
                    weighted_jaccard,
                    order: order_score,
                });
            }
        }
        out
    }

    #[test]
    fn the_host_index_finds_what_comparing_every_pair_finds() {
        let mut seed: u64 = 5;
        let mut next = |m: u64| {
            seed = seed
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            (seed >> 33) % m
        };
        let pool: Vec<String> = (0..30).map(|i| format!("h{i}.example")).collect();
        let runs: Vec<TargetRun> = (0..120)
            .map(|k| {
                let start = T0 + next(20) as i64 * DAY + next(3600) as i64;
                let base = next(25) as usize;
                let hosts: Vec<&str> = (0..next(9) as usize)
                    .map(|i| {
                        if next(4) == 0 {
                            pool[next(30) as usize].as_str()
                        } else {
                            pool[(base + i) % 30].as_str()
                        }
                    })
                    .collect();
                run(&format!("r{k}"), start, &hosts)
            })
            .collect();
        for min_shared in [0, 1, 4] {
            let opt = RecurrenceOptions {
                min_shared,
                max_walkers: 0,
                ..Default::default()
            };
            let want = every_pair(&runs, &opt);
            assert_eq!(reruns(&runs, &opt), want, "min_shared {min_shared}");
            if min_shared == 4 {
                assert!(want.len() > 5, "{}", want.len());
            }
            // Skipping pairs drops exactly those pairs.
            let skip = |i: usize, j: usize| (i + j).is_multiple_of(3);
            let kept: Vec<Rerun> = want
                .into_iter()
                .filter(|m| !skip(m.earlier, m.later))
                .collect();
            assert_eq!(reruns_apart(&runs, &opt, skip, |i| i), kept);
        }
    }
}
