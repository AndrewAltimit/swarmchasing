//! Frozen held-out splits of a labelled set (field manual FM-9.3).
//!
//! - **Time**: the latest `fraction` of labelled records by timestamp is held
//!   out. A linked group (cluster or labelled run) with records on both
//!   sides of the cut is excluded from both, so every held-out record is
//!   later than every tuning record and no group straddles the split.
//! - **Cluster**: linked groups are shuffled with a seeded generator and
//!   taken whole until `fraction` of the records is held out.
//!
//! A group is the union of a record's predicted cluster and its labelled
//! `run`. The output is ids only; the caller writes it somewhere private and
//! never edits it after the first measurement.

use super::LabelSet;
use crate::analyze::Analysis;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SplitKind {
    Time,
    Cluster,
}

impl std::str::FromStr for SplitKind {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        match s {
            "time" => Ok(Self::Time),
            "cluster" => Ok(Self::Cluster),
            o => Err(format!("unknown split `{o}` (time | cluster)")),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Split {
    pub kind: SplitKind,
    pub seed: u64,
    pub fraction: f64,
    /// Held-out record ids, sorted.
    pub held_out: Vec<String>,
    /// Tuning record ids, sorted.
    pub tuning: Vec<String>,
    /// Ids left out of both sides (time split: groups straddling the cut).
    pub excluded: Vec<String>,
    /// Time split: the earliest held-out timestamp.
    pub cutoff_ts: Option<i64>,
}

/// SplitMix64: a small, stable generator, so a seed gives the same split on
/// every machine.
struct SplitMix(u64);
impl SplitMix {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
}

pub fn split(a: &Analysis, labels: &LabelSet, kind: SplitKind, seed: u64, fraction: f64) -> Split {
    let fraction = fraction.clamp(0.0, 1.0);
    // Labelled records, once each: (id, ts, cluster, run).
    let mut recs: Vec<(&str, i64, Option<usize>, Option<&str>)> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for r in &a.results {
        if let Some(l) = labels.labels.get(&r.obs.id)
            && seen.insert(r.obs.id.as_str())
        {
            recs.push((&r.obs.id, r.obs.ts, r.cluster, l.run.as_deref()));
        }
    }
    // Groups: union of cluster and run.
    let mut parent: Vec<usize> = (0..recs.len()).collect();
    fn find(p: &mut [usize], x: usize) -> usize {
        let mut r = x;
        while p[r] != r {
            r = p[r];
        }
        let mut x = x;
        while p[x] != r {
            let n = p[x];
            p[x] = r;
            x = n;
        }
        r
    }
    let mut by_cluster: HashMap<usize, usize> = HashMap::new();
    let mut by_run: HashMap<&str, usize> = HashMap::new();
    for (i, &(_, _, c, run)) in recs.iter().enumerate() {
        for first in [
            c.map(|c| *by_cluster.entry(c).or_insert(i)),
            run.map(|r| *by_run.entry(r).or_insert(i)),
        ]
        .into_iter()
        .flatten()
        {
            let (x, y) = (find(&mut parent, i), find(&mut parent, first));
            if x != y {
                parent[x.max(y)] = x.min(y);
            }
        }
    }
    let mut groups: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
    for i in 0..recs.len() {
        let g = find(&mut parent, i);
        groups.entry(g).or_default().push(i);
    }
    let target = (recs.len() as f64 * fraction).round() as usize;
    let mut held = vec![false; recs.len()];
    let mut excluded = vec![false; recs.len()];
    let mut cutoff_ts = None;
    match kind {
        SplitKind::Time => {
            let mut order: Vec<usize> = (0..recs.len()).collect();
            order.sort_by(|&x, &y| recs[x].1.cmp(&recs[y].1).then(recs[x].0.cmp(recs[y].0)));
            if target > 0 {
                let cut = recs[order[recs.len() - target]].1;
                cutoff_ts = Some(cut);
                for i in 0..recs.len() {
                    held[i] = recs[i].1 >= cut;
                }
                for members in groups.values() {
                    let h = members.iter().filter(|&&m| held[m]).count();
                    if h > 0 && h < members.len() {
                        for &m in members {
                            excluded[m] = true;
                            held[m] = false;
                        }
                    }
                }
            }
        }
        SplitKind::Cluster => {
            let mut rng = SplitMix(seed);
            let mut keyed: Vec<(u64, &Vec<usize>)> = groups
                .values()
                .map(|m| {
                    // Key on the group's smallest id, not its position, so the
                    // order does not depend on input order.
                    let id = m.iter().map(|&i| recs[i].0).min().unwrap_or("");
                    let h = id.bytes().fold(0xcbf2_9ce4_8422_2325u64, |h, b| {
                        (h ^ u64::from(b)).wrapping_mul(0x0000_0100_0000_01b3)
                    });
                    (h, m)
                })
                .collect();
            keyed.sort_by_key(|(h, _)| *h);
            // Fisher-Yates over the id-sorted groups.
            for i in (1..keyed.len()).rev() {
                let j = (rng.next() % (i as u64 + 1)) as usize;
                keyed.swap(i, j);
            }
            let mut n = 0;
            for (_, m) in keyed {
                if n >= target {
                    break;
                }
                for &i in m {
                    held[i] = true;
                }
                n += m.len();
            }
        }
    }
    let pick = |f: &dyn Fn(usize) -> bool| {
        let mut v: Vec<String> = (0..recs.len())
            .filter(|&i| f(i))
            .map(|i| recs[i].0.to_string())
            .collect();
        v.sort();
        v
    };
    Split {
        kind,
        seed,
        fraction,
        held_out: pick(&|i| held[i]),
        tuning: pick(&|i| !held[i] && !excluded[i]),
        excluded: pick(&|i| excluded[i]),
        cutoff_ts,
    }
}

/// Read an id list: one id per line, `#` comments and blank lines ignored.
pub fn parse_id_list(text: &str) -> Vec<String> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(str::to_string)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Observation, Rules, analyze, parse_labels};

    fn set() -> (Analysis, LabelSet) {
        let mut obs = Vec::new();
        let mut labels = String::new();
        for i in 0..20 {
            obs.push(Observation {
                id: format!("r{i}"),
                ts: 1000 + i * 100,
                url: format!("https://www.example.org/{i}"),
                ..Default::default()
            });
            // r9 and r15 share a run: a group across the time cut.
            let run = match i {
                9 | 15 => ",\"run\":\"x\"",
                _ => "",
            };
            labels.push_str(&format!("{{\"id\":\"r{i}\",\"label\":\"benign\"{run}}}\n"));
        }
        (analyze(obs, &Rules::default_rules()), parse_labels(&labels))
    }

    #[test]
    fn time_split_keeps_groups_on_one_side() {
        let (a, l) = set();
        let s = split(&a, &l, SplitKind::Time, 0, 0.25);
        // Latest 5: r15..r19; r15's run reaches r9, so both are excluded.
        assert_eq!(s.held_out, ["r16", "r17", "r18", "r19"]);
        assert_eq!(s.excluded, ["r15", "r9"]);
        assert_eq!(s.tuning.len(), 14);
        assert_eq!(s.cutoff_ts, Some(2500));
    }

    #[test]
    fn cluster_split_is_seeded_and_whole() {
        let (a, l) = set();
        let s1 = split(&a, &l, SplitKind::Cluster, 7, 0.3);
        let s2 = split(&a, &l, SplitKind::Cluster, 7, 0.3);
        assert_eq!(s1.held_out, s2.held_out);
        assert_eq!(
            s1.held_out.contains(&"r9".to_string()),
            s1.held_out.contains(&"r15".to_string())
        );
        assert_eq!(s1.held_out.len() + s1.tuning.len(), 20);
        assert!(s1.held_out.len() >= 6);
        let s3 = split(&a, &l, SplitKind::Cluster, 8, 0.3);
        assert_ne!(s1.held_out, s3.held_out, "another seed, another split");
    }

    #[test]
    fn id_list() {
        assert_eq!(parse_id_list("# h\n a \n\nb\n"), ["a", "b"]);
    }
}
