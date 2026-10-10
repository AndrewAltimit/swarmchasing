//! Cluster-level evaluation: how well linking groups records, against
//! records labelled with their true run (`run` in the label).
//!
//! - **B-cubed** precision, recall and F1 (Bagga and Baldwin 1998), over the
//!   run-labelled records only. Each record's predicted group is its cluster,
//!   or the record alone when it is in none. Precision is the share of the
//!   record's predicted group (its run-labelled members) that shares its run;
//!   recall the share of its run inside its predicted group. Both are averaged
//!   over records.
//! - **False merges**: clusters whose labelled members span two or more runs,
//!   or mix agent and benign records. This is the error that misattributes.
//! - **False splits**: runs whose records sit in more than one predicted group.
//!
//! Report only: no gate reads these numbers.

use super::{Label, LabelSet};
use crate::analyze::Analysis;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashSet};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ClusterEval {
    /// Labelled records that carry a run.
    pub run_labelled: usize,
    pub runs: usize,
    pub bcubed_precision: Option<f64>,
    pub bcubed_recall: Option<f64>,
    pub bcubed_f1: Option<f64>,
    /// Clusters with at least one labelled member.
    pub clusters_checked: usize,
    pub false_merges: Vec<FalseMerge>,
    /// `false_merges.len() / clusters_checked`.
    pub false_merge_rate: Option<f64>,
    /// Runs spread over more than one predicted group.
    pub false_splits: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FalseMerge {
    /// The cluster's stable key.
    pub cluster: String,
    pub members: usize,
    /// The labelled runs it spans.
    pub runs: Vec<String>,
    /// It holds both agent and benign records.
    pub mixes_labels: bool,
}

pub fn cluster_eval(a: &Analysis, labels: &LabelSet) -> ClusterEval {
    // First occurrence of each labelled record: (result index, run, label).
    let mut seen = HashSet::new();
    let mut recs: Vec<(usize, Option<&str>, Label)> = Vec::new();
    for (i, r) in a.results.iter().enumerate() {
        let Some(l) = labels.labels.get(&r.obs.id) else {
            continue;
        };
        if seen.insert(r.obs.id.as_str()) {
            recs.push((i, l.run.as_deref(), l.label));
        }
    }
    // Predicted group: the cluster, or a singleton keyed by the record.
    let group = |i: usize| -> (bool, usize) {
        match a.results[i].cluster {
            Some(c) => (true, c),
            None => (false, i),
        }
    };

    let mut out = ClusterEval::default();
    let run_recs: Vec<(usize, &str)> = recs
        .iter()
        .filter_map(|&(i, run, _)| run.map(|r| (i, r)))
        .collect();
    out.run_labelled = run_recs.len();
    let mut run_size: BTreeMap<&str, usize> = BTreeMap::new();
    let mut group_runs: BTreeMap<(bool, usize), Vec<&str>> = BTreeMap::new();
    for &(i, run) in &run_recs {
        *run_size.entry(run).or_default() += 1;
        group_runs.entry(group(i)).or_default().push(run);
    }
    out.runs = run_size.len();
    if !run_recs.is_empty() {
        let (mut p, mut r) = (0.0, 0.0);
        for &(i, run) in &run_recs {
            let g = &group_runs[&group(i)];
            let same = g.iter().filter(|x| **x == run).count() as f64;
            p += same / g.len() as f64;
            r += same / run_size[run] as f64;
        }
        let n = run_recs.len() as f64;
        let (p, r) = (p / n, r / n);
        out.bcubed_precision = Some(p);
        out.bcubed_recall = Some(r);
        out.bcubed_f1 = Some(if p + r > 0.0 {
            2.0 * p * r / (p + r)
        } else {
            0.0
        });
    }
    let mut run_groups: BTreeMap<&str, BTreeSet<(bool, usize)>> = BTreeMap::new();
    for &(i, run) in &run_recs {
        run_groups.entry(run).or_default().insert(group(i));
    }
    out.false_splits = run_groups
        .into_iter()
        .filter(|(_, g)| g.len() > 1)
        .map(|(r, _)| r.to_string())
        .collect();

    // False merges, over real clusters only.
    let mut by_cluster: BTreeMap<usize, (BTreeSet<&str>, BTreeSet<Label>)> = BTreeMap::new();
    for &(i, run, label) in &recs {
        if let Some(c) = a.results[i].cluster {
            let e = by_cluster.entry(c).or_default();
            if let Some(run) = run {
                e.0.insert(run);
            }
            e.1.insert(label);
        }
    }
    out.clusters_checked = by_cluster.len();
    for (c, (runs, kinds)) in &by_cluster {
        let mixes_labels = kinds.len() > 1;
        if runs.len() > 1 || mixes_labels {
            let cl = &a.clusters[*c];
            out.false_merges.push(FalseMerge {
                cluster: cl.key.clone(),
                members: cl.members.len(),
                runs: runs.iter().map(|s| s.to_string()).collect(),
                mixes_labels,
            });
        }
    }
    out.false_merge_rate = (out.clusters_checked > 0)
        .then(|| out.false_merges.len() as f64 / out.clusters_checked as f64);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Observation, Rules, analyze, parse_labels};

    fn obs(id: &str, ts: i64, url: &str) -> Observation {
        Observation {
            id: id.into(),
            ts,
            url: url.into(),
            ..Default::default()
        }
    }

    #[test]
    fn bcubed_and_false_merges() {
        let records = vec![
            // Run A: two records sharing a tag -> one cluster.
            obs(
                "a1",
                1000,
                "https://r.jina.ai/https://t.example/x?uqtag=aa11",
            ),
            obs(
                "a2",
                1100,
                "https://r.jina.ai/https://t.example/y?uqtag=aa11",
            ),
            // Run A again, unflagged: a false split.
            obs("a3", 1200, "https://t.example/z"),
            // Runs B and C share a popular tag within the link window ->
            // merged: a false merge.
            obs("b1", 5000, "https://r.jina.ai/https://u.example/?tag=sale"),
            obs("c1", 6_000, "https://r.jina.ai/https://v.example/?tag=sale"),
        ];
        let a = analyze(records, &Rules::default_rules());
        let labels = parse_labels(
            "{\"id\":\"a1\",\"label\":\"agent\",\"run\":\"A\"}\n\
             {\"id\":\"a2\",\"label\":\"agent\",\"run\":\"A\"}\n\
             {\"id\":\"a3\",\"label\":\"agent\",\"run\":\"A\"}\n\
             {\"id\":\"b1\",\"label\":\"benign\",\"run\":\"B\"}\n\
             {\"id\":\"c1\",\"label\":\"benign\",\"run\":\"C\"}\n",
        );
        let e = cluster_eval(&a, &labels);
        assert_eq!((e.run_labelled, e.runs), (5, 3));
        // Precision: a1, a2 = 1; a3 = 1 (alone); b1, c1 = 1/2. Mean 0.8.
        assert!((e.bcubed_precision.unwrap() - 0.8).abs() < 1e-9);
        // Recall: a1, a2 = 2/3; a3 = 1/3; b1, c1 = 1. Mean 11/15.
        assert!((e.bcubed_recall.unwrap() - 11.0 / 15.0).abs() < 1e-9);
        assert_eq!(e.false_splits, ["A"]);
        assert_eq!(e.clusters_checked, 2);
        assert_eq!(e.false_merges.len(), 1);
        assert_eq!(e.false_merges[0].runs, ["B", "C"]);
        assert!(!e.false_merges[0].mixes_labels);
    }
}
