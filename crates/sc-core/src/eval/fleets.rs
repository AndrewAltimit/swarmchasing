//! Fleet proposals against records labelled with their true fleet (`fleet`
//! in the label): how often a soft link, or a candidate fleet, pairs two
//! clusters one operator really runs.
//!
//! A cluster's fleet is the most common `fleet` among its labelled members.
//! `none` marks a cluster known to be its own operator's only one, so any
//! pair touching it is wrong. A proposed pair counts only when both clusters
//! carry a fleet. Precision is per soft-link kind, over all soft links, and
//! over the pairs inside candidate fleets; recall is against every pair of
//! labelled clusters sharing a fleet.
//!
//! Report only: no gate reads these numbers. The committed fleets are
//! synthetic and few.

use super::LabelSet;
use crate::analyze::Analysis;
use crate::fleets::SoftLinkKind;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FleetEval {
    /// Clusters with a fleet label.
    pub labelled_clusters: usize,
    /// Fleets other than `none` with two or more labelled clusters.
    pub fleets: usize,
    /// Pairs of labelled clusters in one fleet.
    pub true_pairs: usize,
    /// One row per soft-link kind seen, then `all soft links` and
    /// `candidate fleets`.
    pub rows: Vec<FleetRow>,
}

impl FleetEval {
    pub fn is_empty(&self) -> bool {
        self.labelled_clusters == 0
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FleetRow {
    pub name: String,
    /// Distinct cluster pairs proposed with both clusters labelled.
    pub proposed: usize,
    pub correct: usize,
    pub precision: Option<f64>,
    #[serde(default)]
    pub precision_ci: Option<(f64, f64)>,
    pub recall: Option<f64>,
    /// Wrong pairs as `C3 (fleet-a) ↔ C5 (fleet-b)`, a few.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub wrong: Vec<String>,
}

pub fn fleet_eval(a: &Analysis, labels: &LabelSet) -> FleetEval {
    let mut fleet: BTreeMap<&str, String> = BTreeMap::new();
    for c in &a.clusters {
        let mut votes: BTreeMap<&str, usize> = BTreeMap::new();
        for &m in &c.members {
            if let Some(f) = labels
                .labels
                .get(&a.results[m].obs.id)
                .and_then(|l| l.fleet.as_deref())
            {
                *votes.entry(f).or_default() += 1;
            }
        }
        // Most votes; ties go to the first name.
        let best = votes
            .iter()
            .fold(None::<(&str, usize)>, |best, (&f, &n)| match best {
                Some((_, b)) if b >= n => best,
                _ => Some((f, n)),
            });
        if let Some((f, _)) = best {
            fleet.insert(&c.id, f.to_string());
        }
    }
    let mut out = FleetEval {
        labelled_clusters: fleet.len(),
        ..Default::default()
    };
    if fleet.is_empty() {
        return out;
    }
    let mut sizes: BTreeMap<&str, usize> = BTreeMap::new();
    for f in fleet.values().filter(|f| *f != "none") {
        *sizes.entry(f.as_str()).or_default() += 1;
    }
    out.fleets = sizes.values().filter(|&&n| n >= 2).count();
    out.true_pairs = sizes.values().map(|&n| n * (n - 1) / 2).sum();

    let key = |x: &str, y: &str| -> (String, String) {
        if x <= y {
            (x.to_string(), y.to_string())
        } else {
            (y.to_string(), x.to_string())
        }
    };
    let mut by_kind: BTreeMap<SoftLinkKind, BTreeSet<(String, String)>> = BTreeMap::new();
    for l in &a.soft_links {
        by_kind.entry(l.kind).or_default().insert(key(&l.a, &l.b));
    }
    let all: BTreeSet<(String, String)> = by_kind.values().flatten().cloned().collect();
    let mut in_fleets: BTreeSet<(String, String)> = BTreeSet::new();
    for f in &a.candidate_fleets {
        for (i, x) in f.clusters.iter().enumerate() {
            for y in &f.clusters[i + 1..] {
                in_fleets.insert(key(x, y));
            }
        }
    }
    let row = |name: &str, pairs: &BTreeSet<(String, String)>| -> FleetRow {
        let mut r = FleetRow {
            name: name.to_string(),
            ..Default::default()
        };
        for (x, y) in pairs {
            let (Some(fx), Some(fy)) = (fleet.get(x.as_str()), fleet.get(y.as_str())) else {
                continue;
            };
            r.proposed += 1;
            if fx == fy && fx != "none" {
                r.correct += 1;
            } else if r.wrong.len() < 5 {
                r.wrong.push(format!("{x} ({fx}) ↔ {y} ({fy})"));
            }
        }
        r.precision = (r.proposed > 0).then(|| r.correct as f64 / r.proposed as f64);
        r.precision_ci = super::stats::wilson(r.correct, r.proposed);
        r.recall = (out.true_pairs > 0).then(|| r.correct as f64 / out.true_pairs as f64);
        r
    };
    let mut rows: Vec<FleetRow> = by_kind
        .iter()
        .map(|(k, pairs)| row(k.label(), pairs))
        .filter(|r| r.proposed > 0)
        .collect();
    rows.push(row("all soft links", &all));
    rows.push(row("candidate fleets", &in_fleets));
    out.rows = rows;
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fleets::{CandidateFleet, SoftLink};
    use crate::parse_labels;

    fn link(a: &str, b: &str, kind: SoftLinkKind) -> SoftLink {
        SoftLink {
            a: a.into(),
            b: b.into(),
            kind,
            strength: 0.5,
            lr: 2.0,
            detail: String::new(),
        }
    }

    #[test]
    fn pairs_are_scored_against_fleet_labels() {
        let mut a = Analysis::default();
        for (i, id) in ["C1", "C2", "C3", "C4"].iter().enumerate() {
            a.results.push(crate::analyze::ObsResult {
                obs: crate::Observation {
                    id: format!("r{i}"),
                    ..Default::default()
                },
                score: 1,
                tier: crate::Tier::Significant,
                hits: Vec::new(),
                layers: Vec::new(),
                target_host: None,
                features: Vec::new(),
                cluster: Some(i),
                agent: None,
            });
            a.clusters.push(crate::Cluster {
                id: id.to_string(),
                members: vec![i],
                ..Default::default()
            });
        }
        a.soft_links = vec![
            link("C1", "C2", SoftLinkKind::Scaffold),
            link("C1", "C3", SoftLinkKind::Scaffold),
            link("C2", "C4", SoftLinkKind::CoActivity),
        ];
        a.candidate_fleets = vec![CandidateFleet {
            id: "F1".into(),
            clusters: vec!["C1".into(), "C2".into()],
            kinds: vec![SoftLinkKind::Scaffold],
            links: 1,
            strength: 0.5,
            ..Default::default()
        }];
        let labels = parse_labels(
            "{\"id\":\"r0\",\"label\":\"agent\",\"fleet\":\"f1\"}\n\
             {\"id\":\"r1\",\"label\":\"agent\",\"fleet\":\"f1\"}\n\
             {\"id\":\"r2\",\"label\":\"agent\",\"fleet\":\"none\"}\n",
        );
        let e = fleet_eval(&a, &labels);
        assert_eq!((e.labelled_clusters, e.fleets, e.true_pairs), (3, 1, 1));
        let scaffold = &e.rows[0];
        assert_eq!(scaffold.name, "shared scaffold");
        assert_eq!((scaffold.proposed, scaffold.correct), (2, 1));
        assert_eq!(scaffold.wrong, ["C1 (f1) ↔ C3 (none)"]);
        // C4 carries no fleet: its pair is not counted.
        assert!(e.rows.iter().all(|r| r.name != "co-activity"));
        let fleets = e
            .rows
            .iter()
            .find(|r| r.name == "candidate fleets")
            .unwrap();
        assert_eq!((fleets.proposed, fleets.correct), (1, 1));
        assert_eq!(fleets.recall, Some(1.0));
    }
}
