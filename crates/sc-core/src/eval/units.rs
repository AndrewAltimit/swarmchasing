//! What is counted, and over which records.
//!
//! - **Record unit**: every labelled record counts once. A cluster of ten
//!   flagged records counts ten times.
//! - **Cluster unit**: every predicted group counts once. A group is a
//!   cluster (over its labelled members) or a labelled record in none. It is
//!   flagged at a tier when its tier (the cluster's, or the record's) is at
//!   or above it. A group whose labelled members are all agent is a true
//!   positive when flagged and a false negative when not; all benign, a false
//!   positive or a true negative. A group that mixes agent and benign members
//!   is counted wrong either way: a false positive when flagged (reporting it
//!   misattributes the benign members) and a false negative when not.
//! - **Slices**: the same counts over a subset of the labelled records (the
//!   non-synthetic ones, one file, one source, one provenance).
//! - **Calibration**: the share of labelled records that are agents, per
//!   record tier and per agent grade, with its interval. It shows what a tier
//!   or a grade is worth as evidence on this set.

use super::grades::COLUMNS;
use super::stats::Proportion;
use super::summary::TierSummary;
use super::{Label, LabelSet, Labelled, view};
use crate::analyze::Analysis;
use crate::model::Tier;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};

/// The thresholds every table reports: suggestive or above, significant.
pub const THRESHOLDS: [Tier; 2] = [Tier::Suggestive, Tier::Significant];

/// Every labelled record once (its first occurrence), as (index into
/// `Analysis::results`, its label).
pub fn labelled<'a>(a: &'a Analysis, labels: &'a LabelSet) -> Vec<(usize, &'a Labelled)> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for (i, r) in a.results.iter().enumerate() {
        if let Some(l) = labels.labels.get(&r.obs.id)
            && seen.insert(r.obs.id.as_str())
        {
            out.push((i, l));
        }
    }
    out
}

/// Record-unit counts at each threshold over `(is_agent, tier)` items.
pub fn record_tiers(items: impl IntoIterator<Item = (bool, Tier)>) -> Vec<TierSummary> {
    let mut c = [[0usize; 4]; 2];
    for (agent, tier) in items {
        for (k, t) in THRESHOLDS.iter().enumerate() {
            let slot = match (tier >= *t, agent) {
                (true, true) => 0,
                (true, false) => 1,
                (false, true) => 2,
                (false, false) => 3,
            };
            c[k][slot] += 1;
        }
    }
    THRESHOLDS
        .iter()
        .zip(c)
        .map(|(t, [tp, fp, fn_, tn])| TierSummary::from_counts(*t, tp, fp, fn_, tn))
        .collect()
}

/// Cluster-unit counts at each threshold. Each item is `(group, is_agent,
/// tier)`: items sharing a `Some` group are one unit, whose tier is the
/// highest given; a `None` group is a unit of its own.
pub fn unit_tiers<K: Ord>(
    items: impl IntoIterator<Item = (Option<K>, bool, Tier)>,
) -> Vec<TierSummary> {
    // (has agent, has benign, tier)
    let mut groups: BTreeMap<K, (bool, bool, Tier)> = BTreeMap::new();
    let mut units: Vec<(bool, bool, Tier)> = Vec::new();
    for (g, agent, tier) in items {
        match g {
            Some(k) => {
                let e = groups.entry(k).or_insert((false, false, tier));
                e.0 |= agent;
                e.1 |= !agent;
                if tier > e.2 {
                    e.2 = tier;
                }
            }
            None => units.push((agent, !agent, tier)),
        }
    }
    units.extend(groups.into_values());
    let mut c = [[0usize; 4]; 2];
    for (has_agent, has_benign, tier) in units {
        for (k, t) in THRESHOLDS.iter().enumerate() {
            let flagged = tier >= *t;
            let slot = match (flagged, has_agent, has_benign) {
                (true, true, false) => 0,
                (true, _, _) => 1,
                (false, true, _) => 2,
                (false, false, _) => 3,
            };
            c[k][slot] += 1;
        }
    }
    THRESHOLDS
        .iter()
        .zip(c)
        .map(|(t, [tp, fp, fn_, tn])| TierSummary::from_counts(*t, tp, fp, fn_, tn))
        .collect()
}

/// The numbers over one subset of the labelled records.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Slice {
    pub name: String,
    pub labelled: usize,
    pub agents: usize,
    pub benign: usize,
    /// Record unit.
    pub tiers: Vec<TierSummary>,
    /// Cluster unit.
    pub cluster_tiers: Vec<TierSummary>,
}

/// The slice over `items`.
pub fn slice(a: &Analysis, items: &[(usize, &Labelled)], name: &str) -> Slice {
    let agent = |l: &Labelled| l.label == Label::Agent;
    let agents = items.iter().filter(|(_, l)| agent(l)).count();
    Slice {
        name: name.to_string(),
        labelled: items.len(),
        agents,
        benign: items.len() - agents,
        tiers: record_tiers(items.iter().map(|(i, l)| (agent(l), a.results[*i].tier))),
        cluster_tiers: unit_tiers(items.iter().map(|(i, l)| {
            let r = &a.results[*i];
            match r.cluster {
                Some(c) => (Some(c), agent(l), view::cluster_tier(a, c)),
                None => (None, agent(l), r.tier),
            }
        })),
    }
}

/// One slice per value of `key`, in key order; items with no key are left
/// out.
pub fn breakdown(
    a: &Analysis,
    items: &[(usize, &Labelled)],
    key: impl Fn(usize, &Labelled) -> Option<String>,
) -> Vec<Slice> {
    let mut by: BTreeMap<String, Vec<(usize, &Labelled)>> = BTreeMap::new();
    for &(i, l) in items {
        if let Some(k) = key(i, l) {
            by.entry(k).or_default().push((i, l));
        }
    }
    by.iter().map(|(k, v)| slice(a, v, k)).collect()
}

/// One row of the calibration table: of the `precision.n` labelled records
/// in the row, `precision.k` are agents.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CalibrationRow {
    pub name: String,
    pub precision: Proportion,
}

/// Observed precision per record tier and per agent grade.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Calibration {
    /// `noise`, `suggestive`, `significant`: records at exactly that tier.
    pub by_tier: Vec<CalibrationRow>,
    /// The grade columns (`unflagged`, `unclustered`, `L0`..`L4`), records
    /// graded by their cluster.
    pub by_agent_level: Vec<CalibrationRow>,
}

pub fn calibration(a: &Analysis, items: &[(usize, &Labelled)]) -> Calibration {
    let rows = |names: &[&str], key: &dyn Fn(usize) -> String| -> Vec<CalibrationRow> {
        let mut count: BTreeMap<String, (usize, usize)> = BTreeMap::new();
        for &(i, l) in items {
            let e = count.entry(key(i)).or_default();
            e.0 += usize::from(l.label == Label::Agent);
            e.1 += 1;
        }
        names
            .iter()
            .filter_map(|n| {
                count.get(*n).map(|&(k, n_)| CalibrationRow {
                    name: n.to_string(),
                    precision: Proportion::new(k, n_),
                })
            })
            .collect()
    };
    let tiers = [Tier::Noise, Tier::Suggestive, Tier::Significant].map(|t| t.label());
    Calibration {
        by_tier: rows(&tiers, &|i| a.results[i].tier.label().to_string()),
        by_agent_level: rows(&COLUMNS, &|i| view::grade_column(a, i).to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_cluster_counts_once_and_a_mixed_one_is_wrong_either_way() {
        let s = Tier::Significant;
        let n = Tier::Noise;
        // Cluster 1: ten agent records, flagged. Cluster 2: agent + benign,
        // flagged. Cluster 3: agent + benign, unflagged. One benign single,
        // unflagged; one agent single, unflagged.
        let mut items: Vec<(Option<u8>, bool, Tier)> = vec![(Some(1), true, s); 10];
        items.extend([
            (Some(2), true, s),
            (Some(2), false, s),
            (Some(3), true, n),
            (Some(3), false, n),
            (None, false, n),
            (None, true, n),
        ]);
        let t = unit_tiers(items.clone());
        let sig = &t[1];
        assert_eq!((sig.tp, sig.fp, sig.fn_, sig.tn), (1, 1, 2, 1));
        let r = record_tiers(items.iter().map(|(_, a, t)| (*a, *t)));
        assert_eq!((r[1].tp, r[1].fp, r[1].fn_, r[1].tn), (11, 1, 2, 2));
    }
}
