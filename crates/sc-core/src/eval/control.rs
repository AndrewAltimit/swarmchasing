//! The negative control: an analysis of records from before agents of the
//! kind looked for existed. No such record was sent by one, so every flag,
//! every agent grade above L1 and every plant signal on them is a false
//! alarm, and the rates need no labels.
//!
//! Each rate is a [`Proportion`] with its 95% Wilson interval. When nothing
//! fired, the upper bound is what the control can rule out; with `n` records
//! and none flagged it is close to the rule of three, `3 / n`.

use super::grades::COLUMNS;
use super::stats::Proportion;
use super::units::THRESHOLDS;
use super::view;
use crate::analyze::Analysis;
use crate::model::Tier;
use crate::plant::PlantSignalKind;
use crate::swarm::SwarmEdgeKind;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlSummary {
    /// Distinct records analysed.
    pub records: usize,
    pub clusters: usize,
    /// Records at or above each threshold, of all records.
    pub by_tier: Vec<ControlRow>,
    /// Records per grade column (`unflagged`, `unclustered`, `L0`..`L4`),
    /// of all records.
    pub by_agent_level: Vec<ControlRow>,
    /// Clusters graded L2 or above, of all clusters: the false grades.
    pub clusters_l2_or_above: Proportion,
    /// Clusters carrying each plant signal, of all clusters.
    pub plant_signals: Vec<ControlRow>,
    /// Records in a cluster graded above L0, of all records.
    #[serde(default = "empty")]
    pub records_above_l0: Proportion,
    /// Clusters graded above L0, of all clusters.
    #[serde(default = "empty")]
    pub clusters_above_l0: Proportion,
    /// Per rule that fired at least once: the records it fired on, and those
    /// of them flagged suggestive or above, of all records.
    #[serde(default)]
    pub by_rule: Vec<ControlRuleRow>,
    /// Interaction edges found, and per kind (`S1`..`S5`).
    #[serde(default)]
    pub swarm_edges: usize,
    #[serde(default)]
    pub swarm_edges_by_kind: Vec<ControlCount>,
}

fn empty() -> Proportion {
    Proportion::new(0, 0)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlRuleRow {
    pub rule_id: String,
    /// Records the rule fired on.
    pub fired: Proportion,
    /// Records the rule fired on that were flagged suggestive or above.
    pub flagged: Proportion,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlCount {
    pub name: String,
    pub count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlRow {
    pub name: String,
    pub rate: Proportion,
}

pub fn negative_control(a: &Analysis) -> ControlSummary {
    let mut seen = HashSet::new();
    let mut idx = Vec::new();
    for (i, r) in a.results.iter().enumerate() {
        if seen.insert(r.obs.id.as_str()) {
            idx.push(i);
        }
    }
    let n = idx.len();
    let by_tier = THRESHOLDS
        .iter()
        .map(|t| ControlRow {
            name: format!("{} or above", t.label()),
            rate: Proportion::new(idx.iter().filter(|&&i| a.results[i].tier >= *t).count(), n),
        })
        .collect();
    let mut cols: BTreeMap<&str, usize> = BTreeMap::new();
    for &i in &idx {
        *cols.entry(view::grade_column(a, i)).or_default() += 1;
    }
    let by_agent_level = COLUMNS
        .iter()
        .map(|c| ControlRow {
            name: c.to_string(),
            rate: Proportion::new(cols.get(c).copied().unwrap_or(0), n),
        })
        .collect();
    let nc = a.clusters.len();
    let high = (0..nc)
        .filter(|&c| matches!(view::cluster_level(a, c), "L2" | "L3" | "L4" | "L5"))
        .count();
    let plant_signals = PlantSignalKind::ALL
        .iter()
        .map(|k| ControlRow {
            name: k.label().to_string(),
            rate: Proportion::new(
                (0..nc)
                    .filter(|&c| view::cluster_plant_kinds(a, c).contains(k))
                    .count(),
                nc,
            ),
        })
        .collect();
    let above_l0 = |code: &str| !matches!(code, "L0" | "unflagged" | "unclustered");
    let records_above_l0 = idx
        .iter()
        .filter(|&&i| above_l0(view::grade_column(a, i)))
        .count();
    let clusters_above_l0 = (0..nc)
        .filter(|&c| above_l0(view::cluster_level(a, c)))
        .count();
    // Per rule: (records fired on, of them suggestive or above).
    let mut rules: BTreeMap<&str, (usize, usize)> = BTreeMap::new();
    for &i in &idx {
        let r = &a.results[i];
        let mut ids: Vec<&str> = r.hits.iter().map(|h| h.rule_id.as_str()).collect();
        ids.sort_unstable();
        ids.dedup();
        for id in ids {
            let e = rules.entry(id).or_default();
            e.0 += 1;
            e.1 += usize::from(r.tier >= Tier::Suggestive);
        }
    }
    let by_rule = rules
        .into_iter()
        .map(|(id, (fired, flagged))| ControlRuleRow {
            rule_id: id.to_string(),
            fired: Proportion::new(fired, n),
            flagged: Proportion::new(flagged, n),
        })
        .collect();
    let mut by_kind = [0usize; 5];
    for e in &a.swarm_edges {
        by_kind[e.kind as usize] += 1;
    }
    ControlSummary {
        records: n,
        clusters: nc,
        by_tier,
        by_agent_level,
        clusters_l2_or_above: Proportion::new(high, nc),
        plant_signals,
        records_above_l0: Proportion::new(records_above_l0, n),
        clusters_above_l0: Proportion::new(clusters_above_l0, nc),
        by_rule,
        swarm_edges: a.swarm_edges.len(),
        swarm_edges_by_kind: SwarmEdgeKind::ALL
            .iter()
            .zip(by_kind)
            .map(|(k, count)| ControlCount {
                name: k.id().to_string(),
                count,
            })
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Observation, Rules, analyze};

    #[test]
    fn rates_need_no_labels() {
        let obs = |id: &str, url: &str| Observation {
            id: id.into(),
            url: url.into(),
            ..Default::default()
        };
        let a = analyze(
            vec![
                obs("1", "https://www.example.com/"),
                obs("2", "https://www.example.com/a"),
                obs("3", "https://t.example/?id=1%20OR%201=1"),
                obs("3", "https://t.example/?id=1%20OR%201=1"),
            ],
            &Rules::default_rules(),
        );
        let c = negative_control(&a);
        assert_eq!(c.records, 3);
        assert_eq!(c.by_tier.len(), 2);
        assert_eq!(c.by_tier[1].rate.n, 3);
        assert_eq!(c.by_tier[1].rate.k, 1, "{c:?}");
        let total: usize = c.by_agent_level.iter().map(|r| r.rate.k).sum();
        assert_eq!(total, 3);
        let kinds: Vec<&str> = c.plant_signals.iter().map(|r| r.name.as_str()).collect();
        assert_eq!(
            kinds,
            [
                "provenance monoculture",
                "burned identifier",
                "too perfect",
                "habit mismatch",
                "auto-submitted"
            ]
        );
        // Only the payload record is flagged; each rule that fired is listed
        // with that one record, flagged.
        assert!(!c.by_rule.is_empty());
        assert!(c.by_rule.iter().all(|r| r.fired.k == 1 && r.fired.n == 3));
        assert!(c.by_rule.iter().any(|r| r.flagged.k == 1));
        assert_eq!(c.records_above_l0.n, 3);
        assert_eq!(c.swarm_edges, 0);
        assert_eq!(c.swarm_edges_by_kind.len(), 5);
    }
}
