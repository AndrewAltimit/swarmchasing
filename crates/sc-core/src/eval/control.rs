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
use crate::plant::PlantSignalKind;
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
    let kinds = [
        PlantSignalKind::ProvenanceMonoculture,
        PlantSignalKind::BurnedIdentifier,
        PlantSignalKind::TooPerfect,
        PlantSignalKind::HabitMismatch,
    ];
    let plant_signals = kinds
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
    ControlSummary {
        records: n,
        clusters: nc,
        by_tier,
        by_agent_level,
        clusters_l2_or_above: Proportion::new(high, nc),
        plant_signals,
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
        assert_eq!(c.plant_signals.len(), 4);
    }
}
