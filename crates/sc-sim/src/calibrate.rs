//! Each soft-link kind's likelihood ratio, from simulated truth.
//!
//! Every kind is switched on at a nominal ratio, so each link the analysis
//! can draw is drawn, and each pair of clusters above noise, placed on two
//! distinct true runs, is counted as one operator's or not (two clusters of
//! one run are not what a soft link asks about). A kind's ratio is the
//! share of one operator's pairs it links over the share of unrelated
//! pairs it links, each with half a pair added (so a kind that never fires
//! on one side has a finite ratio). The ratios are the defaults the rules
//! file starts from; the simulator only copies request content, so a kind
//! it cannot produce (a captured secret, a header set) has no estimate.

use crate::measure::majority;
use crate::{Palette, ScenarioFile, Truth, generate, to_ndjson};
use sc_core::eval::stats::wilson;
use sc_core::{Analysis, FieldMap, Format, Rules, SoftLinkKind, Tier, analyze, parse_input};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write;

/// Pairs one kind linked.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct KindPairs {
    /// Pairs of one operator it linked.
    pub same: usize,
    /// Unrelated pairs it linked.
    pub other: usize,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Calibration {
    /// Pairs of clusters above noise, both placed on distinct runs, of one
    /// operator.
    pub same_pairs: usize,
    /// Pairs of clusters above noise, both placed, of different operators.
    pub other_pairs: usize,
    /// By kind.
    pub kinds: BTreeMap<SoftLinkKind, KindPairs>,
}

impl Calibration {
    pub fn add(&mut self, o: &Self) {
        self.same_pairs += o.same_pairs;
        self.other_pairs += o.other_pairs;
        for (k, v) in &o.kinds {
            let e = self.kinds.entry(*k).or_default();
            e.same += v.same;
            e.other += v.other;
        }
    }

    /// The kind's likelihood ratio, `None` when it linked no pair of one
    /// operator.
    pub fn lr(&self, kind: SoftLinkKind) -> Option<f64> {
        let k = self.kinds.get(&kind)?;
        if k.same == 0 {
            return None;
        }
        let hit = (k.same as f64 + 0.5) / (self.same_pairs as f64 + 1.0);
        let miss = (k.other as f64 + 0.5) / (self.other_pairs as f64 + 1.0);
        Some(hit / miss)
    }

    /// A conservative ratio: the lower 95% Wilson bound of the share of one
    /// operator's pairs linked over the upper bound of the share of
    /// unrelated pairs linked. `None` when it linked no pair of one
    /// operator.
    pub fn lr_low(&self, kind: SoftLinkKind) -> Option<f64> {
        let k = self.kinds.get(&kind)?;
        if k.same == 0 {
            return None;
        }
        let (hit, _) = wilson(k.same, self.same_pairs)?;
        let (_, miss) = wilson(k.other, self.other_pairs)?;
        Some(hit / miss.max(f64::MIN_POSITIVE))
    }
}

/// Rules with every soft-link kind on at a nominal ratio and every link
/// listed.
pub fn open_rules(rules: &Rules) -> Rules {
    let mut set = rules.set.clone();
    for k in SoftLinkKind::ALL {
        set.soft_links.set_lr(k, 2.0);
    }
    set.soft_links.min_link_lr = 1.0;
    Rules::compile(set).expect("rules that compiled once compile again")
}

/// One analysis's pairs against truth. `a` should come from
/// [`open_rules`].
pub fn count(a: &Analysis, truth: &Truth) -> Calibration {
    let mut out = Calibration::default();
    // Each placed cluster's run and operator.
    let placed: BTreeMap<usize, (&str, String)> = (0..a.clusters.len())
        .filter(|&c| a.clusters[c].tier > Tier::Noise)
        .filter_map(|c| {
            let ids = a.clusters[c]
                .members
                .iter()
                .map(|&m| a.results[m].obs.id.as_str());
            let run = majority(truth, ids)?;
            // Any record of the run names its operator.
            let row = truth.rows.values().find(|r| r.run == run)?;
            Some((c, (run, row.operator())))
        })
        .collect();
    // One run split in two clusters is not the question a soft link
    // answers: such pairs count on neither side.
    let side = |x: usize, y: usize| -> Option<bool> {
        let (px, py) = (placed.get(&x)?, placed.get(&y)?);
        (px.0 != py.0).then_some(px.1 == py.1)
    };
    let ids: Vec<usize> = placed.keys().copied().collect();
    for (i, &x) in ids.iter().enumerate() {
        for &y in &ids[i + 1..] {
            match side(x, y) {
                Some(true) => out.same_pairs += 1,
                Some(false) => out.other_pairs += 1,
                None => {}
            }
        }
    }
    let mut seen: BTreeMap<SoftLinkKind, BTreeSet<(usize, usize)>> = BTreeMap::new();
    for l in &a.soft_links {
        let (Some(x), Some(y)) = (a.cluster_index(&l.a), a.cluster_index(&l.b)) else {
            continue;
        };
        let Some(same) = side(x, y) else {
            continue;
        };
        if !seen.entry(l.kind).or_default().insert((x.min(y), x.max(y))) {
            continue;
        }
        let e = out.kinds.entry(l.kind).or_default();
        if same {
            e.same += 1;
        } else {
            e.other += 1;
        }
    }
    out
}

/// Every scenario of `file` under each of its seeds, with every kind on.
pub fn calibrate(file: &ScenarioFile, palette: &Palette, rules: &Rules) -> Calibration {
    let open = open_rules(rules);
    let mut total = Calibration::default();
    for s in &file.scenario {
        for k in 0..s.seeds.max(1) {
            let text = to_ndjson(&generate(s, s.seed + k as u64, palette));
            let obs = parse_input(&text, Format::Auto, &FieldMap::default()).observations;
            total.add(&count(&analyze(obs, &open), &Truth::from_ndjson(&text)));
        }
    }
    total
}

/// The calibration as a table, with each kind's ratio and the ratio
/// `rules` sets now.
pub fn render_calibration(c: &Calibration, rules: &Rules) -> String {
    let mut s = String::new();
    let _ = writeln!(
        s,
        "Pairs of clusters above noise on distinct runs: {} of one operator, {} unrelated.\nRatio: share of one operator's pairs linked over share of unrelated pairs linked (half a pair added to each). Low: the lower 95% bound of the first share over the upper bound of the second, the value the rules start from.\n",
        c.same_pairs, c.other_pairs
    );
    let _ = writeln!(
        s,
        "  {:<18} {:<12} {:>6} {:>7} {:>10} {:>8} {:>8}",
        "kind", "family", "same", "other", "ratio", "low", "rules"
    );
    for k in SoftLinkKind::ALL {
        let p = c.kinds.get(&k).cloned().unwrap_or_default();
        let lr = c
            .lr(k)
            .map_or_else(|| "-".to_string(), |x| format!("{x:.1}"));
        let low = c
            .lr_low(k)
            .map_or_else(|| "-".to_string(), |x| format!("{x:.1}"));
        let _ = writeln!(
            s,
            "  {:<18} {:<12} {:>6} {:>7} {:>10} {:>8} {:>8}",
            serde_json::to_value(k)
                .ok()
                .and_then(|v| v.as_str().map(str::to_string))
                .unwrap_or_default(),
            k.family().label(),
            p.same,
            p.other,
            lr,
            low,
            format!("{:.1}", rules.set.soft_links.lr(k)),
        );
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ratios_follow_the_counts() {
        let mut c = Calibration {
            same_pairs: 9,
            other_pairs: 99,
            ..Default::default()
        };
        c.kinds
            .insert(SoftLinkKind::CoTarget, KindPairs { same: 4, other: 0 });
        c.kinds
            .insert(SoftLinkKind::Encoding, KindPairs { same: 0, other: 30 });
        let lr = c.lr(SoftLinkKind::CoTarget).unwrap();
        assert!((lr - (4.5 / 10.0) / (0.5 / 100.0)).abs() < 1e-9, "{lr}");
        assert_eq!(c.lr(SoftLinkKind::Encoding), None);
        let low = c.lr_low(SoftLinkKind::CoTarget).unwrap();
        assert!(low > 1.0 && low < lr, "{low}");
        assert_eq!(c.lr(SoftLinkKind::Scaffold), None);
        let open = open_rules(&Rules::default_rules());
        assert_eq!(open.set.soft_links.lr(SoftLinkKind::RelayStack), 2.0);
        assert_eq!(open.set.soft_links.min_link_lr, 1.0);
    }
}
