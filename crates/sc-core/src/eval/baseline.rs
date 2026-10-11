//! The reviewed benign baseline: what the benign records of the stratified
//! review sample bound about the false-positive rate.
//!
//! A baseline record is a label of class [`CLASS`] (what `swarmchase review`
//! gives a record from a `review sample` queue) that is not `synthetic` and
//! not `tuned`. A record looked at while changing a rule is marked `tuned`
//! and leaves the baseline, since the rules were fitted to it. Records
//! chosen for being flagged, or for looking like agents, are never in it.
//!
//! Per tier, the false-positive rate is the share of baseline benign records
//! the current rules flag at that tier or above. Its 95% upper bound is the
//! rule of three, `3/n`, when none was flagged, and the Wilson upper bound
//! otherwise. Progress is counted against [`TARGET`] benign records.

use super::stats::Proportion;
use super::units::THRESHOLDS;
use super::{Label, LabelSet};
use crate::analyze::Analysis;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// The label class of a record reviewed from a `review sample` queue.
pub const CLASS: &str = "review:baseline-sample";

/// Reviewed benign records the baseline aims for: with none flagged, the
/// rule of three bounds the false-positive rate at 0.3%.
pub const TARGET: usize = 1000;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Baseline {
    pub target: usize,
    /// Baseline records (benign and agent), not synthetic, not tuned.
    pub reviewed: usize,
    pub benign: usize,
    /// Agent records in the sample: misses when unflagged.
    pub agents: usize,
    /// Baseline labels left out as `tuned` or `synthetic`.
    pub excluded: usize,
    pub tiers: Vec<BaselineTier>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineTier {
    /// `suggestive` or `significant`; flagged means at this tier or above.
    pub tier: crate::model::Tier,
    /// Benign baseline records flagged, of all benign baseline records.
    pub fp_rate: Proportion,
    /// The 95% upper bound on the false-positive rate.
    pub upper: Option<f64>,
    /// `rule_of_three` (none flagged) or `wilson`.
    pub method: String,
}

/// The 95% upper bound for `k` of `n`, and how it was found.
pub fn upper_bound(k: usize, n: usize) -> (Option<f64>, &'static str) {
    if n == 0 {
        (None, "none")
    } else if k == 0 {
        (Some((3.0 / n as f64).min(1.0)), "rule_of_three")
    } else {
        (Proportion::new(k, n).hi, "wilson")
    }
}

/// The baseline over `labels`, or `None` when no label is of [`CLASS`].
pub fn baseline(a: &Analysis, labels: &LabelSet) -> Option<Baseline> {
    if !labels
        .labels
        .values()
        .any(|l| l.class.as_deref() == Some(CLASS))
    {
        return None;
    }
    let mut seen = HashSet::new();
    let (mut benign, mut agents, mut excluded) = (Vec::new(), 0, 0);
    for r in &a.results {
        let Some(l) = labels.labels.get(&r.obs.id) else {
            continue;
        };
        if l.class.as_deref() != Some(CLASS) || !seen.insert(r.obs.id.as_str()) {
            continue;
        }
        if l.tuned || l.synthetic {
            excluded += 1;
        } else if l.label == Label::Agent {
            agents += 1;
        } else {
            benign.push(r.tier);
        }
    }
    let n = benign.len();
    let tiers = THRESHOLDS
        .iter()
        .map(|t| {
            let k = benign.iter().filter(|x| *x >= t).count();
            let (upper, method) = upper_bound(k, n);
            BaselineTier {
                tier: *t,
                fp_rate: Proportion::new(k, n),
                upper,
                method: method.to_string(),
            }
        })
        .collect();
    Some(Baseline {
        target: TARGET,
        reviewed: n + agents,
        benign: n,
        agents,
        excluded,
        tiers,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Observation, Rules, analyze, parse_labels};

    #[test]
    fn bounds_the_rate_from_untuned_baseline_benign_records() {
        let o = |id: &str, url: &str| Observation {
            id: id.into(),
            url: url.into(),
            ..Default::default()
        };
        let a = analyze(
            vec![
                o("b1", "https://www.example.com/"),
                o("b2", "https://www.example.com/a"),
                o("b3", "https://www.example.com/b"),
                o("t1", "https://t.example/?id=1%20OR%201=1"),
                o("f1", "https://t.example/?id=2%20OR%201=1"),
            ],
            &Rules::default_rules(),
        );
        let lines = [
            r#"{"id":"b1","label":"benign","class":"review:baseline-sample"}"#,
            r#"{"id":"b2","label":"benign","class":"review:baseline-sample"}"#,
            r#"{"id":"b3","label":"agent","class":"review:baseline-sample"}"#,
            r#"{"id":"t1","label":"benign","class":"review:baseline-sample","tuned":true}"#,
            r#"{"id":"f1","label":"benign","class":"review:flagged"}"#,
        ];
        let b = baseline(&a, &parse_labels(&lines.join("\n"))).unwrap();
        assert_eq!((b.reviewed, b.benign, b.agents, b.excluded), (3, 2, 1, 1));
        let sug = &b.tiers[0];
        assert_eq!((sug.fp_rate.k, sug.fp_rate.n), (0, 2));
        assert_eq!(sug.method, "rule_of_three");
        assert_eq!(sug.upper, Some(1.0));
        assert!(baseline(&a, &parse_labels(lines[4])).is_none());
    }

    #[test]
    fn upper_bounds() {
        assert_eq!(upper_bound(0, 0), (None, "none"));
        assert_eq!(upper_bound(0, 1000), (Some(0.003), "rule_of_three"));
        let (hi, m) = upper_bound(1, 1000);
        assert_eq!(m, "wilson");
        assert!(hi.unwrap() > 0.001 && hi.unwrap() < 0.01);
    }
}
