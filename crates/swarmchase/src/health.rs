//! Source health and rule drift for the watch digest.
//!
//! A source whose pull collapses against its own recent history usually means
//! an API change, an expired key or a spent quota, not a quiet week. A rule
//! whose hit rate on new records jumps against its recent history usually
//! means the rule started matching something ordinary. Both are reported in
//! the digest before a broken source hides a swarm or a noisy rule reaches a
//! notice.

use sc_core::Analysis;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// Successful runs kept per source, and runs kept for the rule baseline.
pub const HISTORY: usize = 8;

/// Runs needed before a source's history is trusted.
const MIN_RUNS: usize = 3;
/// A pull below this fraction of the trailing median is a collapse…
const COLLAPSE_FRACTION: f64 = 0.2;
/// …once the median is at least this many records.
const MIN_MEDIAN: usize = 5;
/// Consecutive failed runs before a source is called failing.
const ERROR_STREAK: u32 = 2;

/// New records needed in this run and in the baseline before rates are compared.
const MIN_RUN_RECORDS: usize = 20;
const MIN_BASELINE_RECORDS: usize = 100;
/// A rule drifts when it fires on at least this many new records…
const MIN_DRIFT_HITS: usize = 5;
/// …at this multiple of its baseline rate…
const DRIFT_FACTOR: f64 = 3.0;
/// …and at least this much higher in absolute terms.
const DRIFT_MIN_DELTA: f64 = 0.02;

/// Per-source history kept in `state.json`.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct SourceHealth {
    /// Records pulled by the last successful runs, oldest first.
    #[serde(default)]
    pub pulled: Vec<usize>,
    /// Failed runs in a row.
    #[serde(default)]
    pub errors_in_row: u32,
}

impl SourceHealth {
    /// A successful pull that is catching up (a source's first pull, or one
    /// spread over several runs) rather than reading what is new since the
    /// last run. It ends an error streak but is not history: its count would
    /// set a median that every ordinary pull after it falls short of.
    pub fn observe_catch_up(&mut self) {
        self.errors_in_row = 0;
    }

    /// Check this run against the history, then add it. `pulled` is `None`
    /// when the pull failed.
    pub fn observe(&mut self, name: &str, pulled: Option<usize>) -> Option<String> {
        let Some(n) = pulled else {
            self.errors_in_row += 1;
            return (self.errors_in_row >= ERROR_STREAK)
                .then(|| format!("`{name}` has failed {} runs in a row", self.errors_in_row));
        };
        self.errors_in_row = 0;
        let alert = (self.pulled.len() >= MIN_RUNS)
            .then(|| median(&self.pulled))
            .filter(|&m| m >= MIN_MEDIAN && (n as f64) < m as f64 * COLLAPSE_FRACTION)
            .map(|m| {
                format!(
                    "`{name}` pulled {n} records against a median of {m} over the last {} runs; check the API, key and quota",
                    self.pulled.len()
                )
            });
        self.pulled.push(n);
        if self.pulled.len() > HISTORY {
            self.pulled.remove(0);
        }
        alert
    }
}

fn median(v: &[usize]) -> usize {
    let mut s = v.to_vec();
    s.sort_unstable();
    s[s.len() / 2]
}

/// Rule hit counts on one run's new records.
#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
pub struct RuleRun {
    pub records: usize,
    #[serde(default)]
    pub hits: BTreeMap<String, usize>,
}

impl RuleRun {
    /// Count each rule once per record, over the records in `ids`.
    pub fn from_analysis(a: &Analysis, ids: &BTreeSet<String>) -> Self {
        let mut run = RuleRun::default();
        for r in a.results.iter().filter(|r| ids.contains(&r.obs.id)) {
            run.records += 1;
            let rules: BTreeSet<&str> = r.hits.iter().map(|h| h.rule_id.as_str()).collect();
            for id in rules {
                *run.hits.entry(id.to_string()).or_default() += 1;
            }
        }
        run
    }
}

/// The rule baseline kept in `state.json`, per watch source: each source has
/// its own mix of rules (a relay's own rule fires on nearly every record from
/// it), so a run whose new records come mostly from one source would
/// otherwise look like drift. It restarts when the rules change, because a
/// changed rule is expected to fire at a different rate.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct RuleHistory {
    #[serde(default)]
    pub rules_version: String,
    #[serde(default)]
    pub sources: BTreeMap<String, Vec<RuleRun>>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Drift {
    pub source: String,
    pub rule: String,
    pub hits: usize,
    pub records: usize,
    pub baseline_hits: usize,
    pub baseline_records: usize,
}

impl Drift {
    pub fn line(&self) -> String {
        let pct = |h: usize, n: usize| 100.0 * h as f64 / n.max(1) as f64;
        format!(
            "`{}` fired on {} of {} new records from {} ({:.1}%) against {:.1}% over its previous {} records",
            self.rule,
            self.hits,
            self.records,
            self.source,
            pct(self.hits, self.records),
            pct(self.baseline_hits, self.baseline_records),
            self.baseline_records
        )
    }
}

impl RuleHistory {
    /// Compare each source's run with that source's baseline, then add it.
    /// Returns the drifting rules, and whether the baseline restarted
    /// because the rules changed.
    pub fn observe(
        &mut self,
        version: &str,
        runs: BTreeMap<String, RuleRun>,
    ) -> (Vec<Drift>, bool) {
        let restarted = !self.rules_version.is_empty() && self.rules_version != version;
        if self.rules_version != version {
            self.rules_version = version.to_string();
            self.sources.clear();
        }
        let mut drifts = Vec::new();
        for (source, run) in runs {
            let history = self.sources.entry(source.clone()).or_default();
            drifts.extend(drift(history, &run).into_iter().map(|d| Drift {
                source: source.clone(),
                ..d
            }));
            if run.records > 0 {
                history.push(run);
                if history.len() > HISTORY {
                    history.remove(0);
                }
            }
        }
        drifts.sort_by(|a, b| b.hits.cmp(&a.hits).then_with(|| a.rule.cmp(&b.rule)));
        (drifts, restarted)
    }
}

fn drift(baseline: &[RuleRun], run: &RuleRun) -> Vec<Drift> {
    let base_records: usize = baseline.iter().map(|r| r.records).sum();
    if run.records < MIN_RUN_RECORDS || base_records < MIN_BASELINE_RECORDS {
        return Vec::new();
    }
    let mut out = Vec::new();
    for (rule, &hits) in &run.hits {
        let base_hits: usize = baseline.iter().filter_map(|r| r.hits.get(rule)).sum();
        let rate = hits as f64 / run.records as f64;
        let base = base_hits as f64 / base_records as f64;
        if hits >= MIN_DRIFT_HITS && rate >= base * DRIFT_FACTOR && rate - base >= DRIFT_MIN_DELTA {
            out.push(Drift {
                source: String::new(),
                rule: rule.clone(),
                hits,
                records: run.records,
                baseline_hits: base_hits,
                baseline_records: base_records,
            });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_collapse_and_error_streak() {
        let mut h = SourceHealth::default();
        for n in [40, 35, 50] {
            assert_eq!(h.observe("s", Some(n)), None);
        }
        assert_eq!(
            h.observe("s", Some(30)),
            None,
            "a quiet run is not a collapse"
        );
        let alert = h.observe("s", Some(2)).expect("collapse");
        assert!(alert.contains("median of 40"), "{alert}");

        assert_eq!(
            h.observe("s", None),
            None,
            "one failure is reported as an error only"
        );
        assert!(h.observe("s", None).unwrap().contains("2 runs in a row"));
        assert_eq!(h.observe("s", Some(40)), None);
        assert_eq!(h.errors_in_row, 0);
        assert_eq!(h.pulled.len(), 6);

        // A catch-up pull ends an error streak without joining the history.
        assert_eq!(h.observe("s", None), None);
        h.observe_catch_up();
        assert_eq!((h.errors_in_row, h.pulled.len()), (0, 6));

        let mut small = SourceHealth::default();
        for n in [2, 3, 2, 0] {
            assert_eq!(small.observe("t", Some(n)), None, "too small to judge");
        }
    }

    fn run(records: usize, hits: &[(&str, usize)]) -> RuleRun {
        RuleRun {
            records,
            hits: hits.iter().map(|(k, v)| (k.to_string(), *v)).collect(),
        }
    }

    fn one(source: &str, r: RuleRun) -> BTreeMap<String, RuleRun> {
        BTreeMap::from([(source.to_string(), r)])
    }

    #[test]
    fn rule_drift_needs_a_baseline_and_restarts_on_new_rules() {
        let mut h = RuleHistory::default();
        for _ in 0..3 {
            let (d, restarted) = h.observe("v1", one("s", run(50, &[("a", 1), ("b", 10)])));
            assert!(d.is_empty() && !restarted);
        }
        // `a` jumps from 2% to 20%; `b` stays at 20%.
        let (d, _) = h.observe("v1", one("s", run(50, &[("a", 10), ("b", 10)])));
        assert_eq!(d.len(), 1);
        assert_eq!((d[0].source.as_str(), d[0].rule.as_str()), ("s", "a"));
        assert_eq!((d[0].baseline_hits, d[0].baseline_records), (3, 150));
        assert!(d[0].line().contains("20.0%"), "{}", d[0].line());

        // A brand-new rule with no baseline hits drifts too.
        let (d, _) = h.observe("v1", one("s", run(40, &[("c", 6)])));
        assert_eq!(d[0].rule, "c");

        // Small runs are not judged.
        let (d, _) = h.observe("v1", one("s", run(10, &[("d", 9)])));
        assert!(d.is_empty());

        let (d, restarted) = h.observe("v2", one("s", run(50, &[("a", 40)])));
        assert!(d.is_empty() && restarted);
        assert_eq!(h.sources["s"].len(), 1);
    }

    #[test]
    fn a_run_dominated_by_one_source_is_not_drift() {
        let mut h = RuleHistory::default();
        // A relay's own rule fires on every record from it, and on none
        // from the other source.
        for _ in 0..3 {
            let runs = BTreeMap::from([
                ("relay".to_string(), run(40, &[("relay.x", 40)])),
                ("other".to_string(), run(160, &[])),
            ]);
            assert!(h.observe("v1", runs).0.is_empty());
        }
        // This run's new records are all from the relay.
        let (d, _) = h.observe("v1", one("relay", run(500, &[("relay.x", 500)])));
        assert!(d.is_empty(), "{d:?}");
    }

    #[test]
    fn rule_run_counts_each_rule_once_per_record() {
        let rules = sc_core::Rules::default_rules();
        let obs = vec![sc_core::Observation {
            id: "x".into(),
            url: "https://r.jina.ai/https://a.example/?q=1'%20OR%201=1--&p=1'%20OR%201=1--".into(),
            ..Default::default()
        }];
        let a = sc_core::analyze(obs, &rules);
        let ids = BTreeSet::from(["x".to_string()]);
        let r = RuleRun::from_analysis(&a, &ids);
        assert_eq!(r.records, 1);
        assert!(!r.hits.is_empty());
        assert!(r.hits.values().all(|&n| n == 1), "{r:?}");
        assert_eq!(RuleRun::from_analysis(&a, &BTreeSet::new()).records, 0);
    }
}
