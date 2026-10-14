//! Source health and rule drift for the watch digest.
//!
//! A source whose pull collapses against its own recent history usually means
//! an API change, an expired key or a spent quota, not a quiet week. A rule
//! whose hit rate on new records jumps against its recent history usually
//! means the rule started matching something ordinary, though a swarm
//! starting below the clustering threshold reads the same: where the onset
//! check (`watch/onset.rs`) also finds the rule rising, the alert says
//! "drift or onset" ([`Reading`]). Both are reported in
//! the digest before a broken source hides a swarm or a noisy rule reaches a
//! notice. A failed run alerts at once, and a failure that goes on alerts
//! again on its 2nd, 4th, 8th... run in a row ([`alert_due`]); a source that
//! keeps pulling nothing, or is skipped run after run, is noted without
//! alerting every time.

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
/// Successful runs in a row with nothing pulled before the digest notes it.
pub const QUIET_RUNS: u32 = 4;

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
    /// Successful runs in a row that pulled nothing.
    #[serde(default)]
    pub empty_runs: u32,
    /// Whether any run has pulled a record.
    #[serde(default)]
    pub ever_pulled: bool,
    /// Runs in a row the source was skipped (no API key).
    #[serde(default)]
    pub skipped_runs: u32,
    /// Pulls in a row whose canary failed.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub canary_failed_runs: u32,
}

fn is_zero(n: &u32) -> bool {
    *n == 0
}

/// Whether the `n`th run of a failure streak alerts: the 1st, 2nd, 4th,
/// 8th and so on. A streak that goes on is still reported, without a
/// mailed digest every run for the same failure.
pub fn alert_due(n: u32) -> bool {
    n.is_power_of_two()
}

impl SourceHealth {
    /// A successful pull that is catching up (a source's first pull, or one
    /// spread over several runs) rather than reading what is new since the
    /// last run. It ends an error streak but is not history: its count would
    /// set a median that every ordinary pull after it falls short of.
    pub fn observe_catch_up(&mut self) {
        self.errors_in_row = 0;
        self.skipped_runs = 0;
    }

    /// A run that skipped the source. Alerts the first time only: after
    /// that the digest's health block still lists it, without mailing a
    /// digest for it every run.
    pub fn observe_skip(&mut self, name: &str, why: &str) -> Option<String> {
        self.skipped_runs += 1;
        (self.skipped_runs == 1).then(|| format!("`{name}` was skipped: {why}"))
    }

    /// Count a successful pull towards the quiet streak. Returns the streak
    /// once it reaches [`QUIET_RUNS`].
    pub fn observe_yield(&mut self, pulled: usize) -> Option<u32> {
        if pulled > 0 {
            self.empty_runs = 0;
            self.ever_pulled = true;
            return None;
        }
        self.empty_runs += 1;
        (self.empty_runs >= QUIET_RUNS).then_some(self.empty_runs)
    }

    /// A pull that read its source: count a failed canary towards its
    /// streak, or end the streak. Returns the streak while it fails.
    pub fn observe_canary(&mut self, canary: Option<bool>) -> Option<u32> {
        if canary == Some(false) {
            self.canary_failed_runs += 1;
            Some(self.canary_failed_runs)
        } else {
            self.canary_failed_runs = 0;
            None
        }
    }

    /// Check this run against the history, then add it. `pulled` is the
    /// error's short reason when the pull failed. A first failure alerts, so
    /// it reaches the admin within one run; a streak alerts again on its
    /// 2nd, 4th, 8th... run ([`alert_due`]), and the digest's source table
    /// shows the error on every run.
    pub fn observe(&mut self, name: &str, pulled: Result<usize, &str>) -> Option<String> {
        self.skipped_runs = 0;
        let n = match pulled {
            Ok(n) => n,
            Err(why) => {
                self.errors_in_row += 1;
                if !alert_due(self.errors_in_row) {
                    return None;
                }
                return Some(if self.errors_in_row == 1 {
                    format!(
                        "`{name}` failed this run ({why}); it retries from its checkpoint next run"
                    )
                } else {
                    format!(
                        "`{name}` has failed {} runs in a row ({why})",
                        self.errors_in_row
                    )
                });
            }
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
    /// How the rise reads, once the onset check has run.
    pub reading: Reading,
}

/// What a rule's jump in rate most likely is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Reading {
    /// A rule matching something ordinary.
    #[default]
    Drift,
    /// Both fit: the onset check also finds the rule's slice rising on its
    /// own, as a swarm starting below the clustering threshold would.
    DriftOrOnset,
    /// Most of the source's slices rose with it: the source changed.
    Source,
}

impl Drift {
    pub fn line(&self) -> String {
        let pct = |h: usize, n: usize| 100.0 * h as f64 / n.max(1) as f64;
        let what = match self.reading {
            Reading::Drift => "",
            Reading::DriftOrOnset => {
                "drift or onset: the rule may match something ordinary, or a swarm may be starting below the clustering threshold (see Slice onsets); "
            }
            Reading::Source => {
                "with most of its source's slices, so read as a source-side change before a noisy rule; "
            }
        };
        format!(
            "{what}`{}` fired on {} of {} new records from {} ({:.1}%) against {:.1}% over its previous {} records",
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
                reading: Reading::Drift,
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
            assert_eq!(h.observe("s", Ok(n)), None);
        }
        assert_eq!(
            h.observe("s", Ok(30)),
            None,
            "a quiet run is not a collapse"
        );
        let alert = h.observe("s", Ok(2)).expect("collapse");
        assert!(alert.contains("median of 40"), "{alert}");

        // The first failure alerts.
        let first = h.observe("s", Err("HTTP 503 after 7 attempts")).unwrap();
        assert!(first.contains("failed this run (HTTP 503"), "{first}");
        assert!(first.contains("next run"), "{first}");
        let second = h.observe("s", Err("HTTP 504")).unwrap();
        assert!(second.contains("2 runs in a row (HTTP 504)"), "{second}");
        // A streak alerts again on its 4th and 8th run, not on every one.
        assert_eq!(h.observe("s", Err("HTTP 504")), None);
        assert!(h.observe("s", Err("HTTP 504")).unwrap().contains("4 runs"));
        for _ in 5..8 {
            assert_eq!(h.observe("s", Err("HTTP 504")), None);
        }
        assert!(h.observe("s", Err("HTTP 504")).unwrap().contains("8 runs"));
        assert_eq!(h.observe("s", Ok(40)), None);
        assert_eq!(h.errors_in_row, 0);
        assert_eq!(h.pulled.len(), 6);

        // A catch-up pull ends an error streak without joining the history.
        assert!(h.observe("s", Err("x")).is_some());
        h.observe_catch_up();
        assert_eq!((h.errors_in_row, h.pulled.len()), (0, 6));

        let mut small = SourceHealth::default();
        for n in [2, 3, 2, 0] {
            assert_eq!(small.observe("t", Ok(n)), None, "too small to judge");
        }
    }

    #[test]
    fn quiet_and_skipped_sources() {
        let mut h = SourceHealth::default();
        for _ in 1..QUIET_RUNS {
            assert_eq!(h.observe_yield(0), None);
        }
        assert_eq!(h.observe_yield(0), Some(QUIET_RUNS));
        assert!(!h.ever_pulled);
        assert_eq!(h.observe_yield(3), None);
        assert!(h.ever_pulled && h.empty_runs == 0);

        // A skip alerts once, then stays quiet until the source runs again.
        let a = h.observe_skip("uq", "URLQUERY_APIKEY not set").unwrap();
        assert!(
            a.contains("`uq` was skipped: URLQUERY_APIKEY not set"),
            "{a}"
        );
        assert_eq!(h.observe_skip("uq", "URLQUERY_APIKEY not set"), None);
        h.observe("uq", Ok(1));
        assert!(h.observe_skip("uq", "again").is_some());

        // A canary streak counts up and ends on a pass or a source with none.
        assert_eq!(h.observe_canary(Some(false)), Some(1));
        assert_eq!(h.observe_canary(Some(false)), Some(2));
        assert_eq!(h.observe_canary(Some(true)), None);
        assert_eq!(h.observe_canary(Some(false)), Some(1));
        assert_eq!(h.observe_canary(None), None);
        let due: Vec<u32> = (1..=20).filter(|&n| alert_due(n)).collect();
        assert_eq!(due, [1, 2, 4, 8, 16]);
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
        assert!(!d[0].line().contains("onset"));
        let mut both = d[0].clone();
        both.reading = Reading::DriftOrOnset;
        assert!(
            both.line().starts_with("drift or onset: "),
            "{}",
            both.line()
        );
        both.reading = Reading::Source;
        assert!(
            both.line().contains("source-side change"),
            "{}",
            both.line()
        );

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
