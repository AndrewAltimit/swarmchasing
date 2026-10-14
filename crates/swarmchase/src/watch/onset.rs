//! Onsets in sub-threshold slices: a swarm that never clusters above noise
//! but changes a count.
//!
//! Each run counts its new records per slice of each source (the rules they
//! hit, their scaffold template, their target's site family;
//! [`sc_core::timing::changepoint::slices`]) against the records the source
//! returned, and keeps the last [`HISTORY`] runs per source in `state.json`.
//! [`sc_core::timing::changepoint::detect`] reads each slice's history for
//! an upward change point. When most of a source's established slices rise
//! together, the digest reports one source-side change (pagination, a new
//! crawl, a recovery) instead of an onset per slice.
//!
//! Onsets are digest leads: they reach the admin in the mailed digest only,
//! never a public artifact. A slice that stays up is reported again on the
//! 2nd, 4th, 8th... run of its streak ([`crate::health::alert_due`]), as
//! health alerts are. The history restarts when the rules change, as the
//! drift baseline does, and runs older than retention are dropped with the
//! records their example IDs name.

use crate::health::{Drift, Reading, alert_due};
use crate::suggest::defang_all;
use sc_core::Analysis;
use sc_core::extract::defang;
use sc_core::timing::changepoint::{self, Bin, ChangePoint, Params};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write;

/// Runs kept per source.
pub const HISTORY: usize = 16;
/// Slices kept per run, the largest counts first.
const MAX_SLICES: usize = 300;
/// Example record IDs kept per slice per run.
const EXAMPLES: usize = 3;
/// A run's records at this multiple of the baseline median, or below its
/// inverse, is a volume change the onset line mentions.
const VOLUME_FACTOR: u64 = 4;
/// Onset lines the digest shows.
const LINES: usize = 15;

/// One run of one source: its new records, and the records in each slice.
#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
pub struct SliceRun {
    pub stamp: String,
    #[serde(default)]
    pub ts: i64,
    pub records: u64,
    #[serde(default)]
    pub counts: BTreeMap<String, u64>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub examples: BTreeMap<String, Vec<String>>,
}

impl SliceRun {
    /// Count each slice once per record, over the records in `ids`.
    pub fn from_analysis(a: &Analysis, ids: &BTreeSet<String>, stamp: &str, ts: i64) -> Self {
        let mut run = SliceRun {
            stamp: stamp.to_string(),
            ts,
            ..Default::default()
        };
        for r in a.results.iter().filter(|r| ids.contains(&r.obs.id)) {
            run.records += 1;
            for s in changepoint::slices(r) {
                let ex = run.examples.entry(s.clone()).or_default();
                if ex.len() < EXAMPLES {
                    ex.push(r.obs.id.clone());
                }
                *run.counts.entry(s).or_default() += 1;
            }
        }
        run.bound();
        run
    }

    /// Keep the [`MAX_SLICES`] largest slices.
    fn bound(&mut self) {
        if self.counts.len() <= MAX_SLICES {
            return;
        }
        let mut by: Vec<(&String, &u64)> = self.counts.iter().collect();
        by.sort_by(|a, b| b.1.cmp(a.1).then_with(|| a.0.cmp(b.0)));
        let keep: BTreeSet<String> = by
            .iter()
            .take(MAX_SLICES)
            .map(|(k, _)| (*k).clone())
            .collect();
        self.counts.retain(|k, _| keep.contains(k));
        self.examples.retain(|k, _| keep.contains(k));
    }
}

/// One source's runs, and the streaks of its rising slices.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct SourceRuns {
    /// Oldest first.
    #[serde(default)]
    pub runs: Vec<SliceRun>,
    /// Runs in a row each slice has been rising.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub streaks: BTreeMap<String, u32>,
    /// Runs in a row the source as a whole has been changing.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub source_streak: u32,
}

fn is_zero(n: &u32) -> bool {
    *n == 0
}

/// The onset history kept in `state.json`.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct OnsetHistory {
    #[serde(default)]
    pub rules_version: String,
    #[serde(default)]
    pub sources: BTreeMap<String, SourceRuns>,
}

/// A slice whose rate rose.
#[derive(Debug, Clone, PartialEq)]
pub struct Onset {
    pub source: String,
    /// `rule:<id>`, `scaffold:<template>` or `family:<site>`.
    pub slice: String,
    pub change: ChangePoint,
    /// The run the rise started in.
    pub since: String,
    /// Some of the slice's records since then, newest run first.
    pub examples: Vec<String>,
    /// Runs in a row the slice has been rising, and whether this one alerts.
    pub streak: u32,
    pub due: bool,
    /// This run's records against the baseline runs' median, when the
    /// source's volume changed too.
    pub volume: Option<(u64, u64)>,
}

impl Onset {
    /// The slice as the digest prints it: hosts and URLs defanged.
    pub fn slice_label(&self) -> String {
        match self.slice.split_once(':') {
            Some(("family", f)) => format!("site family `{}`", defang_all(f)),
            Some(("scaffold", t)) => format!("scaffold `{}`", defang(t)),
            Some(("rule", r)) => format!("rule `{r}`"),
            _ => format!("`{}`", defang_all(&self.slice)),
        }
    }

    pub fn line(&self) -> String {
        let pct = |r: f64| 100.0 * r;
        let mut s = format!(
            "{} on `{}`: {} of {} new records since run {} ({:.2}%) against {} of {} over the baseline runs ({:.2}%)",
            self.slice_label(),
            self.source,
            self.change.new_count,
            self.change.new_exposure,
            self.since,
            pct(self.change.new_rate()),
            self.change.base_count,
            self.change.base_exposure,
            pct(self.change.base_rate()),
        );
        if let Some((now, median)) = self.volume {
            let _ = write!(
                s,
                "; the source returned {now} records this run against a median of {median}, so check it for a source-side change too"
            );
        }
        if !self.examples.is_empty() {
            let ids: Vec<String> = self
                .examples
                .iter()
                .map(|i| format!("`{}`", defang_all(i)))
                .collect();
            let _ = write!(s, "; e.g. {}", ids.join(", "));
        }
        if self.streak > 1 {
            let _ = write!(s, " (rising {} runs in a row)", self.streak);
        }
        s
    }
}

/// Most of a source's established slices rising together.
#[derive(Debug, Clone, PartialEq)]
pub struct SourceSide {
    pub source: String,
    pub rising: usize,
    pub established: usize,
    pub records: u64,
    pub median: u64,
    pub streak: u32,
    pub due: bool,
}

impl SourceSide {
    pub fn line(&self) -> String {
        format!(
            "`{}`: {} of its {} established slices rose together ({} records this run against a median of {}); read as a change in the source (pagination, a new crawl, a recovery), not an onset",
            self.source, self.rising, self.established, self.records, self.median
        )
    }
}

/// What one run's check found.
#[derive(Debug, Default, Clone)]
pub struct Report {
    /// Highest score first.
    pub onsets: Vec<Onset>,
    pub source_side: Vec<SourceSide>,
    pub restarted: bool,
}

impl Report {
    /// Whether anything in it alerts this run.
    pub fn due(&self) -> bool {
        self.onsets.iter().any(|o| o.due) || self.source_side.iter().any(|s| s.due)
    }

    /// Whether `rule` is rising on `source` as an onset.
    pub fn rule_rising(&self, source: &str, rule: &str) -> bool {
        self.onsets
            .iter()
            .any(|o| o.source == source && o.slice.strip_prefix("rule:") == Some(rule))
    }

    /// Whether `source` changed as a whole this run.
    pub fn source_changed(&self, source: &str) -> bool {
        self.source_side.iter().any(|s| s.source == source)
    }
}

fn median(v: &mut [u64]) -> u64 {
    v.sort_unstable();
    v.get(v.len() / 2).copied().unwrap_or(0)
}

impl OnsetHistory {
    pub fn is_empty(&self) -> bool {
        self.sources.is_empty()
    }

    /// Add each source's run to its history, then check every slice the
    /// history holds. A source with no records this run is not checked and
    /// keeps its streaks.
    pub fn observe(&mut self, version: &str, runs: BTreeMap<String, SliceRun>) -> Report {
        let p = Params::default();
        let mut report = Report {
            restarted: !self.rules_version.is_empty() && self.rules_version != version,
            ..Default::default()
        };
        if self.rules_version != version {
            self.rules_version = version.to_string();
            self.sources.clear();
        }
        for (source, run) in runs {
            if run.records == 0 {
                continue;
            }
            let h = self.sources.entry(source.clone()).or_default();
            h.runs.push(run);
            if h.runs.len() > HISTORY {
                h.runs.remove(0);
            }
            let keys: BTreeSet<&String> = h.runs.iter().flat_map(|r| r.counts.keys()).collect();
            let mut found = Vec::new();
            let mut established = 0;
            for key in keys {
                let bins: Vec<Bin> = h
                    .runs
                    .iter()
                    .map(|r| Bin {
                        exposure: r.records,
                        count: r.counts.get(key).copied().unwrap_or(0),
                    })
                    .collect();
                if changepoint::baseline(&bins, &p).is_some_and(|(k, _)| k > 0) {
                    established += 1;
                }
                if let Some(cp) = changepoint::detect(&bins, &p) {
                    found.push((key.clone(), cp));
                }
            }
            let rising_established = found.iter().filter(|(_, cp)| cp.base_count > 0).count();
            // The baseline runs as `detect` splits them, and at least one.
            let len = h.runs.len();
            let recent = len.saturating_sub(p.min_base_runs).min(p.max_recent);
            let base_end = (len - recent).min(len - 1).max(1);
            let records = h.runs.last().map_or(0, |r| r.records);
            let base_median = median(
                &mut h.runs[..base_end]
                    .iter()
                    .map(|r| r.records)
                    .collect::<Vec<_>>(),
            );
            if changepoint::source_wide(rising_established, established) {
                h.source_streak += 1;
                h.streaks.clear();
                report.source_side.push(SourceSide {
                    source: source.clone(),
                    rising: rising_established,
                    established,
                    records,
                    median: base_median,
                    streak: h.source_streak,
                    due: alert_due(h.source_streak),
                });
                continue;
            }
            h.source_streak = 0;
            let volume = (base_median > 0
                && (records >= base_median * VOLUME_FACTOR
                    || records * VOLUME_FACTOR <= base_median))
                .then_some((records, base_median));
            let rising: BTreeSet<&String> = found.iter().map(|(k, _)| k).collect();
            h.streaks.retain(|k, _| rising.contains(k));
            for (key, cp) in found {
                let streak = {
                    let n = h.streaks.entry(key.clone()).or_default();
                    *n += 1;
                    *n
                };
                // `detect` skips runs with no records; the history keeps none.
                let since = h
                    .runs
                    .get(cp.onset)
                    .map(|r| r.stamp.clone())
                    .unwrap_or_default();
                let examples = h.runs[cp.onset.min(h.runs.len())..]
                    .iter()
                    .rev()
                    .flat_map(|r| r.examples.get(&key).into_iter().flatten())
                    .take(EXAMPLES)
                    .cloned()
                    .collect();
                report.onsets.push(Onset {
                    source: source.clone(),
                    slice: key,
                    change: cp,
                    since,
                    examples,
                    streak,
                    due: alert_due(streak),
                    volume,
                });
            }
        }
        report.onsets.sort_by(|a, b| {
            b.change
                .score
                .total_cmp(&a.change.score)
                .then_with(|| a.source.cmp(&b.source))
                .then_with(|| a.slice.cmp(&b.slice))
        });
        report
    }

    /// Drop runs before `cutoff` (their example IDs name records retention
    /// deletes), and sources left with none. Returns the runs dropped.
    pub fn prune(&mut self, cutoff: i64) -> usize {
        let mut n = 0;
        for h in self.sources.values_mut() {
            let before = h.runs.len();
            h.runs.retain(|r| r.ts <= 0 || r.ts >= cutoff);
            n += before - h.runs.len();
        }
        self.sources.retain(|_, h| !h.runs.is_empty());
        n
    }
}

/// Say how each rule drift reads given the onsets: a rule also rising as
/// an onset is "drift or onset", one on a source that changed as a whole is
/// the source.
pub fn read_drifts(r: &Report, drifts: &mut [Drift]) {
    for d in drifts {
        d.reading = if r.source_changed(&d.source) {
            Reading::Source
        } else if r.rule_rising(&d.source, &d.rule) {
            Reading::DriftOrOnset
        } else {
            Reading::Drift
        };
    }
}

/// The digest's `## Slice onsets` section, or nothing when no slice is rising.
pub fn section(r: &Report) -> String {
    let mut t = String::new();
    if r.onsets.is_empty() && r.source_side.is_empty() && !r.restarted {
        return t;
    }
    let _ = writeln!(t, "\n## Slice onsets ({})\n", r.onsets.len());
    let _ = writeln!(
        t,
        "Slices of a source's new records (a rule, a scaffold template, a target site family) whose rate per record rose against the source's earlier runs: a swarm starting below the clustering threshold, or a rule starting to match something ordinary. Leads to review, not findings. A slice still rising is mailed again on the 2nd, 4th, 8th... run of its streak.\n"
    );
    for o in r.onsets.iter().take(LINES) {
        let mark = if o.due { "" } else { " (repeat, not alerting)" };
        let _ = writeln!(t, "- {}{mark}", o.line());
    }
    if r.onsets.len() > LINES {
        let _ = writeln!(t, "- … {} more", r.onsets.len() - LINES);
    }
    if !r.source_side.is_empty() {
        let _ = writeln!(t, "\nSource-side changes:\n");
        for s in &r.source_side {
            let _ = writeln!(t, "- {}", s.line());
        }
    }
    if r.restarted {
        let _ = writeln!(
            t,
            "\nThe rules changed; the onset history restarts from this run."
        );
    }
    t
}

/// Priority reasons for the onsets that alert this run: medium, as a
/// health alert is.
pub fn priority_reasons(r: &Report) -> Vec<super::priority::Reason> {
    let onsets = r
        .onsets
        .iter()
        .filter(|o| o.due)
        .map(|o| super::priority::Reason {
            level: super::priority::Level::Medium,
            kind: "onset".into(),
            text: format!(
                "onset: {} on `{}` since run {}",
                o.slice_label(),
                o.source,
                o.since
            ),
        });
    let sources = r
        .source_side
        .iter()
        .filter(|s| s.due)
        .map(|s| super::priority::Reason {
            level: super::priority::Level::Low,
            kind: "source_change".into(),
            text: format!("source-side change: `{}`", s.source),
        });
    onsets.chain(sources).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(stamp: usize, records: u64, counts: &[(&str, u64)]) -> SliceRun {
        SliceRun {
            stamp: format!("r{stamp:02}"),
            ts: 1_000 + stamp as i64,
            records,
            counts: counts.iter().map(|(k, v)| (k.to_string(), *v)).collect(),
            examples: counts
                .iter()
                .filter(|(_, v)| *v > 0)
                .map(|(k, _)| (k.to_string(), vec![format!("{k}-{stamp}")]))
                .collect(),
        }
    }

    fn one(source: &str, r: SliceRun) -> BTreeMap<String, SliceRun> {
        BTreeMap::from([(source.to_string(), r)])
    }

    /// A multi-run replay: a quiet source, then a swarm on one new template
    /// that hits one rule a little more, a few records a run.
    #[test]
    fn replay_finds_a_sub_threshold_onset_and_throttles_it() {
        let mut h = OnsetHistory::default();
        let quiet = [("rule:a", 2), ("rule:b", 5), ("family:x.example", 3)];
        for i in 0..10 {
            let r = h.observe("v1", one("s", run(i, 120, &quiet)));
            assert!(r.onsets.is_empty() && r.source_side.is_empty(), "run {i}");
        }
        let swarm = [
            ("rule:a", 6),
            ("rule:b", 5),
            ("family:x.example", 3),
            ("scaffold:relay.jina | /w/w.php ? q=payload&uqtag=w3", 4),
        ];
        let mut due = Vec::new();
        let mut a_rose = false;
        for i in 10..20 {
            let r = h.observe("v1", one("s", run(i, 120, &swarm)));
            assert!(r.source_side.is_empty(), "run {i}");
            let o = r
                .onsets
                .iter()
                .find(|o| o.slice.starts_with("scaffold:"))
                .unwrap_or_else(|| panic!("run {i}: {:?}", r.onsets));
            assert_eq!(o.since, "r10");
            assert_eq!(o.change.base_count, 0);
            assert!(o.examples.contains(&format!("{}-{i}", o.slice)), "{o:?}");
            if o.due {
                due.push(o.streak);
            }
            // The rule the swarm lifts from 2 to 6 a run rises a run or two
            // later; the rule it leaves alone never does.
            a_rose |= r.rule_rising("s", "a");
            assert!(!r.rule_rising("s", "b"));
            if i == 10 {
                let line = o.line();
                assert!(line.contains("scaffold `relay.jina"), "{line}");
                assert!(line.contains("since run r10"), "{line}");
                let sec = section(&r);
                assert!(sec.contains("## Slice onsets ("), "{sec}");
                assert_eq!(priority_reasons(&r).len(), r.onsets.len());
            }
            // Once the rise fills the window it is the baseline: it stops.
            if o.streak >= 6 {
                break;
            }
        }
        assert_eq!(due, [1, 2, 4]);
        assert!(a_rose);
    }

    /// The same replay through the analysis: each run's records are analysed
    /// as the watch does, and only the records new in that run are counted.
    #[test]
    fn replay_through_the_analysis() {
        let rules = sc_core::Rules::default_rules();
        let mut h = OnsetHistory::default();
        let mut first = None;
        for i in 0..14u32 {
            let mut obs: Vec<sc_core::Observation> = (0..60)
                .map(|j| sc_core::Observation {
                    id: format!("plain-{i}-{j}"),
                    url: format!("https://site{j}.example/page/{i}"),
                    ..Default::default()
                })
                .collect();
            // From run 9 on, a few relayed probes a run at one new site:
            // too few to cluster above noise, enough to change a count.
            if i >= 9 {
                obs.extend((0..3).map(|j| sc_core::Observation {
                    id: format!("probe-{i}-{j}"),
                    url: format!(
                        "https://r.jina.ai/https://shop.victim.example/item?id={j}'%20OR%201=1--"
                    ),
                    ..Default::default()
                }));
            }
            let ids: BTreeSet<String> = obs.iter().map(|o| o.id.clone()).collect();
            let a = sc_core::analyze(obs, &rules);
            let run = SliceRun::from_analysis(&a, &ids, &format!("r{i:02}"), 1_000 + i as i64);
            assert_eq!(run.records, ids.len() as u64);
            let r = h.observe(&a.rules_version, one("s", run));
            if i < 9 {
                assert!(r.onsets.is_empty(), "run {i}: {:?}", r.onsets);
            }
            if first.is_none() && !r.onsets.is_empty() {
                first = Some((i, r));
            }
        }
        let (i, r) = first.expect("an onset");
        assert!(i <= 10, "found at run {i}");
        assert!(r.source_side.is_empty());
        let fam = r
            .onsets
            .iter()
            .find(|o| o.slice == "family:victim.example")
            .unwrap_or_else(|| panic!("{:?}", r.onsets));
        assert_eq!(fam.since, "r09");
        assert!(fam.examples.iter().all(|e| e.starts_with("probe-")));
        assert!(section(&r).contains("site family `victim[.]example`"));
    }

    #[test]
    fn a_source_that_changes_as_a_whole_is_not_an_onset() {
        let mut h = OnsetHistory::default();
        let quiet = [("rule:a", 2), ("rule:b", 3), ("rule:c", 2), ("family:x", 4)];
        for i in 0..8 {
            h.observe("v1", one("s", run(i, 100, &quiet)));
        }
        // A new crawl: the same number of records, every slice up.
        let r = h.observe(
            "v1",
            one(
                "s",
                run(
                    8,
                    100,
                    &[
                        ("rule:a", 12),
                        ("rule:b", 15),
                        ("rule:c", 10),
                        ("family:x", 20),
                    ],
                ),
            ),
        );
        assert!(r.onsets.is_empty(), "{:?}", r.onsets);
        assert_eq!(r.source_side.len(), 1);
        assert!(r.source_changed("s"));
        assert!(r.due());
        assert!(r.source_side[0].line().contains("4 of its 4 established"));
    }

    #[test]
    fn more_rows_are_not_an_onset_and_volume_is_noted() {
        let mut h = OnsetHistory::default();
        for i in 0..8 {
            h.observe("v1", one("s", run(i, 100, &[("rule:a", 2)])));
        }
        let r = h.observe("v1", one("s", run(8, 1000, &[("rule:a", 21)])));
        assert!(r.onsets.is_empty(), "{:?}", r.onsets);
        // A new slice in a run that also grew is reported, with the volume.
        let r = h.observe(
            "v1",
            one("s", run(9, 1000, &[("rule:a", 20), ("rule:new", 9)])),
        );
        assert_eq!(r.onsets.len(), 1, "{:?}", r.onsets);
        assert_eq!(r.onsets[0].volume, Some((1000, 100)));
        assert!(r.onsets[0].line().contains("source-side change too"));
    }

    #[test]
    fn cold_start_rules_change_and_retention() {
        let mut h = OnsetHistory::default();
        for i in 0..3 {
            let r = h.observe("v1", one("s", run(i, 100, &[("rule:a", 20 * i as u64)])));
            assert!(r.onsets.is_empty(), "cold start");
        }
        // A source with no records this run is not checked or added.
        h.observe("v1", one("s", run(3, 0, &[])));
        assert_eq!(h.sources["s"].runs.len(), 3);
        let r = h.observe("v2", one("s", run(4, 100, &[])));
        assert!(r.restarted && r.onsets.is_empty());
        assert!(section(&r).contains("restarts"));
        assert_eq!(h.sources["s"].runs.len(), 1);
        for i in 5..30 {
            h.observe("v2", one("s", run(i, 100, &[])));
        }
        assert_eq!(h.sources["s"].runs.len(), HISTORY);
        assert_eq!(h.prune(1_020), 6);
        assert_eq!(h.prune(10_000), 10);
        assert!(h.sources.is_empty());
    }

    #[test]
    fn slice_runs_are_bounded() {
        let mut r = SliceRun::default();
        for i in 0..(MAX_SLICES + 50) {
            r.counts.insert(format!("rule:{i:04}"), 1 + (i % 7) as u64);
            r.examples.insert(format!("rule:{i:04}"), vec!["x".into()]);
        }
        r.bound();
        assert_eq!(r.counts.len(), MAX_SLICES);
        assert_eq!(r.examples.len(), MAX_SLICES);
        assert!(r.counts.values().all(|&n| n >= 2), "the smallest go first");
    }

    #[test]
    fn labels_defang_hosts() {
        let o = Onset {
            source: "s".into(),
            slice: "family:a.example".into(),
            change: ChangePoint {
                onset: 0,
                base_count: 0,
                base_exposure: 100,
                new_count: 4,
                new_exposure: 50,
                score: 4.0,
            },
            since: "r1".into(),
            examples: vec!["wellknown:b.example".into()],
            streak: 1,
            due: true,
            volume: None,
        };
        let line = o.line();
        assert!(line.contains("site family `a[.]example`"), "{line}");
        assert!(line.contains("`wellknown:b[.]example`"), "{line}");
        assert!(!line.contains("a.example"), "{line}");
    }
}
