//! Change points in per-run counts: a swarm starting below the clustering
//! threshold.
//!
//! Some swarms never cluster above noise: one agent per tag, a few records a
//! run, each below tier. What they do change is a count. A slice of the
//! watch's new records (a source and a rule, a source and a scaffold
//! template, a source and a target site family) that fired on a handful of
//! records a run starts firing on more, and goes on doing so.
//!
//! [`detect`] reads one slice's per-run counts, each against the run's
//! exposure (the records the source returned that run), with a one-sided
//! Poisson CUSUM: each run adds `k ln r - n p0 (r - 1)`, the log likelihood
//! ratio of a rate `r` times the baseline `p0` against the baseline, and the
//! sum restarts at zero whenever it falls below. The baseline is the pooled
//! rate over the older runs; the CUSUM runs over the newest ones. A source
//! that simply returned more rows raises `n` and the expected count with it,
//! so it is not an onset. Too little history is no alarm.
//!
//! When most of a source's established slices rise together, the cause is
//! the source (pagination, a new crawl, a collapse that recovered), not a
//! swarm: [`source_wide`] says so, and the caller reports one source-side
//! change instead of an onset per slice.
//!
//! No I/O; the watch keeps the history and decides what to report.

use crate::analyze::ObsResult;
use serde::{Deserialize, Serialize};

/// One run of one slice: the records the source returned, and how many of
/// them fell in the slice.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Bin {
    pub exposure: u64,
    pub count: u64,
}

/// Detector settings. [`Params::default`] is what the watch uses.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Params {
    /// The rate ratio the CUSUM is tuned to detect.
    pub ratio: f64,
    /// The CUSUM value that raises an alarm.
    pub threshold: f64,
    /// Older runs needed before the baseline is trusted…
    pub min_base_runs: usize,
    /// …and records over them.
    pub min_base_exposure: u64,
    /// Newest runs the CUSUM reads; the runs before them are the baseline.
    pub max_recent: usize,
    /// Records in the slice since the onset before it alarms.
    pub min_count: u64,
    /// The rate since the onset must be at least this multiple of the
    /// baseline's, whatever the CUSUM says.
    pub min_rise: f64,
}

impl Default for Params {
    fn default() -> Self {
        Params {
            ratio: 3.0,
            threshold: 4.0,
            min_base_runs: 3,
            min_base_exposure: 100,
            max_recent: 6,
            min_count: 3,
            min_rise: 2.0,
        }
    }
}

/// An upward change point in one slice.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ChangePoint {
    /// Index of the run the rise started in (into the bins given).
    pub onset: usize,
    /// Records in the slice, and records the source returned, over the
    /// baseline runs.
    pub base_count: u64,
    pub base_exposure: u64,
    /// The same, from the onset to the newest run.
    pub new_count: u64,
    pub new_exposure: u64,
    /// The CUSUM at the newest run.
    pub score: f64,
}

impl ChangePoint {
    /// Slice records per source record over the baseline runs.
    pub fn base_rate(&self) -> f64 {
        self.base_count as f64 / self.base_exposure.max(1) as f64
    }

    /// Slice records per source record since the onset.
    pub fn new_rate(&self) -> f64 {
        self.new_count as f64 / self.new_exposure.max(1) as f64
    }
}

/// The baseline runs' and the newest runs' split of `bins` (oldest first):
/// at most `max_recent` newest, at least `min_base_runs` older. `None` when
/// there are too few runs for both.
fn split(bins: &[Bin], p: &Params) -> Option<usize> {
    let recent = bins
        .len()
        .checked_sub(p.min_base_runs)?
        .min(p.max_recent.max(1));
    (recent > 0).then(|| bins.len() - recent)
}

/// The baseline count and exposure of `bins` (oldest first, the newest run
/// last), or `None` on a cold start.
pub fn baseline(bins: &[Bin], p: &Params) -> Option<(u64, u64)> {
    let at = split(bins, p)?;
    let (k, n) = bins[..at]
        .iter()
        .fold((0, 0), |(k, n), b| (k + b.count, n + b.exposure));
    (n >= p.min_base_exposure).then_some((k, n))
}

/// Whether the slice's rate rose, as of the newest run: the CUSUM over the
/// newest runs against the older runs' pooled rate stands at or above the
/// threshold. `bins` are oldest first, one per run the source returned
/// records in; runs with no exposure carry nothing and are skipped.
pub fn detect(bins: &[Bin], p: &Params) -> Option<ChangePoint> {
    let bins: Vec<Bin> = bins.iter().copied().filter(|b| b.exposure > 0).collect();
    let at = split(&bins, p)?;
    let (base_count, base_exposure) = baseline(&bins, p)?;
    // Half a record of prior keeps a slice the baseline never saw finite.
    let p0 = (base_count as f64 + 0.5) / base_exposure as f64;
    let (lr, drift) = (p.ratio.ln(), p.ratio - 1.0);
    let mut s = 0.0f64;
    let mut start = at;
    for (i, b) in bins.iter().enumerate().skip(at) {
        let next = s + b.count as f64 * lr - b.exposure as f64 * p0 * drift;
        if next <= 0.0 {
            s = 0.0;
            start = i + 1;
        } else {
            if s == 0.0 {
                start = i;
            }
            s = next;
        }
    }
    if s < p.threshold || start >= bins.len() {
        return None;
    }
    let (new_count, new_exposure) = bins[start..]
        .iter()
        .fold((0, 0), |(k, n), b| (k + b.count, n + b.exposure));
    let cp = ChangePoint {
        onset: start,
        base_count,
        base_exposure,
        new_count,
        new_exposure,
        score: s,
    };
    (new_count >= p.min_count && cp.new_rate() >= p.min_rise * p0).then_some(cp)
}

/// Established slices (ones the baseline saw) needed in alarm, and the share
/// of them, before a rise reads as the source's own change.
const SOURCE_MIN_SLICES: usize = 3;
const SOURCE_SHARE: f64 = 0.6;

/// Whether `rising` of a source's `established` slices rising together is
/// the source changing (pagination, a new crawl, a recovery) rather than a
/// swarm: a swarm adds slices of its own and lifts a few others, while a
/// source change lifts most of what was already there.
pub fn source_wide(rising: usize, established: usize) -> bool {
    rising >= SOURCE_MIN_SLICES && rising as f64 >= SOURCE_SHARE * established as f64
}

/// The slices of one record: `rule:<id>` per rule it hit, and, for a flagged
/// record, `scaffold:<template>` when its request structure is specific and
/// `family:<site>` for its target's registrable-looking part. An unflagged
/// record has none, so the history stays the size of what the rules see.
pub fn slices(r: &ObsResult) -> Vec<String> {
    if r.hits.is_empty() {
        return Vec::new();
    }
    let mut out: Vec<String> = r
        .hits
        .iter()
        .map(|h| format!("rule:{}", h.rule_id))
        .collect();
    out.sort();
    out.dedup();
    let t = crate::scaffold::template(r);
    if t.specificity >= MIN_TEMPLATE_SPECIFICITY {
        out.push(format!(
            "scaffold:{}",
            t.key.chars().take(MAX_KEY).collect::<String>()
        ));
    }
    if let Some(h) = r.target_host.as_deref().filter(|h| !h.is_empty()) {
        out.push(format!("family:{}", site_family(&h.to_ascii_lowercase())));
    }
    out
}

/// Structural parts a template needs before it is its own slice: below
/// this, every plain request shares one template.
const MIN_TEMPLATE_SPECIFICITY: usize = 2;
/// Characters kept of a template key.
const MAX_KEY: usize = 160;

/// The registrable-looking part of a host: its last two labels.
fn site_family(host: &str) -> &str {
    let mut dots = host.rmatch_indices('.');
    dots.next();
    match dots.next() {
        Some((i, _)) => &host[i + 1..],
        None => host,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bins(spec: &[(u64, u64)]) -> Vec<Bin> {
        spec.iter()
            .map(|&(exposure, count)| Bin { exposure, count })
            .collect()
    }

    fn flat(runs: usize, exposure: u64, count: u64) -> Vec<(u64, u64)> {
        vec![(exposure, count); runs]
    }

    #[test]
    fn a_step_up_alarms_at_its_run() {
        let p = Params::default();
        let mut s = flat(8, 100, 1);
        assert_eq!(detect(&bins(&s), &p), None, "a steady rate");
        s.push((100, 6));
        let cp = detect(&bins(&s), &p).expect("step");
        assert_eq!(cp.onset, 8);
        // Nine runs: the newest six are read, the oldest three are the baseline.
        assert_eq!((cp.base_count, cp.base_exposure), (3, 300));
        assert_eq!((cp.new_count, cp.new_exposure), (6, 100));
        assert!(cp.new_rate() > 5.0 * cp.base_rate(), "{cp:?}");
        // It keeps alarming while the rate stays up, from the same onset.
        s.push((100, 5));
        assert_eq!(detect(&bins(&s), &p).unwrap().onset, 8);
    }

    #[test]
    fn a_slice_the_baseline_never_saw() {
        let p = Params::default();
        let mut s = flat(5, 80, 0);
        s.push((80, 2));
        assert_eq!(detect(&bins(&s), &p), None, "two records are not enough");
        s.push((80, 3));
        let cp = detect(&bins(&s), &p).expect("new slice");
        assert_eq!((cp.onset, cp.new_count), (5, 5));
        assert_eq!(cp.base_count, 0);
    }

    #[test]
    fn a_slow_ramp_alarms_before_it_ends() {
        let p = Params::default();
        let mut s = flat(10, 100, 1);
        let mut fired = None;
        for (i, k) in [2, 2, 3, 3, 4, 4, 5].into_iter().enumerate() {
            s.push((100, k));
            if let Some(cp) = detect(&bins(&s), &p) {
                fired = Some((i, cp));
                break;
            }
        }
        let (i, cp) = fired.expect("ramp");
        assert!(i <= 5, "fired at ramp step {i}");
        assert!(cp.onset >= 10, "{cp:?}");
    }

    #[test]
    fn more_rows_at_the_same_rate_is_not_an_onset() {
        let p = Params::default();
        let mut s = flat(8, 100, 2);
        // The source returns ten times as many records, at the same rate.
        s.push((1000, 22));
        s.push((1000, 19));
        assert_eq!(detect(&bins(&s), &p), None);
        // And fewer records at the same rate is no onset either.
        let mut s = flat(8, 1000, 20);
        s.push((50, 2));
        assert_eq!(detect(&bins(&s), &p), None);
    }

    #[test]
    fn cold_start_never_alarms() {
        let p = Params::default();
        assert_eq!(detect(&[], &p), None);
        assert_eq!(detect(&bins(&[(100, 0), (100, 0), (100, 40)]), &p), None);
        // Enough runs, too few records under them.
        assert_eq!(
            detect(&bins(&[(10, 0), (10, 0), (10, 0), (10, 9)]), &p),
            None
        );
        assert_eq!(
            detect(&bins(&[(40, 0), (40, 0), (40, 0), (40, 9)]), &p)
                .unwrap()
                .onset,
            3
        );
        // Runs with no records carry nothing.
        assert_eq!(
            detect(
                &bins(&[(40, 0), (0, 0), (40, 0), (40, 0), (0, 0), (40, 9)]),
                &p
            )
            .unwrap()
            .onset,
            3
        );
    }

    #[test]
    fn a_rise_that_ended_falls_out() {
        let p = Params::default();
        let mut s = flat(6, 100, 3);
        s.push((100, 12));
        assert!(detect(&bins(&s), &p).is_some());
        for _ in 0..3 {
            s.push((100, 0));
        }
        assert_eq!(detect(&bins(&s), &p), None);
    }

    #[test]
    fn source_wide_needs_most_established_slices() {
        assert!(source_wide(3, 4));
        assert!(source_wide(6, 10));
        assert!(!source_wide(2, 2), "too few to tell");
        assert!(!source_wide(3, 12));
    }

    #[test]
    fn site_family_keeps_the_last_two_labels() {
        assert_eq!(site_family("a.b.example.org"), "example.org");
        assert_eq!(site_family("localhost"), "localhost");
    }

    #[test]
    fn slices_of_a_flagged_record() {
        let rules = crate::Rules::default_rules();
        let obs = vec![crate::Observation {
            id: "x".into(),
            url: "https://r.jina.ai/https://shop.a.example/?q=1'%20OR%201=1--&p=1'%20OR%201=1--"
                .into(),
            ..Default::default()
        }];
        let a = crate::analyze(obs, &rules);
        let s = slices(&a.results[0]);
        assert!(s.iter().any(|k| k.starts_with("rule:")), "{s:?}");
        assert!(s.contains(&"family:a.example".to_string()), "{s:?}");
        let plain = crate::analyze(
            vec![crate::Observation {
                id: "y".into(),
                url: "https://a.example/".into(),
                ..Default::default()
            }],
            &rules,
        );
        assert!(slices(&plain.results[0]).is_empty());
    }
}
