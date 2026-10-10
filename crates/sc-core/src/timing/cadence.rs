//! Cadence: gaps, bursts and pauses in a run of timestamps, and how many
//! runs were active at once.

use super::{Span, StaleDates, TimingStats, rhythm::rhythm};
use crate::rules::Linking;

pub(super) fn quantile(sorted: &[f64], q: f64) -> Option<f64> {
    if sorted.is_empty() {
        return None;
    }
    let idx = ((sorted.len() - 1) as f64 * q).round() as usize;
    Some(sorted[idx])
}

/// Silent gaps between consecutive records in sorted `t`, in time order: at
/// least `pause_min_secs` and at least ten times the median gap, so a slow
/// but steady cadence does not read as a string of pauses.
pub(super) fn pause_spans(t: &[i64], median_gap: Option<f64>, pause_min_secs: i64) -> Vec<Span> {
    let floor = (pause_min_secs as f64).max(median_gap.unwrap_or(0.0) * 10.0);
    t.windows(2)
        .filter(|w| (w[1] - w[0]) as f64 >= floor)
        .map(|w| Span {
            start: w[0],
            end: w[1],
            count: 0,
        })
        .collect()
}

/// `ts` need not be sorted. Unknown timestamps (<= 0) are ignored.
pub fn timing(ts: &[i64], cfg: &Linking) -> TimingStats {
    let mut t: Vec<i64> = ts.iter().copied().filter(|&x| x > 0).collect();
    crate::sort::sort(&mut t);
    if t.is_empty() {
        return TimingStats::default();
    }
    let gaps: Vec<i64> = t.windows(2).map(|w| w[1] - w[0]).collect();
    let mut sorted: Vec<f64> = gaps.iter().map(|&g| g as f64).collect();
    crate::sort::by(&mut sorted, |a, b| a.partial_cmp(b).unwrap());
    let median = quantile(&sorted, 0.5);

    let mut bursts = Vec::new();
    let mut i = 0;
    while i < t.len() {
        let mut j = i;
        while j + 1 < t.len() && t[j + 1] - t[j] <= cfg.burst_gap_secs {
            j += 1;
        }
        if j + 1 - i >= cfg.burst_min {
            bursts.push(Span {
                start: t[i],
                end: t[j],
                count: j + 1 - i,
            });
        }
        i = j + 1;
    }

    let mut pauses = pause_spans(&t, median, cfg.pause_min_secs);
    crate::sort::by_key(&mut pauses, |p| std::cmp::Reverse(p.end - p.start));
    pauses.truncate(20);

    let first_hour = t[0] - t[0].rem_euclid(3600);
    let last_hour = t[t.len() - 1] - t[t.len() - 1].rem_euclid(3600);
    let n_hours = ((last_hour - first_hour) / 3600 + 1).min(24 * 400) as usize;
    let mut hourly: Vec<(i64, usize)> = (0..n_hours)
        .map(|h| (first_hour + h as i64 * 3600, 0))
        .collect();
    for &x in &t {
        let h = ((x - first_hour) / 3600) as usize;
        if h < hourly.len() {
            hourly[h].1 += 1;
        }
    }

    TimingStats {
        count: t.len(),
        start: t[0],
        end: t[t.len() - 1],
        median_gap_secs: median,
        p90_gap_secs: quantile(&sorted, 0.9),
        bursts,
        pauses,
        hourly,
        rhythm: rhythm(&t),
        stale_dates: StaleDates::default(),
    }
}

/// Max number of intervals active at the same instant.
pub fn max_concurrency(intervals: &[(i64, i64)]) -> usize {
    let mut ev: Vec<(i64, i32)> = Vec::with_capacity(intervals.len() * 2);
    for &(s, e) in intervals {
        if s > 0 {
            ev.push((s, 1));
            ev.push((e.max(s), -1));
        }
    }
    // Starts before ends at the same instant, so touching intervals overlap.
    crate::sort::by(&mut ev, |a, b| a.0.cmp(&b.0).then(b.1.cmp(&a.1)));
    let (mut cur, mut best) = (0i32, 0i32);
    for (_, d) in ev {
        cur += d;
        best = best.max(cur);
    }
    best as usize
}
