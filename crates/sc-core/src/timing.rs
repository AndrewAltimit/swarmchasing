//! Timing analysis: cadence, bursts, fleet-wide pauses, the hour-of-day
//! rhythm, pauses shared by unlinked clusters, and what date tags the agents
//! put in URLs say: the operator's UTC offset, or a model with no clock
//! writing a stale "today".

use crate::rules::Linking;
use chrono::{DateTime, NaiveDate};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Span {
    pub start: i64,
    pub end: i64,
    pub count: usize,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TimingStats {
    pub count: usize,
    pub start: i64,
    pub end: i64,
    pub median_gap_secs: Option<f64>,
    pub p90_gap_secs: Option<f64>,
    pub bursts: Vec<Span>,
    /// Longest silent gaps, longest first. `count` is unused (0).
    pub pauses: Vec<Span>,
    /// (hour start, count) for every hour between start and end, including empty hours.
    pub hourly: Vec<(i64, usize)>,
    #[serde(default)]
    pub rhythm: Rhythm,
    /// Date tags far behind or ahead of when the records were seen. Filled
    /// by the caller from the records' tags (see [`stale_dates`]); `timing`
    /// sees only timestamps and leaves it empty.
    #[serde(default)]
    pub stale_dates: StaleDates,
}

/// A rhythm needs records on at least this many distinct UTC days.
pub const RHYTHM_MIN_DAYS: usize = 3;
/// ... and at least this many records.
pub const RHYTHM_MIN_RECORDS: usize = 20;
/// ... and activity in at least this many distinct clock hours (day + hour).
pub const RHYTHM_MIN_ACTIVE_HOURS: usize = 12;
/// Share of active hours the busiest window of the day must hold.
pub const RHYTHM_WINDOW_SHARE: f64 = 0.9;
/// A window of at most this many hours reads as a working day.
pub const DAYTIME_MAX_HOURS: usize = 12;
/// A window of at least this many hours, with entropy at least
/// `ROUND_THE_CLOCK_MIN_ENTROPY`, reads as round the clock.
pub const ROUND_THE_CLOCK_MIN_HOURS: usize = 20;
pub const ROUND_THE_CLOCK_MIN_ENTROPY: f64 = 0.85;
/// Local hour assumed to sit in the middle of a working day (09:00–17:00).
pub const LOCAL_MIDDAY: f64 = 13.0;

/// What the hour-of-day profile looks like.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum RhythmVerdict {
    /// Too few days, records or active hours to say.
    #[default]
    TooShort,
    /// Activity spread over (nearly) every hour of the day.
    RoundTheClock,
    /// Activity confined to one window of the UTC day, like one time zone's
    /// working day. `utc_offset_guess` puts the window's middle at
    /// `LOCAL_MIDDAY` local time.
    Daytime {
        utc_offset_guess: i32,
        /// First UTC hour of the window and its width in hours.
        start_hour: u8,
        hours: u8,
    },
    /// Enough data, but neither pattern.
    Unclear,
}

/// Hour-of-day profile. People sleep; agent fleets can run around the clock.
/// Counts are distinct active clock hours, not records, so one burst does
/// not outweigh a day of steady activity. Descriptive: it changes no scores.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Rhythm {
    /// Per UTC hour of day: on how many days that hour saw activity.
    pub hours: [usize; 24],
    /// Shannon entropy of `hours`, normalised to 0..1 (1 = uniform).
    pub entropy: f64,
    /// Longest gap between consecutive records, in hours.
    pub longest_idle_hours: f64,
    /// Distinct UTC days with records.
    pub days: usize,
    pub verdict: RhythmVerdict,
}

/// `t` must be sorted, all > 0.
fn rhythm(t: &[i64]) -> Rhythm {
    let cells: BTreeSet<i64> = t.iter().map(|x| x.div_euclid(3600)).collect();
    let days: BTreeSet<i64> = t.iter().map(|x| x.div_euclid(86400)).collect();
    let mut hours = [0usize; 24];
    for c in &cells {
        hours[c.rem_euclid(24) as usize] += 1;
    }
    let total = cells.len();
    let entropy = if total > 0 {
        -hours
            .iter()
            .filter(|&&n| n > 0)
            .map(|&n| {
                let p = n as f64 / total as f64;
                p * p.ln()
            })
            .sum::<f64>()
            / 24f64.ln()
    } else {
        0.0
    };
    let longest_idle_hours = t.windows(2).map(|w| w[1] - w[0]).max().unwrap_or(0) as f64 / 3600.0;
    let verdict = if days.len() < RHYTHM_MIN_DAYS
        || t.len() < RHYTHM_MIN_RECORDS
        || total < RHYTHM_MIN_ACTIVE_HOURS
    {
        RhythmVerdict::TooShort
    } else {
        // Narrowest circular window holding the required share.
        let need = (total as f64 * RHYTHM_WINDOW_SHARE).ceil() as usize;
        let (width, start) = (1..=24)
            .find_map(|w| {
                (0..24)
                    .filter(|s| (0..w).map(|i| hours[(s + i) % 24]).sum::<usize>() >= need)
                    .max_by_key(|s| (0..w).map(|i| hours[(s + i) % 24]).sum::<usize>())
                    .map(|s| (w, s))
            })
            .unwrap_or((24, 0));
        if width <= DAYTIME_MAX_HOURS {
            let middle = start as f64 + width as f64 / 2.0;
            let offset = (LOCAL_MIDDAY - middle).round() as i32;
            RhythmVerdict::Daytime {
                // Into -11..=12.
                utc_offset_guess: (offset + 11).rem_euclid(24) - 11,
                start_hour: start as u8,
                hours: width as u8,
            }
        } else if width >= ROUND_THE_CLOCK_MIN_HOURS && entropy >= ROUND_THE_CLOCK_MIN_ENTROPY {
            RhythmVerdict::RoundTheClock
        } else {
            RhythmVerdict::Unclear
        }
    };
    Rhythm {
        hours,
        entropy,
        longest_idle_hours,
        days: days.len(),
        verdict,
    }
}

fn quantile(sorted: &[f64], q: f64) -> Option<f64> {
    if sorted.is_empty() {
        return None;
    }
    let idx = ((sorted.len() - 1) as f64 * q).round() as usize;
    Some(sorted[idx])
}

/// Silent gaps between consecutive records in sorted `t`, in time order: at
/// least `pause_min_secs` and at least ten times the median gap, so a slow
/// but steady cadence does not read as a string of pauses.
fn pause_spans(t: &[i64], median_gap: Option<f64>, pause_min_secs: i64) -> Vec<Span> {
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
    t.sort_unstable();
    if t.is_empty() {
        return TimingStats::default();
    }
    let gaps: Vec<i64> = t.windows(2).map(|w| w[1] - w[0]).collect();
    let mut sorted: Vec<f64> = gaps.iter().map(|&g| g as f64).collect();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());
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
    pauses.sort_by_key(|p| std::cmp::Reverse(p.end - p.start));
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
    ev.sort_by(|a, b| a.0.cmp(&b.0).then(b.1.cmp(&a.1)));
    let (mut cur, mut best) = (0i32, 0i32);
    for (_, d) in ev {
        cur += d;
        best = best.max(cur);
    }
    best as usize
}

/// What date tags in URLs (e.g. `archive_test=20261004`) say about the
/// operator's clock. If tags run a day ahead of UTC late in the UTC day, the
/// operator is east of UTC; the range below is every offset consistent with
/// all tagged observations.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DateTagOffset {
    pub tagged: usize,
    pub ahead: usize,
    pub same: usize,
    pub behind: usize,
    /// Offset range in hours, if the observations agree.
    pub min_hours: Option<f64>,
    pub max_hours: Option<f64>,
    pub consistent: bool,
}

pub fn parse_date_tag(v: &str) -> Option<NaiveDate> {
    let v = v.trim();
    let d = if v.len() == 8 && v.bytes().all(|b| b.is_ascii_digit()) {
        NaiveDate::parse_from_str(v, "%Y%m%d").ok()?
    } else if v.len() == 10 {
        NaiveDate::parse_from_str(v, "%Y-%m-%d").ok()?
    } else {
        return None;
    };
    // Only plausible "today" tags.
    (2020..=2100)
        .contains(&chrono::Datelike::year(&d))
        .then_some(d)
}

/// `samples`: (unix ts, date tag found in that observation).
pub fn infer_offset(samples: &[(i64, NaiveDate)]) -> DateTagOffset {
    let mut out = DateTagOffset::default();
    let (mut lo, mut hi) = (-12.0f64, 14.0f64);
    for &(ts, tag) in samples {
        let Some(dt) = DateTime::from_timestamp(ts, 0) else {
            continue;
        };
        let diff = (tag - dt.date_naive()).num_days();
        let h = (ts.rem_euclid(86400)) as f64 / 3600.0;
        match diff {
            1 => {
                out.ahead += 1;
                lo = lo.max(24.0 - h);
            }
            0 => {
                out.same += 1;
                lo = lo.max(-h);
                hi = hi.min(24.0 - h);
            }
            -1 => {
                out.behind += 1;
                hi = hi.min(-h);
            }
            _ => continue, // historic/future dates: not a "today" tag
        }
        out.tagged += 1;
    }
    out.consistent = out.tagged > 0 && lo <= hi;
    if out.consistent {
        out.min_hours = Some((lo * 4.0).ceil() / 4.0);
        out.max_hours = Some((hi * 4.0).floor() / 4.0);
    }
    out
}

/// A date tag at least this many days behind the UTC day it was seen is stale.
pub const STALE_MIN_DAYS: i64 = 7;
/// A tag at least this many days ahead counts as ahead. One day ahead is only
/// a time zone east of UTC (see [`infer_offset`]).
pub const AHEAD_MIN_DAYS: i64 = 2;
/// Stale tags needed before they read as a pattern rather than typos.
pub const STALE_MIN_TAGS: usize = 3;
/// Share of stale tags that must name one date, or lag by about one amount.
pub const STALE_AGREE_SHARE: f64 = 0.6;

/// Date tags that do not name the day they were seen. An agent with no clock
/// that writes "today" into a URL writes the date it believes it is, often
/// one from its training data, so tags that consistently name a date months
/// back hint at a model with no clock tool. Descriptive: it changes no scores
/// and links nothing.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct StaleDates {
    /// Records with a date tag and a known timestamp.
    pub tags: usize,
    /// Tags at least `STALE_MIN_DAYS` behind the UTC day they were seen.
    pub behind: usize,
    /// Tags at least `AHEAD_MIN_DAYS` ahead: a wrong clock, a time zone
    /// mistake or a typo, not a stale date.
    pub ahead: usize,
    /// Median lag of the stale tags, in days.
    pub median_lag_days: Option<i64>,
    /// The date the stale tags name most often (earliest on ties).
    pub modal_date: Option<NaiveDate>,
    /// Share of stale tags naming `modal_date`.
    pub same_date_share: f64,
    /// Share of stale tags within a day of the median lag.
    pub same_lag_share: f64,
    /// At least `STALE_MIN_TAGS` stale tags, at least half of all tags, and
    /// `STALE_AGREE_SHARE` of them naming one date or lagging by one amount.
    pub consistent: bool,
}

/// `samples`: (unix ts, date tag found in that observation), as for
/// [`infer_offset`]. Unknown timestamps (<= 0) are ignored.
pub fn stale_dates(samples: &[(i64, NaiveDate)]) -> StaleDates {
    let mut out = StaleDates::default();
    let mut stale: Vec<(i64, NaiveDate)> = Vec::new();
    for &(ts, tag) in samples {
        let Some(dt) = DateTime::from_timestamp(ts, 0).filter(|_| ts > 0) else {
            continue;
        };
        out.tags += 1;
        let lag = (dt.date_naive() - tag).num_days();
        if lag >= STALE_MIN_DAYS {
            stale.push((lag, tag));
        } else if -lag >= AHEAD_MIN_DAYS {
            out.ahead += 1;
        }
    }
    out.behind = stale.len();
    if stale.is_empty() {
        return out;
    }
    let mut lags: Vec<i64> = stale.iter().map(|s| s.0).collect();
    lags.sort_unstable();
    let median = lags[(lags.len() - 1) / 2];
    let mut by_date: BTreeMap<NaiveDate, usize> = BTreeMap::new();
    for &(_, d) in &stale {
        *by_date.entry(d).or_default() += 1;
    }
    // Earliest date among the most frequent.
    let (&date, &n) = by_date
        .iter()
        .max_by(|a, b| a.1.cmp(b.1).then(b.0.cmp(a.0)))
        .expect("non-empty");
    let near_median = lags.iter().filter(|&&l| (l - median).abs() <= 1).count();
    out.median_lag_days = Some(median);
    out.modal_date = Some(date);
    out.same_date_share = n as f64 / out.behind as f64;
    out.same_lag_share = near_median as f64 / out.behind as f64;
    out.consistent = out.behind >= STALE_MIN_TAGS
        && out.behind * 2 >= out.tags
        && out.same_date_share.max(out.same_lag_share) >= STALE_AGREE_SHARE;
    out
}

/// Pause starts, and pause ends, of two clusters must fall this close
/// together to match.
pub const SHARED_PAUSE_TOLERANCE_SECS: i64 = 120;
/// One matching pause at least this long can stand on its own.
pub const SHARED_PAUSE_LONG_SECS: i64 = 3 * 3600;
/// Otherwise at least this many matching pauses are needed.
pub const SHARED_PAUSE_MIN_MATCHES: usize = 2;
/// Either way, the matches must be at most this likely by chance.
pub const SHARED_PAUSE_MAX_CHANCE: f64 = 0.01;
/// A matching pause that starts or ends on a clock hour counts for this much
/// of a match: unrelated scheduled jobs stop and start on the hour together.
pub const SHARED_PAUSE_CLOCK_WEIGHT: f64 = 0.25;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SharedPauseOptions {
    /// Shortest gap that counts as a pause (also at least ten times the
    /// cluster's median gap, as in [`timing`]).
    pub pause_min_secs: i64,
    pub tolerance_secs: i64,
    pub min_matches: usize,
    pub long_pause_secs: i64,
    pub max_chance: f64,
    pub clock_weight: f64,
}

impl SharedPauseOptions {
    pub fn from_linking(cfg: &Linking) -> Self {
        Self {
            pause_min_secs: cfg.pause_min_secs,
            tolerance_secs: SHARED_PAUSE_TOLERANCE_SECS,
            min_matches: SHARED_PAUSE_MIN_MATCHES,
            long_pause_secs: SHARED_PAUSE_LONG_SECS,
            max_chance: SHARED_PAUSE_MAX_CHANCE,
            clock_weight: SHARED_PAUSE_CLOCK_WEIGHT,
        }
    }
}

impl Default for SharedPauseOptions {
    fn default() -> Self {
        Self::from_linking(&Linking::default())
    }
}

/// Two clusters that go quiet together: their pauses start and end within
/// the tolerance of each other. Evidence that one scheduler, quota or
/// operator may sit behind both. A link to check, never a merge.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SharedPause {
    pub a: String,
    pub b: String,
    /// Matching pauses as (a's, b's), in time order.
    pub pauses: Vec<(Span, Span)>,
    /// How many of `pauses` start or end on a clock hour.
    #[serde(default)]
    pub on_the_hour: usize,
    /// Matches expected if each cluster's pauses sat at random within the
    /// time both clusters were active.
    pub expected: f64,
    /// Chance of at least this many matches under that model (Poisson).
    pub p_chance: f64,
    pub reason: String,
}

/// `clusters`: (cluster id, record timestamps; unsorted is fine, <= 0
/// ignored). Clusters are distinct because they share no linking feature, so
/// every pair is a candidate. Pairs only; groups are their connected
/// components.
///
/// The chance model: a pause in one cluster matches a pause in the other only
/// if their durations differ by less than twice the tolerance, and then only
/// if its start falls in a window `2 * tolerance - |duration difference|`
/// wide. Summing that over all pause pairs, divided by the time both clusters
/// were active, gives the matches expected by chance; busy clusters with many
/// similar pauses expect many and need many more to qualify. Pauses on a
/// shared clock boundary (both crons stopping at midnight) are not random
/// under this model, so a match that starts or ends within the tolerance of a
/// clock hour counts as `clock_weight` of a match, and never qualifies alone
/// as a long pause.
pub fn shared_pauses(
    clusters: &[(String, Vec<i64>)],
    opts: &SharedPauseOptions,
) -> Vec<SharedPause> {
    let tol = opts.tolerance_secs.max(0);
    struct C<'a> {
        id: &'a str,
        start: i64,
        end: i64,
        pauses: Vec<Span>,
    }
    let cs: Vec<C> = clusters
        .iter()
        .filter_map(|(id, ts)| {
            let mut t: Vec<i64> = ts.iter().copied().filter(|&x| x > 0).collect();
            t.sort_unstable();
            let mut gaps: Vec<f64> = t.windows(2).map(|w| (w[1] - w[0]) as f64).collect();
            gaps.sort_by(|a, b| a.partial_cmp(b).unwrap());
            let pauses = pause_spans(&t, quantile(&gaps, 0.5), opts.pause_min_secs);
            (!pauses.is_empty()).then(|| C {
                id,
                start: t[0],
                end: t[t.len() - 1],
                pauses,
            })
        })
        .collect();

    let mut out = Vec::new();
    for (i, a) in cs.iter().enumerate() {
        for b in &cs[i + 1..] {
            let (lo, hi) = (a.start.max(b.start), a.end.min(b.end));
            if hi <= lo {
                continue;
            }
            let inside = |p: &&Span| p.start >= lo - tol && p.end <= hi + tol;
            let pa: Vec<&Span> = a.pauses.iter().filter(inside).collect();
            let pb: Vec<&Span> = b.pauses.iter().filter(inside).collect();

            let mut durs: Vec<i64> = pb.iter().map(|p| p.end - p.start).collect();
            durs.sort_unstable();
            let window = (hi - lo) as f64;
            let expected: f64 = pa
                .iter()
                .map(|p| {
                    let d = p.end - p.start;
                    let from = durs.partition_point(|&x| x < d - 2 * tol);
                    durs[from..]
                        .iter()
                        .take_while(|&&x| x <= d + 2 * tol)
                        .map(|&x| ((2 * tol - (x - d).abs()) as f64 / window).min(1.0))
                        .sum::<f64>()
                })
                .sum();

            // One-to-one, in time order (pauses are already time-ordered).
            let mut used = vec![false; pb.len()];
            let mut pairs = Vec::new();
            for p in &pa {
                if let Some(k) = (0..pb.len()).find(|&k| {
                    !used[k]
                        && (pb[k].start - p.start).abs() <= tol
                        && (pb[k].end - p.end).abs() <= tol
                }) {
                    used[k] = true;
                    pairs.push(((*p).clone(), pb[k].clone()));
                }
            }
            let m = pairs.len();
            if m == 0 {
                continue;
            }
            let hourly = |t: i64| {
                let r = t.rem_euclid(3600);
                r <= tol || r >= 3600 - tol
            };
            let clocked = |(x, _): &&(Span, Span)| hourly(x.start) || hourly(x.end);
            let on_the_hour = pairs.iter().filter(clocked).count();
            let weight = (m - on_the_hour) as f64 + on_the_hour as f64 * opts.clock_weight;
            let longest = pairs
                .iter()
                .filter(|p| !clocked(p))
                .map(|(x, y)| (x.end - x.start).min(y.end - y.start))
                .max()
                .unwrap_or(0);
            let p_chance = poisson_at_least(expected, weight.floor() as usize);
            if (weight < opts.min_matches as f64 && longest < opts.long_pause_secs)
                || p_chance > opts.max_chance
            {
                continue;
            }
            let clock_note = if on_the_hour > 0 {
                format!(
                    ", {on_the_hour} on a clock hour and counted at {:.0}%",
                    opts.clock_weight * 100.0
                )
            } else {
                String::new()
            };
            let reason = format!(
                "{m} pause(s) start and end within {tol} s of each other (longest {} min{clock_note}) with {expected:.2} expected by chance (p {p_chance:.1e}): one scheduler, quota or operator may sit behind both",
                longest / 60
            );
            out.push(SharedPause {
                a: a.id.to_string(),
                b: b.id.to_string(),
                pauses: pairs,
                on_the_hour,
                expected,
                p_chance,
                reason,
            });
        }
    }
    out
}

/// P(X >= m) for X ~ Poisson(lambda).
fn poisson_at_least(lambda: f64, m: usize) -> f64 {
    let (mut term, mut below) = ((-lambda).exp(), 0.0);
    for k in 0..m {
        below += term;
        term *= lambda / (k + 1) as f64;
    }
    (1.0 - below).clamp(0.0, 1.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bursts_and_pauses() {
        let mut ts: Vec<i64> = (0..10).map(|i| 1_000_000 + i * 44).collect();
        ts.extend((0..6).map(|i| 1_010_000 + i * 2));
        let s = timing(&ts, &Linking::default());
        assert_eq!(s.bursts.len(), 1);
        assert_eq!(s.bursts[0].count, 6);
        assert_eq!(s.pauses.len(), 1);
        assert_eq!(s.median_gap_secs, Some(44.0));
    }

    const DAY0: i64 = 1_791_072_000; // midnight UTC

    #[test]
    fn rhythm_round_the_clock() {
        // Every hour for four days, two records an hour.
        let ts: Vec<i64> = (0..96 * 2).map(|i| DAY0 + i * 1800 + 60).collect();
        let r = timing(&ts, &Linking::default()).rhythm;
        assert_eq!(r.days, 4);
        assert_eq!(r.hours, [4; 24]);
        assert!((r.entropy - 1.0).abs() < 1e-9, "{}", r.entropy);
        assert!((r.longest_idle_hours - 0.5).abs() < 1e-9);
        assert_eq!(r.verdict, RhythmVerdict::RoundTheClock);
    }

    #[test]
    fn rhythm_daytime_guesses_offset() {
        // 01:00–08:59 UTC on four days: a 09:00–17:00 working day at UTC+8.
        let ts: Vec<i64> = (0..4)
            .flat_map(|d| (1..9).map(move |h| DAY0 + d * 86400 + h * 3600 + 120))
            .collect();
        let r = timing(&ts, &Linking::default()).rhythm;
        assert_eq!(r.days, 4);
        assert!(r.longest_idle_hours > 14.0);
        assert!(r.entropy < 0.75, "{}", r.entropy);
        assert_eq!(
            r.verdict,
            RhythmVerdict::Daytime {
                utc_offset_guess: 8,
                start_hour: 1,
                hours: 8
            }
        );

        // The same working day at UTC-5 (14:00–21:59 UTC).
        let ts: Vec<i64> = (0..4)
            .flat_map(|d| (14..22).map(move |h| DAY0 + d * 86400 + h * 3600))
            .collect();
        let r = timing(&ts, &Linking::default()).rhythm;
        assert!(
            matches!(
                r.verdict,
                RhythmVerdict::Daytime {
                    utc_offset_guess: -5,
                    ..
                }
            ),
            "{r:?}"
        );
    }

    #[test]
    fn rhythm_too_short_or_unclear() {
        // Two days only.
        let ts: Vec<i64> = (0..48).map(|i| DAY0 + i * 3600).collect();
        assert_eq!(
            timing(&ts, &Linking::default()).rhythm.verdict,
            RhythmVerdict::TooShort
        );
        // One long burst on each of three days: many records, few active hours.
        let ts: Vec<i64> = (0..3)
            .flat_map(|d| (0..30).map(move |i| DAY0 + d * 86400 + 3600 * 3 + i * 10))
            .collect();
        assert_eq!(
            timing(&ts, &Linking::default()).rhythm.verdict,
            RhythmVerdict::TooShort
        );
        // Two shifts twelve hours apart: neither one working day nor all day.
        let ts: Vec<i64> = (0..4)
            .flat_map(|d| {
                [0, 1, 2, 3, 12, 13, 14, 15]
                    .into_iter()
                    .map(move |h| DAY0 + d * 86400 + h * 3600)
            })
            .collect();
        assert_eq!(
            timing(&ts, &Linking::default()).rhythm.verdict,
            RhythmVerdict::Unclear
        );
    }

    #[test]
    fn concurrency() {
        assert_eq!(max_concurrency(&[(1, 10), (5, 20), (9, 30), (25, 40)]), 3);
    }

    #[test]
    fn offset_utc8() {
        // 20:00 UTC on Oct 3 tagged Oct 4 -> at least UTC+4; 10:00 UTC Oct 4 tagged Oct 4 -> < UTC+14
        let d4 = NaiveDate::from_ymd_opt(2026, 10, 4).unwrap();
        let t1 = chrono::NaiveDateTime::parse_from_str("2026-10-03 17:00:00", "%Y-%m-%d %H:%M:%S")
            .unwrap()
            .and_utc()
            .timestamp();
        let t2 = chrono::NaiveDateTime::parse_from_str("2026-10-04 15:00:00", "%Y-%m-%d %H:%M:%S")
            .unwrap()
            .and_utc()
            .timestamp();
        let o = infer_offset(&[(t1, d4), (t2, d4)]);
        assert!(o.consistent);
        assert_eq!(o.min_hours, Some(7.0));
        assert_eq!(o.max_hours, Some(9.0));
    }

    fn ymd(y: i32, m: u32, d: u32) -> NaiveDate {
        NaiveDate::from_ymd_opt(y, m, d).unwrap()
    }

    #[test]
    fn stale_dates_same_training_era_date() {
        // Seen over a week in October 2026, every tag names 2024-01-15.
        let tag = ymd(2024, 1, 15);
        let samples: Vec<(i64, NaiveDate)> =
            (0..8).map(|d| (DAY0 + d * 86400 + 3600, tag)).collect();
        let s = stale_dates(&samples);
        assert_eq!((s.tags, s.behind, s.ahead), (8, 8, 0));
        assert_eq!(s.modal_date, Some(tag));
        assert!((s.same_date_share - 1.0).abs() < 1e-9);
        // Lags grow by a day each day, so few sit within a day of the median.
        assert!(s.same_lag_share < STALE_AGREE_SHARE, "{s:?}");
        let seen = DateTime::from_timestamp(DAY0, 0).unwrap().date_naive();
        assert_eq!(s.median_lag_days, Some((seen - tag).num_days() + 3));
        assert!(s.consistent);
    }

    #[test]
    fn stale_dates_same_lag() {
        // Each tag thirty days behind the day it was seen: one lag, many dates.
        let samples: Vec<(i64, NaiveDate)> = (0..5)
            .map(|d| {
                let ts = DAY0 + d * 86400 + 600;
                let seen = DateTime::from_timestamp(ts, 0).unwrap().date_naive();
                (ts, seen - chrono::Duration::days(30))
            })
            .collect();
        let s = stale_dates(&samples);
        assert_eq!(s.median_lag_days, Some(30));
        assert!((s.same_lag_share - 1.0).abs() < 1e-9);
        assert!((s.same_date_share - 0.2).abs() < 1e-9);
        assert!(s.consistent);
    }

    #[test]
    fn stale_dates_typos_and_correct_tags() {
        let seen = DateTime::from_timestamp(DAY0, 0).unwrap().date_naive();
        // Correct-date tags (and one a day off, a time zone): nothing stale.
        let mut samples: Vec<(i64, NaiveDate)> = (0..10).map(|i| (DAY0 + i * 60, seen)).collect();
        samples.push((DAY0 + 3600, seen + chrono::Duration::days(1)));
        samples.push((DAY0 + 7200, seen - chrono::Duration::days(1)));
        let s = stale_dates(&samples);
        assert_eq!((s.tags, s.behind, s.ahead), (12, 0, 0));
        assert!(!s.consistent);
        assert_eq!(s.median_lag_days, None);

        // One typo year among correct tags, one far-future tag.
        samples.push((DAY0 + 9000, seen - chrono::Duration::days(365)));
        samples.push((DAY0 + 9100, seen + chrono::Duration::days(30)));
        // An unknown timestamp is ignored.
        samples.push((0, ymd(2024, 1, 15)));
        let s = stale_dates(&samples);
        assert_eq!((s.tags, s.behind, s.ahead), (14, 1, 1));
        assert!(!s.consistent);

        // Three stale tags naming scattered dates with scattered lags.
        let s = stale_dates(&[
            (DAY0, ymd(2024, 1, 15)),
            (DAY0, ymd(2025, 3, 2)),
            (DAY0, ymd(2023, 7, 30)),
        ]);
        assert_eq!(s.behind, 3);
        assert!(!s.consistent, "{s:?}");
        // Stale tags but a minority of all tags.
        let mut mixed: Vec<(i64, NaiveDate)> =
            (0..3).map(|i| (DAY0 + i, ymd(2024, 1, 15))).collect();
        mixed.extend((0..4).map(|i| (DAY0 + 100 + i, seen)));
        assert!(!stale_dates(&mixed).consistent);
    }

    /// Records every `step` seconds over [from, to), except inside `gaps`.
    fn activity(from: i64, to: i64, step: i64, gaps: &[(i64, i64)]) -> Vec<i64> {
        (0..)
            .map(|i| from + i * step)
            .take_while(|&x| x < to)
            .filter(|&x| !gaps.iter().any(|&(s, e)| x > s && x < e))
            .collect()
    }

    #[test]
    fn shared_pauses_found() {
        // Two clusters with different cadences, three days long, both silent
        // over the same two half-hour windows (to within a minute or two).
        let end = DAY0 + 3 * 86400;
        let a = activity(
            DAY0,
            end,
            45,
            &[
                (DAY0 + 30_000, DAY0 + 31_800),
                (DAY0 + 120_000, DAY0 + 122_000),
            ],
        );
        let b = activity(
            DAY0 + 7,
            end,
            70,
            &[
                (DAY0 + 30_030, DAY0 + 31_850),
                (DAY0 + 120_050, DAY0 + 121_950),
            ],
        );
        let c = activity(DAY0 + 3, end, 50, &[(DAY0 + 60_000, DAY0 + 62_000)]);
        let out = shared_pauses(
            &[("C1".into(), a), ("C2".into(), b), ("C3".into(), c)],
            &SharedPauseOptions::default(),
        );
        assert_eq!(out.len(), 1, "{out:?}");
        assert_eq!((out[0].a.as_str(), out[0].b.as_str()), ("C1", "C2"));
        assert_eq!(out[0].pauses.len(), 2);
        assert!(out[0].expected < 0.01, "{}", out[0].expected);
        assert!(out[0].reason.contains("2 pause(s)"));
    }

    #[test]
    fn shared_pauses_on_the_hour_count_less() {
        // Two crons that both stop at the top of the hour, twice, and once for
        // four hours: matches by schedule, not by a shared operator.
        let end = DAY0 + 3 * 86400;
        let quiet = [
            (DAY0 + 9 * 3600, DAY0 + 10 * 3600 - 300),
            (DAY0 + 33 * 3600 + 30, DAY0 + 34 * 3600 - 400),
            (DAY0 + 50 * 3600, DAY0 + 54 * 3600),
        ];
        let a = activity(DAY0, end, 45, &quiet);
        let shifted: Vec<(i64, i64)> = quiet.iter().map(|&(x, y)| (x + 20, y - 15)).collect();
        let b = activity(DAY0 + 7, end, 70, &shifted);
        let groups = [("C1".to_string(), a), ("C2".to_string(), b)];
        assert!(
            shared_pauses(&groups, &SharedPauseOptions::default()).is_empty(),
            "on-the-hour pauses alone should not link"
        );
        // Counted in full, the same pauses would be reported.
        let full = SharedPauseOptions {
            clock_weight: 1.0,
            ..SharedPauseOptions::default()
        };
        let out = shared_pauses(&groups, &full);
        assert_eq!(out.len(), 1, "{out:?}");
        assert_eq!(out[0].on_the_hour, 3);
        assert!(
            out[0].reason.contains("on a clock hour"),
            "{}",
            out[0].reason
        );
    }

    #[test]
    fn shared_pauses_one_long_or_one_short() {
        let end = DAY0 + 2 * 86400;
        let long = (DAY0 + 40_000, DAY0 + 40_000 + 4 * 3600);
        let a = activity(DAY0, end, 60, &[long]);
        let b = activity(DAY0 + 11, end, 90, &[(long.0 + 40, long.1 - 30)]);
        let out = shared_pauses(
            &[("C1".into(), a), ("C2".into(), b)],
            &SharedPauseOptions::default(),
        );
        assert_eq!(out.len(), 1, "{out:?}");
        assert_eq!(out[0].pauses.len(), 1);

        // One shared twenty-minute pause alone is not enough.
        let short = (DAY0 + 40_000, DAY0 + 41_200);
        let a = activity(DAY0, end, 60, &[short]);
        let b = activity(DAY0 + 11, end, 90, &[(short.0 + 40, short.1 - 30)]);
        assert!(
            shared_pauses(
                &[("C1".into(), a), ("C2".into(), b)],
                &SharedPauseOptions::default()
            )
            .is_empty()
        );

        // Pauses that start together but end far apart do not match.
        let a = activity(DAY0, end, 60, &[long]);
        let b = activity(DAY0 + 11, end, 90, &[(long.0 + 40, long.1 + 1800)]);
        assert!(
            shared_pauses(
                &[("C1".into(), a), ("C2".into(), b)],
                &SharedPauseOptions::default()
            )
            .is_empty()
        );
    }

    #[test]
    fn shared_pauses_busy_clusters_by_chance() {
        // Two independent clusters, each alternating short bursts with
        // 10–14 minute silences for a day: hundreds of pauses of similar
        // length, so some line up by chance.
        fn busy(seed: u64) -> Vec<i64> {
            let mut x = seed;
            let mut next = |m: u64| {
                x = x
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                (x >> 33) % m
            };
            let mut t = DAY0;
            let mut out = Vec::new();
            while t < DAY0 + 86400 {
                for _ in 0..1 + next(4) {
                    out.push(t);
                    t += 20 + next(40) as i64;
                }
                t += 600 + next(240) as i64;
            }
            out
        }
        let (a, b) = (busy(1), busy(2));
        let opts = SharedPauseOptions::default();
        // The premise: chance alignments exist.
        let loose = SharedPauseOptions {
            max_chance: 1.0,
            ..opts.clone()
        };
        let raw = shared_pauses(
            &[("C1".into(), a.clone()), ("C2".into(), b.clone())],
            &loose,
        );
        assert!(raw.first().is_some_and(|s| s.pauses.len() >= 2), "{raw:?}");
        assert!(raw[0].expected > 1.0, "{}", raw[0].expected);
        // ... and none is flagged.
        assert!(shared_pauses(&[("C1".into(), a), ("C2".into(), b)], &opts).is_empty());
    }

    #[test]
    fn poisson_tail() {
        assert!((poisson_at_least(2.0, 0) - 1.0).abs() < 1e-12);
        assert!((poisson_at_least(2.0, 1) - (1.0 - (-2.0f64).exp())).abs() < 1e-12);
        assert!(poisson_at_least(0.001, 2) < 1e-6);
    }
}
