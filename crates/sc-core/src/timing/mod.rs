//! Timing analysis: cadence, bursts, fleet-wide pauses, the hour-of-day
//! rhythm, pauses shared by unlinked clusters, and what date tags the agents
//! put in URLs say: the operator's UTC offset, or a model with no clock
//! writing a stale "today".

mod cadence;
mod dates;
mod pauses;
mod rhythm;

pub use cadence::*;
pub use dates::*;
pub use pauses::*;
pub use rhythm::*;

use crate::model::TsKind;
use serde::{Deserialize, Serialize};

/// What a set of records' timestamps measure, from their `ts_kind`s.
/// Pace, fan-out and rhythm read request timing: they skip capture times
/// (when an archive saved a URL, not when anyone requested it) and say so
/// for submit times (when a URL reached a scan service, close to the
/// request but not the same).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TimeBasis {
    /// Request times (access logs, operator logs).
    Request,
    /// Scan-service submit times.
    Submit,
    /// Archive capture times.
    Capture,
    /// Capture times alongside request or submit times.
    Mixed,
    /// No record says.
    #[default]
    Unknown,
}

impl TimeBasis {
    /// The basis of records with these timestamp kinds. Unknown kinds only
    /// decide the basis when no record says.
    pub fn of(kinds: impl IntoIterator<Item = TsKind>) -> Self {
        let mut out = TimeBasis::Unknown;
        for k in kinds {
            let b = match k {
                TsKind::Request => TimeBasis::Request,
                TsKind::Submit => TimeBasis::Submit,
                TsKind::Capture => TimeBasis::Capture,
                TsKind::Unknown => continue,
            };
            out = match (out, b) {
                (TimeBasis::Unknown, b) => b,
                (o, b) if o == b => o,
                // Request and submit times together read as submit times.
                (TimeBasis::Request, TimeBasis::Submit)
                | (TimeBasis::Submit, TimeBasis::Request) => TimeBasis::Submit,
                _ => TimeBasis::Mixed,
            };
        }
        out
    }

    pub fn is_unknown(&self) -> bool {
        *self == TimeBasis::Unknown
    }

    /// Whether times on this basis can stand for the order one client sent
    /// requests in: request or submit times, or unknown read as requests.
    /// Capture times (and a mix including them) cannot ([FM-5.4](../../docs/manual/05-linking.md)).
    pub fn is_request_like(self) -> bool {
        matches!(
            self,
            TimeBasis::Request | TimeBasis::Submit | TimeBasis::Unknown
        )
    }

    /// Words a hint adds about its times, or nothing for request times.
    pub fn note(self) -> Option<&'static str> {
        match self {
            TimeBasis::Submit => Some("submit times, close to request times"),
            TimeBasis::Capture => Some("capture times, not request times"),
            TimeBasis::Mixed => Some("capture times left out"),
            TimeBasis::Request | TimeBasis::Unknown => None,
        }
    }
}

/// Whether a record's timestamp can stand for when it was requested.
pub fn request_like(kind: TsKind) -> bool {
    kind != TsKind::Capture
}

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
    /// (hour start, count) for every hour between start and end, including
    /// empty hours. A cluster's timing keeps only the hours with records.
    pub hourly: Vec<(i64, usize)>,
    #[serde(default)]
    pub rhythm: Rhythm,
    /// Date tags far behind or ahead of when the records were seen. Filled
    /// by the caller from the records' tags (see [`stale_dates`]); `timing`
    /// sees only timestamps and leaves it empty.
    #[serde(default)]
    pub stale_dates: StaleDates,
}

#[cfg(test)]
mod tests {
    use super::pauses::poisson_at_least;
    use super::*;
    use crate::rules::Linking;
    use chrono::{DateTime, NaiveDate};

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
