//! What date tags agents put in URLs say: the operator's UTC offset, or a
//! model with no clock writing a stale "today".

use chrono::{DateTime, NaiveDate};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

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
