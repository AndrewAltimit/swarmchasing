//! The hour-of-day rhythm of a cluster: round the clock, a working day
//! (with a guess at its UTC offset), or no clear pattern.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

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
pub(super) fn rhythm(t: &[i64]) -> Rhythm {
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
