//! Pauses shared by clusters that share no identifier: a link to check,
//! never a merge.

use super::Span;
use super::cadence::{pause_spans, quantile};
use crate::rules::Linking;
use serde::{Deserialize, Serialize};

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
pub(super) fn poisson_at_least(lambda: f64, m: usize) -> f64 {
    let (mut term, mut below) = ((-lambda).exp(), 0.0);
    for k in 0..m {
        below += term;
        term *= lambda / (k + 1) as f64;
    }
    (1.0 - below).clamp(0.0, 1.0)
}
