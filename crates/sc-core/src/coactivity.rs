//! Co-activity: clusters that are busy in the same minutes, or one a fixed
//! lag after the other, more often than their own rhythms explain.
//!
//! One dispatcher driving several agents makes them active together: a
//! planner starts sub-agents and each starts a few seconds after the
//! dispatch. Each cluster's request and submit times are binned into active
//! bins, and the pair's coincidences counted at every lag up to
//! `max_lag_bins` either way; the best lag is the statistic, over the union
//! of the two clusters' spans. Two chance models, the larger reported: an
//! analytic one, each active bin of the quieter cluster meeting the other's
//! activity at that cluster's own rate over the union span (a
//! Poisson-binomial tail, times the lags tried), which a short span does
//! not floor; and the share of circular shifts of one cluster's activity
//! over the union span that align as well, the real alignment counted among
//! them, which keeps each cluster's own burstiness and period. When the span
//! allows too few shifts to reach the chance limit, the shifts only veto.
//! The pairs kept are cut at a false discovery rate over every pair tested.
//!
//! Scheduled jobs line up on the clock without any tie between them. As for
//! shared pauses, a coincidence within `clock_tolerance_secs` of a clock
//! hour counts `clock_weight` of one, and when most of either cluster's
//! activity sits on clock hours the shifts are whole hours and the analytic
//! rate is read at the same minute of the hour, so two jobs on one schedule
//! keep their alignment under both models and do not qualify.
//! Archive capture times never count. Pairs are soft links: they never score,
//! link or merge.

use crate::analyze::{Cluster, ObsResult};
use crate::chance::TestFamily;
use crate::model::Tier;
use crate::timing::request_like;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, VecDeque};

/// Co-activity settings (`[co_activity]` in the rules file).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct CoActivityOptions {
    /// Width of an activity bin.
    pub bin_secs: i64,
    /// Lags tried either way, in bins: a follower this many bins behind
    /// still coincides.
    pub max_lag_bins: i64,
    /// Active bins each cluster needs within the time both were active.
    pub min_active_bins: usize,
    /// Weighted coincidences needed at the best lag.
    pub min_coincidences: f64,
    /// Circular shifts over the union span in the second chance model (all
    /// admissible shifts when fewer).
    pub shifts: usize,
    pub max_chance: f64,
    /// Benjamini-Hochberg false discovery rate over the pairs tested.
    pub fdr: f64,
    /// A bin starting this close to a clock hour is on the hour.
    pub clock_tolerance_secs: i64,
    /// What a coincidence on the hour counts for.
    pub clock_weight: f64,
}

impl Default for CoActivityOptions {
    fn default() -> Self {
        Self {
            bin_secs: 60,
            max_lag_bins: 5,
            min_active_bins: 4,
            min_coincidences: 4.0,
            shifts: 199,
            max_chance: 0.01,
            fdr: 0.05,
            clock_tolerance_secs: 120,
            clock_weight: 0.25,
        }
    }
}

/// Pairs kept, most unlikely first.
const MAX_PAIRS: usize = 200;

/// Two clusters active together beyond chance.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CoActivePair {
    /// Cluster ids, `a` the stronger.
    pub a: String,
    pub b: String,
    /// `b`'s activity trails `a`'s by between this and one bin more, in
    /// seconds, at the best lag (negative: `b` leads).
    pub lag_secs: i64,
    /// Weighted coincidences at that lag.
    pub coincidences: f64,
    /// Active bins of each within the time both were active.
    pub active_a: usize,
    pub active_b: usize,
    /// Coincidences expected at the best lag under the analytic model.
    pub expected: f64,
    /// The larger of the two chances below; the analytic one alone when the
    /// span allows too few shifts to reach `max_chance` and none aligned as
    /// well.
    pub chance: f64,
    /// Analytic chance: each active bin of the quieter cluster meets the
    /// other's activity with the share of the union span it covers (of the
    /// bins at the same minute of the hour under hour shifts), as a
    /// Poisson-binomial tail, times the lags tried.
    #[serde(default)]
    pub analytic: f64,
    /// Share of the arrangements that align at least as well: the circular
    /// shifts of one cluster's activity over the union span and the real
    /// alignment, `(ge + 1) / (shifts + 1)`.
    #[serde(default)]
    pub shifted: f64,
    pub shifts: usize,
    /// Coincidences on a clock hour, counted at `clock_weight`.
    #[serde(default)]
    pub on_the_hour: usize,
    /// The shifts were whole hours, because most activity sat on the hour.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub hour_shifts: bool,
    /// Pairs tested, and pairs this unlikely expected among them.
    #[serde(default)]
    pub tested: usize,
    #[serde(default)]
    pub expected_pairs: f64,
    pub bin_secs: i64,
}

impl CoActivePair {
    pub fn detail(&self) -> String {
        let (lo, hi) = (self.lag_secs, self.lag_secs + self.bin_secs);
        let lead = if lo == 0 || hi == 0 {
            format!("within {} s of each other", self.bin_secs)
        } else if lo > 0 {
            format!("{} trailing {} by {lo} to {hi} s", self.b, self.a)
        } else {
            format!("{} trailing {} by {} to {} s", self.a, self.b, -hi, -lo)
        };
        let mut s = format!(
            "{:.1} of {} active {}-second bins coincide, {lead}; {:.1} expected (chance {:.1e}: {:.1e} analytic, a share of {:.3} of {} circular shifts; {:.2} such pairs expected among {} tested)",
            self.coincidences,
            self.active_a.min(self.active_b),
            self.bin_secs,
            self.expected,
            self.chance,
            self.analytic,
            self.shifted,
            self.shifts,
            self.expected_pairs,
            self.tested
        );
        if self.on_the_hour > 0 {
            s.push_str(&format!(", {} on a clock hour", self.on_the_hour));
        }
        if self.hour_shifts {
            s.push_str(", shifted by whole hours");
        }
        s.push_str(": one dispatcher or scheduler may drive both");
        s
    }
}

/// Active bins of one cluster, from request-like times.
struct Series<'a> {
    id: &'a str,
    bins: Vec<i64>,
}

/// Pairs of clusters above noise active together beyond chance, most
/// unlikely first, and the family's multiplicity budget. `max_shared` is
/// `soft_links.max_shared`: a bin with more clusters active than that says
/// nothing about any two of them.
pub(crate) fn coactive_pairs(
    clusters: &[Cluster],
    results: &[ObsResult],
    max_shared: usize,
    opts: &CoActivityOptions,
) -> (Vec<CoActivePair>, TestFamily) {
    let none = || (Vec::new(), TestFamily::cut("co_activity", &[], 0, opts.fdr));
    let bin = opts.bin_secs.max(1);
    let m = opts.max_lag_bins.max(0);
    let series: Vec<Series> = clusters
        .iter()
        .filter(|c| c.tier > Tier::Noise)
        .filter_map(|c| {
            let mut bins: Vec<i64> = c
                .members
                .iter()
                .map(|&i| &results[i].obs)
                .filter(|o| o.ts > 0 && request_like(o.ts_kind))
                .map(|o| o.ts.div_euclid(bin))
                .collect();
            crate::sort::sort(&mut bins);
            bins.dedup();
            (bins.len() >= opts.min_active_bins).then_some(Series { id: &c.id, bins })
        })
        .collect();
    if series.len() < 2 {
        return none();
    }

    // Candidates: pairs with enough bins within the lag of each other,
    // leaving crowded bins out.
    let mut crowd: BTreeMap<i64, usize> = BTreeMap::new();
    for s in &series {
        for &b in &s.bins {
            *crowd.entry(b).or_default() += 1;
        }
    }
    let mut events: Vec<(i64, usize)> = series
        .iter()
        .enumerate()
        .flat_map(|(i, s)| s.bins.iter().map(move |&b| (b, i)))
        .filter(|(b, _)| crowd[b] <= max_shared)
        .collect();
    crate::sort::sort(&mut events);
    let mut near: BTreeMap<(usize, usize), usize> = BTreeMap::new();
    let mut window: VecDeque<(i64, usize)> = VecDeque::new();
    for &(b, i) in &events {
        while window.front().is_some_and(|&(x, _)| x < b - m - 1) {
            window.pop_front();
        }
        for &(_, j) in &window {
            if j != i {
                *near.entry((i.min(j), i.max(j))).or_default() += 1;
            }
        }
        window.push_back((b, i));
    }

    let mut out = Vec::new();
    let mut tested = 0usize;
    for ((x, y), n) in near {
        if (n as f64) < opts.min_coincidences {
            continue;
        }
        if let Some(p) = test_pair(&series[x], &series[y], opts) {
            tested += 1;
            if p.coincidences >= opts.min_coincidences && p.chance <= opts.max_chance {
                out.push(p);
            }
        }
    }
    // Many pairs are tested: keep those under the false-discovery cut.
    let ps: Vec<f64> = out.iter().map(|p| p.chance).collect();
    let family = TestFamily::cut("co_activity", &ps, tested, opts.fdr);
    out.retain(|p| family.keeps(p.chance));
    for p in &mut out {
        p.tested = tested;
        p.expected_pairs = p.chance * tested as f64;
    }
    crate::sort::by(&mut out, |p, q| {
        p.chance
            .total_cmp(&q.chance)
            .then(q.coincidences.total_cmp(&p.coincidences))
    });
    out.truncate(MAX_PAIRS);
    (out, family)
}

/// The best-lag statistic of `x` against `y` over the union of their
/// spans, and its two chances: the analytic one, each bin of the quieter
/// side meeting the other's activity at that side's own rate, and the
/// share of circular shifts of the other side that align as well.
fn test_pair(x: &Series, y: &Series, opts: &CoActivityOptions) -> Option<CoActivePair> {
    let bin = opts.bin_secs.max(1);
    let m = opts.max_lag_bins.max(0);
    let lo = x.bins[0].min(y.bins[0]) - m;
    let hi = x.bins[x.bins.len() - 1].max(y.bins[y.bins.len() - 1]) + m;
    let w = hi - lo + 1;
    let rel = |s: &Series| -> Vec<i64> { s.bins.iter().map(|&b| b - lo).collect() };
    let (bx, by) = (rel(x), rel(y));
    if bx.len() < opts.min_active_bins || by.len() < opts.min_active_bins {
        return None;
    }
    let tol = opts.clock_tolerance_secs.max(0);
    let hourly = |rel: i64| {
        let r = ((rel + lo) * bin).rem_euclid(3600);
        r <= tol || r >= 3600 - tol
    };
    // The smaller side is read against the other's bitmap; the lag is
    // turned back to `x` against `y` at the end.
    let flip = bx.len() > by.len();
    let (fewer, more) = if flip { (&by, &bx) } else { (&bx, &by) };
    // A follower `lag` bins behind lands in bin `b + lag` or the next, as
    // the bin boundary falls: lag `L` reads both.
    let mut map = vec![false; w as usize];
    for &b in more {
        map[b as usize] = true;
        map[(b - 1).rem_euclid(w) as usize] = true;
    }
    let weights: Vec<f64> = fewer
        .iter()
        .map(|&b| if hourly(b) { opts.clock_weight } else { 1.0 })
        .collect();
    let lags: Vec<i64> = (0..=m)
        .flat_map(|l| if l == 0 { vec![0] } else { vec![l, -l] })
        .collect();
    // Best weighted coincidence count over the lags, `more` shifted by `s`.
    let stat = |s: i64| -> (f64, i64) {
        let mut best = (f64::MIN, 0);
        for &lag in &lags {
            let total: f64 = fewer
                .iter()
                .zip(&weights)
                .filter(|&(&b, _)| map[(b + lag - s).rem_euclid(w) as usize])
                .map(|(_, &wt)| wt)
                .sum();
            if total > best.0 + 1e-9 {
                best = (total, lag);
            }
        }
        best
    };
    let (observed, lag) = stat(0);
    let on_the_hour = fewer
        .iter()
        .filter(|&&b| map[(b + lag).rem_euclid(w) as usize] && hourly(b))
        .count();
    let clock_share = |v: &[i64]| v.iter().filter(|&&b| hourly(b)).count() as f64 / v.len() as f64;
    let hour_shifts = clock_share(&bx) >= 0.5 || clock_share(&by) >= 0.5;
    let step = if hour_shifts { (3600 / bin).max(1) } else { 1 };

    // Analytic: a bin of the quieter side meets the other's activity with
    // the share of the union span that activity covers; of the bins at the
    // same minute of the hour, when most activity sits on the hour.
    let per = step.min(w);
    let mut cover = vec![(0usize, 0usize); per as usize];
    for (u, &on) in map.iter().enumerate() {
        let c = &mut cover[u % per as usize];
        c.0 += usize::from(on);
        c.1 += 1;
    }
    let rho: Vec<f64> = fewer
        .iter()
        .map(|&b| {
            let (on, all) = cover[((b + lag).rem_euclid(w) % per) as usize];
            on as f64 / all.max(1) as f64
        })
        .collect();
    let need = (observed - 1e-9).ceil().max(0.0) as usize;
    let analytic = (lags.len() as f64 * crate::chance::at_least(&rho, need)).min(1.0);
    let expected: f64 = rho.iter().sum();

    // Circular shifts over the union span, beyond the lags; the share at
    // least as aligned. Periodic jobs align under the shifts by their
    // period.
    let guard = 2 * (m + 1);
    let admissible: Vec<i64> = (1..w)
        .filter(|&s| s % step == 0 && s.min(w - s) > guard)
        .collect();
    let k = opts.shifts.max(1).min(admissible.len());
    let mut ge = 0usize;
    for i in 0..k {
        let (v, _) = stat(admissible[i * admissible.len() / k]);
        ge += usize::from(v >= observed - 1e-9);
    }
    // The real alignment counts as one of the arrangements, so the share is
    // never zero. When the span allows too few shifts to reach `max_chance`
    // at all, the shifts can only veto: no shift may align as well, and the
    // analytic chance stands.
    let shifted = (ge + 1) as f64 / (k + 1) as f64;
    let resolves = 1.0 / (k + 1) as f64 <= opts.max_chance;
    let chance = if resolves || ge > 0 {
        analytic.max(shifted)
    } else {
        analytic
    };
    // `more` trails `fewer` by `lag` to `lag + 1` bins.
    let lag = if flip { -lag - 1 } else { lag };
    Some(CoActivePair {
        a: x.id.to_string(),
        b: y.id.to_string(),
        lag_secs: lag * bin,
        coincidences: observed,
        active_a: bx.len(),
        active_b: by.len(),
        expected,
        chance,
        analytic,
        shifted,
        shifts: k,
        on_the_hour,
        hour_shifts,
        tested: 0,
        expected_pairs: 0.0,
        bin_secs: bin,
    })
}

#[cfg(test)]
mod tests {
    use crate::analyze::analyze;
    use crate::model::{Observation, TsKind};
    use crate::rules::Rules;

    const T0: i64 = 1_791_000_000 + 17 * 60 + 13;

    fn o(id: &str, ts: i64, url: String, kind: TsKind) -> Observation {
        Observation {
            id: id.into(),
            ts,
            ts_kind: kind,
            url,
            ..Default::default()
        }
    }

    /// Irregular dispatch times over about eight hours, off the clock hour.
    fn dispatches() -> Vec<i64> {
        let mut t = T0;
        let gaps = [
            1500, 2200, 900, 3100, 1300, 2600, 1700, 2900, 1100, 2000, 1400, 2400,
        ];
        gaps.iter()
            .map(|g| {
                t += g;
                t
            })
            .collect()
    }

    /// A planner on its hosts at `times`, and workers on theirs `lag`
    /// seconds after each; each its own tag and payload family.
    fn pair(times: &[i64], lag: i64, kind: TsKind) -> Vec<Observation> {
        let mut obs = Vec::new();
        for (k, &t) in times.iter().enumerate() {
            obs.push(o(
                &format!("p{k}"),
                t,
                format!(
                    "https://p{}.plan.example/s?q=%27%20OR%201%3D1--&uqtag=plan77",
                    k % 5
                ),
                kind,
            ));
            obs.push(o(
                &format!("w{k}"),
                t + lag,
                format!(
                    "https://w{}.work.example/v?x=%3Csvg%20onload%3Dalert(1)%3E&run=work42",
                    k % 5
                ),
                kind,
            ));
        }
        obs
    }

    #[test]
    fn a_worker_trailing_a_planner_is_co_active_with_its_lag() {
        let a = analyze(
            pair(&dispatches(), 75, TsKind::Submit),
            &Rules::default_rules(),
        );
        assert_eq!(a.clusters.len(), 2, "{:?}", a.clusters);
        let p = &a.coactive_pairs;
        assert_eq!(p.len(), 1, "{p:?}");
        let x = &p[0];
        assert!(x.coincidences >= 9.0, "{x:?}");
        assert!(x.chance <= 0.01, "{x:?}");
        // The real alignment counts among the arrangements: never zero.
        assert!(x.shifted >= 1.0 / (x.shifts + 1) as f64, "{x:?}");
        assert!(x.chance >= x.shifted, "{x:?}");
        let f = a
            .multiplicity
            .iter()
            .find(|f| f.family == "co_activity")
            .expect("the co-activity family");
        assert_eq!((f.kept, f.tested), (1, x.tested), "{f:?}");
        // The lag points from the planner to the worker.
        let planner = a.cluster_index("C1").map(|i| &a.clusters[i]).unwrap();
        let planner_first = a.results[planner.members[0]].obs.id.starts_with('p');
        assert_eq!(
            x.lag_secs.signum(),
            if planner_first { 1 } else { -1 },
            "{x:?}"
        );
        assert!((60..=120).contains(&x.lag_secs.abs()), "{x:?}");
        assert!(
            a.soft_links
                .iter()
                .any(|l| l.kind == crate::fleets::SoftLinkKind::CoActivity),
            "{:?}",
            a.soft_links
        );
    }

    #[test]
    fn a_short_dispatch_under_two_hours_reaches_the_limit() {
        // Eight dispatches in 70 minutes: too few circular shifts within the
        // overlap to reach 1%, but the analytic chance reads each bin.
        let mut t = T0;
        let times: Vec<i64> = [300, 840, 420, 660, 360, 900, 480, 240]
            .iter()
            .map(|g| {
                t += g;
                t
            })
            .collect();
        let a = analyze(pair(&times, 75, TsKind::Request), &Rules::default_rules());
        let p = &a.coactive_pairs;
        assert_eq!(p.len(), 1, "{p:?}");
        let x = &p[0];
        assert!(x.chance <= 0.01 && x.analytic <= x.chance, "{x:?}");
        // Too few shifts to reach 1%: they could only veto, and none
        // aligned as well.
        assert!(1.0 / (x.shifts + 1) as f64 > 0.01, "{x:?}");
        assert_eq!(x.chance, x.analytic, "{x:?}");
        assert_eq!(x.tested, 1, "{x:?}");
        assert!((x.expected_pairs - x.chance).abs() < 1e-12);
        assert!(x.detail().contains("analytic"), "{}", x.detail());
    }

    #[test]
    fn two_jobs_on_one_period_off_the_hour_are_not_co_active() {
        // Every ten minutes from :03 for eight hours, the second 20 s after
        // the first: aligned under every shift by a multiple of the period.
        let start = (T0 / 3600 + 1) * 3600 + 180;
        let times: Vec<i64> = (0..48).map(|k| start + k * 600).collect();
        let a = analyze(pair(&times, 20, TsKind::Request), &Rules::default_rules());
        assert_eq!(a.clusters.len(), 2);
        assert!(a.coactive_pairs.is_empty(), "{:?}", a.coactive_pairs);
    }

    #[test]
    fn capture_times_never_count() {
        let a = analyze(
            pair(&dispatches(), 75, TsKind::Capture),
            &Rules::default_rules(),
        );
        assert!(a.coactive_pairs.is_empty(), "{:?}", a.coactive_pairs);
    }

    #[test]
    fn two_crons_on_the_hour_are_not_co_active() {
        // Both run at the top of every hour for a day, and nothing else.
        let hour0 = (T0 / 3600 + 1) * 3600;
        let times: Vec<i64> = (0..24).map(|h| hour0 + h * 3600 + 5).collect();
        let a = analyze(pair(&times, 30, TsKind::Request), &Rules::default_rules());
        assert_eq!(a.clusters.len(), 2);
        assert!(a.coactive_pairs.is_empty(), "{:?}", a.coactive_pairs);
    }

    #[test]
    fn independent_clusters_busy_at_the_same_time_are_not_co_active() {
        // Two clusters active in most minutes of the same two hours.
        let mut obs = Vec::new();
        for k in 0..100 {
            let t = T0 + k * 70;
            obs.push(o(
                &format!("p{k}"),
                t,
                format!(
                    "https://p{}.plan.example/s?q=%27%20OR%201%3D1--&uqtag=plan77",
                    k % 7
                ),
                TsKind::Request,
            ));
            obs.push(o(
                &format!("w{k}"),
                T0 + k * 67 + 13,
                format!(
                    "https://w{}.work.example/v?x=%3Csvg%20onload%3Dalert(1)%3E&run=work42",
                    k % 5
                ),
                TsKind::Request,
            ));
        }
        let a = analyze(obs, &Rules::default_rules());
        assert!(a.coactive_pairs.is_empty(), "{:?}", a.coactive_pairs);
    }
}
