//! S6 dispatch star: one run leading several different-client runs.
//!
//! A planner that dispatches workers is active first, and each worker is
//! active a little after it, at the worker's own lag. Co-activity
//! ([`crate::coactivity`]) finds two clusters busy together but reads no
//! direction; this reads it. Each cluster's request and submit times (the
//! unflagged requests of its runs' clients included, never capture times)
//! are binned in `co_activity.bin_secs` bins, and every ordered pair is read
//! at signed lags: lag `l` counts the leader's active bins with follower
//! activity in bin `b + l` or the next, for every `l` from
//! `-(co_activity.max_lag_bins + 1)` to `co_activity.max_lag_bins`, so the
//! follower is read from that many bins before the leader's bin to one more
//! after. A leader leads a follower when the best lag is zero or more and
//! reads more coincidences than its mirror (`-l - 1`, the follower before the
//! leader by as much).
//!
//! A lead also needs a direction chance alone seldom gives, read on the
//! times themselves rather than the bins: for each of the leader's active
//! bins, the follower's nearest time to the leader's first time there, after
//! it or before it, against even odds (a one-sided sign test). Clusters set
//! off together by one trigger fall either side of each other alike, and two
//! clusters busy in the same bins win lag zero over its mirror by bin
//! boundaries alone.
//!
//! A follower's own chance is the larger of the direction's and
//! co-activity's: the analytic Poisson-binomial tail at the follower's
//! coverage of the union span, times the lags tried, and the share of
//! circular shifts of its activity that align as well; the larger, with the
//! shifts only vetoing when the span allows too few. Both must hold, so the
//! larger is the chance of both. The shifts are only read for a lead that
//! passes the rest. A leader on clock hours is weighted down as co-activity
//! weights it. A star needs `dispatch_min_followers` followers, each under
//! `dispatch_pair_max_chance`, of pairwise different clients, whose own best
//! lag between each other agrees within `dispatch_lag_tolerance_bins` with
//! the difference of their lags to the leader. Clients differ when they
//! differ in a way of sending known on both sides (relay route, user agent,
//! network, header set, encoding); clients known on neither side, as on a
//! submit service or an archive, are never told apart.
//!
//! The star's chance combines its followers' chances, each corrected for the
//! candidate followers the leader had (Sidak), as a product of independent
//! chances, times the star's runs (each could have been read as its
//! leader). Each leader with enough candidate followers is a test, and the
//! stars kept are cut at a false discovery rate over them.
//!
//! **Nearest leaders.** A follower trails its own dispatcher by its own
//! delay and anyone else by that and the other's delay too, so its
//! dispatcher is the cluster after which its delays spread least (their
//! median absolute deviation). A candidate follower another cluster times
//! more tightly, or as tightly while leading the leader (the earlier of two
//! alike is the dispatcher), is that cluster's and is left out of the star.
//! Clusters downstream of the leader (those it leads, directly or through
//! clusters it leads) are not read so: a tree's sub-dispatcher times its
//! own workers more tightly than the root does, and they stay in the root's
//! star, where the tree's reduction ([`crate::swarm::tree`]) finds their
//! nearest leader.
//!
//! **Chains.** One upstream trigger (a feed item, a news alert, a scheduled
//! post) sends unrelated agents after it at their own lags, and the
//! quickest reads as the leader; the second quickest leads every slower one
//! as well. A star one of whose followers leads every other follower, and
//! times them more tightly in sum than the leader, is read as such a chain
//! and not kept: a tree's sub-dispatcher leads its own workers only. A
//! trigger's readers at fixed lags, and a trigger whose quickest reader is
//! seldom late, still read as a dispatch star, so the edge stays a hint
//! for review.

use super::{Ctx, Tests};
use crate::chance::{at_least, product_chance_all, sidak};
use crate::model::Tier;
use crate::swarm::runs::{Fp, differ};
use crate::swarm::{EdgeStrength, SwarmEdgeKind};
use std::collections::BTreeMap;

/// Whether two clusters' clients are told apart: they differ in at least
/// one way of sending known on both sides. Clients known on neither side
/// (submit services, archive captures) are never counted as different.
fn different_clients(a: &Fp, b: &Fp) -> bool {
    differ(a, b).is_some_and(|d| !d.is_empty())
}

/// One cluster's activity over its runs.
struct Activity {
    ci: usize,
    /// Indexes of its runs in `Ctx::runs`.
    runs: Vec<usize>,
    /// Distinct active bins, earliest first.
    bins: Vec<i64>,
    /// Distinct request and submit times in those bins, earliest first.
    times: Vec<i64>,
    fp: Fp,
}

/// An ordered pair read at its best lag.
struct Lead {
    /// The follower is active in bin `b + lag` or the next.
    lag: i64,
    coincidences: f64,
    chance: f64,
    /// Coincidences on a clock hour.
    on_hour: usize,
    /// The leader's bins that met the follower.
    hits: Vec<i64>,
}

/// Lags read, nearest first: `0, -1, 1, -2, ..., m, -m - 1`.
fn signed_lags(m: i64) -> Vec<i64> {
    (0..=m).flat_map(|d| [d, -d - 1]).collect()
}

/// The one-sided sign test of a lead's direction, on the times
/// themselves: for each of the leader's active bins, its first time there
/// and the follower's nearest time within `reach` seconds of it; of those
/// that differ, the chance that at least as many fall after the leader's as
/// do when each is either way at even odds. Two clusters set off together
/// by one trigger (a schedule, a feed item) fall either side of each other
/// alike, whatever lag their bins read best at.
fn direction_chance(x: &[i64], y: &[i64], bin: i64, reach: i64) -> f64 {
    let (mut after, mut n) = (0usize, 0usize);
    let mut prev = None;
    for &t in x {
        let b = t.div_euclid(bin);
        if prev == Some(b) {
            continue;
        }
        prev = Some(b);
        let i = y.partition_point(|&v| v < t);
        let near = [i.checked_sub(1).map(|k| y[k]), y.get(i).copied()]
            .into_iter()
            .flatten()
            .filter(|&v| (v - t).abs() <= reach)
            .min_by_key(|&v| ((v - t).abs(), v));
        if let Some(v) = near.filter(|&v| v != t) {
            n += 1;
            after += usize::from(v > t);
        }
    }
    at_least(&vec![0.5; n], after)
}

/// For each of the leader's bursts (times with no earlier time of its
/// within `reach` seconds), its first time and the follower's first time
/// after it within `reach`: the delay, by the burst's bin. A burst is read
/// once, so a leader sending two requests a minute apart does not read
/// every follower as early after the second.
fn delays(x: &[i64], y: &[i64], bin: i64, reach: i64) -> BTreeMap<i64, i64> {
    let mut out = BTreeMap::new();
    let mut prev: Option<i64> = None;
    for &t in x {
        let b = t.div_euclid(bin);
        let burst = prev.is_some_and(|p| t - p <= reach);
        prev = Some(t);
        if burst {
            continue;
        }
        let i = y.partition_point(|&v| v <= t);
        if let Some(&v) = y.get(i).filter(|&&v| v - t <= reach) {
            out.insert(b, v - t);
        }
    }
    out
}

/// The mean absolute deviation of delays from their median, in seconds:
/// how tightly a follower trails; `None` under three delays.
fn spread(d: &BTreeMap<i64, i64>) -> Option<f64> {
    if d.len() < 3 {
        return None;
    }
    let mut v: Vec<i64> = d.values().copied().collect();
    v.sort_unstable();
    let n = v.len();
    let m = if n % 2 == 1 {
        v[n / 2] as f64
    } else {
        (v[n / 2 - 1] + v[n / 2]) as f64 / 2.0
    };
    Some(v.iter().map(|&x| (x as f64 - m).abs()).sum::<f64>() / n as f64)
}

impl Ctx<'_> {
    /// `f`'s delays after `l`'s events ([`delays`]).
    fn delays_after(&self, l: &Activity, f: &Activity) -> BTreeMap<i64, i64> {
        let bin = self.co.bin_secs.max(1);
        let reach = (self.co.max_lag_bins.max(0) + 2) * bin;
        delays(&l.times, &f.times, bin, reach)
    }

    /// The clusters `acts[li]` leads, directly or through clusters it leads,
    /// among those active within reach of its span: downstream of it.
    fn downstream(&self, acts: &[Activity], li: usize) -> Vec<bool> {
        let l = &acts[li];
        let reach = self.co.max_lag_bins.max(0) + 2;
        let (ls, le) = (l.bins[0] - reach, l.bins[l.bins.len() - 1] + reach);
        let near: Vec<usize> = (0..acts.len())
            .filter(|&c| {
                c != li && acts[c].bins[0] <= le && acts[c].bins[acts[c].bins.len() - 1] >= ls
            })
            .collect();
        let mut down = vec![false; acts.len()];
        let mut stack = vec![li];
        while let Some(x) = stack.pop() {
            for &c in &near {
                if !down[c] && self.leads(&acts[x], &acts[c]) {
                    down[c] = true;
                    stack.push(c);
                }
            }
        }
        down
    }

    /// The spreads of `followers`' delays after `x`, summed; `None` when one
    /// has too few delays to read.
    fn spread_sum(&self, x: &Activity, acts: &[Activity], followers: &[usize]) -> Option<f64> {
        followers
            .iter()
            .map(|&f| spread(&self.delays_after(x, &acts[f])))
            .sum()
    }

    /// Whether candidate follower `fi` of `acts[li]` is another cluster's:
    /// one active within reach of it, not downstream of the leader (`down`),
    /// that leads it and times it more tightly, or as tightly while leading
    /// the leader.
    fn nearer_leader(&self, acts: &[Activity], li: usize, fi: usize, down: &[bool]) -> bool {
        let (l, f) = (&acts[li], &acts[fi]);
        let Some(ours) = spread(&self.delays_after(l, f)) else {
            return false;
        };
        acts.iter().enumerate().any(|(gi, g)| {
            gi != li
                && gi != fi
                && !down[gi]
                && self.near(g, f)
                && self.leads(g, f)
                && spread(&self.delays_after(g, f)).is_some_and(|theirs| {
                    theirs < ours - 1e-9 || (theirs <= ours + 1e-9 && self.leads(g, l))
                })
        })
    }

    /// A candidate follower (of `heads`) that leads every one of the
    /// star's `chosen` followers but itself, and times them more tightly in
    /// sum than the leader: a trigger's chain.
    fn chain(
        &self,
        acts: &[Activity],
        li: usize,
        heads: &[usize],
        chosen: &[usize],
    ) -> Option<usize> {
        let l = &acts[li];
        heads.iter().copied().find(|&c| {
            let rest: Vec<usize> = chosen.iter().copied().filter(|&f| f != c).collect();
            !rest.is_empty()
                && rest.iter().all(|&f| self.leads(&acts[c], &acts[f]))
                && match (
                    self.spread_sum(&acts[c], acts, &rest),
                    self.spread_sum(l, acts, &rest),
                ) {
                    (Some(theirs), Some(ours)) => theirs < ours - 1e-9,
                    _ => false,
                }
        })
    }

    /// Each cluster above noise with enough active bins outside crowded
    /// ones.
    fn activities(&self) -> Vec<Activity> {
        let bin = self.co.bin_secs.max(1);
        let mut by: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
        for (i, r) in self.runs.iter().enumerate() {
            if self.cl[r.ci].tier > Tier::Noise {
                by.entry(r.ci).or_default().push(i);
            }
        }
        let mut acts: Vec<Activity> = by
            .into_iter()
            .map(|(ci, runs)| {
                let mut times: Vec<i64> = runs
                    .iter()
                    .flat_map(|&i| self.runs[i].events.iter().copied())
                    .collect();
                crate::sort::sort(&mut times);
                times.dedup();
                let mut bins: Vec<i64> = times.iter().map(|t| t.div_euclid(bin)).collect();
                bins.dedup();
                let mut fp: Fp = Default::default();
                for &i in &runs {
                    for (d, vals) in self.runs[i].fp.iter().enumerate() {
                        for v in vals {
                            if !fp[d].contains(v) {
                                fp[d].push(v.clone());
                            }
                        }
                    }
                }
                Activity {
                    ci,
                    runs,
                    bins,
                    times,
                    fp,
                }
            })
            .collect();
        // Bins where more clusters are active than `max_shared` say nothing
        // about any two of them.
        let mut crowd: BTreeMap<i64, usize> = BTreeMap::new();
        for a in &acts {
            for &b in &a.bins {
                *crowd.entry(b).or_default() += 1;
            }
        }
        for a in &mut acts {
            a.bins.retain(|b| crowd[b] <= self.max_shared);
            a.times
                .retain(|t| crowd[&t.div_euclid(bin)] <= self.max_shared);
        }
        acts.retain(|a| a.bins.len() >= self.co.min_active_bins.max(1));
        acts
    }

    /// `y` read against `x` at every signed lag (and circular shift `s` of
    /// `y`): the weighted coincidences per lag, in [`signed_lags`] order.
    fn per_lag(&self, x: &[i64], y: &[i64], with_chance: bool) -> Option<(Vec<f64>, Lead)> {
        let co = self.co;
        let bin = co.bin_secs.max(1);
        let m = co.max_lag_bins.max(0);
        let lo = x[0].min(y[0]) - m - 2;
        let hi = x[x.len() - 1].max(y[y.len() - 1]) + m + 2;
        let w = hi - lo + 1;
        let rx: Vec<i64> = x.iter().map(|b| b - lo).collect();
        let mut map = vec![false; w as usize];
        for b in y {
            map[(b - lo) as usize] = true;
            map[(b - lo - 1).rem_euclid(w) as usize] = true;
        }
        let tol = co.clock_tolerance_secs.max(0);
        let hourly = |rel: i64| {
            let r = ((rel + lo) * bin).rem_euclid(3600);
            r <= tol || r >= 3600 - tol
        };
        let weights: Vec<f64> = rx
            .iter()
            .map(|&b| if hourly(b) { co.clock_weight } else { 1.0 })
            .collect();
        let lags = signed_lags(m);
        let stat = |l: i64, s: i64| -> f64 {
            rx.iter()
                .zip(&weights)
                .filter(|&(&b, _)| map[(b + l - s).rem_euclid(w) as usize])
                .map(|(_, &wt)| wt)
                .sum()
        };
        let counts: Vec<f64> = lags.iter().map(|&l| stat(l, 0)).collect();
        let mut best = 0;
        for (i, &c) in counts.iter().enumerate() {
            if c > counts[best] + 1e-9 {
                best = i;
            }
        }
        let (lag, observed) = (lags[best], counts[best]);
        if observed <= 0.0 {
            return None;
        }
        let met: Vec<usize> = (0..rx.len())
            .filter(|&i| map[(rx[i] + lag).rem_euclid(w) as usize])
            .collect();
        let on_hour = met.iter().filter(|&&i| hourly(rx[i])).count();
        let hits: Vec<i64> = met.iter().map(|&i| x[i]).collect();
        if !with_chance {
            return Some((
                counts,
                Lead {
                    lag,
                    coincidences: observed,
                    chance: 1.0,
                    on_hour,
                    hits,
                },
            ));
        }
        // Co-activity's two models at this lag.
        let ry: Vec<i64> = y.iter().map(|b| b - lo).collect();
        let share = |v: &[i64]| v.iter().filter(|&&b| hourly(b)).count() as f64 / v.len() as f64;
        let step = if share(&rx) >= 0.5 || share(&ry) >= 0.5 {
            (3600 / bin).max(1)
        } else {
            1
        };
        let per = step.min(w);
        let mut cover = vec![(0usize, 0usize); per as usize];
        for (u, &on) in map.iter().enumerate() {
            let c = &mut cover[u % per as usize];
            c.0 += usize::from(on);
            c.1 += 1;
        }
        let rho: Vec<f64> = rx
            .iter()
            .map(|&b| {
                let (on, all) = cover[((b + lag).rem_euclid(w) % per) as usize];
                on as f64 / all.max(1) as f64
            })
            .collect();
        let need = (observed - 1e-9).ceil().max(0.0) as usize;
        let analytic = (lags.len() as f64 * at_least(&rho, need)).min(1.0);
        let guard = 2 * (m + 1);
        let admissible: Vec<i64> = (1..w)
            .filter(|&s| s % step == 0 && s.min(w - s) > guard)
            .collect();
        let k = co.shifts.max(1).min(admissible.len());
        let mut ge = 0usize;
        for i in 0..k {
            let s = admissible[i * admissible.len() / k];
            let v = lags.iter().map(|&l| stat(l, s)).fold(f64::MIN, f64::max);
            ge += usize::from(v >= observed - 1e-9);
        }
        let shifted = (ge + 1) as f64 / (k + 1) as f64;
        let resolves = 1.0 / (k + 1) as f64 <= co.max_chance;
        let chance = if resolves || ge > 0 {
            analytic.max(shifted)
        } else {
            analytic
        };
        Some((
            counts,
            Lead {
                lag,
                coincidences: observed,
                chance,
                on_hour,
                hits,
            },
        ))
    }

    /// `f` read against leader `l`: its lead, when it trails `l` at its best
    /// lag, more often than before it, and in a direction chance alone
    /// seldom gives. The lead's chance is the larger of co-activity's and the
    /// direction's ([`direction_chance`]): both must hold. The co-activity
    /// chance, the costly part, is only read for a lead that passes the rest.
    fn lead(&self, l: &Activity, f: &Activity) -> Option<Lead> {
        let direction = self.direction(l, f)?;
        let (_, mut lead) = self.per_lag(&l.bins, &f.bins, true)?;
        lead.chance = lead.chance.max(direction);
        Some(lead)
    }

    /// Whether `l` leads `f` as [`Ctx::lead`] reads it, short of the
    /// co-activity chance: at a lag of zero or more, more often than its
    /// mirror, in a direction chance alone seldom gives.
    fn leads(&self, l: &Activity, f: &Activity) -> bool {
        self.direction(l, f).is_some()
    }

    /// The direction's chance of `f` trailing `l`, when it trails at its
    /// best lag, more often than before it, within `dispatch_pair_max_chance`.
    fn direction(&self, l: &Activity, f: &Activity) -> Option<f64> {
        let (counts, lead) = self.per_lag(&l.bins, &f.bins, false)?;
        if lead.lag < 0 || lead.coincidences < self.co.min_coincidences {
            return None;
        }
        let lags = signed_lags(self.co.max_lag_bins.max(0));
        let mirror = lags.iter().position(|&x| x == -lead.lag - 1)?;
        if lead.coincidences <= counts[mirror] + 1e-9 {
            return None;
        }
        let bin = self.co.bin_secs.max(1);
        let reach = (self.co.max_lag_bins.max(0) + 2) * bin;
        let direction = direction_chance(&l.times, &f.times, bin, reach);
        (direction <= self.opts.dispatch_pair_max_chance).then_some(direction)
    }

    /// Whether `x` and `y` come within reach of each other on enough bins
    /// to be read at all.
    fn near(&self, x: &Activity, y: &Activity) -> bool {
        let reach = self.co.max_lag_bins.max(0) + 2;
        let n = x
            .bins
            .iter()
            .filter(|&&b| {
                let i = y.bins.partition_point(|&v| v < b - reach);
                y.bins.get(i).is_some_and(|&v| v <= b + reach)
            })
            .count();
        n as f64 >= self.co.min_coincidences.max(1.0)
    }

    /// S6: clusters that lead two or more different-client clusters, each
    /// at its own consistent lag. Every cluster with enough candidate
    /// followers is a test.
    pub(super) fn dispatch_stars(&self) -> Tests {
        let mut tests = Tests::default();
        let o = self.opts;
        let min = o.dispatch_min_followers.max(2);
        let acts = self.activities();
        let bin = self.co.bin_secs.max(1);
        for (li, l) in acts.iter().enumerate() {
            let mut cands: Vec<(usize, Lead)> = Vec::new();
            let mut n_cand = 0usize;
            for (fi, f) in acts.iter().enumerate() {
                if fi == li || !different_clients(&l.fp, &f.fp) || !self.near(l, f) {
                    continue;
                }
                n_cand += 1;
                if let Some(lead) = self.lead(l, f)
                    && lead.chance <= o.dispatch_pair_max_chance
                {
                    cands.push((fi, lead));
                }
            }
            if n_cand < min {
                continue;
            }
            tests.tested += 1;
            crate::sort::by(&mut cands, |p, q| {
                p.1.chance
                    .total_cmp(&q.1.chance)
                    .then(q.1.coincidences.total_cmp(&p.1.coincidences))
                    .then(p.0.cmp(&q.0))
            });
            // Followers of pairwise different clients whose lags agree.
            let mut chosen: Vec<&(usize, Lead)> = Vec::new();
            for c in &cands {
                let f = &acts[c.0];
                let fits = chosen.iter().all(|d| {
                    let g = &acts[d.0];
                    different_clients(&g.fp, &f.fp)
                        && self.per_lag(&g.bins, &f.bins, false).is_some_and(|(_, x)| {
                            (x.lag - (c.1.lag - d.1.lag)).abs() <= o.dispatch_lag_tolerance_bins
                        })
                });
                if fits {
                    chosen.push(c);
                }
            }
            if chosen.len() < min {
                continue;
            }
            let ps: Vec<f64> = chosen.iter().map(|c| sidak(c.1.chance, n_cand)).collect();
            let p = (product_chance_all(&ps) * (chosen.len() + 1) as f64).min(1.0);
            if p > o.dispatch_max_chance {
                continue;
            }
            let heads: Vec<usize> = cands.iter().map(|c| c.0).collect();
            let picked: Vec<usize> = chosen.iter().map(|c| c.0).collect();
            if self.chain(&acts, li, &heads, &picked).is_some() {
                continue;
            }
            // Followers another cluster times more tightly are its own:
            // they count toward the star's chance, as the leader does lead
            // them, but the edges go to the leader's own.
            let down = self.downstream(&acts, li);
            let own: Vec<&(usize, Lead)> = chosen
                .iter()
                .copied()
                .filter(|c| !self.nearer_leader(&acts, li, c.0, &down))
                .collect();
            if own.len() < min {
                continue;
            }
            let theirs = chosen.len() - own.len();
            let lc = &self.cl[l.ci];
            let mut edges = Vec::new();
            for c in &own {
                let f = &acts[c.0];
                let fc = &self.cl[f.ci];
                let diff = differ(&l.fp, &f.fp).unwrap_or_default();
                let at = |a: &Activity, bins: &[i64]| -> (usize, Vec<usize>) {
                    let recs: Vec<usize> = self.cl[a.ci]
                        .members
                        .iter()
                        .copied()
                        .filter(|&m| {
                            let ob = &self.res[m].obs;
                            ob.ts > 0
                                && crate::timing::request_like(ob.ts_kind)
                                && bins.binary_search(&ob.ts.div_euclid(bin)).is_ok()
                        })
                        .collect();
                    let recs = if recs.is_empty() {
                        self.cl[a.ci].members.clone()
                    } else {
                        recs
                    };
                    let run = recs
                        .first()
                        .and_then(|m| {
                            a.runs
                                .iter()
                                .copied()
                                .find(|&r| self.runs[r].members.contains(m))
                        })
                        .unwrap_or(a.runs[0]);
                    (run, recs)
                };
                let (lrun, lrecs) = at(l, &c.1.hits);
                let mut fbins: Vec<i64> =
                    c.1.hits
                        .iter()
                        .flat_map(|h| [h + c.1.lag, h + c.1.lag + 1])
                        .collect();
                crate::sort::sort(&mut fbins);
                fbins.dedup();
                let (frun, frecs) = at(f, &fbins);
                let (lrun, frun) = (&self.runs[lrun], &self.runs[frun]);
                let strength = if chosen
                    .iter()
                    .all(|d| d.1.coincidences >= 2.0 * self.co.min_coincidences)
                {
                    EdgeStrength::Moderate
                } else {
                    EdgeStrength::Weak
                };
                let others: Vec<&str> = own
                    .iter()
                    .filter(|d| d.0 != c.0)
                    .map(|d| self.cl[acts[d.0].ci].id.as_str())
                    .collect();
                let mut detail = format!(
                    "{} trails {} by {} to {} bins of {} s in {:.1} of {} active bins (chance {:.1e}); {} leads it and {} at their own consistent lags, combined chance {p:.1e} over {} candidate followers and {} candidate leaders",
                    fc.id,
                    lc.id,
                    c.1.lag,
                    c.1.lag + 1,
                    bin,
                    c.1.coincidences,
                    l.bins.len(),
                    c.1.chance,
                    lc.id,
                    others.join(", "),
                    n_cand,
                    chosen.len() + 1
                );
                if theirs > 0 {
                    detail.push_str(&format!(
                        "; {theirs} candidate follower(s) another cluster times more tightly left out"
                    ));
                }
                if !diff.is_empty() {
                    detail.push_str(&format!("; they differ in {}", diff.join(", ")));
                }
                if c.1.on_hour > 0 {
                    detail.push_str(&format!(", {} on a clock hour", c.1.on_hour));
                }
                detail.push_str(
                    ": one planner may dispatch them, or one upstream trigger (a feed item, a news alert) may send each after it",
                );
                edges.push(self.edge(
                    SwarmEdgeKind::DispatchStar,
                    ((lrun, None, &lrecs), (frun, None, &frecs)),
                    strength,
                    Some(p),
                    detail,
                ));
            }
            tests.found.push((p, edges));
        }
        tests
    }
}

#[cfg(test)]
mod tests {
    use super::{direction_chance, signed_lags};

    #[test]
    fn lags_are_read_nearest_first() {
        assert_eq!(signed_lags(2), vec![0, -1, 1, -2, 2, -3]);
    }

    #[test]
    fn direction_reads_which_side_the_follower_falls() {
        let x: Vec<i64> = (0..8).map(|i| 1000 + i * 3000).collect();
        // Always 40 s after, often in the leader's own bin: 2^-8.
        let after: Vec<i64> = x.iter().map(|t| t + 40).collect();
        assert!((direction_chance(&x, &after, 60, 420) - 1.0 / 256.0).abs() < 1e-12);
        // Either side alike: no direction.
        let both: Vec<i64> = x
            .iter()
            .enumerate()
            .map(|(i, t)| if i % 2 == 0 { t + 20 } else { t - 20 })
            .collect();
        assert!(direction_chance(&x, &both, 60, 420) > 0.5);
        // Out of reach, or at the same second, counts neither way.
        let far: Vec<i64> = x.iter().map(|t| t + 900).collect();
        assert_eq!(direction_chance(&x, &far, 60, 420), 1.0);
        assert_eq!(direction_chance(&x, &x, 60, 420), 1.0);
    }
}
