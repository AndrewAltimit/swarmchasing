//! S3 synchronized start: runs in lockstep.
//!
//! Two runs of different clients whose requests line up event by event at
//! one fixed offset, within a few seconds, as when one orchestrator
//! dispatches each step to several workers. The statistic is the most
//! requests of the shorter run that have a request of the other within
//! `lockstep_tolerance_secs` at one offset up to `lockstep_max_offset_secs`
//! either way. Two chance models, and the larger chance is reported:
//!
//! - **placement**: the shorter run placed rigidly at random over the
//!   analysis span. Runs that merely overlap in a quiet stretch of a long
//!   analysis pass this one, so it is not enough alone.
//! - **own gaps**: the shorter run's start kept and its own gaps between
//!   requests permuted (seeded), continued while none lines up as well.
//!   Two jobs that start together and send at a steady rate stay aligned
//!   under every permutation and do not pass; only a shared order of uneven
//!   gaps does. Schedulers get no other allowance, and a start on the clock
//!   hour neither helps nor hurts.
//!
//! Every pair of different clients within reach is a test, and the edges
//! kept are cut at a false discovery rate over them.

use super::{Ctx, Tests};
use crate::swarm::runs::{Run, differ};
use crate::swarm::{EdgeStrength, SwarmEdgeKind};

/// Requests per run read, earliest first.
const MAX_EVENTS: usize = 400;

/// Pieces of the offset line where the coverage is constant: `(from, to,
/// requests of the shorter run lined up)`.
type Coverage = Vec<(f64, f64, usize)>;

/// For each offset `o` (the shorter run `b` shifted by `-o`), how many of
/// `b`'s requests have one of `a`'s within `tol`; only offsets in `window`
/// when given.
fn coverage(a: &[i64], b: &[i64], tol: i64, window: Option<(i64, i64)>) -> Coverage {
    let mut ends: Vec<(i64, i32)> = Vec::new();
    for &t in b {
        // Offsets `t - x` for the requests `x` of `a` in reach, as merged
        // intervals of `t`'s own, so each request counts once.
        let (lo, hi) = match window {
            Some((wl, wh)) => (t - wh - tol, t - wl + tol),
            None => (i64::MIN, i64::MAX),
        };
        let (from, to) = (
            a.partition_point(|&x| x < lo),
            a.partition_point(|&x| x <= hi),
        );
        let mut cur: Option<(i64, i64)> = None;
        for &x in a[from..to].iter().rev() {
            let (s, e) = (t - x - tol, t - x + tol);
            match &mut cur {
                Some(c) if s <= c.1 => c.1 = c.1.max(e),
                _ => {
                    if let Some(c) = cur {
                        ends.push((c.0, 1));
                        ends.push((c.1, -1));
                    }
                    cur = Some((s, e));
                }
            }
        }
        if let Some(c) = cur {
            ends.push((c.0, 1));
            ends.push((c.1, -1));
        }
    }
    // Opening before closing at one point: closed intervals.
    crate::sort::by(&mut ends, |p, q| p.0.cmp(&q.0).then(q.1.cmp(&p.1)));
    let mut out = Coverage::new();
    let mut level = 0i32;
    for (i, &(x, d)) in ends.iter().enumerate() {
        level += d;
        let next = ends.get(i + 1).map_or(x, |n| n.0);
        // A level reached at a single point still counts there.
        let peak = if d > 0 { level } else { level - d };
        out.push((x as f64, next as f64, level.max(0) as usize));
        if d < 0 && peak > 0 {
            out.push((x as f64, x as f64, peak as usize));
        }
    }
    out
}

/// The most requests lined up at one offset in `[lo, hi]`, and the middle
/// of the first stretch of offsets where they do.
fn best(cov: &Coverage, lo: i64, hi: i64) -> (usize, i64) {
    let (lo, hi) = (lo as f64, hi as f64);
    let mut out = (0, 0);
    for &(s, e, n) in cov {
        if e >= lo && s <= hi && n > out.0 {
            out = (n, ((s.max(lo) + e.min(hi)) / 2.0).round() as i64);
        }
    }
    out
}

/// Share of `[ulo, uhi]` within `d` of an offset where at least `k`
/// requests line up: the placement chance.
fn placed(cov: &Coverage, k: usize, d: i64, ulo: f64, uhi: f64) -> f64 {
    if uhi <= ulo {
        return 1.0;
    }
    let d = d as f64;
    let mut parts: Vec<(f64, f64)> = cov
        .iter()
        .filter(|p| p.2 >= k)
        .map(|p| ((p.0 - d).max(ulo), (p.1 + d).min(uhi)))
        .filter(|p| p.1 > p.0)
        .collect();
    crate::sort::by(&mut parts, |p, q| p.0.total_cmp(&q.0));
    let (mut len, mut end) = (0.0, f64::MIN);
    for (s, e) in parts {
        if e > end {
            len += e - s.max(end);
            end = e;
        }
    }
    (len / (uhi - ulo)).clamp(0.0, 1.0)
}

/// A small seeded generator (splitmix64), the same on every platform.
struct Mix(u64);

impl Mix {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
}

/// FNV-1a over the pair's stable labels: the permutations' seed.
fn seed(parts: &[&str]) -> u64 {
    let mut h = 0xcbf2_9ce4_8422_2325u64;
    for p in parts {
        for b in p.bytes().chain([0]) {
            h = (h ^ u64::from(b)).wrapping_mul(0x0100_0000_01b3);
        }
    }
    h
}

/// One run pair in lockstep: lined-up requests, the shorter run's count,
/// the offset, both chances.
struct Lockstep {
    k: usize,
    of: usize,
    offset: i64,
    placement: f64,
    gaps: f64,
    /// Permutations run.
    perms: usize,
}

impl Ctx<'_> {
    /// S3: run pairs of different clients in lockstep beyond both chance
    /// models. Every pair of different clients within reach of each other
    /// is a test.
    pub(super) fn lockstep(&self) -> Tests {
        let mut tests = Tests::default();
        let o = self.opts;
        let min = o.lockstep_min_events.max(2);
        let timed = self.by_start(&|r| r.events.len() >= min);
        let (Some(lo), Some(hi)) = (
            timed.iter().map(|&i| self.runs[i].events[0]).min(),
            timed
                .iter()
                .filter_map(|&i| self.runs[i].events.last().copied())
                .max(),
        ) else {
            return tests;
        };
        let d = o.lockstep_max_offset_secs.max(0);
        for (n, &i) in timed.iter().enumerate() {
            for &j in &timed[n + 1..] {
                let (x, y) = (&self.runs[i], &self.runs[j]);
                // By start: no later run comes within reach of `x` either.
                if y.start - d > x.end {
                    break;
                }
                if x.ci == y.ci || y.events[0] - d > x.events[x.events.len() - 1] {
                    continue;
                }
                let Some(diff) = differ(&x.fp, &y.fp) else {
                    continue;
                };
                tests.tested += 1;
                let Some(l) = self.test(x, y, (lo, hi)) else {
                    continue;
                };
                let p = l.placement.max(l.gaps);
                if p > o.lockstep_max_chance {
                    continue;
                }
                let differs = if diff.is_empty() {
                    String::new()
                } else {
                    format!("; they differ in {}", diff.join(", "))
                };
                let edge = self.edge(
                    SwarmEdgeKind::SynchronizedStart,
                    ((x, None, &x.members), (y, None, &y.members)),
                    if l.k >= 2 * min && !diff.is_empty() {
                        EdgeStrength::Moderate
                    } else {
                        EdgeStrength::Weak
                    },
                    Some(p),
                    format!(
                        "{} of {} requests of the shorter run line up with the other's at one offset ({} s, within {} s); chance {:.1e} under random placement over the analysis span and {:.1e} under {} permutations of its own gaps (p {p:.1e}){differs}",
                        l.k,
                        l.of,
                        l.offset,
                        o.lockstep_tolerance_secs,
                        l.placement,
                        l.gaps,
                        l.perms
                    ),
                );
                tests.found.push((p, vec![edge]));
            }
        }
        tests
    }

    /// The lockstep statistic of `x` and `y` and its two chances, or `None`
    /// when too few requests line up.
    fn test(&self, x: &Run, y: &Run, (lo, hi): (i64, i64)) -> Option<Lockstep> {
        let o = self.opts;
        let (tol, d) = (
            o.lockstep_tolerance_secs.max(0),
            o.lockstep_max_offset_secs.max(0),
        );
        let cut = |r: &Run| -> Vec<i64> { r.events.iter().take(MAX_EVENTS).copied().collect() };
        // `b` is the shorter run (the later on a tie); offsets are `b`'s
        // time minus `a`'s.
        let (a, b, flip) = if y.events.len() <= x.events.len() {
            (cut(x), cut(y), false)
        } else {
            (cut(y), cut(x), true)
        };
        let full = coverage(&a, &b, tol, None);
        let (k, offset) = best(&full, -d, d);
        if k < o.lockstep_min_events.max(2) || (k as f64) < o.lockstep_min_share * b.len() as f64 {
            return None;
        }
        // Placement: `b` shifted by `u` keeps within the analysis span,
        // and lines up at some offset in reach when an offset within `d`
        // of `-u` reaches `k`.
        let (b0, b1) = (b[0], b[b.len() - 1]);
        let placement = placed(&full, k, d, (b1 - hi) as f64, (b0 - lo) as f64);
        // Own gaps: `b`'s start kept, its gaps shuffled.
        let gaps: Vec<i64> = b.windows(2).map(|w| w[1] - w[0]).collect();
        let (ka, kb) = (&self.cl[x.ci].key, &self.cl[y.ci].key);
        let (na, nb) = (x.n.to_string(), y.n.to_string());
        let mut rng = Mix(seed(&[ka, &na, kb, &nb]));
        let base = o.lockstep_permutations.max(1);
        let most = o.lockstep_max_permutations.max(base);
        let mut ge = 0usize;
        let mut perms = 0usize;
        let mut g = gaps.clone();
        let mut shuffled = Vec::with_capacity(b.len());
        // The base permutations, continued to `most` while none lines up as
        // well: a chance at the base floor is resolved further. Stopping
        // early on a match keeps the chance valid, since a later stop only
        // follows no match.
        while perms < base || (ge == 0 && perms < most) {
            perms += 1;
            for i in (1..g.len()).rev() {
                g.swap(i, (rng.next() % (i as u64 + 1)) as usize);
            }
            shuffled.clear();
            shuffled.push(b0);
            for &step in &g {
                shuffled.push(shuffled[shuffled.len() - 1] + step);
            }
            let (kp, _) = best(&coverage(&a, &shuffled, tol, Some((-d, d))), -d, d);
            ge += usize::from(kp >= k);
        }
        Some(Lockstep {
            k,
            of: b.len(),
            offset: if flip { -offset } else { offset },
            placement,
            gaps: (1 + ge) as f64 / (1 + perms) as f64,
            perms,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn coverage_counts_each_request_once_at_its_offset() {
        let a = [0, 10, 30, 31, 60];
        let b = [5, 15, 35, 65];
        let cov = coverage(&a, &b, 1, None);
        // At offset 5 every request of `b` meets one of `a`.
        assert_eq!(best(&cov, -20, 20), (4, 5));
        assert_eq!(best(&cov, -20, 0).0, 1);
        // A window only reads offsets in it.
        assert_eq!(best(&coverage(&a, &b, 1, Some((4, 6))), 4, 6).0, 4);
    }

    #[test]
    fn placement_is_the_share_of_shifts_reaching_the_count() {
        let cov = vec![(0.0, 10.0, 4), (10.0, 1000.0, 1)];
        // Within 5 of [0, 10] over [-100, 100]: [-5, 15], 20 of 200.
        assert!((placed(&cov, 4, 5, -100.0, 100.0) - 0.1).abs() < 1e-9);
        assert_eq!(placed(&cov, 4, 5, 3.0, 3.0), 1.0);
    }
}
