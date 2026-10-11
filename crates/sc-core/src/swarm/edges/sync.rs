//! S3 synchronized start.

use super::{Ctx, MAX_CHANCE};
use crate::swarm::runs::{differ, fp_of};
use crate::swarm::{EdgeStrength, SwarmEdge, SwarmEdgeKind};
use crate::timing::poisson_at_least;

/// Starts and ends this close together match (S3).
const START_TOLERANCE_SECS: i64 = 120;
/// A match on a clock hour counts for this much of one (S3).
const CLOCK_WEIGHT: f64 = 0.25;

impl Ctx<'_> {
    /// S3: clusters whose runs start and end together beyond chance. The
    /// model is the shared-pause one: a run pair whose lengths differ by less
    /// than twice the tolerance matches by chance with probability `(2 tol -
    /// |length difference|) / W`, `W` the time the runs could start in.
    pub(super) fn synchronized(&self, out: &mut Vec<SwarmEdge>) {
        let (runs, tol) = (self.runs, START_TOLERANCE_SECS);
        let timed = self.by_start(&|r| r.members.len() >= 3);
        let (Some(&lo), Some(hi)) = (timed.first(), timed.iter().map(|&i| runs[i].end).max())
        else {
            return;
        };
        let window = (hi - runs[lo].start).max(1) as f64;
        let mut pairs: Vec<(usize, usize)> = Vec::new();
        for (n, &i) in timed.iter().enumerate() {
            for &j in &timed[n + 1..] {
                let (x, y) = (&runs[i], &runs[j]);
                if y.start - x.start > tol {
                    break;
                }
                let p = (x.ci.min(y.ci), x.ci.max(y.ci));
                if x.ci != y.ci && (x.end - y.end).abs() <= tol && !pairs.contains(&p) {
                    pairs.push(p);
                }
            }
        }
        for (cx, cy) in pairs {
            let fx = fp_of(self.res, &self.cl[cx].members);
            let Some(d) = differ(&fx, &fp_of(self.res, &self.cl[cy].members)) else {
                continue;
            };
            if d.is_empty() {
                continue;
            }
            let (mut expected, mut matched) = (0.0, Vec::<(usize, usize)>::new());
            for &i in &timed {
                for &j in &timed {
                    let (x, y) = (&runs[i], &runs[j]);
                    if x.ci != cx || y.ci != cy {
                        continue;
                    }
                    let dd = ((x.end - x.start) - (y.end - y.start)).abs();
                    if dd < 2 * tol {
                        expected += ((2 * tol - dd) as f64 / window).min(1.0);
                    }
                    if (x.start - y.start).abs() <= tol
                        && (x.end - y.end).abs() <= tol
                        && !matched.iter().any(|m| m.1 == j)
                    {
                        matched.push((i, j));
                    }
                }
            }
            let hourly = |t: i64| {
                let r = t.rem_euclid(3600);
                r <= tol || r >= 3600 - tol
            };
            let mut weight = 0.0;
            for m in &matched {
                let x = &runs[m.0];
                weight += if hourly(x.start) || hourly(x.end) {
                    CLOCK_WEIGHT
                } else {
                    1.0
                };
            }
            let p = poisson_at_least(expected, weight as usize);
            if weight < 1.0 || p > MAX_CHANCE {
                continue;
            }
            let (x, y) = (&runs[matched[0].0], &runs[matched[0].1]);
            self.push(
                out,
                SwarmEdgeKind::SynchronizedStart,
                ((x, None, &x.members), (y, None, &y.members)),
                if matched.len() >= 2 && p <= 1e-4 {
                    EdgeStrength::Moderate
                } else {
                    EdgeStrength::Weak
                },
                Some(p),
                format!(
                    "{} run(s) start and end within {tol} s of each other, {expected:.3} expected by chance (p {p:.1e}); they differ in {}",
                    matched.len(),
                    d.join(", ")
                ),
            );
        }
    }
}
