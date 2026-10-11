//! S4 role sequence.

use super::{Ctx, MAX_CHANCE, MIN_HOSTS};
use crate::swarm::runs::{differ, find};
use crate::swarm::{EdgeStrength, SwarmEdge, SwarmEdgeKind};
use crate::timing::poisson_at_least;

/// The attacking run starts at most this long after the reading run ends (S4).
const ROLE_WINDOW_SECS: i64 = 6 * 3600;

impl Ctx<'_> {
    /// S4: a run that only reads hosts, then a differently fingerprinted run
    /// attacking most of them, each after it was read. Chance: the attacked
    /// hosts drawn at random from every target host in the analysis.
    pub(super) fn role_sequences(&self, out: &mut Vec<SwarmEdge>) {
        let n = self.all_hosts().len().max(1) as f64;
        for x in self.runs {
            if !x.attacks.is_empty() || x.hosts.len() < MIN_HOSTS {
                continue;
            }
            for y in self.runs {
                if y.attacks.len() < MIN_HOSTS
                    || y.start < x.start
                    || y.start > x.end + ROLE_WINDOW_SECS
                {
                    continue;
                }
                let Some(d) = differ(&x.fp, &y.fp) else {
                    continue;
                };
                let (mut shared, mut after) = (0, 0);
                for (h, t) in &x.hosts {
                    if let Some(ty) = find(&y.attacks, h) {
                        shared += 1;
                        after += usize::from(ty > *t);
                    }
                }
                let j = shared as f64 / (x.hosts.len() + y.attacks.len() - shared) as f64;
                if d.is_empty()
                    || shared < MIN_HOSTS
                    || j < 0.5
                    || (after as f64) < 0.8 * shared as f64
                {
                    continue;
                }
                let p = poisson_at_least((x.hosts.len() * y.attacks.len()) as f64 / n, shared);
                if p > MAX_CHANCE {
                    continue;
                }
                self.push(
                    out,
                    SwarmEdgeKind::RoleSequence,
                    ((x, None, &x.members), (y, None, &y.members)),
                    if j >= 0.7 && after == shared {
                        EdgeStrength::Moderate
                    } else {
                        EdgeStrength::Weak
                    },
                    Some(p),
                    format!(
                        "the first only reads {} hosts; the second attacks {shared} of them (Jaccard {j:.2}), {after} after the first read them; they differ in {} (p {p:.1e})",
                        x.hosts.len(),
                        d.join(", ")
                    ),
                );
            }
        }
    }
}
