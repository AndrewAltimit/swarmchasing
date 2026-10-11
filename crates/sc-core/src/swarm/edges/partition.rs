//! S5 disjoint partition.

use super::{Ctx, MIN_HOSTS};
use crate::extract::defang_host;
use crate::swarm::runs::{Keyed, family, find, sort_keyed};
use crate::swarm::{EdgeStrength, SwarmEdge, SwarmEdgeKind};
use crate::timing::poisson_at_least;

/// Partitions kept when near-zero overlap is at most this likely (S5).
const MAX_PARTITION_CHANCE: f64 = 0.05;
/// Runs starting this close together can partition a list (S5).
const PARTITION_WINDOW_SECS: i64 = 600;

impl Ctx<'_> {
    /// S5: runs started together that split one host family with near-zero
    /// overlap. Chance: each run's hosts drawn at random from the family's
    /// hosts in the analysis; kept when so little overlap is unlikely.
    pub(super) fn partitions(&self, out: &mut Vec<SwarmEdge>) {
        // Hosts as `family host`, so a sort groups them by family.
        let by_family = |hosts: &Keyed| -> Keyed {
            let mut v: Keyed = hosts
                .iter()
                .map(|(h, t)| (format!("{} {h}", family(h)), *t))
                .collect();
            sort_keyed(&mut v);
            v
        };
        let fam = |k: &str| k.split(' ').next().unwrap_or("").to_string();
        let all = by_family(&self.all_hosts());
        let per: Vec<Keyed> = self.runs.iter().map(|r| by_family(&r.hosts)).collect();
        let order = self.by_start(&|r| r.hosts.len() >= MIN_HOSTS);
        for (n, &i) in order.iter().enumerate() {
            for &k in &order[n + 1..] {
                let (x, y) = (&self.runs[i], &self.runs[k]);
                if y.start - x.start > PARTITION_WINDOW_SECS {
                    break;
                }
                let mut best: Option<(f64, String, usize, usize, usize)> = None;
                for gx in per[i].chunk_by(|a, b| fam(&a.0) == fam(&b.0)) {
                    let f = fam(&gx[0].0);
                    let in_f = |v: &[(String, i64)]| v.iter().filter(|h| fam(&h.0) == f).count();
                    let ny = in_f(&per[k]);
                    let m = gx.iter().filter(|h| find(&per[k], &h.0).is_some()).count();
                    if gx.len() < MIN_HOSTS || ny < MIN_HOSTS || m * 10 > gx.len().min(ny) {
                        continue;
                    }
                    let lambda = (gx.len() * ny) as f64 / in_f(&all).max(1) as f64;
                    let p = 1.0 - poisson_at_least(lambda, m + 1);
                    if p <= MAX_PARTITION_CHANCE && best.as_ref().is_none_or(|b| p < b.0) {
                        best = Some((p, f, gx.len(), ny, m));
                    }
                }
                let Some((p, f, nx, ny, m)) = best else {
                    continue;
                };
                self.push(
                    out,
                    SwarmEdgeKind::DisjointPartition,
                    ((x, None, &x.members), (y, None, &y.members)),
                    EdgeStrength::Weak,
                    Some(p),
                    format!(
                        "started {} s apart, they split `*.{}` ({nx} and {ny} hosts, {m} shared; p {p:.1e}). One scheduler sharding a list does the same: a fleet signal unless other edges join these runs",
                        y.start - x.start,
                        defang_host(&f)
                    ),
                );
            }
        }
    }
}
