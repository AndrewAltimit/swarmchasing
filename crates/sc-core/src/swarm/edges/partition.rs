//! S5 disjoint partition.
//!
//! Two tests. **Structured**: runs started together whose hosts in one
//! family are disjoint and split their sorted union in a stride (every
//! k-th host) or in contiguous blocks, as a list handed out in shards is.
//! The chance is the share of all ways to split those hosts into parts of
//! these sizes that are that regular. **Random draw**: two runs started
//! together that barely overlap, against hosts drawn at random from the
//! family's hosts in the analysis. The host set is built from the runs, so
//! the random draw can never find a complete sharding of a family; the
//! structured test can.

use super::{Ctx, MAX_CHANCE, MIN_HOSTS};
use crate::extract::defang_host;
use crate::swarm::runs::{Keyed, differ, family, find, sort_keyed};
use crate::swarm::{EdgeStrength, SwarmEdge, SwarmEdgeKind};
use crate::timing::poisson_at_least;
use std::cmp::Ordering;

/// Partitions kept when near-zero overlap is at most this likely (S5).
const MAX_PARTITION_CHANCE: f64 = 0.05;
/// Runs starting this close together can partition a list (S5).
const PARTITION_WINDOW_SECS: i64 = 600;
/// Host orders a list may be sharded in: as text, and with numbers read as
/// numbers (`h2` before `h10`).
const ORDERS: f64 = 2.0;

/// `a` against `b` with runs of digits compared as numbers.
fn natural(a: &str, b: &str) -> Ordering {
    let chunks = |s: &str| -> Vec<(bool, String)> {
        let mut out: Vec<(bool, String)> = Vec::new();
        for c in s.chars() {
            let d = c.is_ascii_digit();
            match out.last_mut() {
                Some((x, s)) if *x == d => s.push(c),
                _ => out.push((d, c.to_string())),
            }
        }
        out
    };
    let (ca, cb) = (chunks(a), chunks(b));
    for (x, y) in ca.iter().zip(&cb) {
        let o = if x.0 && y.0 {
            let (p, q) = (x.1.trim_start_matches('0'), y.1.trim_start_matches('0'));
            p.len().cmp(&q.len()).then(p.cmp(q))
        } else {
            x.1.cmp(&y.1)
        };
        if o != Ordering::Equal {
            return o;
        }
    }
    ca.len().cmp(&cb.len()).then(a.cmp(b))
}

/// How the labels (one per host, in host order) split: `stride` when each
/// stretch of `k` holds every part once in one order, `block` when each
/// part's hosts are contiguous.
fn shape(labels: &[usize], k: usize) -> Option<&'static str> {
    if labels.len() > k && labels.iter().enumerate().all(|(i, &l)| l == labels[i % k]) {
        let mut first: Vec<usize> = labels[..k].to_vec();
        first.sort_unstable();
        first.dedup();
        if first.len() == k {
            return Some("stride");
        }
    }
    let changes = labels.windows(2).filter(|w| w[0] != w[1]).count();
    (changes + 1 == k).then_some("block")
}

/// `ln n!`.
fn ln_factorial(n: usize) -> f64 {
    (2..=n).map(|i| (i as f64).ln()).sum()
}

/// Chance that a split of `sizes.iter().sum()` hosts into parts of these
/// sizes, drawn at random, is a stride or contiguous blocks in one of
/// [`ORDERS`] host orders.
fn regular_chance(sizes: &[usize]) -> f64 {
    let (n, k) = (sizes.iter().sum::<usize>(), sizes.len());
    let total = ln_factorial(n) - sizes.iter().map(|&s| ln_factorial(s)).sum::<f64>();
    // Blocks: the parts in any order.
    let mut regular = (1..=k).product::<usize>() as f64;
    if sizes.iter().any(|&s| s > 1) {
        // Stride: residue `r` holds `ceil((n - r) / k)` hosts; the parts
        // can take the residues in any order that matches those sizes.
        let mut want: Vec<usize> = (0..k).map(|r| (n - r).div_ceil(k)).collect();
        let mut have = sizes.to_vec();
        want.sort_unstable();
        have.sort_unstable();
        if want == have {
            let mut ways = 1.0;
            for g in have.chunk_by(|a, b| a == b) {
                ways *= (1..=g.len()).product::<usize>() as f64;
            }
            regular += ways;
        }
    }
    (ORDERS * regular / total.exp()).min(1.0)
}

impl Ctx<'_> {
    /// S5: runs started together that split one host family.
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
        let per: Vec<Keyed> = self.runs.iter().map(|r| by_family(&r.hosts)).collect();
        let order = self.by_start(&|r| r.hosts.len() >= MIN_HOSTS);
        let mut done: Vec<(usize, usize)> = Vec::new();
        self.structured(&per, &order, &mut done, out);
        self.drawn(&per, &order, &done, out);
    }

    /// Structured splits: from each run, the later runs within the window
    /// with hosts in one of its families, disjoint from it and each other.
    fn structured(
        &self,
        per: &[Keyed],
        order: &[usize],
        done: &mut Vec<(usize, usize)>,
        out: &mut Vec<SwarmEdge>,
    ) {
        let fam = |k: &str| k.split(' ').next().unwrap_or("").to_string();
        let host = |k: &str| k.split_once(' ').map_or("", |x| x.1).to_string();
        let in_f = |i: usize, f: &str| -> Vec<String> {
            per[i]
                .iter()
                .filter(|h| fam(&h.0) == f)
                .map(|h| host(&h.0))
                .collect()
        };
        for (n, &i) in order.iter().enumerate() {
            for g in per[i].chunk_by(|a, b| fam(&a.0) == fam(&b.0)) {
                let f = fam(&g[0].0);
                if g.len() < MIN_HOSTS {
                    continue;
                }
                let mut group: Vec<(usize, Vec<String>)> = vec![(i, in_f(i, &f))];
                for &k in &order[n + 1..] {
                    if self.runs[k].start - self.runs[i].start > PARTITION_WINDOW_SECS {
                        break;
                    }
                    let mine = in_f(k, &f);
                    let apart = group.iter().all(|(g, hs)| {
                        self.runs[*g].ci != self.runs[k].ci && !hs.iter().any(|h| mine.contains(h))
                    });
                    if mine.len() >= MIN_HOSTS && apart {
                        group.push((k, mine));
                    }
                }
                if group.len() < 2 {
                    continue;
                }
                let mut all: Vec<(String, usize)> = group
                    .iter()
                    .enumerate()
                    .flat_map(|(p, (_, hs))| hs.iter().map(move |h| (h.clone(), p)))
                    .collect();
                let mut found = None;
                for natural_order in [true, false] {
                    if natural_order {
                        all.sort_by(|a, b| natural(&a.0, &b.0));
                    } else {
                        all.sort();
                    }
                    let labels: Vec<usize> = all.iter().map(|x| x.1).collect();
                    if let Some(s) = shape(&labels, group.len()) {
                        found = Some(s);
                        break;
                    }
                }
                let Some(how) = found else {
                    continue;
                };
                let sizes: Vec<usize> = group.iter().map(|(_, hs)| hs.len()).collect();
                let p = regular_chance(&sizes);
                if p > MAX_CHANCE {
                    continue;
                }
                let list: Vec<String> = sizes.iter().map(usize::to_string).collect();
                for (a, (x, _)) in group.iter().enumerate() {
                    for (y, _) in &group[a + 1..] {
                        let pair = ((*x).min(*y), (*x).max(*y));
                        if done.contains(&pair) {
                            continue;
                        }
                        done.push(pair);
                        let (rx, ry) = (&self.runs[*x], &self.runs[*y]);
                        let d = differ(&rx.fp, &ry.fp).unwrap_or_default();
                        let clients = if d.is_empty() {
                            "one client, or clients not told apart".to_string()
                        } else {
                            format!("clients differing in {}", d.join(", "))
                        };
                        self.push(
                            out,
                            SwarmEdgeKind::DisjointPartition,
                            ((rx, None, &rx.members), (ry, None, &ry.members)),
                            if d.is_empty() {
                                EdgeStrength::Weak
                            } else {
                                EdgeStrength::Moderate
                            },
                            Some(p),
                            format!(
                                "{} runs started within {} s split `*.{}` ({} hosts) with no host shared, in a {how} split of the sorted hosts; a split that regular {p:.1e} of the time at random; {clients}. One scheduler sharding a list does the same: a fleet signal unless other edges join these runs",
                                group.len(),
                                PARTITION_WINDOW_SECS,
                                defang_host(&f),
                                list.join(" + ")
                            ),
                        );
                    }
                }
            }
        }
    }

    /// Two runs started together that barely overlap in a family, against
    /// hosts drawn at random from the family's hosts in the analysis.
    fn drawn(
        &self,
        per: &[Keyed],
        order: &[usize],
        done: &[(usize, usize)],
        out: &mut Vec<SwarmEdge>,
    ) {
        let fam = |k: &str| k.split(' ').next().unwrap_or("").to_string();
        let all = {
            let mut v: Keyed = self
                .all_hosts()
                .iter()
                .map(|(h, t)| (format!("{} {h}", family(h)), *t))
                .collect();
            sort_keyed(&mut v);
            v
        };
        for (n, &i) in order.iter().enumerate() {
            for &k in &order[n + 1..] {
                let (x, y) = (&self.runs[i], &self.runs[k]);
                if y.start - x.start > PARTITION_WINDOW_SECS {
                    break;
                }
                if done.contains(&(i.min(k), i.max(k))) {
                    continue;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hosts_sort_with_numbers_as_numbers() {
        let mut v = vec!["h10.a", "h2.a", "h1.a", "h02.b"];
        v.sort_by(|a, b| natural(a, b));
        assert_eq!(v, ["h1.a", "h2.a", "h02.b", "h10.a"]);
    }

    #[test]
    fn strides_and_blocks_are_told_apart() {
        assert_eq!(shape(&[0, 1, 2, 0, 1, 2, 0], 3), Some("stride"));
        assert_eq!(shape(&[1, 0, 1, 0], 2), Some("stride"));
        assert_eq!(shape(&[0, 0, 1, 1, 1], 2), Some("block"));
        assert_eq!(shape(&[0, 1, 1, 0], 2), None);
    }

    #[test]
    fn the_chance_counts_the_regular_splits() {
        // Two parts of 4: 70 splits, 2 strides and 2 block orders, in two
        // host orders.
        assert!((regular_chance(&[4, 4]) - 8.0 / 70.0).abs() < 1e-9);
        // Three parts of 4: 34650 splits, 6 strides and 6 block orders.
        assert!((regular_chance(&[4, 4, 4]) - 24.0 / 34650.0).abs() < 1e-9);
        // Sizes no stride gives: blocks only.
        assert!((regular_chance(&[3, 5]) - 4.0 / 56.0).abs() < 1e-9);
    }
}
