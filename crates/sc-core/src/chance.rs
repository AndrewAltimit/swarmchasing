//! Chance helpers the pairwise tests share: the tail of a sum of
//! independent Bernoulli draws, the Benjamini-Hochberg cut over many tested
//! pairs, and the multiplicity budget each family of tests reports.
//!
//! Every pairwise test in the analysis (shared pauses, scaffolds,
//! co-activity, the S3 to S5 interaction edges, platform candidates) belongs
//! to one [`TestFamily`]. A family counts the pairs it tested, keeps those
//! whose chance passes its own limit and a Benjamini-Hochberg cut over every
//! pair tested, and states how many pairs that unlikely chance alone would
//! give among them.

use serde::{Deserialize, Serialize};

/// `P(X >= k)` for `X` the number of successes among independent draws with
/// probabilities `ps` (a Poisson-binomial tail).
pub(crate) fn at_least(ps: &[f64], k: usize) -> f64 {
    if k == 0 {
        return 1.0;
    }
    if k > ps.len() {
        return 0.0;
    }
    // dist[j]: probability of exactly j successes so far, j < k; the mass
    // reaching k is folded into `done`.
    let mut dist = vec![0.0; k];
    dist[0] = 1.0;
    let mut done = 0.0;
    for &p in ps {
        let p = p.clamp(0.0, 1.0);
        done += dist[k - 1] * p;
        for j in (1..k).rev() {
            dist[j] = dist[j] * (1.0 - p) + dist[j - 1] * p;
        }
        dist[0] *= 1.0 - p;
    }
    done.clamp(0.0, 1.0)
}

/// The Benjamini-Hochberg cut for `chances` at false discovery rate `q`
/// over `tested` hypotheses (at least `chances.len()`): the largest chance
/// that is kept, or `None` when none is. A pair is kept when its chance is
/// at most the cut.
pub(crate) fn bh_cut(chances: &[f64], tested: usize, q: f64) -> Option<f64> {
    let mut v: Vec<f64> = chances.to_vec();
    v.sort_by(f64::total_cmp);
    let m = tested.max(v.len()).max(1) as f64;
    v.iter()
        .enumerate()
        .filter(|(i, p)| **p <= (*i + 1) as f64 * q / m)
        .map(|(_, p)| *p)
        .next_back()
}

/// One family of pairwise tests and what its multiplicity budget kept.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct TestFamily {
    /// `shared_pause`, `scaffold`, `co_activity`, `synchronized_start`,
    /// `role_sequence`, `disjoint_partition`, or `platform:<name>`.
    pub family: String,
    /// Pairs (or groups) tested.
    pub tested: usize,
    /// Of those, at or under the family's own chance limit.
    pub passed: usize,
    /// Of those, under the Benjamini-Hochberg cut: the ones reported.
    pub kept: usize,
    /// The false discovery rate the cut is taken at.
    pub fdr: f64,
    /// The largest chance kept, when any is.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cut: Option<f64>,
    /// Tests at least as unlikely as the weakest kept that chance alone
    /// would give among those tested: `tested × cut`.
    pub expected: f64,
}

impl TestFamily {
    /// The family over `chances` (those at or under its own limit) of
    /// `tested` tests, cut at false discovery rate `fdr`. A test is kept when
    /// [`TestFamily::keeps`] its chance.
    pub(crate) fn cut(family: &str, chances: &[f64], tested: usize, fdr: f64) -> Self {
        let tested = tested.max(chances.len());
        let cut = bh_cut(chances, tested, fdr);
        let kept = cut.map_or(0, |c| chances.iter().filter(|&&p| p <= c).count());
        Self {
            family: family.to_string(),
            tested,
            passed: chances.len(),
            kept,
            fdr,
            cut,
            expected: cut.map_or(0.0, |c| c * tested as f64),
        }
    }

    /// Whether a test of this chance is kept.
    pub fn keeps(&self, chance: f64) -> bool {
        self.cut.is_some_and(|c| chance <= c)
    }

    /// `shared_pause: 2 kept of 40 tested (3 under its own limit), ...`.
    pub fn line(&self) -> String {
        format!(
            "{}: {} kept of {} tested ({} under its own limit), {:.2} that unlikely expected by chance (false discovery rate {:.0}%)",
            self.family,
            self.kept,
            self.tested,
            self.passed,
            self.expected,
            self.fdr * 100.0
        )
    }
}

/// The chance that the smallest of `t` independent chances is at most `p`
/// (Sidak): `1 - (1 - p)^t`.
pub(crate) fn sidak(p: f64, t: usize) -> f64 {
    let p = p.clamp(0.0, 1.0);
    if t <= 1 || p >= 1.0 {
        return p;
    }
    // Without cancellation for small `p`.
    (-(t as f64 * (-p).ln_1p()).exp_m1()).clamp(0.0, 1.0)
}

/// The chance of a product `p1 × p2` this small or smaller when the two are
/// independent uniform chances: `x (1 - ln x)` for the product `x`.
pub(crate) fn product_chance(p1: f64, p2: f64) -> f64 {
    let x = (p1 * p2).clamp(0.0, 1.0);
    if x <= 0.0 {
        return 0.0;
    }
    (x * (1.0 - x.ln())).min(1.0)
}

/// Items up to which [`increasing_at_least`] is exact.
const LIS_EXACT_MAX: usize = 30;

/// `ln(n!)`.
pub(crate) fn ln_fact(n: usize) -> f64 {
    (2..=n).map(|i| (i as f64).ln()).sum()
}

/// `P(LIS >= l)` for the longest increasing subsequence of a uniformly
/// random permutation of `k` items. Exact up to [`LIS_EXACT_MAX`] items, by
/// the Robinson-Schensted correspondence: the permutations whose longest
/// increasing subsequence is `l` are counted by the squared numbers of
/// standard Young tableaux (hook length formula) of the partitions of `k`
/// whose first row is `l`. Above that, the union bound over every set of
/// `l` positions, `C(k, l) / l!`, which overstates the chance, never
/// understates it.
pub(crate) fn increasing_at_least(k: usize, l: usize) -> f64 {
    if l <= 1 {
        return 1.0;
    }
    if l > k {
        return 0.0;
    }
    if k <= LIS_EXACT_MAX {
        return lis_table()[k][l];
    }
    let ln = ln_fact(k) - ln_fact(l) - ln_fact(k - l) - ln_fact(l);
    ln.exp().min(1.0)
}

/// `table[k][l]`: `P(LIS >= l)` over permutations of `k` items, for `k` up
/// to [`LIS_EXACT_MAX`].
fn lis_table() -> &'static Vec<Vec<f64>> {
    static TABLE: std::sync::OnceLock<Vec<Vec<f64>>> = std::sync::OnceLock::new();
    TABLE.get_or_init(|| {
        (0..=LIS_EXACT_MAX)
            .map(|k| {
                // exact[l]: P(LIS = l).
                let mut exact = vec![0.0; k + 2];
                let ln_k = ln_fact(k);
                let mut parts = Vec::new();
                partitions(k, k, &mut parts, &mut |lambda| {
                    let ln_f = ln_k - ln_hooks(lambda);
                    exact[lambda[0]] += (2.0 * ln_f - ln_k).exp();
                });
                let mut at_least = vec![0.0; k + 2];
                for l in (0..=k).rev() {
                    at_least[l] = (at_least[l + 1] + exact[l]).min(1.0);
                }
                if k == 0 {
                    at_least[0] = 1.0;
                }
                at_least
            })
            .collect()
    })
}

/// Every partition of `n` into parts of at most `max`, largest first.
fn partitions(n: usize, max: usize, parts: &mut Vec<usize>, f: &mut impl FnMut(&[usize])) {
    if n == 0 {
        if !parts.is_empty() {
            f(parts);
        }
        return;
    }
    for p in (1..=max.min(n)).rev() {
        parts.push(p);
        partitions(n - p, p, parts, f);
        parts.pop();
    }
}

/// The sum of the logs of the hook lengths of partition `lambda`.
fn ln_hooks(lambda: &[usize]) -> f64 {
    let mut s = 0.0;
    for (i, &row) in lambda.iter().enumerate() {
        for j in 0..row {
            // Cells below (i, j): rows after i at least j + 1 long.
            let below = lambda[i + 1..].iter().filter(|&&r| r > j).count();
            s += ((row - j - 1 + below + 1) as f64).ln();
        }
    }
    s
}

/// The longest chain of `points` increasing strictly in both coordinates:
/// the longest increasing subsequence of one order read in the other, with
/// ties in either order never counted as agreement.
pub(crate) fn longest_chain(points: &[(i64, i64)]) -> usize {
    let mut p = points.to_vec();
    p.sort();
    let mut best = vec![1usize; p.len()];
    for j in 0..p.len() {
        for i in 0..j {
            if p[i].0 < p[j].0 && p[i].1 < p[j].1 {
                best[j] = best[j].max(best[i] + 1);
            }
        }
    }
    best.into_iter().max().unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn longest_increasing_subsequence_chances() {
        // Every one of 5! orders: one is fully increasing.
        assert!((increasing_at_least(5, 5) - 1.0 / 120.0).abs() < 1e-12);
        assert_eq!(increasing_at_least(5, 1), 1.0);
        assert_eq!(increasing_at_least(5, 6), 0.0);
        // Brute force over permutations of 6: count by LIS.
        fn perms(v: &mut Vec<i64>, k: usize, out: &mut Vec<Vec<i64>>) {
            if k == v.len() {
                out.push(v.clone());
                return;
            }
            for i in k..v.len() {
                v.swap(k, i);
                perms(v, k + 1, out);
                v.swap(k, i);
            }
        }
        let mut all = Vec::new();
        perms(&mut (0..6).collect(), 0, &mut all);
        for l in 1..=6 {
            let n = all
                .iter()
                .filter(|p| {
                    let pts: Vec<(i64, i64)> =
                        p.iter().enumerate().map(|(i, &x)| (i as i64, x)).collect();
                    longest_chain(&pts) >= l
                })
                .count();
            let want = n as f64 / all.len() as f64;
            assert!((increasing_at_least(6, l) - want).abs() < 1e-9, "{l}");
        }
        // The bound above the exact range is above the exact value below it.
        let exact = increasing_at_least(30, 20);
        let bound = (ln_fact(30) - ln_fact(20) - ln_fact(10) - ln_fact(20)).exp();
        assert!(exact <= bound && exact > 0.0, "{exact} {bound}");
        assert!(increasing_at_least(40, 30) < 1e-20);
        // Ties never count as agreement.
        assert_eq!(longest_chain(&[(0, 0), (0, 1), (1, 0)]), 1);
        assert_eq!(longest_chain(&[(0, 0), (1, 1), (2, 2)]), 3);
    }

    #[test]
    fn a_family_keeps_what_its_cut_keeps_and_states_the_expected() {
        // Lines 0.0125, 0.025, 0.0375, 0.05 over four tests.
        let f = TestFamily::cut("x", &[0.001, 0.04, 0.02], 4, 0.05);
        assert_eq!((f.tested, f.passed, f.kept), (4, 3, 2));
        assert_eq!(f.cut, Some(0.02));
        assert!((f.expected - 0.08).abs() < 1e-12);
        assert!(f.keeps(0.02) && !f.keeps(0.04));
        let none = TestFamily::cut("y", &[0.04], 10, 0.05);
        assert_eq!((none.kept, none.cut, none.expected), (0, None, 0.0));
        assert!(
            none.line().contains("0 kept of 10 tested"),
            "{}",
            none.line()
        );
    }

    #[test]
    fn sidak_and_the_product_chance() {
        assert!((sidak(0.01, 3) - (1.0 - 0.99f64.powi(3))).abs() < 1e-12);
        assert_eq!(sidak(0.2, 1), 0.2);
        assert!(sidak(1e-12, 5) > 4.9e-12);
        // Two independent uniform chances: P(U1 U2 <= x) = x (1 - ln x).
        let x: f64 = 0.01;
        assert!((product_chance(0.1, 0.1) - x * (1.0 - x.ln())).abs() < 1e-12);
        assert_eq!(product_chance(1.0, 1.0), 1.0);
        assert_eq!(product_chance(0.0, 0.5), 0.0);
    }

    #[test]
    fn the_tail_matches_the_binomial() {
        // Binomial(4, 0.5): P(X >= 3) = 5/16.
        assert!((at_least(&[0.5; 4], 3) - 5.0 / 16.0).abs() < 1e-12);
        assert_eq!(at_least(&[0.5; 4], 0), 1.0);
        assert_eq!(at_least(&[0.5; 4], 5), 0.0);
        // Unequal draws: P(both) = 0.1 * 0.2.
        assert!((at_least(&[0.1, 0.2], 2) - 0.02).abs() < 1e-12);
    }

    #[test]
    fn bh_keeps_the_largest_chance_under_its_rank_line() {
        // q = 0.05 over 4 tests: lines 0.0125, 0.025, 0.0375, 0.05.
        assert_eq!(bh_cut(&[0.001, 0.03, 0.02, 0.5], 4, 0.05), Some(0.03));
        assert_eq!(bh_cut(&[0.02, 0.5], 4, 0.05), None);
        // More tested than reported raises the bar.
        assert_eq!(bh_cut(&[0.01], 1, 0.05), Some(0.01));
        assert_eq!(bh_cut(&[0.01], 10, 0.05), None);
    }
}
