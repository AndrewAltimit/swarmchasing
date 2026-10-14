//! Chance helpers the pairwise tests share: the tail of a sum of
//! independent Bernoulli draws, the Benjamini-Hochberg cut over many tested
//! pairs, and the multiplicity budget each family of tests reports.
//!
//! Every pairwise test in the analysis (shared pauses, scaffolds,
//! co-activity, the S3 to S6 interaction edges, platform candidates) belongs
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
    /// `role_sequence`, `disjoint_partition`, `dispatch_star`, or
    /// `platform:<name>`.
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

/// The chance of a product of `ps` this small or smaller when they are
/// independent uniform chances (Fisher's method): `x Σ_{j<n} (-ln x)^j / j!`
/// for the product `x` of `n` chances. Two chances give [`product_chance`].
pub(crate) fn product_chance_all(ps: &[f64]) -> f64 {
    if ps.is_empty() {
        return 1.0;
    }
    let x: f64 = ps.iter().map(|p| p.clamp(0.0, 1.0)).product();
    if x <= 0.0 {
        return 0.0;
    }
    let l = -x.ln();
    let (mut term, mut sum) = (1.0, 1.0);
    for j in 1..ps.len() {
        term *= l / j as f64;
        sum += term;
    }
    (x * sum).min(1.0)
}

/// A small seeded generator (splitmix64), the same on every platform: the
/// permutation tests' source, so a chance is reproducible from the records.
pub(crate) struct Mix(pub(crate) u64);

impl Mix {
    pub(crate) fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    /// Shuffle `v` in place (Fisher-Yates).
    pub(crate) fn shuffle<T>(&mut self, v: &mut [T]) {
        for i in (1..v.len()).rev() {
            v.swap(i, (self.next() % (i as u64 + 1)) as usize);
        }
    }
}

/// FNV-1a over stable labels: a permutation test's seed.
pub(crate) fn seed(parts: &[&str]) -> u64 {
    let mut h = 0xcbf2_9ce4_8422_2325u64;
    for p in parts {
        for b in p.bytes().chain([0]) {
            h = (h ^ u64::from(b)).wrapping_mul(0x0100_0000_01b3);
        }
    }
    h
}

#[cfg(test)]
mod tests {
    use super::*;

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
        // The general form agrees for two, and for one is the chance itself.
        assert!((product_chance_all(&[0.1, 0.1]) - product_chance(0.1, 0.1)).abs() < 1e-12);
        assert!((product_chance_all(&[0.03]) - 0.03).abs() < 1e-12);
        // Three: P(U1 U2 U3 <= x) = x (1 + l + l^2 / 2), l = -ln x.
        let x: f64 = 0.001;
        let l = -x.ln();
        let want = x * (1.0 + l + l * l / 2.0);
        assert!((product_chance_all(&[0.1, 0.1, 0.1]) - want).abs() < 1e-12);
        assert_eq!(product_chance_all(&[]), 1.0);
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
