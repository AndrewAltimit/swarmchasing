//! Interval estimates and agreement statistics for the evaluation.
//!
//! - [`wilson`]: the 95% Wilson score interval for `k` successes in `n`
//!   trials. It behaves at small `n` and near 0 or 1, where the normal
//!   interval does not (it never leaves `[0, 1]` and is not zero-width at
//!   `k = n`).
//! - [`cohen_kappa`]: chance-corrected agreement between two labellers.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// `z` for a two-sided 95% interval.
pub const Z95: f64 = 1.959_963_984_540_054;

/// A proportion with its count and 95% Wilson interval. `value`, `lo` and
/// `hi` are `None` when `n` is 0: nothing was measured.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Proportion {
    pub k: usize,
    pub n: usize,
    pub value: Option<f64>,
    pub lo: Option<f64>,
    pub hi: Option<f64>,
}

impl Proportion {
    pub fn new(k: usize, n: usize) -> Self {
        let ci = wilson(k, n);
        Self {
            k,
            n,
            value: (n > 0).then(|| k as f64 / n as f64),
            lo: ci.map(|c| c.0),
            hi: ci.map(|c| c.1),
        }
    }
}

/// The 95% Wilson score interval `(lo, hi)` for `k` of `n`; `None` when
/// `n` is 0.
pub fn wilson(k: usize, n: usize) -> Option<(f64, f64)> {
    wilson_z(k, n, Z95)
}

pub fn wilson_z(k: usize, n: usize, z: f64) -> Option<(f64, f64)> {
    if n == 0 {
        return None;
    }
    let n = n as f64;
    let p = (k as f64 / n).clamp(0.0, 1.0);
    let z2 = z * z;
    let denom = 1.0 + z2 / n;
    let centre = (p + z2 / (2.0 * n)) / denom;
    let half = (z / denom) * (p * (1.0 - p) / n + z2 / (4.0 * n * n)).sqrt();
    // At k = 0 or k = n one bound is exactly 0 or 1; pin it rather than
    // leave floating-point dust (0.9999999999999999).
    let lo = if k == 0 {
        0.0
    } else {
        (centre - half).max(0.0)
    };
    let hi = if k as f64 == n {
        1.0
    } else {
        (centre + half).min(1.0)
    };
    Some((lo, hi))
}

/// Cohen's κ over paired labels (one pair per item both labellers saw).
/// `None` for no pairs, or when chance agreement is 1 (both labellers used
/// one and the same label throughout, so κ is undefined).
pub fn cohen_kappa<S: AsRef<str>>(pairs: &[(S, S)]) -> Option<f64> {
    if pairs.is_empty() {
        return None;
    }
    let n = pairs.len() as f64;
    let mut a: BTreeMap<&str, f64> = BTreeMap::new();
    let mut b: BTreeMap<&str, f64> = BTreeMap::new();
    let mut agree = 0.0;
    for (x, y) in pairs {
        let (x, y) = (x.as_ref(), y.as_ref());
        *a.entry(x).or_default() += 1.0;
        *b.entry(y).or_default() += 1.0;
        if x == y {
            agree += 1.0;
        }
    }
    let po = agree / n;
    let pe: f64 = a
        .iter()
        .map(|(k, ca)| ca / n * b.get(k).copied().unwrap_or(0.0) / n)
        .sum();
    if (1.0 - pe).abs() < 1e-12 {
        return None;
    }
    Some((po - pe) / (1.0 - pe))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn close(a: f64, b: f64) -> bool {
        (a - b).abs() < 5e-4
    }

    #[test]
    fn wilson_matches_published_values() {
        // Newcombe (1998), table I: 81/263 -> 0.2553 to 0.3662.
        let (lo, hi) = wilson(81, 263).unwrap();
        assert!(close(lo, 0.2553) && close(hi, 0.3662), "{lo} {hi}");
        // All successes: the lower bound is n / (n + z^2).
        let (lo, hi) = wilson(43, 43).unwrap();
        assert!(close(lo, 43.0 / (43.0 + Z95 * Z95)), "{lo}");
        assert_eq!(hi, 1.0);
        assert_eq!(wilson(28, 28).unwrap().1, 1.0);
        let (lo, hi) = wilson(0, 10).unwrap();
        assert_eq!(lo, 0.0);
        assert!(close(hi, 0.2775), "{hi}");
        assert_eq!(wilson(0, 0), None);
        let p = Proportion::new(0, 0);
        assert_eq!((p.value, p.lo, p.hi), (None, None, None));
    }

    #[test]
    fn kappa() {
        // Cohen's worked example shape: 20 yes/yes, 15 no/no, 5 + 10 disagree.
        let mut pairs = Vec::new();
        pairs.extend(std::iter::repeat_n(("y", "y"), 20));
        pairs.extend(std::iter::repeat_n(("n", "n"), 15));
        pairs.extend(std::iter::repeat_n(("y", "n"), 5));
        pairs.extend(std::iter::repeat_n(("n", "y"), 10));
        // po = 0.7, pe = 0.5*0.6 + 0.5*0.4 = 0.5, kappa = 0.4.
        assert!(close(cohen_kappa(&pairs).unwrap(), 0.4));
        assert_eq!(cohen_kappa(&[("a", "a"), ("a", "a")]), None);
        assert_eq!(cohen_kappa::<&str>(&[]), None);
        assert!(close(cohen_kappa(&[("a", "a"), ("b", "b")]).unwrap(), 1.0));
    }
}
