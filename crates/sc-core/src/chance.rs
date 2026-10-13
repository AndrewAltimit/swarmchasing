//! Chance helpers the soft-link models share: the tail of a sum of
//! independent Bernoulli draws, and the Benjamini-Hochberg cut over many
//! tested pairs.

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

#[cfg(test)]
mod tests {
    use super::*;

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
