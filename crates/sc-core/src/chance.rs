//! Chance helpers the soft-link models share: the Benjamini-Hochberg cut
//! over many tested pairs.

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
    fn bh_keeps_the_largest_chance_under_its_rank_line() {
        // q = 0.05 over 4 tests: lines 0.0125, 0.025, 0.0375, 0.05.
        assert_eq!(bh_cut(&[0.001, 0.03, 0.02, 0.5], 4, 0.05), Some(0.03));
        assert_eq!(bh_cut(&[0.02, 0.5], 4, 0.05), None);
        // More tested than reported raises the bar.
        assert_eq!(bh_cut(&[0.01], 1, 0.05), Some(0.01));
        assert_eq!(bh_cut(&[0.01], 10, 0.05), None);
    }
}
