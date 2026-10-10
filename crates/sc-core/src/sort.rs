//! Stable sorts that share one compiled sort routine.
//!
//! The standard library's `sort_by` is generic over the element and the
//! comparison, so every call site compiles its own copy of the sort, a few
//! KiB each. Dozens of them were the largest single cost in the browser
//! module. These functions sort a list of indexes instead, through one
//! instantiation of the standard stable sort that calls the comparison
//! through a `dyn` reference, then move the elements into that order.
//!
//! The result is the standard stable sort's result: a stable sort of a
//! consistent comparison has exactly one answer.

use std::cmp::Ordering;

/// Sort `v` in place, stably, by `cmp`. As `slice::sort_by`.
pub fn by<T>(v: &mut [T], mut cmp: impl FnMut(&T, &T) -> Ordering) {
    if v.len() < 2 {
        return;
    }
    let swaps = {
        let v: &[T] = v;
        swaps(order(v.len(), &mut |a, b| cmp(&v[a], &v[b])))
    };
    for (a, b) in swaps {
        v.swap(a, b);
    }
}

/// Sort `v` in place, stably, by `key`. As `slice::sort_by_key`.
pub fn by_key<T, K: Ord>(v: &mut [T], mut key: impl FnMut(&T) -> K) {
    by(v, |a, b| key(a).cmp(&key(b)));
}

/// Sort `v` in place, stably. As `slice::sort`.
pub fn sort<T: Ord>(v: &mut [T]) {
    by(v, T::cmp);
}

/// The indexes `0..n` in the order `cmp` puts the elements they name.
#[inline(never)]
fn order(n: usize, cmp: &mut dyn FnMut(usize, usize) -> Ordering) -> Vec<usize> {
    let mut idx: Vec<usize> = (0..n).collect();
    idx.sort_by(|&a, &b| cmp(a, b));
    idx
}

/// The swaps that move element `order[i]` to position `i` for every `i`,
/// one cycle of the permutation at a time.
#[inline(never)]
fn swaps(order: Vec<usize>) -> Vec<(usize, usize)> {
    let mut done = vec![false; order.len()];
    let mut out = Vec::new();
    for start in 0..order.len() {
        let mut j = start;
        while !done[j] {
            done[j] = true;
            let k = order[j];
            if k == start {
                break;
            }
            out.push((j, k));
            j = k;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // Matches the standard stable sort, ties included, over many shapes.
    #[test]
    fn matches_the_standard_stable_sort() {
        let mut seed = 0x2545_f491_4f6c_dd1du64;
        let mut next = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        for n in 0..200 {
            let v: Vec<(u64, usize)> = (0..n).map(|i| (next() % 7, i)).collect();
            let mut want = v.clone();
            want.sort_by_key(|p| p.0);
            let mut got = v.clone();
            by_key(&mut got, |p| p.0);
            assert_eq!(got, want);
            // Descending, with everything below 3 tied.
            let cmp = |a: &(u64, usize), b: &(u64, usize)| {
                if a.0 < 3 && b.0 < 3 {
                    Ordering::Equal
                } else {
                    b.0.cmp(&a.0)
                }
            };
            let mut want = v.clone();
            want.sort_by(cmp);
            let mut got = v;
            by(&mut got, cmp);
            assert_eq!(got, want);
        }
        let mut s = vec!["b", "a", "c", "a"];
        sort(&mut s);
        assert_eq!(s, ["a", "a", "b", "c"]);
    }
}
