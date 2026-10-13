//! A small seeded generator (SplitMix64), so a scenario and a seed always
//! give the same records on every platform, the browser included.

#[derive(Debug, Clone)]
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Self {
        Self(seed ^ 0x9e37_79b9_7f4a_7c15)
    }

    /// A generator for a named sub-stream, so adding an actor does not shift
    /// the draws of the others.
    pub fn fork(&self, label: &str) -> Self {
        let mut h = self.0;
        for b in label.bytes() {
            h = (h ^ u64::from(b)).wrapping_mul(0x0100_0000_01b3);
        }
        Self::new(h)
    }

    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    /// Uniform in `[0, 1)`.
    pub fn unit(&mut self) -> f64 {
        (self.next_u64() >> 11) as f64 / (1u64 << 53) as f64
    }

    /// Uniform in `[0, n)`; `0` when `n` is zero.
    pub fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            0
        } else {
            (self.next_u64() % n as u64) as usize
        }
    }

    /// Uniform in `[lo, hi]`.
    pub fn range(&mut self, lo: i64, hi: i64) -> i64 {
        if hi <= lo {
            lo
        } else {
            lo + (self.next_u64() % (hi - lo + 1) as u64) as i64
        }
    }

    /// Log-uniform in `[lo, hi]`: gaps spread over orders of magnitude.
    pub fn log_range(&mut self, lo: f64, hi: f64) -> f64 {
        let (a, b) = (lo.max(1e-3).ln(), hi.max(lo.max(1e-3)).ln());
        (a + (b - a) * self.unit()).exp()
    }

    pub fn chance(&mut self, p: f64) -> bool {
        self.unit() < p
    }

    pub fn pick<'a, T>(&mut self, xs: &'a [T]) -> Option<&'a T> {
        if xs.is_empty() {
            None
        } else {
            Some(&xs[self.below(xs.len())])
        }
    }

    /// `n` lowercase hex digits.
    pub fn hex(&mut self, n: usize) -> String {
        (0..n)
            .map(|_| char::from_digit((self.next_u64() % 16) as u32, 16).unwrap_or('0'))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_seed_same_stream() {
        let (mut a, mut b) = (Rng::new(7), Rng::new(7));
        assert_eq!(a.next_u64(), b.next_u64());
        assert_ne!(
            Rng::new(7).fork("x").next_u64(),
            Rng::new(7).fork("y").next_u64()
        );
        let mut r = Rng::new(1);
        for _ in 0..1000 {
            let u = r.unit();
            assert!((0.0..1.0).contains(&u));
            assert!(r.below(5) < 5);
        }
    }
}
