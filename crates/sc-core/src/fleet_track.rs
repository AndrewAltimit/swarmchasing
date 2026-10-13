//! Candidate fleets followed across analyses, and soft-link evidence
//! accumulated per pair of cluster histories.
//!
//! Each analysis numbers its candidate fleets afresh (`F1`, `F2`). A caller
//! that follows clusters from analysis to analysis (the watch's ledger
//! follows each as a **thread**) can follow fleets too:
//!
//! - **Keys.** A fleet's key is `FK-` and eight hex digits of a hash of its
//!   earliest member thread ([`fleet_key`]), so it does not depend on
//!   numbering or on members joining later.
//! - **Matching.** Each current fleet continues the earlier fleet whose
//!   member threads it overlaps most, at Jaccard [`MATCH_JACCARD`] or more,
//!   one to one, strongest overlaps first ([`match_fleets`]).
//! - **Accumulation.** A slow fleet can be weak in every window and plain
//!   over many. Each pair of threads keeps its soft-link evidence (the log
//!   of the pair's combined likelihood ratio) across analyses
//!   ([`PairTrack`]). Windows overlap, so two analyses reading the same
//!   records count once: an observation adds to the total only when all of
//!   its records come after the records of the observation counted last,
//!   and otherwise replaces that one when stronger. The total halves every
//!   [`HALF_LIFE_SECS`]. A pair is **persistent** when the total reaches
//!   `ln(1 / alpha)` ([`bound`]), the upper threshold of a sequential test
//!   at error rate `alpha` taken in its conservative form.
//!
//! Like candidate fleets, none of this merges clusters, changes a tier or
//! reaches a report outside the admin's own. No I/O.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// The Jaccard overlap of member threads at which a fleet continues an
/// earlier one.
pub const MATCH_JACCARD: f64 = 0.5;
/// Accumulated evidence halves over this span.
pub const HALF_LIFE_SECS: i64 = 14 * 86_400;
/// Error rate of the persistence bound.
pub const ALPHA: f64 = 0.001;

/// `FK-` and the first 8 hex digits of the SHA-256 of `thread`, the
/// fleet's earliest member thread.
pub fn fleet_key(thread: &str) -> String {
    use sha2::{Digest, Sha256};
    let d = Sha256::digest(thread.as_bytes());
    let hex: String = d.iter().take(4).map(|b| format!("{b:02x}")).collect();
    format!("FK-{hex}")
}

/// Jaccard overlap of two sets of thread ids.
pub fn jaccard(a: &BTreeSet<String>, b: &BTreeSet<String>) -> f64 {
    let inter = a.intersection(b).count();
    let union = a.len() + b.len() - inter;
    if union == 0 {
        0.0
    } else {
        inter as f64 / union as f64
    }
}

/// For each of `current` (member threads per fleet), the index into
/// `earlier` it continues: pairs at Jaccard `min` or more, taken one to one
/// from the largest overlap down (ties to the lower indices).
pub fn match_fleets(
    current: &[BTreeSet<String>],
    earlier: &[BTreeSet<String>],
    min: f64,
) -> Vec<Option<usize>> {
    let mut cands: Vec<(f64, usize, usize)> = Vec::new();
    for (i, c) in current.iter().enumerate() {
        for (j, e) in earlier.iter().enumerate() {
            let s = jaccard(c, e);
            if s >= min && s > 0.0 {
                cands.push((s, i, j));
            }
        }
    }
    crate::sort::by(&mut cands, |x, y| {
        y.0.total_cmp(&x.0).then(x.1.cmp(&y.1)).then(x.2.cmp(&y.2))
    });
    let mut out = vec![None; current.len()];
    let mut taken = vec![false; earlier.len()];
    for (_, i, j) in cands {
        if out[i].is_none() && !taken[j] {
            out[i] = Some(j);
            taken[j] = true;
        }
    }
    out
}

/// The persistence bound for error rate `alpha`: `ln(1 / alpha)`.
pub fn bound(alpha: f64) -> f64 {
    (1.0 / alpha.clamp(f64::MIN_POSITIVE, 1.0)).ln()
}

/// One pair of threads' soft-link evidence across analyses.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct PairTrack {
    /// Thread ids, `a < b`.
    pub a: String,
    pub b: String,
    /// Evidence from observations closed before the open one, decayed to
    /// `t`.
    pub banked: f64,
    /// The open observation's evidence (log ratio), decayed to `t`.
    pub open: f64,
    /// The record span the open observation read.
    pub open_start: i64,
    pub open_end: i64,
    /// When the totals were last brought up to date.
    pub t: i64,
    /// Observations that counted on their own.
    pub independent: usize,
    /// Analyses that saw the pair linked.
    pub seen: usize,
    /// The kinds that linked it, latest analysis.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub kinds: Vec<String>,
}

impl PairTrack {
    pub fn new(a: &str, b: &str) -> Self {
        let (a, b) = if a <= b { (a, b) } else { (b, a) };
        Self {
            a: a.into(),
            b: b.into(),
            ..Default::default()
        }
    }

    /// The decayed total.
    pub fn total(&self) -> f64 {
        self.banked + self.open
    }

    /// Bring the totals to time `t`.
    pub fn decay_to(&mut self, t: i64) {
        if t > self.t && self.t > 0 {
            let f = 0.5f64.powf((t - self.t) as f64 / HALF_LIFE_SECS as f64);
            self.banked *= f;
            self.open *= f;
        }
        self.t = self.t.max(t);
    }

    /// Record an analysis at time `t` that linked the pair with log ratio
    /// `llr` from records spanning `start` to `end`.
    pub fn observe(&mut self, llr: f64, start: i64, end: i64, t: i64) {
        self.decay_to(t);
        self.seen += 1;
        let llr = llr.max(0.0);
        if self.independent == 0 || start > self.open_end {
            // All its records come after the open observation's: that one
            // is closed and this one opens.
            self.banked += self.open;
            self.open = llr;
            self.open_start = start;
            self.open_end = end;
            self.independent += 1;
        } else {
            self.open = self.open.max(llr);
            self.open_start = self.open_start.min(start);
            self.open_end = self.open_end.max(end);
        }
    }

    /// Whether the total reaches the bound for `alpha`.
    pub fn persistent(&self, alpha: f64) -> bool {
        self.total() >= bound(alpha)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(xs: &[&str]) -> BTreeSet<String> {
        xs.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn keys_are_stable_and_neutral() {
        let k = fleet_key("k-3f9a2c1b");
        assert!(k.starts_with("FK-") && k.len() == 11, "{k}");
        assert_eq!(k, fleet_key("k-3f9a2c1b"));
        assert_ne!(k, fleet_key("k-3f9a2c1c"));
    }

    #[test]
    fn fleets_match_one_to_one_by_overlap() {
        let earlier = vec![set(&["a", "b", "c"]), set(&["d", "e"])];
        let current = vec![
            set(&["d", "e", "f"]),
            set(&["a", "b"]),
            set(&["a", "c"]),
            set(&["x", "y"]),
        ];
        let m = match_fleets(&current, &earlier, MATCH_JACCARD);
        // {a,b} and {a,c} both overlap the first at 2/3: the lower index
        // takes it.
        assert_eq!(m, [Some(1), Some(0), None, None]);
        assert_eq!(jaccard(&set(&[]), &set(&[])), 0.0);
    }

    #[test]
    fn overlapping_windows_count_once_and_disjoint_ones_add() {
        let day = 86_400;
        let mut p = PairTrack::new("k-b", "k-a");
        assert_eq!((p.a.as_str(), p.b.as_str()), ("k-a", "k-b"));
        // Three runs over one window's records: the strongest counts.
        p.observe(2.0, 0, 10 * day, 10 * day);
        p.observe(2.5, 0, 10 * day, 10 * day);
        p.observe(1.0, day, 11 * day, 10 * day);
        assert_eq!(p.independent, 1);
        assert!((p.total() - 2.5).abs() < 1e-9, "{p:?}");
        // A later window with fresh records adds.
        p.observe(3.0, 12 * day, 20 * day, 10 * day);
        assert_eq!(p.independent, 2);
        assert!((p.total() - 5.5).abs() < 1e-9, "{p:?}");
        assert_eq!(p.seen, 4);
        // Weak each time, persistent together; decay works against it.
        assert!(!p.persistent(ALPHA));
        p.observe(2.0, 21 * day, 22 * day, 10 * day);
        assert!(p.persistent(ALPHA), "{} < {}", p.total(), bound(ALPHA));
        let mut later = p.clone();
        later.decay_to(10 * day + HALF_LIFE_SECS);
        assert!((later.total() - p.total() / 2.0).abs() < 1e-9);
        assert!(!later.persistent(ALPHA));
    }
}
