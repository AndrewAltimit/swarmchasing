//! Parallel fan-out width: how many alike requests a client sends at once.
//!
//! An agent that issues tool calls in parallel sends them in batches of a
//! fixed width: four fetches of four hosts in the same second, then a pause
//! while the model reads the results, then four more. [`fanout`] groups a
//! cluster's records into one-second batches of alike requests (same host or
//! same path shape) and reports the batch width when one width holds for
//! most batches. A scanner that submits a list in bulk, or a source that
//! stamps an import time on every record, can look the same, so this is a
//! hint, not evidence.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Fan-out settings (`[fanout]` in the rules file).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct FanOutOptions {
    /// Records at most this many seconds after a batch's first record join it.
    pub batch_secs: i64,
    /// Batches needed before a width is reported.
    pub min_batches: usize,
    /// Narrowest width worth reporting; width 1 is sequential work.
    pub min_width: usize,
    /// Share of batches the modal width must cover.
    pub min_share: f64,
    /// Cross-service fan-out ([`crate::crossservice`]): submissions of one
    /// target at most this many seconds after its first one count together.
    pub cross_service_secs: i64,
    /// Distinct services one target must reach within that window (below 2:
    /// off).
    pub cross_service_min: usize,
    /// Ordinary targets on other hosts fanned out alike around a cluster
    /// that mark an auto-submitter (0: never).
    pub cross_service_ambient: usize,
}

impl Default for FanOutOptions {
    fn default() -> Self {
        Self {
            batch_secs: 1,
            min_batches: 4,
            min_width: 2,
            min_share: 0.6,
            cross_service_secs: 60,
            cross_service_min: 2,
            cross_service_ambient: 3,
        }
    }
}

/// One record as the fan-out reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FanRequest {
    /// Unix seconds; `<= 0` is ignored.
    pub ts: i64,
    pub host: Option<String>,
    /// Path shape ([`crate::paths::normalize_path`]).
    pub path: String,
}

/// Batch widths over one cluster.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct FanOut {
    /// One-second batches of alike requests, including single requests.
    #[serde(default)]
    pub batches: usize,
    /// Batches by width.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub widths: BTreeMap<usize, usize>,
    /// The width most batches have, when it is at least `min_width`, covers
    /// at least `min_share` of them and there are at least `min_batches`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub modal_width: Option<usize>,
    /// Share of batches at the most common width.
    #[serde(default)]
    pub modal_share: f64,
}

impl FanOut {
    pub fn is_empty(&self) -> bool {
        self.batches == 0
    }
}

/// Batch widths over `reqs`. Nothing when fewer than two records carry a
/// time, or when every time is a whole minute: minute-rounded sources put
/// unrelated requests in one "second".
pub fn fanout(reqs: &[FanRequest], opts: &FanOutOptions) -> FanOut {
    let mut rs: Vec<&FanRequest> = reqs.iter().filter(|r| r.ts > 0).collect();
    if rs.len() < 2 || rs.iter().all(|r| r.ts % 60 == 0) {
        return FanOut::default();
    }
    crate::sort::by_key(&mut rs, |r| r.ts);
    let mut widths: BTreeMap<usize, usize> = BTreeMap::new();
    let mut i = 0;
    while i < rs.len() {
        let n = rs[i..]
            .iter()
            .take_while(|r| r.ts - rs[i].ts <= opts.batch_secs)
            .count();
        for w in alike_groups(&rs[i..i + n]) {
            *widths.entry(w).or_default() += 1;
        }
        i += n;
    }
    let batches: usize = widths.values().sum();
    let (&mode, &count) = widths
        .iter()
        .max_by(|a, b| a.1.cmp(b.1).then(b.0.cmp(a.0)))
        .expect("at least one batch");
    let modal_share = count as f64 / batches as f64;
    FanOut {
        batches,
        modal_width: (batches >= opts.min_batches
            && mode >= opts.min_width
            && modal_share >= opts.min_share)
            .then_some(mode),
        modal_share,
        widths,
    }
}

/// Sizes of the groups of alike requests in one time window: requests are
/// alike when they share a host or a path shape, and alike-ness chains.
fn alike_groups(win: &[&FanRequest]) -> Vec<usize> {
    let mut parent: Vec<usize> = (0..win.len()).collect();
    fn find(p: &mut [usize], x: usize) -> usize {
        let mut r = x;
        while p[r] != r {
            r = p[r];
        }
        p[x] = r;
        r
    }
    for a in 0..win.len() {
        for b in a + 1..win.len() {
            let same_host = win[a].host.is_some() && win[a].host == win[b].host;
            if same_host || win[a].path == win[b].path {
                let (ra, rb) = (find(&mut parent, a), find(&mut parent, b));
                parent[ra.max(rb)] = ra.min(rb);
            }
        }
    }
    let mut sizes: BTreeMap<usize, usize> = BTreeMap::new();
    for x in 0..win.len() {
        *sizes.entry(find(&mut parent, x)).or_default() += 1;
    }
    sizes.into_values().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fanout(reqs: &[FanRequest]) -> FanOut {
        super::fanout(reqs, &FanOutOptions::default())
    }

    fn r(ts: i64, host: &str, path: &str) -> FanRequest {
        FanRequest {
            ts,
            host: Some(host.into()),
            path: path.into(),
        }
    }

    /// `n` batches of `width` requests to different hosts with one path shape,
    /// 30 seconds apart, starting at `t0`.
    fn batches(t0: i64, n: usize, width: usize) -> Vec<FanRequest> {
        (0..n)
            .flat_map(|b| {
                (0..width).map(move |k| {
                    r(
                        t0 + 30 * b as i64 + (k % 2) as i64,
                        &format!("h{k}.example"),
                        "/api/{n}",
                    )
                })
            })
            .collect()
    }

    #[test]
    fn steady_parallel_batches() {
        let mut reqs = batches(1_791_000_007, 5, 4);
        // One straggler on its own.
        reqs.push(r(1_791_000_500, "z.example", "/other"));
        let f = fanout(&reqs);
        assert_eq!(f.batches, 6);
        assert_eq!(f.widths.get(&4), Some(&5));
        assert_eq!(f.widths.get(&1), Some(&1));
        assert_eq!(f.modal_width, Some(4));
        assert!((f.modal_share - 5.0 / 6.0).abs() < 1e-9);
    }

    #[test]
    fn sequential_work_reports_no_width() {
        let reqs: Vec<FanRequest> = (0..10)
            .map(|i| r(1_791_000_007 + 20 * i, "a.example", "/q"))
            .collect();
        let f = fanout(&reqs);
        assert_eq!(f.batches, 10);
        assert_eq!(f.modal_width, None);
    }

    #[test]
    fn unlike_requests_in_one_second_are_not_a_batch() {
        let reqs: Vec<FanRequest> = (0..5)
            .flat_map(|b| {
                let t = 1_791_000_007 + 40 * b;
                [
                    r(t, "a.example", "/login"),
                    r(t, "b.example", "/static/app.js"),
                ]
            })
            .collect();
        let f = fanout(&reqs);
        assert_eq!(f.widths.get(&1), Some(&10));
        assert_eq!(f.modal_width, None);
    }

    #[test]
    fn minute_rounded_times_are_skipped() {
        let reqs: Vec<FanRequest> = batches(1_791_000_000, 6, 3)
            .into_iter()
            .map(|mut x| {
                x.ts -= x.ts % 60;
                x
            })
            .collect();
        assert!(fanout(&reqs).is_empty());
    }

    #[test]
    fn too_few_batches_report_no_width() {
        let f = fanout(&batches(1_791_000_007, 3, 3));
        assert_eq!(f.batches, 3);
        assert_eq!(f.modal_width, None);
    }
}
