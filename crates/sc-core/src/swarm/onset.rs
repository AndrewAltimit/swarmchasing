//! Onset groups: many clusters of different clients that all began within
//! minutes of each other, beyond chance.
//!
//! A swarm of short-lived agents launched together leaves clusters of two or
//! three records each, too few active bins for co-activity or a dispatch
//! star to read. What they still share is their start. Each cluster above
//! noise whose records name a client (a user agent or a network) is one
//! **point**, at its first request or submit time; capture times never
//! count. The densest `window_secs` window holds `m` points of different
//! clients (no two clusters sharing a client: one user agent, network and
//! header set together, [`super::client_key`]), of `N` points over the
//! analysis span `S`. Its chance is the scan
//! statistic's, by Alm's approximation for a Poisson process with
//! `psi = N * window / S` points expected per window:
//! `1 - F(m - 1; psi) * exp(-((m - psi) / m) * psi * (S / window - 1) * p(m - 1; psi))`,
//! which is at least the `(S / window) * P(Poisson >= m)` the platform burst
//! test reads and grows with the number of windows. A window starting on a
//! clock hour (within `clock_tolerance_secs`) counts `clock_weight` of its
//! points: schedules start there. A window kept at `max_chance` with at least
//! `min_clusters` points is a group; its points are taken out and the scan
//! repeats, up to [`MAX_GROUPS`].
//!
//! **Common trigger.** A news story or a disclosed flaw sends unrelated
//! agents to one target at once. A group whose clusters share target
//! families (a host's last two labels) beyond chance is read as that: for
//! each family held by `g` of the `N` point clusters, the group's `n`
//! members hold it as a hypergeometric draw, and the pairs of members
//! sharing a family, summed over families, are compared with their expected
//! count (a Poisson tail). Families, not hosts: unrelated agents on one
//! host in the same minutes are often joined into one cluster by close
//! timing, and those left apart share the site, not the page. At
//! `trigger_max_chance` or below, the group is listed with its shared
//! families as a common trigger and not kept. A swarm sent at one target looks the same and is listed the
//! same way; an analysis holding only the group's clusters has nothing to
//! compare with and never reads a trigger.
//!
//! An onset group is a hint, like an interaction edge: never scored, never a
//! link, never a merge.

use super::runs::{client_key, family};
use crate::analyze::{Cluster, ObsResult};
use crate::extract::defang_host;
use crate::model::Tier;
use crate::timing::request_like;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// Onset settings (`[onset]` in the rules file).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct OnsetOptions {
    /// Width of the scan window.
    pub window_secs: i64,
    /// Points of different clients a group needs.
    pub min_clusters: usize,
    /// A window is a group when its scan chance is at most this.
    pub max_chance: f64,
    /// A group whose members share target families this unlikely is a
    /// common trigger.
    pub trigger_max_chance: f64,
    /// A window starting this close to a clock hour counts
    /// `clock_weight` of its points.
    pub clock_tolerance_secs: i64,
    pub clock_weight: f64,
}

impl Default for OnsetOptions {
    fn default() -> Self {
        Self {
            window_secs: 900,
            min_clusters: 4,
            max_chance: 0.01,
            trigger_max_chance: 0.01,
            clock_tolerance_secs: 120,
            clock_weight: 0.25,
        }
    }
}

/// Scans per analysis.
pub(crate) const MAX_GROUPS: usize = 8;
/// Shared families named per group.
const MAX_HOSTS: usize = 5;

/// Clusters of different clients that began within one window, beyond
/// chance.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OnsetGroup {
    /// Cluster ids and keys, in onset order.
    pub clusters: Vec<String>,
    pub keys: Vec<String>,
    /// The window's first onset.
    pub start: i64,
    pub window_secs: i64,
    /// Points in the analysis, and over what span.
    pub of: usize,
    pub span_secs: i64,
    /// Points expected per window.
    pub expected: f64,
    /// Scan chance of a window this dense anywhere in the span.
    pub chance: f64,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub on_the_hour: bool,
    /// Pairs of members sharing a target family, summed over families, and
    /// as many expected from the families' holders across the analysis.
    pub shared_pairs: usize,
    pub expected_shared: f64,
    /// Chance of so many shared pairs.
    pub trigger_chance: f64,
    /// Shared families beyond chance: one upstream trigger, listed, not
    /// kept.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub common_trigger: bool,
    /// Target families most members share, defanged, most held first.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub shared_families: Vec<String>,
}

impl OnsetGroup {
    pub fn detail(&self) -> String {
        let mut s = format!(
            "{} clusters of different clients began within {} min ({} of {} onsets over {:.1} h, {:.2} expected per window; chance {:.1e}{})",
            self.clusters.len(),
            self.window_secs / 60,
            self.clusters.len(),
            self.of,
            self.span_secs as f64 / 3600.0,
            self.expected,
            self.chance,
            if self.on_the_hour {
                ", on a clock hour, weighted down"
            } else {
                ""
            }
        );
        if self.common_trigger {
            s.push_str(&format!(
                "; they share target families beyond chance ({} pairs, {:.1} expected; chance {:.1e}: {}): one trigger, such as a news story, sends unrelated agents together, so this is listed, not kept",
                self.shared_pairs,
                self.expected_shared,
                self.trigger_chance,
                self.shared_families.join(", ")
            ));
        } else {
            s.push_str(": one launch may have started them");
        }
        s
    }
}

/// One cluster's onset.
struct Point<'a> {
    ts: i64,
    cluster: usize,
    clients: BTreeSet<String>,
    families: BTreeSet<&'a str>,
}

/// Points of different clients among `pts` (in time order), each kept when
/// it shares no client with one kept before it.
fn distinct<'p>(pts: &[&'p Point<'p>]) -> Vec<&'p Point<'p>> {
    let mut kept: Vec<&Point> = Vec::new();
    for p in pts {
        if kept.iter().all(|k| k.clients.is_disjoint(&p.clients)) {
            kept.push(p);
        }
    }
    kept
}

/// `p(k; lambda)`.
fn poisson_pmf(lambda: f64, k: usize) -> f64 {
    if lambda <= 0.0 {
        return if k == 0 { 1.0 } else { 0.0 };
    }
    (-lambda + k as f64 * lambda.ln() - crate::chance::ln_fact(k)).exp()
}

/// `P(X >= m)`, `X ~ Poisson(lambda)`, summed upward for a small tail.
fn poisson_tail(lambda: f64, m: usize) -> f64 {
    if m == 0 {
        return 1.0;
    }
    if (m as f64) <= lambda {
        return crate::timing::poisson_at_least(lambda, m);
    }
    let mut sum = 0.0;
    let mut term = poisson_pmf(lambda, m);
    let mut k = m;
    while term > 0.0 && term > sum * 1e-16 && k < m + 10_000 {
        sum += term;
        k += 1;
        term *= lambda / k as f64;
    }
    sum.min(1.0)
}

/// Alm's approximation of the chance that some window of a Poisson process
/// with `psi` points expected per window, over `windows` windows, holds `m`
/// or more.
pub(crate) fn scan_chance(psi: f64, windows: f64, m: usize) -> f64 {
    if m == 0 || (m as f64) <= psi {
        return 1.0;
    }
    let tail = poisson_tail(psi, m);
    let x = (m as f64 - psi) / m as f64 * psi * (windows - 1.0).max(0.0) * poisson_pmf(psi, m - 1);
    (tail + (1.0 - tail) * -(-x).exp_m1()).clamp(0.0, 1.0)
}

/// Onset groups among the clusters above noise, kept and common-trigger
/// alike, in time order.
pub(crate) fn onset_groups(
    clusters: &[Cluster],
    results: &[ObsResult],
    opts: &OnsetOptions,
) -> Vec<OnsetGroup> {
    let w = opts.window_secs.max(1);
    let mut points: Vec<Point> = clusters
        .iter()
        .enumerate()
        .filter(|(_, c)| c.tier > Tier::Noise)
        .filter_map(|(ci, c)| {
            let ts = c
                .members
                .iter()
                .map(|&m| &results[m].obs)
                .filter(|o| o.ts > 0 && request_like(o.ts_kind))
                .map(|o| o.ts)
                .min()?;
            let clients: BTreeSet<String> = c
                .members
                .iter()
                .filter_map(|&m| client_key(&results[m]))
                .collect();
            // A cluster naming no client cannot be told apart.
            if clients.is_empty() {
                return None;
            }
            let families = c
                .members
                .iter()
                .filter_map(|&m| results[m].target_host.as_deref())
                .map(family)
                .collect();
            Some(Point {
                ts,
                cluster: ci,
                clients,
                families,
            })
        })
        .collect();
    crate::sort::by(&mut points, |a, b| {
        a.ts.cmp(&b.ts).then(a.cluster.cmp(&b.cluster))
    });
    let n = points.len();
    if n < opts.min_clusters.max(2) {
        return Vec::new();
    }
    let span = (points[n - 1].ts - points[0].ts).max(w);
    let psi = n as f64 * w as f64 / span as f64;
    let windows = span as f64 / w as f64;
    // Holders of each family among the points.
    let mut holders: BTreeMap<&str, usize> = BTreeMap::new();
    for p in &points {
        for f in &p.families {
            *holders.entry(f).or_default() += 1;
        }
    }

    let mut left: Vec<&Point> = points.iter().collect();
    let mut out = Vec::new();
    for _ in 0..MAX_GROUPS {
        // The densest window of different clients.
        let mut best: Option<(f64, usize, Vec<&Point>)> = None;
        let mut i = 0;
        for j in 0..left.len() {
            // The window starting at `left[j]` holds `left[j..=i]`.
            i = i.max(j);
            while i + 1 < left.len() && left[i + 1].ts - left[j].ts <= w {
                i += 1;
            }
            let group = distinct(&left[j..=i]);
            let r = left[j].ts.rem_euclid(3600);
            let tol = opts.clock_tolerance_secs.max(0);
            let hourly = r <= tol || r >= 3600 - tol;
            let m = if hourly {
                (group.len() as f64 * opts.clock_weight).floor() as usize
            } else {
                group.len()
            };
            let chance = scan_chance(psi, windows, m);
            if group.len() >= opts.min_clusters && best.as_ref().is_none_or(|b| chance < b.0) {
                best = Some((chance, usize::from(hourly), group));
            }
        }
        let Some((chance, hourly, group)) = best else {
            break;
        };
        if chance > opts.max_chance {
            break;
        }
        let (shared_pairs, expected_shared, trigger_chance, shared_families) =
            trigger(&group, &holders, n);
        let common_trigger = trigger_chance <= opts.trigger_max_chance;
        out.push(OnsetGroup {
            clusters: group
                .iter()
                .map(|p| clusters[p.cluster].id.clone())
                .collect(),
            keys: group
                .iter()
                .map(|p| clusters[p.cluster].key.clone())
                .collect(),
            start: group[0].ts,
            window_secs: w,
            of: n,
            span_secs: span,
            expected: psi,
            chance,
            on_the_hour: hourly == 1,
            shared_pairs,
            expected_shared,
            trigger_chance,
            common_trigger,
            shared_families,
        });
        let taken: BTreeSet<usize> = group.iter().map(|p| p.cluster).collect();
        left.retain(|p| !taken.contains(&p.cluster));
    }
    crate::sort::by(&mut out, |a, b| a.start.cmp(&b.start));
    out
}

/// The "Onset groups" block of a report: the groups `shown` allows (given
/// a group's cluster ids), or nothing.
pub(crate) fn report_block(
    s: &mut String,
    groups: &[OnsetGroup],
    shown: &dyn Fn(&OnsetGroup) -> bool,
) {
    use std::fmt::Write;
    let groups: Vec<&OnsetGroup> = groups.iter().filter(|g| shown(g)).collect();
    if groups.is_empty() {
        return;
    }
    let _ = writeln!(
        s,
        "
## Onset groups

Clusters of different clients that began within minutes of each other, beyond chance: one launch may have started them, or one trigger (a news story, a disclosure) sent unrelated agents at once. Hints to review: none is scored, links or merges anything.
"
    );
    for g in groups.iter().take(8) {
        let _ = writeln!(
            s,
            "- {} from {}: {}",
            g.clusters.join(", "),
            crate::model::fmt_ts(g.start),
            g.detail()
        );
    }
}

/// The group's shared family pairs, their expected count, the chance of so
/// many, and the most shared families (defanged). Under no common trigger,
/// the `n` group members holding a family held by `g` of the `total` points
/// is a hypergeometric draw, with
/// `E[X(X - 1)] = n(n - 1)g(g - 1) / (N(N - 1))`.
fn trigger(
    group: &[&Point],
    holders: &BTreeMap<&str, usize>,
    total: usize,
) -> (usize, f64, f64, Vec<String>) {
    let n = group.len() as f64;
    let big = total as f64;
    let mut held: BTreeMap<&str, usize> = BTreeMap::new();
    for p in group {
        for f in &p.families {
            *held.entry(f).or_default() += 1;
        }
    }
    let observed: usize = held.values().map(|&x| x * x.saturating_sub(1) / 2).sum();
    let expected: f64 = if total < 2 {
        0.0
    } else {
        holders
            .values()
            .map(|&g| {
                let g = g as f64;
                n * (n - 1.0) * g * (g - 1.0) / (big * (big - 1.0)) / 2.0
            })
            .sum()
    };
    let chance = if observed == 0 || total as f64 <= n {
        1.0
    } else {
        poisson_tail(expected, observed)
    };
    let mut shared: Vec<(&str, usize)> = held.into_iter().filter(|&(_, x)| x > 1).collect();
    crate::sort::by(&mut shared, |a, b| b.1.cmp(&a.1).then(a.0.cmp(b.0)));
    let shown = shared
        .iter()
        .take(MAX_HOSTS)
        .map(|(h, x)| format!("{} ({x})", defang_host(h)))
        .collect();
    (observed, expected, chance, shown)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Observation, TsKind};

    /// One cluster above noise of two records from client `k`, starting at
    /// `ts`, on `host`.
    fn push(
        clusters: &mut Vec<Cluster>,
        results: &mut Vec<ObsResult>,
        k: usize,
        ts: i64,
        host: &str,
    ) {
        let mut members = Vec::new();
        for d in [0, 30] {
            members.push(results.len());
            results.push(ObsResult {
                obs: Observation {
                    ts: ts + d,
                    ts_kind: TsKind::Request,
                    user_agent: Some(format!("agent/{k}")),
                    asn: Some(64_500 + k as u32),
                    url: format!("https://{host}/"),
                    ..Default::default()
                },
                score: 3,
                tier: Tier::Suggestive,
                hits: Vec::new(),
                layers: Vec::new(),
                target_host: Some(host.into()),
                features: Vec::new(),
                cluster: Some(clusters.len()),
                agent: None,
            });
        }
        clusters.push(Cluster {
            id: format!("C{}", clusters.len() + 1),
            tier: Tier::Suggestive,
            members,
            ..Default::default()
        });
    }

    /// Six clusters launched within three minutes among twenty spread over
    /// two days; the six on `site(k)`, the rest each on its own site.
    fn launch(site: impl Fn(usize) -> String) -> Vec<OnsetGroup> {
        let (mut clusters, mut results) = (Vec::new(), Vec::new());
        let t0 = 1_772_000_000 + 1_234;
        for k in 0..6 {
            push(&mut clusters, &mut results, k, t0 + 30 * k as i64, &site(k));
        }
        for k in 6..26 {
            let host = format!("h.own{k}.example");
            push(
                &mut clusters,
                &mut results,
                k,
                t0 + 7_919 * (k as i64 - 5),
                &host,
            );
        }
        onset_groups(&clusters, &results, &OnsetOptions::default())
    }

    #[test]
    fn a_launch_is_a_group_and_one_site_a_trigger() {
        let g = launch(|k| format!("h{k}.own-launch{k}.example"));
        assert_eq!(g.len(), 1, "{g:?}");
        assert_eq!(g[0].clusters, ["C1", "C2", "C3", "C4", "C5", "C6"]);
        assert!(!g[0].common_trigger && g[0].chance < 1e-4, "{g:?}");
        assert!(g[0].detail().contains("one launch"));
        // The same six on one site: one trigger, listed, not kept.
        let g = launch(|k| format!("h{k}.news.example"));
        assert_eq!(g.len(), 1, "{g:?}");
        assert!(g[0].common_trigger, "{g:?}");
        assert_eq!(g[0].shared_pairs, 15);
        assert_eq!(g[0].shared_families, ["news[.]example (6)"]);
    }

    #[test]
    fn one_client_counts_once_and_no_client_never() {
        let (mut clusters, mut results) = (Vec::new(), Vec::new());
        let t0 = 1_772_000_000 + 1_234;
        // Six clusters of one client at once, among twenty spread out.
        for k in 0..6 {
            push(
                &mut clusters,
                &mut results,
                0,
                t0 + 30 * k,
                &format!("h.l{k}.example"),
            );
        }
        for k in 6..26 {
            push(
                &mut clusters,
                &mut results,
                k as usize,
                t0 + 7_919 * (k - 5),
                &format!("h.o{k}.example"),
            );
        }
        assert!(onset_groups(&clusters, &results, &OnsetOptions::default()).is_empty());
        // Records naming no client are no points.
        for r in &mut results {
            r.obs.user_agent = None;
            r.obs.asn = None;
        }
        assert!(onset_groups(&clusters, &results, &OnsetOptions::default()).is_empty());
    }

    #[test]
    fn scan_chance_bounds_the_simple_scan() {
        // At least the windows times the Poisson tail, at most one.
        for (psi, windows, m) in [(0.42, 96.0, 4), (0.42, 96.0, 6), (0.1, 200.0, 5)] {
            let c = scan_chance(psi, windows, m);
            let simple = (windows * poisson_tail(psi, m)).min(1.0);
            assert!(c >= poisson_tail(psi, m) && c <= 1.0, "{c}");
            assert!(c >= simple * 0.9, "{c} {simple}");
        }
        // Fifteen in one window of 96 at 0.42 expected is far beyond
        // chance; four is not.
        assert!(scan_chance(0.42, 96.0, 15) < 1e-12);
        assert!(scan_chance(0.42, 96.0, 4) > 0.05);
        assert_eq!(scan_chance(3.0, 10.0, 2), 1.0);
    }

    #[test]
    fn poisson_tail_matches_the_complement_where_both_are_exact() {
        for (l, m) in [(0.5, 3), (2.0, 5), (10.0, 20)] {
            let a = poisson_tail(l, m);
            let b = crate::timing::poisson_at_least(l, m);
            assert!((a - b).abs() < 1e-9, "{l} {m}: {a} {b}");
        }
        // Far in the tail, where the complement rounds to zero.
        assert!(poisson_tail(0.1, 30) > 0.0);
    }
}
