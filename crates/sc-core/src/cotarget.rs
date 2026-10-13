//! Co-target: clusters acting on the same rare targets in the same hours,
//! more often than chance allows.
//!
//! One operator handing one target list to several agents makes them work
//! the same hosts at about the same time, each at its own pace and in its
//! own order: too loose for synchronised starts, too unordered for a rerun.
//! Each cluster above noise becomes a set of **items**, one per target
//! host and action (`probe` for an exploit payload, `callback` for a
//! callback inbox, `fetch` through a relay or carrier, else `visit`), each
//! with the `bin_secs` bins it was active in. Two clusters **share** an
//! item when they were active on it within `max_lag_bins` bins of each
//! other.
//!
//! Popular targets tie nothing: a host touched by more than `max_holders`
//! senders (clusters above noise, and records outside them, as for
//! scaffolds) is left out, so a news story that sends many unrelated
//! agents to one site in one hour, or an operator's own access log where
//! every record names its host, draws no pair. A pair is kept when it
//! shares items on at least `min_hosts` distinct hosts and the
//! hypergeometric chance of sharing that many is at most `max_chance`: one
//! cluster's items drawn at random from every rare item any cluster above
//! noise was active on would meet the other's that often. The chance
//! leaves time aside, so it overstates how often unrelated clusters meet
//! on an item in the same hours, never understates it. An analysis of a
//! few clusters has a small population and ties none. The pairs kept are cut at false discovery rate `fdr` over
//! every pair tested. Each pair's similarity weighs shared items by rarity
//! (the log of clusters over holders). Pairs are soft links: they never
//! score, link or merge.

use crate::analyze::{Cluster, ObsResult};
use crate::model::{IndicatorKind, Tier};
use crate::timing::request_like;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// Co-target settings (`[co_target]` in the rules file).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct CoTargetOptions {
    /// Width of a time bin.
    pub bin_secs: i64,
    /// Bins either way within which two clusters' activity on one item
    /// coincides.
    pub max_lag_bins: i64,
    /// Distinct hosts the shared items must span.
    pub min_hosts: usize,
    /// A host touched by more senders than this ties none.
    pub max_holders: usize,
    pub max_chance: f64,
    /// Benjamini-Hochberg false discovery rate over the pairs tested.
    pub fdr: f64,
}

impl Default for CoTargetOptions {
    fn default() -> Self {
        Self {
            bin_secs: 3600,
            max_lag_bins: 1,
            min_hosts: 3,
            max_holders: 4,
            max_chance: 0.01,
            fdr: 0.05,
        }
    }
}

/// Pairs kept, most unlikely first.
const MAX_PAIRS: usize = 200;

/// Two clusters on the same rare targets in the same hours beyond chance.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CoTargetPair {
    /// Cluster ids, `a` the stronger.
    pub a: String,
    pub b: String,
    /// Items both were active on within the lag.
    pub shared: usize,
    /// Distinct hosts among them.
    pub hosts: usize,
    /// Rare items each was active on.
    pub items_a: usize,
    pub items_b: usize,
    /// Rare items any cluster above noise was active on.
    pub population: usize,
    /// Rarity-weighted share of the smaller side's items that are shared,
    /// 0 to 1.
    pub similarity: f64,
    /// Hypergeometric chance of sharing at least `shared` items.
    pub chance: f64,
    /// Pairs tested, and pairs this unlikely expected among them.
    pub tested: usize,
    pub expected_pairs: f64,
    pub bin_secs: i64,
}

impl CoTargetPair {
    pub fn detail(&self) -> String {
        format!(
            "{} rare targets on {} hosts worked within {} min of each other, of {} and {} each among {} ({:.2} weighted; chance {:.1e}, {:.2} such pairs expected among {} tested): one target list may drive both",
            self.shared,
            self.hosts,
            self.bin_secs / 60,
            self.items_a,
            self.items_b,
            self.population,
            self.similarity,
            self.chance,
            self.expected_pairs,
            self.tested
        )
    }
}

/// What a record did to its target.
fn action(r: &ObsResult) -> &'static str {
    let has = |k: IndicatorKind| r.hits.iter().any(|h| h.kind == k);
    if has(IndicatorKind::Exploit) {
        "probe"
    } else if has(IndicatorKind::Exfil) {
        "callback"
    } else if has(IndicatorKind::Relay) || has(IndicatorKind::Carrier) {
        "fetch"
    } else {
        "visit"
    }
}

/// One cluster's items: (host, action) to its active bins.
struct Side<'a> {
    id: &'a str,
    items: BTreeMap<(&'a str, &'static str), BTreeSet<i64>>,
}

/// Pairs of clusters above noise on the same rare targets in the same
/// hours beyond chance, most unlikely first. `max_shared` is
/// `soft_links.max_shared`: a host held by more clusters than that ties
/// none either.
pub(crate) fn cotarget_pairs(
    clusters: &[Cluster],
    results: &[ObsResult],
    max_shared: usize,
    opts: &CoTargetOptions,
) -> Vec<CoTargetPair> {
    let bin = opts.bin_secs.max(1);
    let lag = opts.max_lag_bins.max(0);
    let shown: Vec<&Cluster> = clusters.iter().filter(|c| c.tier > Tier::Noise).collect();
    let in_shown: BTreeSet<usize> = shown
        .iter()
        .flat_map(|c| c.members.iter().copied())
        .collect();
    // Senders per host: clusters above noise, and records outside them.
    let mut holders: BTreeMap<&str, usize> = BTreeMap::new();
    for c in &shown {
        let hosts: BTreeSet<&str> = c
            .members
            .iter()
            .filter_map(|&m| results[m].target_host.as_deref())
            .collect();
        for h in hosts {
            *holders.entry(h).or_default() += 1;
        }
    }
    for (i, r) in results.iter().enumerate() {
        if !in_shown.contains(&i)
            && let Some(h) = r.target_host.as_deref()
            && let Some(n) = holders.get_mut(h)
        {
            *n += 1;
        }
    }
    let cap = opts.max_holders.min(max_shared);
    let rare = |h: &str| holders.get(h).is_some_and(|&n| n <= cap);

    let sides: Vec<Side> = shown
        .iter()
        .filter_map(|c| {
            let mut items: BTreeMap<(&str, &'static str), BTreeSet<i64>> = BTreeMap::new();
            for &m in &c.members {
                let r = &results[m];
                let Some(h) = r.target_host.as_deref() else {
                    continue;
                };
                if r.obs.ts <= 0 || !request_like(r.obs.ts_kind) || !rare(h) {
                    continue;
                }
                items
                    .entry((h, action(r)))
                    .or_default()
                    .insert(r.obs.ts.div_euclid(bin));
            }
            (!items.is_empty()).then_some(Side { id: &c.id, items })
        })
        .collect();
    if sides.len() < 2 {
        return Vec::new();
    }
    // Rarity weight per host: log of clusters over holders.
    let n_clusters = shown.len() as f64;
    let weight = |h: &str| ((n_clusters + 1.0) / holders.get(h).copied().unwrap_or(1) as f64).ln();

    // Candidates: pairs holding one item within the lag of each other.
    let mut by_item: BTreeMap<(&str, &str), Vec<usize>> = BTreeMap::new();
    for (i, s) in sides.iter().enumerate() {
        for k in s.items.keys() {
            by_item.entry(*k).or_default().push(i);
        }
    }
    let near = |a: &BTreeSet<i64>, b: &BTreeSet<i64>| {
        a.iter()
            .any(|&x| b.range(x - lag..=x + lag).next().is_some())
    };
    let mut shared: BTreeMap<(usize, usize), Vec<(&str, &str)>> = BTreeMap::new();
    for (k, holders) in &by_item {
        for (n, &x) in holders.iter().enumerate() {
            for &y in &holders[n + 1..] {
                if near(&sides[x].items[k], &sides[y].items[k]) {
                    shared.entry((x, y)).or_default().push(*k);
                }
            }
        }
    }

    // Every rare item any cluster above noise was active on.
    let population = by_item.len();
    let mut out = Vec::new();
    let mut tested = 0usize;
    for ((x, y), keys) in shared {
        let (sx, sy) = (&sides[x], &sides[y]);
        tested += 1;
        let hosts: BTreeSet<&str> = keys.iter().map(|k| k.0).collect();
        if hosts.len() < opts.min_hosts {
            continue;
        }
        let k = keys.len();
        let (kx, ny) = (sx.items.len(), sy.items.len());
        let chance = hypergeometric_tail(population.max(kx).max(ny), kx, ny, k);
        let wsum = |s: &Side| s.items.keys().map(|k| weight(k.0)).sum::<f64>();
        let wshared: f64 = keys.iter().map(|k| weight(k.0)).sum();
        let similarity = (wshared / wsum(sx).min(wsum(sy)).max(f64::MIN_POSITIVE)).min(1.0);
        if chance <= opts.max_chance {
            out.push(CoTargetPair {
                a: sx.id.to_string(),
                b: sy.id.to_string(),
                shared: k,
                hosts: hosts.len(),
                items_a: kx,
                items_b: ny,
                population,
                similarity,
                chance,
                tested: 0,
                expected_pairs: 0.0,
                bin_secs: bin,
            });
        }
    }
    let ps: Vec<f64> = out.iter().map(|p| p.chance).collect();
    match crate::chance::bh_cut(&ps, tested, opts.fdr) {
        Some(cut) => out.retain(|p| p.chance <= cut),
        None => out.clear(),
    }
    for p in &mut out {
        p.tested = tested;
        p.expected_pairs = p.chance * tested as f64;
    }
    crate::sort::by(&mut out, |p, q| {
        p.chance
            .total_cmp(&q.chance)
            .then(q.shared.cmp(&p.shared))
            .then(p.a.cmp(&q.a))
            .then(p.b.cmp(&q.b))
    });
    out.truncate(MAX_PAIRS);
    out
}

/// `ln(n!)`.
fn ln_fact(n: usize) -> f64 {
    (2..=n).map(|i| (i as f64).ln()).sum()
}

fn ln_choose(n: usize, k: usize) -> f64 {
    if k > n {
        return f64::NEG_INFINITY;
    }
    ln_fact(n) - ln_fact(k) - ln_fact(n - k)
}

/// `P(X >= k)` for `X` the successes in `draws` draws without replacement
/// from `population` items of which `successes` are successes.
pub(crate) fn hypergeometric_tail(
    population: usize,
    successes: usize,
    draws: usize,
    k: usize,
) -> f64 {
    let (n, s, d) = (population, successes.min(population), draws.min(population));
    let top = s.min(d);
    if k == 0 {
        return 1.0;
    }
    if k > top {
        return 0.0;
    }
    let denom = ln_choose(n, d);
    let mut p = 0.0;
    for x in k..=top {
        if d - x > n - s {
            continue;
        }
        p += (ln_choose(s, x) + ln_choose(n - s, d - x) - denom).exp();
    }
    p.clamp(0.0, 1.0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyze::analyze;
    use crate::model::Observation;
    use crate::rules::Rules;

    #[test]
    fn hypergeometric_tail_matches_small_cases() {
        // 10 items, 3 marked, draw 3: P(all 3) = 1 / C(10,3).
        assert!((hypergeometric_tail(10, 3, 3, 3) - 1.0 / 120.0).abs() < 1e-12);
        assert!((hypergeometric_tail(10, 3, 3, 0) - 1.0).abs() < 1e-12);
        // P(X >= 1) = 1 - C(7,3)/C(10,3).
        let want = 1.0 - 35.0 / 120.0;
        assert!((hypergeometric_tail(10, 3, 3, 1) - want).abs() < 1e-12);
        assert_eq!(hypergeometric_tail(10, 3, 3, 4), 0.0);
        // Everything drawn: sharing all is certain.
        assert!((hypergeometric_tail(5, 5, 5, 5) - 1.0).abs() < 1e-12);
    }

    fn o(id: &str, ts: i64, url: &str) -> Observation {
        Observation {
            id: id.into(),
            ts,
            url: url.into(),
            ..Default::default()
        }
    }

    /// Clusters by inbox: `agents` of them probing `hosts`, each starting
    /// within the hour, plus `others` unrelated clusters on their own
    /// hosts.
    fn records(agents: usize, hosts: &[&str], others: usize) -> Vec<Observation> {
        let t0 = 1_791_000_000;
        let mut obs = Vec::new();
        let inbox = |n: usize| format!("{n:08x}-1111-4c2a-9a55-3f2e1d0c9b8a");
        for a in 0..agents {
            for (k, h) in hosts.iter().enumerate() {
                // Each agent its own order, over ten minutes apart on any
                // one host (closer would join them by timing).
                let t = t0 + (a as i64 * 2000) + ((k + a) % hosts.len()) as i64 * 300;
                obs.push(o(
                    &format!("a{a}-{k}"),
                    t,
                    &format!(
                        "https://{h}/q?id=1%27%20OR%201=1--&hook=https://webhook.site/{}",
                        inbox(a)
                    ),
                ));
            }
        }
        for b in 0..others {
            for k in 0..4 {
                obs.push(o(
                    &format!("b{b}-{k}"),
                    t0 + b as i64 * 900 + k * 200,
                    &format!(
                        "https://h{k}.own{b}.example/q?id=1%27%20OR%201=1--&hook=https://webhook.site/{}",
                        inbox(100 + b)
                    ),
                ));
            }
        }
        obs
    }

    #[test]
    fn agents_on_one_rare_target_list_pair_up() {
        let hosts = [
            "a.list.example",
            "b.list.example",
            "c.list.example",
            "d.list.example",
        ];
        let a = analyze(records(3, &hosts, 6), &Rules::default_rules());
        assert_eq!(a.clusters.len(), 9, "{:?}", a.clusters.len());
        let p = &a.cotarget_pairs;
        assert_eq!(p.len(), 3, "{p:?}");
        for x in p {
            assert_eq!(x.hosts, 4);
            assert!(x.chance < 0.01, "{}", x.detail());
            assert!(x.similarity > 0.9, "{}", x.detail());
        }
        assert!(
            a.soft_links
                .iter()
                .any(|l| l.kind == crate::fleets::SoftLinkKind::CoTarget),
            "{:?}",
            a.soft_links
        );
    }

    #[test]
    fn a_popular_target_ties_nobody() {
        // Eight unrelated agents on one news story's hosts in one hour:
        // every host has more holders than the cap.
        let hosts = ["a.news.example", "b.news.example", "c.news.example"];
        let a = analyze(records(8, &hosts, 4), &Rules::default_rules());
        assert!(a.cotarget_pairs.is_empty(), "{:?}", a.cotarget_pairs);
        // Two hosts in common are not enough either.
        let a = analyze(
            records(3, &["a.list.example", "b.list.example"], 6),
            &Rules::default_rules(),
        );
        assert!(a.cotarget_pairs.is_empty(), "{:?}", a.cotarget_pairs);
    }
}
