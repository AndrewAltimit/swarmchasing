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
//!
//! [`ordered_pairs`] reads what this test leaves aside, the order: two
//! concurrent clusters that first touched the rare hosts they share in the
//! same order, at their own paces, beyond a random order.

use crate::analyze::{Cluster, ObsResult};
use crate::chance::TestFamily;
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
    /// Ordered co-target: rare hosts two concurrent clusters must share
    /// before the order they first touched them in is read
    /// ([`ordered_pairs`]). Its chance and cut are `max_chance` and `fdr`.
    pub order_min_hosts: usize,
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
            order_min_hosts: 5,
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

/// Senders per target host held by a cluster above noise: those clusters,
/// and records outside them.
fn host_holders<'a>(shown: &[&Cluster], results: &'a [ObsResult]) -> BTreeMap<&'a str, usize> {
    let in_shown: BTreeSet<usize> = shown
        .iter()
        .flat_map(|c| c.members.iter().copied())
        .collect();
    let mut holders: BTreeMap<&str, usize> = BTreeMap::new();
    for c in shown {
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
    holders
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
    let holders = host_holders(&shown, results);
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

/// Two concurrent clusters that first touched their shared rare hosts in
/// the same order beyond chance.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OrderedCoTargetPair {
    /// Cluster ids, `a` the stronger.
    pub a: String,
    pub b: String,
    /// Rare hosts both touched.
    pub shared: usize,
    /// The longest run of them both touched in the same order.
    pub in_order: usize,
    /// Chance of so long a run in a random order of `shared` hosts.
    pub chance: f64,
    /// Pairs tested, and pairs this unlikely expected among them.
    pub tested: usize,
    pub expected_pairs: f64,
}

impl OrderedCoTargetPair {
    pub fn detail(&self) -> String {
        format!(
            "{} of {} shared rare hosts first touched in the same order, in the same hours (chance {:.1e} for a random order, {:.2} such pairs expected among {} tested): one ordered target list may drive both",
            self.in_order, self.shared, self.chance, self.expected_pairs, self.tested
        )
    }
}

/// A host name as a sort key with runs of digits read as numbers, as a
/// list sorted "naturally" orders them (`h2` before `h10`).
fn natural_key(h: &str) -> Vec<(u8, usize, String)> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut digits = false;
    for ch in h.chars() {
        if !cur.is_empty() && ch.is_ascii_digit() != digits {
            out.push(natural_part(&cur, digits));
            cur.clear();
        }
        digits = ch.is_ascii_digit();
        cur.push(ch);
    }
    if !cur.is_empty() {
        out.push(natural_part(&cur, digits));
    }
    out
}

fn natural_part(s: &str, digits: bool) -> (u8, usize, String) {
    if digits {
        let t = s.trim_start_matches('0');
        (0, t.len(), t.to_string())
    } else {
        (1, 0, s.to_string())
    }
}

/// Whether both clusters' orders follow one sorted order of the hosts (by
/// text or with numbers read as numbers, either way) at least as far as
/// they follow each other: a public sorted or ranked list gives that order
/// without a shared operator.
fn sorted_explains(hosts: &[&str], tx: &[i64], ty: &[i64], in_order: usize) -> bool {
    let mut by_text: Vec<usize> = (0..hosts.len()).collect();
    by_text.sort_by(|&i, &k| hosts[i].cmp(hosts[k]));
    let keys: Vec<_> = hosts.iter().map(|h| natural_key(h)).collect();
    let mut by_number: Vec<usize> = (0..hosts.len()).collect();
    by_number.sort_by(|&i, &k| keys[i].cmp(&keys[k]).then(hosts[i].cmp(hosts[k])));
    [by_text, by_number].iter().any(|order| {
        let mut rank = vec![0i64; hosts.len()];
        for (r, &i) in order.iter().enumerate() {
            rank[i] = r as i64;
        }
        [1i64, -1].iter().any(|&dir| {
            let follows = |t: &[i64]| {
                let pts: Vec<(i64, i64)> =
                    (0..hosts.len()).map(|i| (t[i], dir * rank[i])).collect();
                crate::chance::longest_chain(&pts) >= in_order
            };
            follows(tx) && follows(ty)
        })
    })
}

/// Whether both clusters' orders follow the order the hosts first appeared
/// in the background (`seen`: each host's earliest time in records outside
/// every cluster above noise) at least as far as they follow each other:
/// readers of one time-ordered source (a certificate log, newly registered
/// domains, a trending list) touch its hosts in the order they arrive,
/// without a shared operator, and other readers of it show that order.
/// Hosts the background never touched take no part.
fn arrival_explains(
    hosts: &[&str],
    seen: &BTreeMap<&str, i64>,
    tx: &[i64],
    ty: &[i64],
    in_order: usize,
) -> bool {
    let follows = |t: &[i64]| {
        let pts: Vec<(i64, i64)> = hosts
            .iter()
            .zip(t)
            .filter_map(|(h, &ti)| seen.get(h).map(|&s| (ti, s)))
            .collect();
        pts.len() >= in_order && crate::chance::longest_chain(&pts) >= in_order
    };
    follows(tx) && follows(ty)
}

/// Pairs of concurrent clusters above noise that first touched the rare
/// hosts they share in the same order beyond chance, most unlikely first,
/// and the family's multiplicity budget. A pair sharing at least
/// `order_min_hosts` rare hosts (rare as [`cotarget_pairs`] counts it),
/// whose first touches of them fall within `bin_secs` of each other's span,
/// is tested: the longest run of shared hosts both first touched in the
/// same order, from request and submit times only, against a random order
/// ([`crate::chance::increasing_at_least`]). Ties in either cluster's times
/// never count as agreement. A pair whose two orders both follow the
/// hosts' sorted order as far is explained by a sorted list, and one whose
/// two orders both follow the hosts' first appearance in the background as
/// far by a time-ordered source ([`arrival_explains`]); both are kept out.
pub(crate) fn ordered_pairs(
    clusters: &[Cluster],
    results: &[ObsResult],
    max_shared: usize,
    opts: &CoTargetOptions,
) -> (Vec<OrderedCoTargetPair>, TestFamily) {
    let shown: Vec<&Cluster> = clusters.iter().filter(|c| c.tier > Tier::Noise).collect();
    let holders = host_holders(&shown, results);
    let cap = opts.max_holders.min(max_shared);
    let rare = |h: &str| holders.get(h).is_some_and(|&n| n <= cap);
    let min_hosts = opts.order_min_hosts.max(2);
    // Each rare host's first appearance outside every cluster above noise.
    let in_shown: BTreeSet<usize> = shown
        .iter()
        .flat_map(|c| c.members.iter().copied())
        .collect();
    let mut seen: BTreeMap<&str, i64> = BTreeMap::new();
    for (i, r) in results.iter().enumerate() {
        if in_shown.contains(&i) || r.obs.ts <= 0 {
            continue;
        }
        if let Some(h) = r.target_host.as_deref().filter(|h| rare(h)) {
            let t = seen.entry(h).or_insert(r.obs.ts);
            *t = (*t).min(r.obs.ts);
        }
    }
    // Each cluster's first touch of each rare host.
    let firsts: Vec<(&str, BTreeMap<&str, i64>)> = shown
        .iter()
        .filter_map(|c| {
            let mut m: BTreeMap<&str, i64> = BTreeMap::new();
            for &i in &c.members {
                let r = &results[i];
                let Some(h) = r.target_host.as_deref() else {
                    continue;
                };
                if r.obs.ts <= 0 || !request_like(r.obs.ts_kind) || !rare(h) {
                    continue;
                }
                let t = m.entry(h).or_insert(r.obs.ts);
                *t = (*t).min(r.obs.ts);
            }
            (m.len() >= min_hosts).then_some((c.id.as_str(), m))
        })
        .collect();
    let mut by_host: BTreeMap<&str, Vec<usize>> = BTreeMap::new();
    for (i, (_, m)) in firsts.iter().enumerate() {
        for h in m.keys() {
            by_host.entry(h).or_default().push(i);
        }
    }
    let mut common: BTreeMap<(usize, usize), Vec<&str>> = BTreeMap::new();
    for (h, ids) in &by_host {
        for (n, &x) in ids.iter().enumerate() {
            for &y in &ids[n + 1..] {
                common.entry((x, y)).or_default().push(h);
            }
        }
    }
    let widen = opts.bin_secs.max(0);
    let span = |t: &[i64]| {
        (
            t.iter().min().copied().unwrap_or(0),
            t.iter().max().copied().unwrap_or(0),
        )
    };
    let mut tested = 0usize;
    let mut out = Vec::new();
    for ((x, y), hosts) in common {
        if hosts.len() < min_hosts {
            continue;
        }
        let (mx, my) = (&firsts[x].1, &firsts[y].1);
        let tx: Vec<i64> = hosts.iter().map(|h| mx[h]).collect();
        let ty: Vec<i64> = hosts.iter().map(|h| my[h]).collect();
        let ((sx, ex), (sy, ey)) = (span(&tx), span(&ty));
        // Concurrent only: a rerun on another day is read by the rerun hint.
        if sx > ey + widen || sy > ex + widen {
            continue;
        }
        tested += 1;
        let pts: Vec<(i64, i64)> = tx.iter().copied().zip(ty.iter().copied()).collect();
        let in_order = crate::chance::longest_chain(&pts);
        let chance = crate::chance::increasing_at_least(hosts.len(), in_order);
        if chance > opts.max_chance
            || sorted_explains(&hosts, &tx, &ty, in_order)
            || arrival_explains(&hosts, &seen, &tx, &ty, in_order)
        {
            continue;
        }
        out.push(OrderedCoTargetPair {
            a: firsts[x].0.to_string(),
            b: firsts[y].0.to_string(),
            shared: hosts.len(),
            in_order,
            chance,
            tested: 0,
            expected_pairs: 0.0,
        });
    }
    let ps: Vec<f64> = out.iter().map(|p| p.chance).collect();
    let family = TestFamily::cut("ordered_co_target", &ps, tested, opts.fdr);
    out.retain(|p| family.keeps(p.chance));
    for p in &mut out {
        p.tested = family.tested;
        p.expected_pairs = p.chance * family.tested as f64;
    }
    crate::sort::by(&mut out, |p, q| {
        p.chance
            .total_cmp(&q.chance)
            .then(q.in_order.cmp(&p.in_order))
            .then(p.a.cmp(&q.a))
            .then(p.b.cmp(&q.b))
    });
    out.truncate(MAX_PAIRS);
    (out, family)
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

    /// Three clusters by inbox, each probing `hosts` in its own order
    /// (`orders[a]`, indexes into `hosts`) at its own pace, starting twenty
    /// minutes apart: concurrent, never on one host within the link window.
    fn ordered(hosts: &[&str], orders: &[Vec<usize>]) -> Vec<Observation> {
        let t0 = 1_791_000_000;
        let inbox = |n: usize| format!("{n:08x}-2222-4b3c-8a66-4e3f2a1b0c9d");
        let mut obs = Vec::new();
        for (a, order) in orders.iter().enumerate() {
            let pace = 900 + 400 * a as i64;
            for (step, &k) in order.iter().enumerate() {
                obs.push(o(
                    &format!("a{a}-{k}"),
                    t0 + a as i64 * 1200 + step as i64 * pace,
                    &format!(
                        "https://{}/q?id=1%27%20OR%201=1--&hook=https://webhook.site/{}",
                        hosts[k],
                        inbox(a)
                    ),
                ));
            }
        }
        obs
    }

    #[test]
    fn one_ordered_list_at_differing_paces_is_an_ordered_pair() {
        // A list in no sorted order, worked in the same order by all three.
        let hosts = [
            "kilo.list.example",
            "alpha.list.example",
            "mike.list.example",
            "delta.list.example",
            "zulu.list.example",
            "echo.list.example",
            "bravo.list.example",
        ];
        let same: Vec<usize> = (0..7).collect();
        let a = analyze(
            ordered(&hosts, &[same.clone(), same.clone(), same.clone()]),
            &Rules::default_rules(),
        );
        assert_eq!(a.clusters.len(), 3, "{:?}", a.clusters.len());
        let p = &a.ordered_cotarget_pairs;
        assert_eq!(p.len(), 3, "{p:?}");
        for x in p {
            assert_eq!((x.shared, x.in_order, x.tested), (7, 7, 3));
            assert!((x.chance - 1.0 / 5040.0).abs() < 1e-12, "{}", x.detail());
            assert!(!x.detail().contains("example"));
        }
        assert!(
            a.soft_links
                .iter()
                .any(|l| l.kind == crate::fleets::SoftLinkKind::OrderedCoTarget),
            "{:?}",
            a.soft_links
        );
        let f = a
            .multiplicity
            .iter()
            .find(|f| f.family == "ordered_co_target");
        assert_eq!(f.map(|f| (f.kept, f.tested)), Some((3, 3)), "{f:?}");

        // Each in its own order: no run long enough.
        let own = vec![
            same.clone(),
            vec![6, 5, 4, 3, 2, 1, 0],
            vec![3, 6, 1, 4, 0, 5, 2],
        ];
        let b = analyze(ordered(&hosts, &own), &Rules::default_rules());
        assert!(
            b.ordered_cotarget_pairs.is_empty(),
            "{:?}",
            b.ordered_cotarget_pairs
        );

        // A sorted list (by number) gives every reader one order: no tie.
        let sorted = [
            "h2.list.example",
            "h3.list.example",
            "h5.list.example",
            "h8.list.example",
            "h13.list.example",
            "h21.list.example",
            "h34.list.example",
        ];
        let c = analyze(
            ordered(&sorted, &[same.clone(), same.clone(), same]),
            &Rules::default_rules(),
        );
        assert_eq!(c.clusters.len(), 3);
        assert!(
            c.ordered_cotarget_pairs.is_empty(),
            "{:?}",
            c.ordered_cotarget_pairs
        );
    }

    #[test]
    fn readers_of_one_time_ordered_source_are_no_ordered_pair() {
        let hosts = [
            "kilo.new.example",
            "alpha.new.example",
            "mike.new.example",
            "delta.new.example",
            "zulu.new.example",
            "echo.new.example",
            "bravo.new.example",
        ];
        let same: Vec<usize> = (0..7).collect();
        let pair = ordered(&hosts, &[same.clone(), same.clone()]);
        let a = analyze(pair.clone(), &Rules::default_rules());
        assert_eq!(
            a.ordered_cotarget_pairs.len(),
            1,
            "{:?}",
            a.ordered_cotarget_pairs
        );
        // Plain visits outside any cluster touch the hosts first, in the
        // order they arrived: the same order, so arrival explains it.
        let background = |order: &[usize]| -> Vec<Observation> {
            order
                .iter()
                .enumerate()
                .map(|(step, &k)| {
                    o(
                        &format!("bg-{k}"),
                        1_790_990_000 + step as i64 * 600,
                        &format!("https://{}/", hosts[k]),
                    )
                })
                .collect()
        };
        let mut fed = pair.clone();
        fed.extend(background(&same));
        let b = analyze(fed, &Rules::default_rules());
        assert_eq!(b.clusters.len(), 2, "{:?}", b.clusters.len());
        assert!(
            b.ordered_cotarget_pairs.is_empty(),
            "{:?}",
            b.ordered_cotarget_pairs
        );
        // Background in another order explains nothing.
        let mut other = pair;
        other.extend(background(&[3, 6, 1, 4, 0, 5, 2]));
        let c = analyze(other, &Rules::default_rules());
        assert_eq!(
            c.ordered_cotarget_pairs.len(),
            1,
            "{:?}",
            c.ordered_cotarget_pairs
        );
    }

    #[test]
    fn natural_order_reads_numbers_as_numbers() {
        let mut v = vec!["h10.x", "h2.x", "h1.x"];
        v.sort_by_key(|h| natural_key(h));
        assert_eq!(v, ["h1.x", "h2.x", "h10.x"]);
    }
}
