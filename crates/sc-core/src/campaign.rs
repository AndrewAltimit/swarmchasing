//! Campaigns: one site worked by many senders with one set of habits that
//! senders elsewhere seldom hold together.
//!
//! An operator running many short sessions against one site, each through
//! a relay with a fresh callback inbox and run tag and a new client, leaves
//! nothing two sessions share outright: linking keeps them apart, and the
//! pairwise and co-group tests drop a site or template held by more than a
//! few senders as a crowd's. What the sessions keep is how they are built:
//! the same carriers, relay, callback service, markers and tag scheme on
//! every one. Each such habit alone is common; on one site, all together,
//! by most of its senders, and seldom together elsewhere, they are one
//! operator's.
//!
//! **Senders** are the clusters above noise and the flagged records outside
//! them, so sessions that never linked count one each. A sender's
//! **habits** are the rule ids hit and the run-tag parameter names carried
//! by at least half of its records. Its **sites** are the host families
//! ([`crate::knowledge::family`]) of its target hosts; families with a
//! record hitting a listed benchmark or practice target are left out.
//!
//! For each site with `min_senders` senders, its **core** is the habits
//! held by at least `core_share` of them; with `min_habits` or more, the
//! senders holding the whole core, or all of it but `slack` habits and at
//! least `min_habits`, are its **members**. The statistic is
//! how unlikely that many of the site's senders hold the core when the
//! site's senders are drawn at random from all senders: the hypergeometric
//! tail `P(X >= k)` for `k` members of `n` senders at the site, among `N`
//! senders of which `M` hold the core as members do.
//!
//! **Null.** The site's senders are drawn at random from all senders
//! `permutations` times (seeded from the site), the core and the statistic
//! read afresh each time, and the site's chance is `(ge + 1) /
//! (permutations + 1)` for `ge` draws scoring as high. Unrelated senders on
//! one popular site draw their habits as senders elsewhere do, so a core
//! they share is shared as widely elsewhere: a news story or a popular
//! relay sends a crowd, not a habit set. Sites are kept at `max_chance` and
//! under a Benjamini-Hochberg cut at false discovery rate `fdr` over the
//! sites tested.
//!
//! A published exploit for one site's flaw, copied whole by unrelated
//! senders who use it nowhere else, reads as a campaign too: what it
//! proposes is one operator, for the admin to check. Campaigns are soft
//! links ([`crate::fleets`]) between their clusters, and a summary of the
//! records outside them; they never score, link or merge.

use crate::analyze::{Cluster, ObsResult};
use crate::chance::{Mix, TestFamily, seed};
use crate::model::{LinkFeature, Tier};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// Campaign settings (`[campaign]` in the rules file).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CampaignOptions {
    /// Senders a site needs to be tested, and members a campaign needs.
    pub min_senders: usize,
    /// Habits its core needs.
    pub min_habits: usize,
    /// Core habits a member may lack, holding at least `min_habits` of
    /// it: a session that skipped one step of the habit set.
    pub slack: usize,
    /// Share of a site's senders a habit of its core is held by.
    pub core_share: f64,
    /// Random draws of the site's senders in the null.
    pub permutations: usize,
    /// A site is kept when its chance is at most this.
    pub max_chance: f64,
    /// Benjamini-Hochberg false discovery rate over the sites tested.
    pub fdr: f64,
}

impl Default for CampaignOptions {
    fn default() -> Self {
        Self {
            min_senders: 4,
            min_habits: 3,
            slack: 1,
            core_share: 0.5,
            permutations: 999,
            max_chance: 0.01,
            fdr: 0.05,
        }
    }
}

/// Senders on one site holding one habit set beyond chance.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Campaign {
    /// `CP1`, `CP2`, ... in this analysis.
    pub id: String,
    /// The host family, as written (defang it to show it).
    pub site: String,
    /// The core: `rule:<id>` and `tag:<parameter name>`, sorted.
    pub habits: Vec<String>,
    /// Member clusters, in analysis order.
    pub clusters: Vec<String>,
    /// Member records outside any cluster, by record id.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub records: Vec<String>,
    /// Senders on the site, and every sender.
    pub senders: usize,
    pub population: usize,
    /// Senders anywhere holding the core as members do.
    pub holders: usize,
    /// `-ln` of the hypergeometric tail.
    pub score: f64,
    pub permutations: usize,
    /// Draws scoring at least as high.
    pub null_ge: usize,
    /// `(null_ge + 1) / (permutations + 1)`.
    pub chance: f64,
    /// Sites tested, and sites this unlikely expected among them.
    pub tested: usize,
    pub expected: f64,
}

impl Campaign {
    /// Members, clusters and records outside them.
    pub fn members(&self) -> usize {
        self.clusters.len() + self.records.len()
    }

    /// The habits without their `rule:` and `tag:` prefixes.
    pub fn habit_names(&self) -> Vec<&str> {
        self.habits
            .iter()
            .map(|h| h.split_once(':').map_or(h.as_str(), |x| x.1))
            .collect()
    }

    pub fn detail(&self) -> String {
        format!(
            "{} of {} senders on one site hold {} habits ({}) that {} of {} senders hold anywhere (score {:.1}, matched in {} of {} random draws of the site's senders, chance {:.1e}; {:.2} expected over {} sites tested): one operator may run them all",
            self.members(),
            self.senders,
            self.habits.len(),
            self.habit_names().join(", "),
            self.holders,
            self.population,
            self.score,
            self.null_ge,
            self.permutations,
            self.chance,
            self.expected,
            self.tested
        )
    }
}

/// One cluster above noise, or one flagged record outside them.
struct Sender {
    cluster: Option<usize>,
    record: usize,
    sites: BTreeSet<String>,
    /// Habit indexes, sorted.
    habits: Vec<usize>,
}

/// A record's habits: the rule ids it hits and the run-tag parameter names
/// it carries.
fn record_habits(r: &ObsResult) -> BTreeSet<String> {
    let mut out: BTreeSet<String> = r
        .hits
        .iter()
        .map(|h| format!("rule:{}", h.rule_id))
        .collect();
    for f in &r.features {
        if let LinkFeature::Param { name, .. } = f {
            out.insert(format!("tag:{name}"));
        }
    }
    out
}

/// The site's core among `at` (sender indexes): habits held by at least
/// `core_share` of them. `None` below `min_habits`.
fn core(senders: &[Sender], at: &[usize], opts: &CampaignOptions) -> Option<Vec<usize>> {
    let mut counts: BTreeMap<usize, usize> = BTreeMap::new();
    for &s in at {
        for &h in &senders[s].habits {
            *counts.entry(h).or_default() += 1;
        }
    }
    let need = (opts.core_share * at.len() as f64).ceil().max(1.0) as usize;
    let k: Vec<usize> = counts
        .into_iter()
        .filter(|&(_, n)| n >= need)
        .map(|(h, _)| h)
        .collect();
    (k.len() >= opts.min_habits.max(1)).then_some(k)
}

/// Whether `s` holds the core but for `slack` habits, and at least
/// `min_habits` of it.
fn holds(s: &Sender, core: &[usize], opts: &CampaignOptions) -> bool {
    let need = core
        .len()
        .saturating_sub(opts.slack)
        .max(opts.min_habits)
        .min(core.len());
    core.iter()
        .filter(|h| s.habits.binary_search(h).is_ok())
        .count()
        >= need
}

/// `-ln P(X >= k)` for `X` hypergeometric: `n` drawn from `total`, `m` of
/// which are marked.
fn hypergeometric_score(total: usize, m: usize, n: usize, k: usize, lnf: &[f64]) -> f64 {
    let ln_choose = |a: usize, b: usize| {
        if b > a {
            f64::NEG_INFINITY
        } else {
            lnf[a] - lnf[b] - lnf[a - b]
        }
    };
    let denom = ln_choose(total, n);
    let top = n.min(m);
    if k > top {
        return 0.0;
    }
    let terms: Vec<f64> = (k..=top)
        .map(|x| ln_choose(m, x) + ln_choose(total - m, n - x) - denom)
        .filter(|t| t.is_finite())
        .collect();
    let Some(max) = terms.iter().copied().reduce(f64::max) else {
        return 0.0;
    };
    let ln_p = max + terms.iter().map(|t| (t - max).exp()).sum::<f64>().ln();
    (-ln_p).max(0.0)
}

/// The statistic of the senders `at` on one site: the score, the core and
/// its members, and its holders anywhere; a score of 0 when the core is
/// too small or held by too few of them.
fn statistic(
    senders: &[Sender],
    at: &[usize],
    opts: &CampaignOptions,
    lnf: &[f64],
) -> (f64, Vec<usize>, Vec<usize>, usize) {
    let Some(k) = core(senders, at, opts) else {
        return (0.0, Vec::new(), Vec::new(), 0);
    };
    let members: Vec<usize> = at
        .iter()
        .copied()
        .filter(|&s| holds(&senders[s], &k, opts))
        .collect();
    if members.len() < opts.min_senders.max(2) {
        return (0.0, k, members, 0);
    }
    let m = senders.iter().filter(|s| holds(s, &k, opts)).count();
    let score = hypergeometric_score(senders.len(), m, at.len(), members.len(), lnf);
    (score, k, members, m)
}

/// Campaigns among clusters above noise and flagged records outside them,
/// strongest first, and the sites' multiplicity budget.
pub(crate) fn campaigns(
    clusters: &[Cluster],
    results: &[ObsResult],
    benchmarks: &crate::knowledge::KnownSet,
    opts: &CampaignOptions,
) -> (Vec<Campaign>, TestFamily) {
    let empty = |tested| {
        (
            Vec::new(),
            TestFamily::cut("campaign", &[], tested, opts.fdr),
        )
    };
    // Families with a record on a listed benchmark are practice, not a site.
    let mut bench: BTreeSet<&str> = BTreeSet::new();
    for r in results {
        if let Some(h) = r.target_host.as_deref()
            && crate::knowledge::hits_any(r, benchmarks)
        {
            bench.insert(crate::knowledge::family(h));
        }
    }
    let mut names: BTreeMap<String, usize> = BTreeMap::new();
    let mut index = |h: String| {
        let n = names.len();
        *names.entry(h).or_insert(n)
    };
    let mut senders: Vec<Sender> = Vec::new();
    let mut add = |cluster: Option<usize>, members: &[usize], senders: &mut Vec<Sender>| {
        let mut sites = BTreeSet::new();
        let mut counts: BTreeMap<String, usize> = BTreeMap::new();
        for &m in members {
            let r = &results[m];
            if let Some(h) = r.target_host.as_deref() {
                let f = crate::knowledge::family(h);
                if !bench.contains(f) {
                    sites.insert(f.to_ascii_lowercase());
                }
            }
            for h in record_habits(r) {
                *counts.entry(h).or_default() += 1;
            }
        }
        let mut habits: Vec<usize> = counts
            .into_iter()
            .filter(|&(_, n)| 2 * n >= members.len())
            .map(|(h, _)| index(h))
            .collect();
        habits.sort_unstable();
        if let Some(&record) = members.first() {
            senders.push(Sender {
                cluster,
                record,
                sites,
                habits,
            });
        }
    };
    let mut clustered = vec![false; results.len()];
    for (ci, c) in clusters.iter().enumerate() {
        for &m in &c.members {
            clustered[m] = true;
        }
        if c.tier > Tier::Noise {
            add(Some(ci), &c.members, &mut senders);
        }
    }
    for (i, r) in results.iter().enumerate() {
        if !clustered[i] && r.tier > Tier::Noise {
            add(None, &[i], &mut senders);
        }
    }
    let habit_names: Vec<String> = {
        let mut v = vec![String::new(); names.len()];
        for (h, i) in names {
            v[i] = h;
        }
        v
    };
    let mut by_site: BTreeMap<&str, Vec<usize>> = BTreeMap::new();
    for (i, s) in senders.iter().enumerate() {
        for f in &s.sites {
            by_site.entry(f.as_str()).or_default().push(i);
        }
    }
    let n_all = senders.len();
    let lnf: Vec<f64> = {
        let mut v = vec![0.0; n_all + 1];
        for i in 1..=n_all {
            v[i] = v[i - 1] + (i as f64).ln();
        }
        v
    };
    let min_senders = opts.min_senders.max(2);
    let sites: Vec<(&str, Vec<usize>)> = by_site
        .into_iter()
        .filter(|(_, at)| at.len() >= min_senders && at.len() < n_all)
        .collect();
    if sites.is_empty() {
        return empty(0);
    }
    let perms = opts.permutations.max(1);
    let mut found = Vec::new();
    let mut chances = Vec::new();
    for (site, at) in &sites {
        let (score, k, members, m) = statistic(&senders, at, opts, &lnf);
        if score <= 0.0 {
            continue;
        }
        let mut mix = Mix(seed(&["campaign", site]));
        let mut order: Vec<usize> = (0..n_all).collect();
        let mut ge = 0;
        for _ in 0..perms {
            // A partial shuffle: the first `n` are the draw.
            for i in 0..at.len() {
                let j = i + (mix.next() % (n_all - i) as u64) as usize;
                order.swap(i, j);
            }
            let (s, ..) = statistic(&senders, &order[..at.len()], opts, &lnf);
            if s >= score - 1e-9 {
                ge += 1;
            }
        }
        let chance = (ge + 1) as f64 / (perms + 1) as f64;
        if chance <= opts.max_chance {
            chances.push(chance);
        }
        found.push((*site, k, members, m, at.len(), score, ge, chance));
    }
    let family = TestFamily::cut("campaign", &chances, sites.len(), opts.fdr);
    let mut out: Vec<Campaign> = found
        .into_iter()
        .filter(|f| f.7 <= opts.max_chance && family.keeps(f.7))
        .map(|(site, k, members, m, n, score, ge, chance)| {
            let mut cl: Vec<usize> = members.iter().filter_map(|&s| senders[s].cluster).collect();
            cl.sort_unstable();
            let mut records: Vec<String> = members
                .iter()
                .filter(|&&s| senders[s].cluster.is_none())
                .map(|&s| results[senders[s].record].obs.id.clone())
                .collect();
            records.sort();
            let mut habits: Vec<String> = k.iter().map(|&h| habit_names[h].clone()).collect();
            habits.sort();
            Campaign {
                id: String::new(),
                site: site.to_string(),
                habits,
                clusters: cl.iter().map(|&c| clusters[c].id.clone()).collect(),
                records,
                senders: n,
                population: n_all,
                holders: m,
                score,
                permutations: perms,
                null_ge: ge,
                chance,
                tested: family.tested,
                expected: chance * family.tested as f64,
            }
        })
        .collect();
    crate::sort::by(&mut out, |p, q| {
        p.chance
            .total_cmp(&q.chance)
            .then(q.score.total_cmp(&p.score))
            .then(p.site.cmp(&q.site))
    });
    for (n, c) in out.iter_mut().enumerate() {
        c.id = format!("CP{}", n + 1);
    }
    (out, family)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyze::analyze;
    use crate::chance::ln_fact;
    use crate::model::{Observation, TsKind};
    use crate::rules::Rules;

    fn obs(id: String, ts: i64, url: String) -> Observation {
        Observation {
            id,
            source: "urlquery".into(),
            ts,
            ts_kind: TsKind::Submit,
            url,
            ..Default::default()
        }
    }

    /// One session's requests: the operator's carrier around a relay of the
    /// site, a fresh inbox and tag each session.
    fn session(k: usize, host: &str, t: i64) -> Vec<Observation> {
        (0..2)
            .map(|r| {
                obs(
                    format!("s{k}r{r}"),
                    t + r as i64 * 40,
                    format!(
                        "https://r.jina.ai/https://{host}/place/{k}{r}?uqscan=x{k:04}r&cb=https://webhook.site/{k:08x}-0000-4000-8000-00000000{r:04}"
                    ),
                )
            })
            .collect()
    }

    /// Unrelated senders, each its own habit: a relay read, a traversal, an
    /// SQL probe, on a site of its own or on one shared site.
    fn other(k: usize, host: &str, t: i64) -> Observation {
        let url = match k % 3 {
            0 => format!("https://r.jina.ai/https://{host}/news/{k}"),
            1 => format!("https://{host}/static/..%2f..%2f..%2fetc/passwd?v={k}"),
            _ => format!("https://{host}/item?id={k}%27%20OR%201=1--"),
        };
        obs(format!("o{k}"), t, url)
    }

    fn rules() -> Rules {
        let mut r = Rules::default_rules();
        r.set.campaign.permutations = 199;
        r
    }

    #[test]
    fn many_sessions_on_one_site_with_one_habit_set_are_one_campaign() {
        let mut v = Vec::new();
        // Twelve sessions on one site over four days, hours apart.
        for k in 0..12 {
            v.extend(session(
                k,
                "maps.site-a.example",
                1_790_000_000 + k as i64 * 29_000,
            ));
        }
        // Forty unrelated senders elsewhere.
        for k in 0..40 {
            v.push(other(
                k,
                &format!("h{k}.site-{k}.example"),
                1_790_000_000 + k as i64 * 7_000,
            ));
        }
        let a = analyze(v, &rules());
        let c = &a.campaigns;
        assert_eq!(c.len(), 1, "{c:?}");
        assert_eq!(c[0].site, "site-a.example");
        assert!(c[0].members() >= 10, "{c:?}");
        assert!(c[0].habits.iter().any(|h| h == "tag:uqscan"), "{c:?}");
        assert!(c[0].chance <= 0.01);
        // Every pair of its clusters is a soft link, and they are one fleet.
        let ids: BTreeSet<&str> = c[0].clusters.iter().map(String::as_str).collect();
        if ids.len() >= 2 {
            assert!(
                a.soft_links
                    .iter()
                    .any(|l| l.kind == crate::fleets::SoftLinkKind::Campaign)
            );
            assert!(a.candidate_fleets.iter().any(|f| {
                f.clusters
                    .iter()
                    .filter(|x| ids.contains(x.as_str()))
                    .count()
                    == ids.len()
            }));
        }
    }

    #[test]
    fn unrelated_senders_on_one_popular_site_are_no_campaign() {
        let mut v = Vec::new();
        // Thirty unrelated senders on one site, thirty elsewhere, all
        // drawing their habits alike.
        for k in 0..30 {
            v.push(other(
                k,
                "www.popular.example",
                1_790_000_000 + k as i64 * 900,
            ));
        }
        for k in 30..60 {
            v.push(other(
                k,
                &format!("h{k}.site-{k}.example"),
                1_790_000_000 + k as i64 * 900,
            ));
        }
        let a = analyze(v, &rules());
        assert!(a.campaigns.is_empty(), "{:?}", a.campaigns);
    }

    #[test]
    fn the_hypergeometric_tail_matches_a_direct_sum() {
        let lnf: Vec<f64> = (0..=20).map(ln_fact).collect();
        // 20 senders, 5 marked, 5 drawn: P(X >= 3).
        let c = |a: f64, b: f64| -> f64 {
            let a = a as usize;
            let b = b as usize;
            (lnf[a] - lnf[b] - lnf[a - b]).exp()
        };
        let p = (3..=5)
            .map(|x| c(5.0, x as f64) * c(15.0, 5.0 - x as f64))
            .sum::<f64>()
            / c(20.0, 5.0);
        let s = hypergeometric_score(20, 5, 5, 3, &lnf);
        assert!((s - (-p.ln())).abs() < 1e-9, "{s} {}", -p.ln());
        assert_eq!(hypergeometric_score(20, 5, 5, 0, &lnf), 0.0);
        assert_eq!(hypergeometric_score(20, 5, 5, 6, &lnf), 0.0);
    }
}
