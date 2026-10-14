//! Playbook alignment: clusters that send one harness's steps in one order.
//!
//! A harness runs a task script: on each host it sends its steps in one
//! order (recon, then traversal, then injection, then script), whatever tag,
//! inbox or step it changes between agents. Scaffold fingerprints
//! ([`crate::scaffold`]) compare the mix of request templates as a set, and
//! an operator who reorders a public harness's steps keeps its set. This
//! reads the order.
//!
//! A record's **step** is its request template ([`crate::scaffold::template`])
//! less the parameters that carry linking values (run tags), so a new tag
//! style or inbox leaves the step as it was. Each cluster's steps on each
//! target host, by request or submit time (never capture times), repeats in
//! a row dropped, are one sequence; the cluster's **profile** is its most
//! common sequence, and it holds a playbook when that profile has
//! `min_steps` steps and is seen on `min_hosts` hosts.
//!
//! Two profiles are aligned locally (Smith-Waterman): a matched step scores
//! its IDF weight, a gap costs `gap_penalty`. The statistic sums the
//! alignment of each of one cluster's host sequences with the other's
//! profile, both ways, so a playbook seen on many hosts counts more than one
//! seen once. Its null shuffles each cluster's steps within each host
//! (`permutations` times, seeded from the two clusters), which keeps every
//! step set and asks only about the order; the share of shuffles scoring as
//! high is the order's chance, which must pass `max_order_chance` on its
//! own. The steps themselves have a base rate as scaffold templates do (the
//! rarest aligned step's other holders, and records outside the clusters
//! carrying it, over the other comparable clusters), and the two chances
//! combine as one test.
//!
//! A public order (a scanner's default, a checklist's) gives unrelated
//! operators one order: a pair whose aligned steps' payload classes follow
//! one of `common_orders` ties none, and a step carried by more than
//! `max_holders` senders is a common default and seeds no comparison.
//! Pairs are soft links in the harness family: they never score, link or
//! merge.

use crate::analyze::{Cluster, ObsResult};
use crate::chance::{Mix, TestFamily, product_chance, seed, sidak};
use crate::model::{LinkFeature, Tier};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// Playbook settings (`[playbook]` in the rules file).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PlaybookOptions {
    /// A step counts only with at least this many structural parts left
    /// once linking parameters are dropped (as `scaffold.min_specificity`).
    pub min_specificity: usize,
    /// Steps a cluster's profile needs, and steps two profiles must align.
    pub min_steps: usize,
    /// Hosts a cluster's profile must be seen on.
    pub min_hosts: usize,
    /// A step carried by more than this many senders (clusters above noise,
    /// and records outside them) is a common default and seeds no pair.
    pub max_holders: usize,
    /// What a gap in an alignment costs, in IDF units.
    pub gap_penalty: f64,
    /// Shuffles of each cluster's steps within host in the order's null.
    /// Its smallest chance is `1 / (permutations + 1)`.
    pub permutations: usize,
    /// The order's own chance must be at most this.
    pub max_order_chance: f64,
    /// Kept when the combined chance is at most this.
    pub max_chance: f64,
    /// Benjamini-Hochberg false discovery rate over the pairs compared.
    pub fdr: f64,
    /// Public orders of payload classes (`recon`, `traversal`, `sqli`,
    /// `xss`, `cmd`, `ssti`): a pair whose aligned steps' classes follow one
    /// of these ties none.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub common_orders: Vec<Vec<String>>,
}

impl Default for PlaybookOptions {
    fn default() -> Self {
        Self {
            min_specificity: 3,
            min_steps: 3,
            min_hosts: 2,
            max_holders: 10,
            gap_penalty: 1.0,
            permutations: 199,
            max_order_chance: 0.05,
            max_chance: 0.01,
            fdr: 0.05,
            common_orders: Vec::new(),
        }
    }
}

/// Steps kept per host sequence, and host sequences kept per cluster.
const MAX_STEPS: usize = 16;
const MAX_HOSTS: usize = 32;
/// Pairs kept, most unlikely first.
const MAX_PAIRS: usize = 200;
/// Aligned steps a pair lists.
const SHOWN_STEPS: usize = 6;
/// The class of a step with no canonical payload.
pub const RECON: &str = "recon";

/// Two clusters sending one playbook's steps in one order beyond chance.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PlaybookPair {
    /// Cluster ids, `a` the stronger.
    pub a: String,
    pub b: String,
    /// The aligned steps in order (a few), and their payload classes.
    pub steps: Vec<String>,
    pub classes: Vec<String>,
    /// Steps the two profiles align.
    pub aligned: usize,
    /// Hosts each cluster's profile is seen on, and the hosts it has.
    pub support_a: usize,
    pub hosts_a: usize,
    pub support_b: usize,
    pub hosts_b: usize,
    /// The alignment statistic, and the shuffles within host scoring as
    /// high, of those read.
    pub score: f64,
    pub beaten: usize,
    pub permutations: usize,
    /// `(beaten + 1) / (permutations + 1)`.
    pub order_chance: f64,
    /// Clusters above noise holding the rarest aligned step, the
    /// comparable clusters (those with a specific step at all), and records
    /// outside them carrying it.
    pub holders: usize,
    pub clusters: usize,
    pub outside: usize,
    /// That step's base rate, as for a scaffold template.
    pub base_rate: f64,
    /// Chance that two unrelated clusters share a step this rare among the
    /// aligned ones: `1 - (1 - base_rate²)^aligned`.
    pub step_chance: f64,
    /// The two combined ([`crate::chance::product_chance`]).
    pub chance: f64,
    /// Pairs compared, and pairs this unlikely expected among them.
    pub tested: usize,
    pub expected_pairs: f64,
}

impl PlaybookPair {
    pub fn detail(&self) -> String {
        format!(
            "{} steps in one order ({}), the playbook on {} of {} and {} of {} hosts; {} of {} shuffles within host score as high (order chance {:.1e}); the rarest step in {} of {} comparable clusters and {} record(s) outside them, a base rate of {:.1e}; chance {:.1e} ({:.2} such pairs expected among {} compared): {}",
            self.aligned,
            self.classes.join(" → "),
            self.support_a,
            self.hosts_a,
            self.support_b,
            self.hosts_b,
            self.beaten,
            self.permutations,
            self.order_chance,
            self.holders,
            self.clusters,
            self.outside,
            self.base_rate,
            self.chance,
            self.expected_pairs,
            self.tested,
            self.steps.first().map_or("", String::as_str)
        )
    }
}

/// A record's step: its request template less the parameters carrying
/// linking values, its structural parts, and its payload classes (`recon`
/// when it has none). `None` below `min_specificity`.
pub fn step(r: &ObsResult, min_specificity: usize) -> Option<(String, BTreeSet<String>)> {
    let t = crate::scaffold::template(r);
    let linking: BTreeSet<String> = r
        .features
        .iter()
        .filter_map(|f| match f {
            LinkFeature::Param { name, .. } => Some(name.to_ascii_lowercase()),
            LinkFeature::Rule { .. } => None,
        })
        .collect();
    let mut spec = 0;
    let mut key = Vec::new();
    let mut classes = BTreeSet::new();
    for p in &t.parts {
        if p.kind == "parameter"
            && p.text.split_once('=').is_some_and(|(n, _)| {
                linking
                    .iter()
                    .any(|l| l == n || (n.len() >= 32 && l.starts_with(n)))
            })
        {
            continue;
        }
        if p.kind == "payloads" {
            for v in p.text.split(',') {
                classes.insert(v.split('.').next().unwrap_or(v).to_string());
            }
        }
        spec += p.weight;
        key.push(format!("{}:{}", p.kind, p.text));
    }
    if spec < min_specificity {
        return None;
    }
    if classes.is_empty() {
        classes.insert(RECON.to_string());
    }
    Some((key.join(" | "), classes))
}

/// One cluster's sequences of step ids on its hosts.
struct Book {
    hosts: Vec<Vec<usize>>,
    profile: Vec<usize>,
    support: usize,
}

/// The most common sequence of at least two steps, the longer on a tie,
/// then the earlier host's; with the hosts it is seen on.
fn profile(hosts: &[Vec<usize>]) -> (Vec<usize>, usize) {
    let mut count: BTreeMap<&[usize], (usize, usize)> = BTreeMap::new();
    for (i, h) in hosts.iter().enumerate() {
        if h.len() >= 2 {
            count.entry(h.as_slice()).or_insert((0, i)).0 += 1;
        }
    }
    count
        .into_iter()
        .max_by(|a, b| {
            (a.1.0, a.0.len())
                .cmp(&(b.1.0, b.0.len()))
                .then(b.1.1.cmp(&a.1.1))
        })
        .map_or((Vec::new(), 0), |(s, (n, _))| (s.to_vec(), n))
}

/// The best local alignment of `x` with `y` (Smith-Waterman): a match
/// scores `w` of its step, a gap costs `gap`. With `trace`, the aligned
/// index pairs in order.
fn align(x: &[usize], y: &[usize], w: &[f64], gap: f64, trace: bool) -> (f64, Vec<(usize, usize)>) {
    let (n, m) = (x.len(), y.len());
    if n == 0 || m == 0 {
        return (0.0, Vec::new());
    }
    let cols = m + 1;
    let mut d = vec![0.0f64; (n + 1) * cols];
    let (mut best, mut at) = (0.0, (0, 0));
    for i in 1..=n {
        for j in 1..=m {
            let diag = if x[i - 1] == y[j - 1] {
                d[(i - 1) * cols + j - 1] + w[x[i - 1]]
            } else {
                f64::MIN
            };
            let v = diag
                .max(d[(i - 1) * cols + j] - gap)
                .max(d[i * cols + j - 1] - gap)
                .max(0.0);
            d[i * cols + j] = v;
            if v > best + 1e-12 {
                best = v;
                at = (i, j);
            }
        }
    }
    if !trace {
        return (best, Vec::new());
    }
    let mut path = Vec::new();
    let (mut i, mut j) = at;
    while i > 0 && j > 0 && d[i * cols + j] > 1e-12 {
        let v = d[i * cols + j];
        if x[i - 1] == y[j - 1] && (v - d[(i - 1) * cols + j - 1] - w[x[i - 1]]).abs() < 1e-9 {
            path.push((i - 1, j - 1));
            i -= 1;
            j -= 1;
        } else if (v - (d[(i - 1) * cols + j] - gap)).abs() < 1e-9 {
            i -= 1;
        } else {
            j -= 1;
        }
    }
    path.reverse();
    (best, path)
}

/// Each of `a`'s host sequences aligned with `b`'s profile, and each of
/// `b`'s with `a`'s.
fn statistic(
    a: &[Vec<usize>],
    pa: &[usize],
    b: &[Vec<usize>],
    pb: &[usize],
    w: &[f64],
    gap: f64,
) -> f64 {
    let one = |hosts: &[Vec<usize>], p: &[usize]| -> f64 {
        hosts.iter().map(|h| align(h, p, w, gap, false).0).sum()
    };
    one(a, pb) + one(b, pa)
}

/// Whether classes in order follow `order` (each step taking a class at or
/// after the last one's place), so a public order explains them.
fn follows(classes: &[&BTreeSet<String>], order: &[String]) -> bool {
    let rank: BTreeMap<&str, usize> = order
        .iter()
        .enumerate()
        .map(|(i, c)| (c.as_str(), i))
        .collect();
    let mut at = 0;
    for cs in classes {
        let Some(r) = cs
            .iter()
            .filter_map(|c| rank.get(c.as_str()).copied())
            .filter(|&r| r >= at)
            .min()
        else {
            return false;
        };
        at = r;
    }
    true
}

/// Pairs of clusters above noise whose playbooks align beyond chance, most
/// unlikely first, and the family's multiplicity budget. `max_shared` is
/// `soft_links.max_shared`.
pub(crate) fn playbook_pairs(
    clusters: &[Cluster],
    results: &[ObsResult],
    max_shared: usize,
    opts: &PlaybookOptions,
) -> (Vec<PlaybookPair>, TestFamily) {
    let family = "playbook";
    let shown: Vec<&Cluster> = clusters.iter().filter(|c| c.tier > Tier::Noise).collect();
    if shown.len() < 3 {
        return (Vec::new(), TestFamily::cut(family, &[], 0, opts.fdr));
    }
    // Step ids and their classes.
    let mut ids: BTreeMap<String, usize> = BTreeMap::new();
    let mut classes: Vec<BTreeSet<String>> = Vec::new();
    let mut keys: Vec<String> = Vec::new();
    let mut intern = |k: String, cs: BTreeSet<String>| -> usize {
        if let Some(&i) = ids.get(&k) {
            return i;
        }
        let i = keys.len();
        ids.insert(k.clone(), i);
        keys.push(k);
        classes.push(cs);
        i
    };
    let mut books: Vec<Book> = Vec::new();
    let mut holders: BTreeMap<usize, BTreeSet<usize>> = BTreeMap::new();
    let mut comparable = 0;
    for (ci, c) in shown.iter().enumerate() {
        let mut by_host: BTreeMap<&str, Vec<(i64, &str, usize)>> = BTreeMap::new();
        let mut any = false;
        for &m in &c.members {
            let r = &results[m];
            let Some((k, cs)) = step(r, opts.min_specificity) else {
                continue;
            };
            let s = intern(k, cs);
            any = true;
            holders.entry(s).or_default().insert(ci);
            let Some(h) = r.target_host.as_deref() else {
                continue;
            };
            if r.obs.ts > 0 && crate::timing::request_like(r.obs.ts_kind) {
                by_host
                    .entry(h)
                    .or_default()
                    .push((r.obs.ts, r.obs.id.as_str(), s));
            }
        }
        comparable += usize::from(any);
        let mut hosts: Vec<(i64, Vec<usize>)> = by_host
            .into_values()
            .map(|mut v| {
                crate::sort::by(&mut v, |p, q| p.0.cmp(&q.0).then(p.1.cmp(q.1)));
                let mut seq: Vec<usize> = v.iter().map(|x| x.2).collect();
                seq.dedup();
                seq.truncate(MAX_STEPS);
                (v[0].0, seq)
            })
            .collect();
        crate::sort::by_key(&mut hosts, |h| h.0);
        hosts.truncate(MAX_HOSTS);
        let hosts: Vec<Vec<usize>> = hosts.into_iter().map(|h| h.1).collect();
        let (profile, support) = profile(&hosts);
        books.push(Book {
            hosts,
            profile,
            support,
        });
    }
    // Records outside the clusters count as more holders, never as more
    // population, as for scaffolds.
    let mut inside = vec![false; results.len()];
    for c in &shown {
        for &m in &c.members {
            inside[m] = true;
        }
    }
    let mut outside: BTreeMap<usize, usize> = BTreeMap::new();
    for (i, r) in results.iter().enumerate() {
        if inside[i] || ids.is_empty() {
            continue;
        }
        if let Some((k, _)) = step(r, opts.min_specificity)
            && let Some(&s) = ids.get(&k)
        {
            *outside.entry(s).or_default() += 1;
        }
    }
    let out_of = |s: usize| outside.get(&s).copied().unwrap_or(0);
    let df = |s: usize| holders.get(&s).map_or(1, BTreeSet::len);
    let n = shown.len() as f64;
    let w: Vec<f64> = (0..keys.len())
        .map(|s| (1.0 + n / df(s) as f64).ln())
        .collect();
    let rate = |s: usize| -> f64 {
        ((df(s) - 1 + out_of(s)) as f64 / comparable.saturating_sub(1).max(1) as f64).min(1.0)
    };
    let usable = |s: usize| {
        let d = df(s);
        d >= 2 && d <= max_shared && d + out_of(s) <= opts.max_holders
    };
    let holds = |b: &Book| b.profile.len() >= opts.min_steps && b.support >= opts.min_hosts;
    // Candidates: two clusters holding a playbook whose profiles share a
    // usable step.
    let mut candidates: BTreeSet<(usize, usize)> = BTreeSet::new();
    for (&s, hs) in &holders {
        if !usable(s) {
            continue;
        }
        let with: Vec<usize> = hs
            .iter()
            .copied()
            .filter(|&c| holds(&books[c]) && books[c].profile.contains(&s))
            .collect();
        for (i, &x) in with.iter().enumerate() {
            for &y in &with[i + 1..] {
                candidates.insert((x, y));
            }
        }
    }
    let tested = candidates.len();
    let gap = opts.gap_penalty.max(0.0);
    let perms = opts.permutations.max(1);
    // Shuffles beating the real order past this many fail the order's
    // limit, and the rest are not read.
    let cap = ((opts.max_order_chance * (perms + 1) as f64).floor() as usize).max(1);
    let mut out = Vec::new();
    for (x, y) in candidates {
        let (bx, by) = (&books[x], &books[y]);
        let (_, path) = align(&bx.profile, &by.profile, &w, gap, true);
        if path.len() < opts.min_steps {
            continue;
        }
        let aligned: Vec<usize> = path.iter().map(|&(i, _)| bx.profile[i]).collect();
        let cls: Vec<&BTreeSet<String>> = aligned.iter().map(|&s| &classes[s]).collect();
        if opts.common_orders.iter().any(|o| follows(&cls, o)) {
            continue;
        }
        let observed = statistic(&bx.hosts, &bx.profile, &by.hosts, &by.profile, &w, gap);
        let mut rng = Mix(seed(&[&shown[x].key, &shown[y].key, family]));
        let (mut hx, mut hy) = (bx.hosts.clone(), by.hosts.clone());
        let mut beaten = 0;
        let mut read = 0;
        while read < perms && beaten < cap {
            hx.iter_mut().for_each(|h| rng.shuffle(h));
            hy.iter_mut().for_each(|h| rng.shuffle(h));
            let (px, _) = profile(&hx);
            let (py, _) = profile(&hy);
            if statistic(&hx, &px, &hy, &py, &w, gap) >= observed - 1e-9 {
                beaten += 1;
            }
            read += 1;
        }
        let order_chance = (beaten + 1) as f64 / (perms + 1) as f64;
        if order_chance > opts.max_order_chance {
            continue;
        }
        let shared: Vec<usize> = aligned.iter().copied().filter(|&s| usable(s)).collect();
        let Some(rarest) = shared
            .iter()
            .copied()
            .min_by(|&a, &b| rate(a).total_cmp(&rate(b)).then(df(a).cmp(&df(b))))
        else {
            continue;
        };
        let r = rate(rarest);
        let step_chance = sidak(r * r, aligned.len());
        let chance = product_chance(step_chance, order_chance);
        if chance > opts.max_chance {
            continue;
        }
        out.push(PlaybookPair {
            a: shown[x].id.clone(),
            b: shown[y].id.clone(),
            steps: aligned
                .iter()
                .take(SHOWN_STEPS)
                .map(|&s| keys[s].clone())
                .collect(),
            classes: cls
                .iter()
                .map(|cs| cs.iter().cloned().collect::<Vec<_>>().join("+"))
                .collect(),
            aligned: aligned.len(),
            support_a: bx.support,
            hosts_a: bx.hosts.len(),
            support_b: by.support,
            hosts_b: by.hosts.len(),
            score: observed,
            beaten,
            permutations: perms,
            order_chance,
            holders: df(rarest),
            clusters: comparable,
            outside: out_of(rarest),
            base_rate: r,
            step_chance,
            chance,
            tested,
            expected_pairs: chance * tested as f64,
        });
    }
    let ps: Vec<f64> = out.iter().map(|p| p.chance).collect();
    let fam = TestFamily::cut(family, &ps, tested, opts.fdr);
    out.retain(|p| fam.keeps(p.chance));
    crate::sort::by(&mut out, |p, q| {
        p.chance
            .total_cmp(&q.chance)
            .then(p.a.cmp(&q.a))
            .then(p.b.cmp(&q.b))
    });
    out.truncate(MAX_PAIRS);
    (out, fam)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyze::analyze;
    use crate::model::Observation;
    use crate::rules::Rules;

    const T0: i64 = 1_791_000_000;

    /// The four steps of one harness on host `h` of agent `c`, tagged
    /// `tag`: an injection, a traversal, a script and a command, each
    /// with the harness's step counter.
    fn steps(c: usize, h: usize, tag: &str) -> [String; 4] {
        let host = format!("h{h}.c{c}.example");
        [
            format!("https://{host}/api/v1/items?id=%27%20OR%201%3D1--&uqtag={tag}&stage=1"),
            format!(
                "https://{host}/download.php?file=..%2F..%2F..%2Fetc%2Fpasswd&uqtag={tag}&stage=2"
            ),
            format!(
                "https://{host}/search/all?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E&uqtag={tag}&stage=3"
            ),
            format!("https://{host}/tools/run?cmd=%3Bid&uqtag={tag}&stage=4"),
        ]
    }

    /// Agent `c` working four hosts, each through the steps in `order`
    /// (shuffled anew on each host when `None`), a day after the last.
    fn agent(c: usize, order: Option<&[usize]>, tag: &str) -> Vec<Observation> {
        let mut out = Vec::new();
        let mut t = T0 + c as i64 * 86_400;
        let mut mix = Mix(c as u64 + 7);
        for h in 0..4 {
            let s = steps(c, h, tag);
            let mut idx: Vec<usize> = (0..4).collect();
            match order {
                Some(o) => idx = o.to_vec(),
                None => mix.shuffle(&mut idx),
            }
            for k in idx {
                out.push(Observation {
                    id: format!("c{c}h{h}s{k}"),
                    ts: t,
                    url: s[k].clone(),
                    ..Default::default()
                });
                t += 45;
            }
            t += 600;
        }
        out
    }

    /// Unrelated background agents, each with a shape of its own.
    fn others(n: usize) -> Vec<Observation> {
        let mut out = Vec::new();
        for c in 0..n {
            for k in 0..3 {
                out.push(Observation {
                    id: format!("bg{c}r{k}"),
                    ts: T0 + 86_400 * 60 + c as i64 * 3_600 + k as i64 * 50,
                    url: format!(
                        "https://h{k}.o{c}.example/p{c}?name{c}=%3Cscript%3Ealert(1)%3C/script%3E&page=2&uqtag=bg{c}x{c}"
                    ),
                    ..Default::default()
                });
            }
        }
        out
    }

    fn tag(c: usize) -> String {
        format!("t{c}{c}x{c}q")
    }

    #[test]
    fn a_step_drops_linking_parameters_only() {
        let a = analyze(
            agent(0, Some(&[0, 1, 2, 3]), "ab12cd"),
            &Rules::default_rules(),
        );
        let b = analyze(
            agent(
                0,
                Some(&[0, 1, 2, 3]),
                "0b6c1f0e-1111-4c2a-9a55-3f2e1d0c9b8a",
            ),
            &Rules::default_rules(),
        );
        let (ka, ca) = step(&a.results[0], 3).unwrap();
        let (kb, _) = step(&b.results[0], 3).unwrap();
        // Another tag style is the same step; the harness's own counter stays.
        assert_eq!(ka, kb);
        assert!(!ka.contains("uqtag"), "{ka}");
        assert!(ka.contains("stage=n0"), "{ka}");
        assert!(!ka.contains("example"), "{ka}");
        assert_eq!(ca.into_iter().collect::<Vec<_>>(), ["sqli"]);
    }

    #[test]
    fn local_alignment_scores_matches_and_gaps() {
        let w = vec![1.0; 6];
        let (s, path) = align(&[0, 1, 2, 3], &[0, 1, 5, 2, 3], &w, 0.5, true);
        assert!((s - 3.5).abs() < 1e-12, "{s}");
        assert_eq!(path, [(0, 0), (1, 1), (2, 3), (3, 4)]);
        let (r, path) = align(&[0, 1, 2, 3], &[3, 2, 1, 0], &w, 0.5, true);
        assert!((r - 1.0).abs() < 1e-12);
        assert_eq!(path.len(), 1);
        assert_eq!(
            profile(&[vec![1, 2], vec![0, 1, 2], vec![1, 2]]),
            (vec![1, 2], 2)
        );
    }

    #[test]
    fn a_public_order_explains_classes_that_follow_it() {
        let set = |c: &str| BTreeSet::from([c.to_string()]);
        let (r, t, s, x) = (set(RECON), set("traversal"), set("sqli"), set("xss"));
        let order: Vec<String> = ["recon", "traversal", "sqli", "xss"]
            .map(String::from)
            .to_vec();
        assert!(follows(&[&r, &t, &t, &s, &x], &order));
        assert!(!follows(&[&t, &s, &t], &order));
        assert!(!follows(&[&x, &s], &order));
        assert!(!follows(&[&set("cmd")], &order));
    }

    /// Three agents of one operator in one order with fresh tags, three
    /// agents with the same steps in an order of their own on each host,
    /// and `n` others.
    fn fleet(n: usize, second: Option<&[usize]>) -> Vec<Observation> {
        let mut obs = Vec::new();
        for c in 0..3 {
            obs.extend(agent(c, Some(&[1, 0, 2, 3]), &tag(c)));
        }
        for c in 3..6 {
            obs.extend(agent(c, second, &tag(c)));
        }
        obs.extend(others(n));
        obs
    }

    #[test]
    fn one_order_across_agents_is_a_pair_and_shuffled_orders_are_not() {
        let a = analyze(fleet(30, None), &Rules::default_rules());
        let p = &a.playbook_pairs;
        let ids = |c: usize| a.results.iter().find(|r| r.obs.id == format!("c{c}h0s0"));
        let cl = |c: usize| a.clusters[ids(c).unwrap().cluster.unwrap()].id.clone();
        let fleet: BTreeSet<String> = (0..3).map(cl).collect();
        assert_eq!(p.len(), 3, "{p:?}");
        for x in p {
            assert!(fleet.contains(&x.a) && fleet.contains(&x.b), "{x:?}");
            assert_eq!((x.aligned, x.support_a, x.hosts_a), (4, 4, 4), "{x:?}");
            assert_eq!(x.beaten, 0, "{x:?}");
            assert!(x.order_chance <= 1.0 / 200.0 + 1e-12, "{x:?}");
            assert_eq!(x.classes, ["traversal", "sqli", "xss", "cmd"]);
            assert!(!x.detail().contains("example"), "{}", x.detail());
        }
        let f = a.multiplicity.iter().find(|f| f.family == "playbook");
        // A shuffled agent repeating one order on two hosts is compared too,
        // and does not pass.
        assert_eq!(f.map(|f| (f.kept, f.tested)), Some((3, 6)), "{f:?}");
        assert!(
            a.soft_links
                .iter()
                .any(|l| l.kind == crate::fleets::SoftLinkKind::Playbook),
            "{:?}",
            a.soft_links
        );
    }

    #[test]
    fn two_fleets_with_one_step_set_in_other_orders_stay_apart() {
        // The second fleet sends the same steps in the reverse order: the
        // two share every template, and only their own pairs align.
        let a = analyze(fleet(30, Some(&[3, 2, 0, 1])), &Rules::default_rules());
        let p = &a.playbook_pairs;
        assert_eq!(p.len(), 6, "{p:?}");
        let ids = |c: usize| {
            let r = a.results.iter().find(|r| r.obs.id == format!("c{c}h0s0"));
            a.clusters[r.unwrap().cluster.unwrap()].id.clone()
        };
        let side = |id: &str| (0..3).any(|c| ids(c) == id);
        for x in p {
            assert_eq!(side(&x.a), side(&x.b), "{x:?}");
        }
    }

    #[test]
    fn a_public_order_ties_none() {
        let mut rules = Rules::default_rules();
        rules.set.playbook.common_orders = vec![
            ["recon", "traversal", "sqli", "xss", "cmd"]
                .map(String::from)
                .to_vec(),
        ];
        let a = analyze(fleet(30, None), &rules);
        assert!(a.playbook_pairs.is_empty(), "{:?}", a.playbook_pairs);
    }

    #[test]
    fn a_step_on_too_many_senders_seeds_nothing() {
        let mut rules = Rules::default_rules();
        rules.set.playbook.max_holders = 5;
        let a = analyze(fleet(30, Some(&[1, 0, 2, 3])), &rules);
        assert!(a.playbook_pairs.is_empty(), "{:?}", a.playbook_pairs);
    }
}
