//! Co-group: three or more clusters sharing several features that few
//! others hold, beyond a degree-preserving null.
//!
//! The pairwise target and harness tests stop at a handful of clusters: a
//! host or template held by more than a few senders ties none, since a news
//! story sends many unrelated agents to one site and a framework gives many
//! operators one request shape. A fleet larger than that cap falls out with
//! them. This test reads the group instead of the pair. Each cluster above
//! noise holds **features** of two families:
//!
//! - **targets**: a rare host family (a host's last two labels), one
//!   feature per episode of activity on it (touches by clusters above noise
//!   no more than `window_secs` apart, request and submit times only), so a
//!   feature is one site in one stretch of hours. Hosts of one site are one
//!   feature: a story names one site, a list names many. Families with a
//!   record hitting a listed benchmark or practice target are left out.
//! - **harness**: a specific request template ([`crate::scaffold::template`])
//!   and a slotted prose template (as prompt echo reads prose). A feature
//!   whose records all carry another adds nothing to it and is left out (a
//!   prose value that only ever comes with one template), and prose
//!   templates carried by exactly the same clusters are one prompt, one
//!   feature: a copied prompt brings all its sentences at once.
//!
//! A feature carried by more than `max_holders` senders (clusters above
//! noise, and records outside them) ties none. The clusters and features of
//! one family form a 0/1 matrix, and a **group** is a set of at least
//! `min_clusters` clusters that all hold the same `min_features` features or
//! more: a biclique, closed so its clusters are exactly those holding all
//! its features. Groups are mined from each feature's holder set and each
//! pair of holder sets' overlap.
//!
//! A group's **score** sums, over its features, how unlikely it is that a
//! holder set of the feature's size, drawn from the clusters that could hold
//! it, contains the whole group: `-ln(C(N - k, h - k) / C(N, h))` for `k`
//! clusters, `h` holders and `N` clusters that could hold it (for a host
//! family, the clusters active within `window_secs` of its episode; for a
//! template, those holding any template; for prose, those writing any).
//!
//! **Null.** Swap randomisation (Gionis et al. 2007): two holdings `(a, f)`
//! and `(b, g)` become `(a, g)` and `(b, f)` when neither is held already,
//! so each cluster keeps its feature count and each feature its holder
//! count; swaps stay within one kind of feature, and a host feature only
//! moves to a cluster active in its hours. `swaps` matrices are drawn
//! (Besag and Clifford's parallel method: a chain run back from the
//! observed matrix, then each sample run forward from there, so the
//! observed matrix is exchangeable with them), the same groups are mined in
//! each, and a group's chance is `(ge + 1) / (swaps + 1)` for `ge` the
//! samples whose strongest group scores at least as high. Comparing with
//! the strongest group of each sample makes the chance familywise over
//! every group mined from the matrix, however many are found, so no
//! further correction is taken per group: a group is kept at `max_chance`
//! and under a Benjamini-Hochberg cut at false discovery rate `fdr` over
//! the matrices mined (one per family), each counted once at its strongest
//! group's chance.
//!
//! A news spike is many senders on one site: one feature, however many
//! clusters. A framework default is one or a few templates. A fleet repeats
//! one holder set across many features. Groups are soft links: they never
//! score, link or merge.

use crate::analyze::{Cluster, ObsResult};
use crate::chance::{Mix, TestFamily};
use crate::fleets::Family;
use crate::model::Tier;
use crate::timing::request_like;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap};

/// Co-group settings (`[biclique]` in the rules file).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct BicliqueOptions {
    /// Touches of one host family by clusters above noise more than this
    /// far apart are separate features; a cluster active within this of an
    /// episode could have held it.
    pub window_secs: i64,
    /// Clusters a group needs.
    pub min_clusters: usize,
    /// Features every cluster of a group must hold.
    pub min_features: usize,
    /// A feature carried by more senders than this (clusters above noise,
    /// and records outside them) ties none.
    pub max_holders: usize,
    /// Randomised matrices drawn for the null.
    pub swaps: usize,
    /// A group is kept when its familywise chance is at most this.
    pub max_chance: f64,
    /// Benjamini-Hochberg false discovery rate over the matrices mined.
    pub fdr: f64,
}

impl Default for BicliqueOptions {
    fn default() -> Self {
        Self {
            window_secs: 21_600,
            min_clusters: 3,
            min_features: 4,
            max_holders: 30,
            swaps: 999,
            max_chance: 0.01,
            fdr: 0.05,
        }
    }
}

/// Groups kept, strongest first.
const MAX_GROUPS: usize = 200;
/// Swap attempts per holding, for the chain back from the observed matrix
/// and for each sample.
const STEPS_PER_HOLDING: usize = 4;

/// Clusters sharing several rarely held features beyond a degree-preserving
/// null.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CoGroup {
    /// Cluster ids, in analysis order.
    pub clusters: Vec<String>,
    /// `targets` (host families in the same hours) or `harness` (request and
    /// prose templates).
    pub family: Family,
    /// Features every member holds, by kind.
    pub hosts: usize,
    pub templates: usize,
    pub prompts: usize,
    /// Clusters holding any feature of the family.
    pub population: usize,
    /// The group's score: the sum over its features of `-ln` the chance that
    /// a holder set of the feature's size contains the whole group.
    pub score: f64,
    /// Randomised matrices drawn, and those whose strongest group scored at
    /// least as high.
    pub swaps: usize,
    pub null_ge: usize,
    /// `(null_ge + 1) / (swaps + 1)`: familywise over every group mined
    /// from the matrix.
    pub chance: f64,
    /// Matrices mined (one per family with a group), and matrices whose
    /// strongest group would be this unlikely expected among them.
    pub tested: usize,
    pub expected: f64,
}

impl CoGroup {
    pub fn detail(&self) -> String {
        let mut parts = Vec::new();
        if self.hosts > 0 {
            parts.push(format!(
                "{} rare host families in the same hours",
                self.hosts
            ));
        }
        if self.templates > 0 {
            parts.push(format!("{} request templates", self.templates));
        }
        if self.prompts > 0 {
            parts.push(format!("{} prose templates", self.prompts));
        }
        format!(
            "{} clusters all hold {} that few others hold (of {} clusters; score {:.1}, beaten or matched by the strongest group in {} of {} degree-preserving randomised matrices, chance {:.1e} over every group mined; {:.2} expected over {} matrices mined): one operator may run them all",
            self.clusters.len(),
            parts.join(" and "),
            self.population,
            self.score,
            self.null_ge,
            self.swaps,
            self.chance,
            self.expected,
            self.tested
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Kind {
    Host,
    Template,
    Prompt,
}

/// One column of a family's matrix.
struct Feat {
    kind: Kind,
    /// Rows holding it, sorted.
    holders: Vec<usize>,
    /// Rows that could hold it (a host family: those active in its hours);
    /// `None` for every row with a feature of its kind.
    allowed: Option<Vec<bool>>,
    /// How many rows could hold it.
    population: usize,
}

/// One family's clusters (rows, by position among those above noise) and
/// features.
struct Matrix {
    family: Family,
    /// Row → position among the clusters above noise.
    clusters: Vec<usize>,
    feats: Vec<Feat>,
}

/// A group found in a matrix: rows and features, both sorted.
struct Found {
    rows: Vec<usize>,
    feats: Vec<usize>,
    score: f64,
}

/// Groups of clusters above noise sharing several rarely held features
/// beyond a degree-preserving null, strongest first, and the family's
/// multiplicity budget. `min_specificity` is `scaffold.min_specificity`;
/// `prose` gives the prose settings and published templates.
pub(crate) fn co_groups(
    clusters: &[Cluster],
    results: &[ObsResult],
    benchmarks: &crate::knowledge::KnownSet,
    min_specificity: usize,
    prose: &crate::prose::PromptEchoOptions,
    opts: &BicliqueOptions,
) -> (Vec<CoGroup>, TestFamily) {
    let shown: Vec<&Cluster> = clusters.iter().filter(|c| c.tier > Tier::Noise).collect();
    let empty = || (Vec::new(), TestFamily::cut("co_group", &[], 0, opts.fdr));
    if shown.len() < opts.min_clusters.max(2) {
        return empty();
    }
    let mut owner: Vec<Option<usize>> = vec![None; results.len()];
    for (ci, c) in shown.iter().enumerate() {
        for &m in &c.members {
            owner[m] = Some(ci);
        }
    }
    let matrices = [
        target_matrix(&shown, results, &owner, benchmarks, opts),
        harness_matrix(results, &owner, min_specificity, prose, opts),
    ];
    let lnf = ln_factorials(shown.len() + 1);
    let mut found: Vec<(usize, Found, usize)> = Vec::new();
    let mut mined = 0;
    for (mi, m) in matrices.iter().enumerate() {
        let holders: Vec<Vec<usize>> = m.feats.iter().map(|f| f.holders.clone()).collect();
        let groups = mine(m, &holders, opts, &lnf);
        if groups.is_empty() {
            continue;
        }
        mined += 1;
        let maxima = null_maxima(m, &shown, opts, &lnf);
        for g in groups {
            let ge = maxima.iter().filter(|&&s| s >= g.score - 1e-9).count();
            found.push((mi, g, ge));
        }
    }
    let swaps = opts.swaps;
    let chance_of = |ge: usize| (ge + 1) as f64 / (swaps + 1) as f64;
    let chances: Vec<(usize, f64)> = found
        .iter()
        .map(|(mi, _, ge)| (*mi, chance_of(*ge)))
        .collect();
    let (family, cut) = family_cut(&chances, mined, opts);
    let tested = family.tested;
    let kept = |p: f64| p <= opts.max_chance && cut.is_some_and(|c| p <= c);
    let mut out: Vec<CoGroup> = found
        .into_iter()
        .filter(|(_, _, ge)| kept(chance_of(*ge)))
        .map(|(mi, g, ge)| {
            let m = &matrices[mi];
            let count = |k: Kind| g.feats.iter().filter(|&&f| m.feats[f].kind == k).count();
            let mut ids: Vec<usize> = g.rows.iter().map(|&r| m.clusters[r]).collect();
            ids.sort_unstable();
            let chance = chance_of(ge);
            CoGroup {
                clusters: ids.iter().map(|&c| shown[c].id.clone()).collect(),
                family: m.family,
                hosts: count(Kind::Host),
                templates: count(Kind::Template),
                prompts: count(Kind::Prompt),
                population: m.clusters.len(),
                score: g.score,
                swaps,
                null_ge: ge,
                chance,
                tested,
                expected: chance * tested as f64,
            }
        })
        .collect();
    crate::sort::by(&mut out, |p, q| {
        p.chance
            .total_cmp(&q.chance)
            .then(q.score.total_cmp(&p.score))
            .then(p.clusters.cmp(&q.clusters))
    });
    out.truncate(MAX_GROUPS);
    (out, family)
}

/// The family's budget over the groups found, as `(matrix, chance)`, of
/// `mined` matrices, and the largest chance kept. Each chance is already
/// familywise over its matrix's groups (the strongest null group is the
/// yardstick), so the cut counts matrices, each once at its strongest
/// group's chance; a group is kept at or under both the cut and
/// `max_chance`.
fn family_cut(
    chances: &[(usize, f64)],
    mined: usize,
    opts: &BicliqueOptions,
) -> (TestFamily, Option<f64>) {
    let mut strongest: BTreeMap<usize, f64> = BTreeMap::new();
    for &(mi, p) in chances {
        let e = strongest.entry(mi).or_insert(p);
        *e = e.min(p);
    }
    let passed: Vec<f64> = strongest
        .values()
        .copied()
        .filter(|&p| p <= opts.max_chance)
        .collect();
    let mut family = TestFamily::cut("co_group", &passed, mined, opts.fdr);
    let cut = family.cut;
    let under = |p: f64| p <= opts.max_chance;
    family.passed = chances.iter().filter(|g| under(g.1)).count();
    family.kept = chances
        .iter()
        .filter(|g| under(g.1) && cut.is_some_and(|c| g.1 <= c))
        .count();
    (family, cut)
}

/// Rows and features from `(row key, feature key)` holdings: each row key
/// becomes a row, each feature a column.
fn columns<R: Ord + Copy>(holdings: &BTreeMap<R, BTreeSet<usize>>) -> (Vec<R>, BTreeMap<R, usize>) {
    let keys: Vec<R> = holdings.keys().copied().collect();
    let index = keys.iter().enumerate().map(|(i, &k)| (k, i)).collect();
    (keys, index)
}

/// Host families in episodes of activity, as features of the targets
/// family.
fn target_matrix(
    shown: &[&Cluster],
    results: &[ObsResult],
    owner: &[Option<usize>],
    benchmarks: &crate::knowledge::KnownSet,
    opts: &BicliqueOptions,
) -> Matrix {
    let window = opts.window_secs.max(0);
    let mut bench: BTreeSet<&str> = BTreeSet::new();
    let mut touches: BTreeMap<&str, Vec<(i64, usize)>> = BTreeMap::new();
    let mut outside: BTreeMap<&str, Vec<i64>> = BTreeMap::new();
    let mut active: Vec<Vec<i64>> = vec![Vec::new(); shown.len()];
    for (i, r) in results.iter().enumerate() {
        let Some(h) = r.target_host.as_deref() else {
            continue;
        };
        let fam = crate::knowledge::family(h);
        if crate::knowledge::hits_any(r, benchmarks) {
            bench.insert(fam);
        }
        if r.obs.ts <= 0 || !request_like(r.obs.ts_kind) {
            continue;
        }
        match owner[i] {
            Some(c) => {
                touches.entry(fam).or_default().push((r.obs.ts, c));
                active[c].push(r.obs.ts);
            }
            None => outside.entry(fam).or_default().push(r.obs.ts),
        }
    }
    for a in &mut active {
        a.sort_unstable();
    }
    for o in outside.values_mut() {
        o.sort_unstable();
    }
    // Each episode: its holders and span.
    let mut episodes: Vec<(BTreeSet<usize>, i64, i64)> = Vec::new();
    for (fam, mut t) in touches {
        if bench.contains(fam) {
            continue;
        }
        t.sort_unstable();
        let mut start = 0;
        for k in 1..=t.len() {
            if k == t.len() || t[k].0 - t[k - 1].0 > window {
                let (from, to) = (t[start].0, t[k - 1].0);
                let holders: BTreeSet<usize> = t[start..k].iter().map(|x| x.1).collect();
                let out = outside.get(fam).map_or(0, |o| {
                    o.partition_point(|&x| x <= to) - o.partition_point(|&x| x < from)
                });
                if holders.len() + out <= opts.max_holders {
                    episodes.push((holders, from, to));
                }
                start = k;
            }
        }
    }
    let mut by_cluster: BTreeMap<usize, BTreeSet<usize>> = BTreeMap::new();
    for (f, (holders, _, _)) in episodes.iter().enumerate() {
        for &c in holders {
            by_cluster.entry(c).or_default().insert(f);
        }
    }
    let (clusters, row) = columns(&by_cluster);
    let feats = episodes
        .into_iter()
        .map(|(holders, from, to)| {
            let allowed: Vec<bool> = clusters
                .iter()
                .map(|&c| {
                    let a = &active[c];
                    let i = a.partition_point(|&x| x < from - window);
                    a.get(i).is_some_and(|&x| x <= to + window)
                })
                .collect();
            Feat {
                kind: Kind::Host,
                holders: holders.iter().map(|c| row[c]).collect(),
                population: allowed.iter().filter(|&&x| x).count(),
                allowed: Some(allowed),
            }
        })
        .collect();
    Matrix {
        family: Family::Targets,
        clusters,
        feats,
    }
}

/// Specific request templates and slotted prose templates, as features of
/// the harness family.
fn harness_matrix(
    results: &[ObsResult],
    owner: &[Option<usize>],
    min_specificity: usize,
    prose: &crate::prose::PromptEchoOptions,
    opts: &BicliqueOptions,
) -> Matrix {
    let min_words = prose.min_words.max(2);
    let common: BTreeSet<String> = prose
        .common_templates
        .iter()
        .map(|t| {
            let t = t.replace("{site}", crate::prose::COMMON_SITE);
            crate::platform::text::slot_tokens(&t, &[crate::prose::COMMON_SITE]).join(" ")
        })
        .collect();
    // (kind, key) → records inside the clusters, records outside.
    let mut held: BTreeMap<(Kind, String), (BTreeSet<usize>, usize)> = BTreeMap::new();
    let mut outside: Vec<(Kind, String)> = Vec::new();
    for (i, r) in results.iter().enumerate() {
        let mut keys: Vec<(Kind, String)> = Vec::new();
        let t = crate::scaffold::template(r);
        if t.specificity >= min_specificity {
            keys.push((Kind::Template, t.key));
        }
        let values: Vec<String> = crate::prose::param_values(r)
            .into_iter()
            .filter(|v| crate::prose::is_prose(v))
            .collect();
        if !values.is_empty() {
            let words = crate::prose::host_words(r.target_host.as_deref());
            let ctx: Vec<&str> = words.iter().map(String::as_str).collect();
            for v in values {
                let tokens = crate::platform::text::slot_tokens(&v, &ctx);
                let key = tokens.join(" ");
                if tokens.len() >= min_words && !common.contains(&key) {
                    keys.push((Kind::Prompt, key));
                }
            }
        }
        match owner[i] {
            Some(_) => {
                for k in keys {
                    held.entry(k).or_default().0.insert(i);
                }
            }
            None => outside.extend(keys),
        }
    }
    for k in outside {
        if let Some(e) = held.get_mut(&k) {
            e.1 += 1;
        }
    }
    let clusters_of = |records: &BTreeSet<usize>| -> BTreeSet<usize> {
        records.iter().filter_map(|&i| owner[i]).collect()
    };
    let usable: Vec<(Kind, BTreeSet<usize>)> = held
        .into_iter()
        .filter(|(_, (records, o))| clusters_of(records).len() + o <= opts.max_holders)
        .map(|((kind, _), (records, _))| (kind, records))
        .collect();
    // A feature every record of which carries another adds nothing to it
    // (a prose value that only ever comes with one request template): it is
    // left out, the first of identical ones kept.
    let mut by_record: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
    for (f, (_, records)) in usable.iter().enumerate() {
        for &i in records {
            by_record.entry(i).or_default().push(f);
        }
    }
    let implied = |f: usize| {
        let records = &usable[f].1;
        let Some(first) = records.iter().next() else {
            return true;
        };
        by_record[first].iter().any(|&g| {
            g != f
                && records.is_subset(&usable[g].1)
                && (records.len() < usable[g].1.len() || g < f)
        })
    };
    // Prose templates carried by exactly the same clusters are one prompt,
    // one feature: a prompt copied from a published list brings all its
    // sentences at once.
    let mut prompts: BTreeSet<BTreeSet<usize>> = BTreeSet::new();
    let kept: Vec<(Kind, BTreeSet<usize>)> = (0..usable.len())
        .filter(|&f| !implied(f))
        .map(|f| (usable[f].0, clusters_of(&usable[f].1)))
        .filter(|(kind, cs)| *kind != Kind::Prompt || prompts.insert(cs.clone()))
        .collect();
    let mut by_cluster: BTreeMap<usize, BTreeSet<usize>> = BTreeMap::new();
    for (f, (_, holders)) in kept.iter().enumerate() {
        for &c in holders {
            by_cluster.entry(c).or_default().insert(f);
        }
    }
    let (clusters, row) = columns(&by_cluster);
    // The clusters that could hold a template, or prose: those holding one.
    let mut per_kind: BTreeMap<Kind, BTreeSet<usize>> = BTreeMap::new();
    for (kind, holders) in &kept {
        per_kind.entry(*kind).or_default().extend(holders);
    }
    let feats = kept
        .iter()
        .map(|(kind, holders)| Feat {
            kind: *kind,
            holders: holders.iter().map(|c| row[c]).collect(),
            allowed: None,
            population: per_kind[kind].len(),
        })
        .collect();
    Matrix {
        family: Family::Harness,
        clusters,
        feats,
    }
}

/// `ln(n!)` for `n` up to `max`.
fn ln_factorials(max: usize) -> Vec<f64> {
    let mut out = vec![0.0; max + 1];
    for n in 2..=max {
        out[n] = out[n - 1] + (n as f64).ln();
    }
    out
}

/// `-ln` of the chance that a random `h`-subset of `n` contains a given
/// `k`-subset: `ln C(n, h) - ln C(n - k, h - k)`.
fn surprise(n: usize, h: usize, k: usize, lnf: &[f64]) -> f64 {
    if k > h || h > n || n >= lnf.len() {
        return 0.0;
    }
    let ln_choose = |a: usize, b: usize| lnf[a] - lnf[b] - lnf[a - b];
    (ln_choose(n, h) - ln_choose(n - k, h - k)).max(0.0)
}

/// Whether sorted `small` is a subset of sorted `big`.
fn subset(small: &[usize], big: &[usize]) -> bool {
    let mut j = 0;
    for &x in small {
        while j < big.len() && big[j] < x {
            j += 1;
        }
        if j == big.len() || big[j] != x {
            return false;
        }
        j += 1;
    }
    true
}

fn intersect(a: &[usize], b: &[usize]) -> Vec<usize> {
    let (mut i, mut j, mut out) = (0, 0, Vec::new());
    while i < a.len() && j < b.len() {
        match a[i].cmp(&b[j]) {
            std::cmp::Ordering::Less => i += 1,
            std::cmp::Ordering::Greater => j += 1,
            std::cmp::Ordering::Equal => {
                out.push(a[i]);
                i += 1;
                j += 1;
            }
        }
    }
    out
}

/// The closed groups of matrix `m` with feature holders `holders`: seeded
/// from each feature's holder set and each pair of holder sets' overlap of
/// at least `min_clusters` rows, each grown to every feature its rows all
/// hold and shrunk to the rows holding all of those.
fn mine(m: &Matrix, holders: &[Vec<usize>], opts: &BicliqueOptions, lnf: &[f64]) -> Vec<Found> {
    let min_k = opts.min_clusters.max(2);
    let min_f = opts.min_features.max(1);
    let eligible: Vec<usize> = (0..holders.len())
        .filter(|&f| holders[f].len() >= min_k)
        .collect();
    if eligible.len() < min_f {
        return Vec::new();
    }
    let mut by_row: Vec<Vec<usize>> = vec![Vec::new(); m.clusters.len()];
    for &f in &eligible {
        for &r in &holders[f] {
            by_row[r].push(f);
        }
    }
    let mut seeds: BTreeSet<Vec<usize>> = eligible.iter().map(|&f| holders[f].clone()).collect();
    let mut pairs: HashMap<(usize, usize), usize> = HashMap::new();
    for fs in &by_row {
        for (i, &f) in fs.iter().enumerate() {
            for &g in &fs[i + 1..] {
                *pairs.entry((f, g)).or_default() += 1;
            }
        }
    }
    for ((f, g), n) in pairs {
        if n >= min_k {
            seeds.insert(intersect(&holders[f], &holders[g]));
        }
    }
    let mut closed: BTreeMap<Vec<usize>, Vec<usize>> = BTreeMap::new();
    for g in seeds {
        let Some(&least) = g.iter().min_by_key(|&&r| by_row[r].len()) else {
            continue;
        };
        let feats: Vec<usize> = by_row[least]
            .iter()
            .copied()
            .filter(|&f| subset(&g, &holders[f]))
            .collect();
        if feats.len() < min_f {
            continue;
        }
        let mut rows = holders[feats[0]].clone();
        for &f in &feats[1..] {
            rows = intersect(&rows, &holders[f]);
        }
        closed.entry(rows).or_insert(feats);
    }
    closed
        .into_iter()
        .map(|(rows, feats)| {
            let k = rows.len();
            let score = feats
                .iter()
                .map(|&f| surprise(m.feats[f].population, holders[f].len(), k, lnf))
                .sum();
            Found { rows, feats, score }
        })
        .collect()
}

/// The holdings of a matrix, for swapping: per kind of feature, every
/// `(row, feature)`, and each row's features.
#[derive(Clone)]
struct State {
    edges: Vec<Vec<(usize, usize)>>,
    by_row: Vec<Vec<usize>>,
}

impl State {
    fn new(m: &Matrix) -> Self {
        let mut kinds: BTreeMap<Kind, Vec<(usize, usize)>> = BTreeMap::new();
        let mut by_row = vec![Vec::new(); m.clusters.len()];
        for (f, feat) in m.feats.iter().enumerate() {
            for &r in &feat.holders {
                kinds.entry(feat.kind).or_default().push((r, f));
                by_row[r].push(f);
            }
        }
        Self {
            edges: kinds.into_values().collect(),
            by_row,
        }
    }

    /// `STEPS_PER_HOLDING` swap attempts per holding.
    fn run(&mut self, m: &Matrix, mix: &mut Mix) {
        let allowed = |f: usize, r: usize| m.feats[f].allowed.as_ref().is_none_or(|a| a[r]);
        for edges in &mut self.edges {
            let n = edges.len();
            if n < 2 {
                continue;
            }
            for _ in 0..n * STEPS_PER_HOLDING {
                let i = (mix.next() % n as u64) as usize;
                let j = (mix.next() % n as u64) as usize;
                let ((r1, f1), (r2, f2)) = (edges[i], edges[j]);
                if r1 == r2
                    || f1 == f2
                    || self.by_row[r1].contains(&f2)
                    || self.by_row[r2].contains(&f1)
                    || !allowed(f2, r1)
                    || !allowed(f1, r2)
                {
                    continue;
                }
                edges[i] = (r1, f2);
                edges[j] = (r2, f1);
                for (r, from, to) in [(r1, f1, f2), (r2, f2, f1)] {
                    if let Some(x) = self.by_row[r].iter_mut().find(|x| **x == from) {
                        *x = to;
                    }
                }
            }
        }
    }

    fn holders(&self, feats: usize) -> Vec<Vec<usize>> {
        let mut out = vec![Vec::new(); feats];
        for (r, fs) in self.by_row.iter().enumerate() {
            for &f in fs {
                out[f].push(r);
            }
        }
        out
    }
}

/// The strongest group's score in each of `swaps` randomised matrices (0
/// when one has none).
fn null_maxima(m: &Matrix, shown: &[&Cluster], opts: &BicliqueOptions, lnf: &[f64]) -> Vec<f64> {
    let mut parts: Vec<&str> = vec!["co_group", m.family.label()];
    parts.extend(m.clusters.iter().map(|&c| shown[c].id.as_str()));
    let mut mix = Mix(crate::chance::seed(&parts));
    let mut start = State::new(m);
    start.run(m, &mut mix);
    (0..opts.swaps)
        .map(|_| {
            let mut s = start.clone();
            s.run(m, &mut mix);
            let holders = s.holders(m.feats.len());
            mine(m, &holders, opts, lnf)
                .iter()
                .map(|g| g.score)
                .fold(0.0, f64::max)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyze::analyze;
    use crate::model::Observation;
    use crate::rules::Rules;

    fn o(id: &str, ts: i64, url: &str) -> Observation {
        Observation {
            id: id.into(),
            ts,
            url: url.into(),
            ..Default::default()
        }
    }

    const T0: i64 = 1_791_000_000;

    /// `agents` clusters (one inbox each) probing one host in each of
    /// `sites` sites, each starting 22 minutes after the last, in its own
    /// order; and `others` clusters probing sites of their own over two
    /// days.
    fn records(agents: usize, sites: usize, others: usize) -> Vec<Observation> {
        let inbox = |n: usize| format!("{n:08x}-1111-4c2a-9a55-3f2e1d0c9b8a");
        let mut obs = Vec::new();
        for a in 0..agents {
            for k in 0..sites {
                let t = T0 + a as i64 * 1300 + ((k + a) % sites) as i64 * 120;
                obs.push(o(
                    &format!("a{a}-{k}"),
                    t,
                    &format!(
                        "https://www.site{k}-list.example/q?id=1%27%20OR%201=1--&hook=https://webhook.site/{}",
                        inbox(a)
                    ),
                ));
            }
        }
        for b in 0..others {
            for k in 0..4 {
                obs.push(o(
                    &format!("b{b}-{k}"),
                    T0 - 86_400 + b as i64 * 4000 + k * 200,
                    &format!(
                        "https://h{k}.own{b}.example/q?id=1%27%20OR%201=1--&hook=https://webhook.site/{}",
                        inbox(1000 + b)
                    ),
                ));
            }
        }
        obs
    }

    #[test]
    fn a_large_list_fleet_is_one_group_and_pairs_cannot_hold_it() {
        let a = analyze(records(8, 6, 40), &Rules::default_rules());
        assert_eq!(a.clusters.len(), 48, "{}", a.clusters.len());
        // Eight holders per site: past every pairwise cap.
        assert!(a.cotarget_pairs.is_empty(), "{:?}", a.cotarget_pairs);
        assert_eq!(a.co_groups.len(), 1, "{:?}", a.co_groups);
        let g = &a.co_groups[0];
        assert_eq!(
            (g.clusters.len(), g.hosts, g.family),
            (8, 6, Family::Targets)
        );
        assert!(g.chance <= 0.01, "{}", g.detail());
        assert!(!g.detail().contains("example"), "{}", g.detail());
        let links = a
            .soft_links
            .iter()
            .filter(|l| l.kind == crate::fleets::SoftLinkKind::CoGroup)
            .count();
        assert_eq!(links, 28);
        let f = a.multiplicity.iter().find(|f| f.family == "co_group");
        assert_eq!(f.map(|f| f.kept), Some(1), "{f:?}");
        assert!(
            a.candidate_fleets.iter().any(|f| f.clusters.len() == 8),
            "{:?}",
            a.candidate_fleets
        );
    }

    #[test]
    fn many_senders_on_one_site_or_few_sites_are_no_group() {
        // A story: twelve agents on six hosts of one site.
        let mut one_site = records(12, 6, 40);
        for x in one_site.iter_mut().filter(|x| x.id.starts_with('a')) {
            x.url = x
                .url
                .replace("www.site", "www.s")
                .replace("-list.example", ".news.example");
        }
        let a = analyze(one_site, &Rules::default_rules());
        assert!(a.co_groups.is_empty(), "{:?}", a.co_groups);
        // Three sites in common are fewer than `min_features`.
        let b = analyze(records(8, 3, 40), &Rules::default_rules());
        assert!(b.co_groups.is_empty(), "{:?}", b.co_groups);
    }

    #[test]
    fn a_listed_benchmark_ties_no_group() {
        let mut obs = records(8, 6, 40);
        for x in obs.iter_mut() {
            x.url = x
                .url
                .replace("www.site0-list.example", "testphp.vulnweb.com")
                .replace("www.site1-list.example", "testasp.vulnweb.com");
        }
        let a = analyze(obs, &Rules::default_rules());
        // Two sites left out as one benchmark family: four remain, at the
        // floor.
        assert_eq!(a.co_groups.len(), 1, "{:?}", a.co_groups);
        assert_eq!(a.co_groups[0].hosts, 4);
    }

    #[test]
    fn swaps_keep_every_margin_and_respect_the_hours() {
        // Three rows, three features; feature 2 may not go to row 0.
        let m = Matrix {
            family: Family::Targets,
            clusters: vec![0, 1, 2],
            feats: vec![
                Feat {
                    kind: Kind::Host,
                    holders: vec![0, 1],
                    allowed: None,
                    population: 3,
                },
                Feat {
                    kind: Kind::Host,
                    holders: vec![0],
                    allowed: None,
                    population: 3,
                },
                Feat {
                    kind: Kind::Host,
                    holders: vec![2],
                    allowed: Some(vec![false, true, true]),
                    population: 2,
                },
            ],
        };
        let mut mix = Mix(5);
        let mut s = State::new(&m);
        let mut seen = BTreeSet::new();
        for _ in 0..200 {
            s.run(&m, &mut mix);
            let h = s.holders(3);
            assert_eq!(h.iter().map(Vec::len).collect::<Vec<_>>(), [2, 1, 1]);
            let mut deg = [0; 3];
            for f in &h {
                for &r in f {
                    deg[r] += 1;
                }
            }
            assert_eq!(deg, [2, 1, 1]);
            assert!(!h[2].contains(&0));
            seen.insert(h);
        }
        assert!(seen.len() > 1, "{seen:?}");
    }

    #[test]
    fn strong_groups_among_many_found_are_kept() {
        // Two groups no randomised matrix matched, at the null's floor,
        // among forty found in one matrix: their chance is familywise
        // already, so the thirty-eight weak ones do not dilute them.
        let opts = BicliqueOptions {
            swaps: 199,
            ..BicliqueOptions::default()
        };
        let floor = 1.0 / 200.0;
        let mut chances = vec![(0, floor), (0, floor)];
        chances.extend((0..38).map(|_| (0, 0.5)));
        let (family, cut) = family_cut(&chances, 1, &opts);
        assert!(cut.is_some_and(|c| floor <= c), "{family:?}");
        assert_eq!((family.tested, family.passed, family.kept), (1, 2, 2));
        // A matrix whose strongest group is common keeps nothing.
        let (family, cut) = family_cut(&[(0, 0.2), (1, 0.3)], 2, &opts);
        assert_eq!((cut, family.kept), (None, 0));
    }

    #[test]
    fn surprise_is_the_chance_a_holder_set_covers_the_group() {
        let lnf = ln_factorials(20);
        // 3 of 10 holding a feature: a given pair is inside with chance
        // C(8,1)/C(10,3) = 8/120.
        assert!((surprise(10, 3, 2, &lnf) - (120.0f64 / 8.0).ln()).abs() < 1e-9);
        assert_eq!(surprise(10, 10, 4, &lnf), 0.0);
        assert!(subset(&[1, 3], &[0, 1, 2, 3]) && !subset(&[1, 4], &[1, 3]));
        assert_eq!(intersect(&[1, 2, 5, 7], &[2, 3, 7]), [2, 7]);
    }
}
