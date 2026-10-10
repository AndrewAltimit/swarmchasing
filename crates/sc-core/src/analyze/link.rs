//! Linking: which flagged records belong together, and the clusters'
//! numbers and stable keys.
//!
//! Records are joined by a shared linking feature, by close timing against
//! the same target with a rule in common, and by a probe chain. Everything
//! else about a cluster is description ([`super::hints`]).

use super::{Cluster, ObsResult};
use crate::chains::Chain;
use crate::model::LinkFeature;
use crate::rules::Rules;
use std::collections::{BTreeMap, BTreeSet, HashMap};

/// What linking found.
pub(super) struct Links<'a> {
    /// Groups of two or more flagged records (indexes into the results).
    pub groups: Vec<Vec<usize>>,
    /// How many flagged records carry each feature.
    pub feature_count: HashMap<&'a LinkFeature, usize>,
    /// Probe chains, linked or not.
    pub chains: Vec<Chain>,
}

/// Link the `flagged` records among `results`.
pub(super) fn link<'a>(results: &'a [ObsResult], flagged: &[usize], rules: &Rules) -> Links<'a> {
    let cfg = &rules.set.linking;
    let mut dsu = Dsu((0..results.len()).collect());

    let mut by_feature: HashMap<&LinkFeature, usize> = HashMap::new();
    let mut feature_count: HashMap<&LinkFeature, usize> = HashMap::new();
    for &i in flagged {
        for f in &results[i].features {
            *feature_count.entry(f).or_default() += 1;
            match by_feature.get(f) {
                Some(&j) => dsu.union(i, j),
                None => {
                    by_feature.insert(f, i);
                }
            }
        }
    }

    // Same target host, close in time, and sharing at least one rule.
    let mut by_host: HashMap<&str, Vec<usize>> = HashMap::new();
    for &i in flagged {
        if let Some(h) = results[i].target_host.as_deref() {
            by_host.entry(h).or_default().push(i);
        }
    }
    for idxs in by_host.values_mut() {
        idxs.sort_by_key(|&i| results[i].obs.ts);
        for w in idxs.windows(2) {
            let (a, b) = (&results[w[0]], &results[w[1]]);
            let close = a.obs.ts > 0 && b.obs.ts > 0 && b.obs.ts - a.obs.ts <= cfg.window_secs;
            let shared = a
                .hits
                .iter()
                .any(|h| b.hits.iter().any(|g| g.rule_id == h.rule_id));
            if close && shared {
                dsu.union(w[0], w[1]);
            }
        }
    }

    // Flagged requests in one probe chain (variants of one request to the
    // same host and path, minutes apart) are one client working an endpoint,
    // even when different rules fired on each.
    let chains = crate::chains::chains(results);
    for ch in &chains {
        let f: Vec<usize> = ch
            .members
            .iter()
            .copied()
            .filter(|&m| results[m].score > 0)
            .collect();
        for w in f.windows(2) {
            dsu.union(w[0], w[1]);
        }
    }

    let mut groups: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
    for &i in flagged {
        groups.entry(dsu.find(i)).or_default().push(i);
    }
    Links {
        groups: groups.into_values().filter(|g| g.len() > 1).collect(),
        feature_count,
        chains,
    }
}

/// Order clusters strongest first, number them `C1..`, give each its key,
/// and point every member record at its cluster.
pub(super) fn number(clusters: &mut [Cluster], results: &mut [ObsResult]) {
    clusters.sort_by(|a, b| {
        b.tier
            .cmp(&a.tier)
            .then(b.members.len().cmp(&a.members.len()))
            .then(a.start.cmp(&b.start))
    });
    let mut keys = BTreeSet::new();
    for (ci, c) in clusters.iter_mut().enumerate() {
        c.id = format!("C{}", ci + 1);
        // Records that share an id can seed two clusters alike.
        let base = cluster_key(&key_seed(results, &c.members));
        c.key = base.clone();
        let mut n = 1;
        while !keys.insert(c.key.clone()) {
            n += 1;
            c.key = format!("{base}-{n}");
        }
        for &m in &c.members {
            results[m].cluster = Some(ci);
        }
    }
}

/// `k-` and the first 8 hex digits of the SHA-256 of `seed`.
pub(super) fn cluster_key(seed: &str) -> String {
    use sha2::{Digest, Sha256};
    let d = Sha256::digest(seed.as_bytes());
    let hex: String = d.iter().take(4).map(|b| format!("{b:02x}")).collect();
    format!("k-{hex}")
}

/// What a cluster's key is made from: the smallest non-empty member record
/// id, or, when no member has an id, the earliest timestamp and URL.
fn key_seed(results: &[ObsResult], members: &[usize]) -> String {
    members
        .iter()
        .map(|&m| results[m].obs.id.as_str())
        .filter(|id| !id.is_empty())
        .min()
        .map(str::to_string)
        .unwrap_or_else(|| {
            members
                .iter()
                .map(|&m| (results[m].obs.ts, results[m].obs.url.as_str()))
                .min()
                .map(|(ts, url)| format!("{ts}\n{url}"))
                .unwrap_or_default()
        })
}

pub(super) struct Dsu(pub(super) Vec<usize>);
impl Dsu {
    /// The set's root, compressing the path on the way. Iterative: a long
    /// chain must not exhaust the stack (the browser's is small).
    pub(super) fn find(&mut self, x: usize) -> usize {
        let mut root = x;
        while self.0[root] != root {
            root = self.0[root];
        }
        let mut x = x;
        while self.0[x] != root {
            let next = self.0[x];
            self.0[x] = root;
            x = next;
        }
        root
    }
    pub(super) fn union(&mut self, a: usize, b: usize) {
        let (a, b) = (self.find(a), self.find(b));
        if a != b {
            self.0[a.max(b)] = a.min(b);
        }
    }
}
