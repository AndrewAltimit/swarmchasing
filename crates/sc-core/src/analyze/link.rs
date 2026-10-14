//! Linking: which flagged records belong together, and the clusters'
//! numbers and stable keys.
//!
//! Records are joined by a shared linking feature (within a time window, and
//! only while the feature is not common), by close request or submit times
//! against the same target with a rule in common, and by a probe chain. Everything else about
//! a cluster is description ([`super::hints`]).

use super::hints::is_context_kind;
use super::{Cluster, CommonFeature, ObsResult};
use crate::chains::Chain;
use crate::model::LinkFeature;
use crate::rules::{Linking, Rules};
use crate::timing::request_like;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

/// What linking found.
pub(super) struct Links<'a> {
    /// Groups of two or more flagged records (indexes into the results).
    pub groups: Vec<Vec<usize>>,
    /// (record, feature) for every record a shared feature joined to another.
    pub joined: HashSet<(usize, &'a LinkFeature)>,
    /// Features shared too widely to link, by group.
    pub common: Vec<CommonFeature>,
    /// Probe chains, linked or not.
    pub chains: Vec<Chain>,
    /// What joined the records: every linking feature group, run of close
    /// requests on one host and request-timed chain that linked.
    pub ties: Vec<Tie>,
}

/// One reason flagged records were joined, with every record it joined.
/// The union of a cluster's ties is its link graph, which the seam review
/// reads ([`crate::seam`]).
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Tie {
    pub members: Vec<usize>,
    pub why: TieWhy,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum TieWhy {
    /// A shared linking feature.
    Feature(LinkFeature),
    /// Close requests on one target host, each within `linking.window_secs`
    /// of the last with a rule in common.
    Timing(String),
    /// A probe chain.
    Chain,
}

/// Link the `flagged` records among `results`.
pub(super) fn link<'a>(results: &'a [ObsResult], flagged: &[usize], rules: &Rules) -> Links<'a> {
    let cfg = &rules.set.linking;
    let mut dsu = Dsu((0..results.len()).collect());

    // A shared feature joins its carriers in groups: consecutive carriers at
    // most `feature_link_window_secs` apart. A group whose feature is common
    // (too many hosts, or too large a share of the records around it) does
    // not link and is reported instead.
    let mut carriers: HashMap<&LinkFeature, Vec<usize>> = HashMap::new();
    for &i in flagged {
        for f in &results[i].features {
            carriers.entry(f).or_default().push(i);
        }
    }
    let mut all_ts: Vec<i64> = results
        .iter()
        .map(|r| r.obs.ts)
        .filter(|&t| t > 0)
        .collect();
    crate::sort::sort(&mut all_ts);
    let mut joined = HashSet::new();
    let mut common = Vec::new();
    let mut ties = Vec::new();
    for (&f, idxs) in &carriers {
        if idxs.len() < 2 {
            continue;
        }
        for group in feature_groups(results, idxs, cfg.feature_link_window_secs) {
            if group.len() < 2 {
                continue;
            }
            if let Some(c) = common_feature(results, f, &group, cfg, &all_ts) {
                common.push(c);
                continue;
            }
            for w in group.windows(2) {
                dsu.union(w[0], w[1]);
            }
            joined.extend(group.iter().map(|&i| (i, f)));
            ties.push(Tie {
                members: group,
                why: TieWhy::Feature(f.clone()),
            });
        }
    }
    crate::sort::by(&mut common, |a, b| {
        a.start.cmp(&b.start).then(a.feature.cmp(&b.feature))
    });

    // Same target host, close in time, and sharing at least one rule that is
    // not a context kind (relay, cache buster, self-identification, header,
    // outcome): every relay user shares the relay rule, and a record placed
    // beside a cluster needs only that to join it. Only request-like times
    // count: two archive captures minutes apart say when a crawler saved
    // them, not that one client sent them together.
    let mut by_host: HashMap<&str, Vec<usize>> = HashMap::new();
    for &i in flagged {
        if let Some(h) = results[i].target_host.as_deref()
            && request_like(results[i].obs.ts_kind)
        {
            by_host.entry(h).or_default().push(i);
        }
    }
    for (host, idxs) in by_host.iter_mut() {
        crate::sort::by_key(idxs, |&i| results[i].obs.ts);
        // Each run of consecutive joined records is one tie.
        let mut run: Vec<usize> = Vec::new();
        for w in idxs.windows(2) {
            let (a, b) = (&results[w[0]], &results[w[1]]);
            let close = a.obs.ts > 0 && b.obs.ts > 0 && b.obs.ts - a.obs.ts <= cfg.window_secs;
            let shared = a
                .hits
                .iter()
                .filter(|h| !is_context_kind(h.kind))
                .any(|h| b.hits.iter().any(|g| g.rule_id == h.rule_id));
            if close && shared {
                dsu.union(w[0], w[1]);
                if run.is_empty() {
                    run.push(w[0]);
                }
                run.push(w[1]);
            } else if !run.is_empty() {
                ties.push(Tie {
                    members: std::mem::take(&mut run),
                    why: TieWhy::Timing(host.to_string()),
                });
            }
        }
        if !run.is_empty() {
            ties.push(Tie {
                members: run,
                why: TieWhy::Timing(host.to_string()),
            });
        }
    }

    // Flagged requests in one probe chain (variants of one request to the
    // same host and path, minutes apart) are one client working an endpoint,
    // even when different rules fired on each.
    // A chain hard-links its flagged records only when its gaps are request
    // or submit times; two archive captures minutes apart say when a crawler
    // saved two URLs, not that one client sent them in sequence (FM-5.4). A
    // capture-timed chain is still reported, as a hint.
    let chains = crate::chains::chains(results, &rules.set.chains);
    for ch in chains.iter().filter(|ch| ch.time_basis.is_request_like()) {
        let f: Vec<usize> = ch
            .members
            .iter()
            .copied()
            .filter(|&m| results[m].score > 0)
            .collect();
        for w in f.windows(2) {
            dsu.union(w[0], w[1]);
        }
        if f.len() > 1 {
            ties.push(Tie {
                members: f,
                why: TieWhy::Chain,
            });
        }
    }

    let mut groups: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
    for &i in flagged {
        groups.entry(dsu.find(i)).or_default().push(i);
    }
    Links {
        groups: groups.into_values().filter(|g| g.len() > 1).collect(),
        joined,
        common,
        chains,
        ties,
    }
}

/// The carriers of one feature in linking groups: in time order, a gap over
/// `window` seconds (when `window` is positive) starts a new group. Carriers
/// with no timestamp join the only timed group, or form their own.
fn feature_groups(results: &[ObsResult], idxs: &[usize], window: i64) -> Vec<Vec<usize>> {
    let (mut timed, untimed): (Vec<usize>, Vec<usize>) =
        idxs.iter().partition(|&&i| results[i].obs.ts > 0);
    crate::sort::by_key(&mut timed, |&i| (results[i].obs.ts, i));
    let mut groups: Vec<Vec<usize>> = Vec::new();
    for i in timed {
        let ts = results[i].obs.ts;
        match groups.last_mut() {
            Some(g) if window <= 0 || ts - results[g[g.len() - 1]].obs.ts <= window => g.push(i),
            _ => groups.push(vec![i]),
        }
    }
    if !untimed.is_empty() {
        match groups.as_mut_slice() {
            [only] => only.extend(untimed),
            _ => groups.push(untimed),
        }
    }
    groups
}

/// Whether one group of a feature's carriers is too common to link it: a
/// published tag, more than `feature_max_hosts` target hosts, or (when `feature_max_share`
/// is set and its time span holds at least `feature_share_min_records`
/// records) more than that share of the records in its span. `all_ts` is
/// every record's timestamp, sorted.
fn common_feature(
    results: &[ObsResult],
    f: &LinkFeature,
    group: &[usize],
    cfg: &Linking,
    all_ts: &[i64],
) -> Option<CommonFeature> {
    let hosts: BTreeSet<&str> = group
        .iter()
        .filter_map(|&i| results[i].target_host.as_deref())
        .collect();
    let ts = group.iter().map(|&i| results[i].obs.ts).filter(|&t| t > 0);
    let (start, end) = (ts.clone().min().unwrap_or(0), ts.max().unwrap_or(0));
    let records = group.len();
    let burned = crate::plant::burned_why(cfg, f.value());
    let published = burned.is_some();
    let reason = if let Some(why) = burned {
        why.to_string()
    } else if cfg.feature_max_hosts > 0 && hosts.len() > cfg.feature_max_hosts {
        format!(
            "on {} target hosts, more than linking.feature_max_hosts ({})",
            hosts.len(),
            cfg.feature_max_hosts
        )
    } else {
        let in_span =
            all_ts.partition_point(|&t| t <= end) - all_ts.partition_point(|&t| t < start);
        let share = records as f64 / in_span.max(1) as f64;
        if cfg.feature_max_share > 0.0
            && start > 0
            && in_span >= cfg.feature_share_min_records
            && share > cfg.feature_max_share
        {
            format!(
                "on {records} of the {in_span} records in its span ({:.0}%), more than linking.feature_max_share ({:.0}%)",
                share * 100.0,
                cfg.feature_max_share * 100.0
            )
        } else {
            return None;
        }
    };
    Some(CommonFeature {
        feature: f.clone(),
        records,
        hosts: hosts.len(),
        start,
        end,
        reason,
        published,
    })
}

/// Order clusters strongest first, number them `C1..`, give each its key,
/// and point every member record at its cluster.
pub(super) fn number(clusters: &mut [Cluster], results: &mut [ObsResult]) {
    crate::sort::by(clusters, |a, b| {
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

/// What a cluster's key is made from: the id of its earliest member that has
/// one (by timestamp, then id; untimed members last), or, when no member has
/// an id, the earliest timestamp and URL.
///
/// Earliest first, not smallest id first: anyone can submit a record to a
/// public scanner and retry until its id sorts low, but its timestamp is
/// when it was sent, so a record placed beside a cluster later cannot take
/// over its key.
fn key_seed(results: &[ObsResult], members: &[usize]) -> String {
    members
        .iter()
        .map(|&m| &results[m].obs)
        .filter(|o| !o.id.is_empty())
        .min_by_key(|o| (o.ts <= 0, o.ts, o.id.as_str()))
        .map(|o| o.id.clone())
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
