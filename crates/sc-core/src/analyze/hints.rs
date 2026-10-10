//! What a cluster looks like: its tier, timing and the descriptive hints
//! (encoding, paths, payload dialect, fan-out, cut lengths) assembled over
//! its members. Hints are shown in reports; none changes a score or a link.

use super::{Cluster, ObsResult};
use crate::fanout::FanRequest;
use crate::model::{IndicatorKind, LinkFeature, Tactic, Tier};
use crate::paths::PathStats;
use crate::rules::Rules;
use crate::timing::{Span, parse_date_tag, stale_dates, timing};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

/// Unflagged requests by target host: the context path hints read around a
/// cluster (a recon opening is rarely flagged itself).
pub(super) fn unflagged_by_host(results: &[ObsResult]) -> HashMap<&str, Vec<usize>> {
    let mut unflagged_by_host: HashMap<&str, Vec<usize>> = HashMap::new();
    for (i, r) in results.iter().enumerate() {
        if r.score == 0
            && r.obs.ts > 0
            && let Some(h) = r.target_host.as_deref()
        {
            unflagged_by_host.entry(h).or_default().push(i);
        }
    }
    unflagged_by_host
}

/// One cluster of `members` (indexes into `results`), not yet numbered.
pub(super) fn cluster(
    results: &[ObsResult],
    mut members: Vec<usize>,
    joined: &HashSet<(usize, &LinkFeature)>,
    unflagged_by_host: &HashMap<&str, Vec<usize>>,
    rules: &Rules,
) -> Cluster {
    let cfg = &rules.set.linking;
    members.sort_by_key(|&i| results[i].obs.ts);
    let mut rules_seen: BTreeMap<String, usize> = BTreeMap::new();
    let mut kinds: BTreeMap<IndicatorKind, usize> = BTreeMap::new();
    let mut tactics: BTreeMap<Tactic, usize> = BTreeMap::new();
    let mut artifacts = 0;
    let mut hosts: BTreeMap<String, usize> = BTreeMap::new();
    let mut asns: BTreeMap<u32, usize> = BTreeMap::new();
    let mut uas: BTreeMap<String, usize> = BTreeMap::new();
    let mut encodings: BTreeMap<String, usize> = BTreeMap::new();
    let mut feats: BTreeMap<&LinkFeature, usize> = BTreeMap::new();
    for &i in &members {
        let r = &results[i];
        for h in &r.hits {
            *rules_seen.entry(h.rule_id.clone()).or_default() += 1;
            *kinds.entry(h.kind).or_default() += 1;
            if let Some(t) = h.tactic {
                *tactics.entry(t).or_default() += 1;
            }
        }
        if r.hits.iter().any(|h| h.artifact) {
            artifacts += 1;
        }
        if let Some(h) = &r.target_host {
            *hosts.entry(h.clone()).or_default() += 1;
        }
        if let Some(a) = r.obs.asn {
            *asns.entry(a).or_default() += 1;
        }
        if let Some(u) = &r.obs.user_agent {
            *uas.entry(u.clone()).or_default() += 1;
        }
        let enc = crate::fingerprint::encoding(&r.obs.url);
        if enc.informative() {
            *encodings.entry(enc.style).or_default() += 1;
        }
        for f in r.features.iter().filter(|f| joined.contains(&(i, *f))) {
            *feats.entry(f).or_default() += 1;
        }
    }
    let score: i32 = rules_seen
        .keys()
        .filter_map(|id| rules.rule(id))
        .map(|r| r.weight)
        .sum();
    let tier = cluster_tier(results, &members);
    let ts: Vec<i64> = members.iter().map(|&i| results[i].obs.ts).collect();
    let mut t = timing(&ts, cfg);
    t.stale_dates = stale_dates(
        &members
            .iter()
            .filter_map(|&i| {
                let r = &results[i];
                r.layers
                    .iter()
                    .flat_map(|l| l.params.iter())
                    .find_map(|(_, v)| parse_date_tag(v))
                    .map(|d| (r.obs.ts, d))
            })
            .filter(|&(ts, _)| ts > 0)
            .collect::<Vec<_>>(),
    );
    let runs = split_runs(&ts, cfg.run_gap_secs);
    let paths = path_stats(
        results,
        &members,
        unflagged_by_host,
        (t.start, t.end),
        cfg.window_secs,
        &rules.set.paths,
    );
    let dialect = crate::dialect::dialect(
        &members
            .iter()
            .map(|&i| payload_variants(&results[i]))
            .collect::<Vec<_>>(),
    );
    let fanout = crate::fanout::fanout(
        &members
            .iter()
            .map(|&i| {
                let r = &results[i];
                FanRequest {
                    ts: r.obs.ts,
                    host: r.target_host.clone(),
                    path: crate::paths::normalize_path(target_text(r)),
                }
            })
            .collect::<Vec<_>>(),
        &rules.set.fanout,
    );
    let cut_lengths = crate::dialect::cut_lengths(
        &members
            .iter()
            .map(|&i| {
                let r = &results[i];
                let fired = r
                    .hits
                    .iter()
                    .any(|h| h.rule_id == rules.set.cut_lengths.rule);
                (r.obs.url.as_str(), fired)
            })
            .collect::<Vec<_>>(),
        &rules.set.cut_lengths,
    );
    Cluster {
        id: String::new(),
        key: String::new(),
        start: t.start,
        end: t.end,
        members,
        tier,
        score,
        rules: rules_seen,
        kinds,
        tactics,
        artifacts,
        target_hosts: hosts,
        asns,
        user_agents: uas,
        encodings,
        paths,
        dialect,
        fanout,
        cut_lengths,
        link_features: feats
            .into_iter()
            .filter(|&(_, n)| n > 1)
            .map(|(f, _)| f.clone())
            .collect(),
        runs,
        timing: t,
    }
}

/// A cluster's tier: its strongest member's, raised one step (suggestive to
/// significant) only by corroboration: two suggestive-or-above members that
/// each carry an evidence kind the other lacks. Context kinds (relay, cache
/// buster, self-identification, header, outcome), which ordinary clients
/// produce too, do not count. Weak rules collected across many members never
/// add up to a higher tier.
pub(super) fn cluster_tier(results: &[ObsResult], members: &[usize]) -> Tier {
    let top = members
        .iter()
        .map(|&i| results[i].tier)
        .max()
        .unwrap_or_default();
    if top != Tier::Suggestive {
        return top;
    }
    let kind_sets: BTreeSet<BTreeSet<IndicatorKind>> = members
        .iter()
        .map(|&i| &results[i])
        .filter(|r| r.tier >= Tier::Suggestive)
        .map(|r| {
            r.hits
                .iter()
                .map(|h| h.kind)
                .filter(|&k| !is_context_kind(k))
                .collect()
        })
        .collect();
    let corroborated = kind_sets
        .iter()
        .any(|a| kind_sets.iter().any(|b| !a.is_subset(b) && !b.is_subset(a)));
    if corroborated { Tier::Significant } else { top }
}

/// Kinds that describe how a request was sent rather than what it did.
fn is_context_kind(k: IndicatorKind) -> bool {
    matches!(
        k,
        IndicatorKind::Relay
            | IndicatorKind::CacheBuster
            | IndicatorKind::SelfId
            | IndicatorKind::Header
            | IndicatorKind::Outcome
    )
}

pub(super) fn split_runs(ts: &[i64], gap: i64) -> Vec<Span> {
    let mut t: Vec<i64> = ts.iter().copied().filter(|&x| x > 0).collect();
    t.sort_unstable();
    let mut runs: Vec<Span> = Vec::new();
    for x in t {
        match runs.last_mut() {
            Some(r) if x - r.end <= gap => {
                r.end = x;
                r.count += 1;
            }
            _ => runs.push(Span {
                start: x,
                end: x,
                count: 1,
            }),
        }
    }
    runs
}

/// The request on the target host: the layer naming that host, else the
/// submitted URL.
pub(super) fn target_text(r: &ObsResult) -> &str {
    r.target_host
        .as_deref()
        .and_then(|host| {
            r.layers.iter().rev().find(|l| {
                l.host
                    .as_deref()
                    .is_some_and(|x| x.eq_ignore_ascii_case(host))
            })
        })
        .map_or(r.obs.url.as_str(), |l| l.text.as_str())
}

/// Canonical payload variants in one record's unwrapped layers and their
/// parameter values.
fn payload_variants(r: &ObsResult) -> BTreeSet<String> {
    let texts = r.layers.iter().flat_map(|l| {
        std::iter::once(l.text.as_str()).chain(l.params.iter().map(|(_, v)| v.as_str()))
    });
    if r.layers.is_empty() {
        crate::dialect::variants(&r.obs.url, [r.obs.url.as_str()])
    } else {
        crate::dialect::variants(&r.obs.url, texts)
    }
}

/// Path hints for one cluster: its members plus the unflagged requests on its
/// hosts from `window` seconds before its start to its end.
fn path_stats(
    results: &[ObsResult],
    members: &[usize],
    unflagged_by_host: &HashMap<&str, Vec<usize>>,
    (start, end): (i64, i64),
    window: i64,
    opts: &crate::paths::PathOptions,
) -> PathStats {
    use crate::paths::*;
    let mut idxs: BTreeSet<usize> = members.iter().copied().collect();
    if start > 0 {
        let hosts: BTreeSet<&str> = members
            .iter()
            .filter_map(|&i| results[i].target_host.as_deref())
            .collect();
        for h in hosts {
            for &i in unflagged_by_host.get(h).into_iter().flatten() {
                let ts = results[i].obs.ts;
                if ts >= start - window && ts <= end {
                    idxs.insert(i);
                }
            }
        }
    }
    let reqs: Vec<PathRequest> = idxs
        .iter()
        .filter_map(|&i| {
            let r = &results[i];
            let host = r.target_host.as_deref()?;
            Some(PathRequest::new(
                host,
                r.obs.ts,
                target_text(r),
                r.obs.status,
            ))
        })
        .collect();

    let mut stats = PathStats {
        preambles: shared_preambles(&reqs, opts),
        shared_unusual_sets: shared_unusual_sets(&reqs, opts),
        ..Default::default()
    };
    for &i in members {
        let r = &results[i];
        let found = if r.layers.is_empty() {
            fabricated_ids(&r.obs.url)
        } else {
            fabricated_in(r.layers.iter().map(|l| l.text.as_str()))
        };
        if !found.is_empty() {
            stats.fabricated_ids += 1;
        }
        for f in found {
            *stats
                .fabricated_reasons
                .entry(f.reason.label().to_string())
                .or_default() += 1;
        }
    }
    stats
}
