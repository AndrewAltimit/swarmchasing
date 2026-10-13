//! What a cluster looks like: its tier and counts ([`base`]), then one
//! function per enrichment the pipeline runs over it (timing, fingerprints,
//! paths, payload dialect, fan-out, prose, declarations, provenance).
//! Hints are shown in reports; none changes a score or a link.

use super::{Cluster, ObsResult};
use crate::fanout::FanRequest;
use crate::model::{IndicatorKind, LinkFeature, Tactic, Tier};
use crate::paths::PathStats;
use crate::rules::{Linking, Rules};
use crate::timing::{Span, TimeBasis, request_like, rhythm_of, stale_dates, timing};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

/// Unflagged requests by target host, each host's in time order: the
/// context path hints read around a cluster (a recon opening is rarely
/// flagged itself).
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
    for v in unflagged_by_host.values_mut() {
        crate::sort::by_key(v, |&i| (results[i].obs.ts, i));
    }
    unflagged_by_host
}

/// Distinct declarations kept per cluster.
const MAX_DECLARED: usize = 8;

/// One cluster of `members` (indexes into `results`), not yet numbered or
/// described: members in time order, tier, score, rule and kind counts,
/// hosts, networks, user agents and the features that joined it.
pub(super) fn base(
    results: &[ObsResult],
    mut members: Vec<usize>,
    joined: &HashSet<(usize, &LinkFeature)>,
    rules: &Rules,
) -> Cluster {
    crate::sort::by_key(&mut members, |&i| results[i].obs.ts);
    let mut rules_seen: BTreeMap<String, usize> = BTreeMap::new();
    let mut kinds: BTreeMap<IndicatorKind, usize> = BTreeMap::new();
    let mut tactics: BTreeMap<Tactic, usize> = BTreeMap::new();
    let mut artifacts = 0;
    let mut hosts: BTreeMap<String, usize> = BTreeMap::new();
    let mut asns: BTreeMap<u32, usize> = BTreeMap::new();
    let mut uas: BTreeMap<String, usize> = BTreeMap::new();
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
        for f in r.features.iter().filter(|f| joined.contains(&(i, *f))) {
            *feats.entry(f).or_default() += 1;
        }
    }
    let score = rules.score(rules_seen.keys().map(String::as_str));
    Cluster {
        tier: cluster_tier(results, &members),
        score,
        rules: rules_seen,
        kinds,
        tactics,
        artifacts,
        target_hosts: hosts,
        asns,
        user_agents: uas,
        link_features: feats
            .into_iter()
            .filter(|&(_, n)| n > 1)
            .map(|(f, _)| f.clone())
            .collect(),
        members,
        ..Default::default()
    }
}

/// Span, time basis, cadence, rhythm, stale date tags and runs.
pub(super) fn cluster_timing(c: &mut Cluster, results: &[ObsResult], cfg: &Linking) {
    let members = &c.members;
    let ts: Vec<i64> = members.iter().map(|&i| results[i].obs.ts).collect();
    let timed = || {
        members
            .iter()
            .map(|&i| &results[i].obs)
            .filter(|o| o.ts > 0)
    };
    let time_basis = TimeBasis::of(timed().map(|o| o.ts_kind));
    let mut t = timing(&ts, cfg);
    // Per cluster only the hours with records; a long, sparse cluster would
    // otherwise carry thousands of empty hours.
    t.hourly.retain(|&(_, n)| n > 0);
    // The hour-of-day profile reads request times; capture times are when
    // an archive saved a URL.
    t.rhythm = rhythm_of(
        &timed()
            .filter(|o| request_like(o.ts_kind))
            .map(|o| o.ts)
            .collect::<Vec<_>>(),
    );
    t.stale_dates = stale_dates(
        &members
            .iter()
            .filter_map(|&i| results[i].date_tag())
            .collect::<Vec<_>>(),
    );
    c.runs = split_runs(&ts, cfg.run_gap_secs);
    c.time_basis = time_basis;
    c.start = t.start;
    c.end = t.end;
    c.timing = t;
}

/// URL encoding styles, header sets and relay stacks of the members.
pub(super) fn fingerprints(c: &mut Cluster, results: &[ObsResult]) {
    for &i in &c.members {
        let r = &results[i];
        if let Some(s) = relay_stack(r) {
            *c.relay_stacks.entry(s).or_default() += 1;
        }
        let enc = crate::fingerprint::encoding(&r.obs.url);
        if enc.informative() {
            *c.encodings.entry(enc.style).or_default() += 1;
        }
        if let Some(h) = crate::fingerprint::header_set(&r.obs.headers) {
            *c.header_sets.entry(h.hash).or_default() += 1;
        }
    }
}

/// Canonical test payloads and the lengths truncated URLs were cut at.
pub(super) fn dialect(c: &mut Cluster, results: &[ObsResult], rules: &Rules) {
    c.dialect = crate::dialect::dialect(
        &c.members
            .iter()
            .map(|&i| payload_variants(&results[i]))
            .collect::<Vec<_>>(),
    );
    c.cut_lengths = crate::dialect::cut_lengths(
        &c.members
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
}

/// Widths of one-second batches, from request-like times only.
pub(super) fn fanout(c: &mut Cluster, results: &[ObsResult], rules: &Rules) {
    c.fanout = crate::fanout::fanout(
        &c.members
            .iter()
            .map(|&i| {
                let r = &results[i];
                FanRequest {
                    ts: if request_like(r.obs.ts_kind) {
                        r.obs.ts
                    } else {
                        0
                    },
                    host: r.target_host.clone(),
                    path: crate::paths::normalize_path(target_text(r)),
                }
            })
            .collect::<Vec<_>>(),
        &rules.set.fanout,
    );
}

/// Prose in parameter values and its guessed languages.
pub(super) fn prose(c: &mut Cluster, results: &[ObsResult]) {
    c.prose = crate::prose::prose_stats(c.members.iter().map(|&i| {
        let r = &results[i];
        let values = r
            .layers
            .iter()
            .flat_map(|l| l.params.iter().map(|(_, v)| v.as_str()))
            .collect();
        (r.target_host.as_deref(), values)
    }));
}

/// Members announcing testing or research, with the contact they name.
pub(super) fn declared(c: &mut Cluster, results: &[ObsResult]) {
    let mut declared: BTreeMap<(String, Option<String>), usize> = BTreeMap::new();
    for &i in &c.members {
        let r = &results[i];
        let params = r.layers.iter().flat_map(|l| l.params.iter());
        if let Some(d) = crate::declared::declared(&r.obs, params) {
            *declared.entry(d).or_default() += 1;
        }
    }
    c.declared = declared
        .into_iter()
        .take(MAX_DECLARED)
        .map(|((text, contact), records)| crate::declared::Declared {
            text,
            contact,
            records,
        })
        .collect();
}

/// Members by provenance, and whether more than one kind of source stands
/// behind them.
pub(super) fn provenance(c: &mut Cluster, results: &[ObsResult]) {
    c.origin.provenance = crate::plant::provenance_counts(results, &c.members);
    c.origin.corroboration = crate::plant::corroboration(results, &c.members);
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

/// Kinds that describe how a request was sent rather than what it did
/// ([`IndicatorKind::is_context`]).
pub fn is_context_kind(k: IndicatorKind) -> bool {
    k.is_context()
}

pub(super) fn split_runs(ts: &[i64], gap: i64) -> Vec<Span> {
    let mut t: Vec<i64> = ts.iter().copied().filter(|&x| x > 0).collect();
    crate::sort::sort(&mut t);
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

/// The relays and carriers one record went through, outermost first, then
/// `target`: the rule ids of its relay and carrier hits in unwrapping order.
/// `None` for a direct request.
pub(crate) fn relay_stack(r: &ObsResult) -> Option<String> {
    let depth = |l: usize| r.layers.get(l).map_or(0, |x| x.depth);
    let mut hops: Vec<(usize, usize, &str)> = r
        .hits
        .iter()
        .filter(|h| matches!(h.kind, IndicatorKind::Relay | IndicatorKind::Carrier))
        .map(|h| (depth(h.layer), h.layer, h.rule_id.as_str()))
        .collect();
    if hops.is_empty() {
        return None;
    }
    crate::sort::sort(&mut hops);
    let mut s = String::new();
    for (_, _, id) in hops {
        s.push_str(id);
        s.push_str(" → ");
    }
    s.push_str("target");
    Some(s)
}

/// The request on the target host: the layer naming that host, else the
/// submitted URL.
pub(crate) fn target_text(r: &ObsResult) -> &str {
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
pub(crate) fn payload_variants(r: &ObsResult) -> BTreeSet<String> {
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
/// hosts from `window` seconds before its start to its end. Reads the
/// cluster's span, so it runs after [`cluster_timing`].
pub(super) fn paths(
    c: &mut Cluster,
    results: &[ObsResult],
    unflagged_by_host: &HashMap<&str, Vec<usize>>,
    rules: &Rules,
) {
    c.paths = path_stats(
        results,
        &c.members,
        unflagged_by_host,
        (c.start, c.end),
        rules.set.linking.window_secs,
        &rules.set.paths,
    );
}

/// The indexes of `by_time` (in order of `ts`) timed from `from` to `to`
/// inclusive.
fn within(by_time: &[usize], ts: impl Fn(usize) -> i64, from: i64, to: i64) -> &[usize] {
    let lo = by_time.partition_point(|&i| ts(i) < from);
    let hi = by_time.partition_point(|&i| ts(i) <= to);
    &by_time[lo..hi.max(lo)]
}

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
            let on_host = unflagged_by_host.get(h).map_or(&[][..], Vec::as_slice);
            idxs.extend(within(on_host, |i| results[i].obs.ts, start - window, end));
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn within_slices_a_time_ordered_list_by_time() {
        let times = [50, 10, 30, 30, 0, 70];
        let ts = |i: usize| times[i];
        let mut by_time: Vec<usize> = (0..times.len()).collect();
        crate::sort::by_key(&mut by_time, |&i| (times[i], i));
        assert_eq!(by_time, [4, 1, 2, 3, 0, 5]);
        assert_eq!(within(&by_time, ts, 10, 50), [1, 2, 3, 0]);
        assert_eq!(within(&by_time, ts, 11, 49), [2, 3]);
        assert_eq!(within(&by_time, ts, 30, 30), [2, 3]);
        assert!(within(&by_time, ts, 31, 49).is_empty());
        assert!(within(&by_time, ts, 60, 20).is_empty());
        assert_eq!(within(&by_time, ts, -5, 100), by_time.as_slice());
    }
}
