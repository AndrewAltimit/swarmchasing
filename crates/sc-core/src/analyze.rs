//! The full pipeline: extract → score → link into clusters → timing.

use crate::dialect::{CutLengths, Dialect, DialectPair};
use crate::extract::{Layer, extract};
use crate::fanout::{FanOut, FanRequest};
use crate::model::{Hit, IndicatorKind, Observation, Tier};
use crate::paths::PathStats;
use crate::rules::Rules;
use crate::timing::{
    DateTagOffset, SharedPause, SharedPauseOptions, Span, TimingStats, infer_offset,
    max_concurrency, parse_date_tag, shared_pauses, stale_dates, timing,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObsResult {
    pub obs: Observation,
    pub score: i32,
    pub tier: Tier,
    pub hits: Vec<Hit>,
    pub layers: Vec<Layer>,
    pub target_host: Option<String>,
    pub features: Vec<String>,
    /// Index into `Analysis::clusters`.
    pub cluster: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Cluster {
    pub id: String,
    pub members: Vec<usize>,
    pub start: i64,
    pub end: i64,
    pub tier: Tier,
    /// Sum of weights over the distinct rules seen anywhere in the cluster.
    pub score: i32,
    pub rules: BTreeMap<String, usize>,
    pub kinds: BTreeMap<IndicatorKind, usize>,
    pub target_hosts: BTreeMap<String, usize>,
    pub asns: BTreeMap<u32, usize>,
    pub user_agents: BTreeMap<String, usize>,
    /// Encoding styles of members' URLs ([`crate::fingerprint::Encoding::style`]),
    /// counting only members whose URL shows an informative style. Descriptive:
    /// it never links records.
    #[serde(default)]
    pub encodings: BTreeMap<String, usize>,
    /// Path hints ([`crate::paths`]) over the requests on the cluster's hosts
    /// during its span. Descriptive: never scored, never linked on.
    #[serde(default, skip_serializing_if = "PathStats::is_empty")]
    pub paths: PathStats,
    /// Canonical test payloads in members' decoded requests
    /// ([`crate::dialect`]). Descriptive: never scored, never linked on.
    #[serde(default, skip_serializing_if = "Dialect::is_empty")]
    pub dialect: Dialect,
    /// Widths of one-second batches of alike members ([`crate::fanout`]).
    /// Descriptive: never scored, never linked on.
    #[serde(default, skip_serializing_if = "FanOut::is_empty")]
    pub fanout: FanOut,
    /// Lengths at which members' truncated URLs were cut
    /// ([`crate::dialect::cut_lengths`]). Descriptive.
    #[serde(default, skip_serializing_if = "CutLengths::is_empty")]
    pub cut_lengths: CutLengths,
    /// Features that joined members together.
    pub link_features: Vec<String>,
    pub runs: Vec<Span>,
    pub timing: TimingStats,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AsnSummary {
    pub asn: u32,
    pub org: Option<String>,
    pub count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Analysis {
    pub rules_version: String,
    pub total: usize,
    pub flagged: usize,
    pub tier_counts: BTreeMap<Tier, usize>,
    pub rule_counts: BTreeMap<String, usize>,
    pub results: Vec<ObsResult>,
    pub clusters: Vec<Cluster>,
    /// Timing over all flagged observations.
    pub timing: TimingStats,
    pub max_concurrent_clusters: usize,
    pub asns: Vec<AsnSummary>,
    pub date_tags: DateTagOffset,
    /// Runs of variants of one request around flagged records.
    #[serde(default)]
    pub chains: Vec<crate::chains::Chain>,
    /// Pairs of clusters that went quiet together more often than chance
    /// allows: a link to check, never a merge.
    #[serde(default)]
    pub shared_pauses: Vec<SharedPause>,
    /// Pairs of clusters favouring the same mix of canonical test payloads:
    /// a link to check, never a merge.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dialect_pairs: Vec<DialectPair>,
}

struct Dsu(Vec<usize>);
impl Dsu {
    fn find(&mut self, x: usize) -> usize {
        let p = self.0[x];
        if p == x {
            return x;
        }
        let r = self.find(p);
        self.0[x] = r;
        r
    }
    fn union(&mut self, a: usize, b: usize) {
        let (a, b) = (self.find(a), self.find(b));
        if a != b {
            self.0[a.max(b)] = a.min(b);
        }
    }
}

fn tier_for(score: i32, significant_hit: bool, rules: &Rules) -> Tier {
    let t = &rules.set.thresholds;
    if significant_hit || score >= t.significant {
        Tier::Significant
    } else if score >= t.suggestive {
        Tier::Suggestive
    } else {
        Tier::Noise
    }
}

pub fn analyze(observations: Vec<Observation>, rules: &Rules) -> Analysis {
    let cfg = &rules.set.linking;
    let mut results: Vec<ObsResult> = observations
        .into_iter()
        .map(|obs| {
            let x = extract(&obs, rules);
            ObsResult {
                tier: tier_for(x.score, x.significant_hit, rules),
                score: x.score,
                hits: x.hits,
                layers: x.layers,
                target_host: x.target_host,
                features: x.features,
                cluster: None,
                obs,
            }
        })
        .collect();

    // Only observations with at least one hit are linked; ordinary traffic
    // to the same host must not be swept into a cluster.
    let flagged: Vec<usize> = (0..results.len())
        .filter(|&i| results[i].score > 0)
        .collect();
    let mut dsu = Dsu((0..results.len()).collect());

    let mut by_feature: HashMap<&str, usize> = HashMap::new();
    let mut feature_count: HashMap<&str, usize> = HashMap::new();
    for &i in &flagged {
        for f in &results[i].features {
            *feature_count.entry(f.as_str()).or_default() += 1;
            match by_feature.get(f.as_str()) {
                Some(&j) => dsu.union(i, j),
                None => {
                    by_feature.insert(f.as_str(), i);
                }
            }
        }
    }

    // Same target host, close in time, and sharing at least one rule.
    let mut by_host: HashMap<&str, Vec<usize>> = HashMap::new();
    for &i in &flagged {
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
    let chains = crate::chains::chains(&results);
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
    for &i in &flagged {
        groups.entry(dsu.find(i)).or_default().push(i);
    }

    // Unflagged requests by target host: the context path hints read around
    // a cluster (a recon opening is rarely flagged itself).
    let mut unflagged_by_host: HashMap<&str, Vec<usize>> = HashMap::new();
    for (i, r) in results.iter().enumerate() {
        if r.score == 0
            && r.obs.ts > 0
            && let Some(h) = r.target_host.as_deref()
        {
            unflagged_by_host.entry(h).or_default().push(i);
        }
    }

    let mut clusters: Vec<Cluster> = Vec::new();
    for (_, mut members) in groups {
        if members.len() < 2 {
            continue;
        }
        members.sort_by_key(|&i| results[i].obs.ts);
        let mut rules_seen: BTreeMap<String, usize> = BTreeMap::new();
        let mut kinds: BTreeMap<IndicatorKind, usize> = BTreeMap::new();
        let mut hosts: BTreeMap<String, usize> = BTreeMap::new();
        let mut asns: BTreeMap<u32, usize> = BTreeMap::new();
        let mut uas: BTreeMap<String, usize> = BTreeMap::new();
        let mut encodings: BTreeMap<String, usize> = BTreeMap::new();
        let mut feats: BTreeSet<String> = BTreeSet::new();
        let mut any_sig = false;
        for &i in &members {
            let r = &results[i];
            any_sig |= r.tier == Tier::Significant
                && r.hits.iter().any(|h| h.kind == IndicatorKind::Exploit);
            for h in &r.hits {
                *rules_seen.entry(h.rule_id.clone()).or_default() += 1;
                *kinds.entry(h.kind).or_default() += 1;
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
            for f in &r.features {
                if feature_count.get(f.as_str()).copied().unwrap_or(0) > 1 {
                    feats.insert(f.clone());
                }
            }
        }
        let score: i32 = rules_seen
            .keys()
            .filter_map(|id| rules.compiled.iter().find(|r| &r.def.id == id))
            .map(|r| r.def.weight)
            .sum();
        let member_tier = members
            .iter()
            .map(|&i| results[i].tier)
            .max()
            .unwrap_or_default();
        // Evidence that stacks across a linked cluster raises its tier.
        let tier = if any_sig || score >= rules.set.thresholds.significant {
            Tier::Significant
        } else {
            member_tier.max(if score >= rules.set.thresholds.suggestive {
                Tier::Suggestive
            } else {
                Tier::Noise
            })
        };
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
            &results,
            &members,
            &unflagged_by_host,
            t.start,
            t.end,
            cfg.window_secs,
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
        );
        let cut_lengths = crate::dialect::cut_lengths(
            &members
                .iter()
                .map(|&i| {
                    let r = &results[i];
                    let fired = r.hits.iter().any(|h| h.rule_id == TRUNCATED_RULE);
                    (r.obs.url.as_str(), fired)
                })
                .collect::<Vec<_>>(),
        );
        clusters.push(Cluster {
            id: String::new(),
            start: t.start,
            end: t.end,
            members,
            tier,
            score,
            rules: rules_seen,
            kinds,
            target_hosts: hosts,
            asns,
            user_agents: uas,
            encodings,
            paths,
            dialect,
            fanout,
            cut_lengths,
            link_features: feats.into_iter().collect(),
            runs,
            timing: t,
        });
    }
    clusters.sort_by(|a, b| {
        b.tier
            .cmp(&a.tier)
            .then(b.members.len().cmp(&a.members.len()))
            .then(a.start.cmp(&b.start))
    });
    for (ci, c) in clusters.iter_mut().enumerate() {
        c.id = format!("C{}", ci + 1);
        for &m in &c.members {
            results[m].cluster = Some(ci);
        }
    }

    let mut tier_counts = BTreeMap::new();
    let mut rule_counts = BTreeMap::new();
    let mut asn_counts: BTreeMap<u32, usize> = BTreeMap::new();
    let mut tag_samples = Vec::new();
    for r in &results {
        *tier_counts.entry(r.tier).or_default() += 1;
        for h in &r.hits {
            *rule_counts.entry(h.rule_id.clone()).or_default() += 1;
        }
        if r.score > 0 {
            if let Some(a) = r.obs.asn {
                *asn_counts.entry(a).or_default() += 1;
            }
            if r.obs.ts > 0
                && let Some(d) = r
                    .layers
                    .iter()
                    .flat_map(|l| l.params.iter())
                    .find_map(|(_, v)| parse_date_tag(v))
            {
                tag_samples.push((r.obs.ts, d));
            }
        }
    }
    let flagged_ts: Vec<i64> = flagged.iter().map(|&i| results[i].obs.ts).collect();
    let mut asns: Vec<AsnSummary> = asn_counts
        .into_iter()
        .map(|(asn, count)| AsnSummary {
            asn,
            org: rules.asn_org(asn).map(str::to_string),
            count,
        })
        .collect();
    asns.sort_by_key(|a| std::cmp::Reverse(a.count));
    let quiet: Vec<(String, Vec<i64>)> = clusters
        .iter()
        .filter(|c| c.tier > Tier::Noise)
        .map(|c| {
            let ts = c.members.iter().map(|&i| results[i].obs.ts);
            (c.id.clone(), ts.filter(|&t| t > 0).collect())
        })
        .collect();
    let shared_pauses = shared_pauses(&quiet, &SharedPauseOptions::from_linking(cfg));
    let dialect_pairs = crate::dialect::dialect_pairs(
        &clusters
            .iter()
            .filter(|c| c.tier > Tier::Noise)
            .map(|c| (c.id.as_str(), &c.dialect))
            .collect::<Vec<_>>(),
    );

    Analysis {
        rules_version: rules.set.meta.version.clone(),
        total: results.len(),
        flagged: flagged.len(),
        tier_counts,
        rule_counts,
        timing: timing(&flagged_ts, cfg),
        max_concurrent_clusters: max_concurrency(
            &clusters
                .iter()
                .flat_map(|c| c.runs.iter().map(|r| (r.start, r.end)))
                .collect::<Vec<_>>(),
        ),
        asns,
        date_tags: infer_offset(&tag_samples),
        chains,
        shared_pauses,
        dialect_pairs,
        results,
        clusters,
    }
}

fn split_runs(ts: &[i64], gap: i64) -> Vec<Span> {
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

/// The rule whose hit marks a URL as cut off.
const TRUNCATED_RULE: &str = "marker.truncated_output";

/// The request on the target host: the layer naming that host, else the
/// submitted URL.
fn target_text(r: &ObsResult) -> &str {
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
    start: i64,
    end: i64,
    window: i64,
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
        preambles: shared_preambles(&reqs, PREAMBLE_LEN, MIN_HOSTS),
        shared_unusual_sets: shared_unusual_sets(&reqs, MIN_JACCARD, MIN_PATHS, MIN_HOSTS),
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

    fn o(ts: i64, url: &str) -> Observation {
        Observation {
            ts,
            url: url.into(),
            ..Default::default()
        }
    }

    #[test]
    fn links_by_inbox_and_host() {
        let inbox = "https://webhook.site/0b6c1f0e-1111-4c2a-9a55-3f2e1d0c9b8a";
        let obs = vec![
            o(1000, &format!("{inbox}?kind=headers0")),
            o(
                1040,
                &format!("https://r.jina.ai/https://data.portal.example/p/1?uqtag=a1b2&cb={inbox}"),
            ),
            o(1090, "https://r.jina.ai/https://data.portal.example/p/2"),
            o(99999, "https://www.example.org/"),
        ];
        let a = analyze(obs, &Rules::default_rules());
        assert_eq!(a.flagged, 3);
        assert_eq!(a.clusters.len(), 1);
        assert_eq!(a.clusters[0].members.len(), 3);
        assert_eq!(a.results[3].cluster, None);
    }

    #[test]
    fn oast_service_name_alone_never_links() {
        let obs = vec![
            o(
                1000,
                "https://a.example/q?cb=c58bduhe008dovpvhvugcfemp9yyyyyyb.oast.fun",
            ),
            o(
                1000 + 86_400,
                "https://b.example/q?cb=c58bduhe008dovpvhvugcfemp9zzzzzzb.oast.fun",
            ),
            o(1000 + 2 * 86_400, "https://c.example/q?cb=//oast.fun"),
            o(1000 + 3 * 86_400, "https://d.example/q?cb=//oast.fun"),
        ];
        let a = analyze(obs, &Rules::default_rules());
        assert_eq!(a.flagged, 4);
        assert_eq!(a.clusters.len(), 0, "{:?}", a.clusters);
        assert!(
            a.results[0]
                .features
                .iter()
                .any(|f| f.ends_with("yyyyyyb.oast.fun")),
            "{:?}",
            a.results[0].features
        );
        assert!(a.results[2].features.is_empty());
        let score = |i: usize| a.results[i].score;
        assert_eq!(
            score(0),
            score(2),
            "the inbox and the bare name score alike"
        );
    }

    #[test]
    fn encoding_styles_describe_but_never_link() {
        let inbox = "https://webhook.site/0b6c1f0e-1111-4c2a-9a55-3f2e1d0c9b8a";
        let other = "https://webhook.site/7d2e4a10-2222-4b3c-8a66-4e3f2a1b0c9d";
        let obs = vec![
            o(1000, &format!("{inbox}?d=a%20b&")),
            o(1040, &format!("{inbox}?d=c%20d&")),
            // Same style, different inbox, far apart: must stay unlinked.
            o(500_000, &format!("{other}?d=e%20f&")),
        ];
        let a = analyze(obs, &Rules::default_rules());
        assert_eq!(a.flagged, 3);
        assert_eq!(a.clusters.len(), 1);
        let c = &a.clusters[0];
        assert_eq!(c.members.len(), 2);
        assert_eq!(c.encodings.len(), 1);
        assert_eq!(c.encodings.get("sp20.amp.noslash"), Some(&2));
        assert_eq!(a.results[2].cluster, None);
    }

    #[test]
    fn path_hints_describe_but_never_score() {
        let inbox = "https://webhook.site/0b6c1f0e-1111-4c2a-9a55-3f2e1d0c9b8a";
        let mut obs = Vec::new();
        for (i, h) in ["a.example", "b.example", "c.example"].iter().enumerate() {
            let t = 1000 + 60 * i as i64;
            for (j, p) in ["/robots.txt", "/.well-known/security.txt", "/.env"]
                .iter()
                .enumerate()
            {
                obs.push(o(t + j as i64, &format!("https://{h}{p}")));
            }
            obs.push(o(
                t + 10,
                &format!(
                    "https://{h}/o/12345678-1234-1234-1234-123456789abc?cb={inbox}?kind=headers0"
                ),
            ));
        }
        let plain: Vec<Observation> = obs
            .iter()
            .filter(|x| x.url.contains("webhook.site"))
            .cloned()
            .collect();
        let a = analyze(obs, &Rules::default_rules());
        let b = analyze(plain, &Rules::default_rules());
        assert_eq!(a.clusters.len(), 1, "{:?}", a.clusters);
        let c = &a.clusters[0];
        assert_eq!(c.members.len(), 3);
        assert_eq!(c.score, b.clusters[0].score);
        assert_eq!(c.paths.preambles.len(), 1, "{:?}", c.paths);
        assert_eq!(c.paths.preambles[0].hosts, 3);
        assert_eq!(c.paths.fabricated_ids, 3);
        assert!(b.clusters[0].paths.preambles.is_empty());
    }
}
