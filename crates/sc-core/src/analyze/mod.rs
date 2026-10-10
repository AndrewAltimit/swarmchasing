//! The full pipeline: extract → score → link into clusters → timing.
//!
//! `link` decides which records belong together, `hints` describes each
//! cluster; this module scores records and assembles the [`Analysis`].

mod hints;
mod link;

pub(crate) use hints::target_text;

use crate::dialect::{CutLengths, Dialect, DialectPair};
use crate::extract::{Layer, extract};
use crate::fanout::FanOut;
use crate::model::{Hit, IndicatorKind, LinkFeature, Observation, Tactic, Tier};
use crate::paths::PathStats;
use crate::rules::Rules;
use crate::timing::{
    DateTagOffset, SharedPause, SharedPauseOptions, Span, TimeBasis, TimingStats, infer_offset,
    max_concurrency, parse_date_tag, shared_pauses, timing,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObsResult {
    pub obs: Observation,
    pub score: i32,
    pub tier: Tier,
    pub hits: Vec<Hit>,
    /// Unwrapped layers. Empty for an unflagged record with nothing to
    /// unwrap: its one layer would only repeat its URL.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub layers: Vec<Layer>,
    pub target_host: Option<String>,
    pub features: Vec<LinkFeature>,
    /// Index into `Analysis::clusters`.
    pub cluster: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Cluster {
    /// Position in this analysis (`C1` is the strongest). Another run over
    /// more records can give the same cluster another number.
    pub id: String,
    /// Stable name (`k-3f9a2c1b`): a hash of the smallest member record id,
    /// so the cluster keeps it while its earliest-named record stays in it.
    #[serde(default)]
    pub key: String,
    pub members: Vec<usize>,
    pub start: i64,
    pub end: i64,
    /// What the members' timestamps measure. Rhythm and fan-out read only
    /// request-like times (request or submit), never capture times.
    #[serde(default, skip_serializing_if = "TimeBasis::is_unknown")]
    pub time_basis: TimeBasis,
    /// The strongest member's tier, raised one step only by corroboration
    /// ([`hints::cluster_tier`]).
    pub tier: Tier,
    /// Sum of weights over the distinct rules seen anywhere in the cluster.
    /// Descriptive: it does not set the tier.
    pub score: i32,
    pub rules: BTreeMap<String, usize>,
    pub kinds: BTreeMap<IndicatorKind, usize>,
    /// Hits per tactic (`T1`..`T9`) over the members.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub tactics: BTreeMap<Tactic, usize>,
    /// Members with a hit that only shows a model wrote the request.
    #[serde(default)]
    pub artifacts: usize,
    pub target_hosts: BTreeMap<String, usize>,
    pub asns: BTreeMap<u32, usize>,
    pub user_agents: BTreeMap<String, usize>,
    /// Encoding styles of members' URLs ([`crate::fingerprint::Encoding::style`]),
    /// counting only members whose URL shows an informative style. Descriptive:
    /// it never links records.
    #[serde(default)]
    pub encodings: BTreeMap<String, usize>,
    /// Header-set fingerprints of members that carry request headers
    /// ([`crate::fingerprint::HeaderSet::hash`]). Descriptive.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub header_sets: BTreeMap<String, usize>,
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
    pub link_features: Vec<LinkFeature>,
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
    /// Linking features shared too widely to link: each group of records
    /// that would otherwise have been joined by one.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub common_features: Vec<CommonFeature>,
    /// Requests for one target whose route climbed (direct, relay, program,
    /// remote browser) within a window: a hint on the clusters they touch.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub escalations: Vec<crate::escalation::Escalation>,
    /// Descriptive ties between clusters above noise (shared pauses, payload
    /// dialects, reruns, recon preambles, path sets, encoding, fan-out, cut
    /// lengths, header sets, escalations, common features), strongest
    /// first. They never merge clusters or change a score.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub soft_links: Vec<crate::fleets::SoftLink>,
    /// Clusters whose combined soft links are strong: proposals for the
    /// admin, never findings.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub candidate_fleets: Vec<crate::fleets::CandidateFleet>,
}

/// A linking feature whose carriers were not joined because it is common:
/// on too many target hosts, or on too large a share of the records around
/// it. A popular or copied tag, not one operator's.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CommonFeature {
    pub feature: LinkFeature,
    /// Flagged records carrying it in this group.
    pub records: usize,
    /// Distinct target hosts among them.
    pub hosts: usize,
    pub start: i64,
    pub end: i64,
    /// Which limit it passed.
    pub reason: String,
}

impl Cluster {
    /// Whether `sel` names this cluster: its id (`C3`, any case) or its key.
    pub fn matches(&self, sel: &str) -> bool {
        let sel = sel.trim();
        self.id.eq_ignore_ascii_case(sel) || (!self.key.is_empty() && self.key == sel)
    }
}

impl Analysis {
    /// The index of the cluster `sel` names, by id or key.
    pub fn cluster_index(&self, sel: &str) -> Option<usize> {
        self.clusters.iter().position(|c| c.matches(sel))
    }

    /// The cluster `sel` names, by id or key.
    pub fn cluster(&self, sel: &str) -> Option<&Cluster> {
        self.cluster_index(sel).map(|i| &self.clusters[i])
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
    let links = link::link(&results, &flagged, rules);
    let unflagged_by_host = hints::unflagged_by_host(&results);
    let mut clusters: Vec<Cluster> = links
        .groups
        .into_iter()
        .map(|members| hints::cluster(&results, members, &links.joined, &unflagged_by_host, rules))
        .collect();
    let chains = links.chains;
    let common_features = links.common;
    link::number(&mut clusters, &mut results);
    let cluster_ids: Vec<String> = clusters.iter().map(|c| c.id.clone()).collect();
    let escalations = crate::escalation::escalations(&results, &cluster_ids, &rules.set.escalation);

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
    crate::sort::by_key(&mut asns, |a| std::cmp::Reverse(a.count));
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
    for r in results.iter_mut() {
        if r.score == 0 && r.layers.len() == 1 && r.layers[0].via == "submitted" {
            r.layers.clear();
        }
    }
    let soft_links = crate::fleets::soft_links(
        &crate::fleets::Signals {
            clusters: &clusters,
            results: &results,
            shared_pauses: &shared_pauses,
            dialect_pairs: &dialect_pairs,
            escalations: &escalations,
            common_features: &common_features,
        },
        &rules.set.soft_links,
    );
    let candidate_fleets =
        crate::fleets::candidate_fleets(&soft_links, &cluster_ids, &rules.set.soft_links);

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
        common_features,
        escalations,
        soft_links,
        candidate_fleets,
        results,
        clusters,
    }
}

#[cfg(test)]
mod tests {
    use super::link::{Dsu, cluster_key};
    use super::*;

    fn o(ts: i64, url: &str) -> Observation {
        Observation {
            ts,
            url: url.into(),
            ..Default::default()
        }
    }

    #[test]
    fn union_find_survives_a_long_chain() {
        let n = 1_000_000;
        let mut d = Dsu((0..n).collect());
        // Each union hangs the previous root under a new one: a chain n deep.
        for i in (0..n - 1).rev() {
            d.union(i, i + 1);
        }
        assert_eq!(d.find(n - 1), 0);
        assert_eq!(d.0[n - 1], 0, "path compressed");
    }

    #[test]
    fn cluster_keys_outlive_cluster_numbers() {
        let inbox = "https://webhook.site/0b6c1f0e-1111-4c2a-9a55-3f2e1d0c9b8a";
        let rec = |id: &str, ts: i64, url: &str| Observation {
            id: id.into(),
            ..o(ts, url)
        };
        let small = vec![
            rec("w:2", 1000, &format!("{inbox}?kind=headers0")),
            rec("w:1", 1040, &format!("{inbox}?kind=body0-0")),
        ];
        let a = analyze(small.clone(), &Rules::default_rules());
        assert_eq!(a.clusters.len(), 1);
        let key = a.clusters[0].key.clone();
        assert!(key.starts_with("k-") && key.len() == 10, "{key}");
        assert_eq!(key, cluster_key("w:1"));

        // A stronger cluster arrives and takes C1; the first keeps its key.
        let mut more = small;
        for i in 0..4 {
            more.push(rec(
                &format!("x:{i}"),
                5000 + i * 30,
                &format!(
                    "https://r.jina.ai/https://p.example/q?id={i}%20UNION%20SELECT%201&uqtag=zz9"
                ),
            ));
        }
        let b = analyze(more, &Rules::default_rules());
        assert_eq!(b.clusters.len(), 2);
        let c = b.cluster(&key).unwrap();
        assert_eq!(c.id, "C2");
        assert_eq!(b.cluster("c2").unwrap().key, key);
        assert_eq!(b.cluster_index(" C1 "), Some(0));
        assert!(b.cluster("k-00000000").is_none());
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

    /// Every hour for four days, three records a second apart each hour, all
    /// with one inbox, timestamped as `kind`.
    fn hourly_fleet(kind: crate::model::TsKind) -> Vec<Observation> {
        let inbox = "https://webhook.site/0b6c1f0e-1111-4c2a-9a55-3f2e1d0c9b8a";
        (0..96 * 3)
            .map(|i| Observation {
                ts_kind: kind,
                ..o(
                    1_791_072_000 + (i / 3) * 3600 + (i % 3).min(1) + 7,
                    &format!("https://h{}.example/q?id={i}&hook={inbox}", i % 3),
                )
            })
            .collect()
    }

    fn report_of(a: &Analysis) -> String {
        crate::report::render_markdown(a, &crate::report::ReportOptions::default())
    }

    #[test]
    fn capture_times_are_not_read_as_request_timing() {
        use crate::model::TsKind;
        use crate::timing::{RhythmVerdict, TimeBasis};
        let req = analyze(hourly_fleet(TsKind::Request), &Rules::default_rules());
        let c = &req.clusters[0];
        assert_eq!(c.time_basis, TimeBasis::Request);
        assert_eq!(c.timing.rhythm.verdict, RhythmVerdict::RoundTheClock);
        assert_eq!(c.fanout.modal_width, Some(3));
        assert!(report_of(&req).contains("active around the clock"));

        let cap = analyze(hourly_fleet(TsKind::Capture), &Rules::default_rules());
        let c = &cap.clusters[0];
        assert_eq!(c.time_basis, TimeBasis::Capture);
        assert_eq!(c.timing.rhythm.verdict, RhythmVerdict::TooShort);
        assert!(c.fanout.is_empty(), "{:?}", c.fanout);
        let md = report_of(&cap);
        assert!(
            !md.contains("daily rhythm") && !md.contains("fan-out"),
            "{md}"
        );
        // Cadence still describes the captures.
        assert_eq!(c.timing.count, 96 * 3);

        // Half captures: the rest still give a rhythm, labelled.
        let mut mixed = hourly_fleet(TsKind::Request);
        for r in mixed.iter_mut().step_by(2) {
            r.ts_kind = TsKind::Capture;
        }
        let m = analyze(mixed, &Rules::default_rules());
        assert_eq!(m.clusters[0].time_basis, TimeBasis::Mixed);
        assert_eq!(
            m.clusters[0].timing.rhythm.verdict,
            RhythmVerdict::RoundTheClock
        );
        assert!(report_of(&m).contains("(capture times left out)"));
    }

    #[test]
    fn submit_times_are_read_as_request_like_and_say_so() {
        use crate::model::TsKind;
        use crate::timing::{RhythmVerdict, TimeBasis};
        let a = analyze(hourly_fleet(TsKind::Submit), &Rules::default_rules());
        let c = &a.clusters[0];
        assert_eq!(c.time_basis, TimeBasis::Submit);
        assert_eq!(c.timing.rhythm.verdict, RhythmVerdict::RoundTheClock);
        assert_eq!(c.fanout.modal_width, Some(3));
        let md = report_of(&a);
        assert!(
            md.contains("(hour-of-day entropy")
                && md.matches("(submit times, close to request times)").count() == 2,
            "{md}"
        );
    }

    #[test]
    fn capture_times_never_link_by_timing() {
        use crate::model::TsKind;
        // Two records for one target a minute apart, sharing a rule, with
        // nothing else in common.
        let pair = |kind| {
            let obs = [
                "https://r.jina.ai/https://a.example/p?x=%7B%7Bhost%7D%7D",
                "https://r.jina.ai/https://a.example/q?y=%7B%7Bname%7D%7D",
            ]
            .iter()
            .enumerate()
            .map(|(i, u)| Observation {
                ts_kind: kind,
                ..o(1_791_000_000 + 60 * i as i64, u)
            })
            .collect();
            analyze(obs, &Rules::default_rules()).clusters.len()
        };
        assert_eq!(pair(TsKind::Request), 1);
        assert_eq!(pair(TsKind::Submit), 1);
        assert_eq!(pair(TsKind::Unknown), 1);
        assert_eq!(pair(TsKind::Capture), 0);
    }

    #[test]
    fn chain_pace_is_not_read_from_capture_times() {
        use crate::model::TsKind;
        let chain = |kind| {
            let t = 1_791_000_000;
            let obs: Vec<Observation> = [
                (0, "?id=1"),
                (20, "?id=2"),
                (45, "?id=1'"),
                (70, "?id=1%20UNION%20SELECT%201"),
            ]
            .iter()
            .map(|&(dt, q)| Observation {
                ts_kind: kind,
                ..o(t + dt, &format!("https://portal.example.gov/item{q}"))
            })
            .collect();
            analyze(obs, &Rules::default_rules())
        };
        let req = chain(TsKind::Request);
        assert!(report_of(&req).contains("model pace"));
        let cap = chain(TsKind::Capture);
        assert_eq!(cap.chains[0].time_basis, crate::timing::TimeBasis::Capture);
        let md = report_of(&cap);
        assert!(
            md.contains("capture times, not request times: pace not read")
                && !md.contains("model pace"),
            "{md}"
        );
        assert!(report_of(&chain(TsKind::Submit)).contains("model pace, from submit times"));
    }

    #[test]
    fn weak_rules_across_members_do_not_raise_a_cluster() {
        // One inbox; each record adds a different context rule. Summed over
        // distinct rules this reaches the significant threshold; no member
        // does, and context kinds corroborate nothing.
        let inbox = "https://webhook.site/0b6c1f0e-1111-4c2a-9a55-3f2e1d0c9b8a";
        let obs = vec![
            o(1000, &format!("https://a.example/x?hook={inbox}&_=1")),
            o(
                1030,
                &format!("https://a.example/y?hook={inbox}&agent=claude"),
            ),
            o(
                1060,
                &format!("https://r.jina.ai/https://a.example/z?hook={inbox}"),
            ),
        ];
        let a = analyze(obs, &Rules::default_rules());
        assert_eq!(a.clusters.len(), 1);
        let c = &a.clusters[0];
        assert!(c.score >= 6, "{}", c.score);
        assert!(
            a.results.iter().all(|r| r.tier == Tier::Suggestive),
            "{:?}",
            a.results
                .iter()
                .map(|r| (r.score, &r.hits))
                .collect::<Vec<_>>()
        );
        assert_eq!(c.tier, Tier::Suggestive);
    }

    #[test]
    fn corroborating_members_raise_a_cluster_one_step() {
        let inbox = "https://webhook.site/0b6c1f0e-1111-4c2a-9a55-3f2e1d0c9b8a";
        let obs = vec![
            // Callback channel and model residue ...
            o(
                1000,
                &format!("https://a.example/p%5D%28https://a.example/p%29?hook={inbox}"),
            ),
            // ... and callback channel and an echo carrier, in another record.
            o(
                1030,
                &format!("https://httpbin.org/anything?u=https://a.example/&hook={inbox}"),
            ),
        ];
        let a = analyze(obs.clone(), &Rules::default_rules());
        assert!(
            a.results.iter().all(|r| r.tier == Tier::Suggestive),
            "{:?}",
            a.results
                .iter()
                .map(|r| (r.score, &r.hits))
                .collect::<Vec<_>>()
        );
        assert_eq!(a.clusters[0].tier, Tier::Significant);

        // The same evidence twice is not corroboration.
        let same = vec![obs[0].clone(), o(1060, &obs[0].url)];
        let b = analyze(same, &Rules::default_rules());
        assert_eq!(b.clusters[0].tier, Tier::Suggestive);

        // A noise-only cluster stays noise.
        let quiet = vec![
            o(1000, "https://r.jina.ai/https://a.example/q?uqtag=abc1"),
            o(1030, "https://r.jina.ai/https://a.example/r?uqtag=abc1"),
        ];
        let q = analyze(quiet, &Rules::default_rules());
        assert!(q.clusters.iter().all(|c| {
            c.tier
                == q.results[c.members[0]]
                    .tier
                    .max(q.results[c.members[1]].tier)
        }));
    }

    #[test]
    fn hits_carry_tactics_and_clusters_count_them() {
        let inbox = "https://webhook.site/0b6c1f0e-1111-4c2a-9a55-3f2e1d0c9b8a";
        let obs = vec![
            o(1000, &format!("{inbox}?kind=headers0")),
            o(
                1040,
                &format!(
                    "https://r.jina.ai/https://p.example/%60https://p.example/x%60?cb={inbox}"
                ),
            ),
        ];
        let a = analyze(obs, &Rules::default_rules());
        let hit = |id: &str| {
            a.results
                .iter()
                .flat_map(|r| &r.hits)
                .find(|h| h.rule_id == id)
                .unwrap()
        };
        assert_eq!(hit("relay.jina").tactic, Some(Tactic::ToolEscalation));
        assert!(hit("marker.md_url_wrapper").artifact);
        assert_eq!(hit("marker.md_url_wrapper").tactic, None);
        let c = &a.clusters[0];
        assert_eq!(c.tactics.get(&Tactic::CallbackChannels), Some(&3));
        assert_eq!(c.tactics.get(&Tactic::ToolEscalation), Some(&1));
        assert_eq!(c.artifacts, 1);
        let json = serde_json::to_value(&a).unwrap();
        assert_eq!(json["clusters"][0]["tactics"]["T7"], 3);
        assert_eq!(json["results"][1]["hits"][0]["tactic"], "T2");
    }

    #[test]
    fn a_feature_reused_months_later_starts_a_new_cluster() {
        let inbox = "https://webhook.site/0b6c1f0e-1111-4c2a-9a55-3f2e1d0c9b8a";
        let day = 86_400;
        let t0 = 1_791_000_000;
        let obs = vec![
            o(t0, &format!("https://a.example/x?cb={inbox}")),
            o(t0 + 2 * day, &format!("https://b.example/y?cb={inbox}")),
            // Three months on, the same inbox on other hosts.
            o(t0 + 90 * day, &format!("https://c.example/z?cb={inbox}")),
            o(t0 + 91 * day, &format!("https://d.example/w?cb={inbox}")),
        ];
        let a = analyze(obs.clone(), &Rules::default_rules());
        assert_eq!(a.clusters.len(), 2, "{:?}", a.clusters);
        assert_eq!(a.results[0].cluster, a.results[1].cluster);
        assert_eq!(a.results[2].cluster, a.results[3].cluster);
        assert_ne!(a.results[0].cluster, a.results[2].cluster);
        for c in &a.clusters {
            assert_eq!(c.link_features.len(), 1, "{:?}", c.link_features);
        }
        assert!(a.common_features.is_empty());

        // With no window, one inbox is one cluster however far apart.
        let mut rules = Rules::default_rules();
        rules.set.linking.feature_link_window_secs = 0;
        let b = analyze(obs, &rules);
        assert_eq!(b.clusters.len(), 1, "{:?}", b.clusters);
        assert_eq!(b.clusters[0].members.len(), 4);
    }

    #[test]
    fn a_popular_tag_is_common_and_never_links() {
        // A copied test tag on many unrelated sites in one afternoon.
        let t0 = 1_791_000_000;
        let obs: Vec<Observation> = (0..25)
            .map(|i| {
                o(
                    t0 + i * 600,
                    &format!("https://site{i}.example/page?q=CHATGPTTEST1"),
                )
            })
            .collect();
        let a = analyze(obs.clone(), &Rules::default_rules());
        assert_eq!(a.clusters.len(), 0, "{:?}", a.clusters);
        assert_eq!(a.common_features.len(), 1, "{:?}", a.common_features);
        let c = &a.common_features[0];
        assert_eq!(c.feature.to_string(), "marker.test_tag:chatgpttest1");
        assert_eq!((c.records, c.hosts), (25, 25));
        assert_eq!((c.start, c.end), (t0, t0 + 24 * 600));
        assert!(c.reason.contains("feature_max_hosts"), "{}", c.reason);
        let report = |audience| {
            crate::report::render_markdown(
                &a,
                &crate::report::ReportOptions {
                    audience,
                    ..Default::default()
                },
            )
        };
        let internal = report(crate::report::Audience::Internal);
        assert!(
            internal.contains("Common features") && internal.contains("chatgpttest1"),
            "{internal}"
        );
        assert!(!report(crate::report::Audience::Provider).contains("Common features"));

        // The same tag on a few hosts still links.
        let few: Vec<Observation> = obs.into_iter().take(4).collect();
        let b = analyze(few, &Rules::default_rules());
        assert_eq!(b.clusters.len(), 1);
        assert!(b.common_features.is_empty());
    }

    #[test]
    fn a_feature_on_most_records_is_common_when_a_share_is_set() {
        // A run parameter value on most of a broad input, one host each.
        let t0 = 1_791_000_000;
        let mut obs: Vec<Observation> = (0..60)
            .map(|i| {
                o(
                    t0 + i * 60,
                    &format!("https://h{}.example/?uqtag=default&_=1", i % 5),
                )
            })
            .collect();
        obs.extend((0..60).map(|i| o(t0 + i * 60 + 30, &format!("https://plain{i}.example/"))));
        let mut rules = Rules::default_rules();
        rules.set.linking.feature_max_share = 0.4;
        rules.set.linking.feature_share_min_records = 100;
        let a = analyze(obs.clone(), &rules);
        assert!(
            a.common_features
                .iter()
                .any(|c| c.feature.to_string() == "param:uqtag=default"
                    && c.reason.contains("feature_max_share")),
            "{:?}",
            a.common_features
        );
        // Off by default: one fleet can be most of a case's records.
        let b = analyze(obs, &Rules::default_rules());
        assert!(b.common_features.is_empty());
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
                .any(|f| f.value().ends_with("yyyyyyb.oast.fun")),
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
