//! The full pipeline: extract → score → link into clusters → timing.
//!
//! `link` decides which records belong together, `hints` describes each
//! cluster; this module scores records and assembles the [`Analysis`].

mod hints;
mod link;

use crate::dialect::{CutLengths, Dialect, DialectPair};
use crate::extract::{Layer, extract};
use crate::fanout::FanOut;
use crate::model::{Hit, IndicatorKind, LinkFeature, Observation, Tactic, Tier};
use crate::paths::PathStats;
use crate::rules::Rules;
use crate::timing::{
    DateTagOffset, SharedPause, SharedPauseOptions, Span, TimingStats, infer_offset,
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
    pub tier: Tier,
    /// Sum of weights over the distinct rules seen anywhere in the cluster.
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
        .map(|members| {
            hints::cluster(
                &results,
                members,
                &links.feature_count,
                &unflagged_by_host,
                rules,
            )
        })
        .collect();
    let chains = links.chains;
    link::number(&mut clusters, &mut results);

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

    #[test]
    fn hits_carry_tactics_and_clusters_count_them() {
        let inbox = "https://webhook.site/0b6c1f0e-1111-4c2a-9a55-3f2e1d0c9b8a";
        let obs = vec![
            o(1000, &format!("{inbox}?kind=headers0")),
            o(
                1040,
                &format!("https://r.jina.ai/https://p.example/%60https://p.example/x%60?cb={inbox}"),
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
