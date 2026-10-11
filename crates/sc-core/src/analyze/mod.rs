//! The full pipeline: extract → score → link into clusters → describe →
//! number → cross-cluster hints.
//!
//! `pipeline` runs the passes in their declared order, `link` decides which
//! records belong together, `hints` describes each cluster; this module
//! holds the types the passes fill in.

mod hints;
mod link;
mod pipeline;

pub use hints::is_context_kind;
pub(crate) use hints::{relay_stack, target_text};

use crate::dialect::{CutLengths, Dialect, DialectPair};
use crate::extract::Layer;
use crate::fanout::FanOut;
use crate::model::{Hit, IndicatorKind, LinkFeature, Observation, Provenance, Tactic, Tier};
use crate::paths::PathStats;
use crate::rules::Rules;
use crate::timing::{DateTagOffset, SharedPause, Span, TimeBasis, TimingStats, infer_offset};
use chrono::NaiveDate;
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

impl ObsResult {
    /// The record's time and the first date tag in its parameters
    /// ([`crate::timing::parse_date_tag`]), when it has both. Parameters
    /// are not serialised, so this reads only an analysis made in this
    /// process.
    pub fn date_tag(&self) -> Option<(i64, NaiveDate)> {
        if self.obs.ts <= 0 {
            return None;
        }
        self.layers
            .iter()
            .flat_map(|l| l.params.iter())
            .find_map(|(_, v)| crate::timing::parse_date_tag(v))
            .map(|d| (self.obs.ts, d))
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Cluster {
    /// Position in this analysis (`C1` is the strongest). Another run over
    /// more records can give the same cluster another number.
    pub id: String,
    /// Stable name (`k-3f9a2c1b`): a hash of its earliest member's record id
    /// (by timestamp, then id), so the cluster keeps it while that record
    /// stays in it, and a record placed beside it later cannot re-key it.
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
    /// The score of the distinct rules seen anywhere in the cluster, read
    /// as one record's ([`crate::rules::Rules::score`]: groups once, context
    /// capped). Descriptive: it does not set the tier.
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
    /// Relay chains of members sent through relays or carriers, outermost
    /// first and ending at the target (`relay.jina → relay.translate_goog →
    /// target`), with how many members used each. Descriptive.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub relay_stacks: BTreeMap<String, usize>,
    /// Members announcing themselves as testing or research, with the
    /// contact they name ([`crate::declared`]). A hint for the case's
    /// handling of authorised testing; never scored.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub declared: Vec<crate::declared::Declared>,
    /// Benchmark targets and stale knowledge (written as `benchmarks` and
    /// `stale_knowledge`).
    #[serde(flatten)]
    pub knowledge: KnowledgeHints,
    /// Prose in members' parameter values and its guessed languages,
    /// against their targets' country domains ([`crate::prose`]).
    /// Descriptive.
    #[serde(default, skip_serializing_if = "crate::prose::Prose::is_empty")]
    pub prose: crate::prose::Prose,
    /// Features that joined members together.
    pub link_features: Vec<LinkFeature>,
    pub runs: Vec<Span>,
    pub timing: TimingStats,
    /// Where its records came from and signs they were planted (written as
    /// `provenance`, `corroboration` and `plant_signals`).
    #[serde(flatten)]
    pub origin: Origin,
    /// How likely an agent, not a person or a tool, sent the requests
    /// ([`crate::agentness`]). Descriptive: never scored, never linked on.
    #[serde(default)]
    pub agent: crate::agentness::AgentAssessment,
    /// Whether the activity went beyond its evident task, and the FM-15.3
    /// tests that decide it ([`crate::scope`]). Inference for review: never
    /// scored, never linked on.
    #[serde(default, skip_serializing_if = "crate::scope::Scope::is_default")]
    pub scope: crate::scope::Scope,
}

/// What the members' targets say about the agent's knowledge
/// ([`crate::knowledge`]). Descriptive: never scored, never linked on.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct KnowledgeHints {
    /// Public benchmark or practice targets the members hit, by
    /// `[[benchmark]]` id: evaluation or training activity, not malice.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub benchmarks: BTreeMap<String, usize>,
    /// Retired endpoints, old client versions and older API versions
    /// repeated across members.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub stale_knowledge: Vec<crate::knowledge::StaleUse>,
}

/// Who could have put a cluster's records where they were found
/// ([`crate::plant`]). For internal review: never scored, never linked on.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Origin {
    /// Members by who can put such a record into its source
    /// ([`Provenance`], written as its label: `submit-anywhere`,
    /// `observed`).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub provenance: BTreeMap<Provenance, usize>,
    /// Whether more than one kind of source, or an operator's logs, stand
    /// behind it ([`crate::plant::corroboration`]). The tier does not read
    /// it.
    #[serde(default)]
    pub corroboration: crate::plant::Corroboration,
    /// Signs it was planted ([`crate::plant`]), never in a public notice.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub plant_signals: Vec<crate::plant::PlantSignal>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AsnSummary {
    pub asn: u32,
    pub org: Option<String>,
    pub count: usize,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
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
    /// lengths, header sets, escalations, common features, captured
    /// secrets), strongest
    /// first. They never merge clusters or change a score.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub soft_links: Vec<crate::fleets::SoftLink>,
    /// Clusters whose combined soft links are strong: proposals for the
    /// admin, never findings.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub candidate_fleets: Vec<crate::fleets::CandidateFleet>,
    /// Pairs of runs whose records suggest agents interacting (SC-T9):
    /// hints for the admin, never scored, never a link or a merge.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub swarm_edges: Vec<crate::swarm::SwarmEdge>,
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
    /// Its value is quoted in a public report (`linking.published_tags`): a
    /// burned identifier, which is no soft link either.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub published: bool,
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

    /// The operator clock offset each cluster's date tags imply, by cluster
    /// id, read as [`Analysis::date_tags`] reads the whole input. Needs the
    /// records' parameters, which are not serialised: call it on an analysis
    /// made in this process.
    pub fn cluster_date_tags(&self) -> BTreeMap<String, DateTagOffset> {
        self.clusters
            .iter()
            .map(|c| {
                let samples: Vec<_> = c
                    .members
                    .iter()
                    .filter_map(|&m| self.results[m].date_tag())
                    .collect();
                (c.id.clone(), infer_offset(&samples))
            })
            .collect()
    }
}

/// Score, link and describe `observations` under `rules`.
pub fn analyze(observations: Vec<Observation>, rules: &Rules) -> Analysis {
    pipeline::run(observations, rules)
}

#[cfg(test)]
mod tests;
