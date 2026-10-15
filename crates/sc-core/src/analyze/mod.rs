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
pub(crate) use hints::{payload_variants, relay_stack, target_text};
pub(crate) use link::{Tie, TieWhy};

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
    /// The agent grade of a flagged record in no cluster
    /// ([`crate::agentness::assess_record`]). A clustered record reads its
    /// cluster's.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent: Option<crate::agentness::AgentAssessment>,
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
    /// Members' targets each sent to several scan services within seconds
    /// ([`crate::crossservice`]), and whether ordinary links around the
    /// cluster were sent alike. Descriptive: never scored, never linked on.
    #[serde(
        default,
        skip_serializing_if = "crate::crossservice::CrossService::is_empty"
    )]
    pub cross_service: crate::crossservice::CrossService,
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
    /// Declared agent identities of the members, checked against the
    /// providers' published ranges and keys ([`crate::identity`]). Filled by
    /// [`crate::identity::annotate`], not by the pipeline: it needs data the
    /// caller holds. Descriptive: never scored, never linked on.
    #[serde(
        default,
        skip_serializing_if = "crate::identity::ClusterIdentity::is_empty"
    )]
    pub identity: crate::identity::ClusterIdentity,
    /// Members' client addresses by the cloud range they fall in, and those
    /// on the Tor exit list ([`crate::netranges`]). Filled by
    /// [`crate::netranges::annotate`], not by the pipeline. Descriptive:
    /// never scored, never linked on.
    #[serde(
        default,
        skip_serializing_if = "crate::netranges::ClusterHosting::is_empty"
    )]
    pub hosting: crate::netranges::ClusterHosting,
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
    /// Pairs of clusters whose requests share a structure (relay route,
    /// parameter slots, encoding, payloads) beyond chance: a link to check,
    /// never a merge.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scaffold_pairs: Vec<crate::scaffold::ScaffoldPair>,
    /// Pairs of clusters active in the same minutes, or one trailing the
    /// other, beyond a circular-shift chance model: a link to check, never a
    /// merge.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub coactive_pairs: Vec<crate::coactivity::CoActivePair>,
    /// Pairs of clusters working the same rare targets in the same hours
    /// beyond a hypergeometric chance model: a link to check, never a merge.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cotarget_pairs: Vec<crate::cotarget::CoTargetPair>,
    /// Pairs of concurrent clusters that first touched their shared rare
    /// hosts in the same order beyond chance: a link to check, never a
    /// merge.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ordered_cotarget_pairs: Vec<crate::cotarget::OrderedCoTargetPair>,
    /// Pairs of clusters whose request templates are one structural part
    /// apart beyond chance, sharing none outright: one harness changed
    /// mid-fleet. A link to check, never a merge.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub lineage_pairs: Vec<crate::scaffold::LineagePair>,
    /// Pairs of clusters writing prose parameter values from one template
    /// beyond chance: a link to check, never a merge.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub prompt_echo_pairs: Vec<crate::prose::PromptEchoPair>,
    /// Groups of three or more clusters all holding several features few
    /// others hold (rare host families in the same hours, request or prose
    /// templates), beyond a degree-preserving null: a link to check, never a
    /// merge.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub co_groups: Vec<crate::biclique::CoGroup>,
    /// Sites worked by many senders (clusters, and flagged records outside
    /// them) with one habit set that senders elsewhere seldom hold
    /// together, beyond chance: a proposal to check, never a merge.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub campaigns: Vec<crate::campaign::Campaign>,
    /// Pairs of clusters whose generated identifiers decode to one
    /// generator (a UUID node id, a Snowflake worker, a clock skew, a
    /// counter), beyond chance: a link to check, never a merge.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub generator_pairs: Vec<crate::generator::GeneratorPair>,
    /// Pairs of clusters sending one playbook's steps on their hosts in
    /// one order beyond chance: a link to check, never a merge.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub playbook_pairs: Vec<crate::playbook::PlaybookPair>,
    /// Descriptive ties between clusters above noise (shared pauses, payload
    /// dialects, reruns, recon preambles, path sets, encoding, fan-out, cut
    /// lengths, header sets, escalations, common features, captured
    /// secrets, scaffolds, scaffold lineage, prompt echoes, co-activity,
    /// co-targets, ordered co-targets, co-groups, generators), strongest first. They never merge clusters or change a score.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub soft_links: Vec<crate::fleets::SoftLink>,
    /// Clusters whose combined soft links are strong: proposals for the
    /// admin, never findings.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub candidate_fleets: Vec<crate::fleets::CandidateFleet>,
    /// The joint caps its soft links were combined under, when the rules
    /// analysed with set others than the bundled ones (a rules file, a
    /// case's pinned rules): [`Analysis::pair_evidence`] reads them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub joint_caps: Option<crate::fleets::JointCaps>,
    /// Pairs of runs whose records suggest agents interacting (SC-T9):
    /// hints for the admin, never scored, never a link or a merge.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub swarm_edges: Vec<crate::swarm::SwarmEdge>,
    /// Dispatch stars chained where a follower leads a star of its own
    /// (two or more generations): a description of who set off whom,
    /// never scored, never a link or a merge.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dispatch_trees: Vec<crate::swarm::DispatchTree>,
    /// Clusters of different clients that began within minutes of each
    /// other beyond chance ([`crate::swarm::OnsetGroup`]), and those read
    /// as one common trigger: hints, never a link or a merge.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub onset_groups: Vec<crate::swarm::OnsetGroup>,
    /// The multiplicity budget of each family of pairwise tests (shared
    /// pauses, scaffolds, co-activity, the S3 to S6 edges): pairs tested,
    /// kept under a false-discovery cut, and expected by chance.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub multiplicity: Vec<crate::chance::TestFamily>,
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
    /// Its value is quoted in a public report (`linking.published_tags`) or
    /// carries one of our canary tokens ([`crate::canary`]): a burned
    /// identifier, which is no soft link either.
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
    /// Every linked pair's combined evidence, under the joint caps of the
    /// rules it was analysed with, as its candidate fleets were combined.
    pub fn pair_evidence(&self) -> BTreeMap<(String, String), crate::fleets::PairEvidence> {
        match &self.joint_caps {
            Some(caps) => crate::fleets::pair_evidence_with(&self.soft_links, caps),
            None => crate::fleets::pair_evidence(&self.soft_links),
        }
    }

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

    /// Give each cluster the key of the cluster in `reference` that holds
    /// most of its members (by record id), so an analysis of a subset of
    /// `reference`'s records speaks of its clusters in `reference`'s key
    /// space. Clusters are taken largest first; when two share a reference
    /// cluster, the larger keeps its key and the other keeps its own (or,
    /// should its own be one taken here, its own with a `-s<n>` suffix). Run
    /// and onset references to cluster keys follow. Only the keys change:
    /// members, scores and ids stay as analysed.
    pub fn rekey_from(&mut self, reference: &Analysis) {
        use std::collections::BTreeSet;
        let mut home: BTreeMap<&str, usize> = BTreeMap::new();
        for r in &reference.results {
            if let Some(ci) = r.cluster {
                home.entry(r.obs.id.as_str()).or_insert(ci);
            }
        }
        let mut order: Vec<usize> = (0..self.clusters.len()).collect();
        crate::sort::by_key(&mut order, |&ci| {
            (std::cmp::Reverse(self.clusters[ci].members.len()), ci)
        });
        let mut wanted: Vec<Option<String>> = vec![None; self.clusters.len()];
        let mut taken: BTreeSet<String> = BTreeSet::new();
        for &ci in &order {
            let mut votes: BTreeMap<usize, usize> = BTreeMap::new();
            for &m in &self.clusters[ci].members {
                if let Some(&rc) = home.get(self.results[m].obs.id.as_str()) {
                    *votes.entry(rc).or_default() += 1;
                }
            }
            let best = votes
                .iter()
                .max_by(|a, b| a.1.cmp(b.1).then(b.0.cmp(a.0)))
                .map(|(&rc, _)| reference.clusters[rc].key.clone());
            if let Some(k) = best.filter(|k| !k.is_empty() && !taken.contains(k)) {
                taken.insert(k.clone());
                wanted[ci] = Some(k);
            }
        }
        let mut map: BTreeMap<String, String> = BTreeMap::new();
        for &ci in &order {
            let old = self.clusters[ci].key.clone();
            let new = match wanted[ci].take() {
                Some(k) => k,
                None => {
                    let mut k = old.clone();
                    let mut n = 1;
                    while taken.contains(&k) {
                        n += 1;
                        k = format!("{old}-s{n}");
                    }
                    taken.insert(k.clone());
                    k
                }
            };
            if new != old {
                map.insert(old, new.clone());
            }
            self.clusters[ci].key = new;
        }
        if map.is_empty() {
            return;
        }
        let swap = |k: &mut String| {
            if let Some(n) = map.get(k.as_str()) {
                *k = n.clone();
            }
        };
        for e in &mut self.swarm_edges {
            swap(&mut e.a.key);
            swap(&mut e.b.key);
        }
        for g in &mut self.onset_groups {
            g.keys.iter_mut().for_each(swap);
        }
    }
}

/// Score, link and describe `observations` under `rules`.
pub fn analyze(observations: Vec<Observation>, rules: &Rules) -> Analysis {
    pipeline::run(observations, rules)
}

#[cfg(test)]
mod tests;
