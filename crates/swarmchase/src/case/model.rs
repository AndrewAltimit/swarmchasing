//! What `case.toml` holds.

use crate::evidence::OperatorEvidence;
use sc_core::{Analysis, Claim, EndpointOptions, Evidence, SwarmEdgeKind, endpoints};
pub use sc_publish::NoticeStatus;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum CaseStatus {
    /// Gathering evidence; nothing sent.
    Open,
    /// Reports sent, notice not yet published.
    Reported,
    /// Notice published.
    Published,
    /// No further action: resolved, or dropped as a false lead.
    Closed,
}

/// The public notice draft inside a case directory.
pub const NOTICE_DRAFT: &str = "notice.md";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum EndpointState {
    /// Not yet decided by the admin.
    #[default]
    Unreviewed,
    /// Evidence that an attack succeeded.
    Compromised,
    /// Attacked or probed recently; no evidence of success.
    Targeted,
    /// Attacked or probed in the past only.
    Historical,
    /// Hit by the swarm but not a target (a relay, a carrier, a fetched page).
    NotAffected,
}

impl EndpointState {
    pub fn label(self) -> &'static str {
        match self {
            Self::Unreviewed => "unreviewed",
            Self::Compromised => "compromised",
            Self::Targeted => "targeted",
            Self::Historical => "historical",
            Self::NotAffected => "not affected",
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CaseEndpoint {
    pub host: String,
    pub state: EndpointState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    /// For a compromised endpoint: what shows the attack succeeded, beyond
    /// the inbound requests (an operator's statement, its logs, a leaked
    /// artifact). A notice says "compromised" only with one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub basis: Option<String>,
    /// Why the notice names this endpoint's operator although every record
    /// on it is submit-anywhere (anyone can submit a URL to a scan service).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub single_source: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Contact {
    pub org: String,
    /// provider | affected (an operator) | registrar | host | csirt |
    /// declared_owner
    pub role: String,
    /// The endpoint this contact is for, when it is for one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    /// email | web_form | portal | phone
    pub channel: String,
    pub address: String,
    /// Where the contact was found (a link).
    pub source: String,
    /// low | medium | high
    pub confidence: String,
    pub found_on: String,
    /// security | abuse, for provider contacts from the directory.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Decision {
    pub date: String,
    pub text: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Sent {
    pub date: String,
    pub recipient: String,
    pub channel: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub report: Option<String>,
    /// When it was sent (RFC 3339, UTC). The lead time runs from here.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub at: Option<String>,
}

impl Sent {
    /// The send time as a Unix timestamp. A send recorded with a date only
    /// counts from the end of that day.
    pub fn time(&self) -> Option<i64> {
        match &self.at {
            Some(at) => parse_time(at),
            None => parse_time(&format!("{}T23:59:59Z", self.date)),
        }
    }
}

/// A Unix timestamp from RFC 3339 text.
pub fn parse_time(s: &str) -> Option<i64> {
    chrono::DateTime::parse_from_rfc3339(s.trim())
        .ok()
        .map(|d| d.timestamp())
}

/// RFC 3339 text (UTC, seconds) for a Unix timestamp.
pub fn rfc3339(ts: i64) -> String {
    chrono::DateTime::<chrono::Utc>::from_timestamp(ts, 0)
        .map(|d| d.format("%Y-%m-%dT%H:%M:%SZ").to_string())
        .unwrap_or_default()
}

/// A time as the admin reads it: `2026-10-12 18:00 UTC`.
pub fn show_time(ts: i64) -> String {
    chrono::DateTime::<chrono::Utc>::from_timestamp(ts, 0)
        .map(|d| d.format("%Y-%m-%d %H:%M UTC").to_string())
        .unwrap_or_default()
}

/// A party the admin could not reach: no security, abuse or registrar
/// contact was found (`case no-contact`). The notice may publish without a
/// send to it, and says contact was attempted.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NoContact {
    /// An endpoint's host, or a provider's organisation.
    pub party: String,
    /// What was tried.
    pub searched: String,
    /// RFC 3339.
    pub at: String,
}

/// An innocent or misleading explanation the self-review checklist asks
/// about before a notice is added.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, clap::ValueEnum,
)]
#[serde(rename_all = "kebab-case")]
pub enum AlternativeKind {
    /// An authorised red-team or research evaluation.
    AuthorisedTest,
    /// A honeypot or canary that drew or staged the activity.
    Honeypot,
    /// A research or commercial scanner, not an agent.
    ResearchScanner,
    /// Self-identification written by someone else to mislead.
    SpoofedSelfId,
    /// Records placed in public sources to be found.
    PlantedRecords,
}

impl AlternativeKind {
    pub const ALL: [AlternativeKind; 5] = [
        Self::AuthorisedTest,
        Self::Honeypot,
        Self::ResearchScanner,
        Self::SpoofedSelfId,
        Self::PlantedRecords,
    ];

    pub fn id(self) -> &'static str {
        match self {
            Self::AuthorisedTest => "authorised-test",
            Self::Honeypot => "honeypot",
            Self::ResearchScanner => "research-scanner",
            Self::SpoofedSelfId => "spoofed-self-id",
            Self::PlantedRecords => "planted-records",
        }
    }
}

/// The admin's decision on one alternative explanation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alternative {
    pub kind: AlternativeKind,
    /// `rejected`, or `accepted` (an authorised test its owner confirmed).
    pub verdict: String,
    /// Why, with links.
    pub why: String,
    pub date: String,
}

/// The admin's acknowledgement of a cluster's plant signals.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlantReview {
    /// The cluster's stable key.
    pub cluster: String,
    pub note: String,
    pub date: String,
}

/// A notice draft's content hash and a time: when `case notice` wrote it,
/// or when the admin re-read it (`case reread`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DraftStamp {
    pub sha256: String,
    /// RFC 3339.
    pub at: String,
}

/// Clusters the admin decided to treat as one fleet (`case fleet merge`):
/// one operator behind several runs. Never set by the analysis itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Fleet {
    /// `fleet-1`, `fleet-2`, ... within the case.
    pub id: String,
    /// Stable cluster keys (`k-3f9a2c1b`), sorted.
    pub clusters: Vec<String>,
    /// When the grouping last changed.
    pub since: String,
    /// Interaction between the fleet's runs that the admin reviewed and
    /// accepts (`case fleet interaction`). Reports and notices call the
    /// fleet a swarm only while this holds an entry.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub swarm_evidence: Vec<SwarmEvidence>,
}

impl Fleet {
    /// Whether reviewed interaction evidence makes the fleet a swarm.
    pub fn is_swarm(&self) -> bool {
        !self.swarm_evidence.is_empty()
    }

    /// `fleet` or `swarm`.
    pub fn noun(&self) -> &'static str {
        if self.is_swarm() { "swarm" } else { "fleet" }
    }
}

/// One piece of interaction evidence the admin accepted for a fleet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwarmEvidence {
    /// What it rests on (`handoff`, `shared_sink`, ...).
    pub kind: SwarmEdgeKind,
    /// The runs involved, as `<cluster key>#<run>`.
    pub runs: Vec<String>,
    /// The admin's reading of the records.
    pub note: String,
    pub date: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Case {
    pub id: String,
    pub title: String,
    pub status: CaseStatus,
    pub notice: NoticeStatus,
    pub opened: String,
    /// Set by `notice add` (the date) until `notice published` confirms the
    /// notice reached the repository's remote: added, not yet public.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub publish_pending: Option<String>,
    /// Weakest evidence that may name a developer outside case notes.
    #[serde(default)]
    pub min_named: Evidence,
    /// The rule set the case renders with, kept at `<data>/rules/<name>.toml`.
    /// Absent in case files from before pinning; those render with the
    /// current rules.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rules_version: Option<String>,
    #[serde(default, rename = "endpoint", skip_serializing_if = "Vec::is_empty")]
    pub endpoints: Vec<CaseEndpoint>,
    /// Attribution established by case work (shared identifiers, provider
    /// infrastructure, provider confirmation). The records' own claims are
    /// derived on every report.
    #[serde(default, rename = "claim", skip_serializing_if = "Vec::is_empty")]
    pub claims: Vec<Claim>,
    #[serde(default, rename = "contact", skip_serializing_if = "Vec::is_empty")]
    pub contacts: Vec<Contact>,
    #[serde(default, rename = "decision", skip_serializing_if = "Vec::is_empty")]
    pub decisions: Vec<Decision>,
    #[serde(default, rename = "sent", skip_serializing_if = "Vec::is_empty")]
    pub sent: Vec<Sent>,
    /// Logs affected operators sent us (`case evidence`).
    #[serde(default, rename = "evidence", skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<OperatorEvidence>,
    /// The admin's fleet grouping of the case's clusters, by stable key.
    #[serde(default, rename = "fleet", skip_serializing_if = "Vec::is_empty")]
    pub fleets: Vec<Fleet>,
    /// The admin's agent grade for the case (`case grade`), the only way to
    /// L5 (documented). Reports show it beside the computed grades.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_grade: Option<sc_core::GradeDecision>,
    /// The lead time for targeted and historical endpoints' operators, in
    /// hours (4 to 12); unset is the default ([`super::lead::OPERATOR_DEFAULT`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lead_hours: Option<u32>,
    /// Parties no contact was found for.
    #[serde(default, rename = "no_contact", skip_serializing_if = "Vec::is_empty")]
    pub no_contact: Vec<NoContact>,
    /// Alternative explanations the admin decided on.
    #[serde(default, rename = "alternative", skip_serializing_if = "Vec::is_empty")]
    pub alternatives: Vec<Alternative>,
    /// Plant signals the admin reviewed, per cluster.
    #[serde(
        default,
        rename = "plant_review",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub plant_reviews: Vec<PlantReview>,
    /// The notice draft `case notice` last wrote.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub drafted: Option<DraftStamp>,
    /// The admin's last re-read of the notice draft (`case reread`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reread: Option<DraftStamp>,
}

impl Case {
    pub fn log(&mut self, today: &str, text: impl Into<String>) {
        self.decisions.push(Decision {
            date: today.to_string(),
            text: text.into(),
        });
    }

    /// The fleet holding cluster `key`, if the admin grouped it.
    pub fn fleet_of(&self, key: &str) -> Option<&Fleet> {
        self.fleets
            .iter()
            .find(|f| f.clusters.iter().any(|k| k == key))
    }

    /// Add every flagged target host not yet listed, as unreviewed.
    pub(crate) fn add_endpoints(&mut self, a: &Analysis) -> usize {
        let known: BTreeSet<String> = self.endpoints.iter().map(|e| e.host.clone()).collect();
        let mut added = 0;
        for v in endpoints(a, &EndpointOptions::default()) {
            if !known.contains(&v.host) {
                self.endpoints.push(CaseEndpoint {
                    host: v.host,
                    ..Default::default()
                });
                added += 1;
            }
        }
        added
    }
}
