//! What `case.toml` holds.

use crate::evidence::OperatorEvidence;
use sc_core::{Analysis, Claim, EndpointOptions, Evidence, endpoints};
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum EndpointState {
    /// Not yet decided by the admin.
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaseEndpoint {
    pub host: String,
    pub state: EndpointState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Sent {
    pub date: String,
    pub recipient: String,
    pub channel: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub report: Option<String>,
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
                    state: EndpointState::Unreviewed,
                    note: None,
                });
                added += 1;
            }
        }
        added
    }
}
