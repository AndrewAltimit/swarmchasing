//! What `case.toml` holds.
//!
//! The enums parse from the words the CLI takes (`FromStr`), so a command
//! line can use them directly; serde names are the `case.toml` spelling.

use crate::evidence::OperatorEvidence;
pub use crate::notice::NoticeStatus;
use sc_core::scope::ScopeFinding;
use sc_core::{Analysis, Claim, EndpointOptions, Evidence, SwarmEdgeKind, endpoints};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Parse `s` as one of `options` (`(word, value)`), ignoring case and
/// treating `-` and `_` alike; the error lists the words.
fn parse_word<T: Copy>(what: &str, s: &str, options: &[(&str, T)]) -> Result<T, String> {
    let norm = |x: &str| x.trim().to_ascii_lowercase().replace('-', "_");
    let want = norm(s);
    options
        .iter()
        .find(|(w, _)| norm(w) == want)
        .map(|(_, v)| *v)
        .ok_or_else(|| {
            let words: Vec<&str> = options.iter().map(|(w, _)| *w).collect();
            format!("unknown {what} `{s}` ({})", words.join("|"))
        })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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

impl CaseStatus {
    pub fn label(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Reported => "reported",
            Self::Published => "published",
            Self::Closed => "closed",
        }
    }
}

impl std::str::FromStr for CaseStatus {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        parse_word(
            "case status",
            s,
            &[
                ("open", Self::Open),
                ("reported", Self::Reported),
                ("published", Self::Published),
                ("closed", Self::Closed),
            ],
        )
    }
}

/// The public notice draft inside a case directory.
pub const NOTICE_DRAFT: &str = "notice.md";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
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

    /// Compromised, targeted or historical: an endpoint a notice names.
    pub fn affected(self) -> bool {
        matches!(self, Self::Compromised | Self::Targeted | Self::Historical)
    }
}

impl std::str::FromStr for EndpointState {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        parse_word(
            "endpoint state",
            s,
            &[
                ("unreviewed", Self::Unreviewed),
                ("compromised", Self::Compromised),
                ("targeted", Self::Targeted),
                ("historical", Self::Historical),
                ("not-affected", Self::NotAffected),
            ],
        )
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
    /// How the indicator notice describes this target without identifying
    /// it ("a national government data portal"). Unset, it is described by
    /// its state only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sector: Option<String>,
}

/// Who a contact is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContactRole {
    /// The AI provider or agent host.
    Provider,
    /// An affected operator.
    Affected,
    /// The registrar's abuse contact for an affected endpoint's domain.
    Registrar,
    /// The hosting network of an affected endpoint.
    Host,
    /// A national or sector CSIRT.
    Csirt,
    /// The declared owner of an "authorised test".
    DeclaredOwner,
    /// A role this toolkit version does not know.
    #[serde(other)]
    Other,
}

impl ContactRole {
    pub fn id(self) -> &'static str {
        match self {
            Self::Provider => "provider",
            Self::Affected => "affected",
            Self::Registrar => "registrar",
            Self::Host => "host",
            Self::Csirt => "csirt",
            Self::DeclaredOwner => "declared_owner",
            Self::Other => "other",
        }
    }

    /// Whether the contact speaks for an affected endpoint (its operator,
    /// registrar or host) rather than for the provider or a responder.
    pub fn for_endpoint(self) -> bool {
        matches!(self, Self::Affected | Self::Registrar | Self::Host)
    }
}

impl std::str::FromStr for ContactRole {
    type Err = String;
    /// The parties a hand-added contact may be for (`case contact add
    /// --party`): `operator` is the affected operator.
    fn from_str(s: &str) -> Result<Self, String> {
        parse_word(
            "party",
            s,
            &[
                ("provider", Self::Provider),
                ("operator", Self::Affected),
                ("affected", Self::Affected),
                ("registrar", Self::Registrar),
                ("host", Self::Host),
                ("csirt", Self::Csirt),
                ("declared-owner", Self::DeclaredOwner),
            ],
        )
    }
}

impl std::fmt::Display for ContactRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.id())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Contact {
    pub org: String,
    pub role: ContactRole,
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

impl Contact {
    /// Whether this contact is for endpoint `host`.
    pub fn is_for(&self, host: &str) -> bool {
        self.endpoint
            .as_deref()
            .is_some_and(|h| h.eq_ignore_ascii_case(host))
    }
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
    /// When it was sent (RFC 3339, UTC). The indicator and naming clocks
    /// run from here.
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
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

impl std::str::FromStr for AlternativeKind {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        let options: Vec<(&str, Self)> = Self::ALL.iter().map(|k| (k.id(), *k)).collect();
        parse_word("alternative", s, &options)
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

/// The draft the naming update is written from, inside a case directory.
pub const NAMING_DRAFT: &str = "naming.md";

/// The two stages of a public notice: the indicator notice, then the naming
/// updates that add affected organisations' names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Stage {
    /// The indicator notice (`notice add`), from `notice.md`.
    Indicators,
    /// A naming update (`notice update --naming`), from `naming.md`.
    Naming,
}

impl Stage {
    pub fn label(self) -> &'static str {
        match self {
            Self::Indicators => "indicator notice",
            Self::Naming => "naming update",
        }
    }

    /// The draft file this stage is written from.
    pub fn draft(self) -> &'static str {
        match self {
            Self::Indicators => NOTICE_DRAFT,
            Self::Naming => NAMING_DRAFT,
        }
    }
}

impl std::str::FromStr for Stage {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        parse_word(
            "stage",
            s,
            &[("indicators", Self::Indicators), ("naming", Self::Naming)],
        )
    }
}

/// A second reviewer's verdict on a draft.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Approve,
    Object,
}

impl Verdict {
    pub fn label(self) -> &'static str {
        match self {
            Self::Approve => "approve",
            Self::Object => "object",
        }
    }
}

impl std::str::FromStr for Verdict {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        parse_word(
            "verdict",
            s,
            &[("approve", Self::Approve), ("object", Self::Object)],
        )
    }
}

/// One second review of one exact draft (`case review`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Review {
    pub stage: Stage,
    pub reviewer: String,
    pub verdict: Verdict,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    /// The SHA-256 of the draft reviewed; an edit to it voids the review.
    pub sha256: String,
    /// RFC 3339.
    pub at: String,
}

/// An operator's written agreement to be named before its naming clock runs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Consent {
    /// The endpoint's host.
    pub party: String,
    /// What the operator said, and where.
    pub note: String,
    /// RFC 3339.
    pub at: String,
}

/// The admin's decision not to name an operator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NamingWithheld {
    /// The endpoint's host.
    pub party: String,
    pub reason: String,
    pub date: String,
}

/// An operator a published naming update named.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Named {
    /// The endpoint's host.
    pub party: String,
    pub date: String,
}

/// The admin's scope finding for one cluster (`case scope`). The analysis
/// suggests one (`Cluster.scope`); this is the decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScopeDecision {
    /// The cluster's stable key.
    pub cluster: String,
    pub finding: ScopeFinding,
    /// The scope tests that failed (`S1`..`S7`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tests: Vec<String>,
    pub note: String,
    pub date: String,
}

/// A scope finding as `case scope --finding` takes it.
pub fn parse_finding(s: &str) -> Result<ScopeFinding, String> {
    parse_word(
        "finding",
        s,
        &[
            ("in-scope", ScopeFinding::InScope),
            ("exceeded", ScopeFinding::ScopeExceeded),
            ("scope-exceeded", ScopeFinding::ScopeExceeded),
            ("not-assessable", ScopeFinding::NotAssessable),
        ],
    )
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
    /// Who decides and publishes for the case. A second review must come
    /// from someone else ([`crate::review`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub admin: Option<String>,
    /// The naming lead for targeted and historical endpoints' operators, in
    /// working days ([`crate::naming::MIN_DAYS`] to [`crate::naming::MAX_DAYS`]);
    /// unset is the minimum. Compromised endpoints' operators wait at least
    /// [`crate::naming::COMPROMISED_DAYS`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub naming_days: Option<u32>,
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
    /// The admin's scope findings, per cluster (`case scope`).
    #[serde(default, rename = "scope", skip_serializing_if = "Vec::is_empty")]
    pub scope_findings: Vec<ScopeDecision>,
    /// Second reviews of the notice and naming drafts (`case review`).
    #[serde(default, rename = "review", skip_serializing_if = "Vec::is_empty")]
    pub reviews: Vec<Review>,
    /// Operators that agreed in writing to be named early (`case consent`).
    #[serde(default, rename = "consent", skip_serializing_if = "Vec::is_empty")]
    pub consents: Vec<Consent>,
    /// Operators the admin decided not to name (`case naming --withhold`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub naming_withheld: Vec<NamingWithheld>,
    /// Operators a published naming update named.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub named: Vec<Named>,
}

/// Check a case id: lowercase letters, digits and hyphens, at most 64
/// characters, not starting with a hyphen. It names a directory.
pub fn check_id(id: &str) -> crate::Result<()> {
    let ok = !id.is_empty()
        && id.len() <= 64
        && id
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        && !id.starts_with('-');
    if !ok {
        crate::bail!(
            "case id `{id}`: use lowercase letters, digits and hyphens (e.g. 2026-10-portal-sqli)"
        );
    }
    Ok(())
}

impl Case {
    /// A new open case, pinned to `rules_version`, with no endpoints yet.
    pub fn new(id: &str, title: &str, opened: &str, rules_version: Option<String>) -> Case {
        Case {
            id: id.to_string(),
            title: title.to_string(),
            status: CaseStatus::Open,
            notice: NoticeStatus::Active,
            opened: opened.to_string(),
            publish_pending: None,
            min_named: Evidence::default(),
            rules_version,
            endpoints: Vec::new(),
            claims: Vec::new(),
            contacts: Vec::new(),
            decisions: Vec::new(),
            sent: Vec::new(),
            evidence: Vec::new(),
            fleets: Vec::new(),
            agent_grade: None,
            admin: None,
            naming_days: None,
            no_contact: Vec::new(),
            alternatives: Vec::new(),
            plant_reviews: Vec::new(),
            drafted: None,
            reread: None,
            scope_findings: Vec::new(),
            reviews: Vec::new(),
            consents: Vec::new(),
            naming_withheld: Vec::new(),
            named: Vec::new(),
        }
    }

    /// `case.toml` text.
    pub fn parse(text: &str) -> crate::Result<Case> {
        toml::from_str(text).map_err(|e| crate::Error(e.to_string()))
    }

    /// The case as `case.toml` text.
    pub fn to_toml(&self) -> crate::Result<String> {
        toml::to_string_pretty(self).map_err(|e| crate::Error(e.to_string()))
    }

    pub fn log(&mut self, today: &str, text: impl Into<String>) {
        self.decisions.push(Decision {
            date: today.to_string(),
            text: text.into(),
        });
    }

    /// Whether the indicator notice was added (published, or pending the
    /// push): the next stage is naming.
    pub fn notice_added(&self) -> bool {
        self.publish_pending.is_some() || self.status == CaseStatus::Published
    }

    /// The stage the next public text is: the indicator notice until it is
    /// added, then naming updates.
    pub fn stage(&self) -> Stage {
        if self.notice_added() {
            Stage::Naming
        } else {
            Stage::Indicators
        }
    }

    /// The admin's latest scope finding for cluster `key`.
    pub fn scope_finding(&self, key: &str) -> Option<&ScopeDecision> {
        self.scope_findings.iter().rev().find(|d| d.cluster == key)
    }

    /// The fleet holding cluster `key`, if the admin grouped it.
    pub fn fleet_of(&self, key: &str) -> Option<&Fleet> {
        self.fleets
            .iter()
            .find(|f| f.clusters.iter().any(|k| k == key))
    }

    /// The endpoint for `host`, any case.
    pub fn endpoint(&self, host: &str) -> Option<&CaseEndpoint> {
        self.endpoints
            .iter()
            .find(|e| e.host.eq_ignore_ascii_case(host))
    }

    /// Hosts of endpoints still unreviewed.
    pub fn unreviewed(&self) -> Vec<&str> {
        self.endpoints
            .iter()
            .filter(|e| e.state == EndpointState::Unreviewed)
            .map(|e| e.host.as_str())
            .collect()
    }

    /// What to tell the admin about unreviewed endpoints, or `None` when
    /// every endpoint is classified: the hosts, defanged, and a
    /// `case endpoint` line ready to run (it takes hosts defanged too).
    pub fn unreviewed_hint(&self) -> Option<String> {
        let hosts = self.unreviewed();
        if hosts.is_empty() {
            return None;
        }
        let shown: Vec<String> = hosts.iter().map(|h| sc_core::defang_host(h)).collect();
        let args: Vec<String> = shown.iter().map(|h| format!("'{h}'")).collect();
        Some(format!(
            "{} endpoint(s) are still unreviewed: {}
  classify them: swarmchase case endpoint {} {} targeted
  (or not-affected, historical, or compromised --basis \"...\")",
            hosts.len(),
            shown.join(", "),
            self.id,
            args.join(" ")
        ))
    }

    /// Contacts in `role`.
    pub fn contacts_in(&self, role: ContactRole) -> impl Iterator<Item = &Contact> {
        self.contacts.iter().filter(move |x| x.role == role)
    }

    /// Add every flagged target host not yet listed, as unreviewed.
    pub fn add_endpoints(&mut self, a: &Analysis) -> usize {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn words_parse_as_the_cli_takes_them() {
        assert_eq!(
            "not-affected".parse::<EndpointState>(),
            Ok(EndpointState::NotAffected)
        );
        assert_eq!(
            "Not_Affected".parse::<EndpointState>(),
            Ok(EndpointState::NotAffected)
        );
        assert!(
            "nope"
                .parse::<EndpointState>()
                .unwrap_err()
                .contains("not-affected")
        );
        assert_eq!("closed".parse::<CaseStatus>(), Ok(CaseStatus::Closed));
        assert_eq!(
            "spoofed-self-id".parse::<AlternativeKind>(),
            Ok(AlternativeKind::SpoofedSelfId)
        );
        assert_eq!("operator".parse::<ContactRole>(), Ok(ContactRole::Affected));
        assert_eq!(
            "declared-owner".parse::<ContactRole>(),
            Ok(ContactRole::DeclaredOwner)
        );
    }

    #[test]
    fn roles_keep_their_case_toml_spelling() {
        let c: Contact = toml::from_str(
            "org = \"o\"\nrole = \"declared_owner\"\nchannel = \"email\"\naddress = \"a@b.example\"\nsource = \"s\"\nconfidence = \"low\"\nfound_on = \"d\"\n",
        )
        .unwrap();
        assert_eq!(c.role, ContactRole::DeclaredOwner);
        assert!(
            toml::to_string(&c)
                .unwrap()
                .contains("role = \"declared_owner\"")
        );
        let odd: Contact = toml::from_str(
            "org = \"o\"\nrole = \"press\"\nchannel = \"email\"\naddress = \"a@b.example\"\nsource = \"s\"\nconfidence = \"low\"\nfound_on = \"d\"\n",
        )
        .unwrap();
        assert_eq!(odd.role, ContactRole::Other);
    }

    #[test]
    fn ids_are_slugs() {
        assert!(check_id("2026-10-portal-sqli").is_ok());
        for bad in ["", "../x", "A", "-x", "a b", "a/b"] {
            assert!(check_id(bad).is_err(), "{bad}");
        }
    }
}
