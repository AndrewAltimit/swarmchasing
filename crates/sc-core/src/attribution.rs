//! Attribution in four layers, each on its own evidence (SC-FM 7).
//!
//! "Whose agents are these?" has four answers, and evidence for one is not
//! evidence for another:
//!
//! | Layer | Question | Named in public |
//! |---|---|---|
//! | [`Role::Developer`] | Who built or runs the agents? | through the naming gate |
//! | [`Role::Host`] | Whose network or platform did the requests come from? | as a host only |
//! | [`Role::Harness`] | Which framework or client library drove the model? | never; ranked candidates |
//! | [`Role::ModelFamily`] | Which family of model chose the actions? | never; ranked likelihoods |
//!
//! Developer and operator claims name the strongest class of evidence they
//! rest on, weakest first ([`Evidence`]):
//!
//! 1. self-identification: a model or vendor name in a request. Agents
//!    misreport who built them, and anyone can submit `?agent=claude` to a
//!    public scanner, so this alone never names a developer;
//! 2. hosting network: the ASN the requests came from. It names a host, and
//!    names a developer only when it belongs to the company the requests
//!    self-identify as. A cloud provider's published ranges add the region
//!    and service as description. A Tor exit names no host and no sender:
//!    its records are left out of every claim, and private reports carry a
//!    caution instead ([`tor_caution`], [`crate::netranges`]);
//! 3. identifiers shared with a confirmed incident (inbox IDs, tags);
//! 4. infrastructure owned by the provider;
//! 5. confirmation by the provider.
//!
//! Levels 1–2, hosting networks, sandbox markers and harness traces come from
//! the records ([`attribute`]). Levels 3–5 and model-family rankings come from
//! case work and are passed in as extra claims. Every claim carries a tag
//! ([`Tag`]: Observed, Documented, Inference, Conclusion) and a label derived
//! from its layer and evidence ([`AttributionLabel`]: Confirmed, Suspected, Possible,
//! Unattributed). A report names a developer only at or above the level the
//! admin sets, and never below the hosting level; harness and model-family
//! candidates are never naming-eligible ([`Claim::nameable`]).

use crate::analyze::{Analysis, Cluster};
use crate::model::IndicatorKind;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default,
)]
#[serde(rename_all = "snake_case")]
pub enum Evidence {
    SelfId,
    HostingAsn,
    #[default]
    SharedIdentifiers,
    ProviderInfrastructure,
    ProviderConfirmed,
}

impl Evidence {
    pub const ALL: [Evidence; 5] = [
        Self::SelfId,
        Self::HostingAsn,
        Self::SharedIdentifiers,
        Self::ProviderInfrastructure,
        Self::ProviderConfirmed,
    ];

    /// The weakest level that may name a developer, whatever the admin sets.
    pub const FLOOR: Evidence = Evidence::HostingAsn;

    pub fn id(self) -> &'static str {
        match self {
            Self::SelfId => "self_id",
            Self::HostingAsn => "hosting_asn",
            Self::SharedIdentifiers => "shared_identifiers",
            Self::ProviderInfrastructure => "provider_infrastructure",
            Self::ProviderConfirmed => "provider_confirmed",
        }
    }

    pub fn describe(self) -> &'static str {
        match self {
            Self::SelfId => "self-identification (a model or vendor name in the requests)",
            Self::HostingAsn => "hosting network (ASN)",
            Self::SharedIdentifiers => "identifiers shared with a confirmed incident",
            Self::ProviderInfrastructure => "infrastructure owned by the provider",
            Self::ProviderConfirmed => "confirmed by the provider",
        }
    }
}

impl std::str::FromStr for Evidence {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        let s = s.to_ascii_lowercase().replace('-', "_");
        Self::ALL.into_iter().find(|e| e.id() == s).ok_or_else(|| {
            let ids: Vec<&str> = Self::ALL.iter().map(|e| e.id()).collect();
            format!("unknown evidence level `{s}` ({})", ids.join("|"))
        })
    }
}

/// The attribution layer a claim is about. Serialised as `role` in case
/// files (the name it had when there were two layers); `layer` is read too.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default,
)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    /// Built or runs the agents.
    #[default]
    Developer,
    /// Owns the network or runtime the requests came from.
    Host,
    /// The agent framework, client library or product around the model.
    Harness,
    /// The family of model that chose the actions.
    ModelFamily,
}

impl Role {
    pub const ALL: [Role; 4] = [
        Self::Developer,
        Self::Host,
        Self::Harness,
        Self::ModelFamily,
    ];

    pub fn id(self) -> &'static str {
        match self {
            Self::Developer => "developer",
            Self::Host => "host",
            Self::Harness => "harness",
            Self::ModelFamily => "model_family",
        }
    }

    /// The layer's heading in reports.
    pub fn heading(self) -> &'static str {
        match self {
            Self::Developer => "Developer and operator",
            Self::Host => "Hosting and runtime",
            Self::Harness => "Harness and framework",
            Self::ModelFamily => "Model family",
        }
    }
}

impl std::str::FromStr for Role {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        match s.to_ascii_lowercase().replace('-', "_").as_str() {
            "developer" | "operator" => Ok(Self::Developer),
            "host" | "hosting" | "runtime" => Ok(Self::Host),
            "harness" | "framework" => Ok(Self::Harness),
            "model_family" | "model" => Ok(Self::ModelFamily),
            other => Err(format!(
                "unknown layer `{other}` (developer|host|harness|model_family)"
            )),
        }
    }
}

/// What kind of statement a claim is (SC-FM 7.6, after ICD 203).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Tag {
    /// What a record shows; cites the record and the rule.
    Observed,
    /// What a cited public document states.
    Documented,
    /// Reasoning from Observed and Documented claims.
    Inference,
    /// The judgment the report asks the reader to act on.
    Conclusion,
}

impl Tag {
    pub fn label(self) -> &'static str {
        match self {
            Self::Observed => "Observed",
            Self::Documented => "Documented",
            Self::Inference => "Inference",
            Self::Conclusion => "Conclusion",
        }
    }
}

impl std::str::FromStr for Tag {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        match s.to_ascii_lowercase().as_str() {
            "observed" => Ok(Self::Observed),
            "documented" => Ok(Self::Documented),
            "inference" => Ok(Self::Inference),
            "conclusion" => Ok(Self::Conclusion),
            other => Err(format!(
                "unknown tag `{other}` (observed|documented|inference|conclusion)"
            )),
        }
    }
}

/// An attribution label, set by the layer and the strongest evidence reached
/// (SC-FM 7.7). The label is about evidence; [`AttributionLabel::word`] is the
/// strongest likelihood word it allows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttributionLabel {
    Unattributed,
    Possible,
    Suspected,
    Confirmed,
}

impl AttributionLabel {
    pub fn label(self) -> &'static str {
        match self {
            Self::Unattributed => "Unattributed",
            Self::Possible => "Possible",
            Self::Suspected => "Suspected",
            Self::Confirmed => "Confirmed",
        }
    }

    /// The strongest likelihood word a statement with this label may use.
    /// Unattributed allows none: report what the records say instead.
    pub fn word(self) -> Option<&'static str> {
        match self {
            Self::Confirmed => Some("almost certain"),
            Self::Suspected => Some("very likely"),
            Self::Possible => Some("likely"),
            Self::Unattributed => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct Claim {
    pub party: String,
    #[serde(alias = "layer")]
    pub role: Role,
    pub evidence: Evidence,
    /// What the evidence is, one line each, citable.
    #[serde(default)]
    pub details: Vec<String>,
    /// The claim's tag. Absent in older case files; [`Claim::tag`] derives it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tag: Option<Tag>,
    /// Records carrying the traces, for ranking harness candidates.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub records: usize,
    /// Model family only: the method's likelihood for this family (0..1).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub likelihood: Option<f64>,
    /// Model family only: the method's accuracy on a held-out set (0..1).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accuracy: Option<f64>,
    /// Model family only: the size of the corpus the method was tuned on.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub corpus_size: Option<usize>,
}

fn is_zero(n: &usize) -> bool {
    *n == 0
}

impl Claim {
    /// A claim with no tag or ranking fields set.
    pub fn new(party: impl Into<String>, role: Role, evidence: Evidence) -> Claim {
        Claim {
            party: party.into(),
            role,
            evidence,
            ..Default::default()
        }
    }

    /// Whether a report may name this party in this layer. Hosts are named
    /// as hosts: that is what an ASN shows. Harness and model-family
    /// candidates are never named, whatever their evidence or likelihood.
    pub fn nameable(&self, min: Evidence) -> bool {
        match self.role {
            Role::Host => true,
            Role::Developer => self.evidence >= min.max(Evidence::FLOOR),
            Role::Harness | Role::ModelFamily => false,
        }
    }

    /// A model-family ranking counts only with a held-out measurement: its
    /// accuracy and the size of its corpus (SC-FM 7.5).
    pub fn measured(&self) -> bool {
        self.accuracy.is_some_and(|a| (0.0..=1.0).contains(&a)) && self.corpus_size.unwrap_or(0) > 0
    }

    /// The label set by the layer and the evidence reached.
    pub fn label(&self) -> AttributionLabel {
        match self.role {
            Role::Developer => match self.evidence {
                Evidence::ProviderConfirmed => AttributionLabel::Confirmed,
                Evidence::ProviderInfrastructure | Evidence::SharedIdentifiers => {
                    AttributionLabel::Suspected
                }
                Evidence::HostingAsn => AttributionLabel::Possible,
                Evidence::SelfId => AttributionLabel::Unattributed,
            },
            Role::Host => match self.evidence {
                Evidence::ProviderConfirmed => AttributionLabel::Confirmed,
                Evidence::SelfId => AttributionLabel::Unattributed,
                _ => AttributionLabel::Suspected,
            },
            // Ranked candidates: never stronger than Possible.
            Role::Harness if self.details.is_empty() => AttributionLabel::Unattributed,
            Role::Harness => AttributionLabel::Possible,
            Role::ModelFamily if self.measured() => AttributionLabel::Possible,
            Role::ModelFamily => AttributionLabel::Unattributed,
        }
    }

    /// The claim's tag: as recorded, else derived. A network seen in the
    /// records is Observed; a provider's statement or documented
    /// infrastructure is Documented; everything else is Inference.
    pub fn tag(&self) -> Tag {
        self.tag.unwrap_or(match (self.role, self.evidence) {
            (Role::Host, Evidence::HostingAsn) => Tag::Observed,
            (
                Role::Developer | Role::Host,
                Evidence::ProviderConfirmed | Evidence::ProviderInfrastructure,
            ) => Tag::Documented,
            _ => Tag::Inference,
        })
    }

    /// Problems that stop a claim from being recorded.
    pub fn problems(&self) -> Vec<String> {
        let mut p = Vec::new();
        if self.party.trim().is_empty() {
            p.push("a claim needs a party".to_string());
        }
        if self.role == Role::ModelFamily && !self.measured() {
            p.push(
                "a model-family claim needs the method's held-out accuracy (0..1) and corpus size"
                    .to_string(),
            );
        }
        if self.role != Role::ModelFamily
            && (self.likelihood.is_some() || self.accuracy.is_some() || self.corpus_size.is_some())
        {
            p.push("likelihood, accuracy and corpus size are for model-family claims".to_string());
        }
        if let Some(l) = self.likelihood
            && !(0.0..=1.0).contains(&l)
        {
            p.push(format!("likelihood {l} is outside 0..1"));
        }
        if self.tag == Some(Tag::Conclusion) && !self.nameable(Evidence::FLOOR) {
            p.push(format!(
                "a {} claim is never a Conclusion: it is reported as a ranked candidate",
                self.role.id()
            ));
        }
        p
    }
}

/// Vendor names that agents put in requests, by the company behind them.
const VENDORS: &[(&str, &[&str])] = &[
    ("Anthropic", &["claude", "anthropic"]),
    ("OpenAI", &["chatgpt", "openai", "gpt"]),
    ("Google", &["gemini"]),
    ("Tencent", &["hunyuan"]),
    ("Alibaba", &["qwen"]),
    ("DeepSeek", &["deepseek"]),
    ("Zhipu AI", &["glm"]),
    ("Moonshot AI", &["kimi"]),
];

/// The company and the vendor name found in a self-identification match.
fn vendor_of(matched: &str) -> Option<(&'static str, &'static str)> {
    let m = matched.to_ascii_lowercase();
    VENDORS.iter().find_map(|(company, names)| {
        names
            .iter()
            .find(|n| m.contains(*n))
            .map(|n| (*company, *n))
    })
}

/// The company a self-identification hit names. A header rule's match is
/// the whole header line, whose key ids, nonces and signatures may hold
/// `gpt` or `kimi` by chance, so only the host names in a header line's
/// value are read (`signature-agent: "https://chatgpt.com"`); any other
/// match is read whole.
fn self_id_vendor(matched: &str) -> Option<(&'static str, &'static str)> {
    let Some((name, value)) = matched.split_once(": ") else {
        return vendor_of(matched);
    };
    if name.is_empty() || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
        return vendor_of(matched);
    }
    value
        .split(|c: char| !(c.is_ascii_alphanumeric() || c == '-' || c == '.'))
        .filter(|t| {
            let labels: Vec<&str> = t.split('.').collect();
            labels.len() > 1
                && labels.iter().all(|l| !l.is_empty())
                && labels
                    .last()
                    .is_some_and(|l| l.len() > 1 && l.chars().all(|c| c.is_ascii_alphabetic()))
        })
        .find_map(vendor_of)
}

/// Coding-harness tokens the `header.coding_agent_ua` rule reads, with the
/// harness each names. Two of them sit inside a Mozilla-compatible user agent
/// (Gemini CLI, Aider), so the first-token rule below would call them browser
/// automation.
const HARNESS_UA: &[(&str, &str)] = &[
    ("google-gemini-cli/", "gemini-cli"),
    ("qwencode/", "qwen-code"),
    ("aider/", "aider"),
    ("crush/", "crush"),
];

/// The coding harness a user agent names: a [`HARNESS_UA`] token at the start
/// or after a separator, so `candycrush/2` is not Crush.
fn harness_product(ua: &str) -> Option<&'static str> {
    let lower = ua.to_ascii_lowercase();
    HARNESS_UA.iter().find_map(|(token, name)| {
        lower
            .match_indices(token)
            .any(|(i, _)| {
                lower[..i]
                    .chars()
                    .next_back()
                    .is_none_or(|c| !c.is_ascii_alphanumeric())
            })
            .then_some(*name)
    })
}

/// The product token of a user agent (`python-httpx/0.27` → `python-httpx`),
/// or the coding harness it names.
fn ua_product(ua: &str) -> Option<String> {
    if let Some(h) = harness_product(ua) {
        return Some(h.to_string());
    }
    let p = ua
        .split(['/', ' ', ';', '('])
        .find(|s| !s.is_empty())?
        .to_ascii_lowercase();
    Some(if p == "mozilla" {
        "browser automation (Mozilla-compatible user agent)".to_string()
    } else {
        p
    })
}

/// Who a runtime marker points at: the domain of a marker hostname, defanged
/// (`a.hysandbox.example.com` → `example[.]com` runtime), when the rule
/// matched a host (`host_match`); else the rule. A header line
/// (`via: 1.1 edge`) names no domain, whatever dotted text it carries.
fn marker_party(rule: &str, matched: &str, host_match: bool) -> String {
    let labels: Vec<&str> = if host_match {
        matched
            .split(|c: char| !(c.is_ascii_alphanumeric() || c == '-' || c == '.'))
            .find(|s| s.contains('.'))
            .unwrap_or("")
            .split('.')
            .filter(|l| !l.is_empty())
            .collect()
    } else {
        Vec::new()
    };
    let tld = labels
        .last()
        .is_some_and(|l| l.len() > 1 && l.chars().all(|c| c.is_ascii_alphabetic()));
    match labels.len() {
        n if n >= 2 && tld => format!(
            "{} runtime",
            crate::extract::defang_host(&format!("{}.{}", labels[n - 2], labels[n - 1]))
        ),
        _ => format!("runtime marked by {rule}"),
    }
}

/// The caution a report gives for `n` records sent through Tor exit relays.
/// It is no claim: it names no party and carries no label, because the
/// network the requests left by says nothing about who sent them.
pub fn tor_caution(n: usize) -> String {
    format!(
        "{n} record(s) were sent through Tor exit relays; the network says nothing about the sender. They are left out of the hosting claims, and nothing here attributes them to Tor or to the people who run its relays."
    )
}

/// Claims the records support for one cluster: developer (self-identification
/// and same-company networks), host (client networks and runtime markers)
/// and harness candidates (client traces). Strongest first within a layer.
pub fn attribute(a: &Analysis, c: &Cluster) -> Vec<Claim> {
    // Developer claims from self-identification: company -> (name, records).
    let mut named: BTreeMap<&str, BTreeMap<String, usize>> = BTreeMap::new();
    // Runtime markers (sandbox hostnames, proxy headers):
    // (rule, matched, matched a host) -> records.
    let mut markers: BTreeMap<(String, String, bool), usize> = BTreeMap::new();
    for &m in &c.members {
        let mut seen = std::collections::BTreeSet::new();
        for h in &a.results[m].hits {
            match h.kind {
                IndicatorKind::SelfId => {
                    if let Some((company, name)) = self_id_vendor(&h.matched)
                        && seen.insert(name)
                    {
                        *named
                            .entry(company)
                            .or_default()
                            .entry(name.to_string())
                            .or_default() += 1;
                    }
                }
                IndicatorKind::Infra => {
                    *markers
                        .entry((h.rule_id.clone(), h.matched.to_ascii_lowercase(), true))
                        .or_default() += 1;
                }
                IndicatorKind::Header if h.rule_id.starts_with("header.via_") => {
                    *markers
                        .entry((h.rule_id.clone(), h.matched.to_ascii_lowercase(), false))
                        .or_default() += 1;
                }
                _ => {}
            }
        }
    }
    // Networks the requests came from: the client's `asn`. A target's network
    // (`target_asn`, where a scan service reached the URL) says nothing about
    // who sent the request.
    // A Tor exit names a relay, not the agent's host: those records are
    // left out of every claim. Tor is no party to the incident, so they get
    // no claim of their own; reports say so in a caution ([`tor_caution`]).
    // Published cloud ranges ([`crate::netranges`]) describe the rest.
    let hosting = &c.hosting;
    let mut sent_from: BTreeMap<u32, usize> = BTreeMap::new();
    let mut classed: BTreeMap<u32, BTreeMap<String, usize>> = BTreeMap::new();
    let mut ranges_only: BTreeMap<String, BTreeMap<String, usize>> = BTreeMap::new();
    for &m in &c.members {
        if hosting.tor.contains(&m) {
            continue;
        }
        let class = hosting.members.get(&m);
        match (a.results[m].obs.asn, class) {
            (Some(asn), class) => {
                *sent_from.entry(asn).or_default() += 1;
                if let Some(cl) = class {
                    *classed
                        .entry(asn)
                        .or_default()
                        .entry(cl.label())
                        .or_default() += 1;
                }
            }
            (None, Some(cl)) => {
                *ranges_only
                    .entry(cl.provider.clone())
                    .or_default()
                    .entry(cl.label())
                    .or_default() += 1;
            }
            (None, None) => {}
        }
    }
    let in_ranges = |classes: Option<&BTreeMap<String, usize>>| -> Vec<String> {
        classes
            .into_iter()
            .flatten()
            .map(|(l, n)| format!("{n} of them from {l} published address ranges"))
            .collect()
    };
    let org = |asn: u32| {
        a.asns
            .iter()
            .find(|s| s.asn == asn)
            .and_then(|s| s.org.clone())
    };

    let mut claims = Vec::new();
    for (company, names) in &named {
        let mut details: Vec<String> = names
            .iter()
            .map(|(n, k)| format!("{k} record(s) name `{n}` in a request parameter"))
            .collect();
        let mut evidence = Evidence::SelfId;
        for (&asn, n) in &sent_from {
            if let Some(o) = org(asn).filter(|o| o.to_lowercase().contains(&company.to_lowercase()))
            {
                evidence = Evidence::HostingAsn;
                details.push(format!(
                    "{n} record(s) sent from AS{asn} ({o}), a network of the same company"
                ));
            }
        }
        claims.push(Claim {
            details,
            tag: Some(Tag::Inference),
            ..Claim::new(*company, Role::Developer, evidence)
        });
    }
    for (&asn, n) in &sent_from {
        let mut details = vec![format!("{n} record(s) sent from AS{asn}")];
        details.extend(in_ranges(classed.get(&asn)));
        claims.push(Claim {
            details,
            tag: Some(Tag::Observed),
            records: *n,
            ..Claim::new(
                org(asn).unwrap_or_else(|| format!("AS{asn}")),
                Role::Host,
                Evidence::HostingAsn,
            )
        });
    }
    // Records with no ASN whose address a provider's published ranges hold.
    for (provider, classes) in &ranges_only {
        let n: usize = classes.values().sum();
        claims.push(Claim {
            details: classes
                .iter()
                .map(|(l, k)| format!("{k} record(s) sent from {l} published address ranges"))
                .collect(),
            tag: Some(Tag::Observed),
            records: n,
            ..Claim::new(provider.clone(), Role::Host, Evidence::HostingAsn)
        });
    }
    for ((rule, matched, host), n) in &markers {
        claims.push(Claim {
            details: vec![format!(
                "{n} record(s) carry the runtime marker `{}` (rule {rule})",
                crate::extract::defang_hosts(matched)
            )],
            tag: Some(Tag::Observed),
            records: *n,
            ..Claim::new(
                marker_party(rule, matched, *host),
                Role::Host,
                Evidence::HostingAsn,
            )
        });
    }
    claims.extend(harness(a, c));
    sort(&mut claims);
    claims
}

/// Harness candidates for a cluster: one per client product in the records'
/// user agents, each with the traces its records share (header fingerprint
/// rules, header-name sets, URL encoding style). Ranked by records; tagged
/// Inference; never named.
pub fn harness(a: &Analysis, c: &Cluster) -> Vec<Claim> {
    let mut by_product: BTreeMap<String, (usize, BTreeMap<String, usize>)> = BTreeMap::new();
    let mut header_sets: BTreeMap<String, usize> = BTreeMap::new();
    for &m in &c.members {
        let o = &a.results[m].obs;
        if let Some(ua) = o.user_agent.as_deref().filter(|u| !u.trim().is_empty())
            && let Some(p) = ua_product(ua)
        {
            let e = by_product.entry(p).or_default();
            e.0 += 1;
            *e.1.entry(ua.to_string()).or_default() += 1;
        }
        if let Some(hs) = crate::fingerprint::header_set(&o.headers) {
            *header_sets
                .entry(format!("{} ({})", hs.hash, hs.names.join(", ")))
                .or_default() += 1;
        }
    }
    let mut shared = Vec::new();
    for (rule, n) in c.rules.iter().filter(|(r, _)| r.starts_with("header.")) {
        shared.push(format!(
            "{n} record(s) match header fingerprint rule {rule}"
        ));
    }
    if let Some((hs, n)) = header_sets.iter().max_by_key(|(_, n)| **n) {
        shared.push(format!("{n} record(s) send the header-name set {hs}"));
    }
    if let Some((style, n)) = c.encodings.iter().max_by_key(|(_, n)| **n) {
        shared.push(format!("{n} record(s) encode URLs in style `{style}`"));
    }
    by_product
        .into_iter()
        .map(|(product, (n, uas))| {
            let mut details: Vec<String> = uas
                .iter()
                .map(|(ua, k)| {
                    format!(
                        "{k} record(s) sent User-Agent `{}`",
                        crate::extract::defang_hosts(ua)
                    )
                })
                .collect();
            details.extend(shared.iter().cloned());
            Claim {
                details,
                tag: Some(Tag::Inference),
                records: n,
                ..Claim::new(product, Role::Harness, Evidence::SelfId)
            }
        })
        .collect()
}

/// Add claims established by case work. A party already claimed in the same
/// layer keeps one claim at the stronger level, with both sets of details.
pub fn merge(mut claims: Vec<Claim>, extra: &[Claim]) -> Vec<Claim> {
    for x in extra {
        match claims
            .iter_mut()
            .find(|c| c.role == x.role && c.party.eq_ignore_ascii_case(&x.party))
        {
            Some(c) => {
                // Stronger evidence brings its own tag (or a derived one).
                if x.evidence > c.evidence {
                    c.tag = x.tag;
                } else {
                    c.tag = x.tag.or(c.tag);
                }
                c.evidence = c.evidence.max(x.evidence);
                for d in &x.details {
                    if !c.details.contains(d) {
                        c.details.push(d.clone());
                    }
                }
                c.records += x.records;
                c.likelihood = x.likelihood.or(c.likelihood);
                c.accuracy = x.accuracy.or(c.accuracy);
                c.corpus_size = x.corpus_size.or(c.corpus_size);
            }
            None => claims.push(x.clone()),
        }
    }
    sort(&mut claims);
    claims
}

/// By layer; within a layer, strongest evidence first, harness candidates by
/// records and model families by likelihood.
fn sort(claims: &mut [Claim]) {
    crate::sort::by(claims, |a, b| {
        a.role
            .cmp(&b.role)
            .then(b.evidence.cmp(&a.evidence))
            .then(b.records.cmp(&a.records))
            .then(
                b.likelihood
                    .unwrap_or(0.0)
                    .total_cmp(&a.likelihood.unwrap_or(0.0)),
            )
            .then(a.party.cmp(&b.party))
    });
}

/// A claim per layer, for exports: the party or candidate, its label,
/// likelihood word, evidence level and tag.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LayerSummary {
    pub layer: Role,
    pub party: String,
    pub label: AttributionLabel,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub likelihood_word: Option<String>,
    pub evidence: Evidence,
    pub tag: Tag,
    /// False for every harness and model-family candidate.
    pub nameable: bool,
}

/// Summaries of `claims` for an export, gated as a report for `min` would
/// be: developers below the gate are left out.
pub fn summaries(claims: &[Claim], min: Evidence) -> Vec<LayerSummary> {
    claims
        .iter()
        .filter(|c| c.role != Role::Developer || c.nameable(min))
        .map(|c| LayerSummary {
            layer: c.role,
            party: c.party.clone(),
            label: c.label(),
            likelihood_word: c.label().word().map(str::to_string),
            evidence: c.evidence,
            tag: c.tag(),
            nameable: c.nameable(min),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyze::analyze;
    use crate::model::Observation;
    use crate::rules::Rules;

    fn cluster_of(asn: Option<u32>, agent: &str) -> (Analysis, usize) {
        cluster_from("manual", asn, agent)
    }

    fn cluster_from(source: &str, asn: Option<u32>, agent: &str) -> (Analysis, usize) {
        let obs = (0..4)
            .map(|i| Observation {
                id: format!("r{i}"),
                source: source.to_string(),
                ts: 1_791_000_000 + i * 40,
                url: format!(
                    "https://r.jina.ai/https://portal.example.gov/q?id={i}%20UNION%20SELECT%201&uqtag=zz9&agent={agent}"
                ),
                asn,
                user_agent: Some("python-httpx/0.27".into()),
                ..Default::default()
            })
            // As stored and read back, the way every record reaches analysis.
            .map(|o| serde_json::from_value(serde_json::to_value(o).unwrap()).unwrap())
            .collect();
        let a = analyze(obs, &Rules::default_rules());
        assert_eq!(a.clusters.len(), 1, "fixture should form one cluster");
        (a, 0)
    }

    fn developer(claims: &[Claim]) -> &Claim {
        claims.iter().find(|c| c.role == Role::Developer).unwrap()
    }

    #[test]
    fn self_identification_alone_never_names_a_developer() {
        let (a, c) = cluster_of(Some(16509), "claude");
        let claims = attribute(&a, &a.clusters[c]);
        let dev = developer(&claims);
        assert_eq!(
            (dev.party.as_str(), dev.evidence),
            ("Anthropic", Evidence::SelfId)
        );
        assert!(dev.details[0].contains("`claude`"), "{:?}", dev.details);
        assert!(!dev.nameable(Evidence::SelfId), "the floor holds");
        assert_eq!(dev.label(), AttributionLabel::Unattributed);
        assert_eq!(dev.label().word(), None);
        let host = claims.iter().find(|c| c.role == Role::Host).unwrap();
        assert_eq!(host.party, "Amazon AWS");
        assert!(host.nameable(Evidence::ProviderConfirmed));
        assert_eq!(
            (host.tag(), host.label()),
            (Tag::Observed, AttributionLabel::Suspected)
        );
    }

    #[test]
    fn same_company_network_corroborates() {
        let (a, c) = cluster_of(Some(132203), "hunyuan");
        let claims = attribute(&a, &a.clusters[c]);
        let dev = &claims[0];
        assert_eq!(
            (dev.party.as_str(), dev.role, dev.evidence),
            ("Tencent", Role::Developer, Evidence::HostingAsn)
        );
        assert!(dev.nameable(Evidence::SelfId));
        assert!(!dev.nameable(Evidence::SharedIdentifiers));
        assert_eq!(dev.label(), AttributionLabel::Possible);

        let merged = merge(
            claims,
            &[Claim {
                details: vec!["confirmed by email".into()],
                ..Claim::new("tencent", Role::Developer, Evidence::ProviderConfirmed)
            }],
        );
        assert_eq!(merged[0].evidence, Evidence::ProviderConfirmed);
        assert_eq!(merged[0].details.len(), 3);
        assert!(merged[0].nameable(Evidence::ProviderConfirmed));
        assert_eq!(merged[0].label(), AttributionLabel::Confirmed);
        assert_eq!(merged[0].label().word(), Some("almost certain"));
    }

    #[test]
    fn scan_service_asn_is_not_where_requests_came_from() {
        let (a, c) = cluster_from(crate::urlquery::SOURCE, Some(132203), "hunyuan");
        let claims = attribute(&a, &a.clusters[c]);
        assert!(claims.iter().all(|c| c.role != Role::Host), "{claims:?}");
        let dev = developer(&claims);
        assert_eq!(
            (dev.party.as_str(), dev.evidence),
            ("Tencent", Evidence::SelfId)
        );
        // A stored urlquery record's `asn` was always the target's.
        let o = &a.results[a.clusters[c].members[0]].obs;
        assert_eq!((o.asn, o.target_asn), (None, Some(132203)));
        assert_eq!(o.ts_kind, crate::model::TsKind::Submit);
    }

    #[test]
    fn harness_candidates_are_ranked_inferences_never_named() {
        let (a, c) = cluster_of(None, "claude");
        let claims = attribute(&a, &a.clusters[c]);
        let h = claims.iter().find(|c| c.role == Role::Harness).unwrap();
        assert_eq!(h.party, "python-httpx");
        assert_eq!(h.records, 4);
        assert_eq!(
            (h.tag(), h.label()),
            (Tag::Inference, AttributionLabel::Possible)
        );
        assert!(
            h.details[0].contains("python-httpx/0.27"),
            "{:?}",
            h.details
        );
        assert!(!h.nameable(Evidence::SelfId));
        // Even confirmed by the provider, a harness is a candidate.
        let confirmed = Claim::new("python-httpx", Role::Harness, Evidence::ProviderConfirmed);
        assert!(!confirmed.nameable(Evidence::SelfId));
        assert!(
            Claim {
                tag: Some(Tag::Conclusion),
                ..confirmed
            }
            .problems()
            .iter()
            .any(|p| p.contains("never a Conclusion"))
        );
    }

    #[test]
    fn coding_harness_user_agents_name_their_harness() {
        for (ua, want) in [
            (
                "Mozilla/5.0 (compatible; Google-Gemini-CLI/1.0; +https://github.com/google-gemini/gemini-cli)",
                "gemini-cli",
            ),
            ("QwenCode/0.0.14 (linux; x64)", "qwen-code"),
            (
                "Mozilla/5.0 (X11; Linux x86_64) Chrome/131.0.0.0 Safari/537.36 Aider/0.86.1 +https://aider.chat/",
                "aider",
            ),
            ("Mozilla./5.0 (Aider/0.86.1 +https://aider.chat/)", "aider"),
            ("crush/1.0", "crush"),
            ("python-httpx/0.27.0", "python-httpx"),
            ("CandyCrush/2.1", "candycrush"),
        ] {
            assert_eq!(ua_product(ua).as_deref(), Some(want), "{ua}");
        }
        let rules = Rules::default_rules();
        let pattern = &rules.rule("header.coding_agent_ua").unwrap().pattern;
        let r = regex::RegexBuilder::new(pattern)
            .case_insensitive(true)
            .build()
            .unwrap();
        for (token, _) in HARNESS_UA {
            let ua = match *token {
                "google-gemini-cli/" => "Mozilla/5.0 (compatible; Google-Gemini-CLI/1.0)",
                "qwencode/" => "QwenCode/1.2.3 (linux; arm64)",
                "aider/" => "Mozilla/5.0 Aider/0.1.0 +https://aider.chat/",
                _ => "crush/1.0",
            };
            assert!(r.is_match(ua), "{token} not read by the rule");
        }
    }

    #[test]
    fn model_family_is_never_naming_eligible() {
        let unmeasured = Claim {
            likelihood: Some(0.9),
            ..Claim::new("family-a", Role::ModelFamily, Evidence::ProviderConfirmed)
        };
        assert!(!unmeasured.problems().is_empty(), "no held-out measurement");
        assert_eq!(unmeasured.label(), AttributionLabel::Unattributed);
        let measured = Claim {
            accuracy: Some(0.81),
            corpus_size: Some(1200),
            ..unmeasured.clone()
        };
        assert!(measured.problems().is_empty(), "{:?}", measured.problems());
        assert_eq!(measured.label(), AttributionLabel::Possible);
        for min in Evidence::ALL {
            assert!(!measured.nameable(min), "never named at {min:?}");
        }
        let s = summaries(std::slice::from_ref(&measured), Evidence::SelfId);
        assert!(!s[0].nameable);
        // Ranked by likelihood within the layer.
        let ranked = merge(
            vec![measured],
            &[Claim {
                likelihood: Some(0.95),
                accuracy: Some(0.81),
                corpus_size: Some(1200),
                ..Claim::new("family-b", Role::ModelFamily, Evidence::SelfId)
            }],
        );
        assert_eq!(ranked[0].party, "family-a", "evidence ranks first");
        let only_likelihood = merge(
            vec![Claim {
                likelihood: Some(0.2),
                ..Claim::new("x", Role::ModelFamily, Evidence::SelfId)
            }],
            &[Claim {
                likelihood: Some(0.7),
                ..Claim::new("y", Role::ModelFamily, Evidence::SelfId)
            }],
        );
        assert_eq!(only_likelihood[0].party, "y");
    }

    #[test]
    fn older_case_claims_parse_and_tags_derive() {
        let c: Claim = toml::from_str(
            "party = \"X\"\nrole = \"developer\"\nevidence = \"provider_confirmed\"\ndetails = [\"mail\"]\n",
        )
        .unwrap();
        assert_eq!((c.tag, c.tag()), (None, Tag::Documented));
        let l: Claim =
            toml::from_str("party = \"Y\"\nlayer = \"harness\"\nevidence = \"self_id\"\n").unwrap();
        assert_eq!(l.role, Role::Harness);
        let back = toml::to_string(&c).unwrap();
        assert!(!back.contains("tag"), "{back}");
    }

    #[test]
    fn levels_parse_and_order() {
        assert_eq!("hosting-asn".parse::<Evidence>(), Ok(Evidence::HostingAsn));
        assert!("vibes".parse::<Evidence>().is_err());
        assert!(Evidence::SelfId < Evidence::ProviderConfirmed);
        assert_eq!("model-family".parse::<Role>(), Ok(Role::ModelFamily));
        assert_eq!("Inference".parse::<Tag>(), Ok(Tag::Inference));
        assert_eq!(vendor_of("model=GPT-4o"), Some(("OpenAI", "gpt")));
        assert_eq!(vendor_of("someone"), None);
        assert_eq!(
            ua_product("python-httpx/0.27").as_deref(),
            Some("python-httpx")
        );
    }

    /// A marker's party is a domain only when the rule matched a host, and
    /// that domain prints defanged; a header marker names its rule.
    #[test]
    fn marker_parties_take_a_domain_only_from_a_host() {
        assert_eq!(
            marker_party(
                "header.via_ats",
                "via: 1.1 edge (apachetrafficserver/9.2)",
                false
            ),
            "runtime marked by header.via_ats"
        );
        assert_eq!(
            marker_party(
                "header.via_hysandbox",
                "via: 1.1 a.hysandbox.tencent-cloud.com",
                false
            ),
            "runtime marked by header.via_hysandbox"
        );
        assert_eq!(
            marker_party(
                "infra.hysandbox_host",
                "a1.hysandbox.tencent-cloud.com",
                true
            ),
            "tencent-cloud[.]com runtime"
        );
        assert_eq!(
            marker_party("infra.x", "1.1", true),
            "runtime marked by infra.x"
        );
    }

    /// A header self-identification hit records the whole header line, so
    /// vendor names inside a key id or nonce are no developer claim.
    #[test]
    fn a_header_self_id_line_names_no_vendor() {
        for line in [
            "signature-input: sig1=(\"@authority\");keyid=\"gptglmkimi\";nonce=\"x\";tag=\"agent-browser-auth\"",
            "signature-input: sig1=();keyid=\"poqkLGiym\";nonce=\"ZO3/XMEZjrvSnLtAP9M7jK0WGQf3J+pbmQRUpKDhF9/jsNCWqUh2sq+TH4WTX3/GpNoSZUa8eNWMKqxWp2/c2g==\"",
        ] {
            assert_eq!(self_id_vendor(line), None, "{line}");
        }
        // A signer's directory host is the agent's own name.
        assert_eq!(
            self_id_vendor("signature-agent: \"https://chatgpt.com\""),
            Some(("OpenAI", "chatgpt"))
        );
        // A parameter value is read whole.
        assert_eq!(self_id_vendor("GPT-4o"), Some(("OpenAI", "gpt")));
    }
}
