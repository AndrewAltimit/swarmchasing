//! Attribution evidence ladder.
//!
//! Every claim about who is behind a cluster names the strongest class of
//! evidence it rests on, weakest first:
//!
//! 1. self-identification: a model or vendor name in a request. Agents
//!    misreport who built them, and anyone can submit `?agent=claude` to a
//!    public scanner, so this alone never names a developer;
//! 2. hosting network: the ASN the requests came from. It names a host, and
//!    names a developer only when it belongs to the company the requests
//!    self-identify as;
//! 3. identifiers shared with a confirmed incident (inbox IDs, tags);
//! 4. infrastructure owned by the provider;
//! 5. confirmation by the provider.
//!
//! Levels 1–2 come from the records. Levels 3–5 come from case work and are
//! passed in as extra claims. A report names a developer only at or above the
//! level the admin sets, and never below the hosting level.

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    /// Built or runs the agents.
    Developer,
    /// Owns the network the requests came from.
    Host,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Claim {
    pub party: String,
    pub role: Role,
    pub evidence: Evidence,
    /// What the evidence is, one line each, citable.
    #[serde(default)]
    pub details: Vec<String>,
}

impl Claim {
    /// Whether a report may name this party in this role. Hosts are named
    /// as hosts: that is what an ASN shows.
    pub fn nameable(&self, min: Evidence) -> bool {
        match self.role {
            Role::Host => true,
            Role::Developer => self.evidence >= min.max(Evidence::FLOOR),
        }
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

/// Claims the records support for one cluster, strongest first.
pub fn attribute(a: &Analysis, c: &Cluster) -> Vec<Claim> {
    // Developer claims from self-identification: company -> (name, records).
    let mut named: BTreeMap<&str, BTreeMap<String, usize>> = BTreeMap::new();
    for &m in &c.members {
        let mut seen = std::collections::BTreeSet::new();
        for h in a.results[m]
            .hits
            .iter()
            .filter(|h| h.kind == IndicatorKind::SelfId)
        {
            if let Some((company, name)) = vendor_of(&h.matched)
                && seen.insert(name)
            {
                *named
                    .entry(company)
                    .or_default()
                    .entry(name.to_string())
                    .or_default() += 1;
            }
        }
    }
    // Networks the requests came from. On a scan-service record the ASN is
    // where the scanner reached the submitted URL (the target or a relay), so
    // it says nothing about who sent the request and is left out.
    let mut sent_from: BTreeMap<u32, usize> = BTreeMap::new();
    for &m in &c.members {
        let o = &a.results[m].obs;
        if let Some(asn) = o.asn.filter(|_| o.source != crate::urlquery::SOURCE) {
            *sent_from.entry(asn).or_default() += 1;
        }
    }
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
            party: company.to_string(),
            role: Role::Developer,
            evidence,
            details,
        });
    }
    for (&asn, n) in &sent_from {
        claims.push(Claim {
            party: org(asn).unwrap_or_else(|| format!("AS{asn}")),
            role: Role::Host,
            evidence: Evidence::HostingAsn,
            details: vec![format!("{n} record(s) sent from AS{asn}")],
        });
    }
    sort(&mut claims);
    claims
}

/// Add claims established by case work. A party already claimed in the same
/// role keeps one claim at the stronger level, with both sets of details.
pub fn merge(mut claims: Vec<Claim>, extra: &[Claim]) -> Vec<Claim> {
    for x in extra {
        match claims
            .iter_mut()
            .find(|c| c.role == x.role && c.party.eq_ignore_ascii_case(&x.party))
        {
            Some(c) => {
                c.evidence = c.evidence.max(x.evidence);
                c.details.extend(x.details.iter().cloned());
            }
            None => claims.push(x.clone()),
        }
    }
    sort(&mut claims);
    claims
}

fn sort(claims: &mut [Claim]) {
    claims.sort_by(|a, b| {
        a.role
            .cmp(&b.role)
            .then(b.evidence.cmp(&a.evidence))
            .then(a.party.cmp(&b.party))
    });
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
                ..Default::default()
            })
            .collect();
        let a = analyze(obs, &Rules::default_rules());
        assert_eq!(a.clusters.len(), 1, "fixture should form one cluster");
        (a, 0)
    }

    #[test]
    fn self_identification_alone_never_names_a_developer() {
        let (a, c) = cluster_of(Some(16509), "claude");
        let claims = attribute(&a, &a.clusters[c]);
        let dev = claims.iter().find(|c| c.role == Role::Developer).unwrap();
        assert_eq!(
            (dev.party.as_str(), dev.evidence),
            ("Anthropic", Evidence::SelfId)
        );
        assert!(dev.details[0].contains("`claude`"), "{:?}", dev.details);
        assert!(!dev.nameable(Evidence::SelfId), "the floor holds");
        let host = claims.iter().find(|c| c.role == Role::Host).unwrap();
        assert_eq!(host.party, "Amazon AWS");
        assert!(host.nameable(Evidence::ProviderConfirmed));
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

        let merged = merge(
            claims,
            &[Claim {
                party: "tencent".into(),
                role: Role::Developer,
                evidence: Evidence::ProviderConfirmed,
                details: vec!["confirmed by email".into()],
            }],
        );
        assert_eq!(merged[0].evidence, Evidence::ProviderConfirmed);
        assert_eq!(merged[0].details.len(), 3);
        assert!(merged[0].nameable(Evidence::ProviderConfirmed));
    }

    #[test]
    fn scan_service_asn_is_not_where_requests_came_from() {
        let (a, c) = cluster_from(crate::urlquery::SOURCE, Some(132203), "hunyuan");
        let claims = attribute(&a, &a.clusters[c]);
        assert!(claims.iter().all(|c| c.role != Role::Host), "{claims:?}");
        let dev = claims.iter().find(|c| c.role == Role::Developer).unwrap();
        assert_eq!(
            (dev.party.as_str(), dev.evidence),
            ("Tencent", Evidence::SelfId)
        );
    }

    #[test]
    fn levels_parse_and_order() {
        assert_eq!("hosting-asn".parse::<Evidence>(), Ok(Evidence::HostingAsn));
        assert!("vibes".parse::<Evidence>().is_err());
        assert!(Evidence::SelfId < Evidence::ProviderConfirmed);
        assert_eq!(vendor_of("model=GPT-4o"), Some(("OpenAI", "gpt")));
        assert_eq!(vendor_of("someone"), None);
    }
}
