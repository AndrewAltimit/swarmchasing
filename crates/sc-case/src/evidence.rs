//! Logs an affected operator sent back after a report (docs/policies.md,
//! "Operator-supplied logs"), and which renderings may use them.
//!
//! They are case evidence, not public records: private reports use them;
//! the public notice uses them only once the operator's agreement is
//! recorded.

use crate::model::{Case, Contact, ContactRole};
use sc_core::Audience;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperatorEvidence {
    /// `e1`, `e2`, … within the case.
    pub id: String,
    /// The operator that sent the logs.
    pub org: String,
    /// The host the logs belong to.
    pub host: String,
    pub received: String,
    /// SHA-256 of the file as received.
    pub sha256: String,
    /// Lines in the file, and records kept from it.
    pub lines: usize,
    pub kept: usize,
    /// When and how the operator agreed to the public notice using these
    /// records. Unset: private reports only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// Which operator evidence a rendering may use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope<'a> {
    /// Case notes, provider reports, bundles kept with the case.
    All,
    /// A report to one affected operator: its own logs only.
    Operator { org: &'a str, host: Option<&'a str> },
    /// The public notice: only logs the operator agreed to publish.
    Public,
}

impl<'a> Scope<'a> {
    /// The scope of a report for `audience`: all of it in case notes and
    /// provider reports, an operator's own logs in a report to that
    /// operator, and in the notice only logs the operator agreed to publish.
    pub fn for_audience(audience: Audience, to: Option<&'a Contact>) -> Scope<'a> {
        match (audience, to) {
            (Audience::Internal | Audience::Provider, _) => Scope::All,
            (Audience::Public, _) => Scope::Public,
            (Audience::Affected, Some(c)) => Scope::Operator {
                org: &c.org,
                host: c.endpoint.as_deref(),
            },
            (Audience::Affected, None) => Scope::Operator {
                org: "",
                host: None,
            },
        }
    }
}

/// A host's registrable domain (public suffix plus one label), from the
/// caller's Public Suffix List; this crate has none.
pub type Registrable<'f> = &'f dyn Fn(&str) -> Option<String>;

/// Whether hosts `a` and `b` are one registrable domain.
fn same_site(a: &str, b: &str, site: Registrable) -> bool {
    a.eq_ignore_ascii_case(b) || site(a).is_some_and(|x| site(b).is_some_and(|y| x == y))
}

impl Scope<'_> {
    /// The target hosts a rendering for this scope may cover, lowercase:
    /// for an operator, the contact's own endpoint and, when the contact is
    /// that endpoint's affected operator, the endpoints of the case's other
    /// affected contacts at the same organisation under the same
    /// registrable domain (`site`). An organisation name is free text: two
    /// unrelated operators recorded under one name share no registrable
    /// domain and never see each other's hosts. `None` for case notes,
    /// provider reports and the notice, which cover the whole case. A
    /// report to one operator never names another one's hosts or carries
    /// its records.
    pub fn hosts(&self, c: &Case, site: Registrable) -> Option<BTreeSet<String>> {
        let Scope::Operator { org, host } = self else {
            return None;
        };
        let mut out: BTreeSet<String> = host.iter().map(|h| h.to_ascii_lowercase()).collect();
        let Some(host) = host else {
            return Some(out);
        };
        let affected_at =
            |x: &Contact| x.role == ContactRole::Affected && x.org.eq_ignore_ascii_case(org);
        let operator = c.contacts.iter().any(|x| affected_at(x) && x.is_for(host));
        if operator && !org.trim().is_empty() {
            out.extend(
                c.contacts
                    .iter()
                    .filter(|x| affected_at(x))
                    .filter_map(|x| x.endpoint.as_deref())
                    .filter(|e| same_site(e, host, site))
                    .map(str::to_ascii_lowercase),
            );
        }
        Some(out)
    }
}

impl OperatorEvidence {
    /// Whether a rendering for `scope` may use these logs. For an operator:
    /// logs of its own endpoint, or of its organisation under the same
    /// registrable domain (`site`); with no endpoint to compare, the
    /// organisation's name alone.
    pub fn in_scope(&self, scope: &Scope, site: Registrable) -> bool {
        match scope {
            Scope::All => true,
            Scope::Operator { org, host } => match host {
                Some(h) => {
                    self.host.eq_ignore_ascii_case(h)
                        || (self.org.eq_ignore_ascii_case(org) && same_site(&self.host, h, site))
                }
                None => self.org.eq_ignore_ascii_case(org),
            },
            Scope::Public => self.public.is_some(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scope_follows_the_audience() {
        let e = OperatorEvidence {
            id: "e1".into(),
            org: "Portal".into(),
            host: "portal.example.gov".into(),
            received: "d".into(),
            sha256: "00".into(),
            lines: 1,
            kept: 1,
            public: None,
            note: None,
        };
        let site = &last_two;
        assert!(e.in_scope(&Scope::for_audience(Audience::Provider, None), site));
        assert!(!e.in_scope(&Scope::for_audience(Audience::Public, None), site));
        assert!(!e.in_scope(&Scope::for_audience(Audience::Affected, None), site));
        assert!(e.in_scope(
            &Scope::Operator {
                org: "other",
                host: Some("PORTAL.example.gov")
            },
            site
        ));
        // Same organisation and registrable domain: its other host's logs.
        assert!(e.in_scope(
            &Scope::Operator {
                org: "portal",
                host: Some("pay.example.gov")
            },
            site
        ));
        // Same name, another operator's domain: nothing.
        assert!(!e.in_scope(
            &Scope::Operator {
                org: "Portal",
                host: Some("portal.unrelated.example")
            },
            site
        ));
    }

    /// The last two labels, standing in for the Public Suffix List.
    fn last_two(h: &str) -> Option<String> {
        let labels: Vec<&str> = h.split('.').collect();
        (labels.len() >= 2).then(|| labels[labels.len() - 2..].join(".").to_ascii_lowercase())
    }

    #[test]
    fn an_operator_scope_covers_its_own_organisation_only() {
        let contact = |org: &str, role, host: &str| Contact {
            org: org.into(),
            role,
            endpoint: Some(host.into()),
            channel: "email".into(),
            address: format!("security@{host}"),
            source: String::new(),
            confidence: "medium".into(),
            found_on: "d".into(),
            purpose: None,
        };
        let mut c = Case::new("t-1", "t", "d", None);
        c.contacts = vec![
            contact(
                "utility.example",
                ContactRole::Affected,
                "Billing.utility.example",
            ),
            contact(
                "utility.example",
                ContactRole::Affected,
                "pay.utility.example",
            ),
            contact(
                "transit.example",
                ContactRole::Affected,
                "p0.transit.example",
            ),
            // A registrar speaks for many operators; it widens nothing.
            contact("utility.example", ContactRole::Registrar, "other.example"),
            // An unrelated operator recorded under the same name.
            contact(
                "utility.example",
                ContactRole::Affected,
                "portal.hosting-ltd.example",
            ),
        ];
        let site = &last_two;
        let hosts = Scope::for_audience(Audience::Affected, Some(&c.contacts[0]))
            .hosts(&c, site)
            .unwrap();
        assert_eq!(
            hosts.into_iter().collect::<Vec<_>>(),
            ["billing.utility.example", "pay.utility.example"]
        );
        let hosts = Scope::for_audience(Audience::Affected, Some(&c.contacts[3]))
            .hosts(&c, site)
            .unwrap();
        assert_eq!(hosts.into_iter().collect::<Vec<_>>(), ["other.example"]);
        let hosts = Scope::for_audience(Audience::Affected, Some(&c.contacts[4]))
            .hosts(&c, site)
            .unwrap();
        assert_eq!(
            hosts.into_iter().collect::<Vec<_>>(),
            ["portal.hosting-ltd.example"]
        );
        assert!(
            Scope::for_audience(Audience::Affected, None)
                .hosts(&c, site)
                .unwrap()
                .is_empty()
        );
        assert!(Scope::All.hosts(&c, site).is_none());
        assert!(Scope::Public.hosts(&c, site).is_none());
    }
}
