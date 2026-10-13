//! Contact discovery for a case's endpoints: the first security.txt on the
//! host or its parent domains, else the registrar's abuse contact from RDAP,
//! each domain read once a run.
//!
//! Only endpoints the admin classified compromised, targeted or historical
//! are looked up, and never a host the rules call a relay, carrier or
//! callback service: reading `<inbox>/.well-known/security.txt` would touch
//! the agent's own callback channel, which collection never does.

use super::parse::{domain_candidates, from_security_txt, rdap_abuse, registered_domain};
use crate::case::{Case, Contact, ContactRole, EndpointState};
use anyhow::Result;
use std::collections::HashMap;
use std::io::Write;

/// The reads contact discovery makes: a domain's security.txt and its RDAP
/// record, each as `(url, body)`, `None` when it could not be read.
pub trait Lookup {
    fn security_txt(&self, domain: &str) -> Option<(String, String)>;
    fn rdap_domain(&self, domain: &str) -> Option<(String, String)>;
}

impl Lookup for sc_collect::Client {
    fn security_txt(&self, domain: &str) -> Option<(String, String)> {
        sc_collect::Client::security_txt(self, domain).ok()
    }
    fn rdap_domain(&self, domain: &str) -> Option<(String, String)> {
        sc_collect::Client::rdap_domain(self, domain).ok()
    }
}

/// [`Lookup`] answers kept for one run, by domain. Subdomains of one
/// registered domain all fall back to its security.txt and its RDAP record,
/// so each is read once a run, not once per host. A failed read is kept too
/// and not retried within the run.
struct RunCache<'a, L: Lookup> {
    inner: &'a L,
    security_txt: HashMap<String, Option<(String, String)>>,
    rdap: HashMap<String, Option<(String, String)>>,
}

impl<'a, L: Lookup> RunCache<'a, L> {
    fn new(inner: &'a L) -> Self {
        Self {
            inner,
            security_txt: HashMap::new(),
            rdap: HashMap::new(),
        }
    }

    fn security_txt(&mut self, domain: &str) -> Option<(String, String)> {
        let inner = self.inner;
        self.security_txt
            .entry(domain.to_ascii_lowercase())
            .or_insert_with(|| inner.security_txt(domain))
            .clone()
    }

    fn rdap_domain(&mut self, domain: &str) -> Option<(String, String)> {
        let inner = self.inner;
        self.rdap
            .entry(domain.to_ascii_lowercase())
            .or_insert_with(|| inner.rdap_domain(domain))
            .clone()
    }
}

/// Find contacts for the case's affected endpoints. `off_limits` says
/// whether a host is a relay, carrier or callback host; neither such a host
/// nor any parent domain of one is ever read.
pub fn find_contacts(
    c: &mut Case,
    client: &impl Lookup,
    off_limits: &dyn Fn(&str) -> bool,
    refresh: bool,
    today: &str,
    out: &mut impl Write,
) -> Result<()> {
    let mut client = RunCache::new(client);
    let unreviewed = c
        .endpoints
        .iter()
        .filter(|e| e.state == EndpointState::Unreviewed)
        .count();
    if unreviewed > 0 {
        writeln!(
            out,
            "{unreviewed} unreviewed endpoint(s) not looked up; classify them with `case endpoint` first"
        )?;
    }
    let hosts: Vec<String> = c
        .endpoints
        .iter()
        .filter(|e| e.state.affected())
        .filter(|e| {
            refresh
                || !c
                    .contacts
                    .iter()
                    .any(|x| x.endpoint.as_ref() == Some(&e.host))
        })
        .map(|e| e.host.clone())
        .collect();
    for host in hosts {
        let shown = sc_core::defang_host(&host);
        if off_limits(&host) {
            writeln!(
                out,
                "{shown}: a relay, carrier or callback host by the rules; not looked up (passive only)"
            )?;
            c.log(
                today,
                format!("contacts for {host}: not looked up (relay, carrier or callback host)"),
            );
            continue;
        }
        let mut found = Vec::new();
        let mut how = "nothing found";
        for d in domain_candidates(&host)
            .into_iter()
            .filter(|d| !off_limits(d))
        {
            if let Some((url, body)) = client.security_txt(&d) {
                let s = sc_core::parse_security_txt(&body);
                found = from_security_txt(&d, &url, &s, today);
                how = "security.txt";
                break;
            }
        }
        if found.is_empty() {
            let domain = registered_domain(&host);
            if let Some((url, body)) = client.rdap_domain(&domain) {
                found = rdap_abuse(&body)
                    .into_iter()
                    .map(|(org, email)| Contact {
                        org,
                        role: ContactRole::Registrar,
                        endpoint: None,
                        channel: "email".into(),
                        address: email,
                        source: url.clone(),
                        confidence: "low".into(),
                        found_on: today.to_string(),
                        purpose: None,
                    })
                    .collect();
                if !found.is_empty() {
                    how = "RDAP registrar abuse contact (fallback)";
                }
            }
        }
        let mut added = 0;
        for mut x in found {
            x.endpoint = Some(host.clone());
            if !c
                .contacts
                .iter()
                .any(|y| y.endpoint == x.endpoint && y.address.eq_ignore_ascii_case(&x.address))
            {
                writeln!(
                    out,
                    "{shown}: {} {} ({}, {} confidence)",
                    x.channel, x.address, x.source, x.confidence
                )?;
                c.contacts.push(x);
                added += 1;
            }
        }
        if added == 0 {
            writeln!(out, "{shown}: {how}, nothing new")?;
        }
        c.log(today, format!("contacts for {host}: {added} new ({how})"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Answers from fixed maps, counting every read by domain.
    #[derive(Default)]
    struct Fake {
        security_txt: std::collections::BTreeMap<&'static str, &'static str>,
        rdap: std::collections::BTreeMap<&'static str, &'static str>,
        reads: std::cell::RefCell<Vec<String>>,
    }

    impl Lookup for Fake {
        fn security_txt(&self, domain: &str) -> Option<(String, String)> {
            self.reads
                .borrow_mut()
                .push(format!("security.txt {domain}"));
            let body = self.security_txt.get(domain)?;
            Some((
                format!("https://{domain}/.well-known/security.txt"),
                body.to_string(),
            ))
        }
        fn rdap_domain(&self, domain: &str) -> Option<(String, String)> {
            self.reads.borrow_mut().push(format!("rdap {domain}"));
            let body = self.rdap.get(domain)?;
            Some((
                format!("https://rdap.org/domain/{domain}"),
                body.to_string(),
            ))
        }
    }

    #[test]
    fn one_run_reads_each_domain_once() {
        use crate::case::{CaseEndpoint, EndpointState};
        let mut c: Case = toml::from_str(
            "id = \"t\"\ntitle = \"T\"\nstatus = \"open\"\nnotice = \"active\"\nopened = \"2026-10-12\"\n",
        )
        .unwrap();
        for h in [
            "a.shop.example.org",
            "b.shop.example.org",
            "c.example.org",
            "x.agency.example.co.uk",
            "y.agency.example.co.uk",
        ] {
            c.endpoints.push(CaseEndpoint {
                host: h.into(),
                state: EndpointState::Targeted,
                ..Default::default()
            });
        }
        let fake = Fake {
            security_txt: [("example.org", "Contact: mailto:security@example.org\n")].into(),
            rdap: [(
                "example.co.uk",
                r#"{"entities":[{"roles":["abuse"],"vcardArray":["vcard",[["fn",{},"text","Reg"],["email",{},"text","abuse@reg.example"]]]}]}"#,
            )]
            .into(),
            ..Fake::default()
        };
        let mut out = Vec::new();
        find_contacts(&mut c, &fake, &|_| false, false, "2026-10-12", &mut out).unwrap();
        let reads = fake.reads.borrow();
        let count = |r: &str| reads.iter().filter(|x| *x == r).count();
        // Every host's own candidates are read; the shared parents once.
        assert_eq!(count("security.txt a.shop.example.org"), 1);
        assert_eq!(count("security.txt shop.example.org"), 1, "{reads:?}");
        assert_eq!(count("security.txt example.org"), 1, "{reads:?}");
        assert_eq!(count("security.txt example.co.uk"), 1, "{reads:?}");
        assert_eq!(count("rdap example.co.uk"), 1, "{reads:?}");
        assert!(!reads.iter().any(|r| r == "rdap example.org"), "{reads:?}");
        // Each host still gets its contacts.
        for (host, address) in [
            ("a.shop.example.org", "security@example.org"),
            ("b.shop.example.org", "security@example.org"),
            ("c.example.org", "security@example.org"),
            ("x.agency.example.co.uk", "abuse@reg.example"),
            ("y.agency.example.co.uk", "abuse@reg.example"),
        ] {
            assert!(
                c.contacts
                    .iter()
                    .any(|x| x.endpoint.as_deref() == Some(host) && x.address == address),
                "{host}: {:?}",
                c.contacts
            );
        }
    }
    #[test]
    fn callback_hosts_and_unclassified_endpoints_are_never_read() {
        use crate::case::{CaseEndpoint, EndpointState};
        let mut c: Case = toml::from_str(
            "id = \"t\"\ntitle = \"T\"\nstatus = \"open\"\nnotice = \"active\"\nopened = \"2026-10-12\"\n",
        )
        .unwrap();
        for (h, state) in [
            ("c3k9q2x7v1.oast.fun", EndpointState::Targeted),
            ("webhook.site", EndpointState::Compromised),
            ("unsure.b.example", EndpointState::Unreviewed),
            ("relay.c.example", EndpointState::NotAffected),
            ("shop.a.example", EndpointState::Targeted),
        ] {
            c.endpoints.push(CaseEndpoint {
                host: h.into(),
                state,
                ..Default::default()
            });
        }
        // The record the case holds names a webhook.site inbox by its id.
        let rules = sc_core::Rules::default_rules();
        let rec = sc_core::Observation {
            url: "https://webhook.site/0f1e2d3c-4b5a-6978-8a9b-0c1d2e3f4a5b".into(),
            ..Default::default()
        };
        let from_records = sc_core::intermediary_hosts(&rec, &rules);
        let off = |h: &str| {
            sc_core::is_intermediary_host(&rules, h)
                || from_records.contains(&h.to_ascii_lowercase())
        };
        let fake = Fake::default();
        let mut out = Vec::new();
        find_contacts(&mut c, &fake, &off, false, "2026-10-12", &mut out).unwrap();
        let reads = fake.reads.borrow();
        for bad in [
            "oast.fun",
            "webhook.site",
            "unsure.b.example",
            "relay.c.example",
        ] {
            assert!(!reads.iter().any(|r| r.contains(bad)), "{bad}: {reads:?}");
        }
        assert!(
            reads.iter().any(|r| r == "security.txt shop.a.example"),
            "{reads:?}"
        );
        let out = String::from_utf8(out).unwrap();
        assert!(out.contains("c3k9q2x7v1[.]oast[.]fun: a relay"), "{out}");
        assert!(out.contains("1 unreviewed endpoint(s)"), "{out}");
    }
}
