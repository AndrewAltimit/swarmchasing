//! The provider directory ([`sc_case::providers`]) applied to a case:
//! seeding provider contacts from the claims that name a provider.

pub use sc_case::providers::{DirContact, Directory, PROVIDERS, Provider, case_channel};

use crate::case::{Case, Contact, ContactRole};
use anyhow::Result;
use std::io::Write;

/// Add the directory's contacts for every provider a developer or host claim
/// names. Returns how many were added.
pub fn seed_providers(
    c: &mut Case,
    claims: &[sc_core::Claim],
    dir: &Directory,
    today: &str,
    out: &mut impl Write,
) -> Result<usize> {
    let mut added = 0;
    let mut seen = std::collections::BTreeSet::new();
    for cl in claims
        .iter()
        .filter(|x| matches!(x.role, sc_core::Role::Developer | sc_core::Role::Host))
    {
        let Some(p) = dir.find(&cl.party) else {
            continue;
        };
        if !seen.insert(p.name.clone()) {
            continue;
        }
        for d in &p.contacts {
            if c.contacts
                .iter()
                .any(|y| y.address.eq_ignore_ascii_case(&d.address))
            {
                continue;
            }
            writeln!(
                out,
                "{} (provider, {} claim): {} {} for {} ({}, verified {})",
                p.name,
                cl.role.id(),
                d.channel,
                d.address,
                d.purpose,
                d.source,
                d.verified
            )?;
            c.contacts.push(Contact {
                org: p.name.clone(),
                role: ContactRole::Provider,
                endpoint: None,
                channel: case_channel(&d.channel)?.into(),
                address: d.address.clone(),
                source: d.source.clone(),
                confidence: "medium".into(),
                found_on: d.verified.clone(),
                purpose: Some(d.purpose.clone()),
            });
            added += 1;
        }
        if let Some(n) = &p.note {
            writeln!(out, "{}: note: {n}", p.name)?;
        }
    }
    if added > 0 {
        c.log(
            today,
            format!("provider contacts: {added} added from the provider directory"),
        );
    }
    Ok(added)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sc_core::{Claim, Evidence, Role};

    #[test]
    fn provider_contacts_are_seeded_from_claims() {
        let mut c: Case = toml::from_str(
            "id = \"t\"\ntitle = \"T\"\nstatus = \"open\"\nnotice = \"active\"\nopened = \"2026-10-12\"\n",
        )
        .unwrap();
        let claims = vec![
            Claim::new("Tencent", Role::Developer, Evidence::SelfId),
            Claim::new("Amazon AWS", Role::Host, Evidence::HostingAsn),
            Claim::new("python-httpx", Role::Harness, Evidence::SelfId),
        ];
        let d = Directory::builtin();
        let mut out = Vec::new();
        let n = seed_providers(&mut c, &claims, &d, "2026-10-13", &mut out).unwrap();
        assert!(n >= 3, "{}", String::from_utf8_lossy(&out));
        assert!(c.contacts.iter().all(|x| x.role == ContactRole::Provider));
        assert!(c.contacts.iter().any(|x| x.org == "Tencent Cloud"));
        assert!(c.contacts.iter().any(|x| x.org == "Amazon Web Services"));
        assert!(
            c.contacts
                .iter()
                .any(|x| x.channel == "web_form" && x.purpose.as_deref() == Some("abuse"))
        );
        // Seeding again adds nothing.
        assert_eq!(
            seed_providers(&mut c, &claims, &d, "2026-10-13", &mut out).unwrap(),
            0
        );
        assert_eq!(c.decisions.len(), 1);
    }
}
