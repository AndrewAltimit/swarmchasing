//! National CSIRTs, by country: the committed directory
//! `contacts/csirts.toml`, built from FIRST's public team directory, and the
//! `case contacts` step that proposes them for affected endpoints.
//!
//! An endpoint's country is its host's country-code top-level domain (an
//! entry's `tlds`, default its lowercased `country`), or the admin's
//! `--country`. Each proposed contact has role `csirt`, the FIRST page the
//! address was read from, and that page's verified date. Nothing is
//! fetched: the directory is built in, and `swarmchase contacts verify
//! --csirts` re-reads its sources for the admin.

use crate::case::{Case, Contact, EndpointState};
use crate::contacts::{DirContact, Directory, Provider, case_channel};
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;

/// The CSIRT directory committed at `contacts/csirts.toml`, built in.
pub const CSIRTS: &str = include_str!("../../../contacts/csirts.toml");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Csirts {
    #[serde(default, rename = "csirt")]
    pub teams: Vec<Csirt>,
}

/// One national team.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Csirt {
    /// ISO 3166-1 alpha-2, upper case.
    pub country: String,
    /// Top-level domains that place a host in this country. Default: the
    /// lowercased country code.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tlds: Vec<String>,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub official: Option<String>,
    /// email | form | portal
    pub channel: String,
    pub address: String,
    /// The page the address was read from.
    pub source: String,
    /// When it was last read there.
    pub verified: String,
}

impl Csirt {
    fn tlds(&self) -> Vec<String> {
        if self.tlds.is_empty() {
            vec![self.country.to_ascii_lowercase()]
        } else {
            self.tlds.iter().map(|t| t.to_ascii_lowercase()).collect()
        }
    }
}

impl Csirts {
    pub fn parse(text: &str) -> Result<Csirts> {
        let d: Csirts = toml::from_str(text).context("parsing the CSIRT directory")?;
        let problems = d.problems();
        if !problems.is_empty() {
            bail!("CSIRT directory: {}", problems.join("; "));
        }
        Ok(d)
    }

    pub fn builtin() -> Csirts {
        Csirts::parse(CSIRTS).expect("contacts/csirts.toml is checked by its tests")
    }

    /// Entries that break the directory's rules: a two-letter country, at
    /// most one team per country and TLD, an https source, a verified date,
    /// a known channel that fits the address.
    pub fn problems(&self) -> Vec<String> {
        let mut out = Vec::new();
        let mut countries = BTreeSet::new();
        let mut tlds = BTreeSet::new();
        for t in &self.teams {
            let at = format!("{} ({})", t.name, t.country);
            if t.country.len() != 2 || !t.country.chars().all(|c| c.is_ascii_uppercase()) {
                out.push(format!("{at}: country is not an ISO 3166-1 alpha-2 code"));
            }
            if !countries.insert(t.country.clone()) {
                out.push(format!("{at}: a second team for {}", t.country));
            }
            for tld in t.tlds() {
                if !tlds.insert(tld.clone()) {
                    out.push(format!("{at}: .{tld} is listed twice"));
                }
            }
            if !t.source.starts_with("https://") {
                out.push(format!("{at}: source is not an https link"));
            }
            if sc_core::parse_ts(&t.verified).is_none() {
                out.push(format!("{at}: verified `{}` is not a date", t.verified));
            }
            if !matches!(t.channel.as_str(), "email" | "form" | "portal") {
                out.push(format!("{at}: channel `{}`", t.channel));
            }
            if (t.channel == "email") != (t.address.contains('@') && !t.address.contains('/')) {
                out.push(format!("{at}: address does not fit channel {}", t.channel));
            }
        }
        out
    }

    /// The team for a country code, any case.
    pub fn for_country(&self, cc: &str) -> Option<&Csirt> {
        self.teams
            .iter()
            .find(|t| t.country.eq_ignore_ascii_case(cc.trim()))
    }

    /// The country a host's top-level domain places it in: a listed TLD's
    /// team's country, else any two-letter TLD upper-cased (a country with
    /// no team listed). `None` for generic TLDs (`.com`, `.org`).
    pub fn country_of(&self, host: &str) -> Option<String> {
        let tld = host
            .trim()
            .trim_end_matches('.')
            .rsplit('.')
            .next()?
            .to_ascii_lowercase();
        if let Some(t) = self.teams.iter().find(|t| t.tlds().contains(&tld)) {
            return Some(t.country.clone());
        }
        (tld.len() == 2 && tld.chars().all(|c| c.is_ascii_lowercase()))
            .then(|| tld.to_ascii_uppercase())
    }

    /// The directory as a provider directory, so `contacts verify` can
    /// re-read it the same way.
    pub fn as_directory(&self) -> Directory {
        Directory {
            providers: self
                .teams
                .iter()
                .map(|t| Provider {
                    name: format!("{} ({})", t.name, t.country),
                    aliases: Vec::new(),
                    kind: "csirt".into(),
                    note: None,
                    contacts: vec![DirContact {
                        channel: t.channel.clone(),
                        address: t.address.clone(),
                        purpose: "security".into(),
                        source: t.source.clone(),
                        verified: t.verified.clone(),
                    }],
                })
                .collect(),
        }
    }
}

/// Propose the national CSIRT for every endpoint not marked not-affected:
/// one contact per team, role `csirt`, with the endpoints it covers in the
/// decision log. `country` overrides every endpoint's TLD. Returns how many
/// contacts were added.
pub(crate) fn seed_csirts(
    c: &mut Case,
    dir: &Csirts,
    country: Option<&str>,
    today: &str,
    out: &mut impl Write,
) -> Result<usize> {
    if let Some(cc) = country
        && dir.for_country(cc).is_none()
    {
        bail!("no national CSIRT listed for `{cc}` in contacts/csirts.toml");
    }
    let mut by_team: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for e in c
        .endpoints
        .iter()
        .filter(|e| e.state != EndpointState::NotAffected)
    {
        let cc = match country {
            Some(cc) => Some(cc.to_ascii_uppercase()),
            None => dir.country_of(&e.host),
        };
        match cc {
            Some(cc) if dir.for_country(&cc).is_some() => {
                by_team.entry(cc).or_default().push(e.host.clone());
            }
            Some(cc) => writeln!(
                out,
                "{}: no national CSIRT listed for {cc}",
                sc_core::defang_host(&e.host)
            )?,
            None => writeln!(
                out,
                "{}: no country in its domain; pass --country if a national CSIRT is relevant",
                sc_core::defang_host(&e.host)
            )?,
        }
    }
    let mut added = 0;
    for (cc, hosts) in by_team {
        let Some(t) = dir.for_country(&cc) else {
            continue;
        };
        let have = c
            .contacts
            .iter()
            .any(|x| x.role == "csirt" && x.address.eq_ignore_ascii_case(&t.address));
        writeln!(
            out,
            "{} (csirt, {cc}): {} {} for {} ({}, verified {}){}",
            t.name,
            t.channel,
            t.address,
            hosts
                .iter()
                .map(|h| sc_core::defang_host(h))
                .collect::<Vec<_>>()
                .join(", "),
            t.source,
            t.verified,
            if have { ", already listed" } else { "" }
        )?;
        if have {
            continue;
        }
        c.contacts.push(Contact {
            org: t.name.clone(),
            role: "csirt".into(),
            endpoint: None,
            channel: case_channel(&t.channel)?.into(),
            address: t.address.clone(),
            source: t.source.clone(),
            confidence: "medium".into(),
            found_on: t.verified.clone(),
            purpose: None,
        });
        c.log(
            today,
            format!(
                "contact proposed: {} (csirt, {cc}) {} for {}",
                t.name,
                t.address,
                hosts.join(", ")
            ),
        );
        added += 1;
    }
    Ok(added)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::case::CaseEndpoint;

    #[test]
    fn the_directory_is_well_formed() {
        let d = Csirts::builtin();
        assert!(d.problems().is_empty(), "{:?}", d.problems());
        assert!(d.teams.len() >= 30);
        for t in &d.teams {
            assert!(
                t.source.starts_with("https://www.first.org/members/teams/"),
                "{}",
                t.name
            );
        }
        assert_eq!(d.for_country("fr").unwrap().name, "CERT-FR");
        let bad = Csirts::parse(
            "[[csirt]]\ncountry = \"fra\"\nname = \"X\"\nchannel = \"email\"\naddress = \"https://x.example\"\nsource = \"http://x.example\"\nverified = \"soon\"\n[[csirt]]\ncountry = \"fra\"\nname = \"Y\"\nchannel = \"email\"\naddress = \"y@y.example\"\nsource = \"https://y.example\"\nverified = \"2026-10-10\"\n",
        );
        let e = bad.unwrap_err().to_string();
        for want in ["alpha-2", "second team", "https", "not a date", "fit"] {
            assert!(e.contains(want), "{want}: {e}");
        }
    }

    #[test]
    fn hosts_map_to_countries_by_tld() {
        let d = Csirts::builtin();
        assert_eq!(d.country_of("portal.example.gov.uk").as_deref(), Some("GB"));
        assert_eq!(d.country_of("www.example.fr.").as_deref(), Some("FR"));
        assert_eq!(d.country_of("agency.example.gov").as_deref(), Some("US"));
        assert_eq!(d.country_of("shop.example.ax").as_deref(), Some("FI"));
        assert_eq!(d.country_of("example.com"), None);
        // A ccTLD with no team listed still names its country.
        assert_eq!(d.country_of("example.zz").as_deref(), Some("ZZ"));
    }

    fn case(hosts: &[(&str, EndpointState)]) -> Case {
        let mut c: Case = toml::from_str(
            "id = \"t\"\ntitle = \"T\"\nstatus = \"open\"\nnotice = \"active\"\nopened = \"2026-10-12\"\n",
        )
        .unwrap();
        for (h, s) in hosts {
            c.endpoints.push(CaseEndpoint {
                host: h.to_string(),
                state: *s,
                ..Default::default()
            });
        }
        c
    }

    #[test]
    fn csirts_are_proposed_per_country() {
        let d = Csirts::builtin();
        let mut c = case(&[
            ("a.example.fr", EndpointState::Targeted),
            ("b.example.fr", EndpointState::Unreviewed),
            ("relay.example.de", EndpointState::NotAffected),
            ("shop.example.com", EndpointState::Targeted),
            ("x.example.zz", EndpointState::Targeted),
        ]);
        let mut out = Vec::new();
        assert_eq!(
            seed_csirts(&mut c, &d, None, "2026-10-13", &mut out).unwrap(),
            1
        );
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("pass --country"), "{text}");
        assert!(text.contains("no national CSIRT listed for ZZ"), "{text}");
        assert_eq!(c.contacts.len(), 1);
        let x = &c.contacts[0];
        assert_eq!((x.role.as_str(), x.org.as_str()), ("csirt", "CERT-FR"));
        assert!(x.source.starts_with("https://www.first.org/"));
        assert!(
            c.decisions[0].text.contains("a.example.fr, b.example.fr"),
            "{:?}",
            c.decisions
        );
        // Again: nothing new.
        assert_eq!(
            seed_csirts(&mut c, &d, None, "2026-10-13", &mut Vec::new()).unwrap(),
            0
        );

        // --country covers hosts whose domain names no country.
        let mut c = case(&[("shop.example.com", EndpointState::Targeted)]);
        seed_csirts(&mut c, &d, Some("nl"), "2026-10-13", &mut Vec::new()).unwrap();
        assert_eq!(c.contacts[0].org, "NCSC-NL");
        assert!(seed_csirts(&mut c, &d, Some("zz"), "d", &mut Vec::new()).is_err());
    }

    #[test]
    fn the_directory_reads_as_a_provider_directory_for_verify() {
        let d = Csirts::builtin().as_directory();
        assert!(d.problems().is_empty(), "{:?}", d.problems());
        let fr = d.find("CERT-FR (FR)").unwrap();
        assert_eq!(fr.contacts[0].address, "cert-fr@ssi.gouv.fr");
    }
}
