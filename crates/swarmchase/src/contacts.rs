//! Contact discovery for affected operators, and the provider directory.
//!
//! For each affected endpoint, the first security.txt (RFC 9116) found on the
//! host or its parent domains, else the registrar's abuse contact from RDAP.
//! Every contact carries its source link, a confidence level and the date it
//! was found. These are reads of published contact files on the affected
//! organisation's own site and the registry, never of agent infrastructure.
//!
//! Providers' channels come from the committed directory
//! (`contacts/providers.toml`, [`Directory`]): `case contacts` adds a
//! provider's entries when a developer or host claim names it, and
//! `swarmchase contacts verify` re-reads each entry's source and drafts the
//! changes for the admin.

use crate::case::{Case, Contact, EndpointState};
use anyhow::{Context, Result};
use sc_core::SecurityTxt;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::io::Write;

/// The host, then each parent down to the registered domain (by the Public
/// Suffix List: `aihw.gov.au`, `agency.gov.uk`, `foo.co.jp`).
pub fn domain_candidates(host: &str) -> Vec<String> {
    let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
    let labels: Vec<&str> = host.split('.').filter(|l| !l.is_empty()).collect();
    let n = labels.len();
    if n < 2 {
        return vec![host];
    }
    let min = sc_collect::psl::registrable_domain(&host)
        .map_or(2, |d| d.split('.').count())
        .clamp(1, n);
    (min..=n).rev().map(|k| labels[n - k..].join(".")).collect()
}

/// The registered domain: the last of [`domain_candidates`].
pub fn registered_domain(host: &str) -> String {
    domain_candidates(host).pop().unwrap_or_default()
}

/// Contacts listed in a security.txt.
pub fn from_security_txt(org: &str, url: &str, s: &SecurityTxt, today: &str) -> Vec<Contact> {
    let expired = s
        .expires
        .as_deref()
        .and_then(sc_core::parse_ts)
        .zip(sc_core::parse_ts(today))
        .is_some_and(|(exp, now)| exp < now);
    let confidence = match (expired, s.signed) {
        (true, _) => "low",
        (false, true) => "high",
        (false, false) => "medium",
    };
    s.contact
        .iter()
        .map(|c| {
            let (channel, address) = match c.strip_prefix("mailto:") {
                Some(a) => ("email", a.to_string()),
                None if c.starts_with("tel:") => ("phone", c.to_string()),
                None => ("web_form", c.to_string()),
            };
            Contact {
                org: org.to_string(),
                role: "affected".into(),
                endpoint: None,
                channel: channel.into(),
                address,
                source: if expired {
                    format!("{url} (expired)")
                } else {
                    url.to_string()
                },
                confidence: confidence.into(),
                found_on: today.to_string(),
                purpose: None,
            }
        })
        .collect()
}

/// Abuse e-mail addresses in an RDAP domain response, with the name of the
/// entity that lists them (usually the registrar).
pub fn rdap_abuse(json: &str) -> Vec<(String, String)> {
    let Ok(v) = serde_json::from_str::<Value>(json) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    walk(&v, None, &mut out);
    out.sort();
    out.dedup();
    out
}

fn walk(v: &Value, parent: Option<String>, out: &mut Vec<(String, String)>) {
    let Some(entities) = v.get("entities").and_then(Value::as_array) else {
        return;
    };
    for e in entities {
        let name = vcard(e, "fn")
            .into_iter()
            .find(|n| !n.trim().is_empty())
            .or_else(|| parent.clone());
        let abuse = e
            .get("roles")
            .and_then(Value::as_array)
            .is_some_and(|r| r.iter().any(|x| x == "abuse"));
        if abuse {
            for email in vcard(e, "email") {
                out.push((name.clone().unwrap_or_else(|| "registrar".into()), email));
            }
        }
        walk(e, name, out);
    }
}

/// Text values of one vCard property in an RDAP entity.
fn vcard(e: &Value, prop: &str) -> Vec<String> {
    e.get("vcardArray")
        .and_then(|a| a.get(1))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|p| p.get(0).and_then(Value::as_str) == Some(prop))
        .filter_map(|p| p.get(3).and_then(Value::as_str))
        .map(str::to_string)
        .collect()
}

/// The reads contact discovery makes: a domain's security.txt and its RDAP
/// record, each as `(url, body)`, `None` when it could not be read.
pub(crate) trait Lookup {
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

pub(crate) fn find_contacts(
    c: &mut Case,
    client: &impl Lookup,
    refresh: bool,
    today: &str,
    out: &mut impl Write,
) -> Result<()> {
    let mut client = RunCache::new(client);
    let hosts: Vec<String> = c
        .endpoints
        .iter()
        .filter(|e| e.state != EndpointState::NotAffected)
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
        let mut found = Vec::new();
        let mut how = "nothing found";
        for d in crate::contacts::domain_candidates(&host) {
            if let Some((url, body)) = client.security_txt(&d) {
                let s = sc_core::parse_security_txt(&body);
                found = crate::contacts::from_security_txt(&d, &url, &s, today);
                how = "security.txt";
                break;
            }
        }
        if found.is_empty() {
            let domain = crate::contacts::registered_domain(&host);
            if let Some((url, body)) = client.rdap_domain(&domain) {
                found = crate::contacts::rdap_abuse(&body)
                    .into_iter()
                    .map(|(org, email)| Contact {
                        org,
                        role: "registrar".into(),
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
                    "{host}: {} {} ({}, {} confidence)",
                    x.channel, x.address, x.source, x.confidence
                )?;
                c.contacts.push(x);
                added += 1;
            }
        }
        if added == 0 {
            writeln!(out, "{host}: {how}, nothing new")?;
        }
        c.log(today, format!("contacts for {host}: {added} new ({how})"));
    }
    Ok(())
}

/// The provider directory committed at `contacts/providers.toml`, built in.
pub const PROVIDERS: &str = include_str!("../../../contacts/providers.toml");

/// Security and abuse channels of AI providers and agent hosts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Directory {
    #[serde(default, rename = "provider")]
    pub providers: Vec<Provider>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Provider {
    pub name: String,
    /// Other names a claim's party may use for this provider.
    #[serde(default)]
    pub aliases: Vec<String>,
    /// model | host | cloud
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    #[serde(default, rename = "contact")]
    pub contacts: Vec<DirContact>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirContact {
    /// email | form | portal
    pub channel: String,
    pub address: String,
    /// security | abuse
    pub purpose: String,
    /// The page the address was read from.
    pub source: String,
    /// When it was last read there.
    pub verified: String,
}

impl Directory {
    pub fn parse(text: &str) -> Result<Directory> {
        let d: Directory = toml::from_str(text).context("parsing the provider directory")?;
        let problems = d.problems();
        if !problems.is_empty() {
            anyhow::bail!("provider directory: {}", problems.join("; "));
        }
        Ok(d)
    }

    /// The built-in directory.
    pub fn builtin() -> Directory {
        Directory::parse(PROVIDERS).expect("contacts/providers.toml is checked by its tests")
    }

    /// The provider a claim's party names, by name or alias.
    pub fn find(&self, party: &str) -> Option<&Provider> {
        let p = party.trim();
        self.providers.iter().find(|x| {
            x.name.eq_ignore_ascii_case(p) || x.aliases.iter().any(|a| a.eq_ignore_ascii_case(p))
        })
    }

    /// Entries that break the directory's rules: every contact has an https
    /// source, a verified date, a known channel and purpose.
    pub fn problems(&self) -> Vec<String> {
        let mut out = Vec::new();
        for p in &self.providers {
            if p.contacts.is_empty() {
                out.push(format!("{}: no contacts", p.name));
            }
            for c in &p.contacts {
                let at = format!("{} {}", p.name, c.address);
                if !c.source.starts_with("https://") {
                    out.push(format!("{at}: source is not an https link"));
                }
                if sc_core::parse_ts(&c.verified).is_none() {
                    out.push(format!("{at}: verified `{}` is not a date", c.verified));
                }
                if !matches!(c.channel.as_str(), "email" | "form" | "portal") {
                    out.push(format!("{at}: channel `{}`", c.channel));
                }
                if !matches!(c.purpose.as_str(), "security" | "abuse") {
                    out.push(format!("{at}: purpose `{}`", c.purpose));
                }
                if (c.channel == "email") != (c.address.contains('@') && !c.address.contains('/')) {
                    out.push(format!("{at}: address does not fit channel {}", c.channel));
                }
            }
        }
        out
    }
}

/// The case.toml channel for a directory or command-line channel.
pub fn case_channel(channel: &str) -> Result<&'static str> {
    Ok(match channel {
        "email" => "email",
        "form" | "web_form" => "web_form",
        "portal" => "portal",
        "phone" => "phone",
        c => anyhow::bail!("unknown channel `{c}` (email|form|portal)"),
    })
}

/// Add the directory's contacts for every provider a developer or host claim
/// names. Returns how many were added.
pub(crate) fn seed_providers(
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
                role: "provider".into(),
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

/// Whether a fetched page still lists `address`.
fn lists(body: &str, address: &str) -> bool {
    let body = body.to_ascii_lowercase();
    let a = address.to_ascii_lowercase();
    let bare = a
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .trim_end_matches('/');
    body.contains(&a) || body.contains(bare)
}

/// What a re-read of one directory contact found.
#[derive(Debug, PartialEq)]
pub enum Check {
    /// The source still lists the address.
    Listed,
    /// The source was read but no longer lists the address.
    Missing,
    /// The source could not be read.
    Unreachable(String),
}

/// Check every directory contact against `fetch(source)`, each source read
/// once. Returns (provider, address, result) in directory order, and any
/// Contact lines of a security.txt source that the directory lacks.
pub fn verify_directory(
    dir: &Directory,
    mut fetch: impl FnMut(&str) -> std::result::Result<String, String>,
) -> (Vec<(String, String, Check)>, Vec<String>) {
    let mut bodies: std::collections::BTreeMap<String, std::result::Result<String, String>> =
        Default::default();
    let mut out = Vec::new();
    let mut new = Vec::new();
    for p in &dir.providers {
        for c in &p.contacts {
            let body = bodies
                .entry(c.source.clone())
                .or_insert_with(|| fetch(&c.source));
            let check = match body {
                Ok(b) if lists(b, &c.address) => Check::Listed,
                Ok(_) => Check::Missing,
                Err(e) => Check::Unreachable(e.clone()),
            };
            out.push((p.name.clone(), c.address.clone(), check));
        }
        for c in p
            .contacts
            .iter()
            .filter(|c| c.source.ends_with("security.txt"))
        {
            if let Some(Ok(b)) = bodies.get(&c.source) {
                for listed in sc_core::parse_security_txt(b).contact {
                    let a = listed.trim_start_matches("mailto:").to_string();
                    let known = p.contacts.iter().any(|x| lists(&a, &x.address))
                        || new.iter().any(|n: &String| n.ends_with(&format!(" {a}")));
                    if !known {
                        new.push(format!("{}: {} also lists {a}", p.name, c.source));
                    }
                }
            }
        }
    }
    (out, new)
}

/// The directory text with `verified` set to `today` for every contact whose
/// address was confirmed, and a comment above each one that was not. A
/// draft for the admin to review and commit; the file itself is not touched.
pub fn draft_update(text: &str, checks: &[(String, String, Check)], today: &str) -> String {
    let mut out = String::new();
    let mut current: Option<&Check> = None;
    let mut pending = String::new();
    for line in text.lines() {
        let t = line.trim();
        if t == "[[provider.contact]]" || t == "[[provider]]" || t == "[[csirt]]" {
            out.push_str(&pending);
            pending.clear();
            current = None;
            pending.push_str(line);
            pending.push('\n');
            continue;
        }
        if let Some(a) = t
            .strip_prefix("address = \"")
            .and_then(|r| r.strip_suffix('"'))
        {
            current = checks.iter().find(|(_, x, _)| x == a).map(|(_, _, c)| c);
            if let Some(c) = current
                && *c != Check::Listed
            {
                let why = match c {
                    Check::Missing => "the source no longer lists this address".to_string(),
                    Check::Unreachable(e) => format!("the source could not be read: {e}"),
                    Check::Listed => unreachable!(),
                };
                pending.push_str(&format!("# NOT CONFIRMED {today}: {why}\n"));
            }
        }
        if t.starts_with("verified = ") && current == Some(&Check::Listed) {
            pending.push_str(&format!("verified = \"{today}\"\n"));
        } else {
            pending.push_str(line);
            pending.push('\n');
        }
    }
    out.push_str(&pending);
    out
}

/// `swarmchase contacts`: the provider directory, or with `--csirts` the
/// national CSIRT directory.
#[derive(clap::Subcommand)]
pub enum ContactsCmd {
    /// List the provider directory.
    List {
        /// List the national CSIRTs (contacts/csirts.toml) instead.
        #[arg(long)]
        csirts: bool,
    },
    /// Re-read every directory entry's source and report what changed. With
    /// --draft, also write an updated copy of the directory (verified dates
    /// refreshed, unconfirmed entries marked) for the admin to review; the
    /// directory itself is never changed.
    Verify {
        /// The directory to check. Default: contacts/providers.toml, or
        /// contacts/csirts.toml with --csirts.
        #[arg(long)]
        file: Option<std::path::PathBuf>,
        /// Check the national CSIRT directory.
        #[arg(long)]
        csirts: bool,
        #[arg(long)]
        draft: Option<std::path::PathBuf>,
    },
}

pub fn run_contacts(cmd: ContactsCmd) -> Result<()> {
    let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
    match cmd {
        ContactsCmd::List { csirts: true } => {
            for t in &crate::csirts::Csirts::builtin().teams {
                println!(
                    "{}  {:<40} {:<8} {} (verified {})",
                    t.country, t.name, t.channel, t.address, t.verified
                );
            }
            Ok(())
        }
        ContactsCmd::List { csirts: false } => {
            let d = Directory::builtin();
            for p in &d.providers {
                println!("{} ({})", p.name, p.kind);
                for c in &p.contacts {
                    println!(
                        "  {:<8} {:<8} {} (verified {})",
                        c.purpose, c.channel, c.address, c.verified
                    );
                }
            }
            Ok(())
        }
        ContactsCmd::Verify {
            file,
            csirts,
            draft,
        } => {
            let file = file.unwrap_or_else(|| {
                if csirts {
                    "contacts/csirts.toml".into()
                } else {
                    "contacts/providers.toml".into()
                }
            });
            let text = std::fs::read_to_string(&file)
                .with_context(|| format!("reading {}", file.display()))?;
            let d = if csirts {
                crate::csirts::Csirts::parse(&text)?.as_directory()
            } else {
                Directory::parse(&text)?
            };
            let http = reqwest::blocking::Client::builder()
                .user_agent(
                    std::env::var("SWARMCHASE_UA")
                        .unwrap_or_else(|_| "swarmchase-contacts-verify".into()),
                )
                .timeout(std::time::Duration::from_secs(30))
                .build()?;
            let fetch = |url: &str| -> std::result::Result<String, String> {
                std::thread::sleep(std::time::Duration::from_millis(500));
                let r = http.get(url).send().map_err(|e| e.to_string())?;
                if !r.status().is_success() {
                    return Err(format!("HTTP {}", r.status()));
                }
                r.text().map_err(|e| e.to_string())
            };
            let (checks, new) = verify_directory(&d, fetch);
            let mut changed = 0;
            for (p, a, c) in &checks {
                let s = match c {
                    Check::Listed => "ok".to_string(),
                    Check::Missing => {
                        changed += 1;
                        "MISSING from its source".to_string()
                    }
                    Check::Unreachable(e) => {
                        changed += 1;
                        format!("UNREACHABLE ({e})")
                    }
                };
                println!("{p:<22} {a:<50} {s}");
            }
            for n in &new {
                println!("new: {n}");
            }
            if let Some(out) = draft {
                std::fs::write(&out, draft_update(&text, &checks, &today))?;
                println!(
                    "wrote a draft to {} (review it, then copy it over {} yourself)",
                    out.display(),
                    file.display()
                );
            }
            println!(
                "{} contact(s) checked, {changed} need a look, {} new listing(s)",
                checks.len(),
                new.len()
            );
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sc_core::{Claim, Evidence, Role};

    #[test]
    fn the_directory_is_well_formed_and_found_by_alias() {
        let d = Directory::builtin();
        assert!(d.problems().is_empty(), "{:?}", d.problems());
        assert!(d.providers.len() >= 10);
        for p in &d.providers {
            for c in &p.contacts {
                assert!(c.source.starts_with("https://"), "{}", p.name);
                assert!(sc_core::parse_ts(&c.verified).is_some(), "{}", p.name);
            }
        }
        assert_eq!(d.find("tencent").unwrap().name, "Tencent Cloud");
        assert_eq!(d.find("Anthropic").unwrap().name, "Anthropic");
        assert_eq!(d.find("Amazon AWS").unwrap().name, "Amazon Web Services");
        assert!(d.find("nobody").is_none());
        let bad = Directory::parse(
            "[[provider]]\nname = \"X\"\nkind = \"model\"\n[[provider.contact]]\nchannel = \"email\"\naddress = \"https://x.example/form\"\npurpose = \"abuse\"\nsource = \"http://x.example\"\nverified = \"soon\"\n",
        );
        let e = bad.unwrap_err().to_string();
        assert!(
            e.contains("https") && e.contains("not a date") && e.contains("fit"),
            "{e}"
        );
    }

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
        assert!(c.contacts.iter().all(|x| x.role == "provider"));
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

    #[test]
    fn verify_reports_changes_and_drafts_an_update() {
        let text = "[[provider]]\nname = \"A\"\nkind = \"model\"\n[[provider.contact]]\nchannel = \"email\"\naddress = \"security@a.example\"\npurpose = \"security\"\nsource = \"https://a.example/.well-known/security.txt\"\nverified = \"2026-01-01\"\n[[provider.contact]]\nchannel = \"form\"\naddress = \"https://a.example/abuse\"\npurpose = \"abuse\"\nsource = \"https://a.example/policy\"\nverified = \"2026-01-01\"\n";
        let d = Directory::parse(text).unwrap();
        let mut fetched = Vec::new();
        let (checks, new) = verify_directory(&d, |u| {
            fetched.push(u.to_string());
            match u {
                "https://a.example/.well-known/security.txt" => Ok(
                    "Contact: mailto:security@a.example\nContact: mailto:psirt@a.example\n".into(),
                ),
                _ => Err("HTTP 404".into()),
            }
        });
        assert_eq!(fetched.len(), 2);
        assert_eq!(checks[0].2, Check::Listed);
        assert_eq!(checks[1].2, Check::Unreachable("HTTP 404".into()));
        assert_eq!(
            new,
            ["A: https://a.example/.well-known/security.txt also lists psirt@a.example"]
        );
        let draft = draft_update(text, &checks, "2026-10-13");
        assert_eq!(
            draft.matches("verified = \"2026-10-13\"").count(),
            1,
            "{draft}"
        );
        assert!(draft.contains("# NOT CONFIRMED 2026-10-13: the source could not be read: HTTP 404\naddress = \"https://a.example/abuse\""), "{draft}");
        assert!(Directory::parse(&draft).is_ok());
    }

    #[test]
    fn candidates_stop_at_the_registered_domain() {
        assert_eq!(
            domain_candidates("amap-pc-ssr.amap.com"),
            ["amap-pc-ssr.amap.com", "amap.com"]
        );
        assert_eq!(
            domain_candidates("vizprod.aihw.gov.au"),
            ["vizprod.aihw.gov.au", "aihw.gov.au"]
        );
        assert_eq!(domain_candidates("example.co.uk"), ["example.co.uk"]);
        // Multi-label public suffixes, from the Public Suffix List.
        assert_eq!(
            domain_candidates("www.agency.gov.uk"),
            ["www.agency.gov.uk", "agency.gov.uk"]
        );
        assert_eq!(
            domain_candidates("a.foo.co.jp"),
            ["a.foo.co.jp", "foo.co.jp"]
        );
        assert_eq!(registered_domain("x.y.foo.co.jp"), "foo.co.jp");
        assert_eq!(registered_domain("a.b.example.org"), "example.org");
        assert_eq!(domain_candidates("localhost"), ["localhost"]);
    }

    #[test]
    fn security_txt_contacts() {
        let s = sc_core::parse_security_txt(
            "Contact: mailto:security@example.org\nContact: https://example.org/vdp\nExpires: 2027-01-01T00:00:00Z\n",
        );
        let c = from_security_txt(
            "example.org",
            "https://example.org/.well-known/security.txt",
            &s,
            "2026-10-12",
        );
        assert_eq!(c.len(), 2);
        assert_eq!(
            (
                c[0].channel.as_str(),
                c[0].address.as_str(),
                c[0].confidence.as_str()
            ),
            ("email", "security@example.org", "medium")
        );
        assert_eq!(c[1].channel, "web_form");
        let late = from_security_txt("example.org", "u", &s, "2027-02-01");
        assert_eq!(late[0].confidence, "low");
        assert!(late[0].source.ends_with("(expired)"));
    }

    #[test]
    fn rdap_abuse_contacts_are_found_in_nested_entities() {
        let json = r#"{"entities":[{"roles":["registrar"],
            "vcardArray":["vcard",[["version",{},"text","4.0"],["fn",{},"text","Example Registrar"]]],
            "entities":[{"roles":["abuse"],
              "vcardArray":["vcard",[["fn",{},"text",""],["email",{},"text","abuse@registrar.example"]]]}]}]}"#;
        // The abuse entity has no name of its own, so it takes the registrar's.
        assert_eq!(
            rdap_abuse(json),
            [(
                "Example Registrar".to_string(),
                "abuse@registrar.example".to_string()
            )]
        );
        assert!(rdap_abuse("not json").is_empty());
    }

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
        find_contacts(&mut c, &fake, false, "2026-10-12", &mut out).unwrap();
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
}
