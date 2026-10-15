//! Declared agent identity (SC-FM 7.11, 7.13): who a request says sent it,
//! and whether the provider's own published documents bear that out.
//!
//! Agent products name themselves in the user agent (`ChatGPT-User`,
//! `Claude-User`, `Perplexity-User`, `Google-Agent`), and some sign their
//! requests (Web Bot Auth: RFC 9421 signatures with a `Signature-Agent`
//! header). Their providers publish the address ranges those products send
//! from and the keys they sign with. Each record is classed by the strongest
//! thing that holds ([`IdentityClass`]):
//!
//! | Class | What holds | Attribution evidence |
//! |---|---|---|
//! | `signature_verified` | a Web Bot Auth signature verifies with a key from the provider's directory | provider infrastructure |
//! | `ip_verified` | a declared product, from an address in its provider's range file | provider infrastructure |
//! | `in_range` | no declaration, from an address in a provider's range file | provider infrastructure |
//! | `signature_present` | a signature that could not be checked | self-identification |
//! | `claimed` | a declared product, and nothing to check it against | self-identification |
//! | `signature_failed` | a signature that is malformed, out of time or does not verify | none |
//! | `spoofed` | a declared product from outside its provider's exhaustive range file, with no valid signature | none |
//! | `none` | nothing declared, no range | none |
//!
//! The catalog of products, range files and directories is
//! [`declared-agents.toml`](../../../../declared-agents.toml), compiled in.
//! The range files and directories are data ([`IdentityData`]), fetched by
//! the CLI from the catalog's URLs only; a `Signature-Agent` URI in a
//! request is never fetched. Nothing here changes a score, tier or link, and
//! a verified identity only suggests a claim: the admin records it.
//!
//! A key directory may say how its signer is operated ([`Access`]): a
//! direct signer is one operator's own agent, an intermediary is a platform
//! many end users direct. A signature verified for an intermediary
//! attributes the platform, not the end user, and a per-end-user RFC 7239
//! `Forwarded` value under it separates end users without naming one.
//!
//! A cluster can also carry a declared-then-undeclared hint ([`fallback`]):
//! a declared agent blocked, and undeclared browser-like requests for the
//! same pages minutes later. A pattern to check, never a score.

pub mod fallback;
pub mod httpsig;
pub mod ranges;
pub mod sfv;

use crate::analyze::{Analysis, Cluster};
use crate::attribution::{Claim, Evidence, Role};
use crate::model::Observation;
use httpsig::{KeyDirectory, Message, Outcome, SigCheck};
use ranges::RangeTable;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// The bundled catalog.
pub const DEFAULT_CATALOG: &str = include_str!("../../../../declared-agents.toml");

/// A provider's published range file.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RangeFile {
    pub id: String,
    pub provider: String,
    pub url: String,
    pub source: String,
    /// Whether the provider presents the file as every address its products
    /// use. An address outside a non-exhaustive file is unlisted, not spoofed.
    #[serde(default = "yes")]
    pub exhaustive: bool,
}

fn yes() -> bool {
    true
}

/// How a signed agent is operated, in Cloudflare's signed-agent classes
/// (<https://developers.cloudflare.com/bots/concepts/bot/signed-agents/>).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Access {
    /// One operator runs it, usually on its own infrastructure.
    Direct,
    /// A service a wide range of end users operate: the operator runs the
    /// software, a different end user starts each action.
    Intermediary,
}

impl Access {
    pub fn id(self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::Intermediary => "intermediary",
        }
    }

    /// What a verified signature from such a signer attributes.
    pub fn meaning(self) -> &'static str {
        match self {
            Self::Direct => "a direct signer: one operator runs it",
            Self::Intermediary => {
                "an intermediary platform many end users direct: the signature attributes the platform, not the end user who started the request"
            }
        }
    }
}

/// A provider's Web Bot Auth key directory.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DirectoryFile {
    pub id: String,
    pub provider: String,
    pub signature_agent: String,
    pub url: String,
    pub source: String,
    /// How the signer is operated, set only where the provider's own
    /// documentation says.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access: Option<Access>,
}

/// An agent product that names itself in the user agent.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DeclaredAgent {
    pub token: String,
    pub provider: String,
    pub product: String,
    /// `user_fetch` | `agent` | `search` | `training`.
    pub purpose: String,
    #[serde(default)]
    pub ranges: Vec<String>,
    #[serde(default)]
    pub directory: Option<String>,
    pub source: String,
}

/// A coding-agent product that acts on GitHub as a GitHub App (or as an
/// account the platform runs for it), named by its login.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DeclaredApp {
    /// The actor login events carry (`claude[bot]`, `Copilot`), matched
    /// case-insensitively and whole.
    pub login: String,
    pub provider: String,
    pub product: String,
    /// Words that claim this product in another App's login (`claude` in
    /// `claude-fleet[bot]`): words of the product's name or of its login,
    /// never the provider's name alone, which its other Apps carry too.
    #[serde(default)]
    pub names: Vec<String>,
    /// The provider's own GitHub organisations: an App acting on their
    /// repositories was installed there by the provider, so its name claims
    /// nothing of others.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub orgs: Vec<String>,
    pub source: String,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct CatalogMeta {
    #[serde(default)]
    pub version: String,
}

/// The catalog: products, range files, directories, GitHub Apps.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Catalog {
    #[serde(default)]
    pub meta: CatalogMeta,
    #[serde(default, rename = "range_file")]
    pub range_files: Vec<RangeFile>,
    #[serde(default, rename = "directory")]
    pub directories: Vec<DirectoryFile>,
    #[serde(default, rename = "agent")]
    pub agents: Vec<DeclaredAgent>,
    #[serde(default, rename = "github_app")]
    pub github_apps: Vec<DeclaredApp>,
}

impl Catalog {
    /// Parse a catalog and check its references.
    pub fn from_toml(text: &str) -> Result<Catalog, String> {
        toml::from_str::<Catalog>(text)
            .map_err(|e| e.to_string())?
            .checked()
    }

    /// The catalog, if its references resolve and every URL is https. The
    /// browser module reads the catalog as JSON and checks it here.
    pub fn checked(self) -> Result<Catalog, String> {
        let c = self;
        for a in &c.agents {
            for r in &a.ranges {
                if !c.range_files.iter().any(|f| &f.id == r) {
                    return Err(format!("agent {}: unknown range file `{r}`", a.token));
                }
            }
            if let Some(d) = &a.directory
                && !c.directories.iter().any(|f| &f.id == d)
            {
                return Err(format!("agent {}: unknown directory `{d}`", a.token));
            }
        }
        for a in &c.github_apps {
            let own: Vec<String> = format!("{} {}", a.product, a.login)
                .to_ascii_lowercase()
                .split(|ch: char| !ch.is_ascii_alphanumeric())
                .filter(|w| !w.is_empty())
                .map(str::to_string)
                .collect();
            for n in &a.names {
                if !own.contains(&n.to_ascii_lowercase()) {
                    return Err(format!(
                        "github_app {}: name `{n}` is not a word of the product or its login",
                        a.login
                    ));
                }
            }
        }
        for u in c
            .range_files
            .iter()
            .map(|f| &f.url)
            .chain(c.directories.iter().map(|d| &d.url))
        {
            if !u.starts_with("https://") {
                return Err(format!("`{u}` is not an https URL"));
            }
        }
        Ok(c)
    }

    /// The bundled catalog.
    pub fn bundled() -> Catalog {
        Self::from_toml(DEFAULT_CATALOG).expect("bundled declared-agents.toml must be valid")
    }

    /// The product a user agent names, by whole token
    /// (`...; ChatGPT-User/1.0; +https://...`), case-insensitively.
    pub fn agent_in_ua(&self, ua: &str) -> Option<&DeclaredAgent> {
        let lower = ua.to_ascii_lowercase();
        let token_char = |c: char| c.is_ascii_alphanumeric() || c == '-' || c == '_';
        self.agents.iter().find(|a| {
            let t = a.token.to_ascii_lowercase();
            lower.match_indices(&t).any(|(i, _)| {
                let before = lower[..i].chars().next_back();
                let after = lower[i + t.len()..].chars().next();
                !before.is_some_and(token_char) && !after.is_some_and(token_char)
            })
        })
    }

    /// The declared App acting under `login`, by whole login.
    pub fn github_app(&self, login: &str) -> Option<&DeclaredApp> {
        self.github_apps
            .iter()
            .find(|a| a.login.eq_ignore_ascii_case(login))
    }

    /// The declared App an undeclared GitHub App login (`name[bot]`) claims
    /// by name: a word of the login that starts with one of an App's
    /// `names`. A lookalike is a spoofing lead, not a finding: any App picks
    /// its own name. On a repository of one of the provider's own `orgs`,
    /// see [`Catalog::provider_repo`].
    pub fn github_lookalike(&self, login: &str) -> Option<&DeclaredApp> {
        let l = login.to_ascii_lowercase();
        let stem = l.strip_suffix("[bot]")?;
        if self.github_app(login).is_some() {
            return None;
        }
        let words: Vec<&str> = stem
            .split(|c: char| !c.is_ascii_alphanumeric())
            .filter(|w| !w.is_empty())
            .collect();
        self.github_apps.iter().find(|a| {
            a.names.iter().any(|n| {
                let n = n.to_ascii_lowercase();
                words.iter().any(|w| w.starts_with(n.as_str()))
            })
        })
    }

    /// Whether `repo_owner` is one of the organisations of `app`'s provider
    /// (any of the provider's declared Apps).
    pub fn provider_repo(&self, app: &DeclaredApp, repo_owner: &str) -> bool {
        !repo_owner.is_empty()
            && self
                .github_apps
                .iter()
                .filter(|a| a.provider == app.provider)
                .flat_map(|a| &a.orgs)
                .any(|o| o.eq_ignore_ascii_case(repo_owner))
    }

    fn range_file(&self, id: &str) -> Option<&RangeFile> {
        self.range_files.iter().find(|f| f.id == id)
    }

    fn directory_for(&self, agent_uri: &str) -> Option<&DirectoryFile> {
        let o = httpsig::origin(agent_uri);
        self.directories
            .iter()
            .find(|d| httpsig::origin(&d.signature_agent) == o)
    }
}

/// The range files and key directories held, by catalog id.
#[derive(Debug, Clone, Default)]
pub struct IdentityData {
    pub ranges: BTreeMap<String, RangeTable>,
    pub directories: BTreeMap<String, KeyDirectory>,
}

impl IdentityData {
    pub fn is_empty(&self) -> bool {
        self.ranges.is_empty() && self.directories.is_empty()
    }
}

/// A record's declared identity, strongest first by [`IdentityClass::rank`].
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum IdentityClass {
    #[default]
    None,
    Claimed,
    SignaturePresent,
    InRange,
    IpVerified,
    SignatureVerified,
    SignatureFailed,
    Spoofed,
}

impl IdentityClass {
    pub fn id(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Claimed => "claimed",
            Self::SignaturePresent => "signature_present",
            Self::InRange => "in_range",
            Self::IpVerified => "ip_verified",
            Self::SignatureVerified => "signature_verified",
            Self::SignatureFailed => "signature_failed",
            Self::Spoofed => "spoofed",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::None => "no declared identity",
            Self::Claimed => "declared in the user agent only (anyone can write this)",
            Self::SignaturePresent => "signed, not verified",
            Self::InRange => "from a provider's published range, undeclared",
            Self::IpVerified => "declared, from the provider's published range",
            Self::SignatureVerified => "signature verified with the provider's published key",
            Self::SignatureFailed => "signature invalid, expired or malformed",
            Self::Spoofed => "declares a provider's product from outside its published ranges",
        }
    }

    /// The attribution evidence the class reaches, if any.
    pub fn evidence(self) -> Option<Evidence> {
        match self {
            Self::SignatureVerified | Self::IpVerified | Self::InRange => {
                Some(Evidence::ProviderInfrastructure)
            }
            Self::Claimed | Self::SignaturePresent => Some(Evidence::SelfId),
            Self::None | Self::SignatureFailed | Self::Spoofed => None,
        }
    }

    /// Ties the request to the provider's infrastructure.
    pub fn verified(self) -> bool {
        self.evidence() == Some(Evidence::ProviderInfrastructure)
    }
}

/// One record's declared identity.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct RecordIdentity {
    pub class: IdentityClass,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    /// The product token, or the signer's `Signature-Agent` URI.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent: Option<String>,
    /// The range file or directory that decided it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub basis: Option<String>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub detail: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<SigCheck>,
    /// The verified signer's access class, when its directory states one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access: Option<Access>,
    /// Under an intermediary signer, the end user the RFC 7239 `Forwarded`
    /// header names (its first `for=`). A key to group requests by, never
    /// attribution; kept out of any output.
    #[serde(skip)]
    pub forwarded: Option<String>,
}

/// The first `for=` of an RFC 7239 `Forwarded` header, unquoted.
pub fn forwarded_for(o: &Observation) -> Option<String> {
    let v = o
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("forwarded"))?
        .1;
    let first = v.split(',').next()?;
    first.split(';').find_map(|pair| {
        let (k, v) = pair.split_once('=')?;
        k.trim()
            .eq_ignore_ascii_case("for")
            .then(|| v.trim().trim_matches('"').to_string())
            .filter(|v| !v.is_empty())
    })
}

/// Class one record. `method` is the request method when the record gives
/// it (a `:method` header on JSON records).
pub fn classify(o: &Observation, catalog: &Catalog, data: &IdentityData) -> RecordIdentity {
    let method = o
        .headers
        .iter()
        .find(|(k, _)| {
            k.eq_ignore_ascii_case(":method") || k.eq_ignore_ascii_case("x-request-method")
        })
        .map(|(_, v)| v.as_str());
    let msg = Message {
        method,
        url: &o.url,
        headers: &o.headers,
    };
    let dirs: Vec<&KeyDirectory> = data.directories.values().collect();
    let sig = httpsig::check(&msg, o.ts, &dirs);
    let declared = o.user_agent.as_deref().and_then(|u| catalog.agent_in_ua(u));
    let signer = sig
        .as_ref()
        .and_then(|s| s.agent.as_deref())
        .and_then(|a| catalog.directory_for(a));
    let provider_of_sig = signer.map(|d| d.provider.clone());
    let mut out = RecordIdentity {
        provider: declared
            .map(|a| a.provider.clone())
            .or(provider_of_sig.clone()),
        agent: declared
            .map(|a| a.token.clone())
            .or_else(|| sig.as_ref().and_then(|s| s.agent.clone())),
        ..Default::default()
    };

    if let Some(s) = &sig
        && let Outcome::Verified { directory } = &s.outcome
    {
        out.class = IdentityClass::SignatureVerified;
        let d = catalog.directories.iter().find(|d| &d.id == directory);
        out.provider = d.map(|d| d.provider.clone()).or(out.provider);
        out.agent = d.map(|d| d.signature_agent.clone()).or(out.agent);
        out.basis = Some(directory.clone());
        out.access = d.and_then(|d| d.access);
        if out.access == Some(Access::Intermediary) {
            out.forwarded = forwarded_for(o);
        }
        out.signature = sig;
        return out;
    }

    // The address against the declared product's range files, else every
    // range held.
    let ip = o.ip.as_deref().filter(|i| ranges::parse_ip(i).is_some());
    if let (Some(ip), Some(a)) = (ip, declared) {
        let held: Vec<(&RangeFile, &RangeTable)> = a
            .ranges
            .iter()
            .filter_map(|id| Some((catalog.range_file(id)?, data.ranges.get(id)?)))
            .collect();
        if let Some((f, t)) = held.iter().find(|(_, t)| t.contains(ip)) {
            out.class = IdentityClass::IpVerified;
            out.basis = Some(f.id.clone());
            // A shared file that names services per prefix may name another.
            let services = t.services_for(ip);
            if !services.is_empty() && !services.iter().any(|s| s.eq_ignore_ascii_case(&a.token)) {
                out.detail = format!(
                    "the file publishes this address for {}, not {}",
                    services.join(", "),
                    a.token
                );
            }
            out.signature = sig;
            return out;
        }
        if let Some((f, _)) = held.iter().find(|(f, _)| f.exhaustive) {
            let no_open_signature = !matches!(
                sig.as_ref().map(|s| &s.outcome),
                Some(Outcome::Unverified(_))
            );
            if no_open_signature {
                out.class = IdentityClass::Spoofed;
                out.basis = Some(f.id.clone());
                out.detail = format!("{ip} is outside {}", f.id);
                out.signature = sig;
                return out;
            }
        } else if let Some((f, _)) = held.first() {
            out.detail = format!("{ip} is not in {} (not documented as exhaustive)", f.id);
        }
    }
    if declared.is_none()
        && sig.is_none()
        && let Some(ip) = ip
        && let Some((id, t)) = data.ranges.iter().find(|(_, t)| t.contains(ip))
    {
        out.class = IdentityClass::InRange;
        out.provider = catalog.range_file(id).map(|f| f.provider.clone());
        // The file's own name for what sends from this prefix, if it gives one.
        let services = t.services_for(ip);
        if !services.is_empty() {
            out.agent = Some(services.join(", "));
        }
        out.basis = Some(id.clone());
        return out;
    }
    out.class = match sig.as_ref().map(|s| &s.outcome) {
        Some(Outcome::Failed(why)) => {
            out.detail = why.clone();
            IdentityClass::SignatureFailed
        }
        Some(Outcome::Unverified(why)) => {
            if out.detail.is_empty() {
                out.detail = why.clone();
            }
            IdentityClass::SignaturePresent
        }
        _ if declared.is_some() => IdentityClass::Claimed,
        _ => IdentityClass::None,
    };
    if out.class == IdentityClass::Claimed
        && out.detail.is_empty()
        && let Some(a) = declared
    {
        let missing: Vec<&str> = a
            .ranges
            .iter()
            .filter(|r| !data.ranges.contains_key(*r))
            .map(String::as_str)
            .collect();
        out.detail = if ip.is_none() {
            "the record carries no client address".into()
        } else if !missing.is_empty() {
            format!("range file not held: {}", missing.join(", "))
        } else {
            String::new()
        };
    }
    out.signature = sig;
    out
}

/// One line of a cluster's identity: members sharing a class, provider and
/// agent.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IdentityLine {
    pub class: IdentityClass,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub basis: Option<String>,
    pub records: usize,
    /// One example reason, for spoofed and failed lines.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub detail: String,
    /// The verified signer's access class, when its directory states one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access: Option<Access>,
    /// Under an intermediary signer, how many distinct end users the
    /// members' `Forwarded` headers name: a grouping key, not attribution.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub end_users: usize,
}

fn is_zero(n: &usize) -> bool {
    *n == 0
}

/// A cluster's declared identities, strongest class first. Members with no
/// declared identity are counted, not listed.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ClusterIdentity {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub lines: Vec<IdentityLine>,
    #[serde(default)]
    pub undeclared: usize,
    /// Which range files and directories were held, with their fetch dates.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub held: Vec<String>,
    /// A declared agent blocked, then undeclared browser-like requests for
    /// the same pages ([`fallback`]). A pattern to check, never a score.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fallback: Option<fallback::Fallback>,
}

impl ClusterIdentity {
    pub fn is_empty(&self) -> bool {
        self.lines.is_empty() && self.fallback.is_none()
    }

    pub fn records(&self, class: IdentityClass) -> usize {
        self.lines
            .iter()
            .filter(|l| l.class == class)
            .map(|l| l.records)
            .sum()
    }

    /// One line for reports: `4 signature verified (OpenAI, https://chatgpt.com); ...`,
    /// hosts defanged.
    pub fn summary(&self) -> String {
        self.lines
            .iter()
            .map(|l| {
                let who: Vec<String> = [l.provider.clone(), l.agent.clone()]
                    .into_iter()
                    .flatten()
                    .map(|s| crate::extract::defang_hosts(&s))
                    .collect();
                let mut s = format!("{} {}", l.records, l.class.id().replace('_', " "));
                if !who.is_empty() {
                    s.push_str(&format!(" ({})", who.join(", ")));
                }
                if let Some(b) = &l.basis {
                    s.push_str(&format!(" by {b}"));
                }
                if l.access == Some(Access::Intermediary) {
                    s.push_str(", an intermediary: the platform, not the end user");
                }
                s
            })
            .collect::<Vec<_>>()
            .join("; ")
    }

    /// Claims the verified lines support, for the admin to record with
    /// `case claim`: never merged automatically. One developer claim per
    /// provider at `provider_infrastructure` (FM-7.11): the requests came
    /// from the provider's systems, which says nothing of who directed them.
    pub fn suggested_claims(&self) -> Vec<Claim> {
        let mut by: BTreeMap<&str, Vec<String>> = BTreeMap::new();
        for l in self.lines.iter().filter(|l| l.class.verified()) {
            let Some(p) = l.provider.as_deref() else {
                continue;
            };
            let what = match l.class {
                IdentityClass::SignatureVerified => {
                    "carry a Web Bot Auth signature verified with a key from"
                }
                IdentityClass::IpVerified => "declare the product and came from an address in",
                _ => "came, undeclared, from an address in",
            };
            let mut line = format!(
                "{} record(s) {what} {} (the provider's published file)",
                l.records,
                l.basis.as_deref().unwrap_or("?")
            );
            if let Some(acc) = l.access {
                line.push_str(&format!("; the signer is {}", acc.meaning()));
            }
            by.entry(p).or_default().push(line);
        }
        by.into_iter()
            .map(|(p, details)| Claim {
                details,
                ..Claim::new(p, Role::Developer, Evidence::ProviderInfrastructure)
            })
            .collect()
    }
}

/// Class every member of `c` and group them.
pub fn cluster_identity(
    c: &Cluster,
    a: &Analysis,
    catalog: &Catalog,
    data: &IdentityData,
) -> ClusterIdentity {
    // (class, provider, agent, basis) -> (records, first detail, access,
    // end users)
    type Key = (
        IdentityClass,
        Option<String>,
        Option<String>,
        Option<String>,
    );
    type Acc = (
        usize,
        String,
        Option<Access>,
        std::collections::BTreeSet<String>,
    );
    let mut lines: BTreeMap<Key, Acc> = BTreeMap::new();
    let mut out = ClusterIdentity::default();
    for &m in &c.members {
        let r = classify(&a.results[m].obs, catalog, data);
        if r.class == IdentityClass::None {
            out.undeclared += 1;
            continue;
        }
        let e = lines
            .entry((r.class, r.provider, r.agent, r.basis))
            .or_default();
        e.0 += 1;
        if e.1.is_empty() {
            e.1 = r.detail;
        }
        e.2 = e.2.or(r.access);
        e.3.extend(r.forwarded);
    }
    out.lines = lines
        .into_iter()
        .map(
            |((class, provider, agent, basis), (records, detail, access, users))| IdentityLine {
                class,
                provider,
                agent,
                basis,
                records,
                detail,
                access,
                end_users: users.len(),
            },
        )
        .collect();
    crate::sort::by(&mut out.lines, |x, y| {
        rank(y.class)
            .cmp(&rank(x.class))
            .then(y.records.cmp(&x.records))
    });
    out.held = held(data);
    out
}

/// Display order: verified first, then the warnings, then the weak claims.
fn rank(c: IdentityClass) -> u8 {
    match c {
        IdentityClass::SignatureVerified => 7,
        IdentityClass::IpVerified => 6,
        IdentityClass::InRange => 5,
        IdentityClass::Spoofed => 4,
        IdentityClass::SignatureFailed => 3,
        IdentityClass::SignaturePresent => 2,
        IdentityClass::Claimed => 1,
        IdentityClass::None => 0,
    }
}

fn held(data: &IdentityData) -> Vec<String> {
    let date = |d: &Option<String>| d.as_deref().map(|d| format!(" ({d})")).unwrap_or_default();
    data.ranges
        .values()
        .map(|t| format!("{}{}", t.id, date(&t.fetched)))
        .chain(
            data.directories
                .values()
                .map(|d| format!("{}{}", d.id, date(&d.fetched))),
        )
        .collect()
}

/// Fill each cluster's identity, and note it on the agent grade: a verified
/// provider identity is a signal for the self-described rung (it shows the
/// provider's agent platform sent the request, not that a model chose the
/// payloads: a user can paste them), and a spoofed one is a counter-signal.
/// Idempotent; changes no score, tier or link.
pub fn annotate(a: &mut Analysis, catalog: &Catalog, data: &IdentityData) {
    use crate::agentness::{AgentLevel, AgentSignal, SignalKind};
    let ids: Vec<ClusterIdentity> = a
        .clusters
        .iter()
        .map(|c| cluster_identity(c, a, catalog, data))
        .collect();
    for (c, id) in a.clusters.iter_mut().zip(ids) {
        let g = &mut c.agent;
        g.signals.retain(|s| s.kind != SignalKind::VerifiedPlatform);
        g.counter.retain(|s| s.kind != SignalKind::SpoofedIdentity);
        let names = |class: &[IdentityClass]| {
            let mut v: Vec<String> = id
                .lines
                .iter()
                .filter(|l| class.contains(&l.class))
                .filter_map(|l| l.agent.clone().or(l.provider.clone()))
                .map(|s| crate::extract::defang_hosts(&s))
                .collect();
            v.dedup();
            v.join(", ")
        };
        let verified = [
            IdentityClass::SignatureVerified,
            IdentityClass::IpVerified,
            IdentityClass::InRange,
        ];
        let n: usize = verified.iter().map(|&k| id.records(k)).sum();
        if n > 0 {
            g.signals.push(AgentSignal {
                kind: SignalKind::VerifiedPlatform,
                records: n,
                detail: names(&verified),
            });
            if g.level == AgentLevel::PayloadsOnly {
                g.level = AgentLevel::SelfDescribed;
            }
        }
        let spoofed = id.records(IdentityClass::Spoofed);
        if spoofed > 0 {
            g.counter.push(AgentSignal {
                kind: SignalKind::SpoofedIdentity,
                records: spoofed,
                detail: names(&[IdentityClass::Spoofed]),
            });
        }
        c.identity = id;
    }
    // Again with the ranges held, which leave out the provider's own systems.
    fallback::mark(a, Some((catalog, data)));
}

#[cfg(test)]
mod tests;
