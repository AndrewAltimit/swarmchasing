//! The provider directory committed at `contacts/providers.toml`: security
//! and abuse channels of AI providers and agent hosts, each with the page
//! it was read from and when. The notice linter reads it for the names a
//! title may not carry; the CLI seeds case contacts from it and re-checks
//! its sources.

use crate::{Result, bail};
use serde::{Deserialize, Serialize};

/// The provider directory, built in.
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

impl Provider {
    /// Its name, then its aliases.
    pub fn names(&self) -> impl Iterator<Item = &String> {
        std::iter::once(&self.name).chain(&self.aliases)
    }
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
        let d: Directory = toml::from_str(text)
            .map_err(|e| crate::Error(format!("parsing the provider directory: {e}")))?;
        let problems = d.problems();
        if !problems.is_empty() {
            bail!("provider directory: {}", problems.join("; "));
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
        self.providers
            .iter()
            .find(|x| x.names().any(|n| n.eq_ignore_ascii_case(p)))
    }

    /// Model providers, whose names a title may carry only when the notice
    /// names them as a developer.
    pub fn models(&self) -> impl Iterator<Item = &Provider> {
        self.providers.iter().filter(|p| p.kind == "model")
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
        c => bail!("unknown channel `{c}` (email|form|portal)"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn channels() {
        assert_eq!(case_channel("form").unwrap(), "web_form");
        assert!(case_channel("pigeon").is_err());
    }
}
