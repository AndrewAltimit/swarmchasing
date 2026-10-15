//! The ai.robots.txt reference list
//! (<https://github.com/ai-robots-txt/ai.robots.txt>, MIT): a community
//! list of AI crawler and agent user-agent tokens, each with its operator
//! and function. Read to propose catalog entries, never to make them: a
//! token it lists that `declared-agents.toml` lacks is a candidate for the
//! admin, and every catalog entry still cites the provider's own page.
//!
//! The list is fetched from its repository's raw file into
//! `<data>/identity/reference/robots.json` and never committed. Nothing in
//! it is fetched in turn: operator links are kept as text.

use crate::Client;
use anyhow::{Context, Result};
use sc_core::identity::Catalog;
use serde_json::Value;
use std::path::{Path, PathBuf};

/// Where the list is served.
pub const URL: &str =
    "https://raw.githubusercontent.com/ai-robots-txt/ai.robots.txt/main/robots.json";
/// Cap on the download (the file is tens of KB).
const MAX_DOWNLOAD: u64 = 8 << 20;

/// `<data>/identity/reference/robots.json`.
pub fn path(data: &Path) -> PathBuf {
    super::dir(data).join("reference").join("robots.json")
}

/// One listed token.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReferenceBot {
    /// The user-agent token (`GPTBot`).
    pub token: String,
    /// The operator as the list writes it, Markdown link markup removed.
    pub operator: String,
    /// What the list says it does (`AI Search Crawlers`).
    pub function: String,
}

/// Download the list to [`path`], checking it parses before it replaces
/// the held copy. Returns the path and the tokens it lists.
pub fn fetch(client: &Client, data: &Path) -> Result<(PathBuf, usize)> {
    let p = path(data);
    let tmp = p.with_extension("new");
    client.download(URL, &tmp, MAX_DOWNLOAD)?;
    let parsed = std::fs::read_to_string(&tmp)
        .map_err(anyhow::Error::from)
        .and_then(|t| parse(&t));
    match parsed {
        Ok(bots) => {
            std::fs::rename(&tmp, &p)?;
            Ok((p, bots.len()))
        }
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            Err(e.context("the download does not parse; the held copy stays"))
        }
    }
}

/// The held list, if fetched.
pub fn load(data: &Path) -> Result<Option<Vec<ReferenceBot>>> {
    let p = path(data);
    match std::fs::read_to_string(&p) {
        Ok(t) => parse(&t).map(Some).with_context(|| p.display().to_string()),
        Err(_) => Ok(None),
    }
}

/// `[Name](https://...)` as `Name`; anything else trimmed.
fn plain(s: &str) -> String {
    let s = s.trim();
    match (s.strip_prefix('['), s.find("](")) {
        (Some(_), Some(i)) if s.ends_with(')') => s[1..i].trim().to_string(),
        _ => s.to_string(),
    }
}

/// Parse `robots.json`: an object keyed by token.
pub fn parse(text: &str) -> Result<Vec<ReferenceBot>> {
    let v: Value = serde_json::from_str(text).context("ai.robots.txt list: not JSON")?;
    let m = v
        .as_object()
        .context("ai.robots.txt list: not an object keyed by token")?;
    let field = |b: &Value, k: &str| {
        b.get(k)
            .and_then(Value::as_str)
            .map(plain)
            .unwrap_or_default()
    };
    let bots: Vec<ReferenceBot> = m
        .iter()
        .filter(|(t, _)| !t.trim().is_empty())
        .map(|(t, b)| ReferenceBot {
            token: t.trim().to_string(),
            operator: field(b, "operator"),
            function: field(b, "function"),
        })
        .collect();
    if bots.is_empty() {
        anyhow::bail!("ai.robots.txt list: no tokens");
    }
    Ok(bots)
}

/// Listed tokens the catalog has no agent for, matched case-insensitively,
/// sorted by operator then token.
pub fn candidates(bots: &[ReferenceBot], catalog: &Catalog) -> Vec<ReferenceBot> {
    let known: std::collections::BTreeSet<String> = catalog
        .agents
        .iter()
        .map(|a| a.token.to_ascii_lowercase())
        .collect();
    let mut out: Vec<ReferenceBot> = bots
        .iter()
        .filter(|b| !known.contains(&b.token.to_ascii_lowercase()))
        .cloned()
        .collect();
    out.sort_by(|a, b| {
        (a.operator.to_lowercase(), &a.token).cmp(&(b.operator.to_lowercase(), &b.token))
    });
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // Invented tokens beside two the catalog holds.
    const LIST: &str = r#"{
      "GPTBot": {"operator": "[OpenAI](https://openai.com)", "respect": "Yes", "function": "Scrapes data to train models.", "frequency": "No information.", "description": "x"},
      "chatgpt-user": {"operator": "OpenAI", "function": "Takes action based on user prompts.", "frequency": "", "description": ""},
      "ExampleAgentBot": {"operator": "[Example Labs](https://labs.example)", "respect": "Unclear at this time.", "function": "AI Agents", "frequency": "Unclear at this time.", "description": "An invented agent."},
      "AnotherFetcher": {"operator": "Another Co", "function": "AI Assistants"}
    }"#;

    #[test]
    fn tokens_the_catalog_lacks_are_proposed() {
        let bots = parse(LIST).unwrap();
        assert_eq!(bots.len(), 4);
        let gpt = bots.iter().find(|b| b.token == "GPTBot").unwrap();
        assert_eq!(gpt.operator, "OpenAI");
        let c = candidates(&bots, &Catalog::bundled());
        let tokens: Vec<&str> = c.iter().map(|b| b.token.as_str()).collect();
        assert_eq!(tokens, ["AnotherFetcher", "ExampleAgentBot"]);
        assert_eq!(c[1].operator, "Example Labs");
        assert!(parse("[]").is_err());
        assert!(parse("{}").is_err());
    }
}
