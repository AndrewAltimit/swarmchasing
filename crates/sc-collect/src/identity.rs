//! Providers' published address-range files and Web Bot Auth key
//! directories, for checking declared agent identity
//! ([`sc_core::identity`]).
//!
//! These are documents a provider publishes about its own agents, at the
//! addresses its documentation gives ([`sc_core::identity::Catalog`], from
//! `declared-agents.toml`): reading them is reading a public record, like a
//! security.txt, not probing agent infrastructure. Only the catalog's URLs
//! are fetched, over HTTPS, following redirects within the same host. A
//! `Signature-Agent` URI seen in a request is never fetched: it is an
//! address the agent supplied (FM-2.1).
//!
//! Each file is kept in `<data>/identity/` with the date it was fetched and
//! its SHA-256, so a case can say which version of a provider's file a
//! verdict rests on. A fetch that does not parse leaves the previous copy in
//! place. The files stay in the data directory and are never committed.

pub mod reference;

use crate::Client;
use crate::client::Opts;
use anyhow::{Context, Result, bail};
use sc_core::identity::httpsig::KeyDirectory;
use sc_core::identity::ranges::RangeTable;
use sc_core::identity::{Catalog, IdentityData};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Cap on one file (the published files are a few KB).
const MAX_BODY: usize = 4 << 20;

/// `<data>/identity`.
pub fn dir(data: &Path) -> PathBuf {
    data.join("identity")
}

fn file(data: &Path, id: &str) -> PathBuf {
    dir(data).join(format!("{id}.json"))
}

fn index_path(data: &Path) -> PathBuf {
    dir(data).join("fetched.json")
}

/// What is known about one held file.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Held {
    pub url: String,
    /// `yyyy-mm-dd`.
    pub fetched: String,
    pub sha256: String,
    /// Prefixes or keys it holds.
    pub entries: usize,
}

/// The held files, by catalog id.
pub fn index(data: &Path) -> BTreeMap<String, Held> {
    std::fs::read_to_string(index_path(data))
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

/// The result of refreshing one file.
#[derive(Debug)]
pub struct Refreshed {
    pub id: String,
    pub url: String,
    pub result: Result<Held>,
}

/// Fetch every range file and directory in `catalog` into `data`, dated
/// `today`. One failure does not stop the others.
pub fn refresh(client: &Client, data: &Path, catalog: &Catalog, today: &str) -> Vec<Refreshed> {
    let mut idx = index(data);
    let mut out = Vec::new();
    let jobs = catalog
        .range_files
        .iter()
        .map(|f| (f.id.as_str(), f.url.as_str(), None))
        .chain(catalog.directories.iter().map(|d| {
            (
                d.id.as_str(),
                d.url.as_str(),
                Some(d.signature_agent.as_str()),
            )
        }));
    for (id, url, agent) in jobs {
        let result = fetch_one(client, data, id, url, agent, today);
        if let Ok(h) = &result {
            idx.insert(id.to_string(), h.clone());
        }
        out.push(Refreshed {
            id: id.to_string(),
            url: url.to_string(),
            result,
        });
    }
    if let Err(e) = write_index(data, &idx) {
        out.push(Refreshed {
            id: "fetched.json".into(),
            url: String::new(),
            result: Err(e),
        });
    }
    out
}

fn write_index(data: &Path, idx: &BTreeMap<String, Held>) -> Result<()> {
    std::fs::create_dir_all(dir(data))?;
    std::fs::write(index_path(data), serde_json::to_string_pretty(idx)?)?;
    Ok(())
}

fn fetch_one(
    client: &Client,
    data: &Path,
    id: &str,
    url: &str,
    agent: Option<&str>,
    today: &str,
) -> Result<Held> {
    if !url.starts_with("https://") {
        bail!("{url}: only https URLs from the catalog are fetched");
    }
    let opts = Opts {
        same_host: true,
        ..Opts::default()
    };
    let f = client.fetch(url, &[], opts)?;
    if !(200..300).contains(&f.status) {
        bail!("GET {url}: HTTP {}", f.status);
    }
    if f.body.len() > MAX_BODY {
        bail!("GET {url}: over {MAX_BODY} bytes");
    }
    let entries = parse(id, agent, &f.body).map_err(anyhow::Error::msg)?;
    let p = file(data, id);
    std::fs::create_dir_all(dir(data))?;
    std::fs::write(&p, &f.body).with_context(|| format!("writing {}", p.display()))?;
    Ok(Held {
        url: url.to_string(),
        fetched: today.to_string(),
        sha256: Sha256::digest(f.body.as_bytes())
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect(),
        entries,
    })
}

/// Entries in a file: prefixes in a range file, keys in a directory.
fn parse(id: &str, agent: Option<&str>, body: &str) -> Result<usize, String> {
    match agent {
        Some(a) => KeyDirectory::parse(id, a, body).map(|d| d.keys.len()),
        None => RangeTable::parse(id, body).map(|t| t.len()),
    }
}

/// Load the held files the catalog names. Files that no longer parse are
/// reported in the warnings and skipped.
pub fn load(data: &Path, catalog: &Catalog) -> (IdentityData, Vec<String>) {
    let idx = index(data);
    let mut d = IdentityData::default();
    let mut warnings = Vec::new();
    let read = |id: &str| std::fs::read_to_string(file(data, id)).ok();
    let date = |id: &str| idx.get(id).map(|h| h.fetched.clone());
    for f in &catalog.range_files {
        let Some(text) = read(&f.id) else { continue };
        match RangeTable::parse(&f.id, &text) {
            Ok(mut t) => {
                t.fetched = date(&f.id);
                d.ranges.insert(f.id.clone(), t);
            }
            Err(e) => warnings.push(e),
        }
    }
    for x in &catalog.directories {
        let Some(text) = read(&x.id) else { continue };
        match KeyDirectory::parse(&x.id, &x.signature_agent, &text) {
            Ok(mut k) => {
                k.fetched = date(&x.id);
                d.directories.insert(x.id.clone(), k);
            }
            Err(e) => warnings.push(e),
        }
    }
    (d, warnings)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn held_files_load_with_their_dates() {
        let data = std::env::temp_dir().join(format!("sc-collect-identity-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&data);
        let catalog = Catalog::bundled();
        let (d, w) = load(&data, &catalog);
        assert!(d.is_empty() && w.is_empty());

        std::fs::create_dir_all(dir(&data)).unwrap();
        std::fs::write(
            file(&data, "openai.chatgpt-user"),
            r#"{"prefixes":[{"ipv4Prefix":"192.0.2.0/28"}]}"#,
        )
        .unwrap();
        std::fs::write(file(&data, "perplexity.user"), "not a range file").unwrap();
        let mut idx = BTreeMap::new();
        idx.insert(
            "openai.chatgpt-user".to_string(),
            Held {
                url: "https://openai.com/chatgpt-user.json".into(),
                fetched: "2026-10-12".into(),
                sha256: "x".into(),
                entries: 1,
            },
        );
        write_index(&data, &idx).unwrap();
        let (d, w) = load(&data, &catalog);
        let t = &d.ranges["openai.chatgpt-user"];
        assert!(t.contains("192.0.2.1"));
        assert_eq!(t.fetched.as_deref(), Some("2026-10-12"));
        assert_eq!(w.len(), 1, "{w:?}");
        assert_eq!(parse("k", Some("https://a.test"), "{}").ok(), None);
        let _ = std::fs::remove_dir_all(data);
    }
}
