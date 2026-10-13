//! The identity page's data (`assets/identity-snapshot.json`): the bundled
//! declared-agent catalog, and optionally a snapshot of the range files and
//! key directories it names, as `swarmchase identity refresh` fetched them.
//!
//! The page checks an operator's log in the browser and fetches nothing, so
//! whatever provider files it starts with come from the build. A snapshot is
//! taken only from a directory `identity refresh` wrote (`fetched.json` and
//! `<catalog id>.json`): each file is embedded only when the catalog names
//! it, it parses as its kind, and its SHA-256 matches the one recorded when
//! it was fetched, so the date shown is the date of that file. Anything
//! else is left out with a warning. Text in, text out: [`crate::build`]
//! reads the directory.

use sc_core::identity::Catalog;
use sc_core::identity::httpsig::KeyDirectory;
use sc_core::identity::ranges::RangeTable;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// Where the page reads it.
pub const SNAPSHOT_PATH: &str = "assets/identity-snapshot.json";

/// One file's entry in `fetched.json`, as `identity refresh` writes it.
#[derive(Debug, Clone, Default, Deserialize)]
struct Held {
    #[serde(default)]
    url: String,
    #[serde(default)]
    fetched: String,
    #[serde(default)]
    sha256: String,
}

/// One embedded file, as the page lists it.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SnapshotFile {
    pub id: String,
    /// `range` or `directory`.
    pub kind: &'static str,
    pub url: String,
    /// `yyyy-mm-dd`, when `identity refresh` fetched it.
    pub fetched: String,
    pub sha256: String,
    /// Prefixes in a range file, keys in a directory.
    pub entries: usize,
}

/// The page's data: the catalog, the files embedded and their text by kind.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Snapshot {
    pub catalog: Catalog,
    pub files: Vec<SnapshotFile>,
    /// File text by catalog id, as `identity_check` takes it.
    pub ranges: BTreeMap<String, String>,
    pub directories: BTreeMap<String, String>,
}

impl Snapshot {
    /// The catalog alone: what a build without a snapshot embeds.
    pub fn empty(catalog: Catalog) -> Self {
        Self {
            catalog,
            ..Default::default()
        }
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| "{}".into())
    }
}

fn sha256_hex(text: &str) -> String {
    Sha256::digest(text.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Build the snapshot from `fetched.json` (`index`) and the files held
/// (`files`, text by catalog id). Returns it with a warning per file left
/// out. An index that does not parse is an error.
pub fn snapshot(
    catalog: Catalog,
    index: &str,
    files: &BTreeMap<String, String>,
) -> Result<(Snapshot, Vec<String>), String> {
    let idx: BTreeMap<String, Held> =
        serde_json::from_str(index).map_err(|e| format!("fetched.json: {e}"))?;
    let mut out = Snapshot::empty(catalog);
    let mut warnings = Vec::new();
    let jobs: Vec<(String, &'static str, String, Option<String>)> = out
        .catalog
        .range_files
        .iter()
        .map(|f| (f.id.clone(), "range", f.url.clone(), None))
        .chain(out.catalog.directories.iter().map(|d| {
            (
                d.id.clone(),
                "directory",
                d.url.clone(),
                Some(d.signature_agent.clone()),
            )
        }))
        .collect();
    for (id, kind, url, agent) in jobs {
        let Some(text) = files.get(&id) else { continue };
        let Some(h) = idx.get(&id) else {
            warnings.push(format!("{id}: not in fetched.json; left out"));
            continue;
        };
        let sha = sha256_hex(text);
        if !h.sha256.eq_ignore_ascii_case(&sha) {
            warnings.push(format!("{id}: SHA-256 differs from fetched.json; left out"));
            continue;
        }
        if !valid_date(&h.fetched) {
            warnings.push(format!("{id}: no fetch date in fetched.json; left out"));
            continue;
        }
        if !h.url.is_empty() && h.url != url {
            warnings.push(format!(
                "{id}: fetched from another URL than the catalog's; left out"
            ));
            continue;
        }
        let entries = match &agent {
            Some(a) => KeyDirectory::parse(&id, a, text).map(|d| d.keys.len()),
            None => RangeTable::parse(&id, text).map(|t| t.len()),
        };
        let entries = match entries {
            Ok(n) => n,
            Err(e) => {
                warnings.push(format!("{e}; left out"));
                continue;
            }
        };
        out.files.push(SnapshotFile {
            id: id.clone(),
            kind,
            url,
            fetched: h.fetched.clone(),
            sha256: sha,
            entries,
        });
        if agent.is_some() {
            out.directories.insert(id, text.clone());
        } else {
            out.ranges.insert(id, text.clone());
        }
    }
    for id in files.keys() {
        let known = out.catalog.range_files.iter().any(|f| &f.id == id)
            || out.catalog.directories.iter().any(|d| &d.id == id);
        if !known {
            warnings.push(format!("{id}: not in the catalog; left out"));
        }
    }
    Ok((out, warnings))
}

/// `yyyy-mm-dd`.
fn valid_date(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 10
        && b[4] == b'-'
        && b[7] == b'-'
        && b.iter()
            .enumerate()
            .all(|(i, c)| i == 4 || i == 7 || c.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use super::*;

    const RANGES: &str =
        r#"{"creationTime":"2026-10-01T00:00:00","prefixes":[{"ipv4Prefix":"192.0.2.0/25"}]}"#;

    fn index(entries: &[(&str, &str, &str)]) -> String {
        let m: BTreeMap<&str, serde_json::Value> = entries
            .iter()
            .map(|(id, url, text)| {
                (
                    *id,
                    serde_json::json!({"url": url, "fetched": "2026-10-10", "sha256": sha256_hex(text), "entries": 1}),
                )
            })
            .collect();
        serde_json::to_string(&m).unwrap()
    }

    #[test]
    fn embeds_only_catalog_files_that_parse_and_match_their_hash() {
        let cat = Catalog::bundled();
        let url = cat
            .range_files
            .iter()
            .find(|f| f.id == "openai.chatgpt-user")
            .unwrap()
            .url
            .clone();
        let mut files = BTreeMap::new();
        files.insert("openai.chatgpt-user".to_string(), RANGES.to_string());
        files.insert("openai.gptbot".to_string(), "not a range file".to_string());
        files.insert("perplexity.bot".to_string(), RANGES.to_string());
        files.insert("made.up".to_string(), RANGES.to_string());
        let idx = index(&[
            ("openai.chatgpt-user", &url, RANGES),
            ("openai.gptbot", "", "not a range file"),
            // Recorded with another file's hash.
            ("perplexity.bot", "", "something else"),
        ]);
        let (s, w) = snapshot(cat, &idx, &files).unwrap();
        assert_eq!(s.files.len(), 1, "{w:?}");
        assert_eq!(s.files[0].id, "openai.chatgpt-user");
        assert_eq!(s.files[0].fetched, "2026-10-10");
        assert_eq!(s.files[0].entries, 1);
        assert!(s.ranges.contains_key("openai.chatgpt-user"));
        assert_eq!(w.len(), 3, "{w:?}");
        assert!(w.iter().any(|x| x.starts_with("made.up")));
        let json = s.to_json();
        assert!(json.contains("\"catalog\"") && json.contains("ChatGPT-User"));
    }

    #[test]
    fn a_bad_index_is_an_error_and_no_snapshot_is_the_catalog_alone() {
        assert!(snapshot(Catalog::bundled(), "nope", &BTreeMap::new()).is_err());
        let s = Snapshot::empty(Catalog::bundled());
        assert!(s.files.is_empty() && s.ranges.is_empty());
        assert!(!s.catalog.agents.is_empty());
    }
}
