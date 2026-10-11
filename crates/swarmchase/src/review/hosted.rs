//! Label suggestions from a hosted model.
//!
//! Policy (docs/policies.md, machine help with labelling): a model the admin
//! does not control may see the public records in [`HOSTED_SOURCES`] (web
//! archive indexes and urlquery), for private labelling only. Operator
//! access logs and any source not on the list are withheld, so a new
//! collector is withheld until someone adds it here on purpose.
//!
//! `review --export-hosted <file>` writes the queue's allowed records as the
//! same text a local model gets ([`crate::suggest::record_text`]): defanged,
//! no IP addresses. The file must be inside the data directory. The model's
//! answers go in `<data>/labels/suggestions-<name>.ndjson`, one
//! `{"id", "label", "reason", "model"}` per line, and `review --serve` shows
//! them beside each record. A suggestion is saved beside the admin's label as
//! `suggested`, never as it, and one for a record outside [`HOSTED_SOURCES`]
//! is dropped when the file is read.

use super::Item;
use crate::suggest::Suggestion;
use crate::util::truncate;
use anyhow::{Context, Result, bail};
use sc_core::Analysis;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Record sources a hosted model may see: public web archive indexes and urlquery.
pub const HOSTED_SOURCES: &[&str] = &["wayback", "arquivo", "memento", "commoncrawl", "urlquery"];

pub fn hosted_ok(source: &str) -> bool {
    HOSTED_SOURCES.contains(&source)
}

/// One exported record: its id, its review group and the text the model reads.
#[derive(Debug, Serialize, Deserialize)]
pub struct ExportLine {
    pub id: String,
    pub group: String,
    pub text: String,
}

/// The export of `items`: the allowed records, and the count withheld per source.
pub fn export_lines(a: &Analysis, items: &[Item]) -> (Vec<ExportLine>, BTreeMap<String, usize>) {
    let mut lines = Vec::new();
    let mut withheld = BTreeMap::new();
    for it in items {
        let r = &a.results[it.idx];
        if !hosted_ok(&r.obs.source) {
            *withheld.entry(r.obs.source.clone()).or_default() += 1;
            continue;
        }
        lines.push(ExportLine {
            id: r.obs.id.clone(),
            group: super::serve::group_of(a, it.idx).0,
            text: crate::suggest::record_text(a, it.idx),
        });
    }
    (lines, withheld)
}

/// `review --export-hosted <out>`.
pub fn export(a: &Analysis, items: &[Item], data: &Path, out: &Path) -> Result<()> {
    check_in_data(data, out)?;
    let (lines, withheld) = export_lines(a, items);
    let mut text = String::new();
    for l in &lines {
        text.push_str(&serde_json::to_string(l)?);
        text.push('\n');
    }
    std::fs::write(out, text).with_context(|| format!("writing {}", out.display()))?;
    let held: Vec<String> = withheld.iter().map(|(s, n)| format!("{s} {n}")).collect();
    println!(
        "{} record(s) written to {} for a hosted model; withheld: {}",
        lines.len(),
        out.display(),
        if held.is_empty() {
            "none".into()
        } else {
            held.join(", ")
        }
    );
    println!(
        "suggestions go in {}, one {{\"id\", \"label\", \"reason\", \"model\"}} per line; `review --serve` shows them",
        data.join("labels")
            .join("suggestions-<name>.ndjson")
            .display()
    );
    Ok(())
}

/// The export holds record content, so it is written only inside the data
/// directory, which stays out of git.
fn check_in_data(data: &Path, out: &Path) -> Result<()> {
    let root = std::fs::canonicalize(data)
        .with_context(|| format!("data directory {}", data.display()))?;
    let parent = match out.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => PathBuf::from("."),
    };
    let dir = std::fs::canonicalize(&parent)
        .with_context(|| format!("export directory {}", parent.display()))?;
    if !dir.starts_with(&root) {
        bail!(
            "--export-hosted {}: write the export inside the data directory {}, which stays out of git",
            out.display(),
            data.display()
        );
    }
    Ok(())
}

#[derive(Deserialize)]
struct SuggestionLine {
    id: String,
    label: String,
    #[serde(default)]
    reason: String,
    #[serde(default)]
    model: String,
}

/// Suggestions read from `labels/suggestions-*.ndjson`, and the lines dropped.
#[derive(Debug, Default)]
pub struct Loaded {
    pub by_id: BTreeMap<String, Suggestion>,
    /// Lines that did not parse or gave another label.
    pub invalid: usize,
    /// Suggestions for a record outside [`HOSTED_SOURCES`] or not in the analysis.
    pub dropped: usize,
}

/// Every suggestions file in `dir`, in name order (a later file wins).
pub fn load_suggestions(dir: &Path, a: &Analysis) -> Result<Loaded> {
    let source: BTreeMap<&str, &str> = a
        .results
        .iter()
        .map(|r| (r.obs.id.as_str(), r.obs.source.as_str()))
        .collect();
    let mut files: Vec<PathBuf> = match std::fs::read_dir(dir) {
        Ok(rd) => rd
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| {
                p.file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.starts_with("suggestions-") && n.ends_with(".ndjson"))
            })
            .collect(),
        Err(_) => Vec::new(),
    };
    files.sort();
    let mut out = Loaded::default();
    for f in files {
        let text =
            std::fs::read_to_string(&f).with_context(|| format!("reading {}", f.display()))?;
        for line in text.lines().filter(|l| !l.trim().is_empty()) {
            let Ok(s) = serde_json::from_str::<SuggestionLine>(line) else {
                out.invalid += 1;
                continue;
            };
            let label = s.label.trim().to_ascii_lowercase();
            if !matches!(label.as_str(), "agent" | "benign" | "unsure") {
                out.invalid += 1;
                continue;
            }
            if !source.get(s.id.as_str()).is_some_and(|src| hosted_ok(src)) {
                out.dropped += 1;
                continue;
            }
            let reason = s.reason.split_whitespace().collect::<Vec<_>>().join(" ");
            let model = if s.model.trim().is_empty() {
                "hosted model".to_string()
            } else {
                truncate(s.model.trim(), 60)
            };
            out.by_id.insert(
                s.id,
                Suggestion {
                    label,
                    reason: crate::suggest::defang_all(&truncate(&reason, 200)),
                    model,
                },
            );
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::review::{CLASS_FLAGGED, queue};
    use sc_core::{Observation, Rules, Tier, analyze};
    use std::collections::BTreeSet;

    fn analysis() -> Analysis {
        let o = |id: &str, source: &str, url: &str| Observation {
            id: id.into(),
            source: source.into(),
            ts: 1000,
            url: url.into(),
            ip: Some("203.0.113.9".into()),
            ..Default::default()
        };
        analyze(
            vec![
                o(
                    "wayback:1",
                    "wayback",
                    "https://r.jina.ai/https://t.example/?q=1%20OR%201=1",
                ),
                o(
                    "urlquery:2",
                    "urlquery",
                    "https://r.jina.ai/https://u.example/?q=1%20OR%201=1",
                ),
                o(
                    "lines:3",
                    "lines",
                    "https://r.jina.ai/https://v.example/?q=1%20OR%201=1",
                ),
            ],
            &Rules::default_rules(),
        )
    }

    fn tmp(name: &str) -> PathBuf {
        let d =
            std::env::temp_dir().join(format!("swarmchase-hosted-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join("labels")).unwrap();
        d
    }

    #[test]
    fn only_listed_sources_are_exported_and_no_ip() {
        let a = analysis();
        let items = queue(&a, &BTreeSet::new(), Tier::Suggestive, 0);
        assert_eq!(items.len(), 3);
        assert!(items.iter().all(|i| i.class == CLASS_FLAGGED));
        let (lines, withheld) = export_lines(&a, &items);
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0].id, "wayback:1");
        assert!(!lines[0].text.contains("203.0.113.9"));
        assert!(lines[0].text.contains("t[.]example"), "{}", lines[0].text);
        assert_eq!(
            withheld.get("lines"),
            Some(&1),
            "operator logs stay withheld"
        );
        assert_eq!(withheld.len(), 1);
        assert!(!hosted_ok("urlscan") && hosted_ok("urlquery") && hosted_ok("wayback"));
    }

    #[test]
    fn export_stays_in_the_data_directory() {
        let d = tmp("export");
        let a = analysis();
        let items = queue(&a, &BTreeSet::new(), Tier::Suggestive, 0);
        let out = d.join("labels").join("hosted.ndjson");
        export(&a, &items, &d, &out).unwrap();
        let text = std::fs::read_to_string(&out).unwrap();
        assert_eq!(text.lines().count(), 2);
        let outside =
            std::env::temp_dir().join(format!("swarmchase-outside-{}.ndjson", std::process::id()));
        let err = export(&a, &items, &d, &outside).unwrap_err().to_string();
        assert!(err.contains("inside the data directory"), "{err}");
        assert!(!outside.exists());
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn suggestions_for_withheld_sources_are_dropped() {
        let d = tmp("load");
        let a = analysis();
        std::fs::write(
            d.join("labels").join("suggestions-claude.ndjson"),
            [
                r#"{"id":"wayback:1","label":"Agent","reason":"sqli via   r.jina.ai","model":"m"}"#,
                r#"{"id":"lines:3","label":"agent","reason":"x"}"#,
                r#"{"id":"nope","label":"agent"}"#,
                r#"{"id":"wayback:1","label":"maybe"}"#,
                "not json",
            ]
            .join("\n"),
        )
        .unwrap();
        std::fs::write(d.join("labels").join("reviewed.ndjson"), "").unwrap();
        let l = load_suggestions(&d.join("labels"), &a).unwrap();
        assert_eq!(l.by_id.len(), 1);
        let s = &l.by_id["wayback:1"];
        assert_eq!(s.label, "agent");
        assert_eq!(s.reason, "sqli via r[.]jina[.]ai");
        assert_eq!(s.model, "m");
        assert_eq!((l.invalid, l.dropped), (2, 2));
        std::fs::remove_dir_all(&d).unwrap();
    }
}
