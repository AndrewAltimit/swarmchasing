//! The inbox's files under `<data>/inbox/`:
//!
//! ```text
//! settings.toml            optional: [intake], [intake.caps], [triage]
//! <id>/intake.json         the redacted submission, receipt time, transport,
//!                          fingerprints, injection flags
//! <id>/held.json           what the watch store held when it arrived
//! <id>/verification.json   lookups of its public-record references
//! <id>/found.ndjson        the records those lookups found (redacted)
//! <id>/admin.json          the admin's signature checks and actions
//! <id>/assessment.json     the latest triage
//! <id>/lead.ndjson         the records `inbox promote` queued for review
//! ```
//!
//! The bytes as received are never kept, only the redacted document.

use crate::store::{read_json, write_json};
use anyhow::{Context, Result, bail};
use sc_core::Observation;
use sc_inbox::{Assessment, Corroboration, Intake, Settings, Verification};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// The admin's signature check of one item.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SignatureCheck {
    /// Valid, and by a signer other than the submitter.
    pub valid: bool,
    pub date: String,
    pub note: String,
}

/// What the admin did with a submission.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Admin {
    #[serde(default)]
    pub signatures: BTreeMap<usize, SignatureCheck>,
    /// Dated lines: promotions and their reasons.
    #[serde(default)]
    pub log: Vec<String>,
}

impl Admin {
    pub fn signature_map(&self) -> BTreeMap<usize, bool> {
        self.signatures.iter().map(|(k, v)| (*k, v.valid)).collect()
    }
}

/// One stored submission and what has been checked about it.
pub struct Stored {
    pub dir: PathBuf,
    pub intake: Intake,
    pub held: Corroboration,
    pub verifications: Vec<Verification>,
    pub found: Vec<Observation>,
    pub admin: Admin,
    pub assessment: Option<Assessment>,
}

pub fn root(data: &Path) -> PathBuf {
    data.join("inbox")
}

/// `<data>/inbox/settings.toml`, or the defaults.
pub fn settings(data: &Path) -> Result<Settings> {
    let p = root(data).join("settings.toml");
    match std::fs::read_to_string(&p) {
        Ok(t) => toml::from_str(&t).with_context(|| format!("parsing {}", p.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Settings::default()),
        Err(e) => Err(e).with_context(|| format!("reading {}", p.display())),
    }
}

fn check_id(id: &str) -> Result<()> {
    let ok = id.starts_with("sub-")
        && id.len() <= 40
        && id
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
    if !ok {
        bail!("not a submission id: {id}");
    }
    Ok(())
}

pub fn dir(data: &Path, id: &str) -> Result<PathBuf> {
    check_id(id)?;
    Ok(root(data).join(id))
}

pub fn load(data: &Path, id: &str) -> Result<Stored> {
    let dir = dir(data, id)?;
    let intake: Intake = read_json(&dir.join("intake.json"))?
        .with_context(|| format!("no submission {id} in {}", root(data).display()))?;
    Ok(Stored {
        held: read_json(&dir.join("held.json"))?.unwrap_or_default(),
        verifications: read_json(&dir.join("verification.json"))?.unwrap_or_default(),
        found: read_ndjson(&dir.join("found.ndjson"))?,
        admin: read_json(&dir.join("admin.json"))?.unwrap_or_default(),
        assessment: read_json(&dir.join("assessment.json"))?,
        intake,
        dir,
    })
}

/// Every stored submission, oldest first.
pub fn all(data: &Path) -> Result<Vec<Stored>> {
    let mut out = Vec::new();
    if let Ok(entries) = std::fs::read_dir(root(data)) {
        for e in entries {
            let p = e?.path();
            if p.join("intake.json").is_file() {
                let id = p.file_name().unwrap_or_default().to_string_lossy();
                out.push(load(data, &id)?);
            }
        }
    }
    out.sort_by(|a, b| (a.intake.received, &a.intake.id).cmp(&(b.intake.received, &b.intake.id)));
    Ok(out)
}

impl Stored {
    pub fn save(&self) -> Result<()> {
        std::fs::create_dir_all(&self.dir)?;
        write_json(&self.dir.join("intake.json"), &self.intake)?;
        write_json(&self.dir.join("held.json"), &self.held)?;
        write_json(&self.dir.join("verification.json"), &self.verifications)?;
        write_json(&self.dir.join("admin.json"), &self.admin)?;
        if let Some(a) = &self.assessment {
            write_json(&self.dir.join("assessment.json"), a)?;
        }
        std::fs::write(
            self.dir.join("found.ndjson"),
            crate::store::to_ndjson(&self.found)?,
        )?;
        Ok(())
    }
}

pub fn read_ndjson(p: &Path) -> Result<Vec<Observation>> {
    match std::fs::read_to_string(p) {
        Ok(t) => t
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| serde_json::from_str(l).with_context(|| format!("parsing {}", p.display())))
            .collect(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(e) => Err(e).with_context(|| format!("reading {}", p.display())),
    }
}
