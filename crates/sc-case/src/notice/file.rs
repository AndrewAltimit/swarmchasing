//! The notice file (`notices/<id>.md`): TOML front matter with the status
//! and the dated updates, then the notice body in Markdown.

use sc_core::scope::ScopeFinding;
use serde::{Deserialize, Serialize};

/// The status a public notice shows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum NoticeStatus {
    #[default]
    Active,
    Contained,
    Historical,
}

impl NoticeStatus {
    pub fn label(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Contained => "contained",
            Self::Historical => "historical",
        }
    }
}

impl std::str::FromStr for NoticeStatus {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        match s.to_ascii_lowercase().as_str() {
            "active" => Ok(Self::Active),
            "contained" => Ok(Self::Contained),
            "historical" => Ok(Self::Historical),
            _ => Err(format!(
                "unknown notice status `{s}` (active|contained|historical)"
            )),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UpdateKind {
    Published,
    /// New activity, new endpoints, a contact's response.
    Update,
    /// The notice's status changed.
    Status,
    /// Something published was wrong.
    Correction,
    /// Names of affected organisations, added once each may be named
    /// (`notice update --naming`).
    Naming,
    /// A provider's or operator's statement, verbatim.
    Reply,
    /// The notice is withdrawn.
    Retraction,
}

impl UpdateKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::Published => "Published",
            Self::Update => "Update",
            Self::Status => "Status change",
            Self::Correction => "Correction",
            Self::Naming => "Affected organisations named",
            Self::Reply => "Statement",
            Self::Retraction => "Retraction",
        }
    }
}

impl std::str::FromStr for UpdateKind {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        match s.to_ascii_lowercase().as_str() {
            "update" => Ok(Self::Update),
            "status" => Ok(Self::Status),
            "correction" => Ok(Self::Correction),
            "reply" | "statement" => Ok(Self::Reply),
            "retraction" => Ok(Self::Retraction),
            "published" => Ok(Self::Published),
            "naming" => {
                Err("a naming update is appended with `notice update <id> --naming`".into())
            }
            _ => Err(format!(
                "unknown update kind `{s}` (update|status|correction|reply|retraction)"
            )),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NoticeUpdate {
    pub date: String,
    pub kind: UpdateKind,
    /// Who a reply is from.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
    pub text: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NoticeMeta {
    pub id: String,
    pub title: String,
    pub status: NoticeStatus,
    pub published: String,
    pub updated: String,
    /// Developers the notice names (at or above the case's naming threshold).
    #[serde(default)]
    pub providers: Vec<String>,
    /// Affected endpoints (hosts).
    #[serde(default)]
    pub affected: Vec<String>,
    /// The affected operators' sector, one of [`SECTORS`]. Optional.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sector: Option<String>,
    /// The admin's scope finding for the clusters the notice covers
    /// (`scope_exceeded` only when every one of them exceeded scope). The
    /// linter reads it for the word "misaligned".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<ScopeFinding>,
    /// The admin's agent grade for the case (`L0`..`L5`), which the linter
    /// reads for the word "misaligned". The body prints no grade.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_grade: Option<String>,
    pub rules_version: String,
    pub toolkit: String,
    #[serde(default, rename = "update")]
    pub updates: Vec<NoticeUpdate>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct NoticeFile {
    pub meta: NoticeMeta,
    pub body: String,
}

const FENCE: &str = "+++";

/// The sectors a notice's `sector` may name. A fixed list, so the notices
/// index can filter on it.
pub const SECTORS: &[&str] = &[
    "government",
    "health",
    "education",
    "research",
    "finance",
    "energy",
    "water",
    "telecom",
    "transport",
    "technology",
    "media",
    "nonprofit",
    "retail",
    "manufacturing",
    "other",
];

pub fn parse_notice(text: &str) -> Result<NoticeFile, String> {
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let rest = text
        .strip_prefix(FENCE)
        .and_then(|r| r.strip_prefix('\n').or_else(|| r.strip_prefix("\r\n")))
        .ok_or("a notice starts with `+++` front matter")?;
    let end = rest
        .find("\n+++")
        .ok_or("front matter is not closed with `+++`")?;
    let meta: NoticeMeta =
        toml::from_str(&rest[..end]).map_err(|e| format!("front matter: {e}"))?;
    let body = rest[end + 4..].trim_start_matches(['\r', '\n']).to_string();
    if !is_slug(&meta.id) {
        return Err(format!("notice id `{}` is not a slug", meta.id));
    }
    Ok(NoticeFile { meta, body })
}

pub fn write_notice(n: &NoticeFile) -> String {
    let meta = toml::to_string_pretty(&n.meta).unwrap_or_default();
    format!("{FENCE}\n{meta}{FENCE}\n\n{}\n", n.body.trim_end())
}

pub fn is_slug(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && !id.starts_with('-')
        && id
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

impl NoticeFile {
    /// Append a dated update, with the status it sets. Updates stay in date
    /// order; a statement names who it is from; `published` is only ever the
    /// first.
    pub fn append(&mut self, u: NoticeUpdate, status: Option<NoticeStatus>) -> Result<(), String> {
        if let Some(last) = self.meta.updates.last()
            && u.date < last.date
        {
            return Err(format!(
                "{} is before the last update ({})",
                u.date, last.date
            ));
        }
        if u.kind == UpdateKind::Reply && u.from.is_none() {
            return Err("a statement needs --from (who it is from)".into());
        }
        if u.kind == UpdateKind::Status && status.is_none() {
            return Err("a status update needs --status".into());
        }
        if u.kind == UpdateKind::Published {
            return Err("`published` is added by `notice add`".into());
        }
        if let Some(s) = status {
            self.meta.status = s;
        }
        self.meta.updated = u.date.clone();
        self.meta.updates.push(u);
        Ok(())
    }
}

/// A report draft's body without its DRAFT banner (and the blank line after
/// it), as a published notice carries it.
pub fn strip_draft_banner(body: &str) -> String {
    let mut out = String::new();
    let mut skip_blank = false;
    for line in body.lines() {
        if line.starts_with("> **DRAFT**") {
            skip_blank = true;
            continue;
        }
        if skip_blank && line.trim().is_empty() {
            skip_blank = false;
            continue;
        }
        skip_blank = false;
        out.push_str(line);
        out.push('\n');
    }
    out
}
