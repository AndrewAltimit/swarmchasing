//! The notice file (`notices/<id>.md`): TOML front matter with the status
//! and the dated updates, then the notice body in Markdown.

use sc_core::Rules;
use sc_core::notice::lint_public;
use serde::{Deserialize, Serialize};
use std::fmt::Write;

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

/// Problems that keep a notice file from being published.
pub fn check_notice(n: &NoticeFile, rules: &Rules) -> Vec<String> {
    let mut out = Vec::new();
    if n.body.contains("**DRAFT**") {
        out.push("still carries the DRAFT banner".into());
    }
    if n.meta.updates.is_empty() {
        out.push("has no updates (the first is `published`)".into());
    }
    if n.meta
        .updates
        .windows(2)
        .any(|w| w[1].date.as_str() < w[0].date.as_str())
    {
        out.push("updates are not in date order".into());
    }
    if let Some(last) = n.meta.updates.last()
        && last.date != n.meta.updated
    {
        out.push(format!(
            "`updated` is {}, the last update is {}",
            n.meta.updated, last.date
        ));
    }
    let mut text = n.body.clone();
    for u in &n.meta.updates {
        // A reply is quoted verbatim, but it is still published.
        let _ = writeln!(text, "\n{}", u.text);
    }
    let _ = writeln!(text, "\n{}", n.meta.title);
    out.extend(lint_public(&text, rules));
    out
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
