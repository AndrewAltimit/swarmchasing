//! Public notices.
//!
//! - What a public notice withholds ([`PublicView`]): callback channels (inbox,
//!   webhook and topic identifiers, paste links), e-mail addresses, run
//!   identifiers that cannot be told apart from credentials, and the request
//!   details for endpoints the admin marked compromised. Anything the view
//!   cannot classify is withheld and flagged for the admin.
//! - A last check over finished text ([`lint_public`]), run on every notice
//!   before it is published and on every committed notice in CI.
//! - The notice file (`notices/<id>.md`): TOML front matter with the status
//!   and the dated updates, then the notice body in Markdown.
//! - What the site and the feed are built from: the body parsed into plain
//!   blocks ([`md_blocks`]) that the page renders as text, and an Atom feed
//!   with one entry per update ([`atom_feed`]).

use crate::analyze::{Analysis, ObsResult};
use crate::model::IndicatorKind;
use crate::rules::{Matcher, Rules, Target};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap};
use std::fmt::Write;
use std::sync::OnceLock;

/// Linking parameters that carry a run or scan tag. Other linking parameters
/// (`tok`, `session`, `sid`, `nonce`) may be credentials and are withheld.
pub const TAG_PARAMS: &[&str] = &[
    "uqtag", "uqscan", "uq_tag", "tag", "run", "runid", "run_id", "cb_tag",
];

pub const WITHHELD: &str = "[withheld]";

fn email_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(r"(?i)\b([a-z0-9._%+-]+)(@|%40)([a-z0-9-]+(\.[a-z0-9-]+)+)\b").unwrap()
    })
}

/// Role mailboxes that may appear in a notice (contacts, corrections).
const ROLE_MAILBOXES: &[&str] = &[
    "security",
    "abuse",
    "cert",
    "csirt",
    "psirt",
    "soc",
    "info",
    "contact",
    "press",
    "disclosure",
    "trustandsafety",
    "safety",
    "noreply",
    "no-reply",
];

/// Replace the local part of every e-mail address: a disposable inbox is a
/// callback channel.
pub fn mask_emails(s: &str) -> String {
    email_re()
        .replace_all(s, |c: &regex::Captures| {
            format!("{WITHHELD}{}{}", &c[2], &c[3])
        })
        .into_owned()
}

/// Decides what a public notice may show, and remembers what it withheld.
pub struct PublicView {
    kinds: HashMap<String, IndicatorKind>,
    exposed: BTreeSet<String>,
    /// What was withheld, for the admin.
    pub withheld: BTreeSet<String>,
    /// What could not be classified (also withheld), for the admin.
    pub flags: BTreeSet<String>,
}

impl PublicView {
    pub fn new(a: &Analysis, exposed_hosts: &[String]) -> Self {
        let mut kinds = HashMap::new();
        for r in &a.results {
            for h in &r.hits {
                kinds.insert(h.rule_id.clone(), h.kind);
            }
        }
        Self {
            kinds,
            exposed: exposed_hosts
                .iter()
                .map(|h| h.to_ascii_lowercase())
                .collect(),
            withheld: BTreeSet::new(),
            flags: BTreeSet::new(),
        }
    }

    /// An endpoint whose request details are withheld (compromised, so the
    /// weakness may still be open).
    pub fn exposed(&self, host: &str) -> bool {
        self.exposed.contains(&host.to_ascii_lowercase())
    }

    pub fn note_exposed(&mut self, host: &str) {
        self.withheld.insert(format!(
            "attack details for {} (endpoint marked compromised)",
            host.replace('.', "[.]")
        ));
    }

    /// The value to show for a linking feature, or `None` to withhold it.
    fn feature_value<'f>(&mut self, f: &'f str) -> Option<&'f str> {
        if let Some(rest) = f.strip_prefix("param:") {
            let (name, value) = rest.split_once('=').unwrap_or((rest, ""));
            if TAG_PARAMS.contains(&name) {
                return Some(f);
            }
            self.withheld
                .insert(format!("value of linking parameter `{name}`"));
            self.flags.insert(format!(
                "linking parameter `{name}` (value {} chars) could be a credential, so it was withheld; if it is a plain run tag, add it back by hand",
                value.chars().count()
            ));
            return None;
        }
        let (rule, _) = f.split_once(':').unwrap_or((f, ""));
        match self.kinds.get(rule) {
            Some(IndicatorKind::AgentMarker) => Some(f),
            Some(IndicatorKind::Exfil) => {
                self.withheld
                    .insert(format!("callback channel identifiers (`{rule}`)"));
                None
            }
            _ => {
                self.withheld.insert(format!("linking identifier `{rule}`"));
                self.flags.insert(format!(
                    "linking identifier from `{rule}` is neither a tag nor a callback channel, so it was withheld"
                ));
                None
            }
        }
    }

    /// A linking feature as a notice may show it.
    pub fn feature(&mut self, f: &str) -> String {
        match self.feature_value(f) {
            Some(v) => mask_emails(v),
            None => match f.strip_prefix("param:") {
                Some(p) => format!("param:{}={WITHHELD}", p.split('=').next().unwrap_or(p)),
                None => format!("{}:{WITHHELD}", f.split(':').next().unwrap_or(f)),
            },
        }
    }

    /// A record's URL as a notice may show it, or `None` when it must be
    /// withheld entirely: it reaches a callback channel, it targets an exposed
    /// endpoint, or a withheld identifier in it could not be located.
    pub fn record_url(&mut self, r: &ObsResult) -> Option<String> {
        if let Some(h) = r.hits.iter().find(|h| h.kind == IndicatorKind::Exfil) {
            self.withheld
                .insert(format!("callback channel identifiers (`{}`)", h.rule_id));
            return None;
        }
        if let Some(h) = r.target_host.as_deref()
            && self.exposed(h)
        {
            self.note_exposed(h);
            return None;
        }
        let mut url = r.obs.url.clone();
        for f in &r.features {
            if self.feature_value(f).is_some() {
                continue;
            }
            let value = f
                .strip_prefix("param:")
                .and_then(|p| p.split_once('=').map(|x| x.1))
                .or_else(|| f.split_once(':').map(|x| x.1))
                .unwrap_or("");
            let lower = url.to_ascii_lowercase();
            match lower.find(&value.to_ascii_lowercase()) {
                Some(p) if !value.is_empty() && lower.len() == url.len() => {
                    url.replace_range(p..p + value.len(), WITHHELD);
                }
                _ => return None,
            }
        }
        Some(mask_emails(&url))
    }
}

/// Undo `defang` so the lint sees what a reader could rebuild.
fn refang(s: &str) -> String {
    s.replace("hxxp", "http")
        .replace("[.]", ".")
        .replace("[:]", ":")
}

/// Check finished public text for anything a notice must not carry: callback
/// channel identifiers (the linking callback rules), e-mail addresses other
/// than role mailboxes, and credential shapes. Returns one line per problem.
pub fn lint_public(text: &str, rules: &Rules) -> Vec<String> {
    let plain = refang(text);
    let mut out = Vec::new();
    for r in rules.of_target(Target::Url) {
        if r.def.kind != IndicatorKind::Exfil || !r.def.link {
            continue;
        }
        if let Matcher::Re(re) = &r.matcher {
            for m in re.find_iter(&plain) {
                out.push(format!(
                    "callback channel identifier ({}): {}",
                    r.def.id,
                    crate::model::truncate(m.as_str(), 60)
                ));
            }
        }
    }
    for c in email_re().captures_iter(&plain) {
        let local = c[1].to_ascii_lowercase();
        if local != "withheld" && !ROLE_MAILBOXES.contains(&local.as_str()) {
            out.push(format!("e-mail address: {}", &c[0]));
        }
    }
    for m in crate::redact::secret_value().find_iter(&plain) {
        out.push(format!(
            "credential-shaped value: {}…",
            m.as_str().chars().take(8).collect::<String>()
        ));
    }
    out
}

// ── Notice files ───────────────────────────────────────────────────────────

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

// ── Site and feed ──────────────────────────────────────────────────────────

/// Inline Markdown, as plain text spans. The page inserts each as text.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "t", content = "v", rename_all = "snake_case")]
pub enum Inline {
    Text(String),
    Strong(String),
    Code(String),
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ListItem {
    pub c: Vec<Inline>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub sub: Vec<Vec<Inline>>,
}

/// The block subset the report renderer writes.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum Block {
    Heading {
        level: u8,
        c: Vec<Inline>,
    },
    Para {
        c: Vec<Inline>,
    },
    Quote {
        lines: Vec<Vec<Inline>>,
    },
    List {
        ordered: bool,
        items: Vec<ListItem>,
    },
    Table {
        head: Vec<Vec<Inline>>,
        rows: Vec<Vec<Vec<Inline>>>,
    },
}

pub fn md_inline(s: &str) -> Vec<Inline> {
    let mut out = Vec::new();
    let mut text = String::new();
    let mut rest = s;
    while !rest.is_empty() {
        let (marker, ctor): (&str, fn(String) -> Inline) = if rest.starts_with("**") {
            ("**", Inline::Strong)
        } else if rest.starts_with('`') {
            ("`", Inline::Code)
        } else {
            let ch = rest.chars().next().unwrap_or_default();
            text.push(ch);
            rest = &rest[ch.len_utf8()..];
            continue;
        };
        match rest[marker.len()..].find(marker) {
            Some(end) => {
                if !text.is_empty() {
                    out.push(Inline::Text(std::mem::take(&mut text)));
                }
                out.push(ctor(rest[marker.len()..marker.len() + end].to_string()));
                rest = &rest[marker.len() * 2 + end..];
            }
            None => {
                text.push_str(marker);
                rest = &rest[marker.len()..];
            }
        }
    }
    if !text.is_empty() {
        out.push(Inline::Text(text));
    }
    out
}

fn table_cells(line: &str) -> Vec<Vec<Inline>> {
    let inner = line.trim().trim_start_matches('|');
    let inner = inner.strip_suffix('|').unwrap_or(inner);
    let mut cells = Vec::new();
    let mut cur = String::new();
    let mut chars = inner.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\\' if chars.peek() == Some(&'|') => {
                cur.push('|');
                chars.next();
            }
            '|' => cells.push(std::mem::take(&mut cur)),
            c => cur.push(c),
        }
    }
    cells.push(cur);
    cells.iter().map(|c| md_inline(c.trim())).collect()
}

fn list_marker(line: &str) -> Option<(usize, bool, &str)> {
    let indent = line.len() - line.trim_start().len();
    let t = line.trim_start();
    if let Some(r) = t.strip_prefix("- ") {
        return Some((indent, false, r));
    }
    let digits = t.chars().take_while(|c| c.is_ascii_digit()).count();
    if digits > 0
        && let Some(r) = t[digits..].strip_prefix(". ")
    {
        return Some((indent, true, r));
    }
    None
}

/// Parse a notice body into blocks.
pub fn md_blocks(body: &str) -> Vec<Block> {
    let lines: Vec<&str> = body.lines().collect();
    let mut out = Vec::new();
    let mut i = 0;
    let mut para: Vec<&str> = Vec::new();
    let flush = |para: &mut Vec<&str>, out: &mut Vec<Block>| {
        if !para.is_empty() {
            out.push(Block::Para {
                c: md_inline(&para.join(" ")),
            });
            para.clear();
        }
    };
    while i < lines.len() {
        let line = lines[i];
        let t = line.trim();
        if t.is_empty() {
            flush(&mut para, &mut out);
            i += 1;
        } else if t.starts_with("<!--") {
            flush(&mut para, &mut out);
            while i < lines.len() && !lines[i].contains("-->") {
                i += 1;
            }
            i += 1;
        } else if let Some(level) = (1..=4).find(|&n| t.starts_with(&format!("{} ", "#".repeat(n))))
        {
            flush(&mut para, &mut out);
            out.push(Block::Heading {
                level: level as u8,
                c: md_inline(t[level + 1..].trim()),
            });
            i += 1;
        } else if t.starts_with('>') {
            flush(&mut para, &mut out);
            let mut q = Vec::new();
            while i < lines.len() && lines[i].trim().starts_with('>') {
                let l = lines[i].trim().trim_start_matches('>').trim();
                q.push(md_inline(l));
                i += 1;
            }
            out.push(Block::Quote { lines: q });
        } else if t.starts_with('|') {
            flush(&mut para, &mut out);
            let head = table_cells(t);
            i += 1;
            if lines.get(i).is_some_and(|l| {
                let l = l.trim();
                l.starts_with("|-") || l.starts_with("|:")
            }) {
                i += 1;
            }
            let mut rows = Vec::new();
            while i < lines.len() && lines[i].trim().starts_with('|') {
                rows.push(table_cells(lines[i]));
                i += 1;
            }
            out.push(Block::Table { head, rows });
        } else if let Some((0, ordered, _)) = list_marker(line) {
            flush(&mut para, &mut out);
            let mut items: Vec<ListItem> = Vec::new();
            while i < lines.len() {
                match list_marker(lines[i]) {
                    Some((0, o, r)) if o == ordered => items.push(ListItem {
                        c: md_inline(r),
                        sub: Vec::new(),
                    }),
                    Some((n, _, r)) if n > 0 && !items.is_empty() => {
                        if let Some(last) = items.last_mut() {
                            last.sub.push(md_inline(r));
                        }
                    }
                    _ => break,
                }
                i += 1;
            }
            out.push(Block::List { ordered, items });
        } else {
            para.push(t);
            i += 1;
        }
    }
    flush(&mut para, &mut out);
    out
}

/// One row of the site's notice index.
#[derive(Debug, Clone, Serialize)]
pub struct IndexEntry<'a> {
    pub id: &'a str,
    pub title: &'a str,
    pub status: NoticeStatus,
    pub published: &'a str,
    pub updated: &'a str,
    pub providers: &'a [String],
    pub affected: &'a [String],
    pub corrected: bool,
    pub retracted: bool,
}

pub fn index_entry(n: &NoticeFile) -> IndexEntry<'_> {
    let has = |k| n.meta.updates.iter().any(|u| u.kind == k);
    IndexEntry {
        id: &n.meta.id,
        title: &n.meta.title,
        status: n.meta.status,
        published: &n.meta.published,
        updated: &n.meta.updated,
        providers: &n.meta.providers,
        affected: &n.meta.affected,
        corrected: has(UpdateKind::Correction),
        retracted: has(UpdateKind::Retraction),
    }
}

/// A notice page for the site: its front matter and its body as blocks.
#[derive(Debug, Clone, Serialize)]
pub struct NoticePage<'a> {
    pub meta: &'a NoticeMeta,
    pub blocks: Vec<Block>,
}

fn xml(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => o.push_str("&amp;"),
            '<' => o.push_str("&lt;"),
            '>' => o.push_str("&gt;"),
            '"' => o.push_str("&quot;"),
            '\'' => o.push_str("&apos;"),
            c if (c as u32) < 0x20 && !matches!(c, '\n' | '\t' | '\r') => {}
            c => o.push(c),
        }
    }
    o
}

/// An Atom feed with one entry per notice update, newest first. `base` is
/// the site's URL, ending in `/`.
pub fn atom_feed(notices: &[NoticeFile], base: &str) -> String {
    let mut entries: Vec<(&NoticeFile, usize, &NoticeUpdate)> = notices
        .iter()
        .flat_map(|n| {
            n.meta
                .updates
                .iter()
                .enumerate()
                .map(move |(i, u)| (n, i, u))
        })
        .collect();
    entries.sort_by(|a, b| {
        b.2.date
            .cmp(&a.2.date)
            .then(a.0.meta.id.cmp(&b.0.meta.id))
            .then(b.1.cmp(&a.1))
    });
    let newest = entries
        .first()
        .map(|e| e.2.date.as_str())
        .unwrap_or("1970-01-01");
    let mut s = String::new();
    let _ = writeln!(s, r#"<?xml version="1.0" encoding="utf-8"?>"#);
    let _ = writeln!(s, r#"<feed xmlns="http://www.w3.org/2005/Atom">"#);
    let _ = writeln!(s, "  <title>Swarmchasing notices</title>");
    let _ = writeln!(s, "  <id>{}notices/feed.xml</id>", xml(base));
    let _ = writeln!(
        s,
        r#"  <link rel="self" href="{}notices/feed.xml"/>"#,
        xml(base)
    );
    let _ = writeln!(s, r#"  <link href="{}"/>"#, xml(base));
    let _ = writeln!(s, "  <updated>{newest}T00:00:00Z</updated>");
    let _ = writeln!(s, "  <author><name>swarmchasing</name></author>");
    for (n, i, u) in entries {
        let link = format!("{base}#notice={}", n.meta.id);
        let _ = writeln!(s, "  <entry>");
        let _ = writeln!(
            s,
            "    <title>{}: {}</title>",
            xml(u.kind.label()),
            xml(&n.meta.title)
        );
        let _ = writeln!(s, "    <id>{}#{i}</id>", xml(&link));
        let _ = writeln!(s, r#"    <link href="{}"/>"#, xml(&link));
        let _ = writeln!(s, "    <updated>{}T00:00:00Z</updated>", xml(&u.date));
        let from = u
            .from
            .as_deref()
            .map(|f| format!("Statement from {f}: "))
            .unwrap_or_default();
        let _ = writeln!(
            s,
            r#"    <content type="text">{}{}</content>"#,
            xml(&from),
            xml(&u.text)
        );
        let _ = writeln!(s, "  </entry>");
    }
    let _ = writeln!(s, "</feed>");
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyze::analyze;
    use crate::model::Observation;

    fn obs(id: &str, ts: i64, url: &str) -> Observation {
        Observation {
            id: id.into(),
            ts,
            url: url.into(),
            ..Default::default()
        }
    }

    #[test]
    fn view_withholds_channels_credentials_and_exposed_hosts() {
        let rules = Rules::default_rules();
        let a = analyze(
            vec![
                obs(
                    "a",
                    1_791_000_000,
                    "https://r.jina.ai/https://portal.example.gov/q?id=1%20UNION%20SELECT%201&uqtag=zz9&tok=abcdef123",
                ),
                obs(
                    "b",
                    1_791_000_030,
                    "https://r.jina.ai/https://portal.example.gov/q?id=2%20UNION%20SELECT%201&uqtag=zz9&cb=https://webhook.site/0f8fad5b-d9cb-469f-a165-70867728950e",
                ),
                obs(
                    "c",
                    1_791_000_060,
                    "https://r.jina.ai/https://hit.example.org/q?id=3%20UNION%20SELECT%201",
                ),
            ],
            &rules,
        );
        let mut v = PublicView::new(&a, &["HIT.example.org".into()]);
        let by = |id: &str| a.results.iter().find(|r| r.obs.id == id).unwrap();

        let url = v.record_url(by("a")).unwrap();
        assert!(url.contains("uqtag=zz9"), "{url}");
        assert!(
            url.contains("tok=[withheld]") && !url.contains("abcdef123"),
            "{url}"
        );
        assert!(v.record_url(by("b")).is_none(), "callback channel");
        assert!(v.record_url(by("c")).is_none(), "exposed endpoint");

        assert_eq!(v.feature("param:uqtag=zz9"), "param:uqtag=zz9");
        assert_eq!(v.feature("param:tok=abcdef123"), "param:tok=[withheld]");
        assert!(
            v.feature("exfil.webhook_site:webhook.site/0f8fad5b-d9cb-469f-a165-70867728950e")
                .ends_with(WITHHELD)
        );
        assert!(v.flags.iter().any(|f| f.contains("`tok`")), "{:?}", v.flags);
        assert!(v.withheld.iter().any(|w| w.contains("hit[.]example[.]org")));
        assert_eq!(
            mask_emails("write to x9q2@mail.tm or a%40b.example"),
            "write to [withheld]@mail.tm or [withheld]%40b.example"
        );
    }

    #[test]
    fn lint_finds_what_a_notice_must_not_carry() {
        let rules = Rules::default_rules();
        let key = "AKIAABCDEFGHIJKLMNOP"; // secret-scan: fixture (fake key)
        let bad = format!(
            "see hxxps://webhook[.]site/0f8fad5b-d9cb-469f-a165-70867728950e and ntfy.sh/agent-run-77, mail x9q2@mail.tm, key {key}"
        );
        let l = lint_public(&bad, &rules);
        assert_eq!(l.len(), 4, "{l:?}");
        let good = "Contact security@example.org. Inbox: [withheld]@mail.tm. Channel `exfil.ntfy:[withheld]`. ntfy.sh is a notification service.";
        assert!(
            lint_public(good, &rules).is_empty(),
            "{:?}",
            lint_public(good, &rules)
        );
    }

    fn notice() -> NoticeFile {
        NoticeFile {
            meta: NoticeMeta {
                id: "2026-10-portal".into(),
                title: "Portal <probe> & co".into(),
                status: NoticeStatus::Active,
                published: "2026-10-20".into(),
                updated: "2026-10-22".into(),
                providers: vec![],
                affected: vec!["portal.example.gov".into()],
                rules_version: "2026-10-12".into(),
                toolkit: "0.1.0".into(),
                updates: vec![
                    NoticeUpdate {
                        date: "2026-10-20".into(),
                        kind: UpdateKind::Published,
                        from: None,
                        text: "Initial notice.".into(),
                    },
                    NoticeUpdate {
                        date: "2026-10-22".into(),
                        kind: UpdateKind::Correction,
                        from: None,
                        text: "The window started a day later.".into(),
                    },
                ],
            },
            body: "# Notice\n\n- **Window:** a → b\n\n## Endpoints\n\n| Host | Hits |\n|---|---|\n| `a[.]b` | 3 \\| 4 |\n\n1. one — `x`\n   - rules: r1\n2. two\n\n> quoted **line**\n\nplain\ncontinued\n".into(),
        }
    }

    #[test]
    fn notice_file_round_trips_and_checks() {
        let n = notice();
        let text = write_notice(&n);
        assert!(
            text.starts_with("+++\n") && text.contains("[[update]]"),
            "{text}"
        );
        let back = parse_notice(&text).unwrap();
        assert_eq!(back, n);
        assert!(check_notice(&n, &Rules::default_rules()).is_empty());

        let mut bad = n.clone();
        bad.body.push_str("\n> **DRAFT** — x\n");
        bad.meta.updated = "2026-10-21".into();
        bad.meta.updates[1].text = "inbox is ntfy.sh/agent-run-77".into();
        assert_eq!(check_notice(&bad, &Rules::default_rules()).len(), 3);
        assert!(parse_notice("no front matter").is_err());
        assert!(parse_notice(&text.replace("2026-10-portal", "../x")).is_err());
    }

    #[test]
    fn blocks_cover_the_report_subset() {
        let b = md_blocks(&notice().body);
        assert!(matches!(&b[0], Block::Heading { level: 1, .. }));
        let Block::List {
            ordered: false,
            items,
        } = &b[1]
        else {
            panic!("{b:?}")
        };
        assert_eq!(
            items[0].c,
            vec![
                Inline::Strong("Window:".into()),
                Inline::Text(" a → b".into())
            ]
        );
        let Block::Table { head, rows } = &b[3] else {
            panic!("{b:?}")
        };
        assert_eq!(head.len(), 2);
        assert_eq!(rows[0][1], vec![Inline::Text("3 | 4".into())]);
        assert_eq!(rows[0][0], vec![Inline::Code("a[.]b".into())]);
        let Block::List {
            ordered: true,
            items,
        } = &b[4]
        else {
            panic!("{b:?}")
        };
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].sub.len(), 1);
        assert!(matches!(&b[5], Block::Quote { lines } if lines.len() == 1));
        assert_eq!(
            b[6],
            Block::Para {
                c: vec![Inline::Text("plain continued".into())]
            }
        );
        assert_eq!(md_inline("a ** b"), vec![Inline::Text("a ** b".into())]);
    }

    #[test]
    fn feed_escapes_and_orders_updates() {
        let f = atom_feed(&[notice()], "https://example.github.io/swarmchasing/");
        assert!(
            f.contains("<title>Correction: Portal &lt;probe&gt; &amp; co</title>"),
            "{f}"
        );
        assert!(f.find("Correction:").unwrap() < f.find("Published:").unwrap());
        assert!(f.contains("<updated>2026-10-22T00:00:00Z</updated>"));
        assert!(f.contains("#notice=2026-10-portal#1"));
    }
}
