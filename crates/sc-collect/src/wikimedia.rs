//! Wikimedia EventStreams (`stream.wikimedia.org`): the edit streams of
//! Wikipedia and its sister wikis as Server-Sent Events. Two streams are
//! read, each from a checkpoint:
//!
//! - `mediawiki.page-links-change` for the record pass ([`WikiLinks`]): one
//!   record per external link an edit added. The record's URL is the link,
//!   never fetched; its reference is the edit's diff on the wiki.
//! - `mediawiki.revision-create` for the platform pass ([`pull_platform`]):
//!   one [`PlatformEvent`] per edit, with the editor as a keyed hash, the
//!   account's registration time as a coarse age, the edit summary as a
//!   sketch and the page title as a template (`user:<user>/sandbox`).
//!
//! Both drop the stream's `canary` events (the service's own health
//! checks) and edits by bot-flagged accounts before anything is kept.
//!
//! A third reader gives labels, not events ([`pull_ai_cleanup`]): the
//! pages editors tag as containing suspected AI-generated text. On the
//! English Wikipedia the cleanup template files a page in a monthly
//! category (`Articles containing suspected AI-generated texts from
//! October 2026`). The categorize events for it are in the
//! `mediawiki.recentchange` stream, which carries every change to every
//! wiki; reading the category itself through the MediaWiki API
//! (`list=categorymembers`, sorted by when each page was added, from the
//! checkpoint) gives the same pages in one or two requests a run. Each page
//! becomes a [`TargetLabel`] (`wiki-ai-cleanup`) on its `<wiki>/<title>`,
//! the target a revision event names, so a wiki candidate whose members
//! edited tagged pages says so. `endpoint` is the wiki (default
//! `en.wikipedia.org`), `pattern` the category name before ` from <month>`
//! (`*` for the default).
//!
//! Coverage: a pull resumes at the millisecond after the last event it read
//! (`since=`), reads until it reaches the time the pull began, and stops
//! early at `scan` minutes of wall time or `max_mb` megabytes; the next run
//! continues from there. Its coverage is in minutes of stream time: read
//! against there to read since the checkpoint. Without a checkpoint it
//! starts an hour back; a checkpoint older than [`MAX_BACKLOG_HOURS`] is
//! skipped to an hour back and the gap counted. A dropped connection is
//! reopened from the last event read, a few times per pull. Events parsed
//! are the canary: a pull that reads none means the format or the pipe
//! broke.
//!
//! `filter` narrows what is kept: `domain:<wiki>` keeps only those wikis,
//! `!domain:<wiki>` drops one, `ns:<n>` keeps only those namespaces.
//!
//! Terms: EventStreams is a public service
//! (<https://wikitech.wikimedia.org/wiki/Event_Platform/EventStreams_HTTP_Service>);
//! Wikimedia's User-Agent policy (<https://foundation.wikimedia.org/wiki/Policy:User-Agent_policy>)
//! asks clients to send an identifying user agent with contact details,
//! which the shared client does, and the API etiquette asks for one
//! connection at a time. Edits are published under the wikis' free
//! licences; we keep the edit's public diff link, time and the added link,
//! not the editor's name. The MediaWiki Action API's etiquette
//! (<https://www.mediawiki.org/wiki/API:Etiquette>) asks for serial
//! requests and an identifying user agent; the category reader makes a few
//! a run and keeps page titles and times only.

use crate::pager::{Coverage, Cursor, Page};
use crate::platform::{PlatformPull, TargetLabel, label_key};
use crate::{CdxQuery, Client, Kind, Needles, Source, short_hash};
use anyhow::Result;
use sc_core::platform::{Action, Platform, PlatformEvent, actor_key, wiki_title_template};
use sc_core::{Observation, Rules, TsKind, redact_observation};
use serde_json::Value;
use std::cell::Cell;
use std::io::{BufRead, BufReader, Read};
use std::rc::Rc;
use std::time::{Duration, Instant};

pub(crate) const BASE: &str = "https://stream.wikimedia.org/v2/stream/";
/// The record pass's stream.
pub const LINKS_STREAM: &str = "mediawiki.page-links-change";
/// The platform pass's stream.
pub const REVISIONS_STREAM: &str = "mediawiki.revision-create";
/// Wall-clock minutes one pull reads unless `query.scan` says otherwise.
const DEFAULT_MINUTES: usize = 5;
/// Megabytes one pull reads unless `query.max_mb` says otherwise.
const DEFAULT_MAX_MB: u64 = 256;
/// A checkpoint further back than this is skipped to [`FRESH_START_MS`].
pub const MAX_BACKLOG_HOURS: i64 = 24;
/// Without a checkpoint, a pull starts this far back.
const FRESH_START_MS: i64 = 3_600_000;
/// Connections one pull opens at most (the first and its reconnects).
const MAX_CONNECTS: usize = 4;
/// Longest SSE line kept; longer events are skipped.
const MAX_LINE: usize = 1 << 20;
/// Registration seconds per account-age rank: a thousand ranks (the
/// detector's `new_account_ranks`) is ten days.
const RANK_SECS: i64 = 864;

/// What `filter` keeps.
#[derive(Debug, Default, Clone)]
pub(crate) struct WikiFilter {
    domains: Vec<String>,
    not_domains: Vec<String>,
    namespaces: Vec<i64>,
}

impl WikiFilter {
    pub(crate) fn new(filter: &[String]) -> Result<Self> {
        let mut f = Self::default();
        for x in filter {
            if let Some(d) = x.strip_prefix("!domain:") {
                f.not_domains.push(d.to_ascii_lowercase());
            } else if let Some(d) = x.strip_prefix("domain:") {
                f.domains.push(d.to_ascii_lowercase());
            } else if let Some(n) = x.strip_prefix("ns:") {
                f.namespaces.push(
                    n.parse()
                        .map_err(|_| anyhow::anyhow!("wikimedia filter `{x}`: not a namespace"))?,
                );
            } else {
                anyhow::bail!(
                    "wikimedia filter `{x}` (expected domain:<wiki>, !domain:<wiki> or ns:<n>)"
                );
            }
        }
        Ok(f)
    }

    fn keeps(&self, v: &Value) -> bool {
        let domain = v
            .pointer("/meta/domain")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_ascii_lowercase();
        if domain == "canary" || self.not_domains.contains(&domain) {
            return false;
        }
        if !self.domains.is_empty() && !self.domains.contains(&domain) {
            return false;
        }
        if !self.namespaces.is_empty() {
            let ns = v.get("page_namespace").and_then(Value::as_i64);
            if !ns.is_some_and(|n| self.namespaces.contains(&n)) {
                return false;
            }
        }
        // Bot-flagged accounts edit by the wiki's leave.
        let bot = v
            .pointer("/performer/user_is_bot")
            .and_then(Value::as_bool)
            .unwrap_or(false)
            || v.pointer("/performer/user_groups")
                .and_then(Value::as_array)
                .is_some_and(|g| g.iter().any(|x| x.as_str() == Some("bot")));
        !bot
    }
}

/// One Server-Sent Event.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct SseEvent {
    pub event: Option<String>,
    pub id: Option<String>,
    pub data: String,
}

/// Read Server-Sent Events from `r`, calling `f` on each until it returns
/// false. Comment lines (`:ok`) are skipped, multi-line `data` is joined
/// with newlines, and lines longer than [`MAX_LINE`] drop their event.
/// Returns whether `f` stopped the read (false: the stream ended).
pub fn read_sse(r: impl Read, f: &mut dyn FnMut(SseEvent) -> bool) -> std::io::Result<bool> {
    let mut r = BufReader::new(r);
    let mut line = Vec::new();
    let mut ev = SseEvent::default();
    let mut has_data = false;
    let mut broken = false;
    loop {
        line.clear();
        let n = (&mut r)
            .take(MAX_LINE as u64)
            .read_until(b'\n', &mut line)?;
        if n == 0 {
            return Ok(false);
        }
        if !line.ends_with(b"\n") && n == MAX_LINE {
            broken = true;
            let mut sink = Vec::new();
            loop {
                sink.clear();
                let m = (&mut r)
                    .take(MAX_LINE as u64)
                    .read_until(b'\n', &mut sink)?;
                if m == 0 || sink.ends_with(b"\n") {
                    break;
                }
            }
            continue;
        }
        let text = String::from_utf8_lossy(&line);
        let l = text.trim_end_matches(['\n', '\r']);
        if l.is_empty() {
            let done = std::mem::take(&mut ev);
            if has_data && !broken && !f(done) {
                return Ok(true);
            }
            has_data = false;
            broken = false;
            continue;
        }
        if l.starts_with(':') {
            continue;
        }
        let (field, value) = match l.split_once(':') {
            Some((k, v)) => (k, v.strip_prefix(' ').unwrap_or(v)),
            None => (l, ""),
        };
        match field {
            "data" => {
                if has_data {
                    ev.data.push('\n');
                }
                ev.data.push_str(value);
                has_data = true;
            }
            "event" => ev.event = Some(value.to_string()),
            "id" => ev.id = Some(value.to_string()),
            _ => {}
        }
    }
}

/// Where and how long one pull reads.
#[derive(Debug, Clone)]
pub(crate) struct Plan {
    /// Event time (ms) to start at.
    pub start_ms: i64,
    /// Stop at the first event at or after this (ms): the pull's own start.
    pub until_ms: i64,
    pub deadline: Instant,
    pub max_bytes: u64,
    /// Minutes of backlog passed over.
    pub skipped_minutes: u64,
}

impl Plan {
    pub(crate) fn new(q: &CdxQuery, checkpoint: Option<i64>, now_ms: i64) -> Self {
        let fresh = now_ms - FRESH_START_MS;
        let oldest = now_ms - MAX_BACKLOG_HOURS * 3_600_000;
        let (start_ms, skipped) = match checkpoint {
            Some(c) if c >= oldest => (c, 0),
            Some(c) => (fresh, ((fresh - c).max(0) / 60_000) as u64),
            None => (fresh, 0),
        };
        let minutes = q.scan.unwrap_or(DEFAULT_MINUTES).clamp(1, 60) as u64;
        Self {
            start_ms,
            until_ms: now_ms,
            deadline: Instant::now() + Duration::from_secs(minutes * 60),
            max_bytes: q.max_mb.unwrap_or(DEFAULT_MAX_MB).max(1) << 20,
            skipped_minutes: skipped,
        }
    }

    fn coverage(&self, last_ms: Option<i64>, parsed: usize) -> Coverage {
        let read_to = last_ms.unwrap_or(self.start_ms).max(self.start_ms);
        Coverage {
            unit: "minutes",
            read: ((read_to - self.start_ms) / 60_000) as u64,
            available: ((self.until_ms - self.start_ms).max(0) / 60_000) as u64
                + self.skipped_minutes,
            skipped: self.skipped_minutes,
            next: Some(last_ms.map_or(self.start_ms, |t| t + 1).max(0) as u64),
            canary: Some(parsed > 0),
        }
    }
}

/// Why a stream read stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Stop {
    /// Reached the time the pull began.
    CaughtUp,
    /// The consumer has all it can keep.
    Full,
    /// Out of time or bytes.
    Budget,
    /// The stream ended or failed; reopen it.
    Ended,
}

/// What a stream read got.
#[derive(Debug, Default)]
pub(crate) struct StreamRead {
    pub last_ms: Option<i64>,
    pub parsed: usize,
}

/// An event's time in ms: `meta.dt`.
fn event_ms(v: &Value) -> Option<i64> {
    let dt = v.pointer("/meta/dt").and_then(Value::as_str)?;
    chrono::DateTime::parse_from_rfc3339(dt)
        .ok()
        .map(|d| d.timestamp_millis())
}

/// Consume one connection's events from `r` into `on`, updating `st`.
/// `bytes` counts what was read through the connection so far.
pub(crate) fn consume(
    r: impl Read,
    plan: &Plan,
    bytes: &Cell<u64>,
    st: &mut StreamRead,
    on: &mut dyn FnMut(&Value) -> bool,
) -> Stop {
    let mut stop = Stop::Ended;
    let res = read_sse(r, &mut |ev| {
        let Ok(v) = serde_json::from_str::<Value>(&ev.data) else {
            return true;
        };
        let Some(ms) = event_ms(&v) else {
            return true;
        };
        if ms >= plan.until_ms {
            stop = Stop::CaughtUp;
            return false;
        }
        // Events from two data centres interleave; never step back.
        if st.last_ms.is_some_and(|l| ms < l) {
            st.parsed += 1;
            return true;
        }
        st.parsed += 1;
        st.last_ms = Some(ms);
        if !on(&v) {
            stop = Stop::Full;
            return false;
        }
        if bytes.get() >= plan.max_bytes || Instant::now() >= plan.deadline {
            stop = Stop::Budget;
            return false;
        }
        true
    });
    match res {
        Ok(_) => stop,
        Err(_) if stop != Stop::Ended => stop,
        Err(_) => Stop::Ended,
    }
}

/// Counts the bytes read through it.
struct Counted<R> {
    inner: R,
    n: Rc<Cell<u64>>,
}

impl<R: Read> Read for Counted<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let k = self.inner.read(buf)?;
        self.n.set(self.n.get() + k as u64);
        Ok(k)
    }
}

/// Read `stream` from the plan's start, reopening a dropped connection from
/// the last event read. The first connection's failure is an error; a later
/// one ends the pull with what it has.
pub(crate) fn read_stream(
    client: &Client,
    stream: &str,
    plan: &Plan,
    on: &mut dyn FnMut(&Value) -> bool,
) -> Result<StreamRead> {
    let bytes = Rc::new(Cell::new(0u64));
    let mut st = StreamRead::default();
    for attempt in 0..MAX_CONNECTS {
        if Instant::now() >= plan.deadline || bytes.get() >= plan.max_bytes {
            break;
        }
        let from = st.last_ms.map_or(plan.start_ms, |t| t + 1);
        let since = chrono::DateTime::from_timestamp_millis(from)
            .unwrap_or_default()
            .format("%Y-%m-%dT%H:%M:%S%.3fZ");
        let url = format!("{BASE}{stream}?since={since}");
        let room = plan.max_bytes.saturating_sub(bytes.get()) + (4 << 20);
        let r = match client.get_stream(&url, room) {
            Ok(r) => r,
            Err(e) if attempt == 0 => return Err(e),
            Err(_) => break,
        };
        let r = Counted {
            inner: r,
            n: bytes.clone(),
        };
        if consume(r, plan, &bytes, &mut st, on) != Stop::Ended {
            break;
        }
    }
    Ok(st)
}

/// Records from one `page-links-change` event: one per external link added
/// that matches `needles` (the link or the page title). Redacted.
pub fn link_records(v: &Value, needles: &Needles) -> Vec<Observation> {
    let s = |p: &str| v.pointer(p).and_then(Value::as_str);
    let (Some(domain), Some(rev)) = (s("/meta/domain"), v.get("rev_id").and_then(Value::as_u64))
    else {
        return Vec::new();
    };
    let db = s("/database").unwrap_or(domain);
    let title = s("/page_title").unwrap_or("");
    let ts = event_ms(v).map_or(0, |ms| ms / 1000);
    let diff = format!("https://{domain}/w/index.php?diff={rev}");
    let Some(links) = v.get("added_links").and_then(Value::as_array) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for l in links {
        if l.get("external").and_then(Value::as_bool) != Some(true) {
            continue;
        }
        let Some(link) = l.get("link").and_then(Value::as_str) else {
            continue;
        };
        // The stream escapes a link's query delimiters (`%3F`, `%3D`,
        // `%26`); the record keeps the link as the editor wrote it.
        let url = match link.strip_prefix("//") {
            Some(rest) => format!("https://{rest}"),
            None => link.to_string(),
        }
        .replace("%3F", "?")
        .replace("%3D", "=")
        .replace("%26", "&");
        if !(url.starts_with("http://") || url.starts_with("https://")) {
            continue;
        }
        if !(needles.matches(&url) || needles.matches(title)) {
            continue;
        }
        let mut o = Observation {
            id: format!("wikimedia:{db}:{rev}:{}", short_hash(&url)),
            source: "wikimedia".into(),
            ts,
            ts_kind: TsKind::Request,
            url,
            reference: Some(diff.clone()),
            ..Default::default()
        };
        redact_observation(&mut o);
        out.push(o);
    }
    out
}

/// A `revision-create` event as a platform event; `None` when it gives the
/// detector nothing to group (no summary and no templated title).
pub fn revision_event(v: &Value, rules: &Rules) -> Option<PlatformEvent> {
    let s = |p: &str| v.pointer(p).and_then(Value::as_str);
    let domain = s("/meta/domain")?;
    let rev = v.get("rev_id").and_then(Value::as_u64)?;
    let user = s("/performer/user_text")?;
    let title = s("/page_title").unwrap_or("");
    let db = s("/database").unwrap_or(domain);
    if v.get("rev_content_changed").and_then(Value::as_bool) == Some(false) {
        return None;
    }
    let registered = s("/performer/user_registration_dt").and_then(crate::parse_date);
    let edits = v
        .pointer("/performer/user_edit_count")
        .and_then(Value::as_u64);
    // The global account name: local user ids differ from wiki to wiki.
    let actor = actor_key(Platform::Wikimedia, user);
    // A user page's title names its user: the target keeps the key instead.
    let underscored = user.replace(' ', "_");
    let target_title = if !user.is_empty() && title.contains(&underscored) {
        title.replace(&underscored, &actor)
    } else {
        title.to_string()
    };
    let e = PlatformEvent {
        id: format!("wm:{db}:{rev}"),
        platform: Platform::Wikimedia,
        action: Action::WikiEdited,
        ts: event_ms(v).map_or(0, |ms| ms / 1000),
        actor,
        actor_rank: registered
            .filter(|&t| t > 0)
            .map(|t| (t / RANK_SECS) as u64),
        first_timer: edits.map(|n| n <= 1),
        target: format!("{domain}/{target_title}"),
        link: format!("https://{domain}/w/index.php?diff={rev}"),
        name_template: wiki_title_template(title, user),
        text: None,
    }
    .with_text(
        s("/comment").unwrap_or(""),
        &[user, &title.replace('_', " ")],
        rules,
    );
    (e.text.is_some() || e.name_template.is_some()).then_some(e)
}

/// The record pass: external links added to wiki pages, as a [`Source`].
/// `query.pattern` is `|`-separated substrings matched against the link and
/// the page title; `query.filter` as in the module docs.
pub struct WikiLinks {
    pub query: CdxQuery,
    filter: WikiFilter,
}

impl WikiLinks {
    pub fn new(query: CdxQuery) -> Result<Self> {
        let filter = WikiFilter::new(&query.filter)?;
        Ok(Self { query, filter })
    }
}

impl Source for WikiLinks {
    fn kind(&self) -> Kind {
        Kind::Wikimedia
    }

    fn query(&self) -> &CdxQuery {
        &self.query
    }

    /// One pull, one page.
    fn page_size(&self) -> usize {
        usize::MAX
    }

    fn page(
        &self,
        client: &Client,
        _since: Option<i64>,
        cursor: Option<&Cursor>,
        size: usize,
    ) -> Result<Page> {
        let at = match cursor {
            Some(Cursor::Offset(ms)) => Some(*ms as i64),
            Some(c) => anyhow::bail!("wikimedia pages by event time, not {c:?}"),
            None => None,
        };
        let plan = Plan::new(
            &self.query,
            at,
            crate::client::now_secs().saturating_mul(1000),
        );
        let needles = Needles::new(&self.query.pattern);
        let mut records = Vec::new();
        let st = read_stream(client, LINKS_STREAM, &plan, &mut |v| {
            if self.filter.keeps(v) {
                records.extend(link_records(v, &needles));
            }
            records.len() < size
        })?;
        records.truncate(size);
        Ok(Page {
            stopped: None,
            records,
            next: None,
            truncated: false,
            coverage: Some(plan.coverage(st.last_ms, st.parsed)),
        })
    }

    fn checkpointed(&self) -> bool {
        true
    }
}

/// The category the English Wikipedia's AI cleanup template files pages
/// in, before its ` from <month> <year>` suffix.
pub const AI_CLEANUP_CATEGORY: &str = "Articles containing suspected AI-generated texts";
/// Category requests one label pull makes unless `scan` says otherwise.
const DEFAULT_CATEGORY_REQUESTS: usize = 4;
/// Without a checkpoint, a label pull reads this far back (seconds).
const LABEL_FRESH_SECS: i64 = 24 * 3600;
/// A label checkpoint further back than this is skipped (seconds).
const LABEL_BACKLOG_SECS: i64 = 7 * 24 * 3600;

/// The monthly categories (`<prefix> from October 2026`) covering `start`
/// to `end` (Unix seconds), oldest first.
pub fn monthly_categories(prefix: &str, start: i64, end: i64) -> Vec<String> {
    use chrono::Datelike;
    let (Some(a), Some(b)) = (
        chrono::DateTime::from_timestamp(start, 0),
        chrono::DateTime::from_timestamp(end, 0),
    ) else {
        return Vec::new();
    };
    let (mut y, mut m) = (a.year(), a.month());
    let mut out = Vec::new();
    while (y, m) <= (b.year(), b.month()) && out.len() < 13 {
        let month = chrono::NaiveDate::from_ymd_opt(y, m, 1)
            .map(|d| d.format("%B").to_string())
            .unwrap_or_default();
        out.push(format!("{prefix} from {month} {y}"));
        (y, m) = if m == 12 { (y + 1, 1) } else { (y, m + 1) };
    }
    out
}

/// Labels from one `list=categorymembers` response, the members it held,
/// and the `cmcontinue` key for more.
pub fn category_labels(
    body: &str,
    domain: &str,
    category: &str,
) -> Result<(Vec<TargetLabel>, usize, Option<String>)> {
    let v: Value =
        serde_json::from_str(body).map_err(|_| anyhow::anyhow!("category members: not JSON"))?;
    if let Some(e) = v.pointer("/error/info").and_then(Value::as_str) {
        anyhow::bail!("category members: {e}");
    }
    let members = v
        .pointer("/query/categorymembers")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow::anyhow!("category members: no `query.categorymembers`"))?;
    let mut out = Vec::new();
    for m in members {
        let (Some(title), Some(ts)) = (
            m.get("title").and_then(Value::as_str),
            m.get("timestamp")
                .and_then(Value::as_str)
                .and_then(crate::parse_date),
        ) else {
            continue;
        };
        let t = title.replace(' ', "_");
        out.push(TargetLabel {
            platform: Platform::Wikimedia,
            target: label_key(Platform::Wikimedia, &format!("{domain}/{t}")),
            kind: "wiki-ai-cleanup".into(),
            source_id: format!("Category:{category}"),
            link: format!("https://{domain}/wiki/{t}"),
            ts,
        });
    }
    let more = v
        .pointer("/continue/cmcontinue")
        .and_then(Value::as_str)
        .map(str::to_string);
    Ok((out, members.len(), more))
}

/// The label pass: pages added to the AI cleanup categories since the
/// checkpoint `mark` (Unix seconds).
pub fn pull_ai_cleanup(client: &Client, q: &CdxQuery, mark: Option<u64>) -> Result<PlatformPull> {
    let domain = q.endpoint.as_deref().unwrap_or("en.wikipedia.org");
    if domain.is_empty()
        || !domain
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
        || !(domain.ends_with(".wikipedia.org") || domain.ends_with(".wikimedia.org"))
    {
        anyhow::bail!("wikimedia-ai-cleanup endpoint `{domain}` is not a Wikimedia wiki");
    }
    let prefix = match q.pattern.trim() {
        "" | "*" => AI_CLEANUP_CATEGORY,
        p => p,
    };
    let now = crate::client::now_secs();
    let fresh = now - LABEL_FRESH_SECS;
    let (start, skipped) = match mark.map(|m| m as i64) {
        Some(m) if m >= now - LABEL_BACKLOG_SECS => (m, 0),
        Some(m) => (fresh, (fresh - m).max(0)),
        None => (fresh, 0),
    };
    let mut budget = q.scan.unwrap_or(DEFAULT_CATEGORY_REQUESTS).clamp(1, 20);
    let mut out = PlatformPull::default();
    let (mut members, mut next, mut complete) = (0u64, start, true);
    let from = chrono::DateTime::from_timestamp(start + 1, 0)
        .unwrap_or_default()
        .format("%Y-%m-%dT%H:%M:%SZ")
        .to_string();
    for cat in monthly_categories(prefix, start, now) {
        let mut cont: Option<String> = None;
        loop {
            if budget == 0 {
                complete = false;
                break;
            }
            budget -= 1;
            let mut u = url::Url::parse(&format!("https://{domain}/w/api.php"))?;
            u.query_pairs_mut()
                .append_pair("action", "query")
                .append_pair("list", "categorymembers")
                .append_pair("cmtitle", &format!("Category:{cat}"))
                .append_pair("cmsort", "timestamp")
                .append_pair("cmdir", "asc")
                .append_pair("cmstart", &from)
                .append_pair("cmprop", "ids|title|timestamp")
                .append_pair("cmtype", "page")
                .append_pair("cmlimit", "500")
                .append_pair("format", "json")
                .append_pair("formatversion", "2");
            if let Some(c) = &cont {
                u.query_pairs_mut().append_pair("cmcontinue", c);
            }
            let body = client.get(u.as_str())?;
            let (labels, n, more) = category_labels(&body, domain, &cat)?;
            members += n as u64;
            if let Some(t) = labels.iter().map(|l| l.ts).max() {
                next = next.max(t);
            }
            out.labels.extend(labels);
            match more {
                Some(c) => cont = Some(c),
                None => break,
            }
        }
    }
    if complete {
        next = next.max(now - 60);
    }
    out.coverage = Coverage {
        unit: "pages",
        read: members,
        available: members + u64::from(skipped > 0 || !complete),
        skipped: u64::from(skipped > 0),
        next: Some(next.max(0) as u64),
        canary: Some(true),
    };
    Ok(out)
}

/// The platform pass: edits from `revision-create`, at most `max`, from the
/// checkpoint `mark` (ms).
pub fn pull_platform(
    client: &Client,
    q: &CdxQuery,
    mark: Option<u64>,
    rules: &Rules,
    max: usize,
) -> Result<PlatformPull> {
    let filter = WikiFilter::new(&q.filter)?;
    let plan = Plan::new(
        q,
        mark.map(|m| m as i64),
        crate::client::now_secs().saturating_mul(1000),
    );
    let mut out = PlatformPull::default();
    let st = read_stream(client, REVISIONS_STREAM, &plan, &mut |v| {
        if !filter.keeps(v) {
            // Bots and canaries: the platform's own automation.
            let domain = v.pointer("/meta/domain").and_then(Value::as_str);
            if domain != Some("canary") {
                out.automation += 1;
            }
            return true;
        }
        if let Some(e) = revision_event(v, rules) {
            out.events.push(e);
        }
        out.events.len() < max
    })?;
    out.coverage = plan.coverage(st.last_ms, st.parsed);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const T: i64 = 1_791_858_048_000;

    fn dt(ms: i64) -> String {
        chrono::DateTime::from_timestamp_millis(ms)
            .unwrap()
            .format("%Y-%m-%dT%H:%M:%S%.3fZ")
            .to_string()
    }

    /// A synthetic links-change event; every name and link is invented.
    fn links_event(ms: i64, domain: &str, bot: bool, links: &[(&str, bool)]) -> String {
        let added: Vec<String> = links
            .iter()
            .map(|(l, ext)| format!(r#"{{"link":"{l}","external":{ext}}}"#))
            .collect();
        format!(
            r#"{{"$schema":"/mediawiki/page/links-change/1.0.0","meta":{{"domain":"{domain}","dt":"{}","stream":"mediawiki.page-links-change"}},"database":"testwiki","page_title":"User:Probe_Account7/sandbox","page_namespace":2,"rev_id":4242,"performer":{{"user_text":"Probe Account7","user_is_bot":{bot},"user_id":77,"user_registration_dt":"2026-10-04T00:00:00Z","user_edit_count":2}},"added_links":[{}]}}"#,
            dt(ms),
            added.join(",")
        )
    }

    fn sse(events: &[String]) -> String {
        let mut t = String::from(":ok\n\n");
        for (i, e) in events.iter().enumerate() {
            t.push_str(&format!(
                "event: message\nid: [{{\"offset\":{i}}}]\ndata: {e}\n\n"
            ));
        }
        t
    }

    #[test]
    fn sse_lines_become_events() {
        let text =
            ": comment\n\nevent: message\nid: 1\ndata: {\"a\":\ndata: 1}\n\ndata: two\r\n\r\n";
        let mut got = Vec::new();
        let stopped = read_sse(text.as_bytes(), &mut |e| {
            got.push(e);
            true
        })
        .unwrap();
        assert!(!stopped);
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].event.as_deref(), Some("message"));
        assert_eq!(got[0].id.as_deref(), Some("1"));
        assert_eq!(got[0].data, "{\"a\":\n1}");
        assert_eq!(got[1].data, "two");
    }

    #[test]
    fn external_links_become_records_and_are_never_followed() {
        let v: Value = serde_json::from_str(&links_event(
            T,
            "en.wikipedia.org",
            false,
            &[
                ("/wiki/User:Probe_Account7", false),
                ("https://r.jina.ai/https://target.example/page", true),
                (
                    "//cite.example/doc%3Fuqtag%3Drun7%26token%3Dabcdefabcdefabcdefabcdef",
                    true,
                ),
                ("mailto:x@example.org", true),
            ],
        ))
        .unwrap();
        let recs = link_records(&v, &Needles::new("*"));
        assert_eq!(recs.len(), 2);
        let r = &recs[0];
        assert_eq!(r.source, "wikimedia");
        assert_eq!(r.ts_kind, TsKind::Request);
        assert_eq!(r.ts, T / 1000);
        assert_eq!(r.url, "https://r.jina.ai/https://target.example/page");
        assert_eq!(
            r.reference.as_deref(),
            Some("https://en.wikipedia.org/w/index.php?diff=4242")
        );
        assert!(r.id.starts_with("wikimedia:testwiki:4242:"));
        assert!(
            recs[1]
                .url
                .starts_with("https://cite.example/doc?uqtag=run7&"),
            "{}",
            recs[1].url
        );
        assert_eq!(link_records(&v, &Needles::new("uqtag=")).len(), 1);
        assert_ne!(recs[0].id, recs[1].id);
        // A pattern keeps only matching links.
        assert_eq!(link_records(&v, &Needles::new("r.jina.ai")).len(), 1);
    }

    #[test]
    fn canary_and_bot_events_are_dropped_and_filters_apply() {
        let f = WikiFilter::new(&[]).unwrap();
        let ev = |d: &str, bot: bool| -> Value {
            serde_json::from_str(&links_event(T, d, bot, &[])).unwrap()
        };
        assert!(f.keeps(&ev("en.wikipedia.org", false)));
        assert!(!f.keeps(&ev("canary", false)));
        assert!(!f.keeps(&ev("en.wikipedia.org", true)));
        let f = WikiFilter::new(&["!domain:www.wikidata.org".into(), "ns:2".into()]).unwrap();
        assert!(f.keeps(&ev("de.wikipedia.org", false)));
        assert!(!f.keeps(&ev("www.wikidata.org", false)));
        let f = WikiFilter::new(&["ns:8".into()]).unwrap();
        assert!(!f.keeps(&ev("en.wikipedia.org", false)));
        let f = WikiFilter::new(&["domain:fr.wikipedia.org".into()]).unwrap();
        assert!(!f.keeps(&ev("en.wikipedia.org", false)));
        assert!(WikiFilter::new(&["collection:x".into()]).is_err());
    }

    #[test]
    fn a_stream_read_stops_at_the_pull_start_and_resumes_after_the_last_event() {
        let events: Vec<String> = (0..6)
            .map(|i| {
                links_event(
                    T + i * 60_000,
                    if i == 2 { "canary" } else { "en.wikipedia.org" },
                    false,
                    &[("https://r.jina.ai/https://t.example/", true)],
                )
            })
            .collect();
        let text = sse(&events);
        let plan = Plan {
            start_ms: T,
            until_ms: T + 4 * 60_000,
            deadline: Instant::now() + Duration::from_secs(60),
            max_bytes: 1 << 20,
            skipped_minutes: 0,
        };
        let f = WikiFilter::new(&[]).unwrap();
        let mut recs = Vec::new();
        let mut st = StreamRead::default();
        let stop = consume(text.as_bytes(), &plan, &Cell::new(0), &mut st, &mut |v| {
            if f.keeps(v) {
                recs.extend(link_records(v, &Needles::new("*")));
            }
            true
        });
        assert_eq!(stop, Stop::CaughtUp);
        // Four events before the pull's start, the canary among them.
        assert_eq!((st.parsed, recs.len()), (4, 3));
        assert_eq!(st.last_ms, Some(T + 3 * 60_000));
        let cov = plan.coverage(st.last_ms, st.parsed);
        assert_eq!(cov.next, Some((T + 3 * 60_000 + 1) as u64));
        assert_eq!((cov.read, cov.available, cov.unit), (3, 4, "minutes"));
        assert_eq!(cov.canary, Some(true));
        // A stream that ends early asks to be reopened.
        let mut st = StreamRead::default();
        let half = sse(&events[..2]);
        let stop = consume(half.as_bytes(), &plan, &Cell::new(0), &mut st, &mut |_| {
            true
        });
        assert_eq!(stop, Stop::Ended);
        // The byte budget stops a read.
        let tight = Plan {
            max_bytes: 1,
            ..plan.clone()
        };
        let mut st = StreamRead::default();
        let stop = consume(
            text.as_bytes(),
            &tight,
            &Cell::new(10),
            &mut st,
            &mut |_| true,
        );
        assert_eq!((stop, st.parsed), (Stop::Budget, 1));
    }

    #[test]
    fn plans_from_the_checkpoint_within_the_backlog() {
        let now = T + 10 * 3_600_000;
        let q = CdxQuery::default();
        let p = Plan::new(&q, None, now);
        assert_eq!((p.start_ms, p.skipped_minutes), (now - 3_600_000, 0));
        let p = Plan::new(&q, Some(now - 5 * 3_600_000), now);
        assert_eq!(p.start_ms, now - 5 * 3_600_000);
        let p = Plan::new(&q, Some(now - 30 * 3_600_000), now);
        assert_eq!(p.start_ms, now - 3_600_000);
        assert_eq!(p.skipped_minutes, 29 * 60);
        assert_eq!(p.max_bytes, DEFAULT_MAX_MB << 20);
    }

    #[test]
    fn ai_cleanup_categories_become_labels_on_revision_targets() {
        let t = |s: &str| crate::parse_date(s).unwrap();
        assert_eq!(
            monthly_categories(
                AI_CLEANUP_CATEGORY,
                t("2026-09-30T23:00:00Z"),
                t("2026-10-13T00:00:00Z")
            ),
            [
                "Articles containing suspected AI-generated texts from September 2026",
                "Articles containing suspected AI-generated texts from October 2026"
            ]
        );
        assert_eq!(
            monthly_categories("x", t("2026-12-31T00:00:00Z"), t("2027-01-01T00:00:00Z")).len(),
            2
        );
        // A synthetic API answer; the page is invented.
        let body = r#"{"batchcomplete":true,"continue":{"cmcontinue":"page|abc|1","continue":"-||"},"query":{"categorymembers":[{"pageid":1,"ns":0,"title":"Probe Topic 42","timestamp":"2026-10-13T17:41:13Z"},{"pageid":2,"ns":0,"title":"No time"}]}}"#;
        let (labels, n, more) = category_labels(body, "en.wikipedia.org", "C").unwrap();
        assert_eq!((labels.len(), n), (1, 2));
        assert_eq!(more.as_deref(), Some("page|abc|1"));
        let l = &labels[0];
        assert_eq!(l.target, "en.wikipedia.org/probe_topic_42");
        assert_eq!(l.link, "https://en.wikipedia.org/wiki/Probe_Topic_42");
        assert_eq!(l.kind, "wiki-ai-cleanup");
        // The label's target is the one a revision event on that page names.
        let rules = Rules::default_rules();
        let text = format!(
            r#"{{"meta":{{"domain":"en.wikipedia.org","dt":"{}"}},"database":"enwiki","page_title":"Probe_Topic_42","page_namespace":0,"rev_id":5,"performer":{{"user_text":"Someone","user_is_bot":false}},"comment":"Expanded the article with a long new section on the history of the topic"}}"#,
            dt(T)
        );
        let e = revision_event(&serde_json::from_str(&text).unwrap(), &rules).unwrap();
        assert_eq!(label_key(e.platform, &e.target), l.target);
        assert!(category_labels(r#"{"error":{"info":"bad title"}}"#, "x", "C").is_err());
    }

    #[test]
    fn revisions_become_platform_events_without_names() {
        let rules = Rules::default_rules();
        let text = format!(
            r#"{{"meta":{{"domain":"en.wikipedia.org","dt":"{}"}},"database":"enwiki","page_title":"User:Probe_Account7/sandbox","page_namespace":2,"rev_id":991,"rev_content_changed":true,"performer":{{"user_text":"Probe Account7","user_is_bot":false,"user_id":555,"user_registration_dt":"2026-10-04T00:00:00Z","user_edit_count":1}},"comment":"Testing an edit from Probe Account7, see https://probe.example/run?id=7"}}"#,
            dt(T)
        );
        let v: Value = serde_json::from_str(&text).unwrap();
        let e = revision_event(&v, &rules).unwrap();
        assert_eq!(e.platform, Platform::Wikimedia);
        assert_eq!(e.action, Action::WikiEdited);
        assert_eq!(e.id, "wm:enwiki:991");
        assert_eq!(e.link, "https://en.wikipedia.org/w/index.php?diff=991");
        assert_eq!(e.name_template.as_deref(), Some("user:<user>/sandbox"));
        assert_eq!(e.first_timer, Some(true));
        assert_eq!(e.owner(), "en.wikipedia.org");
        let reg = crate::parse_date("2026-10-04T00:00:00Z").unwrap();
        assert_eq!(e.actor_rank, Some((reg / RANK_SECS) as u64));
        let json = serde_json::to_string(&e).unwrap();
        for leak in ["Account7", "probe.example", "555"] {
            assert!(!json.contains(leak), "{leak} leaked: {json}");
        }
        // A null edit gives nothing.
        let mut null = v.clone();
        null["rev_content_changed"] = Value::Bool(false);
        assert!(revision_event(&null, &rules).is_none());
    }
}
