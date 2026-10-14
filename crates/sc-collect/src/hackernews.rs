//! Hacker News, read through its search index
//! (`hn.algolia.com/api/v1/search_by_date`): every story and comment
//! posted, newest first, with author, time, title, submitted URL and text.
//! Two passes read it, each from a checkpoint:
//!
//! - the record pass ([`HnLinks`]): one record per link in a story or
//!   comment (its submitted URL and the links in its text) that matches the
//!   query's substrings, and one per item whose title or text matches with
//!   no link that does. The record's URL is the link, never fetched; its
//!   reference is the item's page.
//! - the platform pass ([`pull_platform`]): one [`PlatformEvent`] per story
//!   or comment, the author as a keyed hash, the text as a sketch, a
//!   comment's target its story and a story's the submitted URL's host.
//!
//! Account age: Hacker News numbers no accounts, but its own API
//! (`hacker-news.firebaseio.com/v0/user/<id>.json`) gives an account's
//! creation time. A pull looks up at most `max_lookups` authors, only
//! those whose text shares a template or near-duplicate band with another
//! author's, or carries residue: the authors a group could form around.
//! The creation time becomes a rank in units of [`RANK_SECS`], so a
//! thousand ranks (the detector's `new_account_ranks`) is ten days, as on
//! a wiki. The profile's other fields are not kept.
//!
//! Coverage: the index answers at most 1000 hits a query, so a pull walks
//! back from a little before its own start ([`LAG_SECS`], for indexing) to
//! the checkpoint, one query per window of 1000 hits, at most `scan`
//! queries. A pull that reaches the checkpoint read everything since; one
//! that runs out of queries read the newest part and counts the rest as
//! skipped. Coverage is in minutes of posting time. Without a checkpoint it
//! starts [`FRESH_SECS`] back; a checkpoint older than
//! [`MAX_BACKLOG_HOURS`] is skipped to there and the gap counted. Items
//! parsed are the canary: Hacker News is never quiet for six hours.
//!
//! Terms: the Hacker News API (<https://github.com/HackerNews/API>) is
//! public, published under the MIT licence, and states "There is
//! currently no rate limit". The search index is run by Algolia
//! (<https://hn.algolia.com/api>) as a public API, limited to 10,000
//! requests an hour per IP address. A pull makes a few index queries and a
//! few dozen profile lookups, paced. Posts are public; we keep the item's
//! public link, time and sketch, never the author's name or profile, and
//! never open a submitted URL or a link in a comment.

use crate::pager::{Coverage, Cursor, Page};
use crate::platform::PlatformPull;
use crate::{CdxQuery, Client, Kind, Needles, Source, short_hash};
use anyhow::{Context, Result};
use sc_core::platform::{Action, Platform, PlatformEvent, actor_key};
use sc_core::{Observation, Rules, TsKind, redact_observation};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet, HashSet};

const SEARCH: &str = "https://hn.algolia.com/api/v1/search_by_date";
const USER: &str = "https://hacker-news.firebaseio.com/v0/user/";
const ITEM: &str = "https://news.ycombinator.com/item?id=";
/// Hits per index query: the index's maximum.
const PAGE: usize = 1000;
/// Index queries one pull makes unless `scan` says otherwise.
const DEFAULT_QUERIES: usize = 10;
/// A pull reads up to this long before its own start: items reach the
/// index within a minute or two of posting.
pub const LAG_SECS: i64 = 120;
/// Without a checkpoint, a pull starts this far back.
pub const FRESH_SECS: i64 = 6 * 3600;
/// A checkpoint further back than this is skipped to [`FRESH_SECS`].
pub const MAX_BACKLOG_HOURS: i64 = 24;
/// Creation seconds per account-age rank: a thousand ranks is ten days.
pub const RANK_SECS: i64 = 864;
/// Profile lookups one platform pull makes unless `max_lookups` says otherwise.
pub const DEFAULT_LOOKUPS: usize = 40;

/// One story or comment from the index, its HTML reduced to text.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Item {
    pub id: u64,
    pub story: bool,
    pub author: String,
    pub ts: i64,
    pub title: String,
    /// A story's submitted URL.
    pub url: Option<String>,
    /// The text, tags removed and entities decoded.
    pub text: String,
    /// The `href`s in the text.
    pub links: Vec<String>,
    /// A comment's story.
    pub story_id: Option<u64>,
}

impl Item {
    pub fn link(&self) -> String {
        format!("{ITEM}{}", self.id)
    }
}

/// Items from one index response, and the hits it held.
pub fn parse_hits(body: &str) -> Result<(Vec<Item>, usize)> {
    let v: Value = serde_json::from_str(body).context("HN search: not JSON")?;
    let hits = v
        .get("hits")
        .and_then(Value::as_array)
        .context("HN search: no `hits` array")?;
    let mut out = Vec::new();
    for h in hits {
        let s = |k: &str| h.get(k).and_then(Value::as_str);
        let Some(id) = s("objectID").and_then(|i| i.parse::<u64>().ok()) else {
            continue;
        };
        let Some(ts) = h.get("created_at_i").and_then(Value::as_i64) else {
            continue;
        };
        let tags: Vec<&str> = h
            .get("_tags")
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(Value::as_str).collect())
            .unwrap_or_default();
        let story = tags.contains(&"story");
        let html = s("comment_text").or_else(|| s("story_text")).unwrap_or("");
        let (text, links) = html_text(html);
        out.push(Item {
            id,
            story,
            author: s("author").unwrap_or("").to_string(),
            ts,
            title: if story {
                decode_entities(s("title").unwrap_or(""))
            } else {
                String::new()
            },
            url: s("url").filter(|u| !u.is_empty()).map(str::to_string),
            text,
            links,
            story_id: h.get("story_id").and_then(Value::as_u64),
        });
    }
    Ok((out, hits.len()))
}

/// Decode the HTML entities the index uses.
fn decode_entities(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(i) = rest.find('&') {
        out.push_str(&rest[..i]);
        rest = &rest[i..];
        let Some(end) = rest
            .char_indices()
            .take(10)
            .find(|&(_, c)| c == ';')
            .map(|(k, _)| k)
        else {
            out.push('&');
            rest = &rest[1..];
            continue;
        };
        let ent = &rest[1..end];
        let c = match ent {
            "amp" => Some('&'),
            "lt" => Some('<'),
            "gt" => Some('>'),
            "quot" => Some('"'),
            "apos" => Some('\''),
            "nbsp" => Some(' '),
            _ => ent
                .strip_prefix("#x")
                .or_else(|| ent.strip_prefix("#X"))
                .and_then(|h| u32::from_str_radix(h, 16).ok())
                .or_else(|| ent.strip_prefix('#').and_then(|d| d.parse().ok()))
                .and_then(char::from_u32),
        };
        match c {
            Some(c) => {
                out.push(c);
                rest = &rest[end + 1..];
            }
            None => {
                out.push('&');
                rest = &rest[1..];
            }
        }
    }
    out.push_str(rest);
    out
}

/// Text and `href`s of an HTML fragment: tags removed (a paragraph tag
/// becomes a line break), entities decoded.
pub fn html_text(html: &str) -> (String, Vec<String>) {
    let mut text = String::new();
    let mut links = Vec::new();
    let mut rest = html;
    while let Some(i) = rest.find('<') {
        text.push_str(&rest[..i]);
        let Some(j) = rest[i..].find('>') else {
            text.push_str(&rest[i..]);
            rest = "";
            break;
        };
        let tag = &rest[i + 1..i + j];
        let lower = tag.to_ascii_lowercase();
        if lower == "p" || lower.starts_with("p ") || lower == "br" || lower.starts_with("br") {
            text.push('\n');
        }
        if let Some(k) = lower.find("href=\"") {
            let v = &tag[k + 6..];
            if let Some(e) = v.find('"') {
                links.push(decode_entities(&v[..e]));
            }
        }
        rest = &rest[i + j + 1..];
    }
    text.push_str(rest);
    (decode_entities(&text), links)
}

/// The span one pull reads: after `start`, up to and including `until`
/// (Unix seconds).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Window {
    pub start: i64,
    pub until: i64,
    /// Seconds of backlog passed over.
    pub skipped: i64,
}

impl Window {
    pub fn new(checkpoint: Option<i64>, now: i64) -> Self {
        let until = now - LAG_SECS;
        let fresh = until - FRESH_SECS;
        let (start, skipped) = match checkpoint {
            Some(c) if c >= until - MAX_BACKLOG_HOURS * 3600 => (c.min(until), 0),
            Some(c) => (fresh, (fresh - c).max(0)),
            None => (fresh, 0),
        };
        Self {
            start,
            until,
            skipped,
        }
    }

    /// Coverage once the walk got back to `oldest`, with `parsed` items.
    pub fn coverage(&self, oldest: i64, parsed: usize) -> Coverage {
        let gap = (oldest - self.start).max(0);
        Coverage {
            unit: "minutes",
            read: ((self.until - oldest.max(self.start)).max(0) / 60) as u64,
            available: ((self.until - self.start).max(0) + self.skipped) as u64 / 60,
            skipped: ((self.skipped + gap) / 60) as u64,
            next: Some(self.until.max(0) as u64),
            canary: Some(parsed > 0),
        }
    }
}

/// What a walk over the index got.
#[derive(Debug, Default)]
pub struct WindowRead {
    pub items: Vec<Item>,
    /// How far back the walk got (the window's start once it got there).
    pub oldest: i64,
}

/// The index query for items after `start`, up to `upper`.
fn query_url(start: i64, upper: i64) -> String {
    let mut u = url::Url::parse(SEARCH).expect("constant URL");
    u.query_pairs_mut()
        .append_pair("tags", "(story,comment)")
        .append_pair(
            "numericFilters",
            &format!("created_at_i>{start},created_at_i<={upper}"),
        )
        .append_pair("hitsPerPage", &PAGE.to_string());
    u.to_string()
}

/// Walk the index back from the window's end to its start, at most
/// `queries` queries. `fetch` answers one query URL. The first query's
/// failure is an error; a later one ends the walk with what it has.
pub fn walk(
    w: &Window,
    queries: usize,
    fetch: &mut dyn FnMut(&str) -> Result<String>,
) -> Result<WindowRead> {
    let mut out = WindowRead {
        oldest: w.until,
        ..Default::default()
    };
    let mut seen = HashSet::new();
    let mut upper = w.until;
    for i in 0..queries.max(1) {
        if upper <= w.start {
            out.oldest = w.start;
            break;
        }
        let body = match fetch(&query_url(w.start, upper)) {
            Ok(b) => b,
            Err(e) if i == 0 => return Err(e),
            Err(_) => break,
        };
        let (items, hits) = parse_hits(&body)?;
        let min = items.iter().map(|x| x.ts).min();
        for it in items {
            if seen.insert(it.id) {
                out.items.push(it);
            }
        }
        if hits < PAGE {
            out.oldest = w.start;
            break;
        }
        // Items at the oldest second may run on past this page: ask for
        // that second again (the ids already seen are skipped), unless the
        // whole page was that one second.
        upper = match min {
            Some(m) if m < upper => m,
            _ => upper - 1,
        };
        out.oldest = upper;
    }
    Ok(out)
}

/// Records from one item: its submitted URL and the links in its text
/// that match `needles`, and the item's page when only its title or text
/// matches. Redacted.
pub fn item_records(it: &Item, needles: &Needles) -> Vec<Observation> {
    let page = it.link();
    let mut urls: Vec<String> = Vec::new();
    for u in it.url.iter().chain(it.links.iter()) {
        if (u.starts_with("http://") || u.starts_with("https://"))
            && needles.matches(u)
            && !urls.contains(u)
        {
            urls.push(u.clone());
        }
    }
    for u in crate::gharchive::urls_in(&it.text) {
        let u = u.trim_end_matches(['.', ',', ';', ':']);
        if needles.matches(u) && !urls.iter().any(|x| x == u) {
            urls.push(u.to_string());
        }
    }
    if urls.is_empty() && (needles.matches(&it.title) || needles.matches(&it.text)) {
        urls.push(page.clone());
    }
    urls.into_iter()
        .map(|url| {
            let mut o = Observation {
                id: format!("hackernews:{}:{}", it.id, short_hash(&url)),
                source: "hackernews".into(),
                ts: it.ts,
                ts_kind: TsKind::Request,
                url,
                reference: Some(page.clone()),
                ..Default::default()
            };
            redact_observation(&mut o);
            o
        })
        .collect()
}

/// An item as a platform event; `None` without an author or text.
pub fn item_event(it: &Item, rules: &Rules) -> Option<PlatformEvent> {
    if it.author.is_empty() {
        return None;
    }
    let target = if it.story {
        it.url
            .as_deref()
            .and_then(|u| url::Url::parse(u).ok())
            .and_then(|u| {
                u.host_str()
                    .map(|h| h.trim_start_matches("www.").to_string())
            })
            .unwrap_or_else(|| format!("hn:{}", it.id))
    } else {
        format!("hn:{}", it.story_id.unwrap_or(it.id))
    };
    let text = if it.story {
        format!("{}\n{}", it.title, it.text)
    } else {
        it.text.clone()
    };
    let e = PlatformEvent {
        id: format!("hn:{}", it.id),
        platform: Platform::HackerNews,
        action: if it.story {
            Action::StoryPosted
        } else {
            Action::Comment
        },
        ts: it.ts,
        actor: actor_key(Platform::HackerNews, &it.author),
        target,
        link: it.link(),
        ..Default::default()
    }
    .with_text(&text, &[&it.author], rules);
    e.text.is_some().then_some(e)
}

/// Whether `name` is a Hacker News username (letters, digits, `-`, `_`),
/// safe to put in a profile URL.
fn valid_user(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 32
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

/// The authors worth an account-age lookup, at most `max`: those whose
/// text shares a template or a near-duplicate band with another author's,
/// or carries residue, most-shared first.
pub fn lookup_candidates(items: &[(String, PlatformEvent)], max: usize) -> Vec<String> {
    let mut by_key: BTreeMap<(u8, u64), BTreeSet<&str>> = BTreeMap::new();
    let mut residue: BTreeSet<&str> = BTreeSet::new();
    for (author, e) in items {
        let Some(t) = &e.text else { continue };
        if !t.residue.is_empty() {
            residue.insert(author);
        }
        by_key.entry((0, t.skeleton)).or_default().insert(author);
        for (b, band) in t.minhash.chunks(4).enumerate() {
            let mut h = 0xcbf2_9ce4_8422_2325u64;
            for v in band {
                h = (h ^ *v as u64).wrapping_mul(0x100_0000_01b3);
            }
            by_key.entry((1 + b as u8, h)).or_default().insert(author);
        }
    }
    let mut score: BTreeMap<&str, usize> = BTreeMap::new();
    for set in by_key.values().filter(|s| s.len() > 1) {
        for a in set {
            let s = score.entry(a).or_default();
            *s = (*s).max(set.len());
        }
    }
    for a in residue {
        *score.entry(a).or_default() += 1;
    }
    let mut v: Vec<(&str, usize)> = score.into_iter().collect();
    v.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(b.0)));
    v.into_iter()
        .map(|(a, _)| a.to_string())
        .filter(|a| valid_user(a))
        .take(max)
        .collect()
}

/// An account's creation time from its profile, or `None`.
pub fn parse_user_created(body: &str) -> Option<i64> {
    serde_json::from_str::<Value>(body)
        .ok()?
        .get("created")?
        .as_i64()
}

/// The platform pass: stories and comments since the checkpoint `mark`
/// (Unix seconds), at most `max`, with account age for at most `lookups`
/// authors.
pub fn pull_platform(
    client: &Client,
    q: &CdxQuery,
    mark: Option<u64>,
    rules: &Rules,
    max: usize,
    lookups: usize,
) -> Result<PlatformPull> {
    let w = Window::new(mark.map(|m| m as i64), crate::client::now_secs());
    let queries = q.scan.unwrap_or(DEFAULT_QUERIES).clamp(1, 50);
    let read = walk(&w, queries, &mut |u| client.get(u))?;
    let mut out = PlatformPull {
        coverage: w.coverage(read.oldest, read.items.len()),
        ..Default::default()
    };
    let mut kept: Vec<(String, PlatformEvent)> = Vec::new();
    for it in &read.items {
        if sc_core::platform::automation::is_automation(&it.author) {
            out.automation += 1;
            continue;
        }
        if let Some(e) = item_event(it, rules) {
            if kept.len() < max {
                kept.push((it.author.clone(), e));
            } else {
                out.capped += 1;
            }
        }
    }
    let mut ranks: BTreeMap<String, u64> = BTreeMap::new();
    for a in lookup_candidates(&kept, lookups) {
        // A failed lookup leaves the account without age data.
        if let Ok(body) = client.get(&format!("{USER}{a}.json"))
            && let Some(c) = parse_user_created(&body).filter(|&c| c > 0)
        {
            ranks.insert(a, (c / RANK_SECS) as u64);
        }
    }
    out.events = kept
        .into_iter()
        .map(|(a, mut e)| {
            e.actor_rank = ranks.get(&a).copied();
            e
        })
        .collect();
    Ok(out)
}

/// The record pass: links in Hacker News stories and comments, as a
/// [`Source`]. `query.pattern` is `|`-separated substrings matched against
/// the links, the title and the text; `query.scan` the index queries a pull
/// makes.
pub struct HnLinks {
    pub query: CdxQuery,
}

impl Source for HnLinks {
    fn kind(&self) -> Kind {
        Kind::HackerNews
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
            Some(Cursor::Offset(t)) => Some(*t as i64),
            Some(c) => anyhow::bail!("hackernews pages by posting time, not {c:?}"),
            None => None,
        };
        let w = Window::new(at, crate::client::now_secs());
        let queries = self.query.scan.unwrap_or(DEFAULT_QUERIES).clamp(1, 50);
        let read = walk(&w, queries, &mut |u| client.get(u))?;
        let needles = Needles::new(&self.query.pattern);
        let mut records: Vec<Observation> = read
            .items
            .iter()
            .flat_map(|it| item_records(it, &needles))
            .collect();
        records.truncate(size);
        Ok(Page {
            stopped: None,
            records,
            next: None,
            truncated: false,
            coverage: Some(w.coverage(read.oldest, read.items.len())),
        })
    }

    fn checkpointed(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const T: i64 = 1_791_900_000;

    /// A synthetic index hit; every name, link and text is invented.
    fn hit(id: u64, ts: i64, story: bool, author: &str, html: &str) -> String {
        let text = serde_json::to_string(html).unwrap();
        if story {
            format!(
                r#"{{"_tags":["story","author_{author}","story_{id}"],"author":"{author}","created_at_i":{ts},"objectID":"{id}","story_id":{id},"title":"Show HN: Probe kit &amp; friends","url":"https://www.relay.example/r?u=https://target.example/","story_text":{text}}}"#
            )
        } else {
            format!(
                r#"{{"_tags":["comment","author_{author}","story_9"],"author":"{author}","comment_text":{text},"created_at_i":{ts},"objectID":"{id}","parent_id":9,"story_id":9,"story_title":"A story"}}"#
            )
        }
    }

    fn body(hits: &[String]) -> String {
        format!(r#"{{"hits":[{}],"nbHits":{}}}"#, hits.join(","), hits.len())
    }

    #[test]
    fn html_is_reduced_to_text_and_links() {
        let (t, l) = html_text(
            r#"See <a href="https:&#x2F;&#x2F;r.jina.ai&#x2F;https:&#x2F;&#x2F;t.example&#x2F;" rel="nofollow">this</a><p>I&#x27;m sure &amp; done"#,
        );
        assert_eq!(t, "See this\nI'm sure & done");
        assert_eq!(l, ["https://r.jina.ai/https://t.example/"]);
        assert_eq!(decode_entities("a &bogus; &#65; &"), "a &bogus; A &");
        assert_eq!(decode_entities("&räksmörgås; ä"), "&räksmörgås; ä");
    }

    #[test]
    fn hits_parse_into_items() {
        let b = body(&[
            hit(11, T, true, "probe_7", ""),
            hit(12, T + 1, false, "other-1", "<p>hello"),
        ]);
        let (items, n) = parse_hits(&b).unwrap();
        assert_eq!((items.len(), n), (2, 2));
        assert!(items[0].story);
        assert_eq!(items[0].title, "Show HN: Probe kit & friends");
        assert_eq!(items[1].story_id, Some(9));
        assert_eq!(items[1].text, "\nhello");
        assert!(parse_hits("{}").is_err());
    }

    #[test]
    fn a_walk_pages_back_to_the_checkpoint() {
        let w = Window {
            start: T,
            until: T + 5000,
            skipped: 0,
        };
        // Two full pages, then a short one.
        let mut calls = Vec::new();
        let read = walk(&w, 10, &mut |u| {
            calls.push(u.to_string());
            let n = calls.len() as u64;
            let count = if n < 3 { PAGE } else { 10 };
            let hits: Vec<String> = (0..count as u64)
                .map(|i| {
                    let id = n * 10_000 + i;
                    hit(
                        id,
                        T + 5000 - (n as i64 * 1000) - i as i64 / 100,
                        false,
                        "a",
                        "x",
                    )
                })
                .collect();
            Ok(body(&hits))
        })
        .unwrap();
        assert_eq!(calls.len(), 3);
        assert!(calls[0].contains("created_at_i%3E1791900000%2Ccreated_at_i%3C%3D1791905000"));
        assert_eq!(read.oldest, T);
        assert_eq!(read.items.len(), 2 * PAGE + 10);
        let cov = w.coverage(read.oldest, read.items.len());
        assert_eq!((cov.read, cov.available, cov.skipped), (83, 83, 0));
        assert_eq!(cov.next, Some((T + 5000) as u64));
        // Out of queries: the newest part read, the rest skipped.
        let read = walk(&w, 1, &mut |_| {
            let hits: Vec<String> = (0..PAGE as u64)
                .map(|i| hit(i, T + 4000, false, "a", "x"))
                .collect();
            Ok(body(&hits))
        })
        .unwrap();
        assert_eq!(read.oldest, T + 4000);
        let cov = w.coverage(read.oldest, read.items.len());
        assert_eq!((cov.read, cov.skipped), (16, 66));
        // The first query failing is an error.
        assert!(walk(&w, 3, &mut |_| anyhow::bail!("down")).is_err());
    }

    #[test]
    fn windows_start_at_the_checkpoint_within_the_backlog() {
        let now = T + 100_000;
        let w = Window::new(None, now);
        assert_eq!(
            (w.until, w.start),
            (now - LAG_SECS, now - LAG_SECS - FRESH_SECS)
        );
        let w = Window::new(Some(now - 7200), now);
        assert_eq!((w.start, w.skipped), (now - 7200, 0));
        let w = Window::new(Some(now - 30 * 3600), now);
        assert_eq!(w.start, now - LAG_SECS - FRESH_SECS);
        assert!(w.skipped > 0);
    }

    #[test]
    fn matching_links_become_records_and_are_never_followed() {
        let b = body(&[
            hit(
                21,
                T,
                false,
                "a",
                r#"Try <a href="https:&#x2F;&#x2F;r.jina.ai&#x2F;https:&#x2F;&#x2F;t.example&#x2F;?uqtag=run7">it</a> and https://other.example/"#,
            ),
            hit(22, T, false, "b", "my run tag is uqtag-77 in plain text"),
            hit(23, T, false, "c", "nothing here"),
            hit(24, T, true, "d", ""),
        ]);
        let (items, _) = parse_hits(&b).unwrap();
        let n = Needles::new("r.jina.ai|uqtag|relay.example");
        let recs: Vec<Observation> = items.iter().flat_map(|i| item_records(i, &n)).collect();
        assert_eq!(recs.len(), 3, "{recs:?}");
        assert_eq!(
            recs[0].url,
            "https://r.jina.ai/https://t.example/?uqtag=run7"
        );
        assert_eq!(
            recs[0].reference.as_deref(),
            Some("https://news.ycombinator.com/item?id=21")
        );
        assert_eq!(recs[0].source, "hackernews");
        assert_eq!(recs[0].ts_kind, TsKind::Request);
        // A tag in plain text: the item's page is the record.
        assert_eq!(recs[1].url, "https://news.ycombinator.com/item?id=22");
        assert!(recs[2].url.starts_with("https://www.relay.example/"));
    }

    #[test]
    fn items_become_platform_events_without_names() {
        let rules = Rules::default_rules();
        let b = body(&[
            hit(
                31,
                T,
                true,
                "probe_7",
                "Certainly! Here's my new tool for scanning sites.",
            ),
            hit(
                32,
                T + 5,
                false,
                "probe_8",
                "Certainly! Here is the analysis you asked for, probe_8 reporting from the run.",
            ),
        ]);
        let (items, _) = parse_hits(&b).unwrap();
        let s = item_event(&items[0], &rules).unwrap();
        assert_eq!(s.action, Action::StoryPosted);
        assert_eq!(s.target, "relay.example");
        assert_eq!(s.link, "https://news.ycombinator.com/item?id=31");
        let c = item_event(&items[1], &rules).unwrap();
        assert_eq!(c.action, Action::Comment);
        assert_eq!(c.target, "hn:9");
        assert_eq!(c.platform, Platform::HackerNews);
        let json = serde_json::to_string(&c).unwrap();
        assert!(!json.contains("probe_8"), "{json}");
        assert!(c.actor.starts_with("acct:"));
        let empty = Item {
            author: "x".into(),
            ..Default::default()
        };
        assert!(item_event(&empty, &rules).is_none());
    }

    #[test]
    fn lookups_go_to_authors_a_group_could_form_around() {
        let rules = Rules::default_rules();
        let text = "Please review my report on the critical vulnerability in the parser module now";
        let mk = |a: &str, t: &str| {
            let it = Item {
                id: 1,
                author: a.into(),
                text: t.into(),
                story_id: Some(1),
                ..Default::default()
            };
            (a.to_string(), item_event(&it, &rules).unwrap())
        };
        let items = vec![
            mk("dup-1", text),
            mk("dup-2", text),
            mk(
                "loner",
                "An unrelated thought about compilers and their many optimisation passes",
            ),
            mk("bad name!", text),
        ];
        let c = lookup_candidates(&items, 10);
        assert_eq!(c, ["dup-1", "dup-2"]);
        assert_eq!(lookup_candidates(&items, 1).len(), 1);
        assert_eq!(
            parse_user_created(r#"{"id":"x","created":1700000000,"karma":1}"#),
            Some(1_700_000_000)
        );
        assert_eq!(parse_user_created("null"), None);
    }
}
