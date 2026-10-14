//! GitHub search (`ghsearch`) for the text GH Archive's trimmed payloads
//! leave out: pull request titles and bodies, and commit messages. It asks
//! GitHub's REST search API, one query per substring of the query's
//! pattern and per scope, for items created in a time window:
//!
//! - pull requests: `GET /search/issues?q="<needle>" is:pr created:<from>..<to>`;
//! - commits: `GET /search/commits?q="<needle>" committer-date:<from>..<to>`.
//!
//! Search matches words, not substrings, so every item that comes back is
//! checked again against the substrings themselves. One record per link in
//! an item's text that matches, and one per item whose text matches with
//! no link that does (a run tag). The record's URL is the link, never
//! fetched; its reference is the pull request's or commit's page. Code
//! search is not used: it returns file content, not the request trail.
//!
//! What does not become a record: the footers coding agents add to their
//! own pull requests and commits (`Generated with ...`, `Co-Authored-By:`)
//! are declared, everyday use, and no substring here matches them.
//!
//! Coverage: a pull reads from [`OVERLAP_SECS`] before its checkpoint
//! (Unix seconds), for items indexed late and commits dated before their
//! push, to a little before its own start ([`LAG_SECS`], for indexing), at
//! most `scan` requests, each query paged oldest first by 100 up to the
//! API's 1000 results. The checkpoint moves only as far as every query
//! read: a query the budget, a failed request or the 1000-result cap cut
//! short holds it at the newest item that query reached, so the next pull
//! reads the rest. Seen IDs drop the items read twice. A query GitHub
//! answered with `incomplete_results` counts as skipped. Coverage is in
//! queries. Without a checkpoint a pull starts [`FRESH_SECS`] back; a
//! checkpoint older than [`MAX_BACKLOG_HOURS`] is skipped to there and
//! every query counts once more as skipped. The canary is a response in
//! the shape the parser expects (`total_count` and `items`): most queries
//! find nothing, so an empty pull says only that.
//!
//! Needs a token (`GITHUB_TOKEN`), sent as a bearer token and never logged
//! or cached; without one the watch skips the source.
//!
//! Terms: the search API (<https://docs.github.com/en/rest/search/search>)
//! allows 30 requests a minute with a token and returns at most 1000
//! results a search; the watch paces every host at `min_interval_secs`.
//! GitHub's Acceptable Use Policies (<https://docs.github.com/en/site-policy/acceptable-use-policies/github-acceptable-use-policies>,
//! section 7) let researchers use public, non-personal information for
//! research whose publications are open access, and forbid spam or selling
//! personal information. We keep the matching link, the item's public page
//! and its time, never the author's login or the text.

use crate::pager::{Coverage, Cursor, Page};
use crate::{CdxQuery, Client, Kind, Needles, Source, parse_date, short_hash};
use anyhow::{Context, Result};
use sc_core::{Observation, TsKind, redact_observation};
use serde_json::Value;
use std::collections::HashSet;

const API: &str = "https://api.github.com/search/";
/// Results per request: the API's maximum.
const PER_PAGE: usize = 100;
/// Results one search returns at most.
const MAX_RESULTS: usize = 1000;
/// Requests one pull makes unless `scan` says otherwise.
const DEFAULT_REQUESTS: usize = 40;
/// A pull reads up to this long before its own start.
pub const LAG_SECS: i64 = 600;
/// Without a checkpoint, a pull starts this far back.
pub const FRESH_SECS: i64 = 6 * 3600;
/// A checkpoint further back than this is skipped to [`FRESH_SECS`].
pub const MAX_BACKLOG_HOURS: i64 = 48;
/// A pull starts this far before its checkpoint.
pub const OVERLAP_SECS: i64 = 3 * 3600;

/// What a query searches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    PullRequests,
    Commits,
}

impl Scope {
    fn name(self) -> &'static str {
        match self {
            Self::PullRequests => "pr",
            Self::Commits => "commit",
        }
    }
}

/// One pull request or commit: its page, time and text.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Hit {
    pub link: String,
    pub ts: i64,
    /// A pull request's title and body, or a commit's message.
    pub text: String,
}

/// What one search response held.
#[derive(Debug, Default)]
pub struct Results {
    pub hits: Vec<Hit>,
    /// Items on this page.
    pub items: usize,
    pub total: usize,
    pub incomplete: bool,
}

/// One search response, either scope.
pub fn parse_results(body: &str, scope: Scope) -> Result<Results> {
    let v: Value = serde_json::from_str(body).context("GitHub search: not JSON")?;
    let total = v
        .get("total_count")
        .and_then(Value::as_u64)
        .context("GitHub search: no `total_count`")? as usize;
    let items = v
        .get("items")
        .and_then(Value::as_array)
        .context("GitHub search: no `items` array")?;
    let mut out = Results {
        items: items.len(),
        total,
        incomplete: v
            .get("incomplete_results")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        ..Default::default()
    };
    for it in items {
        let s = |p: &str| it.pointer(p).and_then(Value::as_str);
        let Some(link) = s("/html_url").filter(|u| u.starts_with("https://github.com/")) else {
            continue;
        };
        let (ts, text) = match scope {
            Scope::PullRequests => (
                s("/created_at"),
                format!(
                    "{}\n{}",
                    s("/title").unwrap_or(""),
                    s("/body").unwrap_or("")
                ),
            ),
            Scope::Commits => (
                s("/commit/committer/date").or_else(|| s("/commit/author/date")),
                s("/commit/message").unwrap_or("").to_string(),
            ),
        };
        out.hits.push(Hit {
            link: link.to_string(),
            ts: ts.and_then(parse_date).unwrap_or(0),
            text,
        });
    }
    Ok(out)
}

/// Records from one item: the links in its text that match `needles`, and
/// the item's page when only its text does. Redacted.
pub fn hit_records(hit: &Hit, scope: Scope, needles: &Needles) -> Vec<Observation> {
    let mut urls: Vec<String> = Vec::new();
    for u in crate::gharchive::urls_in(&hit.text) {
        let u = u.trim_end_matches(['.', ',', ';', ':', '`', '*']);
        if needles.matches(u) && !urls.iter().any(|x| x == u) {
            urls.push(u.to_string());
        }
    }
    if urls.is_empty() && needles.matches(&hit.text) {
        urls.push(hit.link.clone());
    }
    let item = short_hash(&hit.link);
    urls.into_iter()
        .map(|url| {
            let mut o = Observation {
                id: format!("ghsearch:{}:{item}:{}", scope.name(), short_hash(&url)),
                source: "ghsearch".into(),
                ts: hit.ts,
                ts_kind: TsKind::Request,
                url,
                reference: Some(hit.link.clone()),
                ..Default::default()
            };
            redact_observation(&mut o);
            o
        })
        .collect()
}

/// The span one pull searches: after `start`, up to `until` (Unix seconds).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Window {
    pub start: i64,
    pub until: i64,
    /// Where the previous pull reached (the checkpoint, or where a fresh or
    /// skipped-ahead pull begins): the next checkpoint is never before it.
    pub from: i64,
    /// Backlog passed over (seconds): a checkpoint older than
    /// [`MAX_BACKLOG_HOURS`].
    pub skipped: i64,
}

impl Window {
    pub fn new(checkpoint: Option<i64>, now: i64) -> Self {
        let until = now - LAG_SECS;
        let fresh = until - FRESH_SECS;
        match checkpoint {
            Some(c) if c >= until - MAX_BACKLOG_HOURS * 3600 => {
                let from = c.min(until);
                Self {
                    start: from - OVERLAP_SECS,
                    until,
                    from,
                    skipped: 0,
                }
            }
            c => Self {
                start: fresh,
                until,
                from: fresh,
                skipped: c.map_or(0, |c| (fresh - c).max(0)),
            },
        }
    }

    /// A window from `start` to `until` with no checkpoint before it.
    pub fn span(start: i64, until: i64) -> Self {
        Self {
            start,
            until,
            from: start,
            skipped: 0,
        }
    }
}

/// The words a search asks for: the substring without the punctuation at
/// its ends (`uqtag=` searches `uqtag`).
fn phrase(needle: &str) -> &str {
    needle.trim_matches(|c: char| !c.is_ascii_alphanumeric())
}

/// The request for one page of one query.
pub fn search_url(scope: Scope, needle: &str, w: &Window, page: usize) -> String {
    let ts = |t: i64| {
        chrono::DateTime::from_timestamp(t, 0)
            .unwrap_or_default()
            .format("%Y-%m-%dT%H:%M:%SZ")
            .to_string()
    };
    let range = format!("{}..{}", ts(w.start), ts(w.until));
    let (path, q, sort) = match scope {
        Scope::PullRequests => (
            "issues",
            format!("\"{}\" is:pr created:{range}", phrase(needle)),
            "created",
        ),
        Scope::Commits => (
            "commits",
            format!("\"{}\" committer-date:{range}", phrase(needle)),
            "committer-date",
        ),
    };
    let mut u = url::Url::parse(&format!("{API}{path}")).expect("constant URL");
    u.query_pairs_mut()
        .append_pair("q", &q)
        .append_pair("sort", sort)
        .append_pair("order", "asc")
        .append_pair("per_page", &PER_PAGE.to_string())
        .append_pair("page", &page.to_string());
    u.to_string()
}

/// What a pull's searches got.
#[derive(Debug, Default)]
pub struct SearchRead {
    pub hits: Vec<(Scope, Hit)>,
    pub queries: usize,
    /// Queries read to their end.
    pub complete: usize,
    /// Responses in the expected shape.
    pub parsed: usize,
    /// Queries GitHub answered with `incomplete_results`: read to their
    /// end, but what the search left out is not read again.
    pub incomplete: usize,
    /// How far every query read (Unix seconds): the window's end when all
    /// were read to their end, else the newest item the least-read query
    /// reached (the window's start for a query not reached at all).
    pub reached: i64,
}

impl SearchRead {
    /// Where the next pull starts: as far as every query read, and never
    /// before where this one started.
    pub fn next(&self, w: &Window) -> i64 {
        self.reached.max(w.from)
    }
}

/// Run every query (each needle in each scope), at most `budget` requests,
/// each paged oldest first. `fetch` answers one request URL. The first
/// request's failure is an error; a later one ends the searches with what
/// they have, and the queries it left unread hold [`SearchRead::reached`].
pub fn search(
    w: &Window,
    needles: &[String],
    scopes: &[Scope],
    budget: usize,
    fetch: &mut dyn FnMut(&str) -> Result<String>,
) -> Result<SearchRead> {
    let mut seen = HashSet::new();
    let mut requests = 0usize;
    let mut phrases: Vec<&str> = Vec::new();
    for n in needles {
        let p = phrase(n);
        if !p.is_empty() && !phrases.contains(&p) {
            phrases.push(p);
        }
    }
    let mut out = SearchRead {
        queries: phrases.len() * scopes.len(),
        reached: w.until,
        ..Default::default()
    };
    let mut failed = false;
    for &scope in scopes {
        for p in &phrases {
            // The newest item this query read; with results oldest first,
            // everything before it is read.
            let mut newest: Option<i64> = None;
            let mut done = false;
            for page in 1..=MAX_RESULTS / PER_PAGE {
                if failed || requests >= budget.max(1) {
                    break;
                }
                requests += 1;
                let body = match fetch(&search_url(scope, p, w, page)) {
                    Ok(b) => b,
                    Err(e) if requests == 1 => return Err(e),
                    Err(_) => {
                        failed = true;
                        break;
                    }
                };
                let r = parse_results(&body, scope)?;
                out.parsed += 1;
                for h in r.hits {
                    if h.ts > 0 {
                        newest = Some(newest.map_or(h.ts, |n| n.max(h.ts)));
                    }
                    if seen.insert(h.link.clone()) {
                        out.hits.push((scope, h));
                    }
                }
                let more = r.items >= PER_PAGE && page * PER_PAGE < r.total;
                if !more {
                    done = true;
                    if r.incomplete {
                        out.incomplete += 1;
                    } else {
                        out.complete += 1;
                    }
                    break;
                }
            }
            if !done {
                // Cut short by the budget, a failed request or the cap.
                let q = newest.unwrap_or(w.start).max(w.start);
                out.reached = out.reached.min(q);
            }
        }
    }
    Ok(out)
}

/// Pull requests and commits whose text carries a relay link or run tag,
/// as a [`Source`]. `query.pattern` is `|`-separated substrings, each one
/// search per scope; `query.endpoint` limits the scopes (`prs` or
/// `commits`, both by default); `query.scan` the requests one pull makes.
pub struct GhSearch {
    query: CdxQuery,
    token: String,
}

impl GhSearch {
    /// The source for `query`, with the token it sends.
    pub fn new(query: CdxQuery, token: String) -> Result<Self> {
        let s = Self { query, token };
        s.scopes()?;
        Ok(s)
    }

    fn scopes(&self) -> Result<Vec<Scope>> {
        Ok(match self.query.endpoint.as_deref() {
            None | Some("all") => vec![Scope::PullRequests, Scope::Commits],
            Some("prs") => vec![Scope::PullRequests],
            Some("commits") => vec![Scope::Commits],
            Some(e) => anyhow::bail!("unknown ghsearch endpoint `{e}` (expected prs or commits)"),
        })
    }
}

impl Source for GhSearch {
    fn kind(&self) -> Kind {
        Kind::GhSearch
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
            Some(c) => anyhow::bail!("ghsearch pages by creation time, not {c:?}"),
            None => None,
        };
        let scopes = self.scopes()?;
        let w = Window::new(at, crate::client::now_secs());
        let needles = Needles::new(&self.query.pattern);
        let budget = self.query.scan.unwrap_or(DEFAULT_REQUESTS).clamp(1, 200);
        let auth = format!("Bearer {}", self.token);
        let headers = [
            ("Authorization", auth.as_str()),
            ("Accept", "application/vnd.github+json"),
            ("X-GitHub-Api-Version", "2022-11-28"),
        ];
        let read = search(&w, needles.terms(), &scopes, budget, &mut |u| {
            client.get_with(u, &headers)
        })?;
        let queries = read.queries as u64;
        // A backlog passed over is a span of every query never read.
        let backlog = if w.skipped > 0 { queries } else { 0 };
        let mut records: Vec<Observation> = read
            .hits
            .iter()
            .flat_map(|(scope, h)| hit_records(h, *scope, &needles))
            .collect();
        records.truncate(size);
        Ok(Page {
            records,
            next: None,
            truncated: false,
            coverage: Some(Coverage {
                unit: "queries",
                read: read.complete as u64,
                available: queries + backlog,
                skipped: read.incomplete as u64 + backlog,
                next: Some(read.next(&w).max(0) as u64),
                canary: Some(read.parsed > 0),
            }),
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

    // Every repository, link and text below is invented.

    fn pr(n: u64, title: &str, body: &str) -> String {
        format!(
            r#"{{"html_url":"https://github.com/probe-owner/repo/pull/{n}","number":{n},"title":{},"body":{},"created_at":"2026-10-13T10:00:00Z","user":{{"login":"probe-user"}},"pull_request":{{}}}}"#,
            serde_json::to_string(title).unwrap(),
            serde_json::to_string(body).unwrap()
        )
    }

    fn commit(sha: &str, message: &str) -> String {
        format!(
            r#"{{"html_url":"https://github.com/probe-owner/repo/commit/{sha}","sha":"{sha}","commit":{{"message":{},"author":{{"name":"Probe","date":"2026-10-13T09:00:00Z"}},"committer":{{"name":"Probe","date":"2026-10-13T09:30:00Z"}}}}}}"#,
            serde_json::to_string(message).unwrap()
        )
    }

    fn body(items: &[String], total: usize) -> String {
        format!(
            r#"{{"total_count":{total},"incomplete_results":false,"items":[{}]}}"#,
            items.join(",")
        )
    }

    #[test]
    fn responses_parse_in_both_scopes() {
        let r = parse_results(&body(&[pr(7, "Fix", "see notes")], 1), Scope::PullRequests).unwrap();
        assert_eq!((r.items, r.total, r.incomplete), (1, 1, false));
        assert_eq!(r.hits[0].link, "https://github.com/probe-owner/repo/pull/7");
        assert_eq!(r.hits[0].ts, parse_date("2026-10-13T10:00:00Z").unwrap());
        assert_eq!(r.hits[0].text, "Fix\nsee notes");
        let r = parse_results(&body(&[commit("abc123", "msg")], 1), Scope::Commits).unwrap();
        assert_eq!(r.hits[0].ts, parse_date("2026-10-13T09:30:00Z").unwrap());
        assert!(parse_results("{}", Scope::Commits).is_err());
        assert!(parse_results(r#"{"total_count":0}"#, Scope::Commits).is_err());
    }

    #[test]
    fn relay_links_and_run_tags_become_records_and_footers_do_not() {
        let n = Needles::new("r.jina.ai/http|uqtag=|chatgpttest");
        let hit = |text: &str| Hit {
            link: "https://github.com/probe-owner/repo/pull/7".into(),
            ts: T,
            text: text.into(),
        };
        let recs = hit_records(
            &hit(
                "Fetched via [it](https://r.jina.ai/https://t.example/?uqtag=run7). And https://other.example/",
            ),
            Scope::PullRequests,
            &n,
        );
        assert_eq!(recs.len(), 1, "{recs:?}");
        assert_eq!(
            recs[0].url,
            "https://r.jina.ai/https://t.example/?uqtag=run7"
        );
        assert_eq!(
            recs[0].reference.as_deref(),
            Some("https://github.com/probe-owner/repo/pull/7")
        );
        assert_eq!(
            (recs[0].source.as_str(), recs[0].ts_kind),
            ("ghsearch", TsKind::Request)
        );
        assert!(recs[0].id.starts_with("ghsearch:pr:"));
        // A run tag with no link: the item's page.
        let recs = hit_records(&hit("probe chatgpttest42 done"), Scope::Commits, &n);
        assert_eq!(recs[0].url, "https://github.com/probe-owner/repo/pull/7");
        // A coding agent's own footer is everyday use, not a record.
        let footer = "Add parser\n\nGenerated with [Claude Code](https://claude.com/claude-code)\n\nCo-Authored-By: Claude <noreply@anthropic.com>";
        assert!(hit_records(&hit(footer), Scope::Commits, &n).is_empty());
    }

    #[test]
    fn searches_page_each_query_within_the_budget() {
        let w = Window::span(T, T + 3600);
        let u = search_url(Scope::PullRequests, "uqtag=", &w, 2);
        assert!(
            u.starts_with(
                "https://api.github.com/search/issues?q=%22uqtag%22+is%3Apr+created%3A2026-"
            ),
            "{u}"
        );
        assert!(u.contains("&page=2") && u.contains("per_page=100"));
        let u = search_url(Scope::Commits, "r.jina.ai/http", &w, 1);
        assert!(
            u.contains("q=%22r.jina.ai%2Fhttp%22+committer-date%3A"),
            "{u}"
        );
        // The first query has two full pages and a short one; the second
        // finds nothing.
        let mut calls: Vec<String> = Vec::new();
        let needles = vec!["uqtag=".to_string(), "chatgpttest".to_string()];
        let read = search(&w, &needles, &[Scope::PullRequests], 10, &mut |u| {
            calls.push(u.to_string());
            Ok(if u.contains("uqtag") {
                let page: usize = u.rsplit("page=").next().unwrap().parse().unwrap();
                let n = if page < 3 { 100 } else { 5 };
                let items: Vec<String> = (0..n)
                    .map(|i| pr((page * 1000 + i) as u64, "t", "b"))
                    .collect();
                body(&items, 205)
            } else {
                body(&[], 0)
            })
        })
        .unwrap();
        assert_eq!(calls.len(), 4);
        assert_eq!((read.queries, read.complete, read.parsed), (2, 2, 4));
        assert_eq!(read.hits.len(), 205);
        // Out of budget: the second query is not reached, and counts.
        let read = search(
            &w,
            &needles,
            &[Scope::PullRequests, Scope::Commits],
            2,
            &mut |_| {
                Ok(body(
                    &(0..100).map(|i| pr(i, "t", "b")).collect::<Vec<_>>(),
                    900,
                ))
            },
        )
        .unwrap();
        assert_eq!((read.queries, read.complete), (4, 0));
        // The first request failing is an error; a later one ends the pull.
        assert!(
            search(&w, &needles, &[Scope::Commits], 5, &mut |_| anyhow::bail!(
                "403"
            ))
            .is_err()
        );
        let mut n = 0;
        let read = search(&w, &needles, &[Scope::Commits], 5, &mut |_| {
            n += 1;
            if n == 1 {
                Ok(body(&[], 0))
            } else {
                anyhow::bail!("403")
            }
        })
        .unwrap();
        assert_eq!((read.queries, read.complete), (2, 1));
    }

    #[test]
    fn windows_start_an_overlap_before_the_checkpoint_within_the_backlog() {
        let now = T + 100_000;
        let fresh = now - LAG_SECS - FRESH_SECS;
        let w = Window::new(None, now);
        assert_eq!((w.start, w.from, w.skipped), (fresh, fresh, 0));
        let w = Window::new(Some(now - 7200), now);
        assert_eq!((w.start, w.from), (now - 7200 - OVERLAP_SECS, now - 7200));
        assert_eq!(w.skipped, 0);
        // An old checkpoint skips ahead, and the gap is counted.
        let w = Window::new(Some(now - 72 * 3600), now);
        assert_eq!((w.start, w.from), (fresh, fresh));
        assert_eq!(w.skipped, fresh - (now - 72 * 3600));
        let code = CdxQuery {
            endpoint: Some("code".into()),
            ..Default::default()
        };
        assert!(GhSearch::new(code, "t".into()).is_err());
    }

    /// A pull request created at `ts`.
    fn pr_at(n: u64, ts: i64) -> String {
        let at = chrono::DateTime::from_timestamp(ts, 0)
            .unwrap()
            .format("%Y-%m-%dT%H:%M:%SZ");
        format!(
            r#"{{"html_url":"https://github.com/probe-owner/repo/pull/{n}","title":"t","body":"b","created_at":"{at}"}}"#
        )
    }

    /// A page of `n` pull requests, the `page`th of `total`, created a
    /// minute apart per page from the checkpoint `T` on.
    fn page_of(page: usize, n: usize, total: usize) -> String {
        let items: Vec<String> = (0..n)
            .map(|i| pr_at((page * 1000 + i) as u64, T + (page as i64) * 60))
            .collect();
        body(&items, total)
    }

    fn page_no(u: &str) -> usize {
        u.rsplit("page=").next().unwrap().parse().unwrap()
    }

    #[test]
    fn the_checkpoint_moves_only_as_far_as_every_query_read() {
        let now = T + 4 * 3600 + LAG_SECS;
        let w = Window::new(Some(T), now);
        let needles = vec!["uqtag=".to_string(), "chatgpttest".to_string()];
        let scopes = [Scope::PullRequests];
        // Results come oldest first.
        assert!(search_url(Scope::Commits, "uqtag=", &w, 1).contains("order=asc"));

        // Every query read to its end: the checkpoint moves to the window's end.
        let read = search(&w, &needles, &scopes, 20, &mut |_| Ok(body(&[], 0))).unwrap();
        assert_eq!(read.next(&w), w.until);

        // The second query's request fails (a rate limit, say): nothing it
        // covers is passed over, so the checkpoint stays where it was.
        let read = search(&w, &needles, &scopes, 20, &mut |u| {
            if u.contains("uqtag") {
                Ok(page_of(1, 3, 3))
            } else {
                anyhow::bail!("HTTP 403")
            }
        })
        .unwrap();
        assert_eq!(read.hits.len(), 3);
        assert_eq!(read.next(&w), T);

        // The 1000-result cap: the next pull starts at the newest item read.
        let read = search(&w, &needles, &scopes, 20, &mut |u| {
            Ok(if u.contains("uqtag") {
                page_of(page_no(u), 100, 5000)
            } else {
                body(&[], 0)
            })
        })
        .unwrap();
        assert_eq!((read.complete, read.parsed), (1, 11));
        assert_eq!(read.next(&w), T + 10 * 60);

        // Out of budget part way through one query: the same.
        let one = vec!["uqtag=".to_string()];
        let read = search(&w, &one, &scopes, 3, &mut |u| {
            Ok(page_of(page_no(u), 100, 500))
        })
        .unwrap();
        assert_eq!(read.complete, 0);
        assert_eq!(read.next(&w), T + 3 * 60);
        // A query the budget never reached holds the checkpoint.
        let read = search(&w, &needles, &scopes, 1, &mut |_| Ok(body(&[], 0))).unwrap();
        assert_eq!((read.complete, read.next(&w)), (1, T));

        // `incomplete_results` is read to its end and counted, not held.
        let read = search(&w, &one, &scopes, 5, &mut |_| {
            Ok(r#"{"total_count":0,"incomplete_results":true,"items":[]}"#.into())
        })
        .unwrap();
        assert_eq!((read.complete, read.incomplete), (0, 1));
        assert_eq!(read.next(&w), w.until);
    }
}
