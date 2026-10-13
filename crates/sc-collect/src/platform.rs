//! Platform events for the coordinated-account detector
//! (`sc_core::platform`): GitHub events from GH Archive, npm search results,
//! PyPI's feeds, the Hugging Face Hub's newest Spaces, models and datasets,
//! and Wikimedia's revision stream ([`crate::wikimedia`]). Metadata and
//! event text only: repositories, packages, Spaces, wiki pages and every
//! URL inside the text are never fetched.
//!
//! GitHub's event payloads are trimmed: a pull request opened carries its
//! number and refs but no title, body or author association, and a push no
//! commits. A pull request opened is kept text-less, with its repository as
//! the target, so many accounts opening pull requests on one repository at
//! once still group; stars and forks are kept the same way.
//!
//! What is kept is what grouping needs, reduced at parse time: logins become
//! a keyed hash ([`sc_core::platform::actor_key`]), a GitHub account id a
//! coarse rank, and text a sketch with URLs, addresses, mentions, numbers
//! and identifiers as slots. Automation accounts are dropped by login before
//! anything is kept ([`sc_core::platform::automation`]).
//!
//! Terms: GH Archive, npm and PyPI as in their record collectors. The Go
//! module index (<https://index.golang.org/>) is public and states no terms
//! or rate limits; a few paced requests a run, each up to its documented
//! maximum of 2000 entries, keep within ordinary use. The
//! Hugging Face Hub API (<https://huggingface.co/docs/hub/api>) is public and
//! documented; its rate limits (<https://huggingface.co/docs/hub/rate-limits>)
//! allow anonymous callers hundreds of API requests per five minutes, and
//! its content policy (<https://huggingface.co/content-policy>) forbids
//! excessive bulk activity and publishing others' private information. One
//! listing request per Hub source per run, keeping ids, owners and times,
//! stays well inside that; a Space's page and app are never opened.

use crate::gharchive::{LAG_HOURS, MAX_FILE, for_each_event, hour_name};
use crate::pager::Coverage;
use crate::{CdxQuery, Client, Needles, parse_date};
use anyhow::{Context, Result, bail};
use sc_core::Rules;
use sc_core::platform::automation::{LoginClass, classify_login, is_automation};
use sc_core::platform::{Action, Platform, PlatformEvent, RANK_UNIT, actor_key, name_template};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::io::Read;

/// Events one GH Archive pull keeps at most, so memory stays bounded.
const DEFAULT_MAX_EVENTS: usize = 500_000;
/// Hours one GH Archive pull reads unless `scan` says otherwise.
const DEFAULT_HOURS: usize = 1;
/// Compressed megabytes one GH Archive pull reads unless `max_mb` says
/// otherwise: room for six of the largest hours.
const DEFAULT_MAX_MB: u64 = 1024;
/// A checkpoint further back than this is skipped to the newest hours.
const MAX_BACKLOG_HOURS: i64 = 24;

/// The `kind`s a platform source can name.
pub const PLATFORM_KINDS: &[&str] = &[
    "gharchive",
    "npm",
    "pypi",
    "huggingface",
    "wikimedia",
    "golang",
    "hackernews",
];

/// A platform source in the watchlist (`[[platform.source]]`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlatformSource {
    pub name: String,
    /// One of [`PLATFORM_KINDS`].
    pub kind: String,
    /// Events one pull keeps at most.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_events: Option<usize>,
    /// Account-age lookups one pull makes at most (`hackernews`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_lookups: Option<usize>,
    #[serde(flatten)]
    pub query: CdxQuery,
}

/// What one pull got.
#[derive(Debug, Default)]
pub struct PlatformPull {
    pub events: Vec<PlatformEvent>,
    pub coverage: Coverage,
    /// Events dropped as automation by login.
    pub automation: usize,
    /// Events dropped at the cap.
    pub capped: usize,
    /// Events from declared coding-agent Apps, by product: tallied, not grouped.
    pub declared: BTreeMap<String, usize>,
    /// Events from undeclared App logins that claim a declared product's
    /// name: login to (the product claimed, events). Spoofing leads.
    pub lookalikes: BTreeMap<String, (String, usize)>,
}

impl PlatformPull {
    fn add_tally(&mut self, t: GhTally) {
        self.events.extend(t.events);
        self.automation += t.automation;
        self.capped += t.capped;
        for (k, n) in t.declared {
            *self.declared.entry(k).or_default() += n;
        }
        for (k, (claim, n)) in t.lookalikes {
            self.lookalikes.entry(k).or_insert((claim, 0)).1 += n;
        }
    }
}

/// Pull one platform source. `mark` is a GH Archive source's checkpoint
/// (the next hour to read), returned in `coverage.next`.
pub fn pull_platform(
    client: &Client,
    src: &PlatformSource,
    mark: Option<u64>,
    rules: &Rules,
) -> Result<PlatformPull> {
    let max = src.max_events.unwrap_or(DEFAULT_MAX_EVENTS);
    match src.kind.as_str() {
        "gharchive" => pull_gharchive(client, &src.query, mark, rules, max),
        "npm" => {
            let mut u = url::Url::parse("https://registry.npmjs.org/-/v1/search")?;
            u.query_pairs_mut()
                .append_pair("text", &src.query.pattern)
                .append_pair("size", &src.query.page_size.clamp(1, 250).to_string());
            let body = client.get(u.as_str()).context("npm search")?;
            let (events, objects) = npm_events(&body, rules)?;
            Ok(feed_pull(events, objects, "packages"))
        }
        "pypi" => {
            let feed = match src.query.endpoint.as_deref().unwrap_or("packages") {
                f @ ("updates" | "packages") => f,
                f => bail!("unknown PyPI feed `{f}` (expected updates or packages)"),
            };
            let body = client.get(&format!("https://pypi.org/rss/{feed}.xml"))?;
            let items = body.matches("<item>").count();
            let events = pypi_events(&body, &Needles::new(&src.query.pattern), rules);
            Ok(feed_pull(events, items, "items"))
        }
        "huggingface" => {
            let what = src.query.endpoint.as_deref().unwrap_or("spaces");
            if !matches!(what, "spaces" | "models" | "datasets") {
                bail!("unknown Hub listing `{what}` (expected spaces, models or datasets)");
            }
            let limit = src.query.limit.clamp(1, 1000);
            let body = client.get(&format!(
                "https://huggingface.co/api/{what}?sort=createdAt&direction=-1&limit={limit}"
            ))?;
            let (events, items) = hf_events(&body, what)?;
            Ok(feed_pull(events, items, "items"))
        }
        "wikimedia" => crate::wikimedia::pull_platform(client, &src.query, mark, rules, max),
        "golang" => pull_golang(client, &src.query, mark, max),
        "hackernews" => crate::hackernews::pull_platform(
            client,
            &src.query,
            mark,
            rules,
            max,
            src.max_lookups
                .unwrap_or(crate::hackernews::DEFAULT_LOOKUPS),
        ),
        k => bail!(
            "unknown platform source kind `{k}` (expected one of {})",
            PLATFORM_KINDS.join(", ")
        ),
    }
}

fn feed_pull(mut events: Vec<PlatformEvent>, read: usize, unit: &'static str) -> PlatformPull {
    let automation = events.iter().filter(|e| e.id.is_empty()).count();
    events.retain(|e| !e.id.is_empty());
    PlatformPull {
        events,
        coverage: Coverage {
            unit,
            read: read as u64,
            available: read as u64,
            canary: Some(read > 0),
            ..Default::default()
        },
        automation,
        ..Default::default()
    }
}

fn pull_gharchive(
    client: &Client,
    q: &CdxQuery,
    mark: Option<u64>,
    rules: &Rules,
    max: usize,
) -> Result<PlatformPull> {
    let latest = crate::client::now_secs() / 3600 - LAG_HOURS;
    let hours = q.scan.unwrap_or(DEFAULT_HOURS).clamp(1, 24) as i64;
    let budget = q.max_mb.unwrap_or(DEFAULT_MAX_MB).max(1) << 20;
    let newest = latest - hours + 1;
    let start = match mark.map(|m| m as i64) {
        Some(h) if h > latest - MAX_BACKLOG_HOURS => h,
        _ => newest,
    };
    let mut out = PlatformPull {
        coverage: Coverage {
            unit: "hours",
            available: (latest - start + 1).max(0) as u64,
            skipped: mark.map_or(0, |m| (start - m as i64).max(0) as u64),
            next: Some(start as u64),
            ..Default::default()
        },
        ..Default::default()
    };
    let mut bytes = 0u64;
    let mut hour = start;
    while hour <= latest && hour < start + hours && bytes < budget {
        let url = format!(
            "https://data.gharchive.org/{}.json.gz",
            hour_name(hour * 3600)
        );
        match client.get_stream_opt(&url, MAX_FILE, true)? {
            Some(r) => {
                let counted = CountRead { inner: r, n: 0 };
                let mut gz = flate2::read::MultiGzDecoder::new(counted);
                let room = max.saturating_sub(out.events.len());
                let (t, err) = read_gharchive(&mut gz, rules, room);
                bytes += gz.get_ref().n;
                let parsed = t.parsed;
                out.add_tally(t);
                match err {
                    // A corrupt or cut-off hour is a gap, not a stall.
                    Some(e) => {
                        eprint!("(skipped unreadable {url}: {e}) ");
                        out.coverage.skipped += 1;
                    }
                    None => {
                        out.coverage.read += 1;
                        out.coverage.canary =
                            Some(out.coverage.canary.unwrap_or(true) && parsed > 0);
                    }
                }
            }
            None => out.coverage.skipped += 1,
        }
        hour += 1;
        out.coverage.next = Some(hour as u64);
    }
    Ok(out)
}

struct CountRead<R> {
    inner: R,
    n: u64,
}

impl<R: Read> Read for CountRead<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let k = self.inner.read(buf)?;
        self.n += k as u64;
        Ok(k)
    }
}

/// What [`gharchive_events`] read.
#[derive(Debug, Default)]
pub struct GhTally {
    pub events: Vec<PlatformEvent>,
    /// Events parsed, kept or not: the canary.
    pub parsed: usize,
    pub automation: usize,
    pub capped: usize,
    /// Events from declared coding-agent Apps, by product.
    pub declared: BTreeMap<String, usize>,
    /// Events from lookalike App logins: login to (product claimed, events).
    pub lookalikes: BTreeMap<String, (String, usize)>,
}

/// Read GH Archive NDJSON from `r` and keep the events the detector reads,
/// at most `max`: issues, pull requests and discussions opened; issue,
/// review and commit comments and reviews; releases published; wiki pages
/// edited; repositories created; repositories starred and forked. Overlong
/// lines are skipped.
pub fn gharchive_events(r: impl Read, rules: &Rules, max: usize) -> Result<GhTally> {
    let (t, err) = read_gharchive(r, rules, max);
    match err {
        Some(e) => Err(e.into()),
        None => Ok(t),
    }
}

/// [`gharchive_events`], keeping what was read before a read error.
fn read_gharchive(r: impl Read, rules: &Rules, max: usize) -> (GhTally, Option<std::io::Error>) {
    let mut out = GhTally::default();
    let err = for_each_event(r, &mut |v| {
        if v.pointer("/repo/name").is_none() {
            return true;
        }
        out.parsed += 1;
        match gh_event(v, rules) {
            GhEvent::Keep(e) if out.events.len() < max => out.events.push(*e),
            GhEvent::Keep(_) => out.capped += 1,
            GhEvent::Automation => out.automation += 1,
            GhEvent::Declared(p) => *out.declared.entry(p).or_default() += 1,
            GhEvent::Lookalike(login, claim) => {
                out.lookalikes.entry(login).or_insert((claim, 0)).1 += 1;
            }
            GhEvent::Skip => {}
        }
        true
    })
    .err();
    (out, err)
}

/// [`gharchive_events`] over a GH Archive hour file on disk (`.json`, or
/// `.json.gz` decompressed on the fly), with no cap.
pub fn gharchive_file(path: &std::path::Path, rules: &Rules) -> Result<GhTally> {
    let f = std::fs::File::open(path).with_context(|| format!("opening {}", path.display()))?;
    if path.extension().is_some_and(|e| e == "gz") {
        gharchive_events(flate2::read::MultiGzDecoder::new(f), rules, usize::MAX)
    } else {
        gharchive_events(f, rules, usize::MAX)
    }
}

enum GhEvent {
    Keep(Box<PlatformEvent>),
    Automation,
    /// A declared coding-agent App's event: its product.
    Declared(String),
    /// A lookalike App's event: its login and the product it claims.
    Lookalike(String, String),
    Skip,
}

fn gh_event(v: &Value, rules: &Rules) -> GhEvent {
    let s = |p: &str| v.pointer(p).and_then(Value::as_str);
    let (Some(kind), Some(repo), Some(id)) = (s("/type"), s("/repo/name"), s("/id")) else {
        return GhEvent::Skip;
    };
    let action = s("/payload/action").unwrap_or("");
    // (action, object holding the text and link)
    let (act, obj) = match (kind, action) {
        ("IssuesEvent", "opened") => (Action::IssueOpened, "/payload/issue"),
        ("PullRequestEvent", "opened") => (Action::PullOpened, "/payload/pull_request"),
        ("IssueCommentEvent", "created") => (Action::Comment, "/payload/comment"),
        ("PullRequestReviewCommentEvent", "created") => (Action::ReviewComment, "/payload/comment"),
        ("PullRequestReviewEvent", "created" | "submitted" | "") => {
            (Action::ReviewComment, "/payload/review")
        }
        ("CommitCommentEvent", _) => (Action::CommitComment, "/payload/comment"),
        ("DiscussionEvent", "created") => (Action::DiscussionOpened, "/payload/discussion"),
        ("ReleaseEvent", "published") => (Action::ReleasePublished, "/payload/release"),
        ("GollumEvent", _) => (Action::WikiEdited, "/payload/pages/0"),
        ("WatchEvent", _) => (Action::Starred, "/payload"),
        ("ForkEvent", _) => (Action::Forked, "/payload/forkee"),
        ("CreateEvent", _) if s("/payload/ref_type") == Some("repository") => {
            (Action::RepoCreated, "/payload")
        }
        _ => return GhEvent::Skip,
    };
    let login = s("/actor/login").unwrap_or("");
    match classify_login(login) {
        LoginClass::Declared(a) => {
            return GhEvent::Declared(format!("{} ({})", a.product, a.provider));
        }
        LoginClass::Lookalike(a) => {
            return GhEvent::Lookalike(
                login.to_ascii_lowercase(),
                format!("{} ({})", a.product, a.provider),
            );
        }
        LoginClass::Automation => return GhEvent::Automation,
        LoginClass::Person => {}
    }
    let actor_id = v.pointer("/actor/id").and_then(Value::as_u64);
    let (owner, name) = repo.split_once('/').unwrap_or(("", repo));
    let field = |f: &str| v.pointer(&format!("{obj}/{f}")).and_then(Value::as_str);
    let link = field("html_url")
        .filter(|l| l.starts_with("https://github.com/"))
        .map(str::to_string)
        .unwrap_or_else(|| {
            let n = v
                .pointer("/payload/number")
                .or_else(|| v.pointer("/payload/pull_request/number"))
                .and_then(Value::as_u64);
            match (act, n) {
                (Action::PullOpened, Some(n)) => format!("https://github.com/{repo}/pull/{n}"),
                _ => format!("https://github.com/{repo}"),
            }
        });
    // Gone from GitHub's trimmed payloads; read where an older event has it.
    let first_timer = field("author_association").map(|a| a == "FIRST_TIMER");
    let text = match act {
        Action::RepoCreated => field("description").unwrap_or("").to_string(),
        Action::Starred | Action::Forked => String::new(),
        Action::WikiEdited => v
            .pointer("/payload/pages")
            .and_then(Value::as_array)
            .map(|pages| {
                pages
                    .iter()
                    .flat_map(|p| {
                        [p.get("title"), p.get("summary")]
                            .into_iter()
                            .flatten()
                            .filter_map(Value::as_str)
                    })
                    .collect::<Vec<_>>()
                    .join("\n")
            })
            .unwrap_or_default(),
        _ => [field("title"), field("name"), field("body")]
            .into_iter()
            .flatten()
            .collect::<Vec<_>>()
            .join("\n"),
    };
    let name_template = match act {
        Action::RepoCreated => name_template(name, owner),
        Action::WikiEdited if field("action") == Some("created") => field("title")
            .or_else(|| field("page_name"))
            .and_then(|t| name_template(t, owner)),
        _ => None,
    };
    let e = PlatformEvent {
        id: format!("gh:{id}"),
        platform: Platform::Github,
        action: act,
        ts: s("/created_at").and_then(parse_date).unwrap_or(0),
        actor: actor_id
            .map(|i| i.to_string())
            .or_else(|| (!login.is_empty()).then(|| login.to_string()))
            .map(|a| actor_key(Platform::Github, &a))
            .unwrap_or_default(),
        actor_rank: actor_id.map(|i| i / RANK_UNIT),
        first_timer,
        target: repo.to_string(),
        link,
        name_template,
        text: None,
    }
    .with_text(&text, &[owner, name, login], rules);
    // A text action with no text, or a repository with neither a templated
    // name nor a description, gives the detector nothing to group; a
    // text-less star, fork or pull request still groups by its target.
    if e.text.is_none() && e.name_template.is_none() && !act.by_target() {
        return GhEvent::Skip;
    }
    GhEvent::Keep(Box::new(e))
}

/// Entries per Go module index request: the documented maximum.
const GO_PAGE: usize = 2000;
/// Go index requests one pull makes unless `scan` says otherwise.
const DEFAULT_GO_PAGES: usize = 6;
/// Without a checkpoint, or one older than [`MAX_BACKLOG_HOURS`], a Go
/// index pull starts this many hours back.
const GO_FRESH_HOURS: i64 = 6;

/// Read the Go module index from the checkpoint `mark` (Unix ms of the
/// last entry read), up to `scan` pages and `max` events.
fn pull_golang(
    client: &Client,
    q: &CdxQuery,
    mark: Option<u64>,
    max: usize,
) -> Result<PlatformPull> {
    let now_ms = crate::client::now_secs() * 1000;
    let fresh = now_ms - GO_FRESH_HOURS * 3_600_000;
    let (mut since, skipped) = match mark.map(|m| m as i64) {
        Some(m) if m >= now_ms - MAX_BACKLOG_HOURS * 3_600_000 => (m, 0),
        Some(m) => (fresh, ((fresh - m).max(0) / 3_600_000) as u64),
        None => (fresh, 0),
    };
    let start = since;
    let pages = q.scan.unwrap_or(DEFAULT_GO_PAGES).clamp(1, 50);
    let mut out = PlatformPull::default();
    let mut entries = 0usize;
    let mut done = false;
    for _ in 0..pages {
        let at = chrono::DateTime::from_timestamp_millis(since)
            .unwrap_or_default()
            .format("%Y-%m-%dT%H:%M:%S%.3fZ");
        let body = client.get(&format!(
            "https://index.golang.org/index?since={at}&limit={GO_PAGE}"
        ))?;
        let (events, n, last) = go_events(&body);
        entries += n;
        out.events.extend(events);
        match last {
            Some(t) if t > since => since = t,
            // The same instant again: step past it rather than loop.
            Some(_) => since += 1,
            None => {}
        }
        if n < GO_PAGE || out.events.len() >= max {
            done = n < GO_PAGE;
            break;
        }
    }
    out.events.truncate(max);
    // Coverage in hours of index time read against hours since the checkpoint.
    let hours = |a: i64, b: i64| ((b - a).max(0) / 3_600_000) as u64;
    out.coverage = Coverage {
        unit: "hours",
        read: if done {
            hours(start, now_ms)
        } else {
            hours(start, since)
        },
        available: hours(start, now_ms) + skipped,
        skipped,
        next: Some(since as u64),
        canary: Some(entries > 0),
    };
    Ok(out)
}

/// Platform events from a Go module index response (NDJSON of `Path`,
/// `Version`, `Timestamp`), the entries it held, and the newest entry's time
/// (Unix ms). The module path's owner (`github.com/<owner>/...`) stands for
/// the account, as a keyed hash.
pub fn go_events(body: &str) -> (Vec<PlatformEvent>, usize, Option<i64>) {
    let mut out = Vec::new();
    let (mut n, mut last) = (0, None);
    for line in body.lines().filter(|l| !l.trim().is_empty()) {
        let Ok(v) = serde_json::from_str::<Value>(line) else {
            continue;
        };
        let s = |k: &str| v.get(k).and_then(Value::as_str);
        let (Some(path), Some(version), Some(ts)) = (s("Path"), s("Version"), s("Timestamp"))
        else {
            continue;
        };
        n += 1;
        let ms = chrono::DateTime::parse_from_rfc3339(ts)
            .ok()
            .map(|d| d.timestamp_millis());
        if let Some(ms) = ms {
            last = Some(last.map_or(ms, |l: i64| l.max(ms)));
        }
        let parts: Vec<&str> = path.split('/').collect();
        let owner = parts.get(1).copied().unwrap_or("");
        // `example.com/owner/name/v2`: the name is before the major version.
        let name = parts
            .iter()
            .rev()
            .find(|p| {
                !(p.len() >= 2 && p.starts_with('v') && p[1..].chars().all(|c| c.is_ascii_digit()))
            })
            .copied()
            .unwrap_or(path);
        if is_automation(owner) {
            continue;
        }
        out.push(PlatformEvent {
            id: format!("go:{path}@{version}"),
            platform: Platform::Go,
            action: Action::PackagePublished,
            ts: ms.map_or(0, |m| m / 1000),
            actor: if owner.is_empty() || parts.len() < 3 {
                String::new()
            } else {
                actor_key(Platform::Go, &format!("{}/{owner}", parts[0]))
            },
            target: path.to_string(),
            link: format!("https://pkg.go.dev/{path}@{version}"),
            name_template: name_template(name, owner),
            ..Default::default()
        });
    }
    (out, n, last)
}

/// Platform events from an npm search response, and the objects it held.
/// The publisher's username becomes a keyed hash; maintainer lists and email
/// addresses are not read.
pub fn npm_events(body: &str, rules: &Rules) -> Result<(Vec<PlatformEvent>, usize)> {
    let v: Value = serde_json::from_str(body).context("npm search: not JSON")?;
    let objs = v
        .get("objects")
        .and_then(Value::as_array)
        .context("npm search: no `objects` array")?;
    let mut out = Vec::new();
    for o in objs {
        let s = |p: &str| o.pointer(p).and_then(Value::as_str);
        let (Some(name), Some(version)) = (s("/package/name"), s("/package/version")) else {
            continue;
        };
        let publisher = s("/package/publisher/username").unwrap_or("");
        if is_automation(publisher) {
            out.push(PlatformEvent::default());
            continue;
        }
        let keywords: Vec<&str> = o
            .pointer("/package/keywords")
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(Value::as_str).collect())
            .unwrap_or_default();
        let text = format!(
            "{}\n{}",
            s("/package/description").unwrap_or(""),
            keywords.join(" ")
        );
        let bare = name.rsplit('/').next().unwrap_or(name);
        let owner = if publisher.is_empty() {
            name.split_once('/').map_or("", |(o, _)| o)
        } else {
            publisher
        };
        out.push(
            PlatformEvent {
                id: format!("npm:{name}@{version}"),
                platform: Platform::Npm,
                action: Action::PackagePublished,
                ts: s("/package/date").and_then(parse_date).unwrap_or(0),
                actor: if publisher.is_empty() {
                    String::new()
                } else {
                    actor_key(Platform::Npm, publisher)
                },
                target: name.to_string(),
                link: format!("https://www.npmjs.com/package/{name}/v/{version}"),
                name_template: name_template(bare, owner),
                ..Default::default()
            }
            .with_text(&text, &[bare, owner], rules),
        );
    }
    Ok((out, objs.len()))
}

/// Platform events from a PyPI RSS feed, items matching `needles` (`*`
/// keeps all). The feeds name no uploader, so the events carry no account.
pub fn pypi_events(body: &str, needles: &Needles, rules: &Rules) -> Vec<PlatformEvent> {
    let mut out = Vec::new();
    for o in crate::pypi::parse_pypi_rss(body, needles) {
        let Some(rest) = o.id.strip_prefix("pypi:") else {
            continue;
        };
        let name = rest.split('@').next().unwrap_or(rest);
        let summary = rss_summary(body, &o.url).unwrap_or_default();
        out.push(
            PlatformEvent {
                id: o.id.clone(),
                platform: Platform::Pypi,
                action: Action::PackagePublished,
                ts: o.ts,
                target: name.to_string(),
                link: o.url.clone(),
                name_template: name_template(name, ""),
                ..Default::default()
            }
            .with_text(&summary, &[name], rules),
        );
    }
    out
}

/// The `<description>` of the RSS item whose link is `link`.
fn rss_summary(body: &str, link: &str) -> Option<String> {
    let item = body
        .split("<item>")
        .skip(1)
        .find(|i| i.contains(&format!("<link>{link}</link>")))?;
    let a = item.find("<description>")? + "<description>".len();
    let b = a + item[a..].find("</description>")?;
    Some(
        item[a..b]
            .replace("&lt;", "<")
            .replace("&gt;", ">")
            .replace("&quot;", "\"")
            .replace("&#39;", "'")
            .replace("&amp;", "&"),
    )
}

/// Platform events from a Hub listing (`spaces`, `models` or `datasets`),
/// and the items it held. The owner is the id's first part, kept as a hash.
pub fn hf_events(body: &str, what: &str) -> Result<(Vec<PlatformEvent>, usize)> {
    let v: Value = serde_json::from_str(body).context("Hub listing: not JSON")?;
    let items = v.as_array().context("Hub listing: not an array")?;
    let (action, path) = match what {
        "models" => (Action::ModelCreated, ""),
        "datasets" => (Action::DatasetCreated, "datasets/"),
        _ => (Action::SpaceCreated, "spaces/"),
    };
    let mut out = Vec::new();
    for it in items {
        let Some(id) = it.get("id").and_then(Value::as_str) else {
            continue;
        };
        let Some((owner, name)) = id.split_once('/') else {
            continue;
        };
        if is_automation(owner) {
            out.push(PlatformEvent::default());
            continue;
        }
        out.push(PlatformEvent {
            id: format!("hf:{what}:{id}"),
            platform: Platform::HuggingFace,
            action,
            ts: it
                .get("createdAt")
                .and_then(Value::as_str)
                .and_then(parse_date)
                .unwrap_or(0),
            actor: actor_key(Platform::HuggingFace, owner),
            target: id.to_string(),
            link: format!("https://huggingface.co/{path}{id}"),
            name_template: name_template(name, owner),
            ..Default::default()
        });
    }
    Ok((out, items.len()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// GH Archive events in the trimmed shape GitHub's Events API serves:
    /// no author association, a pull request as its number and refs only, a
    /// push with no commits. Every account, repository and text is invented.
    const EVENTS: [&str; 16] = [
        r#"{"id":"101","type":"IssuesEvent","created_at":"2026-10-09T07:00:01Z","actor":{"id":250123456,"login":"newacct-1"},"repo":{"name":"libfoo/core"},"payload":{"action":"opened","issue":{"html_url":"https://github.com/libfoo/core/issues/9","title":"Critical vulnerability","body":"Certainly! Here's the report for libfoo. See https://evil.example/x and contact me@mail.example."}}}"#,
        r#"{"id":"102","type":"IssueCommentEvent","created_at":"2026-10-09T07:00:02Z","actor":{"id":5,"login":"dependabot[bot]"},"repo":{"name":"a/b"},"payload":{"action":"created","comment":{"html_url":"https://github.com/a/b/issues/1#c","body":"Bumps x from 1 to 2"}}}"#,
        r#"{"id":"103","type":"PushEvent","created_at":"2026-10-09T07:00:03Z","actor":{"id":6,"login":"someone"},"repo":{"name":"a/b"},"payload":{"repository_id":1,"push_id":2,"ref":"refs/heads/main","head":"aa","before":"bb"}}"#,
        r#"{"id":"104","type":"PullRequestEvent","created_at":"2026-10-09T07:00:04Z","actor":{"id":7,"login":"dev"},"repo":{"name":"a/b"},"payload":{"action":"opened","number":12,"pull_request":{"url":"https://api.github.com/repos/a/b/pulls/12","id":9,"number":12,"head":{"ref":"fix"},"base":{"ref":"main"}}}}"#,
        r#"{"id":"105","type":"CreateEvent","created_at":"2026-10-09T07:00:05Z","actor":{"id":250123999,"login":"newacct-2"},"repo":{"name":"newacct-2/agent-probe-0042"},"payload":{"ref_type":"repository"}}"#,
        r#"{"id":"106","type":"CreateEvent","created_at":"2026-10-09T07:00:06Z","actor":{"id":8,"login":"person"},"repo":{"name":"person/portfolio"},"payload":{"ref_type":"repository"}}"#,
        r#"{"id":"107","type":"WatchEvent","created_at":"2026-10-09T07:00:07Z","actor":{"id":250124001,"login":"newacct-3"},"repo":{"name":"fresh/tool"},"payload":{"action":"started"}}"#,
        r#"{"id":"108","type":"ForkEvent","created_at":"2026-10-09T07:00:08Z","actor":{"id":250124002,"login":"newacct-4"},"repo":{"name":"fresh/tool"},"payload":{"action":"forked","forkee":{"html_url":"https://github.com/newacct-4/tool","full_name":"newacct-4/tool"}}}"#,
        r#"{"id":"109","type":"ReleaseEvent","created_at":"2026-10-09T07:00:09Z","actor":{"id":9,"login":"maint"},"repo":{"name":"c/d"},"payload":{"action":"published","release":{"html_url":"https://github.com/c/d/releases/tag/v1","name":"v1.0.0","body":"First stable release with the new plugin loader and faster startup on large projects."}}}"#,
        r#"{"id":"110","type":"DiscussionEvent","created_at":"2026-10-09T07:00:10Z","actor":{"id":10,"login":"asker"},"repo":{"name":"c/d"},"payload":{"action":"created","discussion":{"html_url":"https://github.com/c/d/discussions/3","title":"How do I configure the cache directory?","body":"The docs mention a flag that no longer exists in the current release."}}}"#,
        r#"{"id":"111","type":"CommitCommentEvent","created_at":"2026-10-09T07:00:11Z","actor":{"id":11,"login":"reviewer"},"repo":{"name":"c/d"},"payload":{"action":"created","comment":{"html_url":"https://github.com/c/d/commit/abc#commitcomment-1","body":"This change breaks the Windows build.\n\nGenerated with [Claude Code](https://claude.com/claude-code)"}}}"#,
        r#"{"id":"112","type":"GollumEvent","created_at":"2026-10-09T07:00:12Z","actor":{"id":250124003,"login":"newacct-5"},"repo":{"name":"e/f"},"payload":{"pages":[{"page_name":"probe-page-0042","title":"probe-page-0042","summary":null,"action":"created","html_url":"https://github.com/e/f/wiki/probe-page-0042"}]}}"#,
        r#"{"id":"113","type":"PullRequestReviewEvent","created_at":"2026-10-09T07:00:13Z","actor":{"id":175728472,"login":"Copilot"},"repo":{"name":"c/d"},"payload":{"action":"created","review":{"html_url":"https://github.com/c/d/pull/4#pullrequestreview-1","body":"Copilot reviewed 3 out of 3 changed files in this pull request and generated 2 comments."}}}"#,
        r#"{"id":"114","type":"IssueCommentEvent","created_at":"2026-10-09T07:00:14Z","actor":{"id":12,"login":"claude-fleet[bot]"},"repo":{"name":"c/d"},"payload":{"action":"created","comment":{"html_url":"https://github.com/c/d/issues/5#c","body":"Automated report from the fleet, please review the attached findings."}}}"#,
        // The shape before GitHub trimmed the payloads: title, body and
        // author association on the pull request.
        r#"{"id":"115","type":"PullRequestEvent","created_at":"2026-10-09T07:00:15Z","actor":{"id":250124004,"login":"newacct-6"},"repo":{"name":"a/b"},"payload":{"action":"opened","number":13,"pull_request":{"html_url":"https://github.com/a/b/pull/13","title":"Fix the parser for nested quotes in the config loader","body":"Handles escaped quotes inside nested sections.","author_association":"FIRST_TIMER"}}}"#,
        "not json",
    ];

    #[test]
    fn keeps_what_grouping_needs_and_no_more() {
        let rules = Rules::default_rules();
        let t = gharchive_events(EVENTS.join("\n").as_bytes(), &rules, 100).unwrap();
        assert_eq!((t.parsed, t.automation), (15, 1));
        let ids: Vec<&str> = t.events.iter().map(|e| e.id.as_str()).collect();
        assert_eq!(
            ids,
            [
                "gh:101", "gh:104", "gh:105", "gh:107", "gh:108", "gh:109", "gh:110", "gh:111",
                "gh:112", "gh:115"
            ]
        );
        let by = |id: &str| t.events.iter().find(|e| e.id == id).unwrap();
        let e = by("gh:101");
        assert_eq!(e.action, Action::IssueOpened);
        assert_eq!(e.actor_rank, Some(250_123));
        assert_eq!(e.first_timer, None);
        assert_eq!(e.link, "https://github.com/libfoo/core/issues/9");
        let json = serde_json::to_string(e).unwrap();
        for leak in ["newacct-1", "evil.example", "mail.example", "250123456"] {
            assert!(!json.contains(leak), "{leak} leaked: {json}");
        }
        assert!(
            e.text
                .as_ref()
                .unwrap()
                .residue
                .contains(&"text.chat_opener".to_string())
        );
        // A trimmed pull request: text-less, kept for its target, linked by number.
        let pr = by("gh:104");
        assert_eq!(pr.action, Action::PullOpened);
        assert!(pr.text.is_none());
        assert_eq!(pr.target, "a/b");
        assert_eq!(pr.link, "https://github.com/a/b/pull/12");
        // The legacy shape still gives its text and first-timer flag.
        let legacy = by("gh:115");
        assert!(legacy.text.is_some());
        assert_eq!(legacy.first_timer, Some(true));
        assert_eq!(
            by("gh:105").name_template.as_deref(),
            Some("agent-probe-<num>")
        );
        assert_eq!(by("gh:107").action, Action::Starred);
        assert_eq!(by("gh:107").target, "fresh/tool");
        assert_eq!(by("gh:108").action, Action::Forked);
        assert_eq!(by("gh:108").target, "fresh/tool");
        assert_eq!(by("gh:109").action, Action::ReleasePublished);
        assert_eq!(by("gh:110").action, Action::DiscussionOpened);
        let cc = by("gh:111");
        assert_eq!(cc.action, Action::CommitComment);
        assert_eq!(cc.text.as_ref().unwrap().self_id, ["selfid.claude_code"]);
        let wiki = by("gh:112");
        assert_eq!(wiki.action, Action::WikiEdited);
        assert_eq!(wiki.name_template.as_deref(), Some("probe-page-<num>"));
        assert_eq!(wiki.link, "https://github.com/e/f/wiki/probe-page-0042");
        // Declared coding agents are tallied by product, lookalikes by login.
        assert_eq!(
            t.declared
                .get("Copilot cloud agent and code review (GitHub)"),
            Some(&1)
        );
        let (claim, n) = &t.lookalikes["claude-fleet[bot]"];
        assert!(claim.contains("Anthropic"), "{claim}");
        assert_eq!(*n, 1);
        let capped = gharchive_events(EVENTS.join("\n").as_bytes(), &rules, 1).unwrap();
        assert_eq!((capped.events.len(), capped.capped), (1, 9));
    }

    #[test]
    fn a_cut_off_hour_keeps_what_parsed() {
        let rules = Rules::default_rules();
        let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        for i in 0..3000 {
            std::io::Write::write_all(
                &mut e,
                format!("{}\n", EVENTS[4].replace("\"105\"", &format!("\"{i}\""))).as_bytes(),
            )
            .unwrap();
        }
        let data = e.finish().unwrap();
        let cut = &data[..data.len() / 2];
        let (t, err) = read_gharchive(flate2::read::MultiGzDecoder::new(cut), &rules, usize::MAX);
        assert!(err.is_some());
        assert!(t.parsed > 0 && t.events.len() == t.parsed, "{}", t.parsed);
        assert!(gharchive_events(flate2::read::MultiGzDecoder::new(cut), &rules, 10).is_err());
    }

    #[test]
    fn npm_pypi_and_hub_listings() {
        let rules = Rules::default_rules();
        let npm = r#"{"objects":[
          {"package":{"name":"agent-probe-0007","version":"0.0.1","date":"2026-10-06T20:51:22.967Z","description":"Probe package for reach testing","keywords":["probe"],"publisher":{"username":"pub-1","email":"pub@example.org"}}},
          {"package":{"name":"@scope/x","version":"1.0.0","publisher":{"username":"renovate-bot"}}}
        ],"total":2}"#;
        let (v, n) = npm_events(npm, &rules).unwrap();
        assert_eq!((v.len(), n), (2, 2));
        let p = feed_pull(v, n, "packages");
        assert_eq!((p.events.len(), p.automation), (1, 1));
        let e = &p.events[0];
        assert_eq!(e.name_template.as_deref(), Some("agent-probe-<num>"));
        assert!(e.actor.starts_with("acct:"));
        assert!(!serde_json::to_string(e).unwrap().contains("example.org"));

        let rss = "<item><title>agent-probe-0009 0.0.1</title><link>https://pypi.org/project/agent-probe-0009/0.0.1/</link><description>Probe &amp; reach</description><pubDate>Sat, 10 Oct 2026 19:57:54 GMT</pubDate></item>";
        let v = pypi_events(rss, &Needles::new("*"), &rules);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].id, "pypi:agent-probe-0009@0.0.1");
        assert!(v[0].actor.is_empty());
        assert_eq!(v[0].text.as_ref().unwrap().excerpt, "probe reach");

        let hub = r#"[{"_id":"x","id":"someone/demo-space-17","createdAt":"2026-10-10T10:00:00.000Z","likes":0},{"id":"no-slash"}]"#;
        let (v, n) = hf_events(hub, "spaces").unwrap();
        assert_eq!((v.len(), n), (1, 2));
        assert_eq!(
            v[0].link,
            "https://huggingface.co/spaces/someone/demo-space-17"
        );
        assert_eq!(v[0].name_template.as_deref(), Some("demo-space-<num>"));
        assert!(hf_events("{}", "spaces").is_err());

        let go = concat!(
            r#"{"Path":"github.com/probe-owner/agent-probe-0042","Version":"v0.0.1","Timestamp":"2026-10-10T10:00:00.123456Z"}"#,
            "\n",
            r#"{"Path":"github.com/probe-owner/agent-probe-0043/v2","Version":"v2.0.0","Timestamp":"2026-10-10T10:00:01Z"}"#,
            "\n",
            r#"{"Path":"golang.org/x/text","Version":"v0.30.0","Timestamp":"2026-10-10T10:00:02Z"}"#,
            "\nnot json\n"
        );
        let (v, n, last) = go_events(go);
        assert_eq!((v.len(), n), (3, 3));
        assert_eq!(v[0].id, "go:github.com/probe-owner/agent-probe-0042@v0.0.1");
        assert_eq!(v[0].name_template.as_deref(), Some("agent-probe-<num>"));
        assert_eq!(v[1].name_template.as_deref(), Some("agent-probe-<num>"));
        assert_eq!(v[0].actor, v[1].actor);
        assert!(v[0].actor.starts_with("acct:"));
        assert!(
            !serde_json::to_string(&v[0])
                .unwrap()
                .contains("\"actor\":\"probe-owner")
        );
        assert_eq!(v[2].name_template, None);
        assert_eq!(
            last,
            crate::parse_date("2026-10-10T10:00:02Z").map(|t| t * 1000)
        );
    }
}
