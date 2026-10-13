//! Platform events for the coordinated-account detector
//! (`sc_core::platform`): GitHub events from GH Archive, npm search results,
//! PyPI's feeds and the Hugging Face Hub's newest Spaces, models and
//! datasets. Metadata and event text only: repositories, packages, Spaces
//! and every URL inside the text are never fetched.
//!
//! What is kept is what grouping needs, reduced at parse time: logins become
//! a keyed hash ([`sc_core::platform::actor_key`]), a GitHub account id a
//! coarse rank, and text a sketch with URLs, addresses, mentions, numbers
//! and identifiers as slots. Automation accounts are dropped by login before
//! anything is kept ([`sc_core::platform::automation`]).
//!
//! Terms: GH Archive, npm and PyPI as in their record collectors. The
//! Hugging Face Hub API (<https://huggingface.co/docs/hub/api>) is public and
//! documented; its rate limits (<https://huggingface.co/docs/hub/rate-limits>)
//! allow anonymous callers hundreds of API requests per five minutes, and
//! its content policy (<https://huggingface.co/content-policy>) forbids
//! excessive bulk activity and publishing others' private information. One
//! listing request per Hub source per run, keeping ids, owners and times,
//! stays well inside that; a Space's page and app are never opened.

use crate::gharchive::{LAG_HOURS, MAX_FILE, MAX_LINE, hour_name};
use crate::pager::Coverage;
use crate::{CdxQuery, Client, Needles, parse_date};
use anyhow::{Context, Result, bail};
use sc_core::Rules;
use sc_core::platform::automation::is_automation;
use sc_core::platform::{Action, Platform, PlatformEvent, RANK_UNIT, actor_key, name_template};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::io::{BufRead, BufReader, Read};

/// Events one GH Archive pull keeps at most, so memory stays bounded.
const DEFAULT_MAX_EVENTS: usize = 500_000;
/// Hours one GH Archive pull reads unless `scan` says otherwise.
const DEFAULT_HOURS: usize = 1;
/// A checkpoint further back than this is skipped to the newest hours.
const MAX_BACKLOG_HOURS: i64 = 24;

/// A platform source in the watchlist (`[[platform.source]]`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlatformSource {
    pub name: String,
    /// `gharchive`, `npm`, `pypi` or `huggingface`.
    pub kind: String,
    /// Events one pull keeps at most.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_events: Option<usize>,
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
        k => bail!(
            "unknown platform source kind `{k}` (expected gharchive, npm, pypi or huggingface)"
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
        capped: 0,
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
    let budget = q.max_mb.unwrap_or(512).max(1) << 20;
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
                let t = gharchive_events(&mut gz, rules, room)
                    .with_context(|| format!("reading {url}"))?;
                bytes += gz.get_ref().n;
                out.events.extend(t.events);
                out.automation += t.automation;
                out.capped += t.capped;
                out.coverage.read += 1;
                out.coverage.canary = Some(out.coverage.canary.unwrap_or(true) && t.parsed > 0);
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
}

/// Read GH Archive NDJSON from `r` and keep the events the detector reads:
/// issues and pull requests opened, issue and review comments, and
/// repositories created; at most `max`. Overlong lines are skipped.
pub fn gharchive_events(r: impl Read, rules: &Rules, max: usize) -> Result<GhTally> {
    let mut r = BufReader::new(r);
    let mut buf = Vec::new();
    let mut out = GhTally::default();
    loop {
        buf.clear();
        let n = (&mut r).take(MAX_LINE as u64).read_until(b'\n', &mut buf)?;
        if n == 0 {
            break;
        }
        if !buf.ends_with(b"\n") && n == MAX_LINE {
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
        let Ok(v) = serde_json::from_slice::<Value>(&buf) else {
            continue;
        };
        if v.pointer("/repo/name").is_none() {
            continue;
        }
        out.parsed += 1;
        match gh_event(&v, rules) {
            GhEvent::Keep(e) if out.events.len() < max => out.events.push(*e),
            GhEvent::Keep(_) => out.capped += 1,
            GhEvent::Automation => out.automation += 1,
            GhEvent::Skip => {}
        }
    }
    Ok(out)
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
    Skip,
}

fn gh_event(v: &Value, rules: &Rules) -> GhEvent {
    let s = |p: &str| v.pointer(p).and_then(Value::as_str);
    let (Some(kind), Some(repo), Some(id)) = (s("/type"), s("/repo/name"), s("/id")) else {
        return GhEvent::Skip;
    };
    let action = s("/payload/action").unwrap_or("");
    // (action, object holding the text and link, title pointer)
    let (act, obj) = match (kind, action) {
        ("IssuesEvent", "opened") => (Action::IssueOpened, "/payload/issue"),
        ("PullRequestEvent", "opened") => (Action::PullOpened, "/payload/pull_request"),
        ("IssueCommentEvent", "created") => (Action::Comment, "/payload/comment"),
        ("PullRequestReviewCommentEvent", "created") => (Action::ReviewComment, "/payload/comment"),
        ("PullRequestReviewEvent", _) => (Action::ReviewComment, "/payload/review"),
        ("CreateEvent", _) if s("/payload/ref_type") == Some("repository") => {
            (Action::RepoCreated, "/payload")
        }
        _ => return GhEvent::Skip,
    };
    let login = s("/actor/login").unwrap_or("");
    if is_automation(login) {
        return GhEvent::Automation;
    }
    let actor_id = v.pointer("/actor/id").and_then(Value::as_u64);
    let (owner, name) = repo.split_once('/').unwrap_or(("", repo));
    let field = |f: &str| v.pointer(&format!("{obj}/{f}")).and_then(Value::as_str);
    let link = field("html_url")
        .filter(|l| l.starts_with("https://github.com/"))
        .map(str::to_string)
        .unwrap_or_else(|| match (act, v.pointer("/payload/number")) {
            (Action::PullOpened, Some(n)) => format!("https://github.com/{repo}/pull/{n}"),
            _ => format!("https://github.com/{repo}"),
        });
    let first_timer = field("author_association").map(|a| a == "FIRST_TIMER");
    let text = match act {
        Action::RepoCreated => field("description").unwrap_or("").to_string(),
        _ => [field("title"), field("body")]
            .into_iter()
            .flatten()
            .collect::<Vec<_>>()
            .join("\n"),
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
        name_template: (act == Action::RepoCreated)
            .then(|| name_template(name, owner))
            .flatten(),
        text: None,
    }
    .with_text(&text, &[owner, name, login], rules);
    // A text action with no text, or a repository with neither a templated
    // name nor a description, gives the detector nothing to group.
    if e.text.is_none() && e.name_template.is_none() {
        return GhEvent::Skip;
    }
    GhEvent::Keep(Box::new(e))
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

    const EVENTS: [&str; 7] = [
        r#"{"id":"101","type":"IssuesEvent","created_at":"2026-10-09T07:00:01Z","actor":{"id":250123456,"login":"newacct-1"},"repo":{"name":"libfoo/core"},"payload":{"action":"opened","issue":{"html_url":"https://github.com/libfoo/core/issues/9","title":"Critical vulnerability","body":"Certainly! Here's the report for libfoo. See https://evil.example/x and contact me@mail.example.","author_association":"FIRST_TIMER"}}}"#,
        r#"{"id":"102","type":"IssueCommentEvent","created_at":"2026-10-09T07:00:02Z","actor":{"id":5,"login":"dependabot[bot]"},"repo":{"name":"a/b"},"payload":{"action":"created","comment":{"html_url":"https://github.com/a/b/issues/1#c","body":"Bumps x from 1 to 2"}}}"#,
        r#"{"id":"103","type":"PushEvent","created_at":"2026-10-09T07:00:03Z","actor":{"id":6,"login":"someone"},"repo":{"name":"a/b"},"payload":{}}"#,
        r#"{"id":"104","type":"PullRequestEvent","created_at":"2026-10-09T07:00:04Z","actor":{"id":7,"login":"dev"},"repo":{"name":"a/b"},"payload":{"action":"opened","number":12,"pull_request":{"title":"Fix the parser for nested quotes in the config loader"}}}"#,
        r#"{"id":"105","type":"CreateEvent","created_at":"2026-10-09T07:00:05Z","actor":{"id":250123999,"login":"newacct-2"},"repo":{"name":"newacct-2/agent-probe-0042"},"payload":{"ref_type":"repository"}}"#,
        r#"{"id":"106","type":"CreateEvent","created_at":"2026-10-09T07:00:06Z","actor":{"id":8,"login":"person"},"repo":{"name":"person/portfolio"},"payload":{"ref_type":"repository"}}"#,
        "not json",
    ];

    #[test]
    fn keeps_what_grouping_needs_and_no_more() {
        let rules = Rules::default_rules();
        let t = gharchive_events(EVENTS.join("\n").as_bytes(), &rules, 100).unwrap();
        assert_eq!((t.parsed, t.automation), (6, 1));
        let ids: Vec<&str> = t.events.iter().map(|e| e.id.as_str()).collect();
        assert_eq!(ids, ["gh:101", "gh:104", "gh:105"]);
        let e = &t.events[0];
        assert_eq!(e.action, Action::IssueOpened);
        assert_eq!(e.actor_rank, Some(250_123));
        assert_eq!(e.first_timer, Some(true));
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
        assert_eq!(t.events[1].link, "https://github.com/a/b/pull/12");
        assert_eq!(
            t.events[2].name_template.as_deref(),
            Some("agent-probe-<num>")
        );
        let capped = gharchive_events(EVENTS.join("\n").as_bytes(), &rules, 1).unwrap();
        assert_eq!((capped.events.len(), capped.capped), (1, 2));
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
    }
}
