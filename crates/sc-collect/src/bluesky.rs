//! Bluesky posts (`bluesky`), from Jetstream, the JSON relay of the AT
//! Protocol firehose that Bluesky runs
//! (`wss://jetstream<n>.<region>.bsky.network/subscribe`). A pull asks for
//! `app.bsky.feed.post` records only, from a cursor, over one WebSocket
//! connection. Two passes read it, each from its own checkpoint:
//!
//! - the record pass ([`BskyLinks`]): one record per link a post carries
//!   (its link facets and its link card) that matches the query's
//!   substrings, and one per post whose text matches with no link that
//!   does. The record's URL is the link, never fetched; its reference is
//!   the post's page on `bsky.app`.
//! - the platform pass ([`pull_platform`]): one [`PlatformEvent`] per post
//!   created: the account's DID as a keyed hash, the text as a sketch, and
//!   as the target the thread's root post for a reply, else the host of a
//!   link card.
//!
//! Coverage: the stream carries tens of posts a second, too many to read
//! six hours of each run. A pull reads a sample: from its checkpoint, or
//! [`SAMPLE_MINUTES`] before its own start when the checkpoint is older,
//! until it catches up with its own start or runs out of `scan`
//! wall-clock minutes, `max_mb` megabytes or `max_events` posts. The
//! stretch between an old checkpoint and the sample is counted as skipped,
//! in minutes of stream time. Posts parsed are the canary.
//!
//! Coverage is the same sampled stretch for both passes, so the record
//! pass sees the links posted in that stretch only, not every link posted
//! since the last run.
//!
//! Deletions: a post deleted while the pull reads is dropped from what it
//! keeps, events and records alike. The platform pass keeps sketches, never
//! the text, and carries only events worth another look, for the watch's
//! `carry_hours`. The record pass keeps the matching link and the post's
//! public page, never the text.
//!
//! Account age: the PLC directory (`plc.directory/<did>/log/audit`) gives
//! a `did:plc` account's first operation, its creation. A pull looks up at
//! most `max_lookups` accounts, only those whose text shares a template or
//! near-duplicate band with another account's or carries residue
//! ([`crate::hackernews::lookup_candidates`]). The time becomes a rank in
//! units of 864 seconds, a thousand ranks to ten days, as on a wiki.
//!
//! Terms: Jetstream is a public service Bluesky runs for consuming the
//! network's public repository events
//! (<https://github.com/bluesky-social/jetstream>), documented with no
//! authentication or published rate limit; one connection a run, read
//! for a bounded time, is ordinary use. The PLC directory
//! (<https://web.plc.directory/>) is the public registry of `did:plc`
//! identities; its audit log is public. Bluesky's developer guidelines
//! (<https://docs.bsky.app/docs/support/developer-guidelines>) ask
//! developers to respect deletions and users' privacy: the platform pass
//! keeps no text, no handle and no DID, only keyed hashes and sketches,
//! carried briefly; a record keeps a matching link and the post's public
//! page, as a Hacker News record keeps the item's page.

use crate::hackernews::{RANK_SECS, lookup_candidates};
use crate::pager::{Coverage, Cursor, Page};
use crate::platform::PlatformPull;
use crate::{CdxQuery, Client, Kind, Needles, Source, short_hash};
use anyhow::{Context, Result, bail};
use sc_core::platform::{Action, Platform, PlatformEvent, actor_key};
use sc_core::{Observation, Rules, TsKind, redact_observation};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant};

/// The Jetstream instance unless `endpoint` names another.
pub const DEFAULT_INSTANCE: &str = "jetstream2.us-east.bsky.network";
const PLC: &str = "https://plc.directory/";
/// Stream minutes a pull reads back from its own start when its
/// checkpoint is older than that.
pub const SAMPLE_MINUTES: i64 = 30;
/// Wall-clock minutes one pull reads unless `scan` says otherwise.
const DEFAULT_MINUTES: usize = 3;
/// Megabytes one pull reads unless `max_mb` says otherwise.
const DEFAULT_MAX_MB: u64 = 256;
/// Profile lookups unless `max_lookups` says otherwise.
pub const DEFAULT_LOOKUPS: usize = 40;
/// Longest message kept.
const MAX_MESSAGE: usize = 1 << 20;

/// A post as a platform event; `None` for anything but a post created.
pub fn post_event(v: &Value, rules: &Rules) -> Option<PlatformEvent> {
    let s = |p: &str| v.pointer(p).and_then(Value::as_str);
    if s("/kind") != Some("commit")
        || s("/commit/operation") != Some("create")
        || s("/commit/collection") != Some("app.bsky.feed.post")
    {
        return None;
    }
    let did = s("/did")?;
    let rkey = s("/commit/rkey")?;
    let us = v.get("time_us").and_then(Value::as_i64)?;
    let text = s("/commit/record/text").unwrap_or("");
    let link_host = s("/commit/record/embed/external/uri")
        .and_then(|u| url::Url::parse(u).ok())
        .and_then(|u| {
            u.host_str()
                .map(|h| h.trim_start_matches("www.").to_string())
        });
    let target = s("/commit/record/reply/root/uri")
        .and_then(root_target)
        .or(link_host)
        .unwrap_or_else(|| format!("post:{rkey}"));
    let e = PlatformEvent {
        id: post_id(did, rkey),
        platform: Platform::Bluesky,
        action: if v.pointer("/commit/record/reply").is_some() {
            Action::Comment
        } else {
            Action::StoryPosted
        },
        ts: us / 1_000_000,
        actor: actor_key(Platform::Bluesky, did),
        target,
        link: format!("https://bsky.app/profile/{did}/post/{rkey}"),
        ..Default::default()
    }
    .with_text(text, &[], rules);
    e.text.is_some().then_some(e)
}

/// A post's event id: the account's keyed hash and the record key, so the
/// id does not carry the DID.
fn post_id(did: &str, rkey: &str) -> String {
    let key = actor_key(Platform::Bluesky, did);
    format!("bsky:{}/{rkey}", key.trim_start_matches("acct:"))
}

/// The links a post carries: its link facets' URIs and its link card's,
/// in that order, without repeats.
pub fn post_links(v: &Value) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut push = |u: &str| {
        if (u.starts_with("http://") || u.starts_with("https://")) && !out.iter().any(|x| x == u) {
            out.push(u.to_string());
        }
    };
    let facets = v
        .pointer("/commit/record/facets")
        .and_then(Value::as_array)
        .into_iter()
        .flatten();
    for f in facets {
        let features = f
            .get("features")
            .and_then(Value::as_array)
            .into_iter()
            .flatten();
        for feat in features {
            if feat.get("$type").and_then(Value::as_str) == Some("app.bsky.richtext.facet#link")
                && let Some(u) = feat.get("uri").and_then(Value::as_str)
            {
                push(u);
            }
        }
    }
    for p in [
        "/commit/record/embed/external/uri",
        "/commit/record/embed/media/external/uri",
    ] {
        if let Some(u) = v.pointer(p).and_then(Value::as_str) {
            push(u);
        }
    }
    out
}

/// Records from one post created: each link that matches `needles`, and
/// the post's page when only its text does. Redacted. Empty for anything
/// but a post created.
pub fn post_records(v: &Value, needles: &Needles) -> Vec<Observation> {
    let s = |p: &str| v.pointer(p).and_then(Value::as_str);
    if s("/kind") != Some("commit")
        || s("/commit/operation") != Some("create")
        || s("/commit/collection") != Some("app.bsky.feed.post")
    {
        return Vec::new();
    }
    let (Some(did), Some(rkey), Some(us)) = (
        s("/did"),
        s("/commit/rkey"),
        v.get("time_us").and_then(Value::as_i64),
    ) else {
        return Vec::new();
    };
    let page = format!("https://bsky.app/profile/{did}/post/{rkey}");
    let mut urls: Vec<String> = post_links(v)
        .into_iter()
        .filter(|u| needles.matches(u))
        .collect();
    if urls.is_empty() && needles.matches(s("/commit/record/text").unwrap_or("")) {
        urls.push(page.clone());
    }
    let key = record_key(did, rkey);
    urls.into_iter()
        .map(|url| {
            let mut o = Observation {
                id: format!("{key}:{}", short_hash(&url)),
                source: "bluesky".into(),
                ts: us / 1_000_000,
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

/// The prefix of a post's record ids, `bluesky:<account hash>/<rkey>`, so
/// the id does not carry the DID.
fn record_key(did: &str, rkey: &str) -> String {
    format!("bluesky{}", post_id(did, rkey).trim_start_matches("bsky"))
}

/// A thread's root as a target, `<did>/<rkey>`, from its
/// `at://<did>/app.bsky.feed.post/<rkey>` URI: the root's author is the
/// target's owner, as a repository's is on GitHub.
fn root_target(uri: &str) -> Option<String> {
    let rest = uri.strip_prefix("at://")?;
    let mut parts = rest.split('/');
    let (did, coll, rkey) = (parts.next()?, parts.next()?, parts.next()?);
    (coll == "app.bsky.feed.post").then(|| format!("{did}/{rkey}"))
}

/// The account and record key a post delete names.
fn deleted(v: &Value) -> Option<(&str, &str)> {
    let s = |p: &str| v.pointer(p).and_then(Value::as_str);
    (s("/kind") == Some("commit")
        && s("/commit/operation") == Some("delete")
        && s("/commit/collection") == Some("app.bsky.feed.post"))
    .then(|| Some((s("/did")?, s("/commit/rkey")?)))
    .flatten()
}

/// Where and how long one pull reads.
#[derive(Debug, Clone)]
pub struct Plan {
    /// Stream time (µs) to start at.
    pub start_us: i64,
    /// Stop at the first event at or after this (µs): the pull's own start.
    pub until_us: i64,
    pub deadline: Instant,
    pub max_bytes: u64,
    pub max_events: usize,
    /// Stream minutes passed over before the sample.
    pub skipped_minutes: u64,
}

impl Plan {
    pub fn new(q: &CdxQuery, checkpoint: Option<i64>, now_us: i64, max_events: usize) -> Self {
        let sample = now_us - SAMPLE_MINUTES * 60_000_000;
        let (start_us, skipped) = match checkpoint {
            Some(c) if c >= sample => (c, 0),
            Some(c) => (sample, ((sample - c).max(0) / 60_000_000) as u64),
            None => (sample, 0),
        };
        let minutes = q.scan.unwrap_or(DEFAULT_MINUTES).clamp(1, 30) as u64;
        Self {
            start_us,
            until_us: now_us,
            deadline: Instant::now() + Duration::from_secs(minutes * 60),
            max_bytes: q.max_mb.unwrap_or(DEFAULT_MAX_MB).max(1) << 20,
            max_events,
            skipped_minutes: skipped,
        }
    }
}

/// What a read keeps from each post.
#[derive(Clone, Copy)]
pub enum Keep<'a> {
    /// Platform events, sketched with these rules.
    Events(&'a Rules),
    /// Records of the links matching these substrings.
    Links(&'a Needles),
}

/// What a read kept.
#[derive(Debug, Default)]
pub struct Read {
    pub events: Vec<PlatformEvent>,
    pub records: Vec<Observation>,
    pub parsed: usize,
    pub bytes: u64,
    pub last_us: Option<i64>,
    pub deleted: usize,
    pub caught_up: bool,
}

impl Read {
    /// Take one message; false when the read should stop.
    pub fn take(&mut self, msg: &str, plan: &Plan, keep: Keep) -> bool {
        self.bytes += msg.len() as u64;
        let Ok(v) = serde_json::from_str::<Value>(msg) else {
            return true;
        };
        let Some(us) = v.get("time_us").and_then(Value::as_i64) else {
            return true;
        };
        if us >= plan.until_us {
            self.caught_up = true;
            return false;
        }
        self.parsed += 1;
        self.last_us = Some(self.last_us.map_or(us, |l| l.max(us)));
        if let Some((did, rkey)) = deleted(&v) {
            let id = post_id(did, rkey);
            let key = format!("{}:", record_key(did, rkey));
            let before = self.events.len() + self.records.len();
            self.events.retain(|e| e.id != id);
            self.records.retain(|o| !o.id.starts_with(&key));
            self.deleted += before - self.events.len() - self.records.len();
        } else {
            match keep {
                Keep::Events(rules) => self.events.extend(post_event(&v, rules)),
                Keep::Links(needles) => self.records.extend(post_records(&v, needles)),
            }
        }
        self.events.len() + self.records.len() < plan.max_events
            && self.bytes < plan.max_bytes
            && Instant::now() < plan.deadline
    }

    pub fn coverage(&self, plan: &Plan) -> Coverage {
        let m = |us: i64| (us.max(0) / 60_000_000) as u64;
        let reached = self.last_us.unwrap_or(plan.start_us).max(plan.start_us);
        Coverage {
            unit: "minutes",
            read: m(reached - plan.start_us),
            available: m(plan.until_us - plan.start_us) + plan.skipped_minutes,
            skipped: plan.skipped_minutes,
            next: Some(self.last_us.map_or(plan.start_us, |l| l + 1).max(0) as u64),
            canary: Some(self.parsed > 0),
        }
    }
}

/// The user agent the shared client sends.
fn user_agent() -> String {
    std::env::var("SWARMCHASE_UA").unwrap_or_else(|_| crate::USER_AGENT.to_string())
}

/// Read Jetstream from the plan's start over one connection, showing each
/// text message to `on_msg` until it returns false.
fn read_stream(instance: &str, plan: &Plan, on_msg: &mut dyn FnMut(&str) -> bool) -> Result<()> {
    use tungstenite::client::IntoClientRequest;
    use tungstenite::stream::MaybeTlsStream;
    let url = format!(
        "wss://{instance}/subscribe?wantedCollections=app.bsky.feed.post&cursor={}",
        plan.start_us
    );
    let mut req = url.as_str().into_client_request()?;
    req.headers_mut()
        .insert("User-Agent", user_agent().parse().context("user agent")?);
    let config = tungstenite::protocol::WebSocketConfig::default()
        .max_message_size(Some(MAX_MESSAGE))
        .max_frame_size(Some(MAX_MESSAGE));
    let (mut ws, _) = tungstenite::client::connect_with_config(req, Some(config), 3)
        .with_context(|| format!("connecting to {instance}"))?;
    let timeout = Some(Duration::from_secs(30));
    match ws.get_mut() {
        MaybeTlsStream::Plain(s) => s.set_read_timeout(timeout)?,
        MaybeTlsStream::Rustls(s) => s.get_mut().set_read_timeout(timeout)?,
        _ => {}
    }
    let mut got = 0usize;
    loop {
        match ws.read() {
            Ok(tungstenite::Message::Text(t)) => {
                got += 1;
                if !on_msg(t.as_str()) {
                    break;
                }
            }
            Ok(tungstenite::Message::Close(_)) => break,
            Ok(_) => {}
            // A dropped or stalled connection ends the pull with what it has.
            Err(e) if got > 0 => {
                eprint!("(jetstream stopped: {e}) ");
                break;
            }
            Err(e) => return Err(e).with_context(|| format!("reading {instance}")),
        }
    }
    let _ = ws.close(None);
    Ok(())
}

/// The Jetstream instance a query names, checked.
fn instance(q: &CdxQuery) -> Result<&str> {
    let instance = q.endpoint.as_deref().unwrap_or(DEFAULT_INSTANCE);
    if !instance.ends_with(".bsky.network")
        || !instance
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
    {
        bail!("bluesky endpoint `{instance}` is not a Jetstream instance");
    }
    Ok(instance)
}

/// An account's creation time from its PLC audit log: the first operation's.
pub fn parse_plc_created(body: &str) -> Option<i64> {
    let v: Value = serde_json::from_str(body).ok()?;
    v.as_array()?
        .first()?
        .get("createdAt")?
        .as_str()
        .and_then(crate::parse_date)
}

/// Pull a sample of posts from the checkpoint `mark` (µs).
pub fn pull_platform(
    client: &Client,
    q: &CdxQuery,
    mark: Option<u64>,
    rules: &Rules,
    max: usize,
    lookups: usize,
) -> Result<PlatformPull> {
    let instance = instance(q)?;
    let now_us = crate::client::now_secs() * 1_000_000;
    let plan = Plan::new(q, mark.map(|m| m as i64), now_us, max);
    let mut read = Read::default();
    read_stream(instance, &plan, &mut |m| {
        read.take(m, &plan, Keep::Events(rules))
    })?;
    let coverage = read.coverage(&plan);
    let pairs: Vec<(String, PlatformEvent)> = read
        .events
        .into_iter()
        .map(|e| {
            // The DID is read back from the post's public link.
            let did = e
                .link
                .strip_prefix("https://bsky.app/profile/")
                .and_then(|r| r.split('/').next())
                .unwrap_or("")
                .to_string();
            (did, e)
        })
        .collect();
    let mut ranks: BTreeMap<String, u64> = BTreeMap::new();
    let wanted: BTreeSet<String> = lookup_candidates_dids(&pairs, lookups);
    for did in wanted {
        if let Ok(body) = client.get(&format!("{PLC}{did}/log/audit"))
            && let Some(t) = parse_plc_created(&body).filter(|&t| t > 0)
        {
            ranks.insert(did, (t / RANK_SECS) as u64);
        }
    }
    let events = pairs
        .into_iter()
        .map(|(did, mut e)| {
            e.actor_rank = ranks.get(&did).copied();
            e
        })
        .collect();
    Ok(PlatformPull {
        events,
        coverage,
        ..Default::default()
    })
}

/// The record pass: links in Bluesky posts, as a [`Source`].
/// `query.pattern` is `|`-separated substrings matched against the links
/// and the text; `query.scan`, `query.max_mb` and `query.endpoint` as for
/// the platform pass.
pub struct BskyLinks {
    pub query: CdxQuery,
}

impl BskyLinks {
    pub fn new(query: CdxQuery) -> Result<Self> {
        instance(&query)?;
        Ok(Self { query })
    }
}

impl Source for BskyLinks {
    fn kind(&self) -> Kind {
        Kind::Bluesky
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
        _client: &Client,
        _since: Option<i64>,
        cursor: Option<&Cursor>,
        size: usize,
    ) -> Result<Page> {
        let at = match cursor {
            Some(Cursor::Offset(us)) => Some(*us as i64),
            Some(c) => bail!("bluesky pages by stream time, not {c:?}"),
            None => None,
        };
        let now_us = crate::client::now_secs() * 1_000_000;
        let plan = Plan::new(&self.query, at, now_us, size);
        let needles = Needles::new(&self.query.pattern);
        let mut read = Read::default();
        read_stream(instance(&self.query)?, &plan, &mut |m| {
            read.take(m, &plan, Keep::Links(&needles))
        })?;
        Ok(Page {
            coverage: Some(read.coverage(&plan)),
            records: read.records,
            next: None,
            truncated: false,
        })
    }

    fn checkpointed(&self) -> bool {
        true
    }
}

/// [`lookup_candidates`] over DIDs, keeping only `did:plc` identities with
/// a well-formed id.
fn lookup_candidates_dids(pairs: &[(String, PlatformEvent)], max: usize) -> BTreeSet<String> {
    let plc: Vec<(String, PlatformEvent)> = pairs
        .iter()
        .filter(|(d, _)| {
            d.strip_prefix("did:plc:").is_some_and(|id| {
                !id.is_empty() && id.len() <= 64 && id.chars().all(|c| c.is_ascii_alphanumeric())
            })
        })
        .map(|(d, e)| (d.replace(':', "_"), e.clone()))
        .collect();
    lookup_candidates(&plc, max)
        .into_iter()
        .map(|d| d.replace('_', ":"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const US: i64 = 1_791_900_000_000_000;

    /// A synthetic Jetstream commit; every DID, key and text is invented.
    fn post(did: &str, rkey: &str, us: i64, text: &str, reply: bool) -> String {
        let reply = if reply {
            r#","reply":{"root":{"uri":"at://did:plc:rootauthor/app.bsky.feed.post/3root","cid":"x"},"parent":{"uri":"at://did:plc:rootauthor/app.bsky.feed.post/3root","cid":"x"}}"#
        } else {
            ""
        };
        format!(
            r#"{{"did":"{did}","time_us":{us},"kind":"commit","commit":{{"rev":"r","operation":"create","collection":"app.bsky.feed.post","rkey":"{rkey}","record":{{"$type":"app.bsky.feed.post","createdAt":"2026-10-13T00:00:00Z","langs":["en"],"text":{}{reply}}},"cid":"c"}}}}"#,
            serde_json::to_string(text).unwrap()
        )
    }

    fn plan() -> Plan {
        Plan {
            start_us: US,
            until_us: US + 600_000_000,
            deadline: Instant::now() + Duration::from_secs(60),
            max_bytes: 1 << 20,
            max_events: 100,
            skipped_minutes: 0,
        }
    }

    #[test]
    fn posts_become_events_without_dids() {
        let rules = Rules::default_rules();
        let v: Value = serde_json::from_str(&post(
            "did:plc:probeaccount1",
            "3kabc",
            US,
            "Certainly! Here's a thread about the new release and why it matters to everyone",
            true,
        ))
        .unwrap();
        let e = post_event(&v, &rules).unwrap();
        assert_eq!(e.platform, Platform::Bluesky);
        assert_eq!(e.action, Action::Comment);
        assert_eq!(e.target, "did:plc:rootauthor/3root");
        assert_eq!(e.owner(), "did:plc:rootauthor");
        assert_eq!(e.ts, US / 1_000_000);
        assert!(e.actor.starts_with("acct:"));
        assert!(!e.id.contains("probeaccount1"), "{}", e.id);
        assert!(
            !serde_json::to_string(&e.text)
                .unwrap()
                .contains("probeaccount1")
        );
        let top: Value =
            serde_json::from_str(&post("did:plc:x", "3k", US, "hello there everyone", false))
                .unwrap();
        assert_eq!(post_event(&top, &rules).unwrap().target, "post:3k");
        let like: Value = serde_json::from_str(
            r#"{"did":"did:plc:x","time_us":1,"kind":"commit","commit":{"operation":"create","collection":"app.bsky.feed.like","rkey":"k","record":{}}}"#,
        )
        .unwrap();
        assert!(post_event(&like, &rules).is_none());
    }

    #[test]
    fn a_read_drops_deleted_posts_and_stops_at_its_start() {
        let rules = Rules::default_rules();
        let p = plan();
        let mut r = Read::default();
        assert!(r.take(
            &post("did:plc:a", "1", US + 1, "first post text here", false),
            &p,
            Keep::Events(&rules)
        ));
        assert!(r.take(
            &post("did:plc:b", "2", US + 2, "second post text here", false),
            &p,
            Keep::Events(&rules)
        ));
        let del = r#"{"did":"did:plc:a","time_us":1791900000000003,"kind":"commit","commit":{"operation":"delete","collection":"app.bsky.feed.post","rkey":"1"}}"#;
        assert!(r.take(del, &p, Keep::Events(&rules)));
        assert_eq!((r.events.len(), r.deleted), (1, 1));
        assert!(r.take("not json", &p, Keep::Events(&rules)));
        assert!(!r.take(
            &post("did:plc:c", "3", US + 600_000_000, "too late", false),
            &p,
            Keep::Events(&rules)
        ));
        assert!(r.caught_up);
        let c = r.coverage(&p);
        assert_eq!((c.available, c.canary), (10, Some(true)));
        assert_eq!(c.next, Some((US + 4) as u64));
    }

    /// A post with link facets and a link card; every DID, key and link is
    /// invented.
    fn linked(did: &str, rkey: &str, us: i64, text: &str, links: &[&str], card: &str) -> String {
        let facets: Vec<String> = links
            .iter()
            .map(|u| {
                format!(
                    r#"{{"index":{{"byteStart":0,"byteEnd":4}},"features":[{{"$type":"app.bsky.richtext.facet#link","uri":"{u}"}}]}}"#
                )
            })
            .collect();
        format!(
            r#"{{"did":"{did}","time_us":{us},"kind":"commit","commit":{{"rev":"r","operation":"create","collection":"app.bsky.feed.post","rkey":"{rkey}","record":{{"$type":"app.bsky.feed.post","createdAt":"2026-10-13T00:00:00Z","text":{},"facets":[{}],"embed":{{"$type":"app.bsky.embed.external","external":{{"uri":"{card}","title":"t","description":"d"}}}}}},"cid":"c"}}}}"#,
            serde_json::to_string(text).unwrap(),
            facets.join(",")
        )
    }

    #[test]
    fn matching_links_become_records_and_are_never_followed() {
        let n = Needles::new("r.jina.ai/http|uqtag");
        let v: Value = serde_json::from_str(&linked(
            "did:plc:probeaccount1",
            "3kabc",
            US,
            "look r.jina.ai/https://t.ex...",
            &[
                "https://r.jina.ai/https://t.example/?uqtag=run7",
                "https://other.example/",
            ],
            "https://r.jina.ai/https://t.example/?uqtag=run7",
        ))
        .unwrap();
        let recs = post_records(&v, &n);
        assert_eq!(recs.len(), 1, "{recs:?}");
        assert_eq!(
            recs[0].url,
            "https://r.jina.ai/https://t.example/?uqtag=run7"
        );
        assert_eq!(
            recs[0].reference.as_deref(),
            Some("https://bsky.app/profile/did:plc:probeaccount1/post/3kabc")
        );
        assert_eq!(
            (recs[0].source.as_str(), recs[0].ts),
            ("bluesky", US / 1_000_000)
        );
        assert_eq!(recs[0].ts_kind, TsKind::Request);
        assert!(recs[0].id.starts_with("bluesky:") && !recs[0].id.contains("probeaccount1"));
        // A run tag in the text alone: the post's page is the record.
        let v: Value =
            serde_json::from_str(&post("did:plc:x", "3k", US, "my tag is uqtag-77", false))
                .unwrap();
        let recs = post_records(&v, &n);
        assert_eq!(recs[0].url, "https://bsky.app/profile/did:plc:x/post/3k");
        // Nothing matching, nothing kept.
        let v: Value =
            serde_json::from_str(&post("did:plc:x", "3m", US, "hello there", false)).unwrap();
        assert!(post_records(&v, &n).is_empty());
    }

    #[test]
    fn a_link_read_drops_records_of_deleted_posts() {
        let n = Needles::new("r.jina.ai/http");
        let p = plan();
        let mut r = Read::default();
        let link = ["https://r.jina.ai/https://t.example/"];
        assert!(r.take(
            &linked("did:plc:a", "1", US + 1, "x", &link, "https://c.example/"),
            &p,
            Keep::Links(&n)
        ));
        assert!(r.take(
            &linked("did:plc:b", "2", US + 2, "x", &link, "https://c.example/"),
            &p,
            Keep::Links(&n)
        ));
        let del = r#"{"did":"did:plc:a","time_us":1791900000000003,"kind":"commit","commit":{"operation":"delete","collection":"app.bsky.feed.post","rkey":"1"}}"#;
        assert!(r.take(del, &p, Keep::Links(&n)));
        assert_eq!((r.records.len(), r.deleted, r.events.len()), (1, 1, 0));
        assert!(
            r.records[0]
                .reference
                .as_deref()
                .unwrap()
                .contains("did:plc:b")
        );
        assert_eq!(r.coverage(&p).canary, Some(true));
        let bad = CdxQuery {
            endpoint: Some("relay.example".into()),
            ..Default::default()
        };
        assert!(BskyLinks::new(bad).is_err());
    }

    #[test]
    fn plans_sample_the_newest_stretch() {
        let q = CdxQuery::default();
        let now = US + 3_600_000_000;
        let p = Plan::new(&q, None, now, 10);
        assert_eq!(p.start_us, now - SAMPLE_MINUTES * 60_000_000);
        let p = Plan::new(&q, Some(now - 60_000_000), now, 10);
        assert_eq!((p.start_us, p.skipped_minutes), (now - 60_000_000, 0));
        let p = Plan::new(&q, Some(now - 6 * 3_600_000_000), now, 10);
        assert_eq!(p.skipped_minutes, 6 * 60 - SAMPLE_MINUTES as u64);
    }

    #[test]
    fn plc_audit_logs_give_creation_times() {
        let log = r#"[{"did":"did:plc:x","operation":{},"cid":"c","nullified":false,"createdAt":"2026-10-12T10:00:00.000Z"},{"createdAt":"2026-10-13T10:00:00.000Z"}]"#;
        assert_eq!(
            parse_plc_created(log),
            crate::parse_date("2026-10-12T10:00:00Z")
        );
        assert_eq!(parse_plc_created("{}"), None);
        let rules = Rules::default_rules();
        let text = "Please review my report on the critical vulnerability in the parser module now";
        let ev = |did: &str| {
            let v: Value = serde_json::from_str(&post(did, "k", US, text, false)).unwrap();
            (did.to_string(), post_event(&v, &rules).unwrap())
        };
        let pairs = vec![
            ev("did:plc:aaa"),
            ev("did:plc:bbb"),
            ev("did:web:example.org"),
        ];
        let got = lookup_candidates_dids(&pairs, 10);
        assert_eq!(
            got.into_iter().collect::<Vec<_>>(),
            ["did:plc:aaa", "did:plc:bbb"]
        );
    }
}
