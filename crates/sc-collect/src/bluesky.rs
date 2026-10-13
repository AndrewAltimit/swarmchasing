//! Bluesky posts for the platform pass (`bluesky`), from Jetstream, the
//! JSON relay of the AT Protocol firehose that Bluesky runs
//! (`wss://jetstream<n>.<region>.bsky.network/subscribe`). A pull asks for
//! `app.bsky.feed.post` records only, from a cursor, over one WebSocket
//! connection, and keeps one [`PlatformEvent`] per post created: the
//! account's DID as a keyed hash, the text as a sketch, and as the target
//! the thread's root post for a reply, else the host of a link card.
//!
//! Coverage: the stream carries tens of posts a second, too many to read
//! six hours of each run. A pull reads a sample: from its checkpoint, or
//! [`SAMPLE_MINUTES`] before its own start when the checkpoint is older,
//! until it catches up with its own start or runs out of `scan`
//! wall-clock minutes, `max_mb` megabytes or `max_events` posts. The
//! stretch between an old checkpoint and the sample is counted as skipped,
//! in minutes of stream time. Posts parsed are the canary.
//!
//! Deletions: a post deleted while the pull reads is dropped from what it
//! keeps. Only sketches are kept, never the text, and only events worth
//! another look are carried, for the watch's `carry_hours`.
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
//! developers to respect deletions and users' privacy: we keep no text,
//! no handle and no DID, only keyed hashes and sketches, carried briefly.

use crate::hackernews::{RANK_SECS, lookup_candidates};
use crate::pager::Coverage;
use crate::platform::PlatformPull;
use crate::{CdxQuery, Client};
use anyhow::{Context, Result, bail};
use sc_core::Rules;
use sc_core::platform::{Action, Platform, PlatformEvent, actor_key};
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

/// A thread's root as a target, `<did>/<rkey>`, from its
/// `at://<did>/app.bsky.feed.post/<rkey>` URI: the root's author is the
/// target's owner, as a repository's is on GitHub.
fn root_target(uri: &str) -> Option<String> {
    let rest = uri.strip_prefix("at://")?;
    let mut parts = rest.split('/');
    let (did, coll, rkey) = (parts.next()?, parts.next()?, parts.next()?);
    (coll == "app.bsky.feed.post").then(|| format!("{did}/{rkey}"))
}

/// The id a delete names, matching [`post_event`]'s ids.
fn deleted_id(v: &Value) -> Option<String> {
    let s = |p: &str| v.pointer(p).and_then(Value::as_str);
    (s("/kind") == Some("commit")
        && s("/commit/operation") == Some("delete")
        && s("/commit/collection") == Some("app.bsky.feed.post"))
    .then(|| Some(post_id(s("/did")?, s("/commit/rkey")?)))
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

/// What a read kept.
#[derive(Debug, Default)]
pub struct Read {
    pub events: Vec<PlatformEvent>,
    pub parsed: usize,
    pub bytes: u64,
    pub last_us: Option<i64>,
    pub deleted: usize,
    pub caught_up: bool,
}

impl Read {
    /// Take one message; false when the read should stop.
    pub fn take(&mut self, msg: &str, plan: &Plan, rules: &Rules) -> bool {
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
        if let Some(id) = deleted_id(&v) {
            let before = self.events.len();
            self.events.retain(|e| e.id != id);
            self.deleted += before - self.events.len();
        } else if let Some(e) = post_event(&v, rules) {
            self.events.push(e);
        }
        self.events.len() < plan.max_events
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

/// Read Jetstream from the plan's start over one connection.
fn read_stream(instance: &str, plan: &Plan, rules: &Rules) -> Result<Read> {
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
    let mut read = Read::default();
    loop {
        match ws.read() {
            Ok(tungstenite::Message::Text(t)) => {
                if !read.take(t.as_str(), plan, rules) {
                    break;
                }
            }
            Ok(tungstenite::Message::Close(_)) => break,
            Ok(_) => {}
            // A dropped or stalled connection ends the pull with what it has.
            Err(e) if read.parsed > 0 => {
                eprint!("(jetstream stopped: {e}) ");
                break;
            }
            Err(e) => return Err(e).with_context(|| format!("reading {instance}")),
        }
    }
    let _ = ws.close(None);
    Ok(read)
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
    let instance = q.endpoint.as_deref().unwrap_or(DEFAULT_INSTANCE);
    if !instance.ends_with(".bsky.network")
        || !instance
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
    {
        bail!("bluesky endpoint `{instance}` is not a Jetstream instance");
    }
    let now_us = crate::client::now_secs() * 1_000_000;
    let plan = Plan::new(q, mark.map(|m| m as i64), now_us, max);
    let read = read_stream(instance, &plan, rules)?;
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
            &rules
        ));
        assert!(r.take(
            &post("did:plc:b", "2", US + 2, "second post text here", false),
            &p,
            &rules
        ));
        let del = r#"{"did":"did:plc:a","time_us":1791900000000003,"kind":"commit","commit":{"operation":"delete","collection":"app.bsky.feed.post","rkey":"1"}}"#;
        assert!(r.take(del, &p, &rules));
        assert_eq!((r.events.len(), r.deleted), (1, 1));
        assert!(r.take("not json", &p, &rules));
        assert!(!r.take(
            &post("did:plc:c", "3", US + 600_000_000, "too late", false),
            &p,
            &rules
        ));
        assert!(r.caught_up);
        let c = r.coverage(&p);
        assert_eq!((c.available, c.canary), (10, Some(true)));
        assert_eq!(c.next, Some((US + 4) as u64));
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
