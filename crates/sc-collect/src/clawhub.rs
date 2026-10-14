//! ClawHub (`clawhub.ai`), the OpenClaw skills registry: its public list of
//! skills, newest first (`GET /api/v1/skills?sort=newest`), read for two
//! things.
//!
//! - **Records** ([`ClawHub`], a record source): skills whose summary,
//!   display name, slug or topics carry a relay link or run tag from the
//!   watchlist's shared list. A matching URL in the summary is the record
//!   (never fetched), its reference the skill's page; a match with no URL
//!   (a run tag) makes the skill's page the record. Leads for review.
//! - **Platform events** ([`clawhub_events`], the platform pass): every
//!   skill as a package published, its owner handle as a keyed hash, its
//!   slug as a name template and its summary sketched, so a fleet of
//!   skills published in a burst under templated names groups.
//!
//! Listing metadata only: owner handle, slug, display name, summary,
//! topics, version and times. Skill files are never downloaded, and no URL
//! in a listing is fetched. A pull pages back from the newest skill to the
//! checkpoint (the newest creation time read, in ms), at most `scan` pages
//! of `page_size` skills.
//!
//! Terms: the ClawHub API documentation
//! (<https://docs.openclaw.ai/clawhub/api>) allows catalogs built on the
//! public read endpoints that cache, honour `429`, `Retry-After` and the
//! rate-limit headers instead of polling aggressively, link to the
//! canonical skill page, do not imply ClawHub's endorsement, and do not
//! mirror hidden, private or moderation-blocked content by bypassing the
//! public filters. Anonymous reads are limited to 3000 a minute per IP; a
//! few paced listing requests a run stay far inside that. Records and
//! events link the canonical page (`clawhub.ai/<owner>/skills/<slug>`).

use crate::pager::{Coverage, Cursor, Page};
use crate::platform::PlatformPull;
use crate::registries::{minutes, split_automation, start_at};
use crate::{CdxQuery, Client, Kind, Needles, Source, short_hash};
use anyhow::{Context, Result};
use sc_core::Rules;
use sc_core::platform::automation::is_automation;
use sc_core::platform::{Action, Platform, PlatformEvent, actor_key, name_template};
use sc_core::{Observation, TsKind, redact_observation};
use serde_json::Value;

const BASE: &str = "https://clawhub.ai/api/v1/skills";
/// Skills per request unless `page_size` says fewer.
const MAX_PAGE: usize = 100;
/// Pages one pull reads unless `scan` says otherwise.
const DEFAULT_PAGES: usize = 5;

/// One skill as the listing gives it.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Skill {
    pub owner: String,
    pub slug: String,
    pub display_name: String,
    pub summary: String,
    pub topics: Vec<String>,
    pub version: String,
    /// When the skill was first published (Unix ms).
    pub created_ms: i64,
}

impl Skill {
    /// The canonical skill page.
    pub fn page(&self) -> String {
        format!("https://clawhub.ai/{}/skills/{}", self.owner, self.slug)
    }

    /// Display name, summary and topics, one per line.
    fn text(&self) -> String {
        let mut t = vec![self.display_name.as_str(), self.summary.as_str()];
        t.extend(self.topics.iter().map(String::as_str));
        t.retain(|s| !s.is_empty());
        t.join("\n")
    }
}

/// One listing page.
#[derive(Debug, Default)]
pub struct SkillPage {
    pub skills: Vec<Skill>,
    /// Items on the page before any was dropped as malformed.
    pub read: usize,
    /// The cursor of the next page.
    pub next: Option<String>,
}

/// Parse a `/api/v1/skills` response.
pub fn parse_skills(body: &str) -> Result<SkillPage> {
    let v: Value = serde_json::from_str(body).context("ClawHub listing: not JSON")?;
    let items = v
        .get("items")
        .and_then(Value::as_array)
        .context("ClawHub listing: no `items` array")?;
    let mut out = SkillPage {
        read: items.len(),
        next: v
            .get("nextCursor")
            .and_then(Value::as_str)
            .filter(|c| !c.is_empty())
            .map(str::to_string),
        ..Default::default()
    };
    for it in items {
        let s = |k: &str| it.get(k).and_then(Value::as_str).map(str::trim);
        let (Some(owner), Some(slug), Some(created)) = (
            s("ownerHandle").filter(|o| !o.is_empty()),
            s("slug").filter(|o| !o.is_empty()),
            it.get("createdAt").and_then(Value::as_f64),
        ) else {
            continue;
        };
        out.skills.push(Skill {
            owner: owner.to_string(),
            slug: slug.to_string(),
            display_name: s("displayName").unwrap_or("").to_string(),
            summary: s("summary").unwrap_or("").to_string(),
            topics: it
                .get("topics")
                .and_then(Value::as_array)
                .map(|a| {
                    a.iter()
                        .filter_map(Value::as_str)
                        .map(str::to_string)
                        .collect()
                })
                .unwrap_or_default(),
            version: it
                .pointer("/latestVersion/version")
                .or_else(|| it.pointer("/tags/latest"))
                .and_then(Value::as_str)
                .unwrap_or("0")
                .to_string(),
            created_ms: created as i64,
        });
    }
    Ok(out)
}

/// What a walk back to the checkpoint read.
#[derive(Debug, Default)]
pub struct Walked {
    /// Skills created after the checkpoint, newest first.
    pub skills: Vec<Skill>,
    pub coverage: Coverage,
}

/// Page the newest-first listing back from now to the checkpoint `mark`
/// (ms), at most `pages` pages and `max` skills. `fetch` answers one page
/// given the cursor of the page before.
pub fn walk(
    mark: Option<u64>,
    pages: usize,
    max: usize,
    now_ms: i64,
    fetch: &mut dyn FnMut(Option<&str>) -> Result<String>,
) -> Result<Walked> {
    let (start, skipped) = start_at(mark.map(|m| m as i64), now_ms);
    let mut out = Walked::default();
    let mut cursor: Option<String> = None;
    let (mut newest, mut reached, mut read) = (None::<i64>, now_ms, 0usize);
    let mut done = false;
    for i in 0..pages.max(1) {
        let body = match fetch(cursor.as_deref()) {
            Ok(b) => b,
            Err(e) if i == 0 => return Err(e),
            Err(_) => break,
        };
        let page = parse_skills(&body)?;
        read += page.read;
        for s in page.skills {
            newest = newest.max(Some(s.created_ms));
            reached = reached.min(s.created_ms);
            if s.created_ms > start && out.skills.len() < max {
                out.skills.push(s);
            }
        }
        if reached <= start || page.next.is_none() || page.read == 0 {
            done = true;
            break;
        }
        if out.skills.len() >= max {
            break;
        }
        cursor = page.next;
    }
    // Read from `reached` up to now; what lies between the checkpoint and
    // `reached` was not reached when the pages or the cap ran out.
    let gap = if done { 0 } else { (reached - start).max(0) };
    out.coverage = minutes(start, now_ms - gap, now_ms, skipped, read > 0);
    out.coverage.skipped += (gap / 60_000) as u64;
    out.coverage.next = Some(newest.unwrap_or(start).max(start).max(0) as u64);
    Ok(out)
}

fn fetch_page(client: &Client, size: usize, cursor: Option<&str>) -> Result<String> {
    let mut u = url::Url::parse(BASE)?;
    {
        let mut p = u.query_pairs_mut();
        p.append_pair("sort", "newest")
            .append_pair("limit", &size.to_string());
        if let Some(c) = cursor {
            p.append_pair("cursor", c);
        }
    }
    client.get(u.as_str()).context("ClawHub skills listing")
}

/// Records from one skill: the URLs in its summary that match `needles`,
/// or its page when only its text matches. Redacted.
pub fn skill_records(s: &Skill, needles: &Needles) -> Vec<Observation> {
    let page = s.page();
    let mut urls: Vec<String> = Vec::new();
    for u in crate::gharchive::urls_in(&s.summary) {
        let u = u.trim_end_matches(['.', ',', ';', ':']);
        if needles.matches(u) && !urls.iter().any(|x| x == u) {
            urls.push(u.to_string());
        }
    }
    if urls.is_empty() && (needles.matches(&s.text()) || needles.matches(&s.slug)) {
        urls.push(page.clone());
    }
    urls.into_iter()
        .map(|url| {
            let mut o = Observation {
                id: format!(
                    "clawhub:{}/{}@{}:{}",
                    s.owner,
                    s.slug,
                    s.version,
                    short_hash(&url)
                ),
                source: "clawhub".into(),
                ts: s.created_ms / 1000,
                // The publish request reaching the registry.
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

/// One skill as a platform event: a package published by its owner (as a
/// keyed hash), named by a template of its slug, its text sketched. An
/// automation owner gives an empty event, dropped and counted.
pub fn skill_event(s: &Skill, rules: &Rules) -> PlatformEvent {
    if is_automation(&s.owner) {
        return PlatformEvent::default();
    }
    let owner = s.owner.to_ascii_lowercase();
    PlatformEvent {
        id: format!("clawhub:{owner}/{}@{}", s.slug, s.version),
        platform: Platform::ClawHub,
        action: Action::PackagePublished,
        ts: s.created_ms / 1000,
        actor: actor_key(Platform::ClawHub, &owner),
        target: format!("{owner}/{}", s.slug),
        link: s.page(),
        name_template: name_template(&s.slug, &owner),
        ..Default::default()
    }
    .with_text(&s.text(), &[&s.slug, &owner, &s.display_name], rules)
}

/// Platform events from a ClawHub listing response, and the items it held.
/// Automation owners give empty events (see [`skill_event`]).
pub fn clawhub_events(body: &str, rules: &Rules) -> Result<(Vec<PlatformEvent>, usize)> {
    let page = parse_skills(body)?;
    let events = page.skills.iter().map(|s| skill_event(s, rules)).collect();
    Ok((events, page.read))
}

/// The platform pass's pull: every skill created since the checkpoint.
pub(crate) fn pull_platform(
    client: &Client,
    q: &CdxQuery,
    mark: Option<u64>,
    rules: &Rules,
    max: usize,
) -> Result<PlatformPull> {
    let now_ms = crate::client::now_secs() * 1000;
    let size = q.page_size.clamp(1, MAX_PAGE);
    let pages = q.scan.unwrap_or(DEFAULT_PAGES).clamp(1, 20);
    let max = max.min(q.limit.max(1));
    let w = walk(mark, pages, max, now_ms, &mut |c| {
        fetch_page(client, size, c)
    })?;
    let events = w.skills.iter().map(|s| skill_event(s, rules)).collect();
    let (events, automation) = split_automation(events);
    Ok(PlatformPull {
        events,
        automation,
        coverage: w.coverage,
        ..Default::default()
    })
}

/// The ClawHub listing as a [`Source`]. `query.pattern` is `|`-separated
/// substrings matched against a skill's summary, display name, slug and
/// topics (`*` keeps every skill); `scan` caps pages a pull reads.
pub struct ClawHub {
    pub query: CdxQuery,
}

impl Source for ClawHub {
    fn kind(&self) -> Kind {
        Kind::ClawHub
    }

    fn query(&self) -> &CdxQuery {
        &self.query
    }

    /// One pull, one walk.
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
        let mark = match cursor {
            Some(Cursor::Offset(t)) => Some(*t as u64),
            Some(c) => anyhow::bail!("clawhub pages by creation time, not {c:?}"),
            None => None,
        };
        let per = self.query.page_size.clamp(1, MAX_PAGE);
        let pages = self.query.scan.unwrap_or(DEFAULT_PAGES).clamp(1, 20);
        let now_ms = crate::client::now_secs() * 1000;
        let w = walk(mark, pages, usize::MAX, now_ms, &mut |c| {
            fetch_page(client, per, c)
        })?;
        let needles = Needles::new(&self.query.pattern);
        let mut records: Vec<Observation> = w
            .skills
            .iter()
            .flat_map(|s| skill_records(s, &needles))
            .collect();
        records.truncate(size);
        Ok(Page {
            records,
            next: None,
            truncated: false,
            coverage: Some(w.coverage),
        })
    }

    /// The checkpoint is the newest creation time read (ms).
    fn checkpointed(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(name: &str) -> String {
        let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/clawhub")
            .join(name);
        std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))
    }

    #[test]
    fn listings_parse_and_link_the_canonical_page() {
        let p = parse_skills(&fixture("page1.json")).unwrap();
        assert_eq!((p.read, p.skills.len()), (4, 3), "one item has no owner");
        let s = &p.skills[0];
        assert_eq!(s.owner, "probe-owner");
        assert_eq!(s.slug, "reach-check-0042");
        assert_eq!(s.version, "0.0.1");
        assert_eq!(s.topics, ["probe"]);
        assert_eq!(
            s.page(),
            "https://clawhub.ai/probe-owner/skills/reach-check-0042"
        );
        assert!(p.next.is_some());
        assert!(parse_skills("{}").is_err());
        assert!(parse_skills("not json").is_err());
    }

    #[test]
    fn matching_summaries_become_records_and_are_never_followed() {
        let p = parse_skills(&fixture("page1.json")).unwrap();
        let n = Needles::new("r.jina.ai|uqtag");
        let recs: Vec<Observation> = p.skills.iter().flat_map(|s| skill_records(s, &n)).collect();
        assert_eq!(recs.len(), 2, "{recs:#?}");
        // A relay link in the summary is the record; its reference the page.
        assert!(
            recs[0]
                .url
                .starts_with("https://r.jina.ai/https://target.example/")
        );
        assert_eq!(
            recs[0].reference.as_deref(),
            Some("https://clawhub.ai/probe-owner/skills/reach-check-0042")
        );
        assert_eq!(recs[0].source, "clawhub");
        assert_eq!(recs[0].ts_kind, TsKind::Request);
        // A run tag with no link: the skill's page is the record.
        assert_eq!(
            recs[1].url,
            "https://clawhub.ai/probe-owner/skills/reach-check-0043"
        );
        assert_eq!(
            sc_core::Provenance::of_source("clawhub"),
            sc_core::Provenance::PublishAnywhere
        );
    }

    #[test]
    fn skills_become_platform_events_with_hashed_owners() {
        let rules = Rules::default_rules();
        let (ev, n) = clawhub_events(&fixture("page1.json"), &rules).unwrap();
        assert_eq!((ev.len(), n), (3, 4));
        let (ev, automation) = split_automation(ev);
        assert_eq!((ev.len(), automation), (2, 1));
        assert_eq!(ev[0].platform, Platform::ClawHub);
        assert_eq!(ev[0].action, Action::PackagePublished);
        assert_eq!(ev[0].actor, ev[1].actor);
        assert!(ev[0].actor.starts_with("acct:"));
        assert_eq!(ev[0].name_template.as_deref(), Some("reach-check-<num>"));
        assert_eq!(ev[0].id, "clawhub:probe-owner/reach-check-0042@0.0.1");
        assert_eq!(ev[0].ts, 1_791_978_499);
        let json = serde_json::to_string(&ev[0]).unwrap();
        assert!(!json.contains("\"actor\":\"probe-owner"), "{json}");
        assert!(!json.contains("target.example"), "{json}");
    }

    #[test]
    fn a_walk_pages_back_to_the_checkpoint() {
        let pages = [fixture("page1.json"), fixture("page2.json")];
        // The checkpoint falls inside page two.
        let mark = 1_791_978_000_000u64;
        let now = 1_791_980_000_000i64;
        let mut asked = Vec::new();
        let w = walk(Some(mark), 5, 100, now, &mut |c| {
            asked.push(c.map(str::to_string));
            Ok(pages[usize::from(c.is_some())].clone())
        })
        .unwrap();
        assert_eq!(asked.len(), 2);
        assert_eq!(asked[1].as_deref(), Some("cursor-2"));
        // Page two's skill at or before the checkpoint is not kept.
        let slugs: Vec<&str> = w.skills.iter().map(|s| s.slug.as_str()).collect();
        assert_eq!(
            slugs,
            [
                "reach-check-0042",
                "reach-check-0043",
                "x",
                "reach-check-0041"
            ]
        );
        assert_eq!(w.coverage.skipped, 0);
        assert_eq!(w.coverage.next, Some(1_791_978_499_670));
        // One page allowed: the rest of the span is counted as skipped.
        let w = walk(Some(mark), 1, 100, now, &mut |_| Ok(pages[0].clone())).unwrap();
        assert!(w.coverage.skipped > 0, "{:?}", w.coverage);
        // A first page that fails is an error; a later one ends the walk.
        assert!(walk(None, 2, 100, now, &mut |_| anyhow::bail!("HTTP 503")).is_err());
    }
}
