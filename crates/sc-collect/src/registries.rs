//! More package registries for the platform pass, beside npm, PyPI and Go
//! modules: NuGet's catalog, Packagist's change feed, RubyGems' newest
//! gems and crates.io's newest crates. Index and listing metadata only:
//! names, versions, times, a summary where the listing carries one, and an
//! owner where it names one, as a keyed hash. No package, archive or
//! repository is downloaded, and no URL in a listing is fetched.
//!
//! - **NuGet** (`nuget`): the catalog (`api.nuget.org/v3/catalog0`) is an
//!   append-only log of package operations in pages, each page listing
//!   package ids, versions and commit times. A pull reads the index, then
//!   the pages committed after its checkpoint (the newest commit time read,
//!   in ms), oldest first, at most `scan` pages; the next pull continues
//!   after the last page read. The pages name no owner, so groups here are
//!   floods of templated names. Leaves (one request per package) are not
//!   read.
//! - **Packagist** (`packagist`): `metadata/changes.json?since=` lists the
//!   packages updated since a timestamp the feed itself hands out (in
//!   ten-thousandths of a second). The vendor (`vendor/name`) stands for the
//!   account, as a keyed hash. The feed keeps a day of changes; an older
//!   checkpoint gets a `resync` answer, counted as a gap.
//! - **RubyGems** (`rubygems`): `activity/latest.json` (gems whose first
//!   version is newest) or `activity/just_updated.json`, fifty a request;
//!   one request a run, a sample. The gemspec's author string stands for
//!   the account, as a keyed hash; the summary is sketched.
//! - **crates.io** (`crates`): `api/v1/crates?sort=new`, a hundred a page,
//!   newest first, paged by the API's seek key back to the checkpoint (the
//!   newest creation time read, in ms), at most `scan` pages. The listing
//!   names no owner; the declared repository's host and owner
//!   (`github.com/<owner>`) stand for the account, as a keyed hash.
//!
//! Without a checkpoint a pull starts [`FRESH_MS`] back; a checkpoint older
//! than [`MAX_BACKLOG_MS`] is skipped to there and the gap counted.
//! Coverage is in minutes of registry time.
//!
//! Terms: NuGet's API is public and documented
//! (<https://learn.microsoft.com/en-us/nuget/api/catalog-resource>); the
//! catalog is the documented way to follow every package operation, read
//! with a cursor, and the nuget.org Terms of Use
//! (<https://www.nuget.org/policies/Terms>) forbid disrupting the service.
//! Packagist's API documentation (<https://packagist.org/apidoc>) points
//! mirrors at the change feed, asks for at most 10 concurrent requests,
//! a randomised schedule off the hour, and a User-Agent with a contact
//! address; the shared user agent names the repository, and
//! `SWARMCHASE_UA` can add a `mailto=`. RubyGems' rate limits
//! (<https://guides.rubygems.org/rubygems-org-rate-limits/>) allow 10 API
//! requests a second per IP. crates.io's data access policy
//! (<https://crates.io/data-access>) allows at most one API request a
//! second with an identifying User-Agent, and prefers the database dump
//! for bulk use; a few paced listing requests a run, never per-crate
//! requests, stay inside that.

use crate::pager::Coverage;
use crate::platform::PlatformPull;
use crate::{CdxQuery, Client, parse_date};
use anyhow::{Context, Result, bail};
use sc_core::Rules;
use sc_core::platform::automation::is_automation;
use sc_core::platform::{Action, Platform, PlatformEvent, actor_key, name_template};
use serde_json::Value;
use std::collections::BTreeSet;

/// Without a checkpoint, a pull starts this far back (ms).
pub const FRESH_MS: i64 = 6 * 3_600_000;
/// A checkpoint further back than this is skipped (ms).
pub const MAX_BACKLOG_MS: i64 = 24 * 3_600_000;

const NUGET_INDEX: &str = "https://api.nuget.org/v3/catalog0/index.json";
const NUGET_PAGES: &str = "https://api.nuget.org/v3/catalog0/";
/// Catalog pages one NuGet pull reads unless `scan` says otherwise.
const DEFAULT_NUGET_PAGES: usize = 4;
const PACKAGIST: &str = "https://packagist.org/metadata/changes.json";
/// Packagist keeps a day of changes; a checkpoint older than this is stale.
const PACKAGIST_KEEP_MS: i64 = 23 * 3_600_000;
const CRATES: &str = "https://crates.io/api/v1/crates";
/// Listing pages one crates.io pull reads unless `scan` says otherwise.
const DEFAULT_CRATES_PAGES: usize = 3;

/// Where a pull starts (ms) and how much backlog it passed over (ms).
pub(crate) fn start_at(mark: Option<i64>, newest: i64) -> (i64, i64) {
    let fresh = newest - FRESH_MS;
    match mark {
        Some(m) if m >= newest - MAX_BACKLOG_MS => (m.min(newest), 0),
        Some(m) => (fresh, (fresh - m).max(0)),
        None => (fresh, 0),
    }
}

/// Coverage in minutes: read from `start` to `reached`, against `start`
/// to `newest`, with `skipped` ms passed over.
pub(crate) fn minutes(
    start: i64,
    reached: i64,
    newest: i64,
    skipped: i64,
    read_any: bool,
) -> Coverage {
    let m = |ms: i64| (ms.max(0) / 60_000) as u64;
    Coverage {
        unit: "minutes",
        read: m(reached.min(newest) - start),
        available: m(newest - start) + m(skipped),
        skipped: m(skipped),
        next: None,
        canary: Some(read_any),
    }
}

pub(crate) fn ms_of(s: &str) -> Option<i64> {
    chrono::DateTime::parse_from_rfc3339(s.trim())
        .ok()
        .map(|d| d.timestamp_millis())
}

/// Drop events from automation accounts (marked by an empty id) and count them.
pub(crate) fn split_automation(mut events: Vec<PlatformEvent>) -> (Vec<PlatformEvent>, usize) {
    let n = events.len();
    events.retain(|e| !e.id.is_empty());
    let dropped = n - events.len();
    (events, dropped)
}

// ── NuGet ──────────────────────────────────────────────────────────────────

/// The catalog pages committed after `after` (ms), oldest first, as (commit
/// ms, page URL), and the index's newest commit (ms). Only page URLs under
/// the catalog's own base are kept.
pub fn nuget_pages(index: &str, after: i64) -> Result<(Vec<(i64, String)>, i64)> {
    let v: Value = serde_json::from_str(index).context("NuGet catalog index: not JSON")?;
    let newest = v
        .get("commitTimeStamp")
        .and_then(Value::as_str)
        .and_then(ms_of)
        .context("NuGet catalog index: no commitTimeStamp")?;
    let items = v
        .get("items")
        .and_then(Value::as_array)
        .context("NuGet catalog index: no `items` array")?;
    let mut pages: Vec<(i64, String)> = items
        .iter()
        .filter_map(|p| {
            let url = p.get("@id")?.as_str()?;
            let ms = ms_of(p.get("commitTimeStamp")?.as_str()?)?;
            (ms > after && url.starts_with(NUGET_PAGES) && url.ends_with(".json"))
                .then(|| (ms, url.to_string()))
        })
        .collect();
    pages.sort();
    Ok((pages, newest))
}

/// Platform events from one catalog page: packages pushed or changed after
/// `after` (ms) whose names follow a template, the items read, and the
/// newest commit (ms). Deletes are not kept.
pub fn nuget_events(page: &str, after: i64) -> Result<(Vec<PlatformEvent>, usize, Option<i64>)> {
    let v: Value = serde_json::from_str(page).context("NuGet catalog page: not JSON")?;
    let items = v
        .get("items")
        .and_then(Value::as_array)
        .context("NuGet catalog page: no `items` array")?;
    let (mut out, mut read, mut newest) = (Vec::new(), 0, None);
    for it in items {
        let s = |k: &str| it.get(k).and_then(Value::as_str);
        let (Some(id), Some(version), Some(ms)) = (
            s("nuget:id"),
            s("nuget:version"),
            s("commitTimeStamp").and_then(ms_of),
        ) else {
            continue;
        };
        if ms <= after {
            continue;
        }
        read += 1;
        newest = Some(newest.map_or(ms, |n: i64| n.max(ms)));
        if s("@type") != Some("nuget:PackageDetails") {
            continue;
        }
        let Some(template) = name_template(id, "") else {
            continue;
        };
        out.push(PlatformEvent {
            id: format!("nuget:{}@{version}", id.to_ascii_lowercase()),
            platform: Platform::Nuget,
            action: Action::PackagePublished,
            ts: ms / 1000,
            target: id.to_ascii_lowercase(),
            link: format!("https://www.nuget.org/packages/{id}/{version}"),
            name_template: Some(template),
            ..Default::default()
        });
    }
    Ok((out, read, newest))
}

fn pull_nuget(
    client: &Client,
    q: &CdxQuery,
    mark: Option<u64>,
    max: usize,
) -> Result<PlatformPull> {
    let index = client.get(NUGET_INDEX).context("NuGet catalog index")?;
    let (_, newest) = nuget_pages(&index, i64::MAX)?;
    let (start, skipped) = start_at(mark.map(|m| m as i64), newest);
    let (pages, _) = nuget_pages(&index, start)?;
    let budget = q.scan.unwrap_or(DEFAULT_NUGET_PAGES).clamp(1, 50);
    let mut out = PlatformPull::default();
    let (mut reached, mut items) = (start, 0usize);
    for (i, (commit, url)) in pages.iter().enumerate() {
        if i >= budget || out.events.len() >= max {
            break;
        }
        let body = match client.get(url) {
            Ok(b) => b,
            Err(e) if i == 0 => return Err(e),
            Err(_) => break,
        };
        let (events, n, _) = nuget_events(&body, start)?;
        items += n;
        out.events.extend(events);
        // A page is read whole, so the next pull starts after its newest commit.
        reached = *commit;
    }
    if pages.is_empty() {
        reached = newest;
    }
    out.capped = out.events.len().saturating_sub(max);
    out.events.truncate(max);
    out.coverage = minutes(
        start,
        reached,
        newest,
        skipped,
        items > 0 || pages.is_empty(),
    );
    out.coverage.next = Some(reached.max(0) as u64);
    Ok(out)
}

// ── Packagist ──────────────────────────────────────────────────────────────

/// What one change-feed response held.
#[derive(Debug, Default)]
pub struct PackagistChanges {
    pub events: Vec<PlatformEvent>,
    /// Actions read.
    pub actions: usize,
    /// The feed asked for a full resync: the checkpoint was too old.
    pub resync: bool,
    /// The feed's timestamp to pass back as `since` (ten-thousandths of a second).
    pub timestamp: Option<u64>,
}

/// Platform events from a Packagist change feed response: one per package
/// updated, the newest change of each, dev branches folded into their
/// package.
pub fn packagist_events(body: &str) -> Result<PackagistChanges> {
    let v: Value = serde_json::from_str(body).context("Packagist changes: not JSON")?;
    let mut out = PackagistChanges {
        timestamp: v.get("timestamp").and_then(Value::as_u64),
        ..Default::default()
    };
    let Some(actions) = v.get("actions").and_then(Value::as_array) else {
        if let Some(e) = v.get("error").and_then(Value::as_str) {
            bail!("Packagist changes: {e}");
        }
        bail!("Packagist changes: no `actions` array");
    };
    let mut seen = BTreeSet::new();
    // Newest last in the feed: walk back so each package keeps its newest change.
    for a in actions.iter().rev() {
        out.actions += 1;
        let s = |k: &str| a.get(k).and_then(Value::as_str);
        match s("type") {
            Some("resync") => {
                out.resync = true;
                continue;
            }
            Some("update") => {}
            _ => continue,
        }
        let (Some(pkg), Some(time)) = (s("package"), a.get("time").and_then(Value::as_i64)) else {
            continue;
        };
        let pkg = pkg.trim_end_matches("~dev").to_ascii_lowercase();
        let Some((vendor, name)) = pkg.split_once('/') else {
            continue;
        };
        if !seen.insert(pkg.clone()) {
            continue;
        }
        if is_automation(vendor) {
            out.events.push(PlatformEvent::default());
            continue;
        }
        out.events.push(PlatformEvent {
            id: format!("packagist:{pkg}@{time}"),
            platform: Platform::Packagist,
            action: Action::PackagePublished,
            ts: time,
            actor: actor_key(Platform::Packagist, vendor),
            target: pkg.clone(),
            link: format!("https://packagist.org/packages/{pkg}"),
            name_template: name_template(name, vendor),
            ..Default::default()
        });
    }
    out.events.reverse();
    Ok(out)
}

fn pull_packagist(client: &Client, mark: Option<u64>, max: usize) -> Result<PlatformPull> {
    let now_ms = crate::client::now_secs() * 1000;
    let fresh = now_ms - FRESH_MS;
    let (since, since_ms, skipped) = match mark {
        Some(m) if (m / 10) as i64 >= now_ms - PACKAGIST_KEEP_MS => (m, (m / 10) as i64, 0),
        Some(m) => ((fresh * 10) as u64, fresh, (fresh - (m / 10) as i64).max(0)),
        None => ((fresh * 10) as u64, fresh, 0),
    };
    let body = client.get(&format!("{PACKAGIST}?since={since}"))?;
    let ch = packagist_events(&body)?;
    let until = ch.timestamp.map_or(now_ms, |t| (t / 10) as i64);
    let gap = if ch.resync { until - since_ms } else { 0 };
    let (mut events, automation) = split_automation(ch.events);
    let capped = events.len().saturating_sub(max);
    events.truncate(max);
    let mut coverage = minutes(
        since_ms,
        if ch.resync { since_ms } else { until },
        until,
        skipped + gap,
        ch.timestamp.is_some(),
    );
    coverage.next = ch.timestamp.or(Some(since));
    Ok(PlatformPull {
        events,
        coverage,
        automation,
        capped,
        ..Default::default()
    })
}

// ── RubyGems ───────────────────────────────────────────────────────────────

/// Platform events from a RubyGems activity listing, and the gems it held.
pub fn rubygems_events(body: &str, rules: &Rules) -> Result<(Vec<PlatformEvent>, usize)> {
    let v: Value = serde_json::from_str(body).context("RubyGems activity: not JSON")?;
    let gems = v.as_array().context("RubyGems activity: not an array")?;
    let mut out = Vec::new();
    for g in gems {
        let s = |k: &str| g.get(k).and_then(Value::as_str);
        let (Some(name), Some(version)) = (s("name"), s("version")) else {
            continue;
        };
        let authors = s("authors").unwrap_or("").trim();
        if is_automation(authors) {
            out.push(PlatformEvent::default());
            continue;
        }
        out.push(
            PlatformEvent {
                id: format!("gem:{name}@{version}"),
                platform: Platform::Rubygems,
                action: Action::PackagePublished,
                ts: s("version_created_at").and_then(parse_date).unwrap_or(0),
                actor: if authors.is_empty() {
                    String::new()
                } else {
                    actor_key(Platform::Rubygems, &authors.to_lowercase())
                },
                target: name.to_string(),
                link: format!("https://rubygems.org/gems/{name}/versions/{version}"),
                name_template: name_template(name, ""),
                ..Default::default()
            }
            .with_text(s("info").unwrap_or(""), &[name, authors], rules),
        );
    }
    Ok((out, gems.len()))
}

// ── crates.io ──────────────────────────────────────────────────────────────

/// The account a declared repository stands for: `<host>/<owner>` on the
/// code hosts that put the owner first in the path.
fn repo_owner(repo: &str) -> Option<(String, String)> {
    let u = url::Url::parse(repo).ok()?;
    let host = u
        .host_str()?
        .trim_start_matches("www.")
        .to_ascii_lowercase();
    if !matches!(
        host.as_str(),
        "github.com" | "gitlab.com" | "codeberg.org" | "bitbucket.org" | "sr.ht" | "git.sr.ht"
    ) {
        return None;
    }
    let owner = u
        .path_segments()?
        .find(|s| !s.is_empty())?
        .to_ascii_lowercase();
    Some((host, owner.trim_start_matches('~').to_string()))
}

/// What one crates.io listing page held.
#[derive(Debug, Default)]
pub struct CratesPage {
    pub events: Vec<PlatformEvent>,
    pub crates: usize,
    /// The oldest creation time on the page (ms).
    pub oldest: Option<i64>,
    /// The newest creation time on the page (ms).
    pub newest: Option<i64>,
    /// The next page's query (`?sort=new&...&seek=...`).
    pub next: Option<String>,
}

/// Platform events from a crates.io listing page: crates created after
/// `after` (ms).
pub fn crates_events(body: &str, after: i64, rules: &Rules) -> Result<CratesPage> {
    let v: Value = serde_json::from_str(body).context("crates.io listing: not JSON")?;
    let list = v
        .get("crates")
        .and_then(Value::as_array)
        .context("crates.io listing: no `crates` array")?;
    let mut out = CratesPage {
        crates: list.len(),
        next: v
            .pointer("/meta/next_page")
            .and_then(Value::as_str)
            .filter(|n| n.starts_with('?'))
            .map(str::to_string),
        ..Default::default()
    };
    for c in list {
        let s = |k: &str| c.get(k).and_then(Value::as_str);
        let (Some(name), Some(ms)) = (s("name"), s("created_at").and_then(ms_of)) else {
            continue;
        };
        out.oldest = Some(out.oldest.map_or(ms, |o: i64| o.min(ms)));
        out.newest = Some(out.newest.map_or(ms, |o: i64| o.max(ms)));
        if ms <= after {
            continue;
        }
        let version = s("newest_version")
            .or_else(|| s("max_version"))
            .unwrap_or("0");
        let owner = s("repository").and_then(repo_owner);
        if owner.as_ref().is_some_and(|(_, o)| is_automation(o)) {
            out.events.push(PlatformEvent::default());
            continue;
        }
        let owner_name = owner.as_ref().map_or("", |(_, o)| o.as_str());
        out.events.push(
            PlatformEvent {
                id: format!("crate:{name}@{version}"),
                platform: Platform::Crates,
                action: Action::PackagePublished,
                ts: ms / 1000,
                actor: owner
                    .as_ref()
                    .map(|(h, o)| actor_key(Platform::Crates, &format!("{h}/{o}")))
                    .unwrap_or_default(),
                target: name.to_string(),
                link: format!("https://crates.io/crates/{name}/{version}"),
                name_template: name_template(name, owner_name),
                ..Default::default()
            }
            .with_text(s("description").unwrap_or(""), &[name, owner_name], rules),
        );
    }
    Ok(out)
}

fn pull_crates(
    client: &Client,
    q: &CdxQuery,
    mark: Option<u64>,
    rules: &Rules,
    max: usize,
) -> Result<PlatformPull> {
    let now_ms = crate::client::now_secs() * 1000;
    let (start, skipped) = start_at(mark.map(|m| m as i64), now_ms);
    let budget = q.scan.unwrap_or(DEFAULT_CRATES_PAGES).clamp(1, 20);
    let mut out = PlatformPull::default();
    let mut query = "?sort=new&per_page=100".to_string();
    let (mut newest, mut reached, mut crates) = (None::<i64>, now_ms, 0usize);
    let mut done = false;
    for i in 0..budget {
        let body = match client.get(&format!("{CRATES}{query}")) {
            Ok(b) => b,
            Err(e) if i == 0 => return Err(e),
            Err(_) => break,
        };
        let page = crates_events(&body, start, rules)?;
        crates += page.crates;
        newest = newest.max(page.newest);
        out.events.extend(page.events);
        reached = page.oldest.unwrap_or(start);
        match page.next {
            Some(n) if reached > start && out.events.len() < max => query = n,
            _ => {
                done = true;
                break;
            }
        }
    }
    let (mut events, automation) = split_automation(std::mem::take(&mut out.events));
    out.capped = events.len().saturating_sub(max);
    events.truncate(max);
    out.events = events;
    out.automation = automation;
    // Read from `reached` up to now; what lies between the checkpoint and
    // `reached` was not reached when the pages ran out.
    let gap = if done { 0 } else { (reached - start).max(0) };
    out.coverage = minutes(start, now_ms - gap, now_ms, skipped, crates > 0);
    out.coverage.skipped += (gap / 60_000) as u64;
    out.coverage.next = Some(newest.unwrap_or(start).max(start).max(0) as u64);
    Ok(out)
}

/// Pull one of this module's registries (`nuget`, `packagist`, `rubygems`,
/// `crates`); `None` for another kind.
pub(crate) fn pull(
    client: &Client,
    kind: &str,
    q: &CdxQuery,
    mark: Option<u64>,
    rules: &Rules,
    max: usize,
) -> Option<Result<PlatformPull>> {
    Some(match kind {
        "nuget" => pull_nuget(client, q, mark, max),
        "packagist" => pull_packagist(client, mark, max),
        "rubygems" => (|| {
            let what = match q.endpoint.as_deref().unwrap_or("latest") {
                w @ ("latest" | "just_updated") => w,
                w => bail!("unknown RubyGems listing `{w}` (expected latest or just_updated)"),
            };
            let body = client.get(&format!("https://rubygems.org/api/v1/activity/{what}.json"))?;
            let (events, n) = rubygems_events(&body, rules)?;
            let (events, automation) = split_automation(events);
            Ok(PlatformPull {
                events,
                automation,
                coverage: Coverage {
                    unit: "items",
                    read: n as u64,
                    available: n as u64,
                    canary: Some(n > 0),
                    ..Default::default()
                },
                ..Default::default()
            })
        })(),
        "crates" => pull_crates(client, q, mark, rules, max),
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // Every package, owner and text below is invented.

    #[test]
    fn nuget_reads_pages_after_the_checkpoint() {
        let index = r#"{"commitTimeStamp":"2026-10-13T18:15:15.8291006Z","count":3,"items":[
          {"@id":"https://api.nuget.org/v3/catalog0/page2.json","commitTimeStamp":"2026-10-13T18:15:15.8291006Z","count":3},
          {"@id":"https://api.nuget.org/v3/catalog0/page0.json","commitTimeStamp":"2026-10-12T01:00:00Z","count":550},
          {"@id":"https://elsewhere.example/page1.json","commitTimeStamp":"2026-10-13T12:00:00Z","count":550},
          {"@id":"https://api.nuget.org/v3/catalog0/page1.json","commitTimeStamp":"2026-10-13T12:00:00Z","count":550}
        ]}"#;
        let after = ms_of("2026-10-13T00:00:00Z").unwrap();
        let (pages, newest) = nuget_pages(index, after).unwrap();
        assert_eq!(newest, ms_of("2026-10-13T18:15:15.8291006Z").unwrap());
        let urls: Vec<&str> = pages.iter().map(|p| p.1.as_str()).collect();
        assert_eq!(
            urls,
            [
                "https://api.nuget.org/v3/catalog0/page1.json",
                "https://api.nuget.org/v3/catalog0/page2.json"
            ]
        );
        let page = r#"{"items":[
          {"@type":"nuget:PackageDetails","commitTimeStamp":"2026-10-13T18:15:15Z","nuget:id":"Probe.Agent0042","nuget:version":"0.0.1"},
          {"@type":"nuget:PackageDetails","commitTimeStamp":"2026-10-13T18:15:15Z","nuget:id":"Microsoft.Extensions.Logging","nuget:version":"8.0.32"},
          {"@type":"nuget:PackageDelete","commitTimeStamp":"2026-10-13T18:15:15Z","nuget:id":"Probe.Agent0043","nuget:version":"0.0.1"},
          {"@type":"nuget:PackageDetails","commitTimeStamp":"2026-10-12T00:00:00Z","nuget:id":"Probe.Agent0001","nuget:version":"0.0.1"}
        ]}"#;
        let (ev, read, last) = nuget_events(page, after).unwrap();
        assert_eq!((ev.len(), read), (1, 3));
        assert_eq!(ev[0].id, "nuget:probe.agent0042@0.0.1");
        assert_eq!(ev[0].name_template.as_deref(), Some("probe-<id>"));
        assert_eq!(
            ev[0].link,
            "https://www.nuget.org/packages/Probe.Agent0042/0.0.1"
        );
        assert!(ev[0].actor.is_empty());
        assert_eq!(last, ms_of("2026-10-13T18:15:15Z"));
        assert!(nuget_pages("{}", 0).is_err());
    }

    #[test]
    fn packagist_folds_dev_branches_and_hashes_vendors() {
        let body = r#"{"actions":[
          {"type":"update","package":"probe-vendor\/reach-check-0007~dev","time":1791914796},
          {"type":"update","package":"probe-vendor\/reach-check-0007","time":1791914800},
          {"type":"update","package":"probe-vendor\/reach-check-0008","time":1791914805},
          {"type":"delete","package":"gone\/pkg","time":1791914806}
        ],"timestamp":17919153710011}"#;
        let ch = packagist_events(body).unwrap();
        assert_eq!((ch.actions, ch.events.len(), ch.resync), (4, 2, false));
        assert_eq!(ch.timestamp, Some(17_919_153_710_011));
        let e = &ch.events[0];
        assert_eq!(e.id, "packagist:probe-vendor/reach-check-0007@1791914800");
        assert_eq!(e.name_template.as_deref(), Some("reach-check-<num>"));
        assert_eq!(e.actor, ch.events[1].actor);
        assert!(
            !serde_json::to_string(e)
                .unwrap()
                .contains("\"actor\":\"probe")
        );
        let r = packagist_events(
            r#"{"actions":[{"type":"resync","time":1,"package":"*"}],"timestamp":5}"#,
        )
        .unwrap();
        assert!(r.resync && r.events.is_empty());
        assert!(packagist_events(r#"{"error":"Invalid since","timestamp":5}"#).is_err());
    }

    #[test]
    fn rubygems_and_crates_listings() {
        let rules = Rules::default_rules();
        let gems = r#"[
          {"name":"probe-kit-17","version":"0.1.0","version_created_at":"2026-10-13T18:02:54.879Z","authors":"Probe Author","info":"A probe kit for checking reach across many sites at once"},
          {"name":"x","version":"1.0.0","authors":"dependabot"}
        ]"#;
        let (ev, n) = rubygems_events(gems, &rules).unwrap();
        assert_eq!((n, ev.len()), (2, 2));
        let (ev, dropped) = split_automation(ev);
        assert_eq!((ev.len(), dropped), (1, 1));
        assert_eq!(ev[0].name_template.as_deref(), Some("probe-kit-<num>"));
        assert!(ev[0].text.is_some());
        assert!(
            !serde_json::to_string(&ev[0])
                .unwrap()
                .contains("Probe Author")
        );

        let list = r#"{"crates":[
          {"name":"agent_probe_0042","created_at":"2026-10-13T18:13:40.546040Z","newest_version":"0.1.0","description":"Probe crate","repository":"https://github.com/probe-owner/agent_probe_0042"},
          {"name":"agent_probe_0043","created_at":"2026-10-13T18:12:00Z","newest_version":"0.1.0","description":null,"repository":"https://github.com/Probe-Owner/x"},
          {"name":"old_crate","created_at":"2026-10-01T00:00:00Z","newest_version":"1.0.0","repository":null}
        ],"meta":{"next_page":"?sort=new&per_page=100&seek=abc"}}"#;
        let after = ms_of("2026-10-13T00:00:00Z").unwrap();
        let p = crates_events(list, after, &rules).unwrap();
        assert_eq!((p.crates, p.events.len()), (3, 2));
        assert_eq!(p.next.as_deref(), Some("?sort=new&per_page=100&seek=abc"));
        assert_eq!(p.oldest, ms_of("2026-10-01T00:00:00Z"));
        assert_eq!(p.events[0].actor, p.events[1].actor);
        assert!(p.events[0].actor.starts_with("acct:"));
        assert_eq!(
            p.events[0].name_template.as_deref(),
            Some("agent-probe-<num>")
        );
        assert_eq!(
            p.events[0].link,
            "https://crates.io/crates/agent_probe_0042/0.1.0"
        );
        assert_eq!(repo_owner("https://example.org/a/b"), None);
    }

    #[test]
    fn checkpoints_and_coverage() {
        let now = 1_791_915_000_000;
        assert_eq!(start_at(None, now), (now - FRESH_MS, 0));
        assert_eq!(start_at(Some(now - 3_600_000), now), (now - 3_600_000, 0));
        let (s, skipped) = start_at(Some(now - 30 * 3_600_000), now);
        assert_eq!((s, skipped), (now - FRESH_MS, 24 * 3_600_000));
        let c = minutes(now - 3_600_000, now - 1_800_000, now, 0, true);
        assert_eq!((c.read, c.available), (30, 60));
    }
}
