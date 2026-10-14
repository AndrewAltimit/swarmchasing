//! Code hosts beside GitHub for the platform pass: GitLab.com's and
//! Codeberg's newest public projects, as repositories created. Listing
//! metadata only: the project's path, owner, description and creation
//! time. No repository, page or URL in a description is fetched.
//!
//! - **GitLab.com** (`gitlab`): `api/v4/projects?visibility=public&simple=true`,
//!   newest first by creation, a hundred a page, anonymous. The top-level
//!   namespace (`<namespace>/<project>`) stands for the account, as a keyed
//!   hash. The listing gives no account age.
//! - **Codeberg** (`codeberg`): Forgejo's `api/v1/repos/search`, newest
//!   first by creation, fifty a page (the instance's maximum), anonymous.
//!   The owner's login stands for the account, as a keyed hash, and the
//!   owner's account creation time, which the listing carries, becomes a
//!   rank in units of [`RANK_SECS`] (a thousand ranks to ten days), as on
//!   a wiki. The owner's other fields (name, email, avatar) are not kept.
//!
//! Both page back from the newest project to the checkpoint (the newest
//! creation time read, in ms), at most `scan` pages and until the event cap;
//! what the pages did not reach is counted as skipped. Without a checkpoint
//! a pull starts [`FRESH_MS`](crate::registries::FRESH_MS) back; a
//! checkpoint older than
//! [`MAX_BACKLOG_MS`](crate::registries::MAX_BACKLOG_MS) is skipped to
//! there and the gap counted. Coverage is in minutes of creation time;
//! projects parsed are the canary. A project with neither a templated name
//! nor a description gives the detector nothing to group and is dropped,
//! as on GitHub.
//!
//! Terms: GitLab's Acceptable Use Policy
//! (<https://handbook.gitlab.com/handbook/legal/acceptable-use-policy/>)
//! forbids disrupting the service and collecting users' personal data;
//! GitLab.com's rate limits (<https://docs.gitlab.com/user/gitlab_com/>)
//! allow anonymous API callers hundreds of requests a minute. Codeberg's
//! Terms of Use (<https://codeberg.org/codeberg/org/src/branch/main/TermsOfUse.md>)
//! govern content and forbid doxxing; its API answers with a rate-limit
//! policy of 2000 requests per ten minutes. A few paced listing requests a
//! run, keeping keyed hashes, sketches and times, stay well inside both.

use crate::hackernews::RANK_SECS;
use crate::platform::PlatformPull;
use crate::registries::{minutes, ms_of, split_automation, start_at};
use crate::{CdxQuery, Client};
use anyhow::{Context, Result};
use sc_core::Rules;
use sc_core::platform::automation::is_automation;
use sc_core::platform::{Action, Platform, PlatformEvent, actor_key, name_template};
use serde_json::Value;
use std::collections::BTreeSet;

const GITLAB: &str = "https://gitlab.com/api/v4/projects?order_by=created_at&sort=desc&visibility=public&simple=true&per_page=100&page=";
const CODEBERG: &str =
    "https://codeberg.org/api/v1/repos/search?sort=created&order=desc&limit=50&page=";
/// Listing pages one pull reads unless `scan` says otherwise.
const DEFAULT_PAGES: usize = 3;

/// What one listing page held.
#[derive(Debug, Default)]
pub struct ListingPage {
    pub events: Vec<PlatformEvent>,
    /// Projects on the page.
    pub projects: usize,
    /// The oldest and newest creation times on the page (ms).
    pub oldest: Option<i64>,
    pub newest: Option<i64>,
}

impl ListingPage {
    fn saw(&mut self, ms: i64) {
        self.oldest = Some(self.oldest.map_or(ms, |o| o.min(ms)));
        self.newest = Some(self.newest.map_or(ms, |o| o.max(ms)));
    }
}

/// A repository created, or `None` when it gives the detector nothing to
/// group. An automation owner gives the empty event that marks a drop.
#[allow(clippy::too_many_arguments)]
fn repo_event(
    platform: Platform,
    id: String,
    ms: i64,
    owner: &str,
    path: &str,
    link: String,
    description: &str,
    rank: Option<u64>,
    rules: &Rules,
) -> Option<PlatformEvent> {
    if is_automation(owner) {
        return Some(PlatformEvent::default());
    }
    let owner = owner.to_ascii_lowercase();
    let name = path.rsplit('/').next().unwrap_or(path);
    let e = PlatformEvent {
        id,
        platform,
        action: Action::RepoCreated,
        ts: ms / 1000,
        actor: actor_key(platform, &owner),
        actor_rank: rank,
        target: path.to_string(),
        link,
        name_template: name_template(name, &owner),
        ..Default::default()
    }
    .with_text(description, &[&owner, name], rules);
    (e.name_template.is_some() || e.text.is_some()).then_some(e)
}

/// Platform events from a GitLab.com projects page: projects created after
/// `after` (ms).
pub fn gitlab_events(body: &str, after: i64, rules: &Rules) -> Result<ListingPage> {
    let v: Value = serde_json::from_str(body).context("GitLab projects: not JSON")?;
    let list = v.as_array().context("GitLab projects: not an array")?;
    let mut out = ListingPage {
        projects: list.len(),
        ..Default::default()
    };
    for p in list {
        let s = |k: &str| p.pointer(k).and_then(Value::as_str);
        let (Some(id), Some(path), Some(ms)) = (
            p.get("id").and_then(Value::as_u64),
            s("/path_with_namespace"),
            s("/created_at").and_then(ms_of),
        ) else {
            continue;
        };
        out.saw(ms);
        if ms <= after {
            continue;
        }
        let owner = path.split('/').next().unwrap_or("");
        let link = s("/web_url")
            .filter(|u| u.starts_with("https://gitlab.com/"))
            .map_or_else(|| format!("https://gitlab.com/{path}"), str::to_string);
        out.events.extend(repo_event(
            Platform::Gitlab,
            format!("gitlab:{id}"),
            ms,
            owner,
            path,
            link,
            s("/description").unwrap_or(""),
            None,
            rules,
        ));
    }
    Ok(out)
}

/// Platform events from a Codeberg repository search page: repositories
/// created after `after` (ms).
pub fn codeberg_events(body: &str, after: i64, rules: &Rules) -> Result<ListingPage> {
    let v: Value = serde_json::from_str(body).context("Codeberg search: not JSON")?;
    let list = v
        .get("data")
        .and_then(Value::as_array)
        .context("Codeberg search: no `data` array")?;
    let mut out = ListingPage {
        projects: list.len(),
        ..Default::default()
    };
    for r in list {
        let s = |k: &str| r.pointer(k).and_then(Value::as_str);
        let (Some(id), Some(path), Some(owner), Some(ms)) = (
            r.get("id").and_then(Value::as_u64),
            s("/full_name"),
            s("/owner/login"),
            s("/created_at").and_then(ms_of),
        ) else {
            continue;
        };
        out.saw(ms);
        if ms <= after {
            continue;
        }
        let rank = s("/owner/created")
            .and_then(ms_of)
            .filter(|&c| c > 0)
            .map(|c| (c / 1000 / RANK_SECS) as u64);
        let link = s("/html_url")
            .filter(|u| u.starts_with("https://codeberg.org/"))
            .map_or_else(|| format!("https://codeberg.org/{path}"), str::to_string);
        out.events.extend(repo_event(
            Platform::Codeberg,
            format!("codeberg:{id}"),
            ms,
            owner,
            path,
            link,
            s("/description").unwrap_or(""),
            rank,
            rules,
        ));
    }
    Ok(out)
}

/// Page a listing back from the newest project to the checkpoint `mark`
/// (ms), at most `pages` pages. `fetch` answers one page number; `parse`
/// reads a page, keeping projects created after its second argument.
fn pull_listing(
    mark: Option<u64>,
    pages: usize,
    max: usize,
    now_ms: i64,
    fetch: &mut dyn FnMut(usize) -> Result<String>,
    parse: &dyn Fn(&str, i64) -> Result<ListingPage>,
) -> Result<PlatformPull> {
    let (start, skipped) = start_at(mark.map(|m| m as i64), now_ms);
    let mut out = PlatformPull::default();
    let mut ids = BTreeSet::new();
    let (mut newest, mut reached, mut projects) = (None::<i64>, now_ms, 0usize);
    let mut done = false;
    for page in 1..=pages.max(1) {
        let body = match fetch(page) {
            Ok(b) => b,
            Err(e) if page == 1 => return Err(e),
            Err(_) => break,
        };
        let p = parse(&body, start)?;
        projects += p.projects;
        newest = newest.max(p.newest);
        // A project created while the pull pages shifts the rest down a
        // place, so a page can repeat one already read.
        out.events.extend(
            p.events
                .into_iter()
                .filter(|e| e.id.is_empty() || ids.insert(e.id.clone())),
        );
        reached = p.oldest.unwrap_or(start);
        if p.projects == 0 || reached <= start {
            done = true;
            break;
        }
        // At the cap the pages left are not read: what lies between the
        // checkpoint and `reached` counts as skipped, as when pages run out.
        if out.events.len() >= max {
            break;
        }
    }
    let (mut events, automation) = split_automation(std::mem::take(&mut out.events));
    out.capped = events.len().saturating_sub(max);
    events.truncate(max);
    out.events = events;
    out.automation = automation;
    let gap = if done { 0 } else { (reached - start).max(0) };
    out.coverage = minutes(start, now_ms - gap, now_ms, skipped, projects > 0);
    out.coverage.skipped += (gap / 60_000) as u64;
    out.coverage.next = Some(newest.unwrap_or(start).max(start).max(0) as u64);
    Ok(out)
}

/// Pull one of this module's code hosts (`gitlab`, `codeberg`); `None` for
/// another kind.
pub(crate) fn pull(
    client: &Client,
    kind: &str,
    q: &CdxQuery,
    mark: Option<u64>,
    rules: &Rules,
    max: usize,
) -> Option<Result<PlatformPull>> {
    let base = match kind {
        "gitlab" => GITLAB,
        "codeberg" => CODEBERG,
        _ => return None,
    };
    let parse = |body: &str, after: i64| match kind {
        "gitlab" => gitlab_events(body, after, rules),
        _ => codeberg_events(body, after, rules),
    };
    let pages = q.scan.unwrap_or(DEFAULT_PAGES).clamp(1, 20);
    let now_ms = crate::client::now_secs() * 1000;
    Some(pull_listing(
        mark,
        pages,
        max,
        now_ms,
        &mut |page| client.get(&format!("{base}{page}")),
        &parse,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Every project, owner and text below is invented.

    const GL: &str = r#"[
      {"id":901,"description":"Probe scan workspace for checking reach","name":"temp scan probe-34881386","path":"probe-34881386","path_with_namespace":"probe-owner/probe-34881386","created_at":"2026-10-13T18:30:42.450Z","web_url":"https://gitlab.com/probe-owner/probe-34881386","namespace":{"id":5,"path":"probe-owner","kind":"user"}},
      {"id":900,"description":null,"name":"Probe","path":"probe-12234806","path_with_namespace":"Other-Owner/sub/probe-12234806","created_at":"2026-10-13T18:29:50Z","web_url":"https://elsewhere.example/x"},
      {"id":899,"description":null,"name":"x","path":"x","path_with_namespace":"dependabot/x","created_at":"2026-10-13T18:29:00Z"},
      {"id":10,"description":"old","path":"old-1","path_with_namespace":"a/old-1","created_at":"2026-10-01T00:00:00Z"}
    ]"#;

    const CB: &str = r#"{"ok":true,"data":[
      {"id":71,"owner":{"id":3,"login":"Probe-Owner","full_name":"Probe Person","email":"probe@noreply.example","created":"2026-10-13T17:00:00+02:00"},"name":"reach-check-0007","full_name":"Probe-Owner/reach-check-0007","description":"","html_url":"https://codeberg.org/Probe-Owner/reach-check-0007","created_at":"2026-10-13T20:19:26+02:00"},
      {"id":70,"owner":{"id":4,"login":"plain","created":"2020-01-01T00:00:00Z"},"name":"notes","full_name":"plain/notes","description":"","created_at":"2026-10-13T20:10:00+02:00"}
    ]}"#;

    #[test]
    fn gitlab_projects_become_repositories_created() {
        let rules = Rules::default_rules();
        let after = ms_of("2026-10-13T00:00:00Z").unwrap();
        let p = gitlab_events(GL, after, &rules).unwrap();
        assert_eq!(p.projects, 4);
        assert_eq!(p.oldest, ms_of("2026-10-01T00:00:00Z"));
        let (ev, dropped) = split_automation(p.events);
        assert_eq!((ev.len(), dropped), (2, 1));
        assert_eq!(ev[0].id, "gitlab:901");
        assert_eq!(ev[0].platform, Platform::Gitlab);
        assert_eq!(ev[0].action, Action::RepoCreated);
        assert_eq!(ev[0].target, "probe-owner/probe-34881386");
        assert_eq!(ev[0].name_template.as_deref(), Some("probe-<num>"));
        assert!(ev[0].text.is_some() && ev[0].actor_rank.is_none());
        // The top-level namespace is the account, whatever the case.
        assert_eq!(ev[1].actor, actor_key(Platform::Gitlab, "other-owner"));
        assert_eq!(
            ev[1].link,
            "https://gitlab.com/Other-Owner/sub/probe-12234806"
        );
        assert!(
            !serde_json::to_string(&ev[1])
                .unwrap()
                .contains("\"actor\":\"other")
        );
        assert!(gitlab_events("{}", 0, &rules).is_err());
    }

    #[test]
    fn codeberg_repositories_carry_the_owners_age() {
        let rules = Rules::default_rules();
        let after = ms_of("2026-10-13T00:00:00Z").unwrap();
        let p = codeberg_events(CB, after, &rules).unwrap();
        assert_eq!(p.projects, 2);
        // `plain/notes` has neither a templated name nor a description.
        assert_eq!(p.events.len(), 1);
        let e = &p.events[0];
        assert_eq!(e.id, "codeberg:71");
        assert_eq!(e.name_template.as_deref(), Some("reach-check-<num>"));
        let created = ms_of("2026-10-13T17:00:00+02:00").unwrap() / 1000;
        assert_eq!(e.actor_rank, Some((created / RANK_SECS) as u64));
        assert_eq!(e.actor, actor_key(Platform::Codeberg, "probe-owner"));
        let json = serde_json::to_string(e).unwrap();
        assert!(
            !json.contains("noreply") && !json.contains("Probe Person"),
            "{json}"
        );
        assert!(codeberg_events("[]", 0, &rules).is_err());
    }

    #[test]
    fn a_listing_pages_back_to_the_checkpoint() {
        let rules = Rules::default_rules();
        let now = ms_of("2026-10-13T19:00:00Z").unwrap();
        let mark = (now - 3_600_000) as u64;
        // Page one is all newer than the checkpoint; page two reaches it.
        let pages = [
            r#"[{"id":3,"description":"Probe scan","path":"probe-3","path_with_namespace":"o/probe-3","created_at":"2026-10-13T18:50:00Z"},
               {"id":2,"description":"Probe scan","path":"probe-2","path_with_namespace":"o/probe-2","created_at":"2026-10-13T18:40:00Z"}]"#,
            r#"[{"id":2,"description":"Probe scan","path":"probe-2","path_with_namespace":"o/probe-2","created_at":"2026-10-13T18:40:00Z"},
               {"id":1,"description":"Probe scan","path":"probe-1","path_with_namespace":"o/probe-1","created_at":"2026-10-13T17:00:00Z"}]"#,
        ];
        let mut asked = Vec::new();
        let parse = |b: &str, a: i64| gitlab_events(b, a, &rules);
        let out = pull_listing(
            Some(mark),
            5,
            100,
            now,
            &mut |p| {
                asked.push(p);
                Ok(pages[p - 1].to_string())
            },
            &parse,
        )
        .unwrap();
        assert_eq!(asked, [1, 2]);
        assert_eq!(out.events.len(), 2, "the repeat on page two is dropped");
        assert_eq!(
            (
                out.coverage.read,
                out.coverage.available,
                out.coverage.skipped
            ),
            (60, 60, 0)
        );
        assert_eq!(
            out.coverage.next,
            ms_of("2026-10-13T18:50:00Z").map(|m| m as u64)
        );
        // Out of pages before the checkpoint: the rest is skipped.
        let out = pull_listing(
            Some(mark),
            1,
            100,
            now,
            &mut |_| Ok(pages[0].to_string()),
            &parse,
        )
        .unwrap();
        assert_eq!((out.coverage.read, out.coverage.skipped), (20, 40));
        // At the event cap before the checkpoint: page two is not read, and
        // what it would have covered is skipped, not claimed as read.
        let mut asked = Vec::new();
        let out = pull_listing(
            Some(mark),
            5,
            2,
            now,
            &mut |p| {
                asked.push(p);
                Ok(pages[p - 1].to_string())
            },
            &parse,
        )
        .unwrap();
        assert_eq!(asked, [1]);
        assert_eq!((out.coverage.read, out.coverage.skipped), (20, 40));
        assert_eq!(
            out.coverage.next,
            ms_of("2026-10-13T18:50:00Z").map(|m| m as u64)
        );
        // The first page failing is an error.
        assert!(pull_listing(None, 2, 100, now, &mut |_| anyhow::bail!("down"), &parse).is_err());
    }
}
