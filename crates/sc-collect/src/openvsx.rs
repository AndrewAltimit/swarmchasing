//! Open VSX (`open-vsx.org`), the open registry of editor extensions: its
//! newest extensions (`GET /api/-/search?sortBy=timestamp&sortOrder=desc`)
//! as platform events, for fleets of extensions published in a burst under
//! templated names by one namespace or many.
//!
//! Search metadata only: namespace, name, version, publish time, the
//! publisher-verified flag and the description, which is sketched. The
//! `files` the listing links (the `.vsix` download, signature, icon) are
//! never fetched, and no URL in a listing is. One page of `page_size`
//! extensions a run; the checkpoint is the newest publish time read (ms),
//! and extensions at or before it are not kept again. When the page does
//! not reach back to the checkpoint, the span it missed counts as skipped.
//!
//! Terms: the Eclipse Foundation's terms of use
//! (<https://www.eclipse.org/legal/terms-of-use/>) say nothing of automated
//! access, and the service rate-limits by tier. The watchlist entry stays
//! off until the Eclipse Foundation confirms automated listing reads are
//! welcome.

use crate::platform::PlatformPull;
use crate::registries::{minutes, ms_of, split_automation, start_at};
use crate::{CdxQuery, Client};
use anyhow::{Context, Result};
use sc_core::Rules;
use sc_core::platform::automation::is_automation;
use sc_core::platform::{Action, Platform, PlatformEvent, actor_key, name_template};
use serde_json::Value;

const SEARCH: &str = "https://open-vsx.org/api/-/search";
/// Most extensions one request asks for.
const MAX_PAGE: usize = 100;

/// What one search page held.
#[derive(Debug, Default)]
pub struct VsxPage {
    /// Extensions published after the checkpoint (automation namespaces as
    /// empty events).
    pub events: Vec<PlatformEvent>,
    /// Extensions on the page.
    pub read: usize,
    /// Of the kept events, how many come from a verified publisher.
    pub verified: usize,
    /// The oldest and newest publish times on the page (ms).
    pub oldest: Option<i64>,
    pub newest: Option<i64>,
}

/// Platform events from an Open VSX search response: extensions published
/// after `after` (ms). The namespace stands for the account, as a keyed
/// hash.
pub fn openvsx_events(body: &str, after: i64, rules: &Rules) -> Result<VsxPage> {
    let v: Value = serde_json::from_str(body).context("Open VSX search: not JSON")?;
    let list = v
        .get("extensions")
        .and_then(Value::as_array)
        .context("Open VSX search: no `extensions` array")?;
    let mut out = VsxPage {
        read: list.len(),
        ..Default::default()
    };
    for x in list {
        let s = |k: &str| x.get(k).and_then(Value::as_str).map(str::trim);
        let (Some(ns), Some(name), Some(version), Some(ms)) = (
            s("namespace").filter(|n| !n.is_empty()),
            s("name").filter(|n| !n.is_empty()),
            s("version"),
            s("timestamp").and_then(ms_of),
        ) else {
            continue;
        };
        out.oldest = Some(out.oldest.map_or(ms, |o: i64| o.min(ms)));
        out.newest = Some(out.newest.map_or(ms, |o: i64| o.max(ms)));
        if ms <= after {
            continue;
        }
        let ns = ns.to_ascii_lowercase();
        if is_automation(&ns) {
            out.events.push(PlatformEvent::default());
            continue;
        }
        if x.get("verified").and_then(Value::as_bool) == Some(true) {
            out.verified += 1;
        }
        let text = format!(
            "{}\n{}",
            s("displayName").unwrap_or(""),
            s("description").unwrap_or("")
        );
        out.events.push(
            PlatformEvent {
                id: format!("openvsx:{ns}.{name}@{version}"),
                platform: Platform::OpenVsx,
                action: Action::PackagePublished,
                ts: ms / 1000,
                actor: actor_key(Platform::OpenVsx, &ns),
                target: format!("{ns}.{name}"),
                link: format!("https://open-vsx.org/extension/{ns}/{name}/{version}"),
                name_template: name_template(name, &ns),
                ..Default::default()
            }
            .with_text(&text, &[name, &ns], rules),
        );
    }
    Ok(out)
}

/// The platform pass's pull: one page of the newest extensions.
pub(crate) fn pull_platform(
    client: &Client,
    q: &CdxQuery,
    mark: Option<u64>,
    rules: &Rules,
    max: usize,
) -> Result<PlatformPull> {
    let size = q.page_size.clamp(1, MAX_PAGE);
    let body = client
        .get(&format!(
            "{SEARCH}?sortBy=timestamp&sortOrder=desc&size={size}&offset=0"
        ))
        .context("Open VSX search")?;
    let now_ms = crate::client::now_secs() * 1000;
    one_page(&body, mark, now_ms, rules, max)
}

/// [`pull_platform`] once the page is in hand.
fn one_page(
    body: &str,
    mark: Option<u64>,
    now_ms: i64,
    rules: &Rules,
    max: usize,
) -> Result<PlatformPull> {
    let (start, skipped) = start_at(mark.map(|m| m as i64), now_ms);
    let page = openvsx_events(body, start, rules)?;
    let (mut events, automation) = split_automation(page.events);
    let capped = events.len().saturating_sub(max);
    events.truncate(max);
    // A full page that ends after the checkpoint missed what lies between.
    let reached = page.oldest.unwrap_or(start);
    let gap = if page.read > 0 && reached > start {
        reached - start
    } else {
        0
    };
    let mut coverage = minutes(start, now_ms - gap, now_ms, skipped, page.read > 0);
    coverage.skipped += (gap / 60_000) as u64;
    coverage.next = Some(page.newest.unwrap_or(start).max(start).max(0) as u64);
    Ok(PlatformPull {
        events,
        automation,
        capped,
        coverage,
        ..Default::default()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> String {
        let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/openvsx/search.json");
        std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))
    }

    #[test]
    fn newest_extensions_become_events_without_touching_files() {
        let rules = Rules::default_rules();
        let after = ms_of("2026-10-14T12:00:00Z").unwrap();
        let p = openvsx_events(&fixture(), after, &rules).unwrap();
        assert_eq!((p.read, p.events.len(), p.verified), (4, 3, 1));
        let (ev, automation) = split_automation(p.events);
        assert_eq!((ev.len(), automation), (2, 1));
        let e = &ev[0];
        assert_eq!(e.id, "openvsx:probe-ns.agent-probe-0042@0.0.1");
        assert_eq!(e.platform, Platform::OpenVsx);
        assert_eq!(e.name_template.as_deref(), Some("agent-probe-<num>"));
        assert_eq!(
            e.link,
            "https://open-vsx.org/extension/probe-ns/agent-probe-0042/0.0.1"
        );
        assert_eq!(e.actor, ev[1].actor);
        let json = serde_json::to_string(e).unwrap();
        assert!(!json.contains(".vsix"), "{json}");
        assert!(!json.contains("\"actor\":\"probe-ns"), "{json}");
        assert!(openvsx_events("{}", 0, &rules).is_err());
    }

    #[test]
    fn a_page_short_of_the_checkpoint_counts_the_rest_as_skipped() {
        let rules = Rules::default_rules();
        let now = ms_of("2026-10-14T13:00:00Z").unwrap();
        // The checkpoint at 11:00; the page reaches back to 11:50.
        let mark = ms_of("2026-10-14T11:00:00Z").unwrap() as u64;
        let out = one_page(&fixture(), Some(mark), now, &rules, 100).unwrap();
        assert_eq!(out.coverage.skipped, 50);
        assert_eq!(out.coverage.read, 70);
        assert_eq!(
            out.coverage.next,
            ms_of("2026-10-14T12:37:30.335018Z").map(|m| m as u64)
        );
        // The checkpoint inside the page: nothing skipped, older ones dropped.
        let mark = ms_of("2026-10-14T12:30:00Z").unwrap() as u64;
        let out = one_page(&fixture(), Some(mark), now, &rules, 100).unwrap();
        assert_eq!(out.coverage.skipped, 0);
        assert_eq!(out.events.len(), 1);
    }
}
