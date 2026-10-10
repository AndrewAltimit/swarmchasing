//! Incremental pulls: each source's cursor, the IDs still inside the overlap
//! window, and a resumable pull (Wayback, Common Crawl) that continues on the
//! next run. Records that carry an IP but no network get their ASN from the
//! offline table when one has been fetched (`swarmchase asn fetch`).

use super::WatchSource;
use crate::health::SourceHealth;
use anyhow::{Context, Result};
use sc_collect::{Client, Cursor, Kind, cdx_ts};
use sc_core::Observation;
use sc_core::asn::AsnTable;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct SourceState {
    /// Newest capture time seen (Unix seconds).
    #[serde(default)]
    pub cursor: i64,
    /// Record IDs still inside the overlap window, with their capture time.
    #[serde(default)]
    pub seen: BTreeMap<String, i64>,
    /// A pull that stopped at `limit` and continues on the next run.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending: Option<Pending>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_run: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    #[serde(default)]
    pub health: SourceHealth,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pending {
    pub resume_key: String,
    /// The `from` the pull started with; the resume key is only valid with it.
    pub from: String,
    /// When the pull's first page was read (Unix seconds). The index is
    /// sorted by URL, so captures made since then of URLs already passed are
    /// not in this pull: the next one reaches back to here, not to the
    /// newest capture seen.
    #[serde(default)]
    pub started: i64,
}

/// Pull one source incrementally. Returns (records pulled, records not seen before).
pub fn pull(
    client: &Client,
    s: &WatchSource,
    st: &mut SourceState,
    overlap: i64,
    asn: Option<&AsnTable>,
) -> Result<(usize, Vec<Observation>)> {
    let kind: Kind = s.kind.parse()?;
    let mut q = s.query.clone();
    let configured_from = q.from.as_deref().and_then(sc_core::parse_ts).unwrap_or(0);
    let from = match &st.pending {
        Some(p) => p.from.clone(),
        None => cdx_ts(configured_from.max(st.cursor - overlap).max(0)),
    };
    // The pull's `since` replaces the configured `from`.
    q.from = None;
    let since = sc_core::parse_ts(&from).filter(|&t| t > 0);
    let limit = q.limit;
    let key = match (kind.key_from_env(), kind.key_env()) {
        (None, Some(env)) if kind.needs_key() => {
            return Err(anyhow::anyhow!("{env} not set")).context(kind.name());
        }
        (k, _) => k,
    };
    let src = sc_collect::source(kind, q, key)?;
    let resumable = src.resumable();
    let cursor = st
        .pending
        .as_ref()
        .filter(|_| resumable)
        .map(|p| Cursor::Key(p.resume_key.clone()));
    let mut res = src.pull(client, since, cursor, limit)?;
    if !resumable {
        res = res.strict()?;
    } else if let Some(e) = &res.stopped {
        // Keep what we have; continue from the last good key next run.
        eprint!("(stopped early: {e:#}) ");
    }
    let started = match &st.pending {
        Some(p) => p.started,
        None => chrono::Utc::now().timestamp(),
    };
    let finished = st.pending.is_some();
    st.pending = match res.next_cursor {
        Some(Cursor::Key(k)) if resumable => Some(Pending {
            resume_key: k,
            from: from.clone(),
            started,
        }),
        _ => None,
    };
    let finished = (finished && st.pending.is_none()).then_some(started);
    if !resumable && res.observations.len() >= limit {
        eprint!("(hit limit {limit}; raise it or narrow the pattern) ");
    } else if res.truncated {
        eprint!("(a page was cut short and the source cannot page; narrow the pattern) ");
    }
    if let Some(t) = asn {
        t.enrich(&mut res.observations);
    }
    Ok((
        res.observations.len(),
        keep_fresh(st, res.observations, overlap, finished),
    ))
}

/// The records not seen before, recorded as seen; IDs the next pull cannot
/// return again are forgotten. `finished` is when a pull that ran over
/// several runs began, once it is done: the next pull starts from then, not
/// from the newest capture it saw (0, a pull saved before that was kept,
/// leaves the cursor alone).
fn keep_fresh(
    st: &mut SourceState,
    records: Vec<Observation>,
    overlap: i64,
    finished: Option<i64>,
) -> Vec<Observation> {
    let mut fresh = Vec::new();
    for o in records {
        if st.seen.contains_key(&o.id) {
            continue;
        }
        st.seen.insert(o.id.clone(), o.ts);
        st.cursor = st.cursor.max(o.ts);
        fresh.push(o);
    }
    if let Some(started) = finished.filter(|&t| t > 0) {
        st.cursor = st.cursor.min(started);
    }
    let keep_from = match &st.pending {
        Some(p) => sc_core::parse_ts(&p.from).unwrap_or(0),
        None => st.cursor - overlap,
    };
    // From the start of that UTC day: some sources (urlquery) take whole
    // days only, so the next pull returns the whole day again.
    let keep_from = keep_from - keep_from.rem_euclid(86_400);
    st.seen.retain(|_, ts| *ts >= keep_from);
    fresh
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_committed_watchlist_names_valid_sources() {
        let wl: super::super::Watchlist =
            toml::from_str(include_str!("../../../../watchlist.toml")).unwrap();
        assert!(!wl.sources.is_empty());
        let mut names = std::collections::BTreeSet::new();
        for s in &wl.sources {
            assert!(names.insert(&s.name), "duplicate source {}", s.name);
            let kind: Kind = s.kind.parse().unwrap();
            // Builds the source, which checks e.g. a CT log's endpoint.
            sc_collect::source(kind, s.query.clone(), Some("k".into())).unwrap();
        }
    }

    #[test]
    fn overlapping_pulls_drop_records_already_seen() {
        let rec = |id: &str, ts: i64| Observation {
            id: id.into(),
            ts,
            ..Default::default()
        };
        let day = 86_400;
        let mut st = SourceState::default();
        let fresh = keep_fresh(
            &mut st,
            vec![rec("a", 9 * day), rec("b", 12 * day)],
            3 * day,
            None,
        );
        assert_eq!(fresh.len(), 2);
        assert_eq!(st.cursor, 12 * day);
        // The next pull reaches back three days and returns `b` again.
        let fresh = keep_fresh(
            &mut st,
            vec![rec("b", 12 * day), rec("c", 13 * day)],
            3 * day,
            None,
        );
        let ids: Vec<&str> = fresh.iter().map(|o| o.id.as_str()).collect();
        assert_eq!(ids, ["c"]);
        // `a` is older than the overlap window now, so it is forgotten.
        assert!(!st.seen.contains_key("a") && st.seen.contains_key("b"));
    }

    #[test]
    fn a_source_that_takes_whole_days_does_not_repeat_records() {
        let rec = |id: &str, ts: i64| Observation {
            id: id.into(),
            ts,
            ..Default::default()
        };
        let (day, hour) = (86_400, 3_600);
        let mut st = SourceState::default();
        let early = rec("early", 9 * day + hour);
        keep_fresh(
            &mut st,
            vec![early.clone(), rec("late", 12 * day + 17 * hour)],
            3 * day,
            None,
        );
        // The next pull asks from day 9 17:00 but gets all of day 9.
        let fresh = keep_fresh(&mut st, vec![early], 3 * day, None);
        assert!(fresh.is_empty());
    }

    #[test]
    fn a_pull_over_several_runs_resumes_from_when_it_began() {
        let day = 86_400;
        let rec = |id: &str, ts: i64| Observation {
            id: id.into(),
            ts,
            ..Default::default()
        };
        let mut st = SourceState::default();
        keep_fresh(
            &mut st,
            vec![rec("a", 16 * day), rec("b", 20 * day)],
            day,
            Some(15 * day),
        );
        assert_eq!(st.cursor, 15 * day);
        // What the next pull can return again is still known.
        assert!(st.seen.contains_key("a") && st.seen.contains_key("b"));
        // A pull that began after its newest capture leaves the cursor, and
        // so does one saved without `started`.
        keep_fresh(&mut st, vec![], day, Some(18 * day));
        keep_fresh(&mut st, vec![], day, Some(0));
        assert_eq!(st.cursor, 15 * day);
        let p: Pending = serde_json::from_str(r#"{"resume_key":"k","from":"20260901"}"#).unwrap();
        assert_eq!(p.started, 0);
    }
}
