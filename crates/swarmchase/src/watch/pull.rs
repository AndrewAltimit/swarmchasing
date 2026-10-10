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
    st.pending = match res.next_cursor {
        Some(Cursor::Key(k)) if resumable => Some(Pending {
            resume_key: k,
            from: from.clone(),
        }),
        _ => None,
    };
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
        keep_fresh(st, res.observations, overlap),
    ))
}

/// The records not seen before, recorded as seen; IDs the next pull cannot
/// return again are forgotten.
fn keep_fresh(st: &mut SourceState, records: Vec<Observation>, overlap: i64) -> Vec<Observation> {
    let mut fresh = Vec::new();
    for o in records {
        if st.seen.contains_key(&o.id) {
            continue;
        }
        st.seen.insert(o.id.clone(), o.ts);
        st.cursor = st.cursor.max(o.ts);
        fresh.push(o);
    }
    let keep_from = match &st.pending {
        Some(p) => sc_core::parse_ts(&p.from).unwrap_or(0),
        None => st.cursor - overlap,
    };
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
        );
        assert_eq!(fresh.len(), 2);
        assert_eq!(st.cursor, 12 * day);
        // The next pull reaches back three days and returns `b` again.
        let fresh = keep_fresh(
            &mut st,
            vec![rec("b", 12 * day), rec("c", 13 * day)],
            3 * day,
        );
        let ids: Vec<&str> = fresh.iter().map(|o| o.id.as_str()).collect();
        assert_eq!(ids, ["c"]);
        // `a` is older than the overlap window now, so it is forgotten.
        assert!(!st.seen.contains_key("a") && st.seen.contains_key("b"));
    }
}
