//! Incremental pulls: each source's cursor, the IDs still inside the overlap
//! window, a resumable pull (Wayback, Common Crawl, footprints, the MCP
//! Registry) that continues on the next run, and the checkpoint a stream
//! source (GH Archive, CT logs) reads on from. Records that carry an IP but no network get their ASN from the
//! offline table when one has been fetched (`swarmchase asn fetch`).

use super::WatchSource;
use crate::health::SourceHealth;
use anyhow::{Context, Result};
use sc_collect::{Client, Coverage, Cursor, Kind, cdx_ts};
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
    /// Where a stream source (GH Archive hours, CT log entries) continues:
    /// the next hour or entry index to read.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mark: Option<u64>,
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

/// What one pull got.
#[derive(Debug, Default)]
pub struct Pulled {
    /// Records pulled, seen before or not.
    pub pulled: usize,
    /// Records not seen before.
    pub new: Vec<Observation>,
    /// How much of a stream or feed it read (see [`Coverage`]).
    pub coverage: Option<Coverage>,
    /// A page failed after earlier pages succeeded; the pull kept what it
    /// had and continues from its checkpoint next run.
    pub stopped: Option<String>,
}

/// Pull one source incrementally.
pub fn pull(
    client: &Client,
    s: &WatchSource,
    st: &mut SourceState,
    overlap: i64,
    asn: Option<&AsnTable>,
) -> Result<Pulled> {
    let kind: Kind = s.kind.parse()?;
    let mut q = s.query.clone();
    let configured_from = q.from.as_deref().and_then(sc_core::parse_ts).unwrap_or(0);
    let from = match &st.pending {
        Some(p) => p.from.clone(),
        None => {
            let cursor = st.cursor.min(chrono::Utc::now().timestamp());
            cdx_ts(configured_from.max(cursor - overlap).max(0))
        }
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
    let checkpointed = src.checkpointed();
    let cursor = if checkpointed {
        st.mark.map(|m| Cursor::Offset(m as usize))
    } else {
        st.pending
            .as_ref()
            .filter(|_| resumable)
            .map(|p| Cursor::Key(p.resume_key.clone()))
    };
    let mut res = src.pull(client, since, cursor, limit)?;
    let mut stopped = None;
    if !resumable && !checkpointed {
        res = res.strict()?;
    } else if let Some(e) = res.stopped.take() {
        // Keep what we have; continue from the last good key next run.
        eprint!("(stopped early: {e:#}) ");
        stopped = Some(super::digest::short_reason(&e));
    }
    if checkpointed && let Some(next) = res.coverage.as_ref().and_then(|c| c.next) {
        st.mark = Some(next);
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
    let hit_limit = !resumable && res.observations.len() >= limit;
    if hit_limit {
        eprint!("(hit limit {limit}; raise it or narrow the pattern) ");
    } else if res.truncated {
        eprint!("(a page was cut short and the source cannot page; narrow the pattern) ");
    }
    if let Some(t) = asn {
        t.enrich(&mut res.observations);
    }
    let now = chrono::Utc::now().timestamp();
    let cap = (hit_limit && !checkpointed)
        .then(|| oldest(&res.observations))
        .flatten();
    Ok(Pulled {
        pulled: res.observations.len(),
        coverage: res.coverage.take(),
        new: keep_fresh(st, res.observations, overlap, finished, now, cap),
        stopped,
    })
}

/// The oldest dated capture among `records`.
fn oldest(records: &[Observation]) -> Option<i64> {
    records.iter().map(|o| o.ts).filter(|&t| t > 0).min()
}

/// The records not seen before, recorded as seen; IDs the next pull cannot
/// return again are forgotten. `finished` is when a pull that ran over
/// several runs began, once it is done: the next pull starts from then, not
/// from the newest capture it saw (0, a pull saved before that was kept,
/// leaves the cursor alone).
///
/// The cursor never passes `now`, so a record stamped in the future cannot
/// move a source's next pull past everything still to come. `cap` is the
/// oldest capture of a pull that hit its limit on a source that cannot page:
/// what lies between the cursor and the newest capture may be missing, so
/// the cursor moves no further than the cap. Records with no time are kept
/// as seen for good: no window would ever drop them from a later pull.
fn keep_fresh(
    st: &mut SourceState,
    records: Vec<Observation>,
    overlap: i64,
    finished: Option<i64>,
    now: i64,
    cap: Option<i64>,
) -> Vec<Observation> {
    let mut fresh = Vec::new();
    // A cursor saved in the future (by an earlier version) heals too.
    st.cursor = st.cursor.min(now);
    let before = st.cursor;
    for o in records {
        if st.seen.contains_key(&o.id) {
            continue;
        }
        st.seen.insert(o.id.clone(), o.ts);
        st.cursor = st.cursor.max(o.ts.min(now));
        fresh.push(o);
    }
    if let Some(cap) = cap {
        st.cursor = st.cursor.min(cap.max(before));
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
    st.seen.retain(|_, ts| *ts <= 0 || *ts >= keep_from);
    fresh
}

#[cfg(test)]
mod tests {
    use super::*;

    /// [`keep_fresh`] at a far-future now, with no limit cap.
    fn kf(
        st: &mut SourceState,
        records: Vec<Observation>,
        overlap: i64,
        finished: Option<i64>,
    ) -> Vec<Observation> {
        keep_fresh(st, records, overlap, finished, i64::MAX, None)
    }

    fn rec(id: &str, ts: i64) -> Observation {
        Observation {
            id: id.into(),
            ts,
            ..Default::default()
        }
    }

    #[test]
    fn a_future_capture_does_not_move_the_cursor_past_now() {
        let day = 86_400;
        let mut st = SourceState::default();
        let now = 10 * day;
        keep_fresh(
            &mut st,
            vec![rec("a", 9 * day), rec("z", 400 * day)],
            day,
            None,
            now,
            None,
        );
        assert_eq!(st.cursor, now);
        // The next pull still reaches back from now and sees new records.
        let fresh = keep_fresh(
            &mut st,
            vec![rec("b", 10 * day + 60)],
            day,
            None,
            now + day,
            None,
        );
        assert_eq!(fresh.len(), 1);
        // A cursor already saved in the future comes back to now.
        let mut st = SourceState {
            cursor: 400 * day,
            ..Default::default()
        };
        keep_fresh(&mut st, vec![], day, None, now, None);
        assert_eq!(st.cursor, now);
    }

    #[test]
    fn a_pull_cut_at_its_limit_keeps_the_cursor_at_its_oldest_capture() {
        let day = 86_400;
        let mut st = SourceState {
            cursor: 5 * day,
            ..Default::default()
        };
        let got = vec![
            rec("n1", 20 * day),
            rec("n2", 18 * day),
            rec("n3", 12 * day),
        ];
        let cap = oldest(&got);
        keep_fresh(&mut st, got, day, None, 30 * day, cap);
        // What lies between day 5 and day 12 may be missing; the next pull
        // reaches back to day 12, not day 20.
        assert_eq!(st.cursor, 12 * day);
        // A cap never moves the cursor backwards.
        keep_fresh(
            &mut st,
            vec![rec("o", 2 * day)],
            day,
            None,
            30 * day,
            Some(2 * day),
        );
        assert_eq!(st.cursor, 12 * day);
    }

    #[test]
    fn undated_records_stay_seen() {
        let day = 86_400;
        let mut st = SourceState::default();
        let fresh = kf(&mut st, vec![rec("u", 0), rec("a", 20 * day)], day, None);
        assert_eq!(fresh.len(), 2);
        let fresh = kf(&mut st, vec![rec("u", 0), rec("b", 40 * day)], day, None);
        let ids: Vec<&str> = fresh.iter().map(|o| o.id.as_str()).collect();
        assert_eq!(ids, ["b"]);
        assert!(st.seen.contains_key("u") && !st.seen.contains_key("a"));
    }

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
        let fresh = kf(
            &mut st,
            vec![rec("a", 9 * day), rec("b", 12 * day)],
            3 * day,
            None,
        );
        assert_eq!(fresh.len(), 2);
        assert_eq!(st.cursor, 12 * day);
        // The next pull reaches back three days and returns `b` again.
        let fresh = kf(
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
        kf(
            &mut st,
            vec![early.clone(), rec("late", 12 * day + 17 * hour)],
            3 * day,
            None,
        );
        // The next pull asks from day 9 17:00 but gets all of day 9.
        let fresh = kf(&mut st, vec![early], 3 * day, None);
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
        kf(
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
        kf(&mut st, vec![], day, Some(18 * day));
        kf(&mut st, vec![], day, Some(0));
        assert_eq!(st.cursor, 15 * day);
        let p: Pending = serde_json::from_str(r#"{"resume_key":"k","from":"20260901"}"#).unwrap();
        assert_eq!(p.started, 0);
    }
}
