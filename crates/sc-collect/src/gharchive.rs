//! GH Archive (`data.gharchive.org`): GitHub's public event stream, one
//! gzipped NDJSON file per hour. A pull streams hours through a decoder a
//! line at a time and keeps only events whose repository name, or a URL in
//! their payload, matches the query; memory stays bounded by one event.
//! Event metadata only: repositories, gists and commits are never fetched.
//!
//! Coverage: a pull reads forward from the hour after the last one read
//! (its checkpoint, passed back as the starting cursor), at most `scan`
//! hours and `max_mb` compressed megabytes, so runs every `scan` hours
//! read the whole stream. Without a checkpoint it reads the newest `scan`
//! hours; a backlog older than [`MAX_BACKLOG_HOURS`] is skipped and counted.
//! An hour the archive never published (HTTP 404) counts as skipped. Every
//! hour read reports its parsed event count as a canary: an hour with no
//! parseable event means the format or the pipe broke, not a quiet hour.
//!
//! Terms: GH Archive (<https://www.gharchive.org/>) republishes events from
//! GitHub's public API and states no further terms. GitHub's Acceptable Use
//! Policies (<https://docs.github.com/en/site-policy/acceptable-use-policies/github-acceptable-use-policies>,
//! section 7) let researchers use public, non-personal information for
//! research whose publications are open access, and forbid spam or selling
//! personal information. We keep the event's public link, type and time, not
//! the actor's profile, and publish only open-access notices.

use crate::pager::{Coverage, Cursor, Page};
use crate::{CdxQuery, Client, Kind, Needles, Source, parse_date};
use anyhow::{Context, Result};
use sc_core::{Observation, TsKind, redact_observation};
use serde_json::Value;
use std::cell::Cell;
use std::io::{BufRead, BufReader, Read};
use std::rc::Rc;

pub(crate) const BASE: &str = "https://data.gharchive.org/";
/// Hours one pull reads unless `query.scan` says otherwise.
const DEFAULT_HOURS: usize = 1;
/// Compressed megabytes one pull reads unless `query.max_mb` says otherwise.
const DEFAULT_MAX_MB: u64 = 256;
/// A checkpoint further back than this is skipped to the newest hours.
pub const MAX_BACKLOG_HOURS: i64 = 48;
/// An hour's file appears about an hour after it ends; read only older ones.
const LAG_HOURS: i64 = 2;
/// Cap on one hour's compressed file.
pub(crate) const MAX_FILE: u64 = 1 << 30;
/// Longest event line kept; longer events are skipped.
pub(crate) const MAX_LINE: usize = 4 << 20;

/// A GH Archive filter as a [`Source`]. `query.pattern` is `|`-separated
/// case-insensitive substrings (a run tag, a relay host); `query.scan` the
/// hours one pull reads, newest first available.
pub struct GhArchive {
    pub query: CdxQuery,
    /// Hours read and compressed bytes downloaded by this pull so far.
    hours_read: Cell<i64>,
    bytes: Rc<Cell<u64>>,
}

impl GhArchive {
    pub fn new(query: CdxQuery) -> Self {
        Self {
            query,
            hours_read: Cell::new(0),
            bytes: Rc::new(Cell::new(0)),
        }
    }

    fn hours(&self) -> i64 {
        self.query.scan.unwrap_or(DEFAULT_HOURS).clamp(1, 48) as i64
    }

    fn budget(&self) -> u64 {
        self.query.max_mb.unwrap_or(DEFAULT_MAX_MB).max(1) << 20
    }

    /// Where a pull starts reading, given its checkpoint (the next hour
    /// to read) and the newest hour available: (first hour, hours there
    /// were to read, hours skipped).
    fn plan(&self, checkpoint: Option<i64>, latest: i64) -> (i64, u64, u64) {
        let newest = latest - self.hours() + 1;
        let start = match checkpoint {
            Some(h) if h > latest - MAX_BACKLOG_HOURS => h,
            Some(_) | None => newest,
        };
        let skipped = checkpoint.map_or(0, |h| (start - h).max(0)) as u64;
        let available = (latest - start + 1).max(0) as u64 + skipped;
        (start, available, skipped)
    }
}

/// Counts the bytes read through it.
struct Counted<R> {
    inner: R,
    n: Rc<Cell<u64>>,
}

impl<R: Read> Read for Counted<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let k = self.inner.read(buf)?;
        self.n.set(self.n.get() + k as u64);
        Ok(k)
    }
}

impl Source for GhArchive {
    fn kind(&self) -> Kind {
        Kind::GhArchive
    }

    fn query(&self) -> &CdxQuery {
        &self.query
    }

    /// One hour's file per page.
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
        let latest = crate::client::now_secs() / 3600 - LAG_HOURS;
        let at = match cursor {
            Some(Cursor::Offset(h)) => Some(*h as i64),
            Some(c) => anyhow::bail!("gharchive pages by hour, not {c:?}"),
            None => None,
        };
        let mut cov = Coverage {
            unit: "hours",
            ..Default::default()
        };
        // The first page plans the pull from the checkpoint; later pages
        // continue at the hour the pager hands back.
        let hour = if self.hours_read.get() == 0 && self.bytes.get() == 0 {
            let (start, available, skipped) = self.plan(at, latest);
            cov.available = available;
            cov.skipped = skipped;
            start
        } else {
            at.unwrap_or(latest)
        };
        if hour > latest {
            // Caught up: nothing new has been published since the last pull.
            cov.next = Some(hour as u64);
            return Ok(Page {
                coverage: Some(cov),
                ..Default::default()
            });
        }
        let url = format!("{BASE}{}.json.gz", hour_name(hour * 3600));
        let mut records = match client.get_stream_opt(&url, MAX_FILE, true)? {
            Some(r) => {
                let r = Counted {
                    inner: r,
                    n: self.bytes.clone(),
                };
                let gz = flate2::read::MultiGzDecoder::new(r);
                let (records, parsed) =
                    filter_events_counted(gz, &Needles::new(&self.query.pattern), size)
                        .with_context(|| format!("reading {url}"))?;
                cov.read = 1;
                cov.canary = Some(parsed > 0);
                records
            }
            // The archive has gaps: an hour it never published.
            None => {
                cov.skipped += 1;
                Vec::new()
            }
        };
        self.hours_read.set(self.hours_read.get() + 1);
        cov.next = Some((hour + 1) as u64);
        let truncated = records.len() > size;
        records.truncate(size);
        let more = hour < latest
            && self.hours_read.get() < self.hours()
            && self.bytes.get() < self.budget();
        Ok(Page {
            records,
            next: more.then(|| Cursor::Offset((hour + 1) as usize)),
            truncated,
            coverage: Some(cov),
        })
    }

    fn checkpointed(&self) -> bool {
        true
    }
}

/// GH Archive's file name for the hour holding `ts`: `2026-10-09-7` (no
/// leading zero on the hour).
pub(crate) fn hour_name(ts: i64) -> String {
    let d = chrono::DateTime::from_timestamp(ts, 0).unwrap_or_default();
    d.format("%Y-%m-%d-%-H").to_string()
}

/// Read NDJSON events from `r` and keep those matching `needles`, at most
/// `max + 1` of them (one more than wanted, so the caller can tell it was
/// cut). Lines longer than [`MAX_LINE`] are skipped. Records are redacted.
pub fn filter_events(r: impl Read, needles: &Needles, max: usize) -> Result<Vec<Observation>> {
    Ok(filter_events_counted(r, needles, max)?.0)
}

/// [`filter_events`], with the number of events parsed (matching or not):
/// the canary that the stream still holds events in the shape expected.
pub fn filter_events_counted(
    r: impl Read,
    needles: &Needles,
    max: usize,
) -> Result<(Vec<Observation>, usize)> {
    let mut r = BufReader::new(r);
    let mut buf = Vec::new();
    let mut out = Vec::new();
    let mut parsed = 0;
    loop {
        buf.clear();
        let n = (&mut r).take(MAX_LINE as u64).read_until(b'\n', &mut buf)?;
        if n == 0 {
            break;
        }
        if !buf.ends_with(b"\n") && n == MAX_LINE {
            // Skip the rest of an overlong line.
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
        if v.pointer("/repo/name").is_some() {
            parsed += 1;
        }
        if let Some(o) = event_to_obs(&v, needles) {
            out.push(o);
            if out.len() > max {
                break;
            }
        }
    }
    Ok((out, parsed))
}

pub(crate) fn event_to_obs(v: &Value, needles: &Needles) -> Option<Observation> {
    let repo = v.pointer("/repo/name").and_then(Value::as_str)?;
    let payload = v.get("payload");
    let hit = needles.matches(repo)
        || payload.is_some_and(|p| {
            let mut found = false;
            walk_strings(p, &mut |s| {
                found = found || urls_in(s).any(|u| needles.matches(u));
            });
            found
        });
    if !hit {
        return None;
    }
    let id = v.get("id").and_then(Value::as_str)?;
    let html = [
        "/payload/comment/html_url",
        "/payload/issue/html_url",
        "/payload/pull_request/html_url",
        "/payload/release/html_url",
        "/payload/forkee/html_url",
    ]
    .iter()
    .find_map(|p| v.pointer(p).and_then(Value::as_str))
    .map(str::to_string)
    .unwrap_or_else(|| format!("https://github.com/{repo}"));
    let mut o = Observation {
        id: format!("gharchive:{id}"),
        source: "gharchive".into(),
        ts: v
            .get("created_at")
            .and_then(Value::as_str)
            .and_then(parse_date)
            .unwrap_or(0),
        ts_kind: TsKind::Request,
        url: html.clone(),
        reference: Some(html),
        ..Default::default()
    };
    redact_observation(&mut o);
    Some(o)
}

fn walk_strings(v: &Value, f: &mut dyn FnMut(&str)) {
    match v {
        Value::String(s) => f(s),
        Value::Array(a) => a.iter().for_each(|x| walk_strings(x, f)),
        Value::Object(m) => m.values().for_each(|x| walk_strings(x, f)),
        _ => {}
    }
}

/// The `http(s)://` URLs in free text.
fn urls_in(s: &str) -> impl Iterator<Item = &str> {
    s.split(|c: char| {
        c.is_whitespace() || matches!(c, '"' | '\'' | '<' | '>' | '(' | ')' | '[' | ']')
    })
    .filter(|t| t.starts_with("http://") || t.starts_with("https://"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn gz(text: &str) -> Vec<u8> {
        let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        e.write_all(text.as_bytes()).unwrap();
        e.finish().unwrap()
    }

    #[test]
    fn keeps_matching_events_from_a_gzip_stream() {
        let lines = [
            r#"{"id":"1","type":"IssueCommentEvent","created_at":"2026-10-09T07:00:01Z","repo":{"name":"someone/proj"},"payload":{"comment":{"html_url":"https://github.com/someone/proj/issues/1#c1","body":"see https://relay.example/https://t.example/?q=1 thanks"}}}"#,
            r#"{"id":"2","type":"PushEvent","created_at":"2026-10-09T07:00:02Z","repo":{"name":"someone/other"},"payload":{"commits":[{"message":"plain text relay.example without scheme"}]}}"#,
            r#"{"id":"3","type":"CreateEvent","created_at":"2026-10-09T07:00:03Z","repo":{"name":"bot123/uqtag-run-7"},"payload":{"ref_type":"repository"}}"#,
            "not json",
        ];
        let data = gz(&lines.join("\n"));
        let r = flate2::read::MultiGzDecoder::new(&data[..]);
        let v = filter_events(r, &Needles::new("relay.example|uqtag"), 10).unwrap();
        let ids: Vec<&str> = v.iter().map(|o| o.id.as_str()).collect();
        assert_eq!(ids, ["gharchive:1", "gharchive:3"]);
        assert_eq!(v[0].url, "https://github.com/someone/proj/issues/1#c1");
        assert_eq!(v[0].ts_kind, TsKind::Request);
        assert_eq!(v[1].url, "https://github.com/bot123/uqtag-run-7");
        // The cap stops reading one past `max`.
        let r = flate2::read::MultiGzDecoder::new(&data[..]);
        assert_eq!(filter_events(r, &Needles::new("*"), 1).unwrap().len(), 2);
    }

    #[test]
    fn parsed_events_are_the_canary() {
        let data = gz(concat!(
            r#"{"id":"1","created_at":"2026-10-09T07:00:01Z","repo":{"name":"a/b"},"payload":{}}"#,
            "\n",
            r#"{"id":"2","created_at":"2026-10-09T07:00:02Z","repo":{"name":"c/d"},"payload":{}}"#,
            "\n{\"not\":\"an event\"}\n"
        ));
        let r = flate2::read::MultiGzDecoder::new(&data[..]);
        let (v, parsed) = filter_events_counted(r, &Needles::new("nothing-matches"), 10).unwrap();
        assert!(v.is_empty());
        assert_eq!(parsed, 2);
    }

    #[test]
    fn plans_from_the_checkpoint_within_the_backlog() {
        let g = GhArchive::new(CdxQuery {
            scan: Some(6),
            ..Default::default()
        });
        let latest = 1000;
        // No checkpoint: the newest six hours.
        assert_eq!(g.plan(None, latest), (995, 6, 0));
        // A checkpoint six hours back: those six hours.
        assert_eq!(g.plan(Some(995), latest), (995, 6, 0));
        // Ten hours back: start there; the pull reads six, the next run the rest.
        assert_eq!(g.plan(Some(991), latest), (991, 10, 0));
        // Caught up.
        assert_eq!(g.plan(Some(1001), latest), (1001, 0, 0));
        // A backlog past the limit is skipped to the newest hours, and counted.
        let (start, available, skipped) = g.plan(Some(900), latest);
        assert_eq!((start, skipped), (995, 95));
        assert_eq!(available, 101);
        assert_eq!(g.budget(), DEFAULT_MAX_MB << 20);
    }

    #[test]
    fn hour_names() {
        assert_eq!(hour_name(1_791_529_200), "2026-10-09-7");
        assert_eq!(hour_name(1_791_583_200), "2026-10-09-22");
        assert_eq!(hour_name(1_791_504_000), "2026-10-09-0");
    }
}
