//! GH Archive (`data.gharchive.org`): GitHub's public event stream, one
//! gzipped NDJSON file per hour. A pull streams the newest hours through a
//! decoder a line at a time and keeps only events whose repository name, or
//! a URL in their payload, matches the query; memory stays bounded by one
//! event. Event metadata only: repositories, gists and commits are never
//! fetched.
//!
//! Terms: GH Archive (<https://www.gharchive.org/>) republishes events from
//! GitHub's public API and states no further terms. GitHub's Acceptable Use
//! Policies (<https://docs.github.com/en/site-policy/acceptable-use-policies/github-acceptable-use-policies>,
//! section 7) let researchers use public, non-personal information for
//! research whose publications are open access, and forbid spam or selling
//! personal information. We keep the event's public link, type and time, not
//! the actor's profile, and publish only open-access notices.

use crate::pager::{Cursor, Page};
use crate::{CdxQuery, Client, Kind, Needles, Source, parse_date};
use anyhow::{Context, Result};
use sc_core::{Observation, TsKind, redact_observation};
use serde_json::Value;
use std::io::{BufRead, BufReader, Read};

const BASE: &str = "https://data.gharchive.org/";
/// Hours one pull reads unless `query.scan` says otherwise.
const DEFAULT_HOURS: usize = 1;
/// An hour's file appears about an hour after it ends; read only older ones.
const LAG_HOURS: i64 = 2;
/// Cap on one hour's compressed file.
const MAX_FILE: u64 = 1 << 30;
/// Longest event line kept; longer events are skipped.
const MAX_LINE: usize = 4 << 20;

/// A GH Archive filter as a [`Source`]. `query.pattern` is `|`-separated
/// case-insensitive substrings (a run tag, a relay host); `query.scan` the
/// hours one pull reads, newest first available.
pub struct GhArchive {
    pub query: CdxQuery,
}

impl GhArchive {
    pub fn new(query: CdxQuery) -> Self {
        Self { query }
    }

    fn hours(&self) -> i64 {
        self.query.scan.unwrap_or(DEFAULT_HOURS).clamp(1, 48) as i64
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
        since: Option<i64>,
        cursor: Option<&Cursor>,
        size: usize,
    ) -> Result<Page> {
        let latest = crate::client::now_secs() / 3600 - LAG_HOURS;
        let hour = match cursor {
            Some(Cursor::Offset(h)) => *h as i64,
            Some(c) => anyhow::bail!("gharchive pages by hour, not {c:?}"),
            // Never further back than the hours budget: the stream is read
            // as a sample of its newest hours.
            None => since
                .map(|t| t / 3600)
                .unwrap_or(i64::MIN)
                .max(latest - self.hours() + 1),
        };
        let url = format!("{BASE}{}.json.gz", hour_name(hour * 3600));
        let r = client.get_stream(&url, MAX_FILE)?;
        let gz = flate2::read::MultiGzDecoder::new(r);
        let mut records = filter_events(gz, &Needles::new(&self.query.pattern), size)
            .with_context(|| format!("reading {url}"))?;
        let truncated = records.len() > size;
        records.truncate(size);
        Ok(Page {
            records,
            next: (hour < latest).then(|| Cursor::Offset((hour + 1) as usize)),
            truncated,
        })
    }
}

/// GH Archive's file name for the hour holding `ts`: `2026-10-09-7` (no
/// leading zero on the hour).
fn hour_name(ts: i64) -> String {
    let d = chrono::DateTime::from_timestamp(ts, 0).unwrap_or_default();
    d.format("%Y-%m-%d-%-H").to_string()
}

/// Read NDJSON events from `r` and keep those matching `needles`, at most
/// `max + 1` of them (one more than wanted, so the caller can tell it was
/// cut). Lines longer than [`MAX_LINE`] are skipped. Records are redacted.
pub fn filter_events(r: impl Read, needles: &Needles, max: usize) -> Result<Vec<Observation>> {
    let mut r = BufReader::new(r);
    let mut buf = Vec::new();
    let mut out = Vec::new();
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
        if let Some(o) = event_to_obs(&v, needles) {
            out.push(o);
            if out.len() > max {
                break;
            }
        }
    }
    Ok(out)
}

fn event_to_obs(v: &Value, needles: &Needles) -> Option<Observation> {
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
    fn hour_names() {
        assert_eq!(hour_name(1_791_529_200), "2026-10-09-7");
        assert_eq!(hour_name(1_791_583_200), "2026-10-09-22");
        assert_eq!(hour_name(1_791_504_000), "2026-10-09-0");
    }
}
