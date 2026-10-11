//! The Wayback Machine CDX index. Sorted by URL, not time, and paged with
//! resume keys that stay valid across runs, so a pull cut short by its limit
//! can continue later.
//!
//! A host with very many captures can time out at the server's gateway when
//! one query spans its whole index. `slice_days` reads the time range in
//! windows instead, oldest first; the resume key then names the window too
//! ([`SliceKey`]), so a pull cut short continues in the same window. CDX
//! `filter` expressions narrow a query on the server.

use crate::pager::{Cursor, Page};
use crate::{CdxQuery, Client, Kind, Source, cdx_ts};
use anyhow::{Context, Result};
use sc_core::Observation;
use sc_core::capture::{Archive, capture};
use sc_core::redact_observation;
use serde_json::Value;

/// A Wayback CDX query as a [`Source`].
pub struct Wayback {
    pub query: CdxQuery,
}

impl Source for Wayback {
    fn kind(&self) -> Kind {
        Kind::Wayback
    }

    fn query(&self) -> &CdxQuery {
        &self.query
    }

    fn resumable(&self) -> bool {
        true
    }

    fn page_size(&self) -> usize {
        self.query.page_size.max(1)
    }

    fn page(
        &self,
        client: &Client,
        since: Option<i64>,
        cursor: Option<&Cursor>,
        size: usize,
    ) -> Result<Page> {
        let (slice, key) = match cursor {
            Some(Cursor::Key(k)) => SliceKey::parse(k),
            Some(c) => anyhow::bail!("wayback pages by resume key, not {c:?}"),
            None => (None, None),
        };
        let mut q = self.query.clone();
        if let Some(t) = since {
            q.from = Some(cdx_ts(t));
        }
        let from = q.from.as_deref().and_then(sc_core::parse_ts);
        let days = self.query.slice_days.filter(|&d| d > 0);
        let (Some(days), Some(from)) = (days, from) else {
            let p = client.wayback_cdx_page(&q, size, key.as_deref())?;
            return Ok(Page {
                records: p.records,
                next: p.resume_key.map(Cursor::Key),
                ..Default::default()
            });
        };
        // A window of `days` from where the last one ended.
        let start = slice.unwrap_or(from);
        let to = q.to.as_deref().and_then(sc_core::parse_ts);
        let end = (start + i64::from(days) * 86_400 - 1).min(to.unwrap_or(i64::MAX));
        q.from = Some(cdx_ts(start));
        q.to = Some(cdx_ts(end));
        let p = client.wayback_cdx_page(&q, size, key.as_deref())?;
        let now = crate::client::now_secs();
        let next = match p.resume_key {
            Some(k) => Some(SliceKey::format(start, Some(&k))),
            None if end < now && to.is_none_or(|t| end < t) => {
                Some(SliceKey::format(end + 1, None))
            }
            None => None,
        };
        Ok(Page {
            records: p.records,
            next: next.map(Cursor::Key),
            ..Default::default()
        })
    }
}

/// The resume key of a pull read in time windows (`slice_days`): the
/// window's start and the CDX resume key within it, as
/// `slice:<yyyyMMddhhmmss>:<resume key>`. Valid across runs, like a plain
/// resume key.
struct SliceKey;

impl SliceKey {
    const PREFIX: &'static str = "slice:";

    fn format(start: i64, key: Option<&str>) -> String {
        format!("{}{}:{}", Self::PREFIX, cdx_ts(start), key.unwrap_or(""))
    }

    /// (window start, resume key). A key without the prefix is a plain
    /// resume key.
    fn parse(k: &str) -> (Option<i64>, Option<String>) {
        let Some(rest) = k.strip_prefix(Self::PREFIX) else {
            return (None, Some(k.to_string()));
        };
        let (ts, key) = rest.split_once(':').unwrap_or((rest, ""));
        (
            sc_core::parse_ts(ts),
            Some(key.to_string()).filter(|k| !k.is_empty()),
        )
    }
}

impl Client {
    /// Wayback Machine CDX index. `pattern` is a CDX url pattern such as
    /// `r.jina.ai/*` or `*.example.gov` (with `match_type`). Pages through the
    /// index until `q.limit` records or the end.
    pub fn wayback_cdx(&self, q: &CdxQuery) -> Result<Vec<Observation>> {
        let src = Wayback { query: q.clone() };
        Ok(src.pull(self, None, None, q.limit)?.strict()?.observations)
    }

    /// One page of Wayback CDX results. Pass the previous page's `resume_key`
    /// (with an otherwise identical query) to continue where it stopped.
    pub fn wayback_cdx_page(
        &self,
        q: &CdxQuery,
        page_size: usize,
        resume_key: Option<&str>,
    ) -> Result<CdxPage> {
        let mut u = url::Url::parse("https://web.archive.org/cdx/search/cdx")?;
        {
            let mut p = u.query_pairs_mut();
            p.append_pair("url", &q.pattern)
                .append_pair("output", "json");
            p.append_pair("fl", "timestamp,original,statuscode,mimetype,digest");
            p.append_pair("limit", &page_size.to_string());
            p.append_pair("showResumeKey", "true");
            if let Some(k) = resume_key {
                p.append_pair("resumeKey", k);
            }
            if let Some(f) = &q.from {
                p.append_pair("from", f);
            }
            if let Some(t) = &q.to {
                p.append_pair("to", t);
            }
            if let Some(m) = &q.match_type {
                p.append_pair("matchType", m);
            }
            if q.collapse_digest {
                p.append_pair("collapse", "digest");
            }
            for f in &q.filter {
                p.append_pair("filter", f);
            }
        }
        let body = self.get(u.as_str())?;
        parse_wayback_cdx(&body)
    }
}

/// One page of CDX results plus the key to fetch the next one, if any.
#[derive(Debug, Clone, Default)]
pub struct CdxPage {
    pub records: Vec<Observation>,
    pub resume_key: Option<String>,
}

/// Parse Wayback CDX JSON (`output=json`, optionally with `showResumeKey=true`).
/// Records are redacted before they are returned.
pub fn parse_wayback_cdx(body: &str) -> Result<CdxPage> {
    let mut page = CdxPage::default();
    if body.trim().is_empty() {
        return Ok(page);
    }
    let rows: Vec<Vec<Value>> = serde_json::from_str(body).context("wayback CDX JSON")?;
    let mut rows = rows.iter().skip(1);
    while let Some(r) = rows.next() {
        if r.is_empty() {
            // An empty row separates the records from the resume key.
            page.resume_key = rows
                .next()
                .and_then(|k| k.first())
                .and_then(Value::as_str)
                .filter(|k| !k.is_empty())
                .map(str::to_string);
            break;
        }
        let s = |i: usize| {
            r.get(i)
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string()
        };
        let mut o = capture(Archive::Wayback, &s(0), &s(1), s(2).parse().ok(), &s(4));
        redact_observation(&mut o);
        page.records.push(o);
    }
    Ok(page)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cdx_with_resume_key() {
        let body = r#"[["timestamp","original","statuscode","mimetype","digest"],
            ["20261004081000","https://r.jina.ai/https://a.example/?api_key=s3cr3t","200","text/html","AAA"],
            ["20261004081500","https://r.jina.ai/https://b.example/","200","text/html","BBB"],
            [],
            ["ai,jina,r)/https://b.example/ 20261004081500"]]"#;
        let p = parse_wayback_cdx(body).unwrap();
        assert_eq!(p.records.len(), 2);
        assert!(p.records[0].id.starts_with("wayback:20261004081000:AAA:"));
        assert!(p.records[0].url.contains("api_key=REDACTED-"));
        assert!(p.resume_key.as_deref().unwrap().ends_with("20261004081500"));
    }

    #[test]
    fn cdx_last_page() {
        let body = r#"[["timestamp","original","statuscode","mimetype","digest"],
            ["20261004081000","https://a.example/","200","text/html","AAA"]]"#;
        let p = parse_wayback_cdx(body).unwrap();
        assert_eq!(p.records.len(), 1);
        assert!(p.resume_key.is_none());
        assert!(parse_wayback_cdx("").unwrap().records.is_empty());
    }

    #[test]
    fn slice_keys_round_trip() {
        let t = 1_791_000_000;
        let k = SliceKey::format(t, Some("ai,jina,r)/x 20261004081500"));
        assert_eq!(
            SliceKey::parse(&k),
            (Some(t), Some("ai,jina,r)/x 20261004081500".into()))
        );
        assert_eq!(SliceKey::parse(&SliceKey::format(t, None)), (Some(t), None));
        // A resume key saved before slicing is a plain key.
        assert_eq!(
            SliceKey::parse("ai,jina,r)/ 2026"),
            (None, Some("ai,jina,r)/ 2026".into()))
        );
    }
}
