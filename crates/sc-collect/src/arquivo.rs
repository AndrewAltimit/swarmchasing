//! The Arquivo.pt CDX index. It has no paging: one request returns up to the
//! limit.
//!
//! Arquivo.pt's crawls reach the index months after capture, but pages saved
//! on demand through its SavePageNow (<https://arquivo.pt/savepagenow>) are
//! merged into the index within days, in collections named `SAWP<n>`
//! (WARC files `save-…`). Anyone can save any URL there, as with urlquery,
//! so `filter = ["collection:SAWP.*"]` reads it as a second submit-anywhere
//! channel. A row is still only a capture time: the submission time is not
//! in the index.
//!
//! Terms: Arquivo.pt's terms of use (<https://sobre.arquivo.pt/en/about/terms-and-conditions/>)
//! offer free access for education, science and research, forbid
//! commercial use and interfering with the system's operation, ask users to
//! cite Arquivo.pt with the access date, and forbid redistributing archived
//! content. We read index rows only, never the archived pages, at the
//! watch's paced rate, and notices cite captures by link.

use crate::pager::{Cursor, Page};
use crate::{CdxQuery, Client, Kind, Source, cdx_ts};
use anyhow::Result;
use sc_core::Observation;
use sc_core::capture::{Archive, capture};
use sc_core::redact_observation;
use serde_json::Value;

/// An Arquivo.pt CDX query as a [`Source`].
pub struct Arquivo {
    pub query: CdxQuery,
}

impl Source for Arquivo {
    fn kind(&self) -> Kind {
        Kind::Arquivo
    }

    fn query(&self) -> &CdxQuery {
        &self.query
    }

    /// One page holds the whole pull.
    fn page_size(&self) -> usize {
        usize::MAX
    }

    fn page(
        &self,
        client: &Client,
        since: Option<i64>,
        _cursor: Option<&Cursor>,
        size: usize,
    ) -> Result<Page> {
        let mut q = self.query.clone();
        if let Some(t) = since {
            q.from = Some(cdx_ts(t));
        }
        q.limit = size;
        let records = client.arquivo_cdx(&q)?;
        // The API takes no offset, page or resume key, so a full page is as far
        // as a query reaches: narrow the pattern or the dates to see the rest.
        let truncated = records.len() >= size;
        Ok(Page {
            stopped: None,
            records,
            next: None,
            truncated,
            coverage: None,
        })
    }
}

impl Client {
    /// Arquivo.pt CDX index (NDJSON). No paging: one request of up to `q.limit` records.
    pub fn arquivo_cdx(&self, q: &CdxQuery) -> Result<Vec<Observation>> {
        let mut u = url::Url::parse("https://arquivo.pt/wayback/cdx")?;
        {
            let mut p = u.query_pairs_mut();
            p.append_pair("url", &q.pattern)
                .append_pair("output", "json");
            p.append_pair("limit", &q.limit.to_string());
            if let Some(f) = &q.from {
                p.append_pair("from", f);
            }
            if let Some(t) = &q.to {
                p.append_pair("to", t);
            }
            if let Some(m) = &q.match_type {
                p.append_pair("matchType", m);
            }
            for f in &q.filter {
                p.append_pair("filter", f);
            }
        }
        let body = self.get(u.as_str())?;
        Ok(parse_arquivo_cdx(&body))
    }
}

/// Parse Arquivo.pt CDX NDJSON. Records are redacted before they are returned.
pub fn parse_arquivo_cdx(body: &str) -> Vec<Observation> {
    let mut out = Vec::new();
    for line in body.lines().filter(|l| !l.trim().is_empty()) {
        let Ok(v) = serde_json::from_str::<Value>(line) else {
            continue;
        };
        let gs = |k: &str| v.get(k).and_then(Value::as_str).map(str::to_string);
        let (Some(ts), Some(orig)) = (gs("timestamp"), gs("url")) else {
            continue;
        };
        let mut o = capture(
            Archive::Arquivo,
            &ts,
            &orig,
            gs("status").and_then(|s| s.parse().ok()),
            &gs("digest").unwrap_or_default(),
        );
        redact_observation(&mut o);
        out.push(o);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arquivo_ndjson() {
        let body = "{\"timestamp\":\"20261004081000\",\"url\":\"https://a.example/?token=x\",\"status\":\"200\",\"digest\":\"D\"}\nnot json\n";
        let v = parse_arquivo_cdx(body);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].status, Some(200));
    }

    #[test]
    fn on_demand_save_rows_parse_like_crawl_rows() {
        // The shape of a SavePageNow row: its own collection and WARC name.
        let body = r#"{"urlkey": "example,relay)/https://t.example/", "timestamp": "20261003101500", "url": "https://relay.example/https://t.example/?uqtag=r1", "mime": "text/plain", "status": "200", "digest": "AAAA", "length": "900", "offset": "10", "filename": "save-merged-p1.arquivo.pt-20261004101041-ABCDEF.warc.gz", "collection": "SAWP9", "source": "cdx_folder:SAWP9.cdxj", "source-coll": "cdx_folder"}"#;
        let v = parse_arquivo_cdx(body);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].source, "arquivo");
        assert!(v[0].id.starts_with("arquivo:20261003101500:AAAA:"));
        assert_eq!(
            v[0].reference.as_deref(),
            Some(
                "https://arquivo.pt/wayback/20261003101500/https://relay.example/https://t.example/?uqtag=r1"
            )
        );
    }
}
