//! Memento timemaps (RFC 7089): the captures of one URL across many web
//! archives, from an aggregator. The default is the Los Alamos TimeTravel
//! service; any endpoint serving link-format timemaps at `<endpoint><url>`
//! works (MemGator, or one archive's own timemap). Only the timemap is read:
//! the mementos it lists are never opened.
//!
//! Terms: TimeTravel (<https://timetravel.mementoweb.org/about/>) is a free
//! research service of LANL's Prototyping Team that publishes no terms beyond
//! its API documentation; the archives it aggregates keep their own terms for
//! the captures, which we only cite by link. Requests stay one at a time.
//!
//! Timemaps are lookups of one exact URL, so this is a per-case source (an
//! endpoint's history beyond the Wayback Machine), not a pattern watch.
//! Wayback Machine and Arquivo.pt mementos are skipped: their own sources
//! collect them under their own record IDs.

use crate::pager::{Cursor, Page};
use crate::{CdxQuery, Client, Kind, Source, parse_date, short_hash};
use anyhow::Result;
use sc_core::{Observation, TsKind, redact_observation};

const TIMETRAVEL: &str = "https://timetravel.mementoweb.org/timemap/link/";

/// A timemap lookup as a [`Source`]. `query.pattern` is the exact URL;
/// `query.endpoint` the timemap endpoint it is appended to.
pub struct Memento {
    pub query: CdxQuery,
}

impl Source for Memento {
    fn kind(&self) -> Kind {
        Kind::Memento
    }

    fn query(&self) -> &CdxQuery {
        &self.query
    }

    /// One timemap holds the whole pull.
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
        let ep = self.query.endpoint.as_deref().unwrap_or(TIMETRAVEL);
        let f = client.fetch(
            &format!("{ep}{}", self.query.pattern),
            &[],
            crate::client::Opts {
                not_found_ok: true,
                ..Default::default()
            },
        )?;
        let from = since.or_else(|| self.query.from.as_deref().and_then(sc_core::parse_ts));
        let to = self.query.to.as_deref().and_then(sc_core::parse_ts);
        let mut records: Vec<Observation> = if f.status == 404 {
            Vec::new()
        } else {
            parse_timemap(&f.body)
        };
        records.retain(|o| from.is_none_or(|t| o.ts >= t) && to.is_none_or(|t| o.ts <= t));
        let truncated = records.len() > size;
        records.truncate(size);
        Ok(Page {
            records,
            next: None,
            truncated,
            coverage: None,
        })
    }
}

/// Parse a link-format timemap into one record per memento, skipping
/// Wayback Machine and Arquivo.pt mementos. Records are redacted before they
/// are returned.
pub fn parse_timemap(body: &str) -> Vec<Observation> {
    let mut original = None;
    let mut mementos = Vec::new();
    let mut rest = body;
    while let Some(a) = rest.find('<') {
        let Some(b) = rest[a..].find('>') else { break };
        let target = &rest[a + 1..a + b];
        let after = &rest[a + b + 1..];
        let end = after.find('<').unwrap_or(after.len());
        let params = &after[..end];
        rest = &after[end..];
        let param = |name: &str| -> Option<String> {
            params.split(';').find_map(|p| {
                let (k, v) = p.split_once('=')?;
                (k.trim().eq_ignore_ascii_case(name)).then(|| {
                    v.trim()
                        .trim_end_matches(',')
                        .trim()
                        .trim_matches('"')
                        .to_string()
                })
            })
        };
        let rel = param("rel").unwrap_or_default();
        let rels: Vec<&str> = rel.split_whitespace().collect();
        if rels.contains(&"original") {
            original = Some(target.to_string());
        }
        if rels.contains(&"memento")
            && let Some(dt) = param("datetime")
        {
            mementos.push((target.to_string(), dt));
        }
    }
    let mut out = Vec::new();
    for (uri, dt) in mementos {
        let Ok(u) = url::Url::parse(&uri) else {
            continue;
        };
        let host = u.host_str().unwrap_or_default().to_ascii_lowercase();
        if host == "web.archive.org" || host == "arquivo.pt" {
            continue;
        }
        let ts = parse_date(&dt).unwrap_or(0);
        let mut o = Observation {
            id: format!("memento:{host}:{}:{}", crate::cdx_ts(ts), short_hash(&uri)),
            source: "memento".into(),
            ts,
            ts_kind: TsKind::Capture,
            url: original.clone().unwrap_or_default(),
            reference: Some(uri),
            ..Default::default()
        };
        if o.url.is_empty() {
            continue;
        }
        redact_observation(&mut o);
        out.push(o);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn link_format_timemap() {
        let body = r#"<https://endpoint.example/api?q=1,2>; rel="original",
<https://agg.example/timemap/link/https://endpoint.example/api?q=1,2>; rel="self"; type="application/link-format",
<https://web.archive.org/web/20260901000000/https://endpoint.example/api?q=1,2>; rel="first memento"; datetime="Tue, 01 Sep 2026 00:00:00 GMT",
<https://archive.example/20260902120000/https://endpoint.example/api?q=1,2>; rel="memento"; datetime="Wed, 02 Sep 2026 12:00:00 GMT",
<https://other.example/x/https://endpoint.example/api?q=1,2>; rel="last memento"; datetime="Thu, 03 Sep 2026 06:30:00 GMT"
"#;
        let v = parse_timemap(body);
        assert_eq!(v.len(), 2, "the Wayback memento is skipped");
        assert_eq!(v[0].url, "https://endpoint.example/api?q=1,2");
        assert_eq!(v[0].ts_kind, TsKind::Capture);
        assert!(
            v[0].id
                .starts_with("memento:archive.example:20260902120000:")
        );
        assert!(
            v[1].reference
                .as_deref()
                .unwrap()
                .starts_with("https://other.example/")
        );
        assert!(parse_timemap("").is_empty());
        assert!(parse_timemap("<html>not a timemap</html>").is_empty());
    }
}
