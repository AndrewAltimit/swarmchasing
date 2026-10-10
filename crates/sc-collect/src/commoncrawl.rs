//! The Common Crawl CDX index (`index.commoncrawl.org`): one index per crawl,
//! listed in `collinfo.json`. Index rows only; the WARC records they point to
//! are never read.
//!
//! Terms: <https://commoncrawl.org/terms-of-use> grant a limited licence to
//! use the service and its data, forbid disrupting the servers, harvesting
//! personal information and disguising the requester, and leave crawled
//! content under its owners' terms. We read index rows politely, store the
//! URL and capture metadata, and cite them by index query.
//!
//! The index pages in blocks (`page`, `showNumPages`); each request asks for
//! one block (about 3,000 rows). Cursors name the crawl and the page, so they
//! stay valid across runs.

use crate::client::Opts;
use crate::pager::{Cursor, Page};
use crate::{CdxQuery, Client, Kind, Source, cdx_ts};
use anyhow::{Context, Result};
use sc_core::{Observation, TsKind, parse_ts, redact_observation};
use serde_json::Value;
use std::cell::RefCell;
use std::collections::HashMap;

const COLLINFO: &str = "https://index.commoncrawl.org/collinfo.json";
const INDEX: &str = "https://index.commoncrawl.org/";

/// A Common Crawl CDX query as a [`Source`]. `query.endpoint` picks the
/// crawls: a crawl id (`CC-MAIN-2026-39`), `latest` (the default) or
/// `latest:N` for the newest N.
pub struct CommonCrawl {
    pub query: CdxQuery,
    crawls: RefCell<Option<Vec<String>>>,
    pages: RefCell<HashMap<String, usize>>,
}

impl CommonCrawl {
    pub fn new(query: CdxQuery) -> Self {
        Self {
            query,
            crawls: RefCell::new(None),
            pages: RefCell::new(HashMap::new()),
        }
    }

    /// The crawls this query reads, newest first.
    fn crawls(&self, client: &Client) -> Result<Vec<String>> {
        if let Some(c) = self.crawls.borrow().as_ref() {
            return Ok(c.clone());
        }
        let ep = self.query.endpoint.as_deref().unwrap_or("latest").trim();
        let list = if let Some(rest) = ep.strip_prefix("latest") {
            let n = rest
                .strip_prefix(':')
                .map(|n| n.parse::<usize>().context("latest:N needs a number"))
                .transpose()?
                .unwrap_or(1)
                .max(1);
            let all = parse_collinfo(&client.get(COLLINFO)?)?;
            all.into_iter().take(n).collect()
        } else {
            vec![ep.to_string()]
        };
        *self.crawls.borrow_mut() = Some(list.clone());
        Ok(list)
    }

    fn base_params(&self, since: Option<i64>) -> Vec<(&'static str, String)> {
        let q = &self.query;
        let mut p = vec![("url", q.pattern.clone()), ("output", "json".into())];
        if let Some(f) = since.map(cdx_ts).or_else(|| q.from.clone()) {
            p.push(("from", f));
        }
        if let Some(t) = &q.to {
            p.push(("to", t.clone()));
        }
        if let Some(m) = &q.match_type {
            p.push(("matchType", m.clone()));
        }
        p
    }

    fn url(crawl: &str, params: &[(&str, String)]) -> Result<String> {
        let mut u = url::Url::parse(&format!("{INDEX}{crawl}-index"))?;
        u.query_pairs_mut().extend_pairs(params);
        Ok(u.into())
    }

    /// How many index pages the query has in `crawl`.
    fn num_pages(&self, client: &Client, crawl: &str, since: Option<i64>) -> Result<usize> {
        if let Some(n) = self.pages.borrow().get(crawl) {
            return Ok(*n);
        }
        let mut p = self.base_params(since);
        p.push(("showNumPages", "true".into()));
        p.push(("pageSize", "1".into()));
        let f = client.fetch(&Self::url(crawl, &p)?, &[], not_found_ok())?;
        let n = if f.status == 404 {
            0
        } else {
            let v: Value = serde_json::from_str(&f.body).context("commoncrawl showNumPages")?;
            v.get("pages").and_then(Value::as_u64).unwrap_or(0) as usize
        };
        self.pages.borrow_mut().insert(crawl.to_string(), n);
        Ok(n)
    }
}

fn not_found_ok() -> Opts {
    Opts {
        not_found_ok: true,
        ..Opts::default()
    }
}

impl Source for CommonCrawl {
    fn kind(&self) -> Kind {
        Kind::CommonCrawl
    }

    fn query(&self) -> &CdxQuery {
        &self.query
    }

    fn resumable(&self) -> bool {
        true
    }

    /// One index block; the block decides how many rows it holds.
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
        let crawls = self.crawls(client)?;
        let (crawl, page) = match cursor {
            Some(Cursor::Key(k)) => parse_cursor(k)?,
            Some(c) => anyhow::bail!("commoncrawl pages by crawl and page, not {c:?}"),
            None => (
                crawls
                    .first()
                    .context("no Common Crawl crawls listed")?
                    .clone(),
                0,
            ),
        };
        let pages = self.num_pages(client, &crawl, since)?;
        let mut records = Vec::new();
        if page < pages {
            let mut p = self.base_params(since);
            p.push(("page", page.to_string()));
            p.push(("pageSize", "1".into()));
            let f = client.fetch(&Self::url(&crawl, &p)?, &[], not_found_ok())?;
            if f.status != 404 {
                records = parse_cc_cdx(&f.body, &crawl);
            }
        }
        let truncated = records.len() > size;
        records.truncate(size);
        let next = if page + 1 < pages {
            Some(format!("{crawl}#{}", page + 1))
        } else {
            // The next crawl in the list, if any.
            crawls
                .iter()
                .position(|c| *c == crawl)
                .and_then(|i| crawls.get(i + 1))
                .map(|c| format!("{c}#0"))
        };
        Ok(Page {
            records,
            next: next.map(Cursor::Key),
            truncated,
        })
    }
}

fn parse_cursor(k: &str) -> Result<(String, usize)> {
    let (c, p) = k
        .rsplit_once('#')
        .with_context(|| format!("bad commoncrawl cursor `{k}`"))?;
    Ok((c.to_string(), p.parse()?))
}

/// The crawl ids in `collinfo.json`, newest first (the order it lists them).
pub fn parse_collinfo(body: &str) -> Result<Vec<String>> {
    let v: Vec<Value> = serde_json::from_str(body).context("collinfo.json")?;
    Ok(v.iter()
        .filter_map(|c| c.get("id").and_then(Value::as_str))
        .filter(|id| id.starts_with("CC-MAIN-"))
        .map(str::to_string)
        .collect())
}

/// Parse Common Crawl CDX NDJSON from `crawl`. Records are redacted before
/// they are returned.
pub fn parse_cc_cdx(body: &str, crawl: &str) -> Vec<Observation> {
    let mut out = Vec::new();
    for line in body.lines().filter(|l| !l.trim().is_empty()) {
        let Ok(v) = serde_json::from_str::<Value>(line) else {
            continue;
        };
        let gs = |k: &str| v.get(k).and_then(Value::as_str).unwrap_or_default();
        let (ts, url) = (gs("timestamp"), gs("url"));
        if ts.is_empty() || url.is_empty() {
            continue;
        }
        let mut lookup = url::Url::parse(&format!("{INDEX}{crawl}-index")).expect("static URL");
        lookup
            .query_pairs_mut()
            .append_pair("url", url)
            .append_pair("output", "json")
            .append_pair("from", ts)
            .append_pair("to", ts);
        let mut o = Observation {
            id: format!("commoncrawl:{ts}:{}", gs("digest")),
            source: "commoncrawl".into(),
            ts: parse_ts(ts).unwrap_or(0),
            ts_kind: TsKind::Capture,
            url: url.to_string(),
            status: gs("status").parse().ok(),
            reference: Some(lookup.into()),
            ..Default::default()
        };
        redact_observation(&mut o);
        // The digest is the body's: same-second captures of different URLs
        // with one body (an error page) would otherwise share an id.
        o.id = format!("{}:{}", o.id, crate::short_hash(&o.url));
        out.push(o);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collinfo_newest_first() {
        let body =
            r#"[{"id":"CC-MAIN-2099-40","cdx-api":"x"},{"id":"CC-MAIN-2099-35"},{"id":"other"}]"#;
        assert_eq!(
            parse_collinfo(body).unwrap(),
            ["CC-MAIN-2099-40", "CC-MAIN-2099-35"]
        );
        assert!(parse_collinfo("<html>").is_err());
    }

    #[test]
    fn cc_rows() {
        let body = concat!(
            r#"{"urlkey":"example,relay)/x","timestamp":"20260910120000","url":"https://relay.example/https://t.example/?api_key=s3cr3tvalue","mime":"text/html","status":"200","digest":"ABC","length":"10","offset":"5","filename":"crawl-data/x.warc.gz"}"#,
            "\nnot json\n",
            r#"{"timestamp":"20260910120500","url":"https://relay.example/b","status":"301","digest":"DEF"}"#
        );
        let v = parse_cc_cdx(body, "CC-MAIN-2099-40");
        assert_eq!(v.len(), 2);
        assert!(v[0].id.starts_with("commoncrawl:20260910120000:ABC:"));
        assert_eq!(v[0].ts_kind, TsKind::Capture);
        assert!(v[0].url.contains("api_key=REDACTED-"));
        assert!(
            v[0].reference
                .as_deref()
                .unwrap()
                .starts_with("https://index.commoncrawl.org/CC-MAIN-2099-40-index?")
        );
        assert_eq!(v[1].status, Some(301));
        assert_eq!(
            parse_cursor("CC-MAIN-2099-40#3").unwrap(),
            ("CC-MAIN-2099-40".to_string(), 3)
        );
    }
}
