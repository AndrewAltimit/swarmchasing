//! urlquery.net report search and single reports. Needs an API key from a
//! urlquery account.
//!
//! The terms allow personal, non-commercial research use and forbid
//! redistributing their content without permission, so records collected
//! here are for our analysis and are cited by report link, not republished.

use crate::pager::{Cursor, Page};
use crate::{CdxQuery, Client, Kind, Source};
use anyhow::{Context, Result};
use sc_core::{Observation, parse_ts, redact_observation};
use serde_json::Value;

const URLQUERY_SEARCH: &str = "https://api.urlquery.net/public/v1/search/reports/";
const URLQUERY_REPORT: &str = "https://api.urlquery.net/public/v1/report/";
/// Conservative page size; the API's own maximum is not documented.
const URLQUERY_MAX_PAGE: usize = 100;

/// A urlquery search as a [`Source`]. `query.pattern` is the search query.
pub struct Urlquery {
    pub query: CdxQuery,
    pub api_key: String,
}

impl Source for Urlquery {
    fn kind(&self) -> Kind {
        Kind::Urlquery
    }

    fn query(&self) -> &CdxQuery {
        &self.query
    }

    fn page_size(&self) -> usize {
        self.query.page_size.clamp(1, URLQUERY_MAX_PAGE)
    }

    fn page(
        &self,
        client: &Client,
        since: Option<i64>,
        cursor: Option<&Cursor>,
        size: usize,
    ) -> Result<Page> {
        let offset = match cursor {
            Some(Cursor::Offset(n)) => *n,
            Some(c) => anyhow::bail!("urlquery pages by offset, not {c:?}"),
            None => 0,
        };
        let mut q = self.query.clone();
        if let Some(t) = since {
            q.from = Some(day(t));
        }
        let p = client.urlquery_page(&self.api_key, &q, offset, size)?;
        let n = p.records.len();
        let next = (n > 0 && offset + n < p.total_hits).then_some(Cursor::Offset(offset + n));
        Ok(Page {
            records: p.records,
            next,
        })
    }
}

impl Client {
    /// urlquery.net report search (`/public/v1/search/reports/`). Pages by
    /// offset until `q.limit` reports or the end. `q.pattern` is the urlquery
    /// search query; `q.from` / `q.to` are narrowed to whole days, which is all
    /// the API accepts.
    pub fn urlquery(&self, api_key: &str, q: &CdxQuery) -> Result<Vec<Observation>> {
        let src = Urlquery {
            query: q.clone(),
            api_key: api_key.to_string(),
        };
        Ok(src.pull(self, None, None, q.limit)?.strict()?.observations)
    }

    pub fn urlquery_page(
        &self,
        api_key: &str,
        q: &CdxQuery,
        offset: usize,
        limit: usize,
    ) -> Result<UrlqueryPage> {
        let mut u = url::Url::parse(URLQUERY_SEARCH)?;
        {
            let mut qp = u.query_pairs_mut();
            qp.append_pair("query", &q.pattern);
            qp.append_pair("limit", &limit.to_string());
            qp.append_pair("offset", &offset.to_string());
            for (k, v) in [("start_date", &q.from), ("end_date", &q.to)] {
                if let Some(d) = v.as_deref().and_then(parse_ts) {
                    qp.append_pair(k, &day(d));
                }
            }
        }
        let body = self
            .get_with(u.as_str(), &[("X-APIKEY", api_key)])
            .context("urlquery search (is URLQUERY_APIKEY valid?)")?;
        parse_urlquery_search(&body)
    }

    /// One urlquery report by ID (bare UUID or `urlquery:<uuid>`), redacted.
    pub fn urlquery_report(&self, api_key: &str, id: &str) -> Result<Observation> {
        let id = id.strip_prefix("urlquery:").unwrap_or(id);
        if !id.chars().all(|c| c.is_ascii_hexdigit() || c == '-') || id.is_empty() {
            anyhow::bail!("not a urlquery report ID: {id}");
        }
        let body = self
            .get_with(&format!("{URLQUERY_REPORT}{id}"), &[("X-APIKEY", api_key)])
            .with_context(|| format!("urlquery report {id}"))?;
        let v: Value = serde_json::from_str(&body).context("urlquery report: not JSON")?;
        let mut o = sc_core::urlquery::report_to_obs(&v)
            .with_context(|| format!("urlquery report {id}: unexpected shape"))?;
        redact_observation(&mut o);
        Ok(o)
    }
}

fn day(ts: i64) -> String {
    chrono::DateTime::from_timestamp(ts, 0)
        .map(|d| d.format("%Y-%m-%d").to_string())
        .unwrap_or_default()
}

/// One page of urlquery search results.
#[derive(Debug, Clone, Default)]
pub struct UrlqueryPage {
    pub records: Vec<Observation>,
    pub total_hits: usize,
}

/// Parse a urlquery search response. Records are redacted before they are returned.
pub fn parse_urlquery_search(body: &str) -> Result<UrlqueryPage> {
    let v: Value = serde_json::from_str(body).context("urlquery search: not JSON")?;
    let reports = v
        .get("reports")
        .and_then(Value::as_array)
        .context("urlquery search: no `reports` array")?;
    let mut records: Vec<Observation> = reports
        .iter()
        .filter_map(sc_core::urlquery::report_to_obs)
        .collect();
    for o in &mut records {
        redact_observation(o);
    }
    Ok(UrlqueryPage {
        total_hits: v
            .get("total_hits")
            .and_then(Value::as_u64)
            .map_or(records.len(), |n| n as usize),
        records,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urlquery_search_page() {
        let body = r#"{"query":"r.jina.ai","total_hits":7,"limit":1,"offset":0,"reports":[
            {"report_id":"a1","date":"2026-10-04T08:10:00Z",
             "url":{"schema":"https","addr":"https://r.jina.ai/https://x.example/?session_token=s3cr3tvalue"},
             "ip":{"addr":"203.0.113.7","asn":64500}}]}"#;
        let p = parse_urlquery_search(body).unwrap();
        assert_eq!(p.total_hits, 7);
        assert_eq!(p.records[0].id, "urlquery:a1");
        assert!(p.records[0].url.contains("session_token=REDACTED-"));
        assert!(parse_urlquery_search(r#"{"error":"unauthorized"}"#).is_err());
        assert_eq!(day(1791101400), "2026-10-04");
    }
}
