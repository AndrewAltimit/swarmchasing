//! urlscan.io public search (`/api/v1/search/`): scans someone submitted to
//! urlscan.io and made public. Result metadata only (the submitted URL, where
//! the scan ended, the target's IP and ASN, the report link); page content,
//! DOMs and screenshots are never fetched.
//!
//! Terms: <https://urlscan.io/terms/> give a licence for personal,
//! non-commercial use, require respecting rate limits and quotas with
//! backoff, forbid scrapers other than acceptable API use, and require
//! written permission for systematic retrieval to build a database or for
//! republishing. So it is a per-case lookup (`swarmchase collect urlscan`),
//! not a scheduled source; records are cited by report link and never
//! republished. An API key (`URLSCAN_APIKEY`) raises the quota but is not
//! needed for public results.

use crate::pager::{Cursor, Page};
use crate::{CdxQuery, Client, Kind, Source, day, parse_date};
use anyhow::{Context, Result};
use sc_core::{Observation, TsKind, redact_observation};
use serde_json::Value;

const SEARCH: &str = "https://urlscan.io/api/v1/search/";
/// The search API's page size cap.
const MAX_PAGE: usize = 100;

/// A urlscan.io search as a [`Source`]. `query.pattern` is a urlscan search
/// query (Elasticsearch query string, e.g. `task.domain:r.jina.ai`).
pub struct Urlscan {
    pub query: CdxQuery,
    pub api_key: Option<String>,
}

impl Source for Urlscan {
    fn kind(&self) -> Kind {
        Kind::Urlscan
    }

    fn query(&self) -> &CdxQuery {
        &self.query
    }

    fn page_size(&self) -> usize {
        self.query.page_size.clamp(1, MAX_PAGE)
    }

    fn page(
        &self,
        client: &Client,
        since: Option<i64>,
        cursor: Option<&Cursor>,
        size: usize,
    ) -> Result<Page> {
        let after = match cursor {
            Some(Cursor::Key(k)) => Some(k.as_str()),
            Some(c) => anyhow::bail!("urlscan pages by search_after key, not {c:?}"),
            None => None,
        };
        let from = since.or_else(|| self.query.from.as_deref().and_then(sc_core::parse_ts));
        let to = self.query.to.as_deref().and_then(sc_core::parse_ts);
        let mut q = format!("({})", self.query.pattern);
        match (from, to) {
            (None, None) => {}
            (f, t) => {
                let f = f.map_or("*".to_string(), day);
                let t = t.map_or("*".to_string(), day);
                q.push_str(&format!(" AND date:[{f} TO {t}]"));
            }
        }
        let mut u = url::Url::parse(SEARCH)?;
        {
            let mut p = u.query_pairs_mut();
            p.append_pair("q", &q)
                .append_pair("size", &size.to_string());
            if let Some(a) = after {
                p.append_pair("search_after", a);
            }
        }
        let body = match &self.api_key {
            Some(k) => client.get_with(u.as_str(), &[("API-Key", k)]),
            None => client.get(u.as_str()),
        }
        .context("urlscan search")?;
        let (records, next) = parse_urlscan_search(&body)?;
        Ok(Page {
            records,
            next: next.map(Cursor::Key),
            truncated: false,
        })
    }
}

/// Parse a urlscan.io search response: the public results, and the
/// `search_after` key of the next page when there is one. Records are
/// redacted before they are returned.
pub fn parse_urlscan_search(body: &str) -> Result<(Vec<Observation>, Option<String>)> {
    let v: Value = serde_json::from_str(body).context("urlscan search: not JSON")?;
    let results = v
        .get("results")
        .and_then(Value::as_array)
        .context("urlscan search: no `results` array")?;
    let mut out = Vec::new();
    for r in results {
        let s = |path: &[&str]| {
            path.iter()
                .try_fold(r, |v, k| v.get(*k))
                .and_then(Value::as_str)
                .map(str::to_string)
        };
        if s(&["task", "visibility"]).is_some_and(|vis| vis != "public") {
            continue;
        }
        let (Some(uuid), Some(url)) = (s(&["task", "uuid"]).or(s(&["_id"])), s(&["task", "url"]))
        else {
            continue;
        };
        if !uuid.chars().all(|c| c.is_ascii_hexdigit() || c == '-') {
            continue;
        }
        let mut o = Observation {
            id: format!("urlscan:{uuid}"),
            source: "urlscan".into(),
            ts: s(&["task", "time"])
                .as_deref()
                .and_then(parse_date)
                .unwrap_or(0),
            ts_kind: TsKind::Submit,
            url,
            // Where urlscan's scanner reached the target: the target's
            // network, never the submitter's.
            ip: s(&["page", "ip"]),
            target_asn: s(&["page", "asn"]).and_then(|a| a.trim_start_matches("AS").parse().ok()),
            status: s(&["page", "status"]).and_then(|x| x.parse().ok()),
            final_url: s(&["page", "url"]),
            reference: Some(format!("https://urlscan.io/result/{uuid}/")),
            ..Default::default()
        };
        redact_observation(&mut o);
        out.push(o);
    }
    let has_more = v.get("has_more").and_then(Value::as_bool).unwrap_or(false);
    let next = results
        .iter()
        .rev()
        .find_map(|r| r.get("sort"))
        .and_then(Value::as_array)
        .filter(|_| has_more)
        .map(|sort| {
            sort.iter()
                .map(|x| match x {
                    Value::String(s) => s.clone(),
                    other => other.to_string(),
                })
                .collect::<Vec<_>>()
                .join(",")
        });
    Ok((out, next))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urlscan_page() {
        let body = r#"{"results":[
          {"task":{"visibility":"public","time":"2026-10-04T08:10:00.000Z","uuid":"0000aaaa-0000-0000-0000-000000000001","url":"https://relay.example/https://t.example/?token=s3cr3tvalue"},
           "page":{"ip":"203.0.113.9","asn":"AS64500","status":"200","url":"https://t.example/"},
           "sort":[1791101400000,"0000aaaa-0000-0000-0000-000000000001"]},
          {"task":{"visibility":"unlisted","uuid":"0000aaaa-0000-0000-0000-000000000002","url":"https://x.example/"}}
        ],"total":10000,"has_more":true}"#;
        let (v, next) = parse_urlscan_search(body).unwrap();
        assert_eq!(v.len(), 1);
        let o = &v[0];
        assert_eq!(o.id, "urlscan:0000aaaa-0000-0000-0000-000000000001");
        assert_eq!((o.ts, o.ts_kind), (1_791_101_400, TsKind::Submit));
        assert_eq!(
            (o.asn, o.target_asn, o.status),
            (None, Some(64500), Some(200))
        );
        assert!(o.url.contains("token=REDACTED-"));
        assert_eq!(
            next.as_deref(),
            Some("1791101400000,0000aaaa-0000-0000-0000-000000000001")
        );
        let (_, last) = parse_urlscan_search(r#"{"results":[],"has_more":false}"#).unwrap();
        assert!(last.is_none());
        assert!(parse_urlscan_search(r#"{"message":"rate limited"}"#).is_err());
    }
}
