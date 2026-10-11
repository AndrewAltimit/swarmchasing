//! npm registry search (`registry.npmjs.org/-/v1/search`): package names,
//! latest versions and publish times matching a text query. Metadata only:
//! tarballs and package code are never downloaded, and maintainer names and
//! email addresses in the response are dropped.
//!
//! Terms: npm's Open Source Terms (<https://docs.npmjs.com/policies/open-source-terms>)
//! allow programmatic access through the publicly documented APIs and
//! replication through the public APIs, forbid automating the website and
//! straining the registry with unreasonable volume, and forbid using the
//! registry as a general-purpose database. A few paced search requests per
//! run, keeping only matches, stays well inside that.
//!
//! The replicate `_changes` feed was considered and not used: its rows carry
//! no time, so they cannot be placed on a timeline without fetching each
//! package document.

use crate::pager::{Coverage, Cursor, Page};
use crate::{CdxQuery, Client, Kind, Source, parse_date};
use anyhow::{Context, Result};
use sc_core::{Observation, TsKind, redact_observation};
use serde_json::Value;

const SEARCH: &str = "https://registry.npmjs.org/-/v1/search";
/// The search API's page size cap.
const MAX_PAGE: usize = 250;

/// An npm search as a [`Source`]. `query.pattern` is the search text (npm
/// search syntax, e.g. `keywords:foo` or a run tag); `query.canary` a search
/// that always has hits, run once per pull as a canary.
pub struct Npm {
    pub query: CdxQuery,
}

impl Source for Npm {
    fn kind(&self) -> Kind {
        Kind::Npm
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
        let offset = match cursor {
            Some(Cursor::Offset(n)) => *n,
            Some(c) => anyhow::bail!("npm pages by offset, not {c:?}"),
            None => 0,
        };
        let search = |text: &str, size: usize, from: usize| -> Result<String> {
            let mut u = url::Url::parse(SEARCH)?;
            u.query_pairs_mut()
                .append_pair("text", text)
                .append_pair("size", &size.to_string())
                .append_pair("from", &from.to_string());
            client.get(u.as_str()).context("npm search")
        };
        let body = search(&self.query.pattern, size, offset)?;
        let (mut records, total, n) = parse_npm_search(&body)?;
        let mut cov = Coverage {
            unit: "packages",
            read: n as u64,
            available: if offset == 0 { total as u64 } else { 0 },
            ..Default::default()
        };
        // Once per pull: a search known to match proves an empty result is
        // the pattern's, not a changed API's.
        if let (0, Some(c)) = (offset, self.query.canary.as_deref()) {
            let (_, hits, _) = parse_npm_search(&search(c, 1, 0)?)?;
            cov.canary = Some(hits > 0);
        }
        let from = since.or_else(|| self.query.from.as_deref().and_then(sc_core::parse_ts));
        let to = self.query.to.as_deref().and_then(sc_core::parse_ts);
        records.retain(|o| from.is_none_or(|t| o.ts >= t) && to.is_none_or(|t| o.ts <= t));
        let next = (n > 0 && offset + n < total).then_some(Cursor::Offset(offset + n));
        Ok(Page {
            records,
            next,
            truncated: false,
            coverage: Some(cov),
        })
    }
}

/// Parse an npm search response: the packages, the total hit count, and how
/// many objects the page held before any filtering. Records are redacted.
pub fn parse_npm_search(body: &str) -> Result<(Vec<Observation>, usize, usize)> {
    let v: Value = serde_json::from_str(body).context("npm search: not JSON")?;
    let objs = v
        .get("objects")
        .and_then(Value::as_array)
        .context("npm search: no `objects` array")?;
    let mut out = Vec::new();
    for o in objs {
        let s = |p: &str| o.pointer(p).and_then(Value::as_str).map(str::to_string);
        let (Some(name), Some(version)) = (s("/package/name"), s("/package/version")) else {
            continue;
        };
        let link = s("/package/links/npm")
            .filter(|l| l.starts_with("https://www.npmjs.com/"))
            .unwrap_or_else(|| format!("https://www.npmjs.com/package/{name}"));
        let mut rec = Observation {
            id: format!("npm:{name}@{version}"),
            source: "npm".into(),
            ts: s("/package/date")
                .as_deref()
                .and_then(parse_date)
                .unwrap_or(0),
            // The publish request reaching the registry.
            ts_kind: TsKind::Request,
            url: format!("{link}/v/{version}"),
            reference: Some(link),
            ..Default::default()
        };
        redact_observation(&mut rec);
        out.push(rec);
    }
    let total = v
        .get("total")
        .and_then(Value::as_u64)
        .map_or(objs.len(), |n| n as usize);
    Ok((out, total, objs.len()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn npm_search_page() {
        let body = r#"{"objects":[
          {"package":{"name":"uqtag-probe","version":"0.0.3","date":"2026-10-06T20:51:22.967Z",
            "publisher":{"username":"someone","email":"someone@example.org"},
            "links":{"npm":"https://www.npmjs.com/package/uqtag-probe"}}},
          {"package":{"name":"no-version"}}
        ],"total":3}"#;
        let (v, total, n) = parse_npm_search(body).unwrap();
        assert_eq!((v.len(), total, n), (1, 3, 2));
        assert_eq!(v[0].id, "npm:uqtag-probe@0.0.3");
        assert_eq!(
            v[0].url,
            "https://www.npmjs.com/package/uqtag-probe/v/0.0.3"
        );
        assert_eq!(v[0].ts, 1_791_319_882);
        let json = serde_json::to_string(&v[0]).unwrap();
        assert!(!json.contains("example.org"), "maintainer data is dropped");
        assert!(parse_npm_search("{}").is_err());
    }
}
