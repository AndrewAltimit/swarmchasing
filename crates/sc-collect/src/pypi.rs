//! PyPI's RSS feeds: the newest releases (`/rss/updates.xml`) or the newest
//! projects (`/rss/packages.xml`). Names, versions, summaries and times only;
//! distributions are never downloaded. Each feed holds the last few dozen
//! items, so one request is one page and frequent runs see more.
//!
//! Terms: PyPI's Terms of Service (<https://policies.python.org/pypi.org/Terms-of-Service/>)
//! allow API use subject to its rate limits, warn that abuse or excessively
//! frequent requests may lead to suspension, and forbid using the data for
//! spam or selling personal information. The feeds are public, cached and
//! revalidated with ETags; one request per feed per run.

use crate::pager::{Coverage, Cursor, Page};
use crate::{CdxQuery, Client, Kind, Needles, Source, parse_date};
use anyhow::Result;
use sc_core::{Observation, TsKind, redact_observation};

/// A PyPI feed filter as a [`Source`]. `query.pattern` is `|`-separated
/// substrings matched against each item's name and summary (`*` keeps all);
/// `query.endpoint` the feed, `updates` (default) or `packages`.
pub struct Pypi {
    pub query: CdxQuery,
}

impl Source for Pypi {
    fn kind(&self) -> Kind {
        Kind::Pypi
    }

    fn query(&self) -> &CdxQuery {
        &self.query
    }

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
        let feed = match self.query.endpoint.as_deref().unwrap_or("updates") {
            "updates" => "updates",
            "packages" => "packages",
            f => anyhow::bail!("unknown PyPI feed `{f}` (expected updates or packages)"),
        };
        let body = client.get(&format!("https://pypi.org/rss/{feed}.xml"))?;
        let needles = Needles::new(&self.query.pattern);
        let from = since.or_else(|| self.query.from.as_deref().and_then(sc_core::parse_ts));
        let mut records: Vec<Observation> = parse_pypi_rss(&body, &needles)
            .into_iter()
            .filter(|o| from.is_none_or(|t| o.ts >= t))
            .collect();
        let truncated = records.len() > size;
        records.truncate(size);
        // The feed always holds its last few dozen items: an empty one means
        // the feed or its format changed.
        let items = body.matches("<item>").count() as u64;
        Ok(Page {
            stopped: None,
            records,
            next: None,
            truncated,
            coverage: Some(Coverage {
                unit: "items",
                read: items,
                available: items,
                canary: Some(items > 0),
                ..Default::default()
            }),
        })
    }
}

/// Parse a PyPI RSS feed, keeping items whose title, link or summary
/// matches. Records are redacted before they are returned.
pub fn parse_pypi_rss(body: &str, needles: &Needles) -> Vec<Observation> {
    let mut out = Vec::new();
    for item in body.split("<item>").skip(1) {
        let item = item.split("</item>").next().unwrap_or_default();
        let (Some(title), Some(link)) = (tag(item, "title"), tag(item, "link")) else {
            continue;
        };
        let summary = tag(item, "description").unwrap_or_default();
        if !link.starts_with("https://pypi.org/project/")
            || !(needles.matches(&title) || needles.matches(&link) || needles.matches(&summary))
        {
            continue;
        }
        // `/project/<name>/<version>/` for a release, `/project/<name>/` for a new project.
        let parts: Vec<&str> = link
            .trim_start_matches("https://pypi.org/project/")
            .split('/')
            .filter(|p| !p.is_empty())
            .collect();
        let id = match parts.as_slice() {
            [name, version, ..] => format!("pypi:{name}@{version}"),
            [name] => format!("pypi:{name}"),
            _ => continue,
        };
        let mut o = Observation {
            id,
            source: "pypi".into(),
            ts: tag(item, "pubDate")
                .as_deref()
                .and_then(parse_date)
                .unwrap_or(0),
            // The upload request reaching the registry.
            ts_kind: TsKind::Request,
            url: link.clone(),
            reference: Some(link),
            ..Default::default()
        };
        redact_observation(&mut o);
        out.push(o);
    }
    out
}

/// The text of the first `<name>` element in `s`, entities decoded.
fn tag(s: &str, name: &str) -> Option<String> {
    let open = format!("<{name}>");
    let a = s.find(&open)? + open.len();
    let b = a + s[a..].find(&format!("</{name}>"))?;
    let t = s[a..b].trim();
    let t = t
        .strip_prefix("<![CDATA[")
        .and_then(|x| x.strip_suffix("]]>"))
        .unwrap_or(t);
    Some(
        t.replace("&lt;", "<")
            .replace("&gt;", ">")
            .replace("&quot;", "\"")
            .replace("&#39;", "'")
            .replace("&amp;", "&"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const FEED: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0"><channel><title>PyPI recent updates</title>
  <item>
    <title>uqtag-helper 0.1.0</title>
    <link>https://pypi.org/project/uqtag-helper/0.1.0/</link>
    <description>Fetch pages through r.jina.ai &amp; friends</description>
    <pubDate>Sat, 10 Oct 2026 19:57:54 GMT</pubDate>
  </item>
  <item>
    <title>plain-lib 2.0</title>
    <link>https://pypi.org/project/plain-lib/2.0/</link>
    <description>Nothing to see</description>
    <pubDate>Sat, 10 Oct 2026 19:57:42 GMT</pubDate>
  </item>
</channel></rss>"#;

    #[test]
    fn rss_items_filtered() {
        let v = parse_pypi_rss(FEED, &Needles::new("r.jina.ai"));
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].id, "pypi:uqtag-helper@0.1.0");
        assert_eq!(v[0].ts, 1_791_662_274);
        assert_eq!(v[0].ts_kind, TsKind::Request);
        assert_eq!(parse_pypi_rss(FEED, &Needles::new("*")).len(), 2);
        let newest = "<item><title>newpkg added to PyPI</title><link>https://pypi.org/project/newpkg/</link><pubDate>Sat, 10 Oct 2026 19:48:59 GMT</pubDate></item>";
        assert_eq!(
            parse_pypi_rss(newest, &Needles::new("*"))[0].id,
            "pypi:newpkg"
        );
        assert!(parse_pypi_rss("<html></html>", &Needles::new("*")).is_empty());
    }
}
