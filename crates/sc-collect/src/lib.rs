//! Passive collectors.
//!
//! Ground rules, enforced by what this crate does and does not implement:
//! - Read **indexes and public records only** (CDX listings, scan-service
//!   search results, CT log entries, registry and event-stream metadata,
//!   security.txt). Never download archived content, package code or WARC data.
//!   Never open captured pages or the URLs agents submitted: they may be live
//!   exploit payloads or trigger callbacks to the operator.
//! - Never read or write agent callback channels (inboxes, ntfy topics, pastes).
//! - Never fetch an address a record supplied (a `Signature-Agent` URI):
//!   provider documents are read only from the addresses the provider documents.
//! - Be polite: one request at a time, with a minimum interval per host, an
//!   identifying user agent, and backoff when a server says it is overloaded.
//! - Redact secrets before records leave this crate (see `sc_core::redact`).
//!
//! [`Client`] is the HTTP client every collector shares. The record sources
//! (see [`Kind`]) implement [`Source`] and page through [`pager`]; crt.sh,
//! security.txt and RDAP are single lookups on the client. [`psl`] finds a
//! host's registrable domain, and [`asn`] fetches and loads the offline
//! IP-to-ASN table. [`identity`] fetches the range files and key
//! directories providers publish for their own agents.

use anyhow::Result;
use serde::{Deserialize, Serialize};

mod arquivo;
pub mod asn;
mod cache;
mod client;
mod commoncrawl;
mod crtsh;
mod ctlog;
mod gharchive;
pub mod identity;
mod mcp;
mod memento;
mod npm;
pub mod pager;
pub mod psl;
mod pypi;
mod rdap;
pub mod securitytxt;
mod urlquery;
mod urlscan;
mod wayback;
mod wellknown;

pub use arquivo::{Arquivo, parse_arquivo_cdx};
pub use client::{Client, DEFAULT_MAX_BODY, Retry, USER_AGENT, parse_retry_after};
pub use commoncrawl::{CommonCrawl, parse_cc_cdx, parse_collinfo};
pub use crtsh::CertRecord;
pub use ctlog::{CtLog, parse_entries, san_dns_names};
pub use gharchive::{GhArchive, filter_events};
pub use mcp::{McpRegistry, parse_mcp_servers};
pub use memento::{Memento, parse_timemap};
pub use npm::{Npm, parse_npm_search};
pub use pager::{Coverage, Cursor, Page, Pull};
pub use pypi::{Pypi, parse_pypi_rss};
pub use urlquery::{Urlquery, UrlqueryPage, parse_urlquery_search};
pub use urlscan::{Urlscan, parse_urlscan_search};
pub use wayback::{CdxPage, Wayback, parse_wayback_cdx};
pub use wellknown::{FOOTPRINTS, WellKnown};

/// A query against a record source: a CDX URL pattern, a search query, or
/// the filter a streamed source keeps records by. Also a `watchlist.toml`
/// source entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CdxQuery {
    pub pattern: String,
    #[serde(default)]
    pub from: Option<String>,
    #[serde(default)]
    pub to: Option<String>,
    /// Maximum records per pull.
    #[serde(default = "default_limit")]
    pub limit: usize,
    /// `exact` | `prefix` | `host` | `domain`
    #[serde(default)]
    pub match_type: Option<String>,
    #[serde(default)]
    pub collapse_digest: bool,
    /// Records per request when paging (Wayback, urlquery, urlscan, npm).
    #[serde(default = "default_page_size")]
    pub page_size: usize,
    /// Which instance of the source to read, where it has several: a CT log's
    /// base URL, a Common Crawl crawl (`CC-MAIN-…`, `latest` or `latest:N`),
    /// a Memento timemap endpoint, a PyPI feed (`updates` or `packages`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    /// For sources read as a stream and filtered: how much of the stream one
    /// pull reads (CT log entries, GH Archive hours).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scan: Option<usize>,
    /// CDX `filter` expressions (`collection:SAWP.*`, `!statuscode:404`),
    /// applied by the index server (Wayback, Arquivo.pt, Common Crawl).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub filter: Vec<String>,
    /// Wayback: read the time range in windows of this many days, oldest
    /// first, so a host with many captures is never asked for all of them in
    /// one index scan.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub slice_days: Option<u32>,
    /// A query known to match, run once per pull to prove the source still
    /// answers the way the parser expects (npm). Its results are not kept.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub canary: Option<String>,
    /// For streamed sources: most compressed megabytes one pull downloads
    /// (GH Archive).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_mb: Option<u64>,
}

fn default_limit() -> usize {
    5000
}

fn default_page_size() -> usize {
    1000
}

impl Default for CdxQuery {
    fn default() -> Self {
        Self {
            pattern: String::new(),
            from: None,
            to: None,
            limit: default_limit(),
            match_type: None,
            collapse_digest: false,
            page_size: default_page_size(),
            endpoint: None,
            scan: None,
            filter: Vec::new(),
            slice_days: None,
            canary: None,
            max_mb: None,
        }
    }
}

/// The record sources.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Wayback,
    Arquivo,
    Urlquery,
    CommonCrawl,
    Urlscan,
    Memento,
    GhArchive,
    Npm,
    Pypi,
    CtLog,
    WellKnown,
    Mcp,
}

impl Kind {
    pub const ALL: [Kind; 12] = [
        Self::Wayback,
        Self::Arquivo,
        Self::Urlquery,
        Self::CommonCrawl,
        Self::Urlscan,
        Self::Memento,
        Self::GhArchive,
        Self::Npm,
        Self::Pypi,
        Self::CtLog,
        Self::WellKnown,
        Self::Mcp,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Self::Wayback => "wayback",
            Self::Arquivo => "arquivo",
            Self::Urlquery => "urlquery",
            Self::CommonCrawl => "commoncrawl",
            Self::Urlscan => "urlscan",
            Self::Memento => "memento",
            Self::GhArchive => "gharchive",
            Self::Npm => "npm",
            Self::Pypi => "pypi",
            Self::CtLog => "ctlog",
            Self::WellKnown => "wellknown",
            Self::Mcp => "mcp",
        }
    }

    /// Whether its records carry the time a URL was submitted (a scan
    /// service), the only request-like time most public records have.
    pub fn submit_time(self) -> bool {
        matches!(self, Self::Urlquery | Self::Urlscan)
    }

    /// The environment variable holding the source's API key, if it takes one.
    pub fn key_env(self) -> Option<&'static str> {
        match self {
            Self::Urlquery => Some("URLQUERY_APIKEY"),
            Self::Urlscan => Some("URLSCAN_APIKEY"),
            _ => None,
        }
    }

    /// Whether the source cannot run without its key.
    pub fn needs_key(self) -> bool {
        self == Self::Urlquery
    }

    /// The API key from [`Kind::key_env`], if set and not blank.
    pub fn key_from_env(self) -> Option<String> {
        std::env::var(self.key_env()?)
            .ok()
            .map(|k| k.trim().to_string())
            .filter(|k| !k.is_empty())
    }
}

impl std::str::FromStr for Kind {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self> {
        Self::ALL
            .into_iter()
            .find(|k| k.name() == s)
            .ok_or_else(|| {
                let names: Vec<&str> = Self::ALL.iter().map(|k| k.name()).collect();
                anyhow::anyhow!("unknown kind `{s}` (expected one of {})", names.join(", "))
            })
    }
}

/// A source of records, read a page at a time.
pub trait Source {
    fn kind(&self) -> Kind;

    fn query(&self) -> &CdxQuery;

    /// Whether its cursor stays valid across runs, so a pull cut short can
    /// continue on the next one.
    fn resumable(&self) -> bool {
        false
    }

    /// Whether it reads a stream from a position kept across runs: the
    /// pull's [`Coverage::next`] is passed back as `Cursor::Offset` to start
    /// the next pull there (GH Archive hours, CT log entries).
    fn checkpointed(&self) -> bool {
        false
    }

    /// Most records one request asks for.
    fn page_size(&self) -> usize;

    /// One page of up to `size` records captured from `since` (Unix seconds,
    /// replacing the query's `from`), continuing at `cursor`.
    fn page(
        &self,
        client: &Client,
        since: Option<i64>,
        cursor: Option<&Cursor>,
        size: usize,
    ) -> Result<Page>;

    /// Up to `limit` records from `since`, continuing at `cursor`.
    fn pull(
        &self,
        client: &Client,
        since: Option<i64>,
        cursor: Option<Cursor>,
        limit: usize,
    ) -> Result<Pull> {
        self.pull_each(client, since, cursor, limit, &mut |_| Ok(()))
    }

    /// [`Source::pull`], showing each page to `on_page` as it arrives.
    fn pull_each(
        &self,
        client: &Client,
        since: Option<i64>,
        cursor: Option<Cursor>,
        limit: usize,
        on_page: &mut dyn FnMut(&Page) -> Result<()>,
    ) -> Result<Pull> {
        let before = client.requests();
        let mut p = pager::pull(
            limit,
            self.page_size(),
            cursor,
            |size, c| self.page(client, since, c, size),
            on_page,
        )?;
        p.requests = client.requests() - before;
        Ok(p)
    }
}

/// The source of `kind` for `query`. urlquery needs an API key; urlscan
/// takes one if given.
pub fn source(kind: Kind, query: CdxQuery, api_key: Option<String>) -> Result<Box<dyn Source>> {
    Ok(match kind {
        Kind::Wayback => Box::new(Wayback { query }),
        Kind::Arquivo => Box::new(Arquivo { query }),
        Kind::Urlquery => Box::new(Urlquery {
            query,
            api_key: api_key.ok_or_else(|| anyhow::anyhow!("urlquery needs an API key"))?,
        }),
        Kind::CommonCrawl => Box::new(CommonCrawl::new(query)),
        Kind::Urlscan => Box::new(Urlscan { query, api_key }),
        Kind::Memento => Box::new(Memento { query }),
        Kind::GhArchive => Box::new(GhArchive::new(query)),
        Kind::Npm => Box::new(Npm { query }),
        Kind::Pypi => Box::new(Pypi { query }),
        Kind::CtLog => Box::new(CtLog::new(query)?),
        Kind::WellKnown => Box::new(WellKnown::new(query)?),
        Kind::Mcp => Box::new(McpRegistry { query }),
    })
}

/// CDX timestamp (`yyyyMMddhhmmss`).
pub fn cdx_ts(ts: i64) -> String {
    chrono::DateTime::from_timestamp(ts, 0)
        .unwrap_or_default()
        .format("%Y%m%d%H%M%S")
        .to_string()
}

/// Case-insensitive substrings a filtered source keeps records by, from a
/// pattern such as `r.jina.ai|uqtag`. An empty pattern or `*` keeps everything.
#[derive(Debug, Clone)]
pub struct Needles(Vec<String>);

impl Needles {
    pub fn new(pattern: &str) -> Self {
        Self(
            pattern
                .split('|')
                .map(|n| n.trim().to_ascii_lowercase())
                .filter(|n| !n.is_empty() && n != "*")
                .collect(),
        )
    }

    pub fn matches(&self, text: &str) -> bool {
        if self.0.is_empty() {
            return true;
        }
        let t = text.to_ascii_lowercase();
        self.0.iter().any(|n| t.contains(n.as_str()))
    }
}

/// An RFC 3339 or RFC 2822 date (or anything `sc_core::parse_ts` reads) as
/// Unix seconds.
pub(crate) fn parse_date(s: &str) -> Option<i64> {
    let s = s.trim();
    chrono::DateTime::parse_from_rfc3339(s)
        .or_else(|_| chrono::DateTime::parse_from_rfc2822(s))
        .ok()
        .map(|d| d.timestamp())
        .or_else(|| sc_core::parse_ts(s))
}

/// The first 12 hex digits of the SHA-256 of `s`, for stable record IDs.
pub(crate) fn short_hash(s: &str) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(s.as_bytes())
        .iter()
        .take(6)
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Day (`yyyy-mm-dd`) of Unix seconds.
pub(crate) fn day(ts: i64) -> String {
    chrono::DateTime::from_timestamp(ts, 0)
        .map(|d| d.format("%Y-%m-%d").to_string())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cdx_timestamps() {
        assert_eq!(cdx_ts(0), "19700101000000");
        assert_eq!(
            sc_core::parse_ts(&cdx_ts(1_791_000_000)),
            Some(1_791_000_000)
        );
    }

    #[test]
    fn kinds_round_trip() {
        for k in Kind::ALL {
            assert_eq!(k.name().parse::<Kind>().unwrap(), k);
        }
        assert!("gopher".parse::<Kind>().is_err());
        assert_eq!(Kind::Urlscan.key_env(), Some("URLSCAN_APIKEY"));
        assert!(Kind::Urlquery.needs_key() && !Kind::Urlscan.needs_key());
    }

    #[test]
    fn needles_and_dates() {
        let n = Needles::new("r.jina.ai | UQTAG");
        assert!(n.matches("https://R.Jina.ai/x") && n.matches("tag uqtag-1"));
        assert!(!n.matches("example.org"));
        assert!(Needles::new("*").matches("anything") && Needles::new("").matches("x"));
        assert_eq!(parse_date("2026-10-10T15:11:09.664Z"), Some(1_791_645_069));
        assert_eq!(
            parse_date("Sat, 10 Oct 2026 19:48:59 GMT"),
            Some(1_791_661_739)
        );
        assert_eq!(short_hash("x").len(), 12);
        assert_eq!(day(1_791_101_400), "2026-10-04");
    }
}
