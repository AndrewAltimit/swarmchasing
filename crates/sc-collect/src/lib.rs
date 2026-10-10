//! Passive collectors.
//!
//! Ground rules, enforced by what this crate does and does not implement:
//! - Read **indexes and public records only** (CDX listings, CT logs, security.txt).
//!   Never open captured pages or the URLs agents submitted: they may be live
//!   exploit payloads or trigger callbacks to the operator.
//! - Never read or write agent callback channels (inboxes, ntfy topics, pastes).
//! - Be polite: one request at a time, with a minimum interval, an identifying
//!   user agent, and backoff when a server says it is overloaded.
//! - Redact secrets before records leave this crate (see `sc_core::redact`).
//!
//! [`Client`] is the HTTP client every collector shares. The record sources
//! (Wayback, Arquivo, urlquery) implement [`Source`], and page through
//! [`pager`]; crt.sh, security.txt and RDAP are single lookups on the client.

use anyhow::Result;
use serde::{Deserialize, Serialize};

mod arquivo;
mod client;
mod crtsh;
pub mod pager;
mod rdap;
mod securitytxt;
mod urlquery;
mod wayback;

pub use arquivo::{Arquivo, parse_arquivo_cdx};
pub use client::{Client, Retry, USER_AGENT};
pub use crtsh::CertRecord;
pub use pager::{Cursor, Page, Pull};
pub use urlquery::{Urlquery, UrlqueryPage, parse_urlquery_search};
pub use wayback::{CdxPage, Wayback, parse_wayback_cdx};

/// A query against a record source: a CDX URL pattern, or for urlquery a
/// search query. Also a `watchlist.toml` source entry.
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
    /// Records per request when paging (Wayback and urlquery).
    #[serde(default = "default_page_size")]
    pub page_size: usize,
}

fn default_limit() -> usize {
    5000
}

fn default_page_size() -> usize {
    1000
}

/// The record sources.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Wayback,
    Arquivo,
    Urlquery,
}

impl Kind {
    pub fn name(self) -> &'static str {
        match self {
            Self::Wayback => "wayback",
            Self::Arquivo => "arquivo",
            Self::Urlquery => "urlquery",
        }
    }
}

impl std::str::FromStr for Kind {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self> {
        Ok(match s {
            "wayback" => Self::Wayback,
            "arquivo" => Self::Arquivo,
            "urlquery" => Self::Urlquery,
            k => anyhow::bail!("unknown kind `{k}` (expected wayback, arquivo or urlquery)"),
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

/// The source of `kind` for `query`. urlquery needs an API key.
pub fn source(kind: Kind, query: CdxQuery, api_key: Option<String>) -> Result<Box<dyn Source>> {
    Ok(match kind {
        Kind::Wayback => Box::new(Wayback { query }),
        Kind::Arquivo => Box::new(Arquivo { query }),
        Kind::Urlquery => Box::new(Urlquery {
            query,
            api_key: api_key.ok_or_else(|| anyhow::anyhow!("urlquery needs an API key"))?,
        }),
    })
}

/// CDX timestamp (`yyyyMMddhhmmss`).
pub fn cdx_ts(ts: i64) -> String {
    chrono::DateTime::from_timestamp(ts, 0)
        .unwrap_or_default()
        .format("%Y%m%d%H%M%S")
        .to_string()
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
        for k in [Kind::Wayback, Kind::Arquivo, Kind::Urlquery] {
            assert_eq!(k.name().parse::<Kind>().unwrap(), k);
        }
        assert!("gopher".parse::<Kind>().is_err());
    }
}
