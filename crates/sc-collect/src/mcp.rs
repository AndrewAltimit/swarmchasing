//! The official MCP Registry (`registry.modelcontextprotocol.io`): the
//! public list of Model Context Protocol servers, read through its list API
//! (`GET /v0.1/servers`, cursor-paged, `updated_since` for incremental
//! pulls). Metadata only: a server's name, version, publish time, and the
//! repository, website and remote-endpoint hosts it declares, kept as a
//! source for linking a run's hosts to the tools it was given. Servers,
//! packages and repositories are never contacted or downloaded, and
//! descriptions, icons, headers and environment variables are dropped.
//!
//! The record's URL is what links it: the repository URL if declared, else
//! the website, else the remote endpoint cut to its origin; its reference is
//! the server version's registry entry.
//!
//! Terms: the Official MCP Registry Terms of Service
//! (<https://modelcontextprotocol.io/registry/terms-of-service>) dedicate
//! Registry Data (names, descriptions, URLs, identifiers) to the public
//! domain under CC0 1.0, say published metadata may be processed by others,
//! and forbid interfering with or disrupting the Registry. One paced request
//! per page of at most 100 servers, only servers updated since the last run.

use crate::pager::{Coverage, Cursor, Page};
use crate::{CdxQuery, Client, Kind, Needles, Source, parse_date};
use anyhow::{Context, Result};
use sc_core::{Observation, TsKind, redact_observation};
use serde_json::Value;

const BASE: &str = "https://registry.modelcontextprotocol.io/v0.1/servers";
/// The list API's page size cap.
const MAX_PAGE: usize = 100;
const OFFICIAL: &str = "io.modelcontextprotocol.registry/official";

/// The MCP Registry list as a [`Source`]. `query.pattern` is `|`-separated
/// substrings matched against a server's name and declared URLs (`*` keeps
/// every server).
pub struct McpRegistry {
    pub query: CdxQuery,
}

impl Source for McpRegistry {
    fn kind(&self) -> Kind {
        Kind::Mcp
    }

    fn query(&self) -> &CdxQuery {
        &self.query
    }

    /// The registry's cursor names the last server read, so it stays valid
    /// with the same `updated_since`.
    fn resumable(&self) -> bool {
        true
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
        let key = match cursor {
            Some(Cursor::Key(k)) => Some(k.as_str()),
            Some(c) => anyhow::bail!("mcp pages by cursor, not {c:?}"),
            None => None,
        };
        let from = since.or_else(|| self.query.from.as_deref().and_then(sc_core::parse_ts));
        let mut u = url::Url::parse(BASE)?;
        {
            let mut p = u.query_pairs_mut();
            p.append_pair("limit", &size.clamp(1, MAX_PAGE).to_string());
            if let Some(t) = from {
                let d = chrono::DateTime::from_timestamp(t, 0).unwrap_or_default();
                p.append_pair("updated_since", &d.format("%Y-%m-%dT%H:%M:%SZ").to_string());
            }
            if let Some(k) = key {
                p.append_pair("cursor", k);
            }
        }
        let body = client.get(u.as_str()).context("mcp registry list")?;
        let list = parse_mcp_servers(&body, &Needles::new(&self.query.pattern))?;
        let to = self.query.to.as_deref().and_then(sc_core::parse_ts);
        let records = list
            .records
            .into_iter()
            .filter(|o| to.is_none_or(|t| o.ts <= t))
            .collect();
        Ok(Page {
            records,
            next: list.next.map(Cursor::Key),
            coverage: Some(Coverage {
                unit: "servers",
                read: list.read as u64,
                available: list.read as u64,
                ..Default::default()
            }),
            ..Default::default()
        })
    }
}

/// One page of the registry list.
#[derive(Debug, Default)]
pub struct McpList {
    /// The servers that matched, as records.
    pub records: Vec<Observation>,
    /// Server entries on the page before matching.
    pub read: usize,
    pub next: Option<String>,
}

/// Parse a `/v0.1/servers` response, keeping servers whose name or declared
/// URLs match. Records are redacted.
pub fn parse_mcp_servers(body: &str, needles: &Needles) -> Result<McpList> {
    let v: Value = serde_json::from_str(body).context("mcp registry: not JSON")?;
    let servers = match v.get("servers") {
        Some(Value::Array(a)) => a.as_slice(),
        Some(Value::Null) => &[],
        _ => anyhow::bail!("mcp registry: no `servers` array"),
    };
    let next = v
        .pointer("/metadata/nextCursor")
        .and_then(Value::as_str)
        .filter(|c| !c.is_empty())
        .map(str::to_string);
    let mut out = McpList {
        read: servers.len(),
        next,
        ..Default::default()
    };
    for e in servers {
        if let Some(o) = server_record(e, needles) {
            out.records.push(o);
        }
    }
    Ok(out)
}

fn server_record(e: &Value, needles: &Needles) -> Option<Observation> {
    let s = e.get("server")?;
    let text = |p: &str| s.pointer(p).and_then(Value::as_str).map(str::trim);
    let name = text("/name").filter(|n| !n.is_empty())?;
    let version = text("/version").unwrap_or("");
    let web = |u: &str| u.starts_with("https://") || u.starts_with("http://");
    let repo = text("/repository/url").filter(|u| web(u));
    let site = text("/websiteUrl").filter(|u| web(u));
    let remotes: Vec<String> = s
        .get("remotes")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|r| r.get("url").and_then(Value::as_str))
        .filter_map(origin)
        .collect();
    let matched = needles.matches(name)
        || repo.is_some_and(|u| needles.matches(u))
        || site.is_some_and(|u| needles.matches(u))
        || remotes.iter().any(|u| needles.matches(u));
    if !matched {
        return None;
    }
    let meta = e.pointer("/_meta").and_then(|m| m.get(OFFICIAL));
    let when = |k: &str| {
        meta.and_then(|m| m.get(k))
            .and_then(Value::as_str)
            .and_then(parse_date)
    };
    let enc = |x: &str| url::form_urlencoded::byte_serialize(x.as_bytes()).collect::<String>();
    let entry = format!("{BASE}/{}/versions/{}", enc(name), enc(version));
    let url = repo
        .map(str::to_string)
        .or_else(|| site.and_then(origin))
        .or_else(|| remotes.first().cloned())
        .unwrap_or_else(|| entry.clone());
    let mut o = Observation {
        id: format!("mcp:{name}@{version}"),
        source: "mcp".into(),
        ts: when("publishedAt")
            .or_else(|| when("updatedAt"))
            .unwrap_or(0),
        // The publish request reaching the registry.
        ts_kind: TsKind::Request,
        url,
        reference: Some(entry),
        ..Default::default()
    };
    redact_observation(&mut o);
    Some(o)
}

/// `https://host[:port]/` of an http(s) URL: the host a server declares,
/// without the path or query it might carry a token in.
fn origin(u: &str) -> Option<String> {
    let p = url::Url::parse(u).ok()?;
    if !matches!(p.scheme(), "http" | "https") {
        return None;
    }
    let host = p.host_str()?;
    Some(match p.port() {
        Some(port) => format!("{}://{host}:{port}/", p.scheme()),
        None => format!("{}://{host}/", p.scheme()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A hand-written page in the registry's shape; no real server.
    const PAGE: &str = r#"{
      "servers": [
        {"server": {"$schema": "https://static.modelcontextprotocol.io/schemas/2025-09-29/server.schema.json",
           "name": "io.example/relay-tools", "title": "Relay tools", "description": "fetch pages through a relay",
           "version": "1.2.0",
           "repository": {"url": "https://github.com/example-org/relay-tools", "source": "github"},
           "remotes": [{"type": "streamable-http", "url": "https://mcp.tools.example/mcp?token=abc",
                        "headers": [{"name": "Authorization", "value": "Bearer x"}]}]},
         "_meta": {"io.modelcontextprotocol.registry/official": {"status": "active",
           "publishedAt": "2026-10-02T04:58:59.331523Z", "updatedAt": "2026-10-03T00:00:00Z", "isLatest": true}}},
        {"server": {"name": "io.example/notes", "version": "0.1.0",
           "websiteUrl": "https://notes.example/docs/start"},
         "_meta": {"io.modelcontextprotocol.registry/official": {"status": "active",
           "publishedAt": "2026-10-04T10:00:00Z", "isLatest": true}}},
        {"server": {"name": "io.example/bare", "version": "2.0.0",
           "remotes": [{"type": "sse", "url": "https://bare.example:8443/sse"}]},
         "_meta": {}},
        {"server": {"version": "9"}}
      ],
      "metadata": {"nextCursor": "io.example/bare:2.0.0", "count": 4}
    }"#;

    #[test]
    fn servers_become_metadata_records() {
        let l = parse_mcp_servers(PAGE, &Needles::new("*")).unwrap();
        assert_eq!(l.read, 4);
        assert_eq!(l.next.as_deref(), Some("io.example/bare:2.0.0"));
        let ids: Vec<&str> = l.records.iter().map(|o| o.id.as_str()).collect();
        assert_eq!(
            ids,
            [
                "mcp:io.example/relay-tools@1.2.0",
                "mcp:io.example/notes@0.1.0",
                "mcp:io.example/bare@2.0.0"
            ]
        );
        let r = &l.records[0];
        assert_eq!(r.url, "https://github.com/example-org/relay-tools");
        assert_eq!(
            r.reference.as_deref(),
            Some(
                "https://registry.modelcontextprotocol.io/v0.1/servers/io.example%2Frelay-tools/versions/1.2.0"
            )
        );
        assert_eq!(r.ts, 1_790_917_139);
        assert_eq!(r.ts_kind, TsKind::Request);
        assert_eq!(l.records[1].url, "https://notes.example/");
        assert_eq!(l.records[2].url, "https://bare.example:8443/");
        assert_eq!(l.records[2].ts, 0);
        // Descriptions, headers and endpoint paths with tokens are not kept.
        let json = serde_json::to_string(&l.records).unwrap();
        assert!(
            !json.contains("Bearer") && !json.contains("token=abc"),
            "{json}"
        );
        assert!(!json.contains("through a relay"), "{json}");
    }

    #[test]
    fn matching_reads_names_and_declared_hosts() {
        let l = parse_mcp_servers(PAGE, &Needles::new("tools.example")).unwrap();
        assert_eq!(l.records.len(), 1);
        let l = parse_mcp_servers(PAGE, &Needles::new("NOTES")).unwrap();
        assert_eq!(l.records[0].id, "mcp:io.example/notes@0.1.0");
        let empty = r#"{"servers": null, "metadata": {"count": 0}}"#;
        let l = parse_mcp_servers(empty, &Needles::new("*")).unwrap();
        assert_eq!((l.read, l.next), (0, None));
        assert!(parse_mcp_servers("{}", &Needles::new("*")).is_err());
    }
}
