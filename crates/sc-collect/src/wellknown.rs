//! Agent protocol footprints in the Wayback Machine CDX index: captures of
//! the well-known files agents and agent platforms publish to announce
//! themselves ([`FOOTPRINTS`]): A2A agent cards, agent registration files,
//! and the Web Bot Auth key directory a signing crawler or agent serves.
//! A capture of one says a host published, or was asked for, an agent's
//! self-description at that time; the host is a lead for linking a run to
//! the platform it ran on.
//!
//! Index rows only: the cards themselves are never fetched, from the
//! archive or the host. The CDX index cannot search one path across all
//! hosts, so `pattern` lists where to look, `|`-separated: a host
//! (`agents.example`) reads that host's `/.well-known/` captures, and
//! `*.domain` reads every subdomain's, with a server-side filter keeping
//! only the footprint files. A domain with very many captures can time out
//! at the server's gateway; list its busy subdomains as hosts instead.
//!
//! Terms: as for the other Wayback Machine sources ([`crate::Wayback`]):
//! the Internet Archive documents the CDX server as a public API
//! (<https://github.com/internetarchive/wayback/tree/master/wayback-cdx-server>)
//! and its terms (<https://archive.org/about/terms>) cover use of its
//! collections; requests are paced, one index page each, and no archived
//! content is read.

use crate::pager::{Cursor, Page};
use crate::{CdxQuery, Client, Kind, Source, cdx_ts};
use anyhow::{Context, Result};

/// The well-known files read, under `/.well-known/`.
pub const FOOTPRINTS: [&str; 4] = [
    "agent-card.json",
    "agent.json",
    "agent-registration.json",
    "http-message-signatures-directory",
];

/// Where to look for footprints.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Scope {
    Host(String),
    Domain(String),
}

/// Footprint captures under a list of hosts and domains, as a [`Source`].
pub struct WellKnown {
    pub query: CdxQuery,
    scopes: Vec<Scope>,
}

impl WellKnown {
    pub fn new(query: CdxQuery) -> Result<Self> {
        let mut scopes = Vec::new();
        for p in query
            .pattern
            .split('|')
            .map(str::trim)
            .filter(|p| !p.is_empty())
        {
            let p = p.to_ascii_lowercase();
            let (domain, name) = match p.strip_prefix("*.") {
                Some(d) => (true, d.to_string()),
                None => (false, p.clone()),
            };
            if name.is_empty()
                || !name
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
            {
                anyhow::bail!("wellknown: `{p}` is not a host or `*.domain`");
            }
            scopes.push(if domain {
                Scope::Domain(name)
            } else {
                Scope::Host(name)
            });
        }
        if scopes.is_empty() {
            anyhow::bail!("wellknown needs `pattern`: hosts or `*.domain`s, `|`-separated");
        }
        Ok(Self { query, scopes })
    }

    /// The CDX query for one scope.
    fn scope_query(&self, scope: &Scope, since: Option<i64>) -> CdxQuery {
        let (pattern, match_type) = match scope {
            Scope::Host(h) => (format!("{h}/.well-known/"), "prefix"),
            Scope::Domain(d) => (d.clone(), "domain"),
        };
        let names: Vec<String> = FOOTPRINTS.iter().map(|f| f.replace('.', "\\.")).collect();
        let mut filter = vec![format!(
            "original:.*/\\.well-known/({})([?#].*)?",
            names.join("|")
        )];
        filter.extend(self.query.filter.iter().cloned());
        CdxQuery {
            pattern,
            match_type: Some(match_type.into()),
            from: since.map(cdx_ts).or_else(|| self.query.from.clone()),
            to: self.query.to.clone(),
            filter,
            ..CdxQuery::default()
        }
    }
}

/// Whether `url`'s path is one of the [`FOOTPRINTS`].
pub fn is_footprint(url: &str) -> bool {
    let path = url::Url::parse(url)
        .map(|u| u.path().to_ascii_lowercase())
        .unwrap_or_default();
    path.strip_prefix("/.well-known/")
        .is_some_and(|f| FOOTPRINTS.contains(&f.trim_end_matches('/')))
}

/// `wk:<scope index>:<resume key>`.
fn parse_key(k: &str) -> Result<(usize, Option<String>)> {
    let rest = k
        .strip_prefix("wk:")
        .with_context(|| format!("wellknown: not a footprint key: {k}"))?;
    let (i, key) = rest.split_once(':').unwrap_or((rest, ""));
    Ok((
        i.parse().context("wellknown: key index")?,
        Some(key.to_string()).filter(|k| !k.is_empty()),
    ))
}

fn format_key(i: usize, key: Option<&str>) -> String {
    format!("wk:{i}:{}", key.unwrap_or(""))
}

impl Source for WellKnown {
    fn kind(&self) -> Kind {
        Kind::WellKnown
    }

    fn query(&self) -> &CdxQuery {
        &self.query
    }

    fn resumable(&self) -> bool {
        true
    }

    fn page_size(&self) -> usize {
        self.query.page_size.max(1)
    }

    fn page(
        &self,
        client: &Client,
        since: Option<i64>,
        cursor: Option<&Cursor>,
        size: usize,
    ) -> Result<Page> {
        let (i, key) = match cursor {
            Some(Cursor::Key(k)) => parse_key(k)?,
            Some(c) => anyhow::bail!("wellknown pages by key, not {c:?}"),
            None => (0, None),
        };
        let Some(scope) = self.scopes.get(i) else {
            return Ok(Page::default());
        };
        let q = self.scope_query(scope, since);
        let p = client.wayback_cdx_page(&q, size, key.as_deref())?;
        let records = p
            .records
            .into_iter()
            .filter(|o| is_footprint(&o.url))
            .collect();
        let next = match p.resume_key {
            Some(k) => Some(format_key(i, Some(&k))),
            None if i + 1 < self.scopes.len() => Some(format_key(i + 1, None)),
            None => None,
        };
        Ok(Page {
            records,
            next: next.map(Cursor::Key),
            ..Default::default()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wk(pattern: &str) -> Result<WellKnown> {
        WellKnown::new(CdxQuery {
            pattern: pattern.into(),
            ..Default::default()
        })
    }

    #[test]
    fn scopes_from_the_pattern() {
        let w = wk("agents.example | *.Tunnel.example").unwrap();
        assert_eq!(
            w.scopes,
            [
                Scope::Host("agents.example".into()),
                Scope::Domain("tunnel.example".into())
            ]
        );
        assert!(wk("").is_err());
        assert!(wk("a.example/path").is_err());

        let q = w.scope_query(&w.scopes[0], Some(1_791_000_000));
        assert_eq!(q.pattern, "agents.example/.well-known/");
        assert_eq!(q.match_type.as_deref(), Some("prefix"));
        assert_eq!(q.from.as_deref(), Some("20261003040000"));
        assert!(q.filter[0].starts_with("original:.*/\\.well-known/(agent-card\\.json|"));
        let q = w.scope_query(&w.scopes[1], None);
        assert_eq!(
            (q.pattern.as_str(), q.match_type.as_deref()),
            ("tunnel.example", Some("domain"))
        );
    }

    #[test]
    fn footprints_and_keys() {
        assert!(is_footprint(
            "https://a.example/.well-known/agent-card.json"
        ));
        assert!(is_footprint(
            "https://a.example/.well-known/http-message-signatures-directory"
        ));
        assert!(is_footprint("http://a.example/.well-known/agent.json?x=1"));
        assert!(!is_footprint("https://a.example/.well-known/security.txt"));
        assert!(!is_footprint(
            "https://a.example/docs/.well-known/agent.json"
        ));
        assert_eq!(parse_key("wk:2:").unwrap(), (2, None));
        let k = format_key(1, Some("com,example)/.well-known/agent.json 2026"));
        assert_eq!(
            parse_key(&k).unwrap(),
            (1, Some("com,example)/.well-known/agent.json 2026".into()))
        );
        assert!(parse_key("other").is_err());
    }

    #[test]
    fn rows_parse_and_filter() {
        // Hand-written CDX rows in the Wayback shape.
        let body = r#"[["timestamp","original","statuscode","mimetype","digest"],
            ["20261004081000","https://agents.example/.well-known/agent-card.json","200","application/json","AAA"],
            ["20261004081500","https://agents.example/.well-known/openid-configuration","200","application/json","BBB"]]"#;
        let p = crate::parse_wayback_cdx(body).unwrap();
        let kept: Vec<_> = p.records.iter().filter(|o| is_footprint(&o.url)).collect();
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].source, "wayback");
    }
}
