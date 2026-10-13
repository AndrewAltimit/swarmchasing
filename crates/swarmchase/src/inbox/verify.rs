//! `inbox verify`: look each public-record reference up by its id, through
//! the collectors' indexes and metadata APIs, and record what came back.
//!
//! Passive only. A lookup reads the source's index or record metadata by
//! the id, or by URL and time for an archive capture's index row: never the
//! submitted URL, never a capture or a scanned page, never a package file.

use sc_collect::{CdxQuery, Client, CommonCrawl, Source, cdx_ts};
use sc_core::Observation;
use sc_inbox::spec::{PublicRecord, RecordSource};
use sc_inbox::{Status, TriageSettings, Verification, check};

/// API keys a lookup may use.
pub struct Keys {
    pub urlquery: Option<String>,
    pub urlscan: Option<String>,
}

impl Keys {
    pub fn from_env() -> Self {
        let get = |k: &str| {
            std::env::var(k)
                .ok()
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
        };
        Self {
            urlquery: get(crate::util::URLQUERY_KEY_ENV),
            urlscan: get("URLSCAN_APIKEY"),
        }
    }
}

/// What a lookup returned: the candidate records, or why there was none.
enum Lookup {
    Found(Vec<Observation>),
    Skipped(String),
}

fn lookup(client: &Client, r: &PublicRecord, keys: &Keys, tol: i64) -> anyhow::Result<Lookup> {
    let id = r.id.as_deref().unwrap_or_default().trim();
    let url = r.url.as_deref().unwrap_or_default();
    let window = |q: &mut CdxQuery| {
        if let Some(t) = r.ts() {
            q.from = Some(cdx_ts(t - tol));
            q.to = Some(cdx_ts(t + tol));
        }
    };
    let cdx = || {
        let mut q = CdxQuery {
            pattern: url.to_string(),
            match_type: Some("exact".into()),
            limit: 20,
            page_size: 20,
            ..Default::default()
        };
        window(&mut q);
        q
    };
    Ok(Lookup::Found(match r.source {
        RecordSource::Urlquery => match &keys.urlquery {
            Some(k) => vec![client.urlquery_report(k, id)?],
            None => {
                return Ok(Lookup::Skipped(format!(
                    "{} is not set",
                    crate::util::URLQUERY_KEY_ENV
                )));
            }
        },
        RecordSource::Urlscan => client.urlscan_by_id(id, keys.urlscan.as_deref())?,
        RecordSource::Wayback => client.wayback_cdx(&cdx())?,
        RecordSource::Arquivo => client.arquivo_cdx(&cdx())?,
        RecordSource::Commoncrawl => {
            let mut q = cdx();
            q.endpoint = r.crawl.clone();
            CommonCrawl::new(q)
                .pull(client, None, None, 20)?
                .strict()?
                .observations
        }
        RecordSource::Gharchive => match r.ts() {
            Some(t) => client.gharchive_event(id, t)?.into_iter().collect(),
            None => return Ok(Lookup::Skipped("no timestamp to find the hour by".into())),
        },
        RecordSource::Npm | RecordSource::Pypi => {
            let (p, v) = (
                r.package.as_deref().unwrap_or_default(),
                r.version.as_deref().unwrap_or_default(),
            );
            let o = if r.source == RecordSource::Npm {
                client.npm_release(p, v)?
            } else {
                client.pypi_release(p, v)?
            };
            o.into_iter().collect()
        }
        RecordSource::Ctlog => {
            let n: u64 = id.parse().unwrap_or(0);
            let domain = r.domain.as_deref().unwrap_or_default();
            client.crtsh_entry(domain, n)?.into_iter().collect()
        }
    }))
}

/// Look up item `item` and check it, for a submission received at
/// `received`.
pub fn verify_item(
    client: &Client,
    item: usize,
    r: &PublicRecord,
    received: i64,
    now: i64,
    keys: &Keys,
    s: &TriageSettings,
) -> (Verification, Vec<Observation>) {
    let failed = |status: Status, detail: String| Verification {
        item,
        status,
        checked: now,
        record_ts: None,
        lead_secs: None,
        predates: false,
        record: None,
        detail,
    };
    match lookup(client, r, keys, s.ts_tolerance_secs) {
        Ok(Lookup::Found(found)) => {
            let v = check(
                item,
                r,
                &found,
                received,
                now,
                s.ts_tolerance_secs,
                s.predate_secs,
            );
            let keep = found
                .into_iter()
                .filter(|o| v.record.as_deref() == Some(o.id.as_str()))
                .collect();
            (v, keep)
        }
        Ok(Lookup::Skipped(why)) => (failed(Status::Skipped, why), Vec::new()),
        Err(e) => {
            // Error messages name the URL, never a key.
            let msg = format!("{e:#}");
            let status = if msg.contains("HTTP 404") {
                Status::NotFound
            } else {
                Status::Error
            };
            (
                failed(status, sc_inbox::inert::inert(&msg, 200)),
                Vec::new(),
            )
        }
    }
}
