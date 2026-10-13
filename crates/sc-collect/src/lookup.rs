//! Single records by id, for checking a reference someone sent: one urlscan
//! result's metadata, one GH Archive event, one npm or PyPI release, one
//! crt.sh certificate. The inbox (`swarmchase inbox verify`) uses these and
//! the archive indexes to check that a record a submission names exists,
//! matches, and predates it.
//!
//! Index rows and metadata only, as everywhere in this crate: no capture,
//! scanned page, package file or repository is downloaded, and the URL a
//! record is of is never requested. Each source's terms are in its own
//! module; one lookup per reference stays well inside them.

use crate::client::Opts;
use crate::gharchive::{BASE, MAX_FILE, MAX_LINE, event_to_obs, hour_name};
use crate::{Client, Needles, parse_date, parse_urlscan_search};
use anyhow::{Context, Result};
use sc_core::{Observation, TsKind, redact_observation};
use serde_json::Value;
use std::io::{BufRead, BufReader, Read};

const URLSCAN_SEARCH: &str = "https://urlscan.io/api/v1/search/";
const NPM_REGISTRY: &str = "https://registry.npmjs.org/";
const PYPI_JSON: &str = "https://pypi.org/pypi/";

fn not_found_ok() -> Opts {
    Opts {
        not_found_ok: true,
        ..Opts::default()
    }
}

/// Characters a package name or version may hold; anything else is refused
/// before a request is made.
fn plain(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 214
        && s.chars().all(|c| {
            c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '@' | '/' | '+' | '~')
        })
}

impl Client {
    /// One public urlscan.io result's metadata by uuid, through the search
    /// API (`_id:<uuid>`), never the result page. Empty when there is none.
    pub fn urlscan_by_id(&self, uuid: &str, api_key: Option<&str>) -> Result<Vec<Observation>> {
        let uuid = uuid.strip_prefix("urlscan:").unwrap_or(uuid);
        if uuid.is_empty() || !uuid.chars().all(|c| c.is_ascii_hexdigit() || c == '-') {
            anyhow::bail!("not a urlscan uuid: {uuid}");
        }
        let mut u = url::Url::parse(URLSCAN_SEARCH)?;
        u.query_pairs_mut()
            .append_pair("q", &format!("_id:{uuid}"))
            .append_pair("size", "1");
        let body = match api_key {
            Some(k) => self.get_with(u.as_str(), &[("API-Key", k)]),
            None => self.get(u.as_str()),
        }
        .context("urlscan search")?;
        Ok(parse_urlscan_search(&body)?.0)
    }

    /// One GH Archive event by id, from the hour file holding `ts` (the
    /// event's `created_at`). The hour is streamed and only the matching
    /// event kept. `None` when the hour has no such event.
    pub fn gharchive_event(&self, id: &str, ts: i64) -> Result<Option<Observation>> {
        if id.is_empty() || !id.chars().all(|c| c.is_ascii_digit()) {
            anyhow::bail!("not a GH Archive event id: {id}");
        }
        let url = format!("{BASE}{}.json.gz", hour_name(ts));
        let Some(r) = self.get_stream_opt(&url, MAX_FILE, true)? else {
            return Ok(None);
        };
        find_event(flate2::read::MultiGzDecoder::new(r), id)
            .with_context(|| format!("reading {url}"))
    }

    /// One npm release's publish time, from the package's registry document
    /// (metadata only, never the tarball). `None` when there is no such
    /// package or version.
    pub fn npm_release(&self, package: &str, version: &str) -> Result<Option<Observation>> {
        if !plain(package) || !plain(version) {
            anyhow::bail!("not a package name and version: {package} {version}");
        }
        let name = package.replace('/', "%2f");
        let f = self.fetch(&format!("{NPM_REGISTRY}{name}"), &[], not_found_ok())?;
        if f.status == 404 {
            return Ok(None);
        }
        let v: Value = serde_json::from_str(&f.body).context("npm registry: not JSON")?;
        Ok(npm_time(&v, package, version))
    }

    /// One PyPI release's first upload time, from its JSON metadata (never
    /// a distribution file). `None` when there is no such release.
    pub fn pypi_release(&self, package: &str, version: &str) -> Result<Option<Observation>> {
        if !plain(package) || !plain(version) || package.contains('/') || version.contains('/') {
            anyhow::bail!("not a package name and version: {package} {version}");
        }
        let f = self.fetch(
            &format!("{PYPI_JSON}{package}/{version}/json"),
            &[],
            not_found_ok(),
        )?;
        if f.status == 404 {
            return Ok(None);
        }
        let v: Value = serde_json::from_str(&f.body).context("PyPI: not JSON")?;
        Ok(pypi_time(&v, package, version))
    }

    /// One certificate by crt.sh id, found among the certificates for
    /// `domain`. Its time is the CT log entry's.
    pub fn crtsh_entry(&self, domain: &str, id: u64) -> Result<Option<Observation>> {
        let recs = self.crtsh(domain)?;
        Ok(recs.into_iter().find(|r| r.id == id).map(|r| {
            let mut o = Observation {
                id: format!("crtsh:{}", r.id),
                source: "ctlog".into(),
                ts: parse_date(&r.entry_timestamp)
                    .or_else(|| parse_date(&format!("{}Z", r.entry_timestamp)))
                    .unwrap_or(0),
                ts_kind: TsKind::Request,
                url: format!("https://{}/", domain.trim_start_matches("*.")),
                reference: Some(format!("https://crt.sh/?id={}", r.id)),
                ..Default::default()
            };
            redact_observation(&mut o);
            o
        }))
    }
}

/// The event with id `id` in an NDJSON stream of GH Archive events.
pub fn find_event(r: impl Read, id: &str) -> Result<Option<Observation>> {
    let needle = format!("\"id\":\"{id}\"");
    let all = Needles::new("*");
    let mut r = BufReader::new(r);
    let mut buf = Vec::new();
    loop {
        buf.clear();
        let n = (&mut r).take(MAX_LINE as u64).read_until(b'\n', &mut buf)?;
        if n == 0 {
            return Ok(None);
        }
        if !buf.windows(needle.len()).any(|w| w == needle.as_bytes()) {
            continue;
        }
        let Ok(v) = serde_json::from_slice::<Value>(&buf) else {
            continue;
        };
        if v.get("id").and_then(Value::as_str) == Some(id) {
            return Ok(event_to_obs(&v, &all));
        }
    }
}

/// An npm package document's publish time for `version`.
pub fn npm_time(doc: &Value, package: &str, version: &str) -> Option<Observation> {
    let ts = doc
        .pointer("/time")
        .and_then(|t| t.get(version))
        .and_then(Value::as_str)
        .and_then(parse_date)?;
    let link = format!("https://www.npmjs.com/package/{package}");
    let mut o = Observation {
        id: format!("npm:{package}@{version}"),
        source: "npm".into(),
        ts,
        ts_kind: TsKind::Request,
        url: format!("{link}/v/{version}"),
        reference: Some(link),
        ..Default::default()
    };
    redact_observation(&mut o);
    Some(o)
}

/// A PyPI release document's earliest upload time.
pub fn pypi_time(doc: &Value, package: &str, version: &str) -> Option<Observation> {
    let ts = doc
        .get("urls")
        .and_then(Value::as_array)?
        .iter()
        .filter_map(|u| u.get("upload_time_iso_8601").and_then(Value::as_str))
        .filter_map(parse_date)
        .min()?;
    let link = format!("https://pypi.org/project/{package}/{version}/");
    let mut o = Observation {
        id: format!("pypi:{package}@{version}"),
        source: "pypi".into(),
        ts,
        ts_kind: TsKind::Request,
        url: link.clone(),
        reference: Some(link),
        ..Default::default()
    };
    redact_observation(&mut o);
    Some(o)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_one_event_by_id() {
        let lines = [
            r#"{"id":"1","type":"PushEvent","created_at":"2026-10-09T07:00:01Z","repo":{"name":"someone/proj"},"payload":{}}"#,
            r#"{"id":"22","type":"CreateEvent","created_at":"2026-10-09T07:00:02Z","repo":{"name":"bot/run-7"},"payload":{}}"#,
        ]
        .join("\n");
        let o = find_event(lines.as_bytes(), "22").unwrap().unwrap();
        assert_eq!(o.id, "gharchive:22");
        assert!(find_event(lines.as_bytes(), "2").unwrap().is_none());
    }

    #[test]
    fn registry_times() {
        let npm: Value = serde_json::json!({"time": {"1.0.0": "2026-09-01T10:00:00.000Z"}});
        let o = npm_time(&npm, "@scope/pkg", "1.0.0").unwrap();
        assert_eq!(o.id, "npm:@scope/pkg@1.0.0");
        assert!(npm_time(&npm, "@scope/pkg", "2.0.0").is_none());
        let pypi: Value = serde_json::json!({"urls": [
            {"upload_time_iso_8601": "2026-09-02T10:00:00.000Z"},
            {"upload_time_iso_8601": "2026-09-01T10:00:00.000Z"}]});
        let o = pypi_time(&pypi, "pkg", "1.0").unwrap();
        assert_eq!(o.ts, sc_core::parse_ts("2026-09-01T10:00:00Z").unwrap());
        assert!(!plain("a b"));
    }
}
