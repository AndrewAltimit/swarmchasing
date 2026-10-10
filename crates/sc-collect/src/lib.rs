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

use anyhow::{Context, Result};
use sc_core::{Observation, parse_ts, redact_observation};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::cell::Cell;
use std::time::{Duration, Instant};

pub const USER_AGENT: &str = concat!(
    "swarmchase/",
    env!("CARGO_PKG_VERSION"),
    " (passive research; +https://github.com/AndrewAltimit/swarmchasing)"
);

/// Retry policy for transient failures (HTTP 429/5xx, timeouts, dropped connections).
#[derive(Debug, Clone, Copy)]
pub struct Retry {
    /// Retries after the first attempt.
    pub max_retries: u32,
    /// First wait; doubles after each retry.
    pub base: Duration,
    /// Cap on any single wait, including a server's `Retry-After`.
    pub max_wait: Duration,
}

impl Default for Retry {
    fn default() -> Self {
        Self {
            max_retries: 5,
            base: Duration::from_secs(5),
            max_wait: Duration::from_secs(300),
        }
    }
}

impl Retry {
    /// Wait before retry number `attempt` (0-based), honouring `Retry-After` when given.
    pub fn wait(&self, attempt: u32, retry_after: Option<Duration>) -> Duration {
        let backoff = self.base.saturating_mul(1u32 << attempt.min(16));
        retry_after.unwrap_or(backoff).min(self.max_wait)
    }
}

pub struct Client {
    http: reqwest::blocking::Client,
    min_interval: Duration,
    retry: Retry,
    last: Cell<Option<Instant>>,
    requests: Cell<usize>,
}

/// Why a request failed, and whether trying again could help.
enum Failure {
    Transient(anyhow::Error, Option<Duration>),
    Fatal(anyhow::Error),
}

impl Client {
    pub fn new(min_interval: Duration) -> Result<Self> {
        let http = reqwest::blocking::Client::builder()
            .user_agent(std::env::var("SWARMCHASE_UA").unwrap_or_else(|_| USER_AGENT.to_string()))
            .timeout(Duration::from_secs(90))
            .build()?;
        Ok(Self {
            http,
            min_interval,
            retry: Retry::default(),
            last: Cell::new(None),
            requests: Cell::new(0),
        })
    }

    pub fn with_retry(mut self, retry: Retry) -> Self {
        self.retry = retry;
        self
    }

    /// HTTP requests sent so far, retries included. Sources with a quota
    /// (urlquery) report this per run.
    pub fn requests(&self) -> usize {
        self.requests.get()
    }

    fn get(&self, url: &str) -> Result<String> {
        self.get_with(url, &[])
    }

    /// GET with extra request headers. Header values (API keys) never appear in
    /// error messages, which name only the URL.
    fn get_with(&self, url: &str, headers: &[(&str, &str)]) -> Result<String> {
        let mut attempt = 0;
        loop {
            match self.try_get(url, headers) {
                Ok(body) => return Ok(body),
                Err(Failure::Fatal(e)) => return Err(e),
                Err(Failure::Transient(e, retry_after)) => {
                    if attempt >= self.retry.max_retries {
                        return Err(e.context(format!("gave up after {} attempts", attempt + 1)));
                    }
                    let wait = self.retry.wait(attempt, retry_after);
                    eprintln!("  {e:#}; retrying in {}s", wait.as_secs());
                    std::thread::sleep(wait);
                    attempt += 1;
                }
            }
        }
    }

    fn try_get(&self, url: &str, headers: &[(&str, &str)]) -> std::result::Result<String, Failure> {
        if let Some(t) = self.last.get() {
            let el = t.elapsed();
            if el < self.min_interval {
                std::thread::sleep(self.min_interval - el);
            }
        }
        self.last.set(Some(Instant::now()));
        self.requests.set(self.requests.get() + 1);
        let mut req = self.http.get(url);
        for (k, v) in headers {
            req = req.header(*k, *v);
        }
        let resp = match req.send() {
            Ok(r) => r,
            Err(e) => {
                let transient = e.is_timeout() || e.is_connect() || e.is_request();
                let e = anyhow::Error::new(e).context(format!("GET {url}"));
                return Err(if transient {
                    Failure::Transient(e, None)
                } else {
                    Failure::Fatal(e)
                });
            }
        };
        let status = resp.status();
        let retry_after = resp
            .headers()
            .get(reqwest::header::RETRY_AFTER)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.trim().parse::<u64>().ok())
            .map(Duration::from_secs);
        let body = match resp.text() {
            Ok(b) => b,
            Err(e) => {
                return Err(Failure::Transient(
                    anyhow::Error::new(e).context(format!("GET {url}: reading body")),
                    None,
                ));
            }
        };
        if status.is_success() {
            return Ok(body);
        }
        let e = anyhow::anyhow!("GET {url}: HTTP {status}: {}", error_excerpt(&body));
        if status.as_u16() == 429 || status.is_server_error() {
            Err(Failure::Transient(e, retry_after))
        } else {
            Err(Failure::Fatal(e))
        }
    }

    /// Wayback Machine CDX index. `pattern` is a CDX url pattern such as
    /// `r.jina.ai/*` or `*.example.gov` (with `match_type`). Pages through the
    /// index until `q.limit` records or the end.
    pub fn wayback_cdx(&self, q: &CdxQuery) -> Result<Vec<Observation>> {
        let mut out = Vec::new();
        let mut key: Option<String> = None;
        while out.len() < q.limit {
            let page_size = (q.limit - out.len()).min(q.page_size.max(1));
            let page = self.wayback_cdx_page(q, page_size, key.as_deref())?;
            out.extend(page.records);
            key = page.resume_key;
            if key.is_none() {
                break;
            }
        }
        Ok(out)
    }

    /// One page of Wayback CDX results. Pass the previous page's `resume_key`
    /// (with an otherwise identical query) to continue where it stopped.
    pub fn wayback_cdx_page(
        &self,
        q: &CdxQuery,
        page_size: usize,
        resume_key: Option<&str>,
    ) -> Result<CdxPage> {
        let mut u = url::Url::parse("https://web.archive.org/cdx/search/cdx")?;
        {
            let mut p = u.query_pairs_mut();
            p.append_pair("url", &q.pattern)
                .append_pair("output", "json");
            p.append_pair("fl", "timestamp,original,statuscode,mimetype,digest");
            p.append_pair("limit", &page_size.to_string());
            p.append_pair("showResumeKey", "true");
            if let Some(k) = resume_key {
                p.append_pair("resumeKey", k);
            }
            if let Some(f) = &q.from {
                p.append_pair("from", f);
            }
            if let Some(t) = &q.to {
                p.append_pair("to", t);
            }
            if let Some(m) = &q.match_type {
                p.append_pair("matchType", m);
            }
            if q.collapse_digest {
                p.append_pair("collapse", "digest");
            }
        }
        let body = self.get(u.as_str())?;
        parse_wayback_cdx(&body)
    }

    /// Arquivo.pt CDX index (NDJSON). No paging: one request of up to `q.limit` records.
    pub fn arquivo_cdx(&self, q: &CdxQuery) -> Result<Vec<Observation>> {
        let mut u = url::Url::parse("https://arquivo.pt/wayback/cdx")?;
        {
            let mut p = u.query_pairs_mut();
            p.append_pair("url", &q.pattern)
                .append_pair("output", "json");
            p.append_pair("limit", &q.limit.to_string());
            if let Some(f) = &q.from {
                p.append_pair("from", f);
            }
            if let Some(t) = &q.to {
                p.append_pair("to", t);
            }
            if let Some(m) = &q.match_type {
                p.append_pair("matchType", m);
            }
        }
        let body = self.get(u.as_str())?;
        Ok(parse_arquivo_cdx(&body))
    }

    /// urlquery.net report search (`/public/v1/search/reports/`). Needs an API
    /// key from a urlquery account. Pages by offset until `q.limit` reports or
    /// the end. `q.pattern` is the urlquery search query; `q.from` / `q.to` are
    /// narrowed to whole days, which is all the API accepts.
    ///
    /// The terms allow personal, non-commercial research use and forbid
    /// redistributing their content without permission, so records collected
    /// here are for our analysis and are cited by report link, not republished.
    pub fn urlquery(&self, api_key: &str, q: &CdxQuery) -> Result<Vec<Observation>> {
        let mut out = Vec::new();
        let mut offset = 0;
        while out.len() < q.limit {
            let size = (q.limit - out.len()).min(q.page_size.clamp(1, URLQUERY_MAX_PAGE));
            let page = self.urlquery_page(api_key, q, offset, size)?;
            let n = page.records.len();
            out.extend(page.records);
            offset += n;
            if n == 0 || offset >= page.total_hits {
                break;
            }
        }
        Ok(out)
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

    /// Certificate Transparency search via crt.sh (e.g. `%.hysandbox.example.com`).
    pub fn crtsh(&self, query: &str) -> Result<Vec<CertRecord>> {
        let mut u = url::Url::parse("https://crt.sh/")?;
        u.query_pairs_mut()
            .append_pair("q", query)
            .append_pair("output", "json");
        let body = self.get(u.as_str())?;
        if body.trim().is_empty() {
            return Ok(vec![]);
        }
        let mut recs: Vec<CertRecord> = serde_json::from_str(&body).context("crt.sh JSON")?;
        recs.sort_by(|a, b| b.entry_timestamp.cmp(&a.entry_timestamp));
        Ok(recs)
    }

    /// RDAP record for a registered domain, via the rdap.org bootstrap
    /// redirector. Returns (request URL, JSON body).
    pub fn rdap_domain(&self, domain: &str) -> Result<(String, String)> {
        let url = format!(
            "https://rdap.org/domain/{}",
            domain.trim().trim_end_matches('.')
        );
        let body = self.get(&url)?;
        Ok((url, body))
    }

    /// Fetch `/.well-known/security.txt` (falling back to `/security.txt`).
    pub fn security_txt(&self, domain: &str) -> Result<(String, String)> {
        let domain = domain
            .trim()
            .trim_start_matches("https://")
            .trim_start_matches("http://")
            .trim_end_matches('/');
        let mut last_err = None;
        for path in ["/.well-known/security.txt", "/security.txt"] {
            let url = format!("https://{domain}{path}");
            match self.get(&url) {
                Ok(body) if body.to_ascii_lowercase().contains("contact:") => {
                    return Ok((url, body));
                }
                Ok(_) => last_err = Some(anyhow::anyhow!("{url}: no Contact field")),
                Err(e) => last_err = Some(e),
            }
        }
        Err(last_err.unwrap())
    }
}

/// A short description of an error body: an HTML page's `<title>`, else the first 200 characters.
fn error_excerpt(body: &str) -> String {
    let lower = body.to_ascii_lowercase();
    if let (Some(a), Some(b)) = (lower.find("<title>"), lower.find("</title>"))
        && a + 7 <= b
    {
        return body[a + 7..b].trim().to_string();
    }
    body.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .chars()
        .take(200)
        .collect()
}

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
    /// Records per request when paging (Wayback only).
    #[serde(default = "default_page_size")]
    pub page_size: usize,
}

fn default_limit() -> usize {
    5000
}

fn default_page_size() -> usize {
    1000
}

const URLQUERY_SEARCH: &str = "https://api.urlquery.net/public/v1/search/reports/";
const URLQUERY_REPORT: &str = "https://api.urlquery.net/public/v1/report/";
/// Conservative page size; the API's own maximum is not documented.
const URLQUERY_MAX_PAGE: usize = 100;

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

/// One page of CDX results plus the key to fetch the next one, if any.
#[derive(Debug, Clone, Default)]
pub struct CdxPage {
    pub records: Vec<Observation>,
    pub resume_key: Option<String>,
}

/// Parse Wayback CDX JSON (`output=json`, optionally with `showResumeKey=true`).
/// Records are redacted before they are returned.
pub fn parse_wayback_cdx(body: &str) -> Result<CdxPage> {
    let mut page = CdxPage::default();
    if body.trim().is_empty() {
        return Ok(page);
    }
    let rows: Vec<Vec<Value>> = serde_json::from_str(body).context("wayback CDX JSON")?;
    let mut rows = rows.iter().skip(1);
    while let Some(r) = rows.next() {
        if r.is_empty() {
            // An empty row separates the records from the resume key.
            page.resume_key = rows
                .next()
                .and_then(|k| k.first())
                .and_then(Value::as_str)
                .filter(|k| !k.is_empty())
                .map(str::to_string);
            break;
        }
        let s = |i: usize| {
            r.get(i)
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string()
        };
        let (ts, orig) = (s(0), s(1));
        let mut o = Observation {
            id: format!("wayback:{ts}:{}", s(4)),
            source: "wayback".into(),
            ts: parse_ts(&ts).unwrap_or(0),
            status: s(2).parse().ok(),
            reference: Some(format!("https://web.archive.org/web/{ts}/{orig}")),
            url: orig,
            ..Default::default()
        };
        redact_observation(&mut o);
        page.records.push(o);
    }
    Ok(page)
}

/// Parse Arquivo.pt CDX NDJSON. Records are redacted before they are returned.
pub fn parse_arquivo_cdx(body: &str) -> Vec<Observation> {
    let mut out = Vec::new();
    for line in body.lines().filter(|l| !l.trim().is_empty()) {
        let Ok(v) = serde_json::from_str::<Value>(line) else {
            continue;
        };
        let gs = |k: &str| v.get(k).and_then(Value::as_str).map(str::to_string);
        let (Some(ts), Some(orig)) = (gs("timestamp"), gs("url")) else {
            continue;
        };
        let mut o = Observation {
            id: format!("arquivo:{ts}:{}", gs("digest").unwrap_or_default()),
            source: "arquivo".into(),
            ts: parse_ts(&ts).unwrap_or(0),
            status: gs("status").and_then(|s| s.parse().ok()),
            reference: Some(format!("https://arquivo.pt/wayback/{ts}/{orig}")),
            url: orig,
            ..Default::default()
        };
        redact_observation(&mut o);
        out.push(o);
    }
    out
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertRecord {
    pub id: u64,
    #[serde(default)]
    pub issuer_name: String,
    #[serde(default)]
    pub common_name: String,
    #[serde(default)]
    pub name_value: String,
    #[serde(default)]
    pub entry_timestamp: String,
    #[serde(default)]
    pub not_before: String,
    #[serde(default)]
    pub not_after: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cdx_with_resume_key() {
        let body = r#"[["timestamp","original","statuscode","mimetype","digest"],
            ["20261004081000","https://r.jina.ai/https://a.example/?api_key=s3cr3t","200","text/html","AAA"],
            ["20261004081500","https://r.jina.ai/https://b.example/","200","text/html","BBB"],
            [],
            ["ai,jina,r)/https://b.example/ 20261004081500"]]"#;
        let p = parse_wayback_cdx(body).unwrap();
        assert_eq!(p.records.len(), 2);
        assert_eq!(p.records[0].id, "wayback:20261004081000:AAA");
        assert!(p.records[0].url.contains("api_key=REDACTED-"));
        assert!(p.resume_key.as_deref().unwrap().ends_with("20261004081500"));
    }

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

    #[test]
    fn cdx_last_page() {
        let body = r#"[["timestamp","original","statuscode","mimetype","digest"],
            ["20261004081000","https://a.example/","200","text/html","AAA"]]"#;
        let p = parse_wayback_cdx(body).unwrap();
        assert_eq!(p.records.len(), 1);
        assert!(p.resume_key.is_none());
        assert!(parse_wayback_cdx("").unwrap().records.is_empty());
    }

    #[test]
    fn arquivo_ndjson() {
        let body = "{\"timestamp\":\"20261004081000\",\"url\":\"https://a.example/?token=x\",\"status\":\"200\",\"digest\":\"D\"}\nnot json\n";
        let v = parse_arquivo_cdx(body);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].status, Some(200));
    }

    #[test]
    fn error_excerpts() {
        let html = "<html><head><meta charset=\"UTF-8\"><title>Internet Archive: Temporarily Offline</title></head><body>...";
        assert_eq!(error_excerpt(html), "Internet Archive: Temporarily Offline");
        assert_eq!(
            error_excerpt(
                "  rate
 limited "
            ),
            "rate limited"
        );
    }

    #[test]
    fn backoff_doubles_and_caps() {
        let r = Retry::default();
        assert_eq!(r.wait(0, None), Duration::from_secs(5));
        assert_eq!(r.wait(2, None), Duration::from_secs(20));
        assert_eq!(r.wait(10, None), Duration::from_secs(300));
        assert_eq!(
            r.wait(0, Some(Duration::from_secs(42))),
            Duration::from_secs(42)
        );
    }
}
