//! The blocking HTTP client every collector shares: one request at a time
//! with a minimum gap per host, an identifying user agent, retries with
//! jittered backoff on transient failures, a cap on response size, an
//! optional on-disk cache with conditional requests, and a request count for
//! sources with a quota.

use crate::cache::{Cached, HttpCache};
use anyhow::Result;
use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::io::Read;
use std::path::Path;
use std::time::{Duration, Instant};

pub const USER_AGENT: &str = concat!(
    "swarmchase/",
    env!("CARGO_PKG_VERSION"),
    " (passive research; +https://github.com/AndrewAltimit/swarmchasing)"
);

/// Default cap on a response body read into memory.
pub const DEFAULT_MAX_BODY: usize = 64 << 20;

/// Retry policy for transient failures (HTTP 429/5xx, timeouts, dropped connections).
#[derive(Debug, Clone, Copy)]
pub struct Retry {
    /// Retries after the first attempt.
    pub max_retries: u32,
    /// First wait; doubles after each retry.
    pub base: Duration,
    /// Cap on any single wait, including a server's `Retry-After`.
    pub max_wait: Duration,
    /// Spread of the backoff wait, as a fraction either side (0.25 waits
    /// between 75% and 125% of it), so clients that failed together do not
    /// retry together. A server's `Retry-After` is honoured as given.
    pub jitter: f64,
}

impl Default for Retry {
    fn default() -> Self {
        Self {
            max_retries: 5,
            base: Duration::from_secs(5),
            max_wait: Duration::from_secs(300),
            jitter: 0.25,
        }
    }
}

impl Retry {
    /// Wait before retry number `attempt` (0-based), honouring `Retry-After`
    /// when given, without jitter.
    pub fn wait(&self, attempt: u32, retry_after: Option<Duration>) -> Duration {
        let backoff = self.base.saturating_mul(1u32 << attempt.min(16));
        retry_after.unwrap_or(backoff).min(self.max_wait)
    }

    /// [`Retry::wait`] with the backoff spread by `unit` (uniform in `[0, 1)`).
    pub fn wait_jittered(
        &self,
        attempt: u32,
        retry_after: Option<Duration>,
        unit: f64,
    ) -> Duration {
        let w = self.wait(attempt, retry_after);
        if retry_after.is_some() || self.jitter <= 0.0 {
            return w;
        }
        let f = 1.0 + self.jitter.min(1.0) * (2.0 * unit.clamp(0.0, 1.0) - 1.0);
        w.mul_f64(f).min(self.max_wait)
    }
}

/// A `Retry-After` value: delay seconds, or an HTTP date (RFC 9110 IMF-fixdate)
/// taken relative to `now` (Unix seconds). A date in the past is no wait.
pub fn parse_retry_after(v: &str, now: i64) -> Option<Duration> {
    let v = v.trim();
    if let Ok(s) = v.parse::<u64>() {
        return Some(Duration::from_secs(s));
    }
    let t = chrono::DateTime::parse_from_rfc2822(v).ok()?.timestamp();
    Some(Duration::from_secs((t - now).max(0) as u64))
}

/// Unix seconds now.
pub(crate) fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

/// A response read into memory.
#[derive(Debug, Clone, Default)]
pub(crate) struct Fetched {
    pub status: u16,
    pub body: String,
    pub content_type: Option<String>,
    /// The URL after redirects.
    pub final_url: String,
}

/// How one request is made.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct Opts {
    /// Follow redirects only within the same host and scheme.
    pub same_host: bool,
    /// A 404 is an answer (an empty index), not an error.
    pub not_found_ok: bool,
}

pub struct Client {
    http: reqwest::blocking::Client,
    /// Follows redirects only within the requested host.
    http_same_host: reqwest::blocking::Client,
    min_interval: Duration,
    retry: Retry,
    max_body: usize,
    cache: Option<HttpCache>,
    last: RefCell<HashMap<String, Instant>>,
    requests: Cell<usize>,
    cache_hits: Cell<usize>,
    rng: Cell<u64>,
}

/// Why a request failed, and whether trying again could help.
enum Failure {
    Transient(anyhow::Error, Option<Duration>),
    Fatal(anyhow::Error),
}

struct Resp {
    fetched: Fetched,
    etag: Option<String>,
    last_modified: Option<String>,
}

impl Client {
    pub fn new(min_interval: Duration) -> Result<Self> {
        let ua = std::env::var("SWARMCHASE_UA").unwrap_or_else(|_| USER_AGENT.to_string());
        let http = reqwest::blocking::Client::builder()
            .user_agent(ua.clone())
            .timeout(Duration::from_secs(90))
            .build()?;
        let http_same_host = reqwest::blocking::Client::builder()
            .user_agent(ua)
            .timeout(Duration::from_secs(30))
            .redirect(reqwest::redirect::Policy::custom(|a| {
                let first = &a.previous()[0];
                if a.previous().len() > 5 {
                    a.error("too many redirects")
                } else if a.url().host_str() != first.host_str() || a.url().scheme() != "https" {
                    a.error("redirect to another host")
                } else {
                    a.follow()
                }
            }))
            .build()?;
        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0x9e37_79b9, |d| d.as_nanos() as u64)
            | 1;
        Ok(Self {
            http,
            http_same_host,
            min_interval,
            retry: Retry::default(),
            max_body: DEFAULT_MAX_BODY,
            cache: None,
            last: RefCell::new(HashMap::new()),
            requests: Cell::new(0),
            cache_hits: Cell::new(0),
            rng: Cell::new(seed),
        })
    }

    pub fn with_retry(mut self, retry: Retry) -> Self {
        self.retry = retry;
        self
    }

    /// Cap on a response body read into memory; a larger response fails.
    pub fn with_max_body(mut self, bytes: usize) -> Self {
        self.max_body = bytes;
        self
    }

    /// Cache responses under `dir`. A cached response younger than `ttl` is
    /// used without a request; an older one is revalidated with its ETag or
    /// Last-Modified. Only requests without extra headers (no API keys) are
    /// cached.
    pub fn with_cache(mut self, dir: &Path, ttl: Duration) -> Self {
        self.cache = Some(HttpCache::new(dir, ttl));
        self
    }

    /// HTTP requests sent so far, retries included. Sources with a quota
    /// (urlquery) report this per run.
    pub fn requests(&self) -> usize {
        self.requests.get()
    }

    /// Responses served from the cache without a request.
    pub fn cache_hits(&self) -> usize {
        self.cache_hits.get()
    }

    pub(crate) fn get(&self, url: &str) -> Result<String> {
        self.get_with(url, &[])
    }

    /// GET with extra request headers. Header values (API keys) never appear in
    /// error messages, which name only the URL.
    pub(crate) fn get_with(&self, url: &str, headers: &[(&str, &str)]) -> Result<String> {
        Ok(self.fetch(url, headers, Opts::default())?.body)
    }

    /// GET with options, through the cache when one is set.
    pub(crate) fn fetch(&self, url: &str, headers: &[(&str, &str)], opts: Opts) -> Result<Fetched> {
        let cache = self.cache.as_ref().filter(|_| headers.is_empty());
        let cached = cache.and_then(|c| c.load(url));
        if let (Some(c), Some(hit)) = (cache, &cached)
            && c.fresh(hit)
        {
            self.cache_hits.set(self.cache_hits.get() + 1);
            return Ok(hit.fetched(url));
        }
        let mut hs: Vec<(&str, &str)> = headers.to_vec();
        if let Some(hit) = &cached {
            if let Some(e) = &hit.meta.etag {
                hs.push(("If-None-Match", e));
            }
            if let Some(m) = &hit.meta.last_modified {
                hs.push(("If-Modified-Since", m));
            }
        }
        let r = self.with_retries(|| self.try_get(url, &hs, opts))?;
        if let (Some(c), Some(hit)) = (cache, &cached)
            && r.fetched.status == 304
        {
            c.touch(url, hit);
            return Ok(hit.fetched(url));
        }
        if let Some(c) = cache
            && (200..300).contains(&r.fetched.status)
        {
            c.store(
                url,
                &r.fetched,
                r.etag.as_deref(),
                r.last_modified.as_deref(),
            );
        }
        Ok(r.fetched)
    }

    fn with_retries<T>(&self, mut f: impl FnMut() -> std::result::Result<T, Failure>) -> Result<T> {
        let mut attempt = 0;
        loop {
            match f() {
                Ok(v) => return Ok(v),
                Err(Failure::Fatal(e)) => return Err(e),
                Err(Failure::Transient(e, retry_after)) => {
                    if attempt >= self.retry.max_retries {
                        return Err(e.context(format!("gave up after {} attempts", attempt + 1)));
                    }
                    let wait = self.retry.wait_jittered(attempt, retry_after, self.unit());
                    eprintln!("  {e:#}; retrying in {}s", wait.as_secs());
                    std::thread::sleep(wait);
                    attempt += 1;
                }
            }
        }
    }

    /// A pseudo-random number in `[0, 1)` for jitter (xorshift; not for secrets).
    fn unit(&self) -> f64 {
        let mut x = self.rng.get();
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.rng.set(x);
        (x >> 11) as f64 / (1u64 << 53) as f64
    }

    /// Wait out the minimum interval for `url`'s host, then count a request.
    fn pace(&self, url: &str) {
        let host = url::Url::parse(url)
            .ok()
            .and_then(|u| u.host_str().map(str::to_string))
            .unwrap_or_default();
        let mut last = self.last.borrow_mut();
        if let Some(t) = last.get(&host) {
            let el = t.elapsed();
            if el < self.min_interval {
                std::thread::sleep(self.min_interval - el);
            }
        }
        last.insert(host, Instant::now());
        self.requests.set(self.requests.get() + 1);
    }

    fn send(
        &self,
        url: &str,
        headers: &[(&str, &str)],
        opts: Opts,
    ) -> std::result::Result<reqwest::blocking::Response, Failure> {
        self.pace(url);
        let http = if opts.same_host {
            &self.http_same_host
        } else {
            &self.http
        };
        let mut req = http.get(url);
        for (k, v) in headers {
            req = req.header(*k, *v);
        }
        match req.send() {
            Ok(r) => Ok(r),
            Err(e) => {
                let transient =
                    !e.is_redirect() && (e.is_timeout() || e.is_connect() || e.is_request());
                let e = anyhow::Error::new(e).context(format!("GET {url}"));
                Err(if transient {
                    Failure::Transient(e, None)
                } else {
                    Failure::Fatal(e)
                })
            }
        }
    }

    fn try_get(
        &self,
        url: &str,
        headers: &[(&str, &str)],
        opts: Opts,
    ) -> std::result::Result<Resp, Failure> {
        let resp = self.send(url, headers, opts)?;
        let status = resp.status();
        let header = |h: reqwest::header::HeaderName| {
            resp.headers()
                .get(h)
                .and_then(|v| v.to_str().ok())
                .map(str::to_string)
        };
        let retry_after =
            header(reqwest::header::RETRY_AFTER).and_then(|v| parse_retry_after(&v, now_secs()));
        let content_type = header(reqwest::header::CONTENT_TYPE);
        let etag = header(reqwest::header::ETAG);
        let last_modified = header(reqwest::header::LAST_MODIFIED);
        let final_url = resp.url().to_string();
        if resp
            .content_length()
            .is_some_and(|n| n > self.max_body as u64)
        {
            return Err(Failure::Fatal(anyhow::anyhow!(
                "GET {url}: response of {} bytes is over the {} byte cap",
                resp.content_length().unwrap_or(0),
                self.max_body
            )));
        }
        let mut bytes = Vec::new();
        if let Err(e) = resp.take(self.max_body as u64 + 1).read_to_end(&mut bytes) {
            return Err(Failure::Transient(
                anyhow::Error::new(e).context(format!("GET {url}: reading body")),
                None,
            ));
        }
        if bytes.len() > self.max_body {
            return Err(Failure::Fatal(anyhow::anyhow!(
                "GET {url}: response is over the {} byte cap",
                self.max_body
            )));
        }
        let body = String::from_utf8_lossy(&bytes).into_owned();
        let code = status.as_u16();
        if status.is_success() || code == 304 || (code == 404 && opts.not_found_ok) {
            return Ok(Resp {
                fetched: Fetched {
                    status: code,
                    body,
                    content_type,
                    final_url,
                },
                etag,
                last_modified,
            });
        }
        let e = anyhow::anyhow!("GET {url}: HTTP {status}: {}", error_excerpt(&body));
        if code == 429 || status.is_server_error() {
            Err(Failure::Transient(e, retry_after))
        } else {
            Err(Failure::Fatal(e))
        }
    }

    /// GET a large file as a stream (never cached, never held in memory).
    /// Reading more than `max_bytes` fails.
    pub(crate) fn get_stream(&self, url: &str, max_bytes: u64) -> Result<Box<dyn Read>> {
        let resp = self.with_retries(|| {
            let r = self.send(url, &[], Opts::default())?;
            let status = r.status();
            if status.is_success() {
                return Ok(r);
            }
            let e = anyhow::anyhow!("GET {url}: HTTP {status}");
            if status.as_u16() == 429 || status.is_server_error() {
                Err(Failure::Transient(e, None))
            } else {
                Err(Failure::Fatal(e))
            }
        })?;
        Ok(Box::new(Capped {
            inner: resp,
            left: max_bytes,
        }))
    }

    /// Download `url` to `path` (through a temporary file beside it). Returns
    /// the bytes written.
    pub fn download(&self, url: &str, path: &Path, max_bytes: u64) -> Result<u64> {
        if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
            std::fs::create_dir_all(dir)?;
        }
        let tmp = path.with_extension("part");
        let mut r = self.get_stream(url, max_bytes)?;
        let mut f = std::fs::File::create(&tmp)?;
        let n = std::io::copy(&mut r, &mut f)?;
        drop(f);
        std::fs::rename(&tmp, path)?;
        Ok(n)
    }
}

/// A reader that fails once more than `left` bytes have been read.
struct Capped<R> {
    inner: R,
    left: u64,
}

impl<R: Read> Read for Capped<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        if n as u64 > self.left {
            return Err(std::io::Error::other("response over the size cap"));
        }
        self.left -= n as u64;
        Ok(n)
    }
}

impl Cached {
    fn fetched(&self, url: &str) -> Fetched {
        Fetched {
            status: 200,
            body: self.body.clone(),
            content_type: self.meta.content_type.clone(),
            final_url: url.to_string(),
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_excerpts() {
        let html = "<html><head><meta charset=\"UTF-8\"><title>Internet Archive: Temporarily Offline</title></head><body>...";
        assert_eq!(error_excerpt(html), "Internet Archive: Temporarily Offline");
        assert_eq!(error_excerpt("  rate\n limited "), "rate limited");
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

    #[test]
    fn jitter_spreads_backoff_but_not_retry_after() {
        let r = Retry::default();
        assert_eq!(r.wait_jittered(2, None, 0.0), Duration::from_secs(15));
        assert_eq!(r.wait_jittered(2, None, 0.5), Duration::from_secs(20));
        assert!(r.wait_jittered(2, None, 0.999) <= Duration::from_secs(25));
        assert_eq!(r.wait_jittered(10, None, 0.999), Duration::from_secs(300));
        let ra = Some(Duration::from_secs(7));
        assert_eq!(r.wait_jittered(0, ra, 0.9), Duration::from_secs(7));
    }

    #[test]
    fn retry_after_seconds_or_http_date() {
        let now = 1_791_664_800; // 2026-10-10T20:40:00Z
        assert_eq!(
            parse_retry_after("120", now),
            Some(Duration::from_secs(120))
        );
        assert_eq!(
            parse_retry_after("Sat, 10 Oct 2026 20:41:30 GMT", now),
            Some(Duration::from_secs(90))
        );
        assert_eq!(
            parse_retry_after("Sat, 10 Oct 2026 20:00:00 GMT", now),
            Some(Duration::ZERO)
        );
        assert_eq!(parse_retry_after("soon", now), None);
    }

    #[test]
    fn jitter_source_stays_in_range() {
        let c = Client::new(Duration::ZERO).unwrap();
        for _ in 0..1000 {
            let u = c.unit();
            assert!((0.0..1.0).contains(&u));
        }
    }
}
