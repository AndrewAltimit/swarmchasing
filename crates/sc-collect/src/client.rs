//! The blocking HTTP client every collector shares: one request at a time
//! with a minimum gap per host, an identifying user agent, retries with
//! jittered backoff on transient failures (and longer patience for a host
//! that answers "temporarily unavailable", which is then skipped for the
//! rest of the run if it stays down), a cap on response size, an
//! optional on-disk cache with conditional requests, and a request count for
//! sources with a quota.

use crate::cache::{Cached, HttpCache};
use anyhow::{Context, Result};
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
    /// Of those, retries after a gateway timeout (HTTP 504) or a request
    /// that timed out. An index query too heavy for the server times out the
    /// same way every time, and each attempt takes a minute or more.
    pub max_timeout_retries: u32,
    /// First wait; doubles after each retry.
    pub base: Duration,
    /// Cap on any single wait, including a server's `Retry-After`.
    pub max_wait: Duration,
    /// Spread of the backoff wait, as a fraction either side (0.25 waits
    /// between 75% and 125% of it), so clients that failed together do not
    /// retry together. A server's `Retry-After` is honoured as given.
    pub jitter: f64,
    /// How long to keep retrying a host that answers HTTP 503 (the Internet
    /// Archive's "Temporarily Offline" page), counted from the first attempt.
    /// Such outages outlast `max_retries` short waits, so they get time
    /// rather than a count. Once it runs out the host counts as down for
    /// the rest of the client's life (one watch run): later requests to it
    /// fail at once instead of waiting out the same outage again.
    pub unavailable_patience: Duration,
}

impl Default for Retry {
    fn default() -> Self {
        Self {
            max_retries: 5,
            max_timeout_retries: 2,
            base: Duration::from_secs(5),
            max_wait: Duration::from_secs(300),
            jitter: 0.25,
            unavailable_patience: Duration::from_secs(600),
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
    /// Hosts that stayed unavailable past `unavailable_patience`, with why.
    down: RefCell<HashMap<String, String>>,
}

/// Why a request failed, and whether trying again could help.
enum Failure {
    Transient(anyhow::Error, Option<Duration>),
    /// A gateway or client timeout: retried at most `max_timeout_retries` times.
    TimedOut(anyhow::Error),
    /// HTTP 503: the service is down for a while. Retried for
    /// `unavailable_patience`, then the host is marked down.
    Unavailable(anyhow::Error, Option<Duration>),
    Fatal(anyhow::Error),
}

/// The host of `url`, or an empty string.
fn host_of(url: &str) -> String {
    url::Url::parse(url)
        .ok()
        .and_then(|u| u.host_str().map(str::to_string))
        .unwrap_or_default()
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
            down: RefCell::new(HashMap::new()),
        })
    }

    /// Hosts given up on as unavailable, with the reason.
    pub fn down_hosts(&self) -> Vec<(String, String)> {
        let mut v: Vec<_> = self
            .down
            .borrow()
            .iter()
            .map(|(h, w)| (h.clone(), w.clone()))
            .collect();
        v.sort();
        v
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
        let r = self.with_retries(url, || self.try_get(url, &hs, opts))?;
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

    /// Run `f` with retries for `url`'s host. A host already marked down this
    /// run fails at once.
    fn with_retries<T>(
        &self,
        url: &str,
        mut f: impl FnMut() -> std::result::Result<T, Failure>,
    ) -> Result<T> {
        let host = host_of(url);
        if let Some(why) = self.down.borrow().get(&host) {
            anyhow::bail!(
                "{host} was unavailable earlier this run ({why}); not retried until the next run"
            );
        }
        let started = Instant::now();
        let (mut attempt, mut timeouts) = (0, 0);
        loop {
            let (e, retry_after, unavailable) = match f() {
                Ok(v) => return Ok(v),
                Err(Failure::Fatal(e)) => return Err(e),
                Err(Failure::Transient(e, retry_after)) => (e, retry_after, false),
                Err(Failure::Unavailable(e, retry_after)) => (e, retry_after, true),
                Err(Failure::TimedOut(e)) => {
                    timeouts += 1;
                    (e, None, false)
                }
            };
            let wait = self.retry.wait_jittered(attempt, retry_after, self.unit());
            let give_up = if unavailable {
                started.elapsed() + wait > self.retry.unavailable_patience
            } else {
                attempt >= self.retry.max_retries || timeouts > self.retry.max_timeout_retries
            };
            if give_up {
                let why = format!(
                    "gave up after {} attempts over {}s",
                    attempt + 1,
                    started.elapsed().as_secs()
                );
                if unavailable && !host.is_empty() {
                    self.down
                        .borrow_mut()
                        .insert(host.clone(), format!("HTTP 503, {why}"));
                }
                return Err(e.context(format!("gave up after {} attempts", attempt + 1)));
            }
            eprintln!("  {e:#}; retrying in {}s", wait.as_secs());
            std::thread::sleep(wait);
            attempt += 1;
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
        let host = host_of(url);
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
                let timed_out = e.is_timeout();
                let e = anyhow::Error::new(e).context(format!("GET {url}"));
                Err(if timed_out {
                    Failure::TimedOut(e)
                } else if transient {
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
        if code == 504 {
            Err(Failure::TimedOut(e))
        } else if code == 503 {
            Err(Failure::Unavailable(e, retry_after))
        } else if code == 429 || status.is_server_error() {
            Err(Failure::Transient(e, retry_after))
        } else {
            Err(Failure::Fatal(e))
        }
    }

    /// GET a large file as a stream (never cached, never held in memory).
    /// Reading more than `max_bytes` fails.
    pub(crate) fn get_stream(&self, url: &str, max_bytes: u64) -> Result<Box<dyn Read>> {
        self.get_stream_opt(url, max_bytes, false)?
            .with_context(|| format!("GET {url}: HTTP 404"))
    }

    /// [`Client::get_stream`], with a 404 (a file the source never
    /// published) as `None` when `not_found_ok`.
    pub(crate) fn get_stream_opt(
        &self,
        url: &str,
        max_bytes: u64,
        not_found_ok: bool,
    ) -> Result<Option<Box<dyn Read>>> {
        let resp = self.with_retries(url, || {
            let r = self.send(url, &[], Opts::default())?;
            let status = r.status();
            if status.is_success() {
                return Ok(Some(r));
            }
            if not_found_ok && status.as_u16() == 404 {
                return Ok(None);
            }
            let e = anyhow::anyhow!("GET {url}: HTTP {status}");
            if status.as_u16() == 504 {
                Err(Failure::TimedOut(e))
            } else if status.as_u16() == 503 {
                Err(Failure::Unavailable(e, None))
            } else if status.as_u16() == 429 || status.is_server_error() {
                Err(Failure::Transient(e, None))
            } else {
                Err(Failure::Fatal(e))
            }
        })?;
        Ok(resp.map(|r| {
            Box::new(Capped {
                inner: r,
                left: max_bytes,
            }) as Box<dyn Read>
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
    fn timeouts_get_fewer_retries_than_other_transient_failures() {
        let c = Client::new(Duration::ZERO).unwrap().with_retry(Retry {
            base: Duration::ZERO,
            ..Retry::default()
        });
        let calls = Cell::new(0);
        let u = "https://index.example/cdx";
        let r: Result<()> = c.with_retries(u, || {
            calls.set(calls.get() + 1);
            Err(Failure::TimedOut(anyhow::anyhow!("HTTP 504")))
        });
        assert!(r.is_err());
        assert_eq!(calls.get(), 3);
        calls.set(0);
        let r: Result<()> = c.with_retries(u, || {
            calls.set(calls.get() + 1);
            Err(Failure::Transient(anyhow::anyhow!("HTTP 500"), None))
        });
        assert!(r.is_err());
        assert_eq!(calls.get(), 6);
        // Neither marks the host down.
        assert!(c.down_hosts().is_empty());
    }

    #[test]
    fn an_unavailable_host_gets_time_then_is_skipped_for_the_run() {
        let c = Client::new(Duration::ZERO).unwrap().with_retry(Retry {
            base: Duration::from_millis(1),
            max_wait: Duration::from_millis(2),
            unavailable_patience: Duration::from_millis(40),
            ..Retry::default()
        });
        let calls = Cell::new(0);
        let u = "https://archive.example/cdx?url=a";
        let r: Result<()> = c.with_retries(u, || {
            calls.set(calls.get() + 1);
            Err(Failure::Unavailable(
                anyhow::anyhow!("HTTP 503: Temporarily Offline"),
                None,
            ))
        });
        assert!(r.is_err());
        // More attempts than `max_retries` allows other failures.
        assert!(calls.get() > 6, "{}", calls.get());
        assert_eq!(c.down_hosts()[0].0, "archive.example");
        // The next request to that host fails without being sent.
        calls.set(0);
        let r: Result<()> = c.with_retries("https://archive.example/other", || {
            calls.set(calls.get() + 1);
            Ok(())
        });
        let e = format!("{:#}", r.unwrap_err());
        assert!(e.contains("unavailable earlier this run"), "{e}");
        assert_eq!(calls.get(), 0);
        // Other hosts are unaffected.
        assert!(c.with_retries("https://other.example/", || Ok(())).is_ok());
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
