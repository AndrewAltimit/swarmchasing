//! The blocking HTTP client every collector shares: one request at a time
//! with a minimum gap, an identifying user agent, retries with backoff on
//! transient failures, and a request count for sources with a quota.

use anyhow::Result;
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

    pub(crate) fn get(&self, url: &str) -> Result<String> {
        self.get_with(url, &[])
    }

    /// GET with extra request headers. Header values (API keys) never appear in
    /// error messages, which name only the URL.
    pub(crate) fn get_with(&self, url: &str, headers: &[(&str, &str)]) -> Result<String> {
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
}
