//! An affected organisation's RFC 9116 security.txt, for its security
//! contact: a published contact file on the organisation's own site.
//!
//! The lookup takes a bare domain name (no path, user info, port or IP
//! address), follows redirects only within that host over HTTPS, and accepts
//! only a `text/plain` answer, or one with no type that is not HTML. An
//! expired file (`Expires` in the past) is still returned, marked expired,
//! since RFC 9116 says to treat its contents as stale rather than void.

use crate::Client;
use crate::client::{Fetched, Opts, now_secs};
use anyhow::{Result, bail};

/// A fetched security.txt.
#[derive(Debug, Clone)]
pub struct Fetch {
    /// Where it was found, after same-host redirects.
    pub url: String,
    pub body: String,
    /// Its `Expires` is in the past.
    pub expired: bool,
}

/// A domain argument as a lowercase ASCII host: an `https://` prefix and a
/// trailing slash are tolerated; a path, query, user info, port or IP address
/// is refused. Internationalised names are converted to punycode.
pub fn validate_domain(arg: &str) -> Result<String> {
    let d = arg.trim();
    let d = d
        .strip_prefix("https://")
        .or_else(|| d.strip_prefix("http://"))
        .unwrap_or(d);
    let d = d.strip_suffix('/').unwrap_or(d).trim_end_matches('.');
    if d.is_empty() {
        bail!("empty domain");
    }
    if let Some(c) = d
        .chars()
        .find(|c| matches!(c, '/' | '\\' | '@' | '?' | '#' | ':' | '%') || c.is_whitespace())
    {
        bail!(
            "`{arg}` is not a bare domain name (found `{c}`): give the host only, with no path, port or user info"
        );
    }
    if d.parse::<std::net::IpAddr>().is_ok() || d.starts_with('[') {
        bail!("`{arg}` is an IP address; security.txt lookups need a domain name");
    }
    let u = url::Url::parse(&format!("https://{d}/"))
        .map_err(|e| anyhow::anyhow!("`{arg}` is not a valid domain name: {e}"))?;
    let Some(url::Host::Domain(host)) = u.host() else {
        bail!("`{arg}` is not a domain name");
    };
    let host = host.to_ascii_lowercase();
    let ok_label = |l: &str| {
        !l.is_empty()
            && l.len() <= 63
            && !l.starts_with('-')
            && !l.ends_with('-')
            && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
    };
    if !host.contains('.') || host.len() > 253 || !host.split('.').all(ok_label) {
        bail!("`{arg}` is not a valid domain name");
    }
    Ok(host)
}

/// Whether a response is an acceptable security.txt: `text/plain`, or no
/// type and a body that is not HTML; with a Contact field.
pub fn check_response(content_type: Option<&str>, body: &str) -> Result<()> {
    let head = body.trim_start().get(..64).unwrap_or(body.trim_start());
    let head = head.to_ascii_lowercase();
    match content_type.map(|t| {
        t.split(';')
            .next()
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase()
    }) {
        Some(t) if t == "text/plain" => {}
        Some(t) => bail!("served as `{t}`, not text/plain"),
        None if head.starts_with("<!doctype") || head.starts_with("<html") => {
            bail!("served as HTML")
        }
        None => {}
    }
    if !body.to_ascii_lowercase().contains("contact:") {
        bail!("no Contact field");
    }
    Ok(())
}

/// Whether the file's `Expires` lies before `now` (Unix seconds). A file
/// with no readable `Expires` is not taken as expired.
pub fn is_expired(body: &str, now: i64) -> bool {
    sc_core::parse_security_txt(body)
        .expires
        .as_deref()
        .and_then(crate::parse_date)
        .is_some_and(|t| t < now)
}

impl Client {
    /// Fetch `/.well-known/security.txt` (falling back to `/security.txt`) for
    /// a bare domain. Returns (request URL, body).
    pub fn security_txt(&self, domain: &str) -> Result<(String, String)> {
        let f = self.security_txt_checked(domain)?;
        Ok((f.url, f.body))
    }

    /// [`Client::security_txt`], with the expiry checked.
    pub fn security_txt_checked(&self, domain: &str) -> Result<Fetch> {
        let host = validate_domain(domain)?;
        let mut last_err = None;
        for path in ["/.well-known/security.txt", "/security.txt"] {
            let url = format!("https://{host}{path}");
            let opts = Opts {
                same_host: true,
                ..Opts::default()
            };
            match self.fetch(&url, &[], opts) {
                Ok(Fetched {
                    body,
                    content_type,
                    final_url,
                    ..
                }) => match check_response(content_type.as_deref(), &body) {
                    Ok(()) => {
                        return Ok(Fetch {
                            url: final_url,
                            expired: is_expired(&body, now_secs()),
                            body,
                        });
                    }
                    Err(e) => last_err = Some(e.context(url)),
                },
                Err(e) => last_err = Some(e),
            }
        }
        Err(last_err.unwrap_or_else(|| anyhow::anyhow!("no security.txt")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_arguments() {
        assert_eq!(validate_domain("Example.ORG").unwrap(), "example.org");
        assert_eq!(
            validate_domain("https://example.org/").unwrap(),
            "example.org"
        );
        assert_eq!(validate_domain("example.org.").unwrap(), "example.org");
        assert_eq!(
            validate_domain("bücher.example").unwrap(),
            "xn--bcher-kva.example"
        );
        for bad in [
            "",
            "example.org/path",
            "user@example.org",
            "example.org:8443",
            "example.org?x=1",
            "203.0.113.7",
            "[2001:db8::1]",
            "localhost",
            "-bad.example",
            "exa mple.org",
            "example.org%2f..",
        ] {
            assert!(validate_domain(bad).is_err(), "{bad} accepted");
        }
    }

    #[test]
    fn response_checks() {
        let ok = "Contact: mailto:security@example.org\n";
        assert!(check_response(Some("text/plain; charset=utf-8"), ok).is_ok());
        assert!(check_response(None, ok).is_ok());
        assert!(check_response(Some("text/html"), ok).is_err());
        assert!(check_response(None, "<!DOCTYPE html><p>Contact: x</p>").is_err());
        assert!(check_response(Some("text/plain"), "Policy: x\n").is_err());
    }

    #[test]
    fn expiry() {
        let body = "Contact: mailto:s@example.org\nExpires: 2026-12-31T23:00:00.000Z\n";
        assert!(!is_expired(body, 1_791_662_400));
        assert!(is_expired(body, 1_830_000_000));
        assert!(!is_expired("Contact: x\n", 1_830_000_000));
    }
}
