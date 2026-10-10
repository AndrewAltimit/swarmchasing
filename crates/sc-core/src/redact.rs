//! Redaction at ingest.
//!
//! Collected records can carry secrets the agents captured or used: session
//! cookies, bearer tokens, API keys. They are useless as evidence and harmful to
//! keep, so they are replaced with a short hash before anything is stored or
//! analysed. The hash is deterministic, so two records that carried the same
//! secret still link to each other.
//!
//! Only secret-shaped values are touched. Attack payloads, agent tags and run
//! identifiers stay as they are, because the rules need them.

use regex::Regex;
use sha2::{Digest, Sha256};
use std::sync::OnceLock;

use crate::model::Observation;

/// Prefix of every replacement value. Redaction skips values that already carry it.
pub const MARK: &str = "REDACTED-";

/// Query/fragment parameter names whose values are always secrets.
const SECRET_PARAM: &str = r"(?i)^(cookies?|set-cookie|auth|authorization|access_?token|session_?token|access_?key|refresh_?token|id_?token|auth_?token|api_?key|apikey|x-api-key|client_?secret|secret|password|passwd|pwd|pass|jwt|bearer|phpsessid|jsessionid|aspsessionid\w*|asp\.net_sessionid|connect\.sid|sessionid|session_id|csrftoken|csrf_token|xsrf-token|_xsrf|sid_guard|sessionid_ss|x5sec|umidtoken|bx-umidtoken)$";

/// Headers whose values are always secrets.
const SECRET_HEADER: &str = r"(?i)^(cookie|set-cookie|authorization|proxy-authorization|x-api-key|x-auth-token|x-csrf-token|x-xsrf-token)$";

/// Well-known credential shapes, redacted wherever they appear.
const SECRET_VALUE: &str = concat!(
    r"eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}", // JWT
    r"|\bAKIA[0-9A-Z]{16}\b",                                         // AWS access key id
    r"|\bgh[pousr]_[A-Za-z0-9]{30,}",                                 // GitHub token
    r"|\bgithub_pat_[A-Za-z0-9_]{30,}",
    r"|\bxox[abposr]-[A-Za-z0-9-]{10,}", // Slack
    r"|\bsk-(ant-)?[A-Za-z0-9_-]{20,}",  // OpenAI / Anthropic style keys
    r"|\bAIza[0-9A-Za-z_-]{35}",         // Google API key
    r"|\bglpat-[A-Za-z0-9_-]{20,}",      // GitLab
);

fn secret_param() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(SECRET_PARAM).unwrap())
}

fn secret_header() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(SECRET_HEADER).unwrap())
}

pub(crate) fn secret_value() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(SECRET_VALUE).unwrap())
}

/// A value that is plainly a template placeholder (`YOUR_API_KEY`,
/// `<your-token>`, `{{token}}`, `${KEY}`, `INSERT_KEY_HERE`). It is no secret,
/// and the rules read it as model output, so it is kept.
fn placeholder() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(concat!(
            r"(?i)^\s*(",
            r"(your|insert|replace|enter)[_-][a-z_-]{1,40}",
            r"|replace_?me|[a-z_-]{1,40}_here",
            r"|<[a-z_ -]{1,40}>|\{\{\s*[a-z_.-]{1,40}\s*\}\}|\$\{[a-z_.-]{1,40}\}",
            r")\s*$"
        ))
        .unwrap()
    })
}

/// `name=value; name2=value2`: a dumped cookie jar, usually from `document.cookie`.
fn cookie_jar() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(r"^\s*[\w.$-]+=[^;=\s]+(\s*;\s*[\w.$-]+=[^;=]*){1,}\s*;?\s*$").unwrap()
    })
}

/// Replacement for a secret: `REDACTED-` plus the first 12 hex digits of its SHA-256.
pub fn hash_token(secret: &str) -> String {
    let d = Sha256::digest(secret.as_bytes());
    let hex: String = d.iter().take(6).map(|b| format!("{b:02x}")).collect();
    format!("{MARK}{hex}")
}

/// Redact secrets in an observation in place. Returns how many values were replaced.
pub fn redact_observation(o: &mut Observation) -> usize {
    let mut n = 0;
    o.url = redact_url(&o.url, &mut n);
    if let Some(f) = o.final_url.take() {
        o.final_url = Some(redact_url(&f, &mut n));
    }
    if let Some(r) = o.reference.take() {
        o.reference = Some(redact_url(&r, &mut n));
    }
    for (k, v) in o.headers.iter_mut() {
        if secret_header().is_match(k) && !v.starts_with(MARK) {
            *v = hash_token(v);
            n += 1;
        } else {
            *v = redact_text(v, &mut n);
        }
    }
    n
}

/// Redact secret-named query and fragment parameters, then well-known credential
/// shapes anywhere in the string. Everything else is left byte-for-byte as is.
pub fn redact_url(url: &str, n: &mut usize) -> String {
    let (head, frag) = match url.split_once('#') {
        Some((h, f)) => (h, Some(f)),
        None => (url, None),
    };
    let (base, query) = match head.split_once('?') {
        Some((b, q)) => (b, Some(q)),
        None => (head, None),
    };
    let mut out = String::with_capacity(url.len());
    out.push_str(base);
    if let Some(q) = query {
        out.push('?');
        out.push_str(&redact_pairs(q, n));
    }
    if let Some(f) = frag {
        out.push('#');
        // OAuth implicit flow puts tokens in the fragment as `k=v&k=v`.
        if f.contains('=') {
            out.push_str(&redact_pairs(f, n));
        } else {
            out.push_str(f);
        }
    }
    redact_text(&out, n)
}

fn redact_pairs(q: &str, n: &mut usize) -> String {
    q.split('&')
        .map(|pair| {
            let Some((k, v)) = pair.split_once('=') else {
                return pair.to_string();
            };
            if v.is_empty() || v.starts_with(MARK) {
                return pair.to_string();
            }
            let name = percent_encoding::percent_decode_str(k).decode_utf8_lossy();
            let decoded = percent_encoding::percent_decode_str(&v.replace('+', " "))
                .decode_utf8_lossy()
                .into_owned();
            if placeholder().is_match(&decoded) {
                pair.to_string()
            } else if secret_param().is_match(&name) || cookie_jar().is_match(&decoded) {
                *n += 1;
                format!("{k}={}", hash_token(&decoded))
            } else {
                pair.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("&")
}

fn redact_text(s: &str, n: &mut usize) -> String {
    let re = secret_value();
    if !re.is_match(s) {
        return s.to_string();
    }
    re.replace_all(s, |c: &regex::Captures| {
        *n += 1;
        hash_token(&c[0])
    })
    .into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn r(u: &str) -> (String, usize) {
        let mut n = 0;
        let s = redact_url(u, &mut n);
        (s, n)
    }

    #[test]
    fn real_values_next_to_placeholder_words_are_still_hashed() {
        for u in [
            "https://api.site.example/v1?api_key=your_key_9f8e7d6c5b4a",
            "https://api.site.example/v1?access_token=abcdef0123456789abcdef",
        ] {
            let (s, n) = r(u);
            assert_eq!(n, 1, "{s}");
            assert!(s.contains("=REDACTED-"), "{s}");
        }
    }

    #[test]
    fn named_params_are_hashed_deterministically() {
        let (a, n) = r("https://x.example/cb?access_token=abc123secret&page=2");
        assert_eq!(n, 1);
        assert!(a.contains("access_token=REDACTED-"));
        assert!(a.ends_with("&page=2"));
        let (b, _) = r("https://y.example/?access_token=abc123secret");
        let tok = |s: &str| s.split("access_token=").nth(1).unwrap()[..21].to_string();
        assert_eq!(tok(&a), tok(&b));
    }

    #[test]
    fn cookie_jars_and_known_shapes() {
        let (a, n) = r("https://hook.example/c?d=sessionid%3Dabc%3B%20csrftoken%3Dxyz");
        assert_eq!(n, 1, "{a}");
        assert!(a.contains("d=REDACTED-"));
        let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.c2lnbmF0dXJlLXZhbHVl"; // secret-scan: fixture (fake signature)
        let (b, n) = r(&format!("https://a.example/x/{jwt}/y"));
        assert_eq!(n, 1);
        assert!(!b.contains("eyJ"));
        let (c, _) = r("https://a.example/#access_token=zzz&state=1");
        assert!(c.contains("#access_token=REDACTED-") && c.ends_with("&state=1"));
    }

    #[test]
    fn payloads_tags_and_links_survive() {
        for u in [
            "https://r.jina.ai/https://site.example/?q=1'%20OR%201=1--&uqtag=run7",
            "https://site.example/?q=<script>alert(document.cookie)</script>",
            "https://site.example/?session=run-42&tok=expt",
            "https://api.site.example/v1?api_key=YOUR_API_KEY",
            "https://api.site.example/v1?token=%3Cyour-token%3E&secret=%7B%7Bsecret%7D%7D",
            "https://api.site.example/v1?access_token=INSERT_TOKEN_HERE&key=$%7BAPI_KEY%7D",
        ] {
            let (s, n) = r(u);
            assert_eq!((s.as_str(), n), (u, 0));
        }
    }

    #[test]
    fn idempotent_and_headers() {
        let mut o = Observation {
            url: "https://a.example/?password=hunter2".into(),
            ..Default::default()
        };
        o.headers.insert("Cookie".into(), "a=b; c=d".into());
        o.headers.insert("Via".into(), "1.1 hysandbox (ATS)".into());
        assert_eq!(redact_observation(&mut o), 2);
        let snapshot = o.clone();
        assert_eq!(redact_observation(&mut o), 0);
        assert_eq!(o, snapshot);
        assert_eq!(o.headers["Via"], "1.1 hysandbox (ATS)");
    }
}
