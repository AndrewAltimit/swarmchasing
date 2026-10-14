//! Redaction at ingest.
//!
//! Collected records can carry secrets the agents captured or used: session
//! cookies, bearer tokens, API keys. They are useless as evidence and harmful to
//! keep, so they are replaced with a short hash before anything is stored or
//! analysed. The hash is deterministic, so two records that carried the same
//! secret still link to each other.
//!
//! Only secret-shaped values are touched. Attack payloads, agent tags and run
//! identifiers stay as they are, because the rules need them. Base64 carried
//! in a URL (a program echoed by httpbin, an encoded parameter) is decoded,
//! and re-encoded from the redacted text only when it held a secret.

use regex::Regex;
use sha2::{Digest, Sha256};
use std::sync::OnceLock;

use crate::model::Observation;

/// Prefix of every replacement value. Redaction skips values that already carry it.
pub const MARK: &str = "REDACTED-";

/// Query/fragment parameter names whose values are always secrets. Matched
/// without case, so `apiKey` and `sessionId` (the credential and session
/// parameters of hosted-browser connect URLs such as
/// `wss://connect.steel.dev?apiKey=...&sessionId=...`) are covered by
/// `api_?key` and `sessionid`.
const SECRET_PARAM: &str = r"(?i)^(cookies?|set-cookie|auth|authorization|access_?token|session_?token|access_?key|refresh_?token|id_?token|auth_?token|api[_-]?key|api[_-]?token|x-api-key|x-bb-api-key|x-browser-use-api-key|x-hyperbrowser-token|x-daytona-preview-token|subscription-key|client_?secret|secret|secret_?key|private_?key|password|passwd|pwd|pass|jwt|bearer|phpsessid|jsessionid|aspsessionid\w*|asp\.net_sessionid|connect\.sid|sessionid|session_id|csrftoken|csrf_token|xsrf-token|_xsrf|sid_guard|sessionid_ss|x5sec|umidtoken|bx-umidtoken|x-amz-signature|x-amz-credential|x-amz-security-token|x-goog-signature|x-goog-credential)$";

/// Generic parameter names (`token`, `key`, an OAuth `code`, a URL
/// signature) whose values are secrets when they look like one: an opaque
/// run of letters and digits ([`opaque`]). Anything else in them, such as an
/// injection probe, stays for the rules.
const OPAQUE_PARAM: &str = r"(?i)^(token|key|code|sig|signature)$";

/// Headers whose values are always secrets. Besides the generic ones, the
/// key and token headers hosted-browser and sandbox services document for
/// their APIs and preview links (Browserbase `X-BB-API-Key`, Browser Use
/// `X-Browser-Use-API-Key`, Hyperbrowser `x-hyperbrowser-token`, Daytona
/// `x-daytona-preview-token`, Modal `Modal-Key` and `Modal-Secret`), and the
/// x402 payment headers (`PAYMENT-SIGNATURE` in version 2, `X-PAYMENT` in
/// version 1), whose value is a signed payment authorization a server could
/// settle. The server's `X-PAYMENT-RESPONSE` / `PAYMENT-RESPONSE` is a
/// settlement receipt that authorizes nothing, so it is kept. The header name
/// survives redaction, so `selfid.agent_commerce` still matches it.
const SECRET_HEADER: &str = r"(?i)^(cookie|set-cookie|authorization|proxy-authorization|x-api-key|x-auth-token|x-csrf-token|x-xsrf-token|x-bb-api-key|x-browser-use-api-key|x-hyperbrowser-token|x-daytona-preview-token|modal-key|modal-secret|payment-signature|x-payment)$";

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

fn opaque_param() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(OPAQUE_PARAM).unwrap())
}

/// `name=value` inside decoded text (a program, a `data:` body).
fn text_pair() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        // A value stops at `?` and `=` (keeping trailing padding), so the
        // pairs of a URL nested in a value are seen on their own.
        Regex::new(r#"\b([A-Za-z][A-Za-z0-9_.-]*)=([^&#\s"'`<>;,(){}\[\]\\?=]+=*)"#).unwrap()
    })
}

/// A value shaped like a token: at least 8 characters of letters, digits and
/// `-_.~+/=`, with both letters and digits, and no `..` (a traversal probe
/// is not a token).
fn opaque(v: &str) -> bool {
    v.len() >= 8
        && !v.contains("..")
        && v.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.~+/=".contains(&b))
        && v.bytes().any(|b| b.is_ascii_alphabetic())
        && v.bytes().any(|b| b.is_ascii_digit())
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
    redact_text(&redact_b64(&out, n), n)
}

/// A run of base64, plain or with `+`, `/` and `=` percent-encoded, long
/// enough to carry a program.
fn b64_run() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"(?:[A-Za-z0-9+/_-]|%2[BbFf]){16,}(?:=|%3[Dd]){0,2}").unwrap())
}

/// Redact secrets inside base64 carried in a URL. Each run is decoded the
/// way the unwrapper decodes it; when the text holds a secret, the run is
/// re-encoded from the redacted text in the same alphabet, padding and
/// percent-encoding, so the stored URL and its decoded layer agree. A run
/// whose text holds no secret is left byte-for-byte as is.
fn redact_b64(url: &str, n: &mut usize) -> String {
    b64_run()
        .replace_all(url, |c: &regex::Captures| {
            redact_run(&c[0], n).unwrap_or_else(|| c[0].to_string())
        })
        .into_owned()
}

/// Base64 decoded strictly, for rewriting: the bytes must be UTF-8 (a
/// sequence cut at the very end is dropped, as scan services cut long URLs)
/// and mostly printable. A misaligned start, such as a path segment before
/// the payload, decodes to invalid UTF-8 and is skipped, so re-encoding never
/// changes anything but the payload.
fn strict_b64(s: &str) -> Option<String> {
    use base64::Engine;
    let mut norm: String = s
        .trim_end_matches('=')
        .chars()
        .map(|c| match c {
            '-' => '+',
            '_' => '/',
            c => c,
        })
        .collect();
    norm.truncate(norm.len() - norm.len() % 4);
    let bytes = base64::engine::general_purpose::STANDARD_NO_PAD
        .decode(&norm)
        .ok()?;
    let text = match std::str::from_utf8(&bytes) {
        Ok(t) => t,
        Err(e) if e.error_len().is_none() => std::str::from_utf8(&bytes[..e.valid_up_to()]).ok()?,
        Err(_) => return None,
    };
    let total = text.chars().count();
    let printable = text
        .chars()
        .filter(|&c| !c.is_control() || c.is_whitespace())
        .count();
    (total >= 12 && printable * 10 >= total * 9 && text.chars().any(|c| c.is_ascii_alphabetic()))
        .then(|| text.to_string())
}

/// Standard base64 can span `/`, so a run is tried from its start and from
/// each segment start after it, as the unwrapper does for paths.
fn redact_run(run: &str, n: &mut usize) -> Option<String> {
    use base64::Engine;
    use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
    let starts = std::iter::once(0).chain(run.match_indices('/').map(|(i, _)| i + 1));
    for start in starts {
        let raw = &run[start..];
        let pct = raw.contains('%');
        let plain = if pct {
            raw.replace("%2B", "+")
                .replace("%2b", "+")
                .replace("%2F", "/")
                .replace("%2f", "/")
                .replace("%3D", "=")
                .replace("%3d", "=")
        } else {
            raw.to_string()
        };
        let Some(text) = strict_b64(&plain) else {
            continue;
        };
        let red = redact_decoded(&text);
        if red == text {
            continue;
        }
        *n += 1;
        let url_safe = plain.contains('-') || plain.contains('_');
        let enc = match (url_safe, plain.ends_with('=')) {
            (false, true) => STANDARD.encode(red.as_bytes()),
            (false, false) => STANDARD_NO_PAD.encode(red.as_bytes()),
            (true, true) => URL_SAFE.encode(red.as_bytes()),
            (true, false) => URL_SAFE_NO_PAD.encode(red.as_bytes()),
        };
        let enc = if pct {
            enc.replace('+', "%2B")
                .replace('/', "%2F")
                .replace('=', "%3D")
        } else {
            enc
        };
        return Some(format!("{}{enc}", &run[..start]));
    }
    None
}

/// Whether the decoded `value` of parameter `name` is a secret. `sas` is set
/// when the same query carries an Azure SAS version (`sv`), whose `sig` is
/// always a signature.
fn secret_pair(name: &str, value: &str, sas: bool) -> bool {
    // One of our canary tokens is public by construction, and hashing it
    // would hide the sighting (crate::canary).
    if value.is_empty()
        || value.starts_with(MARK)
        || placeholder().is_match(value)
        || crate::canary::is_token(value)
    {
        return false;
    }
    secret_param().is_match(name)
        || cookie_jar().is_match(value)
        || (sas && name.eq_ignore_ascii_case("sig"))
        || (opaque_param().is_match(name) && opaque(value))
}

fn decode(s: &str) -> String {
    percent_encoding::percent_decode_str(&s.replace('+', " "))
        .decode_utf8_lossy()
        .into_owned()
}

fn redact_pairs(q: &str, n: &mut usize) -> String {
    let sas = q
        .split('&')
        .any(|p| p.split_once('=').is_some_and(|(k, _)| k == "sv"));
    q.split('&')
        .map(|pair| {
            let Some((k, v)) = pair.split_once('=') else {
                return pair.to_string();
            };
            let name = percent_encoding::percent_decode_str(k).decode_utf8_lossy();
            let decoded = decode(v);
            if secret_pair(&name, &decoded, sas) {
                *n += 1;
                format!("{k}={}", hash_token(&decoded))
            } else if let Some(v) = redact_nested(v, &decoded) {
                *n += 1;
                format!("{k}={v}")
            } else {
                pair.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("&")
}

/// A parameter value that decodes to a URL or a query of its own (a proxy's
/// `?url=https%3A%2F%2F...%3Fkey%3D...`): each secret pair inside is hashed
/// where it stands in the raw value, as `name=value` or `name%3Dvalue`, so
/// nothing else in the value changes. The hash is the one the decoded layer
/// gets, so the stored URL and the layer agree.
fn redact_nested(raw: &str, decoded: &str) -> Option<String> {
    use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
    if !decoded.contains('=') {
        return None;
    }
    let sas = decoded.contains("sv=");
    let mut out = raw.to_string();
    for c in text_pair().captures_iter(decoded) {
        let (name, val) = (&c[1], decode(&c[2]));
        if !secret_pair(name, &val, sas) {
            continue;
        }
        let hash = hash_token(&val);
        let forms = [
            c[2].to_string(),
            val.clone(),
            utf8_percent_encode(&c[2], NON_ALPHANUMERIC).to_string(),
        ];
        for sep in ["=", "%3D", "%3d", "%253D", "%253d"] {
            for form in &forms {
                let from = format!("{name}{sep}{form}");
                if out.contains(&from) {
                    out = out.replace(&from, &format!("{name}{sep}{hash}"));
                }
            }
        }
    }
    (out != raw).then_some(out)
}

/// The value to keep for a decoded query parameter of an unwrapped layer:
/// its hash when it is a secret, else the value itself.
pub fn redact_param(name: &str, value: String, sas: bool) -> String {
    if secret_pair(name, &value, sas) {
        hash_token(&value)
    } else {
        value
    }
}

/// Redact text decoded out of a record: a base64 program, a `data:` body,
/// the percent-decoded text of an inner URL. Secret-named `name=value` pairs
/// anywhere in it and well-known credential shapes are replaced, as at
/// ingest; placeholders stay.
pub fn redact_decoded(text: &str) -> String {
    let mut n = 0;
    let sas = text.contains("sv=");
    let out = text_pair().replace_all(text, |c: &regex::Captures| {
        if secret_pair(&c[1], &decode(&c[2]), sas) {
            format!("{}={}", &c[1], hash_token(&decode(&c[2])))
        } else {
            c[0].to_string()
        }
    });
    redact_text(&out, &mut n)
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
    use base64::Engine;
    use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};

    fn decoded_tail(url: &str, after: &str) -> String {
        let b = url.split_once(after).unwrap().1;
        let b = b.split('&').next().unwrap();
        let b = b
            .replace("%2B", "+")
            .replace("%2F", "/")
            .replace("%3D", "=");
        crate::extract::try_b64(&b).unwrap()
    }

    #[test]
    fn secrets_inside_base64_are_redacted_and_re_encoded() {
        let program = "<script>fetch('https://api.data.example/v1/facts?subscription-key=433468f8d0c4401e9cd359beec6d2bd4&year=2020').then(r=>r.text()).then(t=>document.title=t)</script>";
        // A path payload in the standard alphabet, as httpbin echoes it.
        let url = format!("https://httpbin.org/base64/{}", STANDARD.encode(program));
        let (out, n) = r(&url);
        assert_eq!(n, 1, "{out}");
        assert!(out.starts_with("https://httpbin.org/base64/"), "{out}");
        let text = decoded_tail(&out, "/base64/");
        assert!(!text.contains("433468f8"), "{text}");
        assert!(text.contains("subscription-key=REDACTED-"), "{text}");
        assert!(
            text.contains("&year=2020"),
            "the rest of the program stays: {text}"
        );
        assert_eq!(r(&out), (out.clone(), 0), "idempotent");

        // A percent-encoded parameter value, URL-safe alphabet unpadded.
        let js = "fetch('https://x.example/?q=1&token=ghp_abcdefghijklmnopqrstuvwxyz0123456789')"; // secret-scan: fixture (fake token)
        let v = STANDARD
            .encode(js)
            .replace('+', "%2B")
            .replace('/', "%2F")
            .replace('=', "%3D");
        let (out, n) = r(&format!("https://r.example/run?p={v}&cb=1"));
        assert_eq!(n, 1, "{out}");
        assert!(out.ends_with("&cb=1"), "{out}");
        assert!(!decoded_tail(&out, "p=").contains("ghp_"), "{out}");
        let safe = URL_SAFE_NO_PAD.encode(js);
        let (out, _) = r(&format!("https://e.example/{safe}"));
        let seg = out.rsplit('/').next().unwrap();
        assert!(
            !seg.contains('+') && !seg.contains('/') && !seg.ends_with('='),
            "{seg}"
        );
        assert!(!crate::extract::try_b64(seg).unwrap().contains("ghp_"));
    }

    #[test]
    fn secrets_in_a_percent_encoded_nested_url_are_redacted_in_place() {
        let u = "https://api.codetabs.example/v1/proxy/?quest=https%3A%2F%2Fdata.example%2Fapi%2FFacts%3Fsubscription-key%3D433468f8d0c4401e9cd359beec6d2bd4%26%24select%3DYear";
        let (out, n) = r(u);
        assert_eq!(n, 1, "{out}");
        assert!(!out.contains("433468f8"), "{out}");
        let want = format!(
            "https://api.codetabs.example/v1/proxy/?quest=https%3A%2F%2Fdata.example%2Fapi%2FFacts%3Fsubscription-key%3D{}%26%24select%3DYear",
            hash_token("433468f8d0c4401e9cd359beec6d2bd4")
        );
        assert_eq!(
            out, want,
            "only the value changes, with the decoded layer's hash"
        );
        assert_eq!(r(&out), (out.clone(), 0), "idempotent");
        // A nested URL with nothing secret stays byte-for-byte.
        let plain = "https://api.codetabs.example/v1/proxy/?quest=https%3A%2F%2Fdata.example%2Fp%3Fpage%3D2";
        assert_eq!(r(plain), (plain.to_string(), 0));
    }

    #[test]
    fn base64_without_secrets_is_untouched() {
        let program = "<script>fetch('https://tv.example/api/schedule?day=2026-08-03&key=YOUR_API_KEY').then(r=>r.json())</script>";
        let url = format!("https://httpbin.org/base64/{}", STANDARD.encode(program));
        assert_eq!(r(&url), (url.clone(), 0));
        let ids = "https://cdn.example/assets/a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6/app.js";
        assert_eq!(r(ids), (ids.to_string(), 0));
    }

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
    fn generic_names_signatures_and_cloud_credentials() {
        for u in [
            "https://a.example/v1?token=9f8e7d6c5b4a3f2e1d0c",
            "https://a.example/v1?key=AbCdEf0123456789xyz",
            "https://a.example/v1?api-key=abc",
            "https://a.example/oauth/callback?code=4%2F0AfJohXk9q8w7e6r5t4y&state=xyz",
            "https://a.example/file?signature=b64sig0aB1cD2eF3%3D%3D",
            "https://acct.blob.core.example/c/f?sv=2022-11-02&se=2026-10-05&sig=abc%2Bdef%3D",
            "https://b.s3.example/o?X-Amz-Credential=AKIAEXAMPLE%2F20261004%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Signature=f0e1d2c3b4a5",
            "https://storage.example/o?X-Goog-Signature=0a1b2c3d4e5f",
        ] {
            let (s, n) = r(u);
            assert!(n >= 1, "{u} -> {s}");
            assert!(s.contains("=REDACTED-"), "{s}");
        }
        let (s, n) =
            r("https://b.s3.example/o?X-Amz-Credential=AKIAEXAMPLE%2Fx&X-Amz-Signature=f0e1");
        assert_eq!(n, 2, "{s}");
        // A probe in a generic parameter is not a token: the rules need it.
        for u in [
            "https://a.example/?token=1'%20OR%201=1--",
            "https://a.example/?key=../../../etc/passwd",
            "https://a.example/?code=<script>alert(1)</script>",
            "https://a.example/?sig=short",
            "https://a.example/?code=ABCDEFGHIJ",
            "https://a.example/?key=$%7BAPI_KEY%7D",
        ] {
            let (s, n) = r(u);
            assert_eq!((s.as_str(), n), (u, 0));
        }
    }

    /// Hosted-browser connect URLs carry the account key and the session id
    /// in the query; both are hashed, the host and the other options stay.
    #[test]
    fn remote_browser_connect_urls() {
        for (u, secrets, kept) in [
            (
                "wss://connect.steel.dev?apiKey=ste-9f8e7d6c5b4a3f2e1d0c&sessionId=4c1d2e3f-5a6b-4c7d-8e9f-0a1b2c3d4e5f",
                2,
                "wss://connect.steel.dev?apiKey=REDACTED-",
            ),
            (
                "wss://connect.browser-use.com?apiKey=bu_9f8e7d6c5b4a3f2e&proxyCountryCode=us",
                1,
                "&proxyCountryCode=us",
            ),
            (
                "wss://connect.browserbase.com?api_key=bb_9f8e7d6c5b4a3f2e1d0c&session_id=a1b2c3d4&enableProxy=true",
                2,
                "&enableProxy=true",
            ),
            (
                "wss://connect.hyperbrowser.ai?token=9f8e7d6c5b4a3f2e1d0c",
                1,
                "wss://connect.hyperbrowser.ai?token=REDACTED-",
            ),
            (
                "https://api.example/v1?api_token=abc123def456&x-bb-api-key=bbkey987654",
                2,
                "https://api.example/v1?api_token=REDACTED-",
            ),
        ] {
            let (s, n) = r(u);
            assert_eq!(n, secrets, "{u} -> {s}");
            assert!(s.contains(kept), "{s}");
            assert_eq!(r(&s), (s.clone(), 0), "idempotent");
        }
        // The same key in a program that connects to the browser.
        let prog = "const b = await puppeteer.connect({browserWSEndpoint: 'wss://connect.steel.dev?apiKey=ste-9f8e7d6c5b4a3f2e1d0c&sessionId=s1x2y3z4'})";
        let out = redact_decoded(prog);
        assert!(
            !out.contains("ste-9f8e7d6c") && !out.contains("s1x2y3z4"),
            "{out}"
        );
        assert!(
            out.contains("wss://connect.steel.dev?apiKey=REDACTED-"),
            "{out}"
        );
        // Service key headers.
        let mut o = Observation {
            url: "https://a.example/".into(),
            ..Default::default()
        };
        for h in [
            "X-BB-API-Key",
            "X-Browser-Use-API-Key",
            "x-hyperbrowser-token",
            "x-daytona-preview-token",
            "Modal-Key",
            "Modal-Secret",
        ] {
            o.headers.insert(h.into(), "s3cr3t-value-1".into());
        }
        assert_eq!(redact_observation(&mut o), 6);
        assert!(o.headers.values().all(|v| v.starts_with(MARK)));
    }

    #[test]
    fn decoded_text_is_redacted_but_placeholders_stay() {
        let key = "sk-ant-abcdefghijklmnopqrstuvwxyz012345"; // secret-scan: fixture (fake key)
        let prog = format!(
            "fetch('https://api.example/v1?access_token=s3cr3tvalue&q=1', {{headers: {{'x-api-key': '{key}'}}}}); fetch('https://b.example/?api_key=YOUR_API_KEY')"
        );
        let out = redact_decoded(&prog);
        assert!(!out.contains("s3cr3tvalue") && !out.contains(key), "{out}");
        assert!(
            out.contains("access_token=REDACTED-") && out.contains("&q=1"),
            "{out}"
        );
        assert!(out.contains("api_key=YOUR_API_KEY"), "{out}");
        assert_eq!(redact_decoded(&out), out, "idempotent");
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

    #[test]
    fn x402_payment_headers_are_hashed_and_still_match() {
        let mut o = Observation {
            url: "https://api.data.example/v1/quotes".into(),
            ..Default::default()
        };
        o.headers.insert(
            "PAYMENT-SIGNATURE".into(),
            "eyJ4NDAyVmVyc2lvbiI6Mn0=".into(),
        );
        o.headers
            .insert("X-PAYMENT".into(), "eyJ4NDAyVmVyc2lvbiI6MX0=".into());
        o.headers.insert(
            "X-PAYMENT-RESPONSE".into(),
            "eyJzdWNjZXNzIjp0cnVlfQ==".into(),
        );
        assert_eq!(redact_observation(&mut o), 2);
        assert!(o.headers["PAYMENT-SIGNATURE"].starts_with(MARK));
        assert!(o.headers["X-PAYMENT"].starts_with(MARK));
        assert_eq!(o.headers["X-PAYMENT-RESPONSE"], "eyJzdWNjZXNzIjp0cnVlfQ==");
        // The rule reads the header name, so it fires on the redacted record.
        let rules = crate::rules::Rules::default_rules();
        let x = crate::extract::extract(&o, &rules);
        assert!(
            x.hits.iter().any(|h| h.rule_id == "selfid.agent_commerce"),
            "{:?}",
            x.hits
        );
    }
}
