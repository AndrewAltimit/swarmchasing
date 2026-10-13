//! Canary tokens on the project's own published material, and finding
//! copies of them in records: leak detection for our own text.
//!
//! When the site build turns them on (they are off by default), each page
//! and agent-facing file carries a reference token, distinct per surface
//! (the file's path under the site root) and per period (a calendar month,
//! UTC). A token is derived from a secret seed that is never committed:
//!
//! ```text
//! swc-<YYMM>-<12 base32 chars of HMAC-SHA256(seed, "sc-canary-v1\n" surface "\n" YYMM)>
//! ```
//!
//! The period is in clear; the surface is not, and neither the seed nor
//! another surface's or month's token can be worked out from tokens already
//! published. So a token seen in a public record was copied from our site no
//! earlier than its period began: a reader cannot backdate it.
//!
//! What a sighting shows is limited. Anyone can copy a token from the page,
//! so it says that our text from that surface was copied and repeated,
//! never who copied it. A token-shaped value is therefore never a linking feature
//! (see [`crate::plant`]): it is treated like `linking.published_tags`,
//! so planting one cannot merge clusters. Redaction leaves it in place
//! ([`crate::redact`]), because it is public by construction.
//!
//! No I/O: the seed and the registry of issued tokens are the caller's.

use crate::extract::unwrap_layers;
use crate::model::{Observation, TsKind};
use chrono::{DateTime, Datelike, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

/// The prefix every token starts with.
pub const PREFIX: &str = "swc-";

/// Domain separation for the MAC, versioned so a later scheme cannot
/// collide with this one.
const CONTEXT: &str = "sc-canary-v1";

/// Characters of MAC in a token (60 bits).
const MAC_CHARS: usize = 12;

/// Shortest seed accepted, in bytes.
pub const MIN_SEED: usize = 16;

/// What the site build writes where a surface's token goes. A line
/// carrying it is replaced with the token, or dropped when the build has no
/// seed.
pub const PLACEHOLDER: &str = "@@sc-canary@@";

const B32: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut k = [0u8; 64];
    if key.len() > 64 {
        k[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut inner = Sha256::new();
    inner.update(k.map(|b| b ^ 0x36));
    inner.update(msg);
    let mut outer = Sha256::new();
    outer.update(k.map(|b| b ^ 0x5c));
    outer.update(inner.finalize());
    outer.finalize().into()
}

/// Check a seed: at least [`MIN_SEED`] bytes after trimming.
pub fn check_seed(seed: &str) -> Result<&[u8], String> {
    let s = seed.trim();
    if s.len() < MIN_SEED {
        return Err(format!(
            "the canary seed is {} bytes; use at least {MIN_SEED} (e.g. 32 random bytes as hex)",
            s.len()
        ));
    }
    Ok(s.as_bytes())
}

/// The token for `surface` (a path under the site root, such as
/// `llms.txt` or `docs/index.html`) in `period` (`YYMM`).
pub fn derive(seed: &[u8], surface: &str, period: &str) -> String {
    let mac = hmac_sha256(seed, format!("{CONTEXT}\n{surface}\n{period}").as_bytes());
    // The first 60 bits, five at a time.
    let mut bits: u64 = 0;
    for b in &mac[..8] {
        bits = (bits << 8) | u64::from(*b);
    }
    let mut out = String::with_capacity(PREFIX.len() + 5 + MAC_CHARS);
    out.push_str(PREFIX);
    out.push_str(period);
    out.push('-');
    for i in 0..MAC_CHARS {
        let shift = 64 - 5 * (i + 1);
        out.push(B32[((bits >> shift) & 31) as usize] as char);
    }
    out
}

/// The period (`YYMM`, UTC) a Unix time falls in.
pub fn period_of(ts: i64) -> String {
    DateTime::<Utc>::from_timestamp(ts, 0)
        .map(|d| format!("{:02}{:02}", d.year() % 100, d.month()))
        .unwrap_or_else(|| "0001".into())
}

/// The first and last second of a period, or `None` when it is not `YYMM`.
pub fn period_bounds(period: &str) -> Option<(i64, i64)> {
    if period.len() != 4 || !period.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let y = 2000 + period[..2].parse::<i32>().ok()?;
    let m = period[2..].parse::<u32>().ok()?;
    let start = NaiveDate::from_ymd_opt(y, m, 1)?;
    let next = if m == 12 {
        NaiveDate::from_ymd_opt(y + 1, 1, 1)?
    } else {
        NaiveDate::from_ymd_opt(y, m + 1, 1)?
    };
    let ts = |d: NaiveDate| d.and_hms_opt(0, 0, 0).map(|t| t.and_utc().timestamp());
    Some((ts(start)?, ts(next)? - 1))
}

/// Whether `s` is exactly one token (any case).
pub fn is_token(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == PREFIX.len() + 5 + MAC_CHARS && token_at(b, 0)
}

fn token_at(b: &[u8], i: usize) -> bool {
    let n = PREFIX.len() + 5 + MAC_CHARS;
    if b.len() < i + n || !b[i..i + PREFIX.len()].eq_ignore_ascii_case(PREFIX.as_bytes()) {
        return false;
    }
    let p = i + PREFIX.len();
    b[p..p + 4].iter().all(u8::is_ascii_digit)
        && b[p + 4] == b'-'
        && b[p + 5..p + 5 + MAC_CHARS]
            .iter()
            .all(|c| B32.contains(&c.to_ascii_lowercase()))
}

/// Every token-shaped value in `text`, lowercased, in order, each once. A
/// token must not run on into more letters or digits.
pub fn find_tokens(text: &str) -> Vec<String> {
    let b = text.as_bytes();
    let n = PREFIX.len() + 5 + MAC_CHARS;
    let mut out = Vec::new();
    let mut seen = BTreeSet::new();
    let mut i = 0;
    while i + n <= b.len() {
        let before_ok = i == 0 || !b[i - 1].is_ascii_alphanumeric();
        let after_ok = b.get(i + n).is_none_or(|c| !c.is_ascii_alphanumeric());
        if before_ok && after_ok && token_at(b, i) {
            let t = text[i..i + n].to_ascii_lowercase();
            if seen.insert(t.clone()) {
                out.push(t);
            }
            i += n;
        } else {
            i += 1;
        }
    }
    out
}

/// Whether `text` carries a token-shaped value anywhere.
pub fn contains_token(text: &str) -> bool {
    !find_tokens(text).is_empty()
}

/// One issued token: the surface it was on, its period, and when it was
/// first registered as published.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Issued {
    pub token: String,
    /// Path under the site root (`llms.txt`, `notices/index.html`).
    pub surface: String,
    /// `YYMM`.
    pub period: String,
    /// Unix seconds when a built site carrying it was first registered.
    pub registered: i64,
}

/// The tokens issued so far, kept under the data directory (never in git).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Registry {
    #[serde(default)]
    pub issued: Vec<Issued>,
}

impl Registry {
    /// Record a token; keeps the earliest registration. Returns whether it
    /// was new.
    pub fn add(&mut self, token: &str, surface: &str, period: &str, at: i64) -> bool {
        let token = token.to_ascii_lowercase();
        if let Some(e) = self.issued.iter_mut().find(|e| e.token == token) {
            if at > 0 && (e.registered <= 0 || at < e.registered) {
                e.registered = at;
            }
            return false;
        }
        self.issued.push(Issued {
            token,
            surface: surface.to_string(),
            period: period.to_string(),
            registered: at,
        });
        self.issued
            .sort_by(|a, b| (&a.period, &a.surface).cmp(&(&b.period, &b.surface)));
        true
    }

    pub fn get(&self, token: &str) -> Option<&Issued> {
        let t = token.to_ascii_lowercase();
        self.issued.iter().find(|e| e.token == t)
    }

    /// Every token found in these records, registered or not.
    pub fn sightings(&self, records: &[Observation]) -> Vec<Sighting> {
        let by_token: BTreeMap<&str, &Issued> =
            self.issued.iter().map(|e| (e.token.as_str(), e)).collect();
        let mut out = Vec::new();
        for o in records {
            for (field, token) in tokens_in(o) {
                let issued = by_token.get(token.as_str()).copied();
                let period = token[PREFIX.len()..PREFIX.len() + 4].to_string();
                let not_before = period_bounds(&period).map_or(0, |(s, _)| s);
                out.push(Sighting {
                    record: o.id.clone(),
                    source: o.source.clone(),
                    ts: o.ts,
                    ts_kind: o.ts_kind,
                    reference: o.reference.clone(),
                    field,
                    surface: issued.map(|e| e.surface.clone()),
                    registered: issued.map(|e| e.registered),
                    before_issue: o.ts > 0 && o.ts < not_before,
                    token,
                    period,
                    not_before,
                });
            }
        }
        out
    }
}

/// (field, token) for every token in a record: the URL and each layer
/// unwrapped from it, the final URL, the user agent and the header values.
fn tokens_in(o: &Observation) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    let mut push = |field: String, text: &str| {
        for t in find_tokens(text) {
            if !out.iter().any(|(_, x)| *x == t) {
                out.push((field.clone(), t));
            }
        }
    };
    push("url".into(), &o.url);
    let mut decoded = o.url.clone();
    for _ in 0..2 {
        decoded = percent_encoding::percent_decode_str(&decoded)
            .decode_utf8_lossy()
            .into_owned();
    }
    push("url:decoded".into(), &decoded);
    // Encoded layers (percent-encoding, base64, a nested URL) can hide a
    // token from the plain scan.
    for l in unwrap_layers(&o.url).into_iter().skip(1) {
        push(format!("url:{}", l.via), &l.text);
    }
    if let Some(f) = &o.final_url {
        push("final_url".into(), f);
    }
    if let Some(ua) = &o.user_agent {
        push("user_agent".into(), ua);
    }
    for (k, v) in &o.headers {
        push(format!("header:{k}"), v);
    }
    out
}

/// One of our tokens seen in a record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Sighting {
    pub record: String,
    pub source: String,
    pub ts: i64,
    pub ts_kind: TsKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reference: Option<String>,
    /// Where in the record: `url`, `url:<layer>`, `final_url`,
    /// `user_agent`, `header:<name>`.
    pub field: String,
    pub token: String,
    pub period: String,
    /// The surface it was issued on; `None` when the registry does not hold
    /// it (an older seed, another site's token of the same shape, or a
    /// made-up value).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub surface: Option<String>,
    /// When a site carrying it was first registered.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registered: Option<i64>,
    /// The start of its period: no copy of it can predate this.
    pub not_before: i64,
    /// The record is dated before its period began: the seed has leaked,
    /// the token was made up to match, or the record's time is wrong.
    pub before_issue: bool,
}

impl Sighting {
    /// One line for a digest or the terminal. Names no host: the record is
    /// cited by id and its public reference.
    pub fn line(&self) -> String {
        let surface = self.surface.as_deref().map_or_else(
            || "not in the registry (unverified)".to_string(),
            |s| format!("surface `{s}`"),
        );
        let mut s = format!(
            "`{}` in `{}` of record `{}` ({}, {}): {surface}, period {}, not before {}",
            self.token,
            self.field,
            self.record,
            self.source,
            crate::model::fmt_ts(self.ts),
            self.period,
            crate::model::fmt_ts(self.not_before),
        );
        if self.before_issue {
            s.push_str("; DATED BEFORE ITS PERIOD: check the seed and the record's time");
        }
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEED: &[u8] = b"0123456789abcdef0123456789abcdef";

    #[test]
    fn hmac_matches_rfc_4231_case_2() {
        let mac = hmac_sha256(b"Jefe", b"what do ya want for nothing?");
        let hex: String = mac.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            hex,
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    #[test]
    fn tokens_differ_by_surface_period_and_seed() {
        let a = derive(SEED, "llms.txt", "2610");
        assert!(is_token(&a) && a.starts_with("swc-2610-"));
        assert_eq!(a, derive(SEED, "llms.txt", "2610"));
        assert_ne!(a, derive(SEED, "index.html", "2610"));
        assert_ne!(a, derive(SEED, "llms.txt", "2611"));
        assert_ne!(
            a,
            derive(b"another seed of enough length", "llms.txt", "2610")
        );
        assert!(check_seed("short").is_err());
    }

    #[test]
    fn periods_and_bounds() {
        // 2026-10-12 00:00:00 UTC.
        assert_eq!(period_of(1_791_763_200), "2610");
        let (s, e) = period_bounds("2610").unwrap();
        assert_eq!(fmt_ts(s), "2026-10-01 00:00:00 UTC");
        assert_eq!(fmt_ts(e), "2026-10-31 23:59:59 UTC");
        assert_eq!(
            fmt_ts(period_bounds("2612").unwrap().1),
            "2026-12-31 23:59:59 UTC"
        );
        assert!(period_bounds("2613").is_none() && period_bounds("26x0").is_none());
    }

    use crate::model::fmt_ts;

    #[test]
    fn finds_tokens_on_boundaries_only() {
        let t = derive(SEED, "llms.txt", "2610");
        let upper = t.to_ascii_uppercase();
        let text = format!("ref={upper}&x=1 and x{t} and {t}9 and ({t})");
        assert_eq!(find_tokens(&text), vec![t.clone()]);
        assert!(!contains_token("swc-2610-short"));
    }

    #[test]
    fn sightings_name_the_surface_and_flag_backdating() {
        let t = derive(SEED, "docs/index.html", "2610");
        let mut reg = Registry::default();
        assert!(reg.add(&t, "docs/index.html", "2610", 1_791_000_000));
        assert!(!reg.add(&t, "docs/index.html", "2610", 1_790_000_000));
        assert_eq!(reg.get(&t).unwrap().registered, 1_790_000_000);
        let stray = derive(SEED, "unknown", "2610");
        let enc: String = t.bytes().map(|b| format!("%{b:02X}")).collect();
        let recs = vec![
            Observation {
                id: "r1".into(),
                source: "wayback".into(),
                ts: 1_791_800_000,
                url: format!("https://a.example/submit?ref={t}"),
                ..Default::default()
            },
            Observation {
                id: "r2".into(),
                source: "urlscan".into(),
                ts: 1_700_000_000,
                url: format!("https://b.example/?q={enc}"),
                user_agent: Some(format!("bot {stray}")),
                ..Default::default()
            },
        ];
        let s = reg.sightings(&recs);
        assert_eq!(s.len(), 3, "{s:?}");
        assert_eq!(s[0].surface.as_deref(), Some("docs/index.html"));
        assert!(!s[0].before_issue);
        assert!(s[1].field == "url:decoded" && s[1].before_issue);
        assert!(s[2].surface.is_none() && s[2].field == "user_agent");
        assert!(!s[0].line().contains("a.example"));
    }

    #[test]
    fn a_token_never_links_and_survives_redaction() {
        let t = derive(SEED, "llms.txt", "2610");
        let obs: Vec<Observation> = (0..4)
            .map(|i| Observation {
                id: format!("r{i}"),
                ts: 1_791_000_000 + i * 600,
                url: format!("https://site{i}.example/x?run={t}&token={t}&q=%27%20OR%201=1--"),
                ..Default::default()
            })
            .collect();
        let redacted = crate::redact::redact_url(&obs[0].url, &mut 0);
        assert_eq!(find_tokens(&redacted), vec![t.clone()], "{redacted}");
        let a = crate::analyze(obs, &crate::Rules::default_rules());
        assert!(
            a.clusters.iter().all(|c| c.members.len() == 1),
            "{:?}",
            a.clusters
        );
        let c = a
            .common_features
            .iter()
            .find(|c| c.feature.value() == t)
            .expect("the token is listed as a common feature");
        assert!(c.published && c.reason.contains("canary"), "{}", c.reason);
    }
}
