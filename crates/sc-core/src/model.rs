//! Core data model shared by every tool in the workspace.

use chrono::{DateTime, NaiveDate, NaiveDateTime, Utc};
use serde::{Deserialize, Deserializer, Serialize};
use std::collections::BTreeMap;

/// One publicly recorded request/scan/capture. Everything we analyse is
/// normalised into this shape regardless of where it was collected.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Observation {
    /// Source-specific identifier (scan UUID, CDX timestamp+digest, ...).
    #[serde(default)]
    pub id: String,
    /// Where the record came from: `urlquery`, `wayback`, `arquivo`, `manual`, ...
    #[serde(default)]
    pub source: String,
    /// Unix seconds, UTC. `0` means unknown.
    #[serde(default, deserialize_with = "de_ts")]
    pub ts: i64,
    /// The URL that was requested / submitted.
    pub url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asn: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_agent: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub headers: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    /// Where the page ended up (e.g. `about:neterror`, a Cloudflare challenge).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub final_url: Option<String>,
    /// Link to the public record this observation was taken from.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reference: Option<String>,
}

/// `Observation::source` of logs an affected operator sent us, as
/// `operator:<evidence id>`. They are case evidence, not public records.
pub const OPERATOR_SOURCE: &str = "operator";

impl Observation {
    pub fn operator_supplied(&self) -> bool {
        self.source
            .split(':')
            .next()
            .is_some_and(|s| s == OPERATOR_SOURCE)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IndicatorKind {
    /// Fetch-through / conversion relays (r.jina.ai, allorigins, translate.goog, ...).
    Relay,
    /// Echo or code-hosting services used to carry requests (httpbin, LiveCodes, ...).
    Carrier,
    /// Attack payloads: SQLi, traversal, XSS, command/template injection.
    Exploit,
    /// Tags agents put in URLs (`uqtag=`, `CHATGPTTEST1`, `tok=expt`).
    AgentMarker,
    /// Cache-busting parameters.
    CacheBuster,
    /// Strings where the agent names its model or developer. Weak evidence.
    SelfId,
    /// Disposable inboxes, notification topics, paste bins used for exfil/callbacks.
    Exfil,
    /// Header-level fingerprints (proxy `Via`, normalised `Accept-Encoding`).
    Header,
    /// Outcome states (`about:neterror`, bot challenges).
    Outcome,
    /// Anti-bot token generation / bypass.
    AntiBot,
    /// Hosting infrastructure (ASN, sandbox hostnames).
    Infra,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, Default,
)]
#[serde(rename_all = "snake_case")]
pub enum Tier {
    #[default]
    Noise,
    Suggestive,
    Significant,
}

impl Tier {
    pub fn label(self) -> &'static str {
        match self {
            Tier::Noise => "noise",
            Tier::Suggestive => "suggestive",
            Tier::Significant => "significant",
        }
    }
}

/// A rule that matched an observation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Hit {
    pub rule_id: String,
    pub kind: IndicatorKind,
    pub weight: i32,
    /// The text that matched (truncated).
    pub matched: String,
    /// 0 = the submitted URL; higher = an unwrapped inner layer.
    pub layer: usize,
}

/// Accepts unix seconds (int/float, seconds or millis), RFC 3339, `YYYY-MM-DD HH:MM:SS`,
/// or 14-digit CDX timestamps.
pub fn parse_ts(s: &str) -> Option<i64> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    // CDX timestamps and their prefixes (yyyy, yyyyMM, yyyyMMdd, yyyyMMddhhmm,
    // yyyyMMddhhmmss). Ten digits stays epoch seconds: that is what it always is in practice.
    if matches!(s.len(), 4 | 6 | 8 | 12 | 14) && s.bytes().all(|b| b.is_ascii_digit()) {
        let padded = format!("{s}{}", &"0101000000"[s.len() - 4..]);
        return NaiveDateTime::parse_from_str(&padded, "%Y%m%d%H%M%S")
            .ok()
            .map(|d| d.and_utc().timestamp());
    }
    if let Ok(n) = s.parse::<f64>() {
        return Some(normalise_epoch(n));
    }
    if let Ok(d) = DateTime::parse_from_rfc3339(s) {
        return Some(d.timestamp());
    }
    for fmt in [
        "%Y-%m-%d %H:%M:%S%.f",
        "%Y-%m-%dT%H:%M:%S%.f",
        "%Y-%m-%d %H:%M",
        "%Y/%m/%d %H:%M:%S",
    ] {
        if let Ok(d) = NaiveDateTime::parse_from_str(s, fmt) {
            return Some(d.and_utc().timestamp());
        }
    }
    NaiveDate::parse_from_str(s, "%Y-%m-%d")
        .ok()
        .and_then(|d| d.and_hms_opt(0, 0, 0))
        .map(|d| d.and_utc().timestamp())
}

fn normalise_epoch(n: f64) -> i64 {
    // Anything past year ~5000 in seconds is almost certainly milliseconds.
    if n > 1e11 {
        (n / 1000.0) as i64
    } else {
        n as i64
    }
}

pub fn fmt_ts(ts: i64) -> String {
    if ts <= 0 {
        return "unknown".into();
    }
    DateTime::<Utc>::from_timestamp(ts, 0)
        .map(|d| d.format("%Y-%m-%d %H:%M:%S UTC").to_string())
        .unwrap_or_else(|| ts.to_string())
}

fn de_ts<'de, D: Deserializer<'de>>(d: D) -> Result<i64, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Raw {
        I(i64),
        F(f64),
        S(String),
        N(()),
    }
    Ok(match Raw::deserialize(d)? {
        Raw::I(i) => normalise_epoch(i as f64),
        Raw::F(f) => normalise_epoch(f),
        Raw::S(s) => parse_ts(&s).unwrap_or(0),
        Raw::N(()) => 0,
    })
}

pub(crate) fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let mut t: String = s.chars().take(max).collect();
        t.push('…');
        t
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamps() {
        assert_eq!(parse_ts("20261004081000"), Some(1791101400));
        assert_eq!(parse_ts("2026-10-04T08:10:00Z"), Some(1791101400));
        assert_eq!(parse_ts("2026-10-04 08:10:00"), Some(1791101400));
        assert_eq!(parse_ts("1791101400000"), Some(1791101400));
        assert_eq!(parse_ts("1791101400"), Some(1791101400));
        assert_eq!(parse_ts("202610040810"), Some(1791101400));
        assert_eq!(parse_ts("20261004"), Some(1791072000));
        assert_eq!(parse_ts("202610"), parse_ts("2026-10-01"));
        assert_eq!(parse_ts("2026"), parse_ts("2026-01-01"));
        assert_eq!(parse_ts("nope"), None);
    }
}
