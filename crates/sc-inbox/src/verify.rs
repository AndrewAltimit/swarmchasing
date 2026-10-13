//! Checking a public-record reference against what a lookup found.
//!
//! The lookup itself is I/O and lives in the CLI, through the collectors:
//! the record is found by its id in the source's index or API, never by
//! opening the URL it names or a capture of it. This module decides, from
//! what came back, whether the record exists, matches what the submission
//! says, and predates the submission.

use crate::evidence::{record_id, same_url};
use crate::spec::PublicRecord;
use sc_core::Observation;
use serde::{Deserialize, Serialize};

/// What a lookup showed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    /// Found, matching, and dated before the submission arrived.
    Verified,
    /// The source has no such record.
    NotFound,
    /// Found, but its URL or time is not what the submission says.
    Mismatch,
    /// Found, but dated after the submission arrived: the submission could
    /// not have seen it.
    Postdates,
    /// The lookup failed (network, quota); try again later.
    Error,
    /// Not looked up: the source needs a key that is not set, or has no
    /// lookup by id.
    Skipped,
}

impl Status {
    pub fn label(self) -> &'static str {
        match self {
            Self::Verified => "verified",
            Self::NotFound => "not found",
            Self::Mismatch => "mismatch",
            Self::Postdates => "postdates the submission",
            Self::Error => "lookup failed",
            Self::Skipped => "skipped",
        }
    }
}

/// The result of checking one evidence item.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Verification {
    /// The evidence item's index.
    pub item: usize,
    pub status: Status,
    /// Unix seconds the lookup ran.
    pub checked: i64,
    /// The record's own time in its source, when found.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub record_ts: Option<i64>,
    /// Seconds from the record's time to the submission's receipt.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lead_secs: Option<i64>,
    /// The lead is at least the predating lead in the triage settings.
    #[serde(default)]
    pub predates: bool,
    /// The found record's id, kept in the submission's `records.ndjson`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub record: Option<String>,
    pub detail: String,
}

/// Check reference `r` (item `item`) against `found`, the records a lookup
/// returned for it, for a submission received at `received`. `tolerance` is
/// how far a claimed time may be from the record's, and `predate_secs` the
/// lead that makes a record predate the submission.
pub fn check(
    item: usize,
    r: &PublicRecord,
    found: &[Observation],
    received: i64,
    checked: i64,
    tolerance: i64,
    predate_secs: i64,
) -> Verification {
    let mut v = Verification {
        item,
        status: Status::NotFound,
        checked,
        record_ts: None,
        lead_secs: None,
        predates: false,
        record: None,
        detail: String::new(),
    };
    let want_id = record_id(r);
    // The record the reference names: by id where it fixes one, else the
    // capture nearest the claimed time.
    let hit = match &want_id {
        Some(id) => found.iter().find(|o| o.id.eq_ignore_ascii_case(id)),
        None => {
            let t = r.ts().unwrap_or(0);
            found
                .iter()
                .filter(|o| r.url.as_deref().is_some_and(|u| same_url(u, &o.url)))
                .min_by_key(|o| (o.ts - t).abs())
        }
    };
    let Some(o) = hit else {
        v.detail = match &want_id {
            Some(id) => format!("{} has no record {id}", r.source.name()),
            None => format!(
                "{} has no capture of the URL near the claimed time",
                r.source.name()
            ),
        };
        return v;
    };
    v.record = Some(o.id.clone());
    v.record_ts = (o.ts > 0).then_some(o.ts);
    let mut problems = Vec::new();
    if let Some(u) = &r.url
        && !same_url(u, &o.url)
    {
        problems.push("its URL differs from the one submitted".to_string());
    }
    if let (Some(t), true) = (r.ts(), o.ts > 0)
        && (t - o.ts).abs() > tolerance
    {
        problems.push(format!(
            "its time is {} s from the one submitted",
            (t - o.ts).abs()
        ));
    }
    if !problems.is_empty() {
        v.status = Status::Mismatch;
        v.detail = problems.join("; ");
        return v;
    }
    if o.ts <= 0 {
        v.status = Status::Mismatch;
        v.detail =
            "the record carries no time, so it cannot be shown to predate the submission".into();
        return v;
    }
    let lead = received - o.ts;
    v.lead_secs = Some(lead);
    if lead < 0 {
        v.status = Status::Postdates;
        v.detail = format!("the record is {} s newer than the submission", -lead);
        return v;
    }
    v.status = Status::Verified;
    v.predates = lead >= predate_secs;
    v.detail = format!("found, {} before the submission", span(lead));
    v
}

/// A duration in its largest whole unit: `41 days`, `3 hours`, `12 minutes`.
pub fn span(secs: i64) -> String {
    let s = secs.abs();
    let (n, unit) = if s >= 86_400 {
        (s / 86_400, "day")
    } else if s >= 3_600 {
        (s / 3_600, "hour")
    } else if s >= 60 {
        (s / 60, "minute")
    } else {
        (s, "second")
    };
    format!("{n} {unit}{}", if n == 1 { "" } else { "s" })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spec::RecordSource;

    fn wayback(ts: &str, url: &str) -> PublicRecord {
        PublicRecord {
            source: RecordSource::Wayback,
            id: None,
            url: Some(url.into()),
            timestamp: Some(ts.into()),
            crawl: None,
            package: None,
            version: None,
            domain: None,
            note: None,
        }
    }

    fn capture(ts: &str, url: &str) -> Observation {
        Observation {
            id: format!("wayback:{ts}:D:H"),
            source: "wayback".into(),
            ts: sc_core::parse_ts(ts).unwrap(),
            url: url.into(),
            ..Default::default()
        }
    }

    #[test]
    fn statuses() {
        let recv = sc_core::parse_ts("2026-10-10T00:00:00Z").unwrap();
        let r = wayback("20260901000000", "https://a.example/x");
        let ok = check(
            0,
            &r,
            &[capture("20260901000000", "https://a.example/x")],
            recv,
            recv,
            120,
            172_800,
        );
        assert_eq!(ok.status, Status::Verified);
        assert!(ok.predates);
        assert_eq!(
            check(0, &r, &[], recv, recv, 120, 0).status,
            Status::NotFound
        );
        let other = check(
            0,
            &r,
            &[capture("20260905000000", "https://a.example/x")],
            recv,
            recv,
            120,
            0,
        );
        assert_eq!(other.status, Status::Mismatch);
        let late = wayback("20261011000000", "https://a.example/x");
        let v = check(
            0,
            &late,
            &[capture("20261011000000", "https://a.example/x")],
            recv,
            recv,
            120,
            0,
        );
        assert_eq!(v.status, Status::Postdates);
        let fresh = wayback("20261009235000", "https://a.example/x");
        let v = check(
            0,
            &fresh,
            &[capture("20261009235000", "https://a.example/x")],
            recv,
            recv,
            120,
            172_800,
        );
        assert_eq!(v.status, Status::Verified);
        assert!(!v.predates);
    }
}
