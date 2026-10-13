//! Evidence items: what each can be checked against, how hard it would be
//! to fabricate, and the records it becomes for the analysis.
//!
//! The question for every item is what it would have cost the submitter to
//! make it up. A bare assertion costs nothing. Log lines the submitter holds
//! cost little and nobody else can check them. A record a scan service or an
//! archive took minutes before the report costs one submission to plant. A
//! record in an independent log (an archive capture, a scan-service submit
//! time, a GH Archive event, a CT entry, a registry release) dated well
//! before the report was sent cannot be backdated: whoever made it had to
//! plan the report that far ahead. A request signature or a sensor's or
//! service's signed export, once the admin has checked the signature and
//! that the signer is not the submitter, binds the content to a key the
//! submitter does not hold. Strongest of all is a record the watch already
//! held, found by the watch's own collection before the submission arrived.

use crate::spec::{Evidence, IndicatorKind, LogFormat, PublicRecord, RecordSource};
use crate::verify::{Status, Verification};
use sc_core::{FieldMap, Format, Observation, TsKind, parse_input, redact_observation};
use serde::{Deserialize, Serialize};

/// The source name submitted records carry. Their provenance is
/// `reported`: never an operator's logs, never any public source's records,
/// and never a kind of source for a cluster's corroboration.
pub use sc_core::SUBMISSION_SOURCE;

/// An evidence item's class, strongest first (the derived order is
/// strongest first too).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceClass {
    /// The watch held the record, or a record carrying the indicator, when
    /// the submission arrived: found independently.
    Corroborated,
    /// A request signature (RFC 9421) or a sensor's or service's signed
    /// export whose signature the admin checked, by a signer other than the
    /// submitter (`inbox signature`).
    SignedChecked,
    /// Found by id in an independent public log, matching what the
    /// submission says, and older than the submission by at least the
    /// predating lead: the submitter could not have backdated it.
    VerifiedPredating,
    /// Found and matching, but newer than the lead: anyone could have
    /// submitted or published it just before reporting.
    VerifiedRecent,
    /// A signed artifact whose signature nobody has checked yet. The tool
    /// does not check signatures; the admin does.
    Signed,
    /// A public-record reference not checked yet, or whose lookup failed.
    Unverified,
    /// Log lines only the submitter holds.
    OperatorOnly,
    /// A bare value or statement.
    Assertion,
    /// Checked and not as stated: missing, different, or newer than the
    /// submission itself.
    Contradicted,
}

impl EvidenceClass {
    pub fn label(self) -> &'static str {
        match self {
            Self::Corroborated => "corroborated by the watch",
            Self::SignedChecked => "signed, signature checked",
            Self::VerifiedPredating => "verified, predates the submission",
            Self::VerifiedRecent => "verified, recent (plantable)",
            Self::Signed => "signed (unchecked)",
            Self::Unverified => "not verified yet",
            Self::OperatorOnly => "operator-only logs",
            Self::Assertion => "assertion",
            Self::Contradicted => "contradicted",
        }
    }

    /// Hard to fabricate: corroborated, signed by a third party and
    /// checked, or verified and predating.
    pub fn strong(self) -> bool {
        matches!(
            self,
            Self::Corroborated | Self::SignedChecked | Self::VerifiedPredating
        )
    }

    pub const ALL: [Self; 9] = [
        Self::Corroborated,
        Self::SignedChecked,
        Self::VerifiedPredating,
        Self::VerifiedRecent,
        Self::Signed,
        Self::Unverified,
        Self::OperatorOnly,
        Self::Assertion,
        Self::Contradicted,
    ];
}

/// A stable identity for an item, for duplicate checks and corroboration:
/// `wayback|20261001083000|https://a.example/x`, `indicator|run_tag|abc`.
pub fn item_key(e: &Evidence) -> String {
    match e {
        Evidence::PublicRecord(r) => {
            let mut parts = vec![r.source.name().to_string()];
            for v in [
                &r.id,
                &r.timestamp,
                &r.url,
                &r.crawl,
                &r.package,
                &r.version,
            ]
            .into_iter()
            .flatten()
            {
                parts.push(v.trim().to_string());
            }
            parts.join("|")
        }
        Evidence::LogLines(l) => {
            let mut lines: Vec<&str> = l.lines.iter().map(|x| x.trim()).collect();
            lines.sort();
            format!("log|{}", lines.join("\u{1f}"))
        }
        Evidence::Signed(g) => format!("signed|{}", g.content.trim()),
        Evidence::Indicator(x) => format!(
            "indicator|{}|{}",
            serde_json::to_value(x.kind)
                .ok()
                .and_then(|v| v.as_str().map(str::to_string))
                .unwrap_or_default(),
            x.value.trim()
        ),
    }
}

/// The id a source's own records carry for this reference, where the
/// reference fixes it: `urlquery:<uuid>`, `gharchive:<id>`, `npm:p@1.0`.
/// Archive captures carry a digest the reference does not name, so they
/// are matched by URL and time instead ([`same_capture`]).
pub fn record_id(r: &PublicRecord) -> Option<String> {
    let bare = |v: &Option<String>| {
        v.as_deref().map(|s| {
            let s = s.trim();
            s.split_once(':').map_or(s, |(_, rest)| rest).to_string()
        })
    };
    match r.source {
        RecordSource::Urlquery => bare(&r.id).map(|i| format!("urlquery:{i}")),
        RecordSource::Urlscan => bare(&r.id).map(|i| format!("urlscan:{i}")),
        RecordSource::Gharchive => bare(&r.id).map(|i| format!("gharchive:{i}")),
        RecordSource::Npm => Some(format!(
            "npm:{}@{}",
            r.package.as_deref()?.trim(),
            r.version.as_deref()?.trim()
        )),
        RecordSource::Pypi => Some(format!(
            "pypi:{}@{}",
            r.package.as_deref()?.trim(),
            r.version.as_deref()?.trim()
        )),
        RecordSource::Ctlog => bare(&r.id).map(|i| format!("crtsh:{i}")),
        RecordSource::Wayback | RecordSource::Arquivo | RecordSource::Commoncrawl => None,
    }
}

/// Whether `o` is the record `r` references: the same id where the
/// reference fixes one, else the same source, URL and time (within
/// `tolerance` seconds).
pub fn same_record(r: &PublicRecord, o: &Observation, tolerance: i64) -> bool {
    match record_id(r) {
        Some(id) => o.id.eq_ignore_ascii_case(&id),
        None => same_capture(r, o, tolerance),
    }
}

/// An archive capture of the referenced URL at the referenced time.
pub fn same_capture(r: &PublicRecord, o: &Observation, tolerance: i64) -> bool {
    let source_ok = o.source.split(':').next() == Some(r.source.name());
    let url_ok = r.url.as_deref().is_some_and(|u| same_url(u, &o.url));
    let ts_ok = r.ts().is_some_and(|t| (t - o.ts).abs() <= tolerance);
    source_ok && url_ok && ts_ok
}

/// URLs equal but for scheme case, host case and a trailing slash.
pub fn same_url(a: &str, b: &str) -> bool {
    fn norm(u: &str) -> String {
        let u = u.trim();
        let (scheme, rest) = u.split_once("://").unwrap_or(("", u));
        let (host, path) = match rest.find(['/', '?', '#']) {
            Some(i) => rest.split_at(i),
            None => (rest, ""),
        };
        let path = path.strip_suffix('/').unwrap_or(path);
        format!(
            "{}://{}{}",
            scheme.to_ascii_lowercase(),
            host.to_ascii_lowercase(),
            path
        )
    }
    norm(a) == norm(b)
}

/// The class of item `e`, given its verification (public records), whether
/// the watch held it when the submission arrived, and the admin's check of
/// its signature (signed artifacts).
pub fn classify(
    e: &Evidence,
    verification: Option<&Verification>,
    held: bool,
    signature: Option<bool>,
) -> EvidenceClass {
    if held {
        return EvidenceClass::Corroborated;
    }
    match e {
        Evidence::PublicRecord(_) => match verification.map(|v| v.status) {
            Some(Status::Verified) => {
                if verification.is_some_and(|v| v.predates) {
                    EvidenceClass::VerifiedPredating
                } else {
                    EvidenceClass::VerifiedRecent
                }
            }
            Some(Status::NotFound | Status::Mismatch | Status::Postdates) => {
                EvidenceClass::Contradicted
            }
            Some(Status::Error | Status::Skipped) | None => EvidenceClass::Unverified,
        },
        Evidence::LogLines(_) => EvidenceClass::OperatorOnly,
        Evidence::Signed(_) => match signature {
            Some(true) => EvidenceClass::SignedChecked,
            Some(false) => EvidenceClass::Contradicted,
            None => EvidenceClass::Signed,
        },
        Evidence::Indicator(_) => EvidenceClass::Assertion,
    }
}

/// The records a submission's items become, as the submitter states them:
/// public-record references with a URL, log lines, and URL or payload
/// indicators. Each carries [`SUBMISSION_SOURCE`] (provenance reported), an
/// id `<submission>:<item>[:<n>]`, and is redacted. They are what the
/// submitter claims, not what was found; the records found by verification
/// replace them in the standing set ([`crate::triage`]).
pub fn claimed_records(sub_id: &str, items: &[Evidence]) -> Vec<(usize, Observation)> {
    let mut out = Vec::new();
    for (i, e) in items.iter().enumerate() {
        let base = |url: String, ts: i64| {
            let mut o = Observation {
                id: format!("{sub_id}:{i}"),
                source: SUBMISSION_SOURCE.into(),
                ts,
                ts_kind: TsKind::Unknown,
                url,
                ..Default::default()
            };
            redact_observation(&mut o);
            o
        };
        match e {
            Evidence::PublicRecord(r) => {
                if let Some(u) = &r.url {
                    out.push((i, base(u.clone(), r.ts().unwrap_or(0))));
                }
            }
            Evidence::Indicator(x)
                if matches!(x.kind, IndicatorKind::Url | IndicatorKind::Payload)
                    && (x.value.starts_with("http://") || x.value.starts_with("https://")) =>
            {
                out.push((i, base(x.value.clone(), 0)));
            }
            Evidence::LogLines(l) => {
                let format = match l.format {
                    LogFormat::AccessLog => Format::AccessLog,
                    LogFormat::Ndjson => Format::Ndjson,
                    LogFormat::Lines => Format::Lines,
                };
                let map = FieldMap {
                    host: l.host.clone(),
                    ..FieldMap::default()
                };
                let parsed = parse_input(&l.lines.join("\n"), format, &map);
                for (n, mut o) in parsed.observations.into_iter().enumerate() {
                    o.id = format!("{sub_id}:{i}:{n}");
                    o.source = SUBMISSION_SOURCE.into();
                    o.reference = None;
                    redact_observation(&mut o);
                    out.push((i, o));
                }
            }
            _ => {}
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls_compare_loosely_on_case_and_trailing_slash() {
        assert!(same_url("HTTPS://A.Example/x/", "https://a.example/x"));
        assert!(!same_url("https://a.example/X", "https://a.example/x"));
    }

    #[test]
    fn log_lines_become_submission_records() {
        let l = Evidence::LogLines(crate::spec::LogLines {
            format: LogFormat::AccessLog,
            host: Some("www.example.org".into()),
            lines: vec![
                r#"203.0.113.9 - - [10/Oct/2026:13:55:36 +0000] "GET /?q=1 HTTP/1.1" 200 5 "-" "curl/8""#
                    .into(),
            ],
            note: None,
        });
        let recs = claimed_records("sub-x", &[l]);
        assert_eq!(recs.len(), 1);
        let o = &recs[0].1;
        assert_eq!(o.source, SUBMISSION_SOURCE);
        assert_eq!(o.provenance(), sc_core::Provenance::Reported);
        assert!(!o.operator_supplied());
    }
}
