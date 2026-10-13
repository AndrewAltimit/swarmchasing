//! `watch --public-log <path>`: the few lines of a run that may be shown in
//! a public CI log.
//!
//! The Actions log of a public repository is public, and a run's ordinary
//! output describes unreviewed leads. This summary is built from an
//! allowlist instead of filtered from that output: each source's name and
//! kind (both from the committed watchlist), its status word, its record
//! and request counts and its duration, then totals of the same. Nothing in
//! it is read from a record, an analysis, a lead, an error message or the
//! priority, so nothing about what was found can reach it.

use super::digest::SourceReport;
use serde::Serialize;
use std::fmt::Write as _;

/// One source's public line.
#[derive(Debug, Serialize, PartialEq)]
pub struct Line {
    pub name: String,
    pub kind: String,
    /// [`SourceReport::status`]: `complete`, `partial`, `stopped`, `error`
    /// or `skipped`.
    pub status: &'static str,
    pub pulled: usize,
    pub new: usize,
    pub requests: usize,
    pub duration_ms: u64,
}

/// The run's public summary.
#[derive(Debug, Serialize, PartialEq)]
pub struct PublicLog {
    pub sources: Vec<Line>,
    pub pulled: usize,
    pub new: usize,
    pub requests: usize,
    /// Sources per status word.
    pub by_status: std::collections::BTreeMap<&'static str, usize>,
    pub duration_ms: u64,
}

impl PublicLog {
    pub fn new(sources: &[SourceReport], duration_ms: u64) -> Self {
        let sources: Vec<Line> = sources
            .iter()
            .map(|s| Line {
                name: s.name.clone(),
                kind: s.kind.clone(),
                status: s.status(),
                pulled: s.pulled,
                new: s.new,
                requests: s.requests,
                duration_ms: s.duration_ms,
            })
            .collect();
        let mut by_status = std::collections::BTreeMap::new();
        for l in &sources {
            *by_status.entry(l.status).or_insert(0) += 1;
        }
        Self {
            pulled: sources.iter().map(|l| l.pulled).sum(),
            new: sources.iter().map(|l| l.new).sum(),
            requests: sources.iter().map(|l| l.requests).sum(),
            by_status,
            duration_ms,
            sources,
        }
    }

    /// The text the workflow prints: one line per source, then the totals.
    pub fn render(&self) -> String {
        let mut t = String::new();
        for l in &self.sources {
            let _ = writeln!(
                t,
                "source {} kind={} status={} pulled={} new={} requests={} duration_ms={}",
                safe(&l.name),
                safe(&l.kind),
                l.status,
                l.pulled,
                l.new,
                l.requests,
                l.duration_ms
            );
        }
        let statuses: Vec<String> = self
            .by_status
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect();
        let _ = writeln!(
            t,
            "total sources={} {} pulled={} new={} requests={} duration_ms={}",
            self.sources.len(),
            statuses.join(" "),
            self.pulled,
            self.new,
            self.requests,
            self.duration_ms
        );
        t
    }
}

/// A watchlist name as one printable token: anything but letters, digits,
/// `-`, `_` and `.` becomes `_`, so a name can never carry a line break or
/// a workflow command into the log.
fn safe(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || "-_.".contains(c) {
                c
            } else {
                '_'
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use sc_collect::Coverage;

    #[test]
    fn the_public_log_holds_only_allowlisted_fields() {
        let secret = "https://portal.example.gov/?q=1%27%20OR%201=1&uqtag=r-7f3a";
        let sources = vec![
            SourceReport {
                pulled: 12,
                new: 3,
                requests: 4,
                duration_ms: 1500,
                coverage: Some(Coverage {
                    unit: "hours",
                    read: 6,
                    available: 6,
                    ..Default::default()
                }),
                ..SourceReport::new("jina-reader", "wayback")
            },
            SourceReport {
                error: Some(format!("HTTP 500 from {secret}")),
                requests: 3,
                duration_ms: 20,
                ..SourceReport::new("gh\n::error::x", "gharchive")
            },
            SourceReport {
                stopped: Some(format!("cut at {secret}")),
                pending: true,
                ..SourceReport::new("allorigins", "wayback")
            },
            SourceReport {
                skipped: Some("skipped: URLQUERY_APIKEY not set".into()),
                ..SourceReport::new("uq", "urlquery")
            },
        ];
        let log = PublicLog::new(&sources, 90_000);
        let text = log.render();
        // Every line has exactly the allowlisted shape.
        let source_line = regex::Regex::new(
            r"^source [A-Za-z0-9._-]+ kind=[A-Za-z0-9._-]+ status=(complete|partial|stopped|error|skipped) pulled=\d+ new=\d+ requests=\d+ duration_ms=\d+$",
        )
        .unwrap();
        let total_line = regex::Regex::new(
            r"^total sources=\d+( (complete|partial|stopped|error|skipped)=\d+)+ pulled=\d+ new=\d+ requests=\d+ duration_ms=\d+$",
        )
        .unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), sources.len() + 1, "{text}");
        for l in &lines[..sources.len()] {
            assert!(source_line.is_match(l), "not allowlisted: {l:?}");
        }
        assert!(total_line.is_match(lines[sources.len()]), "{text}");
        // Nothing from an error, a stop reason, coverage or a skip reason.
        for leak in ["portal", "uqtag", "HTTP", "URLQUERY", "hours", "::error::"] {
            assert!(!text.contains(leak), "{leak} leaked: {text}");
        }
        assert!(lines[1].starts_with("source gh___error__x kind=gharchive status=error"));
        assert!(lines[2].contains("status=stopped"));
        assert!(text.ends_with(
            "total sources=4 complete=1 error=1 skipped=1 stopped=1 pulled=12 new=3 requests=7 duration_ms=90000\n"
        ));
        // The serialised form carries the same fields and no others.
        let v = serde_json::to_value(&log).unwrap();
        let mut keys: Vec<&str> = v.as_object().unwrap().keys().map(|k| k.as_str()).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "by_status",
                "duration_ms",
                "new",
                "pulled",
                "requests",
                "sources"
            ]
        );
        let mut keys: Vec<&str> = v["sources"][0]
            .as_object()
            .unwrap()
            .keys()
            .map(|k| k.as_str())
            .collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "duration_ms",
                "kind",
                "name",
                "new",
                "pulled",
                "requests",
                "status"
            ]
        );
    }
}
