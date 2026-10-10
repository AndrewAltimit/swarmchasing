//! Logs an affected operator sent us after a report (docs/policies.md,
//! "Operator-supplied logs").
//!
//! They are case evidence, not public records. `case evidence add` keeps only
//! what the case needs (flagged requests, the same clients' other requests,
//! and probe chains), redacted at ingest, in `<case>/evidence/<eid>.ndjson`.
//! The file as received is not kept, only its SHA-256. Private reports use
//! the records; the public notice uses them only once the operator's
//! agreement is recorded with `case evidence consent`.

use clap::Subcommand;
use sc_core::{FieldMap, Format, OPERATOR_SOURCE, Observation, Rules, Tier, analyze, parse_input};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperatorEvidence {
    /// `e1`, `e2`, … within the case.
    pub id: String,
    /// The operator that sent the logs.
    pub org: String,
    /// The host the logs belong to.
    pub host: String,
    pub received: String,
    /// SHA-256 of the file as received.
    pub sha256: String,
    /// Lines in the file, and records kept from it.
    pub lines: usize,
    pub kept: usize,
    /// When and how the operator agreed to the public notice using these
    /// records. Unset: private reports only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// Which operator evidence a rendering may use.
pub enum Scope<'a> {
    /// Case notes, provider reports, bundles kept with the case.
    All,
    /// A report to one affected operator: its own logs only.
    Operator { org: &'a str, host: Option<&'a str> },
    /// The public notice: only logs the operator agreed to publish.
    Public,
}

impl OperatorEvidence {
    pub fn in_scope(&self, scope: &Scope) -> bool {
        match scope {
            Scope::All => true,
            Scope::Operator { org, host } => {
                self.org.eq_ignore_ascii_case(org)
                    || host.is_some_and(|h| self.host.eq_ignore_ascii_case(h))
            }
            Scope::Public => self.public.is_some(),
        }
    }
}

#[derive(Subcommand)]
pub enum EvidenceCmd {
    /// Add logs an affected operator sent us. Only flagged requests, the same
    /// clients' other requests and probe chains are kept, redacted; the
    /// file itself is not kept. Private reports only until `consent`.
    Add {
        id: String,
        file: PathBuf,
        /// The operator that sent them.
        #[arg(long)]
        org: String,
        /// The host the logs belong to.
        #[arg(long)]
        host: String,
        /// auto | access_log | ndjson | json | lines
        #[arg(long, default_value = "auto")]
        format: Format,
        /// Field mapping for JSON logs, e.g. `ts=time,url=request.url`.
        #[arg(long)]
        map: Option<String>,
        /// When they arrived. Default: today.
        #[arg(long)]
        date: Option<String>,
        #[arg(long)]
        note: Option<String>,
    },
    /// Record that the operator agreed to the public notice using its logs.
    Consent {
        id: String,
        /// e.g. e1
        evidence: String,
        /// How the agreement was given, e.g. "reply of 2026-10-20 to our report".
        #[arg(long)]
        how: String,
        #[arg(long)]
        date: Option<String>,
    },
    /// Record that the operator withdrew its agreement.
    Withdraw {
        id: String,
        evidence: String,
        #[arg(long)]
        date: Option<String>,
    },
    /// List a case's operator evidence.
    List { id: String },
}

pub fn file(case_dir: &Path, eid: &str) -> PathBuf {
    case_dir.join("evidence").join(format!("{eid}.ndjson"))
}

/// Parse a log file and keep what the case needs, as evidence `eid`.
/// Returns the records and the number of lines read.
pub fn ingest(
    text: &str,
    format: Format,
    map: &FieldMap,
    eid: &str,
    rules: &Rules,
) -> (Vec<Observation>, usize, Vec<String>) {
    let parsed = parse_input(text, format, map);
    let lines = parsed.observations.len();
    let mut kept = keep(parsed.observations, rules);
    for o in &mut kept {
        o.id = format!("{eid}-{}", o.id);
        o.source = format!("{OPERATOR_SOURCE}:{eid}");
    }
    (kept, lines, parsed.warnings)
}

/// Flagged requests, every request from a client that made one, and probe
/// chains. Everyone else's traffic stays out of the case.
fn keep(obs: Vec<Observation>, rules: &Rules) -> Vec<Observation> {
    let a = analyze(obs, rules);
    let flagged = |i: usize| a.results[i].tier >= Tier::Suggestive;
    let ips: BTreeSet<&str> = (0..a.results.len())
        .filter(|&i| flagged(i))
        .filter_map(|i| a.results[i].obs.ip.as_deref())
        .collect();
    let mut idx: BTreeSet<usize> = (0..a.results.len())
        .filter(|&i| {
            flagged(i)
                || a.results[i]
                    .obs
                    .ip
                    .as_deref()
                    .is_some_and(|ip| ips.contains(ip))
        })
        .collect();
    for ch in &a.chains {
        idx.extend(ch.members.iter().copied());
    }
    let mut out: Vec<Observation> = idx.into_iter().map(|i| a.results[i].obs.clone()).collect();
    out.sort_by_key(|o| o.ts);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keeps_the_agent_and_drops_everyone_else() {
        let log = [
            r#"203.0.113.9 - - [10/Oct/2026:12:00:00 +0000] "GET /q?id=1 HTTP/1.1" 200 10 "-" "python-httpx/0.27""#,
            r#"203.0.113.9 - - [10/Oct/2026:12:00:40 +0000] "GET /q?id=1%20UNION%20SELECT%201 HTTP/1.1" 500 10 "-" "python-httpx/0.27""#,
            r#"198.51.100.7 - - [10/Oct/2026:12:00:20 +0000] "GET /about HTTP/1.1" 200 10 "-" "Mozilla/5.0""#,
        ]
        .join("\n");
        let map = FieldMap::parse("host=portal.example.gov").unwrap();
        let (kept, lines, _) = ingest(&log, Format::Auto, &map, "e1", &Rules::default_rules());
        assert_eq!(lines, 3);
        let ids: Vec<&str> = kept.iter().map(|o| o.id.as_str()).collect();
        assert_eq!(ids, ["e1-log-1", "e1-log-2"], "{kept:?}");
        assert!(kept.iter().all(|o| o.operator_supplied()));
        assert!(kept[0].url.starts_with("https://portal.example.gov/"));
    }

    #[test]
    fn scope() {
        let mut e = OperatorEvidence {
            id: "e1".into(),
            org: "Portal".into(),
            host: "portal.example.gov".into(),
            received: "2026-10-20".into(),
            sha256: String::new(),
            lines: 0,
            kept: 0,
            public: None,
            note: None,
        };
        assert!(e.in_scope(&Scope::All));
        assert!(!e.in_scope(&Scope::Public));
        assert!(e.in_scope(&Scope::Operator {
            org: "other",
            host: Some("PORTAL.example.gov")
        }));
        assert!(!e.in_scope(&Scope::Operator {
            org: "other",
            host: None
        }));
        e.public = Some("2026-10-21: reply".into());
        assert!(e.in_scope(&Scope::Public));
    }
}
