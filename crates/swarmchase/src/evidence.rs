//! Logs an affected operator sent us after a report (docs/policies.md,
//! "Operator-supplied logs").
//!
//! They are case evidence, not public records. `case evidence add` keeps only
//! what the case needs (flagged requests, the same clients' other requests,
//! and probe chains), redacted at ingest, in `<case>/evidence/<eid>.ndjson`.
//! The file as received is not kept, only its SHA-256. Private reports use
//! the records; the public notice uses them only once the operator's
//! agreement is recorded with `case evidence consent`.

use crate::case::{Case, CaseStatus, NOTICE_DRAFT, case_dir, load, update};
use crate::pinning::case_rules;
use anyhow::{Context, Result, bail};
use clap::Subcommand;
use sc_core::{FieldMap, Format, OPERATOR_SOURCE, Observation, Rules, Tier, analyze, parse_input};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

pub use sc_case::evidence::{OperatorEvidence, Scope};

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

pub(crate) fn run_evidence(root: &Path, cmd: EvidenceCmd, today: &str) -> Result<()> {
    match cmd {
        EvidenceCmd::Add {
            id,
            file,
            org,
            host,
            format,
            map,
            date,
            note,
        } => {
            let bytes =
                std::fs::read(&file).with_context(|| format!("reading {}", file.display()))?;
            let text = String::from_utf8_lossy(&bytes);
            let mut fm = match &map {
                Some(m) => sc_core::FieldMap::parse(m).map_err(anyhow::Error::msg)?,
                None => sc_core::FieldMap::default(),
            };
            fm.host = Some(host.clone());
            let r = Received {
                text: &text,
                format,
                map: &fm,
                org: &org,
                host: &host,
                date,
                note,
            };
            let e = add_evidence(root, &id, r, today)?;
            println!(
                "added {}: kept {} of {} records from {} (private reports only until `swarmchase case evidence consent {id} {} --how …`)",
                e.id, e.kept, e.lines, org, e.id
            );
            Ok(())
        }
        EvidenceCmd::Consent {
            id,
            evidence,
            how,
            date,
        } => {
            let date = date.unwrap_or_else(|| today.to_string());
            update(root, &id, |c| {
                let e = find_evidence(c, &evidence)?;
                e.public = Some(format!("{date}: {how}"));
                let org = e.org.clone();
                c.log(
                    &date,
                    format!("operator evidence {evidence}: {org} agreed to its use in the public notice ({how})"),
                );
                Ok(())
            })?;
            if case_dir(root, &id)?.join(NOTICE_DRAFT).exists() {
                println!(
                    "re-draft the notice to include it: `swarmchase case notice {id} --force`"
                );
            }
            Ok(())
        }
        EvidenceCmd::Withdraw { id, evidence, date } => {
            let date = date.unwrap_or_else(|| today.to_string());
            let mut published = false;
            update(root, &id, |c| {
                let e = find_evidence(c, &evidence)?;
                if e.public.take().is_none() {
                    bail!("{evidence} has no recorded agreement");
                }
                let org = e.org.clone();
                c.log(
                    &date,
                    format!("operator evidence {evidence}: {org} withdrew its agreement"),
                );
                published = c.status == CaseStatus::Published || c.publish_pending.is_some();
                Ok(())
            })?;
            if published {
                eprintln!(
                    "warning: the notice is published and may use these records; append a correction with `swarmchase notice update {id} --kind correction`"
                );
            }
            Ok(())
        }
        EvidenceCmd::List { id } => {
            let c = load(root, &id)?;
            if c.evidence.is_empty() {
                println!("no operator evidence in case {id}");
            }
            for e in &c.evidence {
                println!(
                    "{}  {}  {}  received {}  {}/{} records  sha256 {}  {}",
                    e.id,
                    e.org,
                    sc_core::defang_host(&e.host),
                    e.received,
                    e.kept,
                    e.lines,
                    &e.sha256[..e.sha256.len().min(16)],
                    e.public.as_deref().unwrap_or("private reports only")
                );
            }
            Ok(())
        }
    }
}

fn find_evidence<'a>(c: &'a mut Case, eid: &str) -> Result<&'a mut OperatorEvidence> {
    let id = c.id.clone();
    c.evidence
        .iter_mut()
        .find(|e| e.id == eid)
        .with_context(|| format!("no evidence `{eid}` in case {id}"))
}

/// A log file as an operator sent it.
struct Received<'a> {
    text: &'a str,
    format: Format,
    map: &'a FieldMap,
    /// The operator that sent it, and the host it belongs to.
    org: &'a str,
    host: &'a str,
    /// When it arrived. Default: today.
    date: Option<String>,
    note: Option<String>,
}

fn add_evidence(root: &Path, id: &str, r: Received, today: &str) -> Result<OperatorEvidence> {
    let Received {
        text,
        format,
        map,
        org,
        host,
        date,
        note,
    } = r;
    // Under the case's lock from the read to the write, so a change made
    // meanwhile is neither lost nor lost to.
    crate::case::modify(root, id, |c| {
        let sha256 = crate::bundle::sha256_hex(text.as_bytes());
        if let Some(e) = c.evidence.iter().find(|e| e.sha256 == sha256) {
            bail!("this file is already evidence {} in case {id}", e.id);
        }
        let eid = format!("e{}", c.evidence.len() + 1);
        let (records, lines, warnings) = ingest(text, format, map, &eid, &case_rules(root, c)?);
        for w in warnings.iter().take(5) {
            eprintln!("warning: {w}");
        }
        if lines == 0 {
            bail!("no records in the file (check --format and --map)");
        }
        let dir = case_dir(root, id)?;
        let p = file(&dir, &eid);
        std::fs::create_dir_all(p.parent().unwrap_or(&dir))?;
        std::fs::write(&p, crate::store::to_ndjson(&records)?)?;
        let received = date.unwrap_or_else(|| today.to_string());
        let e = OperatorEvidence {
            id: eid.clone(),
            org: org.to_string(),
            host: host.to_ascii_lowercase(),
            received: received.clone(),
            sha256,
            lines,
            kept: records.len(),
            public: None,
            note,
        };
        c.evidence.push(e.clone());
        c.log(
        &received,
        format!(
            "operator evidence {eid} from {org}: {} of {lines} records kept; private reports only",
            records.len()
        ),
    );
        Ok(e)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::case::test_support::*;
    use crate::case::{Contact, new_case, report};
    use crate::notice::notice_draft;
    use crate::pinning::RulesText;
    use sc_core::Audience;

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

    #[test]
    fn operator_evidence_stays_private_until_agreed() {
        let root = scratch("evidence");
        let rules = RulesText::load(None).unwrap();
        let records: Vec<Observation> = fixture()
            .results
            .iter()
            .filter(|r| r.obs.id != "other")
            .map(|r| r.obs.clone())
            .collect();
        new_case(&root, "t-2", "Portal probe", records, &rules, "2026-10-12").unwrap();
        let log = [
            r#"203.0.113.9 - - [04/Oct/2026:12:00:00 +0000] "GET /q?id=9%20UNION%20SELECT%201&uqtag=zz9 HTTP/1.1" 200 10 "-" "python-httpx/0.27""#,
            r#"198.51.100.7 - - [04/Oct/2026:12:00:20 +0000] "GET /about HTTP/1.1" 200 10 "-" "Mozilla/5.0""#,
        ]
        .join("\n");
        let map = sc_core::FieldMap {
            host: Some("portal.example.gov".into()),
            ..Default::default()
        };
        let add = |d: &str| {
            let r = Received {
                text: &log,
                format: Format::Auto,
                map: &map,
                org: "Portal",
                host: "portal.example.gov",
                date: None,
                note: None,
            };
            add_evidence(&root, "t-2", r, d)
        };
        let e = add("2026-10-20").unwrap();
        assert_eq!((e.id.as_str(), e.lines, e.kept), ("e1", 2, 1));
        assert!(add("2026-10-20").is_err(), "same file twice");

        let marker = "provided by the affected operator";
        let provider = report(&root, "t-2", Audience::Provider, None, None, "d").unwrap();
        assert!(provider.contains(marker), "{provider}");
        let other = Contact {
            org: "Elsewhere".into(),
            role: crate::case::ContactRole::Affected,
            endpoint: Some("elsewhere.example".into()),
            channel: "email".into(),
            address: "security@elsewhere.example".into(),
            source: String::new(),
            confidence: "low".into(),
            found_on: "d".into(),
            purpose: None,
        };
        let md = report(&root, "t-2", Audience::Affected, None, Some(&other), "d").unwrap();
        assert!(!md.contains(marker), "another operator's logs: {md}");

        let (p, review) = notice_draft(&root, "t-2", false, "2026-10-21", 1_791_000_000).unwrap();
        assert!(!std::fs::read_to_string(&p).unwrap().contains(marker));
        assert!(
            review
                .withheld
                .iter()
                .any(|w| w.contains("operator logs e1")),
            "{:?}",
            review.withheld
        );

        update(&root, "t-2", |c| {
            find_evidence(c, "e1")?.public = Some("2026-10-22: reply".into());
            // A notice names only endpoints classified as affected.
            for e in &mut c.endpoints {
                e.state = crate::case::EndpointState::Targeted;
            }
            Ok(())
        })
        .unwrap();
        let (p, review) = notice_draft(&root, "t-2", true, "2026-10-22", 1_791_000_000).unwrap();
        // With the agreement the notice may use the logs, but the indicator
        // notice still lists no record on the operator's host: that would
        // locate it before its naming clock runs.
        assert!(!std::fs::read_to_string(&p).unwrap().contains(marker));
        assert!(
            !review
                .withheld
                .iter()
                .any(|w| w.contains("operator logs e1")),
            "{:?}",
            review.withheld
        );
        assert!(review.lint.is_empty(), "{:?}", review.lint);
        cleanup(&root);
    }
}
