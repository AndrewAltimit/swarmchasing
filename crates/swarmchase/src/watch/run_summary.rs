//! `runs/<stamp>/run.json`: the run in a small, stable JSON for scripts,
//! local dashboards and agents, beside the digest. Field names are
//! documented in docs/reference/watch.md#the-run-summary; a field is only
//! ever added, and a breaking change bumps [`SCHEMA`].
//!
//! It holds what the digest says in structured form: hosts are defanged,
//! and it carries no record URL, IP address or model prompt. It stays in
//! the data directory like the digest.

use super::attention::{Item, Queue};
use super::autonomy::{self, Decision, Mode};
use super::cases::{CaseReport, DueClock};
use super::digest::{Alert, Health, lost_lines};
use super::priority::{Level, Priority, Reason};
use super::timing::Durations;
use super::triage::{Lead, TriageReport};
use sc_core::{Analysis, Tier};
use serde::Serialize;
use std::collections::BTreeMap;

/// Queue items the summary lists.
const ATTENTION_TOP: usize = 10;

/// The format's name and version.
pub const SCHEMA: &str = "swarmchase-watch-run/1";

/// The file name, in the run directory.
pub const FILE: &str = "run.json";

#[derive(Debug, Serialize)]
pub struct RunSummary<'a> {
    pub schema: &'static str,
    /// The run's stamp, also its directory name and `LATEST`.
    pub stamp: &'a str,
    /// When it ran, RFC 3339 UTC.
    pub generated: &'a str,
    pub rules_version: &'a str,
    /// Whether the digest counts as changed (and is emailed).
    pub changed: bool,
    pub priority: Level,
    pub reasons: &'a [Reason],
    pub counts: Counts,
    pub leads: &'a [Lead],
    pub triage: &'a TriageReport,
    pub health: HealthSummary<'a>,
    pub cases: CaseSummary<'a>,
    pub attention: AttentionSummary<'a>,
    pub autonomy: AutonomySummary<'a>,
    /// Milliseconds each phase took, and the run's `total` up to this file.
    pub durations_ms: &'a Durations,
    /// The digest's file name in the same directory.
    pub digest: &'static str,
}

#[derive(Debug, Serialize)]
pub struct AttentionSummary<'a> {
    /// Clusters per band.
    pub by_band: &'a BTreeMap<String, usize>,
    /// The first of the queue; `attention.json` holds it all.
    pub top: &'a [Item],
    pub file: &'static str,
}

#[derive(Debug, Serialize)]
pub struct AutonomySummary<'a> {
    /// Each level's mode.
    pub modes: BTreeMap<&'static str, Mode>,
    /// What the levels did or would have done this run.
    pub decisions: &'a [Decision],
}

#[derive(Debug, Serialize)]
pub struct Counts {
    /// Records in the analysis window.
    pub records: usize,
    /// Records this run reports as new.
    pub new_records: usize,
    /// Of those, records an earlier run stored but ended before reporting.
    pub carried_over: usize,
    /// Of those, records captured before the analysis window; this run
    /// analyses them with it.
    pub new_before_window: usize,
    pub significant: usize,
    pub suggestive: usize,
    pub clusters_above_noise: usize,
}

#[derive(Debug, Serialize)]
pub struct HealthSummary<'a> {
    pub alerts: &'a [Alert],
    /// The digest's "capability lost" lines.
    pub lost: Vec<String>,
    pub sources: Vec<SourceLine>,
}

#[derive(Debug, Serialize)]
pub struct SourceLine {
    pub name: String,
    pub kind: String,
    pub pulled: usize,
    pub new: usize,
    /// `complete`, `partial`, `stopped`, `error` or `skipped`.
    pub status: &'static str,
    /// Milliseconds its pull took.
    pub duration_ms: u64,
}

#[derive(Debug, Serialize)]
pub struct CaseSummary<'a> {
    pub due: &'a [DueClock],
    /// How many "Case status" lines the digest has.
    pub lines: usize,
}

/// Everything the summary is built from.
pub struct Input<'a> {
    pub stamp: &'a str,
    pub generated: &'a str,
    pub analysis: &'a Analysis,
    pub new_records: usize,
    pub carried_over: usize,
    pub new_before_window: usize,
    pub changed: bool,
    pub priority: &'a Priority,
    pub leads: &'a [Lead],
    pub triage: &'a TriageReport,
    pub health: &'a Health,
    pub cases: &'a CaseReport,
    pub attention: &'a Queue,
    pub autonomy: (&'a autonomy::Config, &'a [Decision]),
    pub durations: &'a Durations,
}

pub fn build<'a>(i: &Input<'a>) -> RunSummary<'a> {
    let a = i.analysis;
    let tier = |x| a.tier_counts.get(&x).copied().unwrap_or(0);
    RunSummary {
        schema: SCHEMA,
        stamp: i.stamp,
        generated: i.generated,
        rules_version: &a.rules_version,
        changed: i.changed,
        priority: i.priority.level,
        reasons: &i.priority.reasons,
        counts: Counts {
            records: a.total,
            new_records: i.new_records,
            carried_over: i.carried_over,
            new_before_window: i.new_before_window,
            significant: tier(Tier::Significant),
            suggestive: tier(Tier::Suggestive),
            clusters_above_noise: a
                .clusters
                .iter()
                .filter(|c| c.tier >= Tier::Suggestive)
                .count(),
        },
        leads: i.leads,
        triage: i.triage,
        health: HealthSummary {
            alerts: &i.health.alerts,
            lost: lost_lines(&i.health.sources),
            sources: i
                .health
                .sources
                .iter()
                .map(|s| SourceLine {
                    name: s.name.clone(),
                    kind: s.kind.clone(),
                    pulled: s.pulled,
                    new: s.new,
                    status: s.status(),
                    duration_ms: s.duration_ms,
                })
                .collect(),
        },
        cases: CaseSummary {
            due: &i.cases.due,
            lines: i.cases.lines.len(),
        },
        attention: AttentionSummary {
            by_band: &i.attention.by_band,
            top: &i.attention.items[..i.attention.items.len().min(ATTENTION_TOP)],
            file: super::attention::FILE,
        },
        autonomy: AutonomySummary {
            modes: autonomy::Level::ALL
                .iter()
                .map(|&l| (l.label(), i.autonomy.0.mode(l)))
                .collect(),
            decisions: i.autonomy.1,
        },
        durations_ms: i.durations,
        digest: "digest.md",
    }
}

#[cfg(test)]
mod tests {
    use super::super::digest::{AlertKind, SourceReport, Summary, summarise};
    use super::super::triage::{leads, tests::analysis};
    use super::*;
    use crate::suggest::Suggestion;
    use serde_json::Value;

    #[test]
    fn the_run_summary_has_its_documented_fields() {
        let (a, ids) = analysis();
        let next = summarise(&a, &Summary::default(), "t".into());
        let mut l = leads(&a, &Summary::default(), &next, &ids);
        l[0].suggestion = Some(Suggestion {
            label: "agent".into(),
            reason: "relay plus SQLi".into(),
            model: "m".into(),
        });
        let health = Health {
            sources: vec![SourceReport {
                error: Some("HTTP 503".into()),
                ..SourceReport::new("wayback-jina", "wayback")
            }],
            alerts: vec![Alert::new(
                AlertKind::SourceFailed,
                "wayback-jina",
                "`wayback-jina` failed this run (HTTP 503)".into(),
            )],
            notes: Vec::new(),
        };
        let cases = CaseReport::default();
        let priority = super::super::priority::assess(&l, &health.alerts, &cases.due);
        let queue = super::super::attention::tests::queue_of(&a, &ids);
        let cfg = autonomy::Config::default();
        let triage = TriageReport {
            enabled: true,
            backend: "claude".into(),
            model: "m".into(),
            asked: 1,
            answered: 1,
            withheld: 1,
            ..Default::default()
        };
        let durations = super::super::timing::Phases::new().summary();
        let s = build(&Input {
            stamp: "20261011T000000Z",
            generated: "2026-10-11T00:00:00Z",
            analysis: &a,
            new_records: ids.len(),
            carried_over: 0,
            new_before_window: 0,
            changed: true,
            priority: &priority,
            leads: &l,
            triage: &triage,
            health: &health,
            cases: &cases,
            attention: &queue,
            autonomy: (&cfg, &[]),
            durations: &durations,
        });
        let v: Value = serde_json::to_value(&s).unwrap();
        for k in [
            "schema",
            "stamp",
            "generated",
            "rules_version",
            "changed",
            "priority",
            "reasons",
            "counts",
            "leads",
            "triage",
            "health",
            "cases",
            "attention",
            "autonomy",
            "durations_ms",
            "digest",
        ] {
            assert!(v.get(k).is_some(), "{k} missing in {v}");
        }
        assert_eq!(v["schema"], SCHEMA);
        assert_eq!(v["priority"], priority.level.label());
        let lead = &v["leads"][0];
        for k in [
            "kind", "change", "id", "record", "source", "tier", "score", "records", "grade",
            "targets",
        ] {
            assert!(lead.get(k).is_some(), "lead.{k} missing in {lead}");
        }
        assert!(lead["grade"].as_str().unwrap().starts_with('L'), "{lead}");
        assert_eq!(lead["suggestion"]["label"], "agent");
        assert!(lead.get("idx").is_none());
        assert_eq!(v["health"]["alerts"][0]["kind"], "source_failed");
        assert_eq!(v["health"]["sources"][0]["status"], "error");
        assert!(v["health"]["sources"][0]["duration_ms"].is_u64(), "{v}");
        assert!(v["durations_ms"]["total"].is_u64(), "{v}");
        assert_eq!(v["triage"]["enabled"], true);
        assert_eq!(v["triage"]["backend"], "claude");
        assert_eq!(v["triage"]["withheld"], 1);
        assert_eq!(v["counts"]["new_records"], ids.len());
        assert_eq!(v["attention"]["file"], "attention.json");
        assert!(v["attention"]["top"][0]["band"].is_string(), "{v}");
        assert_eq!(v["autonomy"]["modes"]["interrupt"], "shadow");
        // Hosts defanged, no URL or IP.
        let text = v.to_string();
        assert!(
            !text.contains("https://") && !text.contains("portal.example.gov"),
            "{text}"
        );
        assert!(text.contains("portal[.]example[.]gov"), "{text}");
    }
}
