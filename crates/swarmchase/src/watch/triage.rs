//! A run's new leads, and opt-in label suggestions on them from a model.
//!
//! A lead is a cluster above noise that is new since the previous run or
//! rose a tier, or a new significant record that joined no cluster. Triage
//! asks a model for a label on each lead's strongest record, strongest lead
//! first, up to a count and a time budget per run. Any failure is no
//! suggestion and the watch carries on. Two backends ([`Backend`]):
//!
//! - **local** (`--triage`, or `SWARMCHASE_WATCH_TRIAGE=1`): the model at
//!   `SWARMCHASE_LLM_URL`, through the client of `review --suggest`
//!   ([`crate::suggest`]): local endpoints only, defanged text, no tools,
//!   one record per ask; after three failures in a row the rest are left.
//!   It may see any record. Answers go in `labels/suggestions-local.ndjson`.
//! - **claude** (`--triage=claude`, or `SWARMCHASE_WATCH_TRIAGE=claude`):
//!   Claude through the admin's Claude Code login ([`crate::suggest::claude`]),
//!   many records per call. Claude is a hosted model, so it is sent only
//!   leads from [`HOSTED_SOURCES`](crate::review::hosted::HOSTED_SOURCES), as
//!   `review --export-hosted` writes them; the rest are counted as withheld.
//!   After a usage limit or two failed calls in a row it asks no more this
//!   run. Answers go in `labels/suggestions-claude-watch.ndjson`, with the
//!   grade the model saw and any misfires.
//!
//! Each line is `{"id", "label", "reason", "model", "run"}`, the format
//! review reads suggestions in. A record already in the backend's file is
//! not asked again. A suggestion is shown beside a lead and never labels it,
//! and it never sets the run's priority ([`super::priority`]).

use super::digest::{ClusterSummary, Summary};
use crate::review::hosted::{ExportLine, export_line};
use crate::suggest::claude::{Answer, ClaudeCli, Outcome, SavedLine, append_lines};
use crate::suggest::{Suggester, Suggestion, defang_all};
use crate::util::truncate;
use anyhow::{Context, Result};
use sc_core::agentness::AgentLevel;
use sc_core::{Analysis, ObsResult, Tier, defang_host};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::time::{Duration, Instant};

/// The file the local model's suggestions go in, under `<data>/labels/`.
pub const FILE: &str = "suggestions-local.ndjson";
/// The file Claude's suggestions go in, under `<data>/labels/`. Review
/// reads it as a hosted model's: a line for a withheld source is dropped.
pub const CLAUDE_FILE: &str = "suggestions-claude-watch.ndjson";

/// Failed asks in a row after which the run stops asking.
const MAX_FAILURES_IN_ROW: usize = 3;
/// The longest one ask may take.
const PER_REQUEST: Duration = Duration::from_secs(60);
/// Records per Claude call: one call covers a usual run's leads.
const CLAUDE_CHUNK: usize = 25;
/// The longest one Claude call may take.
const CLAUDE_PER_CALL: Duration = Duration::from_secs(600);
/// Failed Claude calls in a row after which the run stops asking.
const CLAUDE_MAX_FAILURES: usize = 2;

/// Which model triage asks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Backend {
    /// The model server at `SWARMCHASE_LLM_URL`, on this machine or network.
    Local,
    /// Claude through Claude Code, logged in as the user running the watch.
    Claude,
}

impl Backend {
    pub fn label(self) -> &'static str {
        match self {
            Backend::Local => "local",
            Backend::Claude => "claude",
        }
    }
}

/// `SWARMCHASE_WATCH_TRIAGE` read: `claude`, or `local` (also `1`, `true`
/// or `yes`); unset, empty, `0`, `false`, `no` or `off` is no triage. Any
/// other value is an error.
pub fn parse_backend(v: &str) -> std::result::Result<Option<Backend>, String> {
    match v.trim().to_ascii_lowercase().as_str() {
        "" | "0" | "false" | "no" | "off" => Ok(None),
        "1" | "true" | "yes" | "local" => Ok(Some(Backend::Local)),
        "claude" => Ok(Some(Backend::Claude)),
        other => Err(format!(
            "SWARMCHASE_WATCH_TRIAGE `{}`: use local or claude",
            truncate(other, 20)
        )),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LeadKind {
    /// A cluster new since the last run, or one that rose a tier.
    Cluster,
    /// A new significant record outside any cluster.
    Record,
}

/// One new lead of the run.
#[derive(Debug, Clone, Serialize)]
pub struct Lead {
    pub kind: LeadKind,
    /// `new`, or `escalated` for a cluster that rose a tier.
    pub change: &'static str,
    /// The cluster's number in this run's analysis (`C3`), or the record id.
    pub id: String,
    /// The cluster's stable key; empty for a record.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub key: String,
    /// The record the model is asked about: the cluster's strongest.
    pub record: String,
    pub source: String,
    pub tier: Tier,
    pub score: i32,
    pub records: usize,
    /// The cluster's agent grade, or the record's own.
    #[serde(serialize_with = "level_code")]
    pub grade: AgentLevel,
    /// Target hosts, defanged.
    pub targets: Vec<String>,
    /// The local model's suggestion for `record`, when there is one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suggestion: Option<Suggestion>,
    /// Index of `record` in the analysis.
    #[serde(skip)]
    pub idx: usize,
}

fn level_code<S: serde::Serializer>(l: &AgentLevel, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(l.code())
}

impl Lead {
    /// `C3 k-3f9a2c1b` or the record id.
    pub fn name(&self) -> String {
        if self.key.is_empty() {
            self.id.clone()
        } else {
            format!("{} {}", self.id, self.key)
        }
    }

    /// Whether the suggestion says `agent` where the labelling rule allows
    /// at most `unsure`: an agent grade below L2.
    pub fn against_rule(&self) -> bool {
        self.suggestion.as_ref().is_some_and(|s| s.label == "agent")
            && self.grade < AgentLevel::ModelWritten
    }
}

/// The run's leads, strongest first: tier, then grade, then score.
pub fn leads(
    a: &Analysis,
    prev: &Summary,
    next: &Summary,
    new_ids: &BTreeSet<String>,
) -> Vec<Lead> {
    let mut out = Vec::new();
    for (k, c) in &next.clusters {
        if c.tier < Tier::Suggestive {
            continue;
        }
        let change = match prev.clusters.get(k) {
            None => "new",
            Some(p) if c.tier > p.tier => "escalated",
            _ => continue,
        };
        if let Some(l) = cluster_lead(a, c, change) {
            out.push(l);
        }
    }
    for (idx, r) in a.results.iter().enumerate() {
        if r.tier == Tier::Significant && r.cluster.is_none() && new_ids.contains(&r.obs.id) {
            out.push(Lead {
                kind: LeadKind::Record,
                change: "new",
                id: r.obs.id.clone(),
                key: String::new(),
                record: r.obs.id.clone(),
                source: r.obs.source.clone(),
                tier: r.tier,
                score: r.score,
                records: 1,
                grade: r.agent.as_ref().map(|g| g.level).unwrap_or_default(),
                targets: r
                    .target_host
                    .iter()
                    .map(|h| defang_host(&super::digest::clean_host(h)))
                    .collect(),
                suggestion: None,
                idx,
            });
        }
    }
    out.sort_by(|x, y| {
        y.tier
            .cmp(&x.tier)
            .then(y.grade.cmp(&x.grade))
            .then(y.score.cmp(&x.score))
            .then(x.id.cmp(&y.id))
    });
    out
}

fn cluster_lead(a: &Analysis, s: &ClusterSummary, change: &'static str) -> Option<Lead> {
    let c = a.cluster(&s.id)?;
    let best = |m: &usize| {
        let r: &ObsResult = &a.results[*m];
        (
            r.score,
            std::cmp::Reverse(r.obs.ts),
            std::cmp::Reverse(&r.obs.id),
        )
    };
    let idx = c.members.iter().copied().max_by_key(best)?;
    let r = &a.results[idx];
    Some(Lead {
        kind: LeadKind::Cluster,
        change,
        id: c.id.clone(),
        key: c.key.clone(),
        record: r.obs.id.clone(),
        source: r.obs.source.clone(),
        tier: c.tier,
        score: c.score,
        records: c.members.len(),
        grade: c.agent.level,
        targets: s
            .targets
            .iter()
            .map(|h| defang_host(&super::digest::clean_host(h)))
            .collect(),
        suggestion: None,
        idx,
    })
}

/// Limits on one run's asks.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// Leads asked about per run.
    pub max: usize,
    /// Total time the run spends asking.
    pub budget: Duration,
}

/// What triage did this run.
#[derive(Debug, Clone, Default, Serialize)]
pub struct TriageReport {
    pub enabled: bool,
    /// `local` or `claude`.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub backend: String,
    /// The model the suggestions came from.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub model: String,
    /// Leads asked about, and those answered with a usable suggestion.
    pub asked: usize,
    pub answered: usize,
    /// Leads whose record already had a suggestion from an earlier run.
    pub reused: usize,
    /// Leads left unasked: over the count or the time budget, or after
    /// repeated failures or a usage limit.
    pub left: usize,
    /// Leads not sent because a hosted model may not see their source
    /// (operator logs and any source off the hosted list).
    pub withheld: usize,
    /// Why triage did not run or stopped early, when it did.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

impl TriageReport {
    /// The suggestions file this report's backend writes, under `labels/`.
    pub fn file(&self) -> &'static str {
        if self.backend == Backend::Claude.label() {
            CLAUDE_FILE
        } else {
            FILE
        }
    }
}

/// Ask `ask` about `leads` in order, within `limits`, reusing `known`
/// suggestions. `ask` gets the record index and the time it may take.
/// Returns the report and the new suggestions by record id.
pub fn ask_all(
    a: &Analysis,
    leads: &mut [Lead],
    known: &BTreeMap<String, Suggestion>,
    limits: Limits,
    ask: &mut dyn FnMut(&Analysis, usize, Duration) -> Option<Suggestion>,
) -> (TriageReport, Vec<(String, Suggestion)>) {
    let start = Instant::now();
    let mut rep = TriageReport {
        enabled: true,
        ..Default::default()
    };
    let mut fresh = Vec::new();
    let mut failures = 0;
    for l in leads.iter_mut() {
        if let Some(s) = known.get(&l.record) {
            l.suggestion = Some(s.clone());
            rep.reused += 1;
            continue;
        }
        let left = limits.budget.saturating_sub(start.elapsed());
        if rep.asked >= limits.max || left.is_zero() || failures >= MAX_FAILURES_IN_ROW {
            rep.left += 1;
            continue;
        }
        rep.asked += 1;
        match ask(a, l.idx, left.min(PER_REQUEST)) {
            Some(s) => {
                let s = Suggestion {
                    reason: defang_all(&s.reason),
                    ..s
                };
                failures = 0;
                rep.answered += 1;
                l.suggestion = Some(s.clone());
                fresh.push((l.record.clone(), s));
            }
            None => failures += 1,
        }
    }
    if rep.left > 0 {
        rep.note = Some(if failures >= MAX_FAILURES_IN_ROW {
            format!(
                "stopped after {MAX_FAILURES_IN_ROW} failed asks in a row; {} lead(s) not asked",
                rep.left
            )
        } else {
            format!(
                "{} lead(s) not asked: over this run's limit of {} asks or {} s",
                rep.left,
                limits.max,
                limits.budget.as_secs()
            )
        });
    } else if rep.asked > 0 && rep.answered == 0 {
        rep.note = Some("the model gave no usable answer".into());
    }
    (rep, fresh)
}

#[derive(Serialize, Deserialize)]
struct Line {
    id: String,
    label: String,
    #[serde(default)]
    reason: String,
    #[serde(default)]
    model: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    run: String,
}

/// The suggestions already in `labels/suggestions-local.ndjson`; a later
/// line for a record wins, and a line that does not parse is skipped.
pub fn load(labels: &Path) -> BTreeMap<String, Suggestion> {
    load_file(labels, FILE)
}

/// As [`load`], from `labels/<file>`.
pub fn load_file(labels: &Path, file: &str) -> BTreeMap<String, Suggestion> {
    let text = std::fs::read_to_string(labels.join(file)).unwrap_or_default();
    text.lines()
        .filter_map(|l| serde_json::from_str::<Line>(l).ok())
        .filter(|l| matches!(l.label.as_str(), "agent" | "benign" | "unsure"))
        .map(|l| {
            (
                l.id,
                Suggestion {
                    label: l.label,
                    reason: l.reason,
                    model: l.model,
                },
            )
        })
        .collect()
}

/// Append `fresh` to `labels/suggestions-local.ndjson`.
pub fn save(labels: &Path, fresh: &[(String, Suggestion)], stamp: &str) -> Result<()> {
    if fresh.is_empty() {
        return Ok(());
    }
    std::fs::create_dir_all(labels)?;
    let mut text = String::new();
    for (id, s) in fresh {
        text += &serde_json::to_string(&Line {
            id: id.clone(),
            label: s.label.clone(),
            reason: truncate(&s.reason, 200),
            model: s.model.clone(),
            run: stamp.to_string(),
        })?;
        text.push('\n');
    }
    let path = labels.join(FILE);
    crate::store::append(&path, &text).with_context(|| format!("writing {}", path.display()))
}

/// The backend the run triages with: the flag, else
/// `SWARMCHASE_WATCH_TRIAGE` ([`parse_backend`]), else none. A value that
/// does not parse is a warning and no triage.
pub fn backend(flag: Option<Backend>) -> Option<Backend> {
    flag.or_else(|| {
        let v = std::env::var("SWARMCHASE_WATCH_TRIAGE").unwrap_or_default();
        parse_backend(&v).unwrap_or_else(|e| {
            eprintln!("warning: {e}; no model triage this run");
            None
        })
    })
}

/// Triage this run's leads with `backend`, when there is one. Never fails
/// the run: a missing or refused endpoint, a missing `claude`, or a file
/// that cannot be written, is a note in the report.
pub fn run(
    backend: Option<Backend>,
    data: &Path,
    a: &Analysis,
    leads: &mut [Lead],
    stamp: &str,
    limits: Limits,
) -> TriageReport {
    match backend {
        None => TriageReport::default(),
        Some(Backend::Local) => run_local(data, a, leads, stamp, limits),
        Some(Backend::Claude) => match ClaudeCli::from_env() {
            Ok(cli) => run_claude(data, a, leads, stamp, limits, &cli),
            Err(e) => TriageReport {
                enabled: true,
                backend: Backend::Claude.label().into(),
                left: leads.len(),
                note: Some(format!("{}; no model asked", one_line(&e))),
                ..Default::default()
            },
        },
    }
}

fn run_local(
    data: &Path,
    a: &Analysis,
    leads: &mut [Lead],
    stamp: &str,
    limits: Limits,
) -> TriageReport {
    let off = |note: String| TriageReport {
        enabled: true,
        backend: Backend::Local.label().into(),
        left: leads.len(),
        note: Some(note),
        ..Default::default()
    };
    let url = std::env::var("SWARMCHASE_LLM_URL")
        .ok()
        .filter(|v| !v.trim().is_empty());
    let suggester = match url {
        None => return off("SWARMCHASE_LLM_URL is not set; no model asked".into()),
        Some(base) => {
            let model = std::env::var("SWARMCHASE_LLM_MODEL").unwrap_or_default();
            match Suggester::new(&base, &model, PER_REQUEST) {
                Ok(s) => s,
                Err(e) => return off(format!("{}; no model asked", one_line(&e))),
            }
        }
    };
    let labels = data.join("labels");
    let known = load(&labels);
    let (mut rep, fresh) = ask_all(a, leads, &known, limits, &mut |a, idx, t| {
        suggester.suggest_within(a, idx, t)
    });
    rep.model = suggester.model().to_string();
    rep.backend = Backend::Local.label().into();
    if let Err(e) = save(&labels, &fresh, stamp) {
        eprintln!("warning: triage suggestions not saved: {e:#}");
        rep.note = Some(format!("suggestions not saved: {}", one_line(&e)));
    }
    eprintln!(
        "triage: {} lead(s) asked, {} answered, {} reused, {} left",
        rep.asked, rep.answered, rep.reused, rep.left
    );
    rep
}

/// Triage with Claude through `cli`: hosted-source leads only.
pub fn run_claude(
    data: &Path,
    a: &Analysis,
    leads: &mut [Lead],
    stamp: &str,
    limits: Limits,
    cli: &ClaudeCli,
) -> TriageReport {
    let labels = data.join("labels");
    let known = load_file(&labels, CLAUDE_FILE);
    let (mut rep, fresh) = ask_claude(a, leads, &known, limits, &mut |lines, t| {
        cli.suggest(lines, t)
    });
    rep.model = cli.model().to_string();
    for l in leads.iter_mut() {
        if let Some(s) = l.suggestion.as_mut().filter(|s| s.model.is_empty()) {
            s.model = rep.model.clone();
        }
    }
    let saved: Vec<SavedLine> = fresh
        .iter()
        .map(|x| SavedLine::new(x, cli.model(), stamp))
        .collect();
    if let Err(e) = append_lines(&labels.join(CLAUDE_FILE), &saved) {
        eprintln!("warning: triage suggestions not saved: {e:#}");
        rep.note = Some(format!("suggestions not saved: {}", one_line(&e)));
    }
    eprintln!(
        "triage (claude): {} record(s) asked, {} answered, {} reused, {} withheld, {} left",
        rep.asked, rep.answered, rep.reused, rep.withheld, rep.left
    );
    rep
}

/// Ask Claude about `leads` through `ask`, a chunk of export lines per
/// call, within `limits`, reusing `known` suggestions. A lead whose record
/// comes from a source a hosted model may not see is never put in a chunk:
/// it is counted as withheld. Returns the report and the new answers.
pub fn ask_claude(
    a: &Analysis,
    leads: &mut [Lead],
    known: &BTreeMap<String, Suggestion>,
    limits: Limits,
    ask: &mut dyn FnMut(&[ExportLine], Duration) -> Outcome,
) -> (TriageReport, Vec<Answer>) {
    let start = Instant::now();
    let mut rep = TriageReport {
        enabled: true,
        backend: Backend::Claude.label().into(),
        ..Default::default()
    };
    let mut lines: Vec<ExportLine> = Vec::new();
    for l in leads.iter_mut() {
        let Some(line) = export_line(a, l.idx) else {
            rep.withheld += 1;
            continue;
        };
        if let Some(s) = known.get(&l.record) {
            l.suggestion = Some(s.clone());
            rep.reused += 1;
            continue;
        }
        if lines.iter().any(|x| x.id == line.id) {
            continue;
        }
        if lines.len() >= limits.max {
            rep.left += 1;
            continue;
        }
        lines.push(line);
    }
    let mut fresh = Vec::new();
    let mut failures = 0;
    let mut stop: Option<String> = None;
    let mut last_failure = None;
    for chunk in lines.chunks(CLAUDE_CHUNK) {
        let left = limits.budget.saturating_sub(start.elapsed());
        if stop.is_some() || left.is_zero() {
            rep.left += chunk.len();
            continue;
        }
        rep.asked += chunk.len();
        match ask(chunk, left.min(CLAUDE_PER_CALL)) {
            Outcome::Answered(ans) => {
                failures = 0;
                for x in ans {
                    let s = Suggestion {
                        label: x.label.clone(),
                        reason: x.reason.clone(),
                        model: String::new(),
                    };
                    let mut hit = false;
                    for l in leads.iter_mut().filter(|l| l.record == x.id) {
                        l.suggestion = Some(s.clone());
                        hit = true;
                    }
                    if hit {
                        rep.answered += 1;
                        fresh.push(x);
                    }
                }
            }
            Outcome::Failed(why) => {
                failures += 1;
                last_failure = Some(why);
                if failures >= CLAUDE_MAX_FAILURES {
                    stop = Some(format!(
                        "stopped after {CLAUDE_MAX_FAILURES} failed calls in a row"
                    ));
                }
            }
            Outcome::Limited(why) => {
                stop = Some(format!("{why}; no more asks this run"));
            }
        }
    }
    let mut notes = Vec::new();
    if rep.withheld > 0 {
        notes.push(format!(
            "{} lead(s) withheld: their source is not one a hosted model may see",
            rep.withheld
        ));
    }
    if let Some(s) = stop {
        notes.push(s);
    }
    if let Some(w) = last_failure {
        notes.push(w);
    }
    if rep.left > 0 {
        notes.push(format!(
            "{} lead(s) not asked: over this run's limit of {} asks or {} s, or after a stop",
            rep.left,
            limits.max,
            limits.budget.as_secs()
        ));
    }
    if rep.asked > 0 && rep.answered == 0 && notes.is_empty() {
        notes.push("the model gave no usable answer".into());
    }
    if !notes.is_empty() {
        rep.note = Some(notes.join("; "));
    }
    (rep, fresh)
}

fn one_line(e: &anyhow::Error) -> String {
    crate::util::one_line(&format!("{e:#}"), 200)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::suggest::tests::{reply, serve_many};
    use sc_core::{Observation, Rules, analyze};

    /// One relayed SQLi run of six records against one host, and one lone
    /// significant record against another.
    pub(crate) fn analysis() -> (Analysis, BTreeSet<String>) {
        let mut obs: Vec<Observation> = (0..6)
            .map(|i| Observation {
                id: format!("r{i}"),
                source: "wayback".into(),
                ts: 1_791_000_000 + i * 30,
                url: format!(
                    "https://r.jina.ai/https://portal.example.gov/q?id=1'%20OR%201=1--&uqtag=run7&n={i}"
                ),
                ..Default::default()
            })
            .collect();
        obs.push(Observation {
            id: "lone".into(),
            source: "lines".into(),
            ts: 1_791_000_000 + 90 * 86_400 / 10,
            url: "https://r.jina.ai/https://other.example.org/q?id=1'%20OR%201=1--".into(),
            ..Default::default()
        });
        let a = analyze(obs, &Rules::default_rules());
        let ids = a.results.iter().map(|r| r.obs.id.clone()).collect();
        (a, ids)
    }

    fn tmp(name: &str) -> std::path::PathBuf {
        let d =
            std::env::temp_dir().join(format!("swarmchase-triage-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn leads_are_new_clusters_and_lone_significant_records() {
        let (a, ids) = analysis();
        let next = super::super::digest::summarise(&a, &Summary::default(), "t".into());
        let l = leads(&a, &Summary::default(), &next, &ids);
        assert!(
            l.iter()
                .any(|l| l.kind == LeadKind::Cluster && l.change == "new"),
            "{l:?}"
        );
        let lone = l.iter().find(|l| l.kind == LeadKind::Record).unwrap();
        assert_eq!(lone.id, "lone");
        assert_eq!(lone.targets, ["other[.]example[.]org"]);
        // Sorted strongest first.
        assert!(l.windows(2).all(|w| w[0].tier >= w[1].tier), "{l:?}");
        // Nothing is new the second time.
        assert!(leads(&a, &next, &next, &BTreeSet::new()).is_empty());
    }

    #[test]
    fn asks_within_limits_and_reuses_earlier_answers() {
        let (a, ids) = analysis();
        let next = super::super::digest::summarise(&a, &Summary::default(), "t".into());
        let mut l = leads(&a, &Summary::default(), &next, &ids);
        assert!(l.len() >= 2);
        let first = l[0].record.clone();
        let known = BTreeMap::from([(
            first.clone(),
            Suggestion {
                label: "unsure".into(),
                reason: "earlier".into(),
                model: "m".into(),
            },
        )]);
        let mut calls = 0;
        let (rep, fresh) = ask_all(
            &a,
            &mut l,
            &known,
            Limits {
                max: 1,
                budget: Duration::from_secs(60),
            },
            &mut |_, _, _| {
                calls += 1;
                Some(Suggestion {
                    label: "agent".into(),
                    reason: "relay via r.jina.ai".into(),
                    model: "m".into(),
                })
            },
        );
        assert_eq!(calls, 1);
        assert_eq!((rep.reused, rep.asked, rep.answered), (1, 1, 1));
        assert_eq!(rep.left, l.len() - 2);
        assert_eq!(l[0].suggestion.as_ref().unwrap().reason, "earlier");
        assert_eq!(fresh.len(), 1);
        assert_eq!(fresh[0].1.reason, "relay via r[.]jina[.]ai");
    }

    #[test]
    fn repeated_failures_stop_asking() {
        let (a, ids) = analysis();
        let next = super::super::digest::summarise(&a, &Summary::default(), "t".into());
        let mut l = leads(&a, &Summary::default(), &next, &ids);
        // Pad the leads so there are more than the failure limit.
        let extra = l[0].clone();
        for _ in 0..4 {
            l.push(extra.clone());
        }
        let mut calls = 0;
        let (rep, fresh) = ask_all(
            &a,
            &mut l,
            &BTreeMap::new(),
            Limits {
                max: 50,
                budget: Duration::from_secs(60),
            },
            &mut |_, _, _| {
                calls += 1;
                None
            },
        );
        assert_eq!(calls, MAX_FAILURES_IN_ROW);
        assert!(fresh.is_empty());
        assert!(rep.note.unwrap().contains("failed asks in a row"));
    }

    #[test]
    fn a_fake_local_model_is_asked_and_answers_are_saved_for_review() {
        let (a, ids) = analysis();
        let next = super::super::digest::summarise(&a, &Summary::default(), "t".into());
        let mut l = leads(&a, &Summary::default(), &next, &ids);
        let n = l.len();
        let mut answers = vec![Some(reply(
            "{\"label\": \"agent\", \"reason\": \"relayed SQLi probe on portal.example.gov\"}",
        ))];
        answers.extend((1..n).map(|_| Some("not json".to_string())));
        let (addr, h) = serve_many(answers);
        let s = Suggester::new(&addr, "fake-local", Duration::from_secs(10)).unwrap();
        let (rep, fresh) = ask_all(
            &a,
            &mut l,
            &BTreeMap::new(),
            Limits {
                max: 10,
                budget: Duration::from_secs(30),
            },
            &mut |a, idx, t| s.suggest_within(a, idx, t),
        );
        let sent = h.join().unwrap();
        assert_eq!(sent.len(), n);
        assert!(
            sent.iter()
                .all(|r| r.starts_with("POST /v1/chat/completions "))
        );
        assert!(
            sent.iter().all(|r| !r.contains("https://r.jina.ai")),
            "{sent:?}"
        );
        assert_eq!((rep.asked, rep.answered), (n, 1));
        assert_eq!(fresh[0].1.model, "fake-local");
        assert_eq!(
            fresh[0].1.reason,
            "relayed SQLi probe on portal[.]example[.]gov"
        );

        let d = tmp("save");
        let labels = d.join("labels");
        save(&labels, &fresh, "20261011T000000Z").unwrap();
        save(&labels, &fresh, "20261011T060000Z").unwrap();
        let text = std::fs::read_to_string(labels.join(FILE)).unwrap();
        assert_eq!(text.lines().count(), 2);
        let line: serde_json::Value = serde_json::from_str(text.lines().next().unwrap()).unwrap();
        for k in ["id", "label", "reason", "model", "run"] {
            assert!(line.get(k).is_some(), "{k} in {line}");
        }
        let back = load(&labels);
        assert_eq!(back.len(), 1);
        assert_eq!(back[&fresh[0].0], fresh[0].1);
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn triage_is_off_by_default_and_degrades_without_an_endpoint() {
        let (a, ids) = analysis();
        let next = super::super::digest::summarise(&a, &Summary::default(), "t".into());
        let mut l = leads(&a, &Summary::default(), &next, &ids);
        let d = tmp("off");
        let limits = Limits {
            max: 5,
            budget: Duration::from_secs(5),
        };
        let rep = run(None, &d, &a, &mut l, "t", limits);
        assert!(!rep.enabled && rep.asked == 0);
        assert!(l.iter().all(|l| l.suggestion.is_none()));
        assert!(!d.join("labels").exists());
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn the_backend_comes_from_the_flag_or_the_variable() {
        for (v, want) in [
            ("", None),
            ("0", None),
            ("false", None),
            ("1", Some(Backend::Local)),
            ("TRUE", Some(Backend::Local)),
            ("yes", Some(Backend::Local)),
            ("local", Some(Backend::Local)),
            (" claude ", Some(Backend::Claude)),
        ] {
            assert_eq!(parse_backend(v), Ok(want), "{v}");
        }
        assert!(parse_backend("gpt").is_err());
        assert_eq!(backend(Some(Backend::Claude)), Some(Backend::Claude));
    }

    #[test]
    fn claude_is_sent_hosted_sources_only_and_answers_are_saved_for_review() {
        use crate::suggest::claude::tests::{cli_json, fake_claude};
        let (a, ids) = analysis();
        let next = super::super::digest::summarise(&a, &Summary::default(), "t".into());
        let mut l = leads(&a, &Summary::default(), &next, &ids);
        let cluster = l
            .iter()
            .find(|l| l.kind == LeadKind::Cluster)
            .unwrap()
            .record
            .clone();
        assert!(
            l.iter().any(|l| l.source == "lines"),
            "an operator-log lead"
        );
        let reply = cli_json(&format!(
            r#"[{{"id":"{cluster}","label":"unsure","reason":"relayed SQLi on portal.example.gov, payload only","misfires":["nope"]}},{{"id":"lone","label":"agent","reason":"not asked"}}]"#
        ));
        let fake = fake_claude("triage", &reply, 0, false);
        let cli = ClaudeCli::new(fake.clone(), "claude-opus-5-5");
        let d = tmp("claude");
        let limits = Limits {
            max: 20,
            budget: Duration::from_secs(60),
        };
        let rep = run_claude(&d, &a, &mut l, "20261011T000000Z", limits, &cli);
        let sent = std::fs::read_to_string(fake.parent().unwrap().join("prompt.txt")).unwrap();
        // The operator-log lead never reaches the prompt.
        assert!(!sent.contains("\"id\":\"lone\""), "{sent}");
        assert!(!sent.contains("other[.]example[.]org"), "{sent}");
        assert!(sent.contains(&format!("\"id\":\"{cluster}\"")), "{sent}");
        assert!(sent.contains("\"agent_allowed\""), "{sent}");
        assert_eq!((rep.asked, rep.answered, rep.withheld), (1, 1, 1));
        assert_eq!(rep.backend, "claude");
        assert_eq!(rep.file(), CLAUDE_FILE);
        assert!(rep.note.as_deref().unwrap().contains("withheld"));
        let lone = l.iter().find(|l| l.record == "lone").unwrap();
        assert!(lone.suggestion.is_none());
        let got = l.iter().find(|l| l.record == cluster).unwrap();
        assert_eq!(got.suggestion.as_ref().unwrap().model, "claude-opus-5-5");

        let labels = d.join("labels");
        let text = std::fs::read_to_string(labels.join(CLAUDE_FILE)).unwrap();
        assert_eq!(text.lines().count(), 1);
        let v: serde_json::Value = serde_json::from_str(text.lines().next().unwrap()).unwrap();
        for k in ["id", "label", "reason", "model", "grade", "misfires", "run"] {
            assert!(v.get(k).is_some(), "{k} in {v}");
        }
        assert_eq!(v["misfires"], serde_json::json!([]));
        assert!(
            v["reason"]
                .as_str()
                .unwrap()
                .contains("portal[.]example[.]gov")
        );

        // Review reads the file as a hosted model's: a line for an
        // operator-log record is dropped as withheld.
        let mut f = text.clone();
        f += "{\"id\":\"lone\",\"label\":\"agent\",\"reason\":\"x\",\"model\":\"m\"}\n";
        std::fs::write(labels.join(CLAUDE_FILE), f).unwrap();
        let loaded = crate::review::hosted::load_suggestions(&labels, &a).unwrap();
        assert!(loaded.by_id.contains_key(&cluster));
        assert_eq!(loaded.withheld, 1);

        // The next run reuses the answer and asks nothing.
        let mut l2 = leads(&a, &Summary::default(), &next, &ids);
        let rep = run_claude(&d, &a, &mut l2, "t2", limits, &cli);
        assert_eq!((rep.asked, rep.reused), (0, 1));
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn a_usage_limit_stops_claude_for_the_run() {
        let obs: Vec<Observation> = (0..60)
            .map(|i| Observation {
                id: format!("w{i}"),
                source: "wayback".into(),
                ts: 1_791_000_000 + i * 30,
                url: format!(
                    "https://r.jina.ai/https://portal.example.gov/q?id=1'%20OR%201=1--&n={i}"
                ),
                ..Default::default()
            })
            .collect();
        let a = analyze(obs, &Rules::default_rules());
        let ids: BTreeSet<String> = a.results.iter().map(|r| r.obs.id.clone()).collect();
        let next = super::super::digest::summarise(&a, &Summary::default(), "t".into());
        let one = leads(&a, &Summary::default(), &next, &ids).remove(0);
        let mut l: Vec<Lead> = (0..a.results.len())
            .map(|i| Lead {
                idx: i,
                record: a.results[i].obs.id.clone(),
                ..one.clone()
            })
            .collect();
        let mut calls = 0;
        let (rep, fresh) = ask_claude(
            &a,
            &mut l,
            &BTreeMap::new(),
            Limits {
                max: 50,
                budget: Duration::from_secs(60),
            },
            &mut |lines, _| {
                calls += 1;
                assert_eq!(lines.len(), CLAUDE_CHUNK);
                Outcome::Limited("Claude usage limit: resets 3pm".into())
            },
        );
        assert_eq!(calls, 1);
        assert!(fresh.is_empty());
        assert_eq!(
            (rep.asked, rep.answered, rep.left),
            (CLAUDE_CHUNK, 0, 60 - CLAUDE_CHUNK)
        );
        assert!(rep.note.unwrap().contains("no more asks this run"));

        // Two failed calls in a row also stop it.
        let mut calls = 0;
        let (rep, _) = ask_claude(
            &a,
            &mut l,
            &BTreeMap::new(),
            Limits {
                max: 80,
                budget: Duration::from_secs(60),
            },
            &mut |_, _| {
                calls += 1;
                Outcome::Failed("Claude Code failed: boom".into())
            },
        );
        assert_eq!(calls, 2);
        assert!(rep.note.unwrap().contains("boom"));
    }

    #[test]
    fn an_agent_suggestion_below_l2_is_against_the_rule() {
        let (a, ids) = analysis();
        let next = super::super::digest::summarise(&a, &Summary::default(), "t".into());
        let mut l = leads(&a, &Summary::default(), &next, &ids).remove(0);
        let s = |label: &str| Suggestion {
            label: label.into(),
            reason: String::new(),
            model: "m".into(),
        };
        l.grade = AgentLevel::SelfDescribed;
        l.suggestion = Some(s("agent"));
        assert!(l.against_rule());
        l.suggestion = Some(s("unsure"));
        assert!(!l.against_rule());
        l.grade = AgentLevel::ModelWritten;
        l.suggestion = Some(s("agent"));
        assert!(!l.against_rule());
    }
}
