//! The platform pass: coordinated-account swarms on GitHub, package
//! registries, the Hugging Face Hub, Wikimedia wikis and Hacker News
//! (`sc_core::platform`).
//!
//! Each run pulls the watchlist's `[[platform.source]]` entries, adds the
//! events carried from earlier runs, and groups them. Only events worth
//! another look are carried (`<out>/platform/carry.ndjson`): members of a
//! multi-account group and events carrying residue, for `carry_hours`. The
//! full stream is never stored. The candidates go to
//! `runs/<stamp>/platform-swarms.json` and a digest section that lists new
//! and grown ones, weak ones past [`SHOWN_WEAK`] summed by platform.
//!
//! What earlier runs saw is kept in `<out>/platform/baseline.json`
//! ([`sc_core::platform::Baseline`]): the stretch of each platform read in
//! each run and the burst chances of the groups weighed, for `carry_hours`,
//! and the families seen bursting, for `history_days`. Bursts are weighed
//! over the time read, not at all under an hour of it, never below the share
//! of earlier groups that burst as tightly, and a family that burst in an
//! earlier window is not a fresh burst. Candidates never become triage leads: the hosted triage
//! model may see archive and urlquery records only (docs/policies.md).
//!
//! Reference sources (`osv`, `wikimedia-ai-cleanup`) give labels, not
//! events: a package OSV lists as malicious, a wiki page tagged as
//! suspected AI-generated text. Labels are kept in
//! `<out>/platform/labels.ndjson` for `label_days`, and a candidate whose
//! members acted on a labelled target says so in the digest.
//!
//! Build provenance is looked up, not streamed: for the npm and PyPI
//! candidates new or grown this run, up to `provenance_lookups` member
//! releases a run, members on an OSV-labelled package first
//! (`sc_collect::provenance`). Answers are kept in
//! `<out>/platform/provenance.ndjson` for `label_days`, so a release is
//! looked up once, and each npm or PyPI candidate carries what its members'
//! answers say ([`sc_core::platform::CandidateProvenance`]).

use crate::store::{read_json, write_json};
use anyhow::Result;
use sc_collect::Client;
use sc_collect::platform::{PlatformSource, TargetLabel, label_key, pull_platform};
use sc_core::platform::{
    Baseline, CandidateProvenance, PackageProvenance, Platform, PlatformEvent, PlatformOptions,
    PlatformReport, PlatformSwarm, detect_with,
};
use sc_core::{Rules, defang, defang_host, fmt_ts};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::Path;

/// The watchlist's `[platform]` table.
#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    /// How long events worth another look are carried between runs.
    #[serde(default = "default_carry")]
    pub carry_hours: i64,
    #[serde(default)]
    pub options: PlatformOptions,
    /// How long labels from reference sources are kept.
    #[serde(default = "default_label_days")]
    pub label_days: i64,
    /// How long families seen bursting are remembered.
    #[serde(default = "default_history_days")]
    pub history_days: i64,
    /// Package releases whose build provenance one run looks up at most;
    /// 0 turns the lookups off.
    #[serde(default = "default_provenance_lookups")]
    pub provenance_lookups: usize,
    #[serde(default, rename = "source")]
    pub sources: Vec<PlatformSource>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            carry_hours: default_carry(),
            label_days: default_label_days(),
            history_days: default_history_days(),
            provenance_lookups: default_provenance_lookups(),
            options: PlatformOptions::default(),
            sources: Vec::new(),
        }
    }
}

fn default_carry() -> i64 {
    72
}

fn default_label_days() -> i64 {
    30
}

fn default_history_days() -> i64 {
    30
}

/// Weak candidates the digest shows in full; the rest are summed by
/// platform.
pub const SHOWN_WEAK: usize = 10;

fn default_provenance_lookups() -> usize {
    40
}

/// `<out>/platform/state.json`.
#[derive(Debug, Default, Serialize, Deserialize)]
struct State {
    /// GH Archive sources: the next hour to read.
    #[serde(default)]
    marks: BTreeMap<String, u64>,
    /// Candidates already in a digest: id to (events, last event time).
    #[serde(default)]
    reported: BTreeMap<String, (usize, i64)>,
}

/// One source's line in the section.
#[derive(Debug, Default)]
pub struct SourceLine {
    pub name: String,
    pub events: usize,
    pub coverage: String,
    pub automation: usize,
    pub capped: usize,
    /// Declared coding-agent App events by product.
    pub declared: BTreeMap<String, usize>,
    /// Lookalike App logins: login to (product claimed, events).
    pub lookalikes: BTreeMap<String, (String, usize)>,
    /// Labels a reference source gave this run.
    pub labels: usize,
    pub error: Option<String>,
    /// The pull stopped part way: what it read is kept, and the next run
    /// reads the rest.
    pub stopped: Option<String>,
}

/// A candidate's members that acted on labelled targets.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct LabelMatch {
    /// The label kind (`osv-malicious`, `wiki-ai-cleanup`).
    pub kind: String,
    /// Member events on a target with this label.
    pub members: usize,
    /// The labelled targets, at most five.
    pub targets: Vec<String>,
    /// The records that gave the labels, at most five.
    pub sources: Vec<String>,
}

/// What the pass found, for the digest.
#[derive(Debug, Default)]
pub struct Outcome {
    pub report: PlatformReport,
    pub sources: Vec<SourceLine>,
    pub carried: usize,
    /// Candidate ids new this run, and grown since they were reported.
    pub new: BTreeSet<String>,
    pub grown: BTreeSet<String>,
    /// Labels kept from reference sources.
    pub labels: usize,
    /// Candidate id to its members on labelled targets.
    pub labelled: BTreeMap<String, Vec<LabelMatch>>,
    /// Provenance lookups made this run, and how many failed.
    pub provenance_lookups: usize,
    pub provenance_failed: usize,
}

impl Outcome {
    pub fn changed(&self) -> bool {
        !self.new.is_empty() || !self.grown.is_empty()
    }
}

/// Run the pass. `None` when the watchlist has no platform sources.
pub fn run(
    client: &Client,
    out: &Path,
    run_dir: &Path,
    now: i64,
    cfg: &Config,
    rules: &Rules,
) -> Result<Option<Outcome>> {
    if cfg.sources.is_empty() {
        return Ok(None);
    }
    let dir = out.join("platform");
    std::fs::create_dir_all(&dir)?;
    let state_path = dir.join("state.json");
    let mut state: State = read_json(&state_path)?.unwrap_or_default();
    let carry_path = dir.join("carry.ndjson");
    let cutoff = now - cfg.carry_hours.max(1) * 3600;
    let mut batch: Vec<PlatformEvent> = load_events(&carry_path)?
        .into_iter()
        .filter(|e| e.ts >= cutoff)
        .collect();
    let mut outcome = Outcome {
        carried: batch.len(),
        ..Default::default()
    };
    let baseline_path = dir.join("baseline.json");
    let mut baseline: Baseline = read_json(&baseline_path)?.unwrap_or_default();
    baseline.prune(cutoff, now - cfg.history_days.max(1) * 86_400);
    let mut new_labels: Vec<TargetLabel> = Vec::new();
    for src in &cfg.sources {
        eprint!("{:<24} platform {} … ", src.name, src.kind);
        let mut line = SourceLine {
            name: src.name.clone(),
            ..Default::default()
        };
        match pull_platform(client, src, state.marks.get(&src.name).copied(), rules) {
            Ok(p) => {
                if let Some(next) = p.coverage.next {
                    state.marks.insert(src.name.clone(), next);
                }
                eprintln!("{} events ({})", p.events.len(), p.coverage.line());
                line.events = p.events.len();
                line.coverage = p.coverage.line();
                line.automation = p.automation;
                line.capped = p.capped;
                line.declared = p.declared;
                line.lookalikes = p.lookalikes;
                line.labels = p.labels.len();
                note_read(&mut baseline, &p.events);
                if let Some(e) = &p.stopped {
                    eprintln!("  stopped early: {e}");
                    line.stopped = Some(crate::util::one_line(e, 200));
                }
                batch.extend(p.events);
                new_labels.extend(p.labels);
            }
            Err(e) => {
                eprintln!("error: {e:#}");
                line.error = Some(crate::watch::digest::short_reason(&e));
            }
        }
        outcome.sources.push(line);
        write_json(&state_path, &state)?;
    }
    let mut report = detect_with(&batch, &cfg.options, &baseline);
    baseline.record(&report.weighed, now);
    write_json(&baseline_path, &baseline)?;

    let labels_path = dir.join("labels.ndjson");
    let label_cutoff = now - cfg.label_days.max(1) * 86_400;
    let mut labels: Vec<TargetLabel> = if labels_path.exists() {
        crate::store::read_ndjson(&labels_path)?.0
    } else {
        Vec::new()
    };
    labels.extend(new_labels);
    labels.retain(|l| l.ts >= label_cutoff);
    labels.sort();
    labels.dedup();
    let mut text = String::new();
    for l in &labels {
        text.push_str(&serde_json::to_string(l)?);
        text.push('\n');
    }
    crate::store::write_atomic(&labels_path, text.as_bytes())?;
    outcome.labels = labels.len();
    outcome.labelled = match_labels(&report, &batch, &labels);
    if !outcome.labelled.is_empty() {
        write_json(&run_dir.join("platform-labels.json"), &outcome.labelled)?;
    }

    for s in &report.swarms {
        match state.reported.get(&s.id) {
            None => {
                outcome.new.insert(s.id.clone());
            }
            Some((n, _)) if s.events > *n => {
                outcome.grown.insert(s.id.clone());
            }
            _ => {}
        }
        state.reported.insert(s.id.clone(), (s.events, s.end));
    }

    // Build provenance of the reported registry candidates' releases.
    let prov_path = dir.join("provenance.ndjson");
    let mut known: BTreeMap<String, ProvenanceAnswer> = if prov_path.exists() {
        crate::store::read_ndjson::<ProvenanceAnswer>(&prov_path)?
            .0
            .into_iter()
            .filter(|a| a.ts >= label_cutoff)
            .map(|a| (a.member.clone(), a))
            .collect()
    } else {
        BTreeMap::new()
    };
    let wanted = provenance_queue(&report, &outcome, &batch, &labels, &known);
    if cfg.provenance_lookups > 0 && !wanted.is_empty() {
        eprint!("{:<24} provenance … ", "package-provenance");
        let mut failures_in_row = 0;
        for member in wanted.into_iter().take(cfg.provenance_lookups) {
            outcome.provenance_lookups += 1;
            match client.package_provenance(&member) {
                Ok(found) => {
                    failures_in_row = 0;
                    let answer = ProvenanceAnswer {
                        member: member.clone(),
                        ts: now,
                        found,
                    };
                    known.insert(member, answer);
                }
                Err(e) => {
                    outcome.provenance_failed += 1;
                    failures_in_row += 1;
                    if failures_in_row >= 3 {
                        eprint!("stopped after 3 failures in a row ({e:#}) … ");
                        break;
                    }
                }
            }
        }
        eprintln!(
            "{} lookup(s), {} failed",
            outcome.provenance_lookups, outcome.provenance_failed
        );
    }
    let mut text = String::new();
    for a in known.values() {
        text.push_str(&serde_json::to_string(a)?);
        text.push('\n');
    }
    crate::store::write_atomic(&prov_path, text.as_bytes())?;
    attach_provenance(&mut report, &known);

    // Carry what may join a group later; the rest of the stream is dropped.
    let keep: BTreeSet<&str> = report.carry.iter().map(String::as_str).collect();
    let mut seen = BTreeSet::new();
    let mut carry = String::new();
    for e in &batch {
        if e.ts >= cutoff && keep.contains(e.id.as_str()) && seen.insert(e.id.as_str()) {
            carry.push_str(&serde_json::to_string(e)?);
            carry.push('\n');
        }
    }
    crate::store::write_atomic(&carry_path, carry.as_bytes())?;

    state.reported.retain(|_, (_, end)| *end >= cutoff);
    write_json(&state_path, &state)?;
    write_json(&run_dir.join("platform-swarms.json"), &report)?;
    outcome.report = report;
    Ok(Some(outcome))
}

/// Note in `baseline` the stretch each platform was read: from a pull's
/// first event to its last.
pub fn note_read(baseline: &mut Baseline, events: &[PlatformEvent]) {
    let mut span: BTreeMap<Platform, (i64, i64)> = BTreeMap::new();
    for e in events {
        let s = span.entry(e.platform).or_insert((e.ts, e.ts));
        s.0 = s.0.min(e.ts);
        s.1 = s.1.max(e.ts);
    }
    for (p, (from, to)) in span {
        baseline.add_read(p, from, to);
    }
}

/// Each candidate's members that acted on a labelled target, by label kind.
pub fn match_labels(
    report: &PlatformReport,
    events: &[PlatformEvent],
    labels: &[TargetLabel],
) -> BTreeMap<String, Vec<LabelMatch>> {
    let mut by_target: BTreeMap<(sc_core::platform::Platform, &str), Vec<&TargetLabel>> =
        BTreeMap::new();
    for l in labels {
        by_target
            .entry((l.platform, l.target.as_str()))
            .or_default()
            .push(l);
    }
    let by_id: BTreeMap<&str, &PlatformEvent> = events.iter().map(|e| (e.id.as_str(), e)).collect();
    let mut out = BTreeMap::new();
    for s in &report.swarms {
        let mut kinds: BTreeMap<&str, LabelMatch> = BTreeMap::new();
        for id in &s.members {
            let Some(e) = by_id.get(id.as_str()) else {
                continue;
            };
            let key = label_key(e.platform, &e.target);
            let Some(ls) = by_target.get(&(e.platform, key.as_str())) else {
                continue;
            };
            let mut counted = BTreeSet::new();
            for l in ls {
                let m = kinds.entry(&l.kind).or_insert_with(|| LabelMatch {
                    kind: l.kind.clone(),
                    ..Default::default()
                });
                if counted.insert(l.kind.as_str()) {
                    m.members += 1;
                }
                if m.targets.len() < 5 && !m.targets.contains(&l.target) {
                    m.targets.push(l.target.clone());
                }
                if m.sources.len() < 5 && !m.sources.contains(&l.source_id) {
                    m.sources.push(l.source_id.clone());
                }
            }
        }
        if !kinds.is_empty() {
            out.insert(s.id.clone(), kinds.into_values().collect());
        }
    }
    out
}

/// One release's provenance lookup, kept in `platform/provenance.ndjson`:
/// `found` is `None` when the release carries none.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProvenanceAnswer {
    pub member: String,
    /// When it was looked up (Unix seconds).
    pub ts: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub found: Option<PackageProvenance>,
}

/// Members whose provenance to look up, in order: from the npm and PyPI
/// candidates new or grown this run, one member per candidate in turn,
/// each candidate's members on an OSV-labelled package first. Members
/// already answered are left out.
pub fn provenance_queue(
    report: &PlatformReport,
    outcome: &Outcome,
    events: &[PlatformEvent],
    labels: &[TargetLabel],
    known: &BTreeMap<String, ProvenanceAnswer>,
) -> Vec<String> {
    let malicious: BTreeSet<(Platform, &str)> = labels
        .iter()
        .filter(|l| l.kind == "osv-malicious")
        .map(|l| (l.platform, l.target.as_str()))
        .collect();
    let by_id: BTreeMap<&str, &PlatformEvent> = events.iter().map(|e| (e.id.as_str(), e)).collect();
    let mut lists: Vec<Vec<&str>> = Vec::new();
    for s in &report.swarms {
        if !matches!(s.platform, Platform::Npm | Platform::Pypi)
            || !(outcome.new.contains(&s.id) || outcome.grown.contains(&s.id))
        {
            continue;
        }
        let (mut first, mut rest): (Vec<&str>, Vec<&str>) = (Vec::new(), Vec::new());
        for m in &s.members {
            if known.contains_key(m) || sc_collect::provenance::split_member(m).is_none() {
                continue;
            }
            let labelled = by_id.get(m.as_str()).is_some_and(|e| {
                let key = label_key(e.platform, &e.target);
                malicious.contains(&(e.platform, key.as_str()))
            });
            if labelled {
                first.push(m);
            } else {
                rest.push(m);
            }
        }
        first.extend(rest);
        if !first.is_empty() {
            lists.push(first);
        }
    }
    let mut out = Vec::new();
    let mut seen = BTreeSet::new();
    let longest = lists.iter().map(Vec::len).max().unwrap_or(0);
    for i in 0..longest {
        for l in &lists {
            if let Some(m) = l.get(i)
                && seen.insert(*m)
            {
                out.push(m.to_string());
            }
        }
    }
    out
}

/// Put each candidate's members' answers on it.
pub fn attach_provenance(report: &mut PlatformReport, known: &BTreeMap<String, ProvenanceAnswer>) {
    for s in &mut report.swarms {
        let answers: Vec<&ProvenanceAnswer> =
            s.members.iter().filter_map(|m| known.get(m)).collect();
        if answers.is_empty() {
            continue;
        }
        let records = answers.iter().filter_map(|a| a.found.clone()).collect();
        s.provenance = Some(CandidateProvenance::new(answers.len(), records));
    }
}

/// A candidate's provenance line for the digest, or `None` when nothing
/// was looked up. Repositories and workflows are defanged as targets are.
pub fn provenance_line(s: &PlatformSwarm) -> Option<String> {
    let p = s.provenance.as_ref()?;
    if p.with == 0 {
        return Some(format!(
            "- Provenance (weak context): none of {} member release(s) looked up carries build provenance.",
            p.looked_up
        ));
    }
    let list = |v: &[(String, usize)]| {
        v.iter()
            .take(5)
            .map(|(k, n)| format!("`{}` ({n})", defang_host(k).replace('`', "'")))
            .collect::<Vec<_>>()
            .join(", ")
    };
    let mut t = format!(
        "- Provenance: {} of {} member release(s) looked up name a source; repositories {}",
        p.with,
        p.looked_up,
        list(&p.repos)
    );
    if !p.workflows.is_empty() {
        let _ = write!(t, "; workflows {}", list(&p.workflows));
    }
    t.push('.');
    let shared = if p.shared_workflow {
        Some("workflow")
    } else if p.shared_repo {
        Some("repository")
    } else {
        None
    };
    if let Some(what) = shared {
        let _ = write!(
            t,
            " Several packages name one {what}: a same-operator hint, still a hint (a monorepo publishes many packages from one)."
        );
    }
    Some(t)
}

/// What a label kind says, for the digest.
fn label_phrase(kind: &str) -> &str {
    match kind {
        "osv-malicious" => "packages OSV lists as malicious",
        "wiki-ai-cleanup" => "wiki pages editors tagged as suspected AI-generated text",
        k => k,
    }
}

/// Platform events from NDJSON; blank and unreadable lines are skipped.
pub fn load_events(p: &Path) -> Result<Vec<PlatformEvent>> {
    if !p.exists() {
        return Ok(Vec::new());
    }
    Ok(crate::store::read_ndjson(p)?.0)
}

/// The digest section.
pub fn section(o: &Outcome) -> String {
    let r = &o.report;
    let mut t = String::new();
    let shown: Vec<&PlatformSwarm> = r
        .swarms
        .iter()
        .filter(|s| o.new.contains(&s.id) || o.grown.contains(&s.id))
        .collect();
    let _ = writeln!(t, "\n## Platform swarm hints ({})\n", shown.len());
    let _ = writeln!(
        t,
        "Hints, not findings: groups of accounts acting alike on public platforms. {} event(s) from {} account(s) read, {} carried from earlier runs; {} candidate(s), {} new, {} grown, {} below the chance threshold.\n",
        r.events,
        r.accounts,
        o.carried,
        r.swarms.len(),
        o.new.len(),
        o.grown.len(),
        r.below_threshold
    );
    for l in &o.sources {
        match &l.error {
            Some(e) => {
                let _ = writeln!(t, "- `{}` failed ({e}).", l.name);
            }
            None => {
                let _ = writeln!(
                    t,
                    "- `{}`: {} event(s) kept, {}; {} automation event(s) dropped{}.",
                    l.name,
                    l.events,
                    l.coverage,
                    l.automation,
                    if l.capped > 0 {
                        format!(", {} over the cap", l.capped)
                    } else {
                        String::new()
                    }
                );
                if let Some(e) = &l.stopped {
                    let _ = writeln!(
                        t,
                        "  - Stopped part way ({e}); the next run reads the rest from the same checkpoint."
                    );
                }
                if !l.declared.is_empty() {
                    let d: Vec<String> =
                        l.declared.iter().map(|(k, n)| format!("{k} {n}")).collect();
                    let _ = writeln!(
                        t,
                        "  - Declared coding-agent Apps (tallied, not grouped): {}.",
                        d.join(", ")
                    );
                }
                if l.labels > 0 {
                    let _ = writeln!(
                        t,
                        "  - {} label(s) from this reference source ({} kept).",
                        l.labels, o.labels
                    );
                }
                for (login, (claim, n)) in &l.lookalikes {
                    let _ = writeln!(
                        t,
                        "  - Spoofing lead: App `{}` ({n} event(s)) claims {claim} by name but is not its declared App; check who owns it.",
                        login.replace('`', "'")
                    );
                }
            }
        }
    }
    if o.provenance_lookups > 0 {
        let _ = writeln!(
            t,
            "- Package provenance: {} release(s) looked up for new and grown registry candidates, {} failed.",
            o.provenance_lookups, o.provenance_failed
        );
    }
    t.push('\n');
    // Every moderate candidate, and the first weak ones; the rest summed.
    let mut weak = 0;
    let mut rolled: BTreeMap<&str, usize> = BTreeMap::new();
    for s in shown {
        if s.strength == sc_core::platform::HintStrength::Weak {
            weak += 1;
            if weak > SHOWN_WEAK {
                *rolled.entry(s.platform.name()).or_default() += 1;
                continue;
            }
        }
        let tag = if o.new.contains(&s.id) {
            "new"
        } else {
            "grown"
        };
        t.push_str(&render_swarm(s, Some(tag)));
        for m in o.labelled.get(&s.id).into_iter().flatten() {
            let targets: Vec<String> = m.targets.iter().map(|x| defang_host(x)).collect();
            let _ = writeln!(
                t,
                "- Labelled: {} member(s) acted on {} ({}; {}).\n",
                m.members,
                label_phrase(&m.kind),
                targets.join(", "),
                m.sources.join(", ")
            );
        }
    }
    if !rolled.is_empty() {
        let n: usize = rolled.values().sum();
        let by: Vec<String> = rolled.iter().map(|(p, n)| format!("{p} {n}")).collect();
        let _ = writeln!(
            t,
            "And {n} more weak hint(s), not shown ({}); every candidate is in `platform-swarms.json`.\n",
            by.join(", ")
        );
    }
    t.push_str(&render_suppressed(r));
    t
}

/// One candidate as Markdown. Links and dotted names are defanged.
pub fn render_swarm(s: &PlatformSwarm, tag: Option<&str>) -> String {
    let mut t = String::new();
    let strength = match s.strength {
        sc_core::platform::HintStrength::Weak => "weak",
        sc_core::platform::HintStrength::Moderate => "moderate",
    };
    let _ = writeln!(
        t,
        "### {} ({}, {strength}{})\n",
        s.id,
        s.platform.name(),
        tag.map(|x| format!(", {x}")).unwrap_or_default()
    );
    let _ = writeln!(t, "- {}.", s.reason);
    let _ = writeln!(
        t,
        "- {} to {}; joined by {}.",
        fmt_ts(s.start),
        fmt_ts(s.end),
        s.basis
            .iter()
            .map(|b| match b {
                sc_core::platform::Basis::NearDuplicate => "near-duplicate text",
                sc_core::platform::Basis::Template => "a shared template",
                sc_core::platform::Basis::NameTemplate => "templated names",
                sc_core::platform::Basis::Target => "one target",
            })
            .collect::<Vec<_>>()
            .join(", ")
    );
    if !s.template.is_empty() {
        let _ = writeln!(t, "- Template: `{}`", s.template.replace('`', "'"));
    }
    let targets: Vec<String> = s
        .targets
        .iter()
        .map(|(x, n)| format!("{} ({n})", defang_host(x)))
        .collect();
    let _ = writeln!(
        t,
        "- Targets ({}): {}",
        s.distinct_targets,
        targets.join(", ")
    );
    if !s.residue.is_empty() {
        let r: Vec<String> = s
            .residue
            .iter()
            .map(|(k, n)| format!("{k} ({n})"))
            .collect();
        let _ = writeln!(t, "- Residue: {}", r.join(", "));
    }
    if !s.self_id.is_empty() {
        let r: Vec<String> = s
            .self_id
            .iter()
            .map(|(k, n)| format!("{k} ({n})"))
            .collect();
        let _ = writeln!(t, "- Harness self-identification (weak): {}", r.join(", "));
    }
    if let Some(line) = provenance_line(s) {
        let _ = writeln!(t, "{line}");
    }
    if !s.caveats.is_empty() {
        let _ = writeln!(t, "- Rule out: {}.", s.caveats.join("; "));
    }
    for l in s.links.iter().take(5) {
        let _ = writeln!(t, "  - {}", defang(l));
    }
    t.push('\n');
    t
}

fn render_suppressed(r: &PlatformReport) -> String {
    if r.suppressed.is_empty() {
        return String::new();
    }
    let mut by: BTreeMap<&str, (usize, usize, usize)> = BTreeMap::new();
    for s in &r.suppressed {
        let e = by.entry(&s.why).or_default();
        e.0 += 1;
        e.1 += s.events;
        e.2 += s.accounts;
    }
    let parts: Vec<String> = by
        .iter()
        .map(|(w, (g, e, a))| format!("{w}: {g} group(s), {e} event(s), {a} account(s)"))
        .collect();
    format!("Suppressed as benign templates: {}.\n", parts.join("; "))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_committed_watchlist_platform_sources_parse() {
        let wl: super::super::Watchlist =
            toml::from_str(include_str!("../../../../watchlist.toml")).unwrap();
        for s in &wl.platform.sources {
            assert!(
                sc_collect::platform::PLATFORM_KINDS.contains(&s.kind.as_str()),
                "{}",
                s.kind
            );
        }
        assert!(wl.platform.carry_hours > 0);
    }

    #[test]
    fn the_section_shows_the_first_weak_hints_and_sums_the_rest() {
        let mut swarms = Vec::new();
        for i in 0..14 {
            let platform = if i < 12 {
                Platform::Bluesky
            } else {
                Platform::Nuget
            };
            swarms.push(registry_swarm(&format!("PS-{i:08x}"), platform, &["x"]));
        }
        let mut strong = registry_swarm("PS-moderate", Platform::Github, &["y"]);
        strong.strength = sc_core::platform::HintStrength::Moderate;
        swarms.insert(0, strong);
        let o = Outcome {
            new: swarms.iter().map(|s| s.id.clone()).collect(),
            report: PlatformReport {
                swarms,
                ..Default::default()
            },
            ..Default::default()
        };
        let t = section(&o);
        assert!(t.contains("## Platform swarm hints (15)"), "{t}");
        assert!(t.contains("### PS-moderate (github, moderate, new)"), "{t}");
        assert_eq!(t.matches("### PS-").count(), 1 + SHOWN_WEAK, "{t}");
        assert!(
            t.contains("And 4 more weak hint(s), not shown (bluesky 2, nuget 2)"),
            "{t}"
        );
    }

    #[test]
    fn a_pull_notes_the_stretch_each_platform_was_read() {
        let ev = |platform, ts| PlatformEvent {
            id: format!("e{ts}"),
            platform,
            ts,
            ..Default::default()
        };
        let mut b = Baseline::default();
        note_read(
            &mut b,
            &[
                ev(Platform::Bluesky, 1300),
                ev(Platform::Bluesky, 100),
                ev(Platform::HuggingFace, 50),
            ],
        );
        note_read(
            &mut b,
            &[ev(Platform::Bluesky, 1200), ev(Platform::Bluesky, 4000)],
        );
        assert_eq!(b.read_secs(Platform::Bluesky), Some(3900));
        assert_eq!(b.read_secs(Platform::HuggingFace), Some(0));
        assert_eq!(b.read_secs(Platform::Nuget), None);
    }

    #[test]
    fn the_section_defangs_and_lists_new_candidates() {
        let s = PlatformSwarm {
            id: "PS-0000abcd".into(),
            platform: sc_core::platform::Platform::Github,
            basis: vec![sc_core::platform::Basis::Template],
            actions: vec![],
            events: 4,
            accounts: 4,
            start: 1_791_500_000,
            end: 1_791_500_300,
            template: "critical vulnerability in <path>".into(),
            similarity: Some(1.0),
            burst: Default::default(),
            new_accounts: None,
            residue: vec![("text.chat_opener".into(), 4)],
            self_id: vec![("selfid.claude_code".into(), 2)],
            targets: vec![("some.example/repo".into(), 2)],
            distinct_targets: 3,
            p_chance: 1e-6,
            tested: 1,
            strength: sc_core::platform::HintStrength::Moderate,
            caveats: vec!["no account is new".into()],
            links: vec!["https://github.com/a/b/issues/1".into()],
            members: vec![],
            reason: "4 issues opened".into(),
            provenance: None,
        };
        let o = Outcome {
            report: PlatformReport {
                events: 10,
                accounts: 8,
                swarms: vec![s],
                ..Default::default()
            },
            sources: vec![SourceLine {
                name: "gharchive-coordination".into(),
                declared: [("Codex (OpenAI)".to_string(), 3)].into(),
                lookalikes: [(
                    "claude-fleet[bot]".to_string(),
                    ("Claude GitHub App (Anthropic)".to_string(), 2),
                )]
                .into(),
                ..Default::default()
            }],
            new: ["PS-0000abcd".to_string()].into(),
            ..Default::default()
        };
        let t = section(&o);
        assert!(t.contains("## Platform swarm hints (1)"), "{t}");
        assert!(t.contains("### PS-0000abcd (github, moderate, new)"), "{t}");
        assert!(t.contains("hxxps://github[.]com/a/b/issues/1"), "{t}");
        assert!(t.contains("some[.]example/repo (2)"), "{t}");
        assert!(!t.contains("https://"), "{t}");
        assert!(t.contains("Codex (OpenAI) 3"), "{t}");
        assert!(t.contains("Spoofing lead: App `claude-fleet[bot]`"), "{t}");
        assert!(t.contains("selfid.claude_code (2)"), "{t}");
    }

    fn registry_swarm(id: &str, platform: Platform, members: &[&str]) -> PlatformSwarm {
        PlatformSwarm {
            id: id.into(),
            platform,
            basis: vec![],
            actions: vec![],
            events: members.len(),
            accounts: members.len(),
            start: 0,
            end: 0,
            template: String::new(),
            similarity: None,
            burst: Default::default(),
            new_accounts: None,
            residue: vec![],
            self_id: vec![],
            targets: vec![],
            distinct_targets: members.len(),
            p_chance: 1e-6,
            tested: 1,
            strength: sc_core::platform::HintStrength::Weak,
            caveats: vec![],
            links: vec![],
            members: members.iter().map(|m| m.to_string()).collect(),
            reason: String::new(),
            provenance: None,
        }
    }

    #[test]
    fn provenance_is_queued_for_reported_registry_candidates_labelled_first() {
        let ev = |id: &str, target: &str| PlatformEvent {
            id: id.into(),
            platform: Platform::Npm,
            target: target.into(),
            ..Default::default()
        };
        let events = vec![
            ev("npm:a-1@1.0.0", "a-1"),
            ev("npm:a-2@1.0.0", "a-2"),
            ev("npm:a-3@1.0.0", "a-3"),
            ev("npm:b-1@1.0.0", "b-1"),
        ];
        let report = PlatformReport {
            swarms: vec![
                registry_swarm(
                    "PS-1",
                    Platform::Npm,
                    &["npm:a-1@1.0.0", "npm:a-2@1.0.0", "npm:a-3@1.0.0"],
                ),
                registry_swarm("PS-2", Platform::Npm, &["npm:b-1@1.0.0"]),
                // Not reported this run.
                registry_swarm("PS-3", Platform::Npm, &["npm:c-1@1.0.0"]),
                // Not a registry.
                registry_swarm("PS-4", Platform::Github, &["gh:1"]),
            ],
            ..Default::default()
        };
        let o = Outcome {
            new: ["PS-1".to_string(), "PS-4".to_string()].into(),
            grown: ["PS-2".to_string()].into(),
            ..Default::default()
        };
        let labels = vec![TargetLabel {
            platform: Platform::Npm,
            target: "a-3".into(),
            kind: "osv-malicious".into(),
            source_id: "MAL-2026-9".into(),
            link: String::new(),
            ts: 0,
        }];
        let known: BTreeMap<String, ProvenanceAnswer> = [(
            "npm:a-2@1.0.0".to_string(),
            ProvenanceAnswer {
                member: "npm:a-2@1.0.0".into(),
                ts: 0,
                found: None,
            },
        )]
        .into();
        let q = provenance_queue(&report, &o, &events, &labels, &known);
        assert_eq!(q, ["npm:a-3@1.0.0", "npm:b-1@1.0.0", "npm:a-1@1.0.0"]);
    }

    #[test]
    fn provenance_lines_defang_and_name_a_shared_workflow() {
        let rec = |m: &str, pkg: &str| PackageProvenance {
            member: m.into(),
            package: pkg.into(),
            forge: "github".into(),
            repo: "fleet-op/pkgs.io".into(),
            workflow: ".github/workflows/publish.yml".into(),
            ..Default::default()
        };
        let answer = |m: &str, found: Option<PackageProvenance>| {
            (
                m.to_string(),
                ProvenanceAnswer {
                    member: m.into(),
                    ts: 0,
                    found,
                },
            )
        };
        let known: BTreeMap<String, ProvenanceAnswer> = [
            answer("npm:a-1@1.0.0", Some(rec("npm:a-1@1.0.0", "a-1"))),
            answer("npm:a-2@1.0.0", Some(rec("npm:a-2@1.0.0", "a-2"))),
            answer("npm:a-3@1.0.0", None),
            answer("npm:b-1@1.0.0", None),
        ]
        .into();
        let mut report = PlatformReport {
            swarms: vec![
                registry_swarm(
                    "PS-1",
                    Platform::Npm,
                    &["npm:a-1@1.0.0", "npm:a-2@1.0.0", "npm:a-3@1.0.0"],
                ),
                registry_swarm("PS-2", Platform::Npm, &["npm:b-1@1.0.0"]),
                registry_swarm("PS-3", Platform::Npm, &["npm:c-1@1.0.0"]),
            ],
            ..Default::default()
        };
        attach_provenance(&mut report, &known);
        let p = report.swarms[0].provenance.as_ref().unwrap();
        assert_eq!((p.looked_up, p.with), (3, 2));
        assert!(p.shared_workflow);
        // Provenance changes neither chance nor strength.
        assert_eq!(report.swarms[0].p_chance, 1e-6);
        let t = render_swarm(&report.swarms[0], None);
        assert!(t.contains("2 of 3 member release(s)"), "{t}");
        assert!(t.contains("`github:fleet-op/pkgs[.]io` (2)"), "{t}");
        assert!(t.contains("Several packages name one workflow"), "{t}");
        let t = render_swarm(&report.swarms[1], None);
        assert!(t.contains("Provenance (weak context): none of 1"), "{t}");
        assert!(report.swarms[2].provenance.is_none());
        assert!(!render_swarm(&report.swarms[2], None).contains("Provenance"));
    }

    #[test]
    fn candidates_on_labelled_targets_say_so() {
        use sc_core::platform::Platform;
        let ev = |id: &str, target: &str| PlatformEvent {
            id: id.into(),
            platform: Platform::Pypi,
            target: target.into(),
            ..Default::default()
        };
        let events = vec![
            ev("pypi:Agent_Probe.0042@0.0.1", "Agent_Probe.0042"),
            ev("pypi:agent-probe-0043@0.0.1", "agent-probe-0043"),
            ev("pypi:unrelated@1.0", "unrelated"),
        ];
        let swarm = PlatformSwarm {
            id: "PS-00000001".into(),
            platform: Platform::Pypi,
            basis: vec![],
            actions: vec![],
            events: 3,
            accounts: 0,
            start: 0,
            end: 0,
            template: String::new(),
            similarity: None,
            burst: Default::default(),
            new_accounts: None,
            residue: vec![],
            self_id: vec![],
            targets: vec![],
            distinct_targets: 3,
            p_chance: 1e-6,
            tested: 1,
            strength: sc_core::platform::HintStrength::Weak,
            caveats: vec![],
            links: vec![],
            members: events.iter().map(|e| e.id.clone()).collect(),
            reason: String::new(),
            provenance: None,
        };
        let report = PlatformReport {
            swarms: vec![swarm],
            ..Default::default()
        };
        let label = |target: &str, id: &str, platform| TargetLabel {
            platform,
            target: target.into(),
            kind: "osv-malicious".into(),
            source_id: id.into(),
            link: String::new(),
            ts: 0,
        };
        let labels = vec![
            label("agent-probe-0042", "MAL-2026-1", Platform::Pypi),
            label("agent-probe-0043", "MAL-2026-2", Platform::Pypi),
            // The same name on another platform is another package.
            label("unrelated", "MAL-2026-3", Platform::Npm),
        ];
        let m = match_labels(&report, &events, &labels);
        let got = &m["PS-00000001"];
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].members, 2);
        assert_eq!(got[0].sources, ["MAL-2026-1", "MAL-2026-2"]);
        let o = Outcome {
            new: ["PS-00000001".to_string()].into(),
            report,
            labelled: m,
            ..Default::default()
        };
        let t = section(&o);
        assert!(
            t.contains("Labelled: 2 member(s) acted on packages OSV lists as malicious"),
            "{t}"
        );
    }
}
