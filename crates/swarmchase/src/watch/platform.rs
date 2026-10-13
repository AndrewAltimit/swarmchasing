//! The platform pass: coordinated-account swarms on GitHub, npm, PyPI and
//! the Hugging Face Hub (`sc_core::platform`).
//!
//! Each run pulls the watchlist's `[[platform.source]]` entries, adds the
//! events carried from earlier runs, and groups them. Only events worth
//! another look are carried (`<out>/platform/carry.ndjson`): members of a
//! multi-account group and events carrying residue, for `carry_hours`. The
//! full stream is never stored. The candidates go to
//! `runs/<stamp>/platform-swarms.json` and a digest section that lists new
//! and grown ones. Candidates never become triage leads: the hosted triage
//! model may see archive and urlquery records only (docs/policies.md).

use crate::store::{read_json, write_json};
use anyhow::Result;
use sc_collect::Client;
use sc_collect::platform::{PlatformSource, pull_platform};
use sc_core::platform::{PlatformEvent, PlatformOptions, PlatformReport, PlatformSwarm, detect};
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
    #[serde(default, rename = "source")]
    pub sources: Vec<PlatformSource>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            carry_hours: default_carry(),
            options: PlatformOptions::default(),
            sources: Vec::new(),
        }
    }
}

fn default_carry() -> i64 {
    72
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
    pub error: Option<String>,
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
                batch.extend(p.events);
            }
            Err(e) => {
                eprintln!("error: {e:#}");
                line.error = Some(crate::watch::digest::short_reason(&e));
            }
        }
        outcome.sources.push(line);
        write_json(&state_path, &state)?;
    }
    let report = detect(&batch, &cfg.options);

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
    state.reported.retain(|_, (_, end)| *end >= cutoff);
    write_json(&state_path, &state)?;
    write_json(&run_dir.join("platform-swarms.json"), &report)?;
    outcome.report = report;
    Ok(Some(outcome))
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
            }
        }
    }
    t.push('\n');
    for s in shown {
        let tag = if o.new.contains(&s.id) {
            "new"
        } else {
            "grown"
        };
        t.push_str(&render_swarm(s, Some(tag)));
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
                ["gharchive", "npm", "pypi", "huggingface"].contains(&s.kind.as_str()),
                "{}",
                s.kind
            );
        }
        assert!(wl.platform.carry_hours > 0);
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
            targets: vec![("some.example/repo".into(), 2)],
            distinct_targets: 3,
            p_chance: 1e-6,
            strength: sc_core::platform::HintStrength::Moderate,
            caveats: vec!["no account is new".into()],
            links: vec!["https://github.com/a/b/issues/1".into()],
            members: vec![],
            reason: "4 issues opened".into(),
        };
        let o = Outcome {
            report: PlatformReport {
                events: 10,
                accounts: 8,
                swarms: vec![s],
                ..Default::default()
            },
            new: ["PS-0000abcd".to_string()].into(),
            ..Default::default()
        };
        let t = section(&o);
        assert!(t.contains("## Platform swarm hints (1)"), "{t}");
        assert!(t.contains("### PS-0000abcd (github, moderate, new)"), "{t}");
        assert!(t.contains("hxxps://github[.]com/a/b/issues/1"), "{t}");
        assert!(t.contains("some[.]example/repo (2)"), "{t}");
        assert!(!t.contains("https://"), "{t}");
    }
}
