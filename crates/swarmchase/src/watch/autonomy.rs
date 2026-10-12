//! Autonomy levels for the watch, run in shadow first.
//!
//! Each level is something the watch could do on its own about a lead in
//! the attention queue ([`super::attention`]). Every one is internal and
//! reversible; sending, publishing and naming are never among them.
//!
//! | Level | Would do | Modes |
//! |---|---|---|
//! | `interrupt` | Raise the run's priority to high, so the digest reaches the admin now | off, shadow, on |
//! | `watch_harder` | Pull the lead's sources more often and watch its targets, passively | off, shadow |
//! | `draft_case` | Open a draft case, gather contacts and draft the provider report | off, shadow |
//!
//! In **shadow** a level only writes what it would have done to
//! `<data>/autonomy.ndjson`. Over later runs the admin's own decisions (a
//! label on the lead's records, a case covering them) are read against
//! those lines ([`agreement`]), so a level is switched on only when the
//! record shows it would have been right. Only `interrupt` can be on today;
//! on, it adds a high reason to the run's priority and nothing else.
//!
//! Every trigger needs grade L2 or higher: anyone can write a self-
//! description, so L0 and L1 leads never set a level off. `interrupt` is
//! rate-limited per day, and each level fires once per thread per period.

use super::attention::{Band, Item, Queue};
use super::ledger::{Ledger, Trajectory};
use super::priority::{Level as Prio, Reason};
use anyhow::{Result, bail};
use sc_core::agentness::AgentLevel;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

/// The log, in the data directory.
pub const FILE: &str = "autonomy.ndjson";

const HOUR: i64 = 3600;
const DAY: i64 = 86_400;
/// A level fires at most once per thread in this long.
const INTERRUPT_EVERY: i64 = DAY;
const WATCH_EVERY: i64 = 7 * DAY;
/// A draft case needs the lead urgent on this many runs in a row, spanning
/// at least this long.
const DRAFT_RUNS: usize = 2;
const DRAFT_HELD: i64 = 12 * HOUR;
/// A shadow draft case no case followed in this long counts as disagreed.
const DRAFT_DECIDED_AFTER: i64 = 14 * DAY;
/// Growth in a day that interrupts.
const INTERRUPT_GROWTH: f64 = 3.0;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    Off,
    #[default]
    Shadow,
    On,
}

impl Mode {
    pub fn label(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Shadow => "shadow",
            Self::On => "on",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Level {
    Interrupt,
    WatchHarder,
    DraftCase,
}

impl Level {
    pub const ALL: [Level; 3] = [Self::Interrupt, Self::WatchHarder, Self::DraftCase];

    pub fn label(self) -> &'static str {
        match self {
            Self::Interrupt => "interrupt",
            Self::WatchHarder => "watch_harder",
            Self::DraftCase => "draft_case",
        }
    }
}

/// `[autonomy]` in the watchlist.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub interrupt: Mode,
    #[serde(default)]
    pub watch_harder: Mode,
    #[serde(default)]
    pub draft_case: Mode,
    /// Most interrupts in any 24 hours, shadow or on.
    #[serde(default = "default_per_day")]
    pub interrupts_per_day: usize,
}

fn default_per_day() -> usize {
    3
}

impl Default for Config {
    fn default() -> Self {
        Self {
            interrupt: Mode::Shadow,
            watch_harder: Mode::Shadow,
            draft_case: Mode::Shadow,
            interrupts_per_day: default_per_day(),
        }
    }
}

impl Config {
    pub fn mode(&self, l: Level) -> Mode {
        match l {
            Level::Interrupt => self.interrupt,
            Level::WatchHarder => self.watch_harder,
            Level::DraftCase => self.draft_case,
        }
    }

    /// Reject a mode that is not built.
    pub fn check(&self) -> Result<()> {
        for l in [Level::WatchHarder, Level::DraftCase] {
            if self.mode(l) == Mode::On {
                bail!(
                    "[autonomy] {} = \"on\": only `interrupt` can be on; `{}` runs as off or shadow",
                    l.label(),
                    l.label()
                );
            }
        }
        Ok(())
    }
}

/// One line of the log: what a level did, or would have done.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Decision {
    pub run: String,
    /// The run's time, Unix seconds.
    pub t: i64,
    pub level: Level,
    /// `shadow` or `on`.
    pub mode: Mode,
    pub thread: String,
    /// The cluster's number that run and its key.
    pub cluster: String,
    pub key: String,
    pub band: Band,
    pub grade: String,
    /// The fact that set it off.
    pub trigger: String,
    /// What it did, or would have done.
    pub proposal: String,
    /// Why it was held back, when it was (a rate limit).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub suppressed: Option<String>,
}

impl Decision {
    pub fn acted(&self) -> bool {
        self.suppressed.is_none()
    }
}

/// Read the log; a line that does not parse is skipped.
pub fn load(data: &Path) -> Vec<Decision> {
    std::fs::read_to_string(data.join(FILE))
        .unwrap_or_default()
        .lines()
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect()
}

/// Append `ds` to the log.
pub fn append(data: &Path, ds: &[Decision]) -> Result<()> {
    if ds.is_empty() {
        return Ok(());
    }
    let mut text = String::new();
    for d in ds {
        text.push_str(&serde_json::to_string(d)?);
        text.push('\n');
    }
    crate::store::append(&data.join(FILE), &text)
}

/// Drop lines from before `cutoff`. Returns how many went.
pub fn prune(data: &Path, cutoff: i64) -> Result<usize> {
    let p = data.join(FILE);
    if !p.is_file() {
        return Ok(0);
    }
    let all = load(data);
    let kept: Vec<&Decision> = all.iter().filter(|d| d.t >= cutoff).collect();
    let gone = all.len() - kept.len();
    if gone > 0 {
        let mut text = String::new();
        for d in kept {
            text.push_str(&serde_json::to_string(d)?);
            text.push('\n');
        }
        std::fs::write(&p, text)?;
    }
    Ok(gone)
}

/// This run's decisions, from the queue, the ledger and the earlier log.
pub fn decide(
    q: &Queue,
    ledger: &Ledger,
    cfg: &Config,
    t: i64,
    past: &[Decision],
) -> Vec<Decision> {
    let mut out: Vec<Decision> = Vec::new();
    let fired = |out: &[Decision], l: Level, thread: &str, since: i64| {
        past.iter()
            .chain(out.iter())
            .any(|d| d.level == l && d.thread == thread && d.t >= since && d.acted())
    };
    for it in &q.items {
        if it.grade < AgentLevel::ModelWritten {
            continue;
        }
        let Some(th) = ledger.threads.get(&it.thread) else {
            continue;
        };
        let line = |level, mode, trigger: String, proposal: String| Decision {
            run: q.stamp.clone(),
            t,
            level,
            mode,
            thread: it.thread.clone(),
            cluster: it.id.clone(),
            key: it.key.clone(),
            band: it.band,
            grade: it.grade.code().into(),
            trigger,
            proposal,
            suppressed: None,
        };

        let mode = cfg.interrupt;
        if mode != Mode::Off
            && let Some(trigger) = interrupt_trigger(it, th)
            && !fired(&out, Level::Interrupt, &it.thread, t - INTERRUPT_EVERY + 1)
        {
            let mut d = line(
                Level::Interrupt,
                mode,
                trigger,
                "raise the run's priority to high so the digest reaches the admin now".into(),
            );
            let recent = past
                .iter()
                .chain(out.iter())
                .filter(|x| x.level == Level::Interrupt && x.acted() && x.t > t - DAY)
                .count();
            if recent >= cfg.interrupts_per_day {
                d.suppressed = Some(format!(
                    "rate limit: {} interrupt(s) in 24 hours",
                    cfg.interrupts_per_day
                ));
            }
            out.push(d);
        }

        let mode = cfg.watch_harder;
        if mode != Mode::Off
            && it.band == Band::Urgent
            && !fired(&out, Level::WatchHarder, &it.thread, t - WATCH_EVERY + 1)
        {
            out.push(line(
                Level::WatchHarder,
                mode,
                format!("urgent: {}", it.why.first().cloned().unwrap_or_default()),
                format!(
                    "pull {} more often and watch {} for new records, from passive sources only",
                    it.sources.join(", "),
                    if it.targets.is_empty() {
                        "its targets".to_string()
                    } else {
                        it.targets.join(", ")
                    }
                ),
            ));
        }

        let mode = cfg.draft_case;
        if mode != Mode::Off
            && it.band == Band::Urgent
            && it.cases.is_empty()
            && th.held(Band::Urgent.label(), DRAFT_RUNS, DRAFT_HELD)
            && !fired(&out, Level::DraftCase, &it.thread, i64::MIN)
        {
            out.push(line(
                Level::DraftCase,
                mode,
                format!(
                    "urgent on {DRAFT_RUNS} runs over {} hours or more, and no case covers it",
                    DRAFT_HELD / HOUR
                ),
                format!(
                    "open a draft case from cluster {}, find contacts and draft the provider report for the admin",
                    it.key
                ),
            ));
        }
    }
    out
}

/// Why `it` would interrupt, if it would.
fn interrupt_trigger(it: &Item, th: &super::ledger::Thread) -> Option<String> {
    let prev_band = th
        .points
        .len()
        .checked_sub(2)
        .map(|i| th.points[i].band.as_str());
    if it.band == Band::Urgent && prev_band != Some(Band::Urgent.label()) {
        return Some(format!(
            "entered urgent: {}",
            it.why.first().cloned().unwrap_or_default()
        ));
    }
    if it.band < Band::Look {
        return None;
    }
    match it.trajectory {
        Trajectory::Growing if it.growth.is_some_and(|g| g >= INTERRUPT_GROWTH) => Some(format!(
            "grew {:.1}x in a day at {}",
            it.growth.unwrap_or_default(),
            it.grade.code()
        )),
        Trajectory::Resurgent => Some(format!("back after a quiet spell at {}", it.grade.code())),
        _ => None,
    }
}

/// The priority reasons of the decisions a level that is on acted on.
pub fn priority_reasons(ds: &[Decision]) -> Vec<Reason> {
    ds.iter()
        .filter(|d| d.level == Level::Interrupt && d.mode == Mode::On && d.acted())
        .map(|d| Reason {
            level: Prio::High,
            kind: "attention".into(),
            text: format!(
                "{} {} ({}, {}): {}",
                d.cluster,
                d.key,
                d.band.label(),
                d.grade,
                d.trigger
            ),
        })
        .collect()
}

/// How a decision turned out, read from the admin's later decisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    /// A case covers the lead, or a record of it was labelled agent.
    Agreed,
    /// Its records were labelled, none agent and no case; or, for a draft
    /// case, no case followed in two weeks.
    Disagreed,
    Pending,
}

/// What the agreement is read from.
pub struct Evidence<'a> {
    pub ledger: &'a Ledger,
    /// Record id to label.
    pub labels: &'a BTreeMap<String, String>,
    /// Thread id to the cases covering it.
    pub cases: &'a BTreeMap<String, Vec<String>>,
    pub now: i64,
}

impl Evidence<'_> {
    /// `thread` and every thread it was merged into.
    fn line_of(&self, thread: &str) -> Vec<String> {
        let mut out = vec![thread.to_string()];
        while let Some(next) = out
            .last()
            .and_then(|cur| self.ledger.threads.get(cur))
            .and_then(|t| t.merged_into.clone())
        {
            if out.contains(&next) {
                break;
            }
            out.push(next);
        }
        out
    }

    pub fn outcome(&self, d: &Decision) -> Outcome {
        let line = self.line_of(&d.thread);
        if line.iter().any(|t| self.cases.contains_key(t)) {
            return Outcome::Agreed;
        }
        let (mut agent, mut other) = (0, 0);
        for t in &line {
            for m in self
                .ledger
                .threads
                .get(t)
                .map_or(&[][..], |t| &t.members[..])
            {
                match self.labels.get(m).map(String::as_str) {
                    Some("agent") => agent += 1,
                    Some(_) => other += 1,
                    None => {}
                }
            }
        }
        if agent > 0 && d.level != Level::DraftCase {
            return Outcome::Agreed;
        }
        if d.level == Level::DraftCase {
            return if self.now - d.t >= DRAFT_DECIDED_AFTER || (other > 0 && agent == 0) {
                Outcome::Disagreed
            } else {
                Outcome::Pending
            };
        }
        if other > 0 {
            Outcome::Disagreed
        } else {
            Outcome::Pending
        }
    }
}

/// One level's record.
#[derive(Debug, Clone, Serialize)]
pub struct LevelRecord {
    pub level: Level,
    pub mode: Mode,
    pub decisions: usize,
    pub suppressed: usize,
    pub agreed: usize,
    pub disagreed: usize,
    pub pending: usize,
    /// Agreed over agreed and disagreed, when any is decided.
    pub agreement: Option<f64>,
    /// For `draft_case`: threads a case covers that the level never
    /// proposed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub missed: Option<usize>,
}

/// Each level's record over the log.
pub fn agreement(log: &[Decision], cfg: &Config, ev: &Evidence) -> Vec<LevelRecord> {
    Level::ALL
        .iter()
        .map(|&l| {
            let mine: Vec<&Decision> = log.iter().filter(|d| d.level == l).collect();
            let mut r = LevelRecord {
                level: l,
                mode: cfg.mode(l),
                decisions: mine.len(),
                suppressed: mine.iter().filter(|d| !d.acted()).count(),
                agreed: 0,
                disagreed: 0,
                pending: 0,
                agreement: None,
                missed: None,
            };
            for d in mine.iter().filter(|d| d.acted()) {
                match ev.outcome(d) {
                    Outcome::Agreed => r.agreed += 1,
                    Outcome::Disagreed => r.disagreed += 1,
                    Outcome::Pending => r.pending += 1,
                }
            }
            let decided = r.agreed + r.disagreed;
            if decided > 0 {
                r.agreement = Some(((r.agreed as f64 / decided as f64) * 100.0).round() / 100.0);
            }
            if l == Level::DraftCase {
                let proposed: BTreeSet<String> =
                    mine.iter().flat_map(|d| ev.line_of(&d.thread)).collect();
                r.missed = Some(
                    ev.cases
                        .keys()
                        .filter(|t| ev.line_of(t).iter().all(|x| !proposed.contains(x)))
                        .count(),
                );
            }
            r
        })
        .collect()
}

#[cfg(test)]
mod tests;
