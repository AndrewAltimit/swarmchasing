//! Ground truth per record: who sent it, its true run, and the swarm and
//! fleet that run belongs to.
//!
//! The fields are the evaluation set's label fields (`label`, `actor`,
//! `class`, `run`, `swarm`) plus `fleet`, so a simulated file is also an
//! ordinary labelled file for `swarmchase eval`, and a hand-written labelled
//! file can be measured here.

use sc_core::eval::Label;
use sc_core::eval::grades::Actor;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// The truth about one record.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TruthRow {
    /// `agent` or `benign`; none for a person's or tool's payloads, which
    /// are graded, not scored (as in the evaluation set).
    pub label: Option<Label>,
    pub actor: Actor,
    /// The kind of actor (`swarm_agent`, `cron_scanner`, ...).
    pub class: String,
    /// The true run: one client working one stretch of one task.
    pub run: String,
    /// The interacting group the run belongs to, `none` for a run known not
    /// to interact.
    pub swarm: Option<String>,
    /// The operator group: runs one operator or one scaffold deployment
    /// drives. A swarm's runs share its fleet.
    pub fleet: Option<String>,
}

impl TruthRow {
    /// The interacting group, unless `none`.
    pub fn swarm_id(&self) -> Option<&str> {
        self.swarm.as_deref().filter(|s| *s != "none")
    }

    /// Who is behind the run: its fleet, else its swarm, else the run alone.
    pub fn operator(&self) -> String {
        match (self.fleet.as_deref(), self.swarm_id()) {
            (Some(f), _) if f != "none" => format!("fleet:{f}"),
            (_, Some(s)) => format!("swarm:{s}"),
            _ => format!("run:{}", self.run),
        }
    }
}

/// Truth by record id.
#[derive(Debug, Clone, Default)]
pub struct Truth {
    pub rows: BTreeMap<String, TruthRow>,
}

impl Truth {
    pub fn get(&self, id: &str) -> Option<&TruthRow> {
        self.rows.get(id)
    }

    /// Truth from labelled NDJSON: every line with an `id` and a `run`.
    /// `actor` defaults to `agent` for an agent label and `human` otherwise.
    pub fn from_ndjson(text: &str) -> Self {
        let mut out = Self::default();
        for line in text.lines() {
            let Ok(v) = serde_json::from_str::<serde_json::Value>(line.trim()) else {
                continue;
            };
            let s = |k: &str| v.get(k).and_then(|x| x.as_str()).map(str::to_string);
            let (Some(id), Some(run)) = (s("id"), s("run")) else {
                continue;
            };
            let label = match s("label").as_deref() {
                Some("agent" | "significant" | "suggestive") => Some(Label::Agent),
                Some("benign" | "background") => Some(Label::Benign),
                _ => None,
            };
            let actor = s("actor").and_then(|a| Actor::parse(&a)).unwrap_or(
                if label == Some(Label::Agent) {
                    Actor::Agent
                } else {
                    Actor::Human
                },
            );
            out.rows.insert(
                id,
                TruthRow {
                    label,
                    actor,
                    class: s("class").unwrap_or_else(|| "unclassed".into()),
                    run,
                    swarm: s("swarm"),
                    fleet: s("fleet"),
                },
            );
        }
        out
    }
}
