//! Agent grades ([`crate::agentness`]) against who really sent the records:
//! a confusion table of actor by grade. Reported, never gated.
//!
//! A record's actor comes from its `actor` field (`agent`, `human`, `tool`);
//! an agent-labelled record without one counts as `agent`. A record with an
//! `actor` and no `label` is graded here but not scored for detection: a
//! person's attack payloads are flagged by design, and scoring them benign
//! would measure that known limit, not the rules.

use super::{Label, LabelSet};
use crate::analyze::Analysis;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Actor {
    Agent,
    Human,
    Tool,
}

impl Actor {
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "agent" => Some(Self::Agent),
            "human" | "person" => Some(Self::Human),
            "tool" | "scanner" => Some(Self::Tool),
            _ => None,
        }
    }

    pub fn id(self) -> &'static str {
        match self {
            Self::Agent => "agent",
            Self::Human => "human",
            Self::Tool => "tool",
        }
    }
}

/// Columns in order: no rule fired, flagged outside any cluster, then the
/// cluster's grade. L5 is never computed, so it has no column.
pub const COLUMNS: [&str; 7] = ["unflagged", "unclustered", "L0", "L1", "L2", "L3", "L4"];

/// Row → column → records.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct GradeTable {
    pub rows: BTreeMap<String, BTreeMap<String, usize>>,
}

impl GradeTable {
    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }
}

/// The table over `a`. With `control`, every record is one row of that name
/// (a negative control, such as records from before agents existed);
/// otherwise rows are actors, and benign records without one are left out.
pub fn grade_table(a: &Analysis, labels: &LabelSet, control: Option<&str>) -> GradeTable {
    let mut t = GradeTable::default();
    let mut seen = HashSet::new();
    for (i, r) in a.results.iter().enumerate() {
        if !seen.insert(r.obs.id.as_str()) {
            continue;
        }
        let actor = labels.actors.get(&r.obs.id).copied().or_else(|| {
            labels
                .labels
                .get(&r.obs.id)
                .filter(|l| l.label == Label::Agent)
                .map(|_| Actor::Agent)
        });
        let row = match (control, actor) {
            (Some(name), _) => name,
            (None, Some(x)) => x.id(),
            (None, None) => continue,
        };
        let col = super::view::grade_column(a, i);
        *t.rows
            .entry(row.to_string())
            .or_default()
            .entry(col.to_string())
            .or_default() += 1;
    }
    t
}
