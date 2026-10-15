//! The run's priority: how soon the digest needs the admin, from
//! deterministic facts only.
//!
//! - **high**: a new or escalated significant lead graded L2 or higher (a
//!   cluster, or a lone record), or a case clock that has run;
//! - **medium**: any health alert (a source that failed, was skipped, read
//!   nothing in the shape expected, collapsed or lost its host, or a rule
//!   that drifted), a significant lead below L2, or a suggestive lead at L2
//!   or higher;
//! - **low**: none of these.
//!
//! An autonomy level that is on ([`super::autonomy`], `interrupt = "on"`)
//! adds a high reason of kind `attention` for a lead it fired on; its
//! triggers are deterministic facts too.
//!
//! The leads of one campaign ([`sc_core::campaign`]) are one reason, at the
//! level of its strongest: one operator's many sessions are one item for
//! the admin, not one per session.
//!
//! A model's suggestion is never an input: the same facts give the same
//! priority whatever a model said.

use super::cases::DueClock;
use super::digest::Alert;
use super::triage::{Lead, LeadKind};
use sc_core::Tier;
use sc_core::agentness::AgentLevel;
use serde::Serialize;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Level {
    Low,
    Medium,
    High,
}

impl Level {
    pub fn label(self) -> &'static str {
        match self {
            Level::Low => "low",
            Level::Medium => "medium",
            Level::High => "high",
        }
    }
}

/// One fact that raised the priority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Reason {
    pub level: Level,
    /// `lead`, `case_clock`, or the alert's kind.
    pub kind: String,
    /// The line the digest shows, defanged.
    pub text: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Priority {
    pub level: Level,
    /// Highest first.
    pub reasons: Vec<Reason>,
}

impl Priority {
    /// Add reasons, keeping the highest first and leads' order within a level.
    pub fn add(&mut self, more: Vec<Reason>) {
        self.reasons.extend(more);
        self.reasons.sort_by_key(|r| std::cmp::Reverse(r.level));
        self.level = self.reasons.first().map_or(Level::Low, |r| r.level);
    }
}

/// The priority of a run with these leads, health alerts and due clocks.
pub fn assess(leads: &[Lead], alerts: &[Alert], due: &[DueClock]) -> Priority {
    let mut reasons = Vec::new();
    // Each campaign's leads that raise the priority: its reason goes where
    // its strongest lead would.
    let mut campaigns: BTreeMap<&str, (usize, Level, Vec<&Lead>)> = BTreeMap::new();
    for l in leads {
        let graded = l.grade >= AgentLevel::ModelWritten;
        let level = match (l.tier, graded) {
            (Tier::Significant, true) => Level::High,
            (Tier::Significant, false) | (Tier::Suggestive, true) => Level::Medium,
            _ => continue,
        };
        if let Some((id, _)) = &l.campaign {
            let at = reasons.len();
            let e = campaigns
                .entry(id.as_str())
                .or_insert_with(|| (at, level, Vec::new()));
            if e.2.is_empty() {
                reasons.push(Reason {
                    level,
                    kind: "campaign".into(),
                    text: String::new(),
                });
            }
            e.1 = e.1.max(level);
            e.2.push(l);
            continue;
        }
        let what = match (l.kind, l.change) {
            (LeadKind::Cluster, "escalated") => "cluster rose to",
            (LeadKind::Cluster, _) => "new cluster,",
            (LeadKind::Record, _) => "new record outside any cluster,",
        };
        reasons.push(Reason {
            level,
            kind: "lead".into(),
            text: format!(
                "{}: {what} {} at {} ({}), {} record(s); targets {}",
                l.name(),
                l.tier.label(),
                l.grade.code(),
                l.grade.label(),
                l.records,
                if l.targets.is_empty() {
                    "none".to_string()
                } else {
                    l.targets
                        .iter()
                        .take(3)
                        .map(|h| format!("`{h}`"))
                        .collect::<Vec<_>>()
                        .join(", ")
                }
            ),
        });
    }
    for (id, (at, level, members)) in campaigns {
        let first = members[0];
        let site = first.campaign.as_ref().map_or("", |c| c.1.as_str());
        let clusters = members
            .iter()
            .filter(|l| l.kind == LeadKind::Cluster)
            .count();
        reasons[at] = Reason {
            level,
            kind: "campaign".into(),
            text: format!(
                "{id}: campaign on `{site}`, {} new lead(s) ({clusters} cluster(s), {} record(s) outside any cluster); strongest {}, {} at {} ({})",
                members.len(),
                members.len() - clusters,
                first.name(),
                first.tier.label(),
                first.grade.code(),
                first.grade.label(),
            ),
        };
    }
    for d in due {
        reasons.push(Reason {
            level: Level::High,
            kind: "case_clock".into(),
            text: d.line(),
        });
    }
    for a in alerts {
        reasons.push(Reason {
            level: Level::Medium,
            kind: a.kind.label().into(),
            text: a.text.clone(),
        });
    }
    // Stable: leads keep their strongest-first order within a level.
    reasons.sort_by_key(|r| std::cmp::Reverse(r.level));
    Priority {
        level: reasons.first().map_or(Level::Low, |r| r.level),
        reasons,
    }
}

#[cfg(test)]
mod tests {
    use super::super::digest::AlertKind;
    use super::*;
    use crate::suggest::Suggestion;

    fn lead(tier: Tier, grade: AgentLevel) -> Lead {
        Lead {
            kind: LeadKind::Cluster,
            change: "new",
            id: "C1".into(),
            key: "k-1".into(),
            record: "r1".into(),
            source: "wayback".into(),
            tier,
            score: 9,
            records: 4,
            grade,
            targets: vec!["portal[.]example[.]gov".into()],
            suggestion: None,
            campaign: None,
            idx: 0,
        }
    }

    #[test]
    fn levels_follow_the_facts() {
        assert_eq!(assess(&[], &[], &[]).level, Level::Low);
        let suggestive_l0 = lead(Tier::Suggestive, AgentLevel::PayloadsOnly);
        assert_eq!(assess(&[suggestive_l0], &[], &[]).level, Level::Low);
        let sig_l1 = lead(Tier::Significant, AgentLevel::SelfDescribed);
        assert_eq!(
            assess(std::slice::from_ref(&sig_l1), &[], &[]).level,
            Level::Medium
        );
        let sug_l2 = lead(Tier::Suggestive, AgentLevel::ModelWritten);
        assert_eq!(assess(&[sug_l2], &[], &[]).level, Level::Medium);
        let sig_l2 = lead(Tier::Significant, AgentLevel::ModelWritten);
        let p = assess(&[sig_l1, sig_l2], &[], &[]);
        assert_eq!(p.level, Level::High);
        assert_eq!(p.reasons.len(), 2);
        assert!(
            p.reasons[0]
                .text
                .starts_with("C1 k-1: new cluster, significant at L2 (model-written), 4 record(s)"),
            "{:?}",
            p.reasons
        );

        let alert = Alert {
            kind: AlertKind::SourceFailed,
            source: Some("s".into()),
            text: "`s` failed this run (HTTP 503)".into(),
        };
        let p = assess(&[], std::slice::from_ref(&alert), &[]);
        assert_eq!(p.level, Level::Medium);
        assert_eq!(p.reasons[0].kind, "source_failed");

        let due = DueClock {
            case: "p-1".into(),
            clock: "indicators",
            since: 1_791_000_000,
            hosts: Vec::new(),
        };
        let p = assess(&[], &[alert], &[due]);
        assert_eq!(p.level, Level::High);
        assert_eq!(p.reasons[0].kind, "case_clock");
        assert!(p.reasons[0].text.contains("swarmchase notice add p-1"));
    }

    #[test]
    fn a_campaigns_leads_are_one_reason() {
        let mut leads = Vec::new();
        for (i, kind) in [LeadKind::Cluster, LeadKind::Record, LeadKind::Cluster]
            .into_iter()
            .enumerate()
        {
            let mut l = lead(Tier::Significant, AgentLevel::ModelWritten);
            l.kind = kind;
            l.id = format!("C{i}");
            l.campaign = Some(("CP1".into(), "site[.]example".into()));
            leads.push(l);
        }
        let mut other = lead(Tier::Significant, AgentLevel::SelfDescribed);
        other.id = "C9".into();
        leads.push(other);
        let p = assess(&leads, &[], &[]);
        assert_eq!(p.level, Level::High);
        assert_eq!(p.reasons.len(), 2, "{:?}", p.reasons);
        assert_eq!(p.reasons[0].kind, "campaign");
        assert!(
            p.reasons[0].text.starts_with(
                "CP1: campaign on `site[.]example`, 3 new lead(s) (2 cluster(s), 1 record(s) outside any cluster); strongest C0 k-1"
            ),
            "{:?}",
            p.reasons
        );
        assert_eq!(p.reasons[1].level, Level::Medium);
    }

    #[test]
    fn a_suggestion_never_moves_the_priority() {
        let base = lead(Tier::Significant, AgentLevel::SelfDescribed);
        let want = assess(std::slice::from_ref(&base), &[], &[]);
        for label in ["agent", "benign", "unsure"] {
            let mut l = base.clone();
            l.suggestion = Some(Suggestion {
                label: label.into(),
                reason: "x".into(),
                model: "m".into(),
            });
            let got = assess(&[l], &[], &[]);
            assert_eq!(got.level, want.level, "{label}");
            assert_eq!(got.reasons, want.reasons, "{label}");
        }
    }
}
