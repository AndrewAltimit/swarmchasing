//! Crosswalk from the SC-T tactics to other frameworks: MITRE ATLAS and
//! ATT&CK techniques and the OWASP Top 10 for Agentic Applications risks.
//!
//! The mapping is per tactic, not per rule: a rule carries only its tactic
//! ([`crate::rules::RuleDef::tactic`]), and its framework ids are read from
//! here, so the rules file stays small and the ids sit in one place. The
//! Field Manual is the source: the ATT&CK column and the first ATLAS ids
//! follow SC-FM 4.6, the agent-specific ATLAS ids and the OWASP column follow
//! SC-FM 12.4 (ATLAS data version 2026.09). A test reads both manual tables
//! and fails when this one differs. A mapping says what the agent did in the
//! other framework's words; it never says anyone intended it.

use crate::model::Tactic;

/// One tactic's crosswalk.
pub struct Crosswalk {
    pub tactic: Tactic,
    /// Kebab-case phase name, as used for STIX kill chain phases.
    pub phase: &'static str,
    /// MITRE ATLAS technique ids.
    pub atlas: &'static [&'static str],
    /// MITRE ATT&CK technique ids.
    pub attack: &'static [&'static str],
    /// OWASP Top 10 for Agentic Applications risk ids.
    pub owasp_agentic: &'static [&'static str],
}

pub const CROSSWALK: &[Crosswalk] = &[
    Crosswalk {
        tactic: Tactic::TaskRetrieval,
        phase: "task-retrieval",
        atlas: &["AML.T0095", "AML.T0116"],
        attack: &["T1593"],
        owasp_agentic: &[],
    },
    Crosswalk {
        tactic: Tactic::ToolEscalation,
        phase: "tool-escalation",
        atlas: &["AML.T0117", "AML.T0053"],
        attack: &["T1059"],
        owasp_agentic: &["ASI02", "ASI05"],
    },
    Crosswalk {
        tactic: Tactic::AccessControlCircumvention,
        phase: "access-control-circumvention",
        atlas: &["AML.T0117"],
        attack: &["T1090.002"],
        owasp_agentic: &["ASI02"],
    },
    Crosswalk {
        tactic: Tactic::VulnerabilityProbing,
        phase: "vulnerability-probing",
        atlas: &["AML.T0049", "AML.T0006"],
        attack: &["T1190", "T1595.002"],
        owasp_agentic: &["ASI10", "ASI01"],
    },
    Crosswalk {
        tactic: Tactic::AccountAcquisition,
        phase: "account-acquisition",
        atlas: &["AML.T0021", "AML.T0125"],
        attack: &["T1585", "T1136"],
        owasp_agentic: &["ASI03"],
    },
    Crosswalk {
        tactic: Tactic::CredentialReuse,
        phase: "credential-reuse",
        atlas: &["AML.T0012", "AML.T0091"],
        attack: &["T1078", "T1550"],
        owasp_agentic: &["ASI03"],
    },
    Crosswalk {
        tactic: Tactic::CallbackChannels,
        phase: "callback-channels",
        atlas: &["AML.T0072", "AML.T0025", "AML.T0086"],
        attack: &["T1567.004", "T1567.003", "T1102"],
        owasp_agentic: &["ASI02"],
    },
    // Cluster-level tactics are never a rule's tactic, but the crosswalk
    // still names where a reviewer's finding lands.
    Crosswalk {
        tactic: Tactic::OffTaskTargets,
        phase: "off-task-targets",
        atlas: &[],
        attack: &[],
        owasp_agentic: &["ASI01", "ASI10"],
    },
    Crosswalk {
        tactic: Tactic::InterAgentCoordination,
        phase: "inter-agent-coordination",
        atlas: &["AML.T0118", "AML.T0124"],
        attack: &[],
        owasp_agentic: &["ASI07", "ASI08"],
    },
];

/// The crosswalk of tactic `t`.
pub fn of(t: Tactic) -> &'static Crosswalk {
    CROSSWALK
        .iter()
        .find(|c| c.tactic == t)
        .expect("every tactic has a crosswalk row")
}

/// The crosswalk of a tactic written `SC-Tn`, if it is one.
pub fn of_label(label: &str) -> Option<&'static Crosswalk> {
    let id = label.strip_prefix("SC-")?;
    CROSSWALK.iter().find(|c| c.tactic.id() == id)
}

/// The ATLAS technique ids a tactic is evidence of.
pub fn atlas_ids(t: Tactic) -> &'static [&'static str] {
    of(t).atlas
}

/// The OWASP Top 10 for Agentic Applications risk ids a tactic maps to: a
/// risk which, realised, produces the behaviour.
pub fn owasp_ids(t: Tactic) -> &'static [&'static str] {
    of(t).owasp_agentic
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn every_tactic_is_mapped_once() {
        assert_eq!(CROSSWALK.len(), Tactic::ALL.len());
        for t in Tactic::ALL {
            assert_eq!(CROSSWALK.iter().filter(|c| c.tactic == t).count(), 1);
            assert!(of_label(&format!("SC-{}", t.id())).is_some());
        }
        for c in CROSSWALK {
            assert!(c.atlas.iter().all(|a| a.starts_with("AML.T")));
            for id in c.owasp_agentic {
                let n: u8 = id.strip_prefix("ASI").unwrap().parse().unwrap();
                assert!((1..=10).contains(&n), "{id}");
            }
        }
    }

    /// The rows of the Markdown table under the heading starting with
    /// `heading` whose first cell names a tactic.
    fn manual_table(md: &str, heading: &str) -> Vec<Vec<String>> {
        let section = md
            .split("\n## ")
            .find(|s| s.starts_with(heading))
            .unwrap_or_else(|| panic!("no section {heading}"));
        section
            .lines()
            .filter(|l| {
                l.strip_prefix("| SC-T")
                    .is_some_and(|r| r.starts_with(|c: char| c.is_ascii_digit()))
            })
            .map(|l| {
                l.trim_matches('|')
                    .split('|')
                    .map(|c| c.trim().to_string())
                    .collect()
            })
            .collect()
    }

    /// The framework ids in a manual cell: tokens starting with `prefix`
    /// and a digit.
    fn ids(cell: &str, prefix: &str) -> BTreeSet<String> {
        cell.split(|c: char| !(c.is_ascii_alphanumeric() || c == '.'))
            .map(|t| t.trim_end_matches('.'))
            .filter(|t| {
                t.strip_prefix(prefix)
                    .is_some_and(|r| r.starts_with(|c: char| c.is_ascii_digit()))
            })
            .map(str::to_string)
            .collect()
    }

    fn set(ids: &[&str]) -> BTreeSet<String> {
        ids.iter().map(|s| s.to_string()).collect()
    }

    /// The table matches the Field Manual's crosswalks: SC-FM 4.6 (ATLAS
    /// and ATT&CK) and SC-FM 12.4 (agent-specific ATLAS, and OWASP).
    #[test]
    fn matches_the_field_manual() {
        let fm4 = manual_table(
            include_str!("../../../docs/manual/04-indicators.md"),
            "FM-4.6 ",
        );
        let fm12 = manual_table(
            include_str!("../../../docs/manual/12-interoperability.md"),
            "FM-12.4 ",
        );
        assert_eq!(fm4.len(), CROSSWALK.len());
        assert_eq!(fm12.len(), CROSSWALK.len());
        for c in CROSSWALK {
            let label = format!("SC-{}", c.tactic.id());
            let row = |table: &[Vec<String>]| {
                table
                    .iter()
                    .find(|r| r[0].split_whitespace().next() == Some(label.as_str()))
                    .cloned()
                    .unwrap_or_else(|| panic!("{label} missing from the manual"))
            };
            let (r4, r12) = (row(&fm4), row(&fm12));
            let mut atlas = ids(&r4[1], "AML.T");
            atlas.extend(ids(&r12[2], "AML.T"));
            assert_eq!(set(c.atlas), atlas, "{label} ATLAS");
            assert_eq!(set(c.attack), ids(&r4[2], "T"), "{label} ATT&CK");
            assert_eq!(set(c.owasp_agentic), ids(&r12[1], "ASI"), "{label} OWASP");
        }
    }
}
