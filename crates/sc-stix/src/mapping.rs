//! What each SC-T tactic corresponds to in other frameworks, for the
//! `external_references`, `kill_chain_phases` and MISP tags of an export.
//!
//! The rules carry the SC-T tactic of each indicator (`tactic`), not other
//! frameworks' ids, so the cross-walk is this table, keyed by tactic. The
//! Field Manual is the source: the ATT&CK column and the first ATLAS ids
//! follow SC-FM 4.6, the agent-specific ATLAS ids and the OWASP Top 10 for
//! Agentic Applications column (ASI01 to ASI10) follow SC-FM 12.4. A test
//! reads both manual tables and fails when this one differs. A mapping says
//! what the agent did, not that anyone intended it.

use serde_json::{Value, json};

/// The Field Manual section defining the tactics.
pub const SC_T_URL: &str = "https://github.com/AndrewAltimit/swarmchasing/blob/main/docs/manual/04-indicators.md#fm-43-the-sc-t-tactic-taxonomy";
/// The `source_name` of an SC-T reference and the kill chain name of a phase.
pub const SC_T_SOURCE: &str = "swarmchasing-sc-t";

/// One tactic's cross-walk.
pub struct Crosswalk {
    /// `SC-T4`.
    pub tactic: &'static str,
    /// Kebab-case phase name for STIX kill chain phases.
    pub phase: &'static str,
    /// MITRE ATLAS technique ids.
    pub atlas: &'static [&'static str],
    /// MITRE ATT&CK technique ids.
    pub attack: &'static [&'static str],
    /// OWASP Top 10 for Agentic Applications ids.
    pub owasp_agentic: &'static [&'static str],
}

pub const CROSSWALK: &[Crosswalk] = &[
    Crosswalk {
        tactic: "SC-T1",
        phase: "task-retrieval",
        atlas: &["AML.T0095", "AML.T0116"],
        attack: &["T1593"],
        owasp_agentic: &[],
    },
    Crosswalk {
        tactic: "SC-T2",
        phase: "tool-escalation",
        atlas: &["AML.T0117", "AML.T0053"],
        attack: &["T1059"],
        owasp_agentic: &["ASI02", "ASI05"],
    },
    Crosswalk {
        tactic: "SC-T3",
        phase: "access-control-circumvention",
        atlas: &["AML.T0117"],
        attack: &["T1090.002"],
        owasp_agentic: &["ASI02"],
    },
    Crosswalk {
        tactic: "SC-T4",
        phase: "vulnerability-probing",
        atlas: &["AML.T0049", "AML.T0006"],
        attack: &["T1190", "T1595.002"],
        owasp_agentic: &["ASI10", "ASI01"],
    },
    Crosswalk {
        tactic: "SC-T5",
        phase: "account-acquisition",
        atlas: &["AML.T0021", "AML.T0125"],
        attack: &["T1585", "T1136"],
        owasp_agentic: &["ASI03"],
    },
    Crosswalk {
        tactic: "SC-T6",
        phase: "credential-reuse",
        atlas: &["AML.T0012", "AML.T0091"],
        attack: &["T1078", "T1550"],
        owasp_agentic: &["ASI03"],
    },
    Crosswalk {
        tactic: "SC-T7",
        phase: "callback-channels",
        atlas: &["AML.T0072", "AML.T0025", "AML.T0086"],
        attack: &["T1567.004", "T1567.003", "T1102"],
        owasp_agentic: &["ASI02"],
    },
    Crosswalk {
        tactic: "SC-T8",
        phase: "off-task-targets",
        atlas: &[],
        attack: &[],
        owasp_agentic: &["ASI01", "ASI10"],
    },
    Crosswalk {
        tactic: "SC-T9",
        phase: "inter-agent-coordination",
        atlas: &["AML.T0118", "AML.T0124"],
        attack: &[],
        owasp_agentic: &["ASI07", "ASI08"],
    },
];

/// The cross-walk of tactic `SC-Tn`, if it is one.
pub fn of(tactic: &str) -> Option<&'static Crosswalk> {
    CROSSWALK.iter().find(|c| c.tactic == tactic)
}

fn atlas_url(id: &str) -> String {
    format!("https://atlas.mitre.org/techniques/{id}")
}

fn attack_url(id: &str) -> String {
    format!(
        "https://attack.mitre.org/techniques/{}/",
        id.replace('.', "/")
    )
}

const OWASP_URL: &str =
    "https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/";

/// STIX `external_references` for `tactics`, in order: each tactic, then
/// its ATLAS, ATT&CK and OWASP entries, without repeats.
pub fn external_references(tactics: &[String]) -> Vec<Value> {
    let mut out: Vec<Value> = Vec::new();
    let mut push = |v: Value| {
        if !out.contains(&v) {
            out.push(v);
        }
    };
    for t in tactics {
        push(json!({ "source_name": SC_T_SOURCE, "external_id": t, "url": SC_T_URL }));
        let Some(c) = of(t) else { continue };
        for id in c.atlas {
            push(json!({ "source_name": "mitre-atlas", "external_id": id, "url": atlas_url(id) }));
        }
        for id in c.attack {
            push(
                json!({ "source_name": "mitre-attack", "external_id": id, "url": attack_url(id) }),
            );
        }
        for id in c.owasp_agentic {
            push(
                json!({ "source_name": "owasp-agentic-top-10", "external_id": id, "url": OWASP_URL }),
            );
        }
    }
    out
}

/// STIX `kill_chain_phases` for `tactics`.
pub fn kill_chain_phases(tactics: &[String]) -> Vec<Value> {
    tactics
        .iter()
        .filter_map(|t| of(t))
        .map(|c| json!({ "kill_chain_name": SC_T_SOURCE, "phase_name": c.phase }))
        .collect()
}

/// MISP tags for `tactics`: machine tags in the `swarmchasing` namespace,
/// and galaxy-style tags for the ATLAS and ATT&CK techniques and the OWASP
/// entries.
pub fn misp_tags(tactics: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    for t in tactics {
        out.push(format!("swarmchasing:tactic=\"{t}\""));
        let Some(c) = of(t) else { continue };
        out.extend(
            c.atlas
                .iter()
                .map(|id| format!("misp-galaxy:mitre-atlas-attack-pattern=\"{id}\"")),
        );
        out.extend(
            c.attack
                .iter()
                .map(|id| format!("misp-galaxy:mitre-attack-pattern=\"{id}\"")),
        );
        out.extend(
            c.owasp_agentic
                .iter()
                .map(|id| format!("owasp-agentic-top-10:risk=\"{id}\"")),
        );
    }
    let mut seen = std::collections::BTreeSet::new();
    out.retain(|t| seen.insert(t.clone()));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn every_tactic_is_mapped_once() {
        for t in sc_core::Tactic::ALL {
            let id = format!("SC-{}", t.id());
            assert!(of(&id).is_some(), "{id}");
        }
        assert_eq!(CROSSWALK.len(), sc_core::Tactic::ALL.len());
        for c in CROSSWALK {
            for id in c.owasp_agentic {
                let n: u8 = id.strip_prefix("ASI").unwrap().parse().unwrap();
                assert!((1..=10).contains(&n), "{id}");
            }
            assert!(c.atlas.iter().all(|a| a.starts_with("AML.T")));
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

    /// The table matches the Field Manual's cross-walks: SC-FM 4.6 (ATLAS
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
            let row = |table: &[Vec<String>]| {
                table
                    .iter()
                    .find(|r| r[0].split_whitespace().next() == Some(c.tactic))
                    .cloned()
                    .unwrap_or_else(|| panic!("{} missing from the manual", c.tactic))
            };
            let (r4, r12) = (row(&fm4), row(&fm12));
            let mut atlas = ids(&r4[1], "AML.T");
            atlas.extend(ids(&r12[2], "AML.T"));
            assert_eq!(set(c.atlas), atlas, "{} ATLAS", c.tactic);
            assert_eq!(set(c.attack), ids(&r4[2], "T"), "{} ATT&CK", c.tactic);
            assert_eq!(
                set(c.owasp_agentic),
                ids(&r12[1], "ASI"),
                "{} OWASP",
                c.tactic
            );
        }
    }

    #[test]
    fn references_and_tags() {
        let r = external_references(&["SC-T4".into(), "SC-T9".into()]);
        assert_eq!(r[0]["external_id"], "SC-T4");
        assert!(
            r.iter()
                .any(|x| x["url"] == "https://attack.mitre.org/techniques/T1595/002/")
        );
        assert!(r.iter().any(|x| x["external_id"] == "ASI07"));
        assert_eq!(
            kill_chain_phases(&["SC-T7".into()])[0]["phase_name"],
            "callback-channels"
        );
        let t = misp_tags(&["SC-T5".into(), "SC-T6".into()]);
        assert_eq!(
            t.iter()
                .filter(|x| *x == "owasp-agentic-top-10:risk=\"ASI03\"")
                .count(),
            1
        );
    }
}
