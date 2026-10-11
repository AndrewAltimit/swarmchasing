//! What each SC-T tactic corresponds to in other frameworks, for the
//! `external_references` and tags of an export.
//!
//! The rules carry the SC-T tactic of each indicator (`tactic`), not other
//! frameworks' ids, so the cross-walk is this table, keyed by tactic. The
//! MITRE ATLAS and ATT&CK columns follow the Field Manual's cross-walk
//! (SC-FM 4.6). The OWASP Top 10 for Agentic Applications column (ASI01 to
//! ASI10) lists only the entries whose risk the tactic's behaviour shows;
//! a tactic with no defensible entry has none. A mapping says what the
//! agent did, not that anyone intended it.

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
        atlas: &["AML.T0117"],
        attack: &["T1059"],
        owasp_agentic: &["ASI02"],
    },
    Crosswalk {
        tactic: "SC-T3",
        phase: "access-control-circumvention",
        atlas: &["AML.T0117"],
        attack: &["T1090.002"],
        owasp_agentic: &[],
    },
    Crosswalk {
        tactic: "SC-T4",
        phase: "vulnerability-probing",
        atlas: &["AML.T0049", "AML.T0006"],
        attack: &["T1190", "T1595.002"],
        owasp_agentic: &[],
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
        atlas: &["AML.T0072", "AML.T0025"],
        attack: &["T1567.004", "T1567.003", "T1102"],
        owasp_agentic: &[],
    },
    Crosswalk {
        tactic: "SC-T8",
        phase: "off-task-targets",
        atlas: &[],
        attack: &[],
        owasp_agentic: &["ASI10"],
    },
    Crosswalk {
        tactic: "SC-T9",
        phase: "inter-agent-coordination",
        atlas: &["AML.T0118", "AML.T0124"],
        attack: &[],
        owasp_agentic: &["ASI07"],
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
