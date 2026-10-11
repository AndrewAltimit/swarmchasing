//! What each SC-T tactic corresponds to in other frameworks, for the
//! `external_references`, `kill_chain_phases` and MISP tags of an export.
//!
//! The rules carry the SC-T tactic of each indicator (`tactic`), not other
//! frameworks' ids; the crosswalk itself is [`sc_core::crosswalk`], which a
//! test holds to the Field Manual's tables (SC-FM 4.6 and 12.4). A mapping
//! says what the agent did, not that anyone intended it.

use serde_json::{Value, json};

/// The Field Manual section defining the tactics.
pub const SC_T_URL: &str = "https://github.com/AndrewAltimit/swarmchasing/blob/main/docs/manual/04-indicators.md#fm-43-the-sc-t-tactic-taxonomy";
/// The `source_name` of an SC-T reference and the kill chain name of a phase.
pub const SC_T_SOURCE: &str = "swarmchasing-sc-t";

use sc_core::crosswalk::{Crosswalk, of_label};

/// The crosswalk of tactic `SC-Tn`, if it is one.
pub fn of(tactic: &str) -> Option<&'static Crosswalk> {
    of_label(tactic)
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
