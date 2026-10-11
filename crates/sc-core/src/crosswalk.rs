//! Crosswalk from the SC-T tactics to agent-security frameworks
//! (Field Manual FM-12.4): the MITRE ATLAS techniques and the OWASP Top 10
//! for Agentic Applications risks each tactic maps to.
//!
//! The mapping is per tactic, not per rule: a rule carries only its tactic
//! ([`crate::rules::RuleDef::tactic`]), and its framework ids are read from
//! here, so the rules file stays small and the ids are the FM-12.4-verified
//! set in one place. ATLAS ids are from ATLAS data version 2026.09. A
//! mapping says what the agent did in the other framework's words; it never
//! says anyone intended it.

use crate::model::Tactic;

/// The ATLAS technique ids a tactic is evidence of (FM-12.4, FM-4.6).
pub fn atlas_ids(t: Tactic) -> &'static [&'static str] {
    match t {
        Tactic::TaskRetrieval => &["AML.T0116"],
        Tactic::ToolEscalation => &["AML.T0053", "AML.T0117"],
        Tactic::AccessControlCircumvention => &["AML.T0117"],
        Tactic::VulnerabilityProbing => &["AML.T0049", "AML.T0006"],
        Tactic::AccountAcquisition => &["AML.T0021", "AML.T0125"],
        Tactic::CredentialReuse => &["AML.T0012", "AML.T0091"],
        Tactic::CallbackChannels => &["AML.T0086", "AML.T0072"],
        // Cluster-level tactics are never a rule's tactic, but the crosswalk
        // still names where a reviewer's finding lands.
        Tactic::OffTaskTargets => &[],
        Tactic::InterAgentCoordination => &["AML.T0118", "AML.T0124"],
    }
}

/// The OWASP Top 10 for Agentic Applications risk ids a tactic maps to
/// (FM-12.4). A risk which, realised, produces the behaviour.
pub fn owasp_ids(t: Tactic) -> &'static [&'static str] {
    match t {
        Tactic::TaskRetrieval => &[],
        Tactic::ToolEscalation => &["ASI02", "ASI05"],
        Tactic::AccessControlCircumvention => &["ASI02"],
        Tactic::VulnerabilityProbing => &["ASI10", "ASI01"],
        Tactic::AccountAcquisition => &["ASI03"],
        Tactic::CredentialReuse => &["ASI03"],
        Tactic::CallbackChannels => &["ASI02"],
        Tactic::OffTaskTargets => &["ASI01", "ASI10"],
        Tactic::InterAgentCoordination => &["ASI07", "ASI08"],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_tactic_has_a_mapping_shape() {
        for t in [
            Tactic::TaskRetrieval,
            Tactic::ToolEscalation,
            Tactic::AccessControlCircumvention,
            Tactic::VulnerabilityProbing,
            Tactic::AccountAcquisition,
            Tactic::CredentialReuse,
            Tactic::CallbackChannels,
            Tactic::OffTaskTargets,
            Tactic::InterAgentCoordination,
        ] {
            // ATLAS ids are dotted AML.T ids; OWASP ids are ASI<nn>.
            assert!(atlas_ids(t).iter().all(|i| i.starts_with("AML.T")));
            assert!(owasp_ids(t).iter().all(|i| i.starts_with("ASI")));
        }
        assert_eq!(owasp_ids(Tactic::ToolEscalation), &["ASI02", "ASI05"]);
        assert_eq!(
            atlas_ids(Tactic::VulnerabilityProbing),
            &["AML.T0049", "AML.T0006"]
        );
    }
}
