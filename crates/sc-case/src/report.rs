//! What a report rendered from a case is given: its options, the hosts it
//! may name, who the recorded sends reached, and the claims it sees.

use crate::model::{Case, ContactRole, EndpointState};
use sc_core::{Analysis, Audience, Claim, ReportOptions, Reported, Role};
use std::collections::BTreeMap;

pub fn report_options(
    c: &Case,
    audience: Audience,
    reporter: Option<String>,
    today: &str,
) -> ReportOptions {
    ReportOptions {
        audience,
        reporter,
        generated: Some(today.to_string()),
        min_named: c.min_named,
        claims: c.claims.clone(),
        agent_grade: c.agent_grade.clone(),
        exposed_hosts: compromised_hosts(c),
        affected_hosts: Some(affected_hosts(c)),
        reported: Some(reported(c)),
        ..Default::default()
    }
}

/// The endpoints the admin classified compromised.
pub fn compromised_hosts(c: &Case) -> Vec<String> {
    c.endpoints
        .iter()
        .filter(|e| e.state == EndpointState::Compromised)
        .map(|e| e.host.clone())
        .collect()
}

/// The endpoints the admin classified as affected: compromised, targeted or
/// historical. A public notice names these hosts and no others.
pub fn affected_hosts(c: &Case) -> Vec<String> {
    c.endpoints
        .iter()
        .filter(|e| e.state.affected())
        .map(|e| e.host.clone())
        .collect()
}

/// How an indicator notice describes each affected endpoint in place of
/// its host: the admin's description (`case endpoint --sector`), else "an
/// affected organisation". Keyed by lowercased host.
pub fn target_descriptions(c: &Case) -> BTreeMap<String, String> {
    c.endpoints
        .iter()
        .filter(|e| e.state.affected())
        .map(|e| (e.host.to_ascii_lowercase(), description(e)))
        .collect()
}

/// How an indicator notice describes affected endpoint `e`.
pub fn description(e: &crate::model::CaseEndpoint) -> String {
    e.sector
        .clone()
        .unwrap_or_else(|| "an affected organisation".into())
}

/// Which parties the case's recorded sends reached. A send's recipient is
/// matched to a contact by address or organisation; failing that, the draft
/// it names says its audience. Anything else counts as another responder.
pub fn reported(c: &Case) -> Reported {
    let mut r = Reported::default();
    for s in &c.sent {
        let role = c
            .contacts
            .iter()
            .find(|x| {
                x.address.eq_ignore_ascii_case(&s.recipient)
                    || x.org.eq_ignore_ascii_case(&s.recipient)
            })
            .map(|x| x.role);
        let draft = s.report.as_deref().unwrap_or_default();
        match role {
            Some(ContactRole::Provider) => r.provider = true,
            Some(ContactRole::Affected) => r.operators = true,
            Some(_) => r.others = true,
            None if draft.contains("-provider-") => r.provider = true,
            None if draft.contains("-affected-") => r.operators = true,
            None => r.others = true,
        }
    }
    r
}

/// The case's claims together with the records' own, as reports see them.
pub fn all_claims(c: &Case, a: &Analysis) -> Vec<Claim> {
    a.clusters.iter().fold(c.claims.clone(), |acc, cl| {
        sc_core::attribution::merge(acc, &sc_core::attribute(a, cl))
    })
}

/// Developers a public text may name: at or above the case's naming
/// threshold, in claim order, without repeats.
pub fn nameable_developers(c: &Case, claims: &[Claim]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for x in claims
        .iter()
        .filter(|x| x.role == Role::Developer && x.nameable(c.min_named))
    {
        if out.last() != Some(&x.party) {
            out.push(x.party.clone());
        }
    }
    out
}
