//! Drafts for AI incident databases and reporting frameworks (SC-FM 12.3):
//! the AI Incident Database (AIID), the OECD common reporting framework for
//! AI incidents, and, inside the OECD draft, a serious-incident section laid
//! out as Article 73 of the EU AI Act asks of a provider. Files only: the
//! admin reads the draft and submits it by hand, after the notice is
//! public. Nothing here talks to any database or authority.
//!
//! A draft carries only what the notice carries: it is built from the
//! public scope (operator logs only with agreement, compromised endpoints'
//! attack details withheld, [`sc_core::notice::PublicView`]), names a
//! developer only through the case's naming gate with its label and
//! likelihood word, leaves harness and model-family candidates out, and is
//! refused when an endpoint is unreviewed. The caller runs the leak scan
//! over the finished text.

use crate::model::{Case, EndpointState};
use crate::report::{affected_hosts, all_claims, report_options, reported};
use crate::{Result, bail};
use sc_core::notice::PublicView;
use sc_core::{Analysis, Audience, Role, Tier, fmt_ts};
use serde_json::{Value, json};

/// Which database or framework a draft is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Database {
    Aiid,
    Oecd,
}

/// What the case can say in public, gathered once for any draft.
#[derive(Debug, Clone)]
pub struct Public {
    pub title: String,
    pub description: String,
    pub notice_text: String,
    pub first: String,
    pub last: String,
    pub developers: Vec<String>,
    pub hosts: Vec<String>,
    pub affected: Vec<String>,
    pub compromised: bool,
    pub sources: Vec<String>,
    pub notice_url: Option<String>,
}

fn date(ts: i64) -> String {
    fmt_ts(ts).chars().take(10).collect()
}

/// What case `c` can say in public. `a` is its analysis in the public scope
/// under its pinned rules; `notice_text` the published notice's body, else
/// the reviewed draft's (a fresh render when `None`).
pub fn gather(
    c: &Case,
    a: &Analysis,
    notice_text: Option<String>,
    site_url: Option<&str>,
    today: &str,
) -> Result<Public> {
    let unreviewed = c.unreviewed();
    if !unreviewed.is_empty() {
        bail!(
            "classify every endpoint first (unreviewed: {}); the draft withholds attack details for compromised ones",
            unreviewed.join(", ")
        );
    }
    let opts = report_options(c, Audience::Public, None, today);
    let clusters: Vec<&sc_core::Cluster> =
        a.clusters.iter().filter(|x| x.tier > Tier::Noise).collect();
    if clusters.is_empty() {
        bail!("nothing to draft: no non-noise clusters in the public scope");
    }
    let first = clusters.iter().map(|x| x.start).filter(|&t| t > 0).min();
    let last = clusters.iter().map(|x| x.end).max();
    let notice_text = notice_text.unwrap_or_else(|| sc_core::render_notice(a, &opts).markdown);

    let claims = all_claims(c, a);
    let developers = claims
        .iter()
        .filter(|x| x.role == Role::Developer && x.nameable(c.min_named))
        .map(|x| {
            format!(
                "{} ({}: {})",
                x.party,
                x.label().label(),
                x.label().word().unwrap_or("no likelihood word")
            )
        })
        .collect();
    let hosts = claims
        .iter()
        .filter(|x| x.role == Role::Host)
        .map(|x| {
            format!(
                "{} (hosting network; a host is not necessarily the developer)",
                x.party
            )
        })
        .collect();
    let affected = affected_hosts(c);
    let compromised = c
        .endpoints
        .iter()
        .any(|e| e.state == EndpointState::Compromised);

    // Public record links, for records a notice may show.
    let mut view = PublicView::new(a, &opts.exposed_hosts).with_affected(Some(&affected));
    let mut sources = Vec::new();
    for cl in &clusters {
        for &m in &cl.members {
            let r = &a.results[m];
            if let Some(link) = r.obs.reference.as_deref()
                && view.record_url(r).is_some()
                && !sources.iter().any(|s| s == link)
                && sources.len() < 20
            {
                sources.push(link.to_string());
            }
        }
    }
    // The notice page: `<site>/notices/<id>/`, the address it keeps once published.
    let notice_url = site_url.map(|u| format!("{}/notices/{}/", u.trim_end_matches('/'), c.id));
    let description = format!(
        "Automated AI agent activity: {} linked run(s) of {} public record(s) between {} and {}, against {} affected endpoint(s){}.{}",
        clusters.len(),
        clusters.iter().map(|x| x.members.len()).sum::<usize>(),
        first.map(date).unwrap_or_else(|| "an unknown date".into()),
        last.map(date).unwrap_or_else(|| "an unknown date".into()),
        affected.len(),
        if compromised {
            ", at least one with evidence the attack succeeded"
        } else {
            ", with no evidence any attack succeeded"
        },
        reported(c)
            .parties()
            .map(|p| format!(
                " Reported to {p} before the public notice, each with a fixed lead time."
            ))
            .unwrap_or_default()
    );
    Ok(Public {
        title: c.title.clone(),
        description,
        notice_text,
        first: first.map(date).unwrap_or_default(),
        last: last.map(date).unwrap_or_default(),
        developers,
        hosts,
        affected,
        compromised,
        sources,
        notice_url,
    })
}

/// The draft for `db`, as JSON.
pub fn draft(p: &Public, db: Database, reporter: &str, today: &str) -> Value {
    match db {
        Database::Aiid => aiid(p, reporter, today),
        Database::Oecd => oecd(p, reporter, today),
    }
}

fn is_empty(v: &Value) -> bool {
    v.is_null() || v.as_str().is_some_and(str::is_empty) || v.as_array().is_some_and(Vec::is_empty)
}

fn or_missing(v: Value, name: &str, missing: &mut Vec<String>) -> Value {
    if is_empty(&v) {
        missing.push(name.to_string());
    }
    v
}

/// The label every draft carries.
pub const ADMIN: &str = "DRAFT for the admin to review and submit by hand after the notice is public. Nothing was submitted.";

/// AIID: an incident (title, date, description, alleged developer, deployer
/// and harmed parties) with the notice as its report.
pub fn aiid(p: &Public, reporter: &str, today: &str) -> Value {
    let mut missing = Vec::new();
    let url = or_missing(
        json!(p.notice_url),
        "report.url (the published notice's link: pass --site-url)",
        &mut missing,
    );
    let developer = or_missing(
        json!(p.developers),
        "incident.alleged_developer_of_ai_system (no developer passes the naming gate; submit as unknown)",
        &mut missing,
    );
    json!({
        "draft": ADMIN,
        "database": "AI Incident Database (incidentdatabase.ai)",
        "incident": {
            "title": p.title,
            "date": p.first,
            "description": p.description,
            "alleged_developer_of_ai_system": developer,
            "alleged_deployer_of_ai_system": p.developers,
            "alleged_harmed_or_nearly_harmed_parties": p.affected,
            "hosting_networks": p.hosts,
        },
        "report": {
            "title": p.title,
            "url": url,
            "date_published": today,
            "authors": [reporter],
            "submitters": [reporter],
            "text": p.notice_text,
            "source_urls": p.sources,
        },
        "notes": [
            "Developer and deployer are the developer-or-operator layer at or above the case's naming gate, each with its attribution label and likelihood word.",
            "Harness and model-family candidates are never named in public and are left out.",
        ],
        "missing": missing,
    })
}

/// One field of a framework draft: its name, value, whether the framework
/// requires it, and a note for the admin.
fn field(
    name: &str,
    value: Value,
    mandatory: bool,
    note: &str,
    missing: &mut Vec<String>,
) -> Value {
    if mandatory && is_empty(&value) {
        missing.push(name.to_string());
    }
    json!({ "criterion": name, "value": value, "mandatory": mandatory, "note": note })
}

/// The OECD common reporting framework: the criteria the case can fill,
/// with the mandatory ones checked, and the EU AI Act Article 73 section.
pub fn oecd(p: &Public, reporter: &str, today: &str) -> Value {
    let mut missing = Vec::new();
    let kind = if p.compromised { "incident" } else { "hazard" };
    let sources: Vec<String> = p
        .sources
        .iter()
        .cloned()
        .chain(p.notice_url.clone())
        .collect();
    let mut crit = |name: &str, value: Value, mandatory: bool, note: &str| {
        field(name, value, mandatory, note, &mut missing)
    };
    let criteria = vec![
        crit("Title", json!(p.title), false, ""),
        crit(
            "Description of the incident",
            json!(p.description),
            true,
            "Edit to the reader; the published notice is under supporting_text.",
        ),
        crit(
            "Incident or hazard",
            json!(kind),
            false,
            "A hazard when no endpoint shows the attack succeeded (a near miss).",
        ),
        crit(
            "Date of occurrence (first known)",
            json!(p.first),
            false,
            "",
        ),
        crit("Date of occurrence (last known)", json!(p.last), false, ""),
        crit("Date reported", json!(today), false, ""),
        crit(
            "Type of harm",
            Value::Null,
            true,
            "The admin's judgment, e.g. harm to property or to the security of systems; the case does not record it.",
        ),
        crit(
            "Severity of the impact",
            Value::Null,
            true,
            "The admin's judgment; the case does not record it.",
        ),
        crit(
            "Connection between the AI system and the incident",
            json!(
                "Requests were issued by autonomous AI agents (linked runs of automated requests, see the notice); the agents chose the targets and payloads."
            ),
            true,
            "",
        ),
        crit(
            "Affected stakeholders",
            json!(p.affected),
            false,
            "Operators of the affected endpoints.",
        ),
        crit(
            "AI system developer",
            json!(p.developers),
            false,
            "Only at or above the naming gate, with label and likelihood word.",
        ),
        crit(
            "AI system deployer or operator",
            json!(p.developers),
            false,
            "",
        ),
        crit(
            "Hosting infrastructure",
            json!(p.hosts),
            false,
            "A host is not necessarily the developer.",
        ),
        crit(
            "Country",
            Value::Null,
            false,
            "Where the affected operators are; not recorded in the case.",
        ),
        crit(
            "Industry or sector",
            Value::Null,
            false,
            "Of the affected operators; not recorded in the case.",
        ),
        crit(
            "Sources",
            json!(sources),
            false,
            "The published notice and public record links.",
        ),
        crit("Reporter", json!(reporter), false, ""),
    ];
    json!({
        "draft": ADMIN,
        "framework": "OECD common reporting framework for AI incidents (OECD AI Papers No. 34); AI Incidents and Hazards Monitor",
        "criteria": criteria,
        "missing_mandatory": missing,
        "supporting_text": p.notice_text,
        "eu_ai_act_article_73": article_73(p, today),
        "notes": [
            "The criteria marked mandatory are those the OECD names as mandatory; check the full mandatory set against the published framework before submitting.",
            "Harness and model-family candidates are never named in public and are left out.",
        ],
    })
}

/// A serious-incident report laid out as Article 73 of the EU AI Act asks
/// of the provider of a high-risk AI system. The duty to report rests on
/// that provider, and the case does not establish that the agent is a
/// high-risk system; the section is a draft the admin may pass to the
/// provider or to a market surveillance authority, with what the case
/// cannot fill listed.
pub fn article_73(p: &Public, today: &str) -> Value {
    let mut missing = Vec::new();
    let mut f = |name: &str, value: Value, mandatory: bool, note: &str| {
        field(name, value, mandatory, note, &mut missing)
    };
    let fields = vec![
        f(
            "Provider of the AI system",
            json!(p.developers),
            true,
            "The developer layer at or above the naming gate; empty when no developer passes it.",
        ),
        f(
            "AI system and version",
            Value::Null,
            true,
            "Not established from public records.",
        ),
        f(
            "High-risk classification (Annex III area) and EU database registration",
            Value::Null,
            true,
            "Not established; Article 73 applies only to high-risk systems.",
        ),
        f(
            "Description of the incident",
            json!(p.description),
            true,
            "",
        ),
        f(
            "Date of the incident (first and last known)",
            json!([p.first, p.last]),
            true,
            "From the records' timestamps; see the notice for what each timestamp is the time of.",
        ),
        f(
            "Date the reporter became aware",
            json!(today),
            false,
            "The date of this draft; set it to when the case was opened if earlier.",
        ),
        f(
            "Serious incident category (Article 3(49))",
            Value::Null,
            true,
            "The admin's judgment: (a) death or serious harm to health, (b) serious and irreversible disruption of critical infrastructure, (c) infringement of fundamental-rights obligations, (d) serious harm to property or the environment.",
        ),
        f(
            "Affected parties",
            json!(p.affected),
            false,
            "Operators of the affected endpoints, as the notice names them.",
        ),
        f(
            "Causal link between the AI system and the incident",
            json!(
                "Requests were issued by autonomous AI agents (linked runs of automated requests, see the notice); the agents chose the targets and payloads."
            ),
            true,
            "",
        ),
        f(
            "Corrective measures taken",
            Value::Null,
            false,
            "For the provider to state.",
        ),
    ];
    json!({
        "status": "DRAFT, not a filing. Article 73 places the duty to report on the provider of a high-risk AI system; this toolkit is not that provider and does not establish that the system is high-risk.",
        "reporting_periods": "Article 73(2)-(4): no later than 15 days after awareness; 10 days in the event of a death; 2 days for a widespread infringement or a serious incident under Article 3(49)(b).",
        "fields": fields,
        "missing": missing,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::CaseEndpoint;
    use sc_core::{Observation, Rules, analyze};

    fn case_and_analysis() -> (Case, Analysis) {
        let obs: Vec<Observation> = (0..4)
            .map(|i| Observation {
                id: format!("r{i}"),
                ts: 1_791_000_000 + i * 40,
                url: format!(
                    "https://r.jina.ai/https://portal.example.gov/q?id={i}%20UNION%20SELECT%201&uqtag=zz9&agent=hunyuan"
                ),
                reference: Some(format!("https://records.example/r{i}")),
                ..Default::default()
            })
            .collect();
        let a = analyze(obs, &Rules::default_rules());
        let mut c = Case::new("t-1", "Portal probe", "2026-10-12", None);
        c.endpoints.push(CaseEndpoint {
            host: "portal.example.gov".into(),
            ..Default::default()
        });
        (c, a)
    }

    #[test]
    fn drafts_keep_to_the_public_scope() {
        let (mut c, a) = case_and_analysis();
        assert!(
            gather(&c, &a, None, None, "2026-10-20").is_err(),
            "unreviewed"
        );
        c.endpoints[0].state = EndpointState::Targeted;
        let p = gather(&c, &a, None, Some("https://s.example/n/"), "2026-10-20").unwrap();
        let v = draft(&p, Database::Aiid, "Reporter", "2026-10-20");
        assert_eq!(v["report"]["url"], "https://s.example/n/notices/t-1/");
        assert_eq!(v["incident"]["alleged_developer_of_ai_system"], json!([]));
        assert!(
            v["missing"][0]
                .as_str()
                .unwrap()
                .contains("alleged_developer")
        );
        assert!(
            v["report"]["source_urls"]
                .as_array()
                .unwrap()
                .iter()
                .any(|s| s == "https://records.example/r0")
        );

        let v = draft(&p, Database::Oecd, "Reporter", "2026-10-20");
        assert_eq!(
            v["missing_mandatory"],
            json!(["Type of harm", "Severity of the impact"])
        );
        let art = &v["eu_ai_act_article_73"];
        assert!(
            art["status"]
                .as_str()
                .unwrap()
                .starts_with("DRAFT, not a filing")
        );
        assert!(
            art["missing"]
                .as_array()
                .unwrap()
                .iter()
                .any(|m| m == "Serious incident category (Article 3(49))"),
            "{art:#}"
        );
        assert!(
            v["draft"]
                .as_str()
                .unwrap()
                .contains("Nothing was submitted")
        );
    }
}
