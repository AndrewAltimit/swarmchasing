//! Drafts for AI incident databases (SC-FM 12.3): the AI Incident Database
//! (AIID) and the OECD AI Incidents and Hazards Monitor's common reporting
//! framework. Files only: the admin reads the draft and submits it by hand,
//! after the notice is public. Nothing here talks to either database.
//!
//! A draft carries only what the notice carries: it is built from the
//! public scope (operator logs only with agreement, compromised endpoints'
//! attack details withheld, [`sc_core::notice::PublicView`]), names a
//! developer only through the case's naming gate with its label and
//! likelihood word, leaves harness and model-family candidates out, and is
//! refused when the lint finds anything a notice must not carry or when an
//! endpoint is unreviewed.

use super::*;
use crate::pinning::{case_rules, leak_check};
use anyhow::{Result, bail};
use sc_core::attribution::merge;
use sc_core::notice::{PublicView, lint_public};
use sc_core::{Audience, Role, Tier, analyze, attribute, fmt_ts};
use serde_json::{Value, json};
use std::path::Path;

/// Which database a draft is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Database {
    Aiid,
    Oecd,
}

/// What the case can say in public, gathered once for either draft.
struct Public {
    title: String,
    description: String,
    notice_text: String,
    first: String,
    last: String,
    developers: Vec<String>,
    hosts: Vec<String>,
    affected: Vec<String>,
    compromised: bool,
    sources: Vec<String>,
    notice_url: Option<String>,
}

/// The draft for `db`, pretty-printed JSON.
pub fn draft(
    root: &Path,
    notices: &Path,
    id: &str,
    db: Database,
    reporter: &str,
    site_url: Option<&str>,
    today: &str,
) -> Result<String> {
    let c = load(root, id)?;
    let p = gather(root, notices, &c, site_url, today)?;
    let v = match db {
        Database::Aiid => aiid(&p, reporter, today),
        Database::Oecd => oecd(&p, reporter, today),
    };
    let text = format!("{}\n", serde_json::to_string_pretty(&v)?);
    let problems = leak_check(root, &c, |r| lint_public(&text, r))?;
    if !problems.is_empty() {
        bail!(
            "the draft would carry what a notice must not:\n  {}",
            problems.join("\n  ")
        );
    }
    Ok(text)
}

fn date(ts: i64) -> String {
    fmt_ts(ts).chars().take(10).collect()
}

fn gather(
    root: &Path,
    notices: &Path,
    c: &Case,
    site_url: Option<&str>,
    today: &str,
) -> Result<Public> {
    let unreviewed: Vec<&str> = c
        .endpoints
        .iter()
        .filter(|e| e.state == EndpointState::Unreviewed)
        .map(|e| e.host.as_str())
        .collect();
    if !unreviewed.is_empty() {
        bail!(
            "classify every endpoint first (unreviewed: {}); the draft withholds attack details for compromised ones",
            unreviewed.join(", ")
        );
    }
    let rules = case_rules(root, c)?;
    let a = analyze(case_records(root, c, &Scope::Public)?, &rules);
    let opts = report_options(c, Audience::Public, None, today);
    let notice = sc_core::render_notice(&a, &opts);
    let clusters: Vec<&sc_core::Cluster> =
        a.clusters.iter().filter(|x| x.tier > Tier::Noise).collect();
    if clusters.is_empty() {
        bail!("nothing to draft: no non-noise clusters in the public scope");
    }
    let first = clusters.iter().map(|x| x.start).filter(|&t| t > 0).min();
    let last = clusters.iter().map(|x| x.end).max();

    // The published notice's text, else the reviewed draft, else a fresh render.
    let committed = notices.join(format!("{}.md", c.id));
    let draft = case_dir(root, &c.id)?.join(NOTICE_DRAFT);
    let notice_text = [committed, draft]
        .iter()
        .find_map(|p| std::fs::read_to_string(p).ok())
        .and_then(|t| sc_publish::parse_notice(&t).ok())
        .map(|n| sc_publish::strip_draft_banner(&n.body))
        .unwrap_or(notice.markdown.clone());

    let claims = a
        .clusters
        .iter()
        .fold(c.claims.clone(), |acc, cl| merge(acc, &attribute(&a, cl)));
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
    let affected: Vec<String> = c
        .endpoints
        .iter()
        .filter(|e| {
            matches!(
                e.state,
                EndpointState::Compromised | EndpointState::Targeted | EndpointState::Historical
            )
        })
        .map(|e| e.host.clone())
        .collect();
    let compromised = c
        .endpoints
        .iter()
        .any(|e| e.state == EndpointState::Compromised);

    // Public record links, for records a notice may show.
    let mut view = PublicView::new(&a, &opts.exposed_hosts);
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
    let notice_url = site_url.map(|u| format!("{}/#notice={}", u.trim_end_matches('/'), c.id));
    let description = format!(
        "Automated AI agent activity: {} linked run(s) of {} public record(s) between {} and {}, against {} affected endpoint(s){}. Reported to the AI provider and the affected operators at the same time as the public notice.",
        clusters.len(),
        clusters.iter().map(|x| x.members.len()).sum::<usize>(),
        first.map(date).unwrap_or_else(|| "an unknown date".into()),
        last.map(date).unwrap_or_else(|| "an unknown date".into()),
        affected.len(),
        if compromised {
            ", at least one with evidence the attack succeeded"
        } else {
            ", with no evidence any attack succeeded"
        }
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

fn or_missing(v: Value, name: &str, missing: &mut Vec<String>) -> Value {
    let empty = v.is_null()
        || v.as_str().is_some_and(str::is_empty)
        || v.as_array().is_some_and(Vec::is_empty);
    if empty {
        missing.push(name.to_string());
    }
    v
}

const ADMIN: &str = "DRAFT for the admin to review and submit by hand after the notice is public. Nothing was submitted.";

/// AIID: an incident (title, date, description, alleged developer, deployer
/// and harmed parties) with the notice as its report.
fn aiid(p: &Public, reporter: &str, today: &str) -> Value {
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

/// The OECD common reporting framework: the criteria the case can fill,
/// grouped as the framework groups them, with the mandatory ones checked.
fn oecd(p: &Public, reporter: &str, today: &str) -> Value {
    let mut missing_mandatory = Vec::new();
    let kind = if p.compromised { "incident" } else { "hazard" };
    let mut crit = |name: &str, value: Value, mandatory: bool, note: &str| {
        let empty = value.is_null()
            || value.as_str().is_some_and(str::is_empty)
            || value.as_array().is_some_and(Vec::is_empty);
        if empty && mandatory {
            missing_mandatory.push(name.to_string());
        }
        json!({ "criterion": name, "value": value, "mandatory": mandatory, "note": note })
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
            json!(
                p.sources
                    .iter()
                    .cloned()
                    .chain(p.notice_url.clone())
                    .collect::<Vec<_>>()
            ),
            false,
            "The published notice and public record links.",
        ),
        crit("Reporter", json!(reporter), false, ""),
    ];
    json!({
        "draft": ADMIN,
        "framework": "OECD common reporting framework for AI incidents (OECD AI Papers No. 34); AI Incidents and Hazards Monitor",
        "criteria": criteria,
        "missing_mandatory": missing_mandatory,
        "supporting_text": p.notice_text,
        "notes": [
            "The criteria marked mandatory are those the OECD names as mandatory; check the full mandatory set against the published framework before submitting.",
            "Harness and model-family candidates are never named in public and are left out.",
        ],
    })
}

#[cfg(test)]
mod tests {
    use super::super::test_support::*;
    use super::*;
    use crate::pinning::RulesText;
    use sc_core::Observation;

    #[test]
    fn drafts_keep_to_the_public_scope() {
        let root = scratch("incident");
        let rules = RulesText::load(None).unwrap();
        let mut records: Vec<Observation> =
            fixture().results.iter().map(|r| r.obs.clone()).collect();
        for r in records.iter_mut() {
            r.reference = Some(format!("https://records.example/{}", r.id));
        }
        new_case(&root, "t-1", "Portal probe", records, &rules, "2026-10-12").unwrap();
        let notices = root.join("notices");
        let run = |db| {
            draft(
                &root,
                &notices,
                "t-1",
                db,
                "Reporter",
                Some("https://s.example/n/"),
                "2026-10-20",
            )
        };
        assert!(run(Database::Aiid).is_err(), "unreviewed endpoints");
        update(&root, "t-1", |c| {
            c.endpoints[0].state = EndpointState::Targeted;
            for e in c.endpoints.iter_mut().skip(1) {
                e.state = EndpointState::NotAffected;
            }
            Ok(())
        })
        .unwrap();

        let aiid: Value = serde_json::from_str(&run(Database::Aiid).unwrap()).unwrap();
        assert_eq!(aiid["incident"]["title"], "Portal probe");
        assert_eq!(
            aiid["incident"]["alleged_harmed_or_nearly_harmed_parties"],
            json!(["portal.example.gov"])
        );
        assert_eq!(aiid["report"]["url"], "https://s.example/n/#notice=t-1");
        // Self-identification plus a same-company network does not pass the
        // default gate: no developer, and that is listed as missing.
        assert_eq!(
            aiid["incident"]["alleged_developer_of_ai_system"],
            json!([])
        );
        assert!(
            aiid["missing"][0]
                .as_str()
                .unwrap()
                .contains("alleged_developer")
        );
        assert!(!aiid.to_string().contains("python-httpx"));
        assert!(
            aiid["report"]["source_urls"]
                .as_array()
                .unwrap()
                .iter()
                .any(|s| s == "https://records.example/r0")
        );

        update(&root, "t-1", |c| {
            c.claims.push(sc_core::Claim {
                details: vec!["provider statement".into()],
                ..sc_core::Claim::new(
                    "Tencent",
                    Role::Developer,
                    sc_core::Evidence::ProviderConfirmed,
                )
            });
            Ok(())
        })
        .unwrap();
        let oecd: Value = serde_json::from_str(&run(Database::Oecd).unwrap()).unwrap();
        let crit = |n: &str| {
            oecd["criteria"]
                .as_array()
                .unwrap()
                .iter()
                .find(|c| c["criterion"] == n)
                .unwrap()["value"]
                .clone()
        };
        assert_eq!(
            crit("AI system developer"),
            json!(["Tencent (Confirmed: almost certain)"])
        );
        assert_eq!(crit("Incident or hazard"), "hazard");
        assert_eq!(
            oecd["missing_mandatory"],
            json!(["Type of harm", "Severity of the impact"])
        );
        assert!(
            oecd["draft"]
                .as_str()
                .unwrap()
                .contains("Nothing was submitted")
        );
        cleanup(&root);
    }
}
