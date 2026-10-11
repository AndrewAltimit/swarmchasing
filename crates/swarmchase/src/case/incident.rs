//! Drafts for AI incident databases and reporting frameworks (SC-FM 12.3),
//! from a case directory: the public-scope analysis, the published notice
//! or the reviewed draft, and the leak scan over the finished draft. What a
//! draft holds is [`sc_case::incident`]. Files only; nothing is submitted.

use super::*;
use crate::pinning::leak_check;
use anyhow::{Result, bail};
use sc_case::incident::{self, Database};
use sc_core::notice::lint_public;
use std::path::Path;

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
    let a = analysis(root, &c, &Scope::Public)?;
    // The published notice's text, else the reviewed draft.
    let committed = notices.join(format!("{}.md", c.id));
    let draft = case_dir(root, &c.id)?.join(NOTICE_DRAFT);
    let notice_text = [committed, draft]
        .iter()
        .find_map(|p| std::fs::read_to_string(p).ok())
        .and_then(|t| sc_case::notice::parse_notice(&t).ok())
        .map(|n| sc_case::notice::strip_draft_banner(&n.body));
    let p = incident::gather(&c, &a, notice_text, site_url, today)?;
    let v = incident::draft(&p, db, reporter, today);
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

#[cfg(test)]
mod tests {
    use super::super::test_support::*;
    use super::*;
    use crate::pinning::RulesText;
    use serde_json::{Value, json};

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
        assert!(!aiid.to_string().contains("python-httpx"));

        update(&root, "t-1", |c| {
            c.claims.push(sc_core::Claim {
                details: vec!["provider statement".into()],
                ..sc_core::Claim::new(
                    "Tencent",
                    sc_core::Role::Developer,
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
            oecd["eu_ai_act_article_73"]["fields"][0]["value"],
            json!(["Tencent (Confirmed: almost certain)"])
        );
        cleanup(&root);
    }
}
