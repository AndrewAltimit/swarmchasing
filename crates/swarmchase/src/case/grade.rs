//! `case grade`: each cluster's computed agent grade with what it rests on,
//! and the admin's grade for the case. Only this decision reaches L5
//! (documented): operator logs matching a harness, or a provider's
//! confirmation, are case work no record shows.

use super::cli::case_analysis;
use super::*;
use sc_core::{AgentLevel, GradeDecision, Tier};

/// Print the grades, or record (`level`) or remove (`clear`) the decision.
pub(super) fn grade(
    root: &Path,
    id: &str,
    level: Option<AgentLevel>,
    note: Option<&str>,
    clear: bool,
    today: &str,
    out: &mut impl Write,
) -> Result<()> {
    if clear {
        return update(root, id, |c| {
            if c.agent_grade.take().is_none() {
                bail!("case {id} has no agent grade to clear");
            }
            c.log(today, "agent grade cleared");
            Ok(())
        });
    }
    if let Some(level) = level {
        let note = note.map(str::trim).filter(|n| !n.is_empty());
        let Some(note) = note else {
            bail!("an agent grade needs --note: what it rests on, with links");
        };
        return update(root, id, |c| {
            c.log(
                today,
                format!("agent grade: {} {} ({note})", level.code(), level.label()),
            );
            c.agent_grade = Some(GradeDecision {
                level,
                date: today.to_string(),
                note: note.to_string(),
            });
            Ok(())
        });
    }
    let c = load(root, id)?;
    let a = case_analysis(root, &c)?;
    for cl in a.clusters.iter().filter(|cl| cl.tier > Tier::Noise) {
        let g = &cl.agent;
        writeln!(
            out,
            "{} {} [{}] {} {}",
            cl.id,
            cl.key,
            cl.tier.label(),
            g.level.code(),
            g.level.label()
        )?;
        for s in &g.signals {
            let rung = s.kind.level().map_or("", |l| l.code());
            writeln!(out, "  + {rung} {} ({})", s.kind.label(), s.records)?;
        }
        for s in &g.counter {
            writeln!(out, "  - {} ({})", s.kind.label(), s.records)?;
        }
        for cap in &g.caps {
            writeln!(out, "  cap: {}", cap.label())?;
        }
    }
    match &c.agent_grade {
        Some(d) => writeln!(
            out,
            "decision {}: {} {} — {}",
            d.date,
            d.level.code(),
            d.level.label(),
            d.note
        )?,
        None => writeln!(
            out,
            "decision: none (`swarmchase case grade {id} <L0..L5> --note <basis>`)"
        )?,
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::test_support::*;
    use super::*;

    #[test]
    fn grades_show_and_decisions_are_logged() {
        let root = scratch("grade");
        let rules = RulesText::load(None).unwrap();
        let records: Vec<Observation> = fixture().results.iter().map(|r| r.obs.clone()).collect();
        new_case(&root, "g-1", "Portal", records, &rules, "2026-10-12").unwrap();

        let mut out = Vec::new();
        grade(&root, "g-1", None, None, false, "2026-10-12", &mut out).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("[significant] L1 self-described"), "{text}");
        assert!(text.contains("decision: none"), "{text}");

        let l5 = Some(AgentLevel::Documented);
        assert!(grade(&root, "g-1", l5, None, false, "2026-10-13", &mut Vec::new()).is_err());
        grade(
            &root,
            "g-1",
            l5,
            Some("provider confirmed in writing (ticket link)"),
            false,
            "2026-10-13",
            &mut Vec::new(),
        )
        .unwrap();
        let c = load(&root, "g-1").unwrap();
        assert_eq!(
            c.agent_grade.as_ref().unwrap().level,
            AgentLevel::Documented
        );
        assert!(
            c.decisions
                .last()
                .unwrap()
                .text
                .starts_with("agent grade: L5")
        );
        let md = super::super::report(
            &root,
            "g-1",
            sc_core::Audience::Provider,
            None,
            None,
            "2026-10-13",
        )
        .unwrap();
        assert!(
            md.contains("**Case decision** (2026-10-13): L5 documented"),
            "{md}"
        );

        grade(
            &root,
            "g-1",
            None,
            None,
            true,
            "2026-10-14",
            &mut Vec::new(),
        )
        .unwrap();
        assert!(load(&root, "g-1").unwrap().agent_grade.is_none());
        cleanup(&root);
    }
}
