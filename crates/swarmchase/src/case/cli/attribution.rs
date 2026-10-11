//! Attribution from case work: `claim`, and `grade` (each cluster's agent
//! grade, and the admin's grade for the case: the only way to L5,
//! documented: operator logs matching a harness, or a provider's
//! confirmation, are case work no record shows).

use super::Ctx;
use crate::case::{Scope, analysis, load, update};
use anyhow::Result;
use clap::Args;
use sc_case::actions::{self, ClaimInput};
use sc_core::{AgentLevel, Evidence, Role, Tag, Tier};
use std::io::Write;

#[derive(Args)]
pub struct ClaimArgs {
    id: String,
    #[arg(long)]
    party: String,
    /// developer | host | harness | model_family
    #[arg(long, alias = "role", default_value = "developer")]
    layer: Role,
    /// shared_identifiers | provider_infrastructure | provider_confirmed | …
    /// Required for developer and host claims.
    #[arg(long)]
    evidence: Option<Evidence>,
    /// observed | documented | inference | conclusion. Default: derived
    /// from the layer and evidence.
    #[arg(long)]
    tag: Option<Tag>,
    /// Model family: the method's likelihood for this family (0..1).
    #[arg(long)]
    likelihood: Option<f64>,
    /// Model family: the method's accuracy on a held-out set (0..1).
    #[arg(long)]
    accuracy: Option<f64>,
    /// Model family: the size of the corpus the method was tuned on.
    #[arg(long)]
    corpus_size: Option<usize>,
    /// What the evidence is, with a link. Repeatable.
    #[arg(long = "detail", required = true)]
    details: Vec<String>,
}

#[derive(Args)]
pub struct ScopeArgs {
    id: String,
    /// The cluster, by C-number or stable key.
    #[arg(long)]
    cluster: String,
    /// in-scope | exceeded | not-assessable
    #[arg(long, value_parser = sc_case::model::parse_finding)]
    finding: sc_core::scope::ScopeFinding,
    /// The failed scope tests, e.g. S2,S4. Required for exceeded.
    #[arg(long, value_delimiter = ',')]
    tests: Vec<String>,
    /// What the finding rests on, with the records.
    #[arg(long)]
    note: String,
}

#[derive(Args)]
pub struct GradeArgs {
    id: String,
    /// L0..L5, or a name such as `model_written` or `documented`. Omit to
    /// show the grades.
    level: Option<AgentLevel>,
    /// What the decision rests on, with links. Required with a level.
    #[arg(long)]
    note: Option<String>,
    /// Remove the decision.
    #[arg(long, conflicts_with = "level")]
    clear: bool,
}

pub(super) fn claim(ctx: &Ctx, a: ClaimArgs) -> Result<()> {
    update(&ctx.root, &a.id, |c| {
        let x = ClaimInput {
            party: a.party,
            layer: a.layer,
            evidence: a.evidence,
            tag: a.tag,
            likelihood: a.likelihood,
            accuracy: a.accuracy,
            corpus_size: a.corpus_size,
            details: a.details,
        };
        Ok(actions::claim(c, x, &ctx.today)?)
    })
}

pub(super) fn scope(ctx: &Ctx, a: ScopeArgs) -> Result<()> {
    let c = load(&ctx.root, &a.id)?;
    let an = analysis(&ctx.root, &c, &Scope::All)?;
    let key = sc_case::fleet::resolve(&an, &a.cluster)?;
    if let Some(cl) = sc_case::fleet::by_key(&an, &key)
        && !cl.scope.is_default()
    {
        println!(
            "the scope pass suggests: {} (the finding recorded is yours)",
            cl.scope.finding.label()
        );
    }
    update(&ctx.root, &a.id, |c| {
        Ok(actions::scope(
            c, &key, a.finding, &a.tests, &a.note, &ctx.today,
        )?)
    })
}

/// Print the grades, or record (`level`) or remove (`clear`) the decision.
pub(super) fn grade(ctx: &Ctx, a: GradeArgs, out: &mut impl Write) -> Result<()> {
    if a.clear {
        return update(&ctx.root, &a.id, |c| {
            Ok(actions::clear_grade(c, &ctx.today)?)
        });
    }
    if let Some(level) = a.level {
        return update(&ctx.root, &a.id, |c| {
            Ok(actions::grade(c, level, a.note.as_deref(), &ctx.today)?)
        });
    }
    let c = load(&ctx.root, &a.id)?;
    show(&c, &analysis(&ctx.root, &c, &Scope::All)?, out)
}

fn show(c: &sc_case::Case, a: &sc_core::Analysis, out: &mut impl Write) -> Result<()> {
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
            "decision {}: {} {}, {}",
            d.date,
            d.level.code(),
            d.level.label(),
            d.note
        )?,
        None => writeln!(
            out,
            "decision: none (`swarmchase case grade {} <L0..L5> --note <basis>`)",
            c.id
        )?,
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::case::test_support::*;
    use crate::case::{new_case, report};
    use crate::pinning::RulesText;
    use sc_core::Observation;
    use std::path::Path;

    fn ctx(root: &Path, today: &str) -> Ctx {
        Ctx {
            data: root.parent().unwrap().to_path_buf(),
            root: root.to_path_buf(),
            today: today.into(),
            now: 0,
        }
    }

    fn args(level: Option<AgentLevel>, note: Option<&str>, clear: bool) -> GradeArgs {
        GradeArgs {
            id: "g-1".into(),
            level,
            note: note.map(str::to_string),
            clear,
        }
    }

    #[test]
    fn grades_show_and_decisions_are_logged() {
        let root = scratch("grade");
        let rules = RulesText::load(None).unwrap();
        let records: Vec<Observation> = fixture().results.iter().map(|r| r.obs.clone()).collect();
        new_case(&root, "g-1", "Portal", records, &rules, "2026-10-12").unwrap();

        let mut out = Vec::new();
        grade(&ctx(&root, "2026-10-12"), args(None, None, false), &mut out).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("[significant] L1 self-described"), "{text}");
        assert!(text.contains("decision: none"), "{text}");

        let l5 = Some(AgentLevel::Documented);
        let day = ctx(&root, "2026-10-13");
        assert!(grade(&day, args(l5, None, false), &mut Vec::new()).is_err());
        grade(
            &day,
            args(
                l5,
                Some("provider confirmed in writing (ticket link)"),
                false,
            ),
            &mut Vec::new(),
        )
        .unwrap();
        let c = load(&root, "g-1").unwrap();
        assert_eq!(
            c.agent_grade.as_ref().unwrap().level,
            AgentLevel::Documented
        );
        let md = report(
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
            &ctx(&root, "2026-10-14"),
            args(None, None, true),
            &mut Vec::new(),
        )
        .unwrap();
        assert!(load(&root, "g-1").unwrap().agent_grade.is_none());
        cleanup(&root);
    }
}
