//! The agent-likelihood block ([`crate::agentness`]): "Why we think this is
//! an agent" in case notes and provider reports, and the one sentence a
//! public notice may carry. The grade has no held-out measurement, so a
//! public notice never prints it.

use super::{Audience, ReportOptions};
use crate::agentness::{AgentLevel, SignalKind};
use crate::analyze::Cluster;
use std::fmt::Write;

/// The strongest grade among `clusters`, or the admin's decision when there
/// is one.
fn grade(clusters: &[&Cluster], opts: &ReportOptions) -> AgentLevel {
    match &opts.agent_grade {
        Some(d) => d.level,
        None => clusters
            .iter()
            .map(|c| c.agent.level)
            .max()
            .unwrap_or_default(),
    }
}

/// What a public notice adds after "attack payloads were present": nothing,
/// unless the grade is at most L1.
pub(super) fn public_note(clusters: &[&Cluster], opts: &ReportOptions) -> &'static str {
    if grade(clusters, opts) <= AgentLevel::SelfDescribed {
        " This alone does not show what sent them."
    } else {
        ""
    }
}

/// "Why we think this is an agent", for case notes and provider reports.
pub(super) fn section(s: &mut String, clusters: &[&Cluster], opts: &ReportOptions) {
    let internal = opts.audience == Audience::Internal;
    if !(internal || opts.audience == Audience::Provider) || clusters.is_empty() {
        return;
    }
    let _ = writeln!(s, "## Why we think this is an agent\n");
    let _ = writeln!(
        s,
        "A person or a conventional scanner sending the same payloads through the same services leaves the same records. Each cluster is graded by the strongest combination of agent signals it shows, from L0 (payloads only) to L4 (agent likely); only case work reaches L5 (documented). Every signal is a hint that people and tools can also produce, and the grade has no held-out measurement yet.\n"
    );
    for c in clusters {
        let g = &c.agent;
        let _ = writeln!(
            s,
            "- **{}**: {} {}. {}",
            c.id,
            g.level.code(),
            g.level.label(),
            g.level.meaning()
        );
        for x in &g.signals {
            let rung = x.kind.level().map_or("", |l| l.code());
            let _ = writeln!(
                s,
                "  - signal ({rung}): {}: {} record(s){}",
                x.kind.label(),
                x.records,
                detail(&x.detail)
            );
        }
        for x in g
            .counter
            .iter()
            .filter(|x| internal || x.kind != SignalKind::DeclaredTesting)
        {
            let _ = writeln!(
                s,
                "  - counter-signal: {}: {} record(s){}",
                x.kind.label(),
                x.records,
                detail(&x.detail)
            );
        }
        for cap in &g.caps {
            let _ = writeln!(s, "  - cap: {}", cap.label());
        }
    }
    if let Some(d) = &opts.agent_grade {
        let _ = writeln!(
            s,
            "- **Case decision** ({}): {} {}. {}{}",
            d.date,
            d.level.code(),
            d.level.label(),
            d.level.meaning(),
            if internal {
                format!(" Basis: {}", d.note)
            } else {
                String::new()
            }
        );
    }
    let _ = writeln!(s);
}

fn detail(d: &str) -> String {
    if d.is_empty() {
        String::new()
    } else {
        format!(" ({})", crate::extract::defang(d))
    }
}

#[cfg(test)]
mod tests {
    use crate::agentness::GradeDecision;
    use crate::model::Observation;
    use crate::report::{Audience, ReportOptions, render_markdown};
    use crate::rules::Rules;

    fn analysis() -> crate::Analysis {
        let obs = (0..3)
            .map(|i| Observation {
                id: format!("t:{i}"),
                ts: 1_791_000_000 + i * 40,
                url: format!("https://shop.example/item?id={i}%20UNION%20SELECT%201"),
                ..Default::default()
            })
            .collect();
        crate::analyze(obs, &Rules::default_rules())
    }

    #[test]
    fn public_notices_never_print_the_grade() {
        let a = analysis();
        let opts = |audience| ReportOptions {
            audience,
            ..Default::default()
        };
        let public = render_markdown(&a, &opts(Audience::Public));
        assert!(
            public.contains("This alone does not show what sent them."),
            "{public}"
        );
        assert!(!public.contains("Why we think this is an agent"));
        assert!(!public.contains("L0"), "{public}");
        let notes = render_markdown(&a, &opts(Audience::Internal));
        assert!(
            notes.contains("## Why we think this is an agent"),
            "{notes}"
        );
        assert!(notes.contains("L0 payloads only"), "{notes}");
        assert!(!render_markdown(&a, &opts(Audience::Affected)).contains("Why we think"));
    }

    #[test]
    fn a_case_decision_is_shown_and_lifts_the_public_note() {
        let a = analysis();
        let decided = |audience| ReportOptions {
            audience,
            agent_grade: Some(GradeDecision {
                level: crate::AgentLevel::Documented,
                date: "2026-10-01".into(),
                note: "evidence e-1 matches a known harness".into(),
            }),
            ..Default::default()
        };
        let provider = render_markdown(&a, &decided(Audience::Provider));
        assert!(provider.contains("**Case decision** (2026-10-01): L5 documented"));
        assert!(!provider.contains("evidence e-1"), "{provider}");
        let notes = render_markdown(&a, &decided(Audience::Internal));
        assert!(notes.contains("Basis: evidence e-1 matches a known harness"));
        let public = render_markdown(&a, &decided(Audience::Public));
        assert!(!public.contains("does not show what sent them"));
    }
}
