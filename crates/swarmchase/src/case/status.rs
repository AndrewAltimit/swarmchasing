//! `case status`: the list of cases, or one case and what it still needs.

use super::*;
use anyhow::Result;
use sc_core::{Claim, EndpointOptions, Evidence, Role, endpoints, fmt_ts};
use std::io::Write;
use std::path::Path;

pub(crate) fn list(root: &Path, out: &mut impl Write) -> Result<()> {
    let mut cases = all(root)?;
    if cases.is_empty() {
        writeln!(out, "no cases in {}", root.display())?;
        return Ok(());
    }
    cases.sort_by(|a, b| b.opened.cmp(&a.opened).then(a.id.cmp(&b.id)));
    writeln!(
        out,
        "{:<32} {:<10} {:<11} {:<10} title",
        "id", "status", "notice", "opened"
    )?;
    for c in &cases {
        writeln!(
            out,
            "{:<32} {:<10} {:<11} {:<10} {}",
            c.id,
            c.status.label(),
            c.notice.label(),
            c.opened,
            c.title
        )?;
    }
    Ok(())
}

pub(crate) fn status(root: &Path, id: &str, out: &mut impl Write) -> Result<()> {
    let c = load(root, id)?;
    let a = analysis(root, &c, &Scope::All)?;
    writeln!(out, "# {} — {}", c.id, c.title)?;
    writeln!(
        out,
        "status {:?} · notice {:?} · opened {} · developers named at: {}",
        c.status,
        c.notice,
        c.opened,
        c.min_named.max(Evidence::FLOOR).describe()
    )?;
    let current = &sc_core::Rules::default_rules().set.meta.version;
    match &c.rules_version {
        Some(pin) if a.rules_version == *current => writeln!(out, "rules {pin} (pinned)")?,
        Some(pin) => writeln!(
            out,
            "rules {pin} (pinned; current rules {current}, see `swarmchase case rules {}`)",
            c.id
        )?,
        None => writeln!(
            out,
            "rules not pinned; rendering with the current rules {current}"
        )?,
    }
    writeln!(
        out,
        "{} records ({} flagged) · {} clusters · {} → {}",
        a.total,
        a.flagged,
        a.clusters.len(),
        fmt_ts(a.timing.start),
        fmt_ts(a.timing.end)
    )?;
    for cl in &a.clusters {
        writeln!(
            out,
            "  {} {} [{}] {} {} records, {} → {} · {}{}",
            cl.id,
            cl.key,
            cl.tier.label(),
            cl.agent.level.code(),
            cl.members.len(),
            fmt_ts(cl.start),
            fmt_ts(cl.end),
            cl.corroboration.label(),
            c.fleet_of(&cl.key)
                .map(|f| format!(" · {}", f.id))
                .unwrap_or_default()
        )?;
        if !cl.plant_signals.is_empty() {
            let kinds: std::collections::BTreeSet<&str> =
                cl.plant_signals.iter().map(|p| p.kind.label()).collect();
            writeln!(
                out,
                "      plant review: {} (see the case-notes report)",
                kinds.into_iter().collect::<Vec<_>>().join(", ")
            )?;
        }
    }
    if let Some(g) = &c.agent_grade {
        writeln!(
            out,
            "agent grade {} {} (decided {}): {}",
            g.level.code(),
            g.level.label(),
            g.date,
            g.note
        )?;
    }

    writeln!(out, "\nEndpoints")?;
    let views = endpoints(&a, &EndpointOptions::default());
    for e in &c.endpoints {
        let v = views.iter().find(|v| v.host == e.host);
        writeln!(
            out,
            "  {:<12} {:<40} {}{}",
            e.state.label(),
            sc_core::defang_host(&e.host),
            v.map(|v| format!(
                "{} hits, last {}, {}{}",
                v.hits,
                fmt_ts(v.last_seen),
                v.activity.label(),
                if v.payloads { ", payloads" } else { "" }
            ))
            .unwrap_or_default(),
            e.note
                .as_deref()
                .map(|n| format!(" — {n}"))
                .unwrap_or_default()
        )?;
    }

    writeln!(out, "\nAttribution")?;
    let claims = sc_case::report::all_claims(&c, &a);
    if claims.is_empty() {
        writeln!(out, "  none")?;
    }
    for cl in &claims {
        writeln!(
            out,
            "  {:<3} {} ({:?}) — {} · {} · {}",
            if cl.nameable(c.min_named) {
                "✓"
            } else {
                "·"
            },
            cl.party,
            cl.role,
            cl.evidence.describe(),
            cl.label().label(),
            cl.tag().label()
        )?;
    }
    if !c.evidence.is_empty() {
        writeln!(out, "\nOperator evidence")?;
        for e in &c.evidence {
            writeln!(
                out,
                "  {:<4} {} ({}), received {}, {} of {} records kept — {}",
                e.id,
                e.org,
                sc_core::defang_host(&e.host),
                e.received,
                e.kept,
                e.lines,
                e.public
                    .as_deref()
                    .map(|p| format!("may be published ({p})"))
                    .unwrap_or_else(|| "private reports only".into())
            )?;
        }
    }
    writeln!(
        out,
        "\nContacts: {} · decisions: {} · sent: {}",
        c.contacts.len(),
        c.decisions.len(),
        c.sent.len()
    )?;
    if !matches!(c.status, CaseStatus::Published | CaseStatus::Closed) {
        sc_case::lead::show(&c, chrono::Utc::now().timestamp(), out)?;
    }

    let has_draft = case_dir(root, id)?.join(NOTICE_DRAFT).is_file();
    let todo = todo(&c, &claims, has_draft);
    if !todo.is_empty() {
        writeln!(out, "\nNeeds")?;
        for t in todo {
            writeln!(out, "  - {t}")?;
        }
    }
    Ok(())
}

/// What the case still needs before reports can go out.
fn todo(c: &Case, claims: &[Claim], has_draft: bool) -> Vec<String> {
    let mut t = Vec::new();
    let unreviewed = c
        .endpoints
        .iter()
        .filter(|e| e.state == EndpointState::Unreviewed)
        .count();
    if unreviewed > 0 {
        t.push(format!(
            "classify {unreviewed} endpoint(s): `swarmchase case endpoint {} <host>... compromised|targeted|historical|not-affected`",
            c.id
        ));
    }
    let affected = c.endpoints.iter().any(|e| e.state.affected());
    if affected && c.contacts_in(ContactRole::Affected).next().is_none() {
        t.push(format!(
            "find contacts for the affected operators: `swarmchase case contacts {}`",
            c.id
        ));
    }
    if c.contacts_in(ContactRole::Provider).next().is_none() {
        let dir = sc_case::providers::Directory::builtin();
        let known: Vec<&str> = claims
            .iter()
            .filter(|x| matches!(x.role, Role::Developer | Role::Host))
            .filter_map(|x| dir.find(&x.party).map(|p| p.name.as_str()))
            .collect();
        if known.is_empty() {
            t.push(format!(
                "no provider contact: add the provider's security or abuse channel by hand: `swarmchase case contact add {} --party provider --org … --channel email|form|portal --address … --source <link>`",
                c.id
            ));
        } else {
            t.push(format!(
                "no provider contact; the directory has {}: `swarmchase case contacts {} --providers-only`",
                known.join(", "),
                c.id
            ));
        }
    }
    if let Some(d) = &c.publish_pending {
        t.push(format!(
            "notice added {d}, publish pending: commit and push notices/{0}.md, then `swarmchase notice published {0}`",
            c.id
        ));
    } else if !has_draft && matches!(c.status, CaseStatus::Open | CaseStatus::Reported) {
        t.push(format!(
            "no notice draft; draft it after the reports are sent, then re-read it an hour later: `swarmchase case notice {}`",
            c.id
        ));
    } else if matches!(c.status, CaseStatus::Open | CaseStatus::Reported) {
        let undecided: Vec<&str> = AlternativeKind::ALL
            .into_iter()
            .filter(|k| !c.alternatives.iter().any(|x| x.kind == *k))
            .map(|k| k.id())
            .collect();
        if !undecided.is_empty() {
            t.push(format!(
                "decide the alternative explanations ({}): `swarmchase case alternative {} <kind> --rejected \"…\"`",
                undecided.join(", "),
                c.id
            ));
        }
        if c.reread.is_none() {
            t.push(format!(
                "re-read the notice draft an hour or more after writing it: `swarmchase case reread {}`; `swarmchase case checklist {}` shows what `notice add` checks",
                c.id, c.id
            ));
        }
    }
    for e in c
        .endpoints
        .iter()
        .filter(|e| e.state == EndpointState::Compromised && e.basis.is_none())
    {
        t.push(format!(
            "{} is compromised with no recorded basis: `swarmchase case endpoint {} {} compromised --basis \"…\"`",
            sc_core::defang_host(&e.host),
            c.id,
            e.host
        ));
    }
    let named = claims
        .iter()
        .any(|x| x.role == Role::Developer && x.nameable(c.min_named));
    if !named {
        t.push(format!(
            "no developer can be named yet (needs {} or stronger); the provider report can still go to the host",
            c.min_named.max(Evidence::FLOOR).describe()
        ));
    }
    if c.rules_version.is_none() {
        t.push(format!(
            "rules not pinned; pin them so reports stop following rule changes: `swarmchase case rules {} --update`",
            c.id
        ));
    }
    if c.status == CaseStatus::Open && c.sent.is_empty() {
        t.push(format!(
            "draft reports: `swarmchase case report {} --audience provider|affected`",
            c.id
        ));
    }
    t
}
