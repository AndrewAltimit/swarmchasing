//! Report drafts from a case, and the unsent drafts for one contact.

use super::*;
use anyhow::{Result, bail};
use sc_case::text::audience_id;
use sc_core::{Audience, render_markdown};
use std::path::{Path, PathBuf};

pub(crate) fn report(
    root: &Path,
    id: &str,
    audience: Audience,
    reporter: Option<String>,
    to: Option<&Contact>,
    today: &str,
) -> Result<String> {
    if audience == Audience::Affected && to.is_none() {
        bail!(
            "an affected report is for one operator and covers its own endpoints only: pass --to <contact address>"
        );
    }
    let c = load(root, id)?;
    let sc = scope(audience, to);
    let a = analysis(root, &c, &sc)?;
    let md = render_markdown(&a, &report_options(&c, audience, reporter, today));
    let md = sc_case::fleet::with_fleets(md, &sc_case::fleet::report_section(&c, &a, audience));
    // The wider counts read the case's own records and only the logs their
    // operators agreed to publish: another operator's private logs never
    // move what this one is told.
    let md = match sc.hosts(&c, &sc_collect::psl::registrable_domain) {
        Some(hosts) => before_requested_action(
            md,
            &wider_activity(&analysis(root, &c, &Scope::Public)?, &a, &hosts),
        ),
        None => md,
    };
    // A recipient learns when the notice goes public, and that the time is
    // fixed.
    Ok(match audience {
        Audience::Provider | Audience::Affected => format!(
            "{}\n\n{}",
            md.trim_end(),
            sc_case::lead::publication_section(&c, to, chrono::Utc::now().timestamp())
        ),
        _ => md,
    })
}

/// `md` with `section` put before its requested action, or at the end.
fn before_requested_action(md: String, section: &str) -> String {
    if section.is_empty() {
        return md;
    }
    match md.find("## Requested action") {
        Some(i) => format!("{}{section}\n{}", &md[..i], &md[i..]),
        None => format!("{md}\n{section}"),
    }
}

/// For a report to one operator, what the rest of the case says about its
/// records without naming anyone else, read from the case's records and the
/// operator logs agreed for publication (`all`): how many linked clusters
/// in the case hold them, how large those are and how many other hosts they reached
/// (counted, never named), and the operator's own flagged records that link
/// to the activity only through records elsewhere, which its scoped
/// analysis (`own`) therefore puts in no cluster. Empty when its records are
/// in no cluster of the case.
fn wider_activity(
    all: &sc_core::Analysis,
    own: &sc_core::Analysis,
    hosts: &BTreeSet<String>,
) -> String {
    use std::fmt::Write;
    let mine = |r: &sc_core::ObsResult| {
        r.target_host
            .as_deref()
            .is_some_and(|h| hosts.contains(&h.to_ascii_lowercase()))
    };
    let clusters: Vec<&sc_core::Cluster> = all
        .clusters
        .iter()
        .filter(|cl| cl.tier > sc_core::Tier::Noise)
        .filter(|cl| cl.members.iter().any(|&m| mine(&all.results[m])))
        .collect();
    if clusters.is_empty() {
        return String::new();
    }
    let records: usize = clusters.iter().map(|cl| cl.members.len()).sum();
    let others: BTreeSet<String> = clusters
        .iter()
        .flat_map(|cl| cl.target_hosts.keys())
        .map(|h| h.to_ascii_lowercase())
        .filter(|h| !hosts.contains(h))
        .collect();
    let mut s = String::from("## Wider activity\n\n");
    let _ = writeln!(
        s,
        "In this case, the requests aimed at your systems belong to {} linked cluster(s) of {records} records in all ({}), which also reached {} other host(s). We do not name other parties in a report to you.\n",
        clusters.len(),
        clusters
            .iter()
            .map(|cl| format!("`{}`, {}", cl.key, cl.tier.label()))
            .collect::<Vec<_>>()
            .join("; "),
        others.len()
    );
    let in_own: BTreeSet<&str> = own
        .clusters
        .iter()
        .filter(|cl| cl.tier > sc_core::Tier::Noise)
        .flat_map(|cl| cl.members.iter().map(|&m| own.results[m].obs.id.as_str()))
        .collect();
    let mut lone: Vec<&sc_core::ObsResult> = clusters
        .iter()
        .flat_map(|cl| cl.members.iter().map(|&m| &all.results[m]))
        .filter(|r| mine(r) && !in_own.contains(r.obs.id.as_str()))
        .collect();
    lone.sort_by(|x, y| x.obs.ts.cmp(&y.obs.ts).then(x.obs.id.cmp(&y.obs.id)));
    lone.dedup_by(|x, y| x.obs.id == y.obs.id);
    if !lone.is_empty() {
        let _ = writeln!(
            s,
            "Requests to your systems that link to this activity only through records elsewhere (URLs defanged):\n"
        );
        for r in lone.iter().take(10) {
            let rules: Vec<&str> = r.hits.iter().map(|h| h.rule_id.as_str()).collect();
            let _ = writeln!(
                s,
                "1. {}: `{}`\n   - rules: {}",
                sc_core::fmt_ts(r.obs.ts),
                sc_core::clip_defanged(&sc_core::defang(&r.obs.url), 240),
                rules.join(", ")
            );
        }
        if lone.len() > 10 {
            let _ = writeln!(s, "\n{} more not listed.", lone.len() - 10);
        }
        s.push('\n');
    }
    s
}

/// The contact `to` names in case `c`, any case, or an error naming the
/// closest one.
pub(crate) fn find_contact<'a>(c: &'a Case, to: &str) -> Result<&'a Contact> {
    match c
        .contacts
        .iter()
        .find(|x| x.address.eq_ignore_ascii_case(to.trim()))
    {
        Some(x) => Ok(x),
        None => {
            let known: Vec<&str> = c.contacts.iter().map(|x| x.address.as_str()).collect();
            bail!(
                "`{to}` is not a contact in case {}{} (known: {}); add it to case.toml or run `case contacts`",
                c.id,
                sc_case::text::did_you_mean(to, known.iter().copied()),
                if known.is_empty() {
                    "none".into()
                } else {
                    known.join(", ")
                }
            )
        }
    }
}

/// The outbox file stem for a draft to `address`: the date, the audience,
/// the address as a slug and a short hash of the address, so two addresses
/// that slug alike (`a.b@x.org`, `a-b@x.org`) never share a file.
pub(crate) fn stem(today: &str, audience: Audience, address: &str) -> String {
    let address = address.trim().to_ascii_lowercase();
    let slug: String = address
        .chars()
        .map(|ch| if ch.is_ascii_alphanumeric() { ch } else { '-' })
        .collect();
    let hash = sc_case::bundle::sha256_hex(address.as_bytes());
    format!("{today}-{}-{slug}-{}", audience_id(audience), &hash[..6])
}

/// Write the report for one contact into the outbox: an unsent .eml with a
/// fresh bundle attached for e-mail contacts, paste-ready text naming the
/// fresh bundle otherwise. The bundle holds what the report may: for an
/// operator, only the records on its own endpoints. A draft already in the
/// outbox (it may be hand-edited) is kept unless `force`.
pub(crate) fn draft(
    root: &Path,
    id: &str,
    audience: Audience,
    to: &str,
    reporter: Option<String>,
    today: &str,
    force: bool,
) -> Result<PathBuf> {
    if matches!(audience, Audience::Internal | Audience::Public) {
        bail!(
            "only provider and affected reports are sent; case notes stay private and the notice is published (`case notice`)"
        );
    }
    let c = load(root, id)?;
    let contact = find_contact(&c, to)?;
    let dir = case_dir(root, id)?;
    let outbox = dir.join("outbox");
    let stem = stem(today, audience, &contact.address);
    let p = outbox.join(if contact.channel == "email" {
        format!("{stem}.eml")
    } else {
        format!("{stem}.md")
    });
    if p.exists() && !force {
        bail!(
            "{} exists (it may hold your edits); pass --force to write it again",
            p.display()
        );
    }
    let md = report(root, id, audience, reporter, Some(contact), today)?;
    std::fs::create_dir_all(&outbox)?;
    let pinned = Pinned::new(root, &c)?;
    let bundle = crate::bundle::write(
        &dir.join("bundles"),
        id,
        &case_records(root, &c, &scope(audience, Some(contact)))?,
        &pinned.rules,
        today,
        crate::bundle::git_commit(),
        crate::signing::signer()?.as_ref(),
    )?;
    if contact.channel != "email" {
        crate::store::write_atomic(
            &p,
            format!(
                "<!-- Paste into {} ({}). Attach the bundle in {} if the form accepts files; it is the one made for this recipient. -->\n\n{md}",
                contact.address,
                contact.channel,
                bundle.display()
            )
            .as_bytes(),
        )?;
        return Ok(p);
    }
    let subject = match audience {
        Audience::Provider => format!("Suspected AI agent activity: {} [{id}]", c.title),
        _ => format!(
            "Automated agent activity targeting your systems: {} [{id}]",
            c.title
        ),
    };
    crate::store::write_atomic(
        &p,
        crate::bundle::eml(
            &contact.address,
            &subject,
            &md,
            &crate::bundle::attachments(&bundle)?,
        )
        .as_bytes(),
    )?;
    Ok(p)
}

#[cfg(test)]
mod tests {
    use super::super::test_support::*;
    use super::super::{analysis, case_dir, load, new_case, update};
    use super::*;
    use crate::pinning::RulesText;
    use sc_case::evidence::OperatorEvidence;
    use sc_core::Observation;

    #[test]
    fn another_operators_private_logs_leave_the_wider_counts_alone() {
        let root = scratch("wider");
        let rules = RulesText::load(None).unwrap();
        let records: Vec<Observation> = fixture().results.iter().map(|r| r.obs.clone()).collect();
        new_case(&root, "w-1", "Wider", records, &rules, "2026-10-12").unwrap();
        let contact = |org: &str, host: &str| Contact {
            org: org.into(),
            role: ContactRole::Affected,
            endpoint: Some(host.into()),
            channel: "email".into(),
            address: format!("security@{host}"),
            source: String::new(),
            confidence: "medium".into(),
            found_on: "d".into(),
            purpose: None,
        };
        update(&root, "w-1", |c| {
            for e in &mut c.endpoints {
                e.state = EndpointState::Targeted;
            }
            c.contacts = vec![
                contact("example.gov", "portal.example.gov"),
                contact("elsewhere.example", "elsewhere.example"),
            ];
            Ok(())
        })
        .unwrap();
        let wider = |c: &Case| {
            let r = report(
                &root,
                "w-1",
                Audience::Affected,
                None,
                Some(&c.contacts[0]),
                "d",
            )
            .unwrap();
            let at = r.find("## Wider activity").expect("a wider section");
            r[at..].lines().nth(2).unwrap_or_default().to_string()
        };
        let before = wider(&load(&root, "w-1").unwrap());
        // The other operator sends its own logs: more requests of the run,
        // private to the case.
        let dir = case_dir(&root, "w-1").unwrap();
        std::fs::create_dir_all(dir.join("evidence")).unwrap();
        let lines: Vec<String> = (0..3)
            .map(|i| {
                serde_json::to_string(&Observation {
                    id: format!("ev{i}"),
                    ts: 1_791_000_010 + i * 40,
                    url: format!(
                        "https://elsewhere.example/q?id={i}%20UNION%20SELECT%201&uqtag=zz9&agent=hunyuan"
                    ),
                    asn: Some(132203),
                    ..Default::default()
                })
                .unwrap()
            })
            .collect();
        std::fs::write(crate::evidence::file(&dir, "e1"), lines.join("\n")).unwrap();
        update(&root, "w-1", |c| {
            c.evidence.push(OperatorEvidence {
                id: "e1".into(),
                org: "elsewhere.example".into(),
                host: "elsewhere.example".into(),
                received: "d".into(),
                sha256: String::new(),
                lines: 3,
                kept: 3,
                public: None,
                note: None,
            });
            Ok(())
        })
        .unwrap();
        let c = load(&root, "w-1").unwrap();
        let all = analysis(&root, &c, &Scope::All).unwrap();
        assert!(
            all.results.iter().any(|r| r.obs.id == "ev0"),
            "case notes see them"
        );
        assert_eq!(wider(&c), before);
        cleanup(&root);
    }
}
