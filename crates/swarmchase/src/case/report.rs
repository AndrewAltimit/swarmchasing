//! Report drafts from a case, and the unsent drafts for one contact.

use super::*;
use crate::pinning::case_rules;
use crate::util::audience_id;
use anyhow::{Result, bail};
use sc_core::{Audience, ReportOptions, analyze, render_markdown};
use std::path::{Path, PathBuf};

pub(crate) fn report_options(
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
        exposed_hosts: c
            .endpoints
            .iter()
            .filter(|e| e.state == EndpointState::Compromised)
            .map(|e| e.host.clone())
            .collect(),
        ..Default::default()
    }
}

pub(crate) fn report(
    root: &Path,
    id: &str,
    audience: Audience,
    reporter: Option<String>,
    to: Option<&Contact>,
    today: &str,
) -> Result<String> {
    let c = load(root, id)?;
    let a = analyze(
        case_records(root, &c, &scope(audience, to))?,
        &case_rules(root, &c)?,
    );
    Ok(render_markdown(
        &a,
        &report_options(&c, audience, reporter, today),
    ))
}

/// Write the report for one contact into the outbox: an unsent .eml with a
/// fresh bundle attached for e-mail contacts, paste-ready text otherwise.
pub(crate) fn draft(
    root: &Path,
    id: &str,
    audience: Audience,
    to: &str,
    reporter: Option<String>,
    today: &str,
) -> Result<PathBuf> {
    if matches!(audience, Audience::Internal | Audience::Public) {
        bail!(
            "only provider and affected reports are sent; case notes stay private and the notice is published (`case notice`)"
        );
    }
    let c = load(root, id)?;
    let Some(contact) = c
        .contacts
        .iter()
        .find(|x| x.address.eq_ignore_ascii_case(to))
    else {
        let known: Vec<&str> = c.contacts.iter().map(|x| x.address.as_str()).collect();
        bail!(
            "`{to}` is not a contact in case {id} (known: {}); add it to case.toml or run `case contacts`",
            if known.is_empty() {
                "none".into()
            } else {
                known.join(", ")
            }
        );
    };
    let md = report(root, id, audience, reporter, Some(contact), today)?;
    let dir = case_dir(root, id)?;
    let outbox = dir.join("outbox");
    std::fs::create_dir_all(&outbox)?;
    let slug: String = contact
        .address
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() {
                ch.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect();
    let stem = format!("{today}-{}-{slug}", audience_id(audience));
    if contact.channel != "email" {
        let p = outbox.join(format!("{stem}.md"));
        std::fs::write(
            &p,
            format!(
                "<!-- Paste into {} ({}). Attach the latest bundle from {} if the form accepts files. -->\n\n{md}",
                contact.address,
                contact.channel,
                dir.join("bundles").display()
            ),
        )?;
        return Ok(p);
    }
    let bundle = crate::bundle::write(
        &dir.join("bundles"),
        id,
        &case_records(root, &c, &scope(audience, Some(contact)))?,
        &case_rules(root, &c)?,
        today,
        crate::bundle::git_commit(),
    )?;
    let subject = match audience {
        Audience::Provider => format!("Suspected misaligned agent activity: {} [{id}]", c.title),
        _ => format!(
            "Automated agent activity targeting your systems: {} [{id}]",
            c.title
        ),
    };
    let p = outbox.join(format!("{stem}.eml"));
    std::fs::write(
        &p,
        crate::bundle::eml(
            &contact.address,
            &subject,
            &md,
            &crate::bundle::attachments(&bundle)?,
        ),
    )?;
    Ok(p)
}
