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
    let c = load(root, id)?;
    let a = analysis(root, &c, &scope(audience, to))?;
    let md = render_markdown(&a, &report_options(&c, audience, reporter, today));
    let md = sc_case::fleet::with_fleets(md, &sc_case::fleet::report_section(&c, &a, audience));
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
            "`{to}` is not a contact in case {id}{} (known: {}); add it to case.toml or run `case contacts`",
            sc_case::text::did_you_mean(to, known.iter().copied()),
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
    let subject = match audience {
        Audience::Provider => format!("Suspected AI agent activity: {} [{id}]", c.title),
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
