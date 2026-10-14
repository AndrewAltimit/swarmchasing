//! Reports and what goes with them: `report`, `draft` (an unsent .eml or
//! paste-ready text for one contact), `sent` (after the admin sends it),
//! `bundle`, `verify`.

use super::Ctx;
use crate::case::report::{
    draft as draft_for, draft_path, draft_to, find_contact, report as render, stem, stem_tail,
};
use crate::case::{Pinned, Scope, case_dir, case_records, load, update};
use crate::input::load_rules;
use crate::pinning::bundle_rules;
use anyhow::{Context, Result, bail};
use clap::Args;
use sc_case::model::ContactRole;
use sc_case::model::show_time;
use sc_case::text::audience_id;
use sc_core::Audience;
use std::path::{Path, PathBuf};

#[derive(Args)]
pub struct ReportArgs {
    /// The case ID: its directory under <data>/cases/ (`case status` lists them).
    id: String,
    /// provider | affected | internal
    #[arg(long, default_value = "internal")]
    audience: Audience,
    /// Who the report is from, as its "Reporter" line shows it (your name or
    /// organisation). Without it the report has no such line.
    #[arg(long)]
    reporter: Option<String>,
    /// For an affected report: the operator's contact address, as listed in
    /// case.toml. The report covers that operator's endpoints only.
    #[arg(long)]
    to: Option<String>,
    /// With --to: the contact's endpoint, when its address is listed for
    /// more than one operator's endpoints.
    #[arg(long, requires = "to")]
    endpoint: Option<String>,
    /// Default: <case>/reports/<audience>-<date>.md, or for --to the name
    /// its draft would have.
    #[arg(short, long)]
    out: Option<PathBuf>,
}

#[derive(Args)]
pub struct DraftArgs {
    /// The case ID: its directory under <data>/cases/ (`case status` lists them).
    id: String,
    /// provider | affected
    #[arg(long, required_unless_present = "all", conflicts_with = "all")]
    audience: Option<Audience>,
    /// The contact's address, as listed in case.toml.
    #[arg(long, required_unless_present = "all", conflicts_with = "all")]
    to: Option<String>,
    /// With --to: the contact's endpoint, when its address is listed for
    /// more than one operator's endpoints.
    #[arg(long, requires = "to")]
    endpoint: Option<String>,
    /// Draft for every provider and affected contact in case.toml, each with
    /// the audience its role implies, once per operator (an address listed
    /// for two operators' endpoints gets a draft for each). Contacts already
    /// sent to, those of other roles (registrar, host, CSIRT) and those
    /// with a draft already in the outbox are listed and skipped; draft
    /// those one at a time with --audience and --to (and --force).
    #[arg(long)]
    all: bool,
    /// Who the report is from, as its "Reporter" line shows it (your name or
    /// organisation). Without it the report has no such line.
    #[arg(long)]
    reporter: Option<String>,
    /// Write over a draft already in the outbox for the same contact and
    /// day (it may hold your edits), with --all too.
    #[arg(long)]
    force: bool,
}

#[derive(Args)]
pub struct SentArgs {
    /// The case ID: its directory under <data>/cases/ (`case status` lists them).
    id: String,
    /// The recipient's address, as listed in case.toml. With --draft, read
    /// from the draft.
    #[arg(long, required_unless_present = "draft")]
    to: Option<String>,
    /// email | web_form | portal | phone. Default: the draft's channel with
    /// --draft, else email.
    #[arg(long)]
    channel: Option<String>,
    /// The draft `case draft` wrote and you sent (an .eml, or the .md for a
    /// form): the recipient and channel are read from it, and it is recorded
    /// as the report sent.
    #[arg(long, conflicts_with = "report")]
    draft: Option<PathBuf>,
    /// The draft or report that was sent.
    #[arg(long)]
    report: Option<String>,
    /// When it was sent (RFC 3339, e.g. 2026-10-12T14:05:00Z), for a send
    /// recorded afterwards. Default: now. The indicator and naming clocks
    /// run from it.
    #[arg(long, conflicts_with = "date")]
    at: Option<String>,
    /// The day only; the clocks then count from the end of it.
    #[arg(long)]
    date: Option<String>,
    /// Record a send although the same one (same recipient and draft, or
    /// with no draft the same day) is recorded already: the report really
    /// went out twice.
    #[arg(long)]
    again: bool,
}

pub(super) fn report(ctx: &Ctx, a: ReportArgs) -> Result<()> {
    let c = load(&ctx.root, &a.id)?;
    let to =
        a.to.as_deref()
            .map(|to| find_contact(&c, to, a.endpoint.as_deref()))
            .transpose()?;
    let md = render(&ctx.root, &a.id, a.audience, a.reporter, to, &ctx.today)?;
    // A report for one contact is named after it, as its draft is.
    let name = match to {
        Some(x) => format!("{}.md", stem(&ctx.today, a.audience, x)),
        None => format!("{}-{}.md", audience_id(a.audience), ctx.today),
    };
    let path = a
        .out
        .unwrap_or_else(|| ctx.root.join(&a.id).join("reports").join(name));
    crate::util::write_out(Some(&path), &md)
}

pub(super) fn draft(ctx: &Ctx, a: DraftArgs) -> Result<()> {
    let c = load(&ctx.root, &a.id)?;
    if !a.all {
        let (Some(audience), Some(to)) = (a.audience, a.to.as_deref()) else {
            bail!("--audience and --to, or --all");
        };
        if let Some(hint) = c.unreviewed_hint() {
            eprintln!("warning: {hint}\n  classify them before sending");
        }
        let path = draft_for(
            &ctx.root,
            &a.id,
            audience,
            to,
            a.endpoint.as_deref(),
            a.reporter.clone(),
            &ctx.today,
            a.force,
        )?;
        print_wrote(&a.id, &path);
        return Ok(());
    }
    let (targets, skipped) = all_targets(&c);
    for line in &skipped {
        println!("skipped {line}");
    }
    if targets.is_empty() {
        bail!(
            "no provider or affected contact in case {} left to draft for; `swarmchase case contacts {}` finds them",
            a.id,
            a.id
        );
    }
    if let Some(hint) = c.unreviewed_hint() {
        eprintln!("warning: {hint}\n  classify them before sending");
    }
    let dir = case_dir(&ctx.root, &a.id)?;
    for (audience, x) in &targets {
        // A draft already in the outbox may hold the admin's edits: kept,
        // and the rest still drafted.
        let p = draft_path(&dir, &ctx.today, *audience, x);
        if p.exists() && !a.force {
            println!(
                "skipped {} (draft exists; --force writes it again): {}",
                x.address,
                p.display()
            );
            continue;
        }
        let path = draft_to(
            &ctx.root,
            &c,
            *audience,
            x,
            a.reporter.clone(),
            &ctx.today,
            a.force,
        )?;
        print_wrote(&a.id, &path);
    }
    Ok(())
}

fn print_wrote(id: &str, path: &Path) {
    println!(
        "wrote {} (not sent; review it, send it yourself, then `swarmchase case sent {id} --draft {}`)",
        path.display(),
        path.display()
    );
}

/// What `draft --all` drafts: each provider and affected contact not yet
/// sent to, with its audience, once per recipient (an address, and for an
/// affected report the hosts it covers, so an address listed for two
/// operators' endpoints is two recipients); and a line for each contact it
/// skips. A send to a shared address counts for the operator whose draft
/// it records, or for all of them when it records none of theirs.
fn all_targets(
    c: &sc_case::model::Case,
) -> (Vec<(Audience, &sc_case::model::Contact)>, Vec<String>) {
    use std::collections::BTreeSet;
    let site = &sc_collect::psl::registrable_domain;
    let recipient = |audience: Audience, x: &sc_case::model::Contact| {
        let hosts = match audience {
            Audience::Affected => Scope::for_audience(audience, Some(x))
                .hosts(c, site)
                .unwrap_or_default(),
            _ => BTreeSet::new(),
        };
        (
            x.address.trim().to_ascii_lowercase(),
            audience_id(audience),
            hosts,
        )
    };
    let mut targets: Vec<(Audience, &sc_case::model::Contact)> = Vec::new();
    let mut seen = BTreeSet::new();
    let mut skipped = Vec::new();
    for x in &c.contacts {
        let audience = match x.role {
            ContactRole::Provider => Audience::Provider,
            ContactRole::Affected => Audience::Affected,
            other => {
                skipped.push(format!(
                    "{} ({}): draft by hand with --audience and --to",
                    x.address,
                    other.id()
                ));
                continue;
            }
        };
        let me = recipient(audience, x);
        if !seen.insert(me.clone()) {
            continue;
        }
        let same_address =
            |y: &&sc_case::model::Contact| y.address.trim().eq_ignore_ascii_case(x.address.trim());
        let shared = c
            .contacts
            .iter()
            .filter(same_address)
            .any(|y| recipient(audience, y) != me);
        // Drafts name their recipient: a send recording one of this
        // address's drafts counts for that recipient alone.
        let tails: Vec<(bool, String)> = c
            .contacts
            .iter()
            .filter(same_address)
            .map(|y| (recipient(audience, y) == me, stem_tail(audience, y)))
            .collect();
        let sent = c
            .sent
            .iter()
            .filter(|s| s.recipient.trim().eq_ignore_ascii_case(x.address.trim()))
            .any(|s| {
                let whose = s.report.as_deref().and_then(|r| {
                    tails
                        .iter()
                        .find(|(_, t)| r.contains(t.as_str()))
                        .map(|(mine, _)| *mine)
                });
                whose.unwrap_or(true)
            });
        let who = match (shared, x.endpoint.as_deref()) {
            (true, Some(e)) => format!("{} for {}", x.address, sc_core::defang_host(e)),
            _ => x.address.clone(),
        };
        if sent {
            skipped.push(format!("{who} ({}): already sent", x.role.id()));
            continue;
        }
        targets.push((audience, x));
    }
    (targets, skipped)
}

/// The recipient and channel a draft from `case draft` was written for: the
/// `To:` header of an .eml, or the "Paste into <address> (<channel>)" line
/// of a form draft.
pub(crate) fn draft_recipient(text: &str) -> Option<(String, String)> {
    for line in text.lines() {
        if line.is_empty() {
            break; // the end of an .eml's headers
        }
        if let Some(to) = line.strip_prefix("To:") {
            let to = to.trim();
            return (!to.is_empty()).then(|| (to.to_string(), "email".to_string()));
        }
        if let Some(rest) = line.strip_prefix("<!-- Paste into ") {
            let (to, rest) = rest.split_once(" (")?;
            let (channel, _) = rest.split_once(')')?;
            return Some((to.trim().to_string(), channel.trim().to_string()));
        }
    }
    None
}

pub(super) fn sent(ctx: &Ctx, a: SentArgs) -> Result<()> {
    let (to, channel, report) = match &a.draft {
        Some(p) => {
            let text = std::fs::read_to_string(p)
                .with_context(|| format!("reading the draft {}", p.display()))?;
            let Some((to, channel)) = draft_recipient(&text) else {
                bail!(
                    "{} names no recipient (no `To:` header or \"Paste into\" line); pass --to",
                    p.display()
                );
            };
            if let Some(given) = &a.to
                && !given.eq_ignore_ascii_case(&to)
            {
                bail!("--to {given} but the draft {} is to {to}", p.display());
            }
            let name = p.file_name().map_or_else(
                || p.display().to_string(),
                |n| n.to_string_lossy().into_owned(),
            );
            (to, a.channel.clone().unwrap_or(channel), Some(name))
        }
        None => (
            a.to.clone().unwrap_or_default(),
            a.channel.clone().unwrap_or_else(|| "email".into()),
            a.report.clone(),
        ),
    };
    update(&ctx.root, &a.id, |c| {
        if !a.again
            && let Some(s) = sc_case::actions::repeated_send(
                c,
                &to,
                report.as_deref(),
                a.at.as_deref(),
                a.date.as_deref(),
                ctx.now,
            )
        {
            bail!(
                "a send to {to} on {} is recorded already{}; pass --again if it was sent twice",
                s.date,
                s.report
                    .as_deref()
                    .map(|r| format!(" ({r})"))
                    .unwrap_or_default()
            );
        }
        let s = sc_case::actions::sent(
            c,
            &to,
            &channel,
            report,
            a.at.as_deref(),
            a.date.as_deref(),
            ctx.now,
        )?;
        if let Some(t) = sc_case::lead::clock(c).not_before {
            println!(
                "{s} recorded; the indicator notice may be added from {} if nothing else is sent",
                show_time(t)
            );
        } else {
            println!("{s} recorded");
        }
        for o in sc_case::naming::operators(c)
            .iter()
            .filter(|o| o.from.is_some() && o.named.is_none())
        {
            println!(
                "  operator of {}: {}",
                sc_core::defang_host(&o.host),
                o.status(ctx.now)
            );
        }
        Ok(())
    })
}

pub(super) fn bundle(ctx: &Ctx, id: &str, rules: Option<&Path>) -> Result<()> {
    let c = load(&ctx.root, id)?;
    let rules = match rules {
        Some(p) => load_rules(Some(p))?,
        None => Pinned::new(&ctx.root, &c)?.rules,
    };
    let dir = crate::bundle::write(
        &case_dir(&ctx.root, id)?.join("bundles"),
        id,
        &case_records(&ctx.root, &c, &Scope::All)?,
        &rules,
        &ctx.today,
        crate::bundle::git_commit(),
        crate::signing::signer()?.as_ref(),
    )?;
    println!("wrote {}", dir.display());
    Ok(())
}

pub(super) fn verify(
    ctx: &Ctx,
    bundle: &Path,
    rules: Option<&Path>,
    key: Option<&Path>,
) -> Result<()> {
    let rules = match rules {
        Some(p) => load_rules(Some(p))?,
        None => bundle_rules(&ctx.root, bundle)?,
    };
    crate::bundle::report_verify(bundle, &rules, key)
}
