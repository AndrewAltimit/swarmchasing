//! Reports and what goes with them: `report`, `draft` (an unsent .eml or
//! paste-ready text for one contact), `sent` (after the admin sends it),
//! `bundle`, `verify`.

use super::Ctx;
use crate::case::report::{draft as draft_for, report as render};
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
    /// Default: <case>/reports/<audience>-<date>.md
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
    /// Draft for every provider and affected contact in case.toml, each with
    /// the audience its role implies. Contacts already sent to, and those
    /// of other roles (registrar, host, CSIRT), are listed and skipped;
    /// draft those one at a time with --audience and --to.
    #[arg(long)]
    all: bool,
    /// Who the report is from, as its "Reporter" line shows it (your name or
    /// organisation). Without it the report has no such line.
    #[arg(long)]
    reporter: Option<String>,
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
}

pub(super) fn report(ctx: &Ctx, a: ReportArgs) -> Result<()> {
    let md = render(&ctx.root, &a.id, a.audience, a.reporter, None, &ctx.today)?;
    let path = a.out.unwrap_or_else(|| {
        ctx.root.join(&a.id).join("reports").join(format!(
            "{}-{}.md",
            audience_id(a.audience),
            ctx.today
        ))
    });
    crate::util::write_out(Some(&path), &md)
}

pub(super) fn draft(ctx: &Ctx, a: DraftArgs) -> Result<()> {
    let c = load(&ctx.root, &a.id)?;
    let targets: Vec<(Audience, String)> = if a.all {
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
        targets
    } else {
        match (a.audience, a.to) {
            (Some(audience), Some(to)) => vec![(audience, to)],
            _ => bail!("--audience and --to, or --all"),
        }
    };
    let unreviewed = c.unreviewed().len();
    if unreviewed > 0 {
        eprintln!(
            "warning: {unreviewed} endpoint(s) are still unreviewed; classify them before sending"
        );
    }
    for (audience, to) in &targets {
        let path = draft_for(
            &ctx.root,
            &a.id,
            *audience,
            to,
            a.reporter.clone(),
            &ctx.today,
        )?;
        println!(
            "wrote {} (not sent; review it, send it yourself, then `swarmchase case sent {} --draft {}`)",
            path.display(),
            a.id,
            path.display()
        );
    }
    Ok(())
}

/// What `draft --all` drafts: each provider and affected contact not yet
/// sent to, with its audience, once per address; and a line for each
/// contact it skips.
fn all_targets(c: &sc_case::model::Case) -> (Vec<(Audience, String)>, Vec<String>) {
    let mut targets: Vec<(Audience, String)> = Vec::new();
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
        if c.sent
            .iter()
            .any(|s| s.recipient.eq_ignore_ascii_case(&x.address))
        {
            skipped.push(format!("{} ({}): already sent", x.address, x.role.id()));
            continue;
        }
        if !targets
            .iter()
            .any(|(_, to)| to.eq_ignore_ascii_case(&x.address))
        {
            targets.push((audience, x.address.clone()));
        }
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
