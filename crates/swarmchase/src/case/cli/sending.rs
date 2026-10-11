//! Reports and what goes with them: `report`, `draft` (an unsent .eml or
//! paste-ready text for one contact), `sent` (after the admin sends it),
//! `bundle`, `verify`.

use super::Ctx;
use crate::case::report::{draft as draft_for, report as render};
use crate::case::{Pinned, Scope, case_dir, case_records, load, update};
use crate::input::load_rules;
use crate::pinning::bundle_rules;
use anyhow::Result;
use clap::Args;
use sc_case::model::show_time;
use sc_case::text::audience_id;
use sc_core::Audience;
use std::path::{Path, PathBuf};

#[derive(Args)]
pub struct ReportArgs {
    id: String,
    /// provider | affected | internal
    #[arg(long, default_value = "internal")]
    audience: Audience,
    #[arg(long)]
    reporter: Option<String>,
    /// Default: <case>/reports/<audience>-<date>.md
    #[arg(short, long)]
    out: Option<PathBuf>,
}

#[derive(Args)]
pub struct DraftArgs {
    id: String,
    /// provider | affected
    #[arg(long)]
    audience: Audience,
    /// The contact's address, as listed in case.toml.
    #[arg(long)]
    to: String,
    #[arg(long)]
    reporter: Option<String>,
}

#[derive(Args)]
pub struct SentArgs {
    id: String,
    #[arg(long)]
    to: String,
    /// email | web_form | portal | phone
    #[arg(long, default_value = "email")]
    channel: String,
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
    let path = draft_for(&ctx.root, &a.id, a.audience, &a.to, a.reporter, &ctx.today)?;
    let unreviewed = load(&ctx.root, &a.id)?.unreviewed().len();
    if unreviewed > 0 {
        eprintln!(
            "warning: {unreviewed} endpoint(s) are still unreviewed; classify them before sending"
        );
    }
    println!(
        "wrote {} (not sent; review it, send it yourself, then `swarmchase case sent {} --to {}`)",
        path.display(),
        a.id,
        a.to
    );
    Ok(())
}

pub(super) fn sent(ctx: &Ctx, a: SentArgs) -> Result<()> {
    update(&ctx.root, &a.id, |c| {
        let s = sc_case::actions::sent(
            c,
            &a.to,
            &a.channel,
            a.report,
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
    )?;
    println!("wrote {}", dir.display());
    Ok(())
}

pub(super) fn verify(ctx: &Ctx, bundle: &Path, rules: Option<&Path>) -> Result<()> {
    let rules = match rules {
        Some(p) => load_rules(Some(p))?,
        None => bundle_rules(&ctx.root, bundle)?,
    };
    crate::bundle::report_verify(bundle, &rules)
}
