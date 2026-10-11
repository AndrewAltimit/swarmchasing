//! The second review and naming decisions: `review` (a second reviewer's
//! verdict on the current draft, bound to its hash), `review-packet` (what
//! the admin hands the reviewer), `consent` (an operator's written consent
//! to earlier naming), `naming` (the naming clocks, or the decision never
//! to name an operator). Nothing here sends anything.

use super::Ctx;
use crate::case::checklist::Item;
use crate::case::{Case, Stage, case_dir, load, update};
use anyhow::{Result, bail};
use clap::Args;
use sc_case::model::Verdict;
use sc_core::Audience;
use std::io::Write;
use std::path::{Path, PathBuf};

#[derive(Args)]
pub struct ReviewArgs {
    id: String,
    /// The second reviewer's name; never the case's admin.
    #[arg(long)]
    reviewer: String,
    /// approve | object
    #[arg(long)]
    verdict: Verdict,
    /// What the reviewer said; for an objection, what must change.
    #[arg(long)]
    note: Option<String>,
    /// The committed notices directory (for a naming update).
    #[arg(long, default_value = "notices")]
    notices: PathBuf,
}

#[derive(Args)]
pub struct PacketArgs {
    id: String,
    /// The naming update's draft, not the indicator notice's.
    #[arg(long)]
    naming: bool,
    /// The committed notices directory (for a naming update).
    #[arg(long, default_value = "notices")]
    notices: PathBuf,
}

#[derive(Args)]
pub struct ConsentArgs {
    id: String,
    /// The operator: its endpoint's host, or its organisation as the
    /// case's operator contact names it.
    #[arg(long)]
    party: String,
    /// What the operator said in writing, and where it is kept.
    #[arg(long)]
    note: String,
}

#[derive(Args)]
pub struct NamingArgs {
    id: String,
    /// The operator: its endpoint's host, or its organisation as the
    /// case's operator contact names it.
    #[arg(long, requires = "withhold")]
    party: Option<String>,
    /// Never name this operator.
    #[arg(long, requires_all = ["party", "reason"])]
    withhold: bool,
    /// Why it is not to be named.
    #[arg(long)]
    reason: Option<String>,
}

/// The stage's draft hash on disk, and its checklist now.
fn stage_items(
    ctx: &Ctx,
    id: &str,
    stage: Stage,
    notices: &Path,
) -> Result<(Option<String>, Vec<Item>)> {
    Ok(match stage {
        Stage::Indicators => (
            crate::case::checklist::draft_sha(&ctx.root, id).ok(),
            crate::notice::checklist_for(&ctx.root, id, ctx.now)?,
        ),
        Stage::Naming => (
            crate::notice::naming_sha(&ctx.root, id).ok(),
            crate::notice::naming_checklist_for(&ctx.root, id, notices, ctx.now)?,
        ),
    })
}

pub(super) fn review(ctx: &Ctx, a: ReviewArgs) -> Result<()> {
    let stage = load(&ctx.root, &a.id)?.stage();
    let (sha, items) = stage_items(ctx, &a.id, stage, &a.notices)?;
    let Some(sha) = sha else {
        bail!("no {} draft to review in case {}", stage.label(), a.id);
    };
    let blockers = sc_case::review::blockers(&items);
    update(&ctx.root, &a.id, |c| {
        let msg = sc_case::review::record(
            c,
            sc_case::review::Input {
                stage,
                reviewer: &a.reviewer,
                verdict: a.verdict,
                note: a.note.as_deref(),
                sha: &sha,
            },
            &blockers,
            ctx.now,
        )?;
        println!("{msg}");
        Ok(())
    })
}

pub(super) fn packet(ctx: &Ctx, a: PacketArgs) -> Result<()> {
    let c = load(&ctx.root, &a.id)?;
    let stage = if a.naming {
        Stage::Naming
    } else {
        Stage::Indicators
    };
    if stage != c.stage() {
        bail!(
            "case {} is at the {} stage; the packet is for its current draft",
            a.id,
            c.stage().label()
        );
    }
    let dir = case_dir(&ctx.root, &a.id)?;
    let draft = dir.join(stage.draft());
    if !draft.is_file() {
        bail!(
            "no {} draft at {}: `swarmchase case notice {}{}`",
            stage.label(),
            draft.display(),
            a.id,
            if a.naming { " --naming" } else { "" }
        );
    }
    let (sha, items) = stage_items(ctx, &a.id, stage, &a.notices)?;
    let out = dir.join("outbox").join("review");
    std::fs::create_dir_all(&out)?;
    std::fs::copy(&draft, out.join(stage.draft()))?;
    let mut list = Vec::new();
    sc_case::checklist::print_titled(
        &format!("Checklist for the {} draft", stage.label()),
        &items,
        &mut list,
    )?;
    std::fs::write(out.join("checklist.txt"), list)?;
    let md =
        crate::case::report::report(&ctx.root, &a.id, Audience::Internal, None, None, &ctx.today)?;
    std::fs::write(out.join("report-internal.md"), md)?;
    std::fs::write(
        out.join("README.txt"),
        packet_readme(&c, stage, sha.as_deref()),
    )?;
    println!(
        "wrote {} (not sent; hand it to the second reviewer, then record the verdict with `swarmchase case review {} --reviewer \"<name>\" --verdict approve|object`)",
        out.display(),
        a.id
    );
    Ok(())
}

fn packet_readme(c: &Case, stage: Stage, sha: Option<&str>) -> String {
    format!(
        "Second review of the {} for case {}.\n\n\
         Read {} against report-internal.md (the case notes, which are private) and checklist.txt.\n\
         Approve only this exact draft (sha256 {}); any edit to it voids the review.\n\
         Object if the draft says more than the records show, names or locates an affected party it may not, or uses a word the case does not support.\n\
         The case's admin ({}) records your verdict and note; the admin cannot review their own draft.\n",
        stage.label(),
        c.id,
        stage.draft(),
        sha.unwrap_or("unknown"),
        c.admin.as_deref().unwrap_or("not recorded"),
    )
}

pub(super) fn consent(ctx: &Ctx, a: ConsentArgs) -> Result<()> {
    update(&ctx.root, &a.id, |c| {
        sc_case::naming::consent(c, &a.party, &a.note, ctx.now)?;
        println!("{}", c.decisions.last().map_or("", |d| d.text.as_str()));
        Ok(())
    })
}

pub(super) fn naming(ctx: &Ctx, a: NamingArgs, out: &mut impl Write) -> Result<()> {
    if a.withhold {
        let (Some(party), Some(reason)) = (a.party.as_deref(), a.reason.as_deref()) else {
            bail!("--withhold needs --party and --reason");
        };
        return update(&ctx.root, &a.id, |c| {
            Ok(sc_case::naming::withhold(c, party, reason, &ctx.today)?)
        });
    }
    let c = load(&ctx.root, &a.id)?;
    sc_case::naming::show(&c, ctx.now, out)?;
    Ok(())
}
