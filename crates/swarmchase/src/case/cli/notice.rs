//! The public notice from inside the case: `notice` drafts the indicator
//! notice or (`--naming`) the next naming update, `reread` records the
//! admin's re-read, `checklist` prints what `notice add` or `notice update
//! --naming` checks, with both stages' clocks and review state.

use super::Ctx;
use crate::case::{Stage, load};
use anyhow::Result;
use std::io::Write;
use std::path::Path;

pub(super) fn draft(ctx: &Ctx, id: &str, force: bool) -> Result<()> {
    let (path, review) = crate::notice::notice_draft(&ctx.root, id, force, &ctx.today, ctx.now)?;
    for w in &review.withheld {
        println!("withheld: {w}");
    }
    for f in &review.flags {
        println!("decide:   {f}");
    }
    for l in &review.lint {
        println!("LEAK:     {l}");
    }
    for h in &review.unreviewed {
        println!("classify: {h} (unreviewed endpoints block `notice add`)");
    }
    println!(
        "wrote {} (draft; review and edit it, then `swarmchase notice add {id}`)",
        path.display()
    );
    Ok(())
}

pub(super) fn reread(ctx: &Ctx, id: &str) -> Result<()> {
    println!(
        "{}",
        crate::case::checklist::reread(&ctx.root, id, &ctx.today, ctx.now)?
    );
    Ok(())
}

pub(super) fn naming_draft(ctx: &Ctx, id: &str, force: bool) -> Result<()> {
    let (path, hosts) = crate::notice::naming_draft(&ctx.root, id, force, &ctx.today, ctx.now)?;
    for h in &hosts {
        println!("names:    operator of {}", sc_core::defang_host(h));
    }
    println!(
        "wrote {} (draft; review and edit it, have it reviewed, then `swarmchase notice update {id} --naming`)",
        path.display()
    );
    Ok(())
}

/// The current stage's checklist, the clocks of both stages, and the review
/// state of each stage's draft.
pub(super) fn checklist(ctx: &Ctx, id: &str, notices: &Path, out: &mut impl Write) -> Result<()> {
    let c = load(&ctx.root, id)?;
    match c.stage() {
        Stage::Indicators => {
            let items = crate::notice::checklist_for(&ctx.root, id, ctx.now)?;
            sc_case::checklist::print_titled(
                "Stage 1, indicator notice: self-review checklist",
                &items,
                out,
            )?;
        }
        Stage::Naming => {
            writeln!(out, "Stage 1, indicator notice: added")?;
            if ctx.root.join(id).join(crate::case::NAMING_DRAFT).is_file() {
                let items = crate::notice::naming_checklist_for(&ctx.root, id, notices, ctx.now)?;
                sc_case::checklist::print_titled("Stage 2, naming update: checklist", &items, out)?;
            } else {
                writeln!(
                    out,
                    "Stage 2, naming update: no draft (`swarmchase case notice {id} --naming`)"
                )?;
            }
        }
    }
    crate::case::status::clocks(&ctx.root, &c, ctx.now, out)
}
