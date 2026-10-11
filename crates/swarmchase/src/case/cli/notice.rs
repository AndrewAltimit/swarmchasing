//! The public notice from inside the case: `notice` drafts it, `reread`
//! records the admin's re-read, `checklist` prints what `notice add` checks.

use super::Ctx;
use anyhow::Result;
use std::io::Write;

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

pub(super) fn checklist(ctx: &Ctx, id: &str, out: &mut impl Write) -> Result<()> {
    let items = crate::notice::checklist_for(&ctx.root, id, ctx.now)?;
    sc_case::checklist::print(&items, out)?;
    Ok(())
}
