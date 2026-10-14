//! Opening and keeping a case: `new`, `add`, `status`, `rename`, `set`,
//! `note`, `rules`.

use super::Ctx;
use crate::case::select::{Selection, select};
use crate::case::status::{list as list_cases, status as show_case};
use crate::case::{CaseStatus, NoticeStatus, add_records, admin_name, open_case, update};
use crate::pinning::{RulesText, rules_cmd};
use anyhow::Result;
use clap::Args;
use sc_case::actions::{self, Settings};
use sc_core::Evidence;
use std::io::Write;
use std::path::Path;

#[derive(Args)]
pub struct NewArgs {
    /// Short slug, e.g. 2026-10-portal-sqli.
    id: String,
    #[arg(long)]
    title: String,
    #[command(flatten)]
    pub(super) sel: Selection,
}

#[derive(Args)]
pub struct AddArgs {
    id: String,
    #[command(flatten)]
    sel: Selection,
}

#[derive(Args)]
pub struct SetArgs {
    id: String,
    /// open | reported | published | closed
    #[arg(long)]
    status: Option<CaseStatus>,
    /// active | contained | historical
    #[arg(long)]
    notice: Option<NoticeStatus>,
    #[arg(long)]
    min_named: Option<Evidence>,
    /// The naming lead for targeted and historical endpoints' operators, in
    /// UTC working days: 3 (the default and the least) to 20. Compromised
    /// endpoints' operators wait the longer of this and 10.
    #[arg(long)]
    naming_days: Option<u32>,
    /// Who decides and publishes for the case; a second review must come
    /// from someone else.
    #[arg(long)]
    admin: Option<String>,
}

pub(super) fn new(ctx: &Ctx, a: NewArgs, out: &mut impl Write) -> Result<()> {
    let (rules, records) = select(&ctx.data, &a.sel, ctx.now)?;
    // A watch reads the cases; never let it see one half written.
    let lock = crate::store::lock_data(&ctx.data, "case new")?;
    let an = open_case(
        &ctx.root,
        &a.id,
        &a.title,
        records,
        &rules,
        &ctx.today,
        admin_name().as_deref(),
    )?;
    drop(lock);
    println!(
        "opened {} ({} records)",
        ctx.root.join(&a.id).display(),
        an.total
    );
    show_case(&ctx.root, &a.id, out)
}

pub(super) fn add(ctx: &Ctx, a: AddArgs) -> Result<()> {
    let (_, records) = select(&ctx.data, &a.sel, ctx.now)?;
    let _lock = crate::store::lock_data(&ctx.data, "case add")?;
    let (added, hosts) = add_records(&ctx.root, &a.id, records, &ctx.today)?;
    println!("added {added} record(s), {hosts} new endpoint(s)");
    Ok(())
}

pub(super) fn status(ctx: &Ctx, id: Option<&str>, out: &mut impl Write) -> Result<()> {
    match id {
        None => list_cases(&ctx.root, out),
        Some(id) => show_case(&ctx.root, id, out),
    }
}

pub(super) fn rename(ctx: &Ctx, id: &str, new_id: &str) -> Result<()> {
    crate::case::rename(&ctx.root, id, new_id, &ctx.today)?;
    println!(
        "renamed case {id} to {new_id} ({})",
        ctx.root.join(new_id).display()
    );
    Ok(())
}

pub(super) fn set(ctx: &Ctx, a: SetArgs) -> Result<()> {
    update(&ctx.root, &a.id, |c| {
        let s = Settings {
            status: a.status,
            notice: a.notice,
            min_named: a.min_named,
            naming_days: a.naming_days,
            admin: a.admin,
        };
        Ok(actions::set(c, s, &ctx.today)?)
    })
}

pub(super) fn note(ctx: &Ctx, id: &str, text: String) -> Result<()> {
    update(&ctx.root, id, |c| {
        c.log(&ctx.today, text);
        Ok(())
    })
}

pub(super) fn rules(
    ctx: &Ctx,
    id: &str,
    update: bool,
    rules: Option<&Path>,
    out: &mut impl Write,
) -> Result<()> {
    let current = RulesText::load(rules)?;
    rules_cmd(&ctx.root, id, &current, update, &ctx.today, out)
}
