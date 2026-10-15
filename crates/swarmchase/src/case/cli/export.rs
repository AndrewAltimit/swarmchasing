//! `case export`: the case for recipients' tooling (STIX 2.1, MISP) or as a
//! draft for an incident database or reporting framework (OECD with an EU
//! AI Act Article 73 section, AIID). Files only: nothing is sent or
//! submitted.

use super::Ctx;
use crate::case::incident;
use crate::case::report::{find_contact, stem};
use anyhow::{Result, bail};
use clap::Args;
use sc_case::incident::Database;
use sc_case::text::audience_id;
use sc_core::Audience;
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum ExportFormat {
    /// A STIX 2.1 bundle (JSON).
    Stix,
    /// A MISP event (JSON, MISP core format), unpublished, carrying what
    /// the STIX export for the same audience carries.
    Misp,
    /// A draft for the OECD AI incident common reporting framework (JSON,
    /// public scope), with the mandatory criteria it cannot fill listed and
    /// an EU AI Act Article 73 serious-incident section.
    Oecd,
    /// A draft AI Incident Database submission (JSON, public scope).
    Aiid,
}

#[derive(Args)]
pub struct ExportArgs {
    id: String,
    #[arg(long, default_value = "stix")]
    format: ExportFormat,
    /// provider | affected | public
    #[arg(long, default_value = "provider")]
    audience: Audience,
    /// For an affected export: the operator's contact address, as listed in
    /// case.toml. Only the records aimed at that operator's own endpoints,
    /// and its own logs, are included.
    #[arg(long)]
    to: Option<String>,
    /// With --to: the contact's endpoint, when its address is listed for
    /// more than one operator's endpoints.
    #[arg(long, requires = "to")]
    endpoint: Option<String>,
    /// Name for the reporter identity.
    #[arg(long)]
    reporter: Option<String>,
    /// The site's URL, for the notice link in incident database drafts.
    #[arg(long, env = "SWARMCHASE_SITE_URL")]
    site_url: Option<String>,
    /// The committed notices directory, for incident database drafts.
    #[arg(long, default_value = "notices")]
    notices: PathBuf,
    /// Default: <case>/exports/<audience>-<date>.stix.json (or .misp.json),
    /// for --to the name its draft would have, or
    /// <case>/exports/<format>-<date>.json for incident database drafts.
    #[arg(short, long)]
    out: Option<PathBuf>,
    /// Write over an export already at the default path.
    #[arg(long)]
    force: bool,
}

pub(super) fn run(ctx: &Ctx, a: ExportArgs) -> Result<()> {
    let exports = ctx.root.join(&a.id).join("exports");
    let reporter = a.reporter.as_deref().unwrap_or("swarmchasing");
    let (text, name, said) = match a.format {
        ExportFormat::Oecd | ExportFormat::Aiid => {
            let (db, name) = match a.format {
                ExportFormat::Oecd => (Database::Oecd, "oecd"),
                _ => (Database::Aiid, "aiid"),
            };
            if a.audience != Audience::Public && a.audience != Audience::Provider {
                bail!("incident database drafts are public; they take no --audience");
            }
            let text = incident::draft(
                &ctx.root,
                &a.notices,
                &a.id,
                db,
                reporter,
                a.site_url.as_deref(),
                &ctx.today,
            )?;
            (
                text,
                format!("{name}-{}.json", ctx.today),
                "draft only; nothing was submitted. Submit it by hand after the notice is public.",
            )
        }
        ExportFormat::Stix | ExportFormat::Misp => {
            let bundle = crate::stix::export_value(
                &ctx.root,
                &a.id,
                a.audience,
                a.to.as_deref(),
                a.endpoint.as_deref(),
                Some(reporter),
                &ctx.today,
            )?;
            let c = crate::case::load(&ctx.root, &a.id)?;
            let (value, ext) = if a.format == ExportFormat::Misp {
                (sc_stix::misp::event(&bundle, &c.title, &ctx.today), "misp")
            } else {
                (bundle, "stix")
            };
            // An export for one operator is named after it, as its draft
            // is, so two operators' exports never share a file.
            let stem = match (a.audience, a.to.as_deref()) {
                (Audience::Affected, Some(to)) => {
                    let x = find_contact(&c, to, a.endpoint.as_deref())?;
                    stem(&ctx.today, a.audience, x)
                }
                _ => format!("{}-{}", audience_id(a.audience), ctx.today),
            };
            (
                format!("{}\n", serde_json::to_string_pretty(&value)?),
                format!("{stem}.{ext}.json"),
                "draft only; nothing was sent",
            )
        }
    };
    let path = match a.out {
        Some(p) => p,
        None => {
            let p = exports.join(name);
            if p.exists() && !a.force {
                bail!(
                    "{} exists; pass --force to write it again, or -o for another file",
                    p.display()
                );
            }
            p
        }
    };
    crate::util::write_out(Some(&path), &text)?;
    println!("{said}");
    Ok(())
}
