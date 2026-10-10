//! `swarmchase site build`: the public site, built by the same library entry
//! as `sc-site` ([`sc_publish::build::build_site_dir`]), so the admin has one
//! tool. It reads committed inputs only and writes a directory; publishing
//! it is the deploy's job.

use anyhow::{Result, anyhow};
use clap::{Args, Subcommand};
use sc_publish::build::{BuildOptions, build_site_dir};
use std::path::PathBuf;

#[derive(Args)]
pub struct SiteArgs {
    #[command(subcommand)]
    cmd: SiteCmd,
}

#[derive(Subcommand)]
enum SiteCmd {
    /// Build the site from the checkout's notices, docs, rules, evaluation
    /// set and site/ into a directory (what `sc-site` does).
    Build {
        #[arg(long, default_value = "_site")]
        out: PathBuf,
        #[arg(
            long,
            env = "SWARMCHASE_SITE_URL",
            default_value = "http://localhost:8080/"
        )]
        base_url: String,
        /// The repository root.
        #[arg(long, default_value = ".")]
        root: PathBuf,
    },
}

pub fn run(args: SiteArgs) -> Result<()> {
    match args.cmd {
        SiteCmd::Build {
            out,
            base_url,
            root,
        } => {
            let built = build_site_dir(&BuildOptions {
                out,
                base_url,
                root,
                ..Default::default()
            })
            .map_err(|e| anyhow!(e))?;
            for w in &built.warnings {
                eprintln!("warning: {w}");
            }
            println!(
                "{} generated files, {} static files, {} notices -> {}",
                built.generated,
                built.copied,
                built.notices,
                built.out.display()
            );
            Ok(())
        }
    }
}
