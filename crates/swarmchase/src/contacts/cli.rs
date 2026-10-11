//! `swarmchase contacts`: list the provider or CSIRT directory, or re-read
//! every entry's source and draft the changes.

use super::{Check, Directory, draft_update, verify_directory};
use anyhow::{Context, Result};

/// `swarmchase contacts`: the provider directory, or with `--csirts` the
/// national CSIRT directory.
#[derive(clap::Subcommand)]
pub enum ContactsCmd {
    /// List the provider directory.
    List {
        /// List the national CSIRTs (contacts/csirts.toml) instead.
        #[arg(long)]
        csirts: bool,
    },
    /// Re-read every directory entry's source and report what changed. With
    /// --draft, also write an updated copy of the directory (verified dates
    /// refreshed, unconfirmed entries marked) for the admin to review; the
    /// directory itself is never changed.
    Verify {
        /// The directory to check. Default: contacts/providers.toml, or
        /// contacts/csirts.toml with --csirts.
        #[arg(long)]
        file: Option<std::path::PathBuf>,
        /// Check the national CSIRT directory.
        #[arg(long)]
        csirts: bool,
        #[arg(long)]
        draft: Option<std::path::PathBuf>,
    },
}

pub fn run_contacts(cmd: ContactsCmd) -> Result<()> {
    let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
    match cmd {
        ContactsCmd::List { csirts: true } => {
            for t in &crate::csirts::Csirts::builtin().teams {
                println!(
                    "{}  {:<40} {:<8} {} (verified {})",
                    t.country, t.name, t.channel, t.address, t.verified
                );
            }
            Ok(())
        }
        ContactsCmd::List { csirts: false } => {
            let d = Directory::builtin();
            for p in &d.providers {
                println!("{} ({})", p.name, p.kind);
                for c in &p.contacts {
                    println!(
                        "  {:<8} {:<8} {} (verified {})",
                        c.purpose, c.channel, c.address, c.verified
                    );
                }
            }
            Ok(())
        }
        ContactsCmd::Verify {
            file,
            csirts,
            draft,
        } => {
            let file = file.unwrap_or_else(|| {
                if csirts {
                    "contacts/csirts.toml".into()
                } else {
                    "contacts/providers.toml".into()
                }
            });
            let text = std::fs::read_to_string(&file)
                .with_context(|| format!("reading {}", file.display()))?;
            let d = if csirts {
                crate::csirts::Csirts::parse(&text)?.as_directory()
            } else {
                Directory::parse(&text)?
            };
            let http = reqwest::blocking::Client::builder()
                .user_agent(
                    std::env::var("SWARMCHASE_UA")
                        .unwrap_or_else(|_| "swarmchase-contacts-verify".into()),
                )
                .timeout(std::time::Duration::from_secs(30))
                .build()?;
            let fetch = |url: &str| -> std::result::Result<String, String> {
                std::thread::sleep(std::time::Duration::from_millis(500));
                let r = http.get(url).send().map_err(|e| e.to_string())?;
                if !r.status().is_success() {
                    return Err(format!("HTTP {}", r.status()));
                }
                r.text().map_err(|e| e.to_string())
            };
            let (checks, new) = verify_directory(&d, fetch);
            let mut changed = 0;
            for (p, a, c) in &checks {
                let s = match c {
                    Check::Listed => "ok".to_string(),
                    Check::Missing => {
                        changed += 1;
                        "MISSING from its source".to_string()
                    }
                    Check::Unreachable(e) => {
                        changed += 1;
                        format!("UNREACHABLE ({e})")
                    }
                };
                println!("{p:<22} {a:<50} {s}");
            }
            for n in &new {
                println!("new: {n}");
            }
            if let Some(out) = draft {
                std::fs::write(&out, draft_update(&text, &checks, &today))?;
                println!(
                    "wrote a draft to {} (review it, then copy it over {} yourself)",
                    out.display(),
                    file.display()
                );
            }
            println!(
                "{} contact(s) checked, {changed} need a look, {} new listing(s)",
                checks.len(),
                new.len()
            );
            Ok(())
        }
    }
}
