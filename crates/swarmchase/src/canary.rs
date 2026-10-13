//! `swarmchase canary`: the registry of canary tokens the site has
//! published, and finding copies of them in records ([`sc_core::canary`]).
//!
//! Tokens are leak detection for our own published material: each page and
//! agent-facing file carries one, distinct per file and month, when the
//! site build turns them on (`SWARMCHASE_CANARY=on`, off by default). A
//! copy in a public record shows that our text was copied and repeated, from
//! which file and no earlier than which month; never who copied it.
//!
//! ```text
//! <data>/canary/registry.json   every token registered from a built site
//! <data>/runs/<stamp>/canary.json   a watch run's sightings, when it has any
//! ```
//!
//! The seed comes from `SWARMCHASE_CANARY_SEED` (env.list, never committed)
//! and is never printed or written.

use crate::input::{InputArgs, read_records};
use crate::store::{read_json, write_json};
use anyhow::{Context, Result, bail};
use clap::{Args, Subcommand};
use sc_core::Observation;
use sc_core::canary::{Registry, Sighting, check_seed, derive, find_tokens, period_of};
use std::path::{Path, PathBuf};

/// The registry, under the data directory.
pub const REGISTRY: &str = "canary/registry.json";

/// A watch run's sightings, in its run directory.
pub const RUN_FILE: &str = "canary.json";

#[derive(Args)]
pub struct CanaryArgs {
    #[command(subcommand)]
    cmd: CanaryCmd,
    /// Data directory holding the registry.
    #[arg(
        short,
        long,
        default_value = "data",
        env = "SWARMCHASE_DATA",
        global = true
    )]
    data: PathBuf,
}

#[derive(Subcommand)]
enum CanaryCmd {
    /// Register the tokens a built site carries: each is checked against
    /// the seed for its file and month before it is recorded.
    Register {
        /// The built site (`_site`).
        #[arg(default_value = "_site")]
        site: PathBuf,
    },
    /// List the registered tokens.
    List {
        #[arg(long)]
        json: bool,
    },
    /// The token a file under the site root carries in a month (`YYMM`,
    /// default this month).
    Token {
        surface: String,
        #[arg(long)]
        period: Option<String>,
    },
    /// Find registered tokens (and unregistered token-shaped values) in
    /// record files.
    Scan {
        #[command(flatten)]
        input: InputArgs,
        #[arg(long)]
        json: bool,
    },
}

fn seed() -> Result<String> {
    let s = std::env::var("SWARMCHASE_CANARY_SEED")
        .context("SWARMCHASE_CANARY_SEED is not set (see env.list.example)")?;
    check_seed(&s).map_err(anyhow::Error::msg)?;
    Ok(s.trim().to_string())
}

pub fn load(data: &Path) -> Result<Registry> {
    Ok(read_json(&data.join(REGISTRY))?.unwrap_or_default())
}

pub fn run(args: CanaryArgs) -> Result<()> {
    let now = chrono::Utc::now().timestamp();
    match args.cmd {
        CanaryCmd::Register { site } => {
            let seed = seed()?;
            let mut reg = load(&args.data)?;
            let (new, seen) = register(&site, seed.as_bytes(), now, &mut reg)?;
            let p = args.data.join(REGISTRY);
            std::fs::create_dir_all(p.parent().unwrap_or(&args.data))?;
            write_json(&p, &reg)?;
            println!(
                "{seen} token(s) in {}, {new} new; {} registered in {}",
                site.display(),
                reg.issued.len(),
                p.display()
            );
        }
        CanaryCmd::List { json } => {
            let reg = load(&args.data)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&reg)?);
            } else {
                for e in &reg.issued {
                    println!(
                        "{}  {}  {}  registered {}",
                        e.token,
                        e.period,
                        e.surface,
                        sc_core::fmt_ts(e.registered)
                    );
                }
            }
        }
        CanaryCmd::Token { surface, period } => {
            let period = period.unwrap_or_else(|| period_of(now));
            if sc_core::canary::period_bounds(&period).is_none() {
                bail!("period `{period}` is not YYMM");
            }
            println!("{}", derive(seed()?.as_bytes(), &surface, &period));
        }
        CanaryCmd::Scan { input, json } => {
            let reg = load(&args.data)?;
            let found = reg.sightings(&read_records(&input)?);
            if json {
                println!("{}", serde_json::to_string_pretty(&found)?);
            } else if found.is_empty() {
                println!("no canary tokens found");
            } else {
                for s in &found {
                    println!("{}", s.line());
                }
            }
        }
    }
    Ok(())
}

/// Register every token in the surfaces of a built site. Each must be the
/// token the seed gives for its file and its month; anything else is an
/// error, so a site built with another seed is never registered. Returns
/// (new, found).
fn register(site: &Path, seed: &[u8], now: i64, reg: &mut Registry) -> Result<(usize, usize)> {
    let mut found = 0;
    let mut new = 0;
    let mut stack = vec![site.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for e in std::fs::read_dir(&dir).with_context(|| format!("reading {}", dir.display()))? {
            let p = e?.path();
            if p.is_dir() {
                stack.push(p);
                continue;
            }
            let rel = p
                .strip_prefix(site)
                .unwrap_or(&p)
                .to_string_lossy()
                .replace('\\', "/");
            if !sc_publish::agents::is_surface(&rel) {
                continue;
            }
            let text = std::fs::read_to_string(&p).unwrap_or_default();
            for t in find_tokens(&text) {
                let period = &t[sc_core::canary::PREFIX.len()..sc_core::canary::PREFIX.len() + 4];
                if derive(seed, &rel, period) != t {
                    bail!(
                        "{rel}: carries `{t}`, which is not this seed's token for it; was the site built with another seed?"
                    );
                }
                found += 1;
                if reg.add(&t, &rel, period, now) {
                    new += 1;
                }
            }
        }
    }
    Ok((new, found))
}

/// The watch's check: sightings in this run's new records, written to the
/// run directory when there are any. Nothing to do with an empty registry.
pub fn watch_sightings(
    data: &Path,
    fresh: &[Observation],
    run_dir: &Path,
) -> Result<Vec<Sighting>> {
    let reg = load(data)?;
    if reg.issued.is_empty() {
        return Ok(Vec::new());
    }
    let found = reg.sightings(fresh);
    if !found.is_empty() {
        write_json(&run_dir.join(RUN_FILE), &found)?;
    }
    Ok(found)
}

/// The digest's section for a run's sightings; empty with none.
pub fn digest_section(found: &[Sighting]) -> String {
    if found.is_empty() {
        return String::new();
    }
    let mut s = format!(
        "\n## Canary sightings\n\nTokens from our own published pages and files, found in {} new record(s). A copy shows our text was repeated from that file no earlier than its month, not who repeated it; a token never links records. Details in `{RUN_FILE}`.\n\n",
        found.len()
    );
    for x in found {
        s.push_str("- ");
        s.push_str(&x.line());
        s.push('\n');
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registers_only_this_seeds_tokens() {
        let dir = std::env::temp_dir().join(format!("swarmchase-canary-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join(".well-known")).unwrap();
        let seed = b"0123456789abcdef0123456789abcdef";
        let t = derive(seed, "llms.txt", "2610");
        std::fs::write(dir.join("llms.txt"), format!("Reference: {t}\n")).unwrap();
        let s = derive(seed, ".well-known/security.txt", "2610");
        std::fs::write(dir.join(".well-known/security.txt"), format!("# {s}\n")).unwrap();
        // Not a surface: ignored even with a token in it.
        std::fs::write(dir.join("data.json"), "swc-2610-aaaaaaaaaaaa").unwrap();
        let mut reg = Registry::default();
        assert_eq!(register(&dir, seed, 100, &mut reg).unwrap(), (2, 2));
        assert_eq!(register(&dir, seed, 200, &mut reg).unwrap(), (0, 2));
        assert_eq!(reg.get(&t).unwrap().surface, "llms.txt");
        assert_eq!(reg.get(&t).unwrap().registered, 100);
        assert!(register(&dir, b"another seed, long enough", 300, &mut reg).is_err());
        let rec = Observation {
            id: "r1".into(),
            source: "wayback".into(),
            ts: 1_791_000_000,
            url: format!("https://a.example/?q={s}"),
            ..Default::default()
        };
        let found = reg.sightings(&[rec]);
        assert_eq!(
            found[0].surface.as_deref(),
            Some(".well-known/security.txt")
        );
        let d = digest_section(&found);
        assert!(d.contains("## Canary sightings") && !d.contains("a.example"));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
