//! `swarmchase netranges`: the cloud providers' published address ranges
//! and the Tor exit list in `<data>/netranges/` (`sc_collect::netranges`).
//! Once fetched, `watch` and the analysis commands describe each cluster's
//! client addresses by provider, region and service, and leave records sent
//! from Tor exits out of hosting claims. The watch refreshes the files at
//! most once a day.

use anyhow::{Result, bail};
use clap::{Args, Subcommand};
use sc_collect::Client;
use sc_collect::netranges::{FILES, MAX_AGE, Refreshed, age, load_from_data, refresh};
use sc_core::Analysis;
use std::path::{Path, PathBuf};
use std::time::Duration;

#[derive(Args)]
pub struct NetrangesArgs {
    #[command(subcommand)]
    cmd: NetrangesCmd,
    /// Data directory the files live in.
    #[arg(
        short,
        long,
        global = true,
        default_value = "data",
        env = "SWARMCHASE_DATA"
    )]
    data: PathBuf,
}

#[derive(Subcommand)]
enum NetrangesCmd {
    /// Download every file now, whatever the age of the held copies.
    Fetch,
    /// The files, and the age of each held copy.
    Status,
    /// Look up addresses in the held files.
    Lookup { ips: Vec<String> },
}

pub fn run(a: NetrangesArgs) -> Result<()> {
    match a.cmd {
        NetrangesCmd::Fetch => {
            let client = Client::new(Duration::from_secs(1))?;
            let failed = report_refresh(&refresh(&client, &a.data, None));
            if failed > 0 {
                bail!("{failed} file(s) not fetched; the held copies, if any, stay in use");
            }
        }
        NetrangesCmd::Status => {
            for f in FILES {
                match age(&a.data, f) {
                    Some(d) => println!("{}\t{} h old\t{}", f.id, d.as_secs() / 3600, f.url),
                    None => println!("{}\tnot held\t{}", f.id, f.url),
                }
            }
        }
        NetrangesCmd::Lookup { ips } => {
            let Some(t) = load(&a.data) else {
                bail!(
                    "no ranges held in {}; run `swarmchase netranges fetch` first",
                    a.data.display()
                );
            };
            for ip in ips {
                let i = t.lookup(&ip);
                let class = i.class.map_or_else(|| "-".to_string(), |c| c.label());
                let tor = if i.tor { "tor-exit" } else { "-" };
                println!("{ip}\t{class}\t{tor}");
            }
        }
    }
    Ok(())
}

/// Print one line per file; returns how many failed.
fn report_refresh(results: &[(&str, Result<Refreshed>)]) -> usize {
    let mut failed = 0;
    for (id, r) in results {
        match r {
            Ok(Refreshed::Fetched { bytes, entries }) => {
                eprintln!("{id}: {entries} entries ({bytes} bytes)");
            }
            Ok(Refreshed::Fresh) => eprintln!("{id}: held copy is under a day old"),
            Err(e) => {
                failed += 1;
                eprintln!("{id}: FAILED: {e:#}");
            }
        }
    }
    failed
}

/// The watch's refresh: each file at most once a day. Never fails; returns
/// a line per file that could not be refreshed, for the digest.
pub fn refresh_daily(client: &Client, data: &Path) -> Vec<String> {
    refresh(client, data, Some(MAX_AGE))
        .into_iter()
        .filter_map(|(id, r)| r.err().map(|e| format!("{id}: {e:#}")))
        .collect()
}

/// The held ranges, with a warning per file that does not parse.
fn load(data: &Path) -> Option<sc_core::netranges::NetRanges> {
    let (t, warnings) = load_from_data(data);
    for w in &warnings {
        eprintln!("warning: netranges: {w}");
    }
    t
}

/// Describe each cluster's client addresses from the ranges held in `data`.
/// Quiet when nothing is held.
pub fn annotate_in(data: &Path, a: &mut Analysis) {
    if let Some(t) = load(data) {
        let n = sc_core::netranges::annotate(a, &t);
        if n > 0 {
            eprintln!("described {n} clustered record(s) from published network ranges");
        }
    }
}

/// [`annotate_in`] for the data directory the analysis commands use
/// (`SWARMCHASE_DATA`, else `data`).
pub fn annotate(a: &mut Analysis) {
    let data = std::env::var("SWARMCHASE_DATA")
        .ok()
        .filter(|d| !d.is_empty())
        .map_or_else(|| PathBuf::from("data"), PathBuf::from);
    annotate_in(&data, a);
}
