//! `swarmchase platform-swarms`: candidate coordinated-account swarms in
//! platform events, from the watch's carried events, synthetic fixtures, or
//! GH Archive hour files read locally.

use crate::watch::platform::{load_events, render_swarm};
use anyhow::{Context, Result};
use sc_core::platform::{PlatformEvent, PlatformOptions, detect};
use std::path::PathBuf;

#[derive(clap::Args)]
pub struct PlatformArgs {
    /// Platform event NDJSON (the watch's `platform/carry.ndjson`, fixtures),
    /// or GH Archive hour files (`.json` or `.json.gz`) with `--gharchive`.
    #[arg(required = true)]
    inputs: Vec<PathBuf>,
    /// Read the inputs as GH Archive hour files.
    #[arg(long)]
    gharchive: bool,
    /// Detector options as TOML (the watchlist's `[platform.options]` keys).
    #[arg(long)]
    options: Option<PathBuf>,
    #[arg(long)]
    rules: Option<PathBuf>,
    /// Print the full report as JSON.
    #[arg(long)]
    json: bool,
}

pub fn run(a: PlatformArgs) -> Result<()> {
    let rules = crate::input::load_rules(a.rules.as_deref())?;
    let opts: PlatformOptions = match &a.options {
        Some(p) => toml::from_str(
            &std::fs::read_to_string(p).with_context(|| format!("reading {}", p.display()))?,
        )
        .context("platform options")?,
        None => PlatformOptions::default(),
    };
    let mut events: Vec<PlatformEvent> = Vec::new();
    for p in &a.inputs {
        if a.gharchive {
            let t = sc_collect::platform::gharchive_file(p, &rules)?;
            eprintln!(
                "{}: {} events parsed, {} kept, {} automation dropped",
                p.display(),
                t.parsed,
                t.events.len(),
                t.automation
            );
            for (k, n) in &t.declared {
                eprintln!("  declared coding-agent App: {k} {n}");
            }
            for (login, (claim, n)) in &t.lookalikes {
                eprintln!("  spoofing lead: App {login} ({n} event(s)) claims {claim}");
            }
            events.extend(t.events);
        } else {
            events.extend(load_events(p)?);
        }
    }
    let report = detect(&events, &opts);
    if a.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }
    println!(
        "{} event(s) from {} account(s): {} candidate(s), {} suppressed as benign, {} below the chance threshold. Hints, not findings.\n",
        report.events,
        report.accounts,
        report.swarms.len(),
        report.suppressed.len(),
        report.below_threshold
    );
    for s in &report.swarms {
        print!("{}", render_swarm(s, None));
    }
    for s in &report.suppressed {
        println!(
            "suppressed ({}): {} event(s), {} account(s): `{}`",
            s.why, s.events, s.accounts, s.template
        );
    }
    Ok(())
}
