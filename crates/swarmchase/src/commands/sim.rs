//! `swarmchase sim`: swarm and fleet detection measured against labelled
//! ground truth ([`sc_sim`]).

use crate::input::{InputArgs, load_rules, read_records};
use anyhow::{Context, Result, bail};
use clap::{Args, Subcommand};
use sc_sim::{Measurement, Truth, measure, render};
use std::path::PathBuf;

#[derive(Args)]
pub struct SimArgs {
    #[command(subcommand)]
    cmd: SimCmd,
}

#[derive(Subcommand)]
enum SimCmd {
    /// Score interaction edges, soft links, candidate fleets and agent
    /// grades against records labelled with `run`, `swarm` and `fleet`.
    /// Each file is analysed on its own and the counts are summed.
    Score {
        /// Labelled NDJSON files.
        #[arg(required = true)]
        input: Vec<PathBuf>,
        /// Rules file (defaults to the bundled rules/default.toml).
        #[arg(long)]
        rules: Option<PathBuf>,
        /// Also write the measurement as JSON (counts and kind names only).
        #[arg(long)]
        json: Option<PathBuf>,
    },
}

pub fn run(a: SimArgs) -> Result<()> {
    match a.cmd {
        SimCmd::Score { input, rules, json } => {
            let rules = load_rules(rules.as_deref())?;
            let mut total = Measurement::default();
            for p in &input {
                let text = std::fs::read_to_string(p)
                    .with_context(|| format!("reading {}", p.display()))?;
                let truth = Truth::from_ndjson(&text);
                if truth.rows.is_empty() {
                    bail!("{}: no record carries a `run` label", p.display());
                }
                let obs = read_records(&InputArgs::files(vec![p.clone()]))?;
                total.add(&measure(&sc_core::analyze(obs, &rules), &truth));
            }
            print!("{}", render(&total));
            if let Some(j) = json {
                std::fs::write(&j, serde_json::to_string_pretty(&total)? + "\n")
                    .with_context(|| format!("writing {}", j.display()))?;
            }
            Ok(())
        }
    }
}
