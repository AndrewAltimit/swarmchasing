//! `swarmchase sim`: simulated swarms with ground truth, and swarm and fleet
//! detection measured against labelled records ([`sc_sim`]).

use crate::input::{InputArgs, load_rules, read_records};
use anyhow::{Context, Result, bail};
use clap::{Args, Subcommand};
use sc_sim::{
    Gate, Measurement, Palette, ScenarioFile, Truth, bench, calibrate, generate, measure,
    null_counts, render, render_calibration, to_ndjson,
};
use std::path::PathBuf;

#[derive(Args)]
pub struct SimArgs {
    #[command(subcommand)]
    cmd: SimCmd,
}

#[derive(Subcommand)]
enum SimCmd {
    /// Write each scenario's labelled records, one NDJSON file per scenario
    /// and seed, into a directory. Request content is copied from the
    /// committed evaluation records; only senders, times and order are
    /// simulated.
    Write {
        /// Scenario file (TOML, `[[scenario]]` tables).
        scenarios: PathBuf,
        #[arg(short, long)]
        out: PathBuf,
        #[arg(long)]
        rules: Option<PathBuf>,
    },
    /// Generate every scenario under its seeds, analyse each run on its own,
    /// and print the measurement per scenario and summed, and what the null
    /// scenarios drew. With floors or ceilings set, exits non-zero when one
    /// is not met.
    Bench {
        scenarios: PathBuf,
        #[arg(long)]
        rules: Option<PathBuf>,
        /// Print only the summed measurement.
        #[arg(long)]
        total: bool,
        /// Also write the per-scenario measurements as JSON.
        #[arg(long)]
        json: Option<PathBuf>,
        #[command(flatten)]
        gate: GateArgs,
    },
    /// Each soft-link kind's likelihood ratio from simulated truth: every
    /// kind switched on, every pair of clusters above noise counted as one
    /// operator's or not. Prints the ratios beside the ones the rules set.
    Calibrate {
        scenarios: PathBuf,
        #[arg(long)]
        rules: Option<PathBuf>,
    },
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

/// Floors on precision summed over every scenario, and ceilings on the
/// false pairs the null scenarios draw.
#[derive(Args)]
struct GateArgs {
    /// Interaction edges of any kind.
    #[arg(long)]
    min_edge_precision: Option<f64>,
    /// Soft links of any kind.
    #[arg(long)]
    min_link_precision: Option<f64>,
    /// Candidate fleets, as cluster pairs.
    #[arg(long)]
    min_fleet_precision: Option<f64>,
    /// Edges between different runs in the null scenarios, summed over
    /// their seeds.
    #[arg(long)]
    max_null_edges: Option<usize>,
    /// Soft links between different runs in the null scenarios.
    #[arg(long)]
    max_null_links: Option<usize>,
    /// Candidate-fleet cluster pairs between different runs in the null
    /// scenarios.
    #[arg(long)]
    max_null_fleet_pairs: Option<usize>,
}

impl GateArgs {
    fn gate(&self) -> Gate {
        Gate {
            min_edge_precision: self.min_edge_precision,
            min_link_precision: self.min_link_precision,
            min_fleet_precision: self.min_fleet_precision,
            max_null_edges: self.max_null_edges,
            max_null_links: self.max_null_links,
            max_null_fleet_pairs: self.max_null_fleet_pairs,
        }
    }
}

pub fn run(a: SimArgs) -> Result<()> {
    match a.cmd {
        SimCmd::Write {
            scenarios,
            out,
            rules,
        } => {
            let rules = load_rules(rules.as_deref())?;
            let file = read_scenarios(&scenarios)?;
            let palette = Palette::default_palette(&rules);
            std::fs::create_dir_all(&out).with_context(|| format!("creating {}", out.display()))?;
            for s in &file.scenario {
                for k in 0..s.seeds.max(1) {
                    let seed = s.seed + k as u64;
                    let p = out.join(format!("{}-{seed}.ndjson", s.name));
                    std::fs::write(&p, to_ndjson(&generate(s, seed, &palette)))
                        .with_context(|| format!("writing {}", p.display()))?;
                    println!("{}", p.display());
                }
            }
            Ok(())
        }
        SimCmd::Bench {
            scenarios,
            rules,
            total,
            json,
            gate,
        } => {
            let rules = load_rules(rules.as_deref())?;
            let file = read_scenarios(&scenarios)?;
            let results = bench(&file, &Palette::default_palette(&rules), &rules);
            let mut sum = Measurement::default();
            for (name, m) in &results {
                sum.add(m);
                if !total {
                    println!("== {name}");
                    print!("{}", render(m));
                    println!();
                }
            }
            println!("== all scenarios");
            print!("{}", render(&sum));
            let null = null_counts(&results, &file);
            println!(
                "\nNull scenarios ({} over {} seed(s)), between different runs: {} edge(s), {} soft link(s), {} candidate-fleet pair(s). Every one is false.",
                null.scenarios, null.seeds, null.edges, null.links, null.fleet_pairs
            );
            let gate = gate.gate();
            let mut failed = 0;
            if !gate.is_empty() {
                println!();
                for c in gate.check(&sum, &null) {
                    println!("{}", c.line());
                    failed += usize::from(!c.ok);
                }
            }
            if let Some(j) = json {
                let map: std::collections::BTreeMap<&str, &Measurement> = results
                    .iter()
                    .map(|(n, m)| (n.as_str(), m))
                    .chain([("all", &sum)])
                    .collect();
                std::fs::write(
                    &j,
                    serde_json::to_string_pretty(&map)?
                        + "
",
                )
                .with_context(|| format!("writing {}", j.display()))?;
            }
            if failed > 0 {
                bail!("{failed} simulator bound(s) not met");
            }
            Ok(())
        }
        SimCmd::Calibrate { scenarios, rules } => {
            let rules = load_rules(rules.as_deref())?;
            let file = read_scenarios(&scenarios)?;
            let c = calibrate(&file, &Palette::default_palette(&rules), &rules);
            print!("{}", render_calibration(&c, &rules));
            Ok(())
        }
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

fn read_scenarios(p: &std::path::Path) -> Result<ScenarioFile> {
    let text = std::fs::read_to_string(p).with_context(|| format!("reading {}", p.display()))?;
    ScenarioFile::parse(&text).map_err(|e| anyhow::anyhow!("{}: {e}", p.display()))
}
