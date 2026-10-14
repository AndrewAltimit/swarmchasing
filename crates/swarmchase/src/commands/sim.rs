//! `swarmchase sim`: simulated swarms with ground truth, and swarm and fleet
//! detection measured against labelled records ([`sc_sim`]).

use crate::input::{InputArgs, load_rules, read_records};
use anyhow::{Context, Result, bail};
use clap::{Args, Subcommand};
use sc_sim::{
    BenchOptions, Calibration, Gate, Measurement, Palette, ScenarioFile, Truth, bench_with,
    calibrate_by_scenario, check_rules, generate, measure, null_counts, render, render_stratified,
    to_ndjson,
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
        /// Also run `sim calibrate --check` on the same generated records
        /// (each is generated once for both), and fail as it would.
        #[arg(long)]
        calibrate_check: bool,
        /// Cut each generated file into this many prefixes by time and
        /// analyse each, for the minutes each agent run takes to reach L2 or
        /// a candidate fleet (0: off; each prefix is a full analysis).
        #[arg(long, default_value_t = 0)]
        detect_checkpoints: usize,
        #[command(flatten)]
        gate: GateArgs,
    },
    /// Each soft-link kind's likelihood ratio from simulated truth: every
    /// kind switched on, every pair of clusters above noise counted as one
    /// operator's or not. Prints the pooled ratios, the ratios stratified by
    /// scenario and each scenario's, beside the ones the rules set.
    Calibrate {
        scenarios: PathBuf,
        #[arg(long)]
        rules: Option<PathBuf>,
        /// Exit non-zero when a ratio the rules set is above the
        /// stratified lower bound of a kind the scenarios measure, or a
        /// ratio above 1 is measured by no scenario and the scenario file's
        /// `calibration.unmeasured` gives no reason for it.
        #[arg(long)]
        check: bool,
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
    /// Soft links of any kind between distinct runs (pairs of clusters on
    /// one run left out).
    #[arg(long)]
    min_link_cross_run_precision: Option<f64>,
    /// Candidate-fleet cluster pairs between distinct runs.
    #[arg(long)]
    min_fleet_cross_run_precision: Option<f64>,
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
    /// Benign or tool records in clusters graded L2 or above, summed over
    /// every scenario.
    #[arg(long)]
    max_benign_high: Option<usize>,
    /// People's records in clusters graded L3 or above.
    #[arg(long)]
    max_human_high: Option<usize>,
    /// Hold each scenario's `expect` table: every kind it names must draw
    /// pairs and meet its bounds on that scenario.
    #[arg(long)]
    expect: bool,
}

impl GateArgs {
    fn gate(&self) -> Gate {
        Gate {
            min_edge_precision: self.min_edge_precision,
            min_link_precision: self.min_link_precision,
            min_fleet_precision: self.min_fleet_precision,
            min_link_cross_run_precision: self.min_link_cross_run_precision,
            min_fleet_cross_run_precision: self.min_fleet_cross_run_precision,
            max_null_edges: self.max_null_edges,
            max_null_links: self.max_null_links,
            max_null_fleet_pairs: self.max_null_fleet_pairs,
            max_benign_high: self.max_benign_high,
            max_human_high: self.max_human_high,
            expect: self.expect,
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
            calibrate_check,
            detect_checkpoints,
            gate,
        } => {
            let rules = load_rules(rules.as_deref())?;
            let file = read_scenarios(&scenarios)?;
            let out = bench_with(
                &file,
                &Palette::default_palette(&rules),
                &rules,
                BenchOptions {
                    calibrate: calibrate_check,
                    checkpoints: detect_checkpoints,
                },
            );
            let results = out.measured;
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
                for c in gate
                    .check(&sum, &null)
                    .into_iter()
                    .chain(gate.check_scenarios(&results, &file))
                {
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
            let calibration_failed = if calibrate_check {
                println!("\nCalibration check (sim calibrate --check):");
                calibration_check(&out.calibration, &rules, &file)
            } else {
                0
            };
            if failed > 0 {
                bail!("{failed} simulator bound(s) not met");
            }
            if calibration_failed > 0 {
                bail!(
                    "{calibration_failed} soft-link ratio(s) above the simulation's stratified lower bound or unmeasured"
                );
            }
            Ok(())
        }
        SimCmd::Calibrate {
            scenarios,
            rules,
            check,
        } => {
            let rules = load_rules(rules.as_deref())?;
            let file = read_scenarios(&scenarios)?;
            let strata = calibrate_by_scenario(&file, &Palette::default_palette(&rules), &rules);
            print!("{}", render_stratified(&strata, &rules));
            if check {
                println!();
                let failed = calibration_check(&strata, &rules, &file);
                if failed > 0 {
                    bail!(
                        "{failed} soft-link ratio(s) above the simulation's stratified lower bound or unmeasured"
                    );
                }
            }
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

/// Print each kind's check line and return how many failed.
fn calibration_check(
    strata: &[(String, Calibration)],
    rules: &sc_core::Rules,
    file: &ScenarioFile,
) -> usize {
    let mut failed = 0;
    for c in check_rules(strata, rules, &file.calibration.unmeasured) {
        println!("{}", c.line());
        failed += usize::from(!c.ok);
    }
    failed
}

fn read_scenarios(p: &std::path::Path) -> Result<ScenarioFile> {
    let text = std::fs::read_to_string(p).with_context(|| format!("reading {}", p.display()))?;
    ScenarioFile::parse(&text).map_err(|e| anyhow::anyhow!("{}: {e}", p.display()))
}
