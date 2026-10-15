//! `sc-sim`: a seeded swarm simulator with ground truth, and swarm and fleet
//! detection measured against it.
//!
//! [`scenario`] reads scenario files; [`generate`] turns a scenario and a
//! seed into labelled records, copying request content from the committed
//! evaluation records ([`palette`]) and simulating who sends them, when and
//! in what order; [`Truth`] reads who sent each record, its true run, and the
//! swarm and fleet that run belongs to; [`measure`] scores an analysis's
//! interaction edges, soft links, candidate fleets and agent grades against
//! it; [`render`] prints the result; [`gate`] holds floors on precision and
//! ceilings on what the null scenarios draw. No I/O.

pub mod calibrate;
pub mod gate;
pub mod generate;
pub mod measure;
pub mod palette;
pub mod render;
pub mod rng;
pub mod scenario;
pub mod truth;

pub use calibrate::{
    Calibration, RuleCheck, Stratified, calibrate, calibrate_by_scenario, check_rules,
    render_calibration, render_stratified, stratified,
};
pub use calibrate::{JointCheck, check_joint, stratified_joint};
pub use gate::{Check, Gate, NullCounts, null_counts};
pub use generate::{generate, to_ndjson};
pub use measure::{Clustering, Detection, KindStat, Measurement, PairCounts, measure};
pub use palette::{Palette, Template, Use};
pub use render::render;
pub use scenario::{CalibrationConfig, Expect, Scenario, ScenarioFile, TagScope};
pub use truth::{Truth, TruthRow};

use sc_core::{FieldMap, Format, Rules, analyze, parse_input};

/// Each scenario of `file` generated under each of its seeds, analysed on its
/// own and measured; the measurements are summed per scenario.
pub fn bench(file: &ScenarioFile, palette: &Palette, rules: &Rules) -> Vec<(String, Measurement)> {
    bench_with(file, palette, rules, BenchOptions::default()).measured
}

/// What a bench pass measures besides the measurement under the rules.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BenchOptions {
    /// Also count each scenario's cluster pairs with every soft-link kind
    /// on ([`calibrate::count`]), from the same generated records.
    pub calibrate: bool,
    /// Prefixes each generated file is cut into for the time to L2 or a
    /// candidate fleet ([`measure::escalation_times`]); 0 for none. Each
    /// prefix is analysed afresh.
    pub checkpoints: usize,
}

/// A bench pass: the measurement per scenario, and with
/// [`BenchOptions::calibrate`] the calibration counts per scenario.
#[derive(Debug, Clone, Default)]
pub struct BenchResult {
    pub measured: Vec<(String, Measurement)>,
    pub calibration: Vec<(String, Calibration)>,
}

/// [`bench`], generating each scenario's records once for everything
/// `opts` asks for.
pub fn bench_with(
    file: &ScenarioFile,
    palette: &Palette,
    rules: &Rules,
    opts: BenchOptions,
) -> BenchResult {
    let open = opts.calibrate.then(|| calibrate::open_rules(rules));
    let mut out = BenchResult::default();
    for s in &file.scenario {
        let mut total = Measurement::default();
        let mut cal = Calibration::default();
        for k in 0..s.seeds.max(1) {
            let text = to_ndjson(&generate(s, s.seed + k as u64, palette));
            let obs = parse_input(&text, Format::Auto, &FieldMap::default()).observations;
            let truth = Truth::from_ndjson(&text);
            let mut m = measure(&analyze(obs.clone(), rules), &truth);
            if opts.checkpoints > 0 {
                m.detection.checkpoints = opts.checkpoints;
                m.detection.minutes_to_escalate =
                    measure::escalation_times(&obs, &truth, rules, opts.checkpoints);
            }
            total.add(&m);
            if let Some(open) = &open {
                cal.add(&calibrate::count(&analyze(obs, open), &truth));
            }
        }
        out.measured.push((s.name.clone(), total));
        if opts.calibrate {
            out.calibration.push((s.name.clone(), cal));
        }
    }
    out
}

#[cfg(test)]
mod tests;
