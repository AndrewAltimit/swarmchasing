//! `sc-sim`: a seeded swarm simulator with ground truth, and swarm and fleet
//! detection measured against it.
//!
//! [`scenario`] reads scenario files; [`generate`] turns a scenario and a
//! seed into labelled records, copying request content from the committed
//! evaluation records ([`palette`]) and simulating who sends them, when and
//! in what order; [`Truth`] reads who sent each record, its true run, and the
//! swarm and fleet that run belongs to; [`measure`] scores an analysis's
//! interaction edges, soft links, candidate fleets and agent grades against
//! it; [`render`] prints the result. No I/O.

pub mod calibrate;
pub mod generate;
pub mod measure;
pub mod palette;
pub mod render;
pub mod rng;
pub mod scenario;
pub mod truth;

pub use calibrate::{Calibration, calibrate, render_calibration};
pub use generate::{generate, to_ndjson};
pub use measure::{KindStat, Measurement, PairCounts, measure};
pub use palette::{Palette, Template, Use};
pub use render::render;
pub use scenario::{Scenario, ScenarioFile};
pub use truth::{Truth, TruthRow};

use sc_core::{FieldMap, Format, Rules, analyze, parse_input};

/// Each scenario of `file` generated under each of its seeds, analysed on its
/// own and measured; the measurements are summed per scenario.
pub fn bench(file: &ScenarioFile, palette: &Palette, rules: &Rules) -> Vec<(String, Measurement)> {
    let mut out = Vec::new();
    for s in &file.scenario {
        let mut total = Measurement::default();
        for k in 0..s.seeds.max(1) {
            let text = to_ndjson(&generate(s, s.seed + k as u64, palette));
            let obs = parse_input(&text, Format::Auto, &FieldMap::default()).observations;
            total.add(&measure(&analyze(obs, rules), &Truth::from_ndjson(&text)));
        }
        out.push((s.name.clone(), total));
    }
    out
}

#[cfg(test)]
mod tests;
