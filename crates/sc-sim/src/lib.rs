//! `sc-sim`: swarm and fleet detection measured against ground truth.
//!
//! [`Truth`] reads who sent each record, its true run, and the swarm and
//! fleet that run belongs to from labelled records; [`measure`] scores an
//! analysis's interaction edges, soft links, candidate fleets and agent
//! grades against it; [`render`] prints the result. No I/O.

pub mod measure;
pub mod render;
pub mod truth;

pub use measure::{KindStat, Measurement, PairCounts, measure};
pub use render::render;
pub use truth::{Truth, TruthRow};

#[cfg(test)]
mod tests;
