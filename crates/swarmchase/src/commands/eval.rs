//! `swarmchase eval`: the command around [`crate::eval`].

use crate::eval::{self, Floors};
use crate::input::{InputArgs, run_analysis};
use anyhow::Result;
use clap::Args;
use std::path::PathBuf;

#[derive(Args)]
pub struct EvalArgs {
    #[command(flatten)]
    input: InputArgs,
    #[arg(long)]
    labels: Vec<PathBuf>,
    #[command(flatten)]
    floors: Floors,
    /// Also write the full result as JSON.
    #[arg(long)]
    json: Option<PathBuf>,
    /// How many false positives to list.
    #[arg(long, default_value_t = 20)]
    show_fp: usize,
}

pub fn run(args: EvalArgs) -> Result<()> {
    let l = eval::load_labels(&args.labels, &args.input.input)?;
    let a = run_analysis(&args.input)?;
    eval::run(&a, &l, &args.floors, args.json.as_deref(), args.show_fp)
}
