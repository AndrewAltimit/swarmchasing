//! `swarmchase analyze`: the full analysis as JSON.

use crate::input::{InputArgs, run_analysis};
use crate::util::write_out;
use anyhow::Result;
use clap::Args;
use std::path::PathBuf;

#[derive(Args)]
pub struct AnalyzeArgs {
    #[command(flatten)]
    input: InputArgs,
    #[arg(short, long)]
    out: Option<PathBuf>,
    /// Only include flagged records in the output.
    #[arg(long)]
    flagged_only: bool,
}

pub fn run(args: AnalyzeArgs) -> Result<()> {
    let mut a = run_analysis(&args.input)?;
    if args.flagged_only {
        // Keep cluster member indices valid by remapping.
        let keep: Vec<usize> = (0..a.results.len())
            .filter(|&i| a.results[i].score > 0)
            .collect();
        let mut remap = vec![usize::MAX; a.results.len()];
        for (n, &i) in keep.iter().enumerate() {
            remap[i] = n;
        }
        for c in &mut a.clusters {
            c.members = c.members.iter().map(|&m| remap[m]).collect();
        }
        a.results = keep.into_iter().map(|i| a.results[i].clone()).collect();
    }
    write_out(args.out.as_deref(), &serde_json::to_string_pretty(&a)?)
}
