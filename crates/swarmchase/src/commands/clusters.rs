//! `swarmchase clusters`: a summary of each cluster, with its number and
//! stable key.

use crate::input::{InputArgs, run_analysis};
use crate::util::{print_summary, top_counted};
use anyhow::Result;
use clap::Args;
use sc_core::fmt_ts;

#[derive(Args)]
pub struct ClustersArgs {
    #[command(flatten)]
    input: InputArgs,
}

pub fn run(args: ClustersArgs) -> Result<()> {
    let a = run_analysis(&args.input)?;
    print_summary(&a);
    println!();
    for c in &a.clusters {
        let hosts = top_counted(&c.target_hosts, 3);
        let rules = top_counted(&c.rules, 6);
        println!(
            "{:<4} {} [{:<11}] {:>5} records  {} runs  {} → {}",
            c.id,
            c.key,
            c.tier.label(),
            c.members.len(),
            c.runs.len(),
            fmt_ts(c.start),
            fmt_ts(c.end)
        );
        println!("     targets: {}", hosts.join(", "));
        println!("     rules:   {}", rules.join(", "));
        if let Some(g) = c.timing.median_gap_secs {
            println!(
                "     median gap {g:.0}s, {} bursts, {} pauses",
                c.timing.bursts.len(),
                c.timing.pauses.len()
            );
        }
    }
    Ok(())
}
