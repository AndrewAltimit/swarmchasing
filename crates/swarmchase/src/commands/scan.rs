//! `swarmchase scan`: flagged records, strongest first.

use crate::input::{InputArgs, parse_tier, run_analysis};
use crate::util::{print_summary, truncate};
use anyhow::Result;
use clap::Args;
use sc_core::{defang, fmt_ts};

#[derive(Args)]
pub struct ScanArgs {
    #[command(flatten)]
    input: InputArgs,
    /// Minimum tier to show: noise | suggestive | significant
    #[arg(long, default_value = "suggestive")]
    min_tier: String,
    #[arg(long, default_value_t = 50)]
    limit: usize,
}

pub fn run(args: ScanArgs) -> Result<()> {
    let min = parse_tier(&args.min_tier)?;
    let a = run_analysis(&args.input)?;
    print_summary(&a);
    let mut rows: Vec<_> = a
        .results
        .iter()
        .filter(|r| r.score > 0 && r.tier >= min)
        .collect();
    rows.sort_by(|x, y| y.score.cmp(&x.score).then(x.obs.ts.cmp(&y.obs.ts)));
    println!();
    for r in rows.iter().take(args.limit) {
        let rules: Vec<&str> = r.hits.iter().map(|h| h.rule_id.as_str()).collect();
        println!(
            "[{:<11}] {:>3}  {}  {}  {}",
            r.tier.label(),
            r.score,
            fmt_ts(r.obs.ts),
            r.cluster
                .map(|c| a.clusters[c].id.clone())
                .unwrap_or_else(|| "-".into()),
            defang(&truncate(&r.obs.url, 120))
        );
        println!("{:>18}{}", "", rules.join(" "));
    }
    if rows.len() > args.limit {
        println!("… {} more (use --limit)", rows.len() - args.limit);
    }
    Ok(())
}
