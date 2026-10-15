//! `swarmchase scan`: flagged records, strongest first.

use crate::input::{InputArgs, load_rules, parse_tier, read_records_counted};
use crate::util::print_summary;
use anyhow::{Result, bail};
use clap::Args;
use sc_core::{analyze, fmt_ts};

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
    let rules = load_rules(args.input.rules.as_deref())?;
    let (mut obs, bad) = read_records_counted(&args.input)?;
    // Every line unreadable is a wrong file or format, not a clean scan.
    if obs.is_empty() && bad > 0 {
        bail!(
            "no record could be read: {bad} line(s) of input were not records (check the file and --format)"
        );
    }
    crate::commands::asn::enrich(&mut obs);
    let mut a = analyze(obs, &rules);
    crate::commands::identity::annotate(&mut a);
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
            sc_core::clip_defanged(&sc_core::defang(&r.obs.url), 120)
        );
        println!("{:>18}{}", "", rules.join(" "));
    }
    if rows.len() > args.limit {
        println!("… {} more (use --limit)", rows.len() - args.limit);
    }
    Ok(())
}
