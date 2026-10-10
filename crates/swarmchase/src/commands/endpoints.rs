//! `swarmchase endpoints`: flagged activity per target host.

use crate::input::{InputArgs, parse_tier, run_analysis};
use crate::util::print_summary;
use anyhow::Result;
use clap::Args;
use sc_core::{defang, fmt_ts};

#[derive(Args)]
pub struct EndpointsArgs {
    #[command(flatten)]
    input: InputArgs,
    /// Minimum tier to count: noise | suggestive | significant
    #[arg(long, default_value = "suggestive")]
    min_tier: String,
    /// Hits within this many days of the newest record count as ongoing.
    #[arg(long, default_value_t = 7)]
    active_days: i64,
    /// Measure "ongoing" from now instead of from the newest record.
    #[arg(long)]
    from_now: bool,
    #[arg(long)]
    json: bool,
}

pub fn run(args: EndpointsArgs) -> Result<()> {
    let a = run_analysis(&args.input)?;
    let opts = sc_core::EndpointOptions {
        min_tier: parse_tier(&args.min_tier)?,
        now: if args.from_now {
            chrono::Utc::now().timestamp()
        } else {
            0
        },
        active_days: args.active_days,
    };
    let views = sc_core::endpoints(&a, &opts);
    if args.json {
        println!("{}", serde_json::to_string_pretty(&views)?);
        return Ok(());
    }
    print_summary(&a);
    println!(
        "\n{} endpoint(s) at {} or above\n",
        views.len(),
        opts.min_tier.label()
    );
    for v in &views {
        println!(
            "{:<40} [{:<11}] {:>4} hits / {:<4} {:<10} {} → {}",
            defang(&v.host),
            v.max_tier.label(),
            v.hits,
            v.records,
            v.activity.label(),
            fmt_ts(v.first_seen),
            fmt_ts(v.last_seen)
        );
        if v.payloads {
            let p: Vec<&str> = v.payload_rules.keys().map(String::as_str).collect();
            println!("{:>6}payloads: {}", "", p.join(", "));
        }
        if !v.clusters.is_empty() {
            println!("{:>6}clusters: {}", "", v.clusters.join(", "));
        }
    }
    Ok(())
}
