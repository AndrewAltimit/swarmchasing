//! `swarmchase report`: a Markdown report draft for one audience.

use crate::input::{InputArgs, run_analysis};
use crate::util::write_out;
use anyhow::{Context, Result, bail};
use clap::Args;
use sc_core::{Audience, ReportOptions, Rules, render_markdown};
use std::path::PathBuf;

#[derive(Args)]
pub struct ReportArgs {
    #[command(flatten)]
    input: InputArgs,
    /// provider | affected | internal | public
    #[arg(long, default_value = "internal")]
    audience: Audience,
    /// Limit to one cluster, by number (C1) or stable key (k-3f9a2c1b).
    #[arg(long)]
    cluster: Option<String>,
    #[arg(long)]
    reporter: Option<String>,
    /// Weakest evidence that may name a developer outside case notes:
    /// hosting_asn | shared_identifiers | provider_infrastructure |
    /// provider_confirmed. Self-identification alone never names one.
    #[arg(long, default_value = "shared_identifiers")]
    min_named: sc_core::Evidence,
    /// JSON array of claims established by case work, e.g.
    /// [{"party":"Example AI","role":"developer","evidence":"provider_confirmed","details":["…"]}]
    #[arg(long)]
    claims: Option<PathBuf>,
    #[arg(short, long)]
    out: Option<PathBuf>,
}

pub fn run(args: ReportArgs) -> Result<()> {
    if args.min_named < sc_core::Evidence::FLOOR {
        eprintln!(
            "note: self-identification alone never names a developer; using {}",
            sc_core::Evidence::FLOOR.id()
        );
    }
    let claims: Vec<sc_core::Claim> = match &args.claims {
        Some(p) => serde_json::from_str(
            &std::fs::read_to_string(p).with_context(|| format!("reading {}", p.display()))?,
        )
        .with_context(|| format!("parsing {}", p.display()))?,
        None => Vec::new(),
    };
    let a = run_analysis(&args.input)?;
    if let Some(id) = &args.cluster
        && a.cluster(id).is_none()
    {
        bail!("no cluster `{id}` (run `swarmchase clusters` first)");
    }
    let opts = ReportOptions {
        audience: args.audience,
        cluster: args.cluster,
        reporter: args.reporter,
        generated: Some(crate::util::today()),
        min_named: args.min_named,
        claims,
        ..Default::default()
    };
    if args.audience == Audience::Public {
        let n = sc_core::render_notice(&a, &opts);
        for w in &n.withheld {
            eprintln!("withheld: {w}");
        }
        for f in &n.flags {
            eprintln!("decide:   {f}");
        }
        for l in sc_core::notice::lint_public(&n.markdown, &Rules::default_rules())
            .iter()
            .chain(&n.leaks)
        {
            eprintln!("LEAK:     {l}");
        }
        write_out(args.out.as_deref(), &n.markdown)
    } else {
        write_out(args.out.as_deref(), &render_markdown(&a, &opts))
    }
}
