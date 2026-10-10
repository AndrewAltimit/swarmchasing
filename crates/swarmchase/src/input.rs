//! Reading records and rules for the analysis commands.

use anyhow::{Context, Result, bail};
use clap::Args;
use sc_core::{Analysis, FieldMap, Format, Observation, Rules, Tier, analyze, parse_input};
use std::io::Read;
use std::path::{Path, PathBuf};

#[derive(Args, Clone)]
pub struct InputArgs {
    /// Input file(s): NDJSON, JSON, CDX JSON, or one URL per line. `-` for stdin.
    #[arg(required = true)]
    pub input: Vec<PathBuf>,
    /// auto | ndjson | json | lines | access_log
    #[arg(long, default_value = "auto")]
    pub format: Format,
    /// Field mapping for JSON input, e.g. `ts=submitted_at,url=page.url`.
    #[arg(long)]
    pub map: Option<String>,
    /// Rules file (defaults to the bundled rules/default.toml).
    #[arg(long)]
    pub rules: Option<PathBuf>,
}

impl InputArgs {
    /// Record files read with automatic format detection and no mapping.
    pub fn files(input: Vec<PathBuf>) -> Self {
        Self {
            input,
            format: Format::Auto,
            map: None,
            rules: None,
        }
    }
}

pub fn parse_tier(s: &str) -> Result<Tier> {
    Ok(match s {
        "noise" => Tier::Noise,
        "suggestive" => Tier::Suggestive,
        "significant" => Tier::Significant,
        t => bail!("unknown tier `{t}` (noise|suggestive|significant)"),
    })
}

/// The rules file at `p`, or the bundled rules.
pub fn load_rules(p: Option<&Path>) -> Result<Rules> {
    match p {
        Some(p) => Rules::from_toml(
            &std::fs::read_to_string(p).with_context(|| format!("reading {}", p.display()))?,
        )
        .map_err(anyhow::Error::msg),
        None => Ok(Rules::default_rules()),
    }
}

pub fn read_inputs(args: &InputArgs) -> Result<Vec<Observation>> {
    let map = match &args.map {
        Some(m) => FieldMap::parse(m).map_err(anyhow::Error::msg)?,
        None => FieldMap::default(),
    };
    let mut all = Vec::new();
    for p in &args.input {
        let text = if p.as_os_str() == "-" {
            let mut s = String::new();
            std::io::stdin().read_to_string(&mut s)?;
            s
        } else {
            std::fs::read_to_string(p).with_context(|| format!("reading {}", p.display()))?
        };
        let parsed = parse_input(&text, args.format, &map);
        if parsed.redacted > 0 {
            eprintln!(
                "{}: redacted {} secret value(s)",
                p.display(),
                parsed.redacted
            );
        }
        for w in parsed.warnings.iter().take(5) {
            eprintln!("warning: {}: {w}", p.display());
        }
        if parsed.warnings.len() > 5 {
            eprintln!(
                "warning: {}: {} more",
                p.display(),
                parsed.warnings.len() - 5
            );
        }
        all.extend(parsed.observations);
    }
    Ok(all)
}

pub fn run_analysis(args: &InputArgs) -> Result<Analysis> {
    let rules = load_rules(args.rules.as_deref())?;
    Ok(analyze(read_inputs(args)?, &rules))
}
