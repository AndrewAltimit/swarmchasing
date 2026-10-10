//! `swarmchase eval`: the command around [`crate::eval`].

use crate::eval::{self, Floors};
use crate::input::{InputArgs, load_rules, read_records};
use anyhow::{Context, Result, bail};
use clap::Args;
use sc_core::eval::coverage::AllowList;
use sc_core::eval::split::{SplitKind, parse_id_list, split};
use std::path::{Path, PathBuf};

#[derive(Args)]
pub struct EvalArgs {
    #[command(flatten)]
    input: InputArgs,
    #[arg(long)]
    labels: Vec<PathBuf>,
    #[command(flatten)]
    floors: Floors,
    /// Also write the full result as JSON (includes false-positive URLs,
    /// defanged; keep it private for third-party records).
    #[arg(long)]
    json: Option<PathBuf>,
    /// How many false positives to list.
    #[arg(long, default_value_t = 20)]
    show_fp: usize,
    /// Print per-rule coverage: positives, benign hits, hard negatives.
    #[arg(long)]
    coverage: bool,
    /// Coverage allow-list: rule ids that may go without a positive, one per
    /// line with the reason.
    #[arg(long)]
    coverage_allow: Option<PathBuf>,
    /// Fail when a rule has no positive and is not on the allow-list (or the
    /// allow-list lists a covered or unknown rule).
    #[arg(long)]
    require_coverage: bool,
    /// Write the summary JSON the site renders (numbers, rule ids and class
    /// names; no record content).
    #[arg(long)]
    summary_json: Option<PathBuf>,
    /// Write a result file: numbers, input hashes, rules version and
    /// toolkit commit. No record content.
    #[arg(long)]
    save_result: Option<PathBuf>,
    /// For --save-result: regression | held_out | prospective.
    #[arg(long, default_value = "regression")]
    result_kind: String,
    /// For --save-result: what was measured, in words (not file contents).
    #[arg(long, default_value = "")]
    describe: String,
    /// Write a frozen held-out split (time | cluster) to --split-out and exit.
    #[arg(long)]
    split: Option<SplitKind>,
    #[arg(long, default_value_t = 0)]
    seed: u64,
    /// Share of labelled records to hold out.
    #[arg(long, default_value_t = 0.2)]
    fraction: f64,
    /// Where the held-out id list goes. Keep it in the data directory.
    #[arg(long)]
    split_out: Option<PathBuf>,
    /// Score only the labelled records whose id is listed (a held-out split).
    #[arg(long)]
    only_ids: Option<PathBuf>,
    /// Do not score the listed ids (score the tuning side of a split).
    #[arg(long)]
    exclude_ids: Option<PathBuf>,
}

fn read_ids(p: &Path) -> Result<Vec<String>> {
    Ok(parse_id_list(
        &std::fs::read_to_string(p).with_context(|| format!("reading {}", p.display()))?,
    ))
}

pub fn run(args: EvalArgs) -> Result<()> {
    let mut l = eval::load_labels(&args.labels, &args.input.input)?;
    let only = args.only_ids.as_deref().map(read_ids).transpose()?;
    let exclude = args.exclude_ids.as_deref().map(read_ids).transpose()?;
    eval::restrict(&mut l, only.as_deref(), exclude.as_deref());
    let rules_text = crate::pinning::RulesText::load(args.input.rules.as_deref())?.text;
    // No ASN enrichment: eval results must not depend on a local table.
    let a = sc_core::analyze(
        read_records(&args.input)?,
        &load_rules(args.input.rules.as_deref())?,
    );

    if let Some(kind) = args.split {
        let Some(out) = &args.split_out else {
            bail!("--split needs --split-out <file>");
        };
        let s = split(&a, &l, kind, args.seed, args.fraction);
        let mut text = format!(
            "# held-out ids · split {} · seed {} · fraction {} · rules {}\n\
             # {} held out · {} tuning · {} excluded (groups straddling the cut){}\n\
             # Frozen: measure with --only-ids, tune with --exclude-ids; never edit.\n",
            match kind {
                SplitKind::Time => "time",
                SplitKind::Cluster => "cluster",
            },
            s.seed,
            s.fraction,
            a.rules_version,
            s.held_out.len(),
            s.tuning.len(),
            s.excluded.len(),
            s.cutoff_ts
                .map(|t| format!(" · cutoff {}", sc_core::fmt_ts(t)))
                .unwrap_or_default()
        );
        for id in s.held_out.iter() {
            text.push_str(id);
            text.push('\n');
        }
        if !s.excluded.is_empty() {
            text.push_str("# excluded from both sides:\n");
            for id in &s.excluded {
                text.push_str(&format!("# {id}\n"));
            }
        }
        return crate::util::write_out(Some(out), &text);
    }

    let allow_text = match &args.coverage_allow {
        Some(p) => {
            std::fs::read_to_string(p).with_context(|| format!("reading {}", p.display()))?
        }
        None => String::new(),
    };
    let allow = AllowList::parse(&allow_text);
    let (r, cov, summary) =
        sc_core::summarize(&a, &l, &rules_text, &allow_text).map_err(anyhow::Error::msg)?;
    eval::print(&r, &summary, &l, args.show_fp);
    if args.coverage {
        eval::print_coverage(&cov);
    }
    if let Some(p) = &args.json {
        crate::util::write_out(Some(p), &serde_json::to_string_pretty(&r)?)?;
    }
    if let Some(p) = &args.summary_json {
        crate::util::write_out(Some(p), &serde_json::to_string_pretty(&summary)?)?;
    }
    if let Some(p) = &args.save_result {
        let kind = match args.result_kind.as_str() {
            k @ ("regression" | "held_out" | "prospective") => k,
            k => bail!("unknown --result-kind `{k}` (regression | held_out | prospective)"),
        };
        let label_files = if args.labels.is_empty() {
            &args.input.input
        } else {
            &args.labels
        };
        let saved = eval::SavedResult {
            kind,
            description: &args.describe,
            rules_version: &summary.rules_version,
            toolkit: eval::toolkit(),
            records: args
                .input
                .input
                .iter()
                .map(|p| eval::hash_file(p))
                .collect::<Result<_>>()?,
            labels: label_files
                .iter()
                .map(|p| eval::hash_file(p))
                .collect::<Result<_>>()?,
            only_ids: args.only_ids.as_deref().map(eval::hash_file).transpose()?,
            exclude_ids: args
                .exclude_ids
                .as_deref()
                .map(eval::hash_file)
                .transpose()?,
            summary: &summary,
        };
        crate::util::write_out(Some(p), &(serde_json::to_string_pretty(&saved)? + "\n"))?;
    }

    let mut failures = eval::check(&r, &args.floors);
    if args.require_coverage {
        failures.extend(eval::check_coverage(&cov, &allow));
    }
    if !failures.is_empty() {
        for f in &failures {
            eprintln!("eval gate: {f}");
        }
        bail!("eval gate failed ({} check(s) not met)", failures.len());
    }
    Ok(())
}
