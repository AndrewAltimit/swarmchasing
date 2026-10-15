//! `swarmchase eval`: the command around [`crate::eval`].

use crate::eval::{self, Floors};
use crate::input::{InputArgs, load_rules, read_records};
use anyhow::{Context, Result, bail};
use clap::{Args, Subcommand};
use sc_core::eval::coverage::AllowList;
use sc_core::eval::split::{SplitKind, parse_id_list, split};
use sc_core::{Format, Observation};
use std::path::{Path, PathBuf};

#[derive(Args)]
#[command(args_conflicts_with_subcommands = true)]
pub struct EvalArgs {
    #[command(subcommand)]
    cmd: Option<EvalCmd>,
    /// Labelled record files (NDJSON, JSON, CDX JSON or one URL per line).
    /// With `--before`, a watch store directory is read too.
    input: Vec<PathBuf>,
    /// auto | ndjson | json | lines | access_log
    #[arg(long, default_value = "auto")]
    format: Format,
    /// Field mapping for JSON input, e.g. `ts=submitted_at,url=page.url`.
    #[arg(long)]
    map: Option<String>,
    /// Rules file (defaults to the bundled rules/default.toml).
    #[arg(long)]
    rules: Option<PathBuf>,
    #[arg(long)]
    labels: Vec<PathBuf>,
    #[command(flatten)]
    floors: Floors,
    /// Also write the full result as JSON to this file (includes
    /// false-positive URLs, defanged; keep it private for third-party
    /// records). `--json <file>` is an older spelling.
    #[arg(long = "json-out", value_name = "FILE", alias = "json")]
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
    /// names; no record content). With `--before`, the control's summary.
    #[arg(long)]
    summary_json: Option<PathBuf>,
    /// Write a result file: numbers, input hashes, rules version and hash,
    /// toolkit version and commit. No record content.
    #[arg(long)]
    save_result: Option<PathBuf>,
    /// For --save-result: regression | held_out | prospective.
    #[arg(long, default_value = "regression")]
    result_kind: String,
    /// For --save-result: what was measured, in words (not file contents).
    #[arg(long, default_value = "")]
    describe: String,
    /// For --save-result: save a held-out or prospective result that has no
    /// benign record. Its precision cannot be wrong, so it says nothing.
    #[arg(long)]
    allow_no_benign: bool,
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
    /// Fail unless the labelled records scored hash to this (`sha256:` and
    /// hex, as `eval ids-hash` and `--split` print): a frozen split's
    /// membership, checked before anything is measured.
    #[arg(long)]
    expect_ids_sha256: Option<String>,
    /// Negative control: analyse only records timestamped before this date
    /// (YYYY-MM-DD), print label-free false-alarm rates per tier, agent
    /// grade and plant signal, and exit. Labels are not needed and no floor
    /// is checked.
    #[arg(long)]
    before: Option<chrono::NaiveDate>,
    /// Score an SC-Bench file (`eval export-bench` writes one) and exit:
    /// the reference tiers it carries, or `--predictions`.
    #[arg(long)]
    bench: Option<PathBuf>,
    /// With --bench: a detector's predictions, NDJSON with `id` and `tier`
    /// (noise | suggestive | significant) or `flagged`, and optionally
    /// `cluster`.
    #[arg(long, requires = "bench")]
    predictions: Option<PathBuf>,
}

#[derive(Subcommand)]
enum EvalCmd {
    /// Re-hash a saved result's inputs, measure again, and diff the numbers.
    /// Exits non-zero on any difference.
    Repro(ReproArgs),
    /// Check every saved result in a directory: its rules version is not
    /// newer than the bundled rules, a held-out or prospective result has a
    /// benign record (or says it was saved without one), and it was measured
    /// from committed code.
    CheckResults {
        #[arg(default_value = "samples/eval/results")]
        dir: PathBuf,
    },
    /// Write an SC-Bench file from labelled records: ids, labels, splits,
    /// provenance, defanged hosts and what these rules said. No URLs.
    ExportBench(BenchArgs),
    /// Print the membership hash of each file's ids: an id list (`--split`
    /// writes one) or NDJSON records. SHA-256 over the distinct ids,
    /// sorted, one per line, so it does not change with content or order.
    IdsHash {
        #[arg(required = true)]
        files: Vec<PathBuf>,
    },
    /// The negative control on real data: sample pre-2022 Wayback index rows
    /// for the watchlist's relay and carrier sources into
    /// `<data>/controls/pre-era/`, analyse them, and print aggregate
    /// false-alarm rates only.
    PreEra(eval::control::PreEraArgs),
}

#[derive(Args)]
pub struct ReproArgs {
    /// The saved result.
    pub result: PathBuf,
    /// Files to use for the result's inputs, matched by hash, when they are
    /// not at the recorded paths.
    #[arg(long = "input")]
    pub candidates: Vec<PathBuf>,
    /// Rules file, when the result was measured with one.
    #[arg(long)]
    pub rules: Option<PathBuf>,
}

#[derive(Args)]
pub struct BenchArgs {
    /// Labelled record files.
    #[arg(required = true)]
    pub input: Vec<PathBuf>,
    #[arg(long)]
    pub labels: Vec<PathBuf>,
    /// Rules file (defaults to the bundled rules/default.toml).
    #[arg(long)]
    pub rules: Option<PathBuf>,
    /// Where the bench file goes.
    #[arg(short, long)]
    pub out: PathBuf,
    #[arg(long, default_value = "sc-bench")]
    pub name: String,
    #[arg(long, default_value = "")]
    pub describe: String,
    /// The day the labels and splits are frozen (YYYY-MM-DD). Default today.
    #[arg(long)]
    pub freeze_date: Option<chrono::NaiveDate>,
    /// The split of records not held out: regression | held_out | prospective.
    #[arg(long, default_value = "regression")]
    pub split: String,
    /// Ids frozen as held out (an `eval --split` id list).
    #[arg(long)]
    pub held_out_ids: Option<PathBuf>,
    /// Labeller recorded for rows that name none.
    #[arg(long, default_value = "swarmchasing-maintainers")]
    pub labeller: String,
}

impl EvalArgs {
    fn input_args(&self) -> InputArgs {
        InputArgs {
            input: self.input.clone(),
            format: self.format,
            map: self.map.clone(),
            rules: self.rules.clone(),
        }
    }
}

/// Records from files and, with `stores`, watch store directories.
fn read_with_stores(args: &EvalArgs, stores: bool) -> Result<Vec<Observation>> {
    let (dirs, files): (Vec<PathBuf>, Vec<PathBuf>) =
        args.input.iter().cloned().partition(|p| p.is_dir());
    if !dirs.is_empty() && !stores {
        bail!(
            "{} is a directory; pass record files (a watch store is read only with --before)",
            dirs[0].display()
        );
    }
    let mut out = Vec::new();
    for d in &dirs {
        out.extend(crate::store::load_store(d, 0)?);
    }
    if !files.is_empty() {
        let mut ia = args.input_args();
        ia.input = files;
        out.extend(read_records(&ia)?);
    }
    Ok(out)
}

/// `--before`: false alarms on records from before `date`, which no agent
/// of the kind looked for can have sent.
fn control(args: &EvalArgs, date: chrono::NaiveDate) -> Result<()> {
    let cutoff = date
        .and_hms_opt(0, 0, 0)
        .map_or(0, |t| t.and_utc().timestamp());
    let mut records = read_with_stores(args, true)?;
    let all = records.len();
    records.retain(|o| o.ts > 0 && o.ts < cutoff);
    let a = sc_core::analyze(records, &load_rules(args.rules.as_deref())?);
    let c = sc_core::eval::control::negative_control(&a);
    eval::print_control(&c, all, &date.to_string(), &a.rules_version);
    let row = format!("before {date}");
    let t = sc_core::eval::grades::grade_table(&a, &Default::default(), Some(&row));
    eval::print_grades(&t, "control");
    if let Some(p) = &args.summary_json {
        crate::util::write_out(Some(p), &serde_json::to_string_pretty(&c)?)?;
    }
    Ok(())
}

fn read_ids(p: &Path) -> Result<Vec<String>> {
    Ok(parse_id_list(
        &std::fs::read_to_string(p).with_context(|| format!("reading {}", p.display()))?,
    ))
}

pub fn run(args: EvalArgs) -> Result<()> {
    match &args.cmd {
        Some(EvalCmd::Repro(r)) => return eval::repro::run(r),
        Some(EvalCmd::CheckResults { dir }) => return eval::repro::check_results(dir),
        Some(EvalCmd::ExportBench(b)) => return eval::bench::export(b),
        Some(EvalCmd::PreEra(p)) => return eval::control::run(p),
        Some(EvalCmd::IdsHash { files }) => {
            for f in files {
                let text = std::fs::read_to_string(f)
                    .with_context(|| format!("reading {}", f.display()))?;
                let ids = eval::ids_in(&text);
                let h = eval::ids_hash(ids.iter().map(String::as_str));
                println!("sha256:{}  {} ids  {}", h.sha256, h.count, f.display());
            }
            return Ok(());
        }
        None => {}
    }
    if let Some(d) = args.before {
        return control(&args, d);
    }
    if let Some(b) = &args.bench {
        return eval::bench::score_file(b, args.predictions.as_deref(), args.json.as_deref());
    }
    if args.input.is_empty() {
        bail!("no input files (see `swarmchase eval --help`)");
    }
    let mut l = eval::load_labels(&args.labels, &args.input)?;
    let only = args.only_ids.as_deref().map(read_ids).transpose()?;
    let exclude = args.exclude_ids.as_deref().map(read_ids).transpose()?;
    eval::restrict(&mut l, only.as_deref(), exclude.as_deref());
    let rules_text = crate::pinning::RulesText::load(args.rules.as_deref())?.text;
    // No ASN enrichment: eval results must not depend on a local table.
    let a = sc_core::analyze(
        read_with_stores(&args, false)?,
        &load_rules(args.rules.as_deref())?,
    );
    let scored = eval::scored_ids(&a, &l);
    if let Some(want) = &args.expect_ids_sha256 {
        let want = want.trim().trim_start_matches("sha256:");
        if !want.eq_ignore_ascii_case(&scored.sha256) {
            bail!(
                "the {} labelled records scored hash to sha256:{}, not sha256:{want}: the split changed",
                scored.count,
                scored.sha256
            );
        }
    }

    if let Some(kind) = args.split {
        let Some(out) = &args.split_out else {
            bail!("--split needs --split-out <file>");
        };
        let s = split(&a, &l, kind, args.seed, args.fraction);
        let frozen = eval::ids_hash(s.held_out.iter().map(String::as_str));
        eprintln!(
            "held-out ids sha256:{} ({} ids): record it to check the split with --expect-ids-sha256",
            frozen.sha256, frozen.count
        );
        let mut text = format!(
            "# held-out ids · split {} · seed {} · fraction {} · rules {}\n\
             # {} held out · {} tuning · {} excluded (groups straddling the cut){}\n\
             # ids sha256:{} (eval ids-hash; --expect-ids-sha256 checks the side measured)\n\
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
                .unwrap_or_default(),
            frozen.sha256
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
    // Admin review labels only: the evaluation set's labels are not judged
    // by the labelling rule, so for it nothing is printed.
    let label_files = if args.labels.is_empty() {
        &args.input
    } else {
        &args.labels
    };
    let lines = eval::admin_agent_lines(label_files)?;
    if !lines.is_empty() {
        let b = eval::below_rule(&a, &l, &lines);
        let without = if b.ids().next().is_some() {
            let l2 = eval::without_below_rule(&l, &b);
            Some(
                sc_core::summarize(&a, &l2, &rules_text, &allow_text)
                    .map_err(anyhow::Error::msg)?
                    .2,
            )
        } else {
            None
        };
        eval::print_below_rule(&b, &summary, without.as_ref());
    }
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
        if kind != "regression" && summary.benign == 0 && !args.allow_no_benign {
            bail!(
                "a {kind} result with no benign record has a precision that cannot be wrong; \
                 add benign records, or pass --allow-no-benign to save it as a recall-only result"
            );
        }
        let label_files = if args.labels.is_empty() {
            &args.input
        } else {
            &args.labels
        };
        let hash_all = |ps: &[PathBuf]| -> Result<Vec<eval::FileHash>> {
            ps.iter().map(|p| eval::hash_file(p)).collect()
        };
        let saved = eval::SavedResult {
            result_schema: eval::RESULT_SCHEMA,
            kind,
            description: &args.describe,
            rules_version: &summary.rules_version,
            rules_sha256: eval::rules_sha256(&rules_text),
            rules_file: args.rules.as_deref().map(eval::recorded_path),
            toolkit: eval::toolkit(),
            records: hash_all(&args.input)?,
            labels: hash_all(label_files)?,
            only_ids: args.only_ids.as_deref().map(eval::hash_file).transpose()?,
            exclude_ids: args
                .exclude_ids
                .as_deref()
                .map(eval::hash_file)
                .transpose()?,
            scored_ids: Some(scored.clone()),
            counts: eval::Counts::of(&summary),
            allow_no_benign: args.allow_no_benign && summary.benign == 0,
            summary: &summary,
        };
        crate::util::write_out(Some(p), &(serde_json::to_string_pretty(&saved)? + "\n"))?;
    }

    let mut failures = eval::check(&summary, &args.floors);
    if args.require_coverage {
        failures.extend(eval::check_coverage(&cov, &allow));
    }
    if !failures.is_empty() {
        for f in &failures {
            eprintln!("eval gate: {f}");
        }
        return Err(crate::Exit::floor(format!(
            "eval gate failed ({} check(s) not met)",
            failures.len()
        )));
    }
    Ok(())
}
