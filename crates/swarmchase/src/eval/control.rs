//! `swarmchase eval pre-era`: the negative control on real archive data.
//!
//! No agent of the kind looked for sent a request before late 2022, so the
//! relay and carrier captures the Wayback Machine holds from before then are
//! a control set that needs no labels: everything the analysis flags there
//! is a false alarm. The command samples them through the watchlist's own
//! Wayback sources (index rows only, never a capture, at the watchlist's
//! request interval), keeps them under `<data>/controls/pre-era/`, and
//! prints only aggregate numbers.
//!
//! The range from `--from-year` to `--before` is read one calendar year per
//! request, up to `--per-source / years` captures a year, so the sample
//! spreads over the years instead of piling into the first. The index is
//! sorted by URL within a year, so a year's share is the first captures by
//! URL in it, not a random draw. A window collected once is kept and reused
//! (its file name carries the per-year bound), so a second run with the same
//! arguments measures the same records without fetching.

use crate::input::{InputArgs, load_rules, read_records};
use crate::watch::Watchlist;
use anyhow::{Context, Result, bail};
use chrono::{Datelike, NaiveDate};
use sc_collect::{CdxQuery, Client, cdx_ts};
use serde::Serialize;
use std::path::{Path, PathBuf};
use std::time::Duration;

#[derive(clap::Args)]
pub struct PreEraArgs {
    /// Watchlist whose `wayback` sources (the relays and carriers) are sampled.
    #[arg(long, default_value = "watchlist.toml")]
    watchlist: PathBuf,
    /// Data directory; captures go to `<data>/controls/pre-era/`.
    #[arg(short, long, default_value = "data", env = "SWARMCHASE_DATA")]
    data: PathBuf,
    /// Captures before this day only (YYYY-MM-DD).
    #[arg(long, default_value = "2022-11-30")]
    before: NaiveDate,
    /// First calendar year sampled.
    #[arg(long, default_value_t = 2012)]
    from_year: i32,
    /// Most captures per source, split evenly over the years.
    #[arg(long, default_value_t = 600)]
    per_source: usize,
    /// Only this watchlist source (repeatable). Default: every `wayback` one.
    #[arg(long = "source")]
    sources: Vec<String>,
    /// Measure what is already collected; fetch nothing.
    #[arg(long)]
    offline: bool,
    /// Capture years measured: `all`, or `even` or `odd` to tune on one
    /// half of the years and hold the other out. Collection still spreads
    /// `--per-source` over every year, so the halves share their files.
    #[arg(long, value_enum, default_value_t = Years::All)]
    years: Years,
    /// Rules file (defaults to the bundled rules).
    #[arg(long)]
    rules: Option<PathBuf>,
    /// Where the summary JSON goes. Default: `<data>/controls/pre-era/summary.json`.
    #[arg(long)]
    summary_json: Option<PathBuf>,
}

/// Which capture years a run measures.
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Years {
    All,
    Even,
    Odd,
}

impl Years {
    fn keeps(self, year: i32) -> bool {
        match self {
            Self::All => true,
            Self::Even => year % 2 == 0,
            Self::Odd => year % 2 != 0,
        }
    }
}

/// One calendar-year window of one source.
struct Window {
    year: i32,
    from: i64,
    /// Inclusive.
    to: i64,
}

/// Calendar years from `from_year` up to the day before `before`.
fn windows(from_year: i32, before: NaiveDate) -> Vec<Window> {
    let cutoff = before
        .and_hms_opt(0, 0, 0)
        .map_or(0, |t| t.and_utc().timestamp());
    let start = |y: i32| {
        NaiveDate::from_ymd_opt(y, 1, 1)
            .and_then(|d| d.and_hms_opt(0, 0, 0))
            .map_or(0, |t| t.and_utc().timestamp())
    };
    (from_year..=before.year())
        .map(|y| Window {
            year: y,
            from: start(y),
            to: (start(y + 1) - 1).min(cutoff - 1),
        })
        .filter(|w| w.from <= w.to)
        .collect()
}

/// The file a window's captures are kept in. The per-year bound is in the
/// name, so a run with another bound collects afresh instead of mixing.
fn window_path(dir: &Path, source: &str, year: i32, per_year: usize) -> PathBuf {
    dir.join(source).join(format!("{year}-n{per_year}.ndjson"))
}

#[derive(Default, Serialize)]
struct SourceTally {
    name: String,
    windows: usize,
    fetched: usize,
    reused: usize,
    failed: usize,
    records: usize,
}

#[derive(Serialize)]
struct Output<'a> {
    before: String,
    from_year: i32,
    per_source: usize,
    per_year: usize,
    years: Years,
    rules_version: &'a str,
    sources: &'a [SourceTally],
    control: &'a sc_core::eval::control::ControlSummary,
}

pub fn run(args: &PreEraArgs) -> Result<()> {
    let wl: Watchlist = toml::from_str(
        &std::fs::read_to_string(&args.watchlist)
            .with_context(|| format!("reading {}", args.watchlist.display()))?,
    )
    .context("watchlist")?;
    let sources: Vec<_> = wl
        .sources
        .iter()
        .filter(|s| s.kind == "wayback")
        .filter(|s| args.sources.is_empty() || args.sources.contains(&s.name))
        .collect();
    if let Some(missing) = args
        .sources
        .iter()
        .find(|n| !sources.iter().any(|s| &&s.name == n))
    {
        bail!(
            "--source {missing}: no wayback source of that name in {}",
            args.watchlist.display()
        );
    }
    if sources.is_empty() {
        bail!("{}: no wayback sources", args.watchlist.display());
    }
    let wins = windows(args.from_year, args.before);
    if wins.is_empty() {
        bail!("--from-year {} is after --before", args.from_year);
    }
    // The bound is set over every year, so a half reads the same files.
    let per_year = args.per_source.div_ceil(wins.len()).max(1);
    let wins: Vec<Window> = wins
        .into_iter()
        .filter(|w| args.years.keeps(w.year))
        .collect();
    let dir = args.data.join("controls").join("pre-era");
    let client = Client::new(Duration::from_secs(wl.min_interval_secs.max(1)))?;
    eprintln!(
        "pre-era control: {} sources · {} years from {} ({}) · up to {per_year} captures a year · {}",
        sources.len(),
        wins.len(),
        args.from_year,
        match args.years {
            Years::All => "all years",
            Years::Even => "even years",
            Years::Odd => "odd years",
        },
        if args.offline {
            "offline"
        } else {
            "fetching windows not yet collected"
        }
    );

    let mut tallies = Vec::new();
    let mut records = Vec::new();
    for s in &sources {
        let mut files = Vec::new();
        let mut t = SourceTally {
            name: s.name.clone(),
            windows: wins.len(),
            ..Default::default()
        };
        for w in &wins {
            let path = window_path(&dir, &s.name, w.year, per_year);
            if path.is_file() {
                t.reused += 1;
                files.push(path);
                continue;
            }
            if args.offline {
                continue;
            }
            let q = CdxQuery {
                pattern: s.query.pattern.clone(),
                match_type: s.query.match_type.clone(),
                filter: s.query.filter.clone(),
                from: Some(cdx_ts(w.from)),
                to: Some(cdx_ts(w.to)),
                limit: per_year,
                page_size: per_year,
                ..Default::default()
            };
            match client.wayback_cdx(&q) {
                Ok(obs) => {
                    if let Some(d) = path.parent() {
                        std::fs::create_dir_all(d)?;
                    }
                    crate::store::write_atomic(&path, crate::store::to_ndjson(&obs)?.as_bytes())?;
                    eprintln!("  {:<20} {}: {} captures", s.name, w.year, obs.len());
                    t.fetched += 1;
                    files.push(path);
                }
                Err(e) => {
                    // The error names the index query, never a record.
                    eprintln!("  {:<20} {}: failed ({e:#})", s.name, w.year);
                    t.failed += 1;
                }
            }
        }
        if !files.is_empty() {
            let obs = read_records(&InputArgs::files(files))?;
            t.records = obs.len();
            records.extend(obs);
        }
        tallies.push(t);
    }

    let all = records.len();
    let cutoff = args
        .before
        .and_hms_opt(0, 0, 0)
        .map_or(0, |t| t.and_utc().timestamp());
    records.retain(|o| o.ts > 0 && o.ts < cutoff);
    let a = sc_core::analyze(records, &load_rules(args.rules.as_deref())?);
    println!(
        "{:<22} {:>7} {:>7} {:>6} {:>6} {:>8}",
        "source", "windows", "fetched", "reused", "failed", "records"
    );
    for t in &tallies {
        println!(
            "{:<22} {:>7} {:>7} {:>6} {:>6} {:>8}",
            t.name, t.windows, t.fetched, t.reused, t.failed, t.records
        );
    }
    println!();
    let c = sc_core::eval::control::negative_control(&a);
    super::print_control(&c, all, &args.before.to_string(), &a.rules_version);
    let row = format!("before {}", args.before);
    let g = sc_core::eval::grades::grade_table(&a, &Default::default(), Some(&row));
    super::print_grades(&g, "control");
    let out = Output {
        before: args.before.to_string(),
        from_year: args.from_year,
        per_source: args.per_source,
        per_year,
        years: args.years,
        rules_version: &a.rules_version,
        sources: &tallies,
        control: &c,
    };
    let p = args
        .summary_json
        .clone()
        .unwrap_or_else(|| dir.join("summary.json"));
    if let Some(d) = p.parent() {
        std::fs::create_dir_all(d)?;
    }
    crate::util::write_out(Some(&p), &(serde_json::to_string_pretty(&out)? + "\n"))?;
    eprintln!("summary (numbers only): {}", p.display());
    if tallies.iter().any(|t| t.failed > 0) {
        eprintln!("some windows failed; run again to fetch them (collected windows are reused)");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_are_calendar_years_cut_at_the_date() {
        let before = NaiveDate::from_ymd_opt(2022, 11, 30).unwrap();
        let w = windows(2020, before);
        assert_eq!(
            w.iter().map(|w| w.year).collect::<Vec<_>>(),
            [2020, 2021, 2022]
        );
        assert_eq!(cdx_ts(w[0].from), "20200101000000");
        assert_eq!(cdx_ts(w[0].to), "20201231235959");
        assert_eq!(cdx_ts(w[2].to), "20221129235959");
        // A date on New Year's Day leaves its own year out.
        let jan1 = NaiveDate::from_ymd_opt(2022, 1, 1).unwrap();
        assert_eq!(windows(2021, jan1).len(), 1);
        assert!(windows(2023, before).is_empty());
    }

    #[test]
    fn year_halves_split_the_years() {
        assert!(Years::Even.keeps(2014) && !Years::Even.keeps(2015));
        assert!(Years::Odd.keeps(2015) && !Years::Odd.keeps(2014));
        assert!(Years::All.keeps(2014) && Years::All.keeps(2015));
    }

    #[test]
    fn the_committed_watchlist_has_wayback_sources() {
        let wl: Watchlist = toml::from_str(include_str!("../../../../watchlist.toml")).unwrap();
        assert!(wl.sources.iter().any(|s| s.kind == "wayback"));
    }
}
