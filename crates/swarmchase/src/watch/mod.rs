//! `swarmchase watch`: incremental collection, rolling analysis, and a run digest.
//!
//! Data directory layout (outside git):
//!
//! ```text
//! <out>/state.json              per-source cursors and pending resume keys (.bak: the previous copy)
//! <out>/.lock                   held by the run, so one writer works here at a time
//! <out>/store/<source>.ndjson   every record collected within retention, redacted, deduplicated
//! <out>/summary.json            clusters and endpoints as of the last run (digest baseline)
//! <out>/ledger.json             each cluster's history across runs (ledger)
//! <out>/autonomy.ndjson         what autonomy levels did or would have done (autonomy)
//! <out>/platform/               platform pass state and carried events (platform)
//! <out>/runs/<stamp>/           new records per source, analysis, case notes, digest, run.json
//! <out>/LATEST                  stamp of the most recent run
//! ```
//!
//! The digest opens with the run's priority ([`priority`]), set from
//! deterministic facts only, and `run.json` ([`run_summary`]) says the same
//! in a stable JSON for scripts. With `--triage`, a model on the admin's own
//! machine or network, or with `--triage=claude` Claude through the admin's
//! Claude Code login (hosted-source leads only), suggests a label for each
//! new lead ([`triage`]); the suggestions are shown in the digest and saved
//! for review, never as labels.
//!
//! Each run follows its clusters across runs in the ledger ([`ledger`]),
//! ranks them into an attention queue (`runs/<stamp>/attention.json`,
//! [`attention`]), and logs what each autonomy level would have done about
//! the queue ([`autonomy`]); a level runs in shadow unless the watchlist's
//! `[autonomy]` turns it on.
//!
//! Every run also checks source health and rule drift against the trailing
//! history in `state.json` (see `health.rs`) and reports both in the digest,
//! with slices of each source whose rate rose ([`onset`]).
//! The digest also lists runs whose target sequence repeats an earlier run in
//! another cluster (possible reruns, never merged) and bursts of archive
//! captures of a host the store normally holds few captures of.
//!
//! New records are also searched for canary tokens from our own published
//! pages ([`crate::canary`]); a sighting gets its own digest section and a
//! medium priority reason, and never links records.
//!
//! New records are also matched against every case's indicators (see
//! [`crate::case::indicators`]), under the case's pinned rules, and the hits are kept
//! per case in `state.json`. The digest's "Case status" section proposes
//! status changes for the admin to apply ([`cases`]). The watch never changes
//! a case or notice.
//!
//! Each run reads the stored records of the analysis window plus the overlap,
//! and this run's new records whatever their capture time; the archive burst
//! baseline is taken over the same span, and the analysis covers the window
//! and every new record.
//!
//! A run saves `state.json` after each source, with the IDs it stored as
//! `undigested`; they are cleared once the digest and `run.json` are
//! written, so the next run reports what a run cut short had stored. Case
//! hits, rule history, onset history and alert streaks (sources' health
//! included: the saves after each source keep the health the run found)
//! are saved with that same write, and
//! the ledger and the autonomy log just before it, so a run cut short
//! before its digest leaves them as they were. The result is handed to the
//! workflow (`$GITHUB_OUTPUT`) right after the digest and `run.json`,
//! before any later step can fail. Steps after collection that fail become
//! digest alerts instead of ending the run; a step after the digest that
//! fails ends it with an error. A source whose query changed starts over
//! ([`pull::fingerprint`]).
//!
//! Collection has a deadline (`collect_deadline_mins`): sources whose turn
//! comes after it are deferred, reported as such, and go first next run;
//! analysis and the digest still run. A failure that repeats run after run
//! (a source, a host, a canary) alerts on its 1st, 2nd, 4th, 8th... run
//! ([`crate::health::alert_due`]). Changed runs whose digest was never
//! mailed are folded into the next digest ([`mailed`]).
//!
//! Retention (docs/policies.md): run directories and stored records older than
//! `retain_days` are deleted at the end of every run. Records needed for a case
//! are copied into the case first; the watch store is not an archive.
//!
//! Wayback's CDX index is sorted by URL, not time, so a pull cut short by `limit`
//! is continued from its resume key on the next run before the time cursor moves.
//! Archives index captures late, so each pull overlaps the previous one by
//! `overlap_days` and drops records it has already seen ([`pull`]).

pub(crate) mod attention;
pub(crate) mod autonomy;
pub(crate) mod cases;
pub(crate) mod check;
pub(crate) mod digest;
pub(crate) mod fleet_threads;
pub(crate) mod ledger;
pub(crate) mod mailed;
pub(crate) mod onset;
pub(crate) mod platform;
pub(crate) mod priority;
pub(crate) mod public_log;
mod pull;
pub(crate) mod run_summary;
pub(crate) mod timing;
pub(crate) mod triage;

use crate::health::{RuleHistory, RuleRun, SourceHealth, alert_due};
use crate::store::{
    append, load_store_counted, prune, read_json_kept, to_ndjson, write_json, write_json_kept,
};
use anyhow::{Context, Result, bail};
use cases::{CaseCheck, CaseWatch};
use digest::{Alert, AlertKind, DigestInput, Health, SourceReport, Summary, digest, summarise};
use pull::{SourceState, pull};
use sc_collect::{CdxQuery, Client, Kind};
use sc_core::bursts::archive_bursts;
use sc_core::{Observation, ReportOptions, Rules, analyze, render_markdown};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::time::Duration;

const DAY: i64 = 86_400;

#[derive(Deserialize)]
pub struct Watchlist {
    #[serde(default = "default_interval")]
    pub min_interval_secs: u64,
    /// How far each pull reaches back before the newest record already seen.
    #[serde(default = "default_overlap")]
    pub overlap_days: i64,
    /// Records newer than this are analysed together on every run.
    #[serde(default = "default_window")]
    pub analysis_window_days: i64,
    /// Delete run directories and stored records older than this. 0 keeps everything.
    #[serde(default = "default_retain")]
    pub retain_days: i64,
    /// Propose marking an active notice contained once no record has matched
    /// its case for this many days.
    #[serde(default = "default_contained_after")]
    pub contained_after_days: i64,
    /// Reuse a cached HTTP response for this long before revalidating it
    /// (`<data>/cache/http/`). 0 turns the cache off.
    #[serde(default = "default_cache_ttl")]
    pub http_cache_ttl_secs: u64,
    /// Runs that keep their full `analysis.json` and `case-notes.md`; older
    /// runs keep their digest, `run.json`, `summary.json` and attention
    /// queue. 0 keeps every run's analysis.
    #[serde(default = "default_keep_analysis")]
    pub keep_analysis_runs: usize,
    /// Minutes collection may take: a source whose turn comes later is
    /// deferred to the next run, where it goes first, and the analysis and
    /// digest still run. A source already pulling finishes. 0 turns the
    /// deadline off.
    #[serde(default = "default_collect_deadline")]
    pub collect_deadline_mins: u64,
    /// What each autonomy level does ([`autonomy`]); every level is in
    /// shadow by default.
    #[serde(default)]
    pub autonomy: autonomy::Config,
    /// Coordinated-account sources and options ([`platform`]).
    #[serde(default)]
    pub platform: platform::Config,
    #[serde(default, rename = "source")]
    pub sources: Vec<WatchSource>,
}

fn default_cache_ttl() -> u64 {
    3600
}

fn default_keep_analysis() -> usize {
    8
}

fn default_collect_deadline() -> u64 {
    90
}

fn default_interval() -> u64 {
    3
}
fn default_overlap() -> i64 {
    3
}
fn default_window() -> i64 {
    30
}
fn default_retain() -> i64 {
    180
}
fn default_contained_after() -> i64 {
    14
}

#[derive(Deserialize)]
pub struct WatchSource {
    pub name: String,
    /// A source kind (`sc_collect::Kind`): wayback, arquivo, urlquery,
    /// commoncrawl, urlscan, memento, gharchive, npm, pypi, ctlog, wellknown
    /// or mcp.
    pub kind: String,
    #[serde(flatten)]
    pub query: CdxQuery,
}

/// `state.json`.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct State {
    #[serde(default)]
    pub sources: BTreeMap<String, SourceState>,
    /// Rule hit rates on recent runs' new records, for drift checks.
    #[serde(default)]
    pub rules: RuleHistory,
    /// Per-run counts of each source's slices, for onsets ([`onset`]).
    #[serde(default, skip_serializing_if = "onset::OnsetHistory::is_empty")]
    pub onsets: onset::OnsetHistory,
    /// Per case: records that matched its indicators, and what was proposed.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub cases: BTreeMap<String, CaseWatch>,
    /// Per source, the IDs of records stored but not yet reported in a
    /// digest. Saved with each source's progress and cleared once the
    /// run's digest and `run.json` are written, so a run cut short after
    /// collecting reports its records as new in the next run's digest.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub undigested: BTreeMap<String, BTreeSet<String>>,
    /// State of sources no longer in the watchlist, set aside rather than
    /// dropped: a source added back under the same name continues from it.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub retired: BTreeMap<String, SourceState>,
    /// The newest run whose digest was mailed, as the last run found it:
    /// retention may delete that run's marker ([`mailed`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_mailed: Option<String>,
    /// Hosts unavailable on the last runs, with how many runs in a row.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub host_down: BTreeMap<String, u32>,
}

#[derive(clap::Args)]
#[command(args_conflicts_with_subcommands = true)]
pub struct WatchArgs {
    #[command(subcommand)]
    cmd: Option<WatchCmd>,
    /// Watchlist TOML (see watchlist.toml).
    #[arg(default_value = "watchlist.toml")]
    watchlist: PathBuf,
    /// Data directory: state, record store, and per-run output. `-o` and
    /// `--out` are aliases.
    #[arg(
        short = 'd',
        long = "data",
        value_name = "DIR",
        visible_alias = "out",
        short_alias = 'o',
        default_value = "data",
        env = "SWARMCHASE_DATA"
    )]
    out: PathBuf,
    /// Start a new data directory. Without it, a run refuses a directory
    /// that holds no watch data, so a wrong path or an unset
    /// SWARMCHASE_DATA never starts a fresh store beside the real one.
    #[arg(long)]
    init: bool,
    /// Check the watchlist and exit: unknown keys, bad values, duplicate
    /// names, and every source built as a run builds it. Reads no data
    /// directory and sends no request.
    #[arg(long, conflicts_with_all = ["init", "public_log", "triage", "only"])]
    check: bool,
    /// Pull only this source (by name), with its cursor and health as a
    /// full run keeps them; the other sources are left as they are. The
    /// analysis and digest cover the whole store as usual.
    #[arg(long, value_name = "NAME")]
    only: Option<String>,
    /// Also write a summary safe for a public CI log to this file: each
    /// source's name, kind, status, counts and duration, and the totals.
    /// Nothing about records or leads.
    #[arg(long, value_name = "PATH")]
    public_log: Option<PathBuf>,
    /// Rules file (defaults to the bundled rules/default.toml).
    #[arg(long)]
    rules: Option<PathBuf>,
    /// Committed notices, for the case status proposals in the digest.
    #[arg(long, default_value = "notices")]
    notices: PathBuf,
    /// Ask a model for a label suggestion on each new lead: `--triage` or
    /// `--triage=local` asks the model server at SWARMCHASE_LLM_URL;
    /// `--triage=claude` asks Claude through Claude Code, about leads from
    /// hosted sources only. Also set by SWARMCHASE_WATCH_TRIAGE (`local`,
    /// `1`, `true`, or `claude`). Suggestions only: shown in the digest and
    /// saved beside labels, never as them.
    #[arg(
        long,
        value_name = "BACKEND",
        num_args = 0..=1,
        require_equals = true,
        default_missing_value = "local"
    )]
    triage: Option<triage::Backend>,
    /// Most leads triage asks about per run.
    #[arg(long, default_value_t = 20, env = "SWARMCHASE_TRIAGE_MAX")]
    triage_max: usize,
    /// Most seconds triage spends per run.
    #[arg(long, default_value_t = 600, env = "SWARMCHASE_TRIAGE_SECS")]
    triage_secs: u64,
}

#[derive(clap::Subcommand)]
enum WatchCmd {
    /// Make sources start over: forget each one's cursor, seen IDs, resume
    /// key and stream checkpoint, keeping its health history. The next run
    /// pulls it as if new (from its `from`, if set). Takes the data lock.
    Reset {
        /// Source names, as in state.json (sources no longer in the
        /// watchlist included).
        #[arg(required = true)]
        names: Vec<String>,
        /// Data directory (`-o`/`--out` are aliases).
        #[arg(
            short = 'd',
            long = "data",
            value_name = "DIR",
            visible_alias = "out",
            short_alias = 'o',
            default_value = "data",
            env = "SWARMCHASE_DATA"
        )]
        out: PathBuf,
    },
    /// Delete cached HTTP responses (`<data>/cache/http/`) older than
    /// `--max-age-hours`, by default the watchlist's `http_cache_ttl_secs`
    /// and at least a day, as every run does. Takes the data lock.
    PruneCache {
        #[arg(default_value = "watchlist.toml")]
        watchlist: PathBuf,
        /// Data directory (`-o`/`--out` are aliases).
        #[arg(
            short = 'd',
            long = "data",
            value_name = "DIR",
            visible_alias = "out",
            short_alias = 'o',
            default_value = "data",
            env = "SWARMCHASE_DATA"
        )]
        out: PathBuf,
        /// Keep entries younger than this many hours; 0 deletes them all.
        #[arg(long)]
        max_age_hours: Option<u64>,
    },
}

pub fn run(args: WatchArgs) -> Result<()> {
    match args.cmd {
        Some(WatchCmd::Reset { names, out }) => return reset(&out, &names),
        Some(WatchCmd::PruneCache {
            watchlist,
            out,
            max_age_hours,
        }) => {
            let age = match max_age_hours {
                Some(h) => Duration::from_secs(h * 3600),
                None => cache_max_age(&read_watchlist(&watchlist)?),
            };
            return prune_cache_cmd(&out, age);
        }
        None => {}
    }
    if args.check {
        return check::run(&args.watchlist);
    }
    let rules = crate::input::load_rules(args.rules.as_deref())?;
    let triage = triage::backend(args.triage).map(|b| {
        (
            b,
            triage::Limits {
                max: args.triage_max,
                budget: Duration::from_secs(args.triage_secs),
            },
        )
    });
    watch(
        &Paths {
            watchlist: &args.watchlist,
            out: &args.out,
            notices: &args.notices,
            public_log: args.public_log.as_deref(),
        },
        &RunOpts {
            init: args.init,
            only: args.only.as_deref(),
        },
        &rules,
        triage,
    )
}

/// Where a run reads and writes.
struct Paths<'a> {
    watchlist: &'a Path,
    out: &'a Path,
    notices: &'a Path,
    public_log: Option<&'a Path>,
}

/// How a run goes.
struct RunOpts<'a> {
    init: bool,
    /// Pull only this source.
    only: Option<&'a str>,
}

fn read_watchlist(watchlist: &Path) -> Result<Watchlist> {
    toml::from_str(
        &std::fs::read_to_string(watchlist)
            .with_context(|| format!("reading {}", watchlist.display()))?,
    )
    .context("watchlist")
}

/// How long a cached HTTP response is kept: its TTL, and at least a day.
fn cache_max_age(wl: &Watchlist) -> Duration {
    Duration::from_secs(wl.http_cache_ttl_secs.max(DAY as u64))
}

/// `watch reset`: start the named sources over, under the data lock.
fn reset(out: &Path, names: &[String]) -> Result<()> {
    let _lock = crate::store::lock_data(out, "watch reset")?;
    let state_path = out.join("state.json");
    let Some(mut state) = read_json_kept::<State>(&state_path)? else {
        bail!(
            "no state.json in {}; nothing to reset",
            crate::store::describe_data(out)
        );
    };
    let known: Vec<String> = state
        .sources
        .keys()
        .chain(state.retired.keys())
        .cloned()
        .collect();
    for n in names {
        let st = match state.sources.get_mut(n) {
            Some(st) => st,
            None => state.retired.get_mut(n).with_context(|| {
                format!(
                    "no source `{n}` in {}; it knows {}",
                    state_path.display(),
                    known.join(", ")
                )
            })?,
        };
        st.reset_position();
    }
    write_json_kept(&state_path, &state)?;
    println!(
        "reset {}: the next run pulls {} from the start (or its `from`); health history kept",
        names.join(", "),
        if names.len() == 1 { "it" } else { "them" }
    );
    Ok(())
}

/// `watch prune-cache`.
fn prune_cache_cmd(out: &Path, age: Duration) -> Result<()> {
    let _lock = crate::store::lock_data(out, "watch prune-cache")?;
    let dir = out.join("cache").join("http");
    let st = sc_collect::prune_http_cache(&dir, age, chrono::Utc::now().timestamp())
        .with_context(|| format!("pruning {}", dir.display()))?;
    println!(
        "{}: deleted {} entr{} ({}), kept {} ({})",
        dir.display(),
        st.removed,
        if st.removed == 1 { "y" } else { "ies" },
        human_bytes(st.removed_bytes),
        st.entries,
        human_bytes(st.bytes)
    );
    Ok(())
}

fn human_bytes(b: u64) -> String {
    match b {
        b if b >= 1 << 20 => format!("{:.1} MB", b as f64 / f64::from(1u32 << 20)),
        b if b >= 1 << 10 => format!("{:.1} KB", b as f64 / 1024.0),
        b => format!("{b} B"),
    }
}

/// What the collection phase gathered.
#[derive(Default)]
struct Collected {
    reports: Vec<SourceReport>,
    /// This run's new records, and those carried over from a run that
    /// ended before its digest.
    fresh: Vec<Observation>,
    new_ids: BTreeSet<String>,
    ids_by_source: BTreeMap<String, BTreeSet<String>>,
    alerts: Vec<Alert>,
    notes: Vec<String>,
    /// Records reported as new here that an earlier run collected.
    carried: usize,
}

impl Collected {
    fn add(&mut self, source: &str, o: Observation) {
        self.ids_by_source
            .entry(source.to_string())
            .or_default()
            .insert(o.id.clone());
        if self.new_ids.insert(o.id.clone()) {
            self.fresh.push(o);
        }
    }
}

/// A step after collection that failed: the run goes on without it, and
/// the digest says so, rather than losing the records already collected.
fn soft<T>(alerts: &mut Vec<Alert>, step: &str, r: Result<T>) -> Option<T> {
    match r {
        Ok(v) => Some(v),
        Err(e) => {
            eprintln!("{step}: error: {e:#}");
            alerts.push(Alert::new(
                AlertKind::StepFailed,
                step,
                format!(
                    "The run's {step} step failed and was skipped ({}); the rest of the run went ahead.",
                    crate::util::one_line(&format!("{e:#}"), 200)
                ),
            ));
            None
        }
    }
}

/// A history file the run rebuilds as it goes (`summary.json`,
/// `ledger.json`), or its `.bak` copy. When neither reads, the damaged file
/// is moved aside to `<name>.damaged` and the history starts afresh, with
/// an alert, instead of stopping the run.
fn read_history<T: serde::de::DeserializeOwned>(p: &Path, alerts: &mut Vec<Alert>) -> Option<T> {
    match read_json_kept(p) {
        Ok(v) => v,
        Err(e) => {
            let name = p.file_name().unwrap_or_default().to_string_lossy();
            let aside = p.with_file_name(format!("{name}.damaged"));
            let moved = std::fs::rename(p, &aside).is_ok();
            alerts.push(Alert::new(
                AlertKind::StoreDamaged,
                &name,
                format!(
                    "`{name}` could not be read ({}), nor its previous copy; this run starts it afresh{}, so clusters may be reported as new again.",
                    crate::util::one_line(&format!("{e:#}"), 160),
                    if moved {
                        format!(" and kept the damaged file as `{name}.damaged`")
                    } else {
                        String::new()
                    }
                ),
            ));
            None
        }
    }
}

fn watch(
    paths: &Paths,
    opts: &RunOpts,
    rules: &Rules,
    triage_with: Option<(triage::Backend, triage::Limits)>,
) -> Result<()> {
    let (watchlist, out, notices) = (paths.watchlist, paths.out, paths.notices);
    let mut phases = timing::Phases::new();
    let began = std::time::Instant::now();
    let wl = read_watchlist(watchlist)?;
    if wl.sources.is_empty() {
        bail!("{}: no [[source]] entries", watchlist.display());
    }
    wl.autonomy.check()?;
    let sources: Vec<&WatchSource> = match opts.only {
        Some(name) => {
            let s = wl
                .sources
                .iter()
                .find(|s| s.name == name)
                .with_context(|| {
                    format!(
                        "--only {name}: no such source in {}; it has {}",
                        watchlist.display(),
                        wl.sources
                            .iter()
                            .map(|s| s.name.as_str())
                            .collect::<Vec<_>>()
                            .join(", ")
                    )
                })?;
            vec![s]
        }
        None => wl.sources.iter().collect(),
    };
    let mut client = Client::new(Duration::from_secs(wl.min_interval_secs))?;
    if wl.http_cache_ttl_secs > 0 {
        client = client.with_cache(
            &out.join("cache").join("http"),
            Duration::from_secs(wl.http_cache_ttl_secs),
        );
    }
    let asn = sc_collect::asn::load_from_data(out)
        .unwrap_or_else(|e| {
            eprintln!("warning: ASN table not loaded: {e:#}");
            None
        })
        .filter(|t| !t.is_empty());
    let now = chrono::Utc::now();
    let stamp = now.format("%Y%m%dT%H%M%SZ").to_string();
    let run_dir = out.join("runs").join(&stamp);
    if !crate::store::has_data(out) {
        if !opts.init {
            bail!(
                "no watch data in {}; pass --init to start a new data directory there, or point --data or SWARMCHASE_DATA at the existing one",
                crate::store::describe_data(out)
            );
        }
        eprintln!(
            "note: starting a new data directory at {}",
            crate::store::describe_data(out)
        );
    }
    // One writer at a time: a second watch, or a case rename, waits for this
    // one to finish.
    let _lock = crate::store::lock_data(out, "watch")?;
    std::fs::create_dir_all(&run_dir)?;
    std::fs::create_dir_all(out.join("store"))?;

    let state_path = out.join("state.json");
    let mut state: State = read_json_kept(&state_path)?.unwrap_or_default();
    if let Some(m) = mailed::newest_marked(out)
        && state.last_mailed.as_ref().is_none_or(|l| *l < m)
    {
        state.last_mailed = Some(m);
    }
    let mut c = Collected::default();
    carry_over(out, &state, &mut c);
    for w in crate::commands::netranges::refresh_daily(&client, out) {
        c.notes.push(format!("Network ranges not refreshed: {w}"));
    }
    collect(
        &Collect {
            client: &client,
            out,
            run_dir: &run_dir,
            state_path: &state_path,
            stamp: &stamp,
            overlap: wl.overlap_days * DAY,
            asn: asn.as_ref(),
            deadline: (wl.collect_deadline_mins > 0)
                .then(|| began + Duration::from_secs(wl.collect_deadline_mins * 60)),
        },
        &sources,
        &mut state,
        &mut c,
    )?;
    if opts.only.is_none() {
        retire_missing(&wl, &mut state, &mut c.notes);
    }

    let down = client.down_hosts();
    observe_down(&mut state.host_down, &down);
    for (host, why) in down {
        let n = state.host_down.get(&host).copied().unwrap_or(1);
        if alert_due(n) {
            c.alerts.push(Alert::new(
                AlertKind::HostDown,
                &host,
                if n == 1 {
                    format!(
                        "`{host}` was unavailable ({why}); later requests to it this run were not sent, and its sources continue from their checkpoints next run"
                    )
                } else {
                    format!(
                        "`{host}` has been unavailable {n} runs in a row ({why}); its sources continue from their checkpoints when it answers"
                    )
                },
            ));
        } else {
            c.notes.push(format!(
                "`{host}` is still unavailable ({why}), {n} runs in a row; it alerts again on run {} of the streak.",
                n.next_power_of_two()
            ));
        }
    }

    phases.end("collect");
    // From here on a step that fails becomes a digest alert: the records
    // are stored and marked undigested, and the digest is what reports them.
    let Collected {
        reports,
        fresh,
        new_ids,
        ids_by_source,
        mut alerts,
        mut notes,
        carried,
    } = c;
    let canaries = soft(
        &mut alerts,
        "canary",
        crate::canary::watch_sightings(out, &fresh, &run_dir),
    )
    .unwrap_or_default();

    // Coordinated accounts on public platforms: its own pull and store, so a
    // failure here never stops the record analysis.
    let platform_outcome = soft(
        &mut alerts,
        "platform",
        platform::run(&client, out, &run_dir, now.timestamp(), &wl.platform, rules),
    )
    .flatten();

    phases.end("platform");
    // Rolling analysis over everything recent, not just this run's records,
    // so clusters can span runs.
    let since = now.timestamp() - wl.analysis_window_days * DAY;
    // Unreadable lines are moved aside once, so they alert in this run only.
    let set_aside = soft(
        &mut alerts,
        "store",
        crate::store::set_aside_damaged(&out.join("store")),
    )
    .unwrap_or_default();
    for (file, (n, aside)) in &set_aside {
        eprintln!("warning: {file}: {n} unreadable line(s) moved to {aside}");
        alerts.push(Alert::new(
            AlertKind::StoreDamaged,
            file,
            format!(
                "`{file}` had {n} line(s) that cannot be read (a write cut short, or bytes that are not UTF-8); they were moved to `{aside}`, which retention deletes with old records. The records on the other lines were read."
            ),
        ));
    }
    let (mut stored, damaged) = soft(
        &mut alerts,
        "store",
        load_store_counted(&out.join("store"), since - wl.overlap_days * DAY),
    )
    .unwrap_or_default();
    for (file, n) in &damaged {
        eprintln!("warning: {file}: {n} unreadable line(s) skipped");
        alerts.push(Alert::new(
            AlertKind::StoreDamaged,
            file,
            format!(
                "`{file}` has {n} line(s) that cannot be read (a write cut short, or bytes that are not UTF-8); they were skipped. The records on the other lines were read."
            ),
        ));
    }
    let have: BTreeSet<String> = stored.iter().map(|o| o.id.clone()).collect();
    stored.extend(fresh.iter().filter(|o| !have.contains(&o.id)).cloned());
    let bursts = archive_bursts(&stored, &new_ids, rules, now.timestamp());
    let cases_root = out.join("cases");
    let cases = CaseCheck {
        root: &cases_root,
        notices,
        rules,
        stamp: &stamp,
        now: now.timestamp(),
        contained_after_days: wl.contained_after_days,
    }
    .monitor(&fresh, &mut state.cases);
    // The window, and every new record whatever its capture time: a record
    // indexed late is new to us, so it is analysed in the run that found it.
    let before_window = fresh.iter().filter(|o| o.ts > 0 && o.ts < since).count();
    if let Some(note) = before_window_note(&fresh, since, wl.analysis_window_days) {
        notes.push(note);
    }
    let recent: Vec<Observation> = stored
        .into_iter()
        .filter(|o| o.ts >= since || new_ids.contains(&o.id))
        .collect();
    let mut a = analyze(recent, rules);
    crate::commands::netranges::annotate_in(out, &mut a);
    let (mut drifts, restarted) = state.rules.observe(
        &a.rules_version,
        ids_by_source
            .iter()
            .map(|(s, ids)| (s.clone(), RuleRun::from_analysis(&a, ids)))
            .collect(),
    );
    let onsets = state.onsets.observe(
        &a.rules_version,
        ids_by_source
            .iter()
            .map(|(s, ids)| {
                let run = onset::SliceRun::from_analysis(&a, ids, &stamp, now.timestamp());
                (s.clone(), run)
            })
            .collect(),
    );
    onset::read_drifts(&onsets, &mut drifts);
    // Case hits and the rule history are saved with the undigested clear
    // below, not here: a run cut short before its digest must not mark a
    // case hit or a rule run as already reported.
    alerts.extend(
        drifts
            .iter()
            .map(|d| Alert::new(AlertKind::RuleDrift, &d.source, d.line())),
    );
    if restarted {
        notes.push(format!(
            "Rules changed to {}; the drift baseline restarts from this run.",
            a.rules_version
        ));
    }
    crate::util::print_summary(&a);
    soft(
        &mut alerts,
        "analysis",
        serde_json::to_string(&a)
            .map_err(anyhow::Error::from)
            .and_then(|j| Ok(std::fs::write(run_dir.join("analysis.json"), j)?)),
    );
    let md = render_markdown(
        &a,
        &ReportOptions {
            generated: Some(now.format("%Y-%m-%d").to_string()),
            ..Default::default()
        },
    );
    soft(
        &mut alerts,
        "case notes",
        std::fs::write(run_dir.join("case-notes.md"), md).map_err(anyhow::Error::from),
    );
    phases.end("analysis");

    let summary_path = out.join("summary.json");
    let prev: Summary = read_history(&summary_path, &mut alerts).unwrap_or_default();
    let generated = now.format("%Y-%m-%dT%H:%M:%SZ").to_string();
    let next = summarise(&a, &prev, generated.clone());
    let ledger_path = out.join(ledger::FILE);
    let mut ledger: ledger::Ledger =
        read_history(&ledger_path, &mut alerts).unwrap_or_else(ledger::Ledger::new);
    let observed = ledger.observe(&a, &stamp, now.timestamp(), &new_ids);
    let fleets = ledger.observe_fleets(&a, &observed, &stamp, now.timestamp());
    // New or escalated is decided against each cluster's own thread, so a
    // cluster whose key changed is not reported as new.
    let base = digest::baseline(&prev, &next, &ledger, &observed, &stamp);
    let mut leads = triage::leads(&a, &base, &next, &new_ids);
    let triaged = match triage_with {
        Some((backend, limits)) => triage::run(Some(backend), out, &a, &mut leads, &stamp, limits),
        None => triage::TriageReport::default(),
    };
    phases.end("triage");
    let covered = attention::case_threads(&cases_root, &ledger);
    let queue = attention::rank(&attention::Input {
        analysis: &a,
        ledger: &ledger,
        observed: &observed,
        stamp: &stamp,
        now: now.timestamp(),
        cases: &covered,
    });
    ledger.set_bands(&stamp, &queue.bands());
    let decisions = autonomy::decide(
        &queue,
        &ledger,
        &wl.autonomy,
        now.timestamp(),
        &autonomy::load(out),
    );
    // Written before the digest, so a failure is in it.
    soft(
        &mut alerts,
        "attention",
        write_json(&run_dir.join(attention::FILE), &queue),
    );
    // Cached responses are raw collector answers: kept no longer than the
    // TTL (and a day), on every run.
    let cache = soft(
        &mut alerts,
        "cache",
        sc_collect::prune_http_cache(
            &out.join("cache").join("http"),
            cache_max_age(&wl),
            now.timestamp(),
        )
        .map_err(anyhow::Error::from),
    );
    let health = Health {
        sources: reports,
        alerts,
        notes,
    };
    let unmailed = mailed::unmailed(out, &stamp, state.last_mailed.as_deref());
    let mut priority = priority::assess(&leads, &health.alerts, &cases.due);
    priority.add(autonomy::priority_reasons(&decisions));
    priority.add(onset::priority_reasons(&onsets));
    if let Some(top) = unmailed.iter().map(mailed::Unmailed::level).max() {
        priority.add(vec![priority::Reason {
            level: top,
            kind: "unmailed".into(),
            text: format!(
                "{} earlier digest(s) were never mailed; their leads are under Digests not mailed",
                unmailed.len()
            ),
        }]);
    }
    priority.add(
        canaries
            .iter()
            .map(|s| priority::Reason {
                level: priority::Level::Medium,
                kind: "canary".into(),
                text: format!("canary token seen: {}", s.line()),
            })
            .collect(),
    );
    let mut digest = digest(&DigestInput {
        stamp: &stamp,
        analysis: &a,
        prev: &base,
        next: &next,
        new_ids: &new_ids,
        health: &health,
        bursts: &bursts,
        cases: &cases,
        window_days: wl.analysis_window_days,
        leads: &leads,
        triage: &triaged,
        priority: &priority,
        attention: &queue,
        autonomy: &decisions,
    });
    digest
        .text
        .push_str(&fleet_threads::section(&a, &ledger, &fleets));
    digest.text.push_str(&onset::section(&onsets));
    digest.changed |= onsets.due();
    digest
        .text
        .push_str(&crate::canary::digest_section(&canaries));
    digest.changed |= !canaries.is_empty();
    // Before the health block, so leads that were never mailed come early.
    let not_mailed = mailed::section(&unmailed);
    match digest.text.find("## Health (") {
        Some(i) => digest.text.insert_str(i, &not_mailed),
        None => digest.text.push_str(&not_mailed),
    }
    digest.changed |= !unmailed.is_empty();

    if let Some(o) = &platform_outcome {
        digest.text.push_str(&platform::section(o));
        digest.changed |= o.changed();
    }
    digest
        .text
        .push_str(&phases.digest_section(&health.sources));
    if let Some(st) = cache {
        digest.text.push_str(&format!(
            "\nHTTP cache: {} response(s) served from it this run; {} entr{} kept ({}), {} older than {} hours deleted.\n",
            client.cache_hits(),
            st.entries,
            if st.entries == 1 { "y" } else { "ies" },
            human_bytes(st.bytes),
            st.removed,
            cache_max_age(&wl).as_secs() / 3600
        ));
    }
    std::fs::write(run_dir.join("digest.md"), &digest.text)?;
    phases.end("report");
    write_json(
        &run_dir.join(run_summary::FILE),
        &run_summary::build(&run_summary::Input {
            stamp: &stamp,
            generated: &generated,
            analysis: &a,
            new_records: new_ids.len(),
            carried_over: carried,
            new_before_window: before_window,
            changed: digest.changed,
            priority: &priority,
            leads: &leads,
            triage: &triaged,
            health: &health,
            cases: &cases,
            attention: &queue,
            autonomy: (&wl.autonomy, &decisions),
            durations: &phases.summary(),
        }),
    )?;
    // Hand the result to the workflow (digest email) at once: whatever
    // fails after this, the digest that reports the run is still mailed.
    if let Ok(p) = std::env::var("GITHUB_OUTPUT") {
        github_output(
            Path::new(&p),
            &run_dir,
            digest.changed,
            priority.level.label(),
        )?;
    }
    // What fails from here on loses nothing the digest has not reported;
    // the run still ends with an error so it is noticed.
    let mut late = Vec::new();
    let mut later = |step: &str, r: Result<()>| {
        if let Err(e) = r {
            eprintln!("{step}: error: {e:#}");
            late.push(format!("{step}: {e:#}"));
        }
    };
    if let Some(p) = paths.public_log {
        let log = public_log::PublicLog::new(&health.sources, phases.total_ms());
        later(
            "public log",
            std::fs::write(p, log.render()).with_context(|| format!("writing {}", p.display())),
        );
    }
    // Saved only once the digest and run.json report this run: a run that
    // stops before them leaves the ledger and the autonomy log as they
    // were, so the next run reports its carried-over records as leads.
    later("ledger", write_json_kept(&ledger_path, &ledger));
    later("autonomy", autonomy::append(out, &decisions));
    // The digest and run.json report this run's records: they are no
    // longer undigested. Case hits, rule history and streaks go with them.
    // Should the write fail, the next run reports the records again.
    state.undigested.clear();
    later("state", write_json_kept(&state_path, &state));
    later(
        "summary",
        write_json(&run_dir.join("summary.json"), &next)
            .and_then(|()| write_json_kept(&summary_path, &next)),
    );
    later(
        "LATEST",
        crate::store::write_atomic(&out.join("LATEST"), stamp.as_bytes()),
    );
    later(
        "retention",
        retain(
            out,
            &wl,
            now.timestamp(),
            &mut state,
            &state_path,
            &mut ledger,
            &ledger_path,
        ),
    );
    eprintln!(
        "wrote {} ({}, priority {})",
        run_dir.display(),
        if digest.changed {
            "changes"
        } else {
            "no changes"
        },
        priority.level.label()
    );
    if !late.is_empty() {
        bail!(
            "the digest was written, but {} step(s) after it failed: {}",
            late.len(),
            late.join("; ")
        );
    }
    let ran: Vec<_> = health
        .sources
        .iter()
        .filter(|r| r.skipped.is_none() && !r.deferred)
        .collect();
    if ran.is_empty() {
        bail!(
            "no source could run; see {}",
            run_dir.join("digest.md").display()
        );
    }
    if ran.iter().all(|r| r.error.is_some()) {
        bail!(
            "every source failed; see {}",
            run_dir.join("digest.md").display()
        );
    }
    Ok(())
}

/// `run_dir`, `changed` and `priority` for the workflow's mail step.
fn github_output(p: &Path, run_dir: &Path, changed: bool, priority: &str) -> Result<()> {
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(p)
        .with_context(|| format!("opening {}", p.display()))?;
    writeln!(f, "run_dir={}", run_dir.display())?;
    writeln!(f, "changed={changed}")?;
    writeln!(f, "priority={priority}")?;
    Ok(())
}

/// Count each host down this run towards its streak; a host that answered
/// leaves the map.
fn observe_down(streaks: &mut BTreeMap<String, u32>, down: &[(String, String)]) {
    streaks.retain(|h, _| down.iter().any(|(d, _)| d == h));
    for (h, _) in down {
        *streaks.entry(h.clone()).or_default() += 1;
    }
}

/// The digest note for new records captured before the analysis window:
/// they are analysed in the run that found them, but later runs analyse
/// the window only.
fn before_window_note(fresh: &[Observation], since: i64, window_days: i64) -> Option<String> {
    let old: Vec<i64> = fresh
        .iter()
        .map(|o| o.ts)
        .filter(|&t| t > 0 && t < since)
        .collect();
    let oldest = old.iter().copied().min()?;
    Some(format!(
        "{} new record(s) were captured before the {window_days}-day analysis window (the oldest on {}); this run analyses them with the window, later runs leave them out. `case add --record` still finds them in the store until retention deletes them.",
        old.len(),
        sc_core::fmt_ts(oldest)
    ))
}

/// Records an earlier run stored but never reported (it ended before its
/// digest), loaded from the store into this run's new records.
fn carry_over(out: &Path, state: &State, c: &mut Collected) {
    let source_of: BTreeMap<&str, &str> = state
        .undigested
        .iter()
        .flat_map(|(s, ids)| ids.iter().map(move |id| (id.as_str(), s.as_str())))
        .collect();
    if source_of.is_empty() {
        return;
    }
    let all = match load_store_counted(&out.join("store"), i64::MIN) {
        Ok((all, _)) => all,
        Err(e) => {
            soft::<()>(&mut c.alerts, "carry-over", Err(e));
            return;
        }
    };
    for o in all {
        if let Some(src) = source_of.get(o.id.as_str()) {
            c.carried += 1;
            c.add(src, o);
        }
    }
    c.notes.push(format!(
        "{} record(s) stored by an earlier run that ended before its digest are reported as new in this one.",
        c.carried
    ));
}

/// Set aside the state of sources no longer in the watchlist, and restore
/// it for a source added back under the same name.
fn retire_missing(wl: &Watchlist, state: &mut State, notes: &mut Vec<String>) {
    let names: BTreeSet<&str> = wl.sources.iter().map(|s| s.name.as_str()).collect();
    let gone: Vec<String> = state
        .sources
        .keys()
        .filter(|n| !names.contains(n.as_str()))
        .cloned()
        .collect();
    for n in gone {
        if let Some(st) = state.sources.remove(&n) {
            notes.push(format!(
                "`{n}` is no longer in the watchlist; its state is set aside under `retired` in state.json, and a source added back under that name continues from it."
            ));
            state.retired.insert(n, st);
        }
    }
}

/// What every source's pull needs.
struct Collect<'a> {
    client: &'a Client,
    out: &'a Path,
    run_dir: &'a Path,
    state_path: &'a Path,
    stamp: &'a str,
    overlap: i64,
    asn: Option<&'a sc_core::asn::AsnTable>,
    /// When collection stops starting sources.
    deadline: Option<std::time::Instant>,
}

/// Save collection progress (cursors, seen and undigested IDs) with each
/// source's health as the run found it. Health streaks reach the admin only
/// through the digest, so they are saved with the run's final write: a run
/// cut short before its digest leaves them as they were, and the next run
/// alerts on the streak runs its digest would have.
fn save_progress(
    path: &Path,
    state: &mut State,
    start: &mut BTreeMap<String, SourceHealth>,
) -> Result<()> {
    let swap = |state: &mut State, start: &mut BTreeMap<String, SourceHealth>| {
        for (name, st) in &mut state.sources {
            std::mem::swap(&mut st.health, start.entry(name.clone()).or_default());
        }
    };
    swap(state, start);
    let r = write_json_kept(path, state);
    swap(state, start);
    r
}

/// Pull each source in turn, storing what is new and saving `state.json`
/// after each, so an interrupted run keeps its progress; the IDs stored
/// are kept as undigested until a digest reports them. Sources deferred by
/// the last run go first; once the deadline has passed, the rest are
/// deferred.
fn collect(
    x: &Collect,
    sources: &[&WatchSource],
    state: &mut State,
    c: &mut Collected,
) -> Result<()> {
    // Health as the run found it, for the saves after each source.
    let mut start: BTreeMap<String, SourceHealth> = state
        .retired
        .iter()
        .chain(&state.sources)
        .map(|(n, st)| (n.clone(), st.health.clone()))
        .collect();
    let mut order: Vec<&WatchSource> = sources.to_vec();
    order.sort_by_key(|s| !state.sources.get(&s.name).is_some_and(|st| st.deferred));
    let mut deferred = Vec::new();
    for s in order {
        eprint!("{:<24} {:<8} {} … ", s.name, s.kind, s.query.pattern);
        if let Some(st) = state.retired.remove(&s.name) {
            state.sources.entry(s.name.clone()).or_insert(st);
        }
        if x.deadline.is_some_and(|d| std::time::Instant::now() >= d) {
            eprintln!("deferred: collection deadline reached");
            state.sources.entry(s.name.clone()).or_default().deferred = true;
            deferred.push(format!("`{}`", s.name));
            c.reports.push(SourceReport {
                deferred: true,
                ..SourceReport::new(&s.name, &s.kind)
            });
            continue;
        }
        if let Ok(kind) = s.kind.parse::<Kind>()
            && kind.needs_key()
            && kind.key_from_env().is_none()
        {
            let why = format!("{} not set", kind.key_env().unwrap_or("API key"));
            eprintln!("skipped: {why}");
            let st = state.sources.entry(s.name.clone()).or_default();
            c.alerts.extend(
                st.health
                    .observe_skip(&s.name, &why)
                    .map(|t| Alert::new(AlertKind::SourceSkipped, &s.name, t)),
            );
            c.reports.push(SourceReport {
                skipped: Some(format!("skipped: {why}")),
                ..SourceReport::new(&s.name, &s.kind)
            });
            continue;
        }
        let st = state.sources.entry(s.name.clone()).or_default();
        let restarted = st.align(&pull::fingerprint(s));
        if restarted {
            c.notes.push(format!(
                "`{}`'s query changed since its last run (pattern, match type, filter, kind or endpoint); its cursor, resume key and checkpoint were reset, so it reads from the start again.",
                s.name
            ));
        }
        let before = x.client.requests();
        let began = std::time::Instant::now();
        let first_or_resumed = st.cursor == 0 || st.pending.is_some();
        let res = pull(x.client, s, st, x.overlap, x.asn);
        st.last_run = Some(x.stamp.to_string());
        st.deferred = false;
        let mut rep = SourceReport {
            requests: x.client.requests() - before,
            duration_ms: u64::try_from(began.elapsed().as_millis()).unwrap_or(u64::MAX),
            ..SourceReport::new(&s.name, &s.kind)
        };
        let short = res.as_ref().err().map(digest::short_reason);
        if res.is_ok() && (first_or_resumed || st.pending.is_some()) {
            st.health.observe_catch_up();
        } else {
            let outcome = match (&res, &short) {
                (Ok(p), _) => Ok(p.pulled),
                (Err(_), Some(why)) => Err(why.as_str()),
                (Err(_), None) => Err("unknown error"),
            };
            let kind = if outcome.is_ok() {
                AlertKind::SourceCollapsed
            } else {
                AlertKind::SourceFailed
            };
            c.alerts.extend(
                st.health
                    .observe(&s.name, outcome)
                    .map(|t| Alert::new(kind, &s.name, t)),
            );
        }
        match res {
            Ok(p) => {
                let pulled = p.pulled;
                let mut new = p.new;
                let store_file = x.out.join("store").join(format!("{}.ndjson", s.name));
                if restarted || st.restart {
                    // Seen IDs were reset with the position: what the store
                    // already holds is not new.
                    let held: BTreeSet<String> =
                        crate::store::read_ndjson::<Observation>(&store_file)
                            .map(|(v, _)| v.into_iter().map(|o| o.id).collect())
                            .unwrap_or_default();
                    new.retain(|o| !held.contains(&o.id));
                    st.restart = false;
                }
                rep.pulled = pulled;
                rep.new = new.len();
                rep.pending = st.pending.is_some();
                rep.stopped = p.stopped;
                if let Some(cov) = &p.coverage
                    && let Some(n) = st.health.observe_canary(cov.canary)
                {
                    let streak = if n == 1 {
                        String::new()
                    } else {
                        format!(" ({n} runs in a row)")
                    };
                    let line = format!(
                        "`{}` read {} but its canary failed{streak}: nothing came back in the shape the parser expects, so an empty pull here proves nothing. Check the source's format.",
                        s.name,
                        cov.line()
                    );
                    if alert_due(n) {
                        c.alerts
                            .push(Alert::new(AlertKind::CanaryFailed, &s.name, line));
                    } else {
                        c.notes.push(line);
                    }
                }
                rep.coverage = p.coverage;
                rep.quiet = st
                    .health
                    .observe_yield(pulled)
                    .map(|n| (n, st.health.ever_pulled));
                st.last_error = None;
                eprintln!(
                    "{pulled} pulled, {} new{}",
                    new.len(),
                    if rep.pending { " (more next run)" } else { "" }
                );
                if !new.is_empty() {
                    let nd = to_ndjson(&new)?;
                    std::fs::write(x.run_dir.join(format!("{}.ndjson", s.name)), &nd)?;
                    append(&store_file, &nd)?;
                    state
                        .undigested
                        .entry(s.name.clone())
                        .or_default()
                        .extend(new.iter().map(|o| o.id.clone()));
                    for o in new {
                        c.add(&s.name, o);
                    }
                }
            }
            Err(e) => {
                eprintln!("error: {e:#}");
                st.last_error = Some(format!("{e:#}"));
                rep.error = short;
            }
        }
        // Save after every source so an interrupted run keeps its progress.
        save_progress(x.state_path, state, &mut start)?;
        c.reports.push(rep);
    }
    if !deferred.is_empty() {
        c.notes.push(format!(
            "Collection reached its deadline; deferred to the next run, where they go first: {}.",
            deferred.join(", ")
        ));
    }
    Ok(())
}

/// Retention at the end of a run: trim old runs' full analyses, then
/// delete run directories, stored records, case hits, ledger points and
/// autonomy lines older than `retain_days`.
fn retain(
    out: &Path,
    wl: &Watchlist,
    now: i64,
    state: &mut State,
    state_path: &Path,
    ledger: &mut ledger::Ledger,
    ledger_path: &Path,
) -> Result<()> {
    let trimmed = crate::store::trim_analyses(out, wl.keep_analysis_runs)?;
    if trimmed > 0 {
        eprintln!(
            "retention: dropped the full analysis of {trimmed} run(s) beyond the newest {}",
            wl.keep_analysis_runs
        );
    }
    if wl.retain_days > 0 {
        let cutoff = now - wl.retain_days.max(wl.analysis_window_days) * DAY;
        let (runs, records) = prune(out, cutoff)?;
        for cw in state.cases.values_mut() {
            cw.hits.retain(|h| h.ts <= 0 || h.ts >= cutoff);
        }
        state.onsets.prune(cutoff);
        write_json_kept(state_path, state)?;
        if ledger.prune(cutoff) > 0 {
            write_json_kept(ledger_path, ledger)?;
        }
        // Target hosts last seen before the cutoff leave the summary, so a
        // host outlives its records by no more than one run.
        let summary_path = out.join("summary.json");
        if let Some(mut s) = read_json_kept::<Summary>(&summary_path)? {
            let before = s.endpoints.len();
            s.endpoints
                .retain(|_, e| e.last_seen <= 0 || e.last_seen >= cutoff);
            if s.endpoints.len() < before {
                write_json_kept(&summary_path, &s)?;
            }
        }
        autonomy::prune(out, cutoff)?;
        if runs + records > 0 {
            eprintln!(
                "retention: deleted {runs} run dir(s) and {records} stored record(s) older than {} days",
                wl.retain_days
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let d =
            std::env::temp_dir().join(format!("swarmchase-watchmod-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join("store")).unwrap();
        d
    }

    fn list(extra: &str) -> Watchlist {
        toml::from_str(&format!(
            "{extra}\n[[source]]\nname = \"a\"\nkind = \"memento\"\npattern = \"https://a.example/\"\nendpoint = \"http://127.0.0.1:9/\"\n\n[[source]]\nname = \"b\"\nkind = \"memento\"\npattern = \"https://b.example/\"\nendpoint = \"http://127.0.0.1:9/\"\n"
        ))
        .unwrap()
    }

    #[test]
    fn past_the_deadline_sources_are_deferred_and_go_first_next_run() {
        let d = scratch("deadline");
        let wl = list("");
        assert_eq!(wl.collect_deadline_mins, 90);
        let client = Client::new(Duration::ZERO).unwrap();
        let sources: Vec<&WatchSource> = wl.sources.iter().collect();
        let mut state = State::default();
        // `b` was deferred last run.
        state.sources.entry("b".into()).or_default().deferred = true;
        let mut c = Collected::default();
        let x = Collect {
            client: &client,
            out: &d,
            run_dir: &d,
            state_path: &d.join("state.json"),
            stamp: "20261014T000000Z",
            overlap: 0,
            asn: None,
            deadline: Some(std::time::Instant::now()),
        };
        collect(&x, &sources, &mut state, &mut c).unwrap();
        let names: Vec<&str> = c.reports.iter().map(|r| r.name.as_str()).collect();
        assert_eq!(names, ["b", "a"], "deferred sources go first");
        assert!(
            c.reports
                .iter()
                .all(|r| r.deferred && r.status() == "deferred")
        );
        assert!(state.sources["a"].deferred && state.sources["b"].deferred);
        assert_eq!(client.requests(), 0, "nothing was sent");
        assert!(
            c.notes
                .iter()
                .any(|n| n.contains("deferred to the next run") && n.contains("`a`")),
            "{:?}",
            c.notes
        );
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn progress_saves_keep_the_health_the_run_found() {
        let d = scratch("progress");
        let path = d.join("state.json");
        let mut state = State::default();
        state
            .sources
            .entry("a".into())
            .or_default()
            .health
            .errors_in_row = 1;
        state
            .retired
            .entry("r".into())
            .or_default()
            .health
            .skipped_runs = 3;
        let mut start: BTreeMap<String, SourceHealth> = state
            .retired
            .iter()
            .chain(&state.sources)
            .map(|(n, st)| (n.clone(), st.health.clone()))
            .collect();
        // This run: `a` fails again, `r` comes back and runs, `n` is new.
        let a = state.sources.get_mut("a").unwrap();
        a.health.errors_in_row = 2;
        a.cursor = 42;
        let r = state.retired.remove("r").unwrap();
        state.sources.insert("r".into(), r);
        state.sources.get_mut("r").unwrap().health.skipped_runs = 0;
        state
            .sources
            .entry("n".into())
            .or_default()
            .health
            .errors_in_row = 1;
        save_progress(&path, &mut state, &mut start).unwrap();
        let saved: State = read_json_kept(&path).unwrap().unwrap();
        assert_eq!(saved.sources["a"].cursor, 42, "progress is saved");
        assert_eq!(saved.sources["a"].health.errors_in_row, 1);
        assert_eq!(saved.sources["r"].health.skipped_runs, 3);
        assert_eq!(saved.sources["n"].health.errors_in_row, 0);
        // The run itself goes on with the new health.
        assert_eq!(state.sources["a"].health.errors_in_row, 2);
        assert_eq!(state.sources["r"].health.skipped_runs, 0);
        assert_eq!(state.sources["n"].health.errors_in_row, 1);
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn a_host_down_streak_counts_and_ends_when_it_answers() {
        let mut s = BTreeMap::new();
        let down = |h: &str| vec![(h.to_string(), "HTTP 503".to_string())];
        observe_down(&mut s, &down("x"));
        observe_down(&mut s, &down("x"));
        observe_down(&mut s, &down("x"));
        assert_eq!(s["x"], 3);
        assert!(!alert_due(s["x"]));
        observe_down(&mut s, &down("y"));
        assert_eq!(s, BTreeMap::from([("y".to_string(), 1)]));
    }

    #[test]
    fn retention_drops_endpoints_last_seen_before_the_cutoff() {
        let d = scratch("endpoints");
        let wl = list("retain_days = 180\nanalysis_window_days = 30");
        let now = 1_800_000_000;
        let ep = |last_seen| digest::Endpoint {
            first_seen: last_seen,
            last_seen,
            max_tier: sc_core::Tier::Significant,
        };
        let summary = Summary {
            endpoints: BTreeMap::from([
                ("old.example".to_string(), ep(now - 200 * DAY)),
                ("new.example".to_string(), ep(now - DAY)),
                ("undated.example".to_string(), ep(0)),
            ]),
            ..Default::default()
        };
        write_json_kept(&d.join("summary.json"), &summary).unwrap();
        let mut state = State::default();
        let mut ledger = ledger::Ledger::new();
        retain(
            &d,
            &wl,
            now,
            &mut state,
            &d.join("state.json"),
            &mut ledger,
            &d.join(ledger::FILE),
        )
        .unwrap();
        let kept: Summary = read_json_kept(&d.join("summary.json")).unwrap().unwrap();
        let hosts: Vec<&str> = kept.endpoints.keys().map(String::as_str).collect();
        assert_eq!(hosts, ["new.example", "undated.example"]);
        std::fs::remove_dir_all(&d).unwrap();
    }
}
