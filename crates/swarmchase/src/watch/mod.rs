//! `swarmchase watch`: incremental collection, rolling analysis, and a run digest.
//!
//! Data directory layout (outside git):
//!
//! ```text
//! <out>/state.json              per-source cursors and pending resume keys
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
//! history in `state.json` (see `health.rs`) and reports both in the digest.
//! The digest also lists runs whose target sequence repeats an earlier run in
//! another cluster (possible reruns, never merged) and bursts of archive
//! captures of a host the store normally holds few captures of.
//!
//! New records are also matched against every case's indicators (see
//! [`crate::case::indicators`]), under the case's pinned rules, and the hits are kept
//! per case in `state.json`. The digest's "Case status" section proposes
//! status changes for the admin to apply ([`cases`]). The watch never changes
//! a case or notice.
//!
//! Each run reads the stored records of the analysis window plus the overlap,
//! and this run's new records whatever their capture time; the archive burst
//! baseline is taken over the same span.
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
pub(crate) mod digest;
pub(crate) mod ledger;
pub(crate) mod platform;
pub(crate) mod priority;
mod pull;
pub(crate) mod run_summary;
pub(crate) mod triage;

use crate::health::{RuleHistory, RuleRun};
use crate::store::{append, load_store, prune, read_json, to_ndjson, write_json};
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
    /// Per case: records that matched its indicators, and what was proposed.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub cases: BTreeMap<String, CaseWatch>,
}

#[derive(clap::Args)]
pub struct WatchArgs {
    /// Watchlist TOML (see watchlist.toml).
    #[arg(default_value = "watchlist.toml")]
    watchlist: PathBuf,
    /// Data directory: state, record store, and per-run output.
    #[arg(short, long, default_value = "data", env = "SWARMCHASE_DATA")]
    out: PathBuf,
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

pub fn run(args: WatchArgs) -> Result<()> {
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
    watch(&args.watchlist, &args.out, &args.notices, &rules, triage)
}

fn watch(
    watchlist: &Path,
    out: &Path,
    notices: &Path,
    rules: &Rules,
    triage_with: Option<(triage::Backend, triage::Limits)>,
) -> Result<()> {
    let wl: Watchlist = toml::from_str(
        &std::fs::read_to_string(watchlist)
            .with_context(|| format!("reading {}", watchlist.display()))?,
    )
    .context("watchlist")?;
    if wl.sources.is_empty() {
        bail!("{}: no [[source]] entries", watchlist.display());
    }
    wl.autonomy.check()?;
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
        eprintln!(
            "note: starting a new data directory at {}",
            crate::store::describe_data(out)
        );
    }
    std::fs::create_dir_all(&run_dir)?;
    std::fs::create_dir_all(out.join("store"))?;

    let state_path = out.join("state.json");
    let mut state: State = read_json(&state_path)?.unwrap_or_default();
    let mut reports = Vec::new();
    let mut fresh: Vec<Observation> = Vec::new();
    let mut new_ids = BTreeSet::new();
    let mut ids_by_source: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut alerts = Vec::new();

    for s in &wl.sources {
        eprint!("{:<24} {:<8} {} … ", s.name, s.kind, s.query.pattern);
        if let Ok(kind) = s.kind.parse::<Kind>()
            && kind.needs_key()
            && kind.key_from_env().is_none()
        {
            let why = format!("{} not set", kind.key_env().unwrap_or("API key"));
            eprintln!("skipped: {why}");
            let st = state.sources.entry(s.name.clone()).or_default();
            alerts.extend(
                st.health
                    .observe_skip(&s.name, &why)
                    .map(|t| Alert::new(AlertKind::SourceSkipped, &s.name, t)),
            );
            reports.push(SourceReport {
                skipped: Some(format!("skipped: {why}")),
                ..SourceReport::new(&s.name, &s.kind)
            });
            continue;
        }
        let st = state.sources.entry(s.name.clone()).or_default();
        let before = client.requests();
        let first_or_resumed = st.cursor == 0 || st.pending.is_some();
        let res = pull(&client, s, st, wl.overlap_days * DAY, asn.as_ref());
        st.last_run = Some(stamp.clone());
        let mut rep = SourceReport {
            requests: client.requests() - before,
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
            alerts.extend(
                st.health
                    .observe(&s.name, outcome)
                    .map(|t| Alert::new(kind, &s.name, t)),
            );
        }
        match res {
            Ok(p) => {
                let pulled = p.pulled;
                let new = p.new;
                rep.pulled = pulled;
                rep.new = new.len();
                rep.pending = st.pending.is_some();
                rep.stopped = p.stopped;
                if let Some(c) = &p.coverage
                    && c.canary == Some(false)
                {
                    alerts.push(Alert::new(
                        AlertKind::CanaryFailed,
                        &s.name,
                        format!(
                            "`{}` read {} but its canary failed: nothing came back in the shape the parser expects, so an empty pull here proves nothing. Check the source's format.",
                            s.name,
                            c.line()
                        ),
                    ));
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
                    std::fs::write(run_dir.join(format!("{}.ndjson", s.name)), &nd)?;
                    append(&out.join("store").join(format!("{}.ndjson", s.name)), &nd)?;
                    let ids = ids_by_source.entry(s.name.clone()).or_default();
                    for o in new {
                        ids.insert(o.id.clone());
                        if new_ids.insert(o.id.clone()) {
                            fresh.push(o);
                        }
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
        write_json(&state_path, &state)?;
        reports.push(rep);
    }

    for (host, why) in client.down_hosts() {
        alerts.push(Alert::new(
            AlertKind::HostDown,
            &host,
            format!(
                "`{host}` was unavailable ({why}); later requests to it this run were not sent, and its sources continue from their checkpoints next run"
            ),
        ));
    }

    // Coordinated accounts on public platforms: its own pull and store, so a
    // failure here never stops the record analysis.
    let platform_outcome =
        match platform::run(&client, out, &run_dir, now.timestamp(), &wl.platform, rules) {
            Ok(o) => o,
            Err(e) => {
                eprintln!("platform pass: error: {e:#}");
                None
            }
        };

    // Rolling analysis over everything recent, not just this run's records,
    // so clusters can span runs.
    let since = now.timestamp() - wl.analysis_window_days * DAY;
    let mut stored = load_store(&out.join("store"), since - wl.overlap_days * DAY)?;
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
    let recent: Vec<Observation> = stored.into_iter().filter(|o| o.ts >= since).collect();
    let a = analyze(recent, rules);
    let (drifts, restarted) = state.rules.observe(
        &a.rules_version,
        ids_by_source
            .iter()
            .map(|(s, ids)| (s.clone(), RuleRun::from_analysis(&a, ids)))
            .collect(),
    );
    write_json(&state_path, &state)?;
    alerts.extend(
        drifts
            .iter()
            .map(|d| Alert::new(AlertKind::RuleDrift, &d.source, d.line())),
    );
    let mut notes = Vec::new();
    if restarted {
        notes.push(format!(
            "Rules changed to {}; the drift baseline restarts from this run.",
            a.rules_version
        ));
    }
    let health = Health {
        sources: reports,
        alerts,
        notes,
    };
    crate::util::print_summary(&a);
    std::fs::write(run_dir.join("analysis.json"), serde_json::to_string(&a)?)?;
    let md = render_markdown(
        &a,
        &ReportOptions {
            generated: Some(now.format("%Y-%m-%d").to_string()),
            ..Default::default()
        },
    );
    std::fs::write(run_dir.join("case-notes.md"), md)?;

    let summary_path = out.join("summary.json");
    let prev: Summary = read_json(&summary_path)?.unwrap_or_default();
    let generated = now.format("%Y-%m-%dT%H:%M:%SZ").to_string();
    let next = summarise(&a, &prev, generated.clone());
    let mut leads = triage::leads(&a, &prev, &next, &new_ids);
    let triaged = match triage_with {
        Some((backend, limits)) => triage::run(Some(backend), out, &a, &mut leads, &stamp, limits),
        None => triage::TriageReport::default(),
    };
    let ledger_path = out.join(ledger::FILE);
    let mut ledger: ledger::Ledger = read_json(&ledger_path)?.unwrap_or_else(ledger::Ledger::new);
    let observed = ledger.observe(&a, &stamp, now.timestamp(), &new_ids);
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
    let mut priority = priority::assess(&leads, &health.alerts, &cases.due);
    priority.add(autonomy::priority_reasons(&decisions));
    let mut digest = digest(&DigestInput {
        stamp: &stamp,
        analysis: &a,
        prev: &prev,
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
    if let Some(o) = &platform_outcome {
        digest.text.push_str(&platform::section(o));
        digest.changed |= o.changed();
    }
    std::fs::write(run_dir.join("digest.md"), &digest.text)?;
    write_json(&run_dir.join(attention::FILE), &queue)?;
    write_json(&ledger_path, &ledger)?;
    autonomy::append(out, &decisions)?;
    write_json(
        &run_dir.join(run_summary::FILE),
        &run_summary::build(&run_summary::Input {
            stamp: &stamp,
            generated: &generated,
            analysis: &a,
            new_records: new_ids.len(),
            changed: digest.changed,
            priority: &priority,
            leads: &leads,
            triage: &triaged,
            health: &health,
            cases: &cases,
            attention: &queue,
            autonomy: (&wl.autonomy, &decisions),
        }),
    )?;
    write_json(&run_dir.join("summary.json"), &next)?;
    write_json(&summary_path, &next)?;
    std::fs::write(out.join("LATEST"), &stamp)?;
    if wl.retain_days > 0 {
        let cutoff = now.timestamp() - wl.retain_days.max(wl.analysis_window_days) * DAY;
        let (runs, records) = prune(out, cutoff)?;
        for cw in state.cases.values_mut() {
            cw.hits.retain(|h| h.ts <= 0 || h.ts >= cutoff);
        }
        write_json(&state_path, &state)?;
        if ledger.prune(cutoff) > 0 {
            write_json(&ledger_path, &ledger)?;
        }
        autonomy::prune(out, cutoff)?;
        if runs + records > 0 {
            eprintln!(
                "retention: deleted {runs} run dir(s) and {records} stored record(s) older than {} days",
                wl.retain_days
            );
        }
    }
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

    // Hand the result to the workflow (digest email, artifact upload).
    if let Ok(p) = std::env::var("GITHUB_OUTPUT") {
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(p)?;
        writeln!(f, "run_dir={}", run_dir.display())?;
        writeln!(f, "changed={}", digest.changed)?;
        writeln!(f, "priority={}", priority.level.label())?;
    }
    let ran: Vec<_> = health
        .sources
        .iter()
        .filter(|r| r.skipped.is_none())
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
