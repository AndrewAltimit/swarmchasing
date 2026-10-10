//! `swarmchase watch`: incremental collection, rolling analysis, and a run digest.
//!
//! Data directory layout (outside git):
//!
//! ```text
//! <out>/state.json              per-source cursors and pending resume keys
//! <out>/store/<source>.ndjson   every record collected within retention, redacted, deduplicated
//! <out>/summary.json            clusters and endpoints as of the last run (digest baseline)
//! <out>/runs/<stamp>/           new records per source, analysis, case notes, digest
//! <out>/LATEST                  stamp of the most recent run
//! ```
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

mod cases;
mod digest;
mod pull;

use crate::health::{RuleHistory, RuleRun};
use crate::store::{append, load_store, prune, read_json, to_ndjson, write_json};
use anyhow::{Context, Result, bail};
use cases::{CaseCheck, CaseWatch};
use digest::{DigestInput, Health, SourceReport, Summary, digest, summarise};
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
    /// commoncrawl, urlscan, memento, gharchive, npm, pypi or ctlog.
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
}

pub fn run(args: WatchArgs) -> Result<()> {
    let rules = crate::input::load_rules(args.rules.as_deref())?;
    watch(&args.watchlist, &args.out, &args.notices, &rules)
}

fn watch(watchlist: &Path, out: &Path, notices: &Path, rules: &Rules) -> Result<()> {
    let wl: Watchlist = toml::from_str(
        &std::fs::read_to_string(watchlist)
            .with_context(|| format!("reading {}", watchlist.display()))?,
    )
    .context("watchlist")?;
    if wl.sources.is_empty() {
        bail!("{}: no [[source]] entries", watchlist.display());
    }
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
            let why = format!("skipped: {} not set", kind.key_env().unwrap_or("API key"));
            eprintln!("{why}");
            reports.push(SourceReport {
                skipped: Some(why),
                ..SourceReport::new(&s.name)
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
            ..SourceReport::new(&s.name)
        };
        if res.is_ok() && (first_or_resumed || st.pending.is_some()) {
            st.health.observe_catch_up();
        } else {
            alerts.extend(
                st.health
                    .observe(&s.name, res.as_ref().ok().map(|(pulled, _)| *pulled)),
            );
        }
        match res {
            Ok((pulled, new)) => {
                rep.pulled = pulled;
                rep.new = new.len();
                rep.pending = st.pending.is_some();
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
                rep.error = Some(format!("{e:#}"));
            }
        }
        // Save after every source so an interrupted run keeps its progress.
        write_json(&state_path, &state)?;
        reports.push(rep);
    }

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
    alerts.extend(drifts.iter().map(|d| d.line()));
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
    let next = summarise(&a, &prev, now.format("%Y-%m-%dT%H:%M:%SZ").to_string());
    let digest = digest(&DigestInput {
        stamp: &stamp,
        analysis: &a,
        prev: &prev,
        next: &next,
        new_ids: &new_ids,
        health: &health,
        bursts: &bursts,
        cases: &cases,
        window_days: wl.analysis_window_days,
    });
    std::fs::write(run_dir.join("digest.md"), &digest.text)?;
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
        if runs + records > 0 {
            eprintln!(
                "retention: deleted {runs} run dir(s) and {records} stored record(s) older than {} days",
                wl.retain_days
            );
        }
    }
    eprintln!(
        "wrote {} ({})",
        run_dir.display(),
        if digest.changed {
            "changes"
        } else {
            "no changes"
        }
    );

    // Hand the result to the workflow (digest email, artifact upload).
    if let Ok(p) = std::env::var("GITHUB_OUTPUT") {
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(p)?;
        writeln!(f, "run_dir={}", run_dir.display())?;
        writeln!(f, "changed={}", digest.changed)?;
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
