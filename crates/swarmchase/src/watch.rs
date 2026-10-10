//! `swarmchase watch`: incremental collection, rolling analysis, and a run digest.
//!
//! Data directory layout (outside git):
//!
//! ```text
//! <out>/state.json              per-source cursors and pending resume keys
//! <out>/store/<source>.ndjson   every record ever collected, redacted, deduplicated
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
//! [`case::indicators`]), under the case's pinned rules, and the hits are kept
//! per case in `state.json`. The digest's "Case status" section proposes
//! status changes for the admin to apply: an active notice with no matching
//! record for `contained_after_days` could be marked contained, and a
//! contained or historical notice or a closed case with new matching records
//! could be reopened. It also says when the current rules would change tiers
//! in a case pinned to other rules. The watch never changes a case or notice.
//!
//! Retention (docs/policies.md): run directories and stored records older than
//! `retain_days` are deleted at the end of every run. Records needed for a case
//! are copied into the case first; the watch store is not an archive.
//!
//! Wayback's CDX index is sorted by URL, not time, so a pull cut short by `limit`
//! is continued from its resume key on the next run before the time cursor moves.
//! Archives index captures late, so each pull overlaps the previous one by
//! `overlap_days` and drops records it has already seen.

use crate::case::{self, CaseStatus, NoticeStatus};
use crate::health::{RuleHistory, RuleRun, SourceHealth};
use anyhow::{Context, Result, bail};
use sc_collect::{CdxQuery, Client};
use sc_core::rules::Linking;
use sc_core::timing::timing;
use sc_core::{
    Analysis, Observation, RecurrenceOptions, ReportOptions, Rerun, Rules, TargetRun, Tier,
    analyze, render_markdown, reruns,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::io::Write as _;
use std::path::Path;
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
    #[serde(default, rename = "source")]
    pub sources: Vec<WatchSource>,
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
    /// wayback | arquivo | urlquery
    pub kind: String,
    #[serde(flatten)]
    pub query: CdxQuery,
}

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

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct CaseWatch {
    /// Watch records that matched the case's indicators, oldest first.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hits: Vec<CaseHit>,
    /// Proposals already in a digest. A standing proposal is listed on every
    /// run but only marks the first one as changed.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub proposed: BTreeSet<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaseHit {
    pub id: String,
    pub ts: i64,
    /// The watch run that found it.
    pub run: String,
    /// Link to the public record.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reference: Option<String>,
    /// The case indicators it shares.
    pub matched: Vec<String>,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct SourceState {
    /// Newest capture time seen (Unix seconds).
    #[serde(default)]
    pub cursor: i64,
    /// Record IDs still inside the overlap window, with their capture time.
    #[serde(default)]
    pub seen: BTreeMap<String, i64>,
    /// A pull that stopped at `limit` and continues on the next run.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending: Option<Pending>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_run: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    #[serde(default)]
    pub health: SourceHealth,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pending {
    pub resume_key: String,
    /// The `from` the pull started with; the resume key is only valid with it.
    pub from: String,
}

/// What the previous run knew, so the digest can say what changed.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Summary {
    #[serde(default)]
    pub generated: String,
    /// Keyed by the cluster's earliest record ID, which is stable across runs.
    #[serde(default)]
    pub clusters: BTreeMap<String, ClusterSummary>,
    /// Every target host that ever had a flagged record. Cumulative.
    #[serde(default)]
    pub endpoints: BTreeMap<String, Endpoint>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterSummary {
    pub id: String,
    /// The cluster's stable key ([`sc_core::Cluster::key`]).
    #[serde(default)]
    pub key: String,
    pub tier: Tier,
    pub score: i32,
    pub records: usize,
    pub start: i64,
    pub end: i64,
    pub targets: Vec<String>,
    pub rules: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Endpoint {
    pub first_seen: i64,
    pub last_seen: i64,
    pub max_tier: Tier,
}

struct SourceReport {
    name: String,
    pulled: usize,
    new: usize,
    pending: bool,
    /// HTTP requests made, retries included.
    requests: usize,
    error: Option<String>,
    /// Why the source did not run (e.g. no API key). Not an error.
    skipped: Option<String>,
}

/// Environment variable holding the urlquery.net API key (same name as urlquery-cli).
pub const URLQUERY_KEY_ENV: &str = "URLQUERY_APIKEY";

fn urlquery_key() -> Option<String> {
    std::env::var(URLQUERY_KEY_ENV)
        .ok()
        .map(|k| k.trim().to_string())
        .filter(|k| !k.is_empty())
}

pub fn run(watchlist: &Path, out: &Path, notices: &Path, rules: &Rules) -> Result<()> {
    let wl: Watchlist = toml::from_str(
        &std::fs::read_to_string(watchlist)
            .with_context(|| format!("reading {}", watchlist.display()))?,
    )
    .context("watchlist")?;
    if wl.sources.is_empty() {
        bail!("{}: no [[source]] entries", watchlist.display());
    }
    let client = Client::new(Duration::from_secs(wl.min_interval_secs))?;
    let now = chrono::Utc::now();
    let stamp = now.format("%Y%m%dT%H%M%SZ").to_string();
    let run_dir = out.join("runs").join(&stamp);
    std::fs::create_dir_all(&run_dir)?;
    std::fs::create_dir_all(out.join("store"))?;

    let state_path = out.join("state.json");
    let mut state: State = read_json(&state_path)?.unwrap_or_default();
    let mut reports = Vec::new();
    let mut new_ids = BTreeSet::new();
    let mut alerts = Vec::new();

    for s in &wl.sources {
        eprint!("{:<24} {:<8} {} … ", s.name, s.kind, s.query.pattern);
        if s.kind == "urlquery" && urlquery_key().is_none() {
            eprintln!("skipped: {URLQUERY_KEY_ENV} not set");
            reports.push(SourceReport {
                name: s.name.clone(),
                pulled: 0,
                new: 0,
                pending: false,
                requests: 0,
                error: None,
                skipped: Some(format!("skipped: {URLQUERY_KEY_ENV} not set")),
            });
            continue;
        }
        let st = state.sources.entry(s.name.clone()).or_default();
        let before = client.requests();
        let res = pull(&client, s, st, wl.overlap_days * DAY);
        st.last_run = Some(stamp.clone());
        let mut rep = SourceReport {
            name: s.name.clone(),
            pulled: 0,
            new: 0,
            pending: false,
            requests: client.requests() - before,
            error: None,
            skipped: None,
        };
        alerts.extend(
            st.health
                .observe(&s.name, res.as_ref().ok().map(|(pulled, _)| *pulled)),
        );
        match res {
            Ok((pulled, fresh)) => {
                rep.pulled = pulled;
                rep.new = fresh.len();
                rep.pending = st.pending.is_some();
                st.last_error = None;
                eprintln!(
                    "{pulled} pulled, {} new{}",
                    fresh.len(),
                    if rep.pending { " (more next run)" } else { "" }
                );
                if !fresh.is_empty() {
                    let nd = to_ndjson(&fresh)?;
                    std::fs::write(run_dir.join(format!("{}.ndjson", s.name)), &nd)?;
                    append(&out.join("store").join(format!("{}.ndjson", s.name)), &nd)?;
                    new_ids.extend(fresh.iter().map(|o| o.id.clone()));
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
    let stored = load_store(&out.join("store"), i64::MIN)?;
    let bursts = archive_bursts(&stored, &new_ids, rules, now.timestamp());
    let fresh: Vec<Observation> = stored
        .iter()
        .filter(|o| new_ids.contains(&o.id))
        .cloned()
        .collect();
    let cases = monitor_cases(
        &out.join("cases"),
        notices,
        &fresh,
        rules,
        &mut state,
        &stamp,
        now.timestamp(),
        wl.contained_after_days,
    );
    let recent: Vec<Observation> = stored.into_iter().filter(|o| o.ts >= since).collect();
    let a = analyze(recent, rules);
    let (drifts, restarted) = state
        .rules
        .observe(&a.rules_version, RuleRun::from_analysis(&a, &new_ids));
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
    crate::print_summary(&a);
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
    let digest = digest(
        &stamp,
        &a,
        &prev,
        &next,
        &new_ids,
        &health,
        &bursts,
        &cases,
        wl.analysis_window_days,
    );
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

/// Pull one source incrementally. Returns (records pulled, records not seen before).
fn pull(
    client: &Client,
    s: &WatchSource,
    st: &mut SourceState,
    overlap: i64,
) -> Result<(usize, Vec<Observation>)> {
    let mut q = s.query.clone();
    let configured_from = q.from.as_deref().and_then(sc_core::parse_ts).unwrap_or(0);
    let from = match &st.pending {
        Some(p) => p.from.clone(),
        None => cdx_ts(configured_from.max(st.cursor - overlap).max(0)),
    };
    q.from = Some(from.clone()).filter(|f| f != "19700101000000");

    let mut records = Vec::new();
    match s.kind.as_str() {
        "wayback" => {
            let mut key = st.pending.as_ref().map(|p| p.resume_key.clone());
            let mut done = false;
            while records.len() < q.limit {
                let size = (q.limit - records.len()).min(q.page_size.max(1));
                let page = match client.wayback_cdx_page(&q, size, key.as_deref()) {
                    Ok(p) => p,
                    Err(e) if !records.is_empty() => {
                        // Keep what we have; continue from the last good key next run.
                        eprint!("(stopped early: {e:#}) ");
                        break;
                    }
                    Err(e) => return Err(e),
                };
                records.extend(page.records);
                key = page.resume_key;
                if key.is_none() {
                    done = true;
                    break;
                }
            }
            st.pending = match (done, key) {
                (false, Some(k)) => Some(Pending {
                    resume_key: k,
                    from: from.clone(),
                }),
                _ => None,
            };
        }
        "arquivo" | "urlquery" => {
            records = if s.kind == "arquivo" {
                client.arquivo_cdx(&q)?
            } else {
                let key = urlquery_key().with_context(|| format!("{URLQUERY_KEY_ENV} not set"))?;
                client.urlquery(&key, &q)?
            };
            if records.len() >= q.limit {
                eprint!("(hit limit {}; raise it or narrow the pattern) ", q.limit);
            }
        }
        k => bail!("unknown kind `{k}` (expected wayback, arquivo or urlquery)"),
    }

    let pulled = records.len();
    let mut fresh = Vec::new();
    for o in records {
        if st.seen.contains_key(&o.id) {
            continue;
        }
        st.seen.insert(o.id.clone(), o.ts);
        st.cursor = st.cursor.max(o.ts);
        fresh.push(o);
    }
    // Forget IDs the next pull cannot return again.
    let keep_from = match &st.pending {
        Some(p) => sc_core::parse_ts(&p.from).unwrap_or(0),
        None => st.cursor - overlap,
    };
    st.seen.retain(|_, ts| *ts >= keep_from);
    Ok((pulled, fresh))
}

fn summarise(a: &Analysis, prev: &Summary, generated: String) -> Summary {
    let mut s = Summary {
        generated,
        clusters: BTreeMap::new(),
        endpoints: prev.endpoints.clone(),
    };
    for c in &a.clusters {
        let Some(first) = c
            .members
            .iter()
            .map(|&m| &a.results[m].obs)
            .min_by(|x, y| x.ts.cmp(&y.ts).then_with(|| x.id.cmp(&y.id)))
        else {
            continue;
        };
        s.clusters.insert(
            first.id.clone(),
            ClusterSummary {
                id: c.id.clone(),
                key: c.key.clone(),
                tier: c.tier,
                score: c.score,
                records: c.members.len(),
                start: c.start,
                end: c.end,
                targets: top(&c.target_hosts, 3),
                rules: top(&c.rules, 6),
            },
        );
    }
    for r in &a.results {
        if r.tier < Tier::Suggestive {
            continue;
        }
        let Some(h) = &r.target_host else { continue };
        let e = s.endpoints.entry(h.clone()).or_insert(Endpoint {
            first_seen: r.obs.ts,
            last_seen: r.obs.ts,
            max_tier: r.tier,
        });
        e.first_seen = e.first_seen.min(r.obs.ts);
        e.last_seen = e.last_seen.max(r.obs.ts);
        e.max_tier = e.max_tier.max(r.tier);
    }
    s
}

/// How the run's sources fared, with warnings. Any alert or source error
/// makes the run count as changed, so it is emailed.
#[derive(Default)]
struct Health {
    sources: Vec<SourceReport>,
    alerts: Vec<String>,
    notes: Vec<String>,
}

pub struct Digest {
    pub text: String,
    pub changed: bool,
}

#[allow(clippy::too_many_arguments)]
fn digest(
    stamp: &str,
    a: &Analysis,
    prev: &Summary,
    next: &Summary,
    new_ids: &BTreeSet<String>,
    health: &Health,
    bursts: &[ArchiveBurst],
    cases: &CaseReport,
    window_days: i64,
) -> Digest {
    let mut t = String::new();
    let _ = writeln!(t, "# Watch digest {stamp}\n");
    let _ = writeln!(
        t,
        "Unverified leads from passive collection. Review before acting on anything here.\n"
    );

    let _ = writeln!(t, "## Sources\n");
    let _ = writeln!(
        t,
        "| Source | Pulled | New | Requests | Status |\n|---|---:|---:|---:|---|"
    );
    for s in &health.sources {
        let status = match (&s.error, s.pending) {
            _ if s.skipped.is_some() => s.skipped.clone().unwrap_or_default(),
            (Some(e), _) => format!("error: {}", one_line(e, 160)),
            (None, true) => "partial, continues next run".into(),
            (None, false) => "complete".into(),
        };
        let _ = writeln!(
            t,
            "| {} | {} | {} | {} | {status} |",
            s.name, s.pulled, s.new, s.requests
        );
    }

    let _ = writeln!(t, "\n## Health ({})\n", health.alerts.len());
    if health.alerts.is_empty() {
        let _ = writeln!(t, "No source collapses or rule drift.");
    }
    for x in &health.alerts {
        let _ = writeln!(t, "- {x}");
    }
    for x in &health.notes {
        let _ = writeln!(t, "\n{x}");
    }

    let tier = |x| a.tier_counts.get(&x).copied().unwrap_or(0);
    let _ = writeln!(
        t,
        "\n## Last {window_days} days\n\n{} records, {} flagged ({} significant, {} suggestive), {} clusters.\n",
        a.total,
        a.flagged,
        tier(Tier::Significant),
        tier(Tier::Suggestive),
        a.clusters.len()
    );

    let mut new_clusters = Vec::new();
    let mut escalated = Vec::new();
    for (k, c) in &next.clusters {
        if c.tier < Tier::Suggestive {
            continue;
        }
        match prev.clusters.get(k) {
            None => new_clusters.push(c),
            Some(p) if c.tier > p.tier => escalated.push((p.tier, c)),
            _ => {}
        }
    }
    let new_endpoints: Vec<(&String, &Endpoint)> = next
        .endpoints
        .iter()
        .filter(|(h, _)| !prev.endpoints.contains_key(*h))
        .collect();

    let none = |t: &mut String, empty: bool| {
        if empty {
            let _ = writeln!(t, "None.");
        }
    };
    let _ = writeln!(t, "## New clusters ({})\n", new_clusters.len());
    none(&mut t, new_clusters.is_empty());
    for c in &new_clusters {
        let _ = writeln!(t, "- {}", cluster_line(c));
    }
    let _ = writeln!(t, "\n## Tier changes ({})\n", escalated.len());
    none(&mut t, escalated.is_empty());
    for (from, c) in &escalated {
        let _ = writeln!(
            t,
            "- {} → {}: {}",
            from.label(),
            c.tier.label(),
            cluster_line(c)
        );
    }
    let _ = writeln!(t, "\n## Endpoints newly hit ({})\n", new_endpoints.len());
    none(&mut t, new_endpoints.is_empty());
    for (h, e) in &new_endpoints {
        let _ = writeln!(
            t,
            "- `{}` [{}] first seen {}, last {}",
            defang_host(h),
            e.max_tier.label(),
            sc_core::fmt_ts(e.first_seen),
            sc_core::fmt_ts(e.last_seen)
        );
    }

    let mut targets: BTreeMap<&str, usize> = BTreeMap::new();
    for r in &a.results {
        if r.tier >= Tier::Suggestive
            && new_ids.contains(&r.obs.id)
            && let Some(h) = &r.target_host
        {
            *targets.entry(h.as_str()).or_default() += 1;
        }
    }
    let mut targets: Vec<_> = targets.into_iter().collect();
    targets.sort_by_key(|x| std::cmp::Reverse(x.1));
    let _ = writeln!(t, "\n## Top targets in new records\n");
    none(&mut t, targets.is_empty());
    for (h, n) in targets.iter().take(10) {
        let _ = writeln!(t, "- `{}`: {n} flagged", defang_host(h));
    }

    // Descriptive only: a rerun is a lead for the admin, never a merge.
    let (runs, matches) = rerun_matches(a, new_ids);
    let _ = writeln!(t, "\n## Possible reruns ({})\n", matches.len());
    none(&mut t, matches.is_empty());
    for m in &matches {
        let (e, l) = (&runs[m.earlier], &runs[m.later]);
        let _ = writeln!(
            t,
            "- {} repeats {}: {} shared hosts, Jaccard {:.2} (weighted {:.2}), order {:.2}; {}",
            run_label(l),
            run_label(e),
            m.shared.len(),
            m.jaccard,
            m.weighted_jaccard,
            m.order,
            m.shared
                .iter()
                .take(5)
                .map(|h| format!("`{}`", defang_host(h)))
                .collect::<Vec<_>>()
                .join(", ")
        );
    }

    let _ = writeln!(t, "\n## Archive bursts ({})\n", bursts.len());
    none(&mut t, bursts.is_empty());
    for b in bursts {
        let _ = writeln!(
            t,
            "- `{}`: {} captures {} → {} ({} distinct URLs, {} flagged); usually {:.1}/day",
            defang_host(&b.host),
            b.count,
            sc_core::fmt_ts(b.start),
            sc_core::fmt_ts(b.end),
            b.distinct_urls,
            b.flagged,
            b.baseline_per_day
        );
    }

    let _ = writeln!(t, "\n## Case status ({})\n", cases.lines.len());
    none(&mut t, cases.lines.is_empty());
    for l in &cases.lines {
        let _ = writeln!(t, "- {l}");
    }
    if !cases.lines.is_empty() {
        let _ = writeln!(
            t,
            "\nProposals only: nothing here changes a case or notice until you run the command."
        );
    }

    let errors = health.sources.iter().any(|s| s.error.is_some());
    let changed = cases.changed
        || !new_clusters.is_empty()
        || !escalated.is_empty()
        || !new_endpoints.is_empty()
        || !matches.is_empty()
        || !bursts.is_empty()
        || errors
        || !health.alerts.is_empty();
    Digest { text: t, changed }
}

/// The digest's "Case status" lines, and whether any is new since the last run.
#[derive(Default)]
struct CaseReport {
    lines: Vec<String>,
    changed: bool,
}

/// A case as the status check sees it.
struct CaseView<'a> {
    id: &'a str,
    status: CaseStatus,
    /// The published notice's status; `None` before the notice is published.
    notice: Option<NoticeStatus>,
    /// Newest capture time among the case's own records.
    last_seen: i64,
}

/// Match `fresh` against every case's indicators, record the hits in
/// `state`, and propose status changes. Errors are reported per case in the
/// digest; they never stop the watch.
#[allow(clippy::too_many_arguments)]
fn monitor_cases(
    root: &Path,
    notices: &Path,
    fresh: &[Observation],
    current: &Rules,
    state: &mut State,
    stamp: &str,
    now: i64,
    contained_after_days: i64,
) -> CaseReport {
    let mut report = CaseReport::default();
    let cases = match case::all(root) {
        Ok(c) => c,
        Err(e) => {
            report.lines.push(format!("cases not checked: {e:#}"));
            return report;
        }
    };
    state
        .cases
        .retain(|id, _| cases.iter().any(|c| &c.id == id));
    for c in &cases {
        let cw = state.cases.entry(c.id.clone()).or_default();
        let (lines, keys) = match check_case(
            root,
            notices,
            c,
            fresh,
            current,
            cw,
            stamp,
            now,
            contained_after_days,
        ) {
            Ok(x) => x,
            Err(e) => {
                let l = format!(
                    "`{}`: not checked: {}",
                    c.id,
                    one_line(&format!("{e:#}"), 200)
                );
                (vec![l.clone()], BTreeSet::from([l]))
            }
        };
        report.changed |= keys.iter().any(|k| !cw.proposed.contains(k));
        cw.proposed = keys;
        report.lines.extend(lines);
    }
    report
}

/// One case's digest lines, and keys naming them for change detection.
#[allow(clippy::too_many_arguments)]
fn check_case(
    root: &Path,
    notices: &Path,
    c: &case::Case,
    fresh: &[Observation],
    current: &Rules,
    cw: &mut CaseWatch,
    stamp: &str,
    now: i64,
    contained_after_days: i64,
) -> Result<(Vec<String>, BTreeSet<String>)> {
    let rules = case::case_rules(root, c)?;
    let ind = case::indicators(root, c, &rules)?;
    let known: BTreeSet<String> = cw.hits.iter().map(|h| h.id.clone()).collect();
    let new_hits = case_hits(&ind, fresh, &rules, stamp, &known);
    cw.hits.extend(new_hits.iter().cloned());
    let notice = match crate::notice::published_status(notices, &c.id)? {
        Some(s) => Some(s),
        None if c.status == CaseStatus::Published => Some(c.notice),
        None => None,
    };
    let view = CaseView {
        id: &c.id,
        status: c.status,
        notice,
        last_seen: ind.last_seen,
    };
    let mut lines = Vec::new();
    let mut keys = BTreeSet::new();
    if let Some((key, line)) = propose(&view, cw, &new_hits, now, contained_after_days) {
        keys.insert(key);
        lines.push(line);
    }
    let version = &current.set.meta.version;
    // Compared on every run rather than by version name: a rule set edited
    // without a version bump changes tiers too.
    if c.status != CaseStatus::Closed {
        let n = case::tier_changes(root, c, current)?.len();
        if n > 0 {
            keys.insert(format!("rules:{version}:{n}"));
            lines.push(tier_change_line(&c.id, n, version));
        }
    }
    Ok((lines, keys))
}

/// Records in `fresh` that match the case's indicators under its rules,
/// leaving out records already recorded as hits.
fn case_hits(
    ind: &case::CaseIndicators,
    fresh: &[Observation],
    rules: &Rules,
    stamp: &str,
    known: &BTreeSet<String>,
) -> Vec<CaseHit> {
    let mut hits: Vec<CaseHit> = fresh
        .iter()
        .filter(|o| !known.contains(&o.id))
        .filter_map(|o| {
            let matched = ind.matches(o, rules);
            (!matched.is_empty()).then(|| CaseHit {
                id: o.id.clone(),
                ts: o.ts,
                run: stamp.to_string(),
                reference: o.reference.clone(),
                matched,
            })
        })
        .collect();
    hits.sort_by(|a, b| a.ts.cmp(&b.ts).then_with(|| a.id.cmp(&b.id)));
    hits
}

/// The status change to propose for a case, as (key, digest line): reopen
/// when new records match a case whose notice is contained or historical or
/// which is closed; mark contained when an active notice's case has had no
/// matching record for `contained_after_days`. New hits on an active case are
/// reported without a proposal.
fn propose(
    v: &CaseView,
    cw: &CaseWatch,
    new_hits: &[CaseHit],
    now: i64,
    contained_after_days: i64,
) -> Option<(String, String)> {
    let id = v.id;
    let quiet_notice = matches!(
        v.notice,
        Some(NoticeStatus::Contained | NoticeStatus::Historical)
    );
    let closed = v.status == CaseStatus::Closed;
    if !new_hits.is_empty() {
        let what = hits_summary(new_hits);
        let add = format!(
            "`swarmchase case add {id} {}`",
            new_hits
                .iter()
                .take(20)
                .map(|h| format!("--record {}", h.id))
                .collect::<Vec<_>>()
                .join(" ")
        );
        if !(quiet_notice || closed) {
            let key = format!("hits:{}", new_hits[new_hits.len() - 1].id);
            return Some((key, format!("`{id}`: {what}. Add them with {add}")));
        }
        let mut was = Vec::new();
        let mut apply = Vec::new();
        if let Some(n) = v.notice.filter(|_| quiet_notice) {
            was.push(format!("notice {}", n.label()));
            apply.push(format!(
                "`swarmchase notice update {id} --kind status --status active`"
            ));
        }
        if closed {
            was.push("case closed".into());
            let to = if v.notice.is_some() {
                "published"
            } else {
                "open"
            };
            apply.push(format!("`swarmchase case set {id} --status {to}`"));
        }
        apply.push(add);
        return Some((
            format!("reopen:{}", new_hits[new_hits.len() - 1].id),
            format!(
                "`{id}`: propose reopen ({}): {what}. If approved: {}",
                was.join(", "),
                apply.join(", then ")
            ),
        ));
    }
    if v.notice != Some(NoticeStatus::Active) || closed {
        return None;
    }
    let last = cw.hits.iter().map(|h| h.ts).fold(v.last_seen, i64::max);
    if last <= 0 || now - last < contained_after_days * DAY {
        return None;
    }
    Some((
        "contained".into(),
        format!(
            "`{id}`: propose contained: no matching record since {} ({} days). If approved: `swarmchase notice update {id} --kind status --status contained`",
            sc_core::fmt_ts(last),
            (now - last) / DAY
        ),
    ))
}

/// "N new matching record(s) (indicators): links".
fn hits_summary(hits: &[CaseHit]) -> String {
    let matched: BTreeSet<&str> = hits
        .iter()
        .flat_map(|h| h.matched.iter().map(String::as_str))
        .collect();
    let mut shown: Vec<String> = matched
        .iter()
        .take(5)
        .map(|m| format!("`{}`", defang_host(m)))
        .collect();
    if matched.len() > 5 {
        shown.push(format!("{} more", matched.len() - 5));
    }
    let links: Vec<String> = hits
        .iter()
        .take(5)
        .map(|h| h.reference.clone().unwrap_or_else(|| h.id.clone()))
        .collect();
    format!(
        "{} new matching record(s) ({}): {}{}",
        hits.len(),
        shown.join(", "),
        links.join(", "),
        if hits.len() > 5 { ", …" } else { "" }
    )
}

fn tier_change_line(id: &str, n: usize, version: &str) -> String {
    format!(
        "{n} records in case `{id}` would change tier under rules {version}; run `swarmchase case rules {id}`"
    )
}

/// One run (a stretch of a cluster with no long gap) as the rerun check sees it.
struct RunInfo {
    cluster: String,
    start: i64,
    records: usize,
    new: bool,
}

fn run_label(r: &RunInfo) -> String {
    format!(
        "{} run at {} ({} records)",
        r.cluster,
        sc_core::fmt_ts(r.start),
        r.records
    )
}

/// Runs in the analysis whose target sequence repeats an earlier run in a
/// different cluster, where the later run has records new in this watch run.
fn rerun_matches(a: &Analysis, new_ids: &BTreeSet<String>) -> (Vec<RunInfo>, Vec<Rerun>) {
    let mut infos = Vec::new();
    let mut runs = Vec::new();
    for c in &a.clusters {
        for (n, span) in c.runs.iter().enumerate() {
            let members: Vec<&sc_core::ObsResult> = c
                .members
                .iter()
                .map(|&m| &a.results[m])
                .filter(|r| r.obs.ts >= span.start && r.obs.ts <= span.end)
                .collect();
            runs.push(TargetRun {
                key: format!("{}#{}", c.id, n + 1),
                targets: members
                    .iter()
                    .filter_map(|r| Some((r.obs.ts, r.target_host.clone()?)))
                    .collect(),
            });
            infos.push(RunInfo {
                cluster: c.id.clone(),
                start: span.start,
                records: members.len(),
                new: members.iter().any(|r| new_ids.contains(&r.obs.id)),
            });
        }
    }
    let matches = reruns(&runs, &RecurrenceOptions::default())
        .into_iter()
        .filter(|m| infos[m.later].new && infos[m.earlier].cluster != infos[m.later].cluster)
        .collect();
    (infos, matches)
}

/// A cluster of archive captures of one host within minutes, against a host
/// that is otherwise rarely captured.
#[derive(Debug, Clone)]
pub struct ArchiveBurst {
    pub host: String,
    pub start: i64,
    pub end: i64,
    pub count: usize,
    pub distinct_urls: usize,
    /// Captures in the burst that matched at least one rule.
    pub flagged: usize,
    /// The host's captures per day across the store, this burst excluded.
    pub baseline_per_day: f64,
}

/// Bursts of Wayback / Arquivo captures per target host that contain a record
/// new in this run, where the host is normally sparse in the store. The
/// thresholds are the `archive_burst_*` settings in the rules' `[linking]`.
fn archive_bursts(
    store: &[Observation],
    new_ids: &BTreeSet<String>,
    rules: &Rules,
    now: i64,
) -> Vec<ArchiveBurst> {
    struct Capture<'a> {
        ts: i64,
        id: &'a str,
        url: &'a str,
        flagged: bool,
    }
    let mut by_host: BTreeMap<String, Vec<Capture>> = BTreeMap::new();
    let mut first = i64::MAX;
    for o in store {
        if !matches!(o.source.as_str(), "wayback" | "arquivo") || o.ts <= 0 {
            continue;
        }
        let x = sc_core::extract(o, rules);
        let Some(host) = x.target_host.or_else(|| x.layers.first()?.host.clone()) else {
            continue;
        };
        first = first.min(o.ts);
        by_host.entry(host).or_default().push(Capture {
            ts: o.ts,
            id: &o.id,
            url: &o.url,
            flagged: x.score > 0,
        });
    }
    let days = ((now - first) as f64 / DAY as f64).max(1.0);
    let l = &rules.set.linking;
    let cfg = Linking {
        burst_gap_secs: l.archive_burst_gap_secs,
        burst_min: l.archive_burst_min,
        ..Default::default()
    };

    let mut out = Vec::new();
    for (host, caps) in &by_host {
        if !caps.iter().any(|c| new_ids.contains(c.id)) {
            continue;
        }
        let ts: Vec<i64> = caps.iter().map(|c| c.ts).collect();
        for b in timing(&ts, &cfg).bursts {
            let inside: Vec<&Capture> = caps
                .iter()
                .filter(|c| c.ts >= b.start && c.ts <= b.end)
                .collect();
            if !inside.iter().any(|c| new_ids.contains(c.id)) {
                continue;
            }
            let baseline = (caps.len() - b.count) as f64 / days;
            if (b.count as f64) < l.archive_burst_ratio * baseline {
                continue;
            }
            out.push(ArchiveBurst {
                host: host.clone(),
                start: b.start,
                end: b.end,
                count: b.count,
                distinct_urls: inside.iter().map(|c| c.url).collect::<BTreeSet<_>>().len(),
                flagged: inside.iter().filter(|c| c.flagged).count(),
                baseline_per_day: baseline,
            });
        }
    }
    out.sort_by(|x, y| y.count.cmp(&x.count).then_with(|| x.start.cmp(&y.start)));
    out
}

fn cluster_line(c: &ClusterSummary) -> String {
    format!(
        "{}{} [{}] score {}, {} records, {} → {}; targets {}; rules {}",
        c.id,
        if c.key.is_empty() {
            String::new()
        } else {
            format!(" {}", c.key)
        },
        c.tier.label(),
        c.score,
        c.records,
        sc_core::fmt_ts(c.start),
        sc_core::fmt_ts(c.end),
        c.targets
            .iter()
            .map(|h| format!("`{}`", defang_host(h)))
            .collect::<Vec<_>>()
            .join(", "),
        c.rules.join(", ")
    )
}

fn defang_host(h: &str) -> String {
    h.replace('.', "[.]")
}

fn one_line(s: &str, n: usize) -> String {
    let s = s.replace(['\n', '|'], " ");
    if s.chars().count() > n {
        format!("{}…", s.chars().take(n).collect::<String>())
    } else {
        s
    }
}

fn top<K: ToString>(m: &BTreeMap<K, usize>, n: usize) -> Vec<String> {
    let mut v: Vec<(String, usize)> = m.iter().map(|(k, c)| (k.to_string(), *c)).collect();
    v.sort_by_key(|x| std::cmp::Reverse(x.1));
    v.into_iter().take(n).map(|(k, _)| k).collect()
}

/// CDX timestamp (`yyyyMMddhhmmss`).
fn cdx_ts(ts: i64) -> String {
    chrono::DateTime::from_timestamp(ts, 0)
        .unwrap_or_default()
        .format("%Y%m%d%H%M%S")
        .to_string()
}

/// Delete run directories stamped before `cutoff` and stored records captured
/// before it. Records with no timestamp are kept: their age is unknown.
/// Returns (run dirs deleted, records deleted).
fn prune(out: &Path, cutoff: i64) -> Result<(usize, usize)> {
    let mut runs = 0;
    if let Ok(entries) = std::fs::read_dir(out.join("runs")) {
        for entry in entries {
            let p = entry?.path();
            let stamp = p.file_name().and_then(|n| n.to_str()).unwrap_or_default();
            let Ok(t) = chrono::NaiveDateTime::parse_from_str(stamp, "%Y%m%dT%H%M%SZ") else {
                continue; // not a run directory
            };
            if p.is_dir() && t.and_utc().timestamp() < cutoff {
                std::fs::remove_dir_all(&p).with_context(|| format!("deleting {}", p.display()))?;
                runs += 1;
            }
        }
    }
    let mut records = 0;
    if let Ok(entries) = std::fs::read_dir(out.join("store")) {
        for entry in entries {
            let p = entry?.path();
            if p.extension().and_then(|e| e.to_str()) != Some("ndjson") {
                continue;
            }
            let text = std::fs::read_to_string(&p)?;
            let mut kept = String::with_capacity(text.len());
            let mut dropped = 0;
            for line in text.lines().filter(|l| !l.trim().is_empty()) {
                let ts = serde_json::from_str::<Observation>(line).map_or(0, |o| o.ts);
                if ts > 0 && ts < cutoff {
                    dropped += 1;
                } else {
                    kept.push_str(line);
                    kept.push('\n');
                }
            }
            if dropped > 0 {
                let tmp = p.with_extension("ndjson.tmp");
                std::fs::write(&tmp, kept)?;
                std::fs::rename(&tmp, &p)?;
                records += dropped;
            }
        }
    }
    Ok((runs, records))
}

pub(crate) fn load_store(dir: &Path, since: i64) -> Result<Vec<Observation>> {
    let mut out = Vec::new();
    let mut seen = BTreeSet::new();
    for entry in std::fs::read_dir(dir)? {
        let p = entry?.path();
        if p.extension().and_then(|e| e.to_str()) != Some("ndjson") {
            continue;
        }
        let text = std::fs::read_to_string(&p)?;
        for line in text.lines().filter(|l| !l.trim().is_empty()) {
            let Ok(o) = serde_json::from_str::<Observation>(line) else {
                continue;
            };
            if o.ts >= since && seen.insert(o.id.clone()) {
                out.push(o);
            }
        }
    }
    Ok(out)
}

pub fn to_ndjson(obs: &[Observation]) -> Result<String> {
    let mut s = String::new();
    for o in obs {
        s.push_str(&serde_json::to_string(o)?);
        s.push('\n');
    }
    Ok(s)
}

fn append(p: &Path, text: &str) -> Result<()> {
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(p)
        .with_context(|| format!("opening {}", p.display()))?;
    f.write_all(text.as_bytes())?;
    Ok(())
}

pub fn read_json<T: for<'de> Deserialize<'de>>(p: &Path) -> Result<Option<T>> {
    match std::fs::read_to_string(p) {
        Ok(s) => Ok(Some(
            serde_json::from_str(&s).with_context(|| format!("parsing {}", p.display()))?,
        )),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).with_context(|| format!("reading {}", p.display())),
    }
}

/// Write via a temporary file and rename, so a crash never leaves half a file.
pub fn write_json<T: Serialize>(p: &Path, v: &T) -> Result<()> {
    let tmp = p.with_extension("json.tmp");
    std::fs::write(&tmp, serde_json::to_string_pretty(v)?)?;
    std::fs::rename(&tmp, p).with_context(|| format!("writing {}", p.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prune_deletes_old_runs_and_records() {
        let out = std::env::temp_dir().join(format!("swarmchase-prune-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&out);
        for stamp in ["20260101T000000Z", "20261001T000000Z"] {
            std::fs::create_dir_all(out.join("runs").join(stamp)).unwrap();
        }
        std::fs::create_dir_all(out.join("store")).unwrap();
        let rec = |id: &str, ts: i64| Observation {
            id: id.into(),
            ts,
            url: "https://a.example/".into(),
            ..Default::default()
        };
        let cutoff = sc_core::parse_ts("2026-06-01").unwrap();
        let nd = to_ndjson(&[
            rec("old", cutoff - 1),
            rec("new", cutoff),
            rec("undated", 0),
        ])
        .unwrap();
        std::fs::write(out.join("store").join("s.ndjson"), nd).unwrap();

        assert_eq!(prune(&out, cutoff).unwrap(), (1, 1));
        assert!(!out.join("runs").join("20260101T000000Z").exists());
        assert!(out.join("runs").join("20261001T000000Z").exists());
        let kept: Vec<String> = load_store(&out.join("store"), i64::MIN)
            .unwrap()
            .into_iter()
            .map(|o| o.id)
            .collect();
        assert_eq!(kept, ["new", "undated"]);
        std::fs::remove_dir_all(&out).unwrap();
    }

    #[test]
    fn cdx_timestamps() {
        assert_eq!(cdx_ts(0), "19700101000000");
        assert_eq!(
            sc_core::parse_ts(&cdx_ts(1_791_000_000)),
            Some(1_791_000_000)
        );
    }

    #[test]
    fn digest_reports_new_clusters_and_endpoints_once() {
        let rules = Rules::default_rules();
        let obs: Vec<Observation> = (0..6)
            .map(|i| Observation {
                id: format!("r{i}"),
                ts: 1_791_000_000 + i * 30,
                url: format!(
                    "https://r.jina.ai/https://portal.example.gov/q?id=1'%20OR%201=1--&uqtag=run7&n={i}"
                ),
                ..Default::default()
            })
            .collect();
        let a = analyze(obs, &rules);
        assert!(!a.clusters.is_empty());
        let ids: BTreeSet<String> = a.results.iter().map(|r| r.obs.id.clone()).collect();

        let first = summarise(&a, &Summary::default(), "t1".into());
        let d1 = digest(
            "t1",
            &a,
            &Summary::default(),
            &first,
            &ids,
            &Health::default(),
            &[],
            &CaseReport::default(),
            30,
        );
        assert!(d1.changed, "{}", d1.text);
        assert!(d1.text.contains("portal[.]example[.]gov"));

        let second = summarise(&a, &first, "t2".into());
        let d2 = digest(
            "t2",
            &a,
            &first,
            &second,
            &BTreeSet::new(),
            &Health::default(),
            &[],
            &CaseReport::default(),
            30,
        );
        assert!(!d2.changed, "{}", d2.text);

        let alert = Health {
            alerts: vec!["`s` has failed 2 runs in a row".into()],
            ..Default::default()
        };
        let d3 = digest(
            "t3",
            &a,
            &second,
            &second,
            &BTreeSet::new(),
            &alert,
            &[],
            &CaseReport::default(),
            30,
        );
        assert!(
            d3.changed && d3.text.contains("## Health (1)"),
            "{}",
            d3.text
        );
    }

    #[test]
    fn digest_reports_reruns_across_clusters() {
        let rules = Rules::default_rules();
        let hosts = ["a", "b", "c", "d", "e", "f"];
        let run = |tag: &str, start: i64| -> Vec<Observation> {
            hosts
                .iter()
                .enumerate()
                .map(|(i, h)| Observation {
                    id: format!("{tag}-{i}"),
                    ts: start + i as i64 * 40,
                    url: format!(
                        "https://r.jina.ai/https://{h}.portal.example/q?id=1'%20OR%201=1--&uqtag={tag}"
                    ),
                    ..Default::default()
                })
                .collect()
        };
        let mut obs = run("first7", 1_791_000_000);
        obs.extend(run("second9", 1_791_000_000 + 3 * DAY));
        let a = analyze(obs, &rules);
        assert!(a.clusters.len() >= 2, "{:?}", a.clusters.len());
        let new_ids: BTreeSet<String> = (0..hosts.len()).map(|i| format!("second9-{i}")).collect();
        let next = summarise(&a, &Summary::default(), "t1".into());
        let d = digest(
            "t1",
            &a,
            &next,
            &next,
            &new_ids,
            &Health::default(),
            &[],
            &CaseReport::default(),
            30,
        );
        assert!(d.changed, "{}", d.text);
        assert!(d.text.contains("## Possible reruns (1)"), "{}", d.text);
        assert!(d.text.contains("6 shared hosts"), "{}", d.text);
        assert!(d.text.contains("`a[.]portal[.]example`"), "{}", d.text);

        // The same records with nothing new: no rerun to report.
        let d = digest(
            "t2",
            &a,
            &next,
            &next,
            &BTreeSet::new(),
            &Health::default(),
            &[],
            &CaseReport::default(),
            30,
        );
        assert!(d.text.contains("## Possible reruns (0)"), "{}", d.text);
    }

    #[test]
    fn digest_reports_archive_bursts_on_sparse_hosts() {
        let rules = Rules::default_rules();
        let now = 1_791_000_000;
        let cap = |id: String, ts: i64, url: String| Observation {
            id,
            source: "wayback".into(),
            ts,
            url,
            ..Default::default()
        };
        let mut store = Vec::new();
        // A rarely captured host, then six captures within minutes.
        store.push(cap(
            "s-old1".into(),
            now - 50 * DAY,
            "https://sparse.example/".into(),
        ));
        store.push(cap(
            "s-old2".into(),
            now - 20 * DAY,
            "https://sparse.example/".into(),
        ));
        for i in 0..6 {
            store.push(cap(
                format!("s{i}"),
                now - 3600 + i * 60,
                format!("https://sparse.example/report?page={i}"),
            ));
        }
        // A host captured all day, every day: a burst there is normal.
        for d in 0..60 {
            for h in 0..24 {
                store.push(cap(
                    format!("b{d}-{h}"),
                    now - d * DAY - h * 3600 - 7200,
                    "https://busy.example/".into(),
                ));
            }
        }
        for i in 0..6 {
            store.push(cap(
                format!("b-new{i}"),
                now - 1800 + i * 30,
                "https://busy.example/".into(),
            ));
        }
        let new_ids: BTreeSet<String> = store
            .iter()
            .filter(|o| o.ts > now - 2 * 3600)
            .map(|o| o.id.clone())
            .collect();
        let bursts = archive_bursts(&store, &new_ids, &rules, now);
        assert_eq!(bursts.len(), 1, "{bursts:?}");
        assert_eq!(bursts[0].host, "sparse.example");
        assert_eq!((bursts[0].count, bursts[0].distinct_urls), (6, 6));

        // A burst already reported in an earlier run is not repeated.
        assert!(archive_bursts(&store, &BTreeSet::new(), &rules, now).is_empty());

        let a = analyze(Vec::new(), &rules);
        let s = Summary::default();
        let d = digest(
            "t1",
            &a,
            &s,
            &s,
            &new_ids,
            &Health::default(),
            &bursts,
            &CaseReport::default(),
            30,
        );
        assert!(d.changed, "{}", d.text);
        assert!(d.text.contains("## Archive bursts (1)"), "{}", d.text);
        assert!(
            d.text.contains("`sparse[.]example`: 6 captures"),
            "{}",
            d.text
        );
        assert!(!d.text.contains("busy[.]example"), "{}", d.text);
    }

    /// A data directory with case `p-1` opened from four records of one run
    /// against portal.example.gov, pinned to `rules`.
    fn case_data(name: &str, rules: &case::RulesText) -> std::path::PathBuf {
        let data =
            std::env::temp_dir().join(format!("swarmchase-watch-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&data);
        let records: Vec<Observation> = (0..4)
            .map(|i| Observation {
                id: format!("c{i}"),
                ts: CASE_TS + i * 40,
                url: format!(
                    "https://r.jina.ai/https://portal.example.gov/q?id={i}%20UNION%20SELECT%201&uqtag=zz9"
                ),
                ..Default::default()
            })
            .collect();
        case::new_case(
            &data.join("cases"),
            "p-1",
            "Portal probe",
            records,
            rules,
            "2026-10-01",
        )
        .unwrap();
        data
    }

    const CASE_TS: i64 = 1_791_000_000;

    fn obs(id: &str, ts: i64, url: &str) -> Observation {
        Observation {
            id: id.into(),
            ts,
            url: url.into(),
            reference: Some(format!("https://urlquery.example/report/{id}")),
            ..Default::default()
        }
    }

    #[test]
    fn new_records_match_case_indicators() {
        let rules = case::RulesText::load(None).unwrap();
        let data = case_data("match", &rules);
        let c = case::load(&data.join("cases"), "p-1").unwrap();
        let ind = case::indicators(&data.join("cases"), &c, &rules.rules).unwrap();
        assert!(
            ind.features
                .contains_key(&"param:uqtag=zz9".parse::<sc_core::LinkFeature>().unwrap()),
            "{:?}",
            ind.features
        );
        assert!(ind.endpoints.contains("portal.example.gov"));

        let later = CASE_TS + 20 * DAY;
        let fresh = vec![
            // The run tag, on another host.
            obs(
                "tag",
                later,
                "https://r.jina.ai/https://other.example/x?id=1%20UNION%20SELECT%201&uqtag=zz9",
            ),
            // The endpoint, without the tag.
            obs(
                "host",
                later + 60,
                "https://portal.example.gov/q?id=9%20UNION%20SELECT%209",
            ),
            // Ordinary traffic to the endpoint: matches no rule.
            obs("plain", later + 120, "https://portal.example.gov/about"),
            // Unrelated flagged activity.
            obs(
                "other",
                later + 180,
                "https://elsewhere.example/q?id=1%20UNION%20SELECT%201",
            ),
            // One of the case's own records, seen again.
            obs(
                "c0",
                CASE_TS,
                "https://r.jina.ai/https://portal.example.gov/q?id=0%20UNION%20SELECT%201&uqtag=zz9",
            ),
        ];
        let hits = case_hits(&ind, &fresh, &rules.rules, "t1", &BTreeSet::new());
        let ids: Vec<&str> = hits.iter().map(|h| h.id.as_str()).collect();
        assert_eq!(ids, ["tag", "host"], "{hits:?}");
        assert!(
            hits[0].matched.iter().any(|m| m.contains("uqtag=zz9")),
            "{hits:?}"
        );
        assert_eq!(hits[1].matched, ["Endpoint portal.example.gov"]);
        // Hits already recorded are not reported again.
        let known = BTreeSet::from(["tag".to_string()]);
        assert_eq!(case_hits(&ind, &fresh, &rules.rules, "t2", &known).len(), 1);

        // Through the watch: hits are kept per case and listed in the digest.
        let mut state = State::default();
        let r = monitor_cases(
            &data.join("cases"),
            &data.join("notices"),
            &fresh,
            &rules.rules,
            &mut state,
            "t1",
            later + DAY,
            14,
        );
        assert!(r.changed, "{:?}", r.lines);
        assert_eq!(state.cases["p-1"].hits.len(), 2);
        assert!(
            r.lines[0].contains("2 new matching record(s)"),
            "{:?}",
            r.lines
        );
        assert!(
            r.lines[0].contains("--record tag --record host"),
            "{:?}",
            r.lines
        );
        let a = analyze(Vec::new(), &rules.rules);
        let sum = Summary::default();
        let d = digest(
            "t1",
            &a,
            &sum,
            &sum,
            &BTreeSet::new(),
            &Health::default(),
            &[],
            &r,
            30,
        );
        assert!(
            d.changed && d.text.contains("## Case status (1)"),
            "{}",
            d.text
        );
        assert!(d.text.contains("portal[.]example[.]gov"), "{}", d.text);
        std::fs::remove_dir_all(&data).unwrap();
    }

    fn view(notice: Option<NoticeStatus>, status: CaseStatus) -> CaseView<'static> {
        CaseView {
            id: "p-1",
            status,
            notice,
            last_seen: CASE_TS,
        }
    }

    #[test]
    fn quiet_active_notice_is_proposed_contained() {
        let v = view(Some(NoticeStatus::Active), CaseStatus::Published);
        let cw = CaseWatch::default();
        assert!(propose(&v, &cw, &[], CASE_TS + 13 * DAY, 14).is_none());
        let (key, line) = propose(&v, &cw, &[], CASE_TS + 15 * DAY, 14).unwrap();
        assert_eq!(key, "contained");
        assert!(line.contains("(15 days)"), "{line}");
        assert!(
            line.contains("`swarmchase notice update p-1 --kind status --status contained`"),
            "{line}"
        );
        // A recent hit keeps it active.
        let cw = CaseWatch {
            hits: vec![CaseHit {
                id: "h".into(),
                ts: CASE_TS + 10 * DAY,
                run: "t".into(),
                reference: None,
                matched: vec!["Run tag uqtag=zz9".into()],
            }],
            ..Default::default()
        };
        assert!(propose(&v, &cw, &[], CASE_TS + 15 * DAY, 14).is_none());
        // Before publication there is no notice to mark.
        let v = view(None, CaseStatus::Reported);
        assert!(propose(&v, &CaseWatch::default(), &[], CASE_TS + 30 * DAY, 14).is_none());
    }

    #[test]
    fn new_hits_on_a_contained_or_closed_case_propose_reopen() {
        let hit = CaseHit {
            id: "h1".into(),
            ts: CASE_TS + 40 * DAY,
            run: "t".into(),
            reference: Some("https://urlquery.example/report/h1".into()),
            matched: vec!["Callback channel ntfy.sh/zz9".into()],
        };
        let now = CASE_TS + 41 * DAY;
        let v = view(Some(NoticeStatus::Contained), CaseStatus::Published);
        let (key, line) = propose(
            &v,
            &CaseWatch::default(),
            std::slice::from_ref(&hit),
            now,
            14,
        )
        .unwrap();
        assert_eq!(key, "reopen:h1");
        assert!(line.contains("propose reopen (notice contained)"), "{line}");
        assert!(
            line.contains("https://urlquery.example/report/h1"),
            "{line}"
        );
        assert!(line.contains("ntfy[.]sh/zz9`"), "{line}");
        assert!(line.contains("--kind status --status active"), "{line}");

        let v = view(None, CaseStatus::Closed);
        let (_, line) = propose(
            &v,
            &CaseWatch::default(),
            std::slice::from_ref(&hit),
            now,
            14,
        )
        .unwrap();
        assert!(line.contains("(case closed)"), "{line}");
        assert!(
            line.contains("`swarmchase case set p-1 --status open`"),
            "{line}"
        );
        assert!(!line.contains("notice update"), "{line}");

        // On an active case new hits are news, not a proposal.
        let v = view(Some(NoticeStatus::Active), CaseStatus::Published);
        let (_, line) = propose(
            &v,
            &CaseWatch::default(),
            std::slice::from_ref(&hit),
            now,
            14,
        )
        .unwrap();
        assert!(!line.contains("propose"), "{line}");
    }

    #[test]
    fn digest_says_when_current_rules_change_tiers_in_a_case() {
        // The case is pinned to a stricter edit of the bundled rules.
        let current = case::RulesText::load(None).unwrap();
        let text = current
            .text
            .replace("suggestive = 3", "suggestive = 300")
            .replace("significant = 6", "significant = 600")
            .replace("significant = true", "significant = false");
        let strict = case::RulesText {
            rules: Rules::from_toml(&text).unwrap(),
            text,
        };
        let data = case_data("rules", &strict);
        let c = case::load(&data.join("cases"), "p-1").unwrap();
        let n = case::tier_changes(&data.join("cases"), &c, &current.rules)
            .unwrap()
            .len();
        assert!(n > 0);

        let mut state = State::default();
        let mut check = || {
            monitor_cases(
                &data.join("cases"),
                &data.join("notices"),
                &[],
                &current.rules,
                &mut state,
                "t",
                CASE_TS + DAY,
                14,
            )
        };
        let r = check();
        let v = current.version();
        assert_eq!(
            r.lines,
            [format!(
                "{n} records in case `p-1` would change tier under rules {v}; run `swarmchase case rules p-1`"
            )]
        );
        assert!(r.changed);
        // The same line on the next run is not news.
        let r = check();
        assert_eq!(r.lines.len(), 1);
        assert!(!r.changed);
        std::fs::remove_dir_all(&data).unwrap();
    }
}
