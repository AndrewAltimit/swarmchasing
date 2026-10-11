//! The dashboard's overview: one JSON document built from the files a watch
//! run leaves in the data directory, for the page and for scripts.
//!
//! It reads, never writes: `LATEST`, `runs/<stamp>/` (`analysis.json`,
//! `summary.json`, `digest.md` and the per-source record files),
//! `state.json`, `labels/` and `cases/`. Every host is defanged and no
//! record URL is included. The field names are listed in
//! docs/reference/watch.md and change only with [`SCHEMA`].

use crate::health::{QUIET_RUNS, RuleRun};
use crate::review::{CLASS_FLAGGED, ReviewStore, queue, reviewed_ids, serve::group_of};
use crate::store::read_json;
use crate::util::one_line;
use crate::watch::State;
use crate::watch::digest::{Summary, capability, clean_host, short_reason, summarise};
use anyhow::Result;
use sc_collect::Kind;
use sc_core::{Analysis, ObsResult, Tier, defang_host, fmt_ts};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

/// The overview's schema name; bumped when a field changes meaning or goes.
pub const SCHEMA: &str = "swarmchase.dashboard/1";

/// How many lone records and newly hit endpoints the overview lists.
const LIST_MAX: usize = 50;
/// A latest run older than this many hours is called stale (the scheduled
/// watch runs every six hours).
const STALE_HOURS: i64 = 12;

/// What the overview is built from besides the data directory.
pub struct Inputs<'a> {
    pub data: &'a Path,
    /// Source name to its `kind`, from the watchlist, when it was readable.
    pub kinds: &'a BTreeMap<String, String>,
    /// The watch's analysis window, for the page's wording.
    pub window_days: i64,
    /// The run the admin last looked at; `None` compares with the run before
    /// the latest, as the digest does.
    pub since: Option<&'a str>,
    /// The latest run's analysis, when there is one.
    pub analysis: Option<&'a Analysis>,
    pub now: i64,
}

/// Whether `s` is a run stamp (`20261011T060000Z`), the only form a
/// requested `since` may take: it becomes part of a path.
pub fn is_stamp(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 16
        && b[8] == b'T'
        && b[15] == b'Z'
        && b.iter()
            .enumerate()
            .all(|(i, c)| matches!(i, 8 | 15) || c.is_ascii_digit())
}

fn stamp_time(s: &str) -> Option<i64> {
    chrono::NaiveDateTime::parse_from_str(s, "%Y%m%dT%H%M%SZ")
        .ok()
        .map(|t| t.and_utc().timestamp())
}

/// Run directories in `runs/`, newest first.
pub fn runs(data: &Path) -> Vec<String> {
    let mut out: Vec<String> = std::fs::read_dir(data.join("runs"))
        .into_iter()
        .flatten()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().is_dir())
        .filter_map(|e| e.file_name().to_str().map(str::to_string))
        .filter(|s| is_stamp(s))
        .collect();
    out.sort_unstable_by(|a, b| b.cmp(a));
    out
}

/// The latest run's stamp: `LATEST`, else the newest run directory.
pub fn latest(data: &Path) -> Option<String> {
    std::fs::read_to_string(data.join("LATEST"))
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| is_stamp(s))
        .or_else(|| runs(data).into_iter().next())
}

/// The latest run's analysis, if it wrote one.
pub fn load_analysis(data: &Path, stamp: &str) -> Result<Option<Analysis>> {
    read_json(&data.join("runs").join(stamp).join("analysis.json"))
}

/// A path for a command line: absolute, quoted when it holds a space.
pub fn shell_path(p: &Path) -> String {
    let abs = std::path::absolute(p).unwrap_or_else(|_| p.to_path_buf());
    let s = abs.display().to_string();
    if s.contains(char::is_whitespace) || s.contains('\'') {
        format!("\"{s}\"")
    } else {
        s
    }
}

/// Record IDs in `runs/<stamp>/<source>.ndjson`, per source.
fn run_records(data: &Path, stamp: &str) -> BTreeMap<String, BTreeSet<String>> {
    let mut out: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let Ok(rd) = std::fs::read_dir(data.join("runs").join(stamp)) else {
        return out;
    };
    for e in rd.flatten() {
        let p = e.path();
        if p.extension().and_then(|x| x.to_str()) != Some("ndjson") {
            continue;
        }
        let Some(source) = p.file_stem().and_then(|s| s.to_str()) else {
            continue;
        };
        let Ok(text) = std::fs::read_to_string(&p) else {
            continue;
        };
        let ids = out.entry(source.to_string()).or_default();
        for line in text.lines().filter(|l| !l.trim().is_empty()) {
            if let Ok(v) = serde_json::from_str::<Value>(line)
                && let Some(id) = v.get("id").and_then(Value::as_str)
            {
                ids.insert(id.to_string());
            }
        }
    }
    out
}

/// The bullet lines of one `## <title> (n)` section of a digest.
fn digest_section(text: &str, title: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut inside = false;
    for line in text.lines() {
        if let Some(h) = line.strip_prefix("## ") {
            inside = h.starts_with(title);
            continue;
        }
        if inside && let Some(item) = line.strip_prefix("- ") {
            out.push(item.to_string());
        }
    }
    out
}

/// The first `swarmchase …` command quoted in backticks in `line`.
fn command_in(line: &str) -> Option<String> {
    line.split('`')
        .skip(1)
        .step_by(2)
        .find(|s| s.starts_with("swarmchase "))
        .map(str::to_string)
}

/// `line` with its quoted `swarmchase …` commands left out (they are
/// shown on their own), and the other code spans as plain text.
fn without_commands(line: &str) -> String {
    let text: String = line
        .split('`')
        .enumerate()
        .filter(|(i, s)| i % 2 == 0 || !s.starts_with("swarmchase "))
        .map(|(_, s)| s)
        .collect();
    let text = text.split_whitespace().collect::<Vec<_>>().join(" ");
    text.trim_end_matches([':', ';', ',', ' ']).to_string()
}

/// `swarmchase case <sub>` with the data directory added, so the command
/// works from any directory.
fn with_data(cmd: &str, data: &str) -> String {
    match cmd.strip_prefix("swarmchase case ") {
        Some(rest) => format!("swarmchase case -d {data} {rest}"),
        None => cmd.to_string(),
    }
}

fn grade(g: Option<&sc_core::AgentAssessment>) -> Value {
    g.map_or(
        Value::Null,
        |g| json!({ "code": g.level.code(), "label": g.level.label() }),
    )
}

/// The run summary's leads that carry a local model's suggestion: what the
/// model said, beside the grade that bounds it. Never a label.
fn suggestions(leads: &Value) -> Value {
    let list: Vec<Value> = leads
        .as_array()
        .into_iter()
        .flatten()
        .filter(|l| l["suggestion"].is_object())
        .map(|l| {
            let grade = l["grade"].as_str().unwrap_or("");
            let allowed = grade
                .strip_prefix('L')
                .and_then(|n| n.parse::<u8>().ok())
                .is_some_and(|n| n >= 2);
            json!({
                "id": l["id"], "kind": l["kind"], "tier": l["tier"], "grade": grade,
                "label": l["suggestion"]["label"], "reason": l["suggestion"]["reason"],
                "model": l["suggestion"]["model"],
                "conflict": l["suggestion"]["label"] == "agent" && !allowed,
            })
        })
        .collect();
    Value::Array(list)
}

fn host_of(r: &ObsResult) -> String {
    let h = r.target_host.clone().unwrap_or_else(|| {
        reqwest::Url::parse(&r.obs.url)
            .ok()
            .and_then(|u| u.host_str().map(str::to_string))
            .unwrap_or_default()
    });
    defang_host(&clean_host(&h))
}

/// The baseline the "new" section compares with: a stamp and its summary.
struct Baseline {
    stamp: Option<String>,
    basis: &'static str,
    summary: Summary,
}

fn baseline(data: &Path, all: &[String], latest: &str, since: Option<&str>) -> Baseline {
    let summary_of = |s: &str| -> Option<Summary> {
        read_json(&data.join("runs").join(s).join("summary.json"))
            .ok()
            .flatten()
    };
    let (want, basis) = match since {
        Some(s) => (Some(s), "requested"),
        None => (
            all.iter().find(|s| s.as_str() < latest).map(String::as_str),
            "previous-run",
        ),
    };
    let Some(want) = want else {
        return Baseline {
            stamp: None,
            basis: "first-run",
            summary: Summary::default(),
        };
    };
    // The run asked for, or the newest kept run before it (retention may
    // have deleted it).
    for s in all.iter().filter(|s| s.as_str() <= want) {
        if let Some(summary) = summary_of(s) {
            return Baseline {
                stamp: Some(s.clone()),
                basis: if s == want { basis } else { "nearest-kept-run" },
                summary,
            };
        }
    }
    Baseline {
        stamp: None,
        basis: "before-kept-runs",
        summary: Summary::default(),
    }
}

/// The overview document.
pub fn overview(i: &Inputs) -> Result<Value> {
    let data = i.data;
    let d = shell_path(data);
    let all = runs(data);
    let latest = latest(data);
    let state: State = read_json(&data.join("state.json"))?.unwrap_or_default();
    let mut actions: Vec<Value> = Vec::new();

    let Some(latest) = latest else {
        actions.push(json!({
            "kind": "watch",
            "title": "No watch run in this data directory yet",
            "detail": "Run the watch once; it writes state.json, the store and a run directory here.",
            "command": format!("swarmchase watch -o {d}"),
        }));
        return Ok(json!({
            "schema": SCHEMA,
            "generated": fmt_ts(i.now),
            "data_dir": d,
            "has_data": crate::store::has_data(data),
            "run": Value::Null,
            "new": Value::Null,
            "health": health(i, &state, None, &[]),
            "waiting": waiting(i, None, &state, None, &d),
            "actions": actions,
        }));
    };

    let latest_t = stamp_time(&latest).unwrap_or(0);
    let age_hours = (i.now - latest_t) / 3600;
    let digest_text =
        std::fs::read_to_string(data.join("runs").join(&latest).join("digest.md")).ok();
    // The run summary, when the watch wrote one: its priority, model triage
    // and alerts are read as data rather than from the digest's text.
    let summary: Option<Value> = std::fs::read_to_string(
        data.join("runs")
            .join(&latest)
            .join(crate::watch::run_summary::FILE),
    )
    .ok()
    .and_then(|t| serde_json::from_str(&t).ok())
    .filter(|v: &Value| v["schema"] == crate::watch::run_summary::SCHEMA);
    let by_source = run_records(data, &latest);
    let base = baseline(data, &all, &latest, i.since);

    // Records collected by runs after the baseline, up to the latest.
    let mut new_ids = BTreeSet::new();
    for s in all
        .iter()
        .filter(|s| s.as_str() <= latest.as_str())
        .filter(|s| base.stamp.as_deref().is_none_or(|b| s.as_str() > b))
    {
        for ids in run_records(data, s).into_values() {
            new_ids.extend(ids);
        }
    }

    let run = json!({
        "latest": latest,
        "latest_time": fmt_ts(latest_t),
        "age_hours": age_hours,
        "stale": age_hours >= STALE_HOURS,
        "runs": all.iter().take(30).collect::<Vec<_>>(),
        "window_days": i.window_days,
        "rules_version": i.analysis.map(|a| a.rules_version.clone()),
        "records": i.analysis.map(|a| a.total),
        "flagged": i.analysis.map(|a| a.flagged),
        "has_analysis": i.analysis.is_some(),
        "digest": shell_path(&data.join("runs").join(&latest).join("digest.md")),
        "digest_command": format!("cat {}", shell_path(&data.join("runs").join(&latest).join("digest.md"))),
        "priority": summary.as_ref().map(|s| s["priority"].clone()),
        "reasons": summary.as_ref().map_or(Value::Null, |s| s["reasons"].clone()),
        "triage": summary.as_ref().map_or(Value::Null, |s| s["triage"].clone()),
        "suggestions": summary.as_ref().map_or(Value::Null, |s| suggestions(&s["leads"])),
    });
    if age_hours >= STALE_HOURS {
        actions.push(json!({
            "kind": "watch",
            "title": format!("The latest watch run is {age_hours} hours old"),
            "detail": "The scheduled watch runs every six hours; check the workflow or run it by hand.",
            "command": format!("swarmchase watch -o {d}"),
        }));
    }

    let new = i.analysis.map(|a| new_section(a, &base, &new_ids, &d));
    let health = health(
        i,
        &state,
        Some((&latest, &by_source)),
        &match summary
            .as_ref()
            .and_then(|s| s["health"]["alerts"].as_array())
        {
            Some(alerts) => alerts
                .iter()
                .filter_map(|a| a["text"].as_str().map(|t| t.replace("**", "")))
                .collect(),
            None => digest_text.as_deref().map_or(Vec::new(), |t| {
                digest_section(t, "Health")
                    .iter()
                    .map(|l| l.replace("**", ""))
                    .collect()
            }),
        },
    );
    for s in health["sources"].as_array().into_iter().flatten() {
        if s["status"] == "failing" {
            actions.push(json!({
                "kind": "health",
                "title": format!("Source {} is failing", s["name"].as_str().unwrap_or("")),
                "detail": format!("{} ({} runs in a row). Lost meanwhile: {}.", s["reason"].as_str().unwrap_or("error"), s["errors_in_row"], s["lost"].as_str().unwrap_or("its records")),
                "command": format!("swarmchase watch -o {d}"),
            }));
        }
    }
    let mut drifting: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for x in health["drift"].as_array().into_iter().flatten() {
        drifting
            .entry(x["source"].as_str().unwrap_or(""))
            .or_default()
            .push(x["rule"].as_str().unwrap_or(""));
    }
    for (src, rules) in drifting {
        actions.push(json!({
            "kind": "drift",
            "title": format!("{} rule(s) drift on {src}", rules.len()),
            "detail": format!("Fired well above their baseline on this run's new records: {}. Look at what they matched before trusting their leads.", rules.join(", ")),
            "command": format!("swarmchase scan {}", shell_path(&data.join("runs").join(&latest).join(format!("{src}.ndjson")))),
        }));
    }
    if let Some(n) = &new {
        let c = n["clusters"].as_array().map_or(0, Vec::len);
        let l = n["lone_total"].as_u64().unwrap_or(0);
        if c + l as usize > 0 {
            actions.push(json!({
                "kind": "new",
                "title": format!("{c} new or escalated cluster(s), {l} new lone significant record(s)"),
                "detail": "Label them on the review page; open a case from a cluster with its own command below.",
                "command": format!("swarmchase review --serve -d {d}"),
            }));
        }
    }
    let waiting = waiting(i, i.analysis, &state, base.stamp.as_deref(), &d);
    let unreviewed = waiting["review"]["unreviewed"].as_u64().unwrap_or(0);
    if unreviewed > 0
        && new.as_ref().is_none_or(|n| {
            n["clusters"].as_array().is_none_or(Vec::is_empty) && n["lone_total"] == 0
        })
    {
        actions.push(json!({
            "kind": "review",
            "title": format!("{unreviewed} lead(s) wait for a label"),
            "detail": format!("{} group(s) on the review page.", waiting["review"]["groups"]),
            "command": waiting["review"]["command"],
        }));
    }
    for l in digest_text
        .as_deref()
        .map_or(Vec::new(), |t| digest_section(t, "Case status"))
    {
        if let Some(cmd) = command_in(&l) {
            actions.push(json!({
                "kind": "case-proposal",
                "title": "The watch proposes a case change",
                "detail": l,
                "command": with_data(&cmd, &d),
            }));
        }
    }
    for c in waiting["cases"].as_array().into_iter().flatten() {
        if let Some(n) = c["needs"].as_array().and_then(|n| n.first()) {
            actions.push(json!({
                "kind": "case",
                "title": format!("Case {} has {} open item(s)", c["id"].as_str().unwrap_or(""), c["needs"].as_array().map_or(0, Vec::len)),
                "detail": n["text"],
                "command": n["command"],
            }));
        }
    }

    Ok(json!({
        "schema": SCHEMA,
        "generated": fmt_ts(i.now),
        "data_dir": d,
        "has_data": true,
        "run": run,
        "since": { "stamp": base.stamp, "basis": base.basis, "requested": i.since },
        "new": new,
        "health": health,
        "waiting": waiting,
        "actions": actions,
    }))
}

/// New and escalated clusters above noise, and lone significant records
/// collected since the baseline.
fn new_section(a: &Analysis, base: &Baseline, new_ids: &BTreeSet<String>, d: &str) -> Value {
    let next = summarise(a, &base.summary, String::new());
    // Summaries key clusters by their earliest record; find each in `a`.
    let mut by_first: BTreeMap<&str, usize> = BTreeMap::new();
    for (ci, c) in a.clusters.iter().enumerate() {
        if let Some(first) = c
            .members
            .iter()
            .map(|&m| &a.results[m].obs)
            .min_by(|x, y| x.ts.cmp(&y.ts).then_with(|| x.id.cmp(&y.id)))
        {
            by_first.insert(first.id.as_str(), ci);
        }
    }
    let mut clusters = Vec::new();
    for (k, s) in &next.clusters {
        if s.tier < Tier::Suggestive {
            continue;
        }
        let change = match base.summary.clusters.get(k) {
            None => ("new", None),
            Some(p) if s.tier > p.tier => ("escalated", Some(p.tier.label())),
            _ => continue,
        };
        let c = by_first.get(k.as_str()).map(|&ci| &a.clusters[ci]);
        let fresh = c.map_or(0, |c| {
            c.members
                .iter()
                .filter(|&&m| new_ids.contains(&a.results[m].obs.id))
                .count()
        });
        clusters.push((
            s.tier,
            c.map(|c| c.agent.level),
            s.score,
            json!({
                "key": k,
                "id": s.id,
                "cluster_key": s.key,
                "change": change.0,
                "from_tier": change.1,
                "tier": s.tier.label(),
                "grade": grade(c.map(|c| &c.agent)),
                "score": s.score,
                "records": s.records,
                "new_records": fresh,
                "start": fmt_ts(s.start),
                "end": fmt_ts(s.end),
                "targets": s.targets.iter().map(|h| defang_host(&clean_host(h))).collect::<Vec<_>>(),
                "rules": s.rules,
                "open_case": format!(
                    "swarmchase case -d {d} new <case-id> --title \"…\" --cluster {}",
                    if s.key.is_empty() { &s.id } else { &s.key }
                ),
            }),
        ));
    }
    clusters.sort_by_key(|c| std::cmp::Reverse((c.0, c.1, c.2)));

    let mut lone: Vec<&ObsResult> = a
        .results
        .iter()
        .filter(|r| r.tier == Tier::Significant && r.cluster.is_none())
        .filter(|r| new_ids.contains(&r.obs.id))
        .collect();
    lone.sort_by(|x, y| y.score.cmp(&x.score).then(y.obs.ts.cmp(&x.obs.ts)));
    let mut seen = BTreeSet::new();
    lone.retain(|r| seen.insert(r.obs.id.as_str()));
    let lone_json: Vec<Value> = lone
        .iter()
        .take(LIST_MAX)
        .map(|r| {
            let rules: BTreeSet<&str> = r.hits.iter().map(|h| h.rule_id.as_str()).collect();
            json!({
                "id": r.obs.id,
                "tier": r.tier.label(),
                "grade": grade(r.agent.as_ref()),
                "score": r.score,
                "host": host_of(r),
                "rules": rules,
                "source": r.obs.source,
                "time": fmt_ts(r.obs.ts),
            })
        })
        .collect();

    let mut by_tier: BTreeMap<&str, usize> = BTreeMap::new();
    let mut by_grade: BTreeMap<&str, usize> = BTreeMap::new();
    for (t, g, _, _) in &clusters {
        *by_tier.entry(t.label()).or_default() += 1;
        if let Some(g) = g {
            *by_grade.entry(g.code()).or_default() += 1;
        }
    }
    let mut endpoints: Vec<(&String, i64)> = next
        .endpoints
        .iter()
        .filter(|(h, _)| !base.summary.endpoints.contains_key(*h))
        .map(|(h, e)| (h, e.last_seen))
        .collect();
    endpoints.sort_by_key(|e| std::cmp::Reverse(e.1));
    json!({
        "records": new_ids.len(),
        "clusters": clusters.into_iter().map(|c| c.3).collect::<Vec<_>>(),
        "clusters_by_tier": by_tier,
        "clusters_by_grade": by_grade,
        "lone": lone_json,
        "lone_total": lone.len(),
        "endpoints": endpoints.iter().take(LIST_MAX).map(|(h, _)| defang_host(&clean_host(h))).collect::<Vec<_>>(),
        "endpoints_total": endpoints.len(),
    })
}

/// Each source's standing from `state.json`, the latest digest's health
/// alerts, and rule drift on the latest run.
fn health(
    i: &Inputs,
    state: &State,
    latest: Option<(&str, &BTreeMap<String, BTreeSet<String>>)>,
    alerts: &[String],
) -> Value {
    let mut names: BTreeSet<&str> = state.sources.keys().map(String::as_str).collect();
    names.extend(i.kinds.keys().map(String::as_str));
    let mut sources = Vec::new();
    let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
    let mut submit_ran = false;
    for name in names {
        let kind = i.kinds.get(name).map(String::as_str);
        let parsed = kind.and_then(|k| k.parse::<Kind>().ok());
        let st = state.sources.get(name);
        let h = st.map(|s| s.health.clone()).unwrap_or_default();
        let ran_latest =
            latest.is_some_and(|(l, _)| st.and_then(|s| s.last_run.as_deref()) == Some(l));
        let (status, reason) = match st {
            None => ("never-run", None),
            Some(_) if h.skipped_runs > 0 => (
                "skipped",
                Some(match parsed.and_then(Kind::key_env) {
                    Some(env) => format!("{env} not set"),
                    None => "skipped".into(),
                }),
            ),
            Some(s) if h.errors_in_row > 0 => (
                "failing",
                Some(s.last_error.as_deref().map_or("error".into(), |e| {
                    short_reason(&anyhow::anyhow!(e.to_string()))
                })),
            ),
            Some(_) if h.empty_runs >= QUIET_RUNS => ("quiet", None),
            Some(s) if s.pending.is_some() => ("catching-up", None),
            Some(_) => ("ok", None),
        };
        if ran_latest && status != "failing" && parsed.is_some_and(Kind::submit_time) {
            submit_ran = true;
        }
        *counts.entry(status).or_default() += 1;
        let new_latest = latest
            .and_then(|(_, by)| by.get(name))
            .map_or(0, BTreeSet::len);
        sources.push(json!({
            "name": name,
            "kind": kind,
            "status": status,
            "reason": reason,
            "last_run": st.and_then(|s| s.last_run.clone()),
            "ran_latest": ran_latest,
            "new_latest": new_latest,
            "pulled": h.pulled,
            "errors_in_row": h.errors_in_row,
            "empty_runs": h.empty_runs,
            "skipped_runs": h.skipped_runs,
            "ever_pulled": h.ever_pulled,
            "pending": st.is_some_and(|s| s.pending.is_some()),
            "lost": matches!(status, "failing" | "skipped").then(|| capability(kind.unwrap_or(""))),
        }));
    }
    let rank = |s: &Value| match s["status"].as_str() {
        Some("failing") => 0,
        Some("skipped") => 1,
        Some("quiet") => 2,
        Some("catching-up") => 3,
        Some("ok") => 4,
        _ => 5,
    };
    sources.sort_by_key(|s| rank(s));
    let drift = match (i.analysis, latest) {
        (Some(a), Some((_, by))) => drift(a, state, by),
        _ => Vec::new(),
    };
    let submit_known = i
        .kinds
        .values()
        .any(|k| k.parse::<Kind>().is_ok_and(Kind::submit_time));
    let level = if counts.get("failing").copied().unwrap_or(0) > 0 || !drift.is_empty() {
        "alert"
    } else if !alerts.is_empty() || counts.contains_key("skipped") || counts.contains_key("quiet") {
        "warn"
    } else {
        "ok"
    };
    json!({
        "level": level,
        "counts": counts,
        "sources": sources,
        "alerts": alerts,
        "drift": drift,
        "drift_rules_version": state.rules.rules_version,
        "submit_time_ran": if submit_known { Value::Bool(submit_ran) } else { Value::Null },
        "watchlist_read": !i.kinds.is_empty(),
    })
}

/// Rule drift on the latest run's new records, recomputed from the
/// baseline in `state.json`: each source's last kept run is the latest
/// run's when its counts match, and is compared with the runs kept before it.
fn drift(a: &Analysis, state: &State, by: &BTreeMap<String, BTreeSet<String>>) -> Vec<Value> {
    if state.rules.rules_version != a.rules_version {
        return Vec::new();
    }
    let mut history = state.rules.clone();
    let mut runs = BTreeMap::new();
    for (source, ids) in by {
        let run = RuleRun::from_analysis(a, ids);
        let Some(h) = history.sources.get_mut(source) else {
            continue;
        };
        if h.last() == Some(&run) {
            h.pop();
            runs.insert(source.clone(), run);
        }
    }
    let pct = |h: usize, n: usize| (1000.0 * h as f64 / n.max(1) as f64).round() / 10.0;
    let version = history.rules_version.clone();
    history
        .observe(&version, runs)
        .0
        .into_iter()
        .map(|d| {
            json!({
                "source": d.source,
                "rule": d.rule,
                "hits": d.hits,
                "records": d.records,
                "rate_pct": pct(d.hits, d.records),
                "baseline_hits": d.baseline_hits,
                "baseline_records": d.baseline_records,
                "baseline_rate_pct": pct(d.baseline_hits, d.baseline_records),
                "line": d.line(),
            })
        })
        .collect()
}

/// What waits on the admin: the review queue and open cases.
fn waiting(i: &Inputs, a: Option<&Analysis>, state: &State, since: Option<&str>, d: &str) -> Value {
    json!({
        "review": a.map_or(Value::Null, |a| review(i.data, a, d)),
        "cases": cases(i, state, since, d),
    })
}

fn review(data: &Path, a: &Analysis, d: &str) -> Value {
    let labels = data.join("labels");
    let store = match ReviewStore::open(ReviewStore::path_in(data)) {
        Ok(s) => s,
        Err(e) => return json!({ "error": one_line(&format!("{e:#}"), 200) }),
    };
    let done: BTreeSet<String> = store.entries.keys().cloned().collect();
    let items = queue(a, &done, Tier::Suggestive, 0);
    let groups: BTreeSet<String> = items.iter().map(|it| group_of(a, it.idx).0).collect();
    let mut by_tier: BTreeMap<&str, usize> = BTreeMap::new();
    for it in &items {
        *by_tier.entry(a.results[it.idx].tier.label()).or_default() += 1;
    }
    // Progress over the flagged records of the latest analysis.
    let mut window: BTreeMap<&str, usize> = BTreeMap::new();
    let mut flagged = BTreeSet::new();
    for r in a
        .results
        .iter()
        .filter(|r| r.score > 0 && r.tier >= Tier::Suggestive)
    {
        if flagged.insert(r.obs.id.as_str())
            && let Some(v) = store.entries.get(&r.obs.id)
        {
            *window.entry(v.label.as_str()).or_default() += 1;
        }
    }
    let mut labelled: BTreeMap<&str, usize> = BTreeMap::new();
    for v in store.entries.values() {
        *labelled.entry(v.label.as_str()).or_default() += 1;
    }
    let suggestions = crate::review::hosted::load_suggestions(&labels, a)
        .map(|l| {
            items
                .iter()
                .filter(|it| l.by_id.contains_key(&a.results[it.idx].obs.id))
                .count()
        })
        .unwrap_or(0);
    let any = reviewed_ids(&labels).map_or(0, |s| s.len());
    json!({
        "unreviewed": items.len(),
        "groups": groups.len(),
        "unreviewed_by_tier": by_tier,
        "with_suggestion": suggestions,
        "flagged_in_window": flagged.len(),
        "labelled_in_window": window,
        "labelled_total": labelled,
        "reviewed_any_labeller": any,
        "file": shell_path(&ReviewStore::path_in(data)),
        "class": CLASS_FLAGGED,
        "command": format!("swarmchase review --serve -d {d}"),
        "stats_command": format!("swarmchase review --stats -d {d}"),
    })
}

fn cases(i: &Inputs, state: &State, since: Option<&str>, d: &str) -> Value {
    let root = i.data.join("cases");
    if !root.is_dir() {
        return json!([]);
    }
    let all = match crate::case::all(&root) {
        Ok(c) => c,
        Err(e) => return json!([{ "error": one_line(&format!("{e:#}"), 200) }]),
    };
    let mut out = Vec::new();
    for c in all
        .iter()
        .filter(|c| c.status != crate::case::CaseStatus::Closed)
    {
        let clock = sc_case::lead::clock(c);
        let mut clock_lines = Vec::new();
        let _ = crate::case::status::clocks(&root, c, i.now, &mut clock_lines);
        let clock_lines: Vec<String> = String::from_utf8_lossy(&clock_lines)
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .map(str::to_string)
            .collect();
        let needs = needs(&root, &c.id, d);
        let hits = state.cases.get(&c.id).map(|w| &w.hits[..]).unwrap_or(&[]);
        let new_hits = hits
            .iter()
            .filter(|h| since.is_none_or(|s| h.run.as_str() > s))
            .count();
        out.push(json!({
            "id": c.id,
            "title": c.title,
            "status": c.status.label(),
            "notice": c.notice.label(),
            "opened": c.opened,
            "admin": c.admin,
            "notice_added": c.notice_added(),
            "notice_not_before": (!c.notice_added()).then(|| clock.not_before.map(fmt_ts)).flatten(),
            "parties_missing": clock.missing.len(),
            "naming_ready": sc_case::naming::ready(c, i.now).len(),
            "clock": clock_lines,
            "watch_hits": hits.len(),
            "watch_hits_new": new_hits,
            "needs": needs,
            "status_command": format!("swarmchase case -d {d} status {}", c.id),
        }));
    }
    Value::Array(out)
}

/// The "Needs" lines `case status` prints, each with its command.
fn needs(root: &Path, id: &str, d: &str) -> Vec<Value> {
    let mut buf = Vec::new();
    if let Err(e) = crate::case::status::status(root, id, &mut buf) {
        return vec![
            json!({ "text": format!("status failed: {}", one_line(&format!("{e:#}"), 200)), "command": Value::Null }),
        ];
    }
    let text = String::from_utf8_lossy(&buf);
    let Some((_, rest)) = text.split_once("\nNeeds\n") else {
        return Vec::new();
    };
    rest.lines()
        .filter_map(|l| l.trim_start().strip_prefix("- "))
        .map(|l| {
            json!({
                "text": without_commands(l),
                "command": command_in(l).map(|c| with_data(&c, d)),
            })
        })
        .collect()
}
