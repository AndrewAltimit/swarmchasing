//! The overview and the page's endpoints over a synthetic data directory
//! written the way a watch run writes one.

use super::*;
use crate::health::RuleRun;
use crate::localui::Request;
use crate::review::{CLASS_FLAGGED, Review, ReviewStore};
use crate::watch::cases::CaseReport;
use crate::watch::digest::{DigestInput, Health, SourceReport, Summary, digest, summarise};
use sc_core::{Observation, Rules, analyze};
use serde_json::{Value, json};
use std::collections::BTreeSet;

const RUN1: &str = "20261010T060000Z";
const RUN2: &str = "20261011T060000Z";
/// An hour after the second run.
const NOW: i64 = 1_791_694_800;
const CASE: &str = "2026-10-portal-sqli";

fn ts(stamp: &str) -> i64 {
    chrono::NaiveDateTime::parse_from_str(stamp, "%Y%m%dT%H%M%SZ")
        .unwrap()
        .and_utc()
        .timestamp()
}

fn rec(id: &str, source: &str, ts: i64, url: &str) -> Observation {
    Observation {
        id: id.into(),
        source: source.into(),
        ts,
        url: url.into(),
        ..Default::default()
    }
}

/// Synthetic records for each run: an SQL injection run through a relay
/// before the first run, then an exfiltration run to a request inbox, a
/// lone script injection and plain relay captures before the second.
fn records(run: &str) -> Vec<Observation> {
    let inbox = "https://webhook.site/0b6c1f0e-1111-4c2a-9a55-3f2e1d0c9b8a";
    let t = ts(run) - 6 * 3600;
    let mut out = Vec::new();
    if run == RUN1 {
        for i in 0..4 {
            out.push(rec(
                &format!("a{i}"),
                "wayback-jina",
                t + i * 40,
                &format!("https://r.jina.ai/https://portal.example.gov/q?id={i}%20UNION%20SELECT%201&uqtag=zz9"),
            ));
        }
        for i in 0..30 {
            out.push(rec(
                &format!("p1-{i}"),
                "wayback-jina",
                t - 20_000 + i * 600,
                &format!("https://r.jina.ai/https://news.example/story/{i}"),
            ));
        }
        return out;
    }
    for i in 0..6 {
        out.push(rec(
            &format!("b{i}"),
            "wayback-jina",
            t + i * 30,
            &format!("https://r.jina.ai/https://data.portal.example/p/{i}?q=1%20OR%201=1&uqtag=a1b2&cb={inbox}"),
        ));
    }
    out.push(rec(
        "x1",
        "wayback-jina",
        t - 90_000,
        "https://r.jina.ai/https://shop.example/?q=<script>alert(document.cookie)</script>&next=1%20UNION%20SELECT%20password%20FROM%20users",
    ));
    for i in 0..24 {
        out.push(rec(
            &format!("p2-{i}"),
            "wayback-jina",
            t - 40_000 + i * 900,
            &format!("https://r.jina.ai/https://blog.example/post/{i}"),
        ));
    }
    out
}

fn write_run(
    data: &Path,
    run: &str,
    all: &mut Vec<Observation>,
    prev: &Summary,
) -> (Analysis, Summary) {
    let rules = Rules::default_rules();
    let dir = data.join("runs").join(run);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::create_dir_all(data.join("store")).unwrap();
    let fresh = records(run);
    let mut by: BTreeMap<String, Vec<Observation>> = BTreeMap::new();
    for o in &fresh {
        by.entry(o.source.clone()).or_default().push(o.clone());
    }
    for (s, obs) in &by {
        let nd = crate::store::to_ndjson(obs).unwrap();
        std::fs::write(dir.join(format!("{s}.ndjson")), &nd).unwrap();
        crate::store::append(&data.join("store").join(format!("{s}.ndjson")), &nd).unwrap();
    }
    let new_ids: BTreeSet<String> = fresh.iter().map(|o| o.id.clone()).collect();
    all.extend(fresh);
    let a = analyze(all.clone(), &rules);
    let next = summarise(&a, prev, run.into());
    let mut fail = SourceReport::new("urlquery-scan", "urlquery");
    fail.error = Some("HTTP 503 after 3 attempts".into());
    let health = Health {
        sources: vec![SourceReport::new("wayback-jina", "wayback"), fail],
        alerts: if run == RUN2 {
            vec!["`urlquery-scan` has failed 2 runs in a row (HTTP 503 after 3 attempts)".into()]
        } else {
            Vec::new()
        },
        notes: Vec::new(),
    };
    let d = digest(&DigestInput {
        stamp: run,
        analysis: &a,
        prev,
        next: &next,
        new_ids: &new_ids,
        health: &health,
        bursts: &[],
        cases: &CaseReport::default(),
        window_days: 30,
        leads: &[],
        triage: &crate::watch::triage::TriageReport::default(),
        priority: &crate::watch::priority::assess(&[], &health.alerts, &[]),
    });
    std::fs::write(dir.join("digest.md"), d.text).unwrap();
    std::fs::write(
        dir.join("analysis.json"),
        serde_json::to_string(&a).unwrap(),
    )
    .unwrap();
    crate::store::write_json(&dir.join("summary.json"), &next).unwrap();
    crate::store::write_json(&data.join("summary.json"), &next).unwrap();
    std::fs::write(data.join("LATEST"), run).unwrap();
    (a, next)
}

/// Source kinds, as the watchlist would give them.
fn kinds() -> BTreeMap<String, String> {
    [
        ("wayback-jina", "wayback"),
        ("urlquery-scan", "urlquery"),
        ("urlscan-scan", "urlscan"),
        ("ct-relays", "ctlog"),
    ]
    .into_iter()
    .map(|(a, b)| (a.to_string(), b.to_string()))
    .collect()
}

/// A data directory with two watch runs, source states (healthy, failing,
/// skipped, quiet), a drifting rule, two labels and an open case.
pub fn write_fixture(data: &Path) {
    let _ = std::fs::remove_dir_all(data);
    std::fs::create_dir_all(data).unwrap();
    let mut all = Vec::new();
    let (a1, s1) = write_run(data, RUN1, &mut all, &Summary::default());
    let (a2, _) = write_run(data, RUN2, &mut all, &s1);

    // The relay's runs before: no SQL injection on 50 records a run, then
    // this run's counts, so the injection rules drift.
    let ids: BTreeSet<String> = records(RUN2)
        .into_iter()
        .filter(|o| o.source == "wayback-jina")
        .map(|o| o.id)
        .collect();
    let last = RuleRun::from_analysis(&a2, &ids);
    let relay: BTreeMap<String, usize> = last
        .hits
        .iter()
        .filter(|&(_, &n)| n >= ids.len() - 1)
        .map(|(k, _)| (k.clone(), 50))
        .collect();
    let base = json!({ "records": 50, "hits": relay });
    let state = json!({
        "sources": {
            "wayback-jina": { "cursor": ts(RUN2), "last_run": RUN2,
                "health": { "pulled": [40, 35, 50, 30], "ever_pulled": true } },
            "urlquery-scan": { "last_run": RUN2,
                "last_error": "urlquery: GET https://urlquery.net/api/v1/search?q=x: HTTP 503 Service Unavailable: gave up after 3 attempts",
                "health": { "pulled": [3, 4, 2], "errors_in_row": 2, "ever_pulled": true } },
            "urlscan-scan": { "health": { "skipped_runs": 3 } },
            "ct-relays": { "last_run": RUN2, "health": { "pulled": [0, 0, 0, 0, 0], "empty_runs": 5 } },
        },
        "rules": { "rules_version": a2.rules_version,
            "sources": { "wayback-jina": [base, base, base, last] } },
        "cases": { CASE: { "hits": [
            { "id": "b0", "ts": ts(RUN2) - 3600, "run": RUN2, "matched": ["uqtag=a1b2"] },
            { "id": "a1", "ts": ts(RUN1) - 3600, "run": RUN1, "matched": ["uqtag=zz9"] },
        ] } },
    });
    crate::store::write_json(&data.join("state.json"), &state).unwrap();

    // Two labels on the first run's cluster.
    let mut store = ReviewStore::open(ReviewStore::path_in(data)).unwrap();
    for (id, label) in [("a0", "agent"), ("a1", "benign")] {
        let r = a1.results.iter().find(|r| r.obs.id == id).unwrap();
        store.entries.insert(
            id.into(),
            Review {
                record: r.obs.clone(),
                label: label.into(),
                note: None,
                class: CLASS_FLAGGED.into(),
                reviewed_at: "2026-10-10T08:00:00Z".into(),
                tier: r.tier,
                score: r.score,
                rules: r.hits.iter().map(|h| h.rule_id.clone()).collect(),
                rules_version: a1.rules_version.clone(),
                suggested: None,
                tuned: false,
            },
        );
    }
    store.save().unwrap();

    // An open case from the first run's cluster.
    let rules = crate::pinning::RulesText::load(None).unwrap();
    let recs: Vec<Observation> = records(RUN1)
        .into_iter()
        .filter(|o| o.id.starts_with('a'))
        .collect();
    crate::case::new_case(
        &data.join("cases"),
        CASE,
        "Portal SQL injection",
        recs,
        &rules,
        "2026-10-10",
    )
    .unwrap();
}

fn scratch(name: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!(
        "swarmchase-dashboard-{name}-{}",
        std::process::id()
    ));
    write_fixture(&p);
    p
}

fn app(data: &Path) -> DashboardApp {
    DashboardApp::new(data.to_path_buf(), kinds(), 30)
}

fn find<'a>(list: &'a Value, key: &str, val: &str) -> &'a Value {
    list.as_array()
        .unwrap()
        .iter()
        .find(|x| x[key] == val)
        .unwrap_or_else(|| panic!("no {key}={val} in {list}"))
}

#[test]
fn overview_answers_new_health_waiting_and_next() {
    let data = scratch("overview");
    let v = app(&data).overview(None, NOW).unwrap();
    let text = v.to_string();
    assert_eq!(v["schema"], overview::SCHEMA);
    assert_eq!(v["run"]["latest"], RUN2);
    assert_eq!(v["run"]["stale"], false);
    assert_eq!(v["since"]["stamp"], RUN1);
    assert_eq!(v["since"]["basis"], "previous-run");

    // Defanged throughout; no record URL.
    assert!(!text.contains("://"), "{text}");
    for h in [
        "portal.example",
        "shop.example",
        "r.jina.ai",
        "webhook.site",
    ] {
        assert!(!text.contains(h), "{h} not defanged");
    }

    // New: the second run's cluster, graded; the first run's is not new.
    let new = &v["new"];
    assert_eq!(new["records"], records(RUN2).len());
    let clusters = new["clusters"].as_array().unwrap();
    assert!(!clusters.is_empty(), "{new}");
    assert!(clusters.iter().all(|c| c["change"] == "new"));
    let c = &clusters[0];
    assert!(c["grade"]["code"].as_str().unwrap().starts_with('L'), "{c}");
    assert!(c["new_records"].as_u64().unwrap() > 0);
    assert!(c["targets"].to_string().contains("[.]"), "{c}");
    assert!(
        c["open_case"]
            .as_str()
            .unwrap()
            .contains(" new <case-id> --title")
    );
    assert!(
        !clusters
            .iter()
            .any(|c| c["targets"].to_string().contains("portal[.]example[.]gov"))
    );

    // Health: each source's standing, and the drift recomputed.
    let h = &v["health"];
    assert_eq!(h["level"], "alert");
    let s = |n: &str| find(&h["sources"], "name", n).clone();
    assert_eq!(s("wayback-jina")["status"], "ok");
    assert_eq!(s("wayback-jina")["new_latest"], 31);
    let uq = s("urlquery-scan");
    assert_eq!(uq["status"], "failing");
    assert_eq!(uq["reason"], "HTTP 503", "{uq}");
    assert!(uq["lost"].as_str().unwrap().contains("submit-time"));
    assert_eq!(s("urlscan-scan")["status"], "skipped");
    assert_eq!(s("urlscan-scan")["reason"], "URLSCAN_APIKEY not set");
    assert_eq!(s("ct-relays")["status"], "quiet");
    assert_eq!(h["submit_time_ran"], false);
    assert!(h["alerts"][0].as_str().unwrap().contains("urlquery-scan"));
    let drift = h["drift"].as_array().unwrap();
    assert!(!drift.is_empty(), "{h}");
    assert!(drift.iter().all(|d| d["source"] == "wayback-jina"));

    // Waiting: the queue without the two labelled records, and the case.
    let r = &v["waiting"]["review"];
    assert!(r["unreviewed"].as_u64().unwrap() > 0, "{r}");
    assert_eq!(r["labelled_total"]["agent"], 1);
    assert_eq!(r["labelled_total"]["benign"], 1);
    assert!(
        r["command"]
            .as_str()
            .unwrap()
            .starts_with("swarmchase review --serve -d ")
    );
    let case = find(&v["waiting"]["cases"], "id", CASE);
    assert_eq!(case["status"], "open");
    assert_eq!(
        (case["watch_hits"].as_u64(), case["watch_hits_new"].as_u64()),
        (Some(2), Some(1))
    );
    assert!(!case["clock"].as_array().unwrap().is_empty(), "{case}");
    let needs = case["needs"].as_array().unwrap();
    assert!(
        needs
            .iter()
            .all(|n| !n["text"].as_str().unwrap().contains("swarmchase case")),
        "the command is shown on its own: {needs:?}"
    );
    assert!(!needs.is_empty());
    assert!(
        needs
            .iter()
            .filter_map(|n| n["command"].as_str())
            .all(|c| c.starts_with("swarmchase case -d ")),
        "{needs:?}"
    );

    // Next steps, health first, each with a command.
    let actions = v["actions"].as_array().unwrap();
    let kinds: Vec<&str> = actions
        .iter()
        .map(|a| a["kind"].as_str().unwrap())
        .collect();
    assert_eq!(kinds[0], "health", "{kinds:?}");
    assert!(kinds.contains(&"drift") && kinds.contains(&"new") && kinds.contains(&"case"));
    assert!(
        actions.iter().all(|a| a["command"].is_string()),
        "{actions:?}"
    );
    let _ = std::fs::remove_dir_all(data);
}

#[test]
fn since_moves_the_baseline() {
    let data = scratch("since");
    let mut app = app(&data);
    let v = app.overview(Some(RUN2), NOW).unwrap();
    assert_eq!(v["since"]["basis"], "requested");
    assert_eq!(v["new"]["records"], 0);
    assert!(v["new"]["clusters"].as_array().unwrap().is_empty());
    assert_eq!(
        find(&v["waiting"]["cases"], "id", CASE)["watch_hits_new"],
        0
    );

    // Older than every kept run: everything kept is new.
    let v = app.overview(Some("20260101T000000Z"), NOW).unwrap();
    assert_eq!(v["since"]["basis"], "before-kept-runs");
    assert_eq!(
        v["new"]["records"],
        records(RUN1).len() + records(RUN2).len()
    );
    // Between runs: the nearest kept run before it.
    let v = app.overview(Some("20261010T120000Z"), NOW).unwrap();
    assert_eq!(v["since"]["basis"], "nearest-kept-run");
    assert_eq!(v["since"]["stamp"], RUN1);

    // A stale latest run is an action.
    let v = app.overview(None, NOW + 20 * 3600).unwrap();
    assert_eq!(v["run"]["stale"], true);
    assert_eq!(v["actions"][0]["kind"], "watch");
    let _ = std::fs::remove_dir_all(data);
}

#[test]
fn the_run_summary_gives_priority_alerts_and_model_suggestions() {
    let data = scratch("summary");
    let v = app(&data).overview(None, NOW).unwrap();
    assert!(v["run"]["priority"].is_null(), "no run.json, no priority");

    let summary = serde_json::json!({
        "schema": crate::watch::run_summary::SCHEMA,
        "stamp": RUN2,
        "priority": "high",
        "reasons": [{"level": "high", "kind": "lead", "text": "new significant cluster C1 at L2"}],
        "triage": {"enabled": true, "model": "local", "asked": 2, "answered": 2},
        "health": {"alerts": [{"kind": "source_failed", "source": "s", "text": "**s** failed: HTTP 503"}]},
        "leads": [
            {"id": "C1", "kind": "cluster", "tier": "significant", "grade": "L2",
             "suggestion": {"label": "agent", "reason": "relay and residue", "model": "local"}},
            {"id": "r:9", "kind": "record", "tier": "significant", "grade": "L0",
             "suggestion": {"label": "agent", "reason": "payload", "model": "local"}},
            {"id": "r:10", "kind": "record", "tier": "significant", "grade": "L1"},
        ],
    });
    std::fs::write(
        data.join("runs")
            .join(RUN2)
            .join(crate::watch::run_summary::FILE),
        summary.to_string(),
    )
    .unwrap();
    let v = app(&data).overview(None, NOW).unwrap();
    assert_eq!(v["run"]["priority"], "high");
    assert_eq!(v["run"]["reasons"][0]["kind"], "lead");
    assert_eq!(v["health"]["alerts"][0], "s failed: HTTP 503");
    let s = v["run"]["suggestions"].as_array().unwrap();
    assert_eq!(s.len(), 2, "only leads with a suggestion");
    assert_eq!(
        find(&v["run"]["suggestions"], "id", "C1")["conflict"],
        false
    );
    assert_eq!(
        find(&v["run"]["suggestions"], "id", "r:9")["conflict"],
        true,
        "agent below L2 is against the labelling rule"
    );
    let _ = std::fs::remove_dir_all(data);
}

#[test]
fn an_empty_data_directory_says_how_to_start() {
    let data =
        std::env::temp_dir().join(format!("swarmchase-dashboard-empty-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&data);
    let v = app(&data).overview(None, NOW).unwrap();
    assert!(v["run"].is_null());
    assert_eq!(v["has_data"], false);
    assert_eq!(v["actions"][0]["kind"], "watch");
    assert!(
        v["actions"][0]["command"]
            .as_str()
            .unwrap()
            .starts_with("swarmchase watch -o ")
    );
    assert_eq!(
        find(&v["health"]["sources"], "name", "ct-relays")["status"],
        "never-run"
    );
}

fn get(s: &mut crate::localui::Server<DashboardApp>, path: &str) -> (u16, Value) {
    let req = Request {
        method: "GET".into(),
        path: path.into(),
        headers: vec![("host".into(), format!("127.0.0.1:{}", s.port))],
        body: Vec::new(),
    };
    let r = s.handle(&req, "t");
    let body = if r.ctype == "application/json" {
        serde_json::from_slice(&r.body).unwrap()
    } else {
        Value::Null
    };
    (r.status, body)
}

#[test]
fn endpoints_are_read_only_and_check_stamps() {
    let data = scratch("endpoints");
    let mut s = crate::localui::Server::new(app(&data), 8790);
    let (st, v) = get(&mut s, "/api/overview");
    assert_eq!(st, 200);
    assert_eq!(v["run"]["latest"], RUN2);
    let (st, v) = get(&mut s, &format!("/api/overview/since/{RUN2}"));
    assert_eq!((st, v["since"]["basis"].as_str()), (200, Some("requested")));
    assert_eq!(get(&mut s, "/api/overview/since/..%2F..%2Fx").0, 400);
    assert_eq!(get(&mut s, "/api/overview/since/../../etc").0, 400);
    let (st, v) = get(&mut s, &format!("/api/digest/{RUN2}"));
    assert_eq!(st, 200);
    assert!(v["text"].as_str().unwrap().starts_with("# Watch digest"));
    assert_eq!(get(&mut s, "/api/digest/20990101T000000Z").0, 404);
    assert_eq!(get(&mut s, "/api/digest/../state.json").0, 400);
    assert_eq!(get(&mut s, "/api/nope").0, 404);
    assert_eq!(get(&mut s, "/").0, 200);
    let tok = s.token().to_string();
    let host = format!("127.0.0.1:{}", s.port);
    let post = Request {
        method: "POST".into(),
        path: "/api/overview".into(),
        headers: vec![("host".into(), host), ("x-page-token".into(), tok)],
        body: b"{}".to_vec(),
    };
    assert_eq!(s.handle(&post, "t").status, 404, "nothing to write");
    let _ = std::fs::remove_dir_all(data);
}

/// Writes the fixture to `SWARMCHASE_DASHBOARD_FIXTURE`, for looking at the
/// page by hand: `cargo test -p swarmchase dashboard::tests::fixture --
/// --ignored`, then `swarmchase dashboard -d <dir>`.
#[test]
#[ignore]
fn fixture() {
    let dir = std::env::var("SWARMCHASE_DASHBOARD_FIXTURE").expect("SWARMCHASE_DASHBOARD_FIXTURE");
    write_fixture(Path::new(&dir));
}
