//! The admin workflow end to end, offline: a watch over a fixture store,
//! review from scripted answers, a case opened from a cluster key, endpoint
//! decisions, a hand-added contact, a draft with its bundle, verification,
//! the notice draft, `notice add` into a scratch notices directory, and the
//! notice lint. No step touches the network.

use crate::common::{Run, Scratch, ok, run};
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

const DAY: i64 = 86_400;

/// The agent-labelled records of a sample file, moved in time so the newest
/// is two days old, keeping their spacing; those older than 20 days are
/// dropped so every watch and review window holds the same set.
fn fixture_records(now: i64) -> Vec<serde_json::Value> {
    let path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../samples/eval/published-patterns.ndjson");
    let mut recs: Vec<serde_json::Value> = std::fs::read_to_string(path)
        .unwrap()
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).unwrap())
        .filter(|v: &serde_json::Value| v["label"] == "agent")
        .collect();
    let ts = |v: &serde_json::Value| {
        chrono::DateTime::parse_from_rfc3339(v["ts"].as_str().unwrap())
            .unwrap()
            .timestamp()
    };
    let newest = recs.iter().map(ts).max().unwrap();
    let shift = now - 2 * DAY - newest;
    for v in recs.iter_mut() {
        let t = ts(v) + shift;
        v["ts"] = serde_json::json!(t);
        let o = v.as_object_mut().unwrap();
        for k in ["label", "class", "cite", "synthetic", "run"] {
            o.remove(k);
        }
    }
    recs.retain(|v| v["ts"].as_i64().unwrap() > now - 20 * DAY);
    recs
}

fn ndjson(recs: &[serde_json::Value]) -> String {
    recs.iter().map(|v| format!("{v}\n")).collect()
}

/// Run `swarmchase` with `input` on stdin.
fn with_stdin(dir: &Path, args: &[&str], input: &str) -> Run {
    let mut child = Command::new(env!("CARGO_BIN_EXE_swarmchase"))
        .args(args)
        .current_dir(dir)
        .env_remove("SWARMCHASE_DATA")
        .env_remove("URLQUERY_APIKEY")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap();
    child.wait_with_output().unwrap().into()
}

fn hosts(case_toml: &str) -> Vec<String> {
    case_toml
        .lines()
        .filter_map(|l| l.strip_prefix("host = \""))
        .map(|h| h.trim_end_matches('"').to_string())
        .collect()
}

#[test]
fn from_a_watch_digest_to_a_linted_notice() {
    let s = Scratch::new("workflow");
    let dir = s.path();
    let now = chrono::Utc::now().timestamp();
    let recs = fixture_records(now);
    assert!(recs.len() >= 4, "fixture too small: {}", recs.len());
    std::fs::create_dir_all(dir.join("data/store")).unwrap();
    std::fs::write(dir.join("data/store/fixture.ndjson"), ndjson(&recs)).unwrap();
    std::fs::write(dir.join("records.ndjson"), ndjson(&recs)).unwrap();

    // 1. Watch: the only source needs a key that is not set, so nothing is
    // pulled; the run still analyses the store and writes its digest.
    std::fs::write(
        dir.join("watchlist.toml"),
        "[[source]]\nname = \"uq\"\nkind = \"urlquery\"\npattern = \"r.jina.ai\"\n",
    )
    .unwrap();
    let r = run(dir, &["watch", "watchlist.toml", "--out", "data"]);
    assert!(r.stderr.contains("no source could run"), "{}", r.stderr);
    let runs: Vec<_> = std::fs::read_dir(dir.join("data/runs"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    let digest = std::fs::read_to_string(runs[0].join("digest.md")).unwrap();
    assert!(digest.contains("cluster"), "{digest}");

    // 2. Review: label the first lead an agent, then quit.
    let r = with_stdin(
        dir,
        &["review", "--data", "data", "--days", "30"],
        "a scripted\nq\n",
    );
    assert!(r.ok, "{}\n{}", r.stdout, r.stderr);
    let labels = std::fs::read_to_string(dir.join("data/labels/reviewed.ndjson")).unwrap();
    assert!(labels.contains("\"agent\""), "{labels}");

    // 3. A case from the strongest cluster's stable key, taken from the store.
    let r = ok(dir, &["clusters", "records.ndjson"]);
    let key = r
        .stdout
        .lines()
        .find(|l| l.starts_with("C1 "))
        .and_then(|l| l.split_whitespace().nth(1))
        .unwrap_or_else(|| panic!("no C1 in\n{}", r.stdout))
        .to_string();
    let data = "data";
    ok(
        dir,
        &[
            "case",
            "--data",
            data,
            "new",
            "wf-1",
            "--title",
            "Workflow",
            "--cluster",
            &key,
            "--days",
            "30",
        ],
    );
    let toml_path = dir.join("data/cases/wf-1/case.toml");
    let hs = hosts(&std::fs::read_to_string(&toml_path).unwrap());
    assert!(!hs.is_empty());

    // 4. Endpoints: every host targeted.
    let mut args = vec!["case", "--data", data, "endpoint", "wf-1"];
    args.extend(hs.iter().map(String::as_str));
    args.push("targeted");
    ok(dir, &args);

    // 5. Contacts: the directory (offline), then the operator by hand.
    ok(
        dir,
        &[
            "case",
            "--data",
            data,
            "contacts",
            "wf-1",
            "--providers-only",
        ],
    );
    let address = format!("security@{}", hs[0]);
    let source = format!("https://{}/.well-known/security.txt", hs[0]);
    ok(
        dir,
        &[
            "case",
            "--data",
            data,
            "contact",
            "add",
            "wf-1",
            "--party",
            "operator",
            "--org",
            "Example operator",
            "--channel",
            "email",
            "--address",
            &address,
            "--source",
            &source,
            "--endpoint",
            &hs[0],
        ],
    );
    assert!(
        std::fs::read_to_string(&toml_path)
            .unwrap()
            .contains(&address)
    );

    // 6. Draft: an unsent .eml with a fresh bundle, which verifies.
    let r = ok(
        dir,
        &[
            "case",
            "--data",
            data,
            "draft",
            "wf-1",
            "--audience",
            "affected",
            "--to",
            &address,
        ],
    );
    assert!(r.stdout.contains("not sent"), "{}", r.stdout);
    let outbox: Vec<_> = std::fs::read_dir(dir.join("data/cases/wf-1/outbox"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    assert_eq!(outbox.len(), 1);
    let eml = std::fs::read_to_string(&outbox[0]).unwrap();
    assert!(eml.contains("X-Unsent: 1"), "{eml}");
    let r = ok(dir, &["case", "--data", data, "bundle", "wf-1"]);
    let bundle = r
        .stdout
        .lines()
        .find_map(|l| l.strip_prefix("wrote "))
        .unwrap()
        .to_string();
    let r = ok(dir, &["case", "--data", data, "verify", &bundle]);
    assert!(r.stdout.contains("verified"), "{}", r.stdout);
    assert!(r.stdout.contains("SC-FM"), "{}", r.stdout);
    ok(
        dir,
        &["case", "--data", data, "sent", "wf-1", "--to", &address],
    );

    // 7. The notice: drafted in the case, added to a scratch notices
    // directory (publish pending), and linted.
    ok(dir, &["case", "--data", data, "notice", "wf-1"]);
    let r = ok(
        dir,
        &["notice", "--dir", "notices", "add", "wf-1", "--data", data],
    );
    assert!(
        r.stdout.contains("not public until you commit and push"),
        "{}",
        r.stdout
    );
    assert!(dir.join("notices/wf-1.md").is_file());
    let r = ok(dir, &["notice", "--dir", "notices", "lint"]);
    assert!(r.stdout.contains("notices OK (1 checked)"), "{}", r.stdout);
    let r = ok(dir, &["case", "--data", data, "status", "wf-1"]);
    assert!(r.stdout.contains("status Reported"), "{}", r.stdout);
    assert!(r.stdout.contains("publish pending"), "{}", r.stdout);
}
