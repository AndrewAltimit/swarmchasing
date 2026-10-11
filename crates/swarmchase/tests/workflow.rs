//! The admin workflow end to end, offline: a watch over a fixture store,
//! review from scripted answers, a case opened from a cluster key, endpoint
//! decisions, a hand-added contact, a draft with its bundle, verification,
//! timed sends and missing contacts, the alternative explanations, the
//! indicator notice draft and its re-read, `notice add` refused by the
//! self-review checklist until the cooling-off, the lead time and a second
//! review have passed, then added into a scratch notices directory, a
//! naming update after the operator's consent, and the notice lint. No
//! step touches the network.

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

fn rfc3339(ts: i64) -> String {
    chrono::DateTime::<chrono::Utc>::from_timestamp(ts, 0)
        .unwrap()
        .format("%Y-%m-%dT%H:%M:%SZ")
        .to_string()
}

/// Move every time `case.toml` records (`at = "…"`: sends, missing
/// contacts, the draft and its re-read) `secs` into the past, as if that
/// long had passed. The test's clock: nothing in the binary can be told
/// the time.
fn shift_times(case_toml: &Path, secs: i64) {
    let text = std::fs::read_to_string(case_toml).unwrap();
    let out: Vec<String> = text
        .lines()
        .map(|l| match l.strip_prefix("at = \"") {
            Some(rest) => {
                let t = chrono::DateTime::parse_from_rfc3339(rest.trim_end_matches('"'))
                    .unwrap()
                    .timestamp();
                format!("at = \"{}\"", rfc3339(t - secs))
            }
            None => l.to_string(),
        })
        .collect();
    std::fs::write(case_toml, out.join("\n") + "\n").unwrap();
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
    // The first is compromised, with what shows it, and the notice
    // describes it without naming it. The admin is recorded.
    ok(
        dir,
        &[
            "case",
            "--data",
            data,
            "endpoint",
            "wf-1",
            &hs[0],
            "compromised",
            "--basis",
            "operator statement: a web shell was found",
            "--sector",
            "a national government data portal",
        ],
    );
    ok(
        dir,
        &[
            "case",
            "--data",
            data,
            "set",
            "wf-1",
            "--admin",
            "Ada Admin",
        ],
    );

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
    // The report states when the notice goes public, and that it is fixed.
    ok(
        dir,
        &[
            "case",
            "--data",
            data,
            "report",
            "wf-1",
            "--audience",
            "affected",
            "-o",
            "aff.md",
        ],
    );
    let aff = std::fs::read_to_string(dir.join("aff.md")).unwrap();
    assert!(
        aff.contains("## Publication")
            && aff.contains("**Indicators**, not before **")
            && aff.contains("will not name or locate you"),
        "{aff}"
    );
    assert!(aff.contains("appended verbatim"), "{aff}");

    // 7. Sends, each with the time it was made: the operator's report three
    // hours ago. No provider was reported (none can be named, and the
    // directory had no channel for the case), and the other hosts had no
    // contact: both are recorded, so the notice says contact was attempted.
    let three_hours_ago = rfc3339(now - 3 * 3600);
    ok(
        dir,
        &[
            "case",
            "--data",
            data,
            "sent",
            "wf-1",
            "--to",
            &address,
            "--at",
            &three_hours_ago,
        ],
    );
    let c: toml::Value = toml::from_str(&std::fs::read_to_string(&toml_path).unwrap()).unwrap();
    let providers: Vec<String> = c
        .get("contact")
        .and_then(|v| v.as_array())
        .into_iter()
        .flatten()
        .filter(|x| x["role"].as_str() == Some("provider"))
        .map(|x| x["address"].as_str().unwrap().to_string())
        .collect();
    for p in &providers {
        ok(
            dir,
            &[
                "case",
                "--data",
                data,
                "sent",
                "wf-1",
                "--to",
                p,
                "--at",
                &three_hours_ago,
            ],
        );
    }
    if providers.is_empty() {
        ok(
            dir,
            &[
                "case",
                "--data",
                data,
                "no-contact",
                "wf-1",
                "provider",
                "--searched",
                "provider directory: no entry for the vendor the requests name",
            ],
        );
    }
    for h in &hs[1..] {
        ok(
            dir,
            &[
                "case",
                "--data",
                data,
                "no-contact",
                "wf-1",
                h,
                "--searched",
                "security.txt and RDAP: nothing found",
            ],
        );
    }
    // A send cannot be recorded in the future.
    let r = run(
        dir,
        &[
            "case",
            "--data",
            data,
            "sent",
            "wf-1",
            "--to",
            &address,
            "--at",
            &rfc3339(now + 86_400),
        ],
    );
    assert!(!r.ok && r.stderr.contains("future"), "{}", r.stderr);
    for kind in [
        "authorised-test",
        "honeypot",
        "research-scanner",
        "spoofed-self-id",
        "planted-records",
    ] {
        ok(
            dir,
            &[
                "case",
                "--data",
                data,
                "alternative",
                "wf-1",
                kind,
                "--rejected",
                "checked against the records; see case notes",
            ],
        );
    }
    let r = ok(dir, &["case", "--data", data, "status", "wf-1"]);
    assert!(r.stdout.contains("publish not before:"), "{}", r.stdout);

    // 8. The notice: drafted in the case after the sends, then refused until
    // the self-review checklist passes.
    ok(dir, &["case", "--data", data, "notice", "wf-1"]);
    let add = |dir: &Path| {
        run(
            dir,
            &["notice", "--dir", "notices", "add", "wf-1", "--data", data],
        )
    };
    let r = add(dir);
    assert!(!r.ok, "{}", r.stdout);
    assert!(
        r.stdout.contains("[FAIL] the current draft was re-read"),
        "{}",
        r.stdout
    );
    assert!(
        r.stdout.contains("[pass] the withholding scan passes"),
        "{}",
        r.stdout
    );
    // Re-read straight away: inside the cooling-off, so it does not count.
    let r = ok(dir, &["case", "--data", data, "reread", "wf-1"]);
    assert!(r.stdout.contains("less than an hour"), "{}", r.stdout);
    assert!(!add(dir).ok);
    // The clock moves by moving the case's recorded times back: the draft
    // was written two hours ago (after the sends), the re-read is now.
    shift_times(&toml_path, 2 * 3600);
    ok(dir, &["case", "--data", data, "reread", "wf-1"]);
    // The compromised endpoint's operator has 24 hours, 19 of them left;
    // there is no override, and no second review yet.
    let r = add(dir);
    assert!(!r.ok, "{}", r.stdout);
    assert!(
        r.stderr.contains("The lead time runs until"),
        "{}",
        r.stderr
    );
    assert!(
        r.stdout
            .contains("[FAIL] the indicator clock has run for each party"),
        "{}",
        r.stdout
    );
    assert!(
        r.stdout
            .contains("[FAIL] an approved second review of the current draft"),
        "{}",
        r.stdout
    );
    assert!(
        r.stdout
            .contains("[pass] the indicator notice names and locates no affected party"),
        "{}",
        r.stdout
    );
    assert!(!dir.join("notices/wf-1.md").exists());

    // 9. The second review: a packet for the reviewer, never the admin.
    let r = ok(dir, &["case", "--data", data, "review-packet", "wf-1"]);
    assert!(r.stdout.contains("not sent"), "{}", r.stdout);
    let packet = dir.join("data/cases/wf-1/outbox/review");
    for f in [
        "notice.md",
        "checklist.txt",
        "report-internal.md",
        "README.txt",
    ] {
        assert!(packet.join(f).is_file(), "{f}");
    }
    let review = |who: &str, verdict: &str| {
        run(
            dir,
            &[
                "case",
                "--data",
                data,
                "review",
                "wf-1",
                "--reviewer",
                who,
                "--verdict",
                verdict,
                "--note",
                "read against the case notes",
            ],
        )
    };
    let r = review(" ada admin ", "approve");
    assert!(!r.ok && r.stderr.contains("admin"), "{}", r.stderr);
    let r = review("Rae Reviewer", "approve");
    assert!(r.ok, "{}\n{}", r.stdout, r.stderr);
    let r = ok(dir, &["case", "--data", data, "checklist", "wf-1"]);
    assert!(
        r.stdout
            .contains("[pass] an approved second review of the current draft"),
        "{}",
        r.stdout
    );
    assert!(r.stdout.contains("Stage 2, naming"), "{}", r.stdout);
    // Twenty hours on, the lead has passed.
    shift_times(&toml_path, 20 * 3600);
    let r = add(dir);
    assert!(r.ok, "{}\n{}", r.stdout, r.stderr);
    assert!(!r.stdout.contains("[FAIL]"), "{}", r.stdout);
    assert!(
        r.stdout.contains("not public until you commit and push"),
        "{}",
        r.stdout
    );
    let notice = std::fs::read_to_string(dir.join("notices/wf-1.md")).unwrap();
    assert!(
        notice.contains(
            "before publication, each with the fixed lead time of our disclosure policy."
        ),
        "{notice}"
    );
    assert!(
        notice.contains("A second reviewer reviewed it before publication."),
        "{notice}"
    );
    assert!(!notice.contains("Rae"), "{notice}");
    for h in &hs {
        assert!(!notice.contains(h.as_str()), "{h}: {notice}");
        assert!(!notice.contains(&h.replace('.', "[.]")), "{h}: {notice}");
    }
    if hs.len() > 1 {
        assert!(notice.contains("contact was attempted"), "{notice}");
    }
    if providers.is_empty() {
        // Only the operator was sent a report, so the notice says only that.
        assert!(
            notice.contains(
                "Reports went to the affected operators before this notice was published."
            ),
            "{notice}"
        );
        assert!(
            !notice.contains("Reports went to the AI provider"),
            "{notice}"
        );
        assert!(
            notice.contains("No contact could be found for the AI provider"),
            "{notice}"
        );
    }
    let r = ok(dir, &["notice", "--dir", "notices", "lint"]);
    assert!(r.stdout.contains("notices OK (1 checked)"), "{}", r.stdout);
    let r = ok(dir, &["case", "--data", data, "status", "wf-1"]);
    assert!(r.stdout.contains("status Reported"), "{}", r.stdout);
    assert!(r.stdout.contains("publish pending"), "{}", r.stdout);
    assert!(r.stdout.contains("may be named from"), "{}", r.stdout);

    // 10. Names: the compromised endpoint's operator waits 10 working days,
    // unless it consents in writing.
    let r = run(dir, &["case", "--data", data, "notice", "wf-1", "--naming"]);
    assert!(
        !r.ok && r.stderr.contains("may be named from"),
        "{}",
        r.stderr
    );
    ok(
        dir,
        &[
            "case",
            "--data",
            data,
            "consent",
            "wf-1",
            "--party",
            &hs[0],
            "--note",
            "operator e-mail agreeing to be named",
        ],
    );
    let r = ok(dir, &["case", "--data", data, "notice", "wf-1", "--naming"]);
    assert!(r.stdout.contains("names:"), "{}", r.stdout);
    let naming = || {
        run(
            dir,
            &[
                "notice", "--dir", "notices", "update", "wf-1", "--naming", "--data", data,
            ],
        )
    };
    let r = naming();
    assert!(!r.ok, "{}", r.stdout);
    assert!(
        r.stdout
            .contains("[FAIL] an approved second review of the current draft"),
        "{}",
        r.stdout
    );
    let r = review("Rae Reviewer", "approve");
    assert!(r.ok, "{}\n{}", r.stdout, r.stderr);
    let r = naming();
    assert!(r.ok, "{}\n{}", r.stdout, r.stderr);
    let notice = std::fs::read_to_string(dir.join("notices/wf-1.md")).unwrap();
    assert!(notice.contains("kind = \"naming\""), "{notice}");
    assert!(
        notice.contains(&format!("affected = [\"{}\"]", hs[0])),
        "{notice}"
    );
    let r = ok(dir, &["notice", "--dir", "notices", "lint"]);
    assert!(r.stdout.contains("notices OK (1 checked)"), "{}", r.stdout);
}
