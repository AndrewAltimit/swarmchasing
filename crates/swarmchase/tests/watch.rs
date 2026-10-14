//! A watch run with no source able to run: it still writes its digest, and
//! makes no request.

use crate::common::{Scratch, run};

#[test]
fn a_run_without_the_urlquery_key_skips_the_source_and_writes_a_digest() {
    let s = Scratch::new("watch");
    std::fs::write(
        s.path().join("watchlist.toml"),
        "[[source]]\nname = \"uq\"\nkind = \"urlquery\"\npattern = \"r.jina.ai\"\n",
    )
    .unwrap();
    let r = run(
        s.path(),
        &[
            "watch",
            "watchlist.toml",
            "--out",
            "data",
            "--init",
            "--public-log",
            "public.txt",
        ],
    );
    // No source could run, so the run fails, after writing its digest.
    assert!(!r.ok, "{}", r.stderr);
    assert!(r.stderr.contains("no source could run"), "{}", r.stderr);
    assert!(
        r.stderr.contains("starting a new data directory"),
        "{}",
        r.stderr
    );
    let runs: Vec<_> = std::fs::read_dir(s.path().join("data/runs"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    assert_eq!(runs.len(), 1);
    let digest = std::fs::read_to_string(runs[0].join("digest.md")).unwrap();
    assert!(
        digest.contains("| uq | 0 | 0 | 0 |  | skipped: URLQUERY_APIKEY not set |"),
        "{digest}"
    );
    // The health block opens the digest and names what the skip costs.
    assert!(
        digest
            .find("**No submit-time source ran.**")
            .is_some_and(|i| i < digest.find("## Sources").unwrap()),
        "{digest}"
    );
    assert!(
        digest.contains("`uq` was skipped: URLQUERY_APIKEY not set"),
        "{digest}"
    );
    assert!(s.path().join("data/state.json").is_file());
    // The public summary holds the source's allowlisted line and totals.
    let public = std::fs::read_to_string(s.path().join("public.txt")).unwrap();
    assert_eq!(
        public.lines().next(),
        Some("source uq kind=urlquery status=skipped pulled=0 new=0 requests=0 duration_ms=0"),
        "{public}"
    );
    assert!(public.contains("\ntotal sources=1 skipped=1 "), "{public}");
    // run.json carries the phase durations, and the digest a run time line.
    let run_json = std::fs::read_to_string(runs[0].join("run.json")).unwrap();
    let v: serde_json::Value = serde_json::from_str(&run_json).unwrap();
    for phase in [
        "collect", "platform", "analysis", "triage", "report", "total",
    ] {
        assert!(v["durations_ms"][phase].is_u64(), "{phase}: {run_json}");
    }
    assert!(digest.contains("\n## Run time\n"), "{digest}");
    // The ledger and the attention queue are written even with nothing to
    // rank, and the digest says the queue is empty.
    assert!(s.path().join("data/ledger.json").is_file());
    assert!(runs[0].join("attention.json").is_file());
    assert!(
        digest.contains("## Attention queue: 0 urgent, 0 look, 0 watch"),
        "{digest}"
    );
}

/// `swarmchase watch` in `dir` with `$GITHUB_OUTPUT` set to `out`.
fn watch_with_output(
    dir: &std::path::Path,
    out: &std::path::Path,
    args: &[&str],
) -> (bool, String) {
    let o = std::process::Command::new(env!("CARGO_BIN_EXE_swarmchase"))
        .arg("watch")
        .args(args)
        .current_dir(dir)
        .env_remove("SWARMCHASE_DATA")
        .env_remove("URLQUERY_APIKEY")
        .env("GITHUB_OUTPUT", out)
        .output()
        .unwrap();
    (
        o.status.success(),
        String::from_utf8_lossy(&o.stderr).into_owned(),
    )
}

#[test]
fn the_workflow_output_is_written_before_later_steps_and_damage_alerts_once() {
    let s = Scratch::new("watch-output");
    let d = s.path();
    std::fs::write(
        d.join("watchlist.toml"),
        "[[source]]\nname = \"uq\"\nkind = \"urlquery\"\npattern = \"r.jina.ai\"\n",
    )
    .unwrap();
    // A store with one damaged line among good ones.
    std::fs::create_dir_all(d.join("data/store")).unwrap();
    std::fs::write(
        d.join("data/store/old.ndjson"),
        "{\"id\":\"r1\",\"ts\":1,\"url\":\"https://a.example/\"}\n{ torn\n",
    )
    .unwrap();
    // A public log that cannot be written (its path is a directory): a
    // step after the digest fails, and the workflow still gets the result.
    std::fs::create_dir_all(d.join("public-dir")).unwrap();
    let out1 = d.join("out1.txt");
    let (ok1, err) = watch_with_output(
        d,
        &out1,
        &["watchlist.toml", "-d", "data", "--public-log", "public-dir"],
    );
    assert!(!ok1, "{err}");
    assert!(err.contains("public log"), "{err}");
    let o = std::fs::read_to_string(&out1).unwrap();
    assert!(o.contains("changed=true"), "{o}");
    assert!(o.contains("run_dir="), "{o}");
    // The later steps still ran: the state no longer holds the run's IDs.
    assert!(d.join("data/LATEST").is_file());
    let digest = std::fs::read_to_string(
        d.join("data/runs")
            .join(
                std::fs::read_to_string(d.join("data/LATEST"))
                    .unwrap()
                    .trim(),
            )
            .join("digest.md"),
    )
    .unwrap();
    assert!(digest.contains("moved to `store/old.damaged`"), "{digest}");
    assert!(d.join("data/store/old.damaged").is_file());

    // The next run: the damaged line is gone from the store, the skip has
    // already alerted, so nothing changed and nothing is mailed. `-o` is
    // still the data directory.
    std::thread::sleep(std::time::Duration::from_millis(1100));
    let out2 = d.join("out2.txt");
    let (_, err) = watch_with_output(d, &out2, &["watchlist.toml", "-o", "data"]);
    let o = std::fs::read_to_string(&out2).unwrap();
    assert!(o.contains("changed=false"), "{o}\n{err}");
}

#[test]
fn an_autonomy_level_that_is_not_built_cannot_be_on() {
    let s = Scratch::new("watch-autonomy");
    std::fs::write(
        s.path().join("watchlist.toml"),
        "[autonomy]\ndraft_case = \"on\"\n\n[[source]]\nname = \"uq\"\nkind = \"urlquery\"\npattern = \"r.jina.ai\"\n",
    )
    .unwrap();
    let r = run(
        s.path(),
        &["watch", "watchlist.toml", "--out", "data", "--init"],
    );
    assert!(!r.ok);
    assert!(
        r.stderr.contains("only `interrupt` can be on"),
        "{}",
        r.stderr
    );
    // Rejected before anything was collected or written.
    assert!(!s.path().join("data/runs").exists());
}

#[test]
fn a_run_refuses_a_new_data_directory_without_init() {
    let s = Scratch::new("watch-init");
    std::fs::write(
        s.path().join("watchlist.toml"),
        "[[source]]\nname = \"uq\"\nkind = \"urlquery\"\npattern = \"r.jina.ai\"\n",
    )
    .unwrap();
    let r = run(s.path(), &["watch", "watchlist.toml", "--out", "data"]);
    assert!(!r.ok);
    assert!(r.stderr.contains("pass --init"), "{}", r.stderr);
    assert!(r.stderr.contains("SWARMCHASE_DATA"), "{}", r.stderr);
    assert!(!s.path().join("data/state.json").exists());
    assert!(!s.path().join("data/runs").exists());
}

#[test]
fn check_reports_unknown_keys_without_a_data_directory() {
    let s = Scratch::new("watch-check");
    std::fs::write(
        s.path().join("good.toml"),
        "[[source]]\nname = \"j\"\nkind = \"wayback\"\npattern = \"r.jina.ai/*\"\nlimit = 10\n",
    )
    .unwrap();
    std::fs::write(
        s.path().join("bad.toml"),
        "[[source]]\nname = \"j\"\nkind = \"wayback\"\npattern = \"r.jina.ai/*\"\nlimt = 10\n",
    )
    .unwrap();
    let r = run(s.path(), &["watch", "--check", "good.toml"]);
    assert!(r.ok, "{}", r.stderr);
    assert!(r.stdout.contains("ok (1 source(s)"), "{}", r.stdout);
    let r = run(s.path(), &["watch", "--check", "bad.toml"]);
    assert!(!r.ok);
    assert!(r.stderr.contains("unknown key `limt`"), "{}", r.stderr);
    assert!(!s.path().join("data").exists());
}
