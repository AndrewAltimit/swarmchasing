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
    let r = run(s.path(), &["watch", "watchlist.toml", "--out", "data"]);
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
        digest.contains("| uq | 0 | 0 | 0 | skipped: URLQUERY_APIKEY not set |"),
        "{digest}"
    );
    assert!(s.path().join("data/state.json").is_file());
}
