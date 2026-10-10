//! The analysis commands over the sample records.

use crate::common::{Scratch, ok, samples, with_samples};

#[test]
fn scan_lists_flagged_records() {
    let s = Scratch::new("scan");
    let files = samples();
    let r = ok(s.path(), &with_samples(&["scan", "--limit", "5"], &files));
    assert!(r.stdout.contains(" flagged · "), "{}", r.stdout);
    assert!(r.stdout.contains("[significant]"), "{}", r.stdout);
    // URLs are defanged.
    assert!(!r.stdout.contains("https://"), "{}", r.stdout);
}

#[test]
fn clusters_print_their_stable_keys() {
    let s = Scratch::new("clusters");
    let files = samples();
    let r = ok(s.path(), &with_samples(&["clusters"], &files));
    let first = r
        .stdout
        .lines()
        .find(|l| l.starts_with("C1 "))
        .unwrap_or_else(|| panic!("no C1 in\n{}", r.stdout));
    let key = first.split_whitespace().nth(1).unwrap();
    assert!(key.starts_with("k-") && key.len() == 10, "{first}");
}

#[test]
fn public_report_is_a_notice_draft() {
    let s = Scratch::new("report");
    let files = samples();
    let out = s.path().join("public.md");
    let out = out.to_str().unwrap();
    ok(
        s.path(),
        &with_samples(&["report", "--audience", "public", "-o", out], &files),
    );
    let md = std::fs::read_to_string(out).unwrap();
    assert!(md.starts_with("# "), "{md}");
    assert!(md.contains("DRAFT"), "{md}");
}
