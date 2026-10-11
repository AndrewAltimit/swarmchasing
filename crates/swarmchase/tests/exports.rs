//! `case export` from a committed fixture case (`tests/fixtures/case-export`):
//! STIX, MISP and the OECD draft with its EU AI Act Article 73 section are
//! written to files, carry what their audience may see, and say they are
//! drafts.

use crate::common::{Scratch, ok, run};
use serde_json::Value;
use std::path::Path;

/// A scratch data directory holding the fixture case.
fn data_with_fixture(s: &Scratch) -> String {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/case-export");
    let dst = s.path().join("data/cases/fx-1");
    std::fs::create_dir_all(dst.join("raw")).unwrap();
    for f in ["case.toml", "raw/records.ndjson"] {
        std::fs::copy(src.join(f), dst.join(f)).unwrap();
    }
    s.path().join("data").to_string_lossy().into_owned()
}

fn export(s: &Scratch, data: &str, args: &[&str]) -> Value {
    let out = s.path().join("out.json");
    let out = out.to_str().unwrap();
    let mut all = vec!["case", "--data", data, "export", "fx-1", "-o", out];
    all.extend(args);
    let r = ok(s.path(), &all);
    assert!(r.stdout.contains("draft only"), "{}", r.stdout);
    serde_json::from_str(&std::fs::read_to_string(out).unwrap()).unwrap()
}

#[test]
fn stix_carries_the_tactic_crosswalk() {
    let s = Scratch::new("export-stix");
    let data = data_with_fixture(&s);
    let b = export(&s, &data, &["--format", "stix"]);
    assert_eq!(b["type"], "bundle");
    let objs = b["objects"].as_array().unwrap();
    let run = objs.iter().find(|o| o["type"] == "x-sc-agent-run").unwrap();
    let refs = run["external_references"].as_array().unwrap();
    for (source, id) in [
        ("swarmchasing-sc-t", "SC-T4"),
        ("mitre-atlas", "AML.T0049"),
        ("mitre-attack", "T1190"),
    ] {
        assert!(
            refs.iter()
                .any(|r| r["source_name"] == source && r["external_id"] == id),
            "{source} {id}: {refs:#?}"
        );
    }
}

#[test]
fn misp_is_an_unpublished_event_scoped_like_the_stix() {
    let s = Scratch::new("export-misp");
    let data = data_with_fixture(&s);
    let e = export(&s, &data, &["--format", "misp"]);
    let ev = &e["Event"];
    assert_eq!(ev["info"], "Portal probe");
    assert_eq!(ev["published"], false);
    let tags: Vec<&str> = ev["Tag"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert!(tags.contains(&"tlp:amber"), "{tags:?}");
    assert!(tags.contains(&"swarmchasing:tactic=\"SC-T4\""), "{tags:?}");
    let attrs = ev["Attribute"].as_array().unwrap();
    assert!(
        attrs
            .iter()
            .any(|a| a["type"] == "text" && a["value"] == "uqtag=zz9"),
        "{attrs:#?}"
    );
    assert!(
        attrs
            .iter()
            .any(|a| a["type"] == "AS" && a["value"] == "AS132203")
    );
    assert_eq!(ev["Object"][0]["name"], "swarmchasing-agent-run");

    let public = export(&s, &data, &["--format", "misp", "--audience", "public"]);
    assert!(public.to_string().contains("tlp:white"));
}

#[test]
fn oecd_draft_lists_what_the_admin_must_fill() {
    let s = Scratch::new("export-oecd");
    let data = data_with_fixture(&s);
    let d = export(
        &s,
        &data,
        &[
            "--format",
            "oecd",
            "--site-url",
            "https://site.example/swarmchasing/",
        ],
    );
    assert!(
        d["draft"]
            .as_str()
            .unwrap()
            .contains("Nothing was submitted")
    );
    assert_eq!(
        d["missing_mandatory"],
        serde_json::json!(["Type of harm", "Severity of the impact"])
    );
    let art = &d["eu_ai_act_article_73"];
    assert!(
        art["status"]
            .as_str()
            .unwrap()
            .starts_with("DRAFT, not a filing")
    );
    let missing: Vec<&str> = art["missing"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m.as_str().unwrap())
        .collect();
    assert!(
        missing.contains(&"Serious incident category (Article 3(49))"),
        "{missing:?}"
    );
    assert!(d["criteria"].as_array().unwrap().iter().any(|c| {
        c["criterion"] == "Sources"
            && c["value"]
                .as_array()
                .unwrap()
                .iter()
                .any(|v| v == "https://site.example/swarmchasing/#notice=fx-1")
    }));
    // Incident drafts are public: case notes are refused.
    let r = run(
        s.path(),
        &[
            "case",
            "--data",
            &data,
            "export",
            "fx-1",
            "--format",
            "oecd",
            "--audience",
            "internal",
        ],
    );
    assert!(!r.ok);
}
