//! Committed case files and bundles keep reading: the `case.toml` shapes the
//! CLI has written, and a bundle as `case bundle` writes it, from fixtures
//! under `tests/fixtures/` (synthetic records, reserved example names).

use sc_case::bundle::{FILES, MANIFEST, check, manifest_differences, stored_differences};
use sc_case::model::*;
use sc_core::{AgentLevel, Evidence, Role, Rules, Stamp};
use std::path::{Path, PathBuf};

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

fn read(name: &str) -> String {
    std::fs::read_to_string(fixture(name)).unwrap()
}

#[test]
fn a_full_case_file_reads_and_round_trips() {
    let c = Case::parse(&read("case-full.toml")).unwrap();
    assert_eq!(c.status, CaseStatus::Reported);
    assert_eq!(c.min_named, Evidence::SharedIdentifiers);
    assert_eq!(c.rules_version.as_deref(), Some("2026-10-10"));
    assert_eq!(c.lead_hours, Some(8));
    assert_eq!(
        c.agent_grade.as_ref().map(|g| g.level),
        Some(AgentLevel::Documented)
    );
    let states: Vec<EndpointState> = c.endpoints.iter().map(|e| e.state).collect();
    assert_eq!(
        states,
        [
            EndpointState::Compromised,
            EndpointState::NotAffected,
            EndpointState::Historical,
            EndpointState::Unreviewed
        ]
    );
    let roles: Vec<ContactRole> = c.contacts.iter().map(|x| x.role).collect();
    assert_eq!(
        roles,
        [
            ContactRole::Provider,
            ContactRole::Affected,
            ContactRole::Registrar,
            ContactRole::Csirt,
            ContactRole::DeclaredOwner
        ]
    );
    assert_eq!(c.claims[1].role, Role::ModelFamily, "`layer` reads as role");
    assert!(c.fleets[0].is_swarm());
    assert_eq!(c.evidence[0].kept, 9);
    assert_eq!(c.alternatives[0].kind, AlternativeKind::AuthorisedTest);
    assert_eq!(c.plant_reviews.len(), 1);
    assert_eq!(c.sent[1].time(), parse_time("2026-10-13T23:59:59Z"));

    // Written back, it reads the same.
    let text = c.to_toml().unwrap();
    let back = Case::parse(&text).unwrap();
    assert_eq!(back.to_toml().unwrap(), text);
    for section in [
        "[[endpoint]]",
        "[[claim]]",
        "[[contact]]",
        "[[sent]]",
        "[[evidence]]",
        "[[fleet.swarm_evidence]]",
        "[[no_contact]]",
        "[[alternative]]",
        "[[plant_review]]",
        "role = \"declared_owner\"",
        "state = \"not_affected\"",
    ] {
        assert!(text.contains(section), "{section} missing from\n{text}");
    }

    // The clock and the reports read it as the CLI does.
    let clock = sc_case::lead::clock(&c);
    assert_eq!(clock.parties.len(), 3, "{clock:?}");
    assert!(sc_case::report::reported(&c).operators);
    assert_eq!(
        sc_case::report::affected_hosts(&c),
        ["portal.example.gov", "old.example.org"]
    );
}

#[test]
fn an_unpinned_case_file_reads_with_defaults() {
    let c = Case::parse(&read("case-unpinned.toml")).unwrap();
    assert_eq!(c.rules_version, None);
    assert_eq!(c.min_named, Evidence::default());
    assert_eq!(c.lead_hours, None);
    assert!(c.fleets.is_empty() && c.claims.is_empty());
    assert_eq!(c.contacts[0].role, ContactRole::Affected);
    let text = c.to_toml().unwrap();
    assert!(!text.contains("rules_version"), "{text}");
    assert_eq!(
        Case::parse(&text).unwrap().to_toml().unwrap(),
        text,
        "stable"
    );
}

#[test]
fn a_written_bundle_still_verifies() {
    let dir = fixture("bundle-v1");
    let get = |f: &str| std::fs::read_to_string(dir.join(f)).unwrap();
    let manifest = get(MANIFEST);
    let d = manifest_differences(&manifest, |f| {
        std::fs::read(dir.join(f)).map_err(|e| e.to_string())
    })
    .unwrap();
    assert!(d.is_empty(), "{d:?}");
    assert_eq!(FILES.len(), manifest.lines().count());

    // The stamp and the analysis copy read, and agree, whatever the rules.
    let st: Stamp = serde_json::from_str(&get("stamp.json")).unwrap();
    assert_eq!(st.case, "fx-1");
    let analysis = get("analysis.json");
    assert!(stored_differences(&st, &analysis).unwrap().is_empty());

    // The full check runs; under the rules the bundle was made with it
    // verifies.
    let rules = Rules::default_rules();
    let c = check(
        &get("records.ndjson"),
        &analysis,
        &get("stamp.json"),
        &rules,
        env!("CARGO_PKG_VERSION"),
        "hint",
    )
    .unwrap();
    assert!(
        c.notes.is_empty() || c.notes.iter().all(|n| !n.starts_with("analysis.json")),
        "{:?}",
        c.notes
    );
    if rules.set.meta.version == st.rules_version {
        assert!(c.differences.is_empty(), "{:?}", c.differences);
    }
}
