use super::*;
use crate::watch::ledger::{Point, Thread};
use sc_core::Tier;

const T0: i64 = 1_791_000_000;

fn item(thread: &str, band: Band, grade: AgentLevel) -> Item {
    Item {
        rank: 1,
        band,
        thread: thread.into(),
        id: "C1".into(),
        key: thread.into(),
        tier: Tier::Significant,
        grade,
        harm: super::super::attention::Harm::Elevated,
        trajectory: Trajectory::Active,
        growth: None,
        records: 5,
        added: 1,
        target_count: 1,
        targets: vec!["portal[.]example[.]gov".into()],
        sources: vec!["wayback-jina".into()],
        swarm_edges: 0,
        fleet: None,
        why: vec!["L3 adaptive with access-controlled targets".into()],
        caps: Vec::new(),
        momentum: 40,
        factors: Vec::new(),
        cases: Vec::new(),
        first_run: "R1".into(),
        spark: vec![5],
    }
}

/// A thread with one point per band, six hours apart, the last at `t`.
fn thread(id: &str, bands: &[&str], t: i64) -> Thread {
    let n = bands.len() as i64;
    Thread {
        id: id.into(),
        key: id.into(),
        first_run: "R1".into(),
        points: bands
            .iter()
            .enumerate()
            .map(|(i, b)| Point {
                run: format!("R{}", i + 1),
                t: t - (n - 1 - i as i64) * 6 * 3600,
                band: b.to_string(),
                records: 5,
                ..Default::default()
            })
            .collect(),
        members: vec![format!("{id}-m0"), format!("{id}-m1")],
        ..Default::default()
    }
}

fn queue(items: Vec<Item>) -> Queue {
    Queue {
        schema: String::new(),
        stamp: "R9".into(),
        by_band: BTreeMap::new(),
        items,
    }
}

fn ledger(threads: Vec<Thread>) -> Ledger {
    let mut l = Ledger::new();
    for t in threads {
        l.threads.insert(t.id.clone(), t);
    }
    l
}

fn levels(ds: &[Decision]) -> Vec<Level> {
    ds.iter().map(|d| d.level).collect()
}

#[test]
fn every_level_is_in_shadow_by_default_and_only_interrupt_can_be_on() {
    let c = Config::default();
    assert!(Level::ALL.iter().all(|&l| c.mode(l) == Mode::Shadow));
    assert_eq!(c.interrupts_per_day, 3);
    let on: Config = toml::from_str("interrupt = \"on\"\ndraft_case = \"off\"").unwrap();
    assert!(on.check().is_ok());
    assert_eq!(on.mode(Level::WatchHarder), Mode::Shadow);
    let bad: Config = toml::from_str("draft_case = \"on\"").unwrap();
    assert!(
        bad.check()
            .unwrap_err()
            .to_string()
            .contains("only `interrupt`")
    );
    assert!(toml::from_str::<Config>("send_reports = \"on\"").is_err());
}

#[test]
fn an_urgent_lead_interrupts_once_and_watches_harder() {
    let t = T0;
    let l = ledger(vec![thread("k-a", &["look", "urgent"], t)]);
    let q = queue(vec![item("k-a", Band::Urgent, AgentLevel::Adaptive)]);
    let ds = decide(&q, &l, &Config::default(), t, &[]);
    assert_eq!(levels(&ds), [Level::Interrupt, Level::WatchHarder]);
    assert!(ds.iter().all(|d| d.mode == Mode::Shadow && d.acted()));
    assert!(ds[0].trigger.starts_with("entered urgent"), "{:?}", ds[0]);
    assert!(ds[1].proposal.contains("wayback-jina") && ds[1].proposal.contains("passive"));

    // Six hours on, still urgent: nothing new (once a day, once a week).
    let l = ledger(vec![thread(
        "k-a",
        &["look", "urgent", "urgent"],
        t + 6 * 3600,
    )]);
    assert!(decide(&q, &l, &Config::default(), t + 6 * 3600, &ds).is_empty());
}

#[test]
fn nothing_fires_below_l2() {
    let l = ledger(vec![thread("k-a", &["urgent"], T0)]);
    for g in [AgentLevel::PayloadsOnly, AgentLevel::SelfDescribed] {
        let q = queue(vec![item("k-a", Band::Urgent, g)]);
        assert!(decide(&q, &l, &Config::default(), T0, &[]).is_empty());
    }
}

#[test]
fn interrupts_are_rate_limited_per_day() {
    let names = ["k-a", "k-b", "k-c", "k-d"];
    let l = ledger(names.iter().map(|n| thread(n, &["urgent"], T0)).collect());
    let q = queue(
        names
            .iter()
            .map(|n| item(n, Band::Urgent, AgentLevel::Adaptive))
            .collect(),
    );
    let cfg = Config {
        watch_harder: Mode::Off,
        draft_case: Mode::Off,
        ..Config::default()
    };
    let ds = decide(&q, &l, &cfg, T0, &[]);
    assert_eq!(ds.len(), 4);
    assert_eq!(ds.iter().filter(|d| d.acted()).count(), 3);
    assert!(ds[3].suppressed.as_deref().unwrap().contains("rate limit"));
}

#[test]
fn growth_and_returns_interrupt_from_look() {
    let l = ledger(vec![
        thread("k-g", &["look", "look"], T0),
        thread("k-r", &["look"], T0),
        thread("k-s", &["look", "look"], T0),
    ]);
    let mut g = item("k-g", Band::Look, AgentLevel::ModelWritten);
    g.trajectory = Trajectory::Growing;
    g.growth = Some(4.0);
    let mut r = item("k-r", Band::Look, AgentLevel::ModelWritten);
    r.trajectory = Trajectory::Resurgent;
    let mut s = item("k-s", Band::Look, AgentLevel::ModelWritten);
    s.trajectory = Trajectory::Growing;
    s.growth = Some(2.0);
    let ds = decide(&queue(vec![g, r, s]), &l, &Config::default(), T0, &[]);
    assert_eq!(levels(&ds), [Level::Interrupt, Level::Interrupt]);
    assert!(ds[0].trigger.contains("4.0x"));
    assert!(ds[1].trigger.contains("quiet spell"));
}

#[test]
fn a_draft_case_needs_urgent_held_and_no_case() {
    let cfg = Config {
        interrupt: Mode::Off,
        watch_harder: Mode::Off,
        ..Config::default()
    };
    let q = queue(vec![item("k-a", Band::Urgent, AgentLevel::Adaptive)]);
    // One urgent run: not yet.
    let l = ledger(vec![thread("k-a", &["look", "urgent"], T0)]);
    assert!(decide(&q, &l, &cfg, T0, &[]).is_empty());
    // Two urgent runs six hours apart: under twelve hours.
    let l = ledger(vec![thread("k-a", &["urgent", "urgent"], T0)]);
    assert!(decide(&q, &l, &cfg, T0, &[]).is_empty());
    // Three, twelve hours from first to last.
    let l = ledger(vec![thread("k-a", &["urgent", "urgent", "urgent"], T0)]);
    let ds = decide(&q, &l, &cfg, T0, &[]);
    assert_eq!(levels(&ds), [Level::DraftCase]);
    assert!(ds[0].proposal.contains("cluster k-a"));
    // Never twice for one thread.
    assert!(decide(&q, &l, &cfg, T0 + 30 * 86_400, &ds).is_empty());
    // A case already covers it: nothing.
    let mut covered = item("k-a", Band::Urgent, AgentLevel::Adaptive);
    covered.cases = vec!["case-1".into()];
    assert!(decide(&queue(vec![covered]), &l, &cfg, T0, &[]).is_empty());
}

#[test]
fn only_an_interrupt_that_is_on_raises_the_priority() {
    let l = ledger(vec![thread("k-a", &["urgent"], T0)]);
    let q = queue(vec![item("k-a", Band::Urgent, AgentLevel::Adaptive)]);
    let shadow = decide(&q, &l, &Config::default(), T0, &[]);
    assert!(priority_reasons(&shadow).is_empty());
    let on = Config {
        interrupt: Mode::On,
        ..Config::default()
    };
    let ds = decide(&q, &l, &on, T0, &[]);
    let r = priority_reasons(&ds);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].level, Prio::High);
    assert_eq!(r[0].kind, "attention");
    assert!(
        r[0].text.contains("k-a") && r[0].text.contains("urgent"),
        "{r:?}"
    );
}

fn decision(level: Level, thread: &str, t: i64) -> Decision {
    Decision {
        run: "R1".into(),
        t,
        level,
        mode: Mode::Shadow,
        thread: thread.into(),
        cluster: "C1".into(),
        key: thread.into(),
        band: Band::Urgent,
        grade: "L3".into(),
        trigger: String::new(),
        proposal: String::new(),
        suppressed: None,
    }
}

#[test]
fn outcomes_come_from_labels_cases_and_time() {
    let mut merged = thread("k-old", &["urgent"], T0);
    merged.merged_into = Some("k-big".into());
    let l = ledger(vec![
        thread("k-a", &["urgent"], T0),
        thread("k-b", &["urgent"], T0),
        thread("k-c", &["urgent"], T0),
        merged,
        thread("k-big", &["urgent"], T0),
        thread("k-lone", &["urgent"], T0),
    ]);
    let labels: BTreeMap<String, String> = [
        ("k-a-m0", "agent"),
        ("k-b-m0", "benign"),
        ("k-b-m1", "unsure"),
    ]
    .into_iter()
    .map(|(a, b)| (a.to_string(), b.to_string()))
    .collect();
    let cases: BTreeMap<String, Vec<String>> = [("k-big", "case-1"), ("k-lone", "case-2")]
        .into_iter()
        .map(|(t, c)| (t.to_string(), vec![c.to_string()]))
        .collect();
    let now = T0 + 20 * 86_400;
    let ev = Evidence {
        ledger: &l,
        labels: &labels,
        cases: &cases,
        now,
    };
    let o = |lvl, th, t| ev.outcome(&decision(lvl, th, t));
    assert_eq!(o(Level::Interrupt, "k-a", T0), Outcome::Agreed);
    assert_eq!(o(Level::Interrupt, "k-b", T0), Outcome::Disagreed);
    assert_eq!(o(Level::Interrupt, "k-c", T0), Outcome::Pending);
    // A case on the thread it was merged into agrees.
    assert_eq!(o(Level::DraftCase, "k-old", T0), Outcome::Agreed);
    // A draft case with no case after two weeks disagrees; before, it waits.
    assert_eq!(o(Level::DraftCase, "k-c", T0), Outcome::Disagreed);
    assert_eq!(o(Level::DraftCase, "k-c", now - 86_400), Outcome::Pending);
    // An agent label alone does not agree with a draft case.
    assert_eq!(o(Level::DraftCase, "k-a", now - 86_400), Outcome::Pending);

    let mut held = decision(Level::Interrupt, "k-c", T0);
    held.suppressed = Some("rate limit".into());
    let log = vec![
        decision(Level::Interrupt, "k-a", T0),
        decision(Level::Interrupt, "k-b", T0),
        decision(Level::Interrupt, "k-c", T0),
        held,
        decision(Level::DraftCase, "k-old", T0),
    ];
    let recs = agreement(&log, &Config::default(), &ev);
    let i = &recs[0];
    assert_eq!(i.level, Level::Interrupt);
    assert_eq!((i.decisions, i.suppressed), (4, 1));
    assert_eq!((i.agreed, i.disagreed, i.pending), (1, 1, 1));
    assert_eq!(i.agreement, Some(0.5));
    assert_eq!(i.missed, None);
    let d = &recs[2];
    assert_eq!((d.agreed, d.agreement), (1, Some(1.0)));
    // The case on k-lone was never proposed.
    assert_eq!(d.missed, Some(1));
}

#[test]
fn the_log_appends_reads_and_prunes() {
    let dir = std::env::temp_dir().join(format!("swarmchase-autonomy-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    append(
        &dir,
        &[
            decision(Level::Interrupt, "k-a", T0),
            decision(Level::DraftCase, "k-b", T0 + 86_400),
        ],
    )
    .unwrap();
    std::fs::OpenOptions::new()
        .append(true)
        .open(dir.join(FILE))
        .and_then(|mut f| std::io::Write::write_all(&mut f, b"not json\n"))
        .unwrap();
    assert_eq!(load(&dir).len(), 2);
    assert_eq!(prune(&dir, T0 + 1).unwrap(), 1);
    let left = load(&dir);
    assert_eq!(left.len(), 1);
    assert_eq!(left[0].thread, "k-b");
    let _ = std::fs::remove_dir_all(&dir);
}
