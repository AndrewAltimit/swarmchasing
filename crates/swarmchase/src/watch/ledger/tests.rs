use super::*;
use sc_core::{Observation, Rules, analyze};

const T0: i64 = 1_791_000_000;
const HOUR: i64 = 3600;

/// A relayed SQL injection request to `host`, tagged `param=tag`.
fn rec(id: &str, host: &str, query: &str, ts: i64) -> Observation {
    Observation {
        id: id.into(),
        source: "wayback".into(),
        ts,
        url: format!("https://r.jina.ai/https://{host}/q?id=1'%20OR%201=1--&{query}&n={id}"),
        ..Default::default()
    }
}

fn run(n: usize, from: usize, t: i64) -> Vec<Observation> {
    (from..n)
        .map(|i| {
            rec(
                &format!("r{i}"),
                "portal.example.gov",
                "uqtag=run7",
                t + i as i64 * 30,
            )
        })
        .collect()
}

fn ids(obs: &[Observation]) -> BTreeSet<String> {
    obs.iter().map(|o| o.id.clone()).collect()
}

fn above_noise(a: &Analysis) -> Vec<&sc_core::Cluster> {
    a.clusters
        .iter()
        .filter(|c| c.tier >= Tier::Suggestive)
        .collect()
}

#[test]
fn follows_a_cluster_across_runs_and_counts_what_each_run_added() {
    let rules = Rules::default_rules();
    let mut l = Ledger::new();
    let first = run(4, 0, T0);
    let a1 = analyze(first.clone(), &rules);
    assert_eq!(above_noise(&a1).len(), 1);
    let o1 = l.observe(&a1, "R1", T0 + HOUR, &ids(&first));
    let more = run(6, 4, T0);
    let mut all = first.clone();
    all.extend(more.clone());
    let a2 = analyze(all, &rules);
    let o2 = l.observe(&a2, "R2", T0 + 7 * HOUR, &ids(&more));

    assert_eq!(l.threads.len(), 1, "{:?}", l.threads.keys());
    let id = o1.threads.values().next().unwrap();
    assert_eq!(o2.threads.values().next().unwrap(), id);
    let th = &l.threads[id];
    assert_eq!(th.points.len(), 2);
    assert_eq!((th.points[0].added, th.points[1].added), (4, 2));
    assert_eq!(th.points[1].records, 6);
    assert_eq!(th.first_run, "R1");
    assert_eq!(th.last_run, "R2");
    assert_eq!(th.trajectory("R2"), Trajectory::Active);
    assert_eq!(th.trajectory("R3"), Trajectory::Dormant);
    assert_eq!(th.sparkline(10), [4, 6]);
    assert!(th.members.contains(&"r5".to_string()));
}

#[test]
fn a_new_key_keeps_the_thread() {
    let rules = Rules::default_rules();
    let mut l = Ledger::new();
    let all = run(5, 0, T0);
    let a1 = analyze(all.clone(), &rules);
    l.observe(&a1, "R1", T0, &ids(&all));
    // The earliest record leaves the window: the cluster is re-keyed.
    let rest: Vec<Observation> = all[1..].to_vec();
    let a2 = analyze(rest, &rules);
    assert_ne!(above_noise(&a1)[0].key, above_noise(&a2)[0].key);
    l.observe(&a2, "R2", T0 + HOUR, &BTreeSet::new());

    assert_eq!(l.threads.len(), 1);
    let th = l.threads.values().next().unwrap();
    assert_eq!(th.id, above_noise(&a1)[0].key);
    assert_eq!(th.key, above_noise(&a2)[0].key);
    assert_eq!(th.keys.len(), 2);
    assert!(
        th.events.iter().any(|e| e.kind == EventKind::Rekeyed),
        "{:?}",
        th.events
    );
}

/// Two runs, tagged `uqtag=aaa` and `tok=bbbb` on different hosts, and
/// optionally a record carrying both that joins them.
fn pair(bridge: bool) -> Vec<Observation> {
    let mut out = Vec::new();
    for i in 0..3 {
        out.push(rec(
            &format!("x{i}"),
            "one.example.gov",
            "uqtag=aaa",
            T0 + i * 30,
        ));
        out.push(rec(
            &format!("y{i}"),
            "two.example.gov",
            "tok=bbbb",
            T0 + 3 * HOUR + i * 30,
        ));
    }
    if bridge {
        out.push(rec(
            "z",
            "three.example.gov",
            "uqtag=aaa&tok=bbbb",
            T0 + 6 * HOUR,
        ));
    }
    out
}

#[test]
fn merges_and_splits_follow_shared_records() {
    let rules = Rules::default_rules();
    let mut l = Ledger::new();
    let a1 = analyze(pair(false), &rules);
    assert_eq!(above_noise(&a1).len(), 2);
    l.observe(&a1, "R1", T0 + 7 * HOUR, &ids(&pair(false)));
    assert_eq!(l.threads.len(), 2);

    let a2 = analyze(pair(true), &rules);
    assert_eq!(above_noise(&a2).len(), 1);
    l.observe(&a2, "R2", T0 + 8 * HOUR, &ids(&pair(true)[6..]));
    let merged: Vec<&Thread> = l
        .threads
        .values()
        .filter(|t| t.merged_into.is_some())
        .collect();
    assert_eq!(merged.len(), 1, "{:?}", l.threads);
    let into = merged[0].merged_into.clone().unwrap();
    assert!(
        l.threads[&into]
            .events
            .iter()
            .any(|e| e.kind == EventKind::Merged),
        "{:?}",
        l.threads[&into].events
    );

    // Apart again: one part keeps the thread, the other splits from it.
    l.observe(&a1, "R3", T0 + 9 * HOUR, &BTreeSet::new());
    let split: Vec<&Thread> = l
        .threads
        .values()
        .filter(|t| t.events.iter().any(|e| e.kind == EventKind::Split))
        .collect();
    assert_eq!(split.len(), 1, "{:?}", l.threads);
    assert_eq!(l.threads[&into].last_run, "R3");
}

#[test]
fn a_return_after_a_quiet_week_names_the_earlier_thread() {
    let rules = Rules::default_rules();
    let mut l = Ledger::new();
    let first = run(4, 0, T0);
    let a1 = analyze(first.clone(), &rules);
    l.observe(&a1, "R1", T0 + HOUR, &ids(&first));
    // Twenty days on, the same tag on new records; the old ones have left
    // the window, so the analysis makes a new cluster.
    let later: Vec<Observation> = (0..4)
        .map(|i| {
            rec(
                &format!("s{i}"),
                "portal.example.gov",
                "uqtag=run7",
                T0 + 20 * 86_400 + i * 30,
            )
        })
        .collect();
    let a2 = analyze(later.clone(), &rules);
    l.observe(&a2, "R2", T0 + 20 * 86_400 + HOUR, &ids(&later));

    assert_eq!(l.threads.len(), 2);
    let old = l
        .threads
        .values()
        .find(|t| t.first_run == "R1")
        .unwrap()
        .id
        .clone();
    let new = l.threads.values().find(|t| t.first_run == "R2").unwrap();
    assert_eq!(new.recurs.as_deref(), Some(old.as_str()));
    let e = new
        .events
        .iter()
        .find(|e| e.kind == EventKind::Resurgent)
        .unwrap();
    assert!(
        e.detail.contains("uqtag") && e.detail.contains("19 days"),
        "{e:?}"
    );
    // The feature's value never reaches an event.
    assert!(!e.detail.contains("run7"), "{e:?}");
    assert_eq!(new.trajectory("R2"), Trajectory::Resurgent);
}

fn point(run: &str, t: i64, records: usize, added: usize) -> Point {
    Point {
        run: run.into(),
        t,
        records,
        added,
        ..Default::default()
    }
}

#[test]
fn growth_is_read_against_a_point_a_day_old() {
    let mut th = Thread {
        first_run: "R1".into(),
        points: vec![point("R1", T0, 4, 4), point("R2", T0 + 6 * HOUR, 6, 2)],
        ..Default::default()
    };
    assert_eq!(th.growth(), None, "no point a day old");
    th.points.push(point("R3", T0 + 25 * HOUR, 12, 6));
    assert_eq!(th.growth(), Some(3.0));
    assert_eq!(th.trajectory("R3"), Trajectory::Growing);
    // Twice as many but only two more records is not growth.
    th.points = vec![point("R1", T0, 2, 2), point("R2", T0 + 25 * HOUR, 4, 2)];
    assert_eq!(th.trajectory("R2"), Trajectory::Active);
    th.points[1].added = 0;
    assert_eq!(th.trajectory("R2"), Trajectory::Quiet);
}

#[test]
fn held_needs_the_band_on_consecutive_runs_over_a_span() {
    let mut th = Thread::default();
    for (i, b) in ["look", "urgent", "urgent"].iter().enumerate() {
        th.points.push(Point {
            band: b.to_string(),
            ..point(&format!("R{i}"), T0 + i as i64 * 6 * HOUR, 3, 1)
        });
    }
    assert!(th.held("urgent", 2, 6 * HOUR));
    assert!(!th.held("urgent", 2, 12 * HOUR));
    assert!(!th.held("urgent", 3, 0));
}

#[test]
fn prune_drops_old_points_and_empty_threads() {
    let mut l = Ledger::new();
    l.threads.insert(
        "k-old".into(),
        Thread {
            id: "k-old".into(),
            points: vec![point("R1", T0, 3, 3)],
            ..Default::default()
        },
    );
    l.threads.insert(
        "k-live".into(),
        Thread {
            id: "k-live".into(),
            points: vec![point("R1", T0, 3, 3), point("R9", T0 + 90 * 86_400, 5, 2)],
            events: vec![Event {
                run: "R1".into(),
                kind: EventKind::TierUp,
                detail: String::new(),
            }],
            merged_into: Some("k-old".into()),
            ..Default::default()
        },
    );
    assert_eq!(l.prune(T0 + 86_400), 1);
    let th = &l.threads["k-live"];
    assert_eq!(th.points.len(), 1);
    assert!(th.events.is_empty());
    assert_eq!(th.merged_into, None);
}

#[test]
fn grades_are_written_as_codes() {
    let mut l = Ledger::new();
    l.threads.insert(
        "k-1".into(),
        Thread {
            id: "k-1".into(),
            peak_grade: AgentLevel::Adaptive,
            points: vec![Point {
                grade: AgentLevel::ModelWritten,
                ..point("R1", T0, 1, 1)
            }],
            ..Default::default()
        },
    );
    let text = serde_json::to_string(&l).unwrap();
    assert!(
        text.contains("\"peak_grade\":\"L3\"") && text.contains("\"grade\":\"L2\""),
        "{text}"
    );
    let back: Ledger = serde_json::from_str(&text).unwrap();
    assert_eq!(back.threads["k-1"].peak_grade, AgentLevel::Adaptive);
}

/// An analysis of clusters `(id, key, start, records)`, each record a
/// minute apart, with `links` and `fleets` as given.
fn fleet_analysis(
    clusters: &[(&str, &str, i64, &[&str])],
    links: Vec<sc_core::SoftLink>,
    fleets: Vec<sc_core::CandidateFleet>,
) -> Analysis {
    let mut a = Analysis::default();
    for (id, key, start, recs) in clusters {
        let ci = a.clusters.len();
        let mut members = Vec::new();
        for (k, r) in recs.iter().enumerate() {
            members.push(a.results.len());
            a.results.push(sc_core::ObsResult {
                obs: Observation {
                    id: r.to_string(),
                    ts: start + k as i64 * 60,
                    ..Default::default()
                },
                score: 6,
                tier: Tier::Significant,
                hits: Vec::new(),
                layers: Vec::new(),
                target_host: None,
                features: Vec::new(),
                cluster: Some(ci),
                agent: None,
            });
        }
        a.clusters.push(sc_core::Cluster {
            id: id.to_string(),
            key: key.to_string(),
            start: *start,
            end: start + (recs.len() as i64 - 1) * 60,
            members,
            tier: Tier::Significant,
            ..Default::default()
        });
    }
    a.soft_links = links;
    a.candidate_fleets = fleets;
    a
}

fn soft(a: &str, b: &str, kind: sc_core::SoftLinkKind, lr: f64) -> sc_core::SoftLink {
    sc_core::SoftLink {
        a: a.into(),
        b: b.into(),
        kind,
        strength: sc_core::fleets::strength_of(lr),
        lr,
        detail: String::new(),
    }
}

fn fleet(id: &str, clusters: &[&str]) -> sc_core::CandidateFleet {
    sc_core::CandidateFleet {
        id: id.into(),
        clusters: clusters.iter().map(|c| c.to_string()).collect(),
        kinds: vec![sc_core::SoftLinkKind::CoTarget],
        min_lr: 40.0,
        density: 1.0,
        ..Default::default()
    }
}

#[test]
fn a_fleet_keeps_its_key_and_weak_pairs_add_up_across_windows() {
    use sc_core::SoftLinkKind::{CoActivity, CoTarget};
    const DAY: i64 = 86_400;
    let mut l = Ledger::new();
    let weak = 3f64.exp();
    // Run 1: a fleet of k-a and k-b; k-a and k-c weakly linked.
    let a1 = fleet_analysis(
        &[
            ("C1", "k-a", T0, &["a1", "a2"]),
            ("C2", "k-b", T0 + HOUR, &["b1", "b2"]),
            ("C3", "k-c", T0 + 2 * HOUR, &["c1", "c2"]),
        ],
        vec![
            soft("C1", "C2", CoTarget, 40.0),
            soft("C1", "C3", CoActivity, weak),
        ],
        vec![fleet("F1", &["C1", "C2"])],
    );
    let all =
        |a: &Analysis| -> BTreeSet<String> { a.results.iter().map(|r| r.obs.id.clone()).collect() };
    let o1 = l.observe(&a1, "R1", T0 + DAY, &all(&a1));
    let f1 = l.observe_fleets(&a1, &o1, "R1", T0 + DAY);
    let key = f1.keys["F1"].clone();
    assert_eq!(key, sc_core::fleet_track::fleet_key("k-a"));
    assert!(f1.new.contains(&key));
    assert!(f1.persistent.is_empty());

    // Run 2: the same records renumbered; the fleet keeps its key and the
    // weak pair counts once.
    let a2 = fleet_analysis(
        &[
            ("C1", "k-c", T0 + 2 * HOUR, &["c1", "c2"]),
            ("C2", "k-a", T0, &["a1", "a2"]),
            ("C3", "k-b", T0 + HOUR, &["b1", "b2"]),
        ],
        vec![
            soft("C2", "C3", CoTarget, 40.0),
            soft("C1", "C2", CoActivity, weak),
        ],
        vec![fleet("F1", &["C2", "C3"])],
    );
    let o2 = l.observe(&a2, "R2", T0 + DAY + 6 * HOUR, &BTreeSet::new());
    let f2 = l.observe_fleets(&a2, &o2, "R2", T0 + DAY + 6 * HOUR);
    assert_eq!(f2.keys["F1"], key);
    assert!(f2.new.is_empty());
    let f = &l.fleets[&key];
    assert_eq!((f.runs, f.peak, f.fleet.as_str()), (2, 2, "F1"));
    let p = l
        .pairs
        .iter()
        .find(|p| (p.a.as_str(), p.b.as_str()) == ("k-a", "k-c"))
        .unwrap();
    assert_eq!((p.independent, p.seen), (1, 2));
    assert!(f2.persistent.is_empty());

    // Run 3, a week on: fresh records on both threads, weakly linked again.
    // Two windows that share no record add up past the bound, the first
    // decayed by a week.
    let a3 = fleet_analysis(
        &[
            ("C1", "k-a", T0 + 7 * DAY, &["a3", "a4"]),
            ("C2", "k-c", T0 + 7 * DAY + HOUR, &["c3", "c4"]),
        ],
        vec![soft("C1", "C2", CoActivity, 5f64.exp())],
        Vec::new(),
    );
    let o3 = l.observe(&a3, "R3", T0 + 8 * DAY, &all(&a3));
    let f3 = l.observe_fleets(&a3, &o3, "R3", T0 + 8 * DAY);
    assert!(f3.keys.is_empty());
    assert_eq!(f3.persistent.len(), 1, "{:?}", l.pairs);
    let p = &f3.persistent[0];
    assert_eq!(p.independent, 2);
    assert!(p.total() > sc_core::fleet_track::bound(sc_core::fleet_track::ALPHA));
    assert_eq!(p.kinds, ["co-activity"]);

    // The digest names threads and kinds, never a host.
    let text = super::super::fleet_threads::section(&a3, &l, &f3);
    assert!(text.contains("## Fleet threads (0)"), "{text}");
    assert!(text.contains("### Persistent pairs (1)"), "{text}");
    assert!(text.contains("C1 k-a ↔ C2 k-c"), "{text}");
    let text = super::super::fleet_threads::section(&a2, &l, &f2);
    assert!(
        text.contains(&format!("- {key} (F1, 2 runs since R1)")),
        "{text}"
    );

    // The ledger round-trips, and pruning drops what aged out.
    let back: Ledger = serde_json::from_str(&serde_json::to_string(&l).unwrap()).unwrap();
    assert_eq!(back.fleets.len(), 1);
    assert_eq!(back.pairs.len(), l.pairs.len());
    l.prune(T0 + 7 * DAY);
    assert!(l.fleets.is_empty());
}
