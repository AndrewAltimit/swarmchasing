use super::*;
use sc_core::declared::Declared;
use sc_core::plant::PlantSignal;
use sc_core::{Observation, Rules, analyze};

const T0: i64 = 1_791_000_000;

/// The queue of analysis `a` on a fresh ledger, as a first run sees it.
pub(crate) fn queue_of(a: &Analysis, ids: &BTreeSet<String>) -> Queue {
    let mut l = Ledger::new();
    let o = l.observe(a, "R1", T0 + 3600, ids);
    rank(&Input {
        analysis: a,
        ledger: &l,
        observed: &o,
        stamp: "R1",
        now: T0 + 3600,
        cases: &BTreeMap::new(),
    })
}

/// One relayed SQL injection run against `host`, tagged `tag`.
fn records(prefix: &str, host: &str, tag: &str) -> Vec<Observation> {
    (0..4)
        .map(|i| Observation {
            id: format!("{prefix}{i}"),
            source: "wayback".into(),
            ts: T0 + i * 30,
            url: format!("https://r.jina.ai/https://{host}/q?id=1'%20OR%201=1--&uqtag={tag}&n={i}"),
            ..Default::default()
        })
        .collect()
}

/// The single cluster's item after `f` sets its grade and other facts.
fn item_with(f: impl FnOnce(&mut Cluster)) -> Item {
    let obs = records("r", "portal.example.gov", "run7");
    let ids = obs.iter().map(|o| o.id.clone()).collect();
    let mut a = analyze(obs, &Rules::default_rules());
    assert_eq!(a.clusters.len(), 1);
    // The facts under test are set by `f`, not by the fixture's scope pass.
    a.clusters[0].scope = Default::default();
    f(&mut a.clusters[0]);
    let q = queue_of(&a, &ids);
    assert_eq!(q.items.len(), 1);
    q.items[0].clone()
}

fn targets(c: &mut Cluster, classes: &[TargetClass]) {
    c.scope.target_classes = classes.iter().map(|k| (*k, 1)).collect();
}

#[test]
fn bands_come_from_combinations_not_sums() {
    // L3 reaching an access-controlled endpoint: urgent.
    let it = item_with(|c| {
        c.agent.level = AgentLevel::Adaptive;
        targets(c, &[TargetClass::AccessControlled]);
    });
    assert_eq!(it.band, Band::Urgent, "{it:?}");
    assert!(it.why[0].contains("access-controlled"), "{:?}", it.why);
    assert_eq!(it.harm, Harm::Elevated);

    // L2 on sensitive targets: urgent; L2 on public content: look.
    let it = item_with(|c| {
        c.agent.level = AgentLevel::ModelWritten;
        targets(c, &[TargetClass::Sensitive]);
    });
    assert_eq!(it.band, Band::Urgent);
    let it = item_with(|c| {
        c.agent.level = AgentLevel::ModelWritten;
        targets(c, &[TargetClass::PublicContent]);
    });
    assert_eq!(it.band, Band::Look);

    // A self-description with sensitive targets is never urgent: anyone
    // can write one. Significant with those targets is still worth a look.
    let it = item_with(|c| {
        c.agent.level = AgentLevel::SelfDescribed;
        c.tier = Tier::Significant;
        targets(c, &[TargetClass::Sensitive]);
    });
    assert_eq!(it.band, Band::Look, "{it:?}");

    // L2 with scope exceeded: urgent.
    let it = item_with(|c| {
        c.agent.level = AgentLevel::ModelWritten;
        c.scope.finding = ScopeFinding::ScopeExceeded;
    });
    assert_eq!(it.band, Band::Urgent);

    // Payloads alone: watch.
    let it = item_with(|c| {
        c.agent.level = AgentLevel::PayloadsOnly;
        c.tier = Tier::Suggestive;
    });
    assert_eq!(it.band, Band::Watch);
    assert!(!it.why.is_empty());
}

#[test]
fn caps_hold_a_band_down_and_say_so() {
    let urgent = |c: &mut Cluster| {
        c.agent.level = AgentLevel::Adaptive;
        targets(c, &[TargetClass::Sensitive]);
    };
    let it = item_with(|c| {
        urgent(c);
        c.origin.plant_signals.push(PlantSignal {
            kind: PlantSignalKind::TooPerfect,
            records: vec![0],
            detail: String::new(),
            base_rate: None,
        });
    });
    assert_eq!(it.band, Band::Look);
    assert!(it.caps[0].starts_with("held at look"), "{:?}", it.caps);

    // Provenance monoculture, and a signal with a base rate, hold nothing.
    let it = item_with(|c| {
        urgent(c);
        c.origin.plant_signals = vec![
            PlantSignal {
                kind: PlantSignalKind::ProvenanceMonoculture,
                records: vec![0],
                detail: String::new(),
                base_rate: None,
            },
            PlantSignal {
                kind: PlantSignalKind::HabitMismatch,
                records: vec![0],
                detail: String::new(),
                base_rate: Some(0.7),
            },
        ];
    });
    assert_eq!(it.band, Band::Urgent, "{:?}", it.caps);

    let it = item_with(|c| {
        urgent(c);
        c.declared.push(Declared {
            text: "User-Agent: research-bot".into(),
            contact: Some("someone@example.org".into()),
            records: 2,
        });
    });
    assert_eq!(it.band, Band::Look);
    // A declared contact never reaches the queue.
    assert!(!format!("{it:?}").contains("someone@"), "{it:?}");

    let it = item_with(|c| {
        urgent(c);
        targets(c, &[TargetClass::Benchmark]);
    });
    assert_eq!(it.band, Band::Watch);
}

#[test]
fn momentum_is_the_sum_of_named_bounded_parts() {
    let it = item_with(|c| c.agent.level = AgentLevel::ModelWritten);
    let names: Vec<&str> = it.factors.iter().map(|f| f.name.as_str()).collect();
    assert_eq!(
        names,
        [
            "growth",
            "spread",
            "interaction",
            "recency",
            "novelty",
            "volume"
        ]
    );
    assert_eq!(it.factors.iter().map(|f| f.max).sum::<u32>(), 100);
    assert_eq!(
        it.momentum,
        it.factors.iter().map(|f| f.points).sum::<u32>()
    );
    assert!(it.factors.iter().all(|f| f.points <= f.max));
    // A first sighting is new, and its latest record is an hour old.
    assert_eq!(it.trajectory, Trajectory::New);
    let get = |n: &str| it.factors.iter().find(|f| f.name == n).unwrap().points;
    assert_eq!(get("novelty"), 15);
    assert_eq!(get("recency"), 20);
    assert_eq!(get("growth"), 0);
    assert_eq!(it.targets, ["portal[.]example[.]gov"]);
    assert_eq!(it.sources, ["wayback"]);
}

#[test]
fn rank_orders_band_grade_harm_then_cases_then_momentum() {
    let mut obs = records("a", "one.example.gov", "aaa");
    obs.extend(records("b", "two.example.gov", "bbb"));
    obs.extend(records("c", "three.example.gov", "ccc"));
    obs.extend(records("d", "four.example.gov", "ddd"));
    let ids: BTreeSet<String> = obs.iter().map(|o| o.id.clone()).collect();
    let mut a = analyze(obs, &Rules::default_rules());
    assert_eq!(a.clusters.len(), 4);
    let host = |c: &Cluster| c.target_hosts.keys().next().unwrap().clone();
    for c in &mut a.clusters {
        c.scope = Default::default();
        c.tier = Tier::Significant;
        match host(c).as_str() {
            // look at L2
            "one.example.gov" => c.agent.level = AgentLevel::ModelWritten,
            // look at L3: above the L2 lead in the same band
            "two.example.gov" => c.agent.level = AgentLevel::Adaptive,
            // watch at L1, which ranks with L0
            "three.example.gov" => c.agent.level = AgentLevel::SelfDescribed,
            _ => c.agent.level = AgentLevel::PayloadsOnly,
        }
    }
    let mut l = Ledger::new();
    let o = l.observe(&a, "R1", T0 + 3600, &ids);
    let mut cases = BTreeMap::new();
    let q0 = rank(&Input {
        analysis: &a,
        ledger: &l,
        observed: &o,
        stamp: "R1",
        now: T0 + 3600,
        cases: &cases,
    });
    let order: Vec<String> = q0.items.iter().map(|i| i.targets[0].clone()).collect();
    assert_eq!(order[0], "two[.]example[.]gov");
    assert_eq!(order[1], "one[.]example[.]gov");
    assert_eq!(q0.by_band["look"], 2);
    assert_eq!(q0.by_band["watch"], 2);
    assert_eq!(
        q0.items.iter().map(|i| i.rank).collect::<Vec<_>>(),
        [1, 2, 3, 4]
    );

    // Grade and targets come before cases; within the watch band, a lead a
    // case covers goes after one no case does.
    let watch: Vec<&Item> = q0.items.iter().filter(|i| i.band == Band::Watch).collect();
    cases.insert(watch[0].thread.clone(), vec!["case-1".to_string()]);
    let q1 = rank(&Input {
        analysis: &a,
        ledger: &l,
        observed: &o,
        stamp: "R1",
        now: T0 + 3600,
        cases: &cases,
    });
    assert_eq!(q1.items[0].targets, q0.items[0].targets);
    assert_eq!(q1.items[3].thread, watch[0].thread);
    assert_eq!(q1.items[3].cases, ["case-1"]);
}
