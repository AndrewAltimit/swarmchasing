//! The measurement over the committed interaction samples.

use super::*;
use sc_core::{FieldMap, Format, Rules, analyze, parse_input};

const SWARMS: &str = include_str!("../../../samples/eval/swarm-interaction.ndjson");

fn measured() -> Measurement {
    let obs = parse_input(SWARMS, Format::Auto, &FieldMap::default()).observations;
    let a = analyze(obs, &Rules::default_rules());
    measure(&a, &Truth::from_ndjson(SWARMS))
}

#[test]
fn truth_reads_label_fields() {
    let t = Truth::from_ndjson(SWARMS);
    let r = t.get("eval:swarm-shard-00").unwrap();
    assert_eq!(r.swarm_id(), None);
    assert_eq!(r.operator(), "fleet:swarm-shard");
    let r = t.get("eval:swarm-sink-d0").unwrap();
    assert_eq!(r.operator(), "swarm:sink-1");
}

#[test]
fn edges_are_placed_on_true_runs() {
    let m = measured();
    // Three interacting pairs (hand-off, sink, roles) and the shard pair.
    assert_eq!(m.swarm_pairs.total, 3);
    assert_eq!(m.operator_pairs.total, 4);
    let any = &m.edges["any"];
    assert_eq!(any.found, any.of, "{}", render(&m));
    for k in ["shared_sink", "handoff", "role_sequence"] {
        assert_eq!(m.edges[k].correct, 1, "{k}: {}", render(&m));
    }
    // The sharded scheduler is one operator, not a swarm.
    let p = &m.edges["disjoint_partition"];
    assert_eq!((p.correct, p.same_operator), (0, 1), "{}", render(&m));
    // Every kind is listed, fired or not.
    assert!(m.edges.len() > sc_core::SwarmEdgeKind::ALL.len());
}

#[test]
fn measurements_add() {
    let one = measured();
    let mut two = one.clone();
    two.add(&one);
    assert_eq!(two.records, 2 * one.records);
    assert_eq!(two.edges["any"].found, 2 * one.edges["any"].found);
}

const SCENARIOS: &str = include_str!("../../../samples/sim/scenarios.toml");

fn scenario(name: &str) -> Scenario {
    let f = ScenarioFile::parse(SCENARIOS).unwrap();
    f.scenario.into_iter().find(|s| s.name == name).unwrap()
}

#[test]
fn committed_scenarios_parse() {
    let f = ScenarioFile::parse(SCENARIOS).unwrap();
    assert!(f.scenario.len() >= 5);
    assert!(ScenarioFile::parse("[[scenario]]\nname = \"x\"\n").is_err());
}

#[test]
fn generation_is_deterministic_and_labelled() {
    let rules = Rules::default_rules();
    let p = Palette::default_palette(&rules);
    let s = scenario("sink");
    let a = to_ndjson(&generate(&s, 5, &p));
    assert_eq!(a, to_ndjson(&generate(&s, 5, &p)));
    assert_ne!(a, to_ndjson(&generate(&s, 6, &p)));
    let t = Truth::from_ndjson(&a);
    assert_eq!(t.rows.len(), a.lines().count());
    for line in a.lines() {
        let v: serde_json::Value = serde_json::from_str(line).unwrap();
        assert_eq!(v["synthetic"], true);
        assert!(v["cite"].as_str().unwrap().starts_with("synthetic: sc-sim"));
    }
    let obs = parse_input(&a, Format::Auto, &FieldMap::default()).observations;
    assert!(obs.iter().all(|o| o.ts > 0));
    // Every target host is a reserved name the generator chose.
    let hosts: Vec<_> = obs
        .iter()
        .filter_map(|o| sc_core::extract(o, &rules).target_host)
        .collect();
    assert!(!hosts.is_empty());
    assert!(hosts.iter().all(|h| h.ends_with(".example")), "{hosts:?}");
}

#[test]
fn a_swarm_sharing_one_inbox_draws_shared_sink_edges() {
    let rules = Rules::default_rules();
    let file = ScenarioFile {
        scenario: vec![scenario("sink")],
    };
    let r = bench(&file, &Palette::default_palette(&rules), &rules);
    let m = &r[0].1;
    let s1 = &m.edges["shared_sink"];
    assert!(s1.correct > 0 && s1.correct == s1.pairs, "{}", render(m));
}

#[test]
fn separate_runs_get_separate_identifiers() {
    let rules = Rules::default_rules();
    let p = Palette::default_palette(&rules);
    let text = to_ndjson(&generate(&scenario("fleet"), 51, &p));
    let obs = parse_input(&text, Format::Auto, &FieldMap::default()).observations;
    let truth = Truth::from_ndjson(&text);
    let mut owner: std::collections::BTreeMap<String, String> = Default::default();
    for o in &obs {
        let run = &truth.get(&o.id).unwrap().run;
        for f in sc_core::extract(o, &rules).features {
            let prev = owner.entry(f.to_string()).or_insert_with(|| run.clone());
            assert_eq!(prev, run, "{f} shared across runs");
        }
    }
}
