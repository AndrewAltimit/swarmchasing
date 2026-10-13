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
