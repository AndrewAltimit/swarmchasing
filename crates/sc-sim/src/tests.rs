//! The measurement over the committed interaction samples.

use super::*;
use sc_core::{FieldMap, Format, Observation, Rules, analyze, parse_input};

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

#[test]
fn a_gist_one_agent_names_and_others_fetch_draws_handoff_edges() {
    let rules = Rules::default_rules();
    let file = ScenarioFile {
        scenario: vec![scenario("handoff")],
    };
    let r = bench(&file, &Palette::default_palette(&rules), &rules);
    let m = &r[0].1;
    let s2 = &m.edges["handoff"];
    assert!(s2.correct > 0 && s2.correct == s2.pairs, "{}", render(m));
}

#[test]
fn off_hour_swarms_start_off_the_clock() {
    let rules = Rules::default_rules();
    let p = Palette::default_palette(&rules);
    let s = scenario("sync-off-hour");
    for seed in 91..95 {
        let recs = generate(&s, seed, &p);
        let text = to_ndjson(&recs);
        let obs = parse_input(&text, Format::Auto, &FieldMap::default()).observations;
        let truth = Truth::from_ndjson(&text);
        let mut firsts: std::collections::BTreeMap<String, i64> = Default::default();
        for o in &obs {
            let t = truth.get(&o.id).unwrap();
            if t.class == "swarm_agent" {
                firsts.entry(t.run.clone()).or_insert(o.ts);
            }
        }
        assert_eq!(firsts.len(), 3);
        for ts in firsts.values() {
            let past = ts.rem_euclid(3600);
            assert!((7 * 60..54 * 60).contains(&past), "{past}");
        }
    }
}

#[test]
fn every_kind_carries_its_denominator_fired_or_not() {
    // Scenarios where most kinds draw nothing: each still counts the true
    // pairs it could reach, so a sum over seeds reads the misses.
    let rules = Rules::default_rules();
    let file = ScenarioFile {
        scenario: vec![scenario("fleet"), scenario("submit-basis")],
    };
    let mut total = Measurement::default();
    for (_, m) in bench(&file, &Palette::default_palette(&rules), &rules) {
        let links = m.operator_pairs.reachable - m.operator_pairs.joined;
        for (k, s) in &m.edges {
            assert_eq!(s.of, m.swarm_pairs.reachable, "{k}: {}", render(&m));
        }
        for (k, s) in &m.links {
            assert_eq!(s.of, links, "{k}: {}", render(&m));
        }
        assert!(m.edges.contains_key("any"));
        for k in ["any", "candidate_fleet", "co_activity", "scaffold", "rerun"] {
            assert!(m.links.contains_key(k), "{k}");
        }
        total.add(&m);
    }
    let links = total.operator_pairs.reachable - total.operator_pairs.joined;
    assert!(
        total
            .edges
            .values()
            .all(|s| s.of == total.swarm_pairs.reachable)
    );
    assert!(total.links.values().all(|s| s.of == links));
}

/// `name` benched under its first seed only.
fn bench_one(name: &str) -> Measurement {
    let rules = Rules::default_rules();
    let mut s = scenario(name);
    s.seeds = 1;
    let file = ScenarioFile { scenario: vec![s] };
    bench(&file, &Palette::default_palette(&rules), &rules)
        .remove(0)
        .1
}

#[test]
fn a_fleets_harness_adds_its_parameters_in_one_rotation() {
    let rules = Rules::default_rules();
    let p = Palette::default_palette(&rules);
    let text = to_ndjson(&generate(&scenario("fleet"), 51, &p));
    let truth = Truth::from_ndjson(&text);
    let obs = parse_input(&text, Format::Auto, &FieldMap::default()).observations;
    // Per run, the scaffold templates in order and the harness parameters.
    let mut runs: std::collections::BTreeMap<String, Vec<(String, Vec<String>)>> =
        Default::default();
    for o in &obs {
        let t = truth.get(&o.id).unwrap();
        if t.class != "scaffold_fleet" {
            continue;
        }
        let names: Vec<String> = o
            .url
            .split(['?', '&'])
            .skip(1)
            .filter_map(|kv| kv.split_once('=').map(|x| x.0.to_string()))
            .filter(|n| super::generate::is_harness_param(n))
            .collect();
        let origin = o.id.clone();
        runs.entry(t.run.clone()).or_default().push((origin, names));
    }
    assert_eq!(runs.len(), 3);
    for recs in runs.values() {
        assert_eq!(recs.len(), 8);
        // Two harness parameters on every request, the same two everywhere.
        assert!(recs.iter().all(|(_, n)| n.len() == 2), "{recs:?}");
        assert!(recs.windows(2).all(|w| w[0].1 == w[1].1));
    }
    let first: Vec<&Vec<String>> = runs.values().map(|r| &r[0].1).collect();
    assert!(first.windows(2).all(|w| w[0] == w[1]));
}

#[test]
fn a_large_fleet_is_one_co_group_and_a_crowd_on_one_site_none() {
    let m = bench_one("fleet-large");
    let g = &m.links["co_group"];
    assert!(g.found > 0 && g.correct == g.pairs, "{}", render(&m));
    let m = bench_one("news-spike-large");
    assert_eq!(m.links["co_group"].pairs, 0, "{}", render(&m));
}

#[test]
fn styled_tags_are_fresh_per_run_and_keep_their_generator() {
    let rules = Rules::default_rules();
    let p = Palette::default_palette(&rules);
    let text = to_ndjson(&generate(&scenario("fleet-randomtags"), 401, &p));
    let truth = Truth::from_ndjson(&text);
    let obs = parse_input(&text, Format::Auto, &FieldMap::default()).observations;
    // Each fleet run's tag (the last uqtag: palette records carry their
    // own), by actor.
    let mut tags: std::collections::BTreeMap<String, std::collections::BTreeSet<String>> =
        Default::default();
    for o in &obs {
        let t = truth.get(&o.id).unwrap();
        let Some(f) = &t.fleet else { continue };
        if let Some(v) = o
            .url
            .split(['?', '&'])
            .filter_map(|kv| kv.strip_prefix("uqtag="))
            .next_back()
        {
            tags.entry(f.clone()).or_default().insert(v.to_string());
        }
    }
    let fleet = |a: &str| tags[&format!("fleet-randomtags-f{a}")].clone();
    // A fresh tag per run, three runs each.
    for a in ["0", "1", "2"] {
        assert_eq!(fleet(a).len(), 3, "{tags:?}");
    }
    // UUIDv1s on one node; ULIDs of 26 characters; one counter's stem.
    let nodes: std::collections::BTreeSet<String> =
        fleet("0").iter().map(|v| v[24..].to_string()).collect();
    assert!(
        fleet("0")
            .iter()
            .all(|v| v.len() == 36 && &v[14..15] == "1")
    );
    assert_eq!(nodes.len(), 1, "{nodes:?}");
    assert!(fleet("1").iter().all(|v| v.len() == 26));
    let stems: std::collections::BTreeSet<String> = fleet("2")
        .iter()
        .map(|v| v.trim_end_matches(|c: char| c.is_ascii_digit()).to_string())
        .collect();
    assert_eq!(stems.len(), 1, "{stems:?}");
    let m = bench_one("fleet-randomtags");
    let g = &m.links["generator"];
    assert!(g.found > 0 && g.correct == g.pairs, "{}", render(&m));
}

#[test]
fn a_fleet_among_hundreds_of_agents_draws_scaffold_links() {
    let m = bench_one("fleet-crowd");
    let s = &m.links["scaffold"];
    assert!(s.found > 0 && s.correct == s.pairs, "{}", render(&m));
}

#[test]
fn an_agent_changing_route_draws_escalation_links() {
    let m = bench_one("escalation");
    let e = &m.links["escalation"];
    // Each route a separate tool: two clusters of one run.
    assert!(e.pairs > 0 && e.same_run == e.pairs, "{}", render(&m));
    // Counted as split runs rejoined, not as pairs of distinct runs.
    assert!(
        e.rejoined > 0 && e.rejoined <= m.split_pairs,
        "{}",
        render(&m)
    );
    assert_eq!(e.cross_correct, 0);
    assert_eq!(e.cross_run_precision().n, 0);
}

#[test]
fn a_benign_record_without_an_actor_is_left_out_of_the_grades() {
    let t = Truth::from_ndjson(
        "{\"id\":\"b\",\"run\":\"r1\",\"label\":\"benign\"}\n\
         {\"id\":\"a\",\"run\":\"r2\",\"label\":\"agent\"}\n\
         {\"id\":\"h\",\"run\":\"r3\",\"actor\":\"human\"}\n",
    );
    assert_eq!(t.get("b").unwrap().actor, None);
    assert_eq!(
        t.get("a").unwrap().actor,
        Some(sc_core::eval::grades::Actor::Agent)
    );
    assert_eq!(
        t.get("h").unwrap().actor,
        Some(sc_core::eval::grades::Actor::Human)
    );
}

#[test]
fn benign_look_alikes_are_unrelated_tools() {
    let rules = Rules::default_rules();
    let p = Palette::default_palette(&rules);
    let s = scenario("null-lookalikes");
    let text = to_ndjson(&generate(&s, s.seed, &p));
    let truth = Truth::from_ndjson(&text);
    let obs = parse_input(&text, Format::Auto, &FieldMap::default()).observations;
    let mut by_class: std::collections::BTreeMap<String, Vec<&Observation>> = Default::default();
    for o in &obs {
        let t = truth.get(&o.id).unwrap();
        if t.class == "single_agent" {
            continue;
        }
        assert_eq!(t.label, Some(sc_core::Label::Benign), "{}", t.class);
        assert_eq!(t.actor, Some(sc_core::eval::grades::Actor::Tool));
        assert_eq!(t.operator(), format!("run:{}", t.run));
        by_class.entry(t.class.clone()).or_default().push(o);
    }
    let classes: Vec<&str> = by_class.keys().map(String::as_str).collect();
    assert_eq!(
        classes,
        [
            "feed_poller",
            "internet_scanner",
            "link_preview",
            "uptime_monitor"
        ]
    );
    // The monitor's regions check each URL within a second of each other,
    // from different networks.
    let mut checks: std::collections::BTreeMap<String, Vec<i64>> = Default::default();
    for o in &by_class["uptime_monitor"] {
        checks.entry(o.url.clone()).or_default().push(o.ts);
    }
    let first = by_class["uptime_monitor"][0].ts;
    let minute: Vec<i64> = by_class["uptime_monitor"]
        .iter()
        .filter(|o| o.ts - first < 60)
        .map(|o| o.ts)
        .collect();
    assert_eq!(minute.len(), 4, "{minute:?}");
    assert!(minute.iter().max().unwrap() - minute.iter().min().unwrap() <= 1);
    let nets: std::collections::BTreeSet<u32> = by_class["uptime_monitor"]
        .iter()
        .filter_map(|o| o.asn)
        .collect();
    assert_eq!(nets.len(), 4);
    // The scanner's addresses share one network and one /24.
    let scan = &by_class["internet_scanner"];
    let asns: std::collections::BTreeSet<u32> = scan.iter().filter_map(|o| o.asn).collect();
    let ips: std::collections::BTreeSet<&str> =
        scan.iter().filter_map(|o| o.ip.as_deref()).collect();
    let nets: std::collections::BTreeSet<&str> = ips
        .iter()
        .map(|ip| ip.rsplit_once('.').unwrap().0)
        .collect();
    assert_eq!((asns.len(), ips.len(), nets.len()), (1, 6, 1));
}

#[test]
fn a_planter_copying_timing_replays_its_victims_times() {
    let rules = Rules::default_rules();
    let p = Palette::default_palette(&rules);
    let s = scenario("planted-timing");
    let text = to_ndjson(&generate(&s, s.seed, &p));
    let truth = Truth::from_ndjson(&text);
    let obs = parse_input(&text, Format::Auto, &FieldMap::default()).observations;
    let times = |run: &str| -> Vec<i64> {
        obs.iter()
            .filter(|o| truth.get(&o.id).unwrap().run == run)
            .map(|o| o.ts)
            .collect()
    };
    let victim = times("planted-timing-a0-0");
    let planter = times("planted-timing-a1-0");
    assert_eq!(planter.len(), victim.len().min(8), "{planter:?} {victim:?}");
    let offset = planter[0] - victim[0];
    assert!((2..20).contains(&offset), "{offset}");
    for (a, b) in victim.iter().zip(&planter) {
        assert_eq!(b - a, offset);
    }
}

#[test]
fn null_scenarios_are_counted_apart() {
    let rules = Rules::default_rules();
    let f = ScenarioFile::parse(SCENARIOS).unwrap();
    let nulls: Vec<&Scenario> = f.scenario.iter().filter(|s| s.null).collect();
    assert!(nulls.len() >= 2);
    let mut s = nulls[0].clone();
    s.seeds = 1;
    let file = ScenarioFile { scenario: vec![s] };
    let r = bench(&file, &Palette::default_palette(&rules), &rules);
    let n = null_counts(&r, &file);
    assert_eq!((n.scenarios, n.seeds), (1, 1));
    // No two runs are related, so nothing drawn between runs is right.
    let m = &r[0].1;
    assert_eq!((m.swarm_pairs.total, m.operator_pairs.total), (0, 0));
    assert_eq!(n.edges, m.edges["any"].unrelated);
}
