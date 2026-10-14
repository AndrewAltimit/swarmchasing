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
        ..Default::default()
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
        ..Default::default()
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
        ..Default::default()
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
    let file = ScenarioFile {
        scenario: vec![s],
        ..Default::default()
    };
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
fn a_bridging_planter_is_a_seam_between_two_operators() {
    let m = bench_one("planted-bridge");
    let seam = &m.groups["seam"];
    // The planter's client joins both agents' records; the seam names it.
    assert!(seam.of >= 1 && seam.found >= 1, "{}", render(&m));
    assert_eq!(seam.unrelated, 0, "{}", render(&m));
}

#[test]
fn a_launch_is_an_onset_group_and_a_news_spike_none() {
    let rules = Rules::default_rules();
    let p = Palette::default_palette(&rules);
    // No two agents of a launch share a client.
    let s = scenario("swarm-short");
    let text = to_ndjson(&generate(&s, s.seed, &p));
    let truth = Truth::from_ndjson(&text);
    let obs = parse_input(&text, Format::Auto, &FieldMap::default()).observations;
    let mut clients = std::collections::BTreeMap::new();
    for o in &obs {
        let t = truth.get(&o.id).unwrap();
        if t.swarm_id().is_some() {
            clients.insert(t.run.clone(), (o.user_agent.clone(), o.asn));
        }
    }
    let distinct: std::collections::BTreeSet<_> = clients.values().collect();
    assert_eq!((clients.len(), distinct.len()), (15, 15));
    let m = bench_one("swarm-short");
    let g = &m.groups["onset_group"];
    assert!(
        g.found > 0 && g.correct * 10 >= g.pairs * 9,
        "{}",
        render(&m)
    );
    // Unrelated agents on one site keep no group (the scenario's
    // expectations hold the trigger over all its seeds).
    let m = bench_one("news-spike-short");
    assert_eq!(m.groups["onset_group"].pairs, 0, "{}", render(&m));
}

#[test]
fn null_scenarios_are_counted_apart() {
    let rules = Rules::default_rules();
    let f = ScenarioFile::parse(SCENARIOS).unwrap();
    let nulls: Vec<&Scenario> = f.scenario.iter().filter(|s| s.null).collect();
    assert!(nulls.len() >= 2);
    let mut s = nulls[0].clone();
    s.seeds = 1;
    let file = ScenarioFile {
        scenario: vec![s],
        ..Default::default()
    };
    let r = bench(&file, &Palette::default_palette(&rules), &rules);
    let n = null_counts(&r, &file);
    assert_eq!((n.scenarios, n.seeds), (1, 1));
    // No two runs are related, so nothing drawn between runs is right.
    let m = &r[0].1;
    assert_eq!((m.swarm_pairs.total, m.operator_pairs.total), (0, 0));
    assert_eq!(n.edges, m.edges["any"].unrelated);
}

/// Records of one generated scenario under its first seed, with truth.
fn generated(name: &str) -> (Vec<Observation>, Truth) {
    let rules = Rules::default_rules();
    let p = Palette::default_palette(&rules);
    let s = scenario(name);
    let text = to_ndjson(&generate(&s, s.seed, &p));
    let obs = parse_input(&text, Format::Auto, &FieldMap::default()).observations;
    (obs, Truth::from_ndjson(&text))
}

/// `obs` grouped by true run, in time order.
fn by_run<'a>(
    obs: &'a [Observation],
    truth: &Truth,
) -> std::collections::BTreeMap<String, Vec<&'a Observation>> {
    let mut out: std::collections::BTreeMap<String, Vec<&Observation>> = Default::default();
    for o in obs {
        out.entry(truth.get(&o.id).unwrap().run.clone())
            .or_default()
            .push(o);
    }
    for v in out.values_mut() {
        v.sort_by_key(|o| o.ts);
    }
    out
}

fn host(o: &Observation) -> String {
    sc_core::extract(o, &Rules::default_rules())
        .target_host
        .unwrap_or_default()
}

#[test]
fn a_rerun_walks_the_same_hosts_in_order_from_a_new_client_after_a_shared_stall() {
    let (obs, truth) = generated("rerun");
    let runs = by_run(&obs, &truth);
    let first = "rerun-a0-0";
    let (a, b) = (&runs[first], &runs[&format!("{first}r")]);
    let hosts = |r: &[&Observation]| r.iter().map(|o| host(o)).collect::<Vec<_>>();
    assert_eq!(hosts(a), hosts(b));
    assert_ne!(a[0].ip, b[0].ip);
    assert!(b[0].ts - a[0].ts >= 30 * 3600, "{} {}", a[0].ts, b[0].ts);
    let ta = truth.get(&a[0].id).unwrap();
    assert_eq!(ta.operator(), truth.get(&b[0].id).unwrap().operator());
    // The three first-day runs go quiet together, twice, for the stall's
    // length; their pauses start and end within two minutes of each other.
    let pauses: Vec<Vec<(i64, i64)>> = (0..3)
        .map(|k| {
            let r = &runs[&format!("rerun-a0-{k}")];
            r.windows(2)
                .filter(|w| w[1].ts - w[0].ts >= 200 * 60)
                .map(|w| (w[0].ts, w[1].ts))
                .collect()
        })
        .collect();
    for p in &pauses {
        assert_eq!(p.len(), 2, "{pauses:?}");
    }
    for k in 1..3 {
        for (x, y) in pauses[0].iter().zip(&pauses[k]) {
            assert!(
                (x.0 - y.0).abs() <= 120 && (x.1 - y.1).abs() <= 120,
                "{pauses:?}"
            );
        }
    }
}

#[test]
fn a_captured_secret_ties_a_fleet_and_a_demo_key_ties_nothing() {
    let (obs, truth) = generated("shared-secret");
    let key = |o: &Observation| {
        o.url
            .split(['?', '&'])
            .filter_map(|kv| kv.strip_prefix("api_key="))
            .find(|v| v.starts_with("REDACTED-"))
            .map(str::to_string)
    };
    let mut fleet = std::collections::BTreeSet::new();
    let mut stock = std::collections::BTreeSet::new();
    for o in &obs {
        let t = truth.get(&o.id).unwrap();
        match (t.class.as_str(), key(o)) {
            ("scaffold_fleet", Some(k)) => {
                fleet.insert(k);
            }
            ("single_agent", Some(k)) => {
                stock.insert(k);
            }
            _ => {}
        }
    }
    assert_eq!(fleet.len(), 1, "{fleet:?}");
    assert_eq!(stock.len(), 1, "{stock:?}");
    assert!(stock.contains(&sc_core::redact::hash_token("demo")));
    let m = bench_one("shared-secret");
    let s = &m.links["shared_secret"];
    assert!(s.pairs > 0 && s.correct == s.pairs, "{}", render(&m));
}

#[test]
fn an_evasive_swarm_tags_every_request_anew_from_a_new_client() {
    let (obs, truth) = generated("evasive-swarm");
    let runs = by_run(&obs, &truth);
    let swarm: Vec<&Vec<&Observation>> = runs
        .iter()
        .filter(|(r, _)| r.starts_with("evasive-swarm-a0-"))
        .map(|x| x.1)
        .collect();
    assert_eq!(swarm.len(), 3);
    for r in swarm {
        let tags: std::collections::BTreeSet<&str> = r
            .iter()
            .filter_map(|o| o.url.split("uqtag=").nth(1))
            .collect();
        assert_eq!(tags.len(), r.len(), "one tag per request");
        let ips: std::collections::BTreeSet<_> = r.iter().map(|o| &o.ip).collect();
        assert!(ips.len() > r.len() / 2, "{ips:?}");
    }
}

#[test]
fn a_low_and_slow_run_spaces_its_requests_past_the_link_window() {
    let (obs, truth) = generated("low-and-slow");
    let runs = by_run(&obs, &truth);
    let slow = &runs["low-and-slow-a0-0"];
    assert_eq!(slow.len(), 5);
    for w in slow.windows(2) {
        let h = (w[1].ts - w[0].ts) as f64 / 3600.0;
        assert!((72.0..=88.0).contains(&h), "{h}");
    }
}

#[test]
fn link_checkers_and_seo_crawlers_are_unrelated_tools() {
    let (obs, truth) = generated("ci-link-checker");
    let runs = by_run(&obs, &truth);
    assert_eq!(runs.len(), 30);
    let urls = |r: &[&Observation]| r.iter().map(|o| host(o)).collect::<Vec<_>>();
    let one = runs.values().next().unwrap();
    for r in runs.values() {
        let t = truth.get(&r[0].id).unwrap();
        assert_eq!(t.operator(), format!("run:{}", t.run));
        // On the hour, the runner a few seconds late, one list in one order.
        assert!(r[0].ts.rem_euclid(3600) <= 20, "{}", r[0].ts);
        assert_eq!(urls(r), urls(one));
        assert_eq!(r[0].user_agent, one[0].user_agent);
    }
    let (obs, truth) = generated("seo-crawler");
    let runs = by_run(&obs, &truth);
    let vendors: Vec<&Vec<&Observation>> = runs
        .iter()
        .filter(|(r, _)| r.starts_with("seo-crawler-a0-"))
        .map(|x| x.1)
        .collect();
    assert_eq!(vendors.len(), 4);
    for v in vendors {
        // Four consecutive addresses, each with its own share of the sitemap.
        let mut shard: std::collections::BTreeMap<&str, Vec<String>> = Default::default();
        for o in v {
            shard
                .entry(o.ip.as_deref().unwrap())
                .or_default()
                .push(host(o));
        }
        assert_eq!(shard.len(), 4);
        let mut last: Vec<u32> = shard
            .keys()
            .map(|ip| ip.rsplit_once('.').unwrap().1.parse().unwrap())
            .collect();
        last.sort_unstable();
        assert!(last.windows(2).all(|w| w[1] == w[0] + 1), "{last:?}");
        let all: std::collections::BTreeSet<&String> = shard.values().flatten().collect();
        assert_eq!(all.len(), shard.values().map(Vec::len).sum::<usize>());
    }
}

#[test]
fn clusters_are_scored_against_runs() {
    let m = measured();
    let (p, r, f) = m.clustering.bcubed().unwrap();
    assert!((0.0..=1.0).contains(&r) && f > 0.0);
    // The sink swarm's agents share one inbox, and so one cluster: right for
    // precision, a merge of runs for the adjusted Rand index.
    assert!((p - 1.0).abs() < 1e-9, "{p}");
    assert!(m.clustering.ari().unwrap() < 1.0);
    let perfect = Clustering {
        records: 4,
        bcubed_precision_sum: 4.0,
        bcubed_recall_sum: 4.0,
        pairs: 6.0,
        pairs_both: 2.0,
        pairs_group: 2.0,
        pairs_run: 2.0,
    };
    assert_eq!(perfect.ari(), Some(1.0));
    assert_eq!(perfect.bcubed(), Some((1.0, 1.0, 1.0)));
    assert_eq!(Clustering::default().ari(), None);
    // Every agent run is flagged on its first record.
    assert_eq!(m.detection.records_to_flag.len(), m.detection.runs);
    assert_eq!(measure::quantile(&[3.0, 1.0, 2.0], 0.5), Some(2.0));
    assert_eq!(measure::quantile(&[], 0.5), None);
}

#[test]
fn prefixes_time_each_run_to_l2_or_a_fleet() {
    let obs = parse_input(SWARMS, Format::Auto, &FieldMap::default()).observations;
    let truth = Truth::from_ndjson(SWARMS);
    let t = measure::escalation_times(&obs, &truth, &Rules::default_rules(), 3);
    let runs: std::collections::BTreeSet<&str> =
        truth.rows.values().map(|r| r.run.as_str()).collect();
    assert!(!t.is_empty() && t.len() <= runs.len(), "{t:?}");
    assert!(t.iter().all(|m| *m >= 0.0));
    // One bench pass with checkpoints and the calibration counts.
    let rules = Rules::default_rules();
    let mut s = scenario("sink");
    s.seeds = 1;
    let file = ScenarioFile {
        scenario: vec![s],
        ..Default::default()
    };
    let r = bench_with(
        &file,
        &Palette::default_palette(&rules),
        &rules,
        BenchOptions {
            calibrate: true,
            checkpoints: 2,
        },
    );
    assert_eq!(r.calibration.len(), 1);
    assert_eq!(r.measured[0].1.detection.checkpoints, 2);
    assert_eq!(
        r.calibration,
        calibrate_by_scenario(&file, &Palette::default_palette(&rules), &rules)
    );
}

#[test]
fn defaults_and_the_calibration_allow_list_are_read() {
    let f = ScenarioFile::parse(
        "[defaults]\nexpect.human_high = { max_records = 0 }\n\
         [calibration.unmeasured]\nheader_set = \"no headers\"\n\
         [[scenario]]\nname = \"a\"\n[[scenario.actor]]\nkind = \"agent\"\n\
         [[scenario]]\nname = \"b\"\nexpect.human_high = { max_records = 3 }\n\
         [[scenario.actor]]\nkind = \"agent\"\n",
    )
    .unwrap();
    assert_eq!(f.scenario[0].expect["human_high"].max_records, Some(0));
    assert_eq!(f.scenario[1].expect["human_high"].max_records, Some(3));
    assert_eq!(f.calibration.unmeasured["header_set"], "no headers");
    // A kind that is no soft-link kind, and a ceiling with no bound.
    assert!(ScenarioFile::parse("[calibration.unmeasured]\nno_such = \"x\"\n").is_err());
    assert!(
        ScenarioFile::parse(
            "[[scenario]]\nname = \"a\"\nexpect.human_high = {}\n[[scenario.actor]]\nkind = \"agent\"\n"
        )
        .is_err()
    );
    // A grade ceiling is checked against the scenario's own count.
    let m = Measurement {
        human_high: 2,
        ..Default::default()
    };
    let g = Gate {
        expect: true,
        ..Default::default()
    };
    let c = g.check_scenarios(&[("a".to_string(), m.clone()), ("b".to_string(), m)], &f);
    let lines: Vec<String> = c.iter().map(Check::line).collect();
    assert_eq!(lines.len(), 2, "{lines:?}");
    assert!(
        lines[0].starts_with("FAIL a human_high records: 2"),
        "{lines:?}"
    );
    assert!(
        lines[1].starts_with("ok   b human_high records: 2"),
        "{lines:?}"
    );
}
