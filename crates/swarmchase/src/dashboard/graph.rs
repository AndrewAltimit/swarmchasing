//! The link graph: the latest analysis's clusters above noise as nodes, and
//! what ties them as edges: soft links ([`sc_core::fleets`]) and possible
//! interaction ([`sc_core::swarm`]), with the candidate fleets they suggest.
//!
//! Every edge here is descriptive: none merges clusters or changes a score,
//! and the page says so. Each pair's soft links combine as candidate fleets
//! combine them (`1 - Π(1 - s)`); interaction edges keep their own
//! strength. Details are defanged, hosts included, and cut to one line.

use crate::util::one_line;
use crate::watch::attention::Queue;
use sc_core::{Analysis, Tier, defang_host, defang_hosts};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

/// Nodes drawn: linked clusters, by queue rank, then cluster number.
pub const NODES: usize = 60;
/// Characters kept of a link's detail.
const DETAIL: usize = 160;

/// Text made safe to show and cut to one line: URLs and bare hosts
/// defanged as [`sc_core::defang_hosts`] does.
pub fn defang_text(s: &str) -> String {
    defang_hosts(&one_line(s, DETAIL))
}

#[derive(Default)]
struct Pair {
    soft: Vec<Value>,
    /// The soft links combined: the strongest per family, multiplied.
    lr: f64,
    swarm: Vec<Value>,
    swarm_max: Option<sc_core::swarm::EdgeStrength>,
}

/// The `graph` section of the overview.
pub fn graph(a: &Analysis, q: Option<&Queue>) -> Value {
    let shown: Vec<&sc_core::Cluster> =
        a.clusters.iter().filter(|c| c.tier > Tier::Noise).collect();
    let ids: BTreeSet<&str> = shown.iter().map(|c| c.id.as_str()).collect();
    let mut pairs: BTreeMap<(String, String), Pair> = BTreeMap::new();
    let order: BTreeMap<&str, usize> = a
        .clusters
        .iter()
        .enumerate()
        .map(|(i, c)| (c.id.as_str(), i))
        .collect();
    let key = |x: &str, y: &str| {
        if order.get(x) <= order.get(y) {
            (x.to_string(), y.to_string())
        } else {
            (y.to_string(), x.to_string())
        }
    };
    let evidence = sc_core::fleets::pair_evidence(&a.soft_links);
    for l in &a.soft_links {
        if !ids.contains(l.a.as_str()) || !ids.contains(l.b.as_str()) {
            continue;
        }
        let k = key(&l.a, &l.b);
        let lr = evidence
            .get(&(l.a.clone(), l.b.clone()))
            .map_or(1.0, |e| e.lr);
        let p = pairs.entry(k).or_default();
        p.lr = lr;
        p.soft.push(json!({
            "kind": l.kind,
            "label": l.kind.label(),
            "family": l.family().label(),
            "strength": round2(l.strength),
            "lr": round2(l.lr),
            "detail": defang_text(&l.detail),
        }));
    }
    // Interaction inside one cluster (strands of one run) is counted on
    // the node, not drawn.
    let mut inner: BTreeMap<&str, usize> = BTreeMap::new();
    for e in &a.swarm_edges {
        let (x, y) = (e.a.cluster.as_str(), e.b.cluster.as_str());
        if !ids.contains(x) || !ids.contains(y) {
            continue;
        }
        if x == y {
            *inner.entry(x).or_default() += 1;
            continue;
        }
        let p = pairs.entry(key(x, y)).or_default();
        p.swarm_max = p.swarm_max.max(Some(e.strength));
        p.swarm.push(json!({
            "kind": e.kind.id(),
            "label": e.kind.label(),
            "strength": e.strength.label(),
            "runs": [defang_text(&e.a.label()), defang_text(&e.b.label())],
            "detail": defang_text(&e.detail),
        }));
    }

    let mut fleet_of: BTreeMap<&str, &str> = BTreeMap::new();
    for f in &a.candidate_fleets {
        for c in &f.clusters {
            fleet_of.insert(c.as_str(), f.id.as_str());
        }
    }
    let queued: BTreeMap<&str, &crate::watch::attention::Item> = q
        .map(|q| q.items.iter().map(|i| (i.id.as_str(), i)).collect())
        .unwrap_or_default();

    let mut degree: BTreeMap<&str, usize> = BTreeMap::new();
    for (x, y) in pairs.keys() {
        *degree.entry(x.as_str()).or_default() += 1;
        *degree.entry(y.as_str()).or_default() += 1;
    }
    let mut linked: Vec<&sc_core::Cluster> = shown
        .iter()
        .copied()
        .filter(|c| degree.contains_key(c.id.as_str()) || inner.contains_key(c.id.as_str()))
        .collect();
    let total_linked = linked.len();
    linked.sort_by_key(|c| {
        (
            queued.get(c.id.as_str()).map_or(usize::MAX, |i| i.rank),
            order[c.id.as_str()],
        )
    });
    linked.truncate(NODES);
    let drawn: BTreeSet<&str> = linked.iter().map(|c| c.id.as_str()).collect();

    let nodes: Vec<Value> = linked
        .iter()
        .map(|c| {
            let it = queued.get(c.id.as_str());
            let top = c
                .target_hosts
                .iter()
                .max_by(|x, y| x.1.cmp(y.1).then(y.0.cmp(x.0)))
                .map(|(h, _)| defang_host(&crate::watch::digest::clean_host(h)));
            json!({
                "id": c.id,
                "key": c.key,
                "tier": c.tier.label(),
                "grade": c.agent.level.code(),
                "grade_label": c.agent.level.label(),
                "band": it.map(|i| i.band.label()),
                "rank": it.map(|i| i.rank),
                "thread": it.map(|i| i.thread.clone()),
                "records": c.members.len(),
                "targets": c.target_hosts.len(),
                "top_target": top,
                "fleet": fleet_of.get(c.id.as_str()),
                "links": degree.get(c.id.as_str()).copied().unwrap_or(0),
                "inner": inner.get(c.id.as_str()).copied().unwrap_or(0),
            })
        })
        .collect();
    let links: Vec<Value> = pairs
        .into_iter()
        .filter(|((x, y), _)| drawn.contains(x.as_str()) && drawn.contains(y.as_str()))
        .map(|((x, y), p)| {
            let fx = fleet_of.get(x.as_str());
            json!({
                "a": x,
                "b": y,
                "soft_strength": if p.soft.is_empty() { Value::Null } else { json!(round2(sc_core::fleets::strength_of(p.lr))) },
                "soft_lr": if p.soft.is_empty() { Value::Null } else { json!(round2(p.lr)) },
                "soft": p.soft,
                "swarm_strength": p.swarm_max.map(|s| s.label()),
                "swarm": p.swarm,
                "fleet": fx.filter(|f| fleet_of.get(y.as_str()) == Some(f)),
            })
        })
        .collect();
    let fleets: Vec<Value> = a
        .candidate_fleets
        .iter()
        .map(|f| {
            json!({
                "id": f.id,
                "clusters": f.clusters,
                "kinds": f.kinds.iter().map(|k| k.label()).collect::<Vec<_>>(),
                "links": f.links,
                "strength": round2(f.strength),
                "min_lr": round2(f.min_lr),
                "density": round2(f.density),
                "cut_lr": round2(f.cut_lr),
            })
        })
        .collect();
    json!({
        "clusters": shown.len(),
        "linked": total_linked,
        "nodes": nodes,
        "links": links,
        "fleets": fleets,
    })
}

fn round2(x: f64) -> f64 {
    (x * 100.0).round() / 100.0
}

#[cfg(test)]
mod tests {
    use super::*;
    use sc_core::{Rules, analyze};

    #[test]
    fn bare_hosts_and_urls_are_defanged() {
        assert_eq!(
            defang_text("relay, program on portal.example.gov/q and https://x.example/a"),
            "relay, program on portal[.]example[.]gov/q and hxxps://x[.]example/a"
        );
        // Numbers and labels are left alone.
        assert_eq!(
            defang_text("Jaccard 0.52, width 4"),
            "Jaccard 0.52, width 4"
        );
        assert_eq!(defang_text("a\nb|c"), "a b c");
    }

    #[test]
    fn soft_links_join_nodes_and_combine_per_pair() {
        let mut rules = Rules::default_rules();
        rules.set.soft_links.fleet_min_lr = 1.5;
        let a = analyze(crate::case::fleet::tests::two_runs(), &rules);
        assert!(!a.soft_links.is_empty());
        let g = graph(&a, None);
        let nodes = g["nodes"].as_array().unwrap();
        assert_eq!(nodes.len(), 2, "{g}");
        let links = g["links"].as_array().unwrap();
        assert_eq!(links.len(), 1, "{g}");
        let l = &links[0];
        let e = sc_core::fleets::pair_evidence(&a.soft_links);
        let lr = e.values().next().unwrap().lr;
        assert_eq!(l["soft_strength"], round2(sc_core::fleets::strength_of(lr)));
        assert_eq!(l["soft_lr"], round2(lr));
        assert_eq!(l["soft"].as_array().unwrap().len(), a.soft_links.len());
        assert_eq!(l["fleet"], "F1");
        assert_eq!(nodes[0]["fleet"], "F1");
        assert_eq!(g["fleets"][0]["clusters"].as_array().unwrap().len(), 2);
        let text = g.to_string();
        assert!(!text.contains("a.example"), "{text}");
        assert!(text.contains("a[.]example"), "{text}");
    }

    #[test]
    fn interaction_edges_are_drawn_between_clusters_and_counted_within() {
        let text = include_str!("../../../../samples/eval/swarm-interaction.ndjson");
        let obs = sc_core::ingest::parse_input(
            text,
            sc_core::ingest::Format::Ndjson,
            &sc_core::ingest::FieldMap::default(),
        )
        .observations;
        let a = analyze(obs, &Rules::default_rules());
        let g = graph(&a, None);
        let between = a
            .swarm_edges
            .iter()
            .filter(|e| e.a.cluster != e.b.cluster)
            .count();
        let within = a.swarm_edges.len() - between;
        assert!(between > 0 && within > 0, "{:?}", a.swarm_edges);
        let drawn: usize = g["links"]
            .as_array()
            .unwrap()
            .iter()
            .map(|l| l["swarm"].as_array().unwrap().len())
            .sum();
        assert_eq!(drawn, between);
        let inner: u64 = g["nodes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|n| n["inner"].as_u64().unwrap())
            .sum();
        assert_eq!(inner as usize, within);
        // Strand labels name relays and hosts: defanged like the details.
        let text = g.to_string();
        assert!(!text.contains("://"), "{text}");
        for l in g["links"].as_array().unwrap() {
            for s in l["swarm"].as_array().unwrap() {
                for r in s["runs"].as_array().unwrap() {
                    let r = r.as_str().unwrap();
                    assert_eq!(r, defang_text(r), "{r}");
                }
            }
        }
    }

    #[test]
    fn unlinked_clusters_are_counted_not_drawn() {
        let a = analyze(Vec::new(), &Rules::default_rules());
        let g = graph(&a, None);
        assert_eq!(g["nodes"].as_array().unwrap().len(), 0);
        assert_eq!(g["linked"], 0);
    }
}
