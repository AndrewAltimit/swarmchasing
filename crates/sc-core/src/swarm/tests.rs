//! Interaction edges end to end.

use super::artifacts::site_artifact;
use super::edges::MAX_CHANCE;
use super::*;
use crate::analyze::Analysis;
use crate::analyze::analyze;
use crate::model::Observation;

const T0: i64 = 1_791_000_000;
const INBOX: &str = "0b6c1f0e-1111-4c2a-9a55-3f2e1d0c9b8a";
const GIST: &str = "3f9a2c1b7d4e5f60718293a4b5c6d7e8";

fn o(id: &str, ts: i64, url: &str) -> Observation {
    Observation {
        id: id.into(),
        ts,
        url: url.into(),
        ..Default::default()
    }
}

fn with(mut x: Observation, ua: &str, asn: u32) -> Observation {
    x.user_agent = Some(ua.into());
    x.asn = Some(asn);
    x
}

fn edges(obs: Vec<Observation>, kind: SwarmEdgeKind) -> (Analysis, Vec<SwarmEdge>) {
    let a = analyze(obs, &Rules::default_rules());
    let e = a
        .swarm_edges
        .iter()
        .filter(|e| e.kind == kind)
        .cloned()
        .collect();
    (a, e)
}

#[test]
fn kinds_parse_and_name() {
    for k in SwarmEdgeKind::ALL {
        assert_eq!(k.id().parse::<SwarmEdgeKind>(), Ok(k));
        assert_eq!(k.name().parse::<SwarmEdgeKind>(), Ok(k));
    }
    assert_eq!("hand-off".parse(), Ok(SwarmEdgeKind::Handoff));
    assert_eq!("Shared-Sink".parse(), Ok(SwarmEdgeKind::SharedSink));
    assert!("telepathy".parse::<SwarmEdgeKind>().is_err());
}

#[test]
fn artifacts_are_named_by_string_only() {
    for (host, text, want) in [
        (
            "gist.github.com",
            "https://gist.github.com/u/ABCDEF0123456789abcd",
            Some("gist/abcdef0123456789abcd"),
        ),
        (
            "pastebin.com",
            "https://pastebin.com/raw/Xy12Ab34",
            Some("pastebin/Xy12Ab34"),
        ),
        (
            "huggingface.co",
            "https://huggingface.co/spaces/Some_User/My.App",
            Some("hf_space/some-user-my-app"),
        ),
        (
            "some-user-my-app.hf.space",
            "https://some-user-my-app.hf.space/run",
            Some("hf_space/some-user-my-app"),
        ),
        (
            "notes-7.pages.dev",
            "https://notes-7.pages.dev/x",
            Some("site/notes-7.pages.dev"),
        ),
        ("pages.dev", "https://pages.dev/", None),
        ("www.github.io", "https://www.github.io/", None),
        ("gist.github.com", "https://gist.github.com/discover", None),
        ("rentry.co", "https://rentry.co/api/new", None),
    ] {
        assert_eq!(site_artifact(host, text).as_deref(), want, "{text}");
    }
}

/// Two agents writing one inbox: one direct from a cloud network with a
/// headless browser, one through a relay from another network.
fn one_sink() -> Vec<Observation> {
    let mut obs = Vec::new();
    for i in 0..3 {
        obs.push(with(
            o(
                &format!("d{i}"),
                T0 + i * 120,
                &format!("https://h{i}.city.example/q?id={i}&cb=https://webhook.site/{INBOX}"),
            ),
            "HeadlessChrome/124",
            16509,
        ));
        obs.push(with(
            o(&format!("r{i}"), T0 + 60 + i * 120, &format!("https://r.jina.ai/https://k{i}.city.example/p?hook=https://webhook.site/{INBOX}")),
            "python-httpx/0.27",
            14061,
        ));
    }
    obs
}

#[test]
fn two_writers_inside_one_sink_cluster_are_a_shared_sink() {
    let (a, e) = edges(one_sink(), SwarmEdgeKind::SharedSink);
    assert_eq!(a.clusters.len(), 1, "{:?}", a.clusters);
    assert_eq!(e.len(), 1, "{:?}", a.swarm_edges);
    let e = &e[0];
    assert_eq!((e.a.cluster.as_str(), e.b.cluster.as_str()), ("C1", "C1"));
    assert!(e.a.strand.is_some() && e.a.strand != e.b.strand, "{e:?}");
    assert_eq!(e.strength, EdgeStrength::Moderate, "{}", e.detail);
    assert!(
        e.detail.contains("user agent") && e.detail.contains("webhook[.]site"),
        "{}",
        e.detail
    );
    // One client throughout: no edge.
    let same: Vec<Observation> = one_sink()
        .into_iter()
        .map(|x| with(x, "python-httpx/0.27", 14061))
        .collect();
    assert!(edges(same, SwarmEdgeKind::SharedSink).1.is_empty());
}

#[test]
fn a_gist_written_then_fetched_is_a_handoff() {
    let note = format!("https://gist.github.com/fieldnotes/{GIST}");
    let mut obs = Vec::new();
    for i in 0..3 {
        obs.push(with(
            o(
                &format!("w{i}"),
                T0 + i * 60,
                &format!(
                    "https://r.jina.ai/https://a{i}.agency.example/s?uqtag=scout7&notes={note}"
                ),
            ),
            "ScoutBot/1",
            16509,
        ));
    }
    for i in 0..2 {
        obs.push(with(
            o(&format!("f{i}"), T0 + 1500 + i * 60, &format!("https://r.jina.ai/https://gist.githubusercontent.com/fieldnotes/{GIST}/raw?uqtag=exec4k&n={i}")),
            "python-requests/2.31",
            14061,
        ));
    }
    let (a, e) = edges(obs.clone(), SwarmEdgeKind::Handoff);
    assert_eq!(a.clusters.len(), 2, "{:?}", a.clusters);
    assert_eq!(e.len(), 1, "{:?}", a.swarm_edges);
    assert_eq!(e[0].strength, EdgeStrength::Strong);
    assert_eq!(e[0].a.records, ["w0"]);
    assert_eq!(e[0].b.records, ["f0"]);
    assert!(e[0].detail.contains("gist/"), "{}", e[0].detail);
    // Fetched before it was written: no hand-off.
    for x in obs.iter_mut().filter(|x| x.id.starts_with('f')) {
        x.ts -= 3000;
    }
    assert!(edges(obs, SwarmEdgeKind::Handoff).1.is_empty());
}

#[test]
fn reading_hosts_then_attacking_them_is_a_role_sequence() {
    let hosts = ["a", "b", "c", "d", "e"];
    let mut obs = Vec::new();
    for (i, h) in hosts.iter().enumerate() {
        obs.push(with(
            o(
                &format!("x{i}"),
                T0 + i as i64 * 60,
                &format!("https://r.jina.ai/https://{h}.registry.example/?uqtag=map31"),
            ),
            "MapAgent/2",
            16509,
        ));
        obs.push(with(
            o(
                &format!("y{i}"),
                T0 + 1800 + i as i64 * 60,
                &format!("https://{h}.registry.example/item?id=1'%20OR%201=1--&uqtag=hit88"),
            ),
            "curl/8.5",
            14061,
        ));
    }
    // Unrelated hosts elsewhere make random overlap unlikely.
    for i in 0..40 {
        obs.push(o(
            &format!("z{i}"),
            T0 + 90_000 + i * 30,
            &format!(
                "https://r.jina.ai/https://z{i}.other.example/?uqtag=bg{}",
                i / 4
            ),
        ));
    }
    let (a, e) = edges(obs.clone(), SwarmEdgeKind::RoleSequence);
    assert_eq!(e.len(), 1, "{:?}", a.swarm_edges);
    assert_eq!(e[0].strength, EdgeStrength::Moderate);
    assert!(e[0].chance.unwrap() < 1e-3, "{:?}", e[0].chance);
    // The attack before the reading: no sequence.
    for x in obs.iter_mut().filter(|x| x.id.starts_with('y')) {
        x.ts -= 3600;
    }
    assert!(edges(obs, SwarmEdgeKind::RoleSequence).1.is_empty());
}

#[test]
fn a_sharded_list_is_a_partition_and_nothing_else() {
    // One scheduler, one client, two shards of one list started together.
    let mut obs = Vec::new();
    for s in 0..2 {
        for i in 0..8 {
            obs.push(with(
                o(
                    &format!("s{s}{i}"),
                    T0 + s * 40 + i * 50,
                    &format!(
                        "https://h{}.county.example/records?uqtag=shard{s}x&_=1",
                        s * 8 + i
                    ),
                ),
                "SchedBot/1",
                16509,
            ));
        }
    }
    let a = analyze(obs, &Rules::default_rules());
    assert_eq!(a.clusters.len(), 2, "{:?}", a.clusters);
    let kinds: Vec<SwarmEdgeKind> = a.swarm_edges.iter().map(|e| e.kind).collect();
    assert_eq!(
        kinds,
        [SwarmEdgeKind::DisjointPartition],
        "{:?}",
        a.swarm_edges
    );
    assert_eq!(a.swarm_edges[0].strength, EdgeStrength::Weak);
    assert!(a.swarm_edges[0].detail.contains("fleet signal"));
}

#[test]
fn runs_starting_and_stopping_together_beyond_chance() {
    // Two clients, two runs each, started and stopped within a minute of
    // each other, off the clock hour, two days apart.
    let mut obs = Vec::new();
    for (c, (ua, asn)) in [("SyncA/1", 16509), ("SyncB/1", 14061)].iter().enumerate() {
        for (k, day) in [0, 2].iter().enumerate() {
            let t = T0 + day * 86_400 + 1234 + c as i64 * 30;
            for i in 0..5 {
                obs.push(with(
                    o(
                        &format!("c{c}k{k}i{i}"),
                        t + i * 300,
                        &format!("https://r.jina.ai/https://p{c}{i}.example{c}/?uqtag=sync{c}"),
                    ),
                    ua,
                    *asn,
                ));
            }
        }
    }
    let (a, e) = edges(obs.clone(), SwarmEdgeKind::SynchronizedStart);
    assert_eq!(e.len(), 1, "{:?}", a.swarm_edges);
    assert!(e[0].chance.unwrap() <= MAX_CHANCE);
    assert!(e[0].detail.contains("2 run(s)"), "{}", e[0].detail);
    // On the clock hour, the same alignment is what crons do.
    for x in obs.iter_mut() {
        x.ts -= 1234;
    }
    assert!(edges(obs, SwarmEdgeKind::SynchronizedStart).1.is_empty());
}

#[test]
fn edges_never_change_clusters_and_reach_only_internal_and_provider() {
    let a = analyze(one_sink(), &Rules::default_rules());
    assert!(!a.swarm_edges.is_empty());
    let mut b = a.clone();
    b.swarm_edges.clear();
    let render = |a: &Analysis, audience| {
        crate::report::render_markdown(
            a,
            &crate::report::ReportOptions {
                audience,
                ..Default::default()
            },
        )
    };
    use crate::report::Audience::*;
    for au in [Internal, Provider] {
        let md = render(&a, au);
        assert!(md.contains("## Possible interaction (SC-T9)"), "{md}");
        assert!(md.contains("write to `webhook[.]site/"), "defanged: {md}");
    }
    for au in [Affected, Public] {
        assert!(!render(&a, au).contains("Possible interaction"));
    }
    assert!(!render(&b, Internal).contains("Possible interaction"));
}

#[test]
fn eval_counts_edges_against_swarm_groups() {
    let a = analyze(one_sink(), &Rules::default_rules());
    let lines: String = (0..3)
        .flat_map(|i| [format!("d{i}"), format!("r{i}")])
        .map(|id| format!("{{\"id\":\"{id}\",\"label\":\"agent\",\"swarm\":\"sink-1\"}}\n"))
        .collect();
    let e = swarm_eval(&a, &crate::eval::parse_labels(&lines));
    assert_eq!(e.groups, ["sink-1"]);
    assert_eq!(e.found, ["sink-1"]);
    assert_eq!(e.on_groups, 1);
    let none = lines.replace("sink-1", "none");
    let e = swarm_eval(&a, &crate::eval::parse_labels(&none));
    assert!(e.groups.is_empty());
    assert_eq!(e.on_non_swarm, [1, 0, 0, 0, 0]);
}
