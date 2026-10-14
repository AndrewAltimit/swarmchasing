//! Interaction edges end to end.

use super::artifacts::site_artifact;
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
    // The two shards are the list's two halves: a regular split.
    assert!(
        a.swarm_edges[0].detail.contains("block split"),
        "{}",
        a.swarm_edges[0].detail
    );
}

#[test]
fn three_clients_striding_one_whole_family_are_a_structured_partition() {
    // Every host of the family is read, so the hosts drawn at random from
    // the family can never show the split; its regularity does.
    let clients = [
        ("AgentA/1", 16509),
        ("AgentB/2", 14061),
        ("AgentC/3", 24940),
    ];
    let mut obs = Vec::new();
    for (c, (ua, asn)) in clients.iter().enumerate() {
        for i in 0..4 {
            let h = i * 3 + c;
            obs.push(with(
                o(
                    &format!("c{c}h{h}"),
                    T0 + c as i64 * 20 + i as i64 * 70,
                    &format!("https://h{h}.permits.example/view?uqtag=part{c}q&_=1"),
                ),
                ua,
                *asn,
            ));
        }
    }
    let (a, e) = edges(obs, SwarmEdgeKind::DisjointPartition);
    assert_eq!(a.clusters.len(), 3, "{:?}", a.clusters);
    assert_eq!(e.len(), 3, "{:?}", a.swarm_edges);
    for x in &e {
        assert_eq!(x.strength, EdgeStrength::Moderate, "{}", x.detail);
        assert!((x.chance.unwrap() - 24.0 / 34650.0).abs() < 1e-9, "{x:?}");
        assert!(x.detail.contains("stride split"), "{}", x.detail);
        assert!(x.detail.contains("4 + 4 + 4"), "{}", x.detail);
    }
}

/// Uneven gaps one dispatcher hands every worker.
const STEPS: [i64; 9] = [40, 7, 65, 12, 30, 88, 5, 51, 19];

/// One client's run: a tagged, flagged request at each time in `times`,
/// unless `loose(i)`, which sends an unflagged page fetch instead.
fn client_run(
    c: usize,
    (ua, asn): (&str, u32),
    times: &[i64],
    loose: &dyn Fn(usize) -> bool,
) -> Vec<Observation> {
    times
        .iter()
        .enumerate()
        .map(|(i, &t)| {
            let url = if loose(i) {
                format!("https://p{c}{i}.example{c}/page/{i}")
            } else {
                format!("https://r.jina.ai/https://p{c}{i}.example{c}/?uqtag=sync{c}")
            };
            with(o(&format!("c{c}i{i}"), t, &url), ua, asn)
        })
        .collect()
}

/// Times from `start` through `gaps`, each moved by `late(i)`.
fn schedule(start: i64, gaps: &[i64], late: &dyn Fn(usize) -> i64) -> Vec<i64> {
    let mut t = start;
    let mut out = vec![t + late(0)];
    for (i, g) in gaps.iter().enumerate() {
        t += g;
        out.push(t + late(i + 1));
    }
    out
}

/// Background runs spread over two days, so the analysis has a span.
fn background() -> Vec<Observation> {
    (0..6)
        .flat_map(|c| {
            let start = T0 - 86_400 + c as i64 * 29_000;
            client_run(
                10 + c,
                ("BgAgent/2", 63949),
                &schedule(start, &[60, 60, 60], &|_| 0),
                &|_| false,
            )
        })
        .collect()
}

const A: (&str, u32) = ("SyncA/1", 16509);
const B: (&str, u32) = ("SyncB/1", 14061);

#[test]
fn runs_in_lockstep_beyond_both_chances() {
    // Two clients sent each step within 2 s of each other, 9 s apart, off
    // the clock hour.
    let start = T0 + 1234;
    let mut obs = background();
    obs.extend(client_run(0, A, &schedule(start, &STEPS, &|_| 0), &|_| {
        false
    }));
    obs.extend(client_run(
        1,
        B,
        &schedule(start + 9, &STEPS, &|i| (i % 3) as i64),
        &|_| false,
    ));
    let (a, e) = edges(obs.clone(), SwarmEdgeKind::SynchronizedStart);
    assert_eq!(e.len(), 1, "{:?}", a.swarm_edges);
    let p = e[0].chance.unwrap();
    assert!(
        p <= Rules::default_rules().set.swarm.lockstep_max_chance,
        "{p}"
    );
    assert!(e[0].detail.contains("10 of 10 requests"), "{}", e[0].detail);
    assert!(e[0].detail.contains("(10 s"), "{}", e[0].detail);
    assert!(e[0].detail.contains("user agent"), "{}", e[0].detail);
    assert_eq!(e[0].strength, EdgeStrength::Moderate);
    // No permutation lined up as well within the base count, so they ran on
    // to the most: the chance reaches below the base floor of 1 / 200.
    let most = Rules::default_rules().set.swarm.lockstep_max_permutations;
    assert!(
        e[0].detail.contains(&format!("under {most} permutations")),
        "{}",
        e[0].detail
    );
    // The edge states the tests its kind read, and the analysis the family.
    assert!(e[0].tested >= 1, "{:?}", e[0]);
    assert!(e[0].detail.contains("such pairs expected among"));
    let f = a
        .multiplicity
        .iter()
        .find(|f| f.family == "synchronized_start")
        .expect("the S3 family");
    assert_eq!((f.kept, f.tested), (1, e[0].tested), "{f:?}");
    // On the clock hour the same lockstep is no less unlikely: no pass for
    // the hour, no discount either.
    for x in obs
        .iter_mut()
        .filter(|x| x.id.starts_with("c0") || x.id.starts_with("c1"))
    {
        x.ts -= 1234;
    }
    let (a, e) = edges(obs, SwarmEdgeKind::SynchronizedStart);
    assert_eq!(e.len(), 1, "{:?}", a.swarm_edges);
}

#[test]
fn jobs_starting_together_at_a_steady_rate_are_not_in_lockstep() {
    // Two jobs on one clock, a request a minute: every permutation of their
    // own gaps lines up as well.
    let hour = (T0 / 3600 + 2) * 3600;
    let steady = [60; 9];
    let mut obs = background();
    obs.extend(client_run(0, A, &schedule(hour, &steady, &|_| 0), &|_| {
        false
    }));
    obs.extend(client_run(
        1,
        B,
        &schedule(hour + 2, &steady, &|_| 0),
        &|_| false,
    ));
    let (a, e) = edges(obs, SwarmEdgeKind::SynchronizedStart);
    assert!(e.is_empty(), "{:?}", a.swarm_edges);
}

#[test]
fn independent_runs_overlapping_are_not_in_lockstep() {
    let start = T0 + 1234;
    let other = [22, 71, 9, 44, 16, 60, 33, 8, 70];
    let mut obs = background();
    obs.extend(client_run(0, A, &schedule(start, &STEPS, &|_| 0), &|_| {
        false
    }));
    obs.extend(client_run(
        1,
        B,
        &schedule(start + 9, &other, &|_| 0),
        &|_| false,
    ));
    let (a, e) = edges(obs, SwarmEdgeKind::SynchronizedStart);
    assert!(e.is_empty(), "{:?}", a.swarm_edges);
}

#[test]
fn unflagged_requests_of_a_run_count_and_capture_times_never_do() {
    // The second client's run is flagged at only three steps; its other
    // requests, unflagged, still line up.
    let start = T0 + 1234;
    let mut obs = background();
    obs.extend(client_run(0, A, &schedule(start, &STEPS, &|_| 0), &|_| {
        false
    }));
    obs.extend(client_run(
        1,
        B,
        &schedule(start + 9, &STEPS, &|_| 1),
        &|i| !matches!(i, 0 | 4 | 9),
    ));
    let (a, e) = edges(obs.clone(), SwarmEdgeKind::SynchronizedStart);
    assert_eq!(e.len(), 1, "{:?}", a.swarm_edges);
    assert!(e[0].detail.contains("10 of 10"), "{}", e[0].detail);
    for x in obs.iter_mut() {
        x.ts_kind = crate::model::TsKind::Capture;
    }
    let (a, e) = edges(obs, SwarmEdgeKind::SynchronizedStart);
    assert!(e.is_empty(), "{:?}", a.swarm_edges);
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
    assert_eq!(e.on_non_swarm, [1, 0, 0, 0, 0, 0]);
}

/// Irregular dispatch times over about eight hours, off the clock hour.
fn dispatches() -> Vec<i64> {
    let gaps = [
        1500, 2200, 900, 3100, 1300, 2600, 1700, 2900, 1100, 2000, 1400, 2400,
    ];
    schedule(T0 + 17 * 60 + 13, &gaps, &|_| 0)
}

const P: (&str, u32) = ("Planner/1", 8075);

/// A planner at `times`, and one worker per entry of `workers`, each with
/// its client and its delay after every dispatch.
fn star(times: &[i64], workers: &[((&str, u32), i64)]) -> Vec<Observation> {
    let mut obs = background();
    obs.extend(client_run(0, P, times, &|_| false));
    for (k, &(client, lag)) in workers.iter().enumerate() {
        let ts: Vec<i64> = times.iter().map(|t| t + lag).collect();
        obs.extend(client_run(1 + k, client, &ts, &|_| false));
    }
    obs
}

#[test]
fn a_planner_leading_two_workers_is_a_dispatch_star() {
    let (a, e) = edges(
        star(&dispatches(), &[(A, 70), (B, 100)]),
        SwarmEdgeKind::DispatchStar,
    );
    assert_eq!(e.len(), 2, "{:?}", a.swarm_edges);
    for x in &e {
        // The planner leads both spokes.
        assert!(x.a.records.iter().all(|r| r.starts_with("c0")), "{x:?}");
        assert!(x.b.records.iter().all(|r| !r.starts_with("c0")), "{x:?}");
        let p = x.chance.unwrap();
        assert!(
            p <= Rules::default_rules().set.swarm.dispatch_max_chance,
            "{p}"
        );
        assert!(x.detail.contains("upstream trigger"), "{}", x.detail);
        assert!(x.detail.contains("user agent"), "{}", x.detail);
        assert!(x.tested >= 1, "{x:?}");
    }
    let f = a
        .multiplicity
        .iter()
        .find(|f| f.family == "dispatch_star")
        .expect("the S6 family");
    assert_eq!(f.kept, 1, "{f:?}");
    let md = crate::report::render_markdown(&a, &crate::report::ReportOptions::default());
    assert!(md.contains("S6 dispatch star"), "{md}");
}

#[test]
fn one_follower_or_followers_of_one_client_make_no_star() {
    let (a, e) = edges(star(&dispatches(), &[(A, 70)]), SwarmEdgeKind::DispatchStar);
    assert!(e.is_empty(), "{:?}", a.swarm_edges);
    // Two clusters of one client trailing the planner: one worker with two
    // tags, not two workers.
    let (a, e) = edges(
        star(&dispatches(), &[(A, 70), (A, 100)]),
        SwarmEdgeKind::DispatchStar,
    );
    assert!(e.is_empty(), "{:?}", a.swarm_edges);
}

#[test]
fn jobs_on_the_clock_hour_make_no_star() {
    // A job at the top of every hour for a day, two more 30 and 90 s after.
    let hour0 = (T0 / 3600 + 1) * 3600;
    let times: Vec<i64> = (0..24).map(|h| hour0 + h * 3600 + 5).collect();
    let (a, e) = edges(
        star(&times, &[(A, 30), (B, 90)]),
        SwarmEdgeKind::DispatchStar,
    );
    assert!(e.is_empty(), "{:?}", a.swarm_edges);
}

#[test]
fn capture_times_make_no_star() {
    let mut obs = star(&dispatches(), &[(A, 70), (B, 100)]);
    for x in obs.iter_mut() {
        x.ts_kind = crate::model::TsKind::Capture;
    }
    let (a, e) = edges(obs, SwarmEdgeKind::DispatchStar);
    assert!(e.is_empty(), "{:?}", a.swarm_edges);
}

#[test]
fn clusters_set_off_together_make_no_star() {
    // One trigger (a feed item, a schedule) at every dispatch time sets off
    // three clients, each within 45 s either side of it: busy together, but
    // none reliably first.
    let mut mix = crate::chance::Mix(11);
    let times = dispatches();
    let mut obs = background();
    for (k, client) in [P, A, B].into_iter().enumerate() {
        let ts: Vec<i64> = times
            .iter()
            .map(|t| t + (mix.next() % 91) as i64 - 45)
            .collect();
        obs.extend(client_run(k, client, &ts, &|_| false));
    }
    let (a, e) = edges(obs, SwarmEdgeKind::DispatchStar);
    assert!(e.is_empty(), "{:?}", a.swarm_edges);
}

#[test]
fn workers_of_unknown_clients_make_no_star() {
    // Neither worker states a user agent or a network: nothing tells their
    // clients apart, from the planner's or from each other.
    let mut obs = star(&dispatches(), &[(A, 70), (B, 100)]);
    for x in obs
        .iter_mut()
        .filter(|x| x.id.starts_with("c1") || x.id.starts_with("c2"))
    {
        x.user_agent = None;
        x.asn = None;
    }
    let (a, e) = edges(obs, SwarmEdgeKind::DispatchStar);
    assert!(e.is_empty(), "{:?}", a.swarm_edges);
}
