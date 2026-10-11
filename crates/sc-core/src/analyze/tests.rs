//! End-to-end tests of the analysis pipeline.

use super::link::{Dsu, cluster_key};
use super::*;

fn o(ts: i64, url: &str) -> Observation {
    Observation {
        ts,
        url: url.into(),
        ..Default::default()
    }
}

#[test]
fn union_find_survives_a_long_chain() {
    let n = 1_000_000;
    let mut d = Dsu((0..n).collect());
    // Each union hangs the previous root under a new one: a chain n deep.
    for i in (0..n - 1).rev() {
        d.union(i, i + 1);
    }
    assert_eq!(d.find(n - 1), 0);
    assert_eq!(d.0[n - 1], 0, "path compressed");
}

#[test]
fn cluster_keys_outlive_cluster_numbers() {
    let inbox = "https://webhook.site/0b6c1f0e-1111-4c2a-9a55-3f2e1d0c9b8a";
    let rec = |id: &str, ts: i64, url: &str| Observation {
        id: id.into(),
        ..o(ts, url)
    };
    let small = vec![
        rec("w:2", 1000, &format!("{inbox}?kind=headers0")),
        rec("w:1", 1040, &format!("{inbox}?kind=body0-0")),
    ];
    let a = analyze(small.clone(), &Rules::default_rules());
    assert_eq!(a.clusters.len(), 1);
    let key = a.clusters[0].key.clone();
    assert!(key.starts_with("k-") && key.len() == 10, "{key}");
    // The earliest record names it, not the smallest id.
    assert_eq!(key, cluster_key("w:2"));

    // A stronger cluster arrives and takes C1; the first keeps its key.
    let mut more = small;
    for i in 0..4 {
        more.push(rec(
            &format!("x:{i}"),
            5000 + i * 30,
            &format!("https://r.jina.ai/https://p.example/q?id={i}%20UNION%20SELECT%201&uqtag=zz9"),
        ));
    }
    let b = analyze(more, &Rules::default_rules());
    assert_eq!(b.clusters.len(), 2);
    let c = b.cluster(&key).unwrap();
    assert_eq!(c.id, "C2");
    assert_eq!(b.cluster("c2").unwrap().key, key);
    assert_eq!(b.cluster_index(" C1 "), Some(0));
    assert!(b.cluster("k-00000000").is_none());
}

#[test]
fn a_planted_record_with_a_smaller_id_keeps_the_key() {
    let inbox = "https://webhook.site/0b6c1f0e-1111-4c2a-9a55-3f2e1d0c9b8a";
    let rec = |id: &str, ts: i64, url: &str| Observation {
        id: id.into(),
        source: "urlquery".into(),
        ..o(ts, url)
    };
    let real = vec![
        rec("uq-7f", 1000, &format!("{inbox}?kind=headers0")),
        rec("uq-9c", 1040, &format!("{inbox}?kind=body0-0")),
    ];
    let key = analyze(real.clone(), &Rules::default_rules()).clusters[0]
        .key
        .clone();
    // Submitted later with the same inbox and an id that sorts first.
    let mut planted = real;
    planted.push(rec("uq-00", 5000, &format!("{inbox}?kind=done")));
    let b = analyze(planted, &Rules::default_rules());
    assert_eq!(b.clusters.len(), 1);
    assert_eq!(b.clusters[0].members.len(), 3);
    assert_eq!(b.clusters[0].key, key);
    assert_eq!(key, cluster_key("uq-7f"));
    // Untimed records name a cluster only when none is timed.
    let untimed = vec![
        rec("a", 0, &format!("{inbox}?kind=headers0")),
        rec("b", 0, &format!("{inbox}?kind=body0-0")),
    ];
    let mut mixed = untimed.clone();
    mixed.push(rec("c", 1000, &format!("{inbox}?kind=done")));
    assert_eq!(
        analyze(untimed, &Rules::default_rules()).clusters[0].key,
        cluster_key("a")
    );
    assert_eq!(
        analyze(mixed, &Rules::default_rules()).clusters[0].key,
        cluster_key("c")
    );
}

#[test]
fn a_record_sharing_only_a_context_rule_does_not_join_by_timing() {
    // A run on one host, joined by its run tag, and a record placed two
    // minutes later through the same relay (or with the same cache
    // buster) and nothing else.
    let run = [
        "https://r.jina.ai/https://records.t.example/s?id=1%20UNION%20SELECT%201--&uqtag=pl4nt1",
        "https://r.jina.ai/https://records.t.example/i?id=2%20UNION%20SELECT%202--&uqtag=pl4nt1",
    ];
    for decoy in [
        "https://r.jina.ai/https://records.t.example/about",
        "https://records.t.example/status?_=1788426240789",
    ] {
        let obs: Vec<Observation> = run
            .iter()
            .chain([&decoy])
            .enumerate()
            .map(|(i, u)| o(1_791_000_000 + 120 * i as i64, u))
            .collect();
        let a = analyze(obs, &Rules::default_rules());
        assert!(a.results[2].score > 0, "{decoy} is flagged");
        assert_eq!(a.clusters.len(), 1, "{decoy}");
        assert_eq!(a.clusters[0].members, [0, 1], "{decoy}");
        assert_eq!(a.results[2].cluster, None, "{decoy}");
    }
    // A shared rule of another kind still links by timing.
    let obs = vec![
        o(1_791_000_000, run[0]),
        o(
            1_791_000_120,
            "https://r.jina.ai/https://records.t.example/x?id=3%20UNION%20SELECT%203--",
        ),
    ];
    assert_eq!(
        analyze(obs, &Rules::default_rules()).clusters[0]
            .members
            .len(),
        2
    );
}

#[test]
fn links_by_inbox_and_host() {
    let inbox = "https://webhook.site/0b6c1f0e-1111-4c2a-9a55-3f2e1d0c9b8a";
    let obs = vec![
        o(1000, &format!("{inbox}?kind=headers0")),
        o(
            1040,
            &format!("https://r.jina.ai/https://data.portal.example/p/1?uqtag=a1b2&cb={inbox}"),
        ),
        o(
            1090,
            "https://r.jina.ai/https://data.portal.example/p/2?uqtag=c3d4",
        ),
        o(1120, "https://r.jina.ai/https://data.portal.example/p/3"),
        o(99999, "https://www.example.org/"),
    ];
    let a = analyze(obs, &Rules::default_rules());
    assert_eq!(a.flagged, 4);
    assert_eq!(a.clusters.len(), 1);
    assert_eq!(a.clusters[0].members.len(), 3);
    // The bare relay read shares only the relay rule: not joined.
    assert_eq!(a.results[3].cluster, None);
    assert_eq!(a.results[4].cluster, None);
}

/// Every hour for four days, three records a second apart each hour, all
/// with one inbox, timestamped as `kind`.
fn hourly_fleet(kind: crate::model::TsKind) -> Vec<Observation> {
    let inbox = "https://webhook.site/0b6c1f0e-1111-4c2a-9a55-3f2e1d0c9b8a";
    (0..96 * 3)
        .map(|i| Observation {
            ts_kind: kind,
            ..o(
                1_791_072_000 + (i / 3) * 3600 + (i % 3).min(1) + 7,
                &format!("https://h{}.example/q?id={i}&hook={inbox}", i % 3),
            )
        })
        .collect()
}

fn report_of(a: &Analysis) -> String {
    crate::report::render_markdown(a, &crate::report::ReportOptions::default())
}

#[test]
fn capture_times_are_not_read_as_request_timing() {
    use crate::model::TsKind;
    use crate::timing::{RhythmVerdict, TimeBasis};
    let req = analyze(hourly_fleet(TsKind::Request), &Rules::default_rules());
    let c = &req.clusters[0];
    assert_eq!(c.time_basis, TimeBasis::Request);
    assert_eq!(c.timing.rhythm.verdict, RhythmVerdict::RoundTheClock);
    assert_eq!(c.fanout.modal_width, Some(3));
    assert!(report_of(&req).contains("active around the clock"));

    let cap = analyze(hourly_fleet(TsKind::Capture), &Rules::default_rules());
    let c = &cap.clusters[0];
    assert_eq!(c.time_basis, TimeBasis::Capture);
    assert_eq!(c.timing.rhythm.verdict, RhythmVerdict::TooShort);
    assert!(c.fanout.is_empty(), "{:?}", c.fanout);
    let md = report_of(&cap);
    assert!(
        !md.contains("daily rhythm") && !md.contains("fan-out"),
        "{md}"
    );
    // Cadence still describes the captures.
    assert_eq!(c.timing.count, 96 * 3);

    // Half captures: the rest still give a rhythm, labelled.
    let mut mixed = hourly_fleet(TsKind::Request);
    for r in mixed.iter_mut().step_by(2) {
        r.ts_kind = TsKind::Capture;
    }
    let m = analyze(mixed, &Rules::default_rules());
    assert_eq!(m.clusters[0].time_basis, TimeBasis::Mixed);
    assert_eq!(
        m.clusters[0].timing.rhythm.verdict,
        RhythmVerdict::RoundTheClock
    );
    assert!(report_of(&m).contains("(capture times left out)"));
}

#[test]
fn submit_times_are_read_as_request_like_and_say_so() {
    use crate::model::TsKind;
    use crate::timing::{RhythmVerdict, TimeBasis};
    let a = analyze(hourly_fleet(TsKind::Submit), &Rules::default_rules());
    let c = &a.clusters[0];
    assert_eq!(c.time_basis, TimeBasis::Submit);
    assert_eq!(c.timing.rhythm.verdict, RhythmVerdict::RoundTheClock);
    assert_eq!(c.fanout.modal_width, Some(3));
    let md = report_of(&a);
    assert!(
        md.contains("(hour-of-day entropy")
            && md.matches("(submit times, close to request times)").count() == 2,
        "{md}"
    );
}

#[test]
fn benchmark_targets_and_stale_knowledge_are_hints() {
    let inbox = "https://webhook.site/0b6c1f0e-1111-4c2a-9a55-3f2e1d0c9b8a";
    let obs = vec![
        o(
            1000,
            &format!("http://testphp.vulnweb.com/artists.php?artist=1'&cb={inbox}"),
        ),
        o(
            1030,
            &format!("http://testphp.vulnweb.com/listproducts.php?cat=1&cb={inbox}"),
        ),
        // An agent reading two APIs through retired or older endpoints,
        // while v3 is in use on the same host family.
        o(
            2000,
            &format!("https://api.data.example/v1/items?hook={inbox}"),
        ),
        o(
            2030,
            &format!("https://www.data.example/api/v1/stats?hook={inbox}"),
        ),
        o(
            2060,
            &format!("https://graph.facebook.com/v2.8/me?hook={inbox}"),
        ),
        o(
            2090,
            &format!("https://graph.facebook.com/v2.9/page?hook={inbox}"),
        ),
        o(99_000, "https://api.data.example/v3/items"),
    ];
    let a = analyze(obs, &Rules::default_rules());
    let bench: Vec<&Cluster> = a
        .clusters
        .iter()
        .filter(|c| !c.knowledge.benchmarks.is_empty())
        .collect();
    assert_eq!(bench.len(), 1, "{:?}", a.clusters);
    assert_eq!(
        bench[0].knowledge.benchmarks.get("acunetix_vulnweb"),
        Some(&2)
    );
    let stale: Vec<(&str, usize, usize)> = a
        .clusters
        .iter()
        .flat_map(|c| &c.knowledge.stale_knowledge)
        .map(|u| (u.id.as_str(), u.records, u.hosts))
        .collect();
    assert!(stale.contains(&("facebook_graph_v2", 2, 1)), "{stale:?}");
    assert!(
        stale.contains(&(crate::knowledge::OLDER_API_VERSION, 2, 2)),
        "{stale:?}"
    );
    let md = report_of(&a);
    assert!(md.contains("benchmark or practice targets"), "{md}");
    assert!(md.contains("stale knowledge `facebook_graph_v2`"), "{md}");
    // Hints change nothing: same clusters and scores without the lists.
    let mut bare = Rules::default_rules().set;
    bare.benchmarks.clear();
    bare.stale.clear();
    let b = analyze(
        a.results.iter().map(|r| r.obs.clone()).collect(),
        &Rules::compile(bare).unwrap(),
    );
    for (x, y) in a.clusters.iter().zip(&b.clusters) {
        assert_eq!((&x.members, x.score, x.tier), (&y.members, y.score, y.tier));
    }
}

#[test]
fn declared_testing_is_extracted_but_never_scored() {
    let ua = "AcmeScan/1.0 (authorized security test; sec@acme.example)";
    let obs = |ua: Option<&str>| -> Vec<Observation> {
        (0..2)
            .map(|i| Observation {
                user_agent: ua.map(str::to_string),
                ..o(
                    1000 + 30 * i,
                    &format!("https://a.example/item?id={i}%20UNION%20SELECT%20null--"),
                )
            })
            .collect()
    };
    let a = analyze(obs(Some(ua)), &Rules::default_rules());
    let b = analyze(obs(None), &Rules::default_rules());
    let c = &a.clusters[0];
    assert_eq!(c.declared.len(), 1, "{:?}", c.declared);
    assert_eq!(c.declared[0].records, 2);
    assert_eq!(c.declared[0].contact.as_deref(), Some("sec@acme.example"));
    assert!(b.clusters[0].declared.is_empty());
    assert_eq!((c.score, c.tier), (b.clusters[0].score, b.clusters[0].tier));
    let json = serde_json::to_value(&a).unwrap();
    assert_eq!(
        json["clusters"][0]["declared"][0]["contact"],
        "sec@acme.example"
    );
    let report = |audience| {
        crate::report::render_markdown(
            &a,
            &crate::report::ReportOptions {
                audience,
                ..Default::default()
            },
        )
    };
    assert!(report(crate::report::Audience::Internal).contains("sec@acme.example"));
    assert!(!report(crate::report::Audience::Provider).contains("declares testing"));
}

#[test]
fn capture_times_never_link_by_timing() {
    use crate::model::TsKind;
    // Two records for one target a minute apart, sharing a rule, with
    // nothing else in common.
    let pair = |kind| {
        let obs = [
            "https://r.jina.ai/https://a.example/p?x=%7B%7Bhost%7D%7D",
            "https://r.jina.ai/https://a.example/q?y=%7B%7Bname%7D%7D",
        ]
        .iter()
        .enumerate()
        .map(|(i, u)| Observation {
            ts_kind: kind,
            ..o(1_791_000_000 + 60 * i as i64, u)
        })
        .collect();
        analyze(obs, &Rules::default_rules()).clusters.len()
    };
    assert_eq!(pair(TsKind::Request), 1);
    assert_eq!(pair(TsKind::Submit), 1);
    assert_eq!(pair(TsKind::Unknown), 1);
    assert_eq!(pair(TsKind::Capture), 0);
}

#[test]
fn chain_pace_is_not_read_from_capture_times() {
    use crate::model::TsKind;
    let chain = |kind| {
        let t = 1_791_000_000;
        let obs: Vec<Observation> = [
            (0, "?id=1"),
            (20, "?id=2"),
            (45, "?id=1'"),
            (70, "?id=1%20UNION%20SELECT%201"),
        ]
        .iter()
        .map(|&(dt, q)| Observation {
            ts_kind: kind,
            ..o(t + dt, &format!("https://portal.example.gov/item{q}"))
        })
        .collect();
        analyze(obs, &Rules::default_rules())
    };
    let req = chain(TsKind::Request);
    assert!(report_of(&req).contains("model pace"));
    let cap = chain(TsKind::Capture);
    assert_eq!(cap.chains[0].time_basis, crate::timing::TimeBasis::Capture);
    let md = report_of(&cap);
    assert!(
        md.contains("capture times, not request times: pace not read")
            && !md.contains("model pace"),
        "{md}"
    );
    assert!(report_of(&chain(TsKind::Submit)).contains("model pace, from submit times"));
}

#[test]
fn weak_rules_across_members_do_not_raise_a_cluster() {
    // One inbox; each record adds a different context rule. Summed over
    // distinct rules this reaches the significant threshold; no member
    // does, and context kinds corroborate nothing.
    let inbox = "https://webhook.site/0b6c1f0e-1111-4c2a-9a55-3f2e1d0c9b8a";
    let obs = vec![
        o(1000, &format!("https://a.example/x?hook={inbox}&_=1")),
        o(
            1030,
            &format!("https://a.example/y?hook={inbox}&agent=claude"),
        ),
        o(
            1060,
            &format!("https://r.jina.ai/https://a.example/z?hook={inbox}"),
        ),
    ];
    let a = analyze(obs, &Rules::default_rules());
    assert_eq!(a.clusters.len(), 1);
    let c = &a.clusters[0];
    assert!(c.score >= 6, "{}", c.score);
    assert!(
        a.results.iter().all(|r| r.tier == Tier::Suggestive),
        "{:?}",
        a.results
            .iter()
            .map(|r| (r.score, &r.hits))
            .collect::<Vec<_>>()
    );
    assert_eq!(c.tier, Tier::Suggestive);
}

#[test]
fn corroborating_members_raise_a_cluster_one_step() {
    let inbox = "https://webhook.site/0b6c1f0e-1111-4c2a-9a55-3f2e1d0c9b8a";
    let obs = vec![
        // Callback channel and model residue ...
        o(
            1000,
            &format!("https://a.example/p%5D%28https://a.example/p%29?hook={inbox}"),
        ),
        // ... and callback channel and an echo carrier, in another record.
        o(
            1030,
            &format!("https://httpbin.org/anything?u=https://a.example/&hook={inbox}"),
        ),
    ];
    let a = analyze(obs.clone(), &Rules::default_rules());
    assert!(
        a.results.iter().all(|r| r.tier == Tier::Suggestive),
        "{:?}",
        a.results
            .iter()
            .map(|r| (r.score, &r.hits))
            .collect::<Vec<_>>()
    );
    assert_eq!(a.clusters[0].tier, Tier::Significant);

    // The same evidence twice is not corroboration.
    let same = vec![obs[0].clone(), o(1060, &obs[0].url)];
    let b = analyze(same, &Rules::default_rules());
    assert_eq!(b.clusters[0].tier, Tier::Suggestive);

    // A noise-only cluster stays noise.
    let quiet = vec![
        o(1000, "https://r.jina.ai/https://a.example/q?uqtag=abc1"),
        o(1030, "https://r.jina.ai/https://a.example/r?uqtag=abc1"),
    ];
    let q = analyze(quiet, &Rules::default_rules());
    assert!(q.clusters.iter().all(|c| {
        c.tier
            == q.results[c.members[0]]
                .tier
                .max(q.results[c.members[1]].tier)
    }));
}

#[test]
fn hits_carry_tactics_and_clusters_count_them() {
    let inbox = "https://webhook.site/0b6c1f0e-1111-4c2a-9a55-3f2e1d0c9b8a";
    let obs = vec![
        o(1000, &format!("{inbox}?kind=headers0")),
        o(
            1040,
            &format!("https://r.jina.ai/https://p.example/%60https://p.example/x%60?cb={inbox}"),
        ),
    ];
    let a = analyze(obs, &Rules::default_rules());
    let hit = |id: &str| {
        a.results
            .iter()
            .flat_map(|r| &r.hits)
            .find(|h| h.rule_id == id)
            .unwrap()
    };
    assert_eq!(hit("relay.jina").tactic, Some(Tactic::TaskRetrieval));
    assert!(hit("marker.md_url_wrapper").artifact);
    assert_eq!(hit("marker.md_url_wrapper").tactic, None);
    let c = &a.clusters[0];
    assert_eq!(c.tactics.get(&Tactic::CallbackChannels), Some(&3));
    assert_eq!(
        c.tactics.get(&Tactic::TaskRetrieval),
        Some(&2),
        "relay and cache buster"
    );
    assert_eq!(c.artifacts, 1);
    let json = serde_json::to_value(&a).unwrap();
    assert_eq!(json["clusters"][0]["tactics"]["T7"], 3);
    assert_eq!(json["results"][1]["hits"][0]["tactic"], "T1");
}

#[test]
fn a_feature_reused_months_later_starts_a_new_cluster() {
    let inbox = "https://webhook.site/0b6c1f0e-1111-4c2a-9a55-3f2e1d0c9b8a";
    let day = 86_400;
    let t0 = 1_791_000_000;
    let obs = vec![
        o(t0, &format!("https://a.example/x?cb={inbox}")),
        o(t0 + 2 * day, &format!("https://b.example/y?cb={inbox}")),
        // Three months on, the same inbox on other hosts.
        o(t0 + 90 * day, &format!("https://c.example/z?cb={inbox}")),
        o(t0 + 91 * day, &format!("https://d.example/w?cb={inbox}")),
    ];
    let a = analyze(obs.clone(), &Rules::default_rules());
    assert_eq!(a.clusters.len(), 2, "{:?}", a.clusters);
    assert_eq!(a.results[0].cluster, a.results[1].cluster);
    assert_eq!(a.results[2].cluster, a.results[3].cluster);
    assert_ne!(a.results[0].cluster, a.results[2].cluster);
    for c in &a.clusters {
        assert_eq!(c.link_features.len(), 1, "{:?}", c.link_features);
    }
    assert!(a.common_features.is_empty());

    // With no window, one inbox is one cluster however far apart.
    let mut rules = Rules::default_rules();
    rules.set.linking.feature_link_window_secs = 0;
    let b = analyze(obs, &rules);
    assert_eq!(b.clusters.len(), 1, "{:?}", b.clusters);
    assert_eq!(b.clusters[0].members.len(), 4);
}

#[test]
fn a_popular_tag_is_common_and_never_links() {
    // A copied test tag on many unrelated sites in one afternoon.
    let t0 = 1_791_000_000;
    let obs: Vec<Observation> = (0..25)
        .map(|i| {
            o(
                t0 + i * 600,
                &format!("https://site{i}.example/page?q=CHATGPTTEST1"),
            )
        })
        .collect();
    // Not as a published tag here: the host limit is what is tested.
    let mut unpublished = Rules::default_rules();
    unpublished.set.linking.published_tags.clear();
    let a = analyze(obs.clone(), &unpublished);
    assert_eq!(a.clusters.len(), 0, "{:?}", a.clusters);
    assert_eq!(a.common_features.len(), 1, "{:?}", a.common_features);
    let c = &a.common_features[0];
    assert_eq!(c.feature.to_string(), "marker.test_tag:chatgpttest1");
    assert_eq!((c.records, c.hosts), (25, 25));
    assert_eq!((c.start, c.end), (t0, t0 + 24 * 600));
    assert!(c.reason.contains("feature_max_hosts"), "{}", c.reason);
    let report = |audience| {
        crate::report::render_markdown(
            &a,
            &crate::report::ReportOptions {
                audience,
                ..Default::default()
            },
        )
    };
    let internal = report(crate::report::Audience::Internal);
    assert!(
        internal.contains("Common features") && internal.contains("chatgpttest1"),
        "{internal}"
    );
    assert!(!report(crate::report::Audience::Provider).contains("Common features"));

    // The same tag on a few hosts still links ...
    let few: Vec<Observation> = obs.into_iter().take(4).collect();
    let b = analyze(few.clone(), &unpublished);
    assert_eq!(b.clusters.len(), 1);
    assert!(b.common_features.is_empty());

    // ... unless a public report quoted it: then it is common however few.
    let p = analyze(few, &Rules::default_rules());
    assert!(p.clusters.is_empty(), "{:?}", p.clusters);
    assert_eq!(p.common_features.len(), 1);
    assert_eq!(p.common_features[0].hosts, 4);
    assert!(
        p.common_features[0]
            .reason
            .contains("linking.published_tags"),
        "{}",
        p.common_features[0].reason
    );
}

#[test]
fn a_feature_on_most_records_is_common_when_a_share_is_set() {
    // A run parameter value on most of a broad input, one host each.
    let t0 = 1_791_000_000;
    let mut obs: Vec<Observation> = (0..60)
        .map(|i| {
            o(
                t0 + i * 60,
                &format!("https://h{}.example/?uqtag=default&_=1", i % 5),
            )
        })
        .collect();
    obs.extend((0..60).map(|i| o(t0 + i * 60 + 30, &format!("https://plain{i}.example/"))));
    let mut rules = Rules::default_rules();
    rules.set.linking.feature_max_share = 0.4;
    rules.set.linking.feature_share_min_records = 100;
    let a = analyze(obs.clone(), &rules);
    assert!(
        a.common_features
            .iter()
            .any(|c| c.feature.to_string() == "param:uqtag=default"
                && c.reason.contains("feature_max_share")),
        "{:?}",
        a.common_features
    );
    // Off by default: one fleet can be most of a case's records.
    let b = analyze(obs, &Rules::default_rules());
    assert!(b.common_features.is_empty());
}

#[test]
fn oast_service_name_alone_never_links() {
    let obs = vec![
        o(
            1000,
            "https://a.example/q?cb=c58bduhe008dovpvhvugcfemp9yyyyyyb.oast.fun",
        ),
        o(
            1000 + 86_400,
            "https://b.example/q?cb=c58bduhe008dovpvhvugcfemp9zzzzzzb.oast.fun",
        ),
        o(1000 + 2 * 86_400, "https://c.example/q?cb=//oast.fun"),
        o(1000 + 3 * 86_400, "https://d.example/q?cb=//oast.fun"),
    ];
    let a = analyze(obs, &Rules::default_rules());
    assert_eq!(a.flagged, 4);
    assert_eq!(a.clusters.len(), 0, "{:?}", a.clusters);
    assert!(
        a.results[0]
            .features
            .iter()
            .any(|f| f.value().ends_with("yyyyyyb.oast.fun")),
        "{:?}",
        a.results[0].features
    );
    assert!(a.results[2].features.is_empty());
    let score = |i: usize| a.results[i].score;
    assert_eq!(
        score(0),
        score(2),
        "the inbox and the bare name score alike"
    );
}

#[test]
fn encoding_styles_describe_but_never_link() {
    let inbox = "https://webhook.site/0b6c1f0e-1111-4c2a-9a55-3f2e1d0c9b8a";
    let other = "https://webhook.site/7d2e4a10-2222-4b3c-8a66-4e3f2a1b0c9d";
    let obs = vec![
        o(1000, &format!("{inbox}?d=a%20b&")),
        o(1040, &format!("{inbox}?d=c%20d&")),
        // Same style, different inbox, far apart: must stay unlinked.
        o(500_000, &format!("{other}?d=e%20f&")),
    ];
    let a = analyze(obs, &Rules::default_rules());
    assert_eq!(a.flagged, 3);
    assert_eq!(a.clusters.len(), 1);
    let c = &a.clusters[0];
    assert_eq!(c.members.len(), 2);
    assert_eq!(c.encodings.len(), 1);
    assert_eq!(c.encodings.get("sp20.amp.noslash"), Some(&2));
    assert_eq!(a.results[2].cluster, None);
}

#[test]
fn path_hints_describe_but_never_score() {
    let inbox = "https://webhook.site/0b6c1f0e-1111-4c2a-9a55-3f2e1d0c9b8a";
    let mut obs = Vec::new();
    for (i, h) in ["a.example", "b.example", "c.example"].iter().enumerate() {
        let t = 1000 + 60 * i as i64;
        for (j, p) in ["/robots.txt", "/.well-known/security.txt", "/.env"]
            .iter()
            .enumerate()
        {
            obs.push(o(t + j as i64, &format!("https://{h}{p}")));
        }
        obs.push(o(
            t + 10,
            &format!("https://{h}/o/12345678-1234-1234-1234-123456789abc?cb={inbox}?kind=headers0"),
        ));
    }
    let plain: Vec<Observation> = obs
        .iter()
        .filter(|x| x.url.contains("webhook.site"))
        .cloned()
        .collect();
    let a = analyze(obs, &Rules::default_rules());
    let b = analyze(plain, &Rules::default_rules());
    assert_eq!(a.clusters.len(), 1, "{:?}", a.clusters);
    let c = &a.clusters[0];
    assert_eq!(c.members.len(), 3);
    assert_eq!(c.score, b.clusters[0].score);
    assert_eq!(c.paths.preambles.len(), 1, "{:?}", c.paths);
    assert_eq!(c.paths.preambles[0].hosts, 3);
    assert_eq!(c.paths.fabricated_ids, 3);
    assert!(b.clusters[0].paths.preambles.is_empty());
}
