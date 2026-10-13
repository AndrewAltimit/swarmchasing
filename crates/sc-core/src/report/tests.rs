//! Reports end to end: wording per audience, withholding and hint lines.

use super::*;
use crate::analyze::analyze;
use crate::attribution::Role;
use crate::model::Observation;
use crate::rules::Rules;
use crate::timing::SharedPause;

#[test]
fn renders() {
    let obs = (0..4)
        .map(|i| Observation {
            ts: 1_791_000_000 + i * 44,
            url: format!("https://r.jina.ai/https://data.portal.example/view?id={i}%20UNION%20SELECT%201&uqtag=zz9"),
            asn: Some(132203),
            ..Default::default()
        })
        .collect();
    let a = analyze(obs, &Rules::default_rules());
    let md = render_markdown(
        &a,
        &ReportOptions {
            audience: Audience::Provider,
            ..Default::default()
        },
    );
    assert!(md.contains("Attack payloads were present"));
    assert!(md.contains("**Tencent Cloud** (hosting network). 4 record(s) sent from AS132203"));
    assert!(md.contains("hxxps://r[.]jina[.]ai"));
    assert!(!md.contains("https://data.portal.example"));
    assert!(
        !md.contains("## Endpoints"),
        "providers get clusters, not endpoints"
    );

    let md = render_markdown(
        &a,
        &ReportOptions {
            audience: Audience::Affected,
            ..Default::default()
        },
    );
    assert!(md.contains("## Endpoints"));
    assert!(md.contains("| `data[.]portal[.]example` | 4 |"));
    assert!(md.contains("`exploit.sqli_union`"));
}

#[test]
fn renders_rhythm_and_retries() {
    let day0 = 1_791_072_000; // midnight UTC
    // 01:00–08:59 UTC on four days, linked by one tag.
    let mut obs: Vec<Observation> = (0..4)
        .flat_map(|d| (1..9).map(move |h| day0 + d * 86400 + h * 3600))
        .map(|ts| Observation {
            ts,
            url: format!("https://r.jina.ai/https://data.portal.example/view?q={ts}&uqtag=zz9"),
            ..Default::default()
        })
        .collect();
    // A probe chain whose variants follow error responses.
    let t = day0 + 3600 * 2 + 600;
    for (i, (q, status)) in [
        ("1", 200),
        ("1'", 500),
        ("1%20UNION%20SELECT%201", 500),
        ("1%20UNION%20SELECT%201,2", 200),
    ]
    .into_iter()
    .enumerate()
    {
        obs.push(Observation {
            ts: t + i as i64 * 30,
            url: format!("https://r.jina.ai/https://data.portal.example/item?id={q}&uqtag=zz9"),
            status: Some(status),
            ..Default::default()
        });
    }
    let a = analyze(obs, &Rules::default_rules());
    let md = render_markdown(&a, &ReportOptions::default());
    assert!(
        md.contains("daily rhythm: active 01:00–09:00 UTC over 4 days")
            && md.contains("like a working day near UTC+8 (a hint, not evidence"),
        "{md}"
    );
    assert!(
        md.contains("; 2 variants followed an error response"),
        "{md}"
    );
}

#[test]
fn attribution_is_gated_by_evidence() {
    let obs = (0..4)
        .map(|i| Observation {
            ts: 1_791_000_000 + i * 44,
            url: format!("https://r.jina.ai/https://data.portal.example/view?id={i}%20UNION%20SELECT%201&uqtag=zz9&agent=claude"),
            asn: Some(132203),
            ..Default::default()
        })
        .collect();
    let a = analyze(obs, &Rules::default_rules());
    let render = |audience, min_named, claims: Vec<Claim>| {
        render_markdown(
            &a,
            &ReportOptions {
                audience,
                min_named,
                claims,
                ..Default::default()
            },
        )
    };
    let md = render(Audience::Provider, Evidence::SelfId, vec![]);
    assert!(
        !md.contains("Anthropic"),
        "self-identification names no one"
    );
    assert!(md.contains("Some requests name a model or vendor"));
    let md = render(Audience::Internal, Evidence::default(), vec![]);
    assert!(md.contains("Anthropic (developer, **not named outside case notes**)"));

    let confirmed = Claim {
        details: vec!["confirmed in writing".into()],
        ..Claim::new("Anthropic", Role::Developer, Evidence::ProviderConfirmed)
    };
    let md = render(
        Audience::Affected,
        Evidence::default(),
        vec![confirmed.clone()],
    );
    assert!(md.contains("**Anthropic** (developer). Evidence: confirmed by the provider."));
    assert!(md.contains("Label: Confirmed; tag: Documented"), "{md}");
    assert!(
        md.contains("- Confirmed: almost certain operated by **Anthropic**"),
        "{md}"
    );
    assert!(!md.contains("Some requests name a model or vendor"));

    // Model-family and harness candidates: ranked in private reports,
    // never named in public, whatever their evidence.
    let family = Claim {
        likelihood: Some(0.7),
        accuracy: Some(0.8),
        corpus_size: Some(500),
        details: vec!["residue match".into()],
        ..Claim::new("family-q", Role::ModelFamily, Evidence::ProviderConfirmed)
    };
    let md = render(
        Audience::Provider,
        Evidence::default(),
        vec![family.clone()],
    );
    assert!(md.contains("**Model family candidates**"), "{md}");
    assert!(
        md.contains("1. family-q. Label: Possible; tag: Inference."),
        "{md}"
    );
    assert!(
        md.contains("accuracy 80% on a held-out set, corpus of 500"),
        "{md}"
    );
    assert!(!md.contains("operated by **family-q**"), "{md}");
    let public = render(Audience::Public, Evidence::SelfId, vec![family, confirmed]);
    assert!(!public.contains("family-q"), "{public}");
    assert!(public.contains("operated by **Anthropic**"), "{public}");

    // Below shared identifiers, a notice names the provider as the party
    // that was notified, never as the operator.
    let opts = |reported| ReportOptions {
        audience: Audience::Public,
        reported,
        ..Default::default()
    };
    let public = render_markdown(&a, &opts(None));
    assert!(
        public.contains("identify themselves as using `claude` from Anthropic. Self-identification is the weakest evidence we use. We have not confirmed that Anthropic operated, deployed or authorised them. Layer: developer. Label: Unattributed; tag: Inference."),
        "{public}"
    );
    assert!(!public.contains("**Conclusion.**"), "{public}");
    let sent = Reported {
        provider: true,
        ..Default::default()
    };
    assert!(
        render_markdown(&a, &opts(Some(sent)))
            .contains("Anthropic has been sent the full evidence.")
    );
    // Provider infrastructure says whose systems, not who deployed.
    let infra = Claim::new(
        "Anthropic",
        Role::Developer,
        Evidence::ProviderInfrastructure,
    );
    let md = render(Audience::Public, Evidence::default(), vec![infra]);
    assert!(
        md.contains("- Suspected: the requests very likely came from infrastructure that **Anthropic** operates; who deployed the agents is a separate question"),
        "{md}"
    );
}

#[test]
fn renders_dialect_fanout_and_cut_lengths() {
    let payloads = [
        "%3Cscript%3Ealert(1)%3C/script%3E",
        "1'%20OR%201=1--",
        "../../../etc/passwd",
    ];
    let mut obs = Vec::new();
    // Five one-second batches of three alike requests to three hosts.
    for b in 0..5 {
        for (k, h) in ["a", "b", "c"].iter().enumerate() {
            obs.push(Observation {
                ts: 1_791_000_007 + 30 * b + (k % 2) as i64,
                url: format!(
                    "https://r.jina.ai/https://{h}.example/view?uqtag=zz9&q={}",
                    payloads[k]
                ),
                ..Default::default()
            });
        }
    }
    // Three URLs cut mid escape at nearly one length.
    for n in 0..3 {
        obs.push(Observation {
            ts: 1_791_000_500 + 40 * n,
            url: format!(
                "https://r.jina.ai/https://a.example/view?uqtag=zz9&note={}%2",
                "x".repeat(40 + n as usize)
            ),
            ..Default::default()
        });
    }
    // The same payloads from an unlinked client a week later.
    for (k, h) in ["d", "e", "f"].iter().enumerate() {
        obs.push(Observation {
            ts: 1_791_600_000 + 300 * k as i64,
            url: format!(
                "https://r.jina.ai/https://{h}.example/item?uqtag=yy8&id={}",
                payloads[k]
            ),
            ..Default::default()
        });
    }
    let a = analyze(obs, &Rules::default_rules());
    assert_eq!(a.clusters.len(), 2, "{:?}", a.clusters);
    assert_eq!(a.dialect_pairs.len(), 1, "{:?}", a.dialect_pairs);
    let md = render_markdown(&a, &ReportOptions::default());
    assert!(
        md.contains("payload dialect `")
            && md.contains("sqli (quote_or_1eq1 ×5); traversal (depth3 ×5, etc_passwd ×5); xss (script_alert ×5)"),
        "{md}"
    );
    assert!(
        md.contains("parallel fan-out: 5 of 8 one-second batches were 3 alike requests wide"),
        "{md}"
    );
    assert!(
        md.contains("cut lengths: 3 of 3 truncated URLs were cut at "),
        "{md}"
    );
    assert!(
        md.contains(
            "favour the same canonical test payloads: 4 shared variants (`sqli.quote_or_1eq1`"
        ),
        "{md}"
    );

    // A public notice keeps payload details for compromised endpoints out.
    let notice = render_notice(
        &a,
        &ReportOptions {
            exposed_hosts: vec!["a.example".into()],
            ..Default::default()
        },
    );
    let md = notice.markdown;
    assert!(
        md.contains("payload dialect `"),
        "the other cluster keeps its line"
    );
    assert_eq!(md.matches("payload dialect `").count(), 1, "{md}");
    assert!(md.contains("favour the same canonical test payloads: 4 shared variants, Jaccard"));
}

#[test]
fn artifacts_count_is_in_private_reports_only() {
    let obs = (0..3)
        .map(|i| Observation {
            ts: 1_791_000_000 + i * 60,
            url: format!(
                "https://r.jina.ai/https://p.example/%60https://p.example/x{i}%60?uqtag=zz9&id=1'%20OR%201=1--"
            ),
            ..Default::default()
        })
        .collect();
    let a = analyze(obs, &Rules::default_rules());
    let n = a.clusters[0].artifacts;
    assert!(n > 0, "{:?}", a.clusters[0]);
    let line = format!("artifacts: {n} of 3 records carry a trace");
    for (audience, shown) in [
        (Audience::Internal, true),
        (Audience::Provider, true),
        (Audience::Affected, false),
        (Audience::Public, false),
    ] {
        let md = render_markdown(
            &a,
            &ReportOptions {
                audience,
                ..Default::default()
            },
        );
        assert_eq!(md.contains(&line), shown, "{audience:?}: {md}");
    }
}

#[test]
fn public_notice_names_only_affected_hosts() {
    let obs = ["d", "e", "f"]
        .iter()
        .enumerate()
        .map(|(k, h)| Observation {
            ts: 1_791_000_000 + 300 * k as i64,
            url: format!("https://r.jina.ai/https://{h}.example/item?uqtag=zz9&id=1'%20OR%201=1--"),
            ..Default::default()
        })
        .collect();
    let a = analyze(obs, &Rules::default_rules());
    let all = render_notice(&a, &ReportOptions::default());
    assert!(all.markdown.contains("`e[.]example`"), "{}", all.markdown);
    // Without recorded sends the notice claims none.
    assert!(!all.markdown.contains("Reports went"), "{}", all.markdown);
    let sent = render_notice(
        &a,
        &ReportOptions {
            reported: Some(Reported {
                operators: true,
                ..Default::default()
            }),
            ..Default::default()
        },
    );
    assert!(
        sent.markdown
            .contains("Reports went to the affected operators before this notice was published."),
        "{}",
        sent.markdown
    );

    let n = render_notice(
        &a,
        &ReportOptions {
            affected_hosts: Some(vec!["D.example".into()]),
            ..Default::default()
        },
    );
    let md = &n.markdown;
    assert!(md.contains("| `d[.]example` |"), "{md}");
    for other in ["e[.]example", "f[.]example", "e.example", "f.example"] {
        assert!(!md.contains(other), "{other}: {md}");
    }
    assert!(md.contains("2 other hosts not named here"), "{md}");
    assert!(
        n.withheld.iter().any(|w| w.contains("names of 2 host(s)")),
        "{:?}",
        n.withheld
    );
    // Private reports name every host.
    let affected = render_markdown(
        &a,
        &ReportOptions {
            audience: Audience::Affected,
            affected_hosts: Some(vec!["d.example".into()]),
            ..Default::default()
        },
    );
    assert!(affected.contains("`e[.]example`"), "{affected}");
}

#[test]
fn the_indicator_notice_names_no_host() {
    let obs = ["d", "e", "f"]
        .iter()
        .enumerate()
        .map(|(k, h)| Observation {
            ts: 1_791_000_000 + 300 * k as i64,
            url: format!("https://r.jina.ai/https://{h}.example/item?uqtag=zz9&id=1'%20OR%201=1--"),
            ..Default::default()
        })
        .collect();
    let a = analyze(obs, &Rules::default_rules());
    let described = [
        ("d.example", "a national government data portal"),
        ("e.example", "a university research site"),
    ]
    .into_iter()
    .map(|(h, d)| (h.to_string(), d.to_string()))
    .collect();
    let n = render_notice(
        &a,
        &ReportOptions {
            affected_hosts: Some(vec!["d.example".into(), "e.example".into()]),
            exposed_hosts: vec!["e.example".into()],
            target_descriptions: Some(described),
            ..Default::default()
        },
    );
    let md = &n.markdown;
    assert!(md.starts_with("# Public notice: suspected AI agent activity"));
    for host in ["d[.]example", "e[.]example", "f[.]example", ".example"] {
        assert!(!md.contains(host), "{host}: {md}");
    }
    assert!(md.contains("| a national government data portal |"), "{md}");
    assert!(md.contains("a university research site ("), "{md}");
    assert!(md.contains("1 other host not named here"), "{md}");
    assert!(
        n.withheld
            .iter()
            .any(|w| w.contains("names and hosts of 2 affected endpoint(s)")),
        "{:?}",
        n.withheld
    );
    assert!(n.leaks.is_empty(), "{:?}", n.leaks);
}

#[test]
fn single_cluster_reports_name_no_other_cluster() {
    let mut obs = Vec::new();
    for (tag, base) in [("zz9", 1_791_000_000), ("yy8", 1_791_600_000)] {
        for (k, h) in ["d", "e", "f"].iter().enumerate() {
            obs.push(Observation {
                ts: base + 300 * k as i64,
                url: format!(
                    "https://r.jina.ai/https://{h}.example/item?uqtag={tag}&id=1'%20OR%201=1--&p=../../../etc/passwd"
                ),
                ..Default::default()
            });
        }
    }
    let mut a = analyze(obs, &Rules::default_rules());
    assert_eq!(a.clusters.len(), 2, "{:?}", a.clusters);
    assert_eq!(a.dialect_pairs.len(), 1, "{:?}", a.dialect_pairs);
    a.shared_pauses.push(SharedPause {
        a: "C1".into(),
        b: "C2".into(),
        pauses: Vec::new(),
        on_the_hour: 0,
        expected: 0.001,
        p_chance: 0.001,
        reason: "2 pause(s) matched".into(),
    });
    for audience in [Audience::Provider, Audience::Affected, Audience::Public] {
        let opts = ReportOptions {
            audience,
            cluster: Some("C1".into()),
            ..Default::default()
        };
        let md = render_markdown(&a, &opts);
        assert!(!md.contains("C2"), "{audience:?}: {md}");
        assert!(!md.contains("went quiet together"), "{md}");
        assert!(!md.contains("favour the same canonical"), "{md}");
    }
    // Case notes keep the lead; a report on both clusters names both.
    let both = render_markdown(&a, &ReportOptions::default());
    assert!(
        both.contains("**C1** and **C2** went quiet together"),
        "{both}"
    );
    let notes = render_markdown(
        &a,
        &ReportOptions {
            cluster: Some("C1".into()),
            ..Default::default()
        },
    );
    assert!(notes.contains("went quiet together"), "{notes}");
}

#[test]
fn described_hosts_of_one_class_share_an_endpoint_row() {
    let obs = ["d", "e", "f"]
        .iter()
        .enumerate()
        .map(|(k, h)| Observation {
            ts: 1_791_000_000 + 300 * k as i64,
            url: format!("https://r.jina.ai/https://{h}.example/item?uqtag=zz9&id=1'%20OR%201=1--"),
            ..Default::default()
        })
        .collect();
    let a = analyze(obs, &Rules::default_rules());
    let described = ["d.example", "e.example", "f.example"]
        .into_iter()
        .map(|h| (h.to_string(), "a county records office".to_string()))
        .collect();
    let md = render_notice(
        &a,
        &ReportOptions {
            target_descriptions: Some(described),
            ..Default::default()
        },
    )
    .markdown;
    let rows: Vec<&str> = md
        .lines()
        .filter(|l| l.starts_with("| a county records office"))
        .collect();
    assert_eq!(rows.len(), 1, "{md}");
    assert!(
        rows[0].starts_with("| a county records office (3 hosts) | 3 |"),
        "{md}"
    );
    // Named hosts keep a row each.
    let md = render_markdown(&a, &ReportOptions::default());
    for h in ["d[.]example", "e[.]example", "f[.]example"] {
        assert!(md.contains(&format!("| `{h}` |")), "{h}: {md}");
    }
}
