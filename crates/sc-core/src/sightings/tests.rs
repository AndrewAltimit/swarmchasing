//! Sightings: what an export carries and leaves out, and how matching
//! weighs who sent it.

use super::*;
use crate::model::Observation;
use crate::rules::Rules;
use sha2::{Digest, Sha256};

/// 2026-10-04 08:10:00 UTC, in epoch 2026Q4.
const T0: i64 = 1_791_101_400;

/// Four requests to `host` carrying a SQL injection probe and `uqtag=<tag>`,
/// as an access log records them, plus one ordinary visitor.
fn log(host: &str, tag: &str, t0: i64, extra: &str) -> Vec<Observation> {
    let mut v: Vec<Observation> = (0..4)
        .map(|i| Observation {
            id: format!("{host}:{i}"),
            source: "access_log".into(),
            ts: t0 + i * 30,
            ts_kind: crate::model::TsKind::Request,
            url: format!("https://{host}/search?id={i}%20UNION%20SELECT%201&uqtag={tag}{extra}"),
            ip: Some("198.51.100.23".into()),
            asn: Some(64500),
            user_agent: Some("python-httpx/0.27.0".into()),
            ..Default::default()
        })
        .collect();
    v.push(Observation {
        id: format!("{host}:visitor"),
        source: "access_log".into(),
        ts: t0 + 100,
        url: format!("https://{host}/about?ref=newsletter-7731"),
        ip: Some("203.0.113.99".into()),
        user_agent: Some("Mozilla/5.0 (visitor)".into()),
        ..Default::default()
    });
    v
}

fn sightings_of(records: Vec<Observation>, opts: &ExportOptions) -> Sightings {
    let mut records = records;
    for r in &mut records {
        crate::redact::redact_observation(r);
    }
    let a = crate::analyze(records, &Rules::default_rules());
    export(
        &a,
        &ExportOptions {
            generated: "2026-10-12".into(),
            ..opts.clone()
        },
        &EpochKeys::default(),
    )
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[test]
fn an_export_carries_hashes_and_scaffold_never_the_log() {
    let s = sightings_of(
        log("www.shop.example", "zz9", T0, ""),
        &ExportOptions::default(),
    );
    assert_eq!(s.spec, SPEC);
    assert_eq!(s.sightings.len(), 1, "{s:#?}");
    let x = &s.sightings[0];
    assert_eq!(x.id, "S1");
    assert_eq!(x.records, 4);
    assert_eq!(x.epochs, ["2026Q4"]);
    assert_eq!(x.hours, ["2026-10-04T08Z"]);
    assert_eq!(x.time_basis, "request");
    assert!(x.agent_grade.starts_with('L'));
    let f = &x.features[0];
    assert_eq!(
        (f.kind, f.name.as_str(), f.epoch.as_str()),
        (FeatureKind::Param, "uqtag", "2026Q4")
    );
    assert_eq!(f.hash.len(), keys::HASH_HEX);
    assert_eq!(x.scaffold.asns.get(&64500), Some(&4));
    assert!(!x.scaffold.rules.is_empty());

    // Nothing from the log itself: no host, path, query, address or agent.
    let json = serde_json::to_string(&s).unwrap();
    for leak in [
        "shop",
        "search",
        "UNION",
        "198.51.100.23",
        "203.0.113.99",
        "httpx",
        "Mozilla",
        "newsletter",
        "about",
    ] {
        assert!(!json.contains(leak), "`{leak}` in {json}");
    }
    assert!(!s.shares_hosts && x.hosts.is_empty());
    let a = crate::analyze(
        log("www.shop.example", "zz9", T0, ""),
        &Rules::default_rules(),
    );
    assert!(
        !json.contains(&a.clusters[0].key),
        "the cluster key hashes a record id"
    );
    assert_eq!(parse(&json).unwrap(), s);
}

#[test]
fn hosts_are_shared_only_when_asked_and_defanged() {
    let opts = ExportOptions {
        include_hosts: true,
        operator: Some("  Example Shop  ".into()),
        ..Default::default()
    };
    let s = sightings_of(log("www.shop.example", "zz9", T0, ""), &opts);
    assert!(s.shares_hosts);
    assert_eq!(s.operator.as_deref(), Some("Example Shop"));
    assert_eq!(s.sightings[0].hosts, ["www[.]shop[.]example"]);
    // Still no path, query or address.
    let json = serde_json::to_string(&s).unwrap();
    assert!(!json.contains("search") && !json.contains("198.51.100.23"));
}

/// A run tag is low-entropy: `zz9` is guessed in seconds. The export must
/// not carry it in the clear or under any unkeyed hash a lookup table could
/// hold, and the keyed hash must change with the epoch key. What the keyed
/// hash cannot stop is spelled out too: anyone holding the published key
/// can test a guess.
#[test]
fn low_entropy_tags_are_never_plain_or_unkeyed() {
    let tag = "zz9";
    let s = sightings_of(
        log("www.shop.example", tag, T0, ""),
        &ExportOptions::default(),
    );
    let json = serde_json::to_string(&s).unwrap();
    let sha = |t: &str| hex(&Sha256::digest(t.as_bytes()));
    let unkeyed = [
        tag.to_string(),
        sha(tag),
        sha(tag)[..12].to_string(),
        sha(tag)[..32].to_string(),
        sha("uqtag=zz9"),
        sha("param:uqtag=zz9"),
        sha("param:uqtag=zz9")[..32].to_string(),
        crate::redact::hash_token(tag),
        hex(&keys::hmac_sha256(b"", tag.as_bytes()))[..32].to_string(),
    ];
    for u in &unkeyed {
        assert!(
            !json.contains(u.as_str()),
            "unkeyed form `{u}` in the export"
        );
    }

    let f = &s.sightings[0].features[0];
    let k = EpochKeys::default();
    // The honest limit: with the published key, a guess can be tested.
    assert_eq!(k.hash("2026Q4", "param", "uqtag", tag).unwrap(), f.hash);
    // Another epoch's key gives another hash, so one table does not serve
    // every quarter.
    assert_ne!(k.hash("2026Q3", "param", "uqtag", tag).unwrap(), f.hash);
    let other = EpochKeys::from_pairs([("2026Q4", &"11".repeat(32)[..])]).unwrap();
    assert_ne!(other.hash("2026Q4", "param", "uqtag", tag).unwrap(), f.hash);
    // Kind and name are inside the hash: the same text as another feature
    // does not collide.
    assert_ne!(k.hash("2026Q4", "param", "tok", tag).unwrap(), f.hash);
}

#[test]
fn captured_secrets_are_rekeyed_not_copied() {
    let extra = "&access_token=a8f3k29dk3ls02kdm4n5";
    let s = sightings_of(
        log("www.shop.example", "zz9", T0, extra),
        &ExportOptions::default(),
    );
    let x = &s.sightings[0];
    assert!(
        x.features
            .iter()
            .any(|f| f.kind == FeatureKind::Secret && f.name.is_empty())
    );
    let json = serde_json::to_string(&s).unwrap();
    let token = crate::redact::hash_token("a8f3k29dk3ls02kdm4n5");
    assert!(
        !json.contains("REDACTED") && !json.contains(&token[9..]),
        "{json}"
    );
}

#[test]
fn a_swarm_across_a_quarter_boundary_is_hashed_under_both_keys() {
    // 2026-06-30 23:59 and 2026-07-01 00:00.
    let s = sightings_of(
        log("a.example", "zz9", 1_782_863_940, ""),
        &ExportOptions::default(),
    );
    let x = &s.sightings[0];
    assert_eq!(x.epochs, ["2026Q2", "2026Q3"]);
    assert_eq!(x.features.len(), 2);
    // A quarter with no published key is named, and its features left out.
    let a = crate::analyze(log("a.example", "zz9", T0, ""), &Rules::default_rules());
    let none = export(
        &a,
        &ExportOptions::default(),
        &EpochKeys::from_pairs([("2026Q3", &"22".repeat(32)[..])]).unwrap(),
    );
    assert_eq!(none.missing_epochs, ["2026Q4"]);
    assert!(none.sightings[0].features.is_empty());
}

fn party(name: &str, standing: Standing, doc: Sightings) -> Party {
    Party {
        name: name.into(),
        standing,
        doc,
    }
}

#[test]
fn two_operators_seeing_one_tag_match_and_only_vouched_parties_corroborate() {
    let opts = ExportOptions::default();
    let shop = sightings_of(log("www.shop.example", "zz9", T0, ""), &opts);
    let clinic = sightings_of(log("portal.clinic.example", "zz9", T0 + 600, ""), &opts);
    let other = sightings_of(log("x.example", "qq4", T0, ""), &opts);

    let r = match_sightings(&[
        party("case-a", Standing::Contacted, shop.clone()),
        party("case-b", Standing::Contacted, clinic.clone()),
        party("case-c", Standing::Contacted, other.clone()),
    ]);
    assert_eq!(r.pairs.len(), 1, "{r:#?}");
    let p = &r.pairs[0];
    assert_eq!(
        (p.a.party.as_str(), p.b.party.as_str()),
        ("case-a", "case-b")
    );
    assert_eq!(p.shared[0].kind, FeatureKind::Param);
    assert_eq!(p.shared[0].name, "uqtag");
    assert_eq!((p.overlap_hours, p.gap_hours), (1, 0));
    assert!(p.corroborating);
    assert!(p.scaffold.iter().any(|s| s == "asn:AS64500"));
    assert_eq!(r.groups.len(), 1);
    assert!(r.groups[0].corroborated && r.groups[0].independent == 2);
    // case-c shares the scaffold and the hour but no feature: a hint only.
    assert!(r.scaffold_pairs.iter().all(|s| s.a.party != s.b.party));

    // Unverified senders match, but corroborate nothing.
    let r = match_sightings(&[
        party("file-1", Standing::Unverified, shop.clone()),
        party("case-b", Standing::Contacted, clinic.clone()),
    ]);
    assert_eq!(r.pairs.len(), 1);
    assert!(!r.pairs[0].corroborating && !r.groups[0].corroborated);
    assert_eq!(r.groups[0].independent, 1);

    // One party under one name, at its weakest standing: repeating a name
    // never raises it, and its sightings never match each other.
    let r = match_sightings(&[
        party("case-a", Standing::Contacted, shop.clone()),
        party("case-a", Standing::Unverified, clinic.clone()),
    ]);
    assert!(r.pairs.is_empty());
    let r = match_sightings(&[
        party("case-a", Standing::Contacted, shop),
        party("case-a", Standing::Unverified, other),
        party("watch", Standing::Watch, clinic),
    ]);
    assert!(r.pairs.iter().all(|p| p.a.standing == Standing::Unverified));
    assert!(!r.groups[0].corroborated);
}

#[test]
fn a_planted_sighting_that_joins_two_swarms_is_a_bridge() {
    let opts = ExportOptions::default();
    let a = sightings_of(log("a.example", "zz9", T0, ""), &opts);
    let b = sightings_of(log("b.example", "qq4", T0, ""), &opts);
    // The planter copies one feature from each.
    let mut planted = a.clone();
    planted.sightings[0]
        .features
        .extend(b.sightings[0].features.iter().cloned());
    let r = match_sightings(&[
        party("watch", Standing::Watch, a),
        party("case-b", Standing::Contacted, b),
        party("file-x", Standing::Unverified, planted),
    ]);
    assert_eq!(r.groups.len(), 1, "{r:#?}");
    let g = &r.groups[0];
    assert_eq!(g.members.len(), 3);
    assert!(!g.corroborated, "watch and case-b share nothing themselves");
    assert_eq!(g.bridges.len(), 1);
    assert_eq!(g.bridges[0].party, "file-x");
}

#[test]
fn parse_refuses_what_is_not_a_sightings_document() {
    let s = sightings_of(log("a.example", "zz9", T0, ""), &ExportOptions::default());
    let mut bad = s.clone();
    bad.spec = "sc-sightings-v0".into();
    assert!(parse(&serde_json::to_string(&bad).unwrap()).is_err());
    let mut bad = s.clone();
    bad.sightings[0].features[0].hash = "zz9".into();
    assert!(parse(&serde_json::to_string(&bad).unwrap()).is_err());
    let mut bad = s.clone();
    bad.sightings[0].hosts = vec!["a[.]example".into()];
    assert!(parse(&serde_json::to_string(&bad).unwrap()).is_err());
    assert!(parse("{}").is_err());
}
