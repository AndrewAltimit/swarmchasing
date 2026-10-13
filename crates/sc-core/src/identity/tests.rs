//! Classification on synthetic records. The "published" ranges are the
//! documentation blocks (RFC 5737, RFC 3849), and the signing key is RFC
//! 9421's test key; nothing here is a provider's real data.

use super::*;
use crate::ingest::{FieldMap, Format, parse_input};
use crate::rules::Rules;

fn data() -> IdentityData {
    let mut d = IdentityData::default();
    for (id, text) in [
        (
            "openai.chatgpt-user",
            r#"{"prefixes":[{"ipv4Prefix":"192.0.2.0/28"}]}"#,
        ),
        (
            "anthropic.bots",
            r#"{"prefixes":[{"ipv4Prefix":"198.51.100.0/28"}]}"#,
        ),
        (
            "google.user-triggered-agents",
            r#"{"prefixes":[{"ipv6Prefix":"2001:db8:c::/124"}]}"#,
        ),
    ] {
        let mut t = RangeTable::parse(id, text).unwrap();
        t.fetched = Some("2026-10-12".into());
        d.ranges.insert(id.into(), t);
    }
    d
}

/// RFC 9421's test key, standing in for the provider's directory.
fn with_directory(mut d: IdentityData, id: &str, agent: &str) -> IdentityData {
    let jwks = r#"{"keys":[{"kty":"OKP","crv":"Ed25519","x":"JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs"}]}"#;
    d.directories
        .insert(id.into(), KeyDirectory::parse(id, agent, jwks).unwrap());
    d
}

fn log(lines: &str) -> Vec<Observation> {
    let p = parse_input(
        lines,
        Format::AccessLog,
        &FieldMap::parse("host=shop.example").unwrap(),
    );
    assert!(
        p.warnings.iter().all(|w| w.contains("host")),
        "{:?}",
        p.warnings
    );
    p.observations
}

const CHATGPT_UA: &str = "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; ChatGPT-User/1.0; +https://openai.com/bot";

#[test]
fn user_agent_tokens_match_whole() {
    let c = Catalog::bundled();
    assert_eq!(c.agent_in_ua(CHATGPT_UA).unwrap().provider, "OpenAI");
    assert_eq!(
        c.agent_in_ua("Mozilla/5.0 (compatible; Claude-User/1.0; +Claude-User@anthropic.com)")
            .unwrap()
            .token,
        "Claude-User"
    );
    assert!(c.agent_in_ua("NotChatGPT-Userish/2").is_none());
    assert!(c.agent_in_ua("Mozilla/5.0 (Windows NT 10.0)").is_none());
    // Every token the catalog knows is one the `header.agent_ua` rule reads,
    // or a later addition to both.
    let rules = Rules::default_rules();
    let r = rules.rule("header.agent_ua").unwrap();
    for a in &c.agents {
        if a.token == "Google-Agent" {
            continue;
        }
        assert!(
            r.pattern.contains(&a.token),
            "{} missing from header.agent_ua",
            a.token
        );
    }
}

#[test]
fn catalog_references_resolve() {
    let c = Catalog::bundled();
    assert!(!c.agents.is_empty() && !c.range_files.is_empty());
    let bad = "[[agent]]\ntoken='X'\nprovider='P'\nproduct='p'\npurpose='agent'\nranges=['nope']\nsource='s'\n";
    assert!(Catalog::from_toml(bad).unwrap_err().contains("nope"));
    let http = "[[range_file]]\nid='a'\nprovider='P'\nurl='http://a.example/r.json'\nsource='s'\n";
    assert!(Catalog::from_toml(http).is_err());
}

#[test]
fn ua_claims_ranges_and_spoofs_in_an_access_log() {
    let obs = log(&format!(
        r#"192.0.2.9 - - [04/Oct/2026:08:10:00 +0000] "GET /q?id=1 HTTP/1.1" 200 512 "-" "{CHATGPT_UA}"
203.0.113.50 - - [04/Oct/2026:08:10:05 +0000] "GET /q?id=2 HTTP/1.1" 200 512 "-" "{CHATGPT_UA}"
198.51.100.200 - - [04/Oct/2026:08:10:06 +0000] "GET /q?id=3 HTTP/1.1" 200 512 "-" "Mozilla/5.0 (compatible; Claude-User/1.0)"
192.0.2.3 - - [04/Oct/2026:08:10:07 +0000] "GET / HTTP/1.1" 200 512 "-" "Mozilla/5.0 (X11; Linux x86_64) Chrome/126.0"
203.0.113.51 - - [04/Oct/2026:08:10:08 +0000] "GET / HTTP/1.1" 200 512 "-" "curl/8.5"
2001:db8:c::5 - - [04/Oct/2026:08:10:09 +0000] "GET / HTTP/1.1" 200 512 "-" "Mozilla/5.0 (compatible; Google-Agent)""#
    ));
    let (c, d) = (Catalog::bundled(), data());
    let classes: Vec<IdentityClass> = obs.iter().map(|o| classify(o, &c, &d).class).collect();
    assert_eq!(
        classes,
        [
            IdentityClass::IpVerified,
            IdentityClass::Spoofed,
            // Anthropic's list is not documented as exhaustive.
            IdentityClass::Claimed,
            IdentityClass::InRange,
            IdentityClass::None,
            IdentityClass::IpVerified,
        ]
    );
    let spoof = classify(&obs[1], &c, &d);
    assert_eq!(spoof.provider.as_deref(), Some("OpenAI"));
    assert!(
        spoof.detail.contains("outside openai.chatgpt-user"),
        "{}",
        spoof.detail
    );
    assert!(
        classify(&obs[2], &c, &d)
            .detail
            .contains("not documented as exhaustive")
    );

    // Without range files nothing is verified and nothing is a spoof.
    let none = IdentityData::default();
    let r = classify(&obs[1], &c, &none);
    assert_eq!(r.class, IdentityClass::Claimed);
    assert!(r.detail.contains("range file not held"), "{}", r.detail);
    assert_eq!(classify(&obs[3], &c, &none).class, IdentityClass::None);
}

fn signed(ip: &str, agent: &str, sig_b64: &str) -> Observation {
    // draft-meunier-web-bot-auth-architecture-05 A.2.2, for example.com.
    let mut headers = BTreeMap::new();
    headers.insert("signature-agent".into(), format!(r#"agent2="{agent}""#));
    headers.insert(
        "signature-input".into(),
        r#"sig2=("@authority" "signature-agent";key="agent2");created=1735689600;keyid="poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U";alg="ed25519";expires=4889289600;nonce="XeP72svPKNiGEg3aDE7WJuTpN69H08oMFqC8NLFy1MptpENAT3WZTYwK+MYdsFMlaqHCJGo9ZAhqer1NWY9Epg==";tag="web-bot-auth""#.into(),
    );
    headers.insert("signature".into(), format!("sig2=:{sig_b64}:"));
    Observation {
        id: "s".into(),
        ts: 1_735_690_000,
        url: "https://example.com/foo?id=1%27%20OR%201=1--".into(),
        ip: Some(ip.into()),
        user_agent: Some(CHATGPT_UA.into()),
        headers,
        ..Default::default()
    }
}

const A22: &str =
    "DGiW2ErlQh0hc8wY2FQdbnFd6CEmonyY8nlvECIJFaUSYYNvNvSsGyP99BUGtq51gA4ouXlkUwjnta084bpjCg==";

#[test]
fn signatures_outrank_addresses() {
    let mut c = Catalog::bundled();
    // A catalog entry for the vectors' signer, as a provider would document it.
    c.directories.push(DirectoryFile {
        id: "test.signer".into(),
        provider: "Example Provider".into(),
        signature_agent: "https://signature-agent.test".into(),
        url: "https://signature-agent.test/.well-known/http-message-signatures-directory".into(),
        source: "test".into(),
    });
    let d = with_directory(data(), "test.signer", "https://signature-agent.test");
    // Outside every range, but the signature verifies.
    let o = signed("203.0.113.9", "https://signature-agent.test", A22);
    let r = classify(&o, &c, &d);
    if cfg!(feature = "signatures") {
        assert_eq!(r.class, IdentityClass::SignatureVerified, "{r:?}");
        assert_eq!(r.provider.as_deref(), Some("Example Provider"));
        assert_eq!(r.basis.as_deref(), Some("test.signer"));
        // A bad signature from outside the range is a spoof.
        let bad = signed(
            "203.0.113.9",
            "https://signature-agent.test",
            &A22.replace("DGiW", "DGiX"),
        );
        assert_eq!(classify(&bad, &c, &d).class, IdentityClass::Spoofed);
        // ... and a bad one from inside the range is IP-verified, the
        // signature reported beside it.
        let inside = signed(
            "192.0.2.1",
            "https://signature-agent.test",
            &A22.replace("DGiW", "DGiX"),
        );
        let r = classify(&inside, &c, &d);
        assert_eq!(r.class, IdentityClass::IpVerified);
        assert!(matches!(r.signature.unwrap().outcome, Outcome::Failed(_)));
    }
    // A signer whose directory is not held stays unverified, from anywhere.
    let r = classify(&o, &c, &data());
    assert_eq!(r.class, IdentityClass::SignaturePresent);
    assert!(r.detail.contains("never fetched"), "{}", r.detail);
}

#[test]
fn clusters_get_a_line_a_counter_signal_and_a_suggested_claim() {
    let obs = log(&format!(
        r#"192.0.2.9 - - [04/Oct/2026:08:10:00 +0000] "GET /item?id=1%20UNION%20SELECT%201 HTTP/1.1" 200 512 "-" "{CHATGPT_UA}"
192.0.2.9 - - [04/Oct/2026:08:10:30 +0000] "GET /item?id=2%20UNION%20SELECT%202 HTTP/1.1" 200 512 "-" "{CHATGPT_UA}"
203.0.113.50 - - [04/Oct/2026:08:11:00 +0000] "GET /item?id=3%20UNION%20SELECT%203 HTTP/1.1" 200 512 "-" "{CHATGPT_UA}""#
    ));
    let mut a = crate::analyze(obs, &Rules::default_rules());
    assert_eq!(a.clusters.len(), 1, "fixture should form one cluster");
    let before = a.clusters[0].agent.level;
    annotate(&mut a, &Catalog::bundled(), &data());
    annotate(&mut a, &Catalog::bundled(), &data()); // idempotent
    let c = &a.clusters[0];
    assert_eq!(c.identity.records(IdentityClass::IpVerified), 2);
    assert_eq!(c.identity.records(IdentityClass::Spoofed), 1);
    let line = c.identity.summary();
    assert!(
        line.starts_with("2 ip verified (OpenAI, ChatGPT-User) by openai.chatgpt-user"),
        "{line}"
    );
    assert!(line.contains("1 spoofed"), "{line}");
    use crate::agentness::{AgentLevel, SignalKind};
    let n = |v: &[crate::AgentSignal], k| v.iter().filter(|s| s.kind == k).count();
    assert_eq!(n(&c.agent.signals, SignalKind::VerifiedPlatform), 1);
    assert_eq!(n(&c.agent.counter, SignalKind::SpoofedIdentity), 1);
    assert!(c.agent.level >= before && c.agent.level >= AgentLevel::SelfDescribed);
    assert!(c.agent.level < AgentLevel::Documented, "never L5");

    let claims = c.identity.suggested_claims();
    assert_eq!(claims.len(), 1);
    assert_eq!(
        (claims[0].party.as_str(), claims[0].role, claims[0].evidence),
        ("OpenAI", Role::Developer, Evidence::ProviderInfrastructure)
    );
    assert!(claims[0].problems().is_empty());
    // Suggested only: the records' own claims do not include it.
    let own = crate::attribution::attribute(&a, c);
    assert!(
        own.iter()
            .all(|x| x.evidence < Evidence::ProviderInfrastructure),
        "{own:?}"
    );

    // Stored and read back, the identity stays.
    let back: crate::Cluster = serde_json::from_str(&serde_json::to_string(c).unwrap()).unwrap();
    assert_eq!(back.identity, c.identity);
}
