//! `swarmchase case export`: a case as a STIX 2.1 bundle for the tooling of
//! the providers and operators it is reported to.
//!
//! The bundle holds an `identity` for the reporter, an `indicator` per run
//! tag, callback channel, agent marker and flagged user agent, an
//! `observed-data` per cluster with its URLs, domains, addresses and
//! networks, `based-on` relationships between them, and a `report` wrapping
//! it all. Values are real (not defanged): STIX patterns are for machines.
//!
//! The export takes the same operator evidence as the report for that
//! audience ([`Scope`]); a public export also withholds what the public
//! notice withholds ([`PublicView`]), carries no IP addresses or user
//! agents, and is checked with [`lint_public`]. Every id is a UUIDv5 of the
//! content (cyber-observable ids follow the STIX recipe), so the same case
//! exports byte for byte the same. The export is a draft written to a file;
//! nothing is sent.

use crate::case::{self, EndpointState};
use anyhow::{Context, Result, bail};
use clap::Args;
use sc_core::notice::{PublicView, TAG_PARAMS, WITHHELD, lint_public};
use sc_core::rules::Target;
use sc_core::{Analysis, Audience, IndicatorKind, LinkFeature, ObsResult, Rules, Tier, analyze};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum ExportFormat {
    /// A STIX 2.1 bundle (JSON).
    Stix,
}

#[derive(Args)]
pub struct ExportArgs {
    id: String,
    #[arg(long, default_value = "stix")]
    format: ExportFormat,
    /// provider | affected | public
    #[arg(long, default_value = "provider")]
    audience: Audience,
    /// For an affected export: the operator's contact address, as listed in
    /// case.toml. Only that operator's own logs are included.
    #[arg(long)]
    to: Option<String>,
    /// Name for the reporter identity.
    #[arg(long)]
    reporter: Option<String>,
    /// Default: <case>/exports/<audience>-<date>.stix.json
    #[arg(short, long)]
    out: Option<PathBuf>,
}

pub fn run(root: &Path, args: ExportArgs, today: &str) -> Result<()> {
    let ExportFormat::Stix = args.format;
    let text = export(
        root,
        &args.id,
        args.audience,
        args.to.as_deref(),
        args.reporter.as_deref(),
        today,
    )?;
    let path = args.out.unwrap_or_else(|| {
        root.join(&args.id)
            .join("exports")
            .join(format!("{}-{today}.stix.json", audience_id(args.audience)))
    });
    crate::write_out(Some(&path), &text)?;
    println!("draft only; nothing was sent");
    Ok(())
}

fn audience_id(a: Audience) -> &'static str {
    match a {
        Audience::Provider => "provider",
        Audience::Affected => "affected",
        Audience::Internal => "internal",
        Audience::Public => "public",
    }
}

/// The case as a STIX bundle for `audience`, pretty-printed.
pub fn export(
    root: &Path,
    id: &str,
    audience: Audience,
    to: Option<&str>,
    reporter: Option<&str>,
    today: &str,
) -> Result<String> {
    let c = case::load(root, id)?;
    let contact = match (audience, to) {
        (Audience::Internal, _) => {
            bail!("case notes are not exported; use --audience provider, affected or public")
        }
        (Audience::Affected, None) => {
            bail!("an affected export is for one operator: pass --to <contact address>")
        }
        (Audience::Affected, Some(to)) => Some(
            c.contacts
                .iter()
                .find(|x| x.address.eq_ignore_ascii_case(to))
                .with_context(|| format!("`{to}` is not a contact in case {id}"))?,
        ),
        _ => None,
    };
    let unreviewed = c
        .endpoints
        .iter()
        .filter(|e| e.state == EndpointState::Unreviewed)
        .count();
    if unreviewed > 0 {
        if audience == Audience::Public {
            bail!(
                "{unreviewed} endpoint(s) are unreviewed; classify them first (the public export withholds attack details for compromised ones)"
            );
        }
        eprintln!(
            "warning: {unreviewed} endpoint(s) are still unreviewed; classify them before sharing"
        );
    }
    let rules = case::case_rules(root, &c)?;
    let records = case::case_records(root, &c, &case::scope(audience, contact))?;
    let a = analyze(records, &rules);
    let exposed: Vec<String> = c
        .endpoints
        .iter()
        .filter(|e| e.state == EndpointState::Compromised)
        .map(|e| e.host.clone())
        .collect();
    let opts = Options {
        case_id: &c.id,
        title: &c.title,
        audience,
        reporter: reporter.unwrap_or("swarmchasing"),
        today,
        exposed: &exposed,
    };
    let bundle = build(&a, &rules, &opts)?;
    Ok(format!("{}\n", serde_json::to_string_pretty(&bundle)?))
}

struct Options<'a> {
    case_id: &'a str,
    title: &'a str,
    audience: Audience,
    reporter: &'a str,
    today: &'a str,
    exposed: &'a [String],
}

/// One indicator, gathered over every record and cluster it came from.
struct Draft {
    name: String,
    label: String,
    tier: Tier,
    valid_from: i64,
    clusters: BTreeSet<usize>,
}

fn build(a: &Analysis, rules: &Rules, o: &Options) -> Result<Value> {
    let public = o.audience == Audience::Public;
    let mut view = PublicView::new(a, o.exposed);
    let kinds: BTreeMap<&str, IndicatorKind> = rules
        .set
        .rules
        .iter()
        .map(|r| (r.id.as_str(), r.kind))
        .collect();
    let ua_rules: BTreeSet<&str> = rules
        .set
        .rules
        .iter()
        .filter(|r| r.target == Target::UserAgent)
        .map(|r| r.id.as_str())
        .collect();
    let asn_names: BTreeMap<u32, &str> = a
        .asns
        .iter()
        .filter_map(|x| Some((x.asn, x.org.as_deref()?)))
        .collect();

    let created = stix_ts(sc_core::parse_ts(o.today).unwrap_or(0));
    let identity_id = sdo_id("identity", &format!("reporter:{}", o.reporter));
    let marking = if public { TLP_WHITE } else { TLP_AMBER };
    let marking_id = marking.0;

    let mut scos: BTreeMap<String, Value> = BTreeMap::new();
    let mut drafts: BTreeMap<String, Draft> = BTreeMap::new();
    let mut observed: Vec<(usize, Value)> = Vec::new();

    for (ci, cl) in a.clusters.iter().enumerate() {
        if cl.tier == Tier::Noise {
            continue;
        }
        let mut refs = BTreeSet::new();
        for &m in &cl.members {
            let r = &a.results[m];
            // The URL a public notice may show, or none at all.
            let shown = if public {
                view.record_url(r).filter(|u| !u.contains(WITHHELD))
            } else {
                Some(r.obs.url.clone())
            };
            if let Some(u) = shown.as_deref().filter(|u| !u.is_empty()) {
                refs.insert(add_sco(&mut scos, "url", json!({ "value": u })));
            }
            if let Some(h) = r
                .target_host
                .as_deref()
                .filter(|h| h.parse::<IpAddr>().is_err())
            {
                refs.insert(add_sco(&mut scos, "domain-name", json!({ "value": h })));
            }
            // The network observed in the record: the client's, or the
            // target's where a scan service recorded only that.
            if let Some(asn) = r.obs.asn.or(r.obs.target_asn) {
                let mut v = json!({ "number": asn });
                if let Some(n) = asn_names.get(&asn).copied().or_else(|| rules.asn_org(asn)) {
                    v["name"] = json!(n);
                }
                refs.insert(add_sco(&mut scos, "autonomous-system", v));
            }
            if !public && let Some(ip) = r.obs.ip.as_deref() {
                match ip.parse::<IpAddr>() {
                    Ok(IpAddr::V4(_)) => {
                        refs.insert(add_sco(&mut scos, "ipv4-addr", json!({ "value": ip })));
                    }
                    Ok(IpAddr::V6(_)) => {
                        refs.insert(add_sco(&mut scos, "ipv6-addr", json!({ "value": ip })));
                    }
                    Err(_) => {}
                }
            }
            for (pattern, d) in indicators(r, &kinds, &ua_rules, public, shown.is_some(), &mut view)
            {
                let e = drafts.entry(pattern).or_insert(d);
                e.tier = e.tier.max(cl.tier);
                if r.obs.ts > 0 {
                    e.valid_from = e.valid_from.min(r.obs.ts);
                }
                e.clusters.insert(ci);
            }
        }
        if refs.is_empty() {
            continue;
        }
        let mut members: Vec<&str> = cl
            .members
            .iter()
            .map(|&m| a.results[m].obs.id.as_str())
            .collect();
        members.sort_unstable();
        let first = if cl.start > 0 {
            stix_ts(cl.start)
        } else {
            created.clone()
        };
        let last = if cl.end > 0 {
            stix_ts(cl.end)
        } else {
            first.clone()
        };
        observed.push((
            ci,
            json!({
                "type": "observed-data",
                "spec_version": "2.1",
                "id": sdo_id("observed-data", &format!("{}:{}:{}", marking.1, o.case_id, members.join(","))),
                "created_by_ref": identity_id,
                "created": created,
                "modified": created,
                "first_observed": first,
                "last_observed": last,
                "number_observed": cl.members.len().clamp(1, 999_999_999),
                "object_refs": refs.into_iter().collect::<Vec<_>>(),
                "object_marking_refs": [marking_id],
            }),
        ));
    }

    let mut objects = vec![
        json!({
            "type": "identity",
            "spec_version": "2.1",
            "id": identity_id,
            "created": created,
            "modified": created,
            "name": o.reporter,
        }),
        json!({
            "type": "marking-definition",
            "spec_version": "2.1",
            "id": marking.0,
            "created": "2017-01-20T00:00:00.000Z",
            "definition_type": "tlp",
            "name": marking.1,
            "definition": { "tlp": marking.2 },
        }),
    ];
    let mut report_refs = Vec::new();
    let od_ids: BTreeMap<usize, String> = observed
        .iter()
        .map(|(ci, v)| (*ci, v["id"].as_str().unwrap_or_default().to_string()))
        .collect();
    let mut relationships = Vec::new();
    for (pattern, d) in &drafts {
        // Exports under different markings are different objects.
        let id = sdo_id("indicator", &format!("{}:{pattern}", marking.1));
        let malicious = d.tier == Tier::Significant;
        objects.push(json!({
            "type": "indicator",
            "spec_version": "2.1",
            "id": id,
            "created_by_ref": identity_id,
            "created": created,
            "modified": created,
            "name": d.name,
            "indicator_types": [if malicious { "malicious-activity" } else { "anomalous-activity" }],
            "pattern": pattern,
            "pattern_type": "stix",
            "pattern_version": "2.1",
            "valid_from": if d.valid_from == i64::MAX { created.clone() } else { stix_ts(d.valid_from) },
            "confidence": confidence(d.tier),
            "labels": [d.label],
            "object_marking_refs": [marking_id],
        }));
        report_refs.push(id.clone());
        for od in d.clusters.iter().filter_map(|ci| od_ids.get(ci)) {
            let rid = sdo_id("relationship", &format!("{id}:based-on:{od}"));
            relationships.push(json!({
                "type": "relationship",
                "spec_version": "2.1",
                "id": rid,
                "created_by_ref": identity_id,
                "created": created,
                "modified": created,
                "relationship_type": "based-on",
                "source_ref": id,
                "target_ref": od,
                "object_marking_refs": [marking_id],
            }));
            report_refs.push(rid);
        }
    }
    if drafts.is_empty() && observed.is_empty() {
        bail!(
            "nothing to export for this audience (no non-noise clusters, or everything withheld)"
        );
    }
    for (_, v) in observed {
        report_refs.push(v["id"].as_str().unwrap_or_default().to_string());
        objects.push(v);
    }
    objects.extend(relationships);
    report_refs.extend(scos.keys().cloned());

    if public {
        let values: Vec<String> = drafts
            .keys()
            .cloned()
            .chain(
                scos.values()
                    .filter_map(|v| v["value"].as_str().map(str::to_string)),
            )
            .collect();
        let leaks = lint_public(&values.join("\n"), rules);
        if !leaks.is_empty() {
            bail!(
                "the public export would carry what a notice must not:\n  {}",
                leaks.join("\n  ")
            );
        }
    }

    objects.push(json!({
        "type": "report",
        "spec_version": "2.1",
        "id": sdo_id("report", &format!("{}:{}", o.case_id, audience_id(o.audience))),
        "created_by_ref": identity_id,
        "created": created,
        "modified": created,
        "name": o.title,
        "description": format!(
            "DRAFT from swarmchasing case {} ({} export). Verify every item against the public records before sharing.",
            o.case_id,
            audience_id(o.audience)
        ),
        "report_types": ["threat-report"],
        "published": created,
        "object_refs": report_refs,
        "object_marking_refs": [marking_id],
    }));
    objects.extend(scos.into_values());

    let content = serde_json::to_string(&objects)?;
    Ok(json!({
        "type": "bundle",
        "id": format!("bundle--{}", uuid5(STIX_NS, &crate::bundle::sha256_hex(content.as_bytes()))),
        "objects": objects,
    }))
}

/// The indicators one record yields, keyed by STIX pattern. Only patterns
/// that match the record they came from are kept.
fn indicators(
    r: &ObsResult,
    kinds: &BTreeMap<&str, IndicatorKind>,
    ua_rules: &BTreeSet<&str>,
    public: bool,
    url_shown: bool,
    view: &mut PublicView,
) -> Vec<(String, Draft)> {
    let url = r.obs.url.to_ascii_lowercase();
    let mut out = Vec::new();
    let mut seen = BTreeSet::new();
    let mut url_like = |out: &mut Vec<(String, Draft)>, value: &str, name: String, label: &str| {
        let lower = value.to_ascii_lowercase();
        if value.is_empty() || value.ends_with('…') || !url.contains(&lower) {
            return;
        }
        if seen.insert(format!("url:{lower}")) {
            out.push((
                format!("[url:value LIKE '%{}%']", lit(value)),
                draft(name, label.to_string()),
            ));
        }
    };
    let mut domains = BTreeSet::new();

    for f in &r.features {
        if public && view.feature(f) != f.to_string() {
            continue;
        }
        let what = feature_kind(f, kinds);
        let (rule, value) = match f {
            LinkFeature::Param { .. } => {
                let p = f.to_string();
                let p = p.trim_start_matches("param:");
                url_like(&mut out, p, format!("{what} {p}"), "param");
                continue;
            }
            LinkFeature::Rule { rule, value } => (rule.as_str(), value.as_str()),
        };
        match kinds.get(rule) {
            Some(IndicatorKind::Exfil) if !value.contains('/') && url.contains(value) => {
                if domains.insert(value.to_string()) {
                    out.push((
                        format!("[domain-name:value = '{}']", lit(value)),
                        draft(format!("Callback channel {value}"), rule.to_string()),
                    ));
                }
            }
            Some(IndicatorKind::Exfil) => {
                url_like(&mut out, value, format!("Callback channel {value}"), rule)
            }
            _ => url_like(&mut out, value, format!("Agent marker {value}"), rule),
        }
    }
    // Agent markers that are not linking features (a tag parameter's name
    // and value, a test string).
    if !public || url_shown {
        for h in r
            .hits
            .iter()
            .filter(|h| h.kind == IndicatorKind::AgentMarker)
        {
            let f = LinkFeature::rule(&h.rule_id, &h.matched);
            if public && view.feature(&f) != f.to_string() {
                continue;
            }
            url_like(
                &mut out,
                &h.matched,
                format!("Agent marker {}", h.matched),
                &h.rule_id,
            );
        }
    }
    if !public
        && r.hits.iter().any(|h| ua_rules.contains(h.rule_id.as_str()))
        && let Some(ua) = r.obs.user_agent.as_deref().or_else(|| {
            r.obs
                .headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("user-agent"))
                .map(|(_, v)| v.as_str())
        })
    {
        out.push((
            format!(
                "[network-traffic:extensions.'http-request-ext'.request_header.'User-Agent' = '{}']",
                lit(ua)
            ),
            draft(format!("User agent {ua}"), "user-agent".into()),
        ));
    }
    out
}

/// What a linking feature names, as indicators label it: a run tag or other
/// linking parameter, a callback channel, or an agent marker.
pub(crate) fn feature_kind(f: &LinkFeature, kinds: &BTreeMap<&str, IndicatorKind>) -> &'static str {
    match f {
        LinkFeature::Param { name, .. } if TAG_PARAMS.contains(&name.as_str()) => "Run tag",
        LinkFeature::Param { .. } => "Linking parameter",
        LinkFeature::Rule { rule, .. } => match kinds.get(rule.as_str()) {
            Some(IndicatorKind::Exfil) => "Callback channel",
            _ => "Agent marker",
        },
    }
}

fn draft(name: String, label: String) -> Draft {
    Draft {
        name,
        label,
        tier: Tier::Noise,
        valid_from: i64::MAX,
        clusters: BTreeSet::new(),
    }
}

fn confidence(t: Tier) -> u8 {
    match t {
        Tier::Significant => 85,
        Tier::Suggestive => 50,
        Tier::Noise => 15,
    }
}

/// A string literal inside a STIX pattern.
fn lit(s: &str) -> String {
    s.replace('\\', "\\\\").replace('\'', "\\'")
}

fn stix_ts(ts: i64) -> String {
    chrono::DateTime::<chrono::Utc>::from_timestamp(ts.max(0), 0)
        .unwrap_or_default()
        .format("%Y-%m-%dT%H:%M:%S.000Z")
        .to_string()
}

/// Add a cyber-observable once, with its STIX deterministic id (a UUIDv5 of
/// its id-contributing property in the STIX namespace).
fn add_sco(scos: &mut BTreeMap<String, Value>, kind: &str, props: Value) -> String {
    let key = if kind == "autonomous-system" {
        json!({ "number": props["number"] })
    } else {
        json!({ "value": props["value"] })
    };
    let id = format!("{kind}--{}", uuid5(STIX_NS, &key.to_string()));
    scos.entry(id.clone()).or_insert_with(|| {
        let mut v = props;
        v["type"] = json!(kind);
        v["spec_version"] = json!("2.1");
        v["id"] = json!(id);
        v
    });
    id
}

fn sdo_id(kind: &str, name: &str) -> String {
    format!(
        "{kind}--{}",
        uuid5(STIX_NS, &format!("swarmchase:{kind}:{name}"))
    )
}

/// The namespace STIX 2.1 uses for deterministic cyber-observable ids.
const STIX_NS: [u8; 16] = [
    0x00, 0xab, 0xed, 0xb4, 0xaa, 0x42, 0x46, 0x6c, 0x9c, 0x01, 0xfe, 0xd2, 0x33, 0x15, 0xa9, 0xb7,
];

/// The predefined STIX 2.1 TLP marking definitions: id, name, level.
const TLP_WHITE: (&str, &str, &str) = (
    "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
    "TLP:WHITE",
    "white",
);
const TLP_AMBER: (&str, &str, &str) = (
    "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82",
    "TLP:AMBER",
    "amber",
);

/// RFC 4122 name-based UUID, version 5 (SHA-1).
fn uuid5(ns: [u8; 16], name: &str) -> String {
    let mut data = ns.to_vec();
    data.extend_from_slice(name.as_bytes());
    let h = sha1(&data);
    let mut b = [0u8; 16];
    b.copy_from_slice(&h[..16]);
    b[6] = (b[6] & 0x0f) | 0x50;
    b[8] = (b[8] & 0x3f) | 0x80;
    let hex: String = b.iter().map(|x| format!("{x:02x}")).collect();
    format!(
        "{}-{}-{}-{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..]
    )
}

/// SHA-1, for UUIDv5 only (not for integrity: bundles use SHA-256).
fn sha1(data: &[u8]) -> [u8; 20] {
    let mut h: [u32; 5] = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&((data.len() as u64) * 8).to_be_bytes());
    for chunk in msg.chunks(64) {
        let mut w = [0u32; 80];
        for (i, word) in chunk.chunks(4).enumerate() {
            w[i] = u32::from_be_bytes([word[0], word[1], word[2], word[3]]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let [mut a, mut b, mut c, mut d, mut e] = h;
        for (i, wi) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | (!b & d), 0x5A827999),
                20..=39 => (b ^ c ^ d, 0x6ED9EBA1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDC),
                _ => (b ^ c ^ d, 0xCA62C1D6),
            };
            let t = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(*wi);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = t;
        }
        for (x, y) in h.iter_mut().zip([a, b, c, d, e]) {
            *x = x.wrapping_add(y);
        }
    }
    let mut out = [0u8; 20];
    for (i, x) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&x.to_be_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use sc_core::Observation;

    fn scratch(name: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("swarmchase-stix-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        p
    }

    fn ndjson(records: &[Observation]) -> String {
        records
            .iter()
            .map(|o| serde_json::to_string(o).unwrap() + "\n")
            .collect()
    }

    /// A case with a probe cluster on two hosts, one compromised, and logs
    /// from the operator of the other.
    fn fixture(root: &Path) {
        let mut obs: Vec<Observation> = (0..4)
            .map(|i| Observation {
                id: format!("r{i}"),
                source: "urlquery".into(),
                ts: 1_791_000_000 + i * 40,
                url: format!(
                    "https://r.jina.ai/https://portal.example.gov/q?id={i}%20UNION%20SELECT%201&uqtag=zz9"
                ),
                ip: Some("203.0.113.5".into()),
                asn: Some(132203),
                user_agent: Some("python-httpx/0.27".into()),
                ..Default::default()
            })
            .collect();
        obs.push(Observation {
            id: "w1".into(),
            source: "urlquery".into(),
            ts: 1_791_000_200,
            url: "https://hit.example.org/login?user=admin'--&uqtag=zz9".into(),
            ..Default::default()
        });
        let dir = root.join("t-1");
        std::fs::create_dir_all(dir.join("raw")).unwrap();
        std::fs::write(dir.join("raw").join("records.ndjson"), ndjson(&obs)).unwrap();
        let theirs = Observation {
            id: "op1".into(),
            source: "operator:e1".into(),
            ts: 1_791_000_300,
            url: "https://portal.example.gov/q?id=9%20UNION%20SELECT%201&uqtag=opsonly77".into(),
            ..Default::default()
        };
        let p = crate::evidence::file(&dir, "e1");
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, ndjson(&[theirs])).unwrap();
        let mut toml = String::from(
            "id = \"t-1\"
title = \"Portal probe\"
status = \"open\"
notice = \"active\"
opened = \"2026-10-12\"
",
        );
        for (host, state) in [
            ("portal.example.gov", "targeted"),
            ("hit.example.org", "compromised"),
        ] {
            toml += &format!(
                "[[endpoint]]
host = \"{host}\"
state = \"{state}\"
"
            );
        }
        for (org, host) in [("Portal", "portal.example.gov"), ("Hit", "hit.example.org")] {
            toml += &format!(
                "[[contact]]
org = \"{org}\"
role = \"affected\"
endpoint = \"{host}\"
channel = \"email\"
address = \"security@{host}\"
source = \"\"
confidence = \"medium\"
found_on = \"2026-10-12\"
"
            );
        }
        toml += "[[evidence]]
id = \"e1\"
org = \"Portal\"
host = \"portal.example.gov\"
received = \"2026-10-13\"
sha256 = \"00\"
lines = 1
kept = 1
";
        std::fs::write(dir.join("case.toml"), toml).unwrap();
        assert_eq!(case::load(root, "t-1").unwrap().contacts.len(), 2);
    }

    fn objects(text: &str) -> Vec<Value> {
        let v: Value = serde_json::from_str(text).unwrap();
        assert_eq!(v["type"], "bundle");
        assert!(v["id"].as_str().unwrap().starts_with("bundle--"));
        v["objects"].as_array().unwrap().clone()
    }

    #[test]
    fn uuid5_and_sha1_match_reference_values() {
        let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
        assert_eq!(
            hex(&sha1(b"abc")),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );
        assert_eq!(hex(&sha1(b"")), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
        let dns = [
            0x6b, 0xa7, 0xb8, 0x10, 0x9d, 0xad, 0x11, 0xd1, 0x80, 0xb4, 0x00, 0xc0, 0x4f, 0xd4,
            0x30, 0xc8,
        ];
        assert_eq!(
            uuid5(dns, "python.org"),
            "886313e1-3b8a-5372-9b90-0c9aee199e5d"
        );
    }

    #[test]
    fn bundle_is_well_formed() {
        let root = scratch("shape");
        fixture(&root);
        let text = export(
            &root,
            "t-1",
            Audience::Provider,
            None,
            Some("Reporter"),
            "2026-10-14",
        )
        .unwrap();
        let objs = objects(&text);
        let mut ids = BTreeSet::new();
        for o in &objs {
            let id = o["id"].as_str().unwrap();
            let ty = o["type"].as_str().unwrap();
            assert!(id.starts_with(&format!("{ty}--")), "{id}");
            assert_eq!(o["spec_version"], "2.1", "{id}");
            assert!(ids.insert(id.to_string()), "duplicate id {id}");
        }
        let mut refs = Vec::new();
        for o in &objs {
            for k in ["created_by_ref", "source_ref", "target_ref"] {
                if let Some(r) = o[k].as_str() {
                    refs.push(r.to_string());
                }
            }
            for k in ["object_refs", "object_marking_refs"] {
                for r in o[k].as_array().into_iter().flatten() {
                    refs.push(r.as_str().unwrap().to_string());
                }
            }
        }
        for r in &refs {
            assert!(ids.contains(r), "dangling reference {r}");
        }
        let of = |ty: &str| objs.iter().filter(|o| o["type"] == ty).collect::<Vec<_>>();
        assert_eq!(of("identity")[0]["name"], "Reporter");
        assert_eq!(of("report")[0]["name"], "Portal probe");
        assert!(!of("observed-data").is_empty());
        assert!(!of("relationship").is_empty());
        let patterns: Vec<&str> = of("indicator")
            .iter()
            .map(|o| o["pattern"].as_str().unwrap())
            .collect();
        assert!(
            patterns.contains(&"[url:value LIKE '%uqtag=zz9%']"),
            "{patterns:?}"
        );
        assert!(
            patterns
                .iter()
                .any(|p| p.contains("'User-Agent' = 'python-httpx/0.27'")),
            "{patterns:?}"
        );
        assert!(text.contains("\"value\": \"203.0.113.5\""));
        assert!(text.contains("\"number\": 132203"));
        // Providers get every operator's logs.
        assert!(text.contains("opsonly77"));
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn export_is_deterministic() {
        let root = scratch("det");
        fixture(&root);
        let run = || export(&root, "t-1", Audience::Provider, None, None, "2026-10-14").unwrap();
        assert_eq!(run(), run());
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn exports_keep_to_their_audience() {
        let root = scratch("scope");
        fixture(&root);
        let own = export(
            &root,
            "t-1",
            Audience::Affected,
            Some("security@portal.example.gov"),
            None,
            "2026-10-14",
        )
        .unwrap();
        assert!(own.contains("opsonly77"), "an operator's own logs");
        let other = export(
            &root,
            "t-1",
            Audience::Affected,
            Some("security@hit.example.org"),
            None,
            "2026-10-14",
        )
        .unwrap();
        assert!(!other.contains("opsonly77"), "another operator's logs");
        assert!(export(&root, "t-1", Audience::Affected, None, None, "d").is_err());
        assert!(export(&root, "t-1", Audience::Internal, None, None, "d").is_err());

        // Public: no unagreed operator logs, no compromised endpoint's
        // requests, no addresses or user agents.
        let public = export(&root, "t-1", Audience::Public, None, None, "2026-10-14").unwrap();
        assert!(!public.contains("opsonly77"));
        assert!(!public.contains("admin'--"), "{public}");
        assert!(!public.contains("203.0.113.5"));
        assert!(!public.contains("User-Agent"));
        assert!(public.contains("TLP:WHITE"));
        assert!(public.contains("uqtag=zz9"));
        std::fs::remove_dir_all(&root).unwrap();
    }
}
