//! `sc-stix`: a case's analysis as a STIX 2.1 bundle, and as a MISP event,
//! for the tooling of the providers and operators it is reported to.
//!
//! The bundle holds an `identity` for the reporter, an `indicator` per run
//! tag, callback channel, agent marker and flagged user agent, an
//! `observed-data` per cluster with its URLs, domains, addresses and
//! networks, `based-on` relationships between them, and a `report` wrapping
//! it all. Values are real (not defanged): STIX patterns are for machines.
//! Each exported cluster is also an `x-sc-agent-run` object ([`agent_run`]),
//! defined by the `extension-definition` the bundle carries, whose schema is
//! committed at `schemas/stix/x-sc-agent-run.json`. Each fleet the admin
//! merged is a `grouping` of its runs ([`fleet`]). Indicators and runs carry
//! their SC-T tactics as `external_references`, with the tactics' MITRE
//! ATLAS, ATT&CK and OWASP agentic entries ([`mapping`]); indicators also as
//! `kill_chain_phases`.
//!
//! The caller passes the analysis of the records the audience may see
//! (operator evidence scoped as the report for that audience). A public
//! export also withholds what the public notice withholds
//! ([`sc_core::notice::PublicView`]), carries no IP addresses or user
//! agents, and is refused when [`sc_core::notice::lint_public`] finds
//! anything in it. Every id is a UUIDv5 of the content (cyber-observable ids
//! follow the STIX recipe), so the same case exports byte for byte the same.
//!
//! [`misp`] turns a bundle into a MISP event. No I/O: the CLI writes the
//! files, and nothing is ever sent.
//!
//! [`observed`] walks the clusters' records, [`indicators`] turns a record
//! into patterns, [`objects`] builds each object type, and [`ids`] makes the
//! ids, markings and timestamps.

pub mod agent_run;
mod fleet;
mod ids;
mod indicators;
pub mod mapping;
pub mod misp;
mod objects;
mod observed;

pub use indicators::feature_kind;

use ids::{TLP_AMBER, TLP_WHITE, sdo_id, stix_ts};
use objects::Head;
use sc_core::notice::lint_public;
use sc_core::{Analysis, Audience, Claim, Evidence, Rules};
use serde_json::Value;
use std::collections::BTreeMap;

/// What an export is for, and what of the case it carries.
pub struct Options<'a> {
    pub case_id: &'a str,
    pub title: &'a str,
    /// Provider, affected or public; case notes are not exported.
    pub audience: Audience,
    pub reporter: &'a str,
    /// `yyyy-mm-dd`, the export's creation time.
    pub today: &'a str,
    /// Hosts classified compromised: their request details are withheld
    /// from a public export.
    pub exposed: &'a [String],
    /// The hosts the case classified affected; a public export names no
    /// other, as the notice.
    pub affected: &'a [String],
    /// The case's own attribution claims.
    pub claims: &'a [Claim],
    pub min_named: Evidence,
    /// The admin's fleets (`case fleet merge`).
    pub fleets: &'a [sc_case::Fleet],
}

impl Options<'_> {
    fn public(&self) -> bool {
        self.audience == Audience::Public
    }
}

/// The bundle: the reporter and the marking, the indicators, each
/// cluster's observed data, the `based-on` relationships between them, a
/// report wrapping it all, and the cyber-observables.
pub fn build(a: &Analysis, rules: &Rules, o: &Options) -> Result<Value, String> {
    let public = o.public();
    let h = Head {
        identity: sdo_id("identity", &format!("reporter:{}", o.reporter)),
        created: stix_ts(sc_core::parse_ts(o.today).unwrap_or(0)),
        marking: if public { TLP_WHITE } else { TLP_AMBER },
    };
    let observed::Observed {
        scos,
        drafts,
        observed,
    } = observed::observe(a, rules, &h, o);

    let mut objects = vec![
        objects::identity(&h, o.reporter),
        objects::marking(h.marking),
        agent_run::extension_definition(&h),
    ];
    let mut report_refs = vec![agent_run::extension_id()];
    let od_ids: BTreeMap<usize, String> = observed
        .iter()
        .map(|(ci, v)| (*ci, v["id"].as_str().unwrap_or_default().to_string()))
        .collect();
    let mut relationships = Vec::new();
    for (pattern, d) in &drafts {
        let id = objects::indicator_id(&h, pattern);
        objects.push(objects::indicator(&h, &id, pattern, d));
        report_refs.push(id.clone());
        for od in d.clusters.iter().filter_map(|ci| od_ids.get(ci)) {
            let rel = objects::based_on(&h, &id, od);
            report_refs.push(rel["id"].as_str().unwrap_or_default().to_string());
            relationships.push(rel);
        }
    }
    if drafts.is_empty() && observed.is_empty() {
        return Err(
            "nothing to export for this audience (no non-noise clusters, or everything withheld)"
                .into(),
        );
    }
    let mut runs = Vec::new();
    let mut exported = BTreeMap::new();
    for (ci, v) in observed {
        let od = v["id"].as_str().unwrap_or_default().to_string();
        let run = agent_run::agent_run(&h, a, &a.clusters[ci], o, &od);
        let run_id = run["id"].as_str().unwrap_or_default().to_string();
        report_refs.push(od.clone());
        report_refs.push(run_id.clone());
        exported.insert(
            ci,
            fleet::Exported {
                run: run_id,
                observed: od,
            },
        );
        objects.push(v);
        runs.push(run);
    }
    objects.extend(runs);
    for f in o.fleets {
        for v in fleet::fleet_objects(&h, a, o.case_id, f, &exported) {
            report_refs.push(v["id"].as_str().unwrap_or_default().to_string());
            objects.push(v);
        }
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
            .chain(
                objects
                    .iter()
                    .filter(|v| v["type"] == agent_run::TYPE)
                    .map(|v| v["attribution"].to_string()),
            )
            .collect();
        let leaks = lint_public(&values.join("\n"), rules);
        if !leaks.is_empty() {
            return Err(format!(
                "the public export would carry what a notice must not:\n  {}",
                leaks.join("\n  ")
            ));
        }
    }

    objects.push(objects::report(&h, o, report_refs));
    objects.extend(scos.into_values());
    objects::bundle(objects)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sc_core::{Observation, analyze};
    use serde_json::json;
    use std::collections::BTreeSet;

    pub(crate) fn analysis() -> (Analysis, Rules) {
        let rules = Rules::default_rules();
        let obs: Vec<Observation> = (0..4)
            .map(|i| Observation {
                id: format!("r{i}"),
                source: "urlquery".into(),
                ts: 1_791_000_000 + i * 40,
                url: format!(
                    "https://r.jina.ai/https://portal.example.gov/q?id={i}%20UNION%20SELECT%201&uqtag=zz9{}",
                    if i == 0 {
                        "&cb=https://webhook.site/0f8fad5b-d9cb-469f-a165-70867728950e"
                    } else {
                        ""
                    }
                ),
                ip: Some("203.0.113.5".into()),
                asn: Some(132203),
                user_agent: Some("python-httpx/0.27".into()),
                ..Default::default()
            })
            .collect();
        (analyze(obs, &rules), rules)
    }

    pub(crate) fn options(audience: Audience, affected: &[String]) -> Options<'_> {
        Options {
            case_id: "t-1",
            title: "Portal probe",
            audience,
            reporter: "Reporter",
            today: "2026-10-14",
            exposed: &[],
            affected,
            claims: &[],
            min_named: Evidence::default(),
            fleets: &[],
        }
    }

    /// Check `v` against the subset of JSON Schema the committed schema uses.
    fn check(v: &Value, s: &Value, at: &str, errs: &mut Vec<String>) {
        if let Some(c) = s.get("const")
            && v != c
        {
            errs.push(format!("{at}: {v} is not {c}"));
        }
        if let Some(e) = s["enum"].as_array()
            && !e.contains(v)
        {
            errs.push(format!("{at}: {v} not in enum"));
        }
        let ok = match s["type"].as_str() {
            Some("object") => v.is_object(),
            Some("array") => v.is_array(),
            Some("string") => v.is_string(),
            Some("integer") => v.is_u64() || v.is_i64(),
            Some("boolean") => v.is_boolean(),
            _ => true,
        };
        if !ok {
            errs.push(format!("{at}: {v} is not a {}", s["type"]));
        }
        if let (Some(p), Some(t)) = (s["pattern"].as_str(), v.as_str())
            && !regex::Regex::new(p).unwrap().is_match(t)
        {
            errs.push(format!("{at}: `{t}` does not match {p}"));
        }
        if let (Some(m), Some(n)) = (s["minimum"].as_u64(), v.as_u64())
            && n < m
        {
            errs.push(format!("{at}: {n} < {m}"));
        }
        if let Some(o) = v.as_object() {
            for r in s["required"].as_array().into_iter().flatten() {
                if !o.contains_key(r.as_str().unwrap()) {
                    errs.push(format!("{at}: missing {r}"));
                }
            }
            if let Some(m) = s["minProperties"].as_u64()
                && (o.len() as u64) < m
            {
                errs.push(format!("{at}: fewer than {m} properties"));
            }
            for (k, x) in o {
                match (s["properties"].get(k), &s["additionalProperties"]) {
                    (Some(ps), _) => check(x, ps, &format!("{at}.{k}"), errs),
                    (None, Value::Bool(false)) => errs.push(format!("{at}: unexpected {k}")),
                    (None, ap) if ap.is_object() => check(x, ap, &format!("{at}.{k}"), errs),
                    _ => {}
                }
            }
        }
        if let Some(a) = v.as_array() {
            if let Some(m) = s["minItems"].as_u64()
                && (a.len() as u64) < m
            {
                errs.push(format!("{at}: fewer than {m} items"));
            }
            if s["uniqueItems"] == true {
                let set: BTreeSet<String> = a.iter().map(|x| x.to_string()).collect();
                if set.len() != a.len() {
                    errs.push(format!("{at}: repeated items"));
                }
            }
            for (i, x) in a.iter().enumerate() {
                check(x, &s["items"], &format!("{at}[{i}]"), errs);
            }
        }
    }

    #[test]
    fn runs_follow_the_committed_schema_and_carry_their_crosswalk() {
        let schema: Value =
            serde_json::from_str(include_str!("../../../schemas/stix/x-sc-agent-run.json"))
                .unwrap();
        let (a, rules) = analysis();
        let affected = vec!["portal.example.gov".to_string()];
        for audience in [Audience::Provider, Audience::Public] {
            let b = build(&a, &rules, &options(audience, &affected)).unwrap();
            let objs = b["objects"].as_array().unwrap();
            let def = objs
                .iter()
                .find(|o| o["type"] == "extension-definition")
                .unwrap();
            assert_eq!(def["schema"], schema["$id"]);
            assert_eq!(def["version"], agent_run::VERSION);
            let runs: Vec<&Value> = objs
                .iter()
                .filter(|o| o["type"] == agent_run::TYPE)
                .collect();
            assert!(!runs.is_empty());
            for r in runs {
                let mut errs = Vec::new();
                check(r, &schema, "run", &mut errs);
                assert!(errs.is_empty(), "{errs:?}\n{r:#}");
                let refs = r["external_references"].as_array().unwrap();
                assert!(refs.contains(&json!({
                    "source_name": "swarmchasing-sc-t",
                    "external_id": "SC-T4",
                    "url": mapping::SC_T_URL,
                })));
                assert!(
                    refs.iter().any(|x| x["external_id"] == "AML.T0049"),
                    "{r:#}"
                );
            }
            let ind = objs
                .iter()
                .find(|o| o["type"] == "indicator" && o["kill_chain_phases"].is_array());
            assert!(ind.is_some() || audience == Audience::Public);
        }
    }

    #[test]
    fn a_public_export_withholds_addresses_and_agents() {
        let (a, rules) = analysis();
        let affected = vec!["portal.example.gov".to_string()];
        let text = build(&a, &rules, &options(Audience::Public, &affected))
            .unwrap()
            .to_string();
        assert!(!text.contains("203.0.113.5") && !text.contains("User-Agent"));
        assert!(text.contains("TLP:WHITE") && text.contains("uqtag=zz9"));
        let provider = build(&a, &rules, &options(Audience::Provider, &affected))
            .unwrap()
            .to_string();
        assert!(provider.contains("203.0.113.5"));
        assert_eq!(
            provider,
            build(&a, &rules, &options(Audience::Provider, &affected))
                .unwrap()
                .to_string(),
            "deterministic"
        );
    }
}
