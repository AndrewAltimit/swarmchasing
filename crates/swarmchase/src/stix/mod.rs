//! `swarmchase case export --format stix|misp`: a case as a STIX 2.1 bundle
//! (or a MISP event made from it) for the tooling of the providers and
//! operators it is reported to. The bundle is built by [`sc_stix`]; this
//! module reads the case, scopes its records to the audience, and checks
//! what it may export.
//!
//! The export takes the same records and operator evidence as the report
//! for that audience ([`crate::case::Scope`]): an affected export only the
//! records on that operator's own endpoints. A public export also withholds
//! what the public notice withholds. The export is a draft written to a
//! file; nothing is sent.

pub use sc_stix::feature_kind;

use crate::case::{self, Scope};
use anyhow::{Result, bail};
use sc_core::Audience;
use serde_json::Value;

/// The case as a STIX bundle for `audience`, pretty-printed.
pub fn export(
    root: &std::path::Path,
    id: &str,
    audience: Audience,
    to: Option<&str>,
    reporter: Option<&str>,
    today: &str,
) -> Result<String> {
    let v = export_value(root, id, audience, to, None, reporter, today)?;
    Ok(format!(
        "{}
",
        serde_json::to_string_pretty(&v)?
    ))
}

/// The case as a STIX bundle for `audience`. An affected export is for the
/// one operator `to` names (on `endpoint`, when the address is listed for
/// more than one operator's); case notes are not exported.
pub fn export_value(
    root: &std::path::Path,
    id: &str,
    audience: Audience,
    to: Option<&str>,
    endpoint: Option<&str>,
    reporter: Option<&str>,
    today: &str,
) -> Result<Value> {
    let c = case::load(root, id)?;
    let contact = match (audience, to) {
        (Audience::Internal, _) => {
            bail!("case notes are not exported; use --audience provider, affected or public")
        }
        (Audience::Affected, None) => {
            bail!("an affected export is for one operator: pass --to <contact address>")
        }
        (Audience::Affected, Some(to)) => Some(case::find_contact(&c, to, endpoint)?),
        _ => None,
    };
    let unreviewed = c.unreviewed().len();
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
    let pinned = case::Pinned::new(root, &c)?;
    let a = pinned.analysis(&Scope::for_audience(audience, contact))?;
    let exposed = sc_case::report::compromised_hosts(&c);
    let affected = case::affected_hosts(&c);
    let opts = sc_stix::Options {
        case_id: &c.id,
        title: &c.title,
        audience,
        reporter: reporter.unwrap_or("swarmchasing"),
        today,
        exposed: &exposed,
        affected: &affected,
        claims: &c.claims,
        min_named: c.min_named,
        fleets: &c.fleets,
    };
    sc_stix::build(&a, &pinned.rules, &opts).map_err(anyhow::Error::msg)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::case::analysis;
    use sc_core::Observation;
    use std::collections::BTreeSet;
    use std::path::{Path, PathBuf};

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
        // A host the admin classified not affected (a page the agents read).
        obs.push(Observation {
            id: "b1".into(),
            source: "urlquery".into(),
            ts: 1_791_000_240,
            url: "https://bystander.example.net/q?id=1%20UNION%20SELECT%201&uqtag=zz9".into(),
            target_asn: Some(64500),
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
            ("bystander.example.net", "not_affected"),
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
    fn agent_runs_follow_the_committed_schema() {
        let schema: Value =
            serde_json::from_str(include_str!("../../../../schemas/stix/x-sc-agent-run.json"))
                .unwrap();
        let root = scratch("ext");
        fixture(&root);
        for audience in [Audience::Provider, Audience::Public] {
            let text = export(&root, "t-1", audience, None, None, "2026-10-14").unwrap();
            let objs = objects(&text);
            let defs: Vec<&Value> = objs
                .iter()
                .filter(|o| o["type"] == "extension-definition")
                .collect();
            assert_eq!(defs.len(), 1);
            let def = defs[0];
            assert_eq!(def["id"], sc_stix::agent_run::extension_id());
            assert_eq!(def["name"], sc_stix::agent_run::TYPE);
            assert_eq!(def["extension_types"], serde_json::json!(["new-sdo"]));
            assert_eq!(def["schema"], schema["$id"]);
            assert!(
                def["created_by_ref"]
                    .as_str()
                    .unwrap()
                    .starts_with("identity--")
            );
            let runs: Vec<&Value> = objs
                .iter()
                .filter(|o| o["type"] == sc_stix::agent_run::TYPE)
                .collect();
            assert!(!runs.is_empty());
            let ids: BTreeSet<&str> = objs.iter().map(|o| o["id"].as_str().unwrap()).collect();
            let report = objs.iter().find(|o| o["type"] == "report").unwrap();
            for r in &runs {
                let mut errs = Vec::new();
                check(r, &schema, "run", &mut errs);
                assert!(errs.is_empty(), "{errs:?}\n{r:#}");
                assert_eq!(
                    r["extensions"][sc_stix::agent_run::extension_id()]["extension_type"],
                    "new-sdo"
                );
                for od in r["observed_data_refs"].as_array().unwrap() {
                    assert!(ids.contains(od.as_str().unwrap()), "dangling {od}");
                }
                assert!(report["object_refs"].as_array().unwrap().contains(&r["id"]));
                assert!(
                    r["tactics"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .any(|t| t == "SC-T4"),
                    "{r:#}"
                );
                let layers: Vec<&str> = r["attribution"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|x| x["layer"].as_str().unwrap())
                    .collect();
                // The harness candidate (python-httpx) is private only.
                assert_eq!(
                    layers.contains(&"harness"),
                    audience == Audience::Provider,
                    "{audience:?} {layers:?}"
                );
            }
        }
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn run_tactics_come_from_the_rules() {
        let root = scratch("tactics");
        fixture(&root);
        let c = case::load(&root, "t-1").unwrap();
        let a = analysis(&root, &c, &Scope::All).unwrap();
        let text = export(&root, "t-1", Audience::Provider, None, None, "2026-10-14").unwrap();
        for r in objects(&text)
            .iter()
            .filter(|o| o["type"] == sc_stix::agent_run::TYPE)
        {
            let cl = a
                .clusters
                .iter()
                .find(|c| c.key == r["cluster_key"].as_str().unwrap())
                .unwrap();
            let want: BTreeSet<String> = cl
                .members
                .iter()
                .flat_map(|&m| &a.results[m].hits)
                .filter_map(|h| h.tactic.map(|t| format!("SC-{}", t.id())))
                .collect();
            let got: BTreeSet<String> = r["tactics"]
                .as_array()
                .unwrap()
                .iter()
                .map(|t| t.as_str().unwrap().to_string())
                .collect();
            assert!(!got.is_empty());
            assert_eq!(got, want, "{r:#}");
        }
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn fleets_export_as_groupings() {
        let root = scratch("fleet").join("cases");
        let rules = crate::pinning::RulesText::load(None).unwrap();
        let records = crate::case::fleet::tests::two_runs();
        case::new_case(&root, "f-1", "Two runs", records, &rules, "2026-10-12").unwrap();
        let run = || export(&root, "f-1", Audience::Provider, None, None, "2026-10-14").unwrap();
        // No fleet yet: no grouping, whatever the analysis proposes.
        assert!(!objects(&run()).iter().any(|o| o["type"] == "grouping"));

        let c = case::load(&root, "f-1").unwrap();
        let a = analysis(&root, &c, &Scope::All).unwrap();
        let keys: Vec<String> = a.clusters.iter().map(|c| c.key.clone()).collect();
        case::update(&root, "f-1", |c| {
            crate::case::fleet::merge(c, &a, &keys, None, "2026-10-13")?;
            Ok(())
        })
        .unwrap();
        let text = run();
        assert_eq!(text, run(), "deterministic");
        let objs = objects(&text);
        let groups: Vec<&Value> = objs.iter().filter(|o| o["type"] == "grouping").collect();
        assert_eq!(groups.len(), 1);
        let g = groups[0];
        assert_eq!(g["context"], "suspicious-activity");
        assert!(g["id"].as_str().unwrap().starts_with("grouping--"));
        let refs: BTreeSet<&str> = g["object_refs"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r.as_str().unwrap())
            .collect();
        let runs: Vec<&Value> = objs
            .iter()
            .filter(|o| o["type"] == sc_stix::agent_run::TYPE)
            .collect();
        assert_eq!(runs.len(), 2);
        for r in &runs {
            assert!(refs.contains(r["id"].as_str().unwrap()));
            assert!(refs.contains(r["observed_data_refs"][0].as_str().unwrap()));
        }
        let related: Vec<&Value> = objs
            .iter()
            .filter(|o| o["relationship_type"] == "related-to")
            .collect();
        assert!(!related.is_empty());
        for rel in &related {
            assert!(refs.contains(rel["id"].as_str().unwrap()));
            assert!(
                rel["description"]
                    .as_str()
                    .unwrap()
                    .starts_with("soft link: ")
            );
        }
        let ids: BTreeSet<&str> = objs.iter().map(|o| o["id"].as_str().unwrap()).collect();
        for r in &refs {
            assert!(ids.contains(r), "dangling {r}");
        }
        let report = objs.iter().find(|o| o["type"] == "report").unwrap();
        assert!(report["object_refs"].as_array().unwrap().contains(&g["id"]));
        std::fs::remove_dir_all(root.parent().unwrap()).unwrap();
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
        // Only its own endpoint's records: no other operator's host.
        assert!(
            !own.contains("hit.example.org") && !own.contains("bystander"),
            "{own}"
        );
        // The other operator's one record forms no cluster on its own, so
        // there is nothing to export to it; never the whole case.
        let other = export(
            &root,
            "t-1",
            Audience::Affected,
            Some("security@hit.example.org"),
            None,
            "2026-10-14",
        )
        .unwrap_err()
        .to_string();
        assert!(other.contains("nothing to export"), "{other}");
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
        // A host not classified affected is not named, as in the notice:
        // not its domain, its URLs or the network a scanner reached it on.
        assert!(public.contains("portal.example.gov"), "{public}");
        assert!(!public.contains("bystander"), "{public}");
        assert!(!public.contains("64500"), "{public}");
        let provider = export(&root, "t-1", Audience::Provider, None, None, "2026-10-14").unwrap();
        assert!(provider.contains("bystander.example.net"));
        std::fs::remove_dir_all(&root).unwrap();
    }
}
