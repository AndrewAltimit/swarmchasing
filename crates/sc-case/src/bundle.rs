//! Evidence bundles without the files: what a bundle holds, its manifest,
//! and the check that its stamp still follows from its records.
//!
//! A bundle is a directory sent with a report:
//!
//! ```text
//! records.ndjson    the redacted records the report rests on
//! analysis.json     the analysis of those records
//! stamp.json        rules version, toolkit version and commit, method version,
//!                   the rules' figures on the committed evaluation set, and
//!                   the tier of every flagged record and cluster at the time
//! MANIFEST.sha256   SHA-256 of each file above
//! ```
//!
//! The check re-runs the analysis from `records.ndjson` and fails if any
//! tier or cluster differs from the stamp, so a recipient (or we, later) can
//! confirm the report follows from the records. The CLI and the browser
//! toolkit both use it; each reads the files its own way.

use sc_core::{Analysis, EvalSnapshot, Observation, Rules, Stamp, StampCluster, Tier, analyze};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

/// The files a manifest lists, in order.
pub const FILES: [&str; 3] = ["records.ndjson", "analysis.json", "stamp.json"];
/// The manifest's file name.
pub const MANIFEST: &str = "MANIFEST.sha256";

pub fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// The redacted records as NDJSON, one record per line.
pub fn to_ndjson(records: &[Observation]) -> String {
    records
        .iter()
        .filter_map(|o| serde_json::to_string(o).ok())
        .map(|l| l + "\n")
        .collect()
}

/// What goes into a new bundle.
pub struct Contents {
    /// [`FILES`] with their text, then the manifest.
    pub files: Vec<(&'static str, String)>,
    pub analysis: Analysis,
    pub stamp: Stamp,
}

/// The bundle of `records` under `rules` for case `case`, stamped at
/// `generated` by toolkit `toolkit` (at `commit`), with the rules' figures
/// on the evaluation set when the caller has them.
pub fn contents(
    case: &str,
    generated: &str,
    toolkit: &str,
    commit: Option<String>,
    records: &[Observation],
    rules: &Rules,
    eval: Option<EvalSnapshot>,
) -> Result<Contents, String> {
    let a = analyze(records.to_vec(), rules);
    let mut st = Stamp::new(case, generated, toolkit, commit, &a);
    st.eval = eval;
    let texts = [
        to_ndjson(records),
        serde_json::to_string(&a).map_err(|e| e.to_string())?,
        serde_json::to_string_pretty(&st).map_err(|e| e.to_string())?,
    ];
    let mut files = Vec::new();
    let mut manifest = String::new();
    for (name, text) in FILES.iter().zip(texts) {
        manifest.push_str(&format!("{}  {name}\n", sha256_hex(text.as_bytes())));
        files.push((*name, text));
    }
    files.push((MANIFEST, manifest));
    Ok(Contents {
        files,
        analysis: a,
        stamp: st,
    })
}

/// Files whose SHA-256 differs from the manifest, or that it does not list.
/// `read(name)` gives a file's bytes, or an error when it cannot be read.
pub fn manifest_differences(
    manifest: &str,
    mut read: impl FnMut(&str) -> Result<Vec<u8>, String>,
) -> Result<Vec<String>, String> {
    let listed: BTreeMap<&str, &str> = manifest
        .lines()
        .filter_map(|l| l.split_once("  "))
        .map(|(h, f)| (f.trim(), h.trim()))
        .collect();
    let mut diffs = Vec::new();
    for f in FILES {
        let Some(want) = listed.get(f) else {
            diffs.push(format!("{f}: not in the manifest"));
            continue;
        };
        let got = sha256_hex(&read(f).map_err(|e| format!("reading {f}: {e}"))?);
        if &got != want {
            diffs.push(format!("{f}: SHA-256 differs from the manifest"));
        }
    }
    Ok(diffs)
}

/// The outcome of a stamp check.
#[derive(Debug, Serialize)]
pub struct Checked {
    pub stamp: Stamp,
    /// Empty when the bundle verifies.
    pub differences: Vec<String>,
    /// What was noticed but does not fail the check.
    pub notes: Vec<String>,
    pub rules_version: String,
    /// The re-run, not the bundle's copy.
    pub analysis: Analysis,
}

/// Re-run the analysis of `records_ndjson` under `rules` and compare it,
/// and the bundle's own `analysis_json` (when given), with the stamp.
/// `rules_hint` ends the line that says the rules differ: where to find the
/// ones the bundle was made with. A copy of the analysis this version cannot
/// read is noted, not failed: the re-run is what the check rests on.
pub fn check(
    records_ndjson: &str,
    analysis_json: &str,
    stamp_json: &str,
    rules: &Rules,
    toolkit: &str,
    rules_hint: &str,
) -> Result<Checked, String> {
    let st: Stamp = serde_json::from_str(stamp_json).map_err(|e| format!("stamp.json: {e}"))?;
    let records = sc_core::stamp::parse_records(records_ndjson)
        .map_err(|e| format!("records.ndjson: {e}"))?;
    let mut differences = Vec::new();
    let mut notes = Vec::new();
    if st.rules_version != rules.set.meta.version {
        differences.push(format!(
            "rules version {} differs from the bundle's {}; {rules_hint}",
            rules.set.meta.version, st.rules_version
        ));
    }
    let a = analyze(records, rules);
    differences.extend(st.differences(&a));
    if !analysis_json.trim().is_empty() {
        match stored_differences(&st, analysis_json) {
            Ok(d) => differences.extend(d.into_iter().map(|d| format!("analysis.json: {d}"))),
            Err(e) => notes.push(format!("analysis.json not compared: {e}")),
        }
    }
    if st.toolkit_version != toolkit {
        notes.push(format!(
            "made with toolkit {}, checked with {toolkit}",
            st.toolkit_version
        ));
    }
    Ok(Checked {
        stamp: st,
        differences,
        notes,
        rules_version: rules.set.meta.version.clone(),
        analysis: a,
    })
}

/// What the stamp check reads of a bundle's `analysis.json`. Reading only
/// these fields, rather than a whole `Analysis`, keeps bundles from older
/// and newer toolkits readable and the browser module small.
#[derive(Deserialize)]
pub struct Stored {
    pub total: usize,
    pub results: Vec<StoredResult>,
    pub clusters: Vec<StoredCluster>,
}

#[derive(Deserialize)]
pub struct StoredResult {
    pub obs: StoredObs,
    pub tier: Tier,
}

#[derive(Deserialize)]
pub struct StoredObs {
    pub id: String,
}

#[derive(Deserialize)]
pub struct StoredCluster {
    pub tier: Tier,
    pub members: Vec<usize>,
}

/// The stored analysis's differences from the stamp, worded as
/// `Stamp::differences` words them.
pub fn stored_differences(st: &Stamp, text: &str) -> Result<Vec<String>, String> {
    let a: Stored = serde_json::from_str(text).map_err(|e| e.to_string())?;
    let id = |m: usize| {
        a.results
            .get(m)
            .map(|r| r.obs.id.clone())
            .ok_or_else(|| format!("cluster member {m} is not a record"))
    };
    let mut clusters = Vec::with_capacity(a.clusters.len());
    for c in &a.clusters {
        let mut members = c
            .members
            .iter()
            .map(|&m| id(m))
            .collect::<Result<Vec<_>, _>>()?;
        sc_core::sort::sort(&mut members);
        clusters.push(StampCluster {
            tier: c.tier,
            members,
        });
    }
    sc_core::sort::by(&mut clusters, |x, y| x.members.cmp(&y.members));
    let flagged: BTreeMap<&str, Tier> = a
        .results
        .iter()
        .filter(|r| r.tier > Tier::Noise)
        .map(|r| (r.obs.id.as_str(), r.tier))
        .collect();
    let mut diffs = Vec::new();
    if a.total != st.records {
        diffs.push(format!("{} records, stamp says {}", a.total, st.records));
    }
    let ids: BTreeSet<&str> = st
        .flagged
        .keys()
        .map(String::as_str)
        .chain(flagged.keys().copied())
        .collect();
    for i in ids {
        let (was, now) = (st.flagged.get(i), flagged.get(i));
        if was != now {
            let label = |t: Option<&Tier>| t.map_or("noise", |t| t.label());
            diffs.push(format!("record {i}: {} → {}", label(was), label(now)));
        }
    }
    if clusters != st.clusters {
        diffs.push(format!(
            "clusters differ: {} in the stamp, {} now (or members or tiers changed)",
            st.clusters.len(),
            clusters.len()
        ));
    }
    Ok(diffs)
}

#[cfg(test)]
mod tests {
    use super::*;

    const V: &str = "0.1.0";

    fn records() -> Vec<Observation> {
        (0..4)
            .map(|i| Observation {
                id: format!("r{i}"),
                ts: 1_791_000_000 + i * 40,
                url: format!(
                    "https://r.jina.ai/https://portal.example.gov/q?id={i}%20UNION%20SELECT%201&uqtag=zz9"
                ),
                ..Default::default()
            })
            .collect()
    }

    fn bundle(rules: &Rules) -> BTreeMap<&'static str, String> {
        contents("t-1", "2026-10-12", V, None, &records(), rules, None)
            .unwrap()
            .files
            .into_iter()
            .collect()
    }

    fn checked(f: &BTreeMap<&str, String>, rules: &Rules) -> Checked {
        check(
            &f["records.ndjson"],
            &f["analysis.json"],
            &f["stamp.json"],
            rules,
            V,
            "verify with the rules it was made with",
        )
        .unwrap()
    }

    #[test]
    fn a_fresh_bundle_verifies_and_tampering_shows() {
        let rules = Rules::default_rules();
        let f = bundle(&rules);
        fn read(f: &BTreeMap<&str, String>) -> impl FnMut(&str) -> Result<Vec<u8>, String> {
            let f: BTreeMap<String, String> =
                f.iter().map(|(k, v)| (k.to_string(), v.clone())).collect();
            move |n: &str| Ok(f[n].clone().into_bytes())
        }
        assert!(
            manifest_differences(&f[MANIFEST], read(&f))
                .unwrap()
                .is_empty()
        );
        let c = checked(&f, &rules);
        assert!(c.differences.is_empty() && c.notes.is_empty(), "{c:?}");
        assert_eq!(c.stamp.case, "t-1");

        let mut fewer = f.clone();
        fewer.insert(
            "records.ndjson",
            f["records.ndjson"]
                .lines()
                .skip(1)
                .map(|l| format!("{l}\n"))
                .collect(),
        );
        let d = manifest_differences(&f[MANIFEST], read(&fewer)).unwrap();
        assert_eq!(d, ["records.ndjson: SHA-256 differs from the manifest"]);
        let c = checked(&fewer, &rules);
        assert!(
            c.differences.iter().any(|x| x == "3 records, stamp says 4"),
            "{c:?}"
        );
        let other = f["stamp.json"].replace(&rules.set.meta.version, "0000-00-00");
        let mut o = f.clone();
        o.insert("stamp.json", other);
        assert!(checked(&o, &rules).differences[0].starts_with("rules version "));
    }

    #[test]
    fn an_unreadable_analysis_copy_is_noted() {
        let rules = Rules::default_rules();
        let mut f = bundle(&rules);
        f.insert("analysis.json", "{}".into());
        let c = checked(&f, &rules);
        assert!(c.differences.is_empty());
        assert!(c.notes[0].starts_with("analysis.json not compared"));
    }

    // The lean reading of analysis.json says what Stamp::differences says of
    // the full analysis.
    #[test]
    fn stored_check_matches_the_stamp_check() {
        let rules = Rules::default_rules();
        let f = bundle(&rules);
        let st: Stamp = serde_json::from_str(&f["stamp.json"]).unwrap();
        let all = records();
        for records in [all.clone(), all[1..].to_vec(), Vec::new()] {
            let a = analyze(records, &rules);
            let text = serde_json::to_string(&a).unwrap();
            assert_eq!(stored_differences(&st, &text).unwrap(), st.differences(&a));
        }
        assert!(
            stored_differences(
                &st,
                r#"{"total":1,"results":[],"clusters":[{"tier":"noise","members":[3]}]}"#
            )
            .is_err()
        );
    }
}
