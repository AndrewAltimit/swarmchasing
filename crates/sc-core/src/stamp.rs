//! Reproducibility stamps for evidence bundles.
//!
//! A stamp records, at the time a bundle is made, the rules and toolkit
//! versions and the tier of every flagged record and cluster. Checking a
//! bundle re-runs the analysis on its records and compares the result with
//! the stamp. The CLI reads and hashes the files; the browser does the same
//! from files the user picks. Both call into this module for the comparison.

use crate::{Analysis, Observation, Tier};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Stamp {
    pub case: String,
    pub generated: String,
    pub toolkit_version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub toolkit_commit: Option<String>,
    pub rules_version: String,
    pub records: usize,
    /// Flagged record ID -> tier.
    pub flagged: BTreeMap<String, Tier>,
    pub clusters: Vec<StampCluster>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StampCluster {
    pub tier: Tier,
    /// Member record IDs, sorted. Cluster numbers are not stable; members are.
    pub members: Vec<String>,
}

impl Stamp {
    /// The stamp of an analysis.
    pub fn new(
        case: &str,
        generated: &str,
        toolkit_version: &str,
        toolkit_commit: Option<String>,
        a: &Analysis,
    ) -> Stamp {
        let mut clusters: Vec<StampCluster> = a
            .clusters
            .iter()
            .map(|c| {
                let mut members: Vec<String> = c
                    .members
                    .iter()
                    .map(|&m| a.results[m].obs.id.clone())
                    .collect();
                members.sort();
                StampCluster {
                    tier: c.tier,
                    members,
                }
            })
            .collect();
        clusters.sort_by(|x, y| x.members.cmp(&y.members));
        Stamp {
            case: case.to_string(),
            generated: generated.to_string(),
            toolkit_version: toolkit_version.to_string(),
            toolkit_commit,
            rules_version: a.rules_version.clone(),
            records: a.total,
            flagged: a
                .results
                .iter()
                .filter(|r| r.tier > Tier::Noise)
                .map(|r| (r.obs.id.clone(), r.tier))
                .collect(),
            clusters,
        }
    }

    /// How a fresh analysis of the bundle's records differs from this stamp:
    /// record count, each record whose tier changed, and the clusters.
    /// Empty means they agree. The rules version is not compared here; the
    /// caller says how to get the right rules.
    pub fn differences(&self, a: &Analysis) -> Vec<String> {
        let mut diffs = Vec::new();
        let again = Stamp::new(&self.case, &self.generated, "", None, a);
        if again.records != self.records {
            diffs.push(format!(
                "{} records, stamp says {}",
                again.records, self.records
            ));
        }
        let ids: BTreeSet<&String> = self.flagged.keys().chain(again.flagged.keys()).collect();
        for id in ids {
            let (was, now) = (self.flagged.get(id), again.flagged.get(id));
            if was != now {
                let label = |t: Option<&Tier>| t.map_or("noise", |t| t.label());
                diffs.push(format!("record {id}: {} → {}", label(was), label(now)));
            }
        }
        if again.clusters != self.clusters {
            diffs.push(format!(
                "clusters differ: {} in the stamp, {} now (or members or tiers changed)",
                self.clusters.len(),
                again.clusters.len()
            ));
        }
        diffs
    }
}

/// Parse a bundle's `records.ndjson`. Blank lines are skipped.
pub fn parse_records(ndjson: &str) -> Result<Vec<Observation>, String> {
    ndjson
        .lines()
        .enumerate()
        .filter(|(_, l)| !l.trim().is_empty())
        .map(|(n, l)| serde_json::from_str(l).map_err(|e| format!("line {}: {e}", n + 1)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Rules, analyze};

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

    #[test]
    fn stamp_agrees_with_its_own_analysis() {
        let rules = Rules::default_rules();
        let a = analyze(records(), &rules);
        let st = Stamp::new("t", "2026-10-12", "0.1.0", None, &a);
        assert_eq!(st.records, 4);
        assert!(!st.flagged.is_empty());
        assert!(!st.clusters.is_empty());
        assert!(st.differences(&a).is_empty());
        let back: Stamp = serde_json::from_str(&serde_json::to_string(&st).unwrap()).unwrap();
        assert_eq!(back, st);
    }

    #[test]
    fn differences_name_what_changed() {
        let rules = Rules::default_rules();
        let st = Stamp::new("t", "d", "0.1.0", None, &analyze(records(), &rules));
        let fewer = analyze(records().into_iter().skip(1).collect(), &rules);
        let diffs = st.differences(&fewer);
        assert!(
            diffs.iter().any(|d| d == "3 records, stamp says 4"),
            "{diffs:?}"
        );
        assert!(
            diffs.iter().any(|d| d.starts_with("record r0: ")),
            "{diffs:?}"
        );
        assert!(
            diffs.iter().any(|d| d.starts_with("clusters differ")),
            "{diffs:?}"
        );
    }

    #[test]
    fn records_parse_with_line_numbers() {
        let nd = "{\"id\":\"a\",\"url\":\"https://example.org/\"}\n\n{bad\n";
        let err = parse_records(nd).unwrap_err();
        assert!(err.starts_with("line 3: "), "{err}");
        assert_eq!(parse_records("\n").unwrap(), Vec::new());
    }
}
