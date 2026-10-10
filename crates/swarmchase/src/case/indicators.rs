//! What a case's activity is recognised by in new records.

use super::*;
use crate::evidence::Scope;
use anyhow::Result;
use sc_core::{LinkFeature, Observation, Tier, analyze};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

/// What a case's activity is recognised by in new records: the linking
/// features of its non-noise clusters (run tags, inbox and callback channels,
/// agent markers) and the endpoints it hit, as its pinned rules extract them.
pub(crate) struct CaseIndicators {
    /// Linking feature -> what it names (see [`crate::stix::feature_kind`]).
    pub features: BTreeMap<LinkFeature, &'static str>,
    /// Endpoints, except those classified as not affected.
    pub endpoints: BTreeSet<String>,
    /// The case's own records, which never count as new activity.
    pub records: BTreeSet<String>,
    /// Newest capture time among the case's records (0 when none is dated).
    pub last_seen: i64,
}

impl CaseIndicators {
    /// The indicators `o` shares with the case, described for the admin;
    /// empty unless `o` matched at least one rule under `rules` (the case's).
    pub fn matches(&self, o: &Observation, rules: &sc_core::Rules) -> Vec<String> {
        if self.records.contains(&o.id) {
            return Vec::new();
        }
        let x = sc_core::extract(o, rules);
        if x.score <= 0 {
            return Vec::new();
        }
        let mut out: Vec<String> = x
            .features
            .iter()
            .filter_map(|f| {
                let what = self.features.get(f)?;
                let value = match f {
                    LinkFeature::Param { .. } => f.to_string(),
                    LinkFeature::Rule { value, .. } => value.clone(),
                };
                Some(format!("{what} {}", value.trim_start_matches("param:")))
            })
            .collect();
        if let Some(h) = x.target_host.filter(|h| self.endpoints.contains(h)) {
            out.push(format!("Endpoint {h}"));
        }
        out
    }
}

/// The case's indicators under `rules`, which should be its pinned rules
/// ([`case_rules`]).
pub(crate) fn indicators(root: &Path, c: &Case, rules: &sc_core::Rules) -> Result<CaseIndicators> {
    let records = case_records(root, c, &Scope::All)?;
    let a = analyze(records, rules);
    let kinds: BTreeMap<&str, sc_core::IndicatorKind> = rules
        .set
        .rules
        .iter()
        .map(|r| (r.id.as_str(), r.kind))
        .collect();
    let mut features = BTreeMap::new();
    for r in &a.results {
        let in_cluster = r
            .cluster
            .is_some_and(|ci| a.clusters[ci].tier != Tier::Noise);
        if in_cluster {
            for f in &r.features {
                features.insert(f.clone(), crate::stix::feature_kind(f, &kinds));
            }
        }
    }
    Ok(CaseIndicators {
        features,
        endpoints: c
            .endpoints
            .iter()
            .filter(|e| e.state != EndpointState::NotAffected)
            .map(|e| e.host.clone())
            .collect(),
        records: a.results.iter().map(|r| r.obs.id.clone()).collect(),
        last_seen: a.results.iter().map(|r| r.obs.ts).max().unwrap_or(0).max(0),
    })
}
