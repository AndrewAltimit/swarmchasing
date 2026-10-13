//! Sightings: what a swarm left in one operator's logs, in a form the
//! operator can share without sharing its logs or its visitors
//! (SC-Sightings v1, `docs/specs/sightings-v1.md`).
//!
//! [`export`] turns an analysis into a sightings document, one entry per
//! flagged cluster: keyed hashes of the features that linked it ([`keys`]),
//! the scaffold it ran on (relay stacks, payload dialect, rules, tactics,
//! header sets, client networks), hour buckets and the agent grade. It
//! never carries a URL, a path, a query value, an IP address, a user agent
//! or a cookie, and the operator's own hosts only when asked.
//!
//! [`matching::match_sightings`] finds clusters seen by more than one party.
//! A match proposes; it never merges clusters, and how much it counts
//! depends on who the parties are ([`matching::Standing`]), never on what a
//! file says about itself.

pub mod keys;
pub mod matching;

pub use keys::{EpochKeys, epoch_of};
pub use matching::{MatchReport, Party, Standing, match_sightings};

use crate::analyze::{Analysis, Cluster};
use crate::model::{LinkFeature, Tactic, Tier};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// The `spec` every sightings document carries.
pub const SPEC: &str = "sc-sightings-v1";

/// Limits a document must keep to, so a planted file cannot swamp the
/// matcher.
pub const MAX_CLUSTERS: usize = 500;
pub const MAX_FEATURES: usize = 400;
pub const MAX_HOURS: usize = 2_000;

/// One operator's sightings, as it downloads or sends them.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Sightings {
    /// Always [`SPEC`].
    pub spec: String,
    /// The day it was made (`yyyy-mm-dd`), as the caller gives it.
    pub generated: String,
    /// The rules version the analysis ran with.
    pub rules_version: String,
    /// How the sender describes itself, if it chose to. Shown to the admin;
    /// never read as who the sender is.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operator: Option<String>,
    /// Whether the operator chose to include its own host names.
    #[serde(default)]
    pub shares_hosts: bool,
    /// Epochs the records fall in that have no published key: features in
    /// them could not be hashed and are left out.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub missing_epochs: Vec<String>,
    pub sightings: Vec<Sighting>,
}

/// One flagged cluster as seen in the operator's logs.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Sighting {
    /// `S1`, `S2`, ... in the analysis's cluster order. Not the cluster key,
    /// which is a hash of a record id.
    pub id: String,
    pub tier: Tier,
    /// The cluster's computed agent grade, `L0` to `L4`.
    pub agent_grade: String,
    pub records: usize,
    /// What the hours measure (`request` for an access log).
    pub time_basis: String,
    /// Epochs the hours fall in; each feature is hashed under every one.
    pub epochs: Vec<String>,
    /// Hours (UTC) with at least one record, as `yyyy-mm-ddThhZ`.
    #[serde(default)]
    pub hours: Vec<String>,
    /// Keyed hashes of the features that linked the cluster and of the
    /// secrets it carried.
    #[serde(default)]
    pub features: Vec<KeyedFeature>,
    #[serde(default)]
    pub scaffold: Scaffold,
    /// The operator's hosts the cluster reached, defanged; only when
    /// [`Sightings::shares_hosts`].
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hosts: Vec<String>,
}

/// What a keyed hash is of.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FeatureKind {
    /// A strong linking parameter's value (`uqtag`, `run`).
    Param,
    /// What a `link = true` rule matched: an inbox or topic id, a model tag.
    Rule,
    /// A captured secret, by its `REDACTED-` replacement.
    Secret,
}

impl FeatureKind {
    pub fn id(self) -> &'static str {
        match self {
            Self::Param => "param",
            Self::Rule => "rule",
            Self::Secret => "secret",
        }
    }
}

/// A linking feature as shared: its kind and name in the clear, its value
/// only as a keyed hash.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct KeyedFeature {
    pub kind: FeatureKind,
    /// The parameter name or rule id; empty for a secret.
    #[serde(default)]
    pub name: String,
    pub epoch: String,
    pub hash: String,
}

/// How the cluster's requests were made, none of it identifying a visitor.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Scaffold {
    /// Relay chains, outermost first, ending at `target`.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub relay_stacks: BTreeMap<String, usize>,
    /// Canonical test payload ids (`xss.script_alert`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dialect: Vec<String>,
    /// Hits per rule id.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub rules: BTreeMap<String, usize>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub tactics: BTreeMap<Tactic, usize>,
    /// Header-set fingerprints (a hash of the header names).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub header_sets: Vec<String>,
    /// Members by client network (ASN only).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub asns: BTreeMap<u32, usize>,
}

/// What [`export`] includes.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct ExportOptions {
    /// Include the operator's own host names, defanged. Off unless the
    /// operator asks.
    pub include_hosts: bool,
    /// The weakest cluster tier exported.
    pub min_tier: Tier,
    /// Export only this cluster (an id or key).
    pub cluster: Option<String>,
    /// How the sender describes itself, if at all.
    pub operator: Option<String>,
    /// The day it is made, `yyyy-mm-dd` (the core has no clock).
    pub generated: String,
}

impl Default for ExportOptions {
    fn default() -> Self {
        Self {
            include_hosts: false,
            min_tier: Tier::Suggestive,
            cluster: None,
            operator: None,
            generated: String::new(),
        }
    }
}

/// The sightings document for `a`'s flagged clusters.
pub fn export(a: &Analysis, opts: &ExportOptions, keys: &EpochKeys) -> Sightings {
    let mut missing = BTreeSet::new();
    let sightings = a
        .clusters
        .iter()
        .filter(|c| c.tier >= opts.min_tier.max(Tier::Suggestive))
        .filter(|c| opts.cluster.as_deref().is_none_or(|s| c.matches(s)))
        .take(MAX_CLUSTERS)
        .enumerate()
        .map(|(i, c)| sighting(a, c, i, opts, keys, &mut missing))
        .collect();
    Sightings {
        spec: SPEC.into(),
        generated: opts.generated.clone(),
        rules_version: a.rules_version.clone(),
        operator: opts
            .operator
            .as_deref()
            .map(|s| crate::model::truncate(s.trim(), 120))
            .filter(|s| !s.is_empty()),
        shares_hosts: opts.include_hosts,
        missing_epochs: missing.into_iter().collect(),
        sightings,
    }
}

fn sighting(
    a: &Analysis,
    c: &Cluster,
    i: usize,
    opts: &ExportOptions,
    keys: &EpochKeys,
    missing: &mut BTreeSet<String>,
) -> Sighting {
    let members = || c.members.iter().map(|&m| &a.results[m]);
    let hour_starts: BTreeSet<i64> = members()
        .filter(|r| r.obs.ts > 0)
        .map(|r| r.obs.ts - r.obs.ts.rem_euclid(3600))
        .collect();
    let epochs: BTreeSet<String> = hour_starts.iter().filter_map(|&h| epoch_of(h)).collect();
    let keyed: Vec<&String> = epochs
        .iter()
        .filter(|e| {
            let ok = keys.get(e).is_some();
            if !ok {
                missing.insert((*e).clone());
            }
            ok
        })
        .collect();

    // The raw values, never written out: only their keyed hashes are.
    let mut raw: BTreeSet<(FeatureKind, String, String)> = c
        .link_features
        .iter()
        .map(|f| match f {
            LinkFeature::Param { name, value } => (FeatureKind::Param, name.clone(), value.clone()),
            LinkFeature::Rule { rule, value } => (FeatureKind::Rule, rule.clone(), value.clone()),
        })
        .collect();
    let stock = crate::fleets::stock_secrets();
    let mut secrets = BTreeSet::new();
    for r in members() {
        let o = &r.obs;
        let texts = [o.url.as_str(), o.final_url.as_deref().unwrap_or("")];
        let layers = r.layers.iter().map(|l| l.text.as_str());
        let headers = o.headers.values().map(String::as_str);
        for t in texts.into_iter().chain(layers).chain(headers) {
            crate::fleets::redacted_in(t, &mut secrets);
        }
    }
    for s in secrets.into_iter().filter(|s| !stock.contains(*s)) {
        raw.insert((FeatureKind::Secret, String::new(), s.to_string()));
    }
    let mut features: Vec<KeyedFeature> = raw
        .iter()
        .flat_map(|(kind, name, value)| {
            keyed.iter().filter_map(move |e| {
                Some(KeyedFeature {
                    kind: *kind,
                    name: name.clone(),
                    epoch: (*e).clone(),
                    hash: keys.hash(e, kind.id(), name, value)?,
                })
            })
        })
        .collect();
    features.sort();
    features.truncate(MAX_FEATURES);

    let hours: Vec<String> = hour_starts
        .iter()
        .take(MAX_HOURS)
        .map(|&h| crate::model::fmt_ts(h)[..13].replace(' ', "T") + "Z")
        .collect();
    let basis = serde_json::to_value(c.time_basis)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_default();
    Sighting {
        id: format!("S{}", i + 1),
        tier: c.tier,
        agent_grade: c.agent.level.code().into(),
        records: c.members.len(),
        time_basis: basis,
        epochs: epochs.into_iter().collect(),
        hours,
        features,
        scaffold: Scaffold {
            relay_stacks: c.relay_stacks.clone(),
            dialect: c.dialect.variants.keys().cloned().collect(),
            rules: c.rules.clone(),
            tactics: c.tactics.clone(),
            header_sets: c.header_sets.keys().cloned().collect(),
            asns: c.asns.clone(),
        },
        hosts: if opts.include_hosts {
            c.target_hosts
                .keys()
                .map(|h| crate::extract::defang_host(h))
                .collect()
        } else {
            Vec::new()
        },
    }
}

/// Read a sightings document, checking its spec, its limits and the shape
/// of every hash and epoch. A document that fails is refused whole.
pub fn parse(text: &str) -> Result<Sightings, String> {
    let s: Sightings = serde_json::from_str(text).map_err(|e| format!("sightings: {e}"))?;
    if s.spec != SPEC {
        return Err(format!("sightings: spec is `{}`, not `{SPEC}`", s.spec));
    }
    if s.sightings.len() > MAX_CLUSTERS {
        return Err(format!(
            "sightings: {} clusters, over the limit of {MAX_CLUSTERS}",
            s.sightings.len()
        ));
    }
    for x in &s.sightings {
        if x.features.len() > MAX_FEATURES || x.hours.len() > MAX_HOURS {
            return Err(format!("sightings: {} is over the size limits", x.id));
        }
        for f in &x.features {
            let hex_ok = f.hash.len() == keys::HASH_HEX
                && f.hash
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
            if !hex_ok || !keys::valid_epoch(&f.epoch) {
                return Err(format!(
                    "sightings: {} has a feature whose hash or epoch is malformed",
                    x.id
                ));
            }
        }
        if !x.hosts.is_empty() && !s.shares_hosts {
            return Err(format!(
                "sightings: {} lists hosts but the document does not share hosts",
                x.id
            ));
        }
    }
    Ok(s)
}

#[cfg(test)]
mod tests;
