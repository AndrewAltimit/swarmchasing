//! Endpoint view: flagged activity grouped by target host.
//!
//! Operator notices are about endpoints, not clusters. For each host this says
//! how often it was hit, when, whether attack payloads were sent, which clusters
//! touched it, and whether the hits are ongoing or historical. Core has no
//! clock, so "now" is passed in; with `now = 0` the latest record in the
//! analysis stands in for it.

use crate::analyze::Analysis;
use crate::model::{IndicatorKind, Tier};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// How many record links to keep per endpoint.
const MAX_REFERENCES: usize = 10;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Activity {
    /// Last hit within the active window.
    Ongoing,
    /// Last hit before the active window.
    Historical,
    /// No record has a timestamp.
    Unknown,
}

impl Activity {
    pub fn label(self) -> &'static str {
        match self {
            Activity::Ongoing => "ongoing",
            Activity::Historical => "historical",
            Activity::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointView {
    pub host: String,
    /// Records at or above the minimum tier.
    pub hits: usize,
    /// Every record that targets this host, flagged or not.
    pub records: usize,
    pub max_tier: Tier,
    pub first_seen: i64,
    pub last_seen: i64,
    pub activity: Activity,
    /// True when any hit carried an attack payload (an `exploit` rule).
    pub payloads: bool,
    /// Exploit rules seen, with counts.
    pub payload_rules: BTreeMap<String, usize>,
    /// Every rule seen in the hits, with counts.
    pub rules: BTreeMap<String, usize>,
    /// Cluster IDs that include a hit on this host.
    pub clusters: Vec<String>,
    pub sources: BTreeMap<String, usize>,
    /// Links to the public records behind the first hits.
    pub references: Vec<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct EndpointOptions {
    pub min_tier: Tier,
    /// Unix seconds; 0 = the latest record timestamp in the analysis.
    pub now: i64,
    /// Hits within this many days of `now` count as ongoing.
    pub active_days: i64,
}

impl Default for EndpointOptions {
    fn default() -> Self {
        Self {
            min_tier: Tier::Suggestive,
            now: 0,
            active_days: 7,
        }
    }
}

/// Endpoints hit at or above `opts.min_tier`, most severe first: payloads,
/// then tier, then hit count.
pub fn endpoints(a: &Analysis, opts: &EndpointOptions) -> Vec<EndpointView> {
    let now = if opts.now > 0 {
        opts.now
    } else {
        a.results.iter().map(|r| r.obs.ts).max().unwrap_or(0)
    };
    let mut records: BTreeMap<&str, usize> = BTreeMap::new();
    let mut views: BTreeMap<&str, EndpointView> = BTreeMap::new();
    let mut clusters: BTreeMap<&str, BTreeSet<usize>> = BTreeMap::new();

    let mut order: Vec<usize> = (0..a.results.len()).collect();
    order.sort_by_key(|&i| a.results[i].obs.ts);
    for i in order {
        let r = &a.results[i];
        let Some(host) = r.target_host.as_deref() else {
            continue;
        };
        *records.entry(host).or_default() += 1;
        if r.score <= 0 || r.tier < opts.min_tier {
            continue;
        }
        let v = views.entry(host).or_insert_with(|| EndpointView {
            host: host.to_string(),
            hits: 0,
            records: 0,
            max_tier: r.tier,
            first_seen: 0,
            last_seen: 0,
            activity: Activity::Unknown,
            payloads: false,
            payload_rules: BTreeMap::new(),
            rules: BTreeMap::new(),
            clusters: Vec::new(),
            sources: BTreeMap::new(),
            references: Vec::new(),
        });
        v.hits += 1;
        v.max_tier = v.max_tier.max(r.tier);
        if r.obs.ts > 0 {
            if v.first_seen == 0 {
                v.first_seen = r.obs.ts;
            }
            v.last_seen = v.last_seen.max(r.obs.ts);
        }
        for h in &r.hits {
            *v.rules.entry(h.rule_id.clone()).or_default() += 1;
            if h.kind == IndicatorKind::Exploit {
                v.payloads = true;
                *v.payload_rules.entry(h.rule_id.clone()).or_default() += 1;
            }
        }
        if !r.obs.source.is_empty() {
            *v.sources.entry(r.obs.source.clone()).or_default() += 1;
        }
        if let Some(c) = r.cluster {
            clusters.entry(host).or_default().insert(c);
        }
        if let Some(link) = &r.obs.reference
            && v.references.len() < MAX_REFERENCES
            && !v.references.contains(link)
        {
            v.references.push(link.clone());
        }
    }

    let window = opts.active_days.max(0) * 86_400;
    let mut out: Vec<EndpointView> = views
        .into_iter()
        .map(|(host, mut v)| {
            v.records = records.get(host).copied().unwrap_or(v.hits);
            v.clusters = clusters
                .get(host)
                .map(|cs| cs.iter().map(|&c| a.clusters[c].id.clone()).collect())
                .unwrap_or_default();
            v.activity = if v.last_seen <= 0 || now <= 0 {
                Activity::Unknown
            } else if now - v.last_seen <= window {
                Activity::Ongoing
            } else {
                Activity::Historical
            };
            v
        })
        .collect();
    out.sort_by(|x, y| {
        y.payloads
            .cmp(&x.payloads)
            .then(y.max_tier.cmp(&x.max_tier))
            .then(y.hits.cmp(&x.hits))
            .then(x.host.cmp(&y.host))
    });
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Observation;
    use crate::{Rules, analyze};

    fn o(id: &str, ts: i64, url: &str) -> Observation {
        Observation {
            id: id.into(),
            source: "test".into(),
            ts,
            url: url.into(),
            reference: Some(format!("https://records.example/{id}")),
            ..Default::default()
        }
    }

    const DAY: i64 = 86_400;

    #[test]
    fn groups_hits_by_target_host() {
        let t0 = 1_791_000_000;
        let a = analyze(
            vec![
                o(
                    "1",
                    t0,
                    "https://r.jina.ai/https://old.portal.example/x?State_Id=1%20OR%201=1",
                ),
                o(
                    "2",
                    t0 + 60,
                    "https://r.jina.ai/https://old.portal.example/y?id=2147483648",
                ),
                o(
                    "3",
                    t0 + 30 * DAY,
                    "https://r.jina.ai/https://new.portal.example/p?uqtag=a1b2c3",
                ),
                o("4", t0 + 30 * DAY, "https://new.portal.example/about"),
                o("5", t0 + 30 * DAY, "https://quiet.example/"),
            ],
            &Rules::default_rules(),
        );
        let e = endpoints(&a, &EndpointOptions::default());
        let hosts: Vec<&str> = e.iter().map(|v| v.host.as_str()).collect();
        assert_eq!(hosts, ["old.portal.example", "new.portal.example"]);

        let old = &e[0];
        assert!(old.payloads);
        assert!(old.payload_rules.contains_key("exploit.sqli_boolean"));
        assert_eq!(old.hits, 2);
        assert_eq!(old.first_seen, t0);
        assert_eq!(old.last_seen, t0 + 60);
        assert_eq!(old.activity, Activity::Historical);
        assert_eq!(old.references.len(), 2);

        let new = &e[1];
        assert!(!new.payloads);
        assert_eq!(new.hits, 1);
        assert_eq!(
            new.records, 2,
            "the unflagged visit still counts as a record"
        );
        assert_eq!(new.activity, Activity::Ongoing);
    }

    #[test]
    fn explicit_now_and_unknown_times() {
        let a = analyze(
            vec![o("1", 0, "https://r.jina.ai/https://t.example/?q=1%27")],
            &Rules::default_rules(),
        );
        let e = endpoints(
            &a,
            &EndpointOptions {
                min_tier: Tier::Noise,
                now: 1_791_000_000,
                active_days: 7,
            },
        );
        assert_eq!(e.len(), 1);
        assert_eq!(e[0].activity, Activity::Unknown);
    }
}
