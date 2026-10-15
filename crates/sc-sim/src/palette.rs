//! The records the generator copies from.
//!
//! The simulator writes no request content of its own. Every URL it emits is
//! a committed, labelled record from `samples/eval` with only its target host,
//! its identifiers and a cache-busting parameter changed; what it simulates is
//! who sends the records, when, from where and in what order. A template is
//! kept only when its target host appears in its URL as written, so the
//! rewrite reaches the host the analysis reads.

use sc_core::{IndicatorKind, LinkFeature, Observation, Rules, extract};
use std::collections::BTreeMap;

/// The committed labelled files the default palette reads.
pub const DEFAULT_SOURCES: &[(&str, &str)] = &[
    (
        "published-patterns",
        include_str!("../../../samples/eval/published-patterns.ndjson"),
    ),
    (
        "llm-residue",
        include_str!("../../../samples/eval/llm-residue.ndjson"),
    ),
    (
        "rule-coverage",
        include_str!("../../../samples/eval/rule-coverage.ndjson"),
    ),
    (
        "actor-controls",
        include_str!("../../../samples/eval/actor-controls.ndjson"),
    ),
    (
        "carrier-negatives",
        include_str!("../../../samples/eval/carrier-negatives.ndjson"),
    ),
    (
        "linking-negatives",
        include_str!("../../../samples/eval/linking-negatives.ndjson"),
    ),
    (
        "cross-service",
        include_str!("../../../samples/eval/cross-service.ndjson"),
    ),
];

/// What a template is good for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Use {
    /// An agent record with an attack payload (an `exploit` hit).
    Attack,
    /// An agent record with no attack payload: reading, residue, tags.
    Read,
    /// An agent record that names a linking callback inbox (`exfil.*`).
    Sink,
    /// A benign record.
    Benign,
    /// A record a person sent (`actor = human`, no label).
    Human,
    /// A record a conventional tool sent (`actor = tool`, no label).
    Tool,
}

#[derive(Debug, Clone)]
pub struct Template {
    /// Source file and record id, for the `cite` of what is generated.
    pub origin: String,
    pub obs: Observation,
    /// The target host as written in the URL.
    pub host: String,
    /// Benign class, or the agent class.
    pub class: String,
    /// The identifiers to rewrite: linking feature values as they appear.
    pub features: Vec<LinkFeature>,
    /// A rule fires on it as written.
    pub flagged: bool,
    /// Its playbook step ([`sc_core::playbook::step`]) for an attack
    /// template: what a playbook's order is read on, so two templates of
    /// one step are one step in an order.
    pub step: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct Palette {
    pub by_use: BTreeMap<Use, Vec<Template>>,
}

impl Palette {
    /// The palette over the committed evaluation files.
    pub fn default_palette(rules: &Rules) -> Self {
        Self::from_sources(DEFAULT_SOURCES, rules)
    }

    /// A palette over labelled NDJSON texts, each with a name.
    pub fn from_sources(sources: &[(&str, &str)], rules: &Rules) -> Self {
        let mut p = Self::default();
        for (name, text) in sources {
            for line in text.lines() {
                let Ok(v) = serde_json::from_str::<serde_json::Value>(line.trim()) else {
                    continue;
                };
                let Ok(mut obs) = serde_json::from_value::<Observation>(v.clone()) else {
                    continue;
                };
                // Secrets become their `REDACTED-` form here, so the generator
                // can give each run its own (see `generate::rewrite`).
                sc_core::redact_observation(&mut obs);
                let s = |k: &str| v.get(k).and_then(|x| x.as_str()).unwrap_or("").to_string();
                p.add(name, obs, &s("label"), &s("actor"), &s("class"), rules);
            }
        }
        p
    }

    fn add(
        &mut self,
        file: &str,
        obs: Observation,
        label: &str,
        actor: &str,
        class: &str,
        rules: &Rules,
    ) {
        if !obs.url.starts_with("http") || obs.url.contains("translate.goog") {
            return;
        }
        let ex = extract(&obs, rules);
        let Some(host) = ex.target_host.clone() else {
            return;
        };
        if !obs
            .url
            .to_ascii_lowercase()
            .contains(&host.to_ascii_lowercase())
        {
            return;
        }
        let kinds: Vec<IndicatorKind> = ex.hits.iter().map(|h| h.kind).collect();
        let sink = ex
            .features
            .iter()
            .any(|f| matches!(f, LinkFeature::Rule { rule, .. } if rule.starts_with("exfil.")));
        let usage = match (label, actor) {
            ("agent", _) if kinds.contains(&IndicatorKind::Exploit) => Use::Attack,
            ("agent", _) if sink => Use::Sink,
            ("agent", _) if !ex.hits.is_empty() => Use::Read,
            ("benign", _) => Use::Benign,
            ("", "human") => Use::Human,
            ("", "tool" | "scanner") => Use::Tool,
            _ => return,
        };
        let step = (usage == Use::Attack)
            .then(|| {
                let a = sc_core::analyze(vec![obs.clone()], rules);
                a.results
                    .first()
                    .and_then(|r| sc_core::playbook::step(r, 0))
                    .map(|s| s.0)
            })
            .flatten();
        self.by_use.entry(usage).or_default().push(Template {
            origin: format!("{file}/{}", obs.id),
            step,
            host,
            class: class.to_string(),
            flagged: !ex.hits.is_empty(),
            features: ex.features,
            obs,
        });
    }

    pub fn get(&self, u: Use) -> &[Template] {
        self.by_use.get(&u).map_or(&[], Vec::as_slice)
    }

    /// Benign templates of one class that a rule fires on: the benign
    /// content the timing and linking detectors can see. All of the class
    /// when none is flagged.
    pub fn benign_flagged(&self, class: &str) -> Vec<&Template> {
        let all = self.benign(class);
        let flagged: Vec<&Template> = all.iter().copied().filter(|t| t.flagged).collect();
        if flagged.is_empty() { all } else { flagged }
    }

    /// Benign templates of one class, or all benign ones when the class has
    /// none.
    pub fn benign(&self, class: &str) -> Vec<&Template> {
        let all = self.get(Use::Benign);
        let of: Vec<&Template> = all.iter().filter(|t| t.class == class).collect();
        if of.is_empty() {
            all.iter().collect()
        } else {
            of
        }
    }
}
