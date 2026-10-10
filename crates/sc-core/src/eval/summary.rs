//! The whole evaluation as one value: what `swarmchase eval --summary-json`
//! writes and the site renders. Pure, so the browser can compute it too.
//!
//! It carries numbers, rule ids, class and tactic names, cluster keys and
//! run ids. It never carries record content (URLs, record ids), so it can be
//! published for any input. The schema is documented in
//! `docs/reference/evaluation.md`; `schema` is bumped on a breaking change.

use super::clusters::ClusterEval;
use super::coverage::{AllowList, Coverage, RuleMeta, UNTAGGED, coverage, rule_meta};
use super::stats::Proportion;
use super::{EvalReport, Label, LabelSet, Threshold, evaluate};
use crate::analyze::Analysis;
use crate::model::Tier;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashSet};

pub const SCHEMA: u32 = 1;

/// Tactic group for agent records no rule fired on.
pub const NO_RULE: &str = "no_rule_fired";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Summary {
    pub schema: u32,
    pub rules_version: String,
    pub labelled: usize,
    pub agents: usize,
    pub benign: usize,
    pub unlabelled: usize,
    pub missing_records: usize,
    pub tiers: Vec<TierSummary>,
    pub rules: Vec<RuleSummary>,
    pub coverage: CoverageTotals,
    pub agent_classes: Vec<RecallRow>,
    pub benign_classes: Vec<BenignRow>,
    pub tactics: Vec<RecallRow>,
    pub clusters: ClusterEval,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TierSummary {
    /// Records at this tier or above count as flagged.
    pub tier: Tier,
    pub tp: usize,
    pub fp: usize,
    #[serde(rename = "fn")]
    pub fn_: usize,
    pub tn: usize,
    pub precision: Proportion,
    pub recall: Proportion,
}

impl From<&Threshold> for TierSummary {
    fn from(t: &Threshold) -> Self {
        Self {
            tier: t.tier,
            tp: t.tp,
            fp: t.fp,
            fn_: t.fn_,
            tn: t.tn,
            precision: Proportion::new(t.tp, t.tp + t.fp),
            recall: Proportion::new(t.tp, t.tp + t.fn_),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleSummary {
    pub rule_id: String,
    pub tactics: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact: Option<String>,
    /// Labelled records it fired on: agent (true positives) and benign.
    pub tp: usize,
    pub fp: usize,
    /// `tp / (tp + fp)`, with its interval.
    pub precision: Proportion,
    pub hard_negatives: usize,
    pub hard_negatives_fired: usize,
    /// Has at least one positive.
    pub covered: bool,
    /// Allow-list reason for going without one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CoverageTotals {
    pub rules: usize,
    pub covered: usize,
    pub allowed: usize,
    pub uncovered: Vec<String>,
    pub with_hard_negatives: usize,
    pub unknown_hard_negative_ids: Vec<String>,
}

/// Recall over agent records of one class or tactic.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecallRow {
    pub name: String,
    pub n: usize,
    /// Suggestive or above.
    pub suggestive: Proportion,
    pub significant: Proportion,
}

/// False-positive rate over benign records of one class.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenignRow {
    pub name: String,
    pub n: usize,
    /// Flagged suggestive or above (false positives).
    pub suggestive: Proportion,
    pub significant: Proportion,
}

/// Evaluate and summarise. `rules_toml` is the rules file the analysis ran
/// with (for the rule list, tactics and artifacts); `allow` is the coverage
/// allow-list text (empty when there is none).
pub fn summarize(
    a: &Analysis,
    labels: &LabelSet,
    rules_toml: &str,
    allow: &str,
) -> Result<(EvalReport, Coverage, Summary), String> {
    let report = evaluate(a, labels);
    let meta = rule_meta(rules_toml)?;
    let cov = coverage(&report, &meta, &AllowList::parse(allow));
    let s = build(a, labels, &report, &meta, &cov);
    Ok((report, cov, s))
}

fn build(
    a: &Analysis,
    labels: &LabelSet,
    report: &EvalReport,
    meta: &[RuleMeta],
    cov: &Coverage,
) -> Summary {
    let tactic_of: BTreeMap<&str, &[String]> = meta
        .iter()
        .map(|m| (m.id.as_str(), m.tactics.as_slice()))
        .collect();
    // Per tactic: (n, suggestive or above, significant).
    let mut tactics: BTreeMap<String, (usize, usize, usize)> = BTreeMap::new();
    let mut seen = HashSet::new();
    for r in &a.results {
        let Some(l) = labels.labels.get(&r.obs.id) else {
            continue;
        };
        if !seen.insert(r.obs.id.as_str()) || l.label != Label::Agent {
            continue;
        }
        let mut ts: BTreeSet<&str> = BTreeSet::new();
        for h in &r.hits {
            match tactic_of.get(h.rule_id.as_str()) {
                Some(t) => ts.extend(t.iter().map(String::as_str)),
                None => {
                    ts.insert(UNTAGGED);
                }
            }
        }
        if ts.is_empty() {
            ts.insert(NO_RULE);
        }
        for t in ts {
            let e = tactics.entry(t.to_string()).or_default();
            e.0 += 1;
            e.1 += usize::from(r.tier >= Tier::Suggestive);
            e.2 += usize::from(r.tier == Tier::Significant);
        }
    }
    let rules = cov
        .rules
        .iter()
        .map(|c| RuleSummary {
            rule_id: c.rule_id.clone(),
            tactics: c.tactics.clone(),
            artifact: c.artifact.clone(),
            tp: c.positives,
            fp: c.on_benign,
            precision: Proportion::new(c.positives, c.positives + c.on_benign),
            hard_negatives: c.hard_negatives,
            hard_negatives_fired: c.hard_negatives_fired,
            covered: c.positives > 0,
            allowed: c.allowed.clone(),
        })
        .collect();
    Summary {
        schema: SCHEMA,
        rules_version: report.rules_version.clone(),
        labelled: report.labelled,
        agents: report.agents,
        benign: report.benign,
        unlabelled: report.unlabelled,
        missing_records: report.missing_records,
        tiers: report.thresholds.iter().map(TierSummary::from).collect(),
        rules,
        coverage: CoverageTotals {
            rules: cov.rules.len(),
            covered: cov.covered,
            allowed: cov.allowed,
            uncovered: cov.uncovered.clone(),
            with_hard_negatives: cov.with_hard_negatives,
            unknown_hard_negative_ids: cov.unknown_hard_negative_ids.clone(),
        },
        agent_classes: report
            .classes
            .iter()
            .map(|c| RecallRow {
                name: c.class.clone(),
                n: c.agents,
                suggestive: Proportion::new(c.suggestive_or_above, c.agents),
                significant: Proportion::new(c.significant, c.agents),
            })
            .collect(),
        benign_classes: report
            .benign_classes
            .iter()
            .map(|c| BenignRow {
                name: c.class.clone(),
                n: c.benign,
                suggestive: Proportion::new(c.suggestive_or_above, c.benign),
                significant: Proportion::new(c.significant, c.benign),
            })
            .collect(),
        tactics: tactics
            .into_iter()
            .map(|(name, (n, sug, sig))| RecallRow {
                name,
                n,
                suggestive: Proportion::new(sug, n),
                significant: Proportion::new(sig, n),
            })
            .collect(),
        clusters: report.clusters.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Observation, Rules, analyze, parse_labels};

    #[test]
    fn summary_has_no_record_content() {
        let obs = vec![
            Observation {
                id: "x:secret-id".into(),
                url: "https://r.jina.ai/https://data.example.gov/api?State_Id=1%20OR%201=1".into(),
                ..Default::default()
            },
            Observation {
                id: "x:2".into(),
                url: "https://r.jina.ai/https://blog.example.com/post".into(),
                ..Default::default()
            },
        ];
        let a = analyze(obs, &Rules::default_rules());
        let labels = parse_labels(
            "{\"id\":\"x:secret-id\",\"label\":\"agent\",\"class\":\"exploit\"}\n\
             {\"id\":\"x:2\",\"label\":\"benign\",\"class\":\"relay_reading\",\"hard_negative_for\":[\"relay.jina\",\"no.such\"]}\n",
        );
        let (_, cov, s) = summarize(
            &a,
            &labels,
            crate::DEFAULT_RULES,
            "exfil.ntfy no record yet\n",
        )
        .unwrap();
        let json = serde_json::to_string(&s).unwrap();
        assert!(
            !json.contains("secret-id") && !json.contains("example.gov"),
            "{json}"
        );
        assert_eq!(s.tiers.len(), 2);
        assert_eq!(s.tiers[1].precision.k, 1);
        let jina = s.rules.iter().find(|r| r.rule_id == "relay.jina").unwrap();
        assert_eq!(
            (
                jina.tp,
                jina.fp,
                jina.hard_negatives,
                jina.hard_negatives_fired
            ),
            (1, 1, 1, 1)
        );
        assert_eq!(cov.unknown_hard_negative_ids, ["no.such"]);
        assert!(
            s.coverage
                .uncovered
                .contains(&"exfil.webhook_site".to_string())
        );
        assert!(!s.coverage.uncovered.contains(&"exfil.ntfy".to_string()));
        assert_eq!(s.benign_classes[0].name, "relay_reading");
        assert!(s.tactics.iter().any(|t| t.n == 1));
    }
}
