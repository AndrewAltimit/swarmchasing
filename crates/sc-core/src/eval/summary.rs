//! The whole evaluation as one value: what `swarmchase eval --summary-json`
//! writes and the site renders. Pure, so the browser can compute it too.
//!
//! It carries numbers, rule ids, class and tactic names, cluster keys and
//! run ids. It never carries record content (URLs, record ids), so it can be
//! published for any input. The schema is documented in
//! `docs/reference/evaluation.md`; `schema` is bumped on a breaking change.

use super::clusters::ClusterEval;
use super::coverage::{
    AllowList, Coverage, Margins, RuleMeta, UNTAGGED, coverage, margins, rule_meta,
};
use super::stats::Proportion;
use super::units::{self, Calibration, Slice};
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
    /// `tiers` counted per cluster instead of per record ([`units`]).
    #[serde(default)]
    pub cluster_tiers: Vec<TierSummary>,
    /// Every number above the line again, over the records not marked
    /// `synthetic` (reconstructed and collected records).
    #[serde(default)]
    pub non_synthetic: Slice,
    /// One slice per provenance: `synthetic`, `reconstructed`, `collected`.
    #[serde(default)]
    pub by_provenance: Vec<Slice>,
    /// One slice per record source (`manual`, `urlquery`, ...).
    #[serde(default)]
    pub by_source: Vec<Slice>,
    /// One slice per label file, when the caller says which file each label
    /// came from; empty otherwise.
    #[serde(default)]
    pub by_file: Vec<Slice>,
    /// Observed precision per tier and per agent grade.
    #[serde(default)]
    pub calibration: Calibration,
    /// The reviewed benign baseline's false-positive bound and progress;
    /// absent when no label is from a review sample.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub baseline: Option<super::baseline::Baseline>,
    /// How close benign records sit to the suggestive threshold, the false
    /// positives each rule causes, and recall without each rule.
    #[serde(default)]
    pub margins: Margins,
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

impl TierSummary {
    pub fn from_counts(tier: Tier, tp: usize, fp: usize, fn_: usize, tn: usize) -> Self {
        Self {
            tier,
            tp,
            fp,
            fn_,
            tn,
            precision: Proportion::new(tp, tp + fp),
            recall: Proportion::new(tp, tp + fn_),
        }
    }
}

impl From<&Threshold> for TierSummary {
    fn from(t: &Threshold) -> Self {
        Self::from_counts(t.tier, t.tp, t.fp, t.fn_, t.tn)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleSummary {
    pub rule_id: String,
    pub tactics: Vec<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub artifact: bool,
    /// Labelled records it fired on: agent (true positives) and benign.
    pub tp: usize,
    pub fp: usize,
    /// `tp / (tp + fp)`, with its interval.
    pub precision: Proportion,
    pub hard_negatives: usize,
    pub hard_negatives_fired: usize,
    /// Benign records it lifted to suggestive or above: below it without
    /// the rule.
    #[serde(default)]
    pub benign_lifted: usize,
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
    let rules = crate::Rules::from_toml(rules_toml)?;
    let m = margins(a, labels, &rules);
    let s = build(a, labels, &report, &meta, &cov, m);
    Ok((report, cov, s))
}

fn build(
    a: &Analysis,
    labels: &LabelSet,
    report: &EvalReport,
    meta: &[RuleMeta],
    cov: &Coverage,
    margins: Margins,
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
            artifact: c.artifact,
            tp: c.positives,
            fp: c.on_benign,
            precision: Proportion::new(c.positives, c.positives + c.on_benign),
            hard_negatives: c.hard_negatives,
            hard_negatives_fired: c.hard_negatives_fired,
            benign_lifted: margins.lifted.get(&c.rule_id).copied().unwrap_or(0),
            covered: c.positives > 0,
            allowed: c.allowed.clone(),
        })
        .collect();
    let items = units::labelled(a, labels);
    let non_synthetic: Vec<_> = items
        .iter()
        .copied()
        .filter(|(_, l)| !l.synthetic)
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
        cluster_tiers: units::slice(a, &items, "all").cluster_tiers,
        non_synthetic: units::slice(a, &non_synthetic, "non_synthetic"),
        by_provenance: units::breakdown(a, &items, |_, l| Some(l.provenance().to_string())),
        by_source: units::breakdown(a, &items, |i, _| {
            let s = &a.results[i].obs.source;
            Some(if s.is_empty() {
                "unknown".into()
            } else {
                s.clone()
            })
        }),
        by_file: units::breakdown(a, &items, |_, l| l.origin.clone()),
        calibration: units::calibration(a, &items),
        baseline: super::baseline::baseline(a, labels),
        margins,
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
