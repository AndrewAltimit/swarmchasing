//! SC-Bench: a labelled set in a form other groups can score their own
//! detectors against, with this toolkit's scorer.
//!
//! A bench file ([`Bench`], schema `schemas/sc-bench-v1.json`) names each
//! record by id and carries its label, who labelled it, its split, its
//! timestamp kind, where it came from, its defanged target host, and what
//! these rules said at the freeze (`fired_rules`, `tier`, `cluster`). It
//! never carries the record's URL or any other content: a reader obtains the
//! records from their source, under its terms, by id.
//!
//! [`score`] scores predictions (one per record id: a tier, or flagged or
//! not, and optionally a cluster) against the bench labels, per split, with
//! record-unit and cluster-unit counts for all records and for the
//! non-synthetic ones. With no predictions it scores the reference tiers
//! stored in the file.

use super::grades::Actor;
use super::units::{Slice, record_tiers, unit_tiers};
use super::{Label, LabelSet, units};
use crate::analyze::Analysis;
use crate::model::{Tier, TsKind};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};

/// The `format` value of a version 1 bench file.
pub const FORMAT: &str = "sc-bench-v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bench {
    /// Always [`FORMAT`].
    pub format: String,
    pub name: String,
    pub description: String,
    /// The day the labels and splits were frozen (`YYYY-MM-DD`).
    pub freeze_date: String,
    /// The rules that produced the reference fields.
    pub rules_version: String,
    pub rules_sha256: String,
    pub toolkit_version: String,
    pub records: Vec<BenchRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchRecord {
    pub id: String,
    /// The target host, defanged (`a[.]b`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    /// `agent` or `benign`; absent for a record that is graded, not scored.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<Label>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor: Option<Actor>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub class: Option<String>,
    pub labellers: Vec<String>,
    /// `regression` (used to tune), `held_out` or `prospective`.
    pub split: String,
    /// RFC 3339 UTC, absent when unknown.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ts: Option<String>,
    pub ts_kind: TsKind,
    /// The record's source (`urlquery`, `wayback`, `manual`, ...).
    pub source: String,
    /// `synthetic`, `reconstructed` or `collected`.
    pub provenance: String,
    /// Where to obtain the record: a file or dataset name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin: Option<String>,
    /// The true run, for cluster-level scoring.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run: Option<String>,
    /// Reference: rule ids these rules fired on the record.
    pub fired_rules: Vec<String>,
    /// Reference: the record's tier under these rules.
    pub tier: Tier,
    /// Reference: the stable key of the record's cluster.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cluster: Option<String>,
}

/// What the bench header says, given by the caller.
pub struct BenchMeta<'a> {
    pub name: &'a str,
    pub description: &'a str,
    pub freeze_date: &'a str,
    pub rules_sha256: &'a str,
    pub toolkit_version: &'a str,
    /// The split of records not in `held_out`.
    pub split: &'a str,
    /// Ids frozen as held out.
    pub held_out: &'a [String],
    /// Labeller recorded for rows that name none.
    pub default_labeller: &'a str,
}

/// The bench over every labelled or actor-graded record of `a`.
pub fn build(a: &Analysis, labels: &LabelSet, meta: &BenchMeta) -> Bench {
    let mut seen = std::collections::HashSet::new();
    let mut records = Vec::new();
    for r in &a.results {
        let id = r.obs.id.as_str();
        let l = labels.labels.get(id);
        let actor = labels.actors.get(id).copied();
        if (l.is_none() && actor.is_none()) || !seen.insert(id) {
            continue;
        }
        let host = r
            .target_host
            .clone()
            .or_else(|| crate::weburl::WebUrl::parse(&r.obs.url).and_then(|u| u.host))
            .map(|h| crate::extract::defang_host(&h));
        let mut fired: Vec<String> = r.hits.iter().map(|h| h.rule_id.clone()).collect();
        crate::sort::sort(&mut fired);
        fired.dedup();
        let labellers = match l.map(|l| &l.labellers) {
            Some(v) if !v.is_empty() => v.clone(),
            _ => vec![meta.default_labeller.to_string()],
        };
        let ts_kind = if r.obs.ts_kind.is_unknown() {
            TsKind::of_source(&r.obs.source)
        } else {
            r.obs.ts_kind
        };
        records.push(BenchRecord {
            id: id.to_string(),
            host,
            label: l.map(|l| l.label),
            actor,
            class: l.and_then(|l| l.class.clone()),
            labellers,
            split: if meta.held_out.iter().any(|h| h == id) {
                "held_out".into()
            } else {
                meta.split.to_string()
            },
            ts: (r.obs.ts > 0)
                .then(|| chrono::DateTime::<chrono::Utc>::from_timestamp(r.obs.ts, 0))
                .flatten()
                .map(|d| d.format("%Y-%m-%dT%H:%M:%SZ").to_string()),
            ts_kind,
            source: if r.obs.source.is_empty() {
                "unknown".into()
            } else {
                r.obs.source.clone()
            },
            provenance: l
                .map(|l| l.provenance())
                .or_else(|| labels.provenance.get(id).copied())
                .unwrap_or("collected")
                .to_string(),
            origin: l.and_then(|l| l.origin.clone()),
            run: l.and_then(|l| l.run.clone()),
            fired_rules: fired,
            tier: r.tier,
            cluster: r
                .cluster
                .map(|c| super::view::cluster_key(a, c).to_string()),
        });
    }
    crate::sort::by(&mut records, |x, y| x.id.cmp(&y.id));
    Bench {
        format: FORMAT.into(),
        name: meta.name.into(),
        description: meta.description.into(),
        freeze_date: meta.freeze_date.into(),
        rules_version: a.rules_version.clone(),
        rules_sha256: meta.rules_sha256.into(),
        toolkit_version: meta.toolkit_version.into(),
        records,
    }
}

/// Check what the schema cannot express on its own: the format, unique ids,
/// and hosts that are defanged.
pub fn validate(b: &Bench) -> Vec<String> {
    let mut out = Vec::new();
    if b.format != FORMAT {
        out.push(format!("format is `{}`, not `{FORMAT}`", b.format));
    }
    let mut ids = std::collections::HashSet::new();
    for r in &b.records {
        if !ids.insert(r.id.as_str()) {
            out.push(format!("duplicate id {}", r.id));
        }
        if let Some(h) = &r.host
            && h.replace("[.]", "").contains('.')
        {
            out.push(format!("{}: host is not defanged", r.id));
        }
    }
    out
}

/// One detector's output for one record.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Prediction {
    pub id: String,
    /// `noise`, `suggestive` or `significant`.
    #[serde(default)]
    pub tier: Option<Tier>,
    /// A binary detector: flagged counts at both thresholds.
    #[serde(default)]
    pub flagged: Option<bool>,
    /// The detector's group for the record, for cluster-unit scoring.
    #[serde(default)]
    pub cluster: Option<String>,
}

impl Prediction {
    fn tier(&self) -> Tier {
        match (self.tier, self.flagged) {
            (Some(t), _) => t,
            (None, Some(true)) => Tier::Significant,
            _ => Tier::Noise,
        }
    }
}

/// Predictions as NDJSON, one per line, keyed by id. Later lines win.
pub fn parse_predictions(text: &str) -> Result<HashMap<String, Prediction>, String> {
    let mut out = HashMap::new();
    for (n, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let p: Prediction =
            serde_json::from_str(line).map_err(|e| format!("predictions line {}: {e}", n + 1))?;
        if p.tier.is_none() && p.flagged.is_none() {
            return Err(format!(
                "predictions line {}: needs `tier` or `flagged`",
                n + 1
            ));
        }
        out.insert(p.id.clone(), p);
    }
    Ok(out)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchScore {
    pub bench: String,
    pub freeze_date: String,
    /// `reference` (the tiers in the file) or `predictions`.
    pub detector: String,
    /// Labelled records the predictions left out; scored as unflagged.
    pub missing_predictions: usize,
    /// `all` first, then one entry per split.
    pub splits: Vec<SplitScore>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SplitScore {
    pub split: String,
    pub all: Slice,
    pub non_synthetic: Slice,
}

/// Score `preds` (or, when `None`, the reference tiers) against `b`.
pub fn score(b: &Bench, preds: Option<&HashMap<String, Prediction>>) -> BenchScore {
    // (split, synthetic, agent, tier, group)
    type Row<'a> = (&'a str, bool, bool, Tier, Option<String>);
    let mut rows: Vec<Row> = Vec::new();
    let mut missing = 0;
    for r in &b.records {
        let Some(label) = r.label else { continue };
        let (tier, group) = match preds {
            None => (r.tier, r.cluster.clone()),
            Some(p) => match p.get(&r.id) {
                Some(p) => (p.tier(), p.cluster.clone()),
                None => {
                    missing += 1;
                    (Tier::Noise, None)
                }
            },
        };
        rows.push((
            r.split.as_str(),
            r.provenance == "synthetic",
            label == Label::Agent,
            tier,
            group,
        ));
    }
    let slice = |name: &str, keep: &dyn Fn(&Row) -> bool| {
        let sel: Vec<_> = rows.iter().filter(|r| keep(r)).collect();
        let agents = sel.iter().filter(|r| r.2).count();
        Slice {
            name: name.to_string(),
            labelled: sel.len(),
            agents,
            benign: sel.len() - agents,
            tiers: record_tiers(sel.iter().map(|r| (r.2, r.3))),
            cluster_tiers: unit_tiers(sel.iter().map(|r| (r.4.as_deref(), r.2, r.3))),
        }
    };
    let mut splits: BTreeMap<&str, ()> = BTreeMap::new();
    for r in &rows {
        splits.insert(r.0, ());
    }
    let mut out = vec![SplitScore {
        split: "all".into(),
        all: slice("all", &|_| true),
        non_synthetic: slice("non_synthetic", &|r| !r.1),
    }];
    for s in splits.keys() {
        out.push(SplitScore {
            split: s.to_string(),
            all: slice("all", &|r| r.0 == *s),
            non_synthetic: slice("non_synthetic", &|r| r.0 == *s && !r.1),
        });
    }
    BenchScore {
        bench: b.name.clone(),
        freeze_date: b.freeze_date.clone(),
        detector: if preds.is_some() {
            "predictions".into()
        } else {
            "reference".into()
        },
        missing_predictions: missing,
        splits: out,
    }
}

/// The reference tiers in `b` must score as `analysis` did: the same counts
/// as [`units::slice`] over the same records.
pub fn reference_matches(a: &Analysis, labels: &LabelSet, b: &Bench) -> bool {
    let items = units::labelled(a, labels);
    let s = units::slice(a, &items, "all");
    let t = score(b, None);
    serde_json::to_value(&s.tiers).ok() == serde_json::to_value(&t.splits[0].all.tiers).ok()
        && serde_json::to_value(&s.cluster_tiers).ok()
            == serde_json::to_value(&t.splits[0].all.cluster_tiers).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Observation, Rules, analyze, parse_labels};

    #[test]
    fn export_then_score_reproduces_the_eval() {
        let obs = |id: &str, ts: i64, url: &str| Observation {
            id: id.into(),
            source: "manual".into(),
            ts,
            url: url.into(),
            ..Default::default()
        };
        let a = analyze(
            vec![
                obs(
                    "a1",
                    1000,
                    "https://r.jina.ai/https://t.example/x?uqtag=aa11",
                ),
                obs(
                    "a2",
                    1100,
                    "https://r.jina.ai/https://t.example/y?uqtag=aa11",
                ),
                obs("b1", 0, "https://www.example.com/"),
                obs("g1", 0, "https://p.example/?q=1%20OR%201=1"),
            ],
            &Rules::default_rules(),
        );
        let labels = parse_labels(
            "{\"id\":\"a1\",\"label\":\"agent\",\"synthetic\":true}\n\
             {\"id\":\"a2\",\"label\":\"agent\",\"labeller\":\"ann\"}\n\
             {\"id\":\"b1\",\"label\":\"benign\"}\n\
             {\"id\":\"g1\",\"actor\":\"human\"}\n",
        );
        let held = vec!["b1".to_string()];
        let b = build(
            &a,
            &labels,
            &BenchMeta {
                name: "t",
                description: "d",
                freeze_date: "2026-01-01",
                rules_sha256: "x",
                toolkit_version: "0",
                split: "regression",
                held_out: &held,
                default_labeller: "maintainers",
            },
        );
        assert!(validate(&b).is_empty(), "{:?}", validate(&b));
        assert_eq!(b.records.len(), 4);
        let json = serde_json::to_string(&b).unwrap();
        assert!(
            !json.contains("https://") && !json.contains("uqtag"),
            "{json}"
        );
        let a2 = b.records.iter().find(|r| r.id == "a2").unwrap();
        assert_eq!(a2.labellers, ["ann"]);
        assert_eq!(a2.host.as_deref(), Some("t[.]example"));
        assert_eq!(b.records.iter().find(|r| r.id == "g1").unwrap().label, None);
        assert!(reference_matches(&a, &labels, &b));

        let s = score(&b, None);
        assert_eq!(s.splits[0].all.labelled, 3);
        assert_eq!(s.splits[0].non_synthetic.labelled, 2);
        assert_eq!(s.splits.len(), 3, "all, held_out, regression");

        // A detector that flags everything, with no clusters.
        let preds = parse_predictions(
            "{\"id\":\"a1\",\"flagged\":true}\n{\"id\":\"b1\",\"tier\":\"significant\"}\n",
        )
        .unwrap();
        let s = score(&b, Some(&preds));
        assert_eq!(s.missing_predictions, 1);
        let sig = &s.splits[0].all.tiers[1];
        assert_eq!((sig.tp, sig.fp, sig.fn_), (1, 1, 1));
        assert!(parse_predictions("{\"id\":\"x\"}").is_err());
    }
}
