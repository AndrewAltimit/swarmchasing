//! Measure the rules against labelled records.
//!
//! With no embargo, a false positive is published the moment the admin acts on
//! it, so precision is the number that matters most. [`evaluate`] scores an
//! [`Analysis`] against labels and reports, at each tier threshold, how many
//! flagged records were really agent activity (precision) and how much of the
//! labelled agent activity was flagged (recall). It also reports precision per
//! rule, so a noisy rule can be found and down-weighted, and recall per label
//! class, so a class the rules cannot see from one record (for example a plain
//! request to a data source, which Transluce judged from context) does not drag
//! down a single averaged number unnoticed.
//!
//! Labels come from [`parse_labels`], which reads either:
//! - NDJSON with `id` and `label` per line (`agent` / `benign`, or a source's own
//!   vocabulary: `significant` / `suggestive` count as agent with that reference
//!   tier, `background` as benign), plus optional `class`; or
//! - CSV with a header naming `id` or `report_id`, and `label`, or Transluce's
//!   `disposition` + `confidence` (+ `broad_class`). A bare urlquery report ID is
//!   prefixed `urlquery:` to match collected records. `review_required` rows are
//!   skipped: they are unlabelled.
//!
//! Beyond the label, a record may carry `run` (its true run, for the
//! cluster-level evaluation in [`clusters`]) and, when benign,
//! `hard_negative_for` (the rule ids it was written to resemble, for
//! [`coverage`]). Benign records' `class` says what kind of ordinary traffic
//! they are (`relay_reading`, `api_client`, `crawler`, ...), so false
//! positives are reported per benign class.
//!
//! Submodules: [`stats`] (Wilson intervals, Cohen's κ), [`clusters`],
//! [`coverage`], [`split`] (frozen held-out splits) and [`summary`] (the
//! whole evaluation as one JSON-ready value, for the CLI and the site).

pub mod clusters;
pub mod coverage;
pub mod split;
pub mod stats;
pub mod summary;

use crate::analyze::Analysis;
use crate::model::Tier;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Label {
    Agent,
    Benign,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Labelled {
    pub label: Label,
    /// The labeller's own confidence, when it gave one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ref_tier: Option<Tier>,
    /// Kind of activity (e.g. Transluce's `broad_class`), for per-class recall.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub class: Option<String>,
    /// Where the label came from (an article, a dataset), kept for the record.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cite: Option<String>,
    /// The true run the record belongs to, for cluster-level evaluation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run: Option<String>,
    /// For a benign record: the rules it was written to resemble.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hard_negative_for: Vec<String>,
}

#[derive(Debug, Default)]
pub struct LabelSet {
    pub labels: HashMap<String, Labelled>,
    /// Rows with no usable label (e.g. `review_required`), skipped.
    pub skipped: usize,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Threshold {
    /// Records at this tier or above count as flagged.
    pub tier: Tier,
    pub tp: usize,
    pub fp: usize,
    #[serde(rename = "fn")]
    pub fn_: usize,
    pub tn: usize,
    /// `None` when nothing was flagged at this threshold.
    pub precision: Option<f64>,
    pub recall: Option<f64>,
    /// 95% Wilson interval `[lo, hi]` for precision, `None` when undefined.
    #[serde(default)]
    pub precision_ci: Option<(f64, f64)>,
    #[serde(default)]
    pub recall_ci: Option<(f64, f64)>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleStat {
    pub rule_id: String,
    pub on_agent: usize,
    pub on_benign: usize,
    pub precision: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClassStat {
    pub class: String,
    pub agents: usize,
    pub suggestive_or_above: usize,
    pub significant: usize,
}

/// False positives among benign records of one class.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenignClassStat {
    pub class: String,
    pub benign: usize,
    /// Flagged suggestive or above.
    pub suggestive_or_above: usize,
    pub significant: usize,
}

/// Benign records naming a rule in `hard_negative_for`, and how many of
/// them the rule fired on.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HardNegative {
    pub records: usize,
    pub fired: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Miss {
    pub id: String,
    pub label: Label,
    pub tier: Tier,
    pub score: i32,
    pub rules: Vec<String>,
    /// The submitted URL, defanged.
    pub url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvalReport {
    pub rules_version: String,
    /// Records in the analysis that had a label.
    pub labelled: usize,
    /// Records in the analysis with no label (not scored).
    pub unlabelled: usize,
    /// Labels with no matching record (e.g. reports not fetched yet).
    pub missing_records: usize,
    pub agents: usize,
    pub benign: usize,
    pub thresholds: Vec<Threshold>,
    pub rules: Vec<RuleStat>,
    pub classes: Vec<ClassStat>,
    /// False positives per benign class (`unclassed` when none given).
    #[serde(default)]
    pub benign_classes: Vec<BenignClassStat>,
    /// Rule id -> its hard negatives.
    #[serde(default)]
    pub hard_negatives: BTreeMap<String, HardNegative>,
    /// Linking against labelled runs (report only).
    #[serde(default)]
    pub clusters: clusters::ClusterEval,
    /// Labeller's tier → our tier → count, for labels that carry a tier.
    pub agreement: BTreeMap<String, BTreeMap<String, usize>>,
    /// Benign records we flagged, strongest first.
    pub false_positives: Vec<Miss>,
}

fn ratio(n: usize, d: usize) -> Option<f64> {
    (d > 0).then(|| n as f64 / d as f64)
}

pub fn evaluate(a: &Analysis, labels: &LabelSet) -> EvalReport {
    let mut matched = 0;
    let mut unlabelled = 0;
    let mut seen = std::collections::HashSet::new();
    let mut agents = 0;
    let mut benign = 0;
    let mut thresholds: Vec<Threshold> = [Tier::Suggestive, Tier::Significant]
        .into_iter()
        .map(|tier| Threshold {
            tier,
            tp: 0,
            fp: 0,
            fn_: 0,
            tn: 0,
            precision: None,
            recall: None,
            precision_ci: None,
            recall_ci: None,
        })
        .collect();
    let mut rules: BTreeMap<String, (usize, usize)> = BTreeMap::new();
    let mut classes: BTreeMap<String, ClassStat> = BTreeMap::new();
    let mut benign_classes: BTreeMap<String, BenignClassStat> = BTreeMap::new();
    let mut hard_negatives: BTreeMap<String, HardNegative> = BTreeMap::new();
    let mut agreement: BTreeMap<String, BTreeMap<String, usize>> = BTreeMap::new();
    let mut fps = Vec::new();

    for r in &a.results {
        let Some(l) = labels.labels.get(&r.obs.id) else {
            unlabelled += 1;
            continue;
        };
        // A record collected twice is scored once.
        if !seen.insert(r.obs.id.as_str()) {
            continue;
        }
        matched += 1;
        let is_agent = l.label == Label::Agent;
        if is_agent {
            agents += 1;
        } else {
            benign += 1;
        }
        for t in &mut thresholds {
            match (r.tier >= t.tier, is_agent) {
                (true, true) => t.tp += 1,
                (true, false) => t.fp += 1,
                (false, true) => t.fn_ += 1,
                (false, false) => t.tn += 1,
            }
        }
        let mut ids: Vec<&str> = r.hits.iter().map(|h| h.rule_id.as_str()).collect();
        ids.sort_unstable();
        ids.dedup();
        for id in &ids {
            let e = rules.entry((*id).to_string()).or_default();
            if is_agent {
                e.0 += 1;
            } else {
                e.1 += 1;
            }
        }
        if is_agent {
            let class = l.class.clone().unwrap_or_else(|| "unclassed".into());
            let c = classes.entry(class.clone()).or_insert(ClassStat {
                class,
                agents: 0,
                suggestive_or_above: 0,
                significant: 0,
            });
            c.agents += 1;
            c.suggestive_or_above += usize::from(r.tier >= Tier::Suggestive);
            c.significant += usize::from(r.tier == Tier::Significant);
        } else {
            let class = l.class.clone().unwrap_or_else(|| "unclassed".into());
            let c = benign_classes
                .entry(class.clone())
                .or_insert(BenignClassStat {
                    class,
                    benign: 0,
                    suggestive_or_above: 0,
                    significant: 0,
                });
            c.benign += 1;
            c.suggestive_or_above += usize::from(r.tier >= Tier::Suggestive);
            c.significant += usize::from(r.tier == Tier::Significant);
            for rule in &l.hard_negative_for {
                let h = hard_negatives.entry(rule.clone()).or_default();
                h.records += 1;
                h.fired += usize::from(ids.contains(&rule.as_str()));
            }
        }
        if !is_agent && r.tier >= Tier::Suggestive {
            fps.push(Miss {
                id: r.obs.id.clone(),
                label: l.label,
                tier: r.tier,
                score: r.score,
                rules: ids.iter().map(|s| s.to_string()).collect(),
                url: crate::extract::defang(&r.obs.url),
            });
        }
        if let Some(rt) = l.ref_tier {
            *agreement
                .entry(rt.label().to_string())
                .or_default()
                .entry(r.tier.label().to_string())
                .or_default() += 1;
        }
    }
    for t in &mut thresholds {
        t.precision = ratio(t.tp, t.tp + t.fp);
        t.recall = ratio(t.tp, t.tp + t.fn_);
        t.precision_ci = stats::wilson(t.tp, t.tp + t.fp);
        t.recall_ci = stats::wilson(t.tp, t.tp + t.fn_);
    }
    fps.sort_by(|x, y| y.tier.cmp(&x.tier).then(y.score.cmp(&x.score)));
    let missing_records = labels
        .labels
        .keys()
        .filter(|k| !seen.contains(k.as_str()))
        .count();
    let mut rules: Vec<RuleStat> = rules
        .into_iter()
        .map(|(rule_id, (on_agent, on_benign))| RuleStat {
            precision: ratio(on_agent, on_agent + on_benign),
            rule_id,
            on_agent,
            on_benign,
        })
        .collect();
    rules.sort_by(|x, y| {
        (y.on_agent + y.on_benign)
            .cmp(&(x.on_agent + x.on_benign))
            .then_with(|| x.rule_id.cmp(&y.rule_id))
    });
    EvalReport {
        rules_version: a.rules_version.clone(),
        labelled: matched,
        unlabelled,
        missing_records,
        agents,
        benign,
        thresholds,
        rules,
        classes: classes.into_values().collect(),
        benign_classes: benign_classes.into_values().collect(),
        hard_negatives,
        clusters: clusters::cluster_eval(a, labels),
        agreement,
        false_positives: fps,
    }
}

impl EvalReport {
    pub fn threshold(&self, tier: Tier) -> Option<&Threshold> {
        self.thresholds.iter().find(|t| t.tier == tier)
    }
}

/// Map a label word to (label, labeller's tier). `None` = no usable label.
fn label_word(word: &str) -> Option<(Label, Option<Tier>)> {
    match word.trim().to_ascii_lowercase().as_str() {
        "agent" | "positive" | "true" | "1" => Some((Label::Agent, None)),
        "significant" => Some((Label::Agent, Some(Tier::Significant))),
        "suggestive" => Some((Label::Agent, Some(Tier::Suggestive))),
        "benign" | "background" | "negative" | "false" | "0" => Some((Label::Benign, None)),
        _ => None,
    }
}

fn qualify(id: &str) -> String {
    let id = id.trim();
    if id.contains(':') {
        id.to_string()
    } else {
        format!("{}:{id}", crate::urlquery::SOURCE)
    }
}

/// Read labels from NDJSON or CSV (see the module docs).
pub fn parse_labels(text: &str) -> LabelSet {
    let text = text.trim_start_matches('\u{feff}');
    let first = text.trim_start();
    if first.starts_with('{') {
        parse_ndjson_labels(text)
    } else {
        parse_csv_labels(text)
    }
}

fn parse_ndjson_labels(text: &str) -> LabelSet {
    let mut out = LabelSet::default();
    for (n, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let v: serde_json::Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(e) => {
                out.warnings.push(format!("line {}: {e}", n + 1));
                continue;
            }
        };
        let s = |k: &str| v.get(k).and_then(|x| x.as_str()).map(str::to_string);
        let (Some(id), Some(word)) = (s("id"), s("label")) else {
            out.skipped += 1;
            continue;
        };
        let Some((label, ref_tier)) = label_word(&word) else {
            out.skipped += 1;
            continue;
        };
        out.labels.insert(
            id,
            Labelled {
                label,
                ref_tier,
                class: s("class"),
                cite: s("cite"),
                run: s("run"),
                hard_negative_for: v
                    .get("hard_negative_for")
                    .and_then(|x| x.as_array())
                    .map(|a| {
                        a.iter()
                            .filter_map(|x| x.as_str().map(str::to_string))
                            .collect()
                    })
                    .unwrap_or_default(),
            },
        );
    }
    out
}

fn parse_csv_labels(text: &str) -> LabelSet {
    let mut out = LabelSet::default();
    let rows = parse_csv(text);
    let Some((header, rows)) = rows.split_first() else {
        return out;
    };
    let col = |names: &[&str]| {
        header
            .iter()
            .position(|h| names.contains(&h.trim().to_ascii_lowercase().as_str()))
    };
    let Some(id_col) = col(&["id", "report_id"]) else {
        out.warnings
            .push("CSV has no id or report_id column".into());
        return out;
    };
    let label_col = col(&["label"]);
    let disp_col = col(&["disposition"]);
    let conf_col = col(&["confidence"]);
    let class_col = col(&["class", "broad_class"]);
    let cite_col = col(&["cite", "report_url"]);
    let run_col = col(&["run"]);
    if label_col.is_none() && disp_col.is_none() {
        out.warnings
            .push("CSV has neither a label nor a disposition column".into());
        return out;
    }
    for row in rows {
        let get = |c: Option<usize>| c.and_then(|i| row.get(i)).map(|s| s.trim());
        let Some(id) = get(Some(id_col)).filter(|s| !s.is_empty()) else {
            continue;
        };
        let parsed = match (get(label_col), get(disp_col)) {
            (Some(l), _) if !l.is_empty() => label_word(l),
            (_, Some("included")) => get(conf_col)
                .and_then(label_word)
                .or(Some((Label::Agent, None))),
            (_, Some("background")) => Some((Label::Benign, None)),
            _ => None,
        };
        let Some((label, ref_tier)) = parsed else {
            out.skipped += 1;
            continue;
        };
        out.labels.insert(
            qualify(id),
            Labelled {
                label,
                ref_tier,
                class: get(class_col).filter(|s| !s.is_empty()).map(str::to_string),
                cite: get(cite_col).filter(|s| !s.is_empty()).map(str::to_string),
                run: get(run_col).filter(|s| !s.is_empty()).map(str::to_string),
                hard_negative_for: Vec::new(),
            },
        );
    }
    out
}

/// Minimal RFC 4180 reader: quoted fields, doubled quotes, newlines in quotes.
fn parse_csv(text: &str) -> Vec<Vec<String>> {
    let mut rows = Vec::new();
    let mut row = Vec::new();
    let mut field = String::new();
    let mut quoted = false;
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        match (quoted, c) {
            (true, '"') if chars.peek() == Some(&'"') => {
                field.push('"');
                chars.next();
            }
            (true, '"') => quoted = false,
            (true, c) => field.push(c),
            (false, '"') if field.is_empty() => quoted = true,
            (false, ',') => row.push(std::mem::take(&mut field)),
            (false, '\r') => {}
            (false, '\n') => {
                row.push(std::mem::take(&mut field));
                rows.push(std::mem::take(&mut row));
            }
            (false, c) => field.push(c),
        }
    }
    if !field.is_empty() || !row.is_empty() {
        row.push(field);
        rows.push(row);
    }
    rows.retain(|r| !(r.len() == 1 && r[0].is_empty()));
    rows
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Observation, Rules, analyze};

    fn obs(id: &str, url: &str) -> Observation {
        Observation {
            id: id.into(),
            url: url.into(),
            ..Default::default()
        }
    }

    #[test]
    fn transluce_style_csv() {
        let csv = "report_id,report_url,report_date_utc,timestamp_precision,disposition,confidence,broad_class,why_included,caveat\n\
            a1,https://urlquery.net/report/a1,2026-03-06T20:01:26Z,second,included,significant,custom_program,\"Program, with a comma\",x\n\
            a2,https://urlquery.net/report/a2,2026-03-06T20:01:27Z,second,included,suggestive,indirection,\"Said \"\"Jina\"\"\nover two lines\",x\n\
            a3,u,t,second,background,,source_request,y,x\n\
            a4,u,t,second,review_required,,source_request,y,x\n";
        let l = parse_labels(csv);
        assert_eq!(l.labels.len(), 3, "{:?}", l.warnings);
        assert_eq!(l.skipped, 1);
        let a1 = &l.labels["urlquery:a1"];
        assert_eq!(
            (a1.label, a1.ref_tier),
            (Label::Agent, Some(Tier::Significant))
        );
        assert_eq!(a1.class.as_deref(), Some("custom_program"));
        assert_eq!(l.labels["urlquery:a2"].ref_tier, Some(Tier::Suggestive));
        assert_eq!(l.labels["urlquery:a3"].label, Label::Benign);
    }

    #[test]
    fn precision_recall_and_rule_stats() {
        let records = vec![
            // Agent: SQLi through a relay -> significant.
            obs(
                "x:1",
                "https://r.jina.ai/https://data.example.gov/api?State_Id=1%20OR%201=1",
            ),
            // Agent: relay only -> not significant.
            obs("x:2", "https://r.jina.ai/https://data.example.gov/report"),
            // Benign: a person reading an article through the same relay.
            obs("x:3", "https://r.jina.ai/https://blog.example.com/post"),
            // Benign, unflagged.
            obs("x:4", "https://www.example.com/"),
            // Unlabelled.
            obs("x:5", "https://www.example.org/"),
        ];
        let a = analyze(records, &Rules::default_rules());
        let labels = parse_labels(
            "{\"id\":\"x:1\",\"label\":\"agent\",\"class\":\"exploit\"}\n\
             {\"id\":\"x:2\",\"label\":\"agent\",\"class\":\"indirection\"}\n\
             {\"id\":\"x:3\",\"label\":\"benign\"}\n\
             {\"id\":\"x:4\",\"label\":\"benign\"}\n\
             {\"id\":\"x:9\",\"label\":\"agent\"}\n",
        );
        let r = evaluate(&a, &labels);
        assert_eq!((r.labelled, r.unlabelled, r.missing_records), (4, 1, 1));
        assert_eq!((r.agents, r.benign), (2, 2));
        let sig = r.threshold(Tier::Significant).unwrap();
        assert_eq!((sig.tp, sig.fp, sig.fn_, sig.tn), (1, 0, 1, 2));
        assert_eq!(sig.precision, Some(1.0));
        assert_eq!(sig.recall, Some(0.5));
        let jina = r.rules.iter().find(|s| s.rule_id == "relay.jina").unwrap();
        assert_eq!((jina.on_agent, jina.on_benign), (2, 1));
        let exploit = r.classes.iter().find(|c| c.class == "exploit").unwrap();
        assert_eq!(exploit.significant, 1);
    }
}
