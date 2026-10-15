//! Rule coverage: does every rule have labelled evidence behind it?
//!
//! For each rule in a rules file: its **positives** (agent-labelled records
//! it fired on) and its **hard negatives** (benign records written to look
//! like what it matches, which name it in `hard_negative_for`). A rule with
//! no positive is untested: the gate fails on it unless it is on the
//! allow-list (`samples/eval/coverage-allow.txt`, one rule id per line, then
//! the reason).
//!
//! Rule metadata (`tactic`, `artifact`) is read from the rules TOML as a
//! generic value, so rules files with or without those fields both work. A
//! rule without a tactic groups as `untagged`.

use super::EvalReport;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const UNTAGGED: &str = "untagged";

/// What the rules file says about one rule, beyond matching.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleMeta {
    pub id: String,
    /// `T1`..`T9`, or [`UNTAGGED`]. A rule may list several.
    pub tactics: Vec<String>,
    /// The rule only shows how the agent was built (`artifact = true`).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub artifact: bool,
}

/// Every `[[rule]]` in `rules_toml`, in file order. Errors on TOML that does
/// not parse; a rule without an `id` is skipped.
pub fn rule_meta(rules_toml: &str) -> Result<Vec<RuleMeta>, String> {
    let v: toml::Value = toml::from_str(rules_toml).map_err(|e| e.to_string())?;
    let rules = v.get("rule").and_then(|r| r.as_array());
    let mut out = Vec::new();
    for r in rules.into_iter().flatten() {
        let Some(id) = r.get("id").and_then(|x| x.as_str()) else {
            continue;
        };
        let mut tactics: Vec<String> = match r.get("tactic") {
            Some(toml::Value::String(s)) => vec![s.clone()],
            Some(toml::Value::Array(a)) => a
                .iter()
                .filter_map(|x| x.as_str().map(str::to_string))
                .collect(),
            _ => Vec::new(),
        };
        tactics.retain(|t| !t.trim().is_empty());
        if tactics.is_empty() {
            tactics.push(UNTAGGED.into());
        }
        out.push(RuleMeta {
            id: id.to_string(),
            tactics,
            artifact: match r.get("artifact") {
                Some(toml::Value::Boolean(b)) => *b,
                // An older spelling: any value but an empty or `false` string.
                Some(toml::Value::String(s)) => !s.is_empty() && s != "false",
                _ => false,
            },
        });
    }
    Ok(out)
}

/// Rule id -> reason it may go without a positive.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AllowList {
    pub entries: BTreeMap<String, String>,
}

impl AllowList {
    /// One entry per line: the rule id, whitespace, the reason. `#` starts a
    /// comment line; blank lines are ignored. An entry without a reason gets
    /// an empty one, which [`coverage_failures`] rejects.
    pub fn parse(text: &str) -> Self {
        let mut entries = BTreeMap::new();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (id, reason) = line.split_once(char::is_whitespace).unwrap_or((line, ""));
            entries.insert(id.to_string(), reason.trim().to_string());
        }
        Self { entries }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleCoverage {
    pub rule_id: String,
    pub tactics: Vec<String>,
    /// The rule only shows how the agent was built (`artifact = true`).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub artifact: bool,
    /// Agent-labelled records it fired on.
    pub positives: usize,
    /// Benign-labelled records it fired on.
    pub on_benign: usize,
    /// Benign records naming it in `hard_negative_for`.
    pub hard_negatives: usize,
    /// Of those, how many it fired on anyway.
    pub hard_negatives_fired: usize,
    /// The allow-list reason, when it is listed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Coverage {
    pub rules: Vec<RuleCoverage>,
    /// Rules with at least one positive.
    pub covered: usize,
    /// Rules with no positive but on the allow-list.
    pub allowed: usize,
    /// Rules with no positive and not on the allow-list.
    pub uncovered: Vec<String>,
    /// Rules with at least one hard negative.
    pub with_hard_negatives: usize,
    /// `hard_negative_for` ids that name no rule in the file.
    pub unknown_hard_negative_ids: Vec<String>,
}

pub fn coverage(report: &EvalReport, meta: &[RuleMeta], allow: &AllowList) -> Coverage {
    let stats: BTreeMap<&str, _> = report
        .rules
        .iter()
        .map(|s| (s.rule_id.as_str(), s))
        .collect();
    let mut out = Coverage::default();
    for m in meta {
        let s = stats.get(m.id.as_str());
        let hn = report
            .hard_negatives
            .get(&m.id)
            .copied()
            .unwrap_or_default();
        let c = RuleCoverage {
            rule_id: m.id.clone(),
            tactics: m.tactics.clone(),
            artifact: m.artifact,
            positives: s.map_or(0, |s| s.on_agent),
            on_benign: s.map_or(0, |s| s.on_benign),
            hard_negatives: hn.records,
            hard_negatives_fired: hn.fired,
            allowed: allow.entries.get(&m.id).cloned(),
        };
        if c.positives > 0 {
            out.covered += 1;
        } else if c.allowed.is_some() {
            out.allowed += 1;
        } else {
            out.uncovered.push(c.rule_id.clone());
        }
        out.with_hard_negatives += usize::from(c.hard_negatives > 0);
        out.rules.push(c);
    }
    out.unknown_hard_negative_ids = report
        .hard_negatives
        .keys()
        .filter(|id| !meta.iter().any(|m| &m.id == *id))
        .cloned()
        .collect();
    out
}

/// How close benign records sit to the suggestive threshold, and what each
/// rule adds to a record's tier (report only). Numbers and rule ids only.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Margins {
    /// The suggestive threshold the scores are read against.
    pub suggestive: i32,
    /// Benign records scoring one point below it: one more weak hit flags
    /// them.
    pub benign_one_below: usize,
    /// Per hard-negative rule, the highest score among the benign records
    /// written to resemble what it matches.
    pub hard_negatives: Vec<HardNegativeMargin>,
    /// Rule id -> benign records at suggestive or above that would fall
    /// below it without the rule: the false positives it causes.
    pub lifted: BTreeMap<String, usize>,
    /// Agent records at suggestive or above.
    pub agents: usize,
    pub agents_flagged: usize,
    /// Rules whose removal drops an agent record below suggestive, with
    /// the recall left without each, most dropped first. Read off each
    /// record's own hits: no rule is removed and nothing is analysed again.
    pub leave_one_out: Vec<RuleDrop>,
}

/// One hard-negative rule's closest benign record.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HardNegativeMargin {
    pub rule_id: String,
    /// Its hard negatives.
    pub records: usize,
    /// The highest score among them.
    pub max_score: i32,
    /// Points from that score to the suggestive threshold (0 or less:
    /// flagged).
    pub margin: i32,
}

/// What recall at suggestive or above loses without one rule.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RuleDrop {
    pub rule_id: String,
    /// Agent records that fall below suggestive without it.
    pub dropped: usize,
    /// Recall at suggestive or above without it.
    pub recall_without: f64,
}

/// Whether hits `ids` reach suggestive: a significant rule, or a score at
/// the threshold.
fn reaches(rules: &crate::Rules, ids: &[&str]) -> bool {
    ids.iter()
        .any(|id| rules.rule(id).is_some_and(|d| d.significant))
        || rules.score(ids.iter().copied()) >= rules.set.thresholds.suggestive
}

/// The margins of the labelled records of `a`, scored with `rules` (the
/// rules the analysis ran with).
pub fn margins(
    a: &crate::analyze::Analysis,
    labels: &super::LabelSet,
    rules: &crate::Rules,
) -> Margins {
    let suggestive = rules.set.thresholds.suggestive;
    let mut out = Margins {
        suggestive,
        ..Margins::default()
    };
    let mut hn: BTreeMap<&str, (usize, i32)> = BTreeMap::new();
    let mut dropped: BTreeMap<String, usize> = BTreeMap::new();
    for (i, l) in super::units::labelled(a, labels) {
        let r = &a.results[i];
        let mut ids: Vec<&str> = r.hits.iter().map(|h| h.rule_id.as_str()).collect();
        crate::sort::sort(&mut ids);
        ids.dedup();
        let agent = l.label == super::Label::Agent;
        let flagged = r.tier >= crate::model::Tier::Suggestive && reaches(rules, &ids);
        if agent {
            out.agents += 1;
            out.agents_flagged += usize::from(r.tier >= crate::model::Tier::Suggestive);
        } else {
            out.benign_one_below += usize::from(r.score == suggestive - 1);
            for rule in &l.hard_negative_for {
                let e = hn.entry(rule.as_str()).or_insert((0, i32::MIN));
                e.0 += 1;
                e.1 = e.1.max(r.score);
            }
        }
        if !flagged {
            continue;
        }
        for id in &ids {
            let rest: Vec<&str> = ids.iter().copied().filter(|x| x != id).collect();
            if reaches(rules, &rest) {
                continue;
            }
            let map = if agent { &mut dropped } else { &mut out.lifted };
            *map.entry((*id).to_string()).or_default() += 1;
        }
    }
    out.hard_negatives = hn
        .into_iter()
        .map(|(rule, (records, max_score))| HardNegativeMargin {
            rule_id: rule.to_string(),
            records,
            max_score,
            margin: suggestive - max_score,
        })
        .collect();
    crate::sort::by(&mut out.hard_negatives, |x, y| {
        x.margin
            .cmp(&y.margin)
            .then_with(|| x.rule_id.cmp(&y.rule_id))
    });
    let n = out.agents.max(1) as f64;
    out.leave_one_out = dropped
        .into_iter()
        .map(|(rule_id, d)| RuleDrop {
            recall_without: out.agents_flagged.saturating_sub(d) as f64 / n,
            rule_id,
            dropped: d,
        })
        .collect();
    crate::sort::by(&mut out.leave_one_out, |x, y| {
        y.dropped
            .cmp(&x.dropped)
            .then_with(|| x.rule_id.cmp(&y.rule_id))
    });
    out
}

/// What the coverage gate rejects: rules with no positive and no allow-list
/// entry, allow-list entries for rules that now have a positive (remove
/// them) or that name no rule, and entries without a reason.
pub fn coverage_failures(c: &Coverage, allow: &AllowList) -> Vec<String> {
    let mut out: Vec<String> = c
        .uncovered
        .iter()
        .map(|id| format!("rule {id} has no positive in the evaluation set (add a record, or list it in the allow-list with a reason)"))
        .collect();
    for (id, reason) in &allow.entries {
        match c.rules.iter().find(|r| &r.rule_id == id) {
            None => out.push(format!("allow-list names {id}, which is not a rule")),
            Some(r) if r.positives > 0 => out.push(format!(
                "rule {id} now has {} positive(s); remove it from the allow-list",
                r.positives
            )),
            Some(_) if reason.is_empty() => {
                out.push(format!("allow-list entry for {id} gives no reason"))
            }
            Some(_) => {}
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn meta_reads_optional_fields() {
        let toml = r#"
            [meta]
            version = "x"
            [[rule]]
            id = "a.one"
            tactic = "T3"
            artifact = true
            [[rule]]
            id = "a.two"
            tactic = ["T1", "T4"]
            artifact = false
            [[rule]]
            id = "a.three"
            artifact = "yes"
        "#;
        let m = rule_meta(toml).unwrap();
        assert_eq!(m.len(), 3);
        assert_eq!(m[0].tactics, ["T3"]);
        assert!(m[0].artifact);
        assert_eq!(m[1].tactics, ["T1", "T4"]);
        assert!(!m[1].artifact);
        assert_eq!(m[2].tactics, [UNTAGGED]);
        assert!(m[2].artifact);
        // The bundled rules mark their artifacts with a boolean.
        let bundled = rule_meta(crate::DEFAULT_RULES).unwrap();
        assert!(
            bundled
                .iter()
                .any(|r| r.id == "marker.md_link" && r.artifact)
        );
        assert!(
            bundled
                .iter()
                .any(|r| r.id == "exploit.sqli_union" && !r.artifact)
        );
        assert!(rule_meta("not [ toml").is_err());
        assert!(!rule_meta(crate::DEFAULT_RULES).unwrap().is_empty());
    }

    #[test]
    fn margins_read_each_records_own_hits() {
        use crate::{Observation, Rules, analyze, parse_labels};
        let rules = Rules::default_rules();
        let obs = |id: &str, url: &str| Observation {
            id: id.into(),
            ts: 1000,
            url: url.into(),
            ..Default::default()
        };
        let a = analyze(
            vec![
                // An injection payload: flagged on the one rule.
                obs("a1", "https://t.example/p?id=1%27%20OR%20%271%27=%271"),
                // A plain page: no hit.
                obs("b1", "https://u.example/about"),
            ],
            &rules,
        );
        let labels = parse_labels(
            "{\"id\":\"a1\",\"label\":\"agent\"}\n\
             {\"id\":\"b1\",\"label\":\"benign\",\"hard_negative_for\":[\"exploit.sqli_boolean\"]}\n",
        );
        let m = margins(&a, &labels, &rules);
        assert_eq!(m.suggestive, rules.set.thresholds.suggestive);
        assert_eq!((m.agents, m.agents_flagged), (1, 1));
        assert_eq!(m.hard_negatives.len(), 1);
        assert_eq!(m.hard_negatives[0].max_score, 0);
        assert_eq!(m.hard_negatives[0].margin, m.suggestive);
        assert!(m.lifted.is_empty());
        // The agent record stands on the injection rule alone.
        let r = &a.results.iter().find(|r| r.obs.id == "a1").unwrap();
        assert!(r.tier >= crate::model::Tier::Suggestive, "{:?}", r.hits);
        let only = r
            .hits
            .iter()
            .map(|h| h.rule_id.as_str())
            .collect::<std::collections::BTreeSet<_>>();
        if only.len() == 1 {
            assert_eq!(m.leave_one_out.len(), 1, "{m:?}");
            assert_eq!(m.leave_one_out[0].recall_without, 0.0);
        }
    }

    #[test]
    fn allow_list() {
        let a = AllowList::parse("# comment\n\nx.one   no record yet\nx.two\n");
        assert_eq!(a.entries["x.one"], "no record yet");
        assert_eq!(a.entries["x.two"], "");
    }
}
