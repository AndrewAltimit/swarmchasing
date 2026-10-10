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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact: Option<String>,
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
            artifact: r
                .get("artifact")
                .and_then(|x| x.as_str())
                .map(str::to_string),
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact: Option<String>,
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
            artifact: m.artifact.clone(),
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
            artifact = "relay"
            [[rule]]
            id = "a.two"
            tactic = ["T1", "T4"]
            [[rule]]
            id = "a.three"
        "#;
        let m = rule_meta(toml).unwrap();
        assert_eq!(m.len(), 3);
        assert_eq!(m[0].tactics, ["T3"]);
        assert_eq!(m[0].artifact.as_deref(), Some("relay"));
        assert_eq!(m[1].tactics, ["T1", "T4"]);
        assert_eq!(m[2].tactics, [UNTAGGED]);
        assert!(rule_meta("not [ toml").is_err());
        assert!(!rule_meta(crate::DEFAULT_RULES).unwrap().is_empty());
    }

    #[test]
    fn allow_list() {
        let a = AllowList::parse("# comment\n\nx.one   no record yet\nx.two\n");
        assert_eq!(a.entries["x.one"], "no record yet");
        assert_eq!(a.entries["x.two"], "");
    }
}
