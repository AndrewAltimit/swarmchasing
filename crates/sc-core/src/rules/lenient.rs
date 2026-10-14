//! Loading a pinned or historical rules file. The shipped rules load
//! strictly: an unknown key is an error, so a misspelt option never drops a
//! setting silently. A copy pinned by a case was valid when it was pinned,
//! and a key it holds that the current code no longer knows is a retired
//! option. Such a key is dropped with a warning, as is a rule tactic that
//! is now a cluster-level judgment; every other error (a bad value, a bad
//! pattern, a duplicate rule) still fails the load.

use super::{RuleSet, Rules};
use toml_edit::{ImDocument, Item, Value};

/// At most this many keys are dropped from one file before the load gives
/// up, so a file that is not a rules file at all fails rather than looping.
const MAX_DROPPED: usize = 256;

/// One step of the path to a key: a table key, or an index into an array
/// of tables (`[[rule]]`) or of inline tables.
#[derive(Debug, Clone, PartialEq)]
enum Seg {
    Key(String),
    Index(usize),
}

pub(super) fn from_toml_lenient(text: &str) -> Result<(Rules, Vec<String>), String> {
    let mut text = text.to_string();
    let mut warnings = Vec::new();
    for _ in 0..=MAX_DROPPED {
        let err = match toml::from_str::<RuleSet>(&text) {
            Ok(mut set) => {
                retire_tactics(&mut set, &mut warnings);
                return Ok((Rules::compile(set)?, warnings));
            }
            Err(e) => e,
        };
        let path = err
            .message()
            .starts_with("unknown field")
            .then(|| err.span())
            .flatten()
            .and_then(|span| key_path(&text, span.start));
        let Some(path) = path else {
            return Err(format!("rules: {err}"));
        };
        text = remove(&text, &path).ok_or_else(|| format!("rules: {err}"))?;
        warnings.push(format!(
            "rules: ignored unknown key `{}` (an option these rules no longer have)",
            show(&path)
        ));
    }
    Err(format!("rules: more than {MAX_DROPPED} unknown keys"))
}

/// A rule tactic the current rules keep for clusters (off-task targets,
/// inter-agent coordination) is dropped from an older rule that named it,
/// with a warning: the rule still matches and scores as it did.
fn retire_tactics(set: &mut RuleSet, warnings: &mut Vec<String>) {
    use crate::model::Tactic;
    for def in &mut set.rules {
        if let Some(t @ (Tactic::OffTaskTargets | Tactic::InterAgentCoordination)) = def.tactic {
            def.tactic = None;
            warnings.push(format!(
                "rules: ignored tactic {} of rule `{}` (a cluster-level judgment, no longer a rule's)",
                t.id(),
                def.id
            ));
        }
    }
}

fn show(path: &[Seg]) -> String {
    let mut s = String::new();
    for seg in path {
        match seg {
            Seg::Key(k) => {
                if !s.is_empty() {
                    s.push('.');
                }
                s.push_str(k);
            }
            Seg::Index(i) => s.push_str(&format!("[{i}]")),
        }
    }
    s
}

/// The path to the key whose name starts at byte `at`.
fn key_path(text: &str, at: usize) -> Option<Vec<Seg>> {
    let doc = ImDocument::parse(text).ok()?;
    let mut path = Vec::new();
    find_in_table(doc.as_table(), at, &mut path).then_some(path)
}

fn find_in_table(t: &toml_edit::Table, at: usize, path: &mut Vec<Seg>) -> bool {
    for (k, item) in t.iter() {
        path.push(Seg::Key(k.to_string()));
        if t.key(k)
            .and_then(|key| key.span())
            .is_some_and(|s| s.contains(&at))
            || find_in_item(item, at, path)
        {
            return true;
        }
        path.pop();
    }
    false
}

fn find_in_item(item: &Item, at: usize, path: &mut Vec<Seg>) -> bool {
    match item {
        Item::Table(t) => find_in_table(t, at, path),
        Item::ArrayOfTables(a) => a.iter().enumerate().any(|(i, t)| {
            path.push(Seg::Index(i));
            let hit = find_in_table(t, at, path);
            if !hit {
                path.pop();
            }
            hit
        }),
        Item::Value(v) => find_in_value(v, at, path),
        Item::None => false,
    }
}

fn find_in_value(v: &Value, at: usize, path: &mut Vec<Seg>) -> bool {
    match v {
        Value::InlineTable(t) => t.iter().any(|(k, v)| {
            path.push(Seg::Key(k.to_string()));
            let hit = t
                .key(k)
                .and_then(|key| key.span())
                .is_some_and(|s| s.contains(&at))
                || find_in_value(v, at, path);
            if !hit {
                path.pop();
            }
            hit
        }),
        Value::Array(a) => a.iter().enumerate().any(|(i, v)| {
            path.push(Seg::Index(i));
            let hit = find_in_value(v, at, path);
            if !hit {
                path.pop();
            }
            hit
        }),
        _ => false,
    }
}

/// `text` without the key at `path`.
fn remove(text: &str, path: &[Seg]) -> Option<String> {
    let mut doc: toml::Table = toml::from_str(text).ok()?;
    let (last, parents) = path.split_last()?;
    let Seg::Key(last) = last else { return None };
    let mut table = &mut doc;
    let mut segs = parents.iter().peekable();
    while let Some(seg) = segs.next() {
        let Seg::Key(k) = seg else { return None };
        let mut v = table.get_mut(k)?;
        while let Some(Seg::Index(i)) = segs.peek() {
            v = v.as_array_mut()?.get_mut(*i)?;
            segs.next();
        }
        table = v.as_table_mut()?;
    }
    table.remove(last)?;
    toml::to_string(&doc).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_retired_key_is_dropped_with_a_warning() {
        let text = "[meta]\nversion = \"old\"\n\n[soft_links]\nfleet_min_strength = 3.0\nrerun = 2.0\n\n[thresholds]\nsuggestive = 4\nsignificant = 7\nretired_flag = true\n";
        assert!(Rules::from_toml(text).is_err());
        let (r, warnings) = Rules::from_toml_lenient(text).unwrap();
        assert_eq!(r.set.soft_links.rerun, 2.0);
        assert_eq!(r.set.thresholds.suggestive, 4);
        assert_eq!(warnings.len(), 2, "{warnings:?}");
        assert!(
            warnings[0].contains("soft_links.fleet_min_strength"),
            "{warnings:?}"
        );
        assert!(
            warnings[1].contains("thresholds.retired_flag"),
            "{warnings:?}"
        );
    }

    #[test]
    fn other_errors_still_fail() {
        assert!(Rules::from_toml_lenient("[soft_links]\nrerun = \"two\"\n").is_err());
        let dup = "[[rule]]\nid = \"a\"\nkind = \"exfil\"\ntarget = \"url\"\npattern = \"x\"\nweight = 1\n";
        assert!(Rules::from_toml_lenient(&format!("{dup}{dup}")).is_err());
    }

    #[test]
    fn the_shipped_rules_load_without_warnings() {
        let (_, warnings) = Rules::from_toml_lenient(crate::DEFAULT_RULES).unwrap();
        assert!(warnings.is_empty(), "{warnings:?}");
    }
}
