//! Rules pinning without the files: the names a pinned rule set may be
//! kept under, and which records change tier between two rule sets.
//!
//! A case renders with the rules it was opened with, kept as
//! `<data>/rules/<name>.toml`; the CLI does the reading and writing.

use crate::{Result, bail};
use sc_core::{Analysis, Tier};
use std::collections::BTreeMap;

/// A pin name is a file stem in the rules directory, never a path.
pub fn check_pin(name: &str) -> Result<()> {
    let ok = !name.is_empty()
        && !name.starts_with('.')
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'));
    if !ok {
        bail!("rules pin `{name}` is not a valid name");
    }
    Ok(())
}

/// The names a rule set with `version` and source `text` may be pinned
/// under, in order: the version (made a valid name), then the version plus
/// a hash prefix, for an edited file that kept its version.
pub fn pin_names(version: &str, text: &str) -> [String; 2] {
    let mut v: String = version
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_') {
                c
            } else {
                '-'
            }
        })
        .collect();
    if v.is_empty() || v.starts_with('.') {
        v = format!("v{v}");
    }
    let sha = crate::bundle::sha256_hex(text.as_bytes());
    let hashed = format!("{v}-{}", &sha[..12]);
    [v, hashed]
}

/// Records whose tier differs between two analyses of the same records:
/// record ID -> (tier in `before`, tier in `after`).
pub fn tier_changes(before: &Analysis, after: &Analysis) -> BTreeMap<String, (Tier, Tier)> {
    let was: BTreeMap<&str, Tier> = before
        .results
        .iter()
        .map(|r| (r.obs.id.as_str(), r.tier))
        .collect();
    after
        .results
        .iter()
        .filter_map(|r| {
            let w = *was.get(r.obs.id.as_str())?;
            (w != r.tier).then(|| (r.obs.id.clone(), (w, r.tier)))
        })
        .collect()
}

/// The first `max` changes, as `id noise → suggestive`, and how many more.
pub fn describe_changes(changes: &BTreeMap<String, (Tier, Tier)>, max: usize) -> String {
    let mut s: Vec<String> = changes
        .iter()
        .take(max)
        .map(|(id, (a, b))| format!("{id} {} → {}", a.label(), b.label()))
        .collect();
    if changes.len() > max {
        s.push(format!("{} more", changes.len() - max));
    }
    s.join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use sc_core::{Observation, Rules, analyze};

    #[test]
    fn names_are_never_paths() {
        assert!(check_pin("2026.10.1").is_ok());
        for bad in ["", ".x", "../../etc/x", "a/b", "a b"] {
            assert!(check_pin(bad).is_err(), "{bad}");
        }
        let [v, h] = pin_names("2026 10/1", "text");
        assert_eq!(v, "2026-10-1");
        assert!(
            h.starts_with("2026-10-1-") && h.len() == v.len() + 13,
            "{h}"
        );
        assert_eq!(pin_names(".x", "t")[0], "v.x");
    }

    #[test]
    fn changes_are_listed_per_record() {
        let current = Rules::default_rules();
        let text = sc_core::DEFAULT_RULES
            .replace("suggestive = 3", "suggestive = 300")
            .replace("significant = 6", "significant = 600")
            .replace("significant = true", "significant = false");
        let strict = Rules::from_toml(&text).unwrap();
        let obs = vec![Observation {
            id: "r1".into(),
            ts: 1_791_000_000,
            url: "https://r.jina.ai/https://portal.example.gov/q?id=1%20UNION%20SELECT%201".into(),
            ..Default::default()
        }];
        let changes = tier_changes(&analyze(obs.clone(), &current), &analyze(obs, &strict));
        assert_eq!(changes.len(), 1, "{changes:?}");
        assert!(describe_changes(&changes, 5).starts_with("r1 "));
    }
}
