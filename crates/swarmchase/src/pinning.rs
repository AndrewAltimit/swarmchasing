//! Rules pinning: the rule set a case renders with, kept in
//! `<data>/rules/<name>.toml` and named in case.toml, so a case's reports,
//! notice and bundles do not change when the bundled rules do.
//! `case rules <id> --update` re-pins a case to the current rules and logs
//! which records change tier. Pin names and tier changes are
//! [`sc_case::pinning`]; this module keeps the files.

use crate::case::{Case, Scope, case_records, load, save};
use anyhow::{Context, Result, bail};
use sc_case::pinning::{check_pin, describe_changes, pin_names};
use sc_core::{Tier, analyze};
use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};

/// A rule set and the TOML it was compiled from, so a case can keep a copy.
pub struct RulesText {
    pub text: String,
    pub rules: sc_core::Rules,
}

impl RulesText {
    /// The rules file at `p`, or the bundled rules.
    pub fn load(p: Option<&Path>) -> Result<Self> {
        let text = match p {
            Some(p) => {
                std::fs::read_to_string(p).with_context(|| format!("reading {}", p.display()))?
            }
            None => sc_core::DEFAULT_RULES.to_string(),
        };
        let rules = sc_core::Rules::from_toml(&text).map_err(anyhow::Error::msg)?;
        Ok(Self { text, rules })
    }

    pub fn version(&self) -> &str {
        &self.rules.set.meta.version
    }
}

/// Pinned rule sets live beside the cases, in `<data>/rules/`.
fn rules_dir(root: &Path) -> PathBuf {
    root.parent().unwrap_or(root).join("rules")
}

/// Keep a copy of `r` in `<data>/rules/` and return its name there: the rules
/// version, or the version plus a hash prefix when a different rule set
/// already holds that name (an edited file that kept its version).
pub(crate) fn pin_rules(root: &Path, r: &RulesText) -> Result<String> {
    let dir = rules_dir(root);
    std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    let names = pin_names(r.version(), &r.text);
    for name in names.clone() {
        let p = dir.join(format!("{name}.toml"));
        match std::fs::read_to_string(&p) {
            Ok(t) if t == r.text => return Ok(name),
            Ok(_) => continue,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                std::fs::write(&p, &r.text).with_context(|| format!("writing {}", p.display()))?;
                return Ok(name);
            }
            Err(e) => return Err(e).with_context(|| format!("reading {}", p.display())),
        }
    }
    bail!(
        "{}: other rule sets already hold `{}` and `{}`",
        dir.display(),
        names[0],
        names[1]
    )
}

/// The rules a case renders with: its pinned copy, or the current bundled
/// rules for a case file from before pinning.
pub fn case_rules(root: &Path, c: &Case) -> Result<sc_core::Rules> {
    let Some(pin) = &c.rules_version else {
        return Ok(sc_core::Rules::default_rules());
    };
    check_pin(pin)?;
    let p = rules_dir(root).join(format!("{pin}.toml"));
    let text = std::fs::read_to_string(&p).with_context(|| {
        format!(
            "case {} is pinned to rules {pin}, but {} cannot be read",
            c.id,
            p.display()
        )
    })?;
    load_pinned(&p, &text)
}

/// A pinned rules file: it was valid when it was pinned, so a key the
/// current code no longer knows is a retired option, dropped with a warning
/// rather than failing the case.
fn load_pinned(p: &Path, text: &str) -> Result<sc_core::Rules> {
    let (rules, warnings) = sc_core::Rules::from_toml_lenient(text)
        .map_err(|e| anyhow::anyhow!("{}: {e}", p.display()))?;
    for w in warnings {
        eprintln!("warning: {}: {w}", p.display());
    }
    Ok(rules)
}

/// Run a leak check under the case's pinned rules, and under the current
/// rules too when they differ, so a check added after the case was opened
/// still applies. Findings are merged in order, without repeats.
pub fn leak_check(
    root: &Path,
    c: &Case,
    check: impl Fn(&sc_core::Rules) -> Vec<String>,
) -> Result<Vec<String>> {
    let mut out = check(&case_rules(root, c)?);
    let current = sc_core::Rules::default_rules();
    if c.rules_version.as_deref() != Some(current.set.meta.version.as_str()) {
        for p in check(&current) {
            if !out.contains(&p) {
                out.push(p);
            }
        }
    }
    Ok(out)
}

/// The rules to verify a bundle with: the pinned copy named by its stamp when
/// there is one, else the bundled rules.
pub(crate) fn bundle_rules(root: &Path, bundle: &Path) -> Result<sc_core::Rules> {
    let st = crate::bundle::read_stamp(bundle)?;
    let p = rules_dir(root).join(format!("{}.toml", st.rules_version));
    if check_pin(&st.rules_version).is_ok() && p.is_file() {
        let text =
            std::fs::read_to_string(&p).with_context(|| format!("reading {}", p.display()))?;
        return load_pinned(&p, &text);
    }
    Ok(sc_core::Rules::default_rules())
}

/// Records whose tier differs between the case's pinned rules and `current`:
/// record ID -> (pinned tier, current tier).
pub(crate) fn tier_changes(
    root: &Path,
    c: &Case,
    current: &sc_core::Rules,
) -> Result<BTreeMap<String, (Tier, Tier)>> {
    let records = case_records(root, c, &Scope::All)?;
    let before = analyze(records.clone(), &case_rules(root, c)?);
    let after = analyze(records, current);
    Ok(sc_case::pinning::tier_changes(&before, &after))
}

/// `case rules`: pinned against current, and with `update` re-pin to
/// `current` and log the change and the records that changed tier.
pub(crate) fn rules_cmd(
    root: &Path,
    id: &str,
    current: &RulesText,
    update: bool,
    today: &str,
    out: &mut impl Write,
) -> Result<()> {
    let mut c = load(root, id)?;
    let pinned = c
        .rules_version
        .clone()
        .unwrap_or_else(|| "not pinned (renders with the current rules)".into());
    writeln!(out, "pinned:  {pinned}")?;
    writeln!(out, "current: {}", current.version())?;
    let changes = tier_changes(root, &c, &current.rules)?;
    if changes.is_empty() {
        writeln!(out, "no record changes tier under the current rules")?;
    } else {
        writeln!(
            out,
            "{} record(s) change tier under the current rules: {}",
            changes.len(),
            describe_changes(&changes, 20)
        )?;
    }
    if !update {
        writeln!(
            out,
            "re-pin with `swarmchase case rules {id} --update` (reports, notice and bundles then use the current rules)"
        )?;
        return Ok(());
    }
    let pin = pin_rules(root, current)?;
    if c.rules_version.as_deref() == Some(pin.as_str()) {
        writeln!(out, "already pinned to {pin}")?;
        return Ok(());
    }
    let what = if changes.is_empty() {
        "no record changed tier".to_string()
    } else {
        format!(
            "{} record(s) changed tier: {}",
            changes.len(),
            describe_changes(&changes, 10)
        )
    };
    c.log(
        today,
        format!(
            "rules re-pinned: {} → {pin}; {what}",
            c.rules_version.as_deref().unwrap_or("not pinned")
        ),
    );
    c.rules_version = Some(pin.clone());
    save(root, &c)?;
    writeln!(out, "pinned {id} to rules {pin}")?;
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::case::test_support::*;
    use crate::case::{new_case, status, update};
    use sc_core::Observation;
    use sc_core::notice::lint_public;

    #[test]
    fn leak_check_uses_the_pinned_rules_and_the_current_ones() {
        let root = scratch("leak");
        let current = RulesText::load(None).unwrap();
        let records: Vec<Observation> = fixture().results.iter().map(|r| r.obs.clone()).collect();
        new_case(&root, "t-4", "Leak", records, &current, "2026-10-12").unwrap();
        // A pinned rule set with a callback channel the current rules lack.
        let text = format!(
            "{}\n[[rule]]\nid = \"exfil.test_inbox\"\nkind = \"exfil\"\ntarget = \"url\"\npattern = \"zzinbox[0-9]+\"\nweight = 3\nlink = true\n",
            current.text.replace(current.version(), "pinned-test")
        );
        let pinned = RulesText {
            rules: sc_core::Rules::from_toml(&text).unwrap(),
            text,
        };
        let pin = pin_rules(&root, &pinned).unwrap();
        update(&root, "t-4", |c| {
            c.rules_version = Some(pin.clone());
            Ok(())
        })
        .unwrap();
        let c = load(&root, "t-4").unwrap();
        let body = "see zzinbox42 and https://webhook.site/0b6c1f0e-1111-4c2a-9a55-3f2e1d0c9b8a";
        let lint = leak_check(&root, &c, |r| lint_public(body, r)).unwrap();
        assert!(lint.iter().any(|l| l.contains("zzinbox42")), "{lint:?}");
        assert_eq!(
            lint.iter().filter(|l| l.contains("webhook.site")).count(),
            1,
            "{lint:?}"
        );
        cleanup(&root);
    }

    #[test]
    fn a_case_pinned_to_released_rules_with_retired_keys_still_renders() {
        let root = scratch("retired");
        let current = RulesText::load(None).unwrap();
        let records: Vec<Observation> = fixture().results.iter().map(|r| r.obs.clone()).collect();
        new_case(&root, "t-5", "Old pin", records, &current, "2026-10-12").unwrap();
        // Released rules holding `soft_links.fleet_min_strength`, since retired.
        let old = include_str!("../../sc-core/tests/fixtures/rules-history/2026-10-12.3.toml");
        assert!(sc_core::Rules::from_toml(old).is_err());
        let dir = root.parent().unwrap().join("rules");
        std::fs::write(dir.join("2026-10-12.3.toml"), old).unwrap();
        update(&root, "t-5", |c| {
            c.rules_version = Some("2026-10-12.3".into());
            Ok(())
        })
        .unwrap();
        let c = load(&root, "t-5").unwrap();
        assert_eq!(
            case_rules(&root, &c).unwrap().set.meta.version,
            "2026-10-12.3"
        );
        let mut out = Vec::new();
        rules_cmd(&root, "t-5", &current, true, "2026-10-13", &mut out).unwrap();
        let c = load(&root, "t-5").unwrap();
        assert_eq!(c.rules_version.as_deref(), Some(current.version()));
        cleanup(&root);
    }

    #[test]
    fn rules_are_pinned_and_repinned() {
        let root = scratch("rules");
        let current = RulesText::load(None).unwrap();
        let v = current.version().to_string();
        let records: Vec<Observation> = fixture().results.iter().map(|r| r.obs.clone()).collect();
        new_case(
            &root,
            "t-3",
            "Portal probe",
            records,
            &current,
            "2026-10-12",
        )
        .unwrap();
        let c = load(&root, "t-3").unwrap();
        assert_eq!(c.rules_version.as_deref(), Some(v.as_str()));
        let rules_dir = root.parent().unwrap().join("rules");
        assert_eq!(
            std::fs::read_to_string(rules_dir.join(format!("{v}.toml"))).unwrap(),
            current.text
        );
        assert!(c.decisions[0].text.contains(&format!("rules {v}")));

        // An edited rule set that kept its version gets its own name.
        let text = current
            .text
            .replace("suggestive = 3", "suggestive = 300")
            .replace("significant = 6", "significant = 600")
            .replace("significant = true", "significant = false");
        let strict = RulesText {
            rules: sc_core::Rules::from_toml(&text).unwrap(),
            text,
        };
        let pin = pin_rules(&root, &strict).unwrap();
        assert!(
            pin.starts_with(&format!("{v}-")) && pin.len() == v.len() + 13,
            "{pin}"
        );
        assert_eq!(pin_rules(&root, &strict).unwrap(), pin, "stable");
        assert_eq!(pin_rules(&root, &current).unwrap(), v);

        // Showing does not re-pin; updating does, and logs the tier changes.
        let changes = tier_changes(&root, &c, &strict.rules).unwrap();
        assert!(!changes.is_empty());
        let mut out = Vec::new();
        rules_cmd(&root, "t-3", &strict, false, "2026-10-13", &mut out).unwrap();
        let s = String::from_utf8(out).unwrap();
        assert!(
            s.contains(&format!("{} record(s) change tier", changes.len())),
            "{s}"
        );
        assert_eq!(
            load(&root, "t-3").unwrap().rules_version.as_deref(),
            Some(v.as_str())
        );
        rules_cmd(&root, "t-3", &strict, true, "2026-10-13", &mut Vec::new()).unwrap();
        let c = load(&root, "t-3").unwrap();
        assert_eq!(c.rules_version.as_deref(), Some(pin.as_str()));
        let last = &c.decisions.last().unwrap().text;
        assert!(
            last.contains(&format!("rules re-pinned: {v} → {pin}")),
            "{last}"
        );
        assert!(last.contains("changed tier"), "{last}");
        assert_eq!(
            case_rules(&root, &c).unwrap().set.thresholds.suggestive,
            300
        );
        assert!(
            tier_changes(&root, &c, &strict.rules).unwrap().is_empty(),
            "renders with the pinned rules"
        );

        // A case file from before pinning renders with the current rules and
        // says so; re-pinning it works too.
        update(&root, "t-3", |c| {
            c.rules_version = None;
            Ok(())
        })
        .unwrap();
        let toml = std::fs::read_to_string(root.join("t-3").join("case.toml")).unwrap();
        assert!(!toml.contains("rules_version"), "{toml}");
        let mut buf = Vec::new();
        status(&root, "t-3", &mut buf).unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("rules not pinned"), "{s}");
        rules_cmd(&root, "t-3", &current, true, "2026-10-14", &mut Vec::new()).unwrap();
        let c = load(&root, "t-3").unwrap();
        assert_eq!(c.rules_version.as_deref(), Some(v.as_str()));
        assert!(
            c.decisions
                .last()
                .unwrap()
                .text
                .contains(&format!("not pinned → {v}; no record changed tier"))
        );

        // A pin is a name in the rules directory, never a path.
        let mut bad = c.clone();
        bad.rules_version = Some("../../etc/x".into());
        assert!(case_rules(&root, &bad).is_err());
        cleanup(&root);
    }
}
