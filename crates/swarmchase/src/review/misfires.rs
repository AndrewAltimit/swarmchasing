//! `review misfires`: rules whose hits fall mostly on records the admin
//! labelled benign.
//!
//! The review file's records are analysed with the current rules (or
//! `--rules`), and each rule's hits are counted by the admin's label: agent,
//! benign, unsure, and benign records it helped flag at suggestive or above.
//! A rule is listed when at least `--min-benign` benign records fired it and
//! benign records are at least `--share` of its agent and benign hits. Rules
//! a model flagged as misfiring (`misfires` in a suggestions file) are
//! counted beside them.
//!
//! For each listed rule, the benign records it fired on (flagged ones first)
//! are written to `<data>/labels/hard-negative-candidates.ndjson`, with an
//! id list beside it for `review tuned`. They are real records: the admin
//! rebuilds the shape with `.example` hosts before anything goes in
//! `samples/eval/` (docs/guides/writing-rules.md). Nothing is written under
//! `samples/` or `rules/`.

use super::hosted::{self, Loaded, check_in_data};
use super::{Review, ReviewStore};
use anyhow::{Context, Result};
use sc_core::{Analysis, Observation, Tier, defang};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::path::{Path, PathBuf};

#[derive(clap::Args)]
pub struct MisfiresArgs {
    /// Data directory (the watch's `--out`).
    #[arg(short, long, default_value = "data", env = "SWARMCHASE_DATA")]
    data: PathBuf,
    /// Read this labeller's file (`reviewed-<name>.ndjson`) instead of
    /// `reviewed.ndjson`.
    #[arg(long)]
    labeller: Option<String>,
    #[arg(long)]
    rules: Option<PathBuf>,
    /// List a rule when at least this many benign records fired it...
    #[arg(long, default_value_t = 3)]
    min_benign: usize,
    /// ...and benign records are at least this share (0..1) of its agent
    /// and benign hits.
    #[arg(long, default_value_t = 0.5)]
    share: f64,
    /// Candidate hard negatives to write per listed rule.
    #[arg(long, default_value_t = 5)]
    per_rule: usize,
    /// Where the candidates go, inside the data directory. Default:
    /// `<data>/labels/hard-negative-candidates.ndjson`.
    #[arg(short, long)]
    out: Option<PathBuf>,
}

/// One rule's hits on reviewed records, by the admin's label.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct RuleRow {
    pub id: String,
    pub agent: usize,
    pub benign: usize,
    pub unsure: usize,
    /// Benign records it fired on that are at suggestive or above.
    pub benign_flagged: usize,
    /// Suggestions naming it a misfire, and of those, on admin-benign records.
    pub model_flags: usize,
    pub model_flags_benign: usize,
}

impl RuleRow {
    /// Benign share of its agent and benign hits.
    pub fn benign_share(&self) -> Option<f64> {
        let n = self.agent + self.benign;
        (n > 0).then(|| self.benign as f64 / n as f64)
    }

    pub fn listed(&self, min_benign: usize, share: f64) -> bool {
        self.benign >= min_benign && self.benign_share().is_some_and(|s| s >= share)
    }
}

/// Every rule that fired on a reviewed record, with its counts.
pub fn rows(store: &ReviewStore, a: &Analysis, loaded: &Loaded) -> Vec<RuleRow> {
    let mut by: BTreeMap<String, RuleRow> = BTreeMap::new();
    let mut seen = BTreeSet::new();
    for r in &a.results {
        let Some(rev) = store.entries.get(&r.obs.id) else {
            continue;
        };
        if !seen.insert(r.obs.id.as_str()) {
            continue;
        }
        let ids: BTreeSet<&str> = r.hits.iter().map(|h| h.rule_id.as_str()).collect();
        for id in ids {
            let row = by.entry(id.to_string()).or_insert_with(|| RuleRow {
                id: id.to_string(),
                ..Default::default()
            });
            match rev.label.as_str() {
                "agent" => row.agent += 1,
                "benign" => {
                    row.benign += 1;
                    if r.tier >= Tier::Suggestive {
                        row.benign_flagged += 1;
                    }
                }
                "unsure" => row.unsure += 1,
                _ => {}
            }
        }
    }
    for s in &loaded.all {
        let benign = store
            .entries
            .get(&s.id)
            .is_some_and(|r| r.label == "benign");
        for m in &s.misfires {
            let row = by.entry(m.clone()).or_insert_with(|| RuleRow {
                id: m.clone(),
                ..Default::default()
            });
            row.model_flags += 1;
            if benign {
                row.model_flags_benign += 1;
            }
        }
    }
    let mut out: Vec<RuleRow> = by.into_values().collect();
    out.sort_by(|x, y| {
        (y.benign_flagged, y.benign, &x.id).cmp(&(x.benign_flagged, x.benign, &y.id))
    });
    out
}

/// A benign record a listed rule fired on, for the admin to rebuild as a
/// synthetic hard negative.
#[derive(Debug, Serialize)]
pub struct Candidate {
    #[serde(flatten)]
    pub record: Observation,
    pub label: &'static str,
    /// The listed rules it fired.
    pub hard_negative_for: Vec<String>,
    /// What the current rules make of it.
    pub tier: Tier,
    pub score: i32,
    pub rules: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub admin_note: Option<String>,
    /// From a source a hosted model may see ([`hosted::HOSTED_SOURCES`]);
    /// any other line (operator logs) is for the admin or a local model only.
    pub hosted_model_may_see: bool,
    pub candidate: &'static str,
}

pub const CANDIDATE_NOTE: &str = "real record from the data directory: rebuild the shape with .example hosts and a synthetic cite before it goes in samples/eval (docs/guides/writing-rules.md#writing-eval-records)";

/// Up to `per_rule` benign records per listed rule, flagged ones first, one
/// line per record.
pub fn candidates(
    store: &ReviewStore,
    a: &Analysis,
    listed: &[&RuleRow],
    per_rule: usize,
) -> Vec<Candidate> {
    let mut picked: BTreeMap<&str, (usize, BTreeSet<String>)> = BTreeMap::new();
    for row in listed {
        let mut hits: Vec<usize> = (0..a.results.len())
            .filter(|&i| {
                let r = &a.results[i];
                store
                    .entries
                    .get(&r.obs.id)
                    .is_some_and(|rev: &Review| rev.label == "benign")
                    && r.hits.iter().any(|h| h.rule_id == row.id)
            })
            .collect();
        hits.sort_by_key(|&i| {
            let r = &a.results[i];
            (
                std::cmp::Reverse(r.tier),
                std::cmp::Reverse(r.score),
                r.obs.id.clone(),
            )
        });
        hits.dedup_by_key(|i| a.results[*i].obs.id.clone());
        for i in hits.into_iter().take(per_rule) {
            picked
                .entry(a.results[i].obs.id.as_str())
                .or_insert((i, BTreeSet::new()))
                .1
                .insert(row.id.clone());
        }
    }
    picked
        .into_values()
        .map(|(i, rules)| {
            let r = &a.results[i];
            let mut all: Vec<String> = r.hits.iter().map(|h| h.rule_id.clone()).collect();
            all.sort();
            all.dedup();
            Candidate {
                record: r.obs.clone(),
                label: "benign",
                hard_negative_for: rules.into_iter().collect(),
                tier: r.tier,
                score: r.score,
                rules: all,
                admin_note: store.entries[&r.obs.id].note.clone(),
                hosted_model_may_see: hosted::hosted_ok(&r.obs.source),
                candidate: CANDIDATE_NOTE,
            }
        })
        .collect()
}

pub fn render(
    rows: &[RuleRow],
    min_benign: usize,
    share: f64,
    out: &mut impl Write,
) -> Result<Vec<String>> {
    let listed: Vec<&RuleRow> = rows
        .iter()
        .filter(|r| r.listed(min_benign, share))
        .collect();
    writeln!(
        out,
        "rules whose reviewed hits are mostly benign (at least {min_benign} benign, benign share at least {:.0}%):",
        share * 100.0
    )?;
    let header = format!(
        "  {:<36} {:>6} {:>6} {:>6} {:>8} {:>7} {:>7}",
        "rule", "agent", "benign", "unsure", "b-flag", "share", "model"
    );
    if listed.is_empty() {
        writeln!(out, "  none")?;
    } else {
        writeln!(out, "{header}")?;
    }
    let line = |r: &RuleRow| {
        format!(
            "  {:<36} {:>6} {:>6} {:>6} {:>8} {:>7} {:>7}",
            r.id,
            r.agent,
            r.benign,
            r.unsure,
            r.benign_flagged,
            r.benign_share()
                .map_or("n/a".into(), |s| format!("{:.0}%", s * 100.0)),
            if r.model_flags > 0 {
                format!("{}/{}", r.model_flags_benign, r.model_flags)
            } else {
                "-".into()
            }
        )
    };
    for r in &listed {
        writeln!(out, "{}", line(r))?;
    }
    let flagged_only: Vec<&RuleRow> = rows
        .iter()
        .filter(|r| r.model_flags > 0 && !r.listed(min_benign, share))
        .collect();
    if !flagged_only.is_empty() {
        writeln!(
            out,
            "flagged by a model but under the threshold (model column: on admin-benign records / all flags):"
        )?;
        for r in &flagged_only {
            writeln!(out, "{}", line(r))?;
        }
    }
    writeln!(
        out,
        "b-flag: benign records the rule fired on that are at suggestive or above; those would be false positives in a notice."
    )?;
    Ok(listed.iter().map(|r| r.id.clone()).collect())
}

fn write_candidates(out: &Path, cands: &[Candidate]) -> Result<PathBuf> {
    let mut text = String::new();
    for c in cands {
        text.push_str(&serde_json::to_string(c)?);
        text.push('\n');
    }
    std::fs::write(out, text).with_context(|| format!("writing {}", out.display()))?;
    let ids = out.with_extension("ids");
    let mut list = String::from(
        "# record ids in the hard-negative candidates; `swarmchase review tuned <this file>` once a rule change looked at them\n",
    );
    for c in cands {
        list.push_str(&c.record.id);
        list.push('\n');
    }
    std::fs::write(&ids, list).with_context(|| format!("writing {}", ids.display()))?;
    Ok(ids)
}

/// `review misfires`.
pub fn run(args: &MisfiresArgs) -> Result<()> {
    let path = ReviewStore::path_for(&args.data, args.labeller.as_deref())?;
    let store = ReviewStore::open(path)?;
    let rules = crate::pinning::RulesText::load(args.rules.as_deref())?;
    let a = sc_core::analyze(
        store.entries.values().map(|r| r.record.clone()).collect(),
        &rules.rules,
    );
    let loaded = hosted::load_suggestions(&args.data.join("labels"), &a)?;
    let mut stdout = std::io::stdout();
    writeln!(
        stdout,
        "{} reviewed record(s) in {}, analysed with rules {}",
        store.entries.len(),
        store.path.display(),
        a.rules_version
    )?;
    let rows = rows(&store, &a, &loaded);
    let listed_ids = render(&rows, args.min_benign, args.share, &mut stdout)?;
    if listed_ids.is_empty() {
        return Ok(());
    }
    let listed: Vec<&RuleRow> = rows.iter().filter(|r| listed_ids.contains(&r.id)).collect();
    let cands = candidates(&store, &a, &listed, args.per_rule);
    let out = args.out.clone().unwrap_or_else(|| {
        args.data
            .join("labels")
            .join("hard-negative-candidates.ndjson")
    });
    if let Some(dir) = out.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(dir).ok();
    }
    check_in_data(&args.data, &out)?;
    let ids = write_candidates(&out, &cands)?;
    writeln!(
        stdout,
        "\n{} candidate hard negative(s) written to {} (ids in {}):",
        cands.len(),
        out.display(),
        ids.display()
    )?;
    for c in cands.iter().take(20) {
        writeln!(
            stdout,
            "  {} {} · {}",
            c.record.id,
            c.hard_negative_for.join(","),
            defang(&crate::util::truncate(&c.record.url, 100))
        )?;
    }
    writeln!(
        stdout,
        "next: read each in `review --serve` or `swarmchase eval {} --show-fp 20`; rebuild the shapes worth keeping as synthetic records with `hard_negative_for` (docs/guides/writing-rules.md); fix the rule; run the eval gate; then `review tuned {}`",
        store.path.display(),
        ids.display()
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::review::hosted::Stored;
    use crate::review::{CLASS_FLAGGED, Review};
    use sc_core::{Rules, analyze};

    fn fixture() -> (Analysis, ReviewStore, PathBuf) {
        let o = |id: &str, url: &str| Observation {
            id: id.into(),
            source: "wayback".into(),
            ts: 1000,
            url: url.into(),
            ..Default::default()
        };
        let mut obs = Vec::new();
        let mut labels = Vec::new();
        // Four benign articles read through a relay, one with a quote probe
        // as well; two agent records through the same relay.
        for i in 0..4 {
            obs.push(o(
                &format!("read{i}"),
                &format!("https://r.jina.ai/https://news{i}.example/story/{i}"),
            ));
            labels.push((format!("read{i}"), "benign"));
        }
        obs.push(o(
            "readq",
            "https://r.jina.ai/https://shop.example/item?id=1%20UNION%20SELECT%20null--",
        ));
        labels.push(("readq".into(), "benign"));
        for i in 0..2 {
            obs.push(o(
                &format!("ag{i}"),
                &format!("https://r.jina.ai/https://t{i}.example/?q=1%20UNION%20SELECT%20null--"),
            ));
            labels.push((format!("ag{i}"), "agent"));
        }
        let a = analyze(obs, &Rules::default_rules());
        let data = std::env::temp_dir().join(format!("swarmchase-misfires-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&data);
        std::fs::create_dir_all(data.join("labels")).unwrap();
        let mut store = ReviewStore::open(ReviewStore::path_in(&data)).unwrap();
        for (id, label) in labels {
            let r = a.results.iter().find(|r| r.obs.id == id).unwrap();
            store.entries.insert(
                id.clone(),
                Review {
                    record: r.obs.clone(),
                    label: label.into(),
                    note: (id == "readq").then(|| "a tester".to_string()),
                    class: CLASS_FLAGGED.into(),
                    reviewed_at: "x".into(),
                    tier: r.tier,
                    score: r.score,
                    rules: vec![],
                    rules_version: a.rules_version.clone(),
                    suggested: None,
                    tuned: false,
                    grade: None,
                },
            );
        }
        (a, store, data)
    }

    #[test]
    fn mostly_benign_rules_are_listed_with_candidates() {
        let (a, store, data) = fixture();
        let loaded = Loaded {
            all: vec![Stored {
                id: "read0".into(),
                file: "suggestions-c.ndjson".into(),
                label: "benign".into(),
                reason: "r".into(),
                model: "m".into(),
                grade_seen: None,
                misfires: vec!["relay.jina".into(), "marker.never".into()],
            }],
            ..Default::default()
        };
        let rows = rows(&store, &a, &loaded);
        let jina = rows.iter().find(|r| r.id == "relay.jina").unwrap();
        assert_eq!((jina.agent, jina.benign, jina.unsure), (2, 5, 0));
        assert_eq!((jina.model_flags, jina.model_flags_benign), (1, 1));
        assert!(jina.benign_flagged >= 1, "the UNION read is flagged");
        assert!(jina.listed(3, 0.5));
        let never = rows.iter().find(|r| r.id == "marker.never").unwrap();
        assert!(!never.listed(3, 0.5));
        let union: Vec<&RuleRow> = rows.iter().filter(|r| r.id.contains("union")).collect();
        assert!(!union.is_empty());
        assert!(union.iter().all(|r| !r.listed(3, 0.5)), "{union:?}");

        let mut out = Vec::new();
        let listed = render(&rows, 3, 0.5, &mut out).unwrap();
        let out = String::from_utf8(out).unwrap();
        assert_eq!(listed, ["relay.jina"]);
        assert!(out.contains("relay.jina"), "{out}");
        assert!(out.contains("71%"), "{out}");
        assert!(
            out.contains("flagged by a model but under the threshold"),
            "{out}"
        );
        assert!(out.contains("marker.never"), "{out}");

        let l: Vec<&RuleRow> = rows.iter().filter(|r| r.id == "relay.jina").collect();
        let c = candidates(&store, &a, &l, 3);
        assert_eq!(c.len(), 3);
        assert_eq!(c[0].hard_negative_for, ["relay.jina"]);
        assert!(c.iter().all(|c| c.label == "benign"));
        let q = c
            .iter()
            .find(|c| c.record.id == "readq")
            .expect("flagged first");
        assert_eq!(q.admin_note.as_deref(), Some("a tester"));

        let file = data.join("labels").join("hard-negative-candidates.ndjson");
        check_in_data(&data, &file).unwrap();
        let ids = write_candidates(&file, &c).unwrap();
        let text = std::fs::read_to_string(&file).unwrap();
        let first: serde_json::Value = serde_json::from_str(text.lines().next().unwrap()).unwrap();
        assert_eq!(first["label"], "benign");
        assert_eq!(first["hard_negative_for"][0], "relay.jina");
        assert_eq!(first["hosted_model_may_see"], true, "wayback records");
        assert!(first["candidate"].as_str().unwrap().contains(".example"));
        let listed = sc_core::eval::split::parse_id_list(&std::fs::read_to_string(ids).unwrap());
        assert_eq!(listed.len(), 3, "`review tuned` reads the id list");
        assert!(check_in_data(&data, Path::new("samples/eval/x.ndjson")).is_err());
        std::fs::remove_dir_all(&data).unwrap();
    }
}
