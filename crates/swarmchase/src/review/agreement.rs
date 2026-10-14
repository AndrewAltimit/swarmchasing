//! `review agreement`: the admin's labels against model suggestions.
//!
//! For each model, over the records both the admin and the model labelled:
//! a confusion matrix (admin label by suggested label), raw agreement and
//! Cohen's κ, the same split by agent grade, and the suggestions that break
//! the labelling rule (`agent` below L2). The grade is the one the model saw
//! when its line records it, else the one stored with the admin's label,
//! else the grade now. Suggestions come from
//! `labels/suggestions-*.ndjson` and from `suggested` in the review file (a
//! local model's, `review --suggest`). Admin agent labels below the rule,
//! each with the grade stored with it (or the grade now, for a line that
//! stores none, said as such) and its noted reason, and the rules models
//! flagged as misfires are listed after.
//!
//! The records are analysed from the review file itself, so the grade now
//! is over the reviewed records, not the whole store; a cluster with
//! unreviewed members may grade differently in `review --serve`.

use super::hosted::{self, Loaded, code_allows_agent};
use super::{GradeFrom, LabelGrade, Review, ReviewStore};
use anyhow::Result;
use sc_core::Analysis;
use std::collections::BTreeMap;
use std::io::Write;
use std::path::PathBuf;

#[derive(clap::Args)]
pub struct AgreementArgs {
    /// Data directory (the watch's `--out`).
    #[arg(short, long, default_value = "data", env = "SWARMCHASE_DATA")]
    data: PathBuf,
    /// Compare this labeller's file (`reviewed-<name>.ndjson`) instead of
    /// `reviewed.ndjson`.
    #[arg(long)]
    labeller: Option<String>,
    /// Rules file (defaults to the bundled rules/default.toml).
    #[arg(long)]
    rules: Option<PathBuf>,
    /// List up to this many record ids per finding.
    #[arg(long, default_value_t = 10)]
    show: usize,
}

const LABELS: [&str; 3] = ["agent", "benign", "unsure"];

/// One record both the admin and a model labelled.
#[derive(Debug, Clone, PartialEq)]
pub struct Pair {
    pub id: String,
    pub admin: String,
    pub suggested: String,
    /// The grade the model saw, else the one stored with the admin's
    /// label, else the grade now; `none` when ungraded.
    pub grade: String,
    /// Whether `grade` is the one the model saw.
    pub seen: bool,
    /// Whether `grade` is the one stored with the admin's label.
    pub stored: bool,
}

/// An admin `agent` label below the labelling rule.
#[derive(Debug, Clone, PartialEq)]
pub struct AdminBreak {
    pub id: String,
    /// The grade the label was judged against.
    pub grade: LabelGrade,
    pub from: GradeFrom,
    /// The admin's reason, from the label's note.
    pub note: Option<String>,
}

#[derive(Debug, Default)]
pub struct Report {
    /// Pairs by model.
    pub models: BTreeMap<String, Vec<Pair>>,
    /// Suggestion lines for records the admin has not labelled.
    pub unlabelled: usize,
    /// Admin `agent` labels below L2, by the grade stored with each, else
    /// the grade now.
    pub admin_breaks: Vec<AdminBreak>,
    /// Rule id to (suggestions flagging it, of which admin benign, admin agent).
    pub misfires: BTreeMap<String, (usize, usize, usize)>,
}

impl Report {
    /// `agent` suggestions on records graded below L2, for `model`.
    pub fn breaks<'a>(&'a self, model: &str) -> Vec<&'a Pair> {
        self.models
            .get(model)
            .map(|p| {
                p.iter()
                    .filter(|p| p.suggested == "agent" && !code_allows_agent(&p.grade))
                    .collect()
            })
            .unwrap_or_default()
    }
}

/// Pair the admin's labels in `store` with every suggestion: the files'
/// (`loaded`) and those saved with the labels.
pub fn compare(store: &ReviewStore, a: &Analysis, loaded: &Loaded) -> Report {
    let idx: BTreeMap<&str, usize> = a
        .results
        .iter()
        .enumerate()
        .map(|(i, r)| (r.obs.id.as_str(), i))
        .collect();
    let now = |id: &str| -> String {
        idx.get(id)
            .and_then(|&i| hosted::grade_code(a, i))
            .unwrap_or("none")
            .to_string()
    };
    // The grade stored with the admin's label, when the line has one.
    let stored = |id: &str| -> Option<String> {
        store
            .entries
            .get(id)
            .and_then(|r| r.grade.as_ref())
            .map(|g| g.code().replace("no grade", "none"))
    };
    let at_label = |id: &str| -> (String, bool) {
        match stored(id) {
            Some(g) => (g, true),
            None => (now(id), false),
        }
    };
    let admin = |id: &str| -> Option<&Review> {
        store
            .entries
            .get(id)
            .filter(|r| LABELS.contains(&r.label.as_str()))
    };
    let mut rep = Report::default();
    // (model, id) -> pair; a later suggestion for the same record replaces
    // an earlier one, as on the page.
    let mut pairs: BTreeMap<(String, String), Pair> = BTreeMap::new();
    for r in store.entries.values() {
        let Some(s) = &r.suggested else { continue };
        if !LABELS.contains(&r.label.as_str()) {
            continue;
        }
        let (grade, stored) = at_label(&r.record.id);
        pairs.insert(
            (s.model.clone(), r.record.id.clone()),
            Pair {
                id: r.record.id.clone(),
                admin: r.label.clone(),
                suggested: s.label.clone(),
                grade,
                seen: false,
                stored,
            },
        );
    }
    for s in &loaded.all {
        let Some(r) = admin(&s.id) else {
            rep.unlabelled += 1;
            continue;
        };
        for m in &s.misfires {
            let e = rep.misfires.entry(m.clone()).or_default();
            e.0 += 1;
            match r.label.as_str() {
                "benign" => e.1 += 1,
                "agent" => e.2 += 1,
                _ => {}
            }
        }
        let (grade, seen, stored) = match &s.grade_seen {
            Some(g) if !g.is_empty() => (g.clone(), true, false),
            _ => {
                let (g, stored) = at_label(&s.id);
                (g, false, stored)
            }
        };
        pairs.insert(
            (s.model.clone(), s.id.clone()),
            Pair {
                id: s.id.clone(),
                admin: r.label.clone(),
                suggested: s.label.clone(),
                grade,
                seen,
                stored,
            },
        );
    }
    for ((model, _), p) in pairs {
        rep.models.entry(model).or_default().push(p);
    }
    rep.admin_breaks = store
        .entries
        .values()
        .filter(|r| r.label == "agent")
        .filter_map(|r| {
            let now = || {
                idx.get(r.record.id.as_str())
                    .map(|&i| LabelGrade::of(a, i, &r.label))
            };
            let (grade, from) = r.judged_grade(now)?;
            grade.below_rule().then(|| AdminBreak {
                id: r.record.id.clone(),
                grade,
                from,
                note: r.note.clone(),
            })
        })
        .collect();
    rep
}

fn pct(k: usize, n: usize) -> String {
    if n == 0 {
        "n/a".into()
    } else {
        format!("{:.1}%", k as f64 * 100.0 / n as f64)
    }
}

pub fn render(rep: &Report, show: usize, out: &mut impl Write) -> Result<()> {
    if rep.models.is_empty() {
        writeln!(
            out,
            "no suggestion pairs with an admin label ({} suggestion line(s) for records not labelled yet)",
            rep.unlabelled
        )?;
    }
    for (model, pairs) in &rep.models {
        let agree = pairs.iter().filter(|p| p.admin == p.suggested).count();
        let kappa: Vec<(&str, &str)> = pairs
            .iter()
            .map(|p| (p.admin.as_str(), p.suggested.as_str()))
            .collect();
        let kappa = sc_core::eval::stats::cohen_kappa(&kappa)
            .map_or("undefined".into(), |k| format!("{k:.3}"));
        writeln!(
            out,
            "\nmodel {model}: n {} · agree {agree} ({}) · κ {kappa}",
            pairs.len(),
            pct(agree, pairs.len())
        )?;
        writeln!(out, "  admin \\ suggested   agent  benign  unsure")?;
        for a in LABELS {
            let row: Vec<String> = LABELS
                .iter()
                .map(|s| {
                    let n = pairs
                        .iter()
                        .filter(|p| p.admin == a && p.suggested == *s)
                        .count();
                    format!("{n:>6}")
                })
                .collect();
            writeln!(out, "  {a:<18} {}", row.join("  "))?;
        }
        let seen = pairs.iter().filter(|p| p.seen).count();
        let stored = pairs.iter().filter(|p| p.stored).count();
        writeln!(
            out,
            "  by grade ({seen} of {} at the grade the model saw, {stored} at the grade stored with the admin's label, the rest at the grade now):",
            pairs.len()
        )?;
        let mut grades: BTreeMap<&str, Vec<&Pair>> = BTreeMap::new();
        for p in pairs {
            grades.entry(p.grade.as_str()).or_default().push(p);
        }
        for (g, ps) in &grades {
            let agree = ps.iter().filter(|p| p.admin == p.suggested).count();
            let count = |who: fn(&Pair) -> &str, l: &str| ps.iter().filter(|p| who(p) == l).count();
            writeln!(
                out,
                "    {g:<5} n {:>4} · agree {:>4} ({}) · suggested agent {} benign {} unsure {} · admin agent {} benign {} unsure {}",
                ps.len(),
                agree,
                pct(agree, ps.len()),
                count(|p| &p.suggested, "agent"),
                count(|p| &p.suggested, "benign"),
                count(|p| &p.suggested, "unsure"),
                count(|p| &p.admin, "agent"),
                count(|p| &p.admin, "benign"),
                count(|p| &p.admin, "unsure"),
            )?;
        }
        let breaks = rep.breaks(model);
        writeln!(
            out,
            "  labelling rule: {} agent suggestion(s) below L2{}",
            breaks.len(),
            if breaks.is_empty() {
                ""
            } else {
                " (the page shows them as unsure; unsure is the most the rule allows)"
            }
        )?;
        for p in breaks.iter().take(show) {
            writeln!(out, "    {} grade {} · admin {}", p.id, p.grade, p.admin)?;
        }
        let wrong: Vec<&Pair> = pairs
            .iter()
            .filter(|p| p.admin != p.suggested && p.admin != "unsure" && p.suggested != "unsure")
            .collect();
        if !wrong.is_empty() {
            writeln!(
                out,
                "  opposite labels (agent against benign): {}",
                wrong.len()
            )?;
            for p in wrong.iter().take(show) {
                writeln!(
                    out,
                    "    {} grade {} · admin {} · suggested {}",
                    p.id, p.grade, p.admin, p.suggested
                )?;
            }
        }
    }
    if !rep.admin_breaks.is_empty() {
        let now = rep
            .admin_breaks
            .iter()
            .filter(|b| b.from == GradeFrom::Now)
            .count();
        writeln!(
            out,
            "\nadmin agent labels below L2, exceptions to the labelling rule: {} ({} at the grade stored with the label, {now} at the grade now, their lines storing none). Each needs a reason in its note; otherwise relabel it unsure:",
            rep.admin_breaks.len(),
            rep.admin_breaks.len() - now,
        )?;
        for b in rep.admin_breaks.iter().take(show) {
            writeln!(
                out,
                "  {} · {} (grade {}) · {}",
                b.id,
                b.grade.short(),
                b.from.word(),
                b.note
                    .as_deref()
                    .map_or("no reason noted".into(), |n| format!(
                        "reason: {}",
                        crate::suggest::defang_all(n)
                    ))
            )?;
        }
    }
    if !rep.misfires.is_empty() {
        writeln!(
            out,
            "\nrules models flagged as misfires (suggestions flagging · admin benign · admin agent); `review misfires` weighs them against the labels:"
        )?;
        let mut m: Vec<(&String, &(usize, usize, usize))> = rep.misfires.iter().collect();
        m.sort_by_key(|(id, n)| (std::cmp::Reverse(n.0), *id));
        for (id, (n, b, ag)) in m {
            writeln!(out, "  {id:<36} {n:>4} · {b:>4} · {ag:>4}")?;
        }
    }
    Ok(())
}

/// `review agreement`.
pub fn run(args: &AgreementArgs) -> Result<()> {
    let path = ReviewStore::path_for(&args.data, args.labeller.as_deref())?;
    let store = ReviewStore::open(path)?;
    let rules = crate::pinning::RulesText::load(args.rules.as_deref())?;
    let a = sc_core::analyze(
        store.entries.values().map(|r| r.record.clone()).collect(),
        &rules.rules,
    );
    let labels = args.data.join("labels");
    let loaded = hosted::load_suggestions(&labels, &a)?;
    let mut out = std::io::stdout();
    writeln!(
        out,
        "{} admin label(s) in {} · {} suggestion line(s) on reviewed records from {} ({} on records not reviewed, {} invalid, {} for withheld sources)",
        store.entries.len(),
        store.path.display(),
        loaded.all.len(),
        labels.join("suggestions-*.ndjson").display(),
        loaded.dropped - loaded.withheld,
        loaded.invalid,
        loaded.withheld
    )?;
    let mut rep = compare(&store, &a, &loaded);
    // Lines for records outside the review file were dropped on load.
    rep.unlabelled += loaded.dropped - loaded.withheld;
    render(&rep, args.show, &mut out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::review::hosted::Stored;
    use crate::review::{CLASS_FLAGGED, Review};
    use crate::suggest::Suggestion;
    use sc_core::{Observation, Rules, analyze};

    /// Two ungraded plain records, one L2 record (placeholder residue), one
    /// payload-only record.
    pub(crate) fn fixture() -> (Analysis, ReviewStore) {
        let o = |id: &str, url: &str| Observation {
            id: id.into(),
            source: "wayback".into(),
            ts: 1000,
            url: url.into(),
            ..Default::default()
        };
        let a = analyze(
            vec![
                o("p1", "https://www.example.org/a"),
                o("p2", "https://www.example.org/b"),
                o(
                    "l2",
                    "https://w.example/login?user=admin%27--&key=YOUR_API_KEY",
                ),
                o(
                    "l0",
                    "https://r.jina.ai/https://t.example/?q=1%20UNION%20SELECT%20null--",
                ),
            ],
            &Rules::default_rules(),
        );
        let dir = std::env::temp_dir().join(format!(
            "swarmchase-agreement-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let mut store = ReviewStore::open(ReviewStore::path_in(&dir)).unwrap();
        for (id, label, sug) in [
            ("p1", "benign", Some("benign")),
            ("p2", "benign", None),
            ("l2", "agent", None),
            ("l0", "agent", None),
        ] {
            let r = a.results.iter().find(|r| r.obs.id == id).unwrap();
            store.entries.insert(
                id.into(),
                Review {
                    record: r.obs.clone(),
                    label: label.into(),
                    note: None,
                    class: CLASS_FLAGGED.into(),
                    reviewed_at: "x".into(),
                    tier: r.tier,
                    score: r.score,
                    rules: r.hits.iter().map(|h| h.rule_id.clone()).collect(),
                    rules_version: a.rules_version.clone(),
                    suggested: sug.map(|l| Suggestion {
                        label: l.into(),
                        reason: "r".into(),
                        model: "local".into(),
                    }),
                    tuned: false,
                    grade: None,
                },
            );
        }
        (a, store)
    }

    fn stored(id: &str, label: &str, grade: Option<&str>, misfires: &[&str]) -> Stored {
        Stored {
            id: id.into(),
            file: "suggestions-c.ndjson".into(),
            label: label.into(),
            reason: "r".into(),
            model: "claude".into(),
            grade_seen: grade.map(str::to_string),
            misfires: misfires.iter().map(|m| m.to_string()).collect(),
        }
    }

    #[test]
    fn confusion_grades_and_rule_breaks() {
        let (a, store) = fixture();
        let grade = |id: &str| {
            let i = a.results.iter().position(|r| r.obs.id == id).unwrap();
            hosted::grade_code(&a, i).unwrap_or("none").to_string()
        };
        assert_eq!(grade("l2"), "L2");
        assert!(!code_allows_agent(&grade("l0")), "{}", grade("l0"));
        let loaded = Loaded {
            all: vec![
                stored("p1", "unsure", None, &[]),
                stored("p2", "benign", None, &[]),
                stored("l2", "agent", Some("L2"), &[]),
                // Seen at L1: an agent suggestion that breaks the rule.
                stored("l0", "agent", Some("L1"), &["relay.jina"]),
                stored("not-reviewed", "agent", None, &[]),
            ],
            ..Default::default()
        };
        let rep = compare(&store, &a, &loaded);
        assert_eq!(rep.unlabelled, 1);
        assert_eq!(rep.models.len(), 2, "{:?}", rep.models.keys());
        let local = &rep.models["local"];
        assert_eq!(local.len(), 1);
        assert_eq!(
            (local[0].admin.as_str(), local[0].suggested.as_str()),
            ("benign", "benign")
        );
        let c = &rep.models["claude"];
        assert_eq!(c.len(), 4);
        let l0 = c.iter().find(|p| p.id == "l0").unwrap();
        assert_eq!((l0.grade.as_str(), l0.seen), ("L1", true));
        let p2 = c.iter().find(|p| p.id == "p2").unwrap();
        assert_eq!((p2.grade.as_str(), p2.seen), ("none", false));
        let breaks: Vec<&str> = rep.breaks("claude").iter().map(|p| p.id.as_str()).collect();
        assert_eq!(breaks, ["l0"]);
        // The admin's own agent label on a payload-only record breaks the rule.
        assert_eq!(rep.admin_breaks.len(), 1);
        assert_eq!(rep.admin_breaks[0].id, "l0");
        assert_eq!(
            rep.admin_breaks[0].from,
            GradeFrom::Now,
            "an older line: graded now"
        );
        assert_eq!(rep.misfires["relay.jina"], (1, 0, 1));

        let mut out = Vec::new();
        render(&rep, 10, &mut out).unwrap();
        let out = String::from_utf8(out).unwrap();
        assert!(out.contains("model claude: n 4 · agree 3 (75.0%)"), "{out}");
        assert!(
            out.contains("  agent                   2       0       0"),
            "{out}"
        );
        assert!(
            out.contains("  benign                  0       1       1"),
            "{out}"
        );
        assert!(
            out.contains("by grade (2 of 4 at the grade the model saw"),
            "{out}"
        );
        assert!(out.contains("    L1    n    1 · agree    1"), "{out}");
        assert!(out.contains("1 agent suggestion(s) below L2"), "{out}");
        assert!(out.contains("    l0 grade L1 · admin agent"), "{out}");
        assert!(
            out.contains("admin agent labels below L2, exceptions to the labelling rule: 1 (0 at the grade stored with the label, 1 at the grade now"),
            "{out}"
        );
        assert!(out.contains("  l0 · L"), "{out}");
        assert!(out.contains("(grade now) · no reason noted"), "{out}");
        assert!(out.contains("relay.jina"), "{out}");
    }

    #[test]
    fn stored_grades_are_used_before_the_grade_now() {
        let (a, mut store) = fixture();
        let grade_now = |id: &str| {
            let i = a.results.iter().position(|r| r.obs.id == id).unwrap();
            LabelGrade::of(&a, i, "agent")
        };
        // l2 is L2 now, but was labelled agent when its grade was L1: the
        // stored grade marks it an exception, with its reason.
        let mut then = grade_now("l2");
        assert!(then.agent_allowed);
        then.code = Some("L1".into());
        then.agent_allowed = false;
        then.rule = Some(crate::review::BELOW_L2.into());
        let l2 = store.entries.get_mut("l2").unwrap();
        l2.grade = Some(then);
        l2.note = Some("same run as https://t.example".into());
        // l0 stores the grade it was labelled at, below L2.
        store.entries.get_mut("l0").unwrap().grade = Some(grade_now("l0"));
        let loaded = Loaded {
            all: vec![stored("l2", "agent", None, &[])],
            ..Default::default()
        };
        let rep = compare(&store, &a, &loaded);
        let p = &rep.models["claude"][0];
        assert_eq!((p.grade.as_str(), p.seen, p.stored), ("L1", false, true));
        let ids: Vec<(&str, GradeFrom)> = rep
            .admin_breaks
            .iter()
            .map(|b| (b.id.as_str(), b.from))
            .collect();
        assert_eq!(ids, [("l0", GradeFrom::Stored), ("l2", GradeFrom::Stored)]);
        let mut out = Vec::new();
        render(&rep, 10, &mut out).unwrap();
        let out = String::from_utf8(out).unwrap();
        assert!(
            out.contains("1 at the grade stored with the admin's label"),
            "{out}"
        );
        assert!(
            out.contains("exceptions to the labelling rule: 2 (2 at the grade stored"),
            "{out}"
        );
        assert!(
            out.contains("(grade stored) · reason: same run as hxxps://t[.]example"),
            "{out}"
        );
    }
}
