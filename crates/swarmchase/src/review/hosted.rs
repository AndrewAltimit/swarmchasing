//! Label suggestions from a hosted model.
//!
//! Policy (docs/policies.md, machine help with labelling): a model the admin
//! does not control may see the public records in [`HOSTED_SOURCES`] (web
//! archive indexes and urlquery), for private labelling only. Operator
//! access logs and any source not on the list are withheld, so a new
//! collector is withheld until someone adds it here on purpose.
//!
//! `review --export-hosted <file>` writes the queue's allowed records as the
//! same text a local model gets ([`crate::suggest::record_text`]): defanged,
//! no IP addresses. Each line also carries, as fields, what the labelling
//! rule reads: the agent grade, what it was read from (the cluster, or the
//! record alone), whether it allows `agent` (L2 or higher), its signals,
//! counter-signals and caps, and the rules that fired. The file must be
//! inside the data directory; `--batch-size` splits it into numbered files
//! that keep each review group whole.
//!
//! The model's answers go in `<data>/labels/suggestions-<name>.ndjson`, one
//! `{"id", "label", "reason", "model"}` per line, optionally with `grade`
//! (the grade the model saw) and `misfires` (rule ids it thinks fired
//! wrongly). `review check-suggestions` validates a file against its export,
//! and `review --serve` shows the suggestions beside each record. A
//! suggestion is saved beside the admin's label as `suggested`, never as it;
//! one for a record outside [`HOSTED_SOURCES`] is dropped when the file is
//! read, and an `agent` suggestion on a record now graded below L2 is shown
//! as `unsure`, since that is the most the labelling rule allows.

use super::Item;
use crate::suggest::{Suggestion, defang_all};
use crate::util::truncate;
use anyhow::{Context, Result, bail};
use sc_core::{AgentAssessment, AgentLevel, Analysis};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

/// Record sources a hosted model may see: public web archive indexes and urlquery.
pub const HOSTED_SOURCES: &[&str] = &["wayback", "arquivo", "memento", "commoncrawl", "urlquery"];

pub fn hosted_ok(source: &str) -> bool {
    HOSTED_SOURCES.contains(&source)
}

/// The grade the labelling rule reads for record `idx`: its cluster's, or
/// its own when it has no cluster, and which of the two (`cluster`,
/// `record`, or `none` for an ungraded record).
pub fn grade_of(a: &Analysis, idx: usize) -> (Option<&AgentAssessment>, &'static str) {
    let r = &a.results[idx];
    match (r.cluster, &r.agent) {
        (Some(c), _) => (Some(&a.clusters[c].agent), "cluster"),
        (None, Some(g)) => (Some(g), "record"),
        (None, None) => (None, "none"),
    }
}

/// The grade's code (`L0` .. `L4`), `None` when ungraded.
pub fn grade_code(a: &Analysis, idx: usize) -> Option<&'static str> {
    grade_of(a, idx).0.map(|g| g.level.code())
}

/// Whether the labelling rule allows `agent` at this grade: L2 or higher.
pub fn agent_allowed(level: Option<AgentLevel>) -> bool {
    level.is_some_and(|l| l >= AgentLevel::ModelWritten)
}

/// Whether a grade code (`L0` .. `L5`) allows `agent`.
pub fn code_allows_agent(code: &str) -> bool {
    agent_allowed(code.parse().ok())
}

/// One exported record: its id, its review group, the text the model reads,
/// and the fields the labelling rule needs.
#[derive(Debug, Serialize, Deserialize)]
pub struct ExportLine {
    pub id: String,
    pub group: String,
    pub text: String,
    /// `L0` .. `L4`; `None` for an ungraded record (no cluster, no hits).
    #[serde(default)]
    pub grade: Option<String>,
    /// `cluster`, `record` or `none`. Empty in an export written before
    /// these fields existed.
    #[serde(default)]
    pub grade_basis: String,
    /// The grade is L2 or higher, so `agent` is a label the rule allows.
    #[serde(default)]
    pub agent_allowed: bool,
    #[serde(default)]
    pub signals: Vec<String>,
    #[serde(default)]
    pub counter: Vec<String>,
    #[serde(default)]
    pub caps: Vec<String>,
    /// Rule ids that fired on this record.
    #[serde(default)]
    pub rules: Vec<String>,
}

fn signal_text(s: &sc_core::AgentSignal) -> String {
    let mut t = format!("{} ({} record(s)", s.kind.label(), s.records);
    if !s.detail.is_empty() {
        t += &format!("; {}", defang_all(&truncate(&s.detail, 120)));
    }
    t + ")"
}

/// The export of `items`: the allowed records, and the count withheld per source.
pub fn export_lines(a: &Analysis, items: &[Item]) -> (Vec<ExportLine>, BTreeMap<String, usize>) {
    let mut lines = Vec::new();
    let mut withheld = BTreeMap::new();
    for it in items {
        let r = &a.results[it.idx];
        if !hosted_ok(&r.obs.source) {
            *withheld.entry(r.obs.source.clone()).or_default() += 1;
            continue;
        }
        let (g, basis) = grade_of(a, it.idx);
        let mut rules: Vec<String> = r.hits.iter().map(|h| h.rule_id.clone()).collect();
        rules.sort();
        rules.dedup();
        lines.push(ExportLine {
            id: r.obs.id.clone(),
            group: super::serve::group_of(a, it.idx).0,
            text: crate::suggest::record_text(a, it.idx),
            grade: g.map(|g| g.level.code().to_string()),
            grade_basis: basis.into(),
            agent_allowed: agent_allowed(g.map(|g| g.level)),
            signals: g.map_or(Vec::new(), |g| g.signals.iter().map(signal_text).collect()),
            counter: g.map_or(Vec::new(), |g| g.counter.iter().map(signal_text).collect()),
            caps: g.map_or(Vec::new(), |g| {
                g.caps.iter().map(|c| c.label().to_string()).collect()
            }),
            rules,
        });
    }
    (lines, withheld)
}

/// `lines` split into batches of about `size`, each review group whole (a
/// group larger than `size` is one batch of its own).
pub fn batches(lines: Vec<ExportLine>, size: usize) -> Vec<Vec<ExportLine>> {
    let mut groups: Vec<(String, Vec<ExportLine>)> = Vec::new();
    for l in lines {
        match groups.iter_mut().find(|(g, _)| *g == l.group) {
            Some((_, v)) => v.push(l),
            None => groups.push((l.group.clone(), vec![l])),
        }
    }
    let mut out: Vec<Vec<ExportLine>> = Vec::new();
    for (_, g) in groups {
        match out.last_mut() {
            Some(b) if !b.is_empty() && b.len() + g.len() <= size.max(1) => b.extend(g),
            _ => out.push(g),
        }
    }
    out
}

fn write_lines(out: &Path, lines: &[ExportLine]) -> Result<()> {
    let mut text = String::new();
    for l in lines {
        text.push_str(&serde_json::to_string(l)?);
        text.push('\n');
    }
    std::fs::write(out, text).with_context(|| format!("writing {}", out.display()))
}

/// `out` with `-NNN` before its extension: `hosted.ndjson` to `hosted-001.ndjson`.
fn numbered(out: &Path, n: usize) -> PathBuf {
    let stem = out.file_stem().and_then(|s| s.to_str()).unwrap_or("export");
    let ext = out.extension().and_then(|s| s.to_str()).unwrap_or("ndjson");
    out.with_file_name(format!("{stem}-{n:03}.{ext}"))
}

/// `review --export-hosted <out> [--batch-size N]`.
pub fn export(
    a: &Analysis,
    items: &[Item],
    data: &Path,
    out: &Path,
    batch: Option<usize>,
) -> Result<()> {
    check_in_data(data, out)?;
    let (lines, withheld) = export_lines(a, items);
    let n = lines.len();
    let allowed = lines.iter().filter(|l| l.agent_allowed).count();
    let written: Vec<PathBuf> = match batch {
        None => {
            write_lines(out, &lines)?;
            vec![out.to_path_buf()]
        }
        Some(size) => {
            let mut files = Vec::new();
            for (i, b) in batches(lines, size).iter().enumerate() {
                let p = numbered(out, i + 1);
                write_lines(&p, b)?;
                files.push(p);
            }
            files
        }
    };
    let held: Vec<String> = withheld.iter().map(|(s, n)| format!("{s} {n}")).collect();
    println!(
        "{n} record(s) written to {} for a hosted model ({allowed} graded L2 or higher, where `agent` is allowed); withheld: {}",
        if written.len() == 1 {
            written[0].display().to_string()
        } else {
            format!(
                "{} batch file(s), {} .. {}",
                written.len(),
                written[0].display(),
                written[written.len() - 1].display()
            )
        },
        if held.is_empty() {
            "none".into()
        } else {
            held.join(", ")
        }
    );
    println!(
        "suggestions go in {}, one {{\"id\", \"label\", \"reason\", \"model\", \"grade\", \"misfires\"}} per line; check them with `review check-suggestions --export <export> <file>`, and `review --serve` shows them",
        data.join("labels")
            .join("suggestions-<name>.ndjson")
            .display()
    );
    Ok(())
}

/// Files with record content are written only inside the data directory,
/// which stays out of git, and never under a `samples` or `rules`
/// directory, which are committed.
pub fn check_in_data(data: &Path, out: &Path) -> Result<()> {
    let root = std::fs::canonicalize(data)
        .with_context(|| format!("data directory {}", data.display()))?;
    let parent = match out.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => PathBuf::from("."),
    };
    let dir = std::fs::canonicalize(&parent)
        .with_context(|| format!("output directory {}", parent.display()))?;
    if !dir.starts_with(&root) {
        bail!(
            "{}: write it inside the data directory {}, which stays out of git",
            out.display(),
            data.display()
        );
    }
    if dir
        .components()
        .any(|c| matches!(c.as_os_str().to_str(), Some("samples" | "rules")))
    {
        bail!(
            "{}: not under a samples or rules directory; those are committed",
            out.display()
        );
    }
    Ok(())
}

/// One line of a suggestions file. Only `id` and `label` are required;
/// `grade` and `misfires` are optional, so older files still load.
#[derive(Deserialize)]
struct SuggestionLine {
    id: String,
    label: String,
    #[serde(default)]
    reason: String,
    #[serde(default)]
    model: String,
    /// The agent grade the model saw (`L0` .. `L4`).
    #[serde(default)]
    grade: Option<String>,
    /// Rule ids the model thinks fired wrongly on this record.
    #[serde(default)]
    misfires: Vec<String>,
}

/// One suggestion as read, for agreement and misfire reports.
#[derive(Debug, Clone, PartialEq)]
pub struct Stored {
    pub id: String,
    /// The file's name.
    pub file: String,
    /// The label as the model gave it (before any demotion).
    pub label: String,
    pub reason: String,
    pub model: String,
    /// The grade the model saw, when the line records it.
    pub grade_seen: Option<String>,
    pub misfires: Vec<String>,
}

/// Suggestions read from `labels/suggestions-*.ndjson`, and the lines dropped.
#[derive(Debug, Default)]
pub struct Loaded {
    /// What the page shows, one per record: the last file's.
    pub by_id: BTreeMap<String, Suggestion>,
    /// Every accepted line, in file order.
    pub all: Vec<Stored>,
    /// Lines that did not parse or gave another label.
    pub invalid: usize,
    /// Suggestions for a record outside [`HOSTED_SOURCES`] or not in the analysis.
    pub dropped: usize,
    /// Of `dropped`, those for a record from a source a hosted model may not see.
    pub withheld: usize,
    /// `agent` suggestions on a record now graded below L2, shown as `unsure`.
    pub demoted: usize,
}

/// The suggestions files in `dir`, in name order.
pub fn suggestion_files(dir: &Path) -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = match std::fs::read_dir(dir) {
        Ok(rd) => rd
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| {
                p.file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(is_suggestion_name)
            })
            .collect(),
        Err(_) => Vec::new(),
    };
    files.sort();
    files
}

fn is_suggestion_name(n: &str) -> bool {
    n.starts_with("suggestions-") && n.ends_with(".ndjson")
}

/// Every suggestions file in `dir`, in name order (a later file wins).
pub fn load_suggestions(dir: &Path, a: &Analysis) -> Result<Loaded> {
    let index: BTreeMap<&str, usize> = a
        .results
        .iter()
        .enumerate()
        .map(|(i, r)| (r.obs.id.as_str(), i))
        .collect();
    let mut out = Loaded::default();
    for f in suggestion_files(dir) {
        let file = f
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default()
            .to_string();
        let text =
            std::fs::read_to_string(&f).with_context(|| format!("reading {}", f.display()))?;
        for line in text.lines().filter(|l| !l.trim().is_empty()) {
            let Ok(s) = serde_json::from_str::<SuggestionLine>(line) else {
                out.invalid += 1;
                continue;
            };
            let label = s.label.trim().to_ascii_lowercase();
            if !matches!(label.as_str(), "agent" | "benign" | "unsure") {
                out.invalid += 1;
                continue;
            }
            let Some(&idx) = index.get(s.id.as_str()) else {
                out.dropped += 1;
                continue;
            };
            if !hosted_ok(&a.results[idx].obs.source) {
                out.dropped += 1;
                out.withheld += 1;
                continue;
            }
            let reason = s.reason.split_whitespace().collect::<Vec<_>>().join(" ");
            let reason = defang_all(&truncate(&reason, 200));
            let model = if s.model.trim().is_empty() {
                "hosted model".to_string()
            } else {
                truncate(s.model.trim(), 60)
            };
            let mut misfires: Vec<String> = s
                .misfires
                .iter()
                .map(|m| truncate(m.trim(), 80))
                .filter(|m| !m.is_empty())
                .collect();
            misfires.sort();
            misfires.dedup();
            out.all.push(Stored {
                id: s.id.clone(),
                file: file.clone(),
                label: label.clone(),
                reason: reason.clone(),
                model: model.clone(),
                grade_seen: s.grade.map(|g| truncate(g.trim(), 8)),
                misfires,
            });
            let now = grade_code(a, idx);
            let shown = if label == "agent" && !now.is_some_and(code_allows_agent) {
                out.demoted += 1;
                Suggestion {
                    label: "unsure".into(),
                    reason: truncate(
                        &format!(
                            "agent suggested, but the grade is {} (below L2), so unsure: {reason}",
                            now.unwrap_or("none")
                        ),
                        240,
                    ),
                    model,
                }
            } else {
                Suggestion {
                    label,
                    reason,
                    model,
                }
            };
            out.by_id.insert(s.id, shown);
        }
    }
    Ok(out)
}

#[derive(clap::Args)]
pub struct CheckArgs {
    /// The export the suggestions answer (`review --export-hosted`).
    #[arg(long, value_name = "FILE")]
    export: Vec<PathBuf>,
    /// Suggestions files to check.
    #[arg(required = true)]
    files: Vec<PathBuf>,
}

/// What `review check-suggestions` found in one file.
#[derive(Debug, Default, PartialEq)]
pub struct CheckReport {
    pub lines: usize,
    pub by_label: BTreeMap<String, usize>,
    /// Line number and problem; any error fails the check.
    pub errors: Vec<(usize, String)>,
    /// Error counts by kind.
    pub kinds: BTreeMap<&'static str, usize>,
    pub warnings: Vec<String>,
    /// Export ids with no suggestion in this file.
    pub missing: usize,
}

/// Check suggestions `text` against the export lines it answers.
pub fn check_text(name: &str, text: &str, export: &BTreeMap<String, ExportLine>) -> CheckReport {
    let mut r = CheckReport::default();
    if !is_suggestion_name(name) {
        r.warnings.push(format!(
            "{name}: review --serve reads only labels/suggestions-<name>.ndjson"
        ));
    }
    let old_export = export.values().any(|l| l.grade_basis.is_empty());
    if old_export {
        r.warnings.push(
            "the export has no grade fields (written by an older swarmchase): the L2 rule is not checked; export again".into(),
        );
    }
    let mut seen = BTreeSet::new();
    let mut no_grade = 0;
    for (n, line) in text.lines().enumerate().map(|(n, l)| (n + 1, l)) {
        if line.trim().is_empty() {
            continue;
        }
        r.lines += 1;
        let mut err = |kind: &'static str, m: String| {
            *r.kinds.entry(kind).or_default() += 1;
            r.errors.push((n, m));
        };
        let s = match serde_json::from_str::<SuggestionLine>(line) {
            Ok(s) => s,
            Err(e) => {
                err("format", format!("not a suggestion line: {e}"));
                continue;
            }
        };
        let label = s.label.trim().to_ascii_lowercase();
        if !matches!(label.as_str(), "agent" | "benign" | "unsure") {
            err(
                "label",
                format!(
                    "label `{}`: use agent, benign or unsure",
                    truncate(&s.label, 20)
                ),
            );
            continue;
        }
        *r.by_label.entry(label.clone()).or_default() += 1;
        if !seen.insert(s.id.clone()) {
            err("duplicate", format!("{}: a second line for this id", s.id));
        }
        if s.model.trim().is_empty() {
            err("no model", format!("{}: no model id", s.id));
        }
        if s.reason.trim().is_empty() {
            err("no reason", format!("{}: no reason", s.id));
        }
        if s.reason.contains("://") {
            err(
                "undefanged",
                format!(
                    "{}: the reason holds an undefanged URL; write hosts as a[.]b and schemes as hxxp",
                    s.id
                ),
            );
        }
        let Some(e) = export.get(&s.id) else {
            err("not in export", format!("{}: not in the export", s.id));
            continue;
        };
        if !old_export {
            if label == "agent" && !e.agent_allowed {
                err(
                    "L2 rule",
                    format!(
                        "{}: agent at grade {}; agent needs L2 or higher, so unsure is the most it allows",
                        s.id,
                        e.grade.as_deref().unwrap_or("none")
                    ),
                );
            }
            match &s.grade {
                None => no_grade += 1,
                Some(g)
                    if !g
                        .trim()
                        .eq_ignore_ascii_case(e.grade.as_deref().unwrap_or("none")) =>
                {
                    err(
                        "grade differs",
                        format!(
                            "{}: grade {} but the export says {}",
                            s.id,
                            truncate(g, 8),
                            e.grade.as_deref().unwrap_or("none")
                        ),
                    )
                }
                Some(_) => {}
            }
        }
        for m in &s.misfires {
            if !e.rules.contains(m) {
                err(
                    "misfire rule",
                    format!(
                        "{}: misfire `{}` did not fire on this record",
                        s.id,
                        truncate(m, 60)
                    ),
                );
            }
        }
    }
    if no_grade > 0 {
        r.warnings.push(format!(
            "{no_grade} line(s) without `grade`: record the grade the model saw"
        ));
    }
    r.missing = export.keys().filter(|id| !seen.contains(*id)).count();
    r
}

/// `review check-suggestions`.
pub fn check(args: &CheckArgs) -> Result<()> {
    if args.export.is_empty() {
        bail!("--export <file>: the export (or batch files) the suggestions answer");
    }
    let mut export = BTreeMap::new();
    for p in &args.export {
        let text =
            std::fs::read_to_string(p).with_context(|| format!("reading {}", p.display()))?;
        for (n, line) in text.lines().enumerate() {
            if line.trim().is_empty() {
                continue;
            }
            let l: ExportLine = serde_json::from_str(line)
                .with_context(|| format!("{}:{}: not an export line", p.display(), n + 1))?;
            export.insert(l.id.clone(), l);
        }
    }
    let mut failed = 0;
    for f in &args.files {
        let text =
            std::fs::read_to_string(f).with_context(|| format!("reading {}", f.display()))?;
        let name = f.file_name().and_then(|n| n.to_str()).unwrap_or_default();
        let r = check_text(name, &text, &export);
        let labels: Vec<String> = r.by_label.iter().map(|(l, n)| format!("{l} {n}")).collect();
        println!(
            "{}: {} line(s) ({}) · {} error(s) · {} of {} exported record(s) without a suggestion",
            f.display(),
            r.lines,
            if labels.is_empty() {
                "none".into()
            } else {
                labels.join(", ")
            },
            r.errors.len(),
            r.missing,
            export.len()
        );
        if !r.kinds.is_empty() {
            let k: Vec<String> = r.kinds.iter().map(|(k, n)| format!("{k} {n}")).collect();
            println!("  errors by kind: {}", k.join(", "));
        }
        for (n, e) in r.errors.iter().take(50) {
            println!("  line {n}: {e}");
        }
        if r.errors.len() > 50 {
            println!("  ... {} more", r.errors.len() - 50);
        }
        for w in &r.warnings {
            println!("  warning: {w}");
        }
        if !r.errors.is_empty() {
            failed += 1;
        }
    }
    if failed > 0 {
        bail!("{failed} file(s) failed the check; fix the lines above and check again");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::review::{CLASS_FLAGGED, queue};
    use sc_core::{Observation, Rules, Tier, analyze};
    use std::collections::BTreeSet;

    fn analysis() -> Analysis {
        let o = |id: &str, source: &str, url: &str| Observation {
            id: id.into(),
            source: source.into(),
            ts: 1000,
            url: url.into(),
            ip: Some("203.0.113.9".into()),
            ..Default::default()
        };
        analyze(
            vec![
                o(
                    "wayback:1",
                    "wayback",
                    "https://r.jina.ai/https://t.example/?q=1%20OR%201=1",
                ),
                o(
                    "urlquery:2",
                    "urlquery",
                    "https://r.jina.ai/https://u.example/?q=1%20OR%201=1",
                ),
                o(
                    "lines:3",
                    "lines",
                    "https://r.jina.ai/https://v.example/?q=1%20OR%201=1",
                ),
                o(
                    "wayback:4",
                    "wayback",
                    "https://w.example/login?user=admin%27--&key=YOUR_API_KEY",
                ),
            ],
            &Rules::default_rules(),
        )
    }

    fn tmp(name: &str) -> PathBuf {
        let d =
            std::env::temp_dir().join(format!("swarmchase-hosted-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join("labels")).unwrap();
        d
    }

    #[test]
    fn only_listed_sources_are_exported_and_no_ip() {
        let a = analysis();
        let items = queue(&a, &BTreeSet::new(), Tier::Suggestive, 0);
        assert_eq!(items.len(), 4);
        assert!(items.iter().all(|i| i.class == CLASS_FLAGGED));
        let (lines, withheld) = export_lines(&a, &items);
        assert_eq!(lines.len(), 3);
        let w1 = lines.iter().find(|l| l.id == "wayback:1").unwrap();
        assert!(!w1.text.contains("203.0.113.9"));
        assert!(w1.text.contains("t[.]example"), "{}", w1.text);
        assert_eq!(
            withheld.get("lines"),
            Some(&1),
            "operator logs stay withheld"
        );
        assert_eq!(withheld.len(), 1);
        assert!(!hosted_ok("urlscan") && hosted_ok("urlquery") && hosted_ok("wayback"));
    }

    #[test]
    fn the_export_carries_what_the_labelling_rule_reads() {
        let a = analysis();
        let items = queue(&a, &BTreeSet::new(), Tier::Suggestive, 0);
        let (lines, _) = export_lines(&a, &items);
        for l in &lines {
            let idx = a.results.iter().position(|r| r.obs.id == l.id).unwrap();
            assert_eq!(l.grade.as_deref(), grade_code(&a, idx));
            assert_eq!(l.grade_basis, grade_of(&a, idx).1);
            assert_eq!(
                l.agent_allowed,
                l.grade.as_deref().is_some_and(code_allows_agent)
            );
            assert!(!l.rules.is_empty());
            assert!(l.rules.windows(2).all(|w| w[0] < w[1]), "sorted, distinct");
        }
        // The placeholder is model-output residue: an unclustered record
        // graded from its own hits reaches L2.
        let w4 = lines.iter().find(|l| l.id == "wayback:4").unwrap();
        assert_eq!(w4.grade_basis, "record");
        assert_eq!(w4.grade.as_deref(), Some("L2"), "{w4:?}");
        assert!(w4.agent_allowed);
        assert!(!w4.signals.is_empty());
        let json = serde_json::to_string(w4).unwrap();
        assert!(json.contains("\"agent_allowed\":true"), "{json}");
        // An export line from before the grade fields still reads.
        let old: ExportLine = serde_json::from_str(r#"{"id":"x","group":"g","text":"t"}"#).unwrap();
        assert!(old.grade_basis.is_empty() && !old.agent_allowed);
        assert!(code_allows_agent("L2") && code_allows_agent("L4"));
        assert!(!code_allows_agent("L1") && !code_allows_agent("none"));
    }

    #[test]
    fn batches_keep_groups_whole() {
        let l = |id: &str, g: &str| ExportLine {
            id: id.into(),
            group: g.into(),
            text: String::new(),
            grade: None,
            grade_basis: "none".into(),
            agent_allowed: false,
            signals: vec![],
            counter: vec![],
            caps: vec![],
            rules: vec![],
        };
        let lines = vec![
            l("1", "a"),
            l("2", "b"),
            l("3", "a"),
            l("4", "c"),
            l("5", "c"),
            l("6", "c"),
            l("7", "d"),
        ];
        let b = batches(lines, 3);
        let ids: Vec<Vec<&str>> = b
            .iter()
            .map(|b| b.iter().map(|l| l.id.as_str()).collect())
            .collect();
        assert_eq!(ids, [vec!["1", "3", "2"], vec!["4", "5", "6"], vec!["7"]]);
        assert_eq!(
            numbered(Path::new("d/hosted.ndjson"), 2),
            Path::new("d/hosted-002.ndjson")
        );
    }

    #[test]
    fn export_stays_in_the_data_directory() {
        let d = tmp("export");
        let a = analysis();
        let items = queue(&a, &BTreeSet::new(), Tier::Suggestive, 0);
        let out = d.join("labels").join("hosted.ndjson");
        export(&a, &items, &d, &out, None).unwrap();
        let text = std::fs::read_to_string(&out).unwrap();
        assert_eq!(text.lines().count(), 3);
        export(&a, &items, &d, &out, Some(1)).unwrap();
        assert!(d.join("labels").join("hosted-001.ndjson").is_file());
        let outside =
            std::env::temp_dir().join(format!("swarmchase-outside-{}.ndjson", std::process::id()));
        let err = export(&a, &items, &d, &outside, None)
            .unwrap_err()
            .to_string();
        assert!(err.contains("inside the data directory"), "{err}");
        assert!(!outside.exists());
        std::fs::create_dir_all(d.join("samples")).unwrap();
        let err = check_in_data(&d, &d.join("samples").join("x.ndjson"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("committed"), "{err}");
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn suggestions_for_withheld_sources_are_dropped() {
        let d = tmp("load");
        let a = analysis();
        std::fs::write(
            d.join("labels").join("suggestions-claude.ndjson"),
            [
                r#"{"id":"wayback:1","label":"Agent","reason":"sqli via   r.jina.ai","model":"m"}"#,
                r#"{"id":"lines:3","label":"agent","reason":"x"}"#,
                r#"{"id":"nope","label":"agent"}"#,
                r#"{"id":"wayback:1","label":"maybe"}"#,
                "not json",
                r#"{"id":"wayback:4","label":"agent","reason":"placeholder","model":"m","grade":"L2","misfires":["exploit.sqli_quote"," "]}"#,
            ]
            .join("\n"),
        )
        .unwrap();
        std::fs::write(d.join("labels").join("reviewed.ndjson"), "").unwrap();
        let l = load_suggestions(&d.join("labels"), &a).unwrap();
        assert_eq!(l.by_id.len(), 2);
        let s = &l.by_id["wayback:1"];
        // wayback:1 is graded below L2, so its agent suggestion shows as unsure.
        let idx = a
            .results
            .iter()
            .position(|r| r.obs.id == "wayback:1")
            .unwrap();
        assert!(!grade_code(&a, idx).is_some_and(code_allows_agent));
        assert_eq!(s.label, "unsure");
        assert!(s.reason.contains("below L2"), "{}", s.reason);
        assert!(s.reason.ends_with("sqli via r[.]jina[.]ai"), "{}", s.reason);
        assert_eq!(s.model, "m");
        assert_eq!(l.by_id["wayback:4"].label, "agent");
        assert_eq!((l.invalid, l.dropped, l.withheld, l.demoted), (2, 2, 1, 1));
        // `all` keeps what the model said, with what it saw.
        assert_eq!(l.all.len(), 2);
        assert_eq!(l.all[0].label, "agent");
        assert_eq!(l.all[1].grade_seen.as_deref(), Some("L2"));
        assert_eq!(l.all[1].misfires, ["exploit.sqli_quote"]);
        assert_eq!(l.all[1].file, "suggestions-claude.ndjson");
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn check_finds_rule_breaks_and_format_errors() {
        let a = analysis();
        let items = queue(&a, &BTreeSet::new(), Tier::Suggestive, 0);
        let (lines, _) = export_lines(&a, &items);
        let w1 = lines.iter().find(|l| l.id == "wayback:1").unwrap();
        let w1_grade = w1.grade.clone().unwrap_or_default();
        let w1_rule = w1.rules[0].clone();
        let export: BTreeMap<String, ExportLine> =
            lines.into_iter().map(|l| (l.id.clone(), l)).collect();
        let text = [
            format!(
                r#"{{"id":"wayback:1","label":"unsure","reason":"payload only","model":"m","grade":"{w1_grade}","misfires":["{w1_rule}"]}}"#
            ),
            r#"{"id":"wayback:4","label":"agent","reason":"placeholder residue","model":"m","grade":"L2"}"#.into(),
        ]
        .join("\n");
        let r = check_text("suggestions-m.ndjson", &text, &export);
        assert!(r.errors.is_empty(), "{:?}", r.errors);
        assert!(r.warnings.is_empty(), "{:?}", r.warnings);
        assert_eq!((r.lines, r.missing), (2, 1));

        let bad = [
            format!(r#"{{"id":"wayback:1","label":"agent","reason":"r","model":"m","grade":"{w1_grade}"}}"#),
            r#"{"id":"wayback:4","label":"agent","reason":"see https://w.example","model":"","grade":"L3","misfires":["relay.nope"]}"#.into(),
            r#"{"id":"wayback:4","label":"benign","reason":"r","model":"m"}"#.into(),
            r#"{"id":"lines:3","label":"benign","reason":"r","model":"m"}"#.into(),
            r#"{"id":"wayback:1","label":"maybe"}"#.into(),
            "nope".into(),
        ]
        .join("\n");
        let r = check_text("labels.ndjson", &bad, &export);
        let all: Vec<&str> = r.errors.iter().map(|(_, e)| e.as_str()).collect();
        let has = |s: &str| all.iter().any(|e| e.contains(s));
        assert!(has("agent needs L2 or higher"), "{all:?}");
        assert!(has("undefanged URL"), "{all:?}");
        assert!(has("no model id"), "{all:?}");
        assert!(has("grade L3 but the export says L2"), "{all:?}");
        assert!(has("misfire `relay.nope`"), "{all:?}");
        assert!(has("a second line"), "{all:?}");
        assert!(has("not in the export"), "{all:?}");
        assert!(has("label `maybe`"), "{all:?}");
        assert!(has("not a suggestion line"), "{all:?}");
        assert!(r.warnings.iter().any(|w| w.contains("reads only")));
        assert!(r.warnings.iter().any(|w| w.contains("without `grade`")));
    }
}
