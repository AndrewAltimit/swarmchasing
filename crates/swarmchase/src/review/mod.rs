//! `swarmchase review`: the admin labels watch leads, and the labels
//! feed `swarmchase eval`.
//!
//! The queue holds every unreviewed record at or above `--min-tier`, strongest
//! first and kept together by cluster, then (with `--unflagged N`) a fixed
//! pseudo-random sample of unflagged records. Labelling that sample is how the
//! benign baseline grows, and it is also how misses turn up: an
//! unflagged record labelled `agent` is a false negative.
//!
//! Reviews go to `<data>/labels/reviewed.ndjson`, one line per record: the
//! stored (already redacted) record plus `label`, `note`, `class`, what the
//! rules said at review time and the agent grade the label was judged against
//! ([`LabelGrade`]). An `agent` label below L2 is allowed but marked
//! `below_l2`, its reason in the note, so every reader shows it as the
//! exception it is. The file is both a label file and an eval input:
//!
//! ```sh
//! swarmchase eval data/labels/reviewed.ndjson
//! ```
//!
//! With `--labeller <name>` reviews go to `<data>/labels/reviewed-<name>.ndjson`
//! instead, so two people can label the same queue independently.
//! `review --stats` then also reports Cohen's κ between every pair of review
//! files over the records both labelled, and lists where they disagree.
//!
//! It lives in the data directory, outside the checkout, and is never committed:
//! the records are urlquery and archive content, and unpublished leads. It is
//! kept past the watch's retention window because it is the evaluation set,
//! not watch data (see docs/policies.md). `unsure` reviews leave the queue but are not
//! counted by eval.
//!
//! `c` opens a case from the shown record's cluster (or the record alone when
//! it has none), pinned to the rules the session analysed with; `c <case-id>`
//! adds the cluster's records to that case instead. Either way the record
//! stays on screen to be labelled.
//!
//! With `--suggest`, a model running locally ([`crate::suggest`]) proposes a
//! label before each prompt; it is saved beside the admin's label as
//! `suggested`, never as the label.
//!
//! `review --serve` ([`serve`]) shows the same queue as a page on this
//! machine, grouped by cluster or shape, and saves to the same file.
//! `review --export-hosted` ([`hosted`]) writes the queue's public records
//! for a hosted model, whose suggestions the page shows; `review
//! check-suggestions` validates a suggestions file against its export.
//! `review agreement` ([`agreement`]) compares the admin's labels with the
//! suggestions, and `review misfires` ([`misfires`]) lists rules whose
//! reviewed hits are mostly benign, with candidate hard negatives.
//!
//! `review sample` ([`sample`]) writes a stratified, seeded sample of the
//! store as a queue file, and `review <queue> --all` queues every record in
//! it, as `review:baseline-sample`. Two labellers label it; `review --stats`
//! reports their agreement and what the benign records reviewed so far can
//! bound: the rule of three gives a 95% upper bound of `3/n` on the
//! false-positive rate when none of `n` benign records was flagged. `eval`
//! reports the same bound for the current rules. `review tuned <id>...`
//! marks records looked at while changing a rule, which leave the baseline.

pub mod agreement;
pub mod context;
pub mod hosted;
pub mod misfires;
pub mod sample;
pub mod serve;

use crate::suggest::Suggestion;
use crate::util::truncate;
use anyhow::{Context, Result, bail};
use sc_core::{Analysis, Observation, Tier, defang, fmt_ts};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};

pub const CLASS_FLAGGED: &str = "review:flagged";
pub const CLASS_SAMPLE: &str = "review:unflagged-sample";
pub const CLASS_BASELINE: &str = sc_core::eval::baseline::CLASS;

#[derive(clap::Subcommand)]
pub enum ReviewCmd {
    /// Write a stratified, seeded sample of records as a review queue, to
    /// grow a reviewed benign baseline.
    Sample(sample::SampleArgs),
    /// Mark reviewed records as tuned on: looked at while changing a rule.
    /// `eval` leaves them out of the benign baseline.
    Tuned(TunedArgs),
    /// Check a suggestions file against the export it answers: format,
    /// ids, the labelling rule (agent needs L2 or higher), recorded grades
    /// and misfire rule ids.
    CheckSuggestions(hosted::CheckArgs),
    /// Compare the admin's labels with model suggestions: confusion matrix
    /// per model and per agent grade, and suggestions that break the
    /// labelling rule.
    Agreement(agreement::AgreementArgs),
    /// Rules whose reviewed hits are mostly benign, with candidate hard
    /// negatives written to the data directory.
    Misfires(misfires::MisfiresArgs),
    /// Ask Claude through Claude Code (headless, no tools) for suggestions
    /// on `--export-hosted` files, appended to a suggestions file.
    SuggestClaude(crate::suggest::claude::SuggestArgs),
}

#[derive(clap::Args)]
pub struct TunedArgs {
    /// Record ids, or files listing one id per line (`#` comments allowed).
    #[arg(required = true)]
    ids: Vec<String>,
    /// Data directory (the watch's `--out`).
    #[arg(short, long, default_value = "data", env = "SWARMCHASE_DATA")]
    data: PathBuf,
}

#[derive(clap::Args)]
#[command(args_conflicts_with_subcommands = true)]
pub struct ReviewArgs {
    #[command(subcommand)]
    cmd: Option<ReviewCmd>,
    /// Queue every record of the input files, in file order (a queue
    /// `review sample` wrote), as `review:baseline-sample`.
    #[arg(long, requires = "input")]
    all: bool,
    /// Records to review. Default: the watch store's last `--days` days.
    input: Vec<PathBuf>,
    /// Data directory (the watch's `--out`).
    #[arg(short, long, default_value = "data", env = "SWARMCHASE_DATA")]
    data: PathBuf,
    #[arg(long, default_value_t = 30)]
    days: i64,
    /// Queue records at or above this tier: suggestive | significant
    #[arg(long, default_value = "suggestive")]
    min_tier: String,
    /// Also queue this many unflagged records, a stable pseudo-random
    /// sample, to grow the benign baseline and catch misses.
    #[arg(long, default_value_t = 0)]
    unflagged: usize,
    /// Print the queue and exit.
    #[arg(long)]
    list: bool,
    /// Print counts of reviewed records and disagreements, and exit.
    #[arg(long)]
    stats: bool,
    #[arg(long)]
    rules: Option<PathBuf>,
    /// Save reviews as this labeller (`reviewed-<name>.ndjson`), for
    /// inter-rater agreement. Letters, digits, `-` and `_`.
    #[arg(long)]
    labeller: Option<String>,
    /// Show a label suggestion from a model running locally
    /// (`SWARMCHASE_LLM_URL`, loopback or private addresses only) before
    /// each prompt. Saved beside the label as `suggested`, never as it.
    #[arg(long)]
    suggest: bool,
    /// Serve the queue as a page on 127.0.0.1 instead of prompting: records
    /// grouped by cluster or shape, with saved suggestions. Reviewed records
    /// stay on the page so a label can be changed or cleared.
    #[arg(long, conflicts_with_all = ["list", "stats", "suggest"])]
    serve: bool,
    /// Port for `--serve`.
    #[arg(long, default_value_t = 8765, requires = "serve")]
    port: u16,
    /// Pre-era control summary for `--serve`, whose per-rule false-alarm
    /// counts the page shows beside each rule. Default:
    /// `<data>/controls/pre-era/summary.json`, then
    /// `data/controls/pre-era/summary.json`, when present.
    #[arg(long, value_name = "FILE", requires = "serve")]
    control: Option<PathBuf>,
    /// Write the queue's public records (web archives and urlquery) as text
    /// for a hosted model to suggest labels on, and exit. Operator logs and
    /// sources not on the list are withheld. The file must be inside the
    /// data directory.
    #[arg(long, value_name = "FILE", conflicts_with_all = ["list", "stats", "serve", "suggest"])]
    export_hosted: Option<PathBuf>,
    /// With `--export-hosted`: split the export into numbered files of
    /// about this many records, each review group whole, one per subagent.
    #[arg(long, value_name = "N", requires = "export_hosted")]
    batch_size: Option<usize>,
}

pub fn run(args: ReviewArgs) -> Result<()> {
    match args.cmd {
        Some(ReviewCmd::Sample(s)) => return sample::run(s),
        Some(ReviewCmd::Tuned(t)) => return mark_tuned(&t),
        Some(ReviewCmd::CheckSuggestions(c)) => return hosted::check(&c),
        Some(ReviewCmd::Agreement(g)) => return agreement::run(&g),
        Some(ReviewCmd::Misfires(m)) => return misfires::run(&m),
        Some(ReviewCmd::SuggestClaude(s)) => return crate::suggest::claude::run(&s),
        None => {}
    }
    let data = &args.data;
    if args.input.is_empty() || args.stats {
        crate::store::hint_if_empty(data);
    }
    let path = ReviewStore::path_for(data, args.labeller.as_deref())?;
    let mut store = ReviewStore::open(path)?;
    if args.stats {
        let rules = crate::pinning::RulesText::load(args.rules.as_deref())?;
        stats(&store, &rules.rules, &mut std::io::stdout())?;
        return agreement_report(&data.join("labels"), &mut std::io::stdout());
    }
    let min = check_min_tier(crate::input::parse_tier(&args.min_tier)?)?;
    let rules = crate::pinning::RulesText::load(args.rules.as_deref())?;
    let from = if args.input.is_empty() {
        format!("the watch store's last {} days", args.days)
    } else {
        let files: Vec<String> = args.input.iter().map(|p| p.display().to_string()).collect();
        files.join(", ")
    };
    let obs = if args.input.is_empty() {
        let dir = data.join("store");
        if !dir.is_dir() {
            bail!(
                "no watch store at {} (pass record files, or set --data / SWARMCHASE_DATA)",
                dir.display()
            );
        }
        crate::store::load_store(&dir, chrono::Utc::now().timestamp() - args.days * 86_400)?
    } else {
        crate::input::read_inputs(&crate::input::InputArgs::files(args.input))?
    };
    let a = sc_core::analyze(obs, &rules.rules);
    // The page keeps reviewed records on it, so a label can be changed.
    let done = if args.serve {
        BTreeSet::new()
    } else {
        store.entries.keys().cloned().collect()
    };
    let items = if args.all {
        queue_all(&a, &done)
    } else {
        queue(&a, &done, min, args.unflagged)
    };
    if let Some(out) = &args.export_hosted {
        return hosted::export(&a, &items, data, out, args.batch_size);
    }
    println!(
        "{} records · {} reviewed before · {} in the queue ({} flagged, {} unflagged sample, {} baseline sample)",
        a.total,
        store.entries.len(),
        items.len(),
        items.iter().filter(|i| i.class == CLASS_FLAGGED).count(),
        items.iter().filter(|i| i.class == CLASS_SAMPLE).count(),
        items.iter().filter(|i| i.class == CLASS_BASELINE).count(),
    );
    if args.list {
        for it in &items {
            let r = &a.results[it.idx];
            println!(
                "{:<11} {:>3}  {}  {}",
                r.tier.label(),
                r.score,
                r.obs.id,
                defang(&truncate(&r.obs.url, 100))
            );
        }
        return Ok(());
    }
    if items.is_empty() {
        return Ok(());
    }
    if args.serve {
        let labels = data.join("labels");
        let loaded = hosted::load_suggestions(&labels, &a)?;
        println!(
            "{} suggestion(s) from {}{}",
            loaded.by_id.len(),
            labels.join("suggestions-*.ndjson").display(),
            if loaded.invalid + loaded.dropped > 0 {
                format!(
                    " ({} line(s) invalid, {} dropped: not in the queue's analysis or from a source a hosted model may not see)",
                    loaded.invalid, loaded.dropped
                )
            } else {
                String::new()
            }
        );
        if loaded.demoted > 0 {
            println!(
                "{} agent suggestion(s) on records graded below L2 are against the labelling rule; the page flags them (`review agreement` lists them)",
                loaded.demoted
            );
        }
        println!("labels go to {}", store.path.display());
        let control = context::Control::find(args.control.as_deref(), data)?;
        match &control {
            Some(c) => println!("pre-era control from {} ({} records)", c.path, c.records),
            None => println!("no pre-era control summary (swarmchase eval pre-era writes one)"),
        }
        let app = serve::ReviewApp::new(a, items, store, loaded.by_id, from)
            .with_context(&rules.rules, control);
        return crate::localui::Server::new(app, args.port).run("review page");
    }
    let suggester = if args.suggest {
        let s = crate::suggest::Suggester::from_env()?;
        println!(
            "label suggestions from the local model at {} (suggestions only; the label is yours)",
            s.url()
        );
        Some(s)
    } else {
        None
    };
    let suggest = |a: &Analysis, idx: usize| suggester.as_ref().and_then(|s| s.suggest(a, idx));
    let stdin = std::io::stdin();
    let now = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
    let cases = CaseSink {
        root: data.join("cases"),
        rules,
        from,
        today: crate::util::today(),
    };
    let t = session(
        &a,
        &items,
        &mut store,
        stdin.lock(),
        &mut std::io::stdout(),
        &Session {
            now: &now,
            cases: &cases,
            suggest: &suggest,
        },
    )?;
    let labelled: Vec<String> = t.labelled.iter().map(|(k, v)| format!("{v} {k}")).collect();
    println!(
        "\nlabelled {} · skipped {}{}",
        if labelled.is_empty() {
            "none".into()
        } else {
            labelled.join(", ")
        },
        t.skipped,
        if t.quit {
            " · stopped early, run again to continue"
        } else {
            ""
        }
    );
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Review {
    #[serde(flatten)]
    pub record: Observation,
    /// `agent`, `benign` or `unsure`.
    pub label: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    /// Why the record was in the queue: flagged, or the unflagged sample.
    pub class: String,
    pub reviewed_at: String,
    /// What the rules said when the record was reviewed.
    pub tier: Tier,
    pub score: i32,
    #[serde(default)]
    pub rules: Vec<String>,
    pub rules_version: String,
    /// A local model's suggestion shown before the admin labelled the
    /// record (`review --suggest`). Never the label.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub suggested: Option<crate::suggest::Suggestion>,
    /// Looked at while changing a rule (`review tuned`): `eval` leaves it
    /// out of the benign baseline.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub tuned: bool,
    /// The agent grade the label was judged against, as it stood when the
    /// record was labelled. `None` on a line written before grades were
    /// stored: unknown, so readers grade it from the analysis they have and
    /// say that they did.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grade: Option<LabelGrade>,
}

/// The marker on an `agent` label below the labelling rule.
pub const BELOW_L2: &str = "below_l2";

/// What a label was judged against: the agent grade that decides the
/// record's labels (its cluster's, else its own), in short form, and
/// whether the labelling rule allowed `agent` at it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LabelGrade {
    /// `L0` .. `L5`; `None` for an ungraded record.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    /// The rung's name, e.g. `payloads only`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// `cluster`, `record` or `none`.
    pub basis: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cluster: Option<String>,
    /// Signals for, `<signal> (<n> records)`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub signals: Vec<String>,
    /// Signals against, in the same form.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub counter: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub caps: Vec<String>,
    /// The grade is L2 or higher, so the rule allows `agent`.
    pub agent_allowed: bool,
    /// [`BELOW_L2`] on an `agent` label the rule does not allow: an
    /// exception the admin chose, its reason in the review's `note`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule: Option<String>,
}

impl LabelGrade {
    /// The grade record `idx` is labelled against in `a`, for `label`.
    pub fn of(a: &Analysis, idx: usize, label: &str) -> Self {
        let (g, basis) = hosted::grade_of(a, idx);
        let signal =
            |s: &sc_core::AgentSignal| format!("{} ({} records)", s.kind.label(), s.records);
        let allowed = hosted::agent_allowed(g.map(|g| g.level));
        Self {
            code: g.map(|g| g.level.code().to_string()),
            label: g.map(|g| g.level.label().to_string()),
            basis: basis.to_string(),
            cluster: a.results[idx].cluster.map(|c| a.clusters[c].id.clone()),
            signals: g.map_or_else(Vec::new, |g| g.signals.iter().map(signal).collect()),
            counter: g.map_or_else(Vec::new, |g| g.counter.iter().map(signal).collect()),
            caps: g.map_or_else(Vec::new, |g| {
                g.caps.iter().map(|k| k.label().to_string()).collect()
            }),
            agent_allowed: allowed,
            rule: (label == "agent" && !allowed).then(|| BELOW_L2.to_string()),
        }
    }

    /// An `agent` label below the labelling rule.
    pub fn below_rule(&self) -> bool {
        self.rule.as_deref() == Some(BELOW_L2)
    }

    /// The code, or `no grade`.
    pub fn code(&self) -> &str {
        self.code.as_deref().unwrap_or("no grade")
    }

    /// One line: code and name, basis, signals and caps.
    pub fn short(&self) -> String {
        let mut s = match &self.label {
            Some(l) => format!("{} {l}", self.code()),
            None => self.code().to_string(),
        };
        match (&self.cluster, self.basis.as_str()) {
            (Some(c), "cluster") => s.push_str(&format!(" · cluster {c}")),
            (_, "record") => s.push_str(" · record alone"),
            _ => {}
        }
        if !self.signals.is_empty() {
            s.push_str(&format!(" · signals: {}", self.signals.join(", ")));
        }
        if !self.counter.is_empty() {
            s.push_str(&format!(" · against: {}", self.counter.join(", ")));
        }
        if !self.caps.is_empty() {
            s.push_str(&format!(" · caps: {}", self.caps.join("; ")));
        }
        s
    }
}

/// Where a label's grade came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GradeFrom {
    /// Stored with the label when it was written.
    Stored,
    /// Computed now from the analysis at hand: the line stores none.
    Now,
}

impl GradeFrom {
    pub fn word(self) -> &'static str {
        match self {
            Self::Stored => "stored",
            Self::Now => "now",
        }
    }
}

impl Review {
    /// The grade the label was judged against: the stored one, else the one
    /// `now` gives (a line from before grades were stored). `None` when the
    /// line stores none and `now` has no analysis of the record.
    pub fn judged_grade(
        &self,
        now: impl FnOnce() -> Option<LabelGrade>,
    ) -> Option<(LabelGrade, GradeFrom)> {
        match &self.grade {
            Some(g) => Some((g.clone(), GradeFrom::Stored)),
            None => now().map(|g| (g, GradeFrom::Now)),
        }
    }
}

/// Agent labels in a review file below the labelling rule.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct BelowRuleCount {
    /// Agent labels in the file.
    pub agents: usize,
    /// Of those, below L2: by the stored grade, else the grade now.
    pub total: usize,
    /// Below L2 and queued as flagged (what a precision estimate reads).
    pub flagged: usize,
    /// Below L2 by the grade now: the line stores none.
    pub graded_now: usize,
    /// Below L2 with a reason in the note.
    pub with_reason: usize,
    /// Lines storing no grade whose record is not in the analysis.
    pub unknown: usize,
}

/// Count `store`'s agent labels below L2, grading a line that stores no
/// grade by `a`.
pub fn count_below_rule(store: &ReviewStore, a: &Analysis) -> BelowRuleCount {
    let mut c = BelowRuleCount::default();
    let old = store
        .entries
        .values()
        .any(|v| v.label == "agent" && v.grade.is_none());
    let index: BTreeMap<&str, usize> = if old {
        a.results
            .iter()
            .enumerate()
            .rev()
            .map(|(i, r)| (r.obs.id.as_str(), i))
            .collect()
    } else {
        BTreeMap::new()
    };
    for v in store.entries.values().filter(|v| v.label == "agent") {
        c.agents += 1;
        let now = || {
            let &i = index.get(v.record.id.as_str())?;
            Some(LabelGrade::of(a, i, &v.label))
        };
        match v.judged_grade(now) {
            Some((g, from)) if g.below_rule() => {
                c.total += 1;
                c.graded_now += usize::from(from == GradeFrom::Now);
                c.flagged += usize::from(v.class == CLASS_FLAGGED);
                c.with_reason += usize::from(v.note.is_some());
            }
            Some(_) => {}
            None => c.unknown += 1,
        }
    }
    c
}

/// The grade of every record in the review file, from an analysis of the
/// file's own records: what a reader without the watch store grades an
/// older line by. A cluster with members outside the file may grade
/// differently on the review page.
pub fn grades_now(store: &ReviewStore, rules: &sc_core::Rules) -> BTreeMap<String, LabelGrade> {
    let a = sc_core::analyze(
        store.entries.values().map(|r| r.record.clone()).collect(),
        rules,
    );
    let mut out = BTreeMap::new();
    for (i, r) in a.results.iter().enumerate() {
        if let Some(v) = store.entries.get(&r.obs.id) {
            out.entry(r.obs.id.clone())
                .or_insert_with(|| LabelGrade::of(&a, i, &v.label));
        }
    }
    out
}

/// `review tuned`: set `tuned` on the listed records in every review file.
fn mark_tuned(args: &TunedArgs) -> Result<()> {
    let mut ids = BTreeSet::new();
    for a in &args.ids {
        let p = Path::new(a);
        if p.is_file() {
            let text =
                std::fs::read_to_string(p).with_context(|| format!("reading {}", p.display()))?;
            ids.extend(sc_core::eval::split::parse_id_list(&text));
        } else {
            ids.insert(a.clone());
        }
    }
    let mut marked = BTreeSet::new();
    for (who, path) in labeller_files(&args.data.join("labels"))? {
        let mut store = ReviewStore::open(path)?;
        let mut n = 0;
        for id in &ids {
            if let Some(r) = store.entries.get_mut(id)
                && !r.tuned
            {
                r.tuned = true;
                marked.insert(id.clone());
                n += 1;
            }
        }
        if n > 0 {
            store.save()?;
            println!("{who}: marked {n} record(s) tuned");
        }
    }
    let unknown = ids.iter().filter(|id| !marked.contains(*id)).count();
    println!(
        "{} of {} id(s) newly marked tuned; {unknown} not found or already tuned",
        marked.len(),
        ids.len()
    );
    Ok(())
}

/// The review file, keyed by record ID. Saving rewrites it, so a re-review
/// replaces the earlier line instead of duplicating the record.
///
/// Saving merges: under a lock beside the file, it reads the file again and
/// applies only what this store changed since it was opened or last saved,
/// so a long `review --serve` never undoes a `review tuned` (or another
/// reviewer's labels) written meanwhile.
pub struct ReviewStore {
    path: PathBuf,
    pub entries: BTreeMap<String, Review>,
    /// Each entry as last read or written, serialised, to tell what changed.
    base: BTreeMap<String, String>,
}

impl ReviewStore {
    pub fn path_in(data: &Path) -> PathBuf {
        data.join("labels").join("reviewed.ndjson")
    }

    /// The default review file, or labeller `name`'s.
    pub fn path_for(data: &Path, labeller: Option<&str>) -> Result<PathBuf> {
        let Some(name) = labeller else {
            return Ok(Self::path_in(data));
        };
        if name.is_empty()
            || !name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            bail!("--labeller `{name}`: use letters, digits, `-` and `_` only");
        }
        Ok(data.join("labels").join(format!("reviewed-{name}.ndjson")))
    }

    pub fn open(path: PathBuf) -> Result<Self> {
        let entries = Self::read(&path)?;
        let base = snapshot(&entries)?;
        Ok(Self {
            path,
            entries,
            base,
        })
    }

    fn read(path: &Path) -> Result<BTreeMap<String, Review>> {
        let mut entries = BTreeMap::new();
        match std::fs::read_to_string(path) {
            Ok(text) => {
                for (n, line) in text.lines().enumerate() {
                    if line.trim().is_empty() {
                        continue;
                    }
                    let r: Review = serde_json::from_str(line)
                        .with_context(|| format!("{}:{}", path.display(), n + 1))?;
                    entries.insert(r.record.id.clone(), r);
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
        }
        Ok(entries)
    }

    /// Write this store's changes into the file: entries added, changed or
    /// removed here since it was opened (or last saved) replace the file's,
    /// and every other entry in the file stays as the file has it. A record
    /// marked `tuned` in the file meanwhile stays tuned. Afterwards
    /// `entries` holds the merged file.
    pub fn save(&mut self) -> Result<()> {
        let dir = self.path.parent().unwrap_or(Path::new("."));
        std::fs::create_dir_all(dir)?;
        let name = self.path.file_name().unwrap_or_default().to_string_lossy();
        let lock_path = dir.join(format!(".{name}.lock"));
        let lock = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&lock_path)
            .with_context(|| format!("opening {}", lock_path.display()))?;
        lock.lock()
            .with_context(|| format!("locking {}", lock_path.display()))?;
        let mut merged = Self::read(&self.path)?;
        let ours = snapshot(&self.entries)?;
        for (id, r) in &self.entries {
            if self.base.get(id) == ours.get(id) {
                continue;
            }
            let mut r = r.clone();
            let base_tuned = self
                .base
                .get(id)
                .and_then(|t| serde_json::from_str::<Review>(t).ok())
                .is_some_and(|b| b.tuned);
            if merged.get(id).is_some_and(|d| d.tuned) && !base_tuned {
                r.tuned = true;
            }
            merged.insert(id.clone(), r);
        }
        for id in self.base.keys() {
            if !self.entries.contains_key(id) {
                merged.remove(id);
            }
        }
        let mut text = String::new();
        for r in merged.values() {
            text.push_str(&serde_json::to_string(r)?);
            text.push('\n');
        }
        crate::store::write_atomic(&self.path, text.as_bytes())?;
        drop(lock);
        self.base = snapshot(&merged)?;
        self.entries = merged;
        Ok(())
    }
}

/// Each entry serialised, to compare against later.
fn snapshot(entries: &BTreeMap<String, Review>) -> Result<BTreeMap<String, String>> {
    entries
        .iter()
        .map(|(id, r)| Ok((id.clone(), serde_json::to_string(r)?)))
        .collect()
}

/// One record in the queue: an index into `Analysis::results` and its class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Item {
    pub idx: usize,
    pub class: &'static str,
}

/// FNV-1a: a stable order for the unflagged sample, so the same store gives
/// the same sample on every machine and run.
fn fnv(s: &str) -> u64 {
    s.bytes().fold(0xcbf2_9ce4_8422_2325, |h, b| {
        (h ^ u64::from(b)).wrapping_mul(0x0000_0100_0000_01b3)
    })
}

pub fn queue(a: &Analysis, done: &BTreeSet<String>, min_tier: Tier, unflagged: usize) -> Vec<Item> {
    // The same record can appear twice in the input (overlapping pulls); it is
    // queued once.
    let mut queued = BTreeSet::new();
    let mut todo = |i: &usize| {
        let id = &a.results[*i].obs.id;
        !done.contains(id) && queued.insert(id.clone())
    };
    let mut flagged: Vec<usize> = (0..a.results.len())
        .filter(|&i| a.results[i].score > 0 && a.results[i].tier >= min_tier)
        .filter(&mut todo)
        .collect();
    // Strongest cluster first, its members together in time order; then
    // unclustered records by tier and score.
    let rank = |i: usize| {
        let r = &a.results[i];
        let (ct, cid) = r
            .cluster
            .map_or((r.tier, usize::MAX), |c| (a.clusters[c].tier, c));
        (
            std::cmp::Reverse(ct),
            cid,
            std::cmp::Reverse(r.score),
            r.obs.ts,
        )
    };
    flagged.sort_by_key(|&i| rank(i));

    let mut sample: Vec<usize> = (0..a.results.len())
        .filter(|&i| a.results[i].score == 0)
        .filter(&mut todo)
        .collect();
    sample.sort_by_key(|&i| fnv(&a.results[i].obs.id));
    sample.truncate(unflagged);

    flagged
        .into_iter()
        .map(|idx| Item {
            idx,
            class: CLASS_FLAGGED,
        })
        .chain(sample.into_iter().map(|idx| Item {
            idx,
            class: CLASS_SAMPLE,
        }))
        .collect()
}

/// Every unreviewed record, once, in input order, as the baseline sample.
pub fn queue_all(a: &Analysis, done: &BTreeSet<String>) -> Vec<Item> {
    let mut queued = BTreeSet::new();
    (0..a.results.len())
        .filter(|&i| {
            let id = &a.results[i].obs.id;
            !done.contains(id) && queued.insert(id.clone())
        })
        .map(|idx| Item {
            idx,
            class: CLASS_BASELINE,
        })
        .collect()
}

#[derive(Debug, PartialEq, Eq)]
pub enum Answer {
    /// Label, note, and whether it applies to every queued record in the cluster.
    Label(&'static str, Option<String>, bool),
    /// Open a case from the cluster, or add it to the named case.
    Case(Option<String>),
    Skip,
    Quit,
    Help,
}

/// `a`, `b`, `u` label one record; `A`, `B`, `U` label every queued record in
/// its cluster. Anything after the key is the note: `b reading an article`.
/// `c` opens a case from the cluster; `c <case-id>` adds it to that case.
pub fn parse_answer(line: &str) -> Answer {
    let line = line.trim();
    let mut chars = line.chars();
    let Some(key) = chars.next() else {
        return Answer::Help;
    };
    let rest = chars.as_str();
    // A key must stand alone: `bogus` is not `b` with the note `ogus`.
    if !rest.is_empty() && !rest.starts_with(char::is_whitespace) {
        return Answer::Help;
    }
    let note = Some(rest.trim().to_string()).filter(|n| !n.is_empty());
    let label = match key.to_ascii_lowercase() {
        'a' => "agent",
        'b' => "benign",
        'u' => "unsure",
        's' => return Answer::Skip,
        'c' => return Answer::Case(note),
        'q' => return Answer::Quit,
        _ => return Answer::Help,
    };
    Answer::Label(label, note, key.is_ascii_uppercase())
}

const HELP: &str = "  a = agent, b = benign, u = unsure, s = skip, q = quit (progress is saved)\n  \
     A / B / U label every queued record in this cluster. Text after the key is a note: `b ordinary article read`\n  \
     c opens a case from this cluster; `c <case-id>` adds the cluster to that case";

fn show(out: &mut impl Write, a: &Analysis, item: Item, pos: usize, total: usize) -> Result<()> {
    let r = &a.results[item.idx];
    let cluster = r
        .cluster
        .map(|c| {
            let c = &a.clusters[c];
            format!(
                "  cluster {} {} ({}, {} records)",
                c.id,
                c.key,
                c.tier.label(),
                c.members.len()
            )
        })
        .unwrap_or_default();
    let sample = if item.class == CLASS_SAMPLE {
        "  [unflagged sample]"
    } else {
        ""
    };
    writeln!(
        out,
        "\n[{pos}/{total}] {} score {}{cluster}{sample}",
        r.tier.label(),
        r.score
    )?;
    writeln!(
        out,
        "  time:    {}   source: {}",
        fmt_ts(r.obs.ts),
        r.obs.source
    )?;
    let g = LabelGrade::of(a, item.idx, "unsure");
    writeln!(
        out,
        "  grade:   {}{}",
        g.short(),
        if g.agent_allowed {
            ""
        } else {
            " (below L2: unsure is the most the rule allows)"
        }
    )?;
    writeln!(out, "  url:     {}", defang(&truncate(&r.obs.url, 300)))?;
    for l in r.layers.iter().filter(|l| l.via != "submitted").take(5) {
        writeln!(
            out,
            "  {:<8} {}",
            format!("[{}]", l.via),
            defang(&truncate(
                &l.text.split_whitespace().collect::<Vec<_>>().join(" "),
                200
            ))
        )?;
    }
    if let Some(h) = &r.target_host {
        writeln!(out, "  target:  {}", sc_core::defang_host(h))?;
    }
    if let Some(f) = &r.obs.final_url {
        writeln!(out, "  final:   {}", defang(&truncate(f, 120)))?;
    }
    for h in &r.hits {
        writeln!(
            out,
            "  rule:    {} (+{}) {}",
            h.rule_id,
            h.weight,
            defang(&truncate(&h.matched, 80))
        )?;
    }
    if let Some(link) = &r.obs.reference {
        writeln!(out, "  record:  {link}")?;
    }
    Ok(())
}

/// Where `c` opens or extends cases during a session.
pub struct CaseSink {
    /// The case root, `<data>/cases`.
    pub root: PathBuf,
    /// The rules the session analysed with; a new case is pinned to them.
    pub rules: crate::pinning::RulesText,
    /// What is being reviewed (record files, or the watch store), for the
    /// decision log.
    pub from: String,
    /// Date for the decision log.
    pub today: String,
}

/// What `c` did: the case, whether it was opened, and how many records it took.
#[derive(Debug, PartialEq, Eq)]
pub struct CaseAction {
    pub id: String,
    pub opened: bool,
    pub added: usize,
}

/// Open a case from the cluster of record `idx` (the record alone when it is
/// unclustered), or add those records to case `into`, and log in the case's
/// decision log where they came from.
pub fn case_from_cluster(
    a: &Analysis,
    idx: usize,
    into: Option<&str>,
    sink: &CaseSink,
) -> Result<CaseAction> {
    let r = &a.results[idx];
    let (members, what, slug) = match r.cluster {
        Some(c) => {
            let c = &a.clusters[c];
            let slug: String =
                c.id.chars()
                    .map(|ch| {
                        if ch.is_ascii_alphanumeric() {
                            ch.to_ascii_lowercase()
                        } else {
                            '-'
                        }
                    })
                    .collect();
            (
                c.members.clone(),
                format!("cluster {} ({})", c.id, c.key),
                slug,
            )
        }
        None => (vec![idx], format!("record {}", r.obs.id), "record".into()),
    };
    // The same record can be in the input twice; the case takes it once.
    let mut seen = BTreeSet::new();
    let records: Vec<Observation> = members
        .iter()
        .map(|&m| &a.results[m].obs)
        .filter(|o| seen.insert(o.id.clone()))
        .cloned()
        .collect();
    let origin = format!("review of {}, {what}", sink.from);
    let today = sink.today.as_str();

    if let Some(id) = into {
        let c = crate::case::load(&sink.root, id)?;
        if c.status == crate::case::CaseStatus::Closed {
            bail!("case {id} is closed");
        }
        let (added, _) = crate::case::add_records(&sink.root, id, records, today)?;
        if added > 0 {
            crate::case::log_entry(
                &sink.root,
                id,
                today,
                format!("added {added} record(s) from {origin}"),
            )?;
        }
        return Ok(CaseAction {
            id: id.to_string(),
            opened: false,
            added,
        });
    }

    let base = format!("review-{today}-{slug}");
    let id = (1..)
        .map(|n| {
            if n == 1 {
                base.clone()
            } else {
                format!("{base}-{n}")
            }
        })
        .find(|id| !sink.root.join(id).join("case.toml").exists())
        .expect("an unused case id");
    let title = format!(
        "Review lead: {what} ({} records, {})",
        records.len(),
        r.cluster.map_or(r.tier, |c| a.clusters[c].tier).label()
    );
    let added = records.len();
    crate::case::new_case(&sink.root, &id, &title, records, &sink.rules, today)?;
    crate::case::log_entry(&sink.root, &id, today, format!("opened from {origin}"))?;
    Ok(CaseAction {
        id,
        opened: true,
        added,
    })
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Tally {
    pub labelled: BTreeMap<&'static str, usize>,
    pub skipped: usize,
    pub quit: bool,
}

/// What a review session works with besides the queue: the time stamped on
/// each answer, where `c` opens cases, and the label suggester (`--suggest`;
/// `|_, _| None` without it).
#[derive(Clone, Copy)]
pub struct Session<'a> {
    pub now: &'a str,
    pub cases: &'a CaseSink,
    pub suggest: &'a dyn Fn(&Analysis, usize) -> Option<Suggestion>,
}

/// Step through `items`, reading answers from `input`. Each answer is saved
/// before the next record is shown, so quitting or a crash loses nothing.
pub fn session(
    a: &Analysis,
    items: &[Item],
    store: &mut ReviewStore,
    mut input: impl BufRead,
    out: &mut impl Write,
    ctx: &Session,
) -> Result<Tally> {
    let Session {
        now,
        cases,
        suggest,
    } = *ctx;
    let mut tally = Tally::default();
    let total = items.len();
    let mut pos = 0;
    while pos < items.len() {
        let item = items[pos];
        let id = &a.results[item.idx].obs.id;
        if store.entries.contains_key(id) {
            pos += 1; // labelled with its cluster
            continue;
        }
        show(out, a, item, pos + 1, total)?;
        let suggestion = suggest(a, item.idx);
        if let Some(s) = &suggestion {
            writeln!(
                out,
                "  suggestion: {}, {} ({}; a suggestion only)",
                s.label,
                defang(&s.reason),
                s.model
            )?;
        }
        let answer = loop {
            write!(out, "label> ")?;
            out.flush()?;
            let mut line = String::new();
            if input.read_line(&mut line)? == 0 {
                break Answer::Quit; // end of input
            }
            match parse_answer(&line) {
                Answer::Help => writeln!(out, "{HELP}")?,
                Answer::Case(into) => {
                    match case_from_cluster(a, item.idx, into.as_deref(), cases) {
                        Ok(c) if c.opened => writeln!(
                            out,
                            "  opened case {} with {} record(s): `swarmchase case status {}`",
                            c.id, c.added, c.id
                        )?,
                        Ok(c) => writeln!(out, "  added {} record(s) to case {}", c.added, c.id)?,
                        Err(e) => writeln!(out, "  case: {e:#}")?,
                    }
                }
                a => break a,
            }
        };
        match answer {
            Answer::Quit => {
                tally.quit = true;
                break;
            }
            Answer::Skip => tally.skipped += 1,
            Answer::Label(label, note, whole_cluster) => {
                let targets: Vec<Item> = match (whole_cluster, a.results[item.idx].cluster) {
                    (true, Some(c)) => items[pos..]
                        .iter()
                        .copied()
                        .filter(|it| a.results[it.idx].cluster == Some(c))
                        .collect(),
                    _ => vec![item],
                };
                let (label, note) = confirm_below_rule(a, &targets, label, note, &mut input, out)?;
                for it in &targets {
                    let r = &a.results[it.idx];
                    store.entries.insert(
                        r.obs.id.clone(),
                        Review {
                            record: r.obs.clone(),
                            label: label.to_string(),
                            note: note.clone(),
                            class: it.class.to_string(),
                            reviewed_at: now.to_string(),
                            tier: r.tier,
                            score: r.score,
                            rules: r.hits.iter().map(|h| h.rule_id.clone()).collect(),
                            rules_version: a.rules_version.clone(),
                            // Only the shown record had a suggestion.
                            suggested: suggestion.clone().filter(|_| it.idx == item.idx),
                            tuned: false,
                            grade: Some(LabelGrade::of(a, it.idx, label)),
                        },
                    );
                    *tally.labelled.entry(label).or_default() += 1;
                }
                store.save()?;
                if targets.len() > 1 {
                    writeln!(out, "  labelled {} records `{label}`", targets.len())?;
                }
            }
            Answer::Help | Answer::Case(_) => unreachable!(),
        }
        pos += 1;
    }
    Ok(tally)
}

/// `agent` on records graded below L2: say what the grade is and what the
/// rule says, and ask for a reason, saved as the note, unless the answer
/// carried one. The reason is required: Enter asks again, `u` labels them
/// unsure instead. The label is saved with its grade, marked below the rule.
fn confirm_below_rule(
    a: &Analysis,
    targets: &[Item],
    label: &'static str,
    note: Option<String>,
    input: &mut impl BufRead,
    out: &mut impl Write,
) -> Result<(&'static str, Option<String>)> {
    if label != "agent" {
        return Ok((label, note));
    }
    let below: Vec<LabelGrade> = targets
        .iter()
        .map(|it| LabelGrade::of(a, it.idx, label))
        .filter(LabelGrade::below_rule)
        .collect();
    let Some(g) = below.first() else {
        return Ok((label, note));
    };
    writeln!(
        out,
        "  below the labelling rule: {} of {} record(s) at {}",
        below.len(),
        targets.len(),
        g.short()
    )?;
    writeln!(
        out,
        "  agent needs an agent grade of L2 or higher; below it, unsure is the most the evidence allows. An agent label here is saved as an exception, marked `{BELOW_L2}` with this grade."
    )?;
    if note.is_some() {
        return Ok((label, note));
    }
    loop {
        write!(
            out,
            "  reason, saved as the note (required; `u` for unsure instead)> "
        )?;
        out.flush()?;
        let mut line = String::new();
        if input.read_line(&mut line)? == 0 {
            // Input ended without a reason: unsure, the most the rule allows.
            return Ok(("unsure", None));
        }
        match line.trim() {
            "" => continue,
            "u" => return Ok(("unsure", None)),
            r => return Ok((label, Some(r.to_string()))),
        }
    }
}

/// Counts in the review file, and where the rules disagree with the admin.
pub fn stats(store: &ReviewStore, rules: &sc_core::Rules, out: &mut impl Write) -> Result<()> {
    let mut by: BTreeMap<(&str, &str), usize> = BTreeMap::new();
    for r in store.entries.values() {
        *by.entry((r.class.as_str(), r.label.as_str())).or_default() += 1;
    }
    writeln!(
        out,
        "{} reviewed records in {}",
        store.entries.len(),
        store.path.display()
    )?;
    for ((class, label), n) in &by {
        writeln!(out, "  {class:<26} {label:<7} {n:>6}")?;
    }
    let fp = store
        .entries
        .values()
        .filter(|r| r.label == "benign" && r.tier >= Tier::Suggestive)
        .count();
    let missed = store
        .entries
        .values()
        .filter(|r| r.label == "agent" && r.tier < Tier::Suggestive)
        .count();
    writeln!(
        out,
        "flagged at review but labelled benign: {fp} · labelled agent but not flagged: {missed}"
    )?;
    below_rule(store, rules, 10, out)?;
    baseline(store, out)?;
    if fp + missed > 0 {
        writeln!(
            out,
            "Run `swarmchase eval {}` for the full table. Fix the rules and add a reconstructed record to samples/eval/ as a regression case.",
            store.path.display()
        )?;
    }
    Ok(())
}

/// Agent labels below the labelling rule, each with the grade it was judged
/// against: the one stored with the label, else (an older line) the grade
/// now from the review file's own records, said as such.
pub fn below_rule(
    store: &ReviewStore,
    rules: &sc_core::Rules,
    show: usize,
    out: &mut impl Write,
) -> Result<()> {
    let agents: Vec<&Review> = store
        .entries
        .values()
        .filter(|r| r.label == "agent")
        .collect();
    if agents.is_empty() {
        return Ok(());
    }
    let now = if agents.iter().any(|r| r.grade.is_none()) {
        grades_now(store, rules)
    } else {
        BTreeMap::new()
    };
    let below: Vec<(&Review, LabelGrade, GradeFrom)> = agents
        .iter()
        .filter_map(|r| {
            let (g, from) = r.judged_grade(|| now.get(&r.record.id).cloned())?;
            g.below_rule().then_some((*r, g, from))
        })
        .collect();
    let from_now = below.iter().filter(|b| b.2 == GradeFrom::Now).count();
    writeln!(
        out,
        "agent labels below the labelling rule (agent needs L2 or higher): {} of {} agent label(s){}",
        below.len(),
        agents.len(),
        if from_now > 0 {
            format!(
                "; {from_now} graded now from the review file's records, since their lines store no grade"
            )
        } else {
            String::new()
        }
    )?;
    for (r, g, from) in below.iter().take(show) {
        writeln!(
            out,
            "  {} · {} (grade {}) · {}",
            r.record.id,
            g.short(),
            from.word(),
            r.note
                .as_deref()
                .map_or("no reason noted".into(), |n| format!(
                    "reason: {}",
                    crate::suggest::defang_all(n)
                ))
        )?;
    }
    if below.len() > show {
        writeln!(out, "  and {} more", below.len() - show)?;
    }
    Ok(())
}

/// The baseline sample reviewed so far (`review:baseline-sample`) and what
/// its benign records bound: the false-positive rate at suggestive or above
/// (tier at review time) with its Wilson interval, and with none flagged the
/// rule of three, `3/n`. Agent labels in it are misses.
pub fn baseline(store: &ReviewStore, out: &mut impl Write) -> Result<()> {
    let all: Vec<&Review> = store
        .entries
        .values()
        .filter(|r| r.class == CLASS_BASELINE)
        .collect();
    if all.is_empty() {
        return Ok(());
    }
    let sampled: Vec<&&Review> = all.iter().filter(|r| !r.tuned).collect();
    let benign: Vec<&&&Review> = sampled.iter().filter(|r| r.label == "benign").collect();
    let agents = sampled.iter().filter(|r| r.label == "agent").count();
    let n = benign.len();
    let k = benign.iter().filter(|r| r.tier >= Tier::Suggestive).count();
    let p = sc_core::eval::stats::Proportion::new(k, n);
    let pct = |x: Option<f64>| x.map_or("n/a".into(), |v| format!("{:.2}%", v * 100.0));
    let target = sc_core::eval::baseline::TARGET;
    writeln!(
        out,
        "benign baseline: {} baseline-sample reviews ({} tuned, left out) · {n} benign of the {target} target · {agents} agent (misses) · benign flagged suggestive+ at review {k} · FP rate {} [{}–{}]",
        all.len(),
        all.len() - sampled.len(),
        pct(p.value),
        pct(p.lo),
        pct(p.hi)
    )?;
    if n == 0 {
        return Ok(());
    }
    if k == 0 {
        writeln!(
            out,
            "  none flagged: by the rule of three the FP rate is below 3/{n} = {:.2}% (95%); below 0.5% needs more than 600 benign records with none flagged",
            300.0 / n as f64
        )?;
    }
    writeln!(
        out,
        "  for the current rules, run `swarmchase eval {}`",
        store.path.display()
    )?;
    Ok(())
}

/// The ids of every record in any review file in `dir`.
pub fn reviewed_ids(dir: &Path) -> Result<BTreeSet<String>> {
    let mut out = BTreeSet::new();
    for (_, p) in labeller_files(dir)? {
        out.extend(ReviewStore::open(p)?.entries.into_keys());
    }
    Ok(out)
}

/// Each reviewed record's label across the review files in `dir`; the
/// default file's label wins over another labeller's.
pub fn labels(dir: &Path) -> Result<BTreeMap<String, String>> {
    let mut out = BTreeMap::new();
    let mut files = labeller_files(dir)?;
    files.sort_by_key(|(who, _)| who == "default");
    for (_, p) in files {
        for (id, r) in ReviewStore::open(p)?.entries {
            out.insert(id, r.label);
        }
    }
    Ok(out)
}

/// Every review file in `dir` with its labeller: `default` for
/// `reviewed.ndjson`, else the name in `reviewed-<name>.ndjson`.
fn labeller_files(dir: &Path) -> Result<Vec<(String, PathBuf)>> {
    let mut out = Vec::new();
    let Ok(rd) = std::fs::read_dir(dir) else {
        return Ok(out);
    };
    for e in rd {
        let p = e?.path();
        let Some(name) = p.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        let who = if name == "reviewed.ndjson" {
            "default".to_string()
        } else if let Some(n) = name
            .strip_prefix("reviewed-")
            .and_then(|n| n.strip_suffix(".ndjson"))
        {
            n.to_string()
        } else {
            continue;
        };
        out.push((who, p));
    }
    out.sort();
    Ok(out)
}

/// Agreement between two labellers over the records both reviewed.
#[derive(Debug, PartialEq)]
pub struct PairAgreement {
    pub a: String,
    pub b: String,
    pub overlap: usize,
    pub agree: usize,
    pub kappa: Option<f64>,
    /// (record id, a's label, b's label).
    pub disagreements: Vec<(String, String, String)>,
}

pub fn pair_agreement(a: (&str, &ReviewStore), b: (&str, &ReviewStore)) -> PairAgreement {
    let mut pairs = Vec::new();
    let mut disagreements = Vec::new();
    for (id, ra) in &a.1.entries {
        if let Some(rb) = b.1.entries.get(id) {
            pairs.push((ra.label.as_str(), rb.label.as_str()));
            if ra.label != rb.label {
                disagreements.push((id.clone(), ra.label.clone(), rb.label.clone()));
            }
        }
    }
    PairAgreement {
        a: a.0.to_string(),
        b: b.0.to_string(),
        overlap: pairs.len(),
        agree: pairs.len() - disagreements.len(),
        kappa: sc_core::eval::stats::cohen_kappa(&pairs),
        disagreements,
    }
}

/// Cohen's κ for every pair of review files in `dir`.
pub fn agreement_report(dir: &Path, out: &mut impl Write) -> Result<()> {
    let files = labeller_files(dir)?;
    if files.len() < 2 {
        return Ok(());
    }
    let stores: Vec<(String, ReviewStore)> = files
        .into_iter()
        .map(|(who, p)| Ok((who, ReviewStore::open(p)?)))
        .collect::<Result<_>>()?;
    writeln!(
        out,
        "\ninter-rater agreement (Cohen's κ over records both labelled; labels agent / benign / unsure):"
    )?;
    for i in 0..stores.len() {
        for j in i + 1..stores.len() {
            let p = pair_agreement((&stores[i].0, &stores[i].1), (&stores[j].0, &stores[j].1));
            if p.overlap == 0 {
                writeln!(out, "  {} vs {}: no records in common", p.a, p.b)?;
                continue;
            }
            let kappa = p
                .kappa
                .map_or("undefined (one label throughout)".into(), |k| {
                    format!("{k:.3}")
                });
            writeln!(
                out,
                "  {} vs {}: n {} · agree {} · κ {kappa}",
                p.a, p.b, p.overlap, p.agree
            )?;
            for (id, la, lb) in &p.disagreements {
                writeln!(out, "    {id}: {} {la} · {} {lb}", p.a, p.b)?;
            }
        }
    }
    Ok(())
}

pub fn check_min_tier(t: Tier) -> Result<Tier> {
    if t == Tier::Noise {
        bail!(
            "--min-tier noise would queue every record with any hit; use --unflagged for a sample instead"
        );
    }
    Ok(t)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sc_core::{Rules, analyze};

    fn o(id: &str, ts: i64, url: &str) -> Observation {
        Observation {
            id: id.into(),
            source: "test".into(),
            ts,
            url: url.into(),
            ..Default::default()
        }
    }

    fn analysis() -> Analysis {
        let inbox = "https://webhook.site/0b6c1f0e-1111-4c2a-9a55-3f2e1d0c9b8a";
        let mut obs = vec![
            o("c1", 1000, &format!("{inbox}?kind=headers0")),
            o(
                "c2",
                1040,
                &format!("https://r.jina.ai/https://data.portal.example/p/1?uqtag=a1b2&cb={inbox}"),
            ),
            o(
                "solo",
                5000,
                "https://r.jina.ai/https://t.example/?q=1%20OR%201=1",
            ),
        ];
        for i in 0..20 {
            obs.push(o(
                &format!("plain{i}"),
                9000 + i,
                &format!("https://www.example.org/{i}"),
            ));
        }
        analyze(obs, &Rules::default_rules())
    }

    fn tmp_store(name: &str) -> ReviewStore {
        let dir =
            std::env::temp_dir().join(format!("swarmchase-review-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        ReviewStore::open(ReviewStore::path_in(&dir)).unwrap()
    }

    /// Cases go in the store's data directory.
    fn sink(store: &ReviewStore) -> CaseSink {
        CaseSink {
            root: store.path.parent().unwrap().parent().unwrap().join("cases"),
            rules: crate::pinning::RulesText::load(None).unwrap(),
            from: "leads.ndjson".into(),
            today: "2026-10-12".into(),
        }
    }

    #[test]
    fn a_save_keeps_what_another_writer_saved_meanwhile() {
        let a = analysis();
        let review = |id: &str, label: &str| {
            let r = a.results.iter().find(|r| r.obs.id == id).unwrap();
            Review {
                record: r.obs.clone(),
                label: label.into(),
                note: None,
                class: CLASS_FLAGGED.into(),
                reviewed_at: "x".into(),
                tier: r.tier,
                score: r.score,
                rules: Vec::new(),
                rules_version: a.rules_version.clone(),
                suggested: None,
                tuned: false,
                grade: None,
            }
        };
        let mut first = tmp_store("merge");
        first.entries.insert("c1".into(), review("c1", "agent"));
        first.entries.insert("c2".into(), review("c2", "benign"));
        first.save().unwrap();
        // A long-lived page opens the file, then `review tuned` marks c1.
        let mut page = ReviewStore::open(first.path.clone()).unwrap();
        let mut tuned = ReviewStore::open(first.path.clone()).unwrap();
        tuned.entries.get_mut("c1").unwrap().tuned = true;
        tuned.save().unwrap();
        // The page labels another record, relabels c1 and clears c2.
        page.entries
            .insert("plain1".into(), review("plain1", "benign"));
        page.entries.get_mut("c1").unwrap().label = "unsure".into();
        page.entries.remove("c2");
        page.save().unwrap();
        let saved = ReviewStore::open(first.path.clone()).unwrap().entries;
        let ids: Vec<&str> = saved.keys().map(String::as_str).collect();
        assert_eq!(ids, ["c1", "plain1"]);
        assert_eq!(saved["c1"].label, "unsure");
        assert!(saved["c1"].tuned, "the tuned mark survives the page's save");
        assert_eq!(page.entries.len(), 2);
        // No temporary file is left beside the review file.
        let dir = first.path.parent().unwrap();
        let tmp = std::fs::read_dir(dir)
            .unwrap()
            .filter(|e| {
                e.as_ref()
                    .unwrap()
                    .path()
                    .extension()
                    .is_some_and(|x| x == "tmp")
            })
            .count();
        assert_eq!(tmp, 0);
        let _ = std::fs::remove_dir_all(dir.parent().unwrap());
    }

    #[test]
    fn labeller_files_and_kappa() {
        let dir =
            std::env::temp_dir().join(format!("swarmchase-review-kappa-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(
            ReviewStore::path_for(&dir, None).unwrap(),
            ReviewStore::path_in(&dir)
        );
        assert!(ReviewStore::path_for(&dir, Some("../x")).is_err());
        let a = analysis();
        let mk = |who: &str, labels: &[(&str, &str)]| {
            let path = ReviewStore::path_for(&dir, Some(who)).unwrap();
            let mut s = ReviewStore::open(path).unwrap();
            for (id, l) in labels {
                let r = a.results.iter().find(|r| r.obs.id == *id).unwrap();
                s.entries.insert(
                    id.to_string(),
                    Review {
                        record: r.obs.clone(),
                        label: l.to_string(),
                        note: None,
                        class: CLASS_FLAGGED.into(),
                        reviewed_at: "x".into(),
                        tier: r.tier,
                        score: r.score,
                        rules: Vec::new(),
                        rules_version: a.rules_version.clone(),
                        suggested: None,
                        tuned: false,
                        grade: None,
                    },
                );
            }
            s.save().unwrap();
            s
        };
        let ann = mk(
            "ann",
            &[
                ("c1", "agent"),
                ("c2", "agent"),
                ("plain1", "benign"),
                ("plain2", "benign"),
            ],
        );
        let bob = mk(
            "bob",
            &[
                ("c1", "agent"),
                ("c2", "benign"),
                ("plain1", "benign"),
                ("solo", "agent"),
            ],
        );
        let p = pair_agreement(("ann", &ann), ("bob", &bob));
        assert_eq!((p.overlap, p.agree), (3, 2));
        assert_eq!(
            p.disagreements,
            [("c2".into(), "agent".into(), "benign".into())]
        );
        // po = 2/3; pe = (2/3)(1/3) + (1/3)(2/3) = 4/9; kappa = 0.4.
        assert!((p.kappa.unwrap() - 0.4).abs() < 1e-9);
        let mut out = Vec::new();
        agreement_report(&dir.join("labels"), &mut out).unwrap();
        let out = String::from_utf8(out).unwrap();
        assert!(out.contains("ann vs bob: n 3 · agree 2 · κ 0.400"), "{out}");
        assert!(out.contains("c2: ann agent · bob benign"), "{out}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn all_queues_every_record_and_stats_bound_the_baseline() {
        let a = analysis();
        let q = queue_all(&a, &BTreeSet::new());
        assert_eq!(q.len(), a.results.len());
        assert!(q.iter().all(|i| i.class == CLASS_BASELINE));
        let mut store = tmp_store("baseline");
        for it in q.iter().filter(|it| a.results[it.idx].score == 0) {
            let r = &a.results[it.idx];
            store.entries.insert(
                r.obs.id.clone(),
                Review {
                    record: r.obs.clone(),
                    label: "benign".into(),
                    note: None,
                    class: CLASS_BASELINE.into(),
                    reviewed_at: "x".into(),
                    tier: r.tier,
                    score: r.score,
                    rules: Vec::new(),
                    rules_version: a.rules_version.clone(),
                    suggested: None,
                    tuned: false,
                    grade: None,
                },
            );
        }
        let n = store.entries.len();
        let mut out = Vec::new();
        baseline(&store, &mut out).unwrap();
        let out = String::from_utf8(out).unwrap();
        assert!(
            out.contains(&format!("{n} benign of the 1000 target · 0 agent")),
            "{out}"
        );
        assert!(out.contains(&format!("below 3/{n}")), "{out}");

        // A tuned record leaves the baseline, here and in eval's labels.
        let id = store.entries.keys().next().unwrap().clone();
        store.entries.get_mut(&id).unwrap().tuned = true;
        let mut out = Vec::new();
        baseline(&store, &mut out).unwrap();
        let out = String::from_utf8(out).unwrap();
        assert!(out.contains("(1 tuned, left out)"), "{out}");
        assert!(out.contains(&format!("{} benign of", n - 1)), "{out}");
        store.save().unwrap();
        let text = std::fs::read_to_string(&store.path).unwrap();
        let labels = sc_core::parse_labels(&text);
        assert!(labels.labels[&id].tuned);
        let b = sc_core::eval::baseline::baseline(&a, &labels).unwrap();
        assert_eq!((b.benign, b.excluded), (n - 1, 1));

        // `review tuned` marks by id in every review file.
        let data = store.path.parent().unwrap().parent().unwrap().to_path_buf();
        let other = store.entries.keys().nth(1).unwrap().clone();
        mark_tuned(&TunedArgs {
            ids: vec![other.clone(), "no:such".into()],
            data: data.clone(),
        })
        .unwrap();
        assert!(ReviewStore::open(store.path.clone()).unwrap().entries[&other].tuned);
        assert_eq!(reviewed_ids(&data.join("labels")).unwrap().len(), n);
    }

    #[test]
    fn answers() {
        assert_eq!(parse_answer("a"), Answer::Label("agent", None, false));
        assert_eq!(
            parse_answer(" b  article read \n"),
            Answer::Label("benign", Some("article read".into()), false)
        );
        assert_eq!(parse_answer("A"), Answer::Label("agent", None, true));
        assert_eq!(parse_answer("u"), Answer::Label("unsure", None, false));
        assert_eq!(parse_answer("bogus"), Answer::Help);
        assert_eq!(parse_answer(""), Answer::Help);
        assert_eq!(parse_answer("q"), Answer::Quit);
        assert_eq!(parse_answer("s"), Answer::Skip);
        assert_eq!(parse_answer("c"), Answer::Case(None));
        assert_eq!(parse_answer("c t-3"), Answer::Case(Some("t-3".into())));
        assert_eq!(parse_answer("cases"), Answer::Help);
    }

    #[test]
    fn queue_orders_flagged_then_a_stable_sample() {
        let a = analysis();
        let q = queue(&a, &BTreeSet::new(), Tier::Suggestive, 3);
        let flagged: Vec<&str> = q
            .iter()
            .filter(|i| i.class == CLASS_FLAGGED)
            .map(|i| a.results[i.idx].obs.id.as_str())
            .collect();
        assert!(flagged.contains(&"solo"));
        assert_eq!(q.iter().filter(|i| i.class == CLASS_SAMPLE).count(), 3);
        assert_eq!(
            q,
            queue(&a, &BTreeSet::new(), Tier::Suggestive, 3),
            "deterministic"
        );

        let done: BTreeSet<String> = flagged.iter().map(|s| s.to_string()).collect();
        assert!(
            queue(&a, &done, Tier::Suggestive, 0).is_empty(),
            "reviewed records leave the queue"
        );
    }

    #[test]
    fn session_saves_labels_that_eval_reads() {
        let a = analysis();
        let q = queue(&a, &BTreeSet::new(), Tier::Suggestive, 1);
        let mut store = tmp_store("session");
        let cases = sink(&store);
        let mut out = Vec::new();
        // First record: help, then a cluster-wide agent label; the rest benign; then quit.
        let input = "?\nA run of the webhook cluster\nb\nb\nb\nb\nq\n";
        // A model that always says benign: shown, saved beside the label,
        // never taken as it.
        let suggest = |_: &Analysis, _: usize| {
            Some(Suggestion {
                label: "benign".into(),
                reason: "looks like a reader".into(),
                model: "m".into(),
            })
        };
        let t = session(
            &a,
            &q,
            &mut store,
            input.as_bytes(),
            &mut out,
            &Session {
                now: "2026-10-12",
                cases: &cases,
                suggest: &suggest,
            },
        )
        .unwrap();
        let out = String::from_utf8(out).unwrap();
        assert!(out.contains("a = agent"));
        assert!(
            out.contains("suggestion: benign, looks like a reader (m; a suggestion only)"),
            "{out}"
        );
        assert!(t.labelled.values().sum::<usize>() >= 2);
        let shown = &store.entries[&a.results[q[0].idx].obs.id];
        assert_eq!(shown.label, "agent");
        assert_eq!(shown.suggested.as_ref().unwrap().label, "benign");

        let reopened = ReviewStore::open(store.path.clone()).unwrap();
        assert_eq!(reopened.entries.len(), store.entries.len());
        let text = std::fs::read_to_string(&store.path).unwrap();
        let labels = sc_core::parse_labels(&text);
        assert_eq!(labels.labels.len(), store.entries.len());
        let parsed = sc_core::parse_input(&text, sc_core::Format::Auto, &Default::default());
        assert_eq!(
            parsed.observations.len(),
            store.entries.len(),
            "the review file is also eval input"
        );

        let first = &a.results[q[0].idx];
        if let Some(c) = first.cluster {
            for &m in &a.clusters[c].members {
                let r = &reopened.entries[&a.results[m].obs.id];
                assert_eq!(r.label, "agent");
                // Only the record on screen had a suggestion.
                assert_eq!(r.suggested.is_some(), m == q[0].idx);
            }
        }
        assert_eq!(
            labels.labels[&first.obs.id].label,
            sc_core::Label::Agent,
            "eval reads the admin's label"
        );
        std::fs::remove_dir_all(store.path.parent().unwrap().parent().unwrap()).unwrap();
    }

    #[test]
    fn agent_below_the_rule_shows_the_grade_and_asks_for_a_reason() {
        let a = analysis();
        let solo = a.results.iter().position(|r| r.obs.id == "solo").unwrap();
        assert!(!LabelGrade::of(&a, solo, "agent").agent_allowed);
        let q = vec![Item {
            idx: solo,
            class: CLASS_FLAGGED,
        }];
        let run = |input: &str| {
            let mut store = tmp_store("below");
            let cases = sink(&store);
            let mut out = Vec::new();
            session(
                &a,
                &q,
                &mut store,
                input.as_bytes(),
                &mut out,
                &Session {
                    now: "2026-10-12",
                    cases: &cases,
                    suggest: &|_, _| None,
                },
            )
            .unwrap();
            let r = store.entries.get("solo").cloned();
            let _ = std::fs::remove_dir_all(store.path.parent().unwrap().parent().unwrap());
            (r, String::from_utf8(out).unwrap())
        };
        // A reason at the prompt is saved as the note, with the grade.
        let (r, out) = run("a\nseen with cluster c4\n");
        assert!(out.contains("  grade:   L"), "{out}");
        assert!(
            out.contains("(below L2: unsure is the most the rule allows)"),
            "{out}"
        );
        assert!(
            out.contains("below the labelling rule: 1 of 1 record(s) at L"),
            "{out}"
        );
        assert!(out.contains("marked `below_l2`"), "{out}");
        let r = r.unwrap();
        assert_eq!(r.label, "agent");
        assert_eq!(r.note.as_deref(), Some("seen with cluster c4"));
        let g = r.grade.unwrap();
        assert!(g.below_rule() && !g.agent_allowed);
        assert_eq!(g.basis, "record");
        // A note given with the key is the reason: no prompt.
        let (r, out) = run("a pasted with residue\n");
        assert!(!out.contains("reason, saved as the note"), "{out}");
        assert_eq!(r.unwrap().note.as_deref(), Some("pasted with residue"));
        // `u` at the prompt labels unsure instead, with no marker.
        let (r, _) = run("a\nu\n");
        let r = r.unwrap();
        assert_eq!(r.label, "unsure");
        assert!(r.grade.unwrap().rule.is_none());
        // Enter asks again: the reason is required.
        let (r, out) = run("a\n\nthe run's write-up\n");
        assert_eq!(out.matches("reason, saved as the note").count(), 2, "{out}");
        let r = r.unwrap();
        assert_eq!(
            (r.label.as_str(), r.note.as_deref()),
            ("agent", Some("the run's write-up"))
        );
        // Input ending without one labels unsure.
        let (r, _) = run("a\n\n");
        assert_eq!(r.unwrap().label, "unsure");
    }

    #[test]
    fn old_lines_without_a_grade_read_and_are_graded_now_in_stats() {
        let a = analysis();
        let mut store = tmp_store("old");
        let solo = a.results.iter().find(|r| r.obs.id == "solo").unwrap();
        let mut line = serde_json::to_value(Review {
            record: solo.obs.clone(),
            label: "agent".into(),
            note: None,
            class: CLASS_FLAGGED.into(),
            reviewed_at: "x".into(),
            tier: solo.tier,
            score: solo.score,
            rules: Vec::new(),
            rules_version: a.rules_version.clone(),
            suggested: None,
            tuned: false,
            grade: None,
        })
        .unwrap();
        assert!(line.get("grade").is_none(), "no grade, no field: {line}");
        // An older line has no `grade` field at all.
        line.as_object_mut().unwrap().remove("grade");
        std::fs::create_dir_all(store.path.parent().unwrap()).unwrap();
        std::fs::write(&store.path, format!("{line}\n")).unwrap();
        store = ReviewStore::open(store.path.clone()).unwrap();
        let old = &store.entries["solo"];
        assert!(old.grade.is_none());
        let (g, from) = old
            .judged_grade(|| Some(LabelGrade::of(&a, 0, "agent")))
            .unwrap();
        assert_eq!(from, GradeFrom::Now);
        assert!(g.rule.is_some() || g.agent_allowed);
        assert!(
            old.judged_grade(|| None).is_none(),
            "unknown without an analysis"
        );

        let mut out = Vec::new();
        stats(&store, &Rules::default_rules(), &mut out).unwrap();
        let out = String::from_utf8(out).unwrap();
        assert!(
            out.contains("agent labels below the labelling rule (agent needs L2 or higher): 1 of 1 agent label(s); 1 graded now from the review file's records"),
            "{out}"
        );
        assert!(out.contains("  solo · L"), "{out}");
        assert!(out.contains("(grade now) · no reason noted"), "{out}");
        let c = count_below_rule(&store, &a);
        assert_eq!((c.agents, c.total, c.graded_now, c.flagged), (1, 1, 1, 1));

        // Once stored, the stored grade is read and said so.
        let idx = a.results.iter().position(|r| r.obs.id == "solo").unwrap();
        store.entries.get_mut("solo").unwrap().grade = Some(LabelGrade::of(&a, idx, "agent"));
        store.entries.get_mut("solo").unwrap().note = Some("why".into());
        let mut out = Vec::new();
        stats(&store, &Rules::default_rules(), &mut out).unwrap();
        let out = String::from_utf8(out).unwrap();
        assert!(out.contains("1 of 1 agent label(s)\n"), "{out}");
        assert!(out.contains("(grade stored) · reason: why"), "{out}");
        let c = count_below_rule(&store, &a);
        assert_eq!((c.graded_now, c.with_reason), (0, 1));
        let _ = std::fs::remove_dir_all(store.path.parent().unwrap().parent().unwrap());
    }

    #[test]
    fn end_of_input_quits_cleanly() {
        let a = analysis();
        let q = queue(&a, &BTreeSet::new(), Tier::Suggestive, 0);
        let mut store = tmp_store("eof");
        let cases = sink(&store);
        let t = session(
            &a,
            &q,
            &mut store,
            "".as_bytes(),
            &mut Vec::new(),
            &Session {
                now: "x",
                cases: &cases,
                suggest: &|_, _| None,
            },
        )
        .unwrap();
        assert!(t.quit);
        assert!(store.entries.is_empty());
    }

    #[test]
    fn c_opens_a_case_from_the_cluster_or_adds_to_one() {
        let a = analysis();
        let store = tmp_store("case");
        let sink = sink(&store);
        let idx = a.results.iter().position(|r| r.cluster.is_some()).unwrap();
        let cluster = &a.clusters[a.results[idx].cluster.unwrap()];
        let members: BTreeSet<&str> = cluster
            .members
            .iter()
            .map(|&m| a.results[m].obs.id.as_str())
            .collect();

        let opened = case_from_cluster(&a, idx, None, &sink).unwrap();
        assert!(opened.opened);
        assert_eq!(opened.added, members.len());
        assert!(opened.id.starts_with("review-2026-10-12-"), "{}", opened.id);
        let c = crate::case::load(&sink.root, &opened.id).unwrap();
        assert!(c.rules_version.is_some(), "pinned");
        assert_eq!(
            c.decisions.last().unwrap().text,
            format!(
                "opened from review of leads.ndjson, cluster {} ({})",
                cluster.id, cluster.key
            )
        );
        let again = case_from_cluster(&a, idx, None, &sink).unwrap();
        assert_eq!(again.id, format!("{}-2", opened.id), "never overwrites");

        // `c <id>`: the cluster again adds nothing; another record is added
        // and logged.
        let same = case_from_cluster(&a, idx, Some(&opened.id), &sink).unwrap();
        assert_eq!((same.opened, same.added), (false, 0));
        let solo = a.results.iter().position(|r| r.obs.id == "solo").unwrap();
        let more = case_from_cluster(&a, solo, Some(&opened.id), &sink).unwrap();
        assert!(more.added >= 1);
        let c = crate::case::load(&sink.root, &opened.id).unwrap();
        let last = &c.decisions.last().unwrap().text;
        assert!(
            last.starts_with(&format!(
                "added {} record(s) from review of leads.ndjson, ",
                more.added
            )),
            "{last}"
        );
        assert!(case_from_cluster(&a, idx, Some("no-such-case"), &sink).is_err());

        // In a session: `c` opens, a bad id is reported and re-prompts, then
        // the record is still labelled.
        let q = queue(&a, &BTreeSet::new(), Tier::Suggestive, 0);
        let mut store = store;
        let mut out = Vec::new();
        let t = session(
            &a,
            &q,
            &mut store,
            "c\nc no-such-case\na\nq\n".as_bytes(),
            &mut out,
            &Session {
                now: "2026-10-12",
                cases: &sink,
                suggest: &|_, _| None,
            },
        )
        .unwrap();
        let out = String::from_utf8(out).unwrap();
        assert!(out.contains("opened case review-2026-10-12-"), "{out}");
        assert!(out.contains("case: no case at"), "{out}");
        assert_eq!(t.labelled.get("agent"), Some(&1));
        std::fs::remove_dir_all(sink.root.parent().unwrap()).unwrap();
    }
}
