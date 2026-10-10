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
//! stored (already redacted) record plus `label`, `note`, `class` and what the
//! rules said at review time. The file is both a label file and an eval input:
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

use crate::util::truncate;
use anyhow::{Context, Result, bail};
use sc_core::{Analysis, Observation, Tier, defang, fmt_ts};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};

pub const CLASS_FLAGGED: &str = "review:flagged";
pub const CLASS_SAMPLE: &str = "review:unflagged-sample";

#[derive(clap::Args)]
pub struct ReviewArgs {
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
}

pub fn run(args: ReviewArgs) -> Result<()> {
    let data = &args.data;
    if args.input.is_empty() || args.stats {
        crate::store::hint_if_empty(data);
    }
    let path = ReviewStore::path_for(data, args.labeller.as_deref())?;
    let mut store = ReviewStore::open(path)?;
    if args.stats {
        stats(&store, &mut std::io::stdout())?;
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
    let done = store.entries.keys().cloned().collect();
    let items = queue(&a, &done, min, args.unflagged);
    println!(
        "{} records · {} reviewed before · {} in the queue ({} flagged, {} unflagged sample)",
        a.total,
        store.entries.len(),
        items.len(),
        items.iter().filter(|i| i.class == CLASS_FLAGGED).count(),
        items.iter().filter(|i| i.class == CLASS_SAMPLE).count(),
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
    let stdin = std::io::stdin();
    let t = session(
        &a,
        &items,
        &mut store,
        stdin.lock(),
        &mut std::io::stdout(),
        &chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
        &CaseSink {
            root: data.join("cases"),
            rules,
            from,
            today: crate::util::today(),
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
}

/// The review file, keyed by record ID. Saving rewrites it, so a re-review
/// replaces the earlier line instead of duplicating the record.
pub struct ReviewStore {
    path: PathBuf,
    pub entries: BTreeMap<String, Review>,
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
        let mut entries = BTreeMap::new();
        match std::fs::read_to_string(&path) {
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
        Ok(Self { path, entries })
    }

    pub fn save(&self) -> Result<()> {
        if let Some(dir) = self.path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let mut text = String::new();
        for r in self.entries.values() {
            text.push_str(&serde_json::to_string(r)?);
            text.push('\n');
        }
        let tmp = self.path.with_extension("ndjson.tmp");
        std::fs::write(&tmp, text)?;
        std::fs::rename(&tmp, &self.path)
            .with_context(|| format!("writing {}", self.path.display()))
    }
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

/// Step through `items`, reading answers from `input`. Each answer is saved
/// before the next record is shown, so quitting or a crash loses nothing.
pub fn session(
    a: &Analysis,
    items: &[Item],
    store: &mut ReviewStore,
    mut input: impl BufRead,
    out: &mut impl Write,
    now: &str,
    cases: &CaseSink,
) -> Result<Tally> {
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

/// Counts in the review file, and where the rules disagree with the admin.
pub fn stats(store: &ReviewStore, out: &mut impl Write) -> Result<()> {
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
    if fp + missed > 0 {
        writeln!(
            out,
            "Run `swarmchase eval {}` for the full table. Fix the rules and add a reconstructed record to samples/eval/ as a regression case.",
            store.path.display()
        )?;
    }
    Ok(())
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
        let t = session(
            &a,
            &q,
            &mut store,
            input.as_bytes(),
            &mut out,
            "2026-10-12",
            &cases,
        )
        .unwrap();
        assert!(String::from_utf8(out).unwrap().contains("a = agent"));
        assert!(t.labelled.values().sum::<usize>() >= 2);

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
                assert_eq!(reopened.entries[&a.results[m].obs.id].label, "agent");
            }
        }
        std::fs::remove_dir_all(store.path.parent().unwrap().parent().unwrap()).unwrap();
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
            "x",
            &cases,
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
            "2026-10-12",
            &sink,
        )
        .unwrap();
        let out = String::from_utf8(out).unwrap();
        assert!(out.contains("opened case review-2026-10-12-"), "{out}");
        assert!(out.contains("case: no case at"), "{out}");
        assert_eq!(t.labelled.get("agent"), Some(&1));
        std::fs::remove_dir_all(sink.root.parent().unwrap()).unwrap();
    }
}
