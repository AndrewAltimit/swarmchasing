//! `swarmchase inbox`: outside reports of swarms (SC-Submission v1).
//!
//! Submissions arrive as files: an email attachment, a GitHub private
//! vulnerability report, or a drop directory on the runner. `inbox add`
//! validates and redacts each one and keeps it under `<data>/inbox/`
//! ([`files`]), outside git, then triages it. `inbox verify` looks its
//! public-record references up by id ([`verify`]); `inbox signature`
//! records the admin's check of a signed artifact; `inbox triage` shows what
//! deserves the admin's attention; `inbox promote` turns an examined
//! submission into a review lead or adds what the toolkit found to a case.
//!
//! What a submission is and how it is judged is the `sc-inbox` crate; this
//! module reads and writes the files and runs the lookups. Nothing in a
//! submission is ever published from here, and no URL in one is opened.

pub mod files;
pub mod verify;

use crate::pinning::RulesText;
use anyhow::{Context, Result, bail};
use clap::{Args, Subcommand};
use files::{SignatureCheck, Stored};
use sc_core::{Rules, defang, fmt_ts};
use sc_inbox::inert::inert;
use sc_inbox::{Checks, Evidence, EvidenceClass, Prior, Verdict, assess, corroborate, intake};
use std::io::Write;
use std::path::{Path, PathBuf};

#[derive(Args)]
pub struct InboxArgs {
    #[command(subcommand)]
    cmd: InboxCmd,
    /// Data directory (the watch's `--out`).
    #[arg(
        short,
        long,
        default_value = "data",
        env = "SWARMCHASE_DATA",
        global = true
    )]
    data: PathBuf,
    /// Rules file; the bundled rules by default.
    #[arg(long, global = true)]
    rules: Option<PathBuf>,
}

#[derive(Subcommand)]
enum InboxCmd {
    /// Take in submission files (or every `*.json` in a directory): validate,
    /// redact, store under the data directory, match against the watch
    /// store, and triage. The files themselves are not kept.
    Add {
        #[arg(required = true)]
        paths: Vec<PathBuf>,
        /// How they arrived: email | github-pvr | drop | manual
        #[arg(long, default_value = "drop")]
        via: String,
        /// The sender as the transport saw them (an address, an account).
        /// Kept private; used for rate limits before the submitter's own key.
        #[arg(long)]
        from: Option<String>,
    },
    /// List stored submissions with their verdicts.
    List {
        /// Only this verdict: examine | hold | discard
        #[arg(long)]
        verdict: Option<Verdict>,
    },
    /// Show one submission in full, every string inert.
    Show { id: String },
    /// Look up its public-record references by id (index rows and metadata
    /// only) and triage it again.
    Verify {
        /// Submission ids; `--all` for every one with references not yet
        /// verified.
        ids: Vec<String>,
        #[arg(long)]
        all: bool,
    },
    /// Record the admin's check of a signed artifact: valid and by a signer
    /// other than the submitter (`--valid`), or not (`--invalid`).
    Signature {
        id: String,
        /// The evidence item's index.
        item: usize,
        #[arg(long, conflicts_with = "invalid", required_unless_present = "invalid")]
        valid: bool,
        #[arg(long)]
        invalid: bool,
        /// How it was checked (key source, signer).
        #[arg(long)]
        note: String,
    },
    /// Triage every submission again under the current rules and settings,
    /// and print those to examine (`--all` for every one).
    Triage {
        #[arg(long)]
        all: bool,
        #[arg(long)]
        json: bool,
    },
    /// Admin action: queue an examined submission's records for review
    /// (`<data>/inbox/<id>/lead.ndjson`), or add them to a case. Only the
    /// records the toolkit found itself go to a case.
    Promote {
        id: String,
        #[arg(long)]
        case: Option<String>,
        /// Also queue the submitter's own records for review (never to a case).
        #[arg(long, conflicts_with = "case")]
        with_claimed: bool,
        /// Why a submission not triaged examine is promoted anyway; logged.
        #[arg(long)]
        reason: Option<String>,
    },
}

pub fn run(args: InboxArgs) -> Result<()> {
    let rules = RulesText::load(args.rules.as_deref())?.rules;
    let data = &args.data;
    let now = chrono::Utc::now().timestamp();
    let out = &mut std::io::stdout();
    match args.cmd {
        InboxCmd::Add { paths, via, from } => add(data, &rules, &paths, &via, from.as_deref(), now),
        InboxCmd::List { verdict } => list(data, verdict, out),
        InboxCmd::Show { id } => show(&files::load(data, &id)?, out),
        InboxCmd::Verify { ids, all } => verify_cmd(data, &rules, ids, all, now),
        InboxCmd::Signature {
            id,
            item,
            valid,
            invalid: _,
            note,
        } => {
            let mut s = files::load(data, &id)?;
            match s.intake.submission.evidence.get(item) {
                Some(Evidence::Signed(_)) => {}
                _ => bail!("item {item} of {id} is not a signed artifact"),
            }
            s.admin.signatures.insert(
                item,
                SignatureCheck {
                    valid,
                    date: crate::util::today(),
                    note,
                },
            );
            retriage(&mut s, data, &rules)?;
            s.save()?;
            print_line(&s, out)
        }
        InboxCmd::Triage { all, json } => triage(data, &rules, all, json, out),
        InboxCmd::Promote {
            id,
            case,
            with_claimed,
            reason,
        } => promote(data, &rules, &id, case.as_deref(), with_claimed, reason),
    }
}

/// Triage `s` again from what is stored.
fn retriage(s: &mut Stored, data: &Path, rules: &Rules) -> Result<()> {
    let settings = files::settings(data)?;
    let sigs = s.admin.signature_map();
    s.assessment = Some(assess(
        &s.intake,
        Checks {
            verifications: &s.verifications,
            found: &s.found,
            held: &s.held,
            signatures: &sigs,
        },
        rules,
        &settings.triage,
    ));
    Ok(())
}

/// The files `paths` name: each file, and the `*.json` files of each
/// directory, in name order.
fn submission_files(paths: &[PathBuf]) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    for p in paths {
        if p.is_dir() {
            let mut v: Vec<PathBuf> = std::fs::read_dir(p)?
                .filter_map(|e| e.ok().map(|e| e.path()))
                .filter(|f| f.is_file() && f.extension().and_then(|e| e.to_str()) == Some("json"))
                .collect();
            v.sort();
            out.extend(v);
        } else {
            out.push(p.clone());
        }
    }
    Ok(out)
}

fn add(
    data: &Path,
    rules: &Rules,
    paths: &[PathBuf],
    via: &str,
    from: Option<&str>,
    now: i64,
) -> Result<()> {
    if !matches!(via, "email" | "github-pvr" | "drop" | "manual") {
        bail!("--via is email, github-pvr, drop or manual");
    }
    let settings = files::settings(data)?;
    let mut prior: Vec<Prior> = files::all(data)?
        .iter()
        .map(|s| Prior::of(&s.intake))
        .collect();
    // The watch's records now: everything the watch holds was collected
    // before these submissions arrived.
    let store_dir = data.join("store");
    let store = if store_dir.is_dir() {
        crate::store::load_store(&store_dir, i64::MIN)?
    } else {
        Vec::new()
    };
    let (mut taken, mut refused) = (0, 0);
    for f in submission_files(paths)? {
        let meta = std::fs::metadata(&f).with_context(|| format!("reading {}", f.display()))?;
        if meta.len() as usize > settings.intake.caps.max_bytes {
            eprintln!(
                "{}: refused: {} bytes; the cap is {}",
                f.display(),
                meta.len(),
                settings.intake.caps.max_bytes
            );
            refused += 1;
            continue;
        }
        let text =
            std::fs::read_to_string(&f).with_context(|| format!("reading {}", f.display()))?;
        match intake(&text, now, via, from, &prior, &settings.intake) {
            Err(e) => {
                eprintln!("{}: refused: {}", f.display(), inert(&e.to_string(), 400));
                refused += 1;
            }
            Ok(i) => {
                let held = corroborate(&i, &store, rules, &settings.triage);
                let mut s = Stored {
                    dir: files::dir(data, &i.id)?,
                    intake: i,
                    held,
                    verifications: Vec::new(),
                    found: Vec::new(),
                    admin: Default::default(),
                    assessment: None,
                };
                retriage(&mut s, data, rules)?;
                s.save()?;
                prior.push(Prior::of(&s.intake));
                print_line(&s, &mut std::io::stdout())?;
                taken += 1;
            }
        }
    }
    eprintln!(
        "{taken} taken in, {refused} refused, under {}. The files themselves were not kept; only the redacted documents were.",
        files::root(data).display()
    );
    Ok(())
}

fn verify_cmd(data: &Path, rules: &Rules, ids: Vec<String>, all: bool, now: i64) -> Result<()> {
    if ids.is_empty() && !all {
        bail!("name submission ids, or --all");
    }
    let settings = files::settings(data)?;
    let mut targets: Vec<Stored> = if all {
        files::all(data)?
            .into_iter()
            .filter(|s| {
                s.intake
                    .submission
                    .evidence
                    .iter()
                    .enumerate()
                    .any(|(n, e)| {
                        matches!(e, Evidence::PublicRecord(_))
                            && !s.verifications.iter().any(|v| {
                                v.item == n
                                    && !matches!(
                                        v.status,
                                        sc_inbox::Status::Error | sc_inbox::Status::Skipped
                                    )
                            })
                    })
            })
            .collect()
    } else {
        ids.iter()
            .map(|id| files::load(data, id))
            .collect::<Result<_>>()?
    };
    let client = sc_collect::Client::new(std::time::Duration::from_millis(1500))?;
    let keys = verify::Keys::from_env();
    for s in &mut targets {
        let mut vs = Vec::new();
        let mut found = Vec::new();
        for (n, e) in s.intake.submission.evidence.iter().enumerate() {
            let Evidence::PublicRecord(r) = e else {
                continue;
            };
            let (v, recs) = verify::verify_item(
                &client,
                n,
                r,
                s.intake.received,
                now,
                &keys,
                &settings.triage,
            );
            println!(
                "{} item {n} ({}): {}: {}",
                s.intake.id,
                r.source.name(),
                v.status.label(),
                v.detail
            );
            vs.push(v);
            found.extend(recs);
        }
        s.verifications = vs;
        s.found = found;
        retriage(s, data, rules)?;
        s.save()?;
        print_line(s, &mut std::io::stdout())?;
    }
    eprintln!("{} lookup request(s)", client.requests());
    Ok(())
}

/// One line per submission: id, verdict, received, items by class, summary.
fn print_line(s: &Stored, out: &mut impl Write) -> Result<()> {
    let a = s.assessment.as_ref();
    let strong: usize = a.map_or(0, |a| {
        a.counts
            .iter()
            .filter(|(c, _)| c.strong())
            .map(|(_, n)| n)
            .sum()
    });
    writeln!(
        out,
        "{}  {:<7}  {}  {} item(s), {strong} strong  {}  {}",
        s.intake.id,
        a.map_or("-", |a| a.verdict.label()),
        fmt_ts(s.intake.received).get(..16).unwrap_or(""),
        s.intake.submission.evidence.len(),
        if s.intake.submission.submitter.ai_agent {
            "agent"
        } else {
            "person"
        },
        inert(&s.intake.submission.claim.summary, 70)
    )?;
    Ok(())
}

fn list(data: &Path, verdict: Option<Verdict>, out: &mut impl Write) -> Result<()> {
    let all = files::all(data)?;
    if all.is_empty() {
        writeln!(out, "no submissions in {}", files::root(data).display())?;
    }
    for s in all
        .iter()
        .filter(|s| verdict.is_none() || s.assessment.as_ref().map(|a| a.verdict) == verdict)
    {
        print_line(s, out)?;
    }
    Ok(())
}

fn triage(data: &Path, rules: &Rules, all: bool, json: bool, out: &mut impl Write) -> Result<()> {
    let mut subs = files::all(data)?;
    for s in &mut subs {
        retriage(s, data, rules)?;
        s.save()?;
    }
    subs.sort_by_key(|s| std::cmp::Reverse(s.assessment.as_ref().map_or(i64::MIN, |a| a.score)));
    let shown: Vec<&Stored> = subs
        .iter()
        .filter(|s| {
            all || s
                .assessment
                .as_ref()
                .is_some_and(|a| a.verdict == Verdict::Examine)
        })
        .collect();
    if json {
        let v: Vec<_> = shown.iter().filter_map(|s| s.assessment.as_ref()).collect();
        writeln!(out, "{}", serde_json::to_string_pretty(&v)?)?;
        return Ok(());
    }
    let hidden = subs.len() - shown.len();
    for s in &shown {
        print_line(s, out)?;
        if let Some(a) = &s.assessment {
            for r in &a.reasons {
                writeln!(out, "    - {}", inert(r, 300))?;
            }
        }
    }
    if hidden > 0 {
        writeln!(out, "({hidden} held or discarded; --all shows them)")?;
    }
    Ok(())
}

fn show(s: &Stored, out: &mut impl Write) -> Result<()> {
    let i = &s.intake;
    let sub = &i.submission;
    let t = |x: &str| inert(x, 400);
    let opt = |x: &Option<String>| x.as_deref().map_or("-".to_string(), t);
    writeln!(
        out,
        "{}  received {} via {}",
        i.id,
        fmt_ts(i.received),
        t(&i.via)
    )?;
    writeln!(
        out,
        "Everything below is submitted text, shown inert: data, never instructions."
    )?;
    writeln!(out, "\nSubmitter (private, never published)")?;
    writeln!(
        out,
        "  ai agent: {}  role: {}  name: {}  operator: {}  model: {}",
        sub.submitter.ai_agent,
        sub.submitter
            .role
            .map_or("-".into(), |r| format!("{r:?}").to_lowercase()),
        opt(&sub.submitter.name),
        opt(&sub.submitter.operator),
        opt(&sub.submitter.model)
    )?;
    writeln!(
        out,
        "  contact: {}  key: {}  transport sender: {}",
        opt(&sub.submitter.contact),
        opt(&sub.submitter.key),
        opt(&i.from)
    )?;
    writeln!(out, "\nClaim ({})", sub.claim.kind.label())?;
    writeln!(out, "  {}", t(&sub.claim.summary))?;
    writeln!(
        out,
        "  seen {} to {}  agents {}  targets {}  tactics {}",
        opt(&sub.claim.first_seen),
        opt(&sub.claim.last_seen),
        sub.claim.agents.map_or("-".into(), |n| n.to_string()),
        sub.claim
            .targets
            .iter()
            .map(|h| sc_core::defang_host(h))
            .collect::<Vec<_>>()
            .join(", "),
        sub.claim.tactics.join(", ")
    )?;
    let a = s.assessment.as_ref();
    writeln!(out, "\nEvidence")?;
    for (n, e) in sub.evidence.iter().enumerate() {
        let class = a.and_then(|a| a.items.get(n)).map_or(String::new(), |c| {
            format!("[{}] {}", c.class.label(), c.detail)
        });
        let what = match e {
            Evidence::PublicRecord(r) => format!(
                "{} id {} url {} at {}",
                r.source.name(),
                opt(&r.id),
                r.url.as_deref().map_or("-".into(), |u| t(&defang(u))),
                opt(&r.timestamp)
            ),
            Evidence::LogLines(l) => format!(
                "{} log line(s){}: {}",
                l.lines.len(),
                l.host.as_deref().map_or(String::new(), |h| format!(
                    " for {}",
                    sc_core::defang_host(h)
                )),
                l.lines.first().map_or(String::new(), |x| inert(x, 160))
            ),
            Evidence::Signed(g) => format!(
                "{:?} signed by {}: {}",
                g.scheme,
                opt(&g.signer),
                inert(&g.content, 160)
            ),
            Evidence::Indicator(x) => format!("{:?}: {}", x.kind, inert(&x.value, 160)),
        };
        writeln!(out, "  {n}. {} {what}", e.kind())?;
        if !class.is_empty() {
            writeln!(out, "     {class}")?;
        }
        if let Some(note) = e.note() {
            writeln!(out, "     note: {}", t(note))?;
        }
        if let Some(c) = s.admin.signatures.get(&n) {
            writeln!(
                out,
                "     signature checked {}: {} ({})",
                c.date,
                if c.valid { "valid" } else { "not valid" },
                t(&c.note)
            )?;
        }
    }
    if let Some(a) = a {
        writeln!(out, "\nTriage: {}", a.verdict.label())?;
        for r in &a.reasons {
            writeln!(out, "  - {}", inert(r, 300))?;
        }
        writeln!(out, "  fabrication cost: {}", a.cost)?;
        let g = |g: &sc_inbox::triage::Grade| {
            format!(
                "{} record(s), {} flagged, tier {}, {} cluster(s), agent grade {}, plant signals {}",
                g.records,
                g.flagged,
                g.tier.label(),
                g.clusters,
                g.agent,
                g.plant_signals
            )
        };
        writeln!(out, "  found by the toolkit: {}", g(&a.standing))?;
        writeln!(out, "  as submitted: {}", g(&a.claimed))?;
        for x in &a.inflation {
            writeln!(out, "  inflated: {x}")?;
        }
        let counts: Vec<String> = EvidenceClass::ALL
            .iter()
            .filter_map(|c| a.counts.get(c).map(|n| format!("{} {n}", c.label())))
            .collect();
        writeln!(out, "  items: {}", counts.join(", "))?;
    }
    if i.redacted > 0 {
        writeln!(out, "\n{} value(s) redacted at ingest", i.redacted)?;
    }
    for l in &s.admin.log {
        writeln!(out, "log: {}", t(l))?;
    }
    Ok(())
}

fn promote(
    data: &Path,
    rules: &Rules,
    id: &str,
    case: Option<&str>,
    with_claimed: bool,
    reason: Option<String>,
) -> Result<()> {
    let mut s = files::load(data, id)?;
    retriage(&mut s, data, rules)?;
    let a = s.assessment.clone().context("no triage")?;
    let today = crate::util::today();
    if a.verdict != Verdict::Examine && reason.is_none() {
        bail!(
            "{id} is triaged {}; give --reason to promote it anyway (logged)",
            a.verdict.label()
        );
    }
    // What the toolkit found itself: verified records and the watch's own.
    let verified: std::collections::BTreeSet<&str> = s
        .verifications
        .iter()
        .filter(|v| v.status == sc_inbox::Status::Verified)
        .filter_map(|v| v.record.as_deref())
        .collect();
    let mut seen = std::collections::BTreeSet::new();
    let mut records: Vec<sc_core::Observation> = s
        .found
        .iter()
        .filter(|o| verified.contains(o.id.as_str()))
        .chain(s.held.records.iter())
        .filter(|o| seen.insert(o.id.clone()))
        .cloned()
        .collect();
    let why = reason.map_or(String::new(), |r| format!(" ({})", inert(&r, 200)));
    match case {
        Some(case_id) => {
            if records.is_empty() {
                bail!("{id} has no record the toolkit found itself; nothing to add to a case");
            }
            let root = data.join("cases");
            crate::case::load(&root, case_id)?;
            let (n, hosts) = crate::case::add_records(&root, case_id, records, &today)?;
            crate::case::log_entry(
                &root,
                case_id,
                &today,
                format!("added {n} record(s) found for inbox submission {id}{why}"),
            )?;
            s.admin.log.push(format!(
                "{today} promoted to case {case_id}: {n} record(s){why}"
            ));
            println!("added {n} record(s), {hosts} new endpoint(s) to case {case_id}");
        }
        None => {
            if with_claimed {
                records.extend(
                    sc_inbox::evidence::claimed_records(
                        &s.intake.id,
                        &s.intake.submission.evidence,
                    )
                    .into_iter()
                    .map(|(_, o)| o),
                );
            }
            if records.is_empty() {
                bail!("{id} has no records to review (try --with-claimed)");
            }
            let p = s.dir.join("lead.ndjson");
            std::fs::write(&p, crate::store::to_ndjson(&records)?)?;
            s.admin.log.push(format!(
                "{today} promoted for review: {} record(s){}{why}",
                records.len(),
                if with_claimed {
                    ", the submitter's own included"
                } else {
                    ""
                }
            ));
            println!(
                "wrote {} record(s) to {}\nreview them with: swarmchase review {}",
                records.len(),
                p.display(),
                p.display()
            );
        }
    }
    s.save()
}
