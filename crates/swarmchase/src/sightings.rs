//! `swarmchase sightings`: make a sightings file from your own logs, and
//! match sightings files from several operators (SC-Sightings v1).
//!
//! `export` is what the workbench's *Share sightings* does, for an operator
//! who prefers the CLI. `match` is the admin's: it reads sightings files,
//! optionally the watch store's clusters, and prints which clusters more than
//! one party saw. It is read-only: it writes nothing into the watch data or
//! a case, and the scheduled watch never runs it. A match is a proposal for
//! case work, never a merge.

use crate::input::{InputArgs, load_rules, run_analysis};
use anyhow::{Context, Result, bail};
use clap::{Args, Subcommand};
use sc_core::sightings::{
    self, EpochKeys, ExportOptions, MatchReport, Party, Standing, match_sightings,
};
use sc_core::{Tier, analyze};
use std::path::{Path, PathBuf};

#[derive(Args)]
pub struct SightingsArgs {
    #[command(subcommand)]
    cmd: SightingsCmd,
}

#[derive(Subcommand)]
enum SightingsCmd {
    /// Make a sightings file from records (your access log): keyed hashes of
    /// linking features, scaffold, hour buckets and grades of each flagged
    /// cluster. No URL, path, query value, IP address or user agent.
    Export(ExportArgs),
    /// Match sightings files against each other and, with `--store`, against
    /// the watch store's clusters. Read-only; prints proposals.
    Match(MatchArgs),
}

#[derive(Args)]
struct ExportArgs {
    #[command(flatten)]
    input: InputArgs,
    /// Include your own host names, defanged. Off by default.
    #[arg(long)]
    include_hosts: bool,
    /// How you describe yourself to the recipient (a case id from our report).
    #[arg(long)]
    operator: Option<String>,
    /// Export only this cluster (id or key).
    #[arg(long)]
    cluster: Option<String>,
    /// Write here instead of standard output.
    #[arg(short, long)]
    out: Option<PathBuf>,
}

#[derive(Args)]
struct MatchArgs {
    /// Sightings files (`sc-sightings-v1` JSON).
    files: Vec<PathBuf>,
    /// `FILE=CASE`: the file came back from the affected operator of case
    /// CASE. It counts as `contacted` when the case records a report sent to
    /// an affected operator's contact, else `claimed`. Files without one are
    /// `unverified` and corroborate nothing.
    #[arg(long, value_name = "FILE=CASE")]
    vouch: Vec<String>,
    /// Also match the watch store's clusters (`<data>/store`), as party
    /// `watch`. Reads the store; writes nothing.
    #[arg(long)]
    store: bool,
    /// With `--store`: records captured in the last N days.
    #[arg(long, default_value_t = 30)]
    days: i64,
    /// Rules for the store's analysis (defaults to the bundled rules).
    #[arg(long)]
    rules: Option<PathBuf>,
    /// Data directory: cases in `<data>/cases`, the store in `<data>/store`.
    #[arg(short, long, default_value = "data", env = "SWARMCHASE_DATA")]
    data: PathBuf,
    /// Print the match report as JSON.
    #[arg(long)]
    json: bool,
}

pub fn run(args: SightingsArgs) -> Result<()> {
    match args.cmd {
        SightingsCmd::Export(a) => export(a),
        SightingsCmd::Match(a) => run_match(a),
    }
}

fn export(a: ExportArgs) -> Result<()> {
    let analysis = run_analysis(&a.input)?;
    let opts = ExportOptions {
        include_hosts: a.include_hosts,
        min_tier: Tier::Suggestive,
        cluster: a.cluster,
        operator: a.operator,
        generated: crate::util::today(),
    };
    let doc = sightings::export(&analysis, &opts, &EpochKeys::default());
    for e in &doc.missing_epochs {
        eprintln!("warning: no published key for epoch {e}; its features are left out");
    }
    let text = serde_json::to_string_pretty(&doc)? + "\n";
    match a.out {
        Some(p) => {
            std::fs::write(&p, text).with_context(|| format!("writing {}", p.display()))?;
            eprintln!(
                "wrote {} sighting(s) to {}{}",
                doc.sightings.len(),
                p.display(),
                if doc.shares_hosts {
                    " (with your host names)"
                } else {
                    ""
                }
            );
        }
        None => print!("{text}"),
    }
    Ok(())
}

/// The standing case `id` gives a file vouched for with it.
fn case_standing(data: &Path, id: &str) -> Result<Standing> {
    let c = crate::case::load(&data.join("cases"), id)?;
    let reached = c.sent.iter().any(|s| {
        let to = s.recipient.to_ascii_lowercase();
        c.contacts.iter().any(|k| {
            k.role.for_endpoint()
                && [&k.address, &k.org]
                    .iter()
                    .any(|v| !v.is_empty() && to.contains(&v.to_ascii_lowercase()))
        })
    });
    Ok(if reached {
        Standing::Contacted
    } else {
        Standing::Claimed
    })
}

fn run_match(a: MatchArgs) -> Result<()> {
    if a.files.is_empty() && !a.store {
        bail!("give sightings files, and --store to match the watch store too");
    }
    let mut vouched: Vec<(PathBuf, String)> = Vec::new();
    for v in &a.vouch {
        let Some((f, case)) = v.split_once('=') else {
            bail!("--vouch `{v}`: give FILE=CASE");
        };
        vouched.push((PathBuf::from(f), case.to_string()));
    }
    let mut parties = Vec::new();
    for f in &a.files {
        let text =
            std::fs::read_to_string(f).with_context(|| format!("reading {}", f.display()))?;
        let doc = sightings::parse(&text).map_err(|e| anyhow::anyhow!("{}: {e}", f.display()))?;
        let case = vouched.iter().find(|(p, _)| p == f).map(|(_, c)| c.clone());
        let (name, standing) = match case {
            Some(c) => {
                let s = case_standing(&a.data, &c)?;
                (c, s)
            }
            None => (format!("file:{}", f.display()), Standing::Unverified),
        };
        if let Some(op) = &doc.operator {
            eprintln!(
                "{}: describes itself as `{}` (not checked)",
                f.display(),
                crate::util::one_line(op, 120)
            );
        }
        parties.push(Party {
            name,
            standing,
            doc,
        });
    }
    for (p, _) in &vouched {
        if !a.files.contains(p) {
            bail!(
                "--vouch names {}, which is not among the files",
                p.display()
            );
        }
    }
    if a.store {
        let dir = a.data.join("store");
        crate::store::hint_if_empty(&a.data);
        let since = chrono::Utc::now().timestamp() - a.days * 86_400;
        let records = crate::store::load_store(&dir, since)
            .with_context(|| format!("reading the watch store at {}", dir.display()))?;
        let rules = load_rules(a.rules.as_deref())?;
        let analysis = analyze(records, &rules);
        let doc = sightings::export(
            &analysis,
            &ExportOptions {
                generated: crate::util::today(),
                ..Default::default()
            },
            &EpochKeys::default(),
        );
        parties.push(Party {
            name: "watch".into(),
            standing: Standing::Watch,
            doc,
        });
    }
    let report = match_sightings(&parties);
    if a.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print_report(&report);
    }
    Ok(())
}

fn who(r: &sightings::matching::SightingRef) -> String {
    format!("{} {} ({})", r.party, r.sighting, r.standing.label())
}

fn print_report(r: &MatchReport) {
    if r.groups.is_empty() {
        println!("no cluster was seen by more than one party");
    }
    for (i, g) in r.groups.iter().enumerate() {
        let verdict = if g.corroborated {
            "corroborated by independent parties: review for case work"
        } else {
            "not corroborated: no two vouched parties share a feature"
        };
        println!(
            "G{} {} sightings, {} parties, {} independent: {verdict}",
            i + 1,
            g.members.len(),
            g.parties,
            g.independent
        );
        for m in &g.members {
            println!("     {}", who(m));
        }
        for b in &g.bridges {
            println!(
                "     bridge: {} joins sightings that share nothing with each other; check it before reading the group as one swarm",
                who(b)
            );
        }
    }
    if !r.pairs.is_empty() {
        println!();
        println!("pairs (proposals, never merges):");
    }
    for p in &r.pairs {
        let shared: Vec<String> = p
            .shared
            .iter()
            .map(|s| {
                if s.name.is_empty() {
                    format!("{} [{}]", s.kind.id(), s.epoch)
                } else {
                    format!("{} {} [{}]", s.kind.id(), s.name, s.epoch)
                }
            })
            .collect();
        let when = match (p.overlap_hours, p.gap_hours) {
            (0, g) if g < 0 => "no hours to compare".to_string(),
            (0, g) => format!("{g} h apart"),
            (n, _) => format!("{n} h in common"),
        };
        println!(
            "  {} ~ {}: {}; {when}{}",
            who(&p.a),
            who(&p.b),
            shared.join(", "),
            if p.corroborating { "" } else { "; weak" }
        );
        if !p.scaffold.is_empty() {
            println!("     scaffold: {}", p.scaffold.join(", "));
        }
    }
    if !r.scaffold_pairs.is_empty() {
        println!();
        println!("scaffold only (same hours, alike requests, no shared feature; hints):");
    }
    for p in &r.scaffold_pairs {
        println!(
            "  {} ~ {}: {} h in common; {}",
            who(&p.a),
            who(&p.b),
            p.overlap_hours,
            p.scaffold.join(", ")
        );
    }
}
