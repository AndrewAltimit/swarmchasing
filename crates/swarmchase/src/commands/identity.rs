//! `swarmchase identity`: declared agent identity ([`sc_core::identity`]).
//! `refresh` fetches the providers' published range files and key
//! directories named in `declared-agents.toml` into `<data>/identity/`;
//! `status` lists what is held; `check` classes each record of a log or
//! export; `reference` lists user-agent tokens the ai.robots.txt list names
//! that the catalog lacks, as candidates for review. Once fetched, the analysis commands (`report`, `clusters`,
//! `analyze`) add each cluster's identity line.

use crate::input::{InputArgs, read_inputs};
use crate::util::today;
use anyhow::Result;
use clap::{Args, Subcommand};
use sc_collect::Client;
use sc_core::identity::{Catalog, IdentityClass, IdentityData, classify};
use sc_core::{Analysis, defang, defang_hosts};
use std::path::{Path, PathBuf};
use std::time::Duration;

#[derive(Args)]
pub struct IdentityArgs {
    #[command(subcommand)]
    cmd: IdentityCmd,
    /// Data directory the files live in.
    #[arg(
        short,
        long,
        global = true,
        default_value = "data",
        env = "SWARMCHASE_DATA"
    )]
    data: PathBuf,
}

#[derive(Subcommand)]
enum IdentityCmd {
    /// Fetch every range file and key directory in the catalog. Only the
    /// catalog's URLs are fetched, never an address a record carries.
    Refresh,
    /// The catalog and what is held, with fetch dates.
    Status,
    /// Fetch the ai.robots.txt list into <data>/identity/reference/ and
    /// print the user-agent tokens it lists that the catalog lacks, as
    /// candidates for review. Proposes only: the catalog is never edited,
    /// and each entry added by hand cites the provider's own page.
    Reference {
        /// Read the held copy instead of fetching it again.
        #[arg(long)]
        offline: bool,
    },
    /// Class each record's declared identity: verified, spoofed, claimed.
    Check {
        #[command(flatten)]
        input: InputArgs,
        /// Also list records with no declared identity.
        #[arg(long)]
        all: bool,
        /// One JSON object per record.
        #[arg(long)]
        json: bool,
    },
}

pub fn run(a: IdentityArgs) -> Result<()> {
    let catalog = Catalog::bundled();
    match a.cmd {
        IdentityCmd::Refresh => {
            let client = Client::new(Duration::from_secs(1))?;
            let mut failed = 0;
            for r in sc_collect::identity::refresh(&client, &a.data, &catalog, &today()) {
                match r.result {
                    Ok(h) => eprintln!("{}: {} entries ({})", r.id, h.entries, h.url),
                    Err(e) => {
                        failed += 1;
                        eprintln!("{}: FAILED: {e:#}", r.id);
                    }
                }
            }
            if failed > 0 {
                eprintln!(
                    "{failed} file(s) not refreshed; the previous copies, if any, stay in use"
                );
            }
        }
        IdentityCmd::Status => status(&a.data, &catalog),
        IdentityCmd::Reference { offline } => reference(&a.data, &catalog, offline)?,
        IdentityCmd::Check { input, all, json } => {
            let (data, _) = load(&a.data, &catalog);
            let records = read_inputs(&input)?;
            let mut counts = std::collections::BTreeMap::<IdentityClass, usize>::new();
            for o in &records {
                let r = classify(o, &catalog, &data);
                *counts.entry(r.class).or_default() += 1;
                if r.class == IdentityClass::None && !all {
                    continue;
                }
                if json {
                    let mut v = serde_json::to_value(&r)?;
                    v["id"] = o.id.clone().into();
                    v["ip"] = o.ip.clone().into();
                    println!("{v}");
                    continue;
                }
                let who: Vec<&str> = [r.provider.as_deref(), r.agent.as_deref()]
                    .into_iter()
                    .flatten()
                    .collect();
                println!(
                    "{}\t{}\t{}\t{}\t{}",
                    o.id,
                    defang_hosts(o.ip.as_deref().unwrap_or("-")),
                    r.class.id(),
                    defang_hosts(&who.join(" ")),
                    defang_hosts(&r.detail)
                );
            }
            let line: Vec<String> = counts
                .iter()
                .map(|(c, n)| format!("{n} {}", c.id()))
                .collect();
            eprintln!("{} record(s): {}", records.len(), line.join(", "));
            for line in file_ages(&data, now()) {
                eprintln!("{line}");
            }
            if data.is_empty() {
                eprintln!(
                    "no range files or directories held: nothing can be verified or shown spoofed; run `swarmchase identity refresh`"
                );
            }
        }
    }
    Ok(())
}

/// One candidate as `identity reference` prints it, every host in the
/// list's free text (`[Webz.io](https://webz.io/)`) defanged.
fn reference_line(b: &sc_collect::identity::reference::ReferenceBot) -> String {
    format!(
        "{}\t{}\t{}",
        defang_hosts(&b.token),
        defang_hosts(&b.operator),
        defang_hosts(&b.function)
    )
}

/// `identity reference`: the listed tokens the catalog has no agent for.
fn reference(data: &Path, catalog: &Catalog, offline: bool) -> Result<()> {
    use sc_collect::identity::reference;
    if !offline {
        let client = Client::new(Duration::from_secs(1))?;
        let (p, n) = reference::fetch(&client, data)?;
        eprintln!("wrote {} ({n} tokens)", p.display());
    }
    let Some(bots) = reference::load(data)? else {
        anyhow::bail!(
            "no reference list at {}; run `swarmchase identity reference` without --offline",
            reference::path(data).display()
        );
    };
    let c = reference::candidates(&bots, catalog);
    for b in &c {
        println!("{}", reference_line(b));
    }
    eprintln!(
        "{} of {} listed token(s) are not in declared-agents.toml: candidates for review, not entries. An entry needs the provider's own page as its `source`.",
        c.len(),
        bots.len()
    );
    Ok(())
}

fn status(data: &Path, catalog: &Catalog) {
    let idx = sc_collect::identity::index(data);
    println!("catalog {}", catalog.meta.version);
    let row = |id: &str, url: &str| match idx.get(id) {
        Some(h) => println!(
            "{id}\t{}\t{} entries{}\t{url}",
            h.fetched,
            h.entries,
            h.created
                .as_deref()
                .map(|c| format!(", created {c}"))
                .unwrap_or_default()
        ),
        None => println!("{id}\tnot held\t-\t{url}"),
    };
    for f in &catalog.range_files {
        row(&f.id, &f.url);
    }
    for d in &catalog.directories {
        row(&d.id, &d.url);
    }
    for a in &catalog.agents {
        println!(
            "agent {}\t{}\t{}\tranges: {}{}",
            a.token,
            a.provider,
            a.purpose,
            a.ranges.join(", "),
            a.directory
                .as_deref()
                .map(|d| format!("; signs: {d}"))
                .unwrap_or_default()
        );
    }
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

/// One line per held range file that dates itself (`creationTime`, as
/// draft-illyes-webbotauth-jafar has it): how old the provider's file was
/// at `now`, and its `synctoken` when it has one. A verdict on an old log
/// says how far apart the log and the file are.
fn file_ages(data: &IdentityData, now: i64) -> Vec<String> {
    data.ranges
        .values()
        .filter_map(|t| {
            let created = t.created.as_deref()?;
            let age = t
                .age_days(now)
                .map_or_else(|| "age unknown".to_string(), |d| format!("{d} day(s) old"));
            let sync = t
                .synctoken
                .as_deref()
                .map(|s| format!(", synctoken {}", defang(s)))
                .unwrap_or_default();
            Some(format!(
                "range file {}: created {}, {age}{sync}",
                t.id,
                defang(created)
            ))
        })
        .collect()
}

fn load(data: &Path, catalog: &Catalog) -> (IdentityData, Vec<String>) {
    let (d, warnings) = sc_collect::identity::load(data, catalog);
    for w in &warnings {
        eprintln!("warning: identity: {w}");
    }
    (d, warnings)
}

/// Fill each cluster's declared identity from the files held in the data
/// directory (`SWARMCHASE_DATA`, else `data`). Quiet when no member declares
/// anything.
pub fn annotate(a: &mut Analysis) {
    let data = std::env::var("SWARMCHASE_DATA")
        .ok()
        .filter(|d| !d.is_empty())
        .map_or_else(|| PathBuf::from("data"), PathBuf::from);
    let catalog = Catalog::bundled();
    let (held, _) = load(&data, &catalog);
    sc_core::identity::annotate(a, &catalog, &held);
    let n = a.clusters.iter().filter(|c| !c.identity.is_empty()).count();
    if n > 0 && held.is_empty() {
        eprintln!(
            "{n} cluster(s) declare an agent identity; no published ranges or keys are held to check them (`swarmchase identity refresh`)"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sc_core::identity::ranges::RangeTable;

    #[test]
    fn reference_lines_defang_free_text_hosts() {
        let b = sc_collect::identity::reference::ReferenceBot {
            token: "Webzio-Extended".into(),
            operator: "[Webz.io](https://webz.io/)".into(),
            function: "AI data scrapers, see docs.webz.io".into(),
        };
        let line = reference_line(&b);
        assert_eq!(
            line,
            "Webzio-Extended\t[Webz[.]io](hxxps://webz[.]io/)\tAI data scrapers, see docs[.]webz[.]io"
        );
    }

    #[test]
    fn check_states_each_dated_files_age() {
        let mut d = IdentityData::default();
        for (id, text) in [
            (
                "openai.chatgpt-user",
                r#"{"creationTime":"2026-10-10T14:30:00Z","synctoken":"20261010143000","prefixes":[{"ipv4Prefix":"192.0.2.0/28"}]}"#,
            ),
            (
                "anthropic.bots",
                r#"{"prefixes":[{"ipv4Prefix":"198.51.100.0/28"}]}"#,
            ),
        ] {
            d.ranges
                .insert(id.into(), RangeTable::parse(id, text).unwrap());
        }
        let now = sc_core::parse_ts("2026-10-14T00:00:00Z").unwrap();
        assert_eq!(
            file_ages(&d, now),
            [
                "range file openai.chatgpt-user: created 2026-10-10T14:30:00Z, 3 day(s) old, synctoken 20261010143000"
            ]
        );
    }
}
