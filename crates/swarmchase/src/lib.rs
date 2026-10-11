//! `swarmchase`: find, link and report AI agent activity in public records.
//!
//! The library behind the `swarmchase` binary. [`run`] parses the arguments
//! and dispatches; each command lives in its own module ([`commands`],
//! [`watch`], [`review`], [`case`], [`notice`]). What a case is, and every
//! decision on one, is the `sc-case` crate; the STIX and MISP builders are
//! `sc-stix`. This crate reads and writes the files and talks to the
//! network.

use anyhow::Result;
use clap::{Parser, Subcommand};
use commands::{analyze, clusters, collect, endpoints, report, scan};
use std::path::PathBuf;

pub mod backup;
pub mod bundle;
pub mod case;
pub mod commands;
pub mod contacts;
pub mod csirts;
pub mod eval;
pub mod evidence;
pub mod health;
pub mod input;
pub mod notice;
pub mod pinning;
pub mod review;
pub mod stix;
pub mod store;
pub mod suggest;
pub mod util;
pub mod watch;

#[derive(Parser)]
#[command(name = "swarmchase", version, about)]
pub struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
pub enum Cmd {
    /// List flagged records, strongest first.
    Scan(scan::ScanArgs),
    /// Full analysis (records, clusters, timing) as JSON.
    Analyze(analyze::AnalyzeArgs),
    /// Summarise clusters.
    Clusters(clusters::ClustersArgs),
    /// Flagged activity per target host: hits, first and last seen, payloads,
    /// clusters, and whether the hits are ongoing or historical.
    Endpoints(endpoints::EndpointsArgs),
    /// Draft a disclosure report (Markdown).
    Report(report::ReportArgs),
    /// Show the relay/carrier layers inside a URL and the rules it triggers.
    Unwrap { url: String },
    /// Defang URLs for safe sharing.
    Defang { urls: Vec<String> },
    /// Collect index records from public archives (never opens captures).
    Collect {
        #[command(subcommand)]
        source: collect::CollectSource,
    },
    /// Certificate Transparency lookup via crt.sh.
    Certs {
        /// e.g. `%.example.com`
        query: String,
        #[arg(long)]
        json: bool,
    },
    /// Find the security contact for an affected domain (RFC 9116 security.txt).
    Contact { domain: String },
    /// The provider directory (contacts/providers.toml): list it, or re-read
    /// every entry's source and draft the changes.
    Contacts {
        #[command(subcommand)]
        cmd: contacts::ContactsCmd,
    },
    /// Collect new records from every source in a watchlist, analyse the recent
    /// window, and write a digest of what changed since the last run.
    Watch(watch::WatchArgs),
    /// Precision and recall of the rules on labelled records. Labels come from
    /// `--labels` (NDJSON or CSV, including Transluce's reports.csv) or, without
    /// it, from a `label` field on each input record. With floors set, exits
    /// non-zero when a floor is not met.
    Eval(Box<commands::eval::EvalArgs>),
    /// Label watch leads as agent, benign or unsure, one record at a time.
    /// Labels go to `<data>/labels/reviewed.ndjson` (`reviewed-<name>.ndjson`
    /// with `--labeller`), which `swarmchase eval`
    /// reads directly. Progress is saved after every answer.
    Review(review::ReviewArgs),
    /// Case files: open, classify endpoints, record attribution, draft reports
    /// and notices, record the second review and the naming decisions.
    Case(case::CaseArgs),
    /// Public notices: add a reviewed draft, append updates, lint, build the site files.
    Notice(notice::NoticeArgs),
    /// Encrypted backups of cases, labels, pinned rules and state.json:
    /// create, list, verify, restore, and keygen for the age identity.
    Backup(backup::BackupArgs),
    /// The public site: `site build` writes it into a directory from the
    /// committed inputs, as `sc-site` does.
    Site(commands::site::SiteArgs),
    /// The offline IP-to-ASN table: fetch it into the data directory, look up addresses.
    Asn(commands::asn::AsnArgs),
    /// Validate a rules file, or print the bundled rules.
    Rules {
        file: Option<PathBuf>,
        #[arg(long)]
        dump: bool,
    },
}

/// Parse the command line and run the command.
pub fn run() -> Result<()> {
    match Cli::parse().cmd {
        Cmd::Scan(a) => scan::run(a),
        Cmd::Analyze(a) => analyze::run(a),
        Cmd::Clusters(a) => clusters::run(a),
        Cmd::Endpoints(a) => endpoints::run(a),
        Cmd::Report(a) => report::run(a),
        Cmd::Unwrap { url } => commands::unwrap::run(url),
        Cmd::Defang { urls } => {
            commands::unwrap::defang_urls(&urls);
            Ok(())
        }
        Cmd::Collect { source } => collect::run(source),
        Cmd::Certs { query, json } => commands::certs::run(&query, json),
        Cmd::Contact { domain } => commands::contact::run(&domain),
        Cmd::Contacts { cmd } => contacts::run_contacts(cmd),
        Cmd::Watch(a) => watch::run(a),
        Cmd::Eval(a) => commands::eval::run(*a),
        Cmd::Review(a) => review::run(a),
        Cmd::Case(a) => case::run(a),
        Cmd::Notice(a) => notice::run(a),
        Cmd::Backup(a) => backup::run(a),
        Cmd::Site(a) => commands::site::run(a),
        Cmd::Asn(a) => commands::asn::run(a),
        Cmd::Rules { file, dump } => commands::rules::run(file.as_deref(), dump),
    }
}
