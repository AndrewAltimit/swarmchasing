//! `swarmchase`: find, link and report AI agent activity in public records.
//!
//! The library behind the `swarmchase` binary. [`run`] parses the arguments
//! and dispatches; each command lives in its own module ([`commands`],
//! [`watch`], [`review`], [`case`], [`inbox`], [`notice`]). What a case is, and every
//! decision on one, is the `sc-case` crate; the STIX and MISP builders are
//! `sc-stix`. This crate reads and writes the files and talks to the
//! network.

use anyhow::Result;
use clap::{Parser, Subcommand};
use commands::{analyze, clusters, collect, endpoints, report, scan};
use std::path::PathBuf;

pub mod backup;
pub mod bundle;
pub mod canary;
pub mod case;
pub mod commands;
pub mod contacts;
pub mod csirts;
pub mod dashboard;
pub mod eval;
pub mod evidence;
pub mod health;
pub mod inbox;
pub mod input;
pub mod localui;
pub mod notice;
pub mod pinning;
pub mod review;
pub mod sightings;
pub mod signing;
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
    /// Interaction edges, soft links, candidate fleets and agent grades
    /// against labelled true runs, swarms and fleets.
    Sim(commands::sim::SimArgs),
    /// Candidate coordinated-account swarms in platform events (GitHub, npm,
    /// PyPI, Hugging Face): many accounts posting near-identical or templated
    /// text, or creating templated names, in a burst beyond chance. Hints for
    /// review, never findings.
    PlatformSwarms(commands::platform::PlatformArgs),
    /// Label watch leads as agent, benign or unsure, one record at a time.
    /// Labels go to `<data>/labels/reviewed.ndjson` (`reviewed-<name>.ndjson`
    /// with `--labeller`), which `swarmchase eval`
    /// reads directly. Progress is saved after every answer.
    Review(review::ReviewArgs),
    /// The state of monitoring on a page on 127.0.0.1: what is new since you
    /// last looked, source health and rule drift, the review queue and open
    /// cases, and the command for each next step. `--json` prints the same
    /// overview for a script. Read-only.
    Dashboard(dashboard::DashboardArgs),
    /// Case files: open, classify endpoints, record attribution, draft reports
    /// and notices, record the second review and the naming decisions.
    Case(case::CaseArgs),
    /// Outside swarm reports (SC-Submission v1): take in, verify by id,
    /// triage, and promote to review or a case. Nothing is published.
    Inbox(inbox::InboxArgs),
    /// Public notices: add a reviewed draft, append updates, lint, build the site files.
    Notice(notice::NoticeArgs),
    /// Encrypted backups of cases, labels, pinned rules and state.json:
    /// create, list, verify, restore, and keygen for the age identity.
    Backup(backup::BackupArgs),
    /// The public site: `site build` writes it into a directory from the
    /// committed inputs, as `sc-site` does.
    Site(commands::site::SiteArgs),
    /// Canary tokens on our own published pages: register a built site's
    /// tokens, list them, derive one, or find copies in records.
    Canary(canary::CanaryArgs),
    /// The Ed25519 key evidence bundles are signed with: generate one (the
    /// secret goes to a file, never the terminal), or show the public key of
    /// SWARMCHASE_SIGNING_KEY.
    Key(signing::KeyArgs),
    /// The offline IP-to-ASN table: fetch it into the data directory, look up addresses.
    Asn(commands::asn::AsnArgs),
    /// Cloud providers' published address ranges and the Tor exit list:
    /// fetch them into the data directory, look up addresses.
    Netranges(commands::netranges::NetrangesArgs),
    /// Sightings (SC-Sightings v1): `export` makes one from your own logs,
    /// `match` finds clusters several operators saw. Never merges clusters.
    Sightings(sightings::SightingsArgs),
    /// Declared agent identity: fetch providers' published ranges and keys,
    /// and check which records' agent claims they bear out or contradict.
    Identity(commands::identity::IdentityArgs),
    /// Validate a rules file, or print the bundled rules.
    Rules {
        file: Option<PathBuf>,
        #[arg(long)]
        dump: bool,
    },
}

/// Exit statuses beyond 0 (success) and 1 (an error).
pub mod exit {
    /// A watch run that finished, digest written, with alerts in it.
    pub const ALERTS: u8 = 2;
    /// `eval` or `sim bench` ran, and a floor or ceiling was not met.
    pub const FLOOR_NOT_MET: u8 = 3;
}

/// A command's outcome that sets its own exit status ([`exit`]): returned
/// as the command's error, so it ends the command like one.
#[derive(Debug)]
pub struct Exit {
    pub code: u8,
    pub message: String,
}

impl std::fmt::Display for Exit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for Exit {}

impl Exit {
    /// A watch run that finished with alerts ([`exit::ALERTS`]).
    pub fn alerts(message: impl Into<String>) -> anyhow::Error {
        Exit {
            code: exit::ALERTS,
            message: message.into(),
        }
        .into()
    }

    /// A floor or ceiling not met ([`exit::FLOOR_NOT_MET`]).
    pub fn floor(message: impl Into<String>) -> anyhow::Error {
        Exit {
            code: exit::FLOOR_NOT_MET,
            message: message.into(),
        }
        .into()
    }
}

/// The exit status for a command's result, printing the error (or, for a
/// run with alerts, the note) to stderr: 0, 1 for an error, or the
/// [`Exit`] code.
pub fn exit_status(r: Result<()>) -> std::process::ExitCode {
    match r {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => match e.downcast_ref::<Exit>() {
            Some(x) if x.code == exit::ALERTS => {
                eprintln!("note: {}", x.message);
                std::process::ExitCode::from(x.code)
            }
            Some(x) => {
                eprintln!("Error: {}", x.message);
                std::process::ExitCode::from(x.code)
            }
            None => {
                eprintln!("Error: {e:?}");
                std::process::ExitCode::FAILURE
            }
        },
    }
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
        Cmd::Sim(a) => commands::sim::run(a),
        Cmd::PlatformSwarms(a) => commands::platform::run(a),
        Cmd::Review(a) => review::run(a),
        Cmd::Dashboard(a) => dashboard::run(a),
        Cmd::Case(a) => case::run(a),
        Cmd::Inbox(a) => inbox::run(a),
        Cmd::Notice(a) => notice::run(a),
        Cmd::Backup(a) => backup::run(a),
        Cmd::Site(a) => commands::site::run(a),
        Cmd::Asn(a) => commands::asn::run(a),
        Cmd::Netranges(a) => commands::netranges::run(a),
        Cmd::Sightings(a) => sightings::run(a),
        Cmd::Canary(a) => canary::run(a),
        Cmd::Key(a) => signing::run(a),
        Cmd::Identity(a) => commands::identity::run(a),
        Cmd::Rules { file, dump } => commands::rules::run(file.as_deref(), dump),
    }
}
