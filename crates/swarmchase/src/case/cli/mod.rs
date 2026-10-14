//! The `case` subcommands, one module per group:
//!
//! - [`open`]: open a case, add records, show it, rename it, change its
//!   settings, note a decision, re-pin its rules.
//! - [`endpoints`]: classify endpoints, record missing contacts, decide
//!   alternative explanations, review plant signals.
//! - [`attribution`]: claims and the agent grade.
//! - [`fleet`]: fleet merges and splits, interaction evidence.
//! - [`contacts`]: find contacts, add or remove one by hand.
//! - [`sending`]: reports, drafts for one contact, sends, bundles.
//! - [`notice`]: the notice and naming drafts, the re-read and the
//!   checklists.
//! - [`review`]: the second review and its packet, operators' consent to
//!   earlier naming, and the decision not to name one.
//! - [`export`]: STIX, MISP and incident-framework drafts.
//!
//! Each parses its arguments and calls the decisions in [`sc_case`]; the
//! case files are read and written through [`super`].

mod attribution;
mod contacts;
mod endpoints;
mod export;
mod fleet;
mod notice;
mod open;
mod review;
mod sending;

use crate::evidence::EvidenceCmd;
use anyhow::Result;
use clap::{Args, Subcommand};
use std::path::PathBuf;

#[derive(Args)]
pub struct CaseArgs {
    /// Data directory; cases live in `<data>/cases/`.
    #[arg(
        short,
        long,
        default_value = "data",
        env = "SWARMCHASE_DATA",
        global = true
    )]
    data: PathBuf,
    #[command(subcommand)]
    cmd: CaseCmd,
}

/// What every subcommand gets: where the cases are and the clock.
pub(super) struct Ctx {
    /// The data directory.
    pub data: PathBuf,
    /// `<data>/cases`.
    pub root: PathBuf,
    pub today: String,
    pub now: i64,
}

#[derive(Subcommand)]
pub enum CaseCmd {
    /// Open a case from clusters or records, copying the records into it.
    New(open::NewArgs),
    /// Add records to a case (new activity, a linked cluster).
    Add(open::AddArgs),
    /// List cases, or show one with what it still needs.
    Status {
        /// A case ID; without one, every case is listed.
        id: Option<String>,
        /// Print it as one JSON document on stdout.
        #[arg(long)]
        json: bool,
    },
    /// Classify affected endpoints, one or more hosts at a time.
    Endpoint(endpoints::EndpointArgs),
    /// Record that no contact could be found for a party: an endpoint's
    /// host, a provider organisation, or `provider` when the case has no
    /// provider contact. The notice may then publish without a send to it.
    NoContact(endpoints::NoContactArgs),
    /// Record the decision on an alternative explanation, or list them.
    Alternative(endpoints::AlternativeArgs),
    /// Record that you reviewed a cluster's plant signals.
    PlantReview(endpoints::PlantReviewArgs),
    /// Record that you re-read the current notice draft, by its hash. `notice
    /// add` needs a re-read of the exact draft, an hour or more after it was
    /// written.
    Reread {
        /// The case ID: its directory under <data>/cases/ (`case status` lists them).
        id: String,
    },
    /// Print the checklist `notice add` runs, or once the indicator notice
    /// is added the one `notice update --naming` runs, with both stages'
    /// clocks and review state.
    Checklist {
        /// The case ID: its directory under <data>/cases/ (`case status` lists them).
        id: String,
        /// The committed notices directory (for the naming checklist).
        #[arg(long, default_value = "notices")]
        notices: PathBuf,
    },
    /// Record the admin's scope finding for a cluster (SC-FM 15.4). Notices
    /// say "misaligned" only for clusters found to exceed scope.
    Scope(attribution::ScopeArgs),
    /// Record a second reviewer's verdict on the current draft of the next
    /// stage (the indicator notice, then naming updates), bound to its hash.
    Review(review::ReviewArgs),
    /// Write the current draft, its checklist and the internal report into
    /// <case>/outbox/review/ for the second reviewer. Nothing is sent.
    ReviewPacket(review::PacketArgs),
    /// Record an operator's written consent to be named before its naming
    /// clock runs.
    Consent(review::ConsentArgs),
    /// Show each operator's naming clock, or decide never to name one.
    Naming(review::NamingArgs),
    /// Give a case a new ID. A case with a published notice keeps its ID.
    Rename {
        /// The case ID: its directory under <data>/cases/ (`case status` lists them).
        id: String,
        /// The new ID: lowercase letters, digits and hyphens.
        new_id: String,
    },
    /// Record an attribution claim established by case work.
    Claim(attribution::ClaimArgs),
    /// Show each cluster's agent grade (L0..L4) with its signals,
    /// counter-signals and caps, or record the admin's grade for the case
    /// with what it rests on. L5 (documented: operator logs matching a
    /// harness, a provider's confirmation) is set only here.
    Grade(attribution::GradeArgs),
    /// Change the case or notice status, the developer naming threshold, the
    /// naming lead or the admin.
    Set(open::SetArgs),
    /// Find contacts: the provider directory's channels for every provider a
    /// developer or host claim names, then for the case's endpoints the
    /// security.txt on the host or its parent domains, else the registrar's
    /// abuse contact from RDAP. Endpoints marked not-affected are skipped.
    Contacts(contacts::ContactsArgs),
    /// Add or remove a contact by hand.
    Contact {
        #[command(subcommand)]
        cmd: contacts::ContactCmd,
    },
    /// Write an evidence bundle: records, analysis, reproducibility stamp and
    /// a SHA-256 manifest, signed when SWARMCHASE_SIGNING_KEY is set.
    Bundle {
        /// The case ID: its directory under <data>/cases/ (`case status` lists them).
        id: String,
        /// Rules file (defaults to the bundled rules/default.toml).
        #[arg(long)]
        rules: Option<PathBuf>,
    },
    /// Check a bundle: its signature against the published key, the
    /// manifest hashes, then re-run the analysis and compare every tier and
    /// cluster with its stamp. An invalid signature fails; an unsigned
    /// bundle is reported as unsigned.
    Verify {
        bundle: PathBuf,
        /// The rules the bundle was made with, if not the bundled rules.
        #[arg(long)]
        rules: Option<PathBuf>,
        /// The published key file. Default: keys/bundle-signing.pub.
        #[arg(long, env = crate::signing::PUBLIC_ENV)]
        key: Option<PathBuf>,
    },
    /// Prepare a report for one contact: an unsent .eml with a fresh evidence
    /// bundle attached for e-mail, paste-ready text otherwise. Nothing is sent.
    Draft(sending::DraftArgs),
    /// Record a report the admin sent.
    Sent(sending::SentArgs),
    /// Logs an affected operator sent us: add them, record the operator's
    /// agreement to use them in the public notice, or list them.
    Evidence {
        #[command(subcommand)]
        cmd: EvidenceCmd,
    },
    /// Append a dated entry to the decision log.
    Note {
        /// The case ID: its directory under <data>/cases/ (`case status` lists them).
        id: String,
        /// The entry, as one argument (quote it).
        text: String,
    },
    /// Treat soft-linked clusters as one fleet, or split one off again: the
    /// admin's decision, logged with the soft links it rests on. Reports and
    /// exports then group the clusters. Never automatic.
    Fleet {
        #[command(subcommand)]
        cmd: fleet::FleetCmd,
    },
    /// Show the rules the case is pinned to, the current rules, and which
    /// records would change tier; with --update, re-pin to the current rules.
    Rules {
        /// The case ID: its directory under <data>/cases/ (`case status` lists them).
        id: String,
        #[arg(long)]
        update: bool,
        /// The rules to compare with and pin. Default: the bundled rules.
        #[arg(long)]
        rules: Option<PathBuf>,
    },
    /// Draft the indicator notice into <case>/notice.md and list what it
    /// withheld and what needs a decision; with --naming, draft the next
    /// naming update into <case>/naming.md. Review and edit it, then
    /// `swarmchase notice add <id>` (or `notice update <id> --naming`).
    Notice {
        /// The case ID: its directory under <data>/cases/ (`case status` lists them).
        id: String,
        /// Replace an existing draft (and any edits made to it).
        #[arg(long)]
        force: bool,
        /// Draft the naming update for the operators that may be named now.
        #[arg(long)]
        naming: bool,
    },
    /// Render a report draft from the case's records and case.toml.
    Report(sending::ReportArgs),
    /// Export the case for the recipients' tooling, scoped to an audience:
    /// a STIX 2.1 bundle, a MISP event, or a draft for the OECD AI incident
    /// framework (with an EU AI Act Article 73 section) or the AI Incident
    /// Database. Written to a file; nothing is sent or submitted.
    Export(export::ExportArgs),
}

pub fn run(args: CaseArgs) -> Result<()> {
    let ctx = Ctx {
        root: args.data.join("cases"),
        data: args.data,
        today: crate::util::today(),
        now: chrono::Utc::now().timestamp(),
    };
    let reads_data = match &args.cmd {
        CaseCmd::Verify { .. } => false,
        // A case opened from record files needs nothing there yet.
        CaseCmd::New(a) => a.sel.input.is_empty(),
        _ => true,
    };
    if reads_data {
        crate::store::hint_if_empty(&ctx.data);
    }
    let out = &mut std::io::stdout();
    match args.cmd {
        CaseCmd::New(a) => open::new(&ctx, a, out),
        CaseCmd::Add(a) => open::add(&ctx, a),
        CaseCmd::Status { id, json } => open::status(&ctx, id.as_deref(), json, out),
        CaseCmd::Rename { id, new_id } => open::rename(&ctx, &id, &new_id),
        CaseCmd::Set(a) => open::set(&ctx, a),
        CaseCmd::Note { id, text } => open::note(&ctx, &id, text),
        CaseCmd::Rules { id, update, rules } => {
            open::rules(&ctx, &id, update, rules.as_deref(), out)
        }
        CaseCmd::Endpoint(a) => endpoints::endpoint(&ctx, a),
        CaseCmd::NoContact(a) => endpoints::no_contact(&ctx, a),
        CaseCmd::Alternative(a) => endpoints::alternative(&ctx, a),
        CaseCmd::PlantReview(a) => endpoints::plant_review(&ctx, a),
        CaseCmd::Claim(a) => attribution::claim(&ctx, a),
        CaseCmd::Grade(a) => attribution::grade(&ctx, a, out),
        CaseCmd::Fleet { cmd } => fleet::run(&ctx, cmd, out),
        CaseCmd::Contacts(a) => contacts::find(&ctx, a, out),
        CaseCmd::Contact { cmd } => contacts::contact(&ctx, cmd),
        CaseCmd::Report(a) => sending::report(&ctx, a),
        CaseCmd::Draft(a) => sending::draft(&ctx, a),
        CaseCmd::Sent(a) => sending::sent(&ctx, a),
        CaseCmd::Bundle { id, rules } => sending::bundle(&ctx, &id, rules.as_deref()),
        CaseCmd::Verify { bundle, rules, key } => {
            sending::verify(&ctx, &bundle, rules.as_deref(), key.as_deref())
        }
        CaseCmd::Evidence { cmd } => crate::evidence::run_evidence(&ctx.root, cmd, &ctx.today),
        CaseCmd::Notice {
            id,
            force,
            naming: false,
        } => notice::draft(&ctx, &id, force),
        CaseCmd::Notice {
            id,
            force,
            naming: true,
        } => notice::naming_draft(&ctx, &id, force),
        CaseCmd::Reread { id } => notice::reread(&ctx, &id),
        CaseCmd::Checklist { id, notices } => notice::checklist(&ctx, &id, &notices, out),
        CaseCmd::Scope(a) => attribution::scope(&ctx, a),
        CaseCmd::Review(a) => review::review(&ctx, a),
        CaseCmd::ReviewPacket(a) => review::packet(&ctx, a),
        CaseCmd::Consent(a) => review::consent(&ctx, a),
        CaseCmd::Naming(a) => review::naming(&ctx, a, out),
        CaseCmd::Export(a) => export::run(&ctx, a),
    }
}
