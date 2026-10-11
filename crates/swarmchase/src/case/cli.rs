//! The `case` subcommands.

use super::report::{draft, report};
use super::select::select;
use super::status::{list, status};
use super::*;
use crate::evidence::EvidenceCmd;
use crate::input::load_rules;
use crate::pinning::{RulesText, bundle_rules, case_rules, rules_cmd};
use crate::util::audience_id;
use anyhow::{Context, Result, bail};
use clap::{Args, Subcommand};
use sc_core::{Audience, Claim, Evidence, Role, Tag};
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

/// Which records to take into a case.
#[derive(Args)]
pub struct Selection {
    /// Record files. Default: the watch store's last `--days` days.
    pub(super) input: Vec<PathBuf>,
    #[arg(long, default_value_t = 30)]
    pub(super) days: i64,
    /// Clusters to take, by number in this analysis (C1) or stable key
    /// (k-3f9a2c1b); `swarmchase clusters` lists both.
    #[arg(long = "cluster")]
    pub(super) clusters: Vec<String>,
    /// Individual records to take, by ID.
    #[arg(long = "record")]
    pub(super) records: Vec<String>,
    /// Also take every flagged record on the hosts those records target,
    /// including other clusters, so the endpoint view is complete.
    #[arg(long)]
    pub(super) host_hits: bool,
    #[arg(long)]
    pub(super) rules: Option<PathBuf>,
}

#[derive(Subcommand)]
pub enum CaseCmd {
    /// Open a case from clusters or records, copying the records into it.
    New {
        /// Short slug, e.g. 2026-10-portal-sqli.
        id: String,
        #[arg(long)]
        title: String,
        #[command(flatten)]
        sel: Selection,
    },
    /// Add records to a case (new activity, a linked cluster).
    Add {
        id: String,
        #[command(flatten)]
        sel: Selection,
    },
    /// List cases, or show one with what it still needs.
    Status { id: Option<String> },
    /// Classify affected endpoints, one or more hosts at a time.
    Endpoint {
        id: String,
        #[arg(required = true, num_args = 1..)]
        hosts: Vec<String>,
        state: EndpointState,
        #[arg(long)]
        note: Option<String>,
        /// For `compromised` (required): what shows the attack succeeded,
        /// beyond the inbound requests, with links.
        #[arg(long)]
        basis: Option<String>,
        /// Why the notice may name the operator although every record on
        /// the endpoint is submit-anywhere.
        #[arg(long)]
        single_source_reason: Option<String>,
    },
    /// Record that no contact could be found for a party: an endpoint's
    /// host, a provider organisation, or `provider` when the case has no
    /// provider contact. The notice may then publish without a send to it.
    NoContact {
        id: String,
        party: String,
        /// What was tried (security.txt, RDAP, the provider directory, …).
        #[arg(long)]
        searched: String,
    },
    /// Record the decision on an alternative explanation, or list them.
    Alternative {
        id: String,
        /// authorised-test | honeypot | research-scanner | spoofed-self-id |
        /// planted-records. Omit to list the decisions.
        kind: Option<AlternativeKind>,
        /// Why the explanation does not hold, with links.
        #[arg(long, conflicts_with = "accepted")]
        rejected: Option<String>,
        /// authorised-test only: the owner confirmed it, with the link.
        #[arg(long)]
        accepted: Option<String>,
    },
    /// Record that you reviewed a cluster's plant signals.
    PlantReview {
        id: String,
        /// The cluster, by C-number or stable key.
        cluster: String,
        /// What you checked and why the cluster stands.
        #[arg(long)]
        note: String,
    },
    /// Record that you re-read the current notice draft, by its hash. `notice
    /// add` needs a re-read of the exact draft, an hour or more after it was
    /// written.
    Reread { id: String },
    /// Print the self-review checklist `notice add` runs.
    Checklist { id: String },
    /// Give a case a new ID. A case with a published notice keeps its ID.
    Rename { id: String, new_id: String },
    /// Record an attribution claim established by case work.
    Claim {
        id: String,
        #[arg(long)]
        party: String,
        /// developer | host | harness | model_family
        #[arg(long, alias = "role", default_value = "developer")]
        layer: Role,
        /// shared_identifiers | provider_infrastructure | provider_confirmed | …
        /// Required for developer and host claims.
        #[arg(long)]
        evidence: Option<Evidence>,
        /// observed | documented | inference | conclusion. Default: derived
        /// from the layer and evidence.
        #[arg(long)]
        tag: Option<Tag>,
        /// Model family: the method's likelihood for this family (0..1).
        #[arg(long)]
        likelihood: Option<f64>,
        /// Model family: the method's accuracy on a held-out set (0..1).
        #[arg(long)]
        accuracy: Option<f64>,
        /// Model family: the size of the corpus the method was tuned on.
        #[arg(long)]
        corpus_size: Option<usize>,
        /// What the evidence is, with a link. Repeatable.
        #[arg(long = "detail", required = true)]
        details: Vec<String>,
    },
    /// Show each cluster's agent grade (L0..L4) with its signals,
    /// counter-signals and caps, or record the admin's grade for the case
    /// with what it rests on. L5 (documented: operator logs matching a
    /// harness, a provider's confirmation) is set only here.
    Grade {
        id: String,
        /// L0..L5, or a name such as `model_written` or `documented`. Omit to
        /// show the grades.
        level: Option<sc_core::AgentLevel>,
        /// What the decision rests on, with links. Required with a level.
        #[arg(long)]
        note: Option<String>,
        /// Remove the decision.
        #[arg(long, conflicts_with = "level")]
        clear: bool,
    },
    /// Change the case or notice status, or the naming threshold.
    Set {
        id: String,
        #[arg(long)]
        status: Option<CaseStatus>,
        #[arg(long)]
        notice: Option<NoticeStatus>,
        #[arg(long)]
        min_named: Option<Evidence>,
        /// The lead time for targeted and historical endpoints' operators,
        /// 4 to 12 hours (default 6).
        #[arg(long)]
        lead_hours: Option<u32>,
    },
    /// Find contacts: the provider directory's channels for every provider a
    /// developer or host claim names, then for the case's endpoints the
    /// security.txt on the host or its parent domains, else the registrar's
    /// abuse contact from RDAP. Endpoints marked not-affected are skipped.
    Contacts {
        id: String,
        /// Look up endpoints that already have contacts too.
        #[arg(long)]
        refresh: bool,
        /// Only add provider contacts from the directory; no network lookups
        /// and no CSIRTs.
        #[arg(long)]
        providers_only: bool,
        /// The country whose national CSIRT to propose for every endpoint
        /// (ISO 3166-1 alpha-2). Default: each host's country-code TLD.
        #[arg(long)]
        country: Option<String>,
    },
    /// Add or remove a contact by hand.
    Contact {
        #[command(subcommand)]
        cmd: ContactCmd,
    },
    /// Write an evidence bundle: records, analysis, reproducibility stamp and
    /// a SHA-256 manifest.
    Bundle {
        id: String,
        #[arg(long)]
        rules: Option<PathBuf>,
    },
    /// Check a bundle: manifest hashes, then re-run the analysis and compare
    /// every tier and cluster with its stamp.
    Verify {
        bundle: PathBuf,
        /// The rules the bundle was made with, if not the bundled rules.
        #[arg(long)]
        rules: Option<PathBuf>,
    },
    /// Prepare a report for one contact: an unsent .eml with a fresh evidence
    /// bundle attached for e-mail, paste-ready text otherwise. Nothing is sent.
    Draft {
        id: String,
        /// provider | affected
        #[arg(long)]
        audience: Audience,
        /// The contact's address, as listed in case.toml.
        #[arg(long)]
        to: String,
        #[arg(long)]
        reporter: Option<String>,
    },
    /// Record a report the admin sent.
    Sent {
        id: String,
        #[arg(long)]
        to: String,
        /// email | web_form | portal | phone
        #[arg(long, default_value = "email")]
        channel: String,
        /// The draft or report that was sent.
        #[arg(long)]
        report: Option<String>,
        /// When it was sent (RFC 3339, e.g. 2026-10-12T14:05:00Z), for a send
        /// recorded afterwards. Default: now. The lead time runs from it.
        #[arg(long, conflicts_with = "date")]
        at: Option<String>,
        /// The day only; the lead time then counts from the end of it.
        #[arg(long)]
        date: Option<String>,
    },
    /// Logs an affected operator sent us: add them, record the operator's
    /// agreement to use them in the public notice, or list them.
    Evidence {
        #[command(subcommand)]
        cmd: EvidenceCmd,
    },
    /// Append a dated entry to the decision log.
    Note { id: String, text: String },
    /// Treat soft-linked clusters as one fleet, or split one off again: the
    /// admin's decision, logged with the soft links it rests on. Reports and
    /// exports then group the clusters. Never automatic.
    Fleet {
        #[command(subcommand)]
        cmd: FleetCmd,
    },
    /// Show the rules the case is pinned to, the current rules, and which
    /// records would change tier; with --update, re-pin to the current rules.
    Rules {
        id: String,
        #[arg(long)]
        update: bool,
        /// The rules to compare with and pin. Default: the bundled rules.
        #[arg(long)]
        rules: Option<PathBuf>,
    },
    /// Draft the public notice into <case>/notice.md and list what it
    /// withheld and what needs a decision. Review and edit it, then
    /// `swarmchase notice add <id>`.
    Notice {
        id: String,
        /// Replace an existing draft (and any edits made to it).
        #[arg(long)]
        force: bool,
    },
    /// Render a report draft from the case's records and case.toml.
    Report {
        id: String,
        /// provider | affected | internal
        #[arg(long, default_value = "internal")]
        audience: Audience,
        #[arg(long)]
        reporter: Option<String>,
        /// Default: <case>/reports/<audience>-<date>.md
        #[arg(short, long)]
        out: Option<PathBuf>,
    },
    /// Export the case for the recipients' tooling (`--format stix`: a STIX
    /// 2.1 bundle), scoped to an audience. Written to a file; nothing is sent.
    Export(crate::stix::ExportArgs),
}

#[derive(Subcommand)]
pub enum FleetCmd {
    /// Merge clusters (by stable key, or C-number in the case's analysis),
    /// and any fleets already holding them, into one fleet.
    Merge {
        id: String,
        #[arg(required = true, num_args = 2..)]
        clusters: Vec<String>,
        /// The admin's reason. Required when no soft link joins the clusters.
        #[arg(long)]
        why: Option<String>,
    },
    /// Take one cluster out of its fleet; a fleet left with one cluster is
    /// dissolved.
    Split {
        id: String,
        cluster: String,
        #[arg(long)]
        why: Option<String>,
    },
    /// The case's fleets, and the candidate fleets the analysis proposes.
    Show { id: String },
    /// Record interaction between a fleet's runs that you reviewed (SC-T9);
    /// while it stands, reports and the notice call the fleet a swarm.
    Interaction {
        id: String,
        /// The fleet (`fleet-1`).
        fleet: String,
        /// shared_sink | handoff | synchronized_start | role_sequence |
        /// disjoint_partition (or S1..S5).
        #[arg(long)]
        kind: sc_core::SwarmEdgeKind,
        /// A run, as <cluster>#<run> (`C3#2` or `k-3f9a2c1b#2`). Repeat.
        #[arg(long = "run", required = true)]
        runs: Vec<String>,
        /// What the records show.
        #[arg(long)]
        note: String,
    },
    /// Withdraw interaction record <n> (from `fleet show`).
    Withdraw {
        id: String,
        fleet: String,
        n: usize,
        #[arg(long)]
        why: Option<String>,
    },
}

/// Who a hand-added contact is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Party {
    /// The AI provider or agent host.
    Provider,
    /// An affected operator.
    Operator,
    /// A national or sector CSIRT.
    Csirt,
    /// The declared owner of an "authorised test".
    DeclaredOwner,
}

impl Party {
    /// The contact role case.toml uses.
    pub fn role(self) -> &'static str {
        match self {
            Self::Provider => "provider",
            Self::Operator => "affected",
            Self::Csirt => "csirt",
            Self::DeclaredOwner => "declared_owner",
        }
    }
}

#[derive(Subcommand)]
pub enum ContactCmd {
    /// Add a contact found by hand (a provider's abuse form, a CSIRT, a
    /// declared owner). Every contact needs the link it was found at.
    Add {
        id: String,
        #[arg(long)]
        party: Party,
        #[arg(long)]
        org: String,
        /// email | form | portal
        #[arg(long, default_value = "email")]
        channel: String,
        /// The e-mail address, or the form or portal URL.
        #[arg(long)]
        address: String,
        /// Where the contact was found (a link).
        #[arg(long)]
        source: String,
        /// low | medium | high
        #[arg(long, default_value = "medium")]
        confidence: String,
        /// The endpoint this contact is for, for an operator.
        #[arg(long)]
        endpoint: Option<String>,
    },
    /// Remove a contact by address.
    Rm { id: String, address: String },
}

/// The case's claims together with the records' own, as reports see them.
pub(crate) fn all_claims(root: &std::path::Path, c: &Case) -> Result<Vec<Claim>> {
    let a = case_analysis(root, c)?;
    Ok(a.clusters.iter().fold(c.claims.clone(), |acc, cl| {
        sc_core::attribution::merge(acc, &sc_core::attribute(&a, cl))
    }))
}

fn contact_cmd(root: &std::path::Path, cmd: ContactCmd, today: &str) -> Result<()> {
    match cmd {
        ContactCmd::Add {
            id,
            party,
            org,
            channel,
            address,
            source,
            confidence,
            endpoint,
        } => update(root, &id, |c| {
            let channel = crate::contacts::case_channel(&channel)?;
            if !matches!(confidence.as_str(), "low" | "medium" | "high") {
                bail!("confidence `{confidence}`: low|medium|high");
            }
            if !(source.starts_with("https://") || source.starts_with("http://")) {
                bail!("--source must be the link the contact was found at");
            }
            let is_email = address.contains('@') && !address.contains('/');
            if (channel == "email") != is_email {
                bail!("`{address}` does not fit channel {channel}");
            }
            if let Some(h) = &endpoint
                && !c.endpoints.iter().any(|e| e.host.eq_ignore_ascii_case(h))
            {
                bail!("no endpoint `{h}` in case {id}");
            }
            if c.contacts
                .iter()
                .any(|x| x.address.eq_ignore_ascii_case(&address) && x.endpoint == endpoint)
            {
                bail!("`{address}` is already a contact in case {id}");
            }
            c.contacts.push(Contact {
                org: org.clone(),
                role: party.role().into(),
                endpoint: endpoint.clone(),
                channel: channel.into(),
                address: address.clone(),
                source: source.clone(),
                confidence: confidence.clone(),
                found_on: today.to_string(),
                purpose: None,
            });
            c.log(
                today,
                format!(
                    "contact added: {org} ({}) {channel} {address}",
                    party.role()
                ),
            );
            Ok(())
        }),
        ContactCmd::Rm { id, address } => update(root, &id, |c| {
            let before = c.contacts.len();
            c.contacts
                .retain(|x| !x.address.eq_ignore_ascii_case(&address));
            let n = before - c.contacts.len();
            if n == 0 {
                bail!("`{address}` is not a contact in case {id}");
            }
            c.log(today, format!("contact removed: {address}"));
            Ok(())
        }),
    }
}

/// The case's analysis over all its records, under its pinned rules.
pub(crate) fn case_analysis(root: &std::path::Path, c: &Case) -> Result<sc_core::Analysis> {
    Ok(sc_core::analyze(
        case_records(root, c, &Scope::All)?,
        &case_rules(root, c)?,
    ))
}

fn fleet_cmd(
    root: &std::path::Path,
    cmd: FleetCmd,
    today: &str,
    out: &mut impl std::io::Write,
) -> Result<()> {
    match cmd {
        FleetCmd::Merge { id, clusters, why } => {
            let a = case_analysis(root, &load(root, &id)?)?;
            update(root, &id, |c| {
                let f = super::fleet::merge(c, &a, &clusters, why.as_deref(), today)?;
                println!("{}", c.decisions.last().map_or("", |d| d.text.as_str()));
                println!("merged into {f}");
                Ok(())
            })
        }
        FleetCmd::Split { id, cluster, why } => {
            let a = case_analysis(root, &load(root, &id)?)?;
            update(root, &id, |c| {
                super::fleet::split(c, &a, &cluster, why.as_deref(), today)?;
                println!("{}", c.decisions.last().map_or("", |d| d.text.as_str()));
                Ok(())
            })
        }
        FleetCmd::Show { id } => {
            let c = load(root, &id)?;
            super::fleet::show(&c, &case_analysis(root, &c)?, out)
        }
        FleetCmd::Interaction {
            id,
            fleet,
            kind,
            runs,
            note,
        } => {
            let a = case_analysis(root, &load(root, &id)?)?;
            update(root, &id, |c| {
                super::fleet::interaction(c, &a, &fleet, kind, &runs, &note, today)?;
                println!("{}", c.decisions.last().map_or("", |d| d.text.as_str()));
                Ok(())
            })
        }
        FleetCmd::Withdraw { id, fleet, n, why } => update(root, &id, |c| {
            super::fleet::withdraw(c, &fleet, n, why.as_deref(), today)?;
            println!("{}", c.decisions.last().map_or("", |d| d.text.as_str()));
            Ok(())
        }),
    }
}

/// Classify `hosts`. Every host is found before anything changes, so a typo
/// changes nothing. `compromised` needs a basis beyond the inbound requests,
/// given now or recorded before.
pub(crate) fn classify(
    c: &mut Case,
    hosts: &[String],
    state: EndpointState,
    note: Option<&str>,
    basis: Option<&str>,
    single_source: Option<&str>,
    today: &str,
) -> Result<()> {
    let id = c.id.clone();
    let found = hosts
        .iter()
        .map(|host| {
            c.endpoints
                .iter()
                .position(|e| e.host.eq_ignore_ascii_case(host))
                .with_context(|| format!("no endpoint `{host}` in case {id}"))
        })
        .collect::<Result<Vec<usize>>>()?;
    fn given(s: Option<&str>) -> Option<&str> {
        s.map(str::trim).filter(|s| !s.is_empty())
    }
    if basis.is_some() && state != EndpointState::Compromised {
        bail!("--basis is for compromised endpoints");
    }
    if state == EndpointState::Compromised && given(basis).is_none() {
        let missing: Vec<&str> = found
            .iter()
            .filter(|&&i| c.endpoints[i].basis.is_none())
            .map(|&i| c.endpoints[i].host.as_str())
            .collect();
        if !missing.is_empty() {
            bail!(
                "compromised needs --basis \"…\": what shows the attack succeeded beyond the inbound requests (an operator's statement, its logs, a leaked artifact), for {}",
                missing.join(", ")
            );
        }
    }
    for (host, i) in hosts.iter().zip(found) {
        let e = &mut c.endpoints[i];
        e.state = state;
        e.note = note.map(str::to_string).or(e.note.take());
        if state != EndpointState::Compromised {
            e.basis = None;
        } else if let Some(b) = given(basis) {
            e.basis = Some(b.to_string());
        }
        if let Some(r) = given(single_source) {
            e.single_source = Some(r.to_string());
        }
        let mut text = format!("endpoint {host}: {}", state.label());
        for (what, v) in [
            ("", note),
            ("basis: ", given(basis)),
            (
                "named on submit-anywhere records only: ",
                given(single_source),
            ),
        ] {
            if let Some(v) = v {
                text += &format!(" ({what}{v})");
            }
        }
        c.log(today, text);
    }
    Ok(())
}

/// Record that no contact was found for `party`: an endpoint's host, a
/// provider organisation among the contacts, or [`super::lead::ANY_PROVIDER`].
pub(crate) fn no_contact(c: &mut Case, party: &str, searched: &str, now: i64) -> Result<()> {
    let is_host = c
        .endpoints
        .iter()
        .any(|e| e.host.eq_ignore_ascii_case(party));
    let is_provider = party.eq_ignore_ascii_case(super::lead::ANY_PROVIDER)
        || c.contacts
            .iter()
            .any(|x| x.role == "provider" && x.org.eq_ignore_ascii_case(party));
    if !(is_host || is_provider) {
        bail!(
            "`{party}` is neither an endpoint nor a provider organisation in case {}",
            c.id
        );
    }
    if searched.trim().is_empty() {
        bail!("--searched: what was tried (security.txt, RDAP, the provider directory, …)");
    }
    let addresses: Vec<&str> = c
        .contacts
        .iter()
        .filter(|x| {
            x.endpoint
                .as_deref()
                .is_some_and(|h| h.eq_ignore_ascii_case(party))
                || (x.role == "provider" && x.org.eq_ignore_ascii_case(party))
        })
        .map(|x| x.address.as_str())
        .collect();
    if !addresses.is_empty() {
        bail!(
            "case {} lists a contact for `{party}` ({}); send it the report, or remove a contact that does not work with `case contact rm`",
            c.id,
            addresses.join(", ")
        );
    }
    c.no_contact.push(NoContact {
        party: party.to_string(),
        searched: searched.to_string(),
        at: rfc3339(now),
    });
    let today = rfc3339(now)[..10].to_string();
    c.log(
        &today,
        format!("no contact found for {party} (searched: {searched}); the notice says contact was attempted"),
    );
    Ok(())
}

/// Record the admin's decision on one alternative explanation.
pub(crate) fn alternative(
    c: &mut Case,
    kind: AlternativeKind,
    rejected: Option<&str>,
    accepted: Option<&str>,
    today: &str,
) -> Result<()> {
    let (verdict, why) = match (rejected, accepted) {
        (Some(w), None) => ("rejected", w),
        (None, Some(w)) if kind == AlternativeKind::AuthorisedTest => ("accepted", w),
        (None, Some(_)) => bail!(
            "only an authorised test is accepted here (its owner confirmed it); if another explanation holds, the case is not an incident: close it"
        ),
        _ => bail!("give --rejected \"why\" (or, for authorised-test, --accepted \"link\")"),
    };
    if why.trim().is_empty() {
        bail!("say why, with links");
    }
    c.alternatives.push(Alternative {
        kind,
        verdict: verdict.into(),
        why: why.to_string(),
        date: today.to_string(),
    });
    c.log(
        today,
        format!("alternative {}: {verdict} ({why})", kind.id()),
    );
    Ok(())
}

/// Record a send. `at` (RFC 3339) or `date` say when; default now. A send
/// time in the future is refused: the lead time runs from the real send.
pub(crate) fn sent(
    c: &mut Case,
    to: &str,
    channel: &str,
    report: Option<String>,
    at: Option<&str>,
    date: Option<&str>,
    now: i64,
) -> Result<String> {
    let at = match (at, date) {
        (Some(a), _) => {
            let t = parse_time(a).with_context(|| {
                format!("--at `{a}`: give an RFC 3339 time, e.g. 2026-10-12T14:05:00Z")
            })?;
            Some(t)
        }
        (None, Some(_)) => None,
        (None, None) => Some(now),
    };
    if at.is_some_and(|t| t > now + 300) {
        bail!("a send cannot be recorded in the future");
    }
    let date = at
        .map(|t| rfc3339(t)[..10].to_string())
        .or(date.map(str::to_string))
        .unwrap_or_default();
    c.sent.push(Sent {
        date: date.clone(),
        recipient: to.to_string(),
        channel: channel.to_string(),
        report,
        at: at.map(rfc3339),
    });
    let when = at.map(show_time).unwrap_or_else(|| date.clone());
    c.log(&date, format!("sent to {to} by {channel} at {when}"));
    if c.status == CaseStatus::Open {
        c.status = CaseStatus::Reported;
        c.log(&date, "status: reported");
    }
    Ok(format!("send to {to} at {when}"))
}

pub fn run(args: CaseArgs) -> Result<()> {
    let root = args.data.join("cases");
    let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
    let now = chrono::Utc::now().timestamp();
    let mut out = std::io::stdout();
    let reads_data = match &args.cmd {
        CaseCmd::Verify { .. } => false,
        // A case opened from record files needs nothing there yet.
        CaseCmd::New { sel, .. } => sel.input.is_empty(),
        _ => true,
    };
    if reads_data {
        crate::store::hint_if_empty(&args.data);
    }
    match args.cmd {
        CaseCmd::New { id, title, sel } => {
            let (rules, records) = select(&args.data, &sel, now)?;
            let a = new_case(&root, &id, &title, records, &rules, &today)?;
            println!("opened {} ({} records)", root.join(&id).display(), a.total);
            status(&root, &id, &mut out)
        }
        CaseCmd::Add { id, sel } => {
            let (_, records) = select(&args.data, &sel, now)?;
            let (added, hosts) = add_records(&root, &id, records, &today)?;
            println!("added {added} record(s), {hosts} new endpoint(s)");
            Ok(())
        }
        CaseCmd::Status { id: None } => list(&root, &mut out),
        CaseCmd::Status { id: Some(id) } => status(&root, &id, &mut out),
        CaseCmd::Endpoint {
            id,
            hosts,
            state,
            note,
            basis,
            single_source_reason,
        } => update(&root, &id, |c| {
            classify(
                c,
                &hosts,
                state,
                note.as_deref(),
                basis.as_deref(),
                single_source_reason.as_deref(),
                &today,
            )
        }),
        CaseCmd::NoContact {
            id,
            party,
            searched,
        } => update(&root, &id, |c| {
            no_contact(c, &party, &searched, now)?;
            println!("{}", c.decisions.last().map_or("", |d| d.text.as_str()));
            Ok(())
        }),
        CaseCmd::Alternative {
            id,
            kind,
            rejected,
            accepted,
        } => match kind {
            None => {
                let c = load(&root, &id)?;
                for k in AlternativeKind::ALL {
                    match c.alternatives.iter().rev().find(|x| x.kind == k) {
                        Some(x) => println!("{:<18} {} {}: {}", k.id(), x.verdict, x.date, x.why),
                        None => println!("{:<18} not decided", k.id()),
                    }
                }
                Ok(())
            }
            Some(k) => update(&root, &id, |c| {
                alternative(c, k, rejected.as_deref(), accepted.as_deref(), &today)
            }),
        },
        CaseCmd::PlantReview { id, cluster, note } => {
            let c = load(&root, &id)?;
            let a = case_analysis(&root, &c)?;
            let key = super::fleet::resolve(&a, &cluster)?;
            let n = super::fleet::by_key(&a, &key).map_or(0, |cl| cl.plant_signals.len());
            update(&root, &id, |c| {
                if note.trim().is_empty() {
                    bail!("--note: what you checked and why the cluster stands");
                }
                c.plant_reviews.retain(|r| r.cluster != key);
                c.plant_reviews.push(PlantReview {
                    cluster: key.clone(),
                    note: note.clone(),
                    date: today.clone(),
                });
                c.log(
                    &today,
                    format!("plant signals reviewed on {key} ({n} signal(s)): {note}"),
                );
                Ok(())
            })
        }
        CaseCmd::Reread { id } => {
            println!("{}", super::checklist::reread(&root, &id, &today, now)?);
            Ok(())
        }
        CaseCmd::Checklist { id } => {
            let items = crate::notice::checklist_for(&root, &id, now)?;
            super::checklist::print(&items, &mut out)?;
            Ok(())
        }
        CaseCmd::Rename { id, new_id } => {
            rename(&root, &id, &new_id, &today)?;
            println!(
                "renamed case {id} to {new_id} ({})",
                root.join(&new_id).display()
            );
            Ok(())
        }
        CaseCmd::Claim {
            id,
            party,
            layer,
            evidence,
            tag,
            likelihood,
            accuracy,
            corpus_size,
            details,
        } => update(&root, &id, |c| {
            let evidence = match (evidence, layer) {
                (Some(e), _) => e,
                (None, Role::Harness | Role::ModelFamily) => Evidence::SelfId,
                (None, _) => bail!("a {} claim needs --evidence", layer.id()),
            };
            let claim = Claim {
                party: party.clone(),
                role: layer,
                evidence,
                details: details.clone(),
                tag,
                records: 0,
                likelihood,
                accuracy,
                corpus_size,
            };
            let problems = claim.problems();
            if !problems.is_empty() {
                bail!("claim not recorded: {}", problems.join("; "));
            }
            c.log(
                &today,
                format!(
                    "claim: {party} ({} layer, {}, {}) on {}",
                    layer.id(),
                    claim.label().label(),
                    claim.tag().label(),
                    evidence.describe()
                ),
            );
            c.claims.push(claim);
            Ok(())
        }),
        CaseCmd::Grade {
            id,
            level,
            note,
            clear,
        } => super::grade::grade(&root, &id, level, note.as_deref(), clear, &today, &mut out),
        CaseCmd::Set {
            id,
            status,
            notice,
            min_named,
            lead_hours,
        } => update(&root, &id, |c| {
            if let Some(h) = lead_hours {
                super::lead::set_operator_lead(c, h, &today)?;
            }
            if let Some(s) = status {
                c.status = s;
                c.log(&today, format!("status: {s:?}").to_lowercase());
            }
            if let Some(n) = notice {
                c.notice = n;
                c.log(&today, format!("notice status: {n:?}").to_lowercase());
            }
            if let Some(m) = min_named {
                let m = m.max(Evidence::FLOOR);
                c.min_named = m;
                c.log(&today, format!("developers named at: {}", m.describe()));
            }
            Ok(())
        }),
        CaseCmd::Contacts {
            id,
            refresh,
            providers_only,
            country,
        } => {
            let claims = all_claims(&root, &load(&root, &id)?)?;
            let dir = crate::contacts::Directory::builtin();
            let csirts = crate::csirts::Csirts::builtin();
            update(&root, &id, |c| {
                let n = crate::contacts::seed_providers(c, &claims, &dir, &today, &mut out)?;
                if n == 0 {
                    println!("provider directory: nothing new for this case's claims");
                }
                if providers_only {
                    return Ok(());
                }
                let n =
                    crate::csirts::seed_csirts(c, &csirts, country.as_deref(), &today, &mut out)?;
                if n > 0 {
                    println!(
                        "{n} national CSIRT(s) proposed; remove any not relevant with `case contact rm`"
                    );
                }
                let client = sc_collect::Client::new(std::time::Duration::from_millis(500))?;
                crate::contacts::find_contacts(c, &client, refresh, &today, &mut std::io::stdout())
            })
        }
        CaseCmd::Contact { cmd } => contact_cmd(&root, cmd, &today),
        CaseCmd::Bundle { id, rules } => {
            let c = load(&root, &id)?;
            let rules = match rules {
                Some(p) => load_rules(Some(&p))?,
                None => case_rules(&root, &c)?,
            };
            let dir = crate::bundle::write(
                &case_dir(&root, &id)?.join("bundles"),
                &id,
                &case_records(&root, &c, &Scope::All)?,
                &rules,
                &today,
                crate::bundle::git_commit(),
            )?;
            println!("wrote {}", dir.display());
            Ok(())
        }
        CaseCmd::Verify { bundle, rules } => {
            let rules = match rules {
                Some(p) => load_rules(Some(&p))?,
                None => bundle_rules(&root, &bundle)?,
            };
            crate::bundle::report_verify(&bundle, &rules)
        }
        CaseCmd::Draft {
            id,
            audience,
            to,
            reporter,
        } => {
            let path = draft(&root, &id, audience, &to, reporter, &today)?;
            let unreviewed = load(&root, &id)?
                .endpoints
                .iter()
                .filter(|e| e.state == EndpointState::Unreviewed)
                .count();
            if unreviewed > 0 {
                eprintln!(
                    "warning: {unreviewed} endpoint(s) are still unreviewed; classify them before sending"
                );
            }
            println!(
                "wrote {} (not sent; review it, send it yourself, then `swarmchase case sent {id} --to {to}`)",
                path.display()
            );
            Ok(())
        }
        CaseCmd::Sent {
            id,
            to,
            channel,
            report,
            at,
            date,
        } => update(&root, &id, |c| {
            let s = sent(
                c,
                &to,
                &channel,
                report.clone(),
                at.as_deref(),
                date.as_deref(),
                now,
            )?;
            if let Some(t) = super::lead::clock(c).not_before {
                println!(
                    "{} recorded; the notice may be added from {} if nothing else is sent",
                    s,
                    show_time(t)
                );
            }
            Ok(())
        }),
        CaseCmd::Evidence { cmd } => crate::evidence::run_evidence(&root, cmd, &today),
        CaseCmd::Fleet { cmd } => fleet_cmd(&root, cmd, &today, &mut out),
        CaseCmd::Note { id, text } => update(&root, &id, |c| {
            c.log(&today, text.clone());
            Ok(())
        }),
        CaseCmd::Rules { id, update, rules } => {
            let current = RulesText::load(rules.as_deref())?;
            rules_cmd(&root, &id, &current, update, &today, &mut out)
        }
        CaseCmd::Notice { id, force } => {
            let (path, review) = crate::notice::notice_draft(&root, &id, force, &today, now)?;
            for w in &review.withheld {
                println!("withheld: {w}");
            }
            for f in &review.flags {
                println!("decide:   {f}");
            }
            for l in &review.lint {
                println!("LEAK:     {l}");
            }
            for h in &review.unreviewed {
                println!("classify: {h} (unreviewed endpoints block `notice add`)");
            }
            println!(
                "wrote {} (draft; review and edit it, then `swarmchase notice add {id}`)",
                path.display()
            );
            Ok(())
        }
        CaseCmd::Report {
            id,
            audience,
            reporter,
            out: path,
        } => {
            let md = report(&root, &id, audience, reporter, None, &today)?;
            let path = path.unwrap_or_else(|| {
                root.join(&id)
                    .join("reports")
                    .join(format!("{}-{today}.md", audience_id(audience)))
            });
            crate::util::write_out(Some(&path), &md)
        }
        CaseCmd::Export(a) => crate::stix::run(&root, a, &today),
    }
}
