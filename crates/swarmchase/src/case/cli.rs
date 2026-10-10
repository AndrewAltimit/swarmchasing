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
    },
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
    /// Change the case or notice status, or the naming threshold.
    Set {
        id: String,
        #[arg(long)]
        status: Option<CaseStatus>,
        #[arg(long)]
        notice: Option<NoticeStatus>,
        #[arg(long)]
        min_named: Option<Evidence>,
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
        /// Default: today.
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
    }
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
        } => update(&root, &id, |c| {
            // Every host is found before anything changes, so a typo changes nothing.
            let found = hosts
                .iter()
                .map(|host| {
                    c.endpoints
                        .iter()
                        .position(|e| e.host.eq_ignore_ascii_case(host))
                        .with_context(|| format!("no endpoint `{host}` in case {id}"))
                })
                .collect::<Result<Vec<usize>>>()?;
            for (host, i) in hosts.iter().zip(found) {
                let e = &mut c.endpoints[i];
                e.state = state;
                e.note = note.clone().or(e.note.take());
                let text = format!(
                    "endpoint {host}: {}{}",
                    state.label(),
                    note.as_deref()
                        .map(|n| format!(" ({n})"))
                        .unwrap_or_default()
                );
                c.log(&today, text);
            }
            Ok(())
        }),
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
        CaseCmd::Set {
            id,
            status,
            notice,
            min_named,
        } => update(&root, &id, |c| {
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
            date,
        } => update(&root, &id, |c| {
            let date = date.clone().unwrap_or_else(|| today.clone());
            c.sent.push(Sent {
                date: date.clone(),
                recipient: to.clone(),
                channel: channel.clone(),
                report: report.clone(),
            });
            c.log(&date, format!("sent to {to} by {channel}"));
            if c.status == CaseStatus::Open {
                c.status = CaseStatus::Reported;
                c.log(&date, "status: reported");
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
            let (path, review) = crate::notice::notice_draft(&root, &id, force, &today)?;
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
