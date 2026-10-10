//! `swarmchase case`: case files for incidents the admin has decided to pursue.
//!
//! A case lives in `<data>/cases/<id>/`, outside git, like the watch data:
//!
//! ```text
//! case.toml            status, pinned rules, endpoints, attribution claims, contacts,
//!                      decisions, sends
//! raw/records.ndjson   the redacted records the case rests on, copied out of the
//!                      watch store before retention deletes them
//! reports/             drafts rendered from the records and case.toml
//! bundles/<date>/      evidence bundles (records, analysis, stamp, manifest)
//! outbox/              unsent e-mail drafts and paste-ready text for the admin
//! evidence/<eid>.ndjson  logs affected operators sent us (`case evidence`)
//! notice.md            the public notice draft (`case notice`), edited by the
//!                      admin, then added to notices/ with `swarmchase notice add`
//! ```
//!
//! The rules a case was opened with are kept in `<data>/rules/<version>.toml`
//! and named in case.toml, so its reports, notice and bundles do not change
//! when the bundled rules do. `case rules <id> --update` re-pins a case to the
//! current rules and logs which records change tier.
//!
//! Cases stay private until the admin publishes: an open case names
//! organisations on unconfirmed evidence, and private reports include details
//! that public notices withhold (docs/policies.md).

use crate::evidence::{self, EvidenceCmd, OperatorEvidence, Scope};
use crate::input::{InputArgs, load_rules, read_inputs};
use crate::store::{load_store, to_ndjson};
use crate::util::audience_id;
use anyhow::{Context, Result, bail};
use clap::{Args, Subcommand};
use sc_core::notice::lint_public;
use sc_core::{
    Analysis, Audience, Claim, EndpointOptions, Evidence, LinkFeature, Observation, ReportOptions,
    Role, Tier, analyze, endpoints, fmt_ts, render_markdown, render_notice,
};
pub use sc_publish::NoticeStatus;
use sc_publish::{NoticeFile, NoticeMeta, write_notice};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum CaseStatus {
    /// Gathering evidence; nothing sent.
    Open,
    /// Reports sent, notice not yet published.
    Reported,
    /// Notice published.
    Published,
    /// No further action: resolved, or dropped as a false lead.
    Closed,
}

/// The public notice draft inside a case directory.
pub const NOTICE_DRAFT: &str = "notice.md";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum EndpointState {
    /// Not yet decided by the admin.
    Unreviewed,
    /// Evidence that an attack succeeded.
    Compromised,
    /// Attacked or probed recently; no evidence of success.
    Targeted,
    /// Attacked or probed in the past only.
    Historical,
    /// Hit by the swarm but not a target (a relay, a carrier, a fetched page).
    NotAffected,
}

impl EndpointState {
    fn label(self) -> &'static str {
        match self {
            Self::Unreviewed => "unreviewed",
            Self::Compromised => "compromised",
            Self::Targeted => "targeted",
            Self::Historical => "historical",
            Self::NotAffected => "not affected",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaseEndpoint {
    pub host: String,
    pub state: EndpointState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Contact {
    pub org: String,
    /// provider | affected | registrar | host | cert
    pub role: String,
    /// The endpoint this contact is for, when it is for one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    /// email | web_form | portal | phone
    pub channel: String,
    pub address: String,
    /// Where the contact was found (a link).
    pub source: String,
    /// low | medium | high
    pub confidence: String,
    pub found_on: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Decision {
    pub date: String,
    pub text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Sent {
    pub date: String,
    pub recipient: String,
    pub channel: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub report: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Case {
    pub id: String,
    pub title: String,
    pub status: CaseStatus,
    pub notice: NoticeStatus,
    pub opened: String,
    /// Weakest evidence that may name a developer outside case notes.
    #[serde(default)]
    pub min_named: Evidence,
    /// The rule set the case renders with, kept at `<data>/rules/<name>.toml`.
    /// Absent in case files from before pinning; those render with the
    /// current rules.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rules_version: Option<String>,
    #[serde(default, rename = "endpoint", skip_serializing_if = "Vec::is_empty")]
    pub endpoints: Vec<CaseEndpoint>,
    /// Attribution established by case work (shared identifiers, provider
    /// infrastructure, provider confirmation). The records' own claims are
    /// derived on every report.
    #[serde(default, rename = "claim", skip_serializing_if = "Vec::is_empty")]
    pub claims: Vec<Claim>,
    #[serde(default, rename = "contact", skip_serializing_if = "Vec::is_empty")]
    pub contacts: Vec<Contact>,
    #[serde(default, rename = "decision", skip_serializing_if = "Vec::is_empty")]
    pub decisions: Vec<Decision>,
    #[serde(default, rename = "sent", skip_serializing_if = "Vec::is_empty")]
    pub sent: Vec<Sent>,
    /// Logs affected operators sent us (`case evidence`).
    #[serde(default, rename = "evidence", skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<OperatorEvidence>,
}

impl Case {
    pub fn log(&mut self, today: &str, text: impl Into<String>) {
        self.decisions.push(Decision {
            date: today.to_string(),
            text: text.into(),
        });
    }

    /// Add every flagged target host not yet listed, as unreviewed.
    fn add_endpoints(&mut self, a: &Analysis) -> usize {
        let known: BTreeSet<String> = self.endpoints.iter().map(|e| e.host.clone()).collect();
        let mut added = 0;
        for v in endpoints(a, &EndpointOptions::default()) {
            if !known.contains(&v.host) {
                self.endpoints.push(CaseEndpoint {
                    host: v.host,
                    state: EndpointState::Unreviewed,
                    note: None,
                });
                added += 1;
            }
        }
        added
    }
}

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
    input: Vec<PathBuf>,
    #[arg(long, default_value_t = 30)]
    days: i64,
    /// Clusters to take, by number in this analysis (C1) or stable key
    /// (k-3f9a2c1b); `swarmchase clusters` lists both.
    #[arg(long = "cluster")]
    clusters: Vec<String>,
    /// Individual records to take, by ID.
    #[arg(long = "record")]
    records: Vec<String>,
    /// Also take every flagged record on the hosts those records target,
    /// including other clusters, so the endpoint view is complete.
    #[arg(long)]
    host_hits: bool,
    #[arg(long)]
    rules: Option<PathBuf>,
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
    /// Classify an affected endpoint.
    Endpoint {
        id: String,
        host: String,
        state: EndpointState,
        #[arg(long)]
        note: Option<String>,
    },
    /// Record an attribution claim established by case work.
    Claim {
        id: String,
        #[arg(long)]
        party: String,
        /// developer | host
        #[arg(long, default_value = "developer")]
        role: String,
        /// shared_identifiers | provider_infrastructure | provider_confirmed | …
        #[arg(long)]
        evidence: Evidence,
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
    /// Find contacts for the case's endpoints: security.txt on the host or
    /// its parent domains, else the registrar's abuse contact from RDAP.
    /// Endpoints marked not-affected are skipped.
    Contacts {
        id: String,
        /// Look up endpoints that already have contacts too.
        #[arg(long)]
        refresh: bool,
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

pub fn run(args: CaseArgs) -> Result<()> {
    let root = args.data.join("cases");
    let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
    let now = chrono::Utc::now().timestamp();
    let mut out = std::io::stdout();
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
            host,
            state,
            note,
        } => update(&root, &id, |c| {
            let e = c
                .endpoints
                .iter_mut()
                .find(|e| e.host.eq_ignore_ascii_case(&host))
                .with_context(|| format!("no endpoint `{host}` in case {id}"))?;
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
            Ok(())
        }),
        CaseCmd::Claim {
            id,
            party,
            role,
            evidence,
            details,
        } => update(&root, &id, |c| {
            let role = match role.as_str() {
                "developer" => Role::Developer,
                "host" => Role::Host,
                r => bail!("unknown role `{r}` (developer|host)"),
            };
            c.log(
                &today,
                format!("claim: {party} ({role:?}) on {}", evidence.describe()),
            );
            c.claims.push(Claim {
                party: party.clone(),
                role,
                evidence,
                details: details.clone(),
            });
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
        CaseCmd::Contacts { id, refresh } => {
            let client = sc_collect::Client::new(std::time::Duration::from_millis(500))?;
            update(&root, &id, |c| {
                find_contacts(c, &client, refresh, &today, &mut std::io::stdout())
            })
        }
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
        CaseCmd::Evidence { cmd } => run_evidence(&root, cmd, &today),
        CaseCmd::Note { id, text } => update(&root, &id, |c| {
            c.log(&today, text.clone());
            Ok(())
        }),
        CaseCmd::Rules { id, update, rules } => {
            let current = RulesText::load(rules.as_deref())?;
            rules_cmd(&root, &id, &current, update, &today, &mut out)
        }
        CaseCmd::Notice { id, force } => {
            let (path, review) = notice_draft(&root, &id, force, &today)?;
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

fn find_contacts(
    c: &mut Case,
    client: &sc_collect::Client,
    refresh: bool,
    today: &str,
    out: &mut impl Write,
) -> Result<()> {
    let hosts: Vec<String> = c
        .endpoints
        .iter()
        .filter(|e| e.state != EndpointState::NotAffected)
        .filter(|e| {
            refresh
                || !c
                    .contacts
                    .iter()
                    .any(|x| x.endpoint.as_ref() == Some(&e.host))
        })
        .map(|e| e.host.clone())
        .collect();
    for host in hosts {
        let mut found = Vec::new();
        let mut how = "nothing found";
        for d in crate::contacts::domain_candidates(&host) {
            if let Ok((url, body)) = client.security_txt(&d) {
                let s = sc_core::parse_security_txt(&body);
                found = crate::contacts::from_security_txt(&d, &url, &s, today);
                how = "security.txt";
                break;
            }
        }
        if found.is_empty() {
            let domain = crate::contacts::registered_domain(&host);
            if let Ok((url, body)) = client.rdap_domain(&domain) {
                found = crate::contacts::rdap_abuse(&body)
                    .into_iter()
                    .map(|(org, email)| Contact {
                        org,
                        role: "registrar".into(),
                        endpoint: None,
                        channel: "email".into(),
                        address: email,
                        source: url.clone(),
                        confidence: "low".into(),
                        found_on: today.to_string(),
                    })
                    .collect();
                if !found.is_empty() {
                    how = "RDAP registrar abuse contact (fallback)";
                }
            }
        }
        let mut added = 0;
        for mut x in found {
            x.endpoint = Some(host.clone());
            if !c
                .contacts
                .iter()
                .any(|y| y.endpoint == x.endpoint && y.address.eq_ignore_ascii_case(&x.address))
            {
                writeln!(
                    out,
                    "{host}: {} {} ({}, {} confidence)",
                    x.channel, x.address, x.source, x.confidence
                )?;
                c.contacts.push(x);
                added += 1;
            }
        }
        if added == 0 {
            writeln!(out, "{host}: {how}, nothing new")?;
        }
        c.log(today, format!("contacts for {host}: {added} new ({how})"));
    }
    Ok(())
}

/// Write the report for one contact into the outbox: an unsent .eml with a
/// fresh bundle attached for e-mail contacts, paste-ready text otherwise.
fn draft(
    root: &Path,
    id: &str,
    audience: Audience,
    to: &str,
    reporter: Option<String>,
    today: &str,
) -> Result<PathBuf> {
    if matches!(audience, Audience::Internal | Audience::Public) {
        bail!(
            "only provider and affected reports are sent; case notes stay private and the notice is published (`case notice`)"
        );
    }
    let c = load(root, id)?;
    let Some(contact) = c
        .contacts
        .iter()
        .find(|x| x.address.eq_ignore_ascii_case(to))
    else {
        let known: Vec<&str> = c.contacts.iter().map(|x| x.address.as_str()).collect();
        bail!(
            "`{to}` is not a contact in case {id} (known: {}); add it to case.toml or run `case contacts`",
            if known.is_empty() {
                "none".into()
            } else {
                known.join(", ")
            }
        );
    };
    let md = report(root, id, audience, reporter, Some(contact), today)?;
    let dir = case_dir(root, id)?;
    let outbox = dir.join("outbox");
    std::fs::create_dir_all(&outbox)?;
    let slug: String = contact
        .address
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() {
                ch.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect();
    let stem = format!("{today}-{}-{slug}", audience_id(audience));
    if contact.channel != "email" {
        let p = outbox.join(format!("{stem}.md"));
        std::fs::write(
            &p,
            format!(
                "<!-- Paste into {} ({}). Attach the latest bundle from {} if the form accepts files. -->\n\n{md}",
                contact.address,
                contact.channel,
                dir.join("bundles").display()
            ),
        )?;
        return Ok(p);
    }
    let bundle = crate::bundle::write(
        &dir.join("bundles"),
        id,
        &case_records(root, &c, &scope(audience, Some(contact)))?,
        &case_rules(root, &c)?,
        today,
        crate::bundle::git_commit(),
    )?;
    let subject = match audience {
        Audience::Provider => format!("Suspected misaligned agent activity: {} [{id}]", c.title),
        _ => format!(
            "Automated agent activity targeting your systems: {} [{id}]",
            c.title
        ),
    };
    let p = outbox.join(format!("{stem}.eml"));
    std::fs::write(
        &p,
        crate::bundle::eml(
            &contact.address,
            &subject,
            &md,
            &crate::bundle::attachments(&bundle)?,
        ),
    )?;
    Ok(p)
}

fn check_id(id: &str) -> Result<()> {
    let ok = !id.is_empty()
        && id.len() <= 64
        && id
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        && !id.starts_with('-');
    if !ok {
        bail!(
            "case id `{id}`: use lowercase letters, digits and hyphens (e.g. 2026-10-portal-sqli)"
        );
    }
    Ok(())
}

/// Load records, analyse them, and pick the selected clusters and records.
fn select(data: &Path, sel: &Selection, now: i64) -> Result<(RulesText, Vec<Observation>)> {
    if sel.clusters.is_empty() && sel.records.is_empty() {
        bail!("choose records with --cluster and/or --record");
    }
    let rules = RulesText::load(sel.rules.as_deref())?;
    let obs = if sel.input.is_empty() {
        let dir = data.join("store");
        if !dir.is_dir() {
            bail!(
                "no watch store at {} (pass record files, or set --data / SWARMCHASE_DATA)",
                dir.display()
            );
        }
        load_store(&dir, now - sel.days * 86_400)?
    } else {
        read_inputs(&InputArgs {
            input: sel.input.clone(),
            format: sc_core::Format::Auto,
            map: None,
            rules: None,
        })?
    };
    let a = analyze(obs, &rules.rules);
    let picked = pick(&a, &sel.clusters, &sel.records, sel.host_hits)?;
    Ok((rules, picked))
}

fn pick(
    a: &Analysis,
    clusters: &[String],
    records: &[String],
    host_hits: bool,
) -> Result<Vec<Observation>> {
    let mut idx = BTreeSet::new();
    for id in clusters {
        let c = a
            .cluster(id)
            .with_context(|| format!("no cluster `{id}` in this analysis"))?;
        idx.extend(c.members.iter().copied());
    }
    for id in records {
        let i = a
            .results
            .iter()
            .position(|r| &r.obs.id == id)
            .with_context(|| format!("no record `{id}` in this analysis"))?;
        idx.insert(i);
    }
    if !host_hits {
        return Ok(idx.into_iter().map(|i| a.results[i].obs.clone()).collect());
    }
    let hosts: BTreeSet<&str> = idx
        .iter()
        .filter_map(|&i| a.results[i].target_host.as_deref())
        .collect();
    for (i, r) in a.results.iter().enumerate() {
        if r.tier >= Tier::Suggestive && r.target_host.as_deref().is_some_and(|h| hosts.contains(h))
        {
            idx.insert(i);
        }
    }
    Ok(idx.into_iter().map(|i| a.results[i].obs.clone()).collect())
}

pub fn case_dir(root: &Path, id: &str) -> Result<PathBuf> {
    check_id(id)?;
    Ok(root.join(id))
}

pub fn load(root: &Path, id: &str) -> Result<Case> {
    let p = case_dir(root, id)?.join("case.toml");
    let text =
        std::fs::read_to_string(&p).with_context(|| format!("no case at {}", p.display()))?;
    toml::from_str(&text).with_context(|| format!("parsing {}", p.display()))
}

fn save(root: &Path, c: &Case) -> Result<()> {
    let dir = case_dir(root, &c.id)?;
    std::fs::create_dir_all(&dir)?;
    let p = dir.join("case.toml");
    let tmp = dir.join("case.toml.tmp");
    std::fs::write(&tmp, toml::to_string_pretty(c)?)?;
    std::fs::rename(&tmp, &p).with_context(|| format!("writing {}", p.display()))
}

pub fn update(root: &Path, id: &str, f: impl FnOnce(&mut Case) -> Result<()>) -> Result<()> {
    let mut c = load(root, id)?;
    f(&mut c)?;
    save(root, &c)?;
    println!("updated {}", root.join(id).join("case.toml").display());
    Ok(())
}

/// Which operator evidence a report for `audience` may use: all of it in case
/// notes and provider reports, an operator's own logs in a report to that
/// operator, and in the notice only logs the operator agreed to publish.
pub(crate) fn scope(audience: Audience, to: Option<&Contact>) -> Scope<'_> {
    match (audience, to) {
        (Audience::Internal | Audience::Provider, _) => Scope::All,
        (Audience::Public, _) => Scope::Public,
        (Audience::Affected, Some(c)) => Scope::Operator {
            org: &c.org,
            host: c.endpoint.as_deref(),
        },
        (Audience::Affected, None) => Scope::Operator {
            org: "",
            host: None,
        },
    }
}

/// The case's records plus the operator evidence `scope` allows.
pub fn case_records(root: &Path, c: &Case, scope: &Scope) -> Result<Vec<Observation>> {
    let mut all = load_records(root, &c.id)?;
    let dir = case_dir(root, &c.id)?;
    for e in c.evidence.iter().filter(|e| e.in_scope(scope)) {
        let p = evidence::file(&dir, &e.id);
        let text =
            std::fs::read_to_string(&p).with_context(|| format!("reading {}", p.display()))?;
        for l in text.lines().filter(|l| !l.trim().is_empty()) {
            all.push(serde_json::from_str(l).with_context(|| format!("parsing {}", p.display()))?);
        }
    }
    Ok(all)
}

fn run_evidence(root: &Path, cmd: EvidenceCmd, today: &str) -> Result<()> {
    match cmd {
        EvidenceCmd::Add {
            id,
            file,
            org,
            host,
            format,
            map,
            date,
            note,
        } => {
            let bytes =
                std::fs::read(&file).with_context(|| format!("reading {}", file.display()))?;
            let text = String::from_utf8_lossy(&bytes);
            let mut fm = match &map {
                Some(m) => sc_core::FieldMap::parse(m).map_err(anyhow::Error::msg)?,
                None => sc_core::FieldMap::default(),
            };
            fm.host = Some(host.clone());
            let e = add_evidence(
                root, &id, &text, format, &fm, &org, &host, date, note, today,
            )?;
            println!(
                "added {}: kept {} of {} records from {} (private reports only until `swarmchase case evidence consent {id} {} --how …`)",
                e.id, e.kept, e.lines, org, e.id
            );
            Ok(())
        }
        EvidenceCmd::Consent {
            id,
            evidence,
            how,
            date,
        } => {
            let date = date.unwrap_or_else(|| today.to_string());
            update(root, &id, |c| {
                let e = find_evidence(c, &evidence)?;
                e.public = Some(format!("{date}: {how}"));
                let org = e.org.clone();
                c.log(
                    &date,
                    format!("operator evidence {evidence}: {org} agreed to its use in the public notice ({how})"),
                );
                Ok(())
            })?;
            if case_dir(root, &id)?.join(NOTICE_DRAFT).exists() {
                println!(
                    "re-draft the notice to include it: `swarmchase case notice {id} --force`"
                );
            }
            Ok(())
        }
        EvidenceCmd::Withdraw { id, evidence, date } => {
            let date = date.unwrap_or_else(|| today.to_string());
            let mut published = false;
            update(root, &id, |c| {
                let e = find_evidence(c, &evidence)?;
                if e.public.take().is_none() {
                    bail!("{evidence} has no recorded agreement");
                }
                let org = e.org.clone();
                c.log(
                    &date,
                    format!("operator evidence {evidence}: {org} withdrew its agreement"),
                );
                published = c.status == CaseStatus::Published;
                Ok(())
            })?;
            if published {
                eprintln!(
                    "warning: the notice is published and may use these records; append a correction with `swarmchase notice update {id} --kind correction`"
                );
            }
            Ok(())
        }
        EvidenceCmd::List { id } => {
            let c = load(root, &id)?;
            if c.evidence.is_empty() {
                println!("no operator evidence in case {id}");
            }
            for e in &c.evidence {
                println!(
                    "{}  {}  {}  received {}  {}/{} records  sha256 {}  {}",
                    e.id,
                    e.org,
                    sc_core::defang_host(&e.host),
                    e.received,
                    e.kept,
                    e.lines,
                    &e.sha256[..e.sha256.len().min(16)],
                    e.public.as_deref().unwrap_or("private reports only")
                );
            }
            Ok(())
        }
    }
}

fn find_evidence<'a>(c: &'a mut Case, eid: &str) -> Result<&'a mut OperatorEvidence> {
    let id = c.id.clone();
    c.evidence
        .iter_mut()
        .find(|e| e.id == eid)
        .with_context(|| format!("no evidence `{eid}` in case {id}"))
}

#[allow(clippy::too_many_arguments)]
fn add_evidence(
    root: &Path,
    id: &str,
    text: &str,
    format: sc_core::Format,
    map: &sc_core::FieldMap,
    org: &str,
    host: &str,
    date: Option<String>,
    note: Option<String>,
    today: &str,
) -> Result<OperatorEvidence> {
    let mut c = load(root, id)?;
    let sha256 = crate::bundle::sha256_hex(text.as_bytes());
    if let Some(e) = c.evidence.iter().find(|e| e.sha256 == sha256) {
        bail!("this file is already evidence {} in case {id}", e.id);
    }
    let eid = format!("e{}", c.evidence.len() + 1);
    let (records, lines, warnings) =
        evidence::ingest(text, format, map, &eid, &case_rules(root, &c)?);
    for w in warnings.iter().take(5) {
        eprintln!("warning: {w}");
    }
    if lines == 0 {
        bail!("no records in the file (check --format and --map)");
    }
    let dir = case_dir(root, id)?;
    let p = evidence::file(&dir, &eid);
    std::fs::create_dir_all(p.parent().unwrap_or(&dir))?;
    std::fs::write(&p, to_ndjson(&records)?)?;
    let received = date.unwrap_or_else(|| today.to_string());
    let e = OperatorEvidence {
        id: eid.clone(),
        org: org.to_string(),
        host: host.to_ascii_lowercase(),
        received: received.clone(),
        sha256,
        lines,
        kept: records.len(),
        public: None,
        note,
    };
    c.evidence.push(e.clone());
    c.log(
        &received,
        format!(
            "operator evidence {eid} from {org}: {} of {lines} records kept; private reports only",
            records.len()
        ),
    );
    save(root, &c)?;
    Ok(e)
}

/// A rule set and the TOML it was compiled from, so a case can keep a copy.
pub struct RulesText {
    pub text: String,
    pub rules: sc_core::Rules,
}

impl RulesText {
    /// The rules file at `p`, or the bundled rules.
    pub fn load(p: Option<&Path>) -> Result<Self> {
        let text = match p {
            Some(p) => {
                std::fs::read_to_string(p).with_context(|| format!("reading {}", p.display()))?
            }
            None => sc_core::DEFAULT_RULES.to_string(),
        };
        let rules = sc_core::Rules::from_toml(&text).map_err(anyhow::Error::msg)?;
        Ok(Self { text, rules })
    }

    pub fn version(&self) -> &str {
        &self.rules.set.meta.version
    }
}

/// Pinned rule sets live beside the cases, in `<data>/rules/`.
fn rules_dir(root: &Path) -> PathBuf {
    root.parent().unwrap_or(root).join("rules")
}

/// A pin name is a file stem in the rules directory, never a path.
fn check_pin(name: &str) -> Result<()> {
    let ok = !name.is_empty()
        && !name.starts_with('.')
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'));
    if !ok {
        bail!("rules pin `{name}` is not a valid name");
    }
    Ok(())
}

/// Keep a copy of `r` in `<data>/rules/` and return its name there: the rules
/// version, or the version plus a hash prefix when a different rule set
/// already holds that name (an edited file that kept its version).
pub(crate) fn pin_rules(root: &Path, r: &RulesText) -> Result<String> {
    let dir = rules_dir(root);
    std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    let mut v: String = r
        .version()
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_') {
                c
            } else {
                '-'
            }
        })
        .collect();
    if v.is_empty() || v.starts_with('.') {
        v = format!("v{v}");
    }
    let sha = crate::bundle::sha256_hex(r.text.as_bytes());
    for name in [v.clone(), format!("{v}-{}", &sha[..12])] {
        let p = dir.join(format!("{name}.toml"));
        match std::fs::read_to_string(&p) {
            Ok(t) if t == r.text => return Ok(name),
            Ok(_) => continue,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                std::fs::write(&p, &r.text).with_context(|| format!("writing {}", p.display()))?;
                return Ok(name);
            }
            Err(e) => return Err(e).with_context(|| format!("reading {}", p.display())),
        }
    }
    bail!(
        "{}: other rule sets already hold `{v}` and `{v}-{}`",
        dir.display(),
        &sha[..12]
    )
}

/// The rules a case renders with: its pinned copy, or the current bundled
/// rules for a case file from before pinning.
pub fn case_rules(root: &Path, c: &Case) -> Result<sc_core::Rules> {
    let Some(pin) = &c.rules_version else {
        return Ok(sc_core::Rules::default_rules());
    };
    check_pin(pin)?;
    let p = rules_dir(root).join(format!("{pin}.toml"));
    let text = std::fs::read_to_string(&p).with_context(|| {
        format!(
            "case {} is pinned to rules {pin}, but {} cannot be read",
            c.id,
            p.display()
        )
    })?;
    sc_core::Rules::from_toml(&text).map_err(|e| anyhow::anyhow!("{}: {e}", p.display()))
}

/// Run a leak check under the case's pinned rules, and under the current
/// rules too when they differ, so a check added after the case was opened
/// still applies. Findings are merged in order, without repeats.
pub fn leak_check(
    root: &Path,
    c: &Case,
    check: impl Fn(&sc_core::Rules) -> Vec<String>,
) -> Result<Vec<String>> {
    let mut out = check(&case_rules(root, c)?);
    let current = sc_core::Rules::default_rules();
    if c.rules_version.as_deref() != Some(current.set.meta.version.as_str()) {
        for p in check(&current) {
            if !out.contains(&p) {
                out.push(p);
            }
        }
    }
    Ok(out)
}

/// The rules to verify a bundle with: the pinned copy named by its stamp when
/// there is one, else the bundled rules.
fn bundle_rules(root: &Path, bundle: &Path) -> Result<sc_core::Rules> {
    let st = crate::bundle::read_stamp(bundle)?;
    let p = rules_dir(root).join(format!("{}.toml", st.rules_version));
    if check_pin(&st.rules_version).is_ok() && p.is_file() {
        return load_rules(Some(&p));
    }
    Ok(sc_core::Rules::default_rules())
}

/// Records whose tier differs between the case's pinned rules and `current`:
/// record ID -> (pinned tier, current tier).
pub(crate) fn tier_changes(
    root: &Path,
    c: &Case,
    current: &sc_core::Rules,
) -> Result<BTreeMap<String, (Tier, Tier)>> {
    let records = case_records(root, c, &Scope::All)?;
    let before = analyze(records.clone(), &case_rules(root, c)?);
    let after = analyze(records, current);
    let was: BTreeMap<&str, Tier> = before
        .results
        .iter()
        .map(|r| (r.obs.id.as_str(), r.tier))
        .collect();
    Ok(after
        .results
        .iter()
        .filter_map(|r| {
            let w = *was.get(r.obs.id.as_str())?;
            (w != r.tier).then(|| (r.obs.id.clone(), (w, r.tier)))
        })
        .collect())
}

/// What a case's activity is recognised by in new records: the linking
/// features of its non-noise clusters (run tags, inbox and callback channels,
/// agent markers) and the endpoints it hit, as its pinned rules extract them.
pub(crate) struct CaseIndicators {
    /// Linking feature -> what it names (see [`crate::stix::feature_kind`]).
    pub features: BTreeMap<LinkFeature, &'static str>,
    /// Endpoints, except those classified as not affected.
    pub endpoints: BTreeSet<String>,
    /// The case's own records, which never count as new activity.
    pub records: BTreeSet<String>,
    /// Newest capture time among the case's records (0 when none is dated).
    pub last_seen: i64,
}

impl CaseIndicators {
    /// The indicators `o` shares with the case, described for the admin;
    /// empty unless `o` matched at least one rule under `rules` (the case's).
    pub fn matches(&self, o: &Observation, rules: &sc_core::Rules) -> Vec<String> {
        if self.records.contains(&o.id) {
            return Vec::new();
        }
        let x = sc_core::extract(o, rules);
        if x.score <= 0 {
            return Vec::new();
        }
        let mut out: Vec<String> = x
            .features
            .iter()
            .filter_map(|f| {
                let what = self.features.get(f)?;
                let value = match f {
                    LinkFeature::Param { .. } => f.to_string(),
                    LinkFeature::Rule { value, .. } => value.clone(),
                };
                Some(format!("{what} {}", value.trim_start_matches("param:")))
            })
            .collect();
        if let Some(h) = x.target_host.filter(|h| self.endpoints.contains(h)) {
            out.push(format!("Endpoint {h}"));
        }
        out
    }
}

/// The case's indicators under `rules`, which should be its pinned rules
/// ([`case_rules`]).
pub(crate) fn indicators(root: &Path, c: &Case, rules: &sc_core::Rules) -> Result<CaseIndicators> {
    let records = case_records(root, c, &Scope::All)?;
    let a = analyze(records, rules);
    let kinds: BTreeMap<&str, sc_core::IndicatorKind> = rules
        .set
        .rules
        .iter()
        .map(|r| (r.id.as_str(), r.kind))
        .collect();
    let mut features = BTreeMap::new();
    for r in &a.results {
        let in_cluster = r
            .cluster
            .is_some_and(|ci| a.clusters[ci].tier != Tier::Noise);
        if in_cluster {
            for f in &r.features {
                features.insert(f.clone(), crate::stix::feature_kind(f, &kinds));
            }
        }
    }
    Ok(CaseIndicators {
        features,
        endpoints: c
            .endpoints
            .iter()
            .filter(|e| e.state != EndpointState::NotAffected)
            .map(|e| e.host.clone())
            .collect(),
        records: a.results.iter().map(|r| r.obs.id.clone()).collect(),
        last_seen: a.results.iter().map(|r| r.obs.ts).max().unwrap_or(0).max(0),
    })
}

/// Every case under `root`, by ID. A case file that does not parse is an error.
pub(crate) fn all(root: &Path) -> Result<Vec<Case>> {
    let mut cases = Vec::new();
    if let Ok(entries) = std::fs::read_dir(root) {
        for e in entries {
            let p = e?.path();
            if p.join("case.toml").is_file() {
                let id = p.file_name().unwrap_or_default().to_string_lossy();
                cases.push(load(root, &id)?);
            }
        }
    }
    cases.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(cases)
}

fn describe_changes(changes: &BTreeMap<String, (Tier, Tier)>, max: usize) -> String {
    let mut s: Vec<String> = changes
        .iter()
        .take(max)
        .map(|(id, (a, b))| format!("{id} {} → {}", a.label(), b.label()))
        .collect();
    if changes.len() > max {
        s.push(format!("{} more", changes.len() - max));
    }
    s.join(", ")
}

/// `case rules`: pinned against current, and with `update` re-pin to
/// `current` and log the change and the records that changed tier.
fn rules_cmd(
    root: &Path,
    id: &str,
    current: &RulesText,
    update: bool,
    today: &str,
    out: &mut impl Write,
) -> Result<()> {
    let mut c = load(root, id)?;
    let pinned = c
        .rules_version
        .clone()
        .unwrap_or_else(|| "not pinned (renders with the current rules)".into());
    writeln!(out, "pinned:  {pinned}")?;
    writeln!(out, "current: {}", current.version())?;
    let changes = tier_changes(root, &c, &current.rules)?;
    if changes.is_empty() {
        writeln!(out, "no record changes tier under the current rules")?;
    } else {
        writeln!(
            out,
            "{} record(s) change tier under the current rules: {}",
            changes.len(),
            describe_changes(&changes, 20)
        )?;
    }
    if !update {
        writeln!(
            out,
            "re-pin with `swarmchase case rules {id} --update` (reports, notice and bundles then use the current rules)"
        )?;
        return Ok(());
    }
    let pin = pin_rules(root, current)?;
    if c.rules_version.as_deref() == Some(pin.as_str()) {
        writeln!(out, "already pinned to {pin}")?;
        return Ok(());
    }
    let what = if changes.is_empty() {
        "no record changed tier".to_string()
    } else {
        format!(
            "{} record(s) changed tier: {}",
            changes.len(),
            describe_changes(&changes, 10)
        )
    };
    c.log(
        today,
        format!(
            "rules re-pinned: {} → {pin}; {what}",
            c.rules_version.as_deref().unwrap_or("not pinned")
        ),
    );
    c.rules_version = Some(pin.clone());
    save(root, &c)?;
    writeln!(out, "pinned {id} to rules {pin}")?;
    Ok(())
}

/// Append a decision log entry without printing anything.
pub(crate) fn log_entry(root: &Path, id: &str, today: &str, text: impl Into<String>) -> Result<()> {
    let mut c = load(root, id)?;
    c.log(today, text);
    save(root, &c)
}

fn records_path(root: &Path, id: &str) -> Result<PathBuf> {
    Ok(case_dir(root, id)?.join("raw").join("records.ndjson"))
}

fn load_records(root: &Path, id: &str) -> Result<Vec<Observation>> {
    let p = records_path(root, id)?;
    let text = std::fs::read_to_string(&p).with_context(|| format!("reading {}", p.display()))?;
    text.lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).with_context(|| format!("parsing {}", p.display())))
        .collect()
}

/// Open a case from `records`, pinned to `rules`.
pub(crate) fn new_case(
    root: &Path,
    id: &str,
    title: &str,
    records: Vec<Observation>,
    rules: &RulesText,
    today: &str,
) -> Result<Analysis> {
    let dir = case_dir(root, id)?;
    if dir.join("case.toml").exists() {
        bail!("case {id} already exists; use `case add` to add records");
    }
    if records.is_empty() {
        bail!("no records selected");
    }
    std::fs::create_dir_all(dir.join("raw"))?;
    let pin = pin_rules(root, rules)?;
    std::fs::write(records_path(root, id)?, to_ndjson(&records)?)?;
    let a = analyze(records, &rules.rules);
    let mut c = Case {
        id: id.to_string(),
        title: title.to_string(),
        status: CaseStatus::Open,
        notice: NoticeStatus::Active,
        opened: today.to_string(),
        min_named: Evidence::default(),
        rules_version: Some(pin.clone()),
        endpoints: Vec::new(),
        claims: Vec::new(),
        contacts: Vec::new(),
        decisions: Vec::new(),
        sent: Vec::new(),
        evidence: Vec::new(),
    };
    c.add_endpoints(&a);
    c.log(
        today,
        format!(
            "opened with {} records ({} flagged), rules {pin}",
            a.total, a.flagged
        ),
    );
    save(root, &c)?;
    Ok(a)
}

/// Add the records the case does not hold yet, and any new endpoints they
/// bring, judged by the case's pinned rules.
pub(crate) fn add_records(
    root: &Path,
    id: &str,
    records: Vec<Observation>,
    today: &str,
) -> Result<(usize, usize)> {
    let mut c = load(root, id)?;
    let mut all = load_records(root, id)?;
    let have: BTreeSet<String> = all.iter().map(|o| o.id.clone()).collect();
    let fresh: Vec<Observation> = records
        .into_iter()
        .filter(|o| !have.contains(&o.id))
        .collect();
    if fresh.is_empty() {
        return Ok((0, 0));
    }
    let mut f = std::fs::OpenOptions::new()
        .append(true)
        .open(records_path(root, id)?)?;
    f.write_all(to_ndjson(&fresh)?.as_bytes())?;
    let n = fresh.len();
    all.extend(fresh);
    let hosts = c.add_endpoints(&analyze(all, &case_rules(root, &c)?));
    c.log(
        today,
        format!("added {n} record(s), {hosts} new endpoint(s)"),
    );
    save(root, &c)?;
    Ok((n, hosts))
}

fn list(root: &Path, out: &mut impl Write) -> Result<()> {
    let mut cases = all(root)?;
    if cases.is_empty() {
        writeln!(out, "no cases in {}", root.display())?;
        return Ok(());
    }
    cases.sort_by(|a, b| b.opened.cmp(&a.opened).then(a.id.cmp(&b.id)));
    writeln!(
        out,
        "{:<32} {:<10} {:<11} {:<10} title",
        "id", "status", "notice", "opened"
    )?;
    for c in &cases {
        writeln!(
            out,
            "{:<32} {:<10} {:<11} {:<10} {}",
            c.id,
            format!("{:?}", c.status).to_lowercase(),
            format!("{:?}", c.notice).to_lowercase(),
            c.opened,
            c.title
        )?;
    }
    Ok(())
}

fn status(root: &Path, id: &str, out: &mut impl Write) -> Result<()> {
    let c = load(root, id)?;
    let a = analyze(case_records(root, &c, &Scope::All)?, &case_rules(root, &c)?);
    writeln!(out, "# {} — {}", c.id, c.title)?;
    writeln!(
        out,
        "status {:?} · notice {:?} · opened {} · developers named at: {}",
        c.status,
        c.notice,
        c.opened,
        c.min_named.max(Evidence::FLOOR).describe()
    )?;
    let current = &sc_core::Rules::default_rules().set.meta.version;
    match &c.rules_version {
        Some(pin) if a.rules_version == *current => writeln!(out, "rules {pin} (pinned)")?,
        Some(pin) => writeln!(
            out,
            "rules {pin} (pinned; current rules {current}, see `swarmchase case rules {}`)",
            c.id
        )?,
        None => writeln!(
            out,
            "rules not pinned; rendering with the current rules {current}"
        )?,
    }
    writeln!(
        out,
        "{} records ({} flagged) · {} clusters · {} → {}",
        a.total,
        a.flagged,
        a.clusters.len(),
        fmt_ts(a.timing.start),
        fmt_ts(a.timing.end)
    )?;
    for cl in &a.clusters {
        writeln!(
            out,
            "  {} [{}] {} records, {} → {}",
            cl.id,
            cl.tier.label(),
            cl.members.len(),
            fmt_ts(cl.start),
            fmt_ts(cl.end)
        )?;
    }

    writeln!(out, "\nEndpoints")?;
    let views = endpoints(&a, &EndpointOptions::default());
    for e in &c.endpoints {
        let v = views.iter().find(|v| v.host == e.host);
        writeln!(
            out,
            "  {:<12} {:<40} {}{}",
            e.state.label(),
            sc_core::defang_host(&e.host),
            v.map(|v| format!(
                "{} hits, last {}, {}{}",
                v.hits,
                fmt_ts(v.last_seen),
                v.activity.label(),
                if v.payloads { ", payloads" } else { "" }
            ))
            .unwrap_or_default(),
            e.note
                .as_deref()
                .map(|n| format!(" — {n}"))
                .unwrap_or_default()
        )?;
    }

    writeln!(out, "\nAttribution")?;
    let claims = a.clusters.iter().fold(c.claims.clone(), |acc, cl| {
        sc_core::attribution::merge(acc, &sc_core::attribute(&a, cl))
    });
    if claims.is_empty() {
        writeln!(out, "  none")?;
    }
    for cl in &claims {
        writeln!(
            out,
            "  {:<3} {} ({:?}) — {}",
            if cl.nameable(c.min_named) {
                "✓"
            } else {
                "·"
            },
            cl.party,
            cl.role,
            cl.evidence.describe()
        )?;
    }
    if !c.evidence.is_empty() {
        writeln!(out, "\nOperator evidence")?;
        for e in &c.evidence {
            writeln!(
                out,
                "  {:<4} {} ({}), received {}, {} of {} records kept — {}",
                e.id,
                e.org,
                sc_core::defang_host(&e.host),
                e.received,
                e.kept,
                e.lines,
                e.public
                    .as_deref()
                    .map(|p| format!("may be published ({p})"))
                    .unwrap_or_else(|| "private reports only".into())
            )?;
        }
    }
    writeln!(
        out,
        "\nContacts: {} · decisions: {} · sent: {}",
        c.contacts.len(),
        c.decisions.len(),
        c.sent.len()
    )?;

    let todo = todo(&c, &claims);
    if !todo.is_empty() {
        writeln!(out, "\nNeeds")?;
        for t in todo {
            writeln!(out, "  - {t}")?;
        }
    }
    Ok(())
}

/// What the case still needs before reports can go out.
fn todo(c: &Case, claims: &[Claim]) -> Vec<String> {
    let mut t = Vec::new();
    let unreviewed = c
        .endpoints
        .iter()
        .filter(|e| e.state == EndpointState::Unreviewed)
        .count();
    if unreviewed > 0 {
        t.push(format!(
            "classify {unreviewed} endpoint(s): `swarmchase case endpoint {} <host> compromised|targeted|historical|not-affected`",
            c.id
        ));
    }
    let affected = c.endpoints.iter().any(|e| {
        matches!(
            e.state,
            EndpointState::Compromised | EndpointState::Targeted | EndpointState::Historical
        )
    });
    if affected && !c.contacts.iter().any(|x| x.role == "affected") {
        t.push(format!(
            "find contacts for the affected operators: `swarmchase case contacts {}`",
            c.id
        ));
    }
    let named = claims
        .iter()
        .any(|x| x.role == Role::Developer && x.nameable(c.min_named));
    if !named {
        t.push(format!(
            "no developer can be named yet (needs {} or stronger); the provider report can still go to the host",
            c.min_named.max(Evidence::FLOOR).describe()
        ));
    }
    if c.rules_version.is_none() {
        t.push(format!(
            "rules not pinned; pin them so reports stop following rule changes: `swarmchase case rules {} --update`",
            c.id
        ));
    }
    if c.status == CaseStatus::Open && c.sent.is_empty() {
        t.push(format!(
            "draft reports: `swarmchase case report {} --audience provider|affected`",
            c.id
        ));
    }
    t
}

fn report_options(
    c: &Case,
    audience: Audience,
    reporter: Option<String>,
    today: &str,
) -> ReportOptions {
    ReportOptions {
        audience,
        reporter,
        generated: Some(today.to_string()),
        min_named: c.min_named,
        claims: c.claims.clone(),
        exposed_hosts: c
            .endpoints
            .iter()
            .filter(|e| e.state == EndpointState::Compromised)
            .map(|e| e.host.clone())
            .collect(),
        ..Default::default()
    }
}

fn report(
    root: &Path,
    id: &str,
    audience: Audience,
    reporter: Option<String>,
    to: Option<&Contact>,
    today: &str,
) -> Result<String> {
    let c = load(root, id)?;
    let a = analyze(
        case_records(root, &c, &scope(audience, to))?,
        &case_rules(root, &c)?,
    );
    Ok(render_markdown(
        &a,
        &report_options(&c, audience, reporter, today),
    ))
}

/// What the admin reviews in a notice draft.
pub struct NoticeReview {
    pub withheld: Vec<String>,
    pub flags: Vec<String>,
    /// Anything a notice must not carry that got through anyway.
    pub lint: Vec<String>,
    pub unreviewed: Vec<String>,
}

fn notice_draft(
    root: &Path,
    id: &str,
    force: bool,
    today: &str,
) -> Result<(PathBuf, NoticeReview)> {
    let c = load(root, id)?;
    let path = case_dir(root, id)?.join(NOTICE_DRAFT);
    if path.exists() && !force {
        bail!(
            "{} exists and may hold your edits; pass --force to replace it",
            path.display()
        );
    }
    let a = analyze(
        case_records(root, &c, &Scope::Public)?,
        &case_rules(root, &c)?,
    );
    let opts = report_options(&c, Audience::Public, None, today);
    let notice = render_notice(&a, &opts);
    let claims = a.clusters.iter().fold(c.claims.clone(), |acc, cl| {
        sc_core::attribution::merge(acc, &sc_core::attribute(&a, cl))
    });
    let mut providers: Vec<String> = claims
        .iter()
        .filter(|x| x.role == Role::Developer && x.nameable(c.min_named))
        .map(|x| x.party.clone())
        .collect();
    providers.dedup();
    let n = NoticeFile {
        meta: NoticeMeta {
            id: id.to_string(),
            title: c.title.clone(),
            status: c.notice,
            published: today.to_string(),
            updated: today.to_string(),
            providers,
            affected: c
                .endpoints
                .iter()
                .filter(|e| {
                    matches!(
                        e.state,
                        EndpointState::Compromised
                            | EndpointState::Targeted
                            | EndpointState::Historical
                    )
                })
                .map(|e| e.host.clone())
                .collect(),
            rules_version: a.rules_version.clone(),
            toolkit: env!("CARGO_PKG_VERSION").to_string(),
            updates: Vec::new(),
        },
        body: notice.markdown.clone(),
    };
    std::fs::write(&path, write_notice(&n))?;
    let mut withheld = notice.withheld;
    for e in c
        .evidence
        .iter()
        .filter(|e| e.public.is_none() && e.kept > 0)
    {
        withheld.push(format!(
            "operator logs {} from {} (no agreement recorded; `swarmchase case evidence consent {id} {}`)",
            e.id, e.org, e.id
        ));
    }
    let mut lint = leak_check(root, &c, |r| {
        lint_public(&format!("{}\n{}", n.meta.title, n.body), r)
    })?;
    lint.extend(notice.leaks);
    let review = NoticeReview {
        lint,
        withheld,
        flags: notice.flags,
        unreviewed: c
            .endpoints
            .iter()
            .filter(|e| e.state == EndpointState::Unreviewed)
            .map(|e| e.host.clone())
            .collect(),
    };
    update(root, id, |c| {
        c.log(
            today,
            format!(
                "notice drafted ({} withheld, {} to decide)",
                review.withheld.len(),
                review.flags.len()
            ),
        );
        Ok(())
    })?;
    Ok((path, review))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A case root, `<scratch data dir>/cases`; pinned rules go beside it.
    fn scratch(name: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("swarmchase-case-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        p.join("cases")
    }

    fn cleanup(root: &Path) {
        std::fs::remove_dir_all(root.parent().unwrap()).unwrap();
    }

    fn fixture() -> Analysis {
        let mut obs: Vec<Observation> = (0..4)
            .map(|i| Observation {
                id: format!("r{i}"),
                ts: 1_791_000_000 + i * 40,
                url: format!(
                    "https://r.jina.ai/https://portal.example.gov/q?id={i}%20UNION%20SELECT%201&uqtag=zz9&agent=hunyuan"
                ),
                asn: Some(132203),
                ..Default::default()
            })
            .collect();
        // A flagged record on the same host, outside the cluster.
        obs.push(Observation {
            id: "late".into(),
            ts: 1_791_900_000,
            url: "https://portal.example.gov/q?id=1%20UNION%20SELECT%202".into(),
            ..Default::default()
        });
        // Unrelated activity elsewhere.
        obs.push(Observation {
            id: "other".into(),
            ts: 1_791_000_100,
            url: "https://r.jina.ai/https://elsewhere.example/q?id=1%20UNION%20SELECT%201".into(),
            ..Default::default()
        });
        analyze(obs, &sc_core::Rules::default_rules())
    }

    #[test]
    fn ids_are_slugs() {
        assert!(check_id("2026-10-portal-sqli").is_ok());
        for bad in ["", "../x", "A", "-x", "a b", "a/b"] {
            assert!(check_id(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn pick_takes_clusters_and_optionally_every_hit_on_their_hosts() {
        let a = fixture();
        let c = a
            .clusters
            .iter()
            .find(|c| c.target_hosts.contains_key("portal.example.gov"))
            .unwrap();
        let ids = |host_hits| -> BTreeSet<String> {
            pick(&a, std::slice::from_ref(&c.id), &[], host_hits)
                .unwrap()
                .into_iter()
                .map(|o| o.id)
                .collect()
        };
        assert!(!ids(false).contains("late"));
        let ids = ids(true);
        assert!(ids.contains("r0") && ids.contains("late"), "{ids:?}");
        assert!(!ids.contains("other"));
        assert!(pick(&a, &["C99".into()], &[], false).is_err());
    }

    #[test]
    fn case_lifecycle() {
        let root = scratch("life");
        let rules = RulesText::load(None).unwrap();
        let a = fixture();
        let records: Vec<Observation> = a
            .results
            .iter()
            .filter(|r| r.obs.id != "other")
            .map(|r| r.obs.clone())
            .collect();
        new_case(&root, "t-1", "Portal probe", records, &rules, "2026-10-12").unwrap();
        assert!(
            new_case(&root, "t-1", "again", vec![], &rules, "2026-10-12").is_err(),
            "no overwrite"
        );

        let c = load(&root, "t-1").unwrap();
        assert_eq!(c.status, CaseStatus::Open);
        assert_eq!(c.endpoints.len(), 1);
        assert_eq!(c.endpoints[0].host, "portal.example.gov");
        assert_eq!(c.endpoints[0].state, EndpointState::Unreviewed);

        // Adding records dedupes and picks up new hosts.
        let other: Vec<Observation> = a.results.iter().map(|r| r.obs.clone()).collect();
        assert_eq!(
            add_records(&root, "t-1", other, "2026-10-13").unwrap(),
            (1, 1)
        );
        assert_eq!(load_records(&root, "t-1").unwrap().len(), 6);

        // Self-identification plus a same-company network is not enough to
        // name a developer at the default threshold; a case claim is.
        let mut buf = Vec::new();
        status(&root, "t-1", &mut buf).unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("Tencent (Developer)"), "{s}");
        assert!(s.contains("no developer can be named yet"), "{s}");
        assert!(s.contains("classify 2 endpoint(s)"), "{s}");

        update(&root, "t-1", |c| {
            c.claims.push(Claim {
                party: "Tencent".into(),
                role: Role::Developer,
                evidence: Evidence::SharedIdentifiers,
                details: vec!["uqtag zz9 also in a confirmed incident".into()],
            });
            c.endpoints[0].state = EndpointState::Targeted;
            Ok(())
        })
        .unwrap();
        let md = report(&root, "t-1", Audience::Provider, None, None, "2026-10-14").unwrap();
        assert!(md.contains("**Tencent** (developer)"), "{md}");

        // Drafts go only to listed contacts, and never as case notes.
        assert!(draft(&root, "t-1", Audience::Affected, "x@y.example", None, "d").is_err());
        update(&root, "t-1", |c| {
            c.contacts.push(Contact {
                org: "portal.example.gov".into(),
                role: "affected".into(),
                endpoint: Some("portal.example.gov".into()),
                channel: "email".into(),
                address: "security@portal.example.gov".into(),
                source: "https://portal.example.gov/.well-known/security.txt".into(),
                confidence: "medium".into(),
                found_on: "2026-10-14".into(),
            });
            Ok(())
        })
        .unwrap();
        assert!(
            draft(
                &root,
                "t-1",
                Audience::Internal,
                "security@portal.example.gov",
                None,
                "d"
            )
            .is_err()
        );
        let p = draft(
            &root,
            "t-1",
            Audience::Affected,
            "SECURITY@portal.example.gov",
            None,
            "2026-10-14",
        )
        .unwrap();
        let eml = std::fs::read_to_string(&p).unwrap();
        assert!(eml.contains("To: security@portal.example.gov\r\n"));
        assert!(eml.contains("filename=\"MANIFEST.sha256\""));
        let bundle = root.join("t-1").join("bundles").join("2026-10-14");
        assert!(
            crate::bundle::verify(&bundle, &rules.rules)
                .unwrap()
                .is_empty()
        );
        let c = load(&root, "t-1").unwrap();
        assert_eq!(c.decisions.len(), 2);
        assert!(toml::to_string_pretty(&c).unwrap().contains("[[claim]]"));
        assert!(
            draft(
                &root,
                "t-1",
                Audience::Public,
                "security@portal.example.gov",
                None,
                "d"
            )
            .is_err(),
            "notices are published, not sent"
        );

        // The notice: drafted in the case, blocked while an endpoint is
        // unreviewed, then added to notices/ without its draft banner.
        let (p, review) = notice_draft(&root, "t-1", false, "2026-10-15").unwrap();
        assert!(review.lint.is_empty(), "{:?}", review.lint);
        assert_eq!(review.unreviewed, vec!["elsewhere.example".to_string()]);
        assert!(
            notice_draft(&root, "t-1", false, "2026-10-15").is_err(),
            "keeps edits"
        );
        let md = std::fs::read_to_string(&p).unwrap();
        assert!(md.contains("providers = [\"Tencent\"]"), "{md}");
        assert!(md.contains("affected = [\"portal.example.gov\"]"), "{md}");
        let notices = root.join("notices");
        let rules = sc_core::Rules::default_rules();
        assert!(crate::notice::add_for_test(&root, "t-1", &notices, &rules, "2026-10-16").is_err());
        update(&root, "t-1", |c| {
            c.endpoints[1].state = EndpointState::NotAffected;
            Ok(())
        })
        .unwrap();
        let added =
            crate::notice::add_for_test(&root, "t-1", &notices, &rules, "2026-10-16").unwrap();
        let text = std::fs::read_to_string(&added).unwrap();
        assert!(!text.contains("DRAFT"), "{text}");
        assert!(text.contains("kind = \"published\""), "{text}");
        assert_eq!(load(&root, "t-1").unwrap().status, CaseStatus::Published);
        assert!(crate::notice::add_for_test(&root, "t-1", &notices, &rules, "2026-10-16").is_err());
        cleanup(&root);
    }

    #[test]
    fn leak_check_uses_the_pinned_rules_and_the_current_ones() {
        let root = scratch("leak");
        let current = RulesText::load(None).unwrap();
        let records: Vec<Observation> = fixture().results.iter().map(|r| r.obs.clone()).collect();
        new_case(&root, "t-4", "Leak", records, &current, "2026-10-12").unwrap();
        // A pinned rule set with a callback channel the current rules lack.
        let text = format!(
            "{}\n[[rule]]\nid = \"exfil.test_inbox\"\nkind = \"exfil\"\ntarget = \"url\"\npattern = \"zzinbox[0-9]+\"\nweight = 3\nlink = true\n",
            current.text.replace(current.version(), "pinned-test")
        );
        let pinned = RulesText {
            rules: sc_core::Rules::from_toml(&text).unwrap(),
            text,
        };
        let pin = pin_rules(&root, &pinned).unwrap();
        update(&root, "t-4", |c| {
            c.rules_version = Some(pin.clone());
            Ok(())
        })
        .unwrap();
        let c = load(&root, "t-4").unwrap();
        let body = "see zzinbox42 and https://webhook.site/0b6c1f0e-1111-4c2a-9a55-3f2e1d0c9b8a";
        let lint = leak_check(&root, &c, |r| lint_public(body, r)).unwrap();
        assert!(lint.iter().any(|l| l.contains("zzinbox42")), "{lint:?}");
        assert_eq!(
            lint.iter().filter(|l| l.contains("webhook.site")).count(),
            1,
            "{lint:?}"
        );
        cleanup(&root);
    }

    #[test]
    fn rules_are_pinned_and_repinned() {
        let root = scratch("rules");
        let current = RulesText::load(None).unwrap();
        let v = current.version().to_string();
        let records: Vec<Observation> = fixture().results.iter().map(|r| r.obs.clone()).collect();
        new_case(
            &root,
            "t-3",
            "Portal probe",
            records,
            &current,
            "2026-10-12",
        )
        .unwrap();
        let c = load(&root, "t-3").unwrap();
        assert_eq!(c.rules_version.as_deref(), Some(v.as_str()));
        let rules_dir = root.parent().unwrap().join("rules");
        assert_eq!(
            std::fs::read_to_string(rules_dir.join(format!("{v}.toml"))).unwrap(),
            current.text
        );
        assert!(c.decisions[0].text.contains(&format!("rules {v}")));

        // An edited rule set that kept its version gets its own name.
        let text = current
            .text
            .replace("suggestive = 3", "suggestive = 300")
            .replace("significant = 6", "significant = 600")
            .replace("significant = true", "significant = false");
        let strict = RulesText {
            rules: sc_core::Rules::from_toml(&text).unwrap(),
            text,
        };
        let pin = pin_rules(&root, &strict).unwrap();
        assert!(
            pin.starts_with(&format!("{v}-")) && pin.len() == v.len() + 13,
            "{pin}"
        );
        assert_eq!(pin_rules(&root, &strict).unwrap(), pin, "stable");
        assert_eq!(pin_rules(&root, &current).unwrap(), v);

        // Showing does not re-pin; updating does, and logs the tier changes.
        let changes = tier_changes(&root, &c, &strict.rules).unwrap();
        assert!(!changes.is_empty());
        let mut out = Vec::new();
        rules_cmd(&root, "t-3", &strict, false, "2026-10-13", &mut out).unwrap();
        let s = String::from_utf8(out).unwrap();
        assert!(
            s.contains(&format!("{} record(s) change tier", changes.len())),
            "{s}"
        );
        assert_eq!(
            load(&root, "t-3").unwrap().rules_version.as_deref(),
            Some(v.as_str())
        );
        rules_cmd(&root, "t-3", &strict, true, "2026-10-13", &mut Vec::new()).unwrap();
        let c = load(&root, "t-3").unwrap();
        assert_eq!(c.rules_version.as_deref(), Some(pin.as_str()));
        let last = &c.decisions.last().unwrap().text;
        assert!(
            last.contains(&format!("rules re-pinned: {v} → {pin}")),
            "{last}"
        );
        assert!(last.contains("changed tier"), "{last}");
        assert_eq!(
            case_rules(&root, &c).unwrap().set.thresholds.suggestive,
            300
        );
        assert!(
            tier_changes(&root, &c, &strict.rules).unwrap().is_empty(),
            "renders with the pinned rules"
        );

        // A case file from before pinning renders with the current rules and
        // says so; re-pinning it works too.
        update(&root, "t-3", |c| {
            c.rules_version = None;
            Ok(())
        })
        .unwrap();
        let toml = std::fs::read_to_string(root.join("t-3").join("case.toml")).unwrap();
        assert!(!toml.contains("rules_version"), "{toml}");
        let mut buf = Vec::new();
        status(&root, "t-3", &mut buf).unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("rules not pinned"), "{s}");
        rules_cmd(&root, "t-3", &current, true, "2026-10-14", &mut Vec::new()).unwrap();
        let c = load(&root, "t-3").unwrap();
        assert_eq!(c.rules_version.as_deref(), Some(v.as_str()));
        assert!(
            c.decisions
                .last()
                .unwrap()
                .text
                .contains(&format!("not pinned → {v}; no record changed tier"))
        );

        // A pin is a name in the rules directory, never a path.
        let mut bad = c.clone();
        bad.rules_version = Some("../../etc/x".into());
        assert!(case_rules(&root, &bad).is_err());
        cleanup(&root);
    }

    #[test]
    fn operator_evidence_stays_private_until_agreed() {
        let root = scratch("evidence");
        let rules = RulesText::load(None).unwrap();
        let records: Vec<Observation> = fixture()
            .results
            .iter()
            .filter(|r| r.obs.id != "other")
            .map(|r| r.obs.clone())
            .collect();
        new_case(&root, "t-2", "Portal probe", records, &rules, "2026-10-12").unwrap();
        let log = [
            r#"203.0.113.9 - - [20/Oct/2026:12:00:00 +0000] "GET /q?id=9%20UNION%20SELECT%201&uqtag=zz9 HTTP/1.1" 200 10 "-" "python-httpx/0.27""#,
            r#"198.51.100.7 - - [20/Oct/2026:12:00:20 +0000] "GET /about HTTP/1.1" 200 10 "-" "Mozilla/5.0""#,
        ]
        .join("\n");
        let map = sc_core::FieldMap {
            host: Some("portal.example.gov".into()),
            ..Default::default()
        };
        let add = |d: &str| {
            add_evidence(
                &root,
                "t-2",
                &log,
                sc_core::Format::Auto,
                &map,
                "Portal",
                "portal.example.gov",
                None,
                None,
                d,
            )
        };
        let e = add("2026-10-20").unwrap();
        assert_eq!((e.id.as_str(), e.lines, e.kept), ("e1", 2, 1));
        assert!(add("2026-10-20").is_err(), "same file twice");

        let marker = "provided by the affected operator";
        let provider = report(&root, "t-2", Audience::Provider, None, None, "d").unwrap();
        assert!(provider.contains(marker), "{provider}");
        let other = Contact {
            org: "Elsewhere".into(),
            role: "affected".into(),
            endpoint: Some("elsewhere.example".into()),
            channel: "email".into(),
            address: "security@elsewhere.example".into(),
            source: String::new(),
            confidence: "low".into(),
            found_on: "d".into(),
        };
        let md = report(&root, "t-2", Audience::Affected, None, Some(&other), "d").unwrap();
        assert!(!md.contains(marker), "another operator's logs: {md}");

        let (p, review) = notice_draft(&root, "t-2", false, "2026-10-21").unwrap();
        assert!(!std::fs::read_to_string(&p).unwrap().contains(marker));
        assert!(
            review
                .withheld
                .iter()
                .any(|w| w.contains("operator logs e1")),
            "{:?}",
            review.withheld
        );

        update(&root, "t-2", |c| {
            find_evidence(c, "e1")?.public = Some("2026-10-22: reply".into());
            Ok(())
        })
        .unwrap();
        let (p, review) = notice_draft(&root, "t-2", true, "2026-10-22").unwrap();
        assert!(std::fs::read_to_string(&p).unwrap().contains(marker));
        assert!(review.lint.is_empty(), "{:?}", review.lint);
        cleanup(&root);
    }
}
