//! What the admin decides about the case's endpoints and its alternatives:
//! `endpoint`, `no-contact`, `alternative`, `plant-review`.

use super::Ctx;
use crate::case::{AlternativeKind, EndpointState, Scope, analysis, load, update};
use anyhow::Result;
use clap::Args;
use sc_case::{actions, fleet};

#[derive(Args)]
pub struct EndpointArgs {
    id: String,
    #[arg(required = true, num_args = 1..)]
    hosts: Vec<String>,
    /// compromised | targeted | historical | not-affected | unreviewed
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
}

#[derive(Args)]
pub struct NoContactArgs {
    id: String,
    party: String,
    /// What was tried (security.txt, RDAP, the provider directory, …).
    #[arg(long)]
    searched: String,
}

#[derive(Args)]
pub struct AlternativeArgs {
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
}

#[derive(Args)]
pub struct PlantReviewArgs {
    id: String,
    /// The cluster, by C-number or stable key.
    cluster: String,
    /// What you checked and why the cluster stands.
    #[arg(long)]
    note: String,
}

pub(super) fn endpoint(ctx: &Ctx, a: EndpointArgs) -> Result<()> {
    update(&ctx.root, &a.id, |c| {
        Ok(actions::classify(
            c,
            &a.hosts,
            a.state,
            a.note.as_deref(),
            a.basis.as_deref(),
            a.single_source_reason.as_deref(),
            &ctx.today,
        )?)
    })
}

pub(super) fn no_contact(ctx: &Ctx, a: NoContactArgs) -> Result<()> {
    update(&ctx.root, &a.id, |c| {
        actions::no_contact(c, &a.party, &a.searched, ctx.now)?;
        println!("{}", c.decisions.last().map_or("", |d| d.text.as_str()));
        Ok(())
    })
}

pub(super) fn alternative(ctx: &Ctx, a: AlternativeArgs) -> Result<()> {
    let Some(k) = a.kind else {
        let c = load(&ctx.root, &a.id)?;
        for k in AlternativeKind::ALL {
            match c.alternatives.iter().rev().find(|x| x.kind == k) {
                Some(x) => println!("{:<18} {} {}: {}", k.id(), x.verdict, x.date, x.why),
                None => println!("{:<18} not decided", k.id()),
            }
        }
        return Ok(());
    };
    update(&ctx.root, &a.id, |c| {
        Ok(actions::alternative(
            c,
            k,
            a.rejected.as_deref(),
            a.accepted.as_deref(),
            &ctx.today,
        )?)
    })
}

pub(super) fn plant_review(ctx: &Ctx, a: PlantReviewArgs) -> Result<()> {
    let c = load(&ctx.root, &a.id)?;
    let an = analysis(&ctx.root, &c, &Scope::All)?;
    let key = fleet::resolve(&an, &a.cluster)?;
    let n = fleet::by_key(&an, &key).map_or(0, sc_case::checklist::plant_signals);
    update(&ctx.root, &a.id, |c| {
        Ok(actions::plant_review(c, &key, n, &a.note, &ctx.today)?)
    })
}
