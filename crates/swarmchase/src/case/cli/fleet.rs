//! `case fleet`: merge, split, show, and the interaction evidence that
//! makes a fleet a swarm ([`sc_case::fleet`]).

use super::Ctx;
use crate::case::{Scope, analysis, load, update};
use anyhow::Result;
use clap::Subcommand;
use sc_case::fleet;
use std::io::Write;

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
        /// disjoint_partition | dispatch_star (or S1..S6).
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

/// Print the decision the last change logged.
fn logged(c: &sc_case::Case) {
    println!("{}", c.decisions.last().map_or("", |d| d.text.as_str()));
}

pub(super) fn run(ctx: &Ctx, cmd: FleetCmd, out: &mut impl Write) -> Result<()> {
    let (root, today) = (ctx.root.as_path(), ctx.today.as_str());
    let analysed =
        |id: &str| -> Result<sc_core::Analysis> { analysis(root, &load(root, id)?, &Scope::All) };
    match cmd {
        FleetCmd::Merge { id, clusters, why } => {
            let a = analysed(&id)?;
            update(root, &id, |c| {
                let f = fleet::merge(c, &a, &clusters, why.as_deref(), today)?;
                logged(c);
                println!("merged into {f}");
                Ok(())
            })
        }
        FleetCmd::Split { id, cluster, why } => {
            let a = analysed(&id)?;
            update(root, &id, |c| {
                fleet::split(c, &a, &cluster, why.as_deref(), today)?;
                logged(c);
                Ok(())
            })
        }
        FleetCmd::Show { id } => {
            let c = load(root, &id)?;
            Ok(fleet::show(&c, &analysis(root, &c, &Scope::All)?, out)?)
        }
        FleetCmd::Interaction {
            id,
            fleet: f,
            kind,
            runs,
            note,
        } => {
            let a = analysed(&id)?;
            update(root, &id, |c| {
                fleet::interaction(c, &a, &f, kind, &runs, &note, today)?;
                logged(c);
                Ok(())
            })
        }
        FleetCmd::Withdraw {
            id,
            fleet: f,
            n,
            why,
        } => update(root, &id, |c| {
            fleet::withdraw(c, &f, n, why.as_deref(), today)?;
            logged(c);
            Ok(())
        }),
    }
}
