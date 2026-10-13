//! A case's contacts: `contacts` finds them, `contact add|rm` changes one by
//! hand.

use super::Ctx;
use crate::case::{ContactRole, Scope, analysis, load, update};
use anyhow::Result;
use clap::{Args, Subcommand};
use sc_case::actions::{self, ContactInput};
use std::io::Write;

#[derive(Args)]
pub struct ContactsArgs {
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
}

#[derive(Subcommand)]
pub enum ContactCmd {
    /// Add a contact found by hand (a provider's abuse form, a CSIRT, a
    /// declared owner). Every contact needs the link it was found at.
    Add {
        id: String,
        /// provider | operator | csirt | declared-owner
        #[arg(long)]
        party: ContactRole,
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

pub(super) fn find(ctx: &Ctx, a: ContactsArgs, out: &mut impl Write) -> Result<()> {
    let c = load(&ctx.root, &a.id)?;
    let claims = sc_case::report::all_claims(&c, &analysis(&ctx.root, &c, &Scope::All)?);
    // Relay, carrier and callback hosts by the case's pinned rules and the
    // current ones, and every host such a rule matched in the case's records
    // (an inbox id a URL pattern needs): none of them is ever read.
    let rules = [
        crate::case::Pinned::new(&ctx.root, &c)?.rules,
        sc_core::Rules::default_rules(),
    ];
    let callbacks: std::collections::BTreeSet<String> =
        crate::case::case_records(&ctx.root, &c, &Scope::All)?
            .iter()
            .flat_map(|o| rules.iter().flat_map(|r| sc_core::intermediary_hosts(o, r)))
            .collect();
    let dir = sc_case::providers::Directory::builtin();
    let csirts = crate::csirts::Csirts::builtin();
    let today = ctx.today.as_str();
    update(&ctx.root, &a.id, |c| {
        let n = crate::contacts::seed_providers(c, &claims, &dir, today, out)?;
        if n == 0 {
            println!("provider directory: nothing new for this case's claims");
        }
        if a.providers_only {
            return Ok(());
        }
        let n = crate::csirts::seed_csirts(c, &csirts, a.country.as_deref(), today, out)?;
        if n > 0 {
            println!(
                "{n} national CSIRT(s) proposed; remove any not relevant with `case contact rm`"
            );
        }
        let client = sc_collect::Client::new(std::time::Duration::from_millis(500))?;
        let off = |h: &str| {
            let h = h.to_ascii_lowercase();
            rules.iter().any(|r| sc_core::is_intermediary_host(r, &h)) || callbacks.contains(&h)
        };
        crate::contacts::find_contacts(c, &client, &off, a.refresh, today, out)
    })
}

pub(super) fn contact(ctx: &Ctx, cmd: ContactCmd) -> Result<()> {
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
        } => update(&ctx.root, &id, |c| {
            let x = ContactInput {
                role: party,
                org,
                channel,
                address,
                source,
                confidence,
                endpoint,
            };
            Ok(actions::add_contact(c, x, &ctx.today)?)
        }),
        ContactCmd::Rm { id, address } => update(&ctx.root, &id, |c| {
            Ok(actions::remove_contact(c, &address, &ctx.today)?)
        }),
    }
}
