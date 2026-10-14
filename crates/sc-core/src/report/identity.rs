//! The declared-identity block ([`crate::identity`]): one line per cluster
//! whose members declare an agent product or sign their requests, in case
//! notes and provider reports. Case notes add the claims a verified identity
//! supports, as commands for the admin, and the declared-then-undeclared
//! hint ([`crate::identity::fallback`]); nothing is claimed automatically.
//! Reports to affected operators and public notices carry none of it.

use super::{Audience, ReportOptions};
use crate::analyze::Cluster;
use crate::extract::defang;
use crate::identity::{Access, IdentityClass};
use std::fmt::Write;

pub(super) fn section(s: &mut String, clusters: &[&Cluster], opts: &ReportOptions) {
    let internal = opts.audience == Audience::Internal;
    if !(internal || opts.audience == Audience::Provider) {
        return;
    }
    // The fallback hint is for case notes only.
    let shown =
        |c: &Cluster| !c.identity.lines.is_empty() || (internal && c.identity.fallback.is_some());
    let with: Vec<&&Cluster> = clusters.iter().filter(|c| shown(c)).collect();
    if with.is_empty() {
        return;
    }
    let _ = writeln!(s, "## Declared agent identity\n");
    let _ = writeln!(
        s,
        "Requests that name an agent product or carry a Web Bot Auth signature, checked against the address ranges and signing keys the provider publishes. A verified identity shows the request came from the provider's systems, not who directed the agent; a user agent alone is self-identification.\n"
    );
    for c in with {
        let id = &c.identity;
        if id.lines.is_empty() {
            let _ = writeln!(s, "- **{}**: no verified or claimed identity", c.id);
        } else {
            let _ = writeln!(s, "- **{}**: {}", c.id, id.summary());
        }
        for l in id.lines.iter().filter(|l| {
            matches!(
                l.class,
                IdentityClass::Spoofed
                    | IdentityClass::SignatureFailed
                    | IdentityClass::IpVerified
                    | IdentityClass::InRange
            ) && !l.detail.is_empty()
        }) {
            let _ = writeln!(s, "  - {}: {}", l.class.label(), defang(&l.detail));
        }
        for l in id
            .lines
            .iter()
            .filter(|l| l.access == Some(Access::Intermediary))
        {
            let who = l.agent.as_deref().or(l.provider.as_deref()).unwrap_or("?");
            let mut line = format!("  - {}: {}", defang(who), Access::Intermediary.meaning());
            if l.end_users > 0 {
                let _ = write!(
                    line,
                    "; {} distinct end user(s) by their `Forwarded` header, a key to group requests by, not attribution",
                    l.end_users
                );
            }
            let _ = writeln!(s, "{line}");
        }
        if !id.held.is_empty() {
            let _ = writeln!(s, "  - checked against: {}", id.held.join(", "));
        }
        if internal {
            if let Some(f) = &id.fallback {
                let _ = writeln!(s, "  - declared, then undeclared: {}", f.detail());
            }
            for claim in id.suggested_claims() {
                let _ = writeln!(
                    s,
                    "  - suggested claim (not recorded): `swarmchase case claim <case> --party \"{}\" --layer developer --evidence {} --detail \"{}\"`",
                    claim.party,
                    claim.evidence.id(),
                    defang(&claim.details.join("; ")).replace('"', "'")
                );
            }
        }
    }
    let _ = writeln!(s);
}
