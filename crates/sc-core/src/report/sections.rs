//! Report sections that read more than the selected clusters: who is
//! behind them, and every flagged hit on the hosts they touched.

use super::{Audience, ReportOptions};
use crate::analyze::Analysis;
use crate::attribution::{Claim, Evidence, Role};
use crate::endpoints::{EndpointOptions, EndpointView, endpoints};
use crate::model::fmt_ts;
use crate::notice::PublicView;
use std::collections::BTreeMap;
use std::fmt::Write;

/// Who is behind the clusters, each claim with the evidence it rests on.
/// Case notes show every claim; other audiences see a developer named only
/// at or above `opts.min_named`.
pub(super) fn attribution_section(s: &mut String, claims: &[Claim], opts: &ReportOptions) {
    if claims.is_empty() {
        return;
    }
    let min = opts.min_named.max(Evidence::FLOOR);
    let internal = opts.audience == Audience::Internal;
    let _ = writeln!(s, "## Attribution\n");
    let _ = writeln!(
        s,
        "Each claim names the strongest evidence it rests on. A developer is named only on evidence at least as strong as: {}.\n",
        min.describe()
    );
    let mut withheld = 0;
    for c in claims {
        let detail = c.details.join("; ");
        match c.role {
            Role::Developer if c.nameable(min) => {
                let _ = writeln!(
                    s,
                    "- **{}** (developer). Evidence: {}. {detail}.",
                    c.party,
                    c.evidence.describe()
                );
            }
            Role::Developer if internal => {
                let _ = writeln!(
                    s,
                    "- {} (developer, **not named outside case notes**). Evidence: {}. {detail}.",
                    c.party,
                    c.evidence.describe()
                );
            }
            Role::Developer => withheld += 1,
            Role::Host => {
                let _ = writeln!(
                    s,
                    "- **{}** (hosting network). {detail}. A host is not necessarily the developer.",
                    c.party
                );
            }
        }
    }
    if withheld > 0 {
        let _ = writeln!(
            s,
            "- Some requests name a model or vendor. That is not attribution: agents misreport who built them, and anyone can submit such a string to a public scanner."
        );
    }
    let _ = writeln!(s);
}

/// Every flagged hit on the hosts these clusters touched, including hits
/// outside the clusters: an operator checks its logs per host, not per cluster.
pub(super) fn endpoint_table(
    s: &mut String,
    a: &Analysis,
    hosts: &BTreeMap<String, usize>,
    mut view: Option<&mut PublicView>,
) {
    let views: Vec<EndpointView> = endpoints(a, &EndpointOptions::default())
        .into_iter()
        .filter(|v| hosts.contains_key(&v.host))
        .collect();
    if views.is_empty() {
        return;
    }
    let _ = writeln!(s, "## Endpoints\n");
    let _ = writeln!(
        s,
        "Every flagged request to each host, including requests outside the linked clusters. \"Ongoing\" means hit within 7 days of the newest record reviewed.\n"
    );
    let _ = writeln!(
        s,
        "| Host | Hits | First seen | Last seen | Status | Attack payloads |\n|---|---|---|---|---|---|"
    );
    for v in &views {
        let exposed = view.as_deref().is_some_and(|p| p.exposed(&v.host));
        if exposed && let Some(p) = view.as_deref_mut() {
            p.note_exposed(&v.host);
        }
        let payloads = if exposed {
            "withheld (endpoint compromised)".into()
        } else if v.payloads {
            v.payload_rules
                .keys()
                .map(|r| format!("`{r}`"))
                .collect::<Vec<_>>()
                .join(", ")
        } else {
            "none seen".into()
        };
        let _ = writeln!(
            s,
            "| `{}` | {} | {} | {} | {} | {payloads} |",
            v.host.replace('.', "[.]"),
            v.hits,
            fmt_ts(v.first_seen),
            fmt_ts(v.last_seen),
            v.activity.label()
        );
    }
    let _ = writeln!(s);
}
