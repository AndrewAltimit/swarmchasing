//! Report sections that read more than the selected clusters: who is
//! behind them, and every flagged hit on the hosts they touched.

use super::{Audience, ReportOptions};
use crate::analyze::Analysis;
use crate::attribution::{Claim, Evidence, Role, Tag};
use crate::endpoints::{EndpointOptions, EndpointView, endpoints};
use crate::extract::defang_host;
use crate::model::fmt_ts;
use crate::notice::PublicView;
use std::collections::BTreeMap;
use std::fmt::Write;

/// Who is behind the clusters, layer by layer, each claim with its label,
/// tag and the evidence it rests on. Case notes show every claim; other
/// audiences see a developer named only at or above `opts.min_named`. Harness
/// and model-family candidates are listed as ranked candidates in private
/// reports and never in public.
pub(super) fn attribution_section(s: &mut String, claims: &[Claim], opts: &ReportOptions) {
    if claims.is_empty() {
        return;
    }
    let min = opts.min_named.max(Evidence::FLOOR);
    let internal = opts.audience == Audience::Internal;
    let public = opts.audience == Audience::Public;
    let _ = writeln!(s, "## Attribution\n");
    let _ = writeln!(
        s,
        "Each claim gives its layer, label (Confirmed, Suspected, Possible, Unattributed), tag (Observed, Documented, Inference, Conclusion) and the strongest evidence it rests on. A developer is named only on evidence at least as strong as: {}. Harness and model-family candidates are never named in public.\n",
        min.describe()
    );
    let tags = |c: &Claim| format!("Label: {}; tag: {}", c.label().label(), c.tag().label());
    let mut withheld = 0;
    let mut candidates = 0;
    for c in claims {
        let detail = c.details.join("; ");
        match c.role {
            Role::Developer if c.nameable(min) => {
                let _ = writeln!(
                    s,
                    "- **{}** (developer). Evidence: {}. {detail}. {}.",
                    c.party,
                    c.evidence.describe(),
                    tags(c)
                );
            }
            Role::Developer if internal => {
                let _ = writeln!(
                    s,
                    "- {} (developer, **not named outside case notes**). Evidence: {}. {detail}. {}.",
                    c.party,
                    c.evidence.describe(),
                    tags(c)
                );
            }
            Role::Developer => withheld += 1,
            Role::Host => {
                let _ = writeln!(
                    s,
                    "- **{}** (hosting network). {detail}. {}. A host is not necessarily the developer.",
                    c.party,
                    tags(c)
                );
            }
            Role::Harness | Role::ModelFamily => candidates += 1,
        }
    }
    if withheld > 0 {
        let _ = writeln!(
            s,
            "- Some requests name a model or vendor. That is not attribution: agents misreport who built them, and anyone can submit such a string to a public scanner."
        );
    }
    let _ = writeln!(s);
    if candidates > 0 && !public {
        candidate_lists(s, claims);
    }
    let concluded: Vec<&Claim> = claims
        .iter()
        .filter(|c| c.role == Role::Developer && c.nameable(min))
        .filter(|c| c.label().word().is_some())
        .collect();
    if !concluded.is_empty() {
        let _ = writeln!(s, "**Conclusion.**");
        for c in concluded {
            let _ = writeln!(
                s,
                "- {}: {} operated by **{}** ({}). Tag: {}.",
                c.label().label(),
                c.label().word().unwrap_or_default(),
                c.party,
                c.evidence.describe(),
                Tag::Conclusion.label()
            );
        }
        let _ = writeln!(s);
    }
}

/// Harness candidates by records, model families by likelihood: ranked,
/// never named.
fn candidate_lists(s: &mut String, claims: &[Claim]) {
    for role in [Role::Harness, Role::ModelFamily] {
        let list: Vec<&Claim> = claims.iter().filter(|c| c.role == role).collect();
        if list.is_empty() {
            continue;
        }
        let _ = writeln!(
            s,
            "**{} candidates** (ranked; never named as the source in public):\n",
            role.heading()
        );
        for (i, c) in list.iter().enumerate() {
            let measure = match role {
                Role::ModelFamily if c.measured() => format!(
                    " Likelihood {}; method accuracy {:.0}% on a held-out set, corpus of {}.",
                    c.likelihood
                        .map_or("not given".to_string(), |l| format!("{:.0}%", l * 100.0)),
                    c.accuracy.unwrap_or(0.0) * 100.0,
                    c.corpus_size.unwrap_or(0)
                ),
                Role::ModelFamily => {
                    " Not used: no held-out measurement of the method.".to_string()
                }
                _ => String::new(),
            };
            let _ = writeln!(
                s,
                "{}. {} — Label: {}; tag: {}.{measure} Traces: {}.",
                i + 1,
                c.party,
                c.label().label(),
                c.tag().label(),
                c.details.join("; ")
            );
        }
        let _ = writeln!(s);
    }
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
            defang_host(&v.host),
            v.hits,
            fmt_ts(v.first_seen),
            fmt_ts(v.last_seen),
            v.activity.label()
        );
    }
    let _ = writeln!(s);
}
