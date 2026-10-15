//! Report sections that read more than the selected clusters: who is
//! behind them, and every flagged hit on the hosts they touched.

use super::{Audience, ReportOptions};
use crate::analyze::Analysis;
use crate::attribution::{Claim, Evidence, Role, Tag};
use crate::endpoints::{Activity, EndpointOptions, EndpointView, endpoints};
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
///
/// `tor` counts the records sent through Tor exit relays. They are in no
/// claim; private reports say so in a caution, and a public notice leaves
/// them out of its attribution altogether.
pub(super) fn attribution_section(
    s: &mut String,
    claims: &[Claim],
    tor: usize,
    opts: &ReportOptions,
    one: bool,
) {
    let public = opts.audience == Audience::Public;
    let caution = tor > 0 && !public;
    if claims.is_empty() && !caution {
        return;
    }
    let min = opts.min_named.max(Evidence::FLOOR);
    let internal = opts.audience == Audience::Internal;
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
            // In public, a provider below shared identifiers is the party
            // that was notified, never the one that did it.
            Role::Developer if public && c.evidence < Evidence::SharedIdentifiers => {
                instrument(s, c, opts, one)
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
    if caution {
        let _ = writeln!(s, "**Caution.** {}\n", crate::attribution::tor_caution(tor));
    }
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
            let word = c.label().word().unwrap_or_default();
            // Infrastructure shows whose systems sent the requests, not who
            // deployed the agents on them.
            let what = if c.evidence == Evidence::ProviderInfrastructure {
                format!(
                    "the requests {word} came from infrastructure that **{}** operates; who deployed the agents is a separate question",
                    c.party
                )
            } else {
                format!("{word} operated by **{}**", c.party)
            };
            let _ = writeln!(
                s,
                "- {}: {what} ({}). Tag: {}.",
                c.label().label(),
                c.evidence.describe(),
                Tag::Conclusion.label()
            );
        }
        let _ = writeln!(s);
    }
}

/// A public notice's line for a provider the requests name below shared
/// identifiers: what the requests say, how weak that is, and that the
/// provider was sent the evidence.
fn instrument(s: &mut String, c: &Claim, opts: &ReportOptions, one: bool) {
    let models: Vec<String> = c
        .details
        .iter()
        .filter_map(|d| d.split_once(" name `")?.1.split('`').next())
        .map(|m| format!("`{m}`"))
        .collect();
    let p = &c.party;
    let _ = write!(
        s,
        "- Requests in {} identify themselves as using {} from {p}. Self-identification is the weakest evidence we use. We have not confirmed that {p} operated, deployed or authorised them.",
        if one {
            "this cluster"
        } else {
            "these clusters"
        },
        if models.is_empty() {
            "a model".into()
        } else {
            models.join(", ")
        }
    );
    if opts.reported.is_some_and(|r| r.provider) {
        let _ = write!(s, " {p} has been sent the full evidence.");
    }
    let _ = writeln!(
        s,
        " Layer: developer. Label: {}; tag: {}.",
        c.label().label(),
        c.tag().label()
    );
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
                "{}. {}. Label: {}; tag: {}.{measure} Traces: {}.",
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
/// `unnamed` hosts (not classified as affected) are counted, not listed.
/// With `described` (the indicator notice), each host appears by its
/// description, never by name.
pub(super) fn endpoint_table(
    s: &mut String,
    a: &Analysis,
    hosts: &BTreeMap<String, usize>,
    unnamed: usize,
    described: Option<&BTreeMap<String, String>>,
    mut view: Option<&mut PublicView>,
) {
    let label = |h: &str| match described {
        Some(d) => d
            .get(&h.to_ascii_lowercase())
            .cloned()
            .unwrap_or_else(|| "an affected organisation".into()),
        None => format!("`{}`", defang_host(h)),
    };
    let mut views: Vec<EndpointView> = endpoints(a, &EndpointOptions::default())
        .into_iter()
        .filter(|v| hosts.contains_key(&v.host))
        .collect();
    if described.is_some() {
        // Ordered by description, so the order says nothing about the names.
        views.sort_by_cached_key(|v| (label(&v.host), v.first_seen, v.hits));
    }
    if views.is_empty() && unnamed == 0 {
        return;
    }
    let _ = writeln!(s, "## Endpoints\n");
    let _ = writeln!(
        s,
        "Every flagged request to each host, including requests outside the linked clusters. \"Ongoing\" means hit within 7 days of the newest record reviewed.\n"
    );
    if !views.is_empty() {
        let _ = writeln!(
            s,
            "| {} | Hits | First seen | Last seen | Status | Attack payloads |\n|---|---|---|---|---|---|",
            if described.is_some() {
                "Target"
            } else {
                "Host"
            }
        );
    }
    // Described hosts sharing a description are one row with a host count:
    // identical rows would only repeat the class. Named hosts keep a row each.
    let mut i = 0;
    while i < views.len() {
        let mut j = i + 1;
        if described.is_some() {
            while j < views.len() && label(&views[j].host) == label(&views[i].host) {
                j += 1;
            }
        }
        let group = &views[i..j];
        let mut exposed = false;
        for v in group {
            if view.as_deref().is_some_and(|p| p.exposed(&v.host)) {
                exposed = true;
                if let Some(p) = view.as_deref_mut() {
                    p.note_exposed(&v.host);
                }
            }
        }
        let rules: std::collections::BTreeSet<&str> = group
            .iter()
            .flat_map(|v| v.payload_rules.keys().map(String::as_str))
            .collect();
        let payloads = if exposed {
            "withheld (endpoint compromised)".into()
        } else if group.iter().any(|v| v.payloads) {
            rules
                .iter()
                .map(|r| format!("`{r}`"))
                .collect::<Vec<_>>()
                .join(", ")
        } else {
            "none seen".into()
        };
        let activity = group
            .iter()
            .map(|v| v.activity)
            .min_by_key(|a| match a {
                Activity::Ongoing => 0,
                Activity::Historical => 1,
                Activity::Unknown => 2,
            })
            .unwrap_or(Activity::Unknown);
        let target = if group.len() > 1 {
            format!("{} ({} hosts)", label(&group[0].host), group.len())
        } else {
            label(&group[0].host)
        };
        let _ = writeln!(
            s,
            "| {target} | {} | {} | {} | {} | {payloads} |",
            group.iter().map(|v| v.hits).sum::<usize>(),
            fmt_ts(group.iter().map(|v| v.first_seen).min().unwrap_or(0)),
            fmt_ts(group.iter().map(|v| v.last_seen).max().unwrap_or(0)),
            activity.label()
        );
        i = j;
    }
    if unnamed > 0 {
        let _ = writeln!(
            s,
            "\n{} (not classified as affected).",
            super::hosts_not_named(unnamed)
        );
    }
    let _ = writeln!(s);
}
