//! Disclosure drafts. Every report is a *draft* for a human to verify.
//!
//! `audience` holds the wording that differs per reader, `hints` the
//! one-line cluster hints, `sections` attribution and the endpoint table;
//! this module selects the clusters and lays the report out.

mod audience;
mod hints;
mod sections;

pub use audience::Audience;

use hints::{cut_line, dialect_line, fanout_line, rhythm_line, stale_dates_line};
use sections::{attribution_section, endpoint_table};

use crate::analyze::{Analysis, Cluster};
use crate::attribution::{Claim, Evidence, attribute, merge};
use crate::extract::{defang, defang_host};
use crate::model::{IndicatorKind, Tier, fmt_ts, top_counts, truncate};
use crate::notice::PublicView;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt::Write;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportOptions {
    #[serde(default)]
    pub audience: Audience,
    /// Cluster id (`C1`) or key (`k-3f9a2c1b`); `None` = every non-noise cluster.
    #[serde(default)]
    pub cluster: Option<String>,
    #[serde(default)]
    pub reporter: Option<String>,
    /// Date string supplied by the caller (core has no clock).
    #[serde(default)]
    pub generated: Option<String>,
    #[serde(default = "ten")]
    pub max_evidence: usize,
    /// Weakest evidence that may name a developer outside case notes.
    /// Never below `hosting_asn`: self-identification alone names no one.
    #[serde(default)]
    pub min_named: Evidence,
    /// Claims established by case work (shared identifiers, provider
    /// infrastructure, provider confirmation), merged with the records' own.
    #[serde(default)]
    pub claims: Vec<Claim>,
    /// Endpoints whose attack details the public notice withholds (marked
    /// compromised: the weakness may still be open).
    #[serde(default)]
    pub exposed_hosts: Vec<String>,
}

/// A public notice draft and what the admin must look at before publishing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Notice {
    pub markdown: String,
    /// What the draft withheld.
    pub withheld: Vec<String>,
    /// What could not be classified; withheld, but the admin decides.
    pub flags: Vec<String>,
    /// Withheld values that still appear in the draft. Empty unless
    /// something went wrong; the lines never repeat the values.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub leaks: Vec<String>,
}

fn ten() -> usize {
    10
}

impl Default for ReportOptions {
    fn default() -> Self {
        Self {
            audience: Audience::default(),
            cluster: None,
            reporter: None,
            generated: None,
            max_evidence: ten(),
            min_named: Evidence::default(),
            claims: Vec::new(),
            exposed_hosts: Vec::new(),
        }
    }
}

fn kind_label(k: IndicatorKind) -> &'static str {
    match k {
        IndicatorKind::Relay => "Relay / fetch-through services",
        IndicatorKind::Carrier => "Carrier services and inline programs",
        IndicatorKind::Exploit => "Attack payloads",
        IndicatorKind::AgentMarker => "Agent tags and markers",
        IndicatorKind::CacheBuster => "Cache-busting parameters",
        IndicatorKind::SelfId => "Self-identification strings (unreliable)",
        IndicatorKind::Exfil => "Callback / exfiltration channels",
        IndicatorKind::Header => "Header fingerprints",
        IndicatorKind::Outcome => "Outcome states",
        IndicatorKind::AntiBot => "Anti-bot bypass",
        IndicatorKind::Infra => "Infrastructure",
    }
}

fn dur(secs: i64) -> String {
    match secs {
        s if s < 120 => format!("{s}s"),
        s if s < 7200 => format!("{}m", s / 60),
        s if s < 172800 => format!("{:.1}h", s as f64 / 3600.0),
        s => format!("{:.1}d", s as f64 / 86400.0),
    }
}

pub fn render_markdown(a: &Analysis, opts: &ReportOptions) -> String {
    let mut view =
        (opts.audience == Audience::Public).then(|| PublicView::new(a, &opts.exposed_hosts));
    render(a, opts, view.as_mut())
}

/// The public notice for these clusters, with what it withheld.
pub fn render_notice(a: &Analysis, opts: &ReportOptions) -> Notice {
    let opts = ReportOptions {
        audience: Audience::Public,
        ..opts.clone()
    };
    let mut view = PublicView::new(a, &opts.exposed_hosts);
    let markdown = render(a, &opts, Some(&mut view));
    Notice {
        leaks: view.leaks(&markdown),
        markdown,
        withheld: view.withheld.into_iter().collect(),
        flags: view.flags.into_iter().collect(),
    }
}

fn render(a: &Analysis, opts: &ReportOptions, mut view: Option<&mut PublicView>) -> String {
    let clusters: Vec<&Cluster> = match &opts.cluster {
        Some(id) => a.clusters.iter().filter(|c| c.matches(id)).collect(),
        None => a.clusters.iter().filter(|c| c.tier > Tier::Noise).collect(),
    };
    let mut s = String::new();
    let title = audience::title(opts.audience);
    let _ = writeln!(s, "# {title}\n");
    let _ = writeln!(
        s,
        "> **DRAFT** — generated by swarmchase. Verify every item against the public records before sending.\n"
    );
    if let Some(g) = &opts.generated {
        let _ = writeln!(s, "- **Prepared:** {g}");
    }
    if let Some(r) = &opts.reporter {
        let _ = writeln!(s, "- **Reporter:** {r}");
    }
    let start = clusters
        .iter()
        .map(|c| c.start)
        .filter(|&t| t > 0)
        .min()
        .unwrap_or(a.timing.start);
    let end = clusters.iter().map(|c| c.end).max().unwrap_or(a.timing.end);
    let n_obs: usize = clusters.iter().map(|c| c.members.len()).sum();
    let tier = clusters.iter().map(|c| c.tier).max().unwrap_or_default();
    let _ = writeln!(s, "- **Window:** {} → {}", fmt_ts(start), fmt_ts(end));
    let _ = writeln!(
        s,
        "- **Records:** {n_obs} linked public records in {} cluster(s) (of {} records reviewed, {} flagged)",
        clusters.len(),
        a.total,
        a.flagged
    );
    let _ = writeln!(s, "- **Evidence tier:** {}", tier.label());
    let _ = writeln!(
        s,
        "- **Method:** swarmchasing {}, rules version {}\n",
        env!("CARGO_PKG_VERSION"),
        a.rules_version
    );

    let _ = writeln!(s, "## Summary\n");
    let mut hosts: BTreeMap<String, usize> = BTreeMap::new();
    let mut kinds: BTreeMap<IndicatorKind, usize> = BTreeMap::new();
    for c in &clusters {
        for (h, n) in &c.target_hosts {
            *hosts.entry(h.clone()).or_default() += n;
        }
        for (k, n) in &c.kinds {
            *kinds.entry(*k).or_default() += n;
        }
    }
    let host_list: Vec<String> = top_counts(&hosts, 5)
        .into_iter()
        .map(|(h, n)| {
            format!(
                "`{}` ({n})",
                defang(&format!("https://{h}")).trim_start_matches("hxxps://")
            )
        })
        .collect();
    let _ = writeln!(s, "{}", audience::summary(opts.audience, &host_list));
    if kinds.contains_key(&IndicatorKind::Exploit) {
        let _ = writeln!(
            s,
            "\n**Attack payloads were present** (see Indicators). We did not test whether they succeeded."
        );
    }
    let _ = writeln!(s);

    let _ = writeln!(s, "## Indicators\n");
    let _ = writeln!(s, "| Category | Rule | Records |\n|---|---|---|");
    let mut rule_rows: BTreeMap<(IndicatorKind, String), usize> = BTreeMap::new();
    for c in &clusters {
        for &m in &c.members {
            for h in &a.results[m].hits {
                *rule_rows.entry((h.kind, h.rule_id.clone())).or_default() += 1;
            }
        }
    }
    for ((k, id), n) in &rule_rows {
        let _ = writeln!(s, "| {} | `{id}` | {n} |", kind_label(*k));
    }
    let _ = writeln!(s);

    let claims = clusters
        .iter()
        .fold(Vec::new(), |acc, c| merge(acc, &attribute(a, c)));
    attribution_section(&mut s, &merge(claims, &opts.claims), opts);

    if opts.audience != Audience::Provider {
        endpoint_table(&mut s, a, &hosts, view.as_deref_mut());
    }

    let _ = writeln!(s, "## Timeline\n");
    for c in &clusters {
        let med = c
            .timing
            .median_gap_secs
            .map(|g| format!(", median gap {}", dur(g as i64)))
            .unwrap_or_default();
        let _ = writeln!(
            s,
            "- **{}** ({}) — {} records, {} run(s), {} → {}{med}",
            c.id,
            c.tier.label(),
            c.members.len(),
            c.runs.len(),
            fmt_ts(c.start),
            fmt_ts(c.end)
        );
        for p in c.timing.pauses.iter().take(3) {
            let _ = writeln!(
                s,
                "  - pause {} → {} ({})",
                fmt_ts(p.start),
                fmt_ts(p.end),
                dur(p.end - p.start)
            );
        }
        for ch in a
            .chains
            .iter()
            .filter(|ch| ch.members.iter().any(|m| c.members.contains(m)))
        {
            if view.as_deref().is_some_and(|v| v.exposed(&ch.host)) {
                continue;
            }
            let varied: Vec<String> = ch.varied.iter().map(|p| format!("`{p}`")).collect();
            let unflagged = ch.members.len() - ch.flagged;
            let retries = match ch.retries_after_error {
                0 => String::new(),
                1 => "; 1 variant followed an error response".into(),
                n => format!("; {n} variants followed an error response"),
            };
            let _ = writeln!(
                s,
                "  - iterative probing: {} variants of {} on `{}{}` over {} (median gap {}, {}){}{retries}",
                ch.variants,
                varied.join(", "),
                defang_host(&ch.host),
                truncate(&ch.path, 60),
                dur(ch.end - ch.start),
                dur(ch.median_gap_secs),
                ch.pace.describe(ch.time_basis),
                if unflagged > 0 {
                    format!("; {unflagged} of its requests matched no rule")
                } else {
                    String::new()
                }
            );
        }
        for e in a.escalations.iter().filter(|e| e.clusters.contains(&c.id)) {
            if view.as_deref().is_some_and(|v| v.exposed(&e.host)) {
                continue;
            }
            let basis = e
                .time_basis
                .note()
                .map(|n| format!("; {n}"))
                .unwrap_or_default();
            let _ = writeln!(
                s,
                "  - route escalation on `{}{}`: {} over {}{basis}. One client changing route to reach a page is consistent with an agent working around a failure; two people reading it by different routes look the same (a hint, not evidence)",
                defang_host(&e.host),
                truncate(&e.path, 60),
                e.route_line(),
                dur(e.end - e.start)
            );
        }
        if let Some(line) = rhythm_line(&c.timing.rhythm) {
            let _ = writeln!(s, "  - {line}{}", basis_note(c));
        }
        if let Some(line) = stale_dates_line(&c.timing.stale_dates) {
            let _ = writeln!(s, "  - {line}");
        }
        if !c.link_features.is_empty() {
            let shown: Vec<String> = c
                .link_features
                .iter()
                .take(5)
                .map(|f| match view.as_deref_mut() {
                    Some(v) => v.feature(f),
                    None => f.to_string(),
                })
                .map(|f| format!("`{}`", defang(&truncate(&f, 90))))
                .collect();
            let _ = writeln!(s, "  - linked by: {}", shown.join(", "));
        }
        if let [(style, &n)] = c.encodings.iter().collect::<Vec<_>>()[..]
            && n == c.members.len()
            && n > 1
        {
            let _ = writeln!(
                s,
                "  - all {n} records share one URL encoding style (`{style}`): consistent with one client, not evidence on its own"
            );
        }
        for p in &c.paths.preambles {
            let _ = writeln!(
                s,
                "  - {} hosts opened with the same recon requests (`{}`): consistent with one client, not evidence on its own",
                p.hosts,
                p.paths.join(" → ")
            );
        }
        for set in &c.paths.shared_unusual_sets {
            let nf = if set.not_found > 0 {
                format!("; {} of those requests got 404/410", set.not_found)
            } else {
                String::new()
            };
            let shown: Vec<String> = set
                .paths
                .iter()
                .take(8)
                .map(|p| format!("`{}`", defang(&truncate(p, 60))))
                .collect();
            let _ = writeln!(
                s,
                "  - {} hosts were asked for the same unusual path set ({}){nf}",
                set.hosts,
                shown.join(", ")
            );
        }
        if c.paths.fabricated_ids > 0 {
            let _ = writeln!(
                s,
                "  - {} records carry identifiers no generator produces (patterned or invalid UUIDs, hand-typed hashes), consistent with invented placeholders",
                c.paths.fabricated_ids
            );
        }
        // Payload details stay out of a public notice for compromised endpoints.
        if !touches_exposed(view.as_deref(), c)
            && let Some(line) = dialect_line(&c.dialect)
        {
            let _ = writeln!(s, "  - {line}");
        }
        if let Some(line) = fanout_line(&c.fanout) {
            let _ = writeln!(s, "  - {line}{}", basis_note(c));
        }
        if let Some(line) = cut_line(&c.cut_lengths) {
            let _ = writeln!(s, "  - {line}");
        }
        for (st, n) in c
            .relay_stacks
            .iter()
            .filter(|(st, _)| st.matches(" → ").count() >= 2)
        {
            let _ = writeln!(
                s,
                "  - relay stack `{st}` on {n} records: one client's habit, not evidence on its own"
            );
        }
        // A named contact is for the admin to check, not for a recipient.
        if opts.audience == Audience::Internal {
            for d in &c.declared {
                let contact = d
                    .contact
                    .as_ref()
                    .map(|x| format!(", contact `{x}`"))
                    .unwrap_or_default();
                let _ = writeln!(
                    s,
                    "  - declares testing on {} records: `{}`{contact}. Check it with its owner before treating the cluster as authorised; anyone can write this",
                    d.records,
                    defang(&d.text)
                );
            }
        }
    }
    // A pair hint names both clusters. Outside case notes it appears only
    // when the report covers both, so a report on one cluster never names
    // another (which may be someone else's).
    let selected = |id: &str| clusters.iter().any(|c| c.id == id);
    let pair_shown = |x: &str, y: &str| {
        if opts.audience == Audience::Internal {
            selected(x) || selected(y)
        } else {
            selected(x) && selected(y)
        }
    };
    for sp in a.shared_pauses.iter().filter(|sp| pair_shown(&sp.a, &sp.b)) {
        let _ = writeln!(
            s,
            "\n**{}** and **{}** went quiet together: {}. Their records share no identifier; a link to check, not a merge.",
            sp.a, sp.b, sp.reason
        );
    }
    for p in a.dialect_pairs.iter().filter(|p| pair_shown(&p.a, &p.b)) {
        let pair: Vec<&Cluster> = a
            .clusters
            .iter()
            .filter(|c| c.id == p.a || c.id == p.b)
            .collect();
        let list = if pair.iter().any(|c| touches_exposed(view.as_deref(), c)) {
            String::new()
        } else {
            let shown: Vec<String> = p.shared.iter().map(|v| format!("`{v}`")).collect();
            format!(" ({})", shown.join(", "))
        };
        let _ = writeln!(
            s,
            "\n**{}** and **{}** favour the same canonical test payloads: {} shared variants{list}, Jaccard {:.2}. \
             Their records share no identifier and these payloads are in every public cheat sheet; a link to check, not a merge.",
            p.a,
            p.b,
            p.shared.len(),
            p.jaccard
        );
    }
    let fleets: Vec<&crate::fleets::CandidateFleet> = a
        .candidate_fleets
        .iter()
        .filter(|f| f.clusters.iter().any(|id| selected(id)))
        .collect();
    if opts.audience == Audience::Internal && !fleets.is_empty() {
        let _ = writeln!(
            s,
            "\n## Candidate fleets\n\nClusters tied by soft links (shared pauses, reruns, recon openings, encoding and the like). Each tie is shared by unrelated clients too: a proposal to check, never a merge.\n"
        );
        for f in fleets {
            let kinds: Vec<&str> = f.kinds.iter().map(|k| k.label()).collect();
            let _ = writeln!(
                s,
                "- **{}**: {} — {} soft link(s): {} (weakest pair {:.2})",
                f.id,
                f.clusters.join(", "),
                f.links,
                kinds.join(", "),
                f.strength
            );
            for l in a
                .soft_links
                .iter()
                .filter(|l| f.clusters.contains(&l.a) && f.clusters.contains(&l.b))
                .take(8)
            {
                let _ = writeln!(
                    s,
                    "  - {} ↔ {}: {} ({:.2}): {}",
                    l.a,
                    l.b,
                    l.kind.label(),
                    l.strength,
                    defang(&truncate(&l.detail, 160))
                );
            }
        }
    }
    if opts.audience == Audience::Internal && !a.common_features.is_empty() {
        let _ = writeln!(
            s,
            "\nCommon features, not used to link (a popular or copied value, not one operator's):\n"
        );
        for c in a.common_features.iter().take(10) {
            let _ = writeln!(
                s,
                "- `{}`: {} records, {} → {}, {}",
                defang(&truncate(&c.feature.to_string(), 90)),
                c.records,
                fmt_ts(c.start),
                fmt_ts(c.end),
                c.reason
            );
        }
    }
    if a.date_tags.consistent && a.date_tags.ahead > 0 {
        let _ = writeln!(
            s,
            "\nDate tags in the requests ran ahead of UTC in {} of {} tagged records, consistent with an operator clock between UTC{:+} and UTC{:+}.",
            a.date_tags.ahead,
            a.date_tags.tagged,
            a.date_tags.min_hours.unwrap_or(0.0),
            a.date_tags.max_hours.unwrap_or(0.0)
        );
    }
    let _ = writeln!(s);

    let _ = writeln!(s, "## Representative records\n");
    let _ = writeln!(
        s,
        "URLs are defanged. Records are listed by evidence strength.\n"
    );
    let mut ev: Vec<usize> = clusters
        .iter()
        .flat_map(|c| c.members.iter().copied())
        .collect();
    crate::sort::by(&mut ev, |&x, &y| {
        a.results[y]
            .score
            .cmp(&a.results[x].score)
            .then(a.results[x].obs.ts.cmp(&a.results[y].obs.ts))
    });
    ev.truncate(opts.max_evidence);
    for i in ev {
        let r = &a.results[i];
        let rules: Vec<&str> = r.hits.iter().map(|h| h.rule_id.as_str()).collect();
        let url = match view.as_deref_mut() {
            Some(v) => v.record_url(r),
            None => Some(r.obs.url.clone()),
        };
        match &url {
            Some(u) => {
                let _ = writeln!(
                    s,
                    "1. {} — `{}`",
                    fmt_ts(r.obs.ts),
                    defang(&truncate(u, 240))
                );
            }
            None => {
                let _ = writeln!(
                    s,
                    "1. {} — `{}` — request withheld from the public notice (sent to the affected parties)",
                    fmt_ts(r.obs.ts),
                    defang_host(r.target_host.as_deref().unwrap_or("unknown host"))
                );
            }
        }
        let _ = writeln!(s, "   - rules: {}", rules.join(", "));
        if r.obs.operator_supplied() {
            let _ = writeln!(
                s,
                "   - source: server logs provided by the affected operator"
            );
        }
        if let (Some(rf), Some(_)) = (&r.obs.reference, &url) {
            let _ = writeln!(s, "   - public record: {rf}");
        }
    }
    let _ = writeln!(s);

    let _ = writeln!(s, "## Method and limitations\n");
    let _ = writeln!(
        s,
        "- Collected passively from public records (scan services, web archives, certificate logs). We did not open the submitted URLs, interact with the targets, or read or post to any callback channels.\n\
         - Records were linked by shared unique identifiers (inbox IDs, tags), by timing against the same target, and by probe chains (variants of one request to the same host and path, minutes apart). Linking is probabilistic.\n\
         - Model names inside requests are **not** reliable attribution: agents misreport who built them.\n\
         - Network attribution (ASN) identifies the hosting provider, not necessarily the developer of the agent.\n\
         - Public records cover a fraction of activity. Private or account-linked scans are invisible to us."
    );
    if a.results.iter().any(|r| r.obs.operator_supplied()) {
        let _ = writeln!(
            s,
            "- Some records come from server logs an affected operator provided after our report. They are not public records and are marked as provided by the operator."
        );
    }
    let _ = writeln!(s);

    let _ = writeln!(s, "## Requested action\n");
    let _ = writeln!(s, "{}", audience::requested_action(opts.audience));
    s
}

/// What a timing hint's times were, when not plain request times.
fn basis_note(c: &Cluster) -> String {
    c.time_basis
        .note()
        .map(|n| format!(" ({n})"))
        .unwrap_or_default()
}

/// Whether a public notice withholds attack details for any of the cluster's hosts.
fn touches_exposed(view: Option<&PublicView>, c: &Cluster) -> bool {
    view.is_some_and(|v| c.target_hosts.keys().any(|h| v.exposed(h)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyze::analyze;
    use crate::attribution::Role;
    use crate::model::Observation;
    use crate::rules::Rules;
    use crate::timing::SharedPause;

    #[test]
    fn renders() {
        let obs = (0..4)
            .map(|i| Observation {
                ts: 1_791_000_000 + i * 44,
                url: format!("https://r.jina.ai/https://data.portal.example/view?id={i}%20UNION%20SELECT%201&uqtag=zz9"),
                asn: Some(132203),
                ..Default::default()
            })
            .collect();
        let a = analyze(obs, &Rules::default_rules());
        let md = render_markdown(
            &a,
            &ReportOptions {
                audience: Audience::Provider,
                ..Default::default()
            },
        );
        assert!(md.contains("Attack payloads were present"));
        assert!(md.contains("**Tencent Cloud** (hosting network). 4 record(s) sent from AS132203"));
        assert!(md.contains("hxxps://r[.]jina[.]ai"));
        assert!(!md.contains("https://data.portal.example"));
        assert!(
            !md.contains("## Endpoints"),
            "providers get clusters, not endpoints"
        );

        let md = render_markdown(
            &a,
            &ReportOptions {
                audience: Audience::Affected,
                ..Default::default()
            },
        );
        assert!(md.contains("## Endpoints"));
        assert!(md.contains("| `data[.]portal[.]example` | 4 |"));
        assert!(md.contains("`exploit.sqli_union`"));
    }

    #[test]
    fn renders_rhythm_and_retries() {
        let day0 = 1_791_072_000; // midnight UTC
        // 01:00–08:59 UTC on four days, linked by one tag.
        let mut obs: Vec<Observation> = (0..4)
            .flat_map(|d| (1..9).map(move |h| day0 + d * 86400 + h * 3600))
            .map(|ts| Observation {
                ts,
                url: format!("https://r.jina.ai/https://data.portal.example/view?q={ts}&uqtag=zz9"),
                ..Default::default()
            })
            .collect();
        // A probe chain whose variants follow error responses.
        let t = day0 + 3600 * 2 + 600;
        for (i, (q, status)) in [
            ("1", 200),
            ("1'", 500),
            ("1%20UNION%20SELECT%201", 500),
            ("1%20UNION%20SELECT%201,2", 200),
        ]
        .into_iter()
        .enumerate()
        {
            obs.push(Observation {
                ts: t + i as i64 * 30,
                url: format!("https://r.jina.ai/https://data.portal.example/item?id={q}&uqtag=zz9"),
                status: Some(status),
                ..Default::default()
            });
        }
        let a = analyze(obs, &Rules::default_rules());
        let md = render_markdown(&a, &ReportOptions::default());
        assert!(
            md.contains("daily rhythm: active 01:00–09:00 UTC over 4 days")
                && md.contains("like a working day near UTC+8 (a hint, not evidence"),
            "{md}"
        );
        assert!(
            md.contains("; 2 variants followed an error response"),
            "{md}"
        );
    }

    #[test]
    fn attribution_is_gated_by_evidence() {
        let obs = (0..4)
            .map(|i| Observation {
                ts: 1_791_000_000 + i * 44,
                url: format!("https://r.jina.ai/https://data.portal.example/view?id={i}%20UNION%20SELECT%201&uqtag=zz9&agent=claude"),
                asn: Some(132203),
                ..Default::default()
            })
            .collect();
        let a = analyze(obs, &Rules::default_rules());
        let render = |audience, min_named, claims: Vec<Claim>| {
            render_markdown(
                &a,
                &ReportOptions {
                    audience,
                    min_named,
                    claims,
                    ..Default::default()
                },
            )
        };
        let md = render(Audience::Provider, Evidence::SelfId, vec![]);
        assert!(
            !md.contains("Anthropic"),
            "self-identification names no one"
        );
        assert!(md.contains("Some requests name a model or vendor"));
        let md = render(Audience::Internal, Evidence::default(), vec![]);
        assert!(md.contains("Anthropic (developer, **not named outside case notes**)"));

        let confirmed = Claim {
            details: vec!["confirmed in writing".into()],
            ..Claim::new("Anthropic", Role::Developer, Evidence::ProviderConfirmed)
        };
        let md = render(
            Audience::Affected,
            Evidence::default(),
            vec![confirmed.clone()],
        );
        assert!(md.contains("**Anthropic** (developer). Evidence: confirmed by the provider."));
        assert!(md.contains("Label: Confirmed; tag: Documented"), "{md}");
        assert!(
            md.contains("- Confirmed: almost certain operated by **Anthropic**"),
            "{md}"
        );
        assert!(!md.contains("Some requests name a model or vendor"));

        // Model-family and harness candidates: ranked in private reports,
        // never named in public, whatever their evidence.
        let family = Claim {
            likelihood: Some(0.7),
            accuracy: Some(0.8),
            corpus_size: Some(500),
            details: vec!["residue match".into()],
            ..Claim::new("family-q", Role::ModelFamily, Evidence::ProviderConfirmed)
        };
        let md = render(
            Audience::Provider,
            Evidence::default(),
            vec![family.clone()],
        );
        assert!(md.contains("**Model family candidates**"), "{md}");
        assert!(
            md.contains("1. family-q — Label: Possible; tag: Inference."),
            "{md}"
        );
        assert!(
            md.contains("accuracy 80% on a held-out set, corpus of 500"),
            "{md}"
        );
        assert!(!md.contains("operated by **family-q**"), "{md}");
        let public = render(Audience::Public, Evidence::SelfId, vec![family, confirmed]);
        assert!(!public.contains("family-q"), "{public}");
        assert!(public.contains("operated by **Anthropic**"), "{public}");
    }

    #[test]
    fn renders_dialect_fanout_and_cut_lengths() {
        let payloads = [
            "%3Cscript%3Ealert(1)%3C/script%3E",
            "1'%20OR%201=1--",
            "../../../etc/passwd",
        ];
        let mut obs = Vec::new();
        // Five one-second batches of three alike requests to three hosts.
        for b in 0..5 {
            for (k, h) in ["a", "b", "c"].iter().enumerate() {
                obs.push(Observation {
                    ts: 1_791_000_007 + 30 * b + (k % 2) as i64,
                    url: format!(
                        "https://r.jina.ai/https://{h}.example/view?uqtag=zz9&q={}",
                        payloads[k]
                    ),
                    ..Default::default()
                });
            }
        }
        // Three URLs cut mid escape at nearly one length.
        for n in 0..3 {
            obs.push(Observation {
                ts: 1_791_000_500 + 40 * n,
                url: format!(
                    "https://r.jina.ai/https://a.example/view?uqtag=zz9&note={}%2",
                    "x".repeat(40 + n as usize)
                ),
                ..Default::default()
            });
        }
        // The same payloads from an unlinked client a week later.
        for (k, h) in ["d", "e", "f"].iter().enumerate() {
            obs.push(Observation {
                ts: 1_791_600_000 + 300 * k as i64,
                url: format!(
                    "https://r.jina.ai/https://{h}.example/item?uqtag=yy8&id={}",
                    payloads[k]
                ),
                ..Default::default()
            });
        }
        let a = analyze(obs, &Rules::default_rules());
        assert_eq!(a.clusters.len(), 2, "{:?}", a.clusters);
        assert_eq!(a.dialect_pairs.len(), 1, "{:?}", a.dialect_pairs);
        let md = render_markdown(&a, &ReportOptions::default());
        assert!(
            md.contains("payload dialect `")
                && md.contains("sqli (quote_or_1eq1 ×5); traversal (depth3 ×5, etc_passwd ×5); xss (script_alert ×5)"),
            "{md}"
        );
        assert!(
            md.contains("parallel fan-out: 5 of 8 one-second batches were 3 alike requests wide"),
            "{md}"
        );
        assert!(
            md.contains("cut lengths: 3 of 3 truncated URLs were cut at "),
            "{md}"
        );
        assert!(
            md.contains(
                "favour the same canonical test payloads: 4 shared variants (`sqli.quote_or_1eq1`"
            ),
            "{md}"
        );

        // A public notice keeps payload details for compromised endpoints out.
        let notice = render_notice(
            &a,
            &ReportOptions {
                exposed_hosts: vec!["a.example".into()],
                ..Default::default()
            },
        );
        let md = notice.markdown;
        assert!(
            md.contains("payload dialect `"),
            "the other cluster keeps its line"
        );
        assert_eq!(md.matches("payload dialect `").count(), 1, "{md}");
        assert!(md.contains("favour the same canonical test payloads: 4 shared variants, Jaccard"));
    }

    #[test]
    fn single_cluster_reports_name_no_other_cluster() {
        let mut obs = Vec::new();
        for (tag, base) in [("zz9", 1_791_000_000), ("yy8", 1_791_600_000)] {
            for (k, h) in ["d", "e", "f"].iter().enumerate() {
                obs.push(Observation {
                    ts: base + 300 * k as i64,
                    url: format!(
                        "https://r.jina.ai/https://{h}.example/item?uqtag={tag}&id=1'%20OR%201=1--&p=../../../etc/passwd"
                    ),
                    ..Default::default()
                });
            }
        }
        let mut a = analyze(obs, &Rules::default_rules());
        assert_eq!(a.clusters.len(), 2, "{:?}", a.clusters);
        assert_eq!(a.dialect_pairs.len(), 1, "{:?}", a.dialect_pairs);
        a.shared_pauses.push(SharedPause {
            a: "C1".into(),
            b: "C2".into(),
            pauses: Vec::new(),
            on_the_hour: 0,
            expected: 0.001,
            p_chance: 0.001,
            reason: "2 pause(s) matched".into(),
        });
        for audience in [Audience::Provider, Audience::Affected, Audience::Public] {
            let opts = ReportOptions {
                audience,
                cluster: Some("C1".into()),
                ..Default::default()
            };
            let md = render_markdown(&a, &opts);
            assert!(!md.contains("C2"), "{audience:?}: {md}");
            assert!(!md.contains("went quiet together"), "{md}");
            assert!(!md.contains("favour the same canonical"), "{md}");
        }
        // Case notes keep the lead; a report on both clusters names both.
        let both = render_markdown(&a, &ReportOptions::default());
        assert!(
            both.contains("**C1** and **C2** went quiet together"),
            "{both}"
        );
        let notes = render_markdown(
            &a,
            &ReportOptions {
                cluster: Some("C1".into()),
                ..Default::default()
            },
        );
        assert!(notes.contains("went quiet together"), "{notes}");
    }
}
