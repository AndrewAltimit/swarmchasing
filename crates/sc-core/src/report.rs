//! Disclosure drafts. Every report is a *draft* for a human to verify.

use crate::analyze::{Analysis, Cluster};
use crate::attribution::{Claim, Evidence, Role, attribute, merge};
use crate::dialect::{CutGroup, CutLengths, Dialect};
use crate::endpoints::{EndpointOptions, EndpointView, endpoints};
use crate::extract::defang;
use crate::fanout::FanOut;
use crate::model::{IndicatorKind, Tier, fmt_ts, truncate};
use crate::notice::PublicView;
use crate::timing::{Rhythm, RhythmVerdict, STALE_AGREE_SHARE, STALE_MIN_DAYS, StaleDates};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt::Write;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum Audience {
    /// The AI developer whose agents appear to be responsible.
    Provider,
    /// The operator of a targeted or compromised system.
    Affected,
    /// Our own case notes.
    #[default]
    Internal,
    /// The public notice: withholds callback channels, credential-like
    /// identifiers and attack details for compromised endpoints.
    Public,
}

impl std::str::FromStr for Audience {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        match s.to_ascii_lowercase().as_str() {
            "provider" => Ok(Self::Provider),
            "affected" | "victim" | "operator" => Ok(Self::Affected),
            "internal" => Ok(Self::Internal),
            "public" | "notice" => Ok(Self::Public),
            _ => Err(format!(
                "unknown audience `{s}` (provider|affected|internal|public)"
            )),
        }
    }
}

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

fn top<K: ToString + Clone>(m: &BTreeMap<K, usize>, n: usize) -> Vec<(String, usize)> {
    let mut v: Vec<(String, usize)> = m.iter().map(|(k, c)| (k.to_string(), *c)).collect();
    v.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    v.truncate(n);
    v
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
    let title = match opts.audience {
        Audience::Provider => "Report of suspected misaligned agent activity",
        Audience::Affected => "Notice: automated agent activity targeting your systems",
        Audience::Internal => "Case notes: agent activity",
        Audience::Public => "Public notice: suspected misaligned agent activity",
    };
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
    let host_list: Vec<String> = top(&hosts, 5)
        .into_iter()
        .map(|(h, n)| {
            format!(
                "`{}` ({n})",
                defang(&format!("https://{h}")).trim_start_matches("hxxps://")
            )
        })
        .collect();
    let _ = match opts.audience {
        Audience::Provider => writeln!(
            s,
            "We observed automated activity consistent with AI agents operating with little or no human oversight. \
             Based on the indicators below, we believe some of it may originate from agents built on or hosted by your platform. \
             Targets included {}.",
            if host_list.is_empty() {
                "unidentified hosts".into()
            } else {
                host_list.join(", ")
            }
        ),
        Audience::Affected => writeln!(
            s,
            "Public scan and archive records show automated agents sending requests to systems we believe you operate ({}). \
             We are sharing this so you can check your own logs. We have not confirmed whether any request succeeded.",
            if host_list.is_empty() {
                "see below".into()
            } else {
                host_list.join(", ")
            }
        ),
        Audience::Internal => writeln!(s, "Targets: {}.", host_list.join(", ")),
        Audience::Public => writeln!(
            s,
            "Public scan and archive records show automated activity consistent with AI agents operating with little or no human oversight, aimed at {}. \
             Reports went to the AI provider and the affected operators when this notice was published. We have not confirmed whether any request succeeded.",
            if host_list.is_empty() {
                "unidentified hosts".into()
            } else {
                host_list.join(", ")
            }
        ),
    };
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
                ch.host.replace('.', "[.]"),
                truncate(&ch.path, 60),
                dur(ch.end - ch.start),
                dur(ch.median_gap_secs),
                ch.pace.label(),
                if unflagged > 0 {
                    format!("; {unflagged} of its requests matched no rule")
                } else {
                    String::new()
                }
            );
        }
        if let Some(line) = rhythm_line(&c.timing.rhythm) {
            let _ = writeln!(s, "  - {line}");
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
            let _ = writeln!(s, "  - {line}");
        }
        if let Some(line) = cut_line(&c.cut_lengths) {
            let _ = writeln!(s, "  - {line}");
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
    ev.sort_by(|&x, &y| {
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
                    r.target_host
                        .as_deref()
                        .unwrap_or("unknown host")
                        .replace('.', "[.]")
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
    let _ = match opts.audience {
        Audience::Provider => writeln!(
            s,
            "- Check whether these patterns match agents or sandboxes on your platform during the window above.\n\
             - If they do, stop the runs and review why the agents chose to probe or circumvent access controls.\n\
             - Let us know whether you can confirm or rule out involvement, so the public record can be corrected."
        ),
        Audience::Affected => writeln!(
            s,
            "- Check your access logs for the window above and the parameters listed.\n\
             - Treat any request carrying attack payloads as an intrusion attempt and check whether it was handled safely.\n\
             - Rotate any credentials or API keys issued to throwaway accounts during this window.\n\
             - Contact us with questions; we will share raw record links on request."
        ),
        Audience::Internal => writeln!(
            s,
            "- [ ] verify records\n- [ ] identify contacts (`swarmchase contact <domain>`)\n- [ ] send provider + affected notices"
        ),
        Audience::Public => writeln!(
            s,
            "- If you operate a listed host, check your access logs for the window above and the indicators listed, and contact us for the full report.\n\
             - If you run an agent platform, check whether these patterns match your users' agents.\n\
             - If anything here is wrong, tell us: corrections are published on this page with their date."
        ),
    };
    s
}

/// Whether a public notice withholds attack details for any of the cluster's hosts.
fn touches_exposed(view: Option<&PublicView>, c: &Cluster) -> bool {
    view.is_some_and(|v| c.target_hosts.keys().any(|h| v.exposed(h)))
}

/// The cluster's canonical test payloads, or nothing for fewer than two
/// records (one person pasting one payload is no habit).
fn dialect_line(d: &Dialect) -> Option<String> {
    if d.records < 2 {
        return None;
    }
    let fams: Vec<String> = d
        .families()
        .into_iter()
        .map(|(fam, vs)| {
            let vs: Vec<String> = vs.iter().map(|(v, n)| format!("{v} ×{n}")).collect();
            format!("{fam} ({})", vs.join(", "))
        })
        .collect();
    let order = if d.first_seen.len() > 1 {
        let shown: Vec<&str> = d.first_seen.iter().take(8).map(String::as_str).collect();
        format!("; first seen {}", shown.join(" → "))
    } else {
        String::new()
    };
    Some(format!(
        "payload dialect `{}` over {} records: {}{order}. Which canonical test payloads a client reaches for is consistent with one model or tool, not evidence on its own",
        d.signature,
        d.records,
        fams.join("; ")
    ))
}

/// The modal batch width, when one width holds for most batches.
fn fanout_line(f: &FanOut) -> Option<String> {
    let w = f.modal_width?;
    let widths: Vec<String> = f.widths.iter().map(|(w, n)| format!("{w}×{n}")).collect();
    Some(format!(
        "parallel fan-out: {} of {} one-second batches were {w} alike requests wide (width×batches: {}), like an agent issuing tool calls in parallel; a scanner submitting a list in bulk looks the same (a hint, not evidence)",
        f.widths.get(&w).copied().unwrap_or(0),
        f.batches,
        widths.join(", ")
    ))
}

/// Truncated URLs cut at nearly one length.
fn cut_line(c: &CutLengths) -> Option<String> {
    let span = |g: &CutGroup| {
        if g.min == g.max {
            format!("{}", g.min)
        } else {
            format!("{}–{}", g.min, g.max)
        }
    };
    let mut parts = Vec::new();
    if let Some(g) = &c.url {
        parts.push(format!(
            "{} of {} truncated URLs were cut at {} characters",
            g.records,
            c.truncated,
            span(g)
        ));
    }
    if let Some(g) = &c.value {
        parts.push(format!(
            "{} of {} cut parameter values were {} characters long",
            g.records,
            c.truncated,
            span(g)
        ));
    }
    if parts.is_empty() {
        return None;
    }
    Some(format!(
        "cut lengths: {}, consistent with a model or tool output limit, not evidence on its own (rule out the source's own display limit first)",
        parts.join("; ")
    ))
}

/// The hour-of-day profile as a hint, or nothing when there is too little to say.
/// Date tags far behind when they were seen, or nothing when they agree with
/// the clock.
fn stale_dates_line(d: &StaleDates) -> Option<String> {
    if !d.consistent {
        return None;
    }
    let named = match d.modal_date {
        Some(date) if d.same_date_share >= STALE_AGREE_SHARE => {
            format!(", {:.0}% naming {date}", d.same_date_share * 100.0)
        }
        _ => String::new(),
    };
    Some(format!(
        "date tags: {} of {} name a day at least {STALE_MIN_DAYS} days before they were seen (median lag {} days{named}), like a model with no clock writing the date it believes is today (a hint, not evidence)",
        d.behind,
        d.tags,
        d.median_lag_days.unwrap_or(0)
    ))
}

fn rhythm_line(r: &Rhythm) -> Option<String> {
    let over = format!(
        "over {} days (hour-of-day entropy {:.2}, longest idle {})",
        r.days,
        r.entropy,
        dur((r.longest_idle_hours * 3600.0) as i64)
    );
    Some(match r.verdict {
        RhythmVerdict::TooShort => return None,
        RhythmVerdict::RoundTheClock => format!(
            "daily rhythm: active around the clock {over}; people sleep, automated fleets need not (a hint, not evidence)"
        ),
        RhythmVerdict::Daytime {
            utc_offset_guess,
            start_hour,
            hours,
        } => format!(
            "daily rhythm: active {start_hour:02}:00–{:02}:00 UTC {over}, like a working day near UTC{utc_offset_guess:+} (a hint, not evidence of where the operator is)",
            (start_hour as u32 + hours as u32) % 24
        ),
        RhythmVerdict::Unclear => format!("daily rhythm: no clear pattern {over}"),
    })
}

/// Who is behind the clusters, each claim with the evidence it rests on.
/// Case notes show every claim; other audiences see a developer named only
/// at or above `opts.min_named`.
fn attribution_section(s: &mut String, claims: &[Claim], opts: &ReportOptions) {
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
fn endpoint_table(
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyze::analyze;
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
            party: "Anthropic".into(),
            role: Role::Developer,
            evidence: Evidence::ProviderConfirmed,
            details: vec!["confirmed in writing".into()],
        };
        let md = render(Audience::Affected, Evidence::default(), vec![confirmed]);
        assert!(md.contains("**Anthropic** (developer). Evidence: confirmed by the provider."));
        assert!(!md.contains("Some requests name a model or vendor"));
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
