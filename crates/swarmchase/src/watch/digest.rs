//! The run digest: what changed since the previous run, how the sources
//! fared, and the leads (reruns, archive bursts, case status) for the admin.

use super::attention::{Band, Queue};
use super::autonomy::{Decision, Mode};
use super::cases::CaseReport;
use super::priority::{Level, Priority};
use super::triage::{Lead, LeadKind, TriageReport};
use crate::util::{one_line, top_keys};
use sc_collect::{Coverage, Kind};
use sc_core::bursts::ArchiveBurst;
use sc_core::recurrence::{ClusterRun, cluster_reruns};
use sc_core::{Analysis, Hit, IndicatorKind, ObsResult, Tier, defang_host};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

/// What the previous run knew, so the digest can say what changed.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Summary {
    #[serde(default)]
    pub generated: String,
    /// Keyed by the cluster's earliest record ID, which is stable across runs.
    #[serde(default)]
    pub clusters: BTreeMap<String, ClusterSummary>,
    /// Every target host that ever had a flagged record. Cumulative.
    #[serde(default)]
    pub endpoints: BTreeMap<String, Endpoint>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterSummary {
    pub id: String,
    /// The cluster's stable key ([`sc_core::Cluster::key`]).
    #[serde(default)]
    pub key: String,
    pub tier: Tier,
    pub score: i32,
    pub records: usize,
    pub start: i64,
    pub end: i64,
    pub targets: Vec<String>,
    pub rules: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Endpoint {
    pub first_seen: i64,
    pub last_seen: i64,
    pub max_tier: Tier,
}

/// One source's line in the digest.
#[derive(Default)]
pub struct SourceReport {
    pub name: String,
    /// Its `kind` in the watchlist.
    pub kind: String,
    pub pulled: usize,
    pub new: usize,
    pub pending: bool,
    /// HTTP requests made, retries included.
    pub requests: usize,
    pub error: Option<String>,
    /// Why the source did not run (e.g. no API key). Not an error.
    pub skipped: Option<String>,
    /// A page failed after earlier ones succeeded: what it kept counts, and
    /// it continues next run.
    pub stopped: Option<String>,
    /// How much of a stream or feed it read.
    pub coverage: Option<Coverage>,
    /// Successful runs in a row that pulled nothing, once that reaches
    /// [`crate::health::QUIET_RUNS`], and whether it ever pulled a record.
    pub quiet: Option<(u32, bool)>,
    /// Wall-clock milliseconds the source's pull took.
    pub duration_ms: u64,
    /// Not pulled: the collection deadline was reached before its turn. It
    /// goes first next run.
    pub deferred: bool,
}

impl SourceReport {
    pub fn new(name: &str, kind: &str) -> Self {
        Self {
            name: name.to_string(),
            kind: kind.to_string(),
            ..Default::default()
        }
    }

    fn ran(&self) -> bool {
        self.skipped.is_none() && self.error.is_none() && !self.deferred
    }

    /// One word for the run summary: `skipped`, `deferred`, `error`,
    /// `stopped`, `partial` (continues next run) or `complete`.
    pub fn status(&self) -> &'static str {
        if self.deferred {
            return "deferred";
        }
        match (&self.skipped, &self.error, &self.stopped, self.pending) {
            (Some(_), ..) => "skipped",
            (None, Some(_), ..) => "error",
            (None, None, Some(_), _) => "stopped",
            (None, None, None, true) => "partial",
            (None, None, None, false) => "complete",
        }
    }
}

/// What the digest loses when a source of `kind` does not run.
pub fn capability(kind: &str) -> &'static str {
    match kind {
        "urlquery" | "urlscan" => {
            "submit-time records, the only request-like times: timing links, pace, agent grades above L2 and interaction edges (S1–S6)"
        }
        "wayback" | "commoncrawl" | "memento" => {
            "archive captures through this relay or carrier: the targets, payloads and run tags it wraps"
        }
        "arquivo" => {
            "Arquivo.pt captures, including on-demand saves (a second submit-anywhere channel)"
        }
        "gharchive" => "GitHub event leads: run-named repositories and pasted relay URLs",
        "npm" | "pypi" => "registry leads: packages carrying run tags",
        "wikimedia" => "wiki edit leads: relay and run-tag links added to wiki pages",
        "hackernews" => "Hacker News leads: relay and run-tag links in stories and comments",
        "bluesky" => {
            "Bluesky leads: relay and run-tag links in a sampled stretch of posts, not every post since the last run"
        }
        "ghsearch" => {
            "GitHub leads from pull request text and commit messages, which GH Archive's payloads leave out"
        }
        "ctlog" => "certificate leads: new relay look-alikes and mirrors",
        "wellknown" => "agent protocol footprints: agent cards and signature key directories",
        "mcp" => "MCP Registry metadata for linking hosts to tool servers",
        _ => "this source's records",
    }
}

/// The health block's lines on lost capability: sources that were skipped,
/// failed, stopped early or read only part of their stream, and the run-wide
/// loss when no submit-time source ran.
pub(super) fn lost_lines(sources: &[SourceReport]) -> Vec<String> {
    let mut out = Vec::new();
    let submit = |r: &&SourceReport| r.kind.parse::<Kind>().is_ok_and(Kind::submit_time);
    if !sources.iter().filter(submit).any(|r| r.ran()) {
        out.push(
            "**No submit-time source ran.** Timing links, pace, agent grades above L2 and interaction edges (S1–S6) are unavailable this run: archive capture times cannot stand in for submission times."
                .to_string(),
        );
    }
    for r in sources {
        let what = capability(&r.kind);
        if r.deferred {
            out.push(format!(
                "`{}` deferred: the collection deadline was reached before its turn; it goes first next run. Lost this run: {what}.",
                r.name
            ));
        } else if let Some(why) = &r.skipped {
            let why = why.strip_prefix("skipped: ").unwrap_or(why);
            out.push(format!("`{}` skipped ({why}). Lost: {what}.", r.name));
        } else if let Some(e) = &r.error {
            out.push(format!(
                "`{}` failed ({}). Lost this run: {what}.",
                r.name,
                one_line(e, 120)
            ));
        } else if let Some(e) = &r.stopped {
            out.push(format!(
                "`{}` stopped early ({}) after {} records; it continues from its checkpoint next run.",
                r.name,
                one_line(e, 120),
                r.pulled
            ));
        }
        if let Some(c) = &r.coverage
            && c.skipped > 0
        {
            out.push(format!(
                "`{}` read {}: the skipped part of the stream is not read.",
                r.name,
                c.line()
            ));
        }
    }
    out
}

/// Notes on sources that keep pulling nothing.
fn quiet_lines(sources: &[SourceReport]) -> Vec<String> {
    sources
        .iter()
        .filter_map(|r| {
            let (runs, ever) = r.quiet?;
            let canary = match r.coverage.as_ref().and_then(|c| c.canary) {
                Some(true) => {
                    "; its canary passed, so the pipe works and the pattern finds nothing"
                }
                _ => "",
            };
            Some(format!(
                "`{}` has pulled nothing in {runs} runs{}{canary}.",
                r.name,
                if ever { "" } else { " and never has" }
            ))
        })
        .collect()
}

/// A failed source's reason in a few words, for its status cell: the HTTP
/// status or the root cause, and the attempts made (`HTTP 504 after 3
/// attempts`). Request URLs are left out: they are long, and a watch query
/// can carry text the digest has no business repeating. The full error goes
/// to the run's log and the watch state.
pub fn short_reason(e: &anyhow::Error) -> String {
    let msgs: Vec<String> = e.chain().map(|c| c.to_string()).collect();
    let attempts = msgs.iter().find_map(|m| {
        m.strip_prefix("gave up after ")
            .and_then(|r| r.strip_suffix(" attempts"))
            .map(str::to_string)
    });
    // The messages that say what went wrong, without the retry wrapper and
    // without contexts that only name the request (`GET <url>`).
    let causes: Vec<String> = msgs
        .iter()
        .filter(|m| !m.starts_with("gave up after "))
        .map(|m| without_urls(m))
        .filter(|m| !m.is_empty() && m != "GET")
        .collect();
    let what = causes
        .iter()
        .find_map(|m| http_status(m))
        .or_else(|| match causes.as_slice() {
            [] => None,
            [only] => Some(only.clone()),
            [first, .., last] => Some(format!("{first}: {last}")),
        })
        .unwrap_or_else(|| "unknown error".into());
    let what = one_line(&what, 120);
    match attempts {
        Some(n) => format!("{what} after {n} attempts"),
        None => what,
    }
}

/// `HTTP <code>` when `m` reports a response status.
fn http_status(m: &str) -> Option<String> {
    m.match_indices("HTTP ").find_map(|(i, _)| {
        let code = m.get(i + 5..i + 8)?;
        let next = m[i + 8..].chars().next();
        (code.bytes().all(|b| b.is_ascii_digit()) && !next.is_some_and(|c| c.is_ascii_digit()))
            .then(|| format!("HTTP {code}"))
    })
}

/// `m` with every word that holds a URL removed, and a request method left
/// in front of one (`GET https://a/b: reading body` is `reading body`).
fn without_urls(m: &str) -> String {
    let mut words: Vec<&str> = m.split_whitespace().collect();
    if words.len() > 1 && words[0] == "GET" && words[1].contains("://") {
        words.remove(0);
    }
    let s = words
        .into_iter()
        .filter(|w| !w.contains("://"))
        .collect::<Vec<_>>()
        .join(" ");
    s.trim_end_matches([':', ' ']).to_string()
}

/// How the run's sources fared, with warnings. Any alert makes the run
/// count as changed, so it is emailed; a failure streak alerts on its 1st,
/// 2nd, 4th, 8th... run ([`crate::health::alert_due`]), so a source that
/// keeps failing does not mail every run.
#[derive(Default)]
pub struct Health {
    pub sources: Vec<SourceReport>,
    pub alerts: Vec<Alert>,
    pub notes: Vec<String>,
}

/// What a health alert is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AlertKind {
    /// The source's pull failed.
    SourceFailed,
    /// The source was skipped for the first time (no API key).
    SourceSkipped,
    /// The source pulled far less than its recent median.
    SourceCollapsed,
    /// The source answered, but not in the shape the parser expects.
    CanaryFailed,
    /// A host stayed unavailable through its retries.
    HostDown,
    /// A rule's hit rate jumped on one source's new records.
    RuleDrift,
    /// A store file has lines that cannot be read (a write cut short, bytes
    /// that are not UTF-8); they are skipped.
    StoreDamaged,
    /// A step after collection failed (a file not written, a history not
    /// read); the run went on without it.
    StepFailed,
    Other,
}

impl AlertKind {
    pub fn label(self) -> &'static str {
        match self {
            AlertKind::SourceFailed => "source_failed",
            AlertKind::SourceSkipped => "source_skipped",
            AlertKind::SourceCollapsed => "source_collapsed",
            AlertKind::CanaryFailed => "canary_failed",
            AlertKind::HostDown => "host_down",
            AlertKind::RuleDrift => "rule_drift",
            AlertKind::StoreDamaged => "store_damaged",
            AlertKind::StepFailed => "step_failed",
            AlertKind::Other => "other",
        }
    }
}

/// One health alert: its kind, the source or host it concerns, and the line.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Alert {
    pub kind: AlertKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    pub text: String,
}

impl Alert {
    pub fn new(kind: AlertKind, source: &str, text: String) -> Self {
        Self {
            kind,
            source: Some(source.to_string()),
            text,
        }
    }
}

impl From<&str> for Alert {
    fn from(text: &str) -> Self {
        Self {
            kind: AlertKind::Other,
            source: None,
            text: text.to_string(),
        }
    }
}

/// Everything one digest is written from.
pub struct DigestInput<'a> {
    pub stamp: &'a str,
    /// The analysis of the window.
    pub analysis: &'a Analysis,
    /// The previous run's summary, and this run's.
    pub prev: &'a Summary,
    pub next: &'a Summary,
    /// Records this run collected.
    pub new_ids: &'a BTreeSet<String>,
    pub health: &'a Health,
    pub bursts: &'a [ArchiveBurst],
    pub cases: &'a CaseReport,
    pub window_days: i64,
    /// The run's new leads ([`super::triage::leads`]), with any suggestions.
    pub leads: &'a [Lead],
    pub triage: &'a TriageReport,
    pub priority: &'a Priority,
    /// The run's attention queue ([`super::attention`]).
    pub attention: &'a Queue,
    /// What the autonomy levels did or would have done this run.
    pub autonomy: &'a [Decision],
}

pub struct Digest {
    pub text: String,
    pub changed: bool,
}

pub fn summarise(a: &Analysis, prev: &Summary, generated: String) -> Summary {
    let mut s = Summary {
        generated,
        clusters: BTreeMap::new(),
        endpoints: BTreeMap::new(),
    };
    // Keys written before hosts were cleaned are merged into their clean form.
    for (h, e) in &prev.endpoints {
        let h = clean_host(h);
        if h.is_empty() {
            continue;
        }
        let m = s.endpoints.entry(h).or_insert_with(|| e.clone());
        m.first_seen = m.first_seen.min(e.first_seen);
        m.last_seen = m.last_seen.max(e.last_seen);
        m.max_tier = m.max_tier.max(e.max_tier);
    }
    for c in &a.clusters {
        let Some(first) = c
            .members
            .iter()
            .map(|&m| &a.results[m].obs)
            .min_by(|x, y| x.ts.cmp(&y.ts).then_with(|| x.id.cmp(&y.id)))
        else {
            continue;
        };
        s.clusters.insert(
            first.id.clone(),
            ClusterSummary {
                id: c.id.clone(),
                key: c.key.clone(),
                tier: c.tier,
                score: c.score,
                records: c.members.len(),
                start: c.start,
                end: c.end,
                targets: top_keys(&c.target_hosts, 3),
                rules: top_keys(&c.rules, 6),
            },
        );
    }
    for r in &a.results {
        if r.tier < Tier::Suggestive {
            continue;
        }
        let Some(h) = r.target_host.as_deref().map(clean_host) else {
            continue;
        };
        if h.is_empty() {
            continue;
        }
        let e = s.endpoints.entry(h).or_insert(Endpoint {
            first_seen: r.obs.ts,
            last_seen: r.obs.ts,
            max_tier: r.tier,
        });
        e.first_seen = e.first_seen.min(r.obs.ts);
        e.last_seen = e.last_seen.max(r.obs.ts);
        e.max_tier = e.max_tier.max(r.tier);
    }
    s
}

/// The previous run's summary as the ledger follows it: a cluster whose key
/// changed this run (its earliest member left the window) is listed under
/// its new key, at the tier its thread had on the previous run, so it is
/// compared with itself and not reported as new. Only threads seen on the
/// previous run carry over; a thread seen before that and back now is
/// reported as new here and as a return by the ledger.
pub fn baseline(
    prev: &Summary,
    next: &Summary,
    ledger: &super::ledger::Ledger,
    observed: &super::ledger::Observed,
    stamp: &str,
) -> Summary {
    let mut base = prev.clone();
    // `2026-10-12T06:00:00Z` is run `20261012T060000Z`.
    let prev_run: String = prev
        .generated
        .chars()
        .filter(|c| *c != '-' && *c != ':')
        .collect();
    for (k, c) in &next.clusters {
        if prev.clusters.contains_key(k) {
            continue;
        }
        let Some(th) = observed
            .threads
            .get(&c.id)
            .and_then(|t| ledger.threads.get(t))
        else {
            continue;
        };
        let before = th
            .points
            .iter()
            .rev()
            .find(|p| p.run != stamp)
            .filter(|p| prev_run.is_empty() || p.run == prev_run);
        if let Some(p) = before {
            base.clusters.insert(
                k.clone(),
                ClusterSummary {
                    tier: p.tier,
                    ..c.clone()
                },
            );
        }
    }
    base
}

pub fn digest(d: &DigestInput) -> Digest {
    let (a, prev, next, health) = (d.analysis, d.prev, d.next, d.health);
    let mut t = String::new();
    let _ = writeln!(t, "# Watch digest {}\n", d.stamp);
    let _ = writeln!(
        t,
        "Unverified leads from passive collection. Review before acting on anything here.\n"
    );
    needs_attention(&mut t, d.priority);
    attention_queue(&mut t, d.attention, d.autonomy);

    // Health first: a source that did not run hides whatever it would have
    // found, so what was lost is the first thing to read.
    let _ = writeln!(t, "## Health ({})\n", health.alerts.len());
    let lost = lost_lines(&health.sources);
    if health.alerts.is_empty() && lost.is_empty() {
        let _ = writeln!(
            t,
            "Every source ran. No failures, source collapses or rule drift."
        );
    }
    for x in &health.alerts {
        let _ = writeln!(t, "- {}", x.text);
    }
    // A blank line between blocks, not before the first.
    let gap = |t: &String| if t.ends_with("\n\n") { "" } else { "\n" };
    if !lost.is_empty() {
        let _ = writeln!(t, "{}Capability lost this run:\n", gap(&t));
        for x in &lost {
            let _ = writeln!(t, "- {x}");
        }
    }
    let quiet = quiet_lines(&health.sources);
    if !quiet.is_empty() {
        let _ = writeln!(t, "{}Quiet sources:\n", gap(&t));
        for x in &quiet {
            let _ = writeln!(t, "- {x}");
        }
    }
    for x in &health.notes {
        let _ = writeln!(t, "\n{x}");
    }

    let _ = writeln!(t, "\n## Sources\n");
    let _ = writeln!(
        t,
        "| Source | Pulled | New | Requests | Coverage | Status |\n|---|---:|---:|---:|---|---|"
    );
    for s in &health.sources {
        let status = match (&s.error, &s.stopped, s.pending) {
            _ if s.deferred => "deferred: collection deadline reached".into(),
            _ if s.skipped.is_some() => s.skipped.clone().unwrap_or_default(),
            (Some(e), _, _) => format!("error: {}", one_line(e, 160)),
            (None, Some(e), _) => format!("stopped early: {}", one_line(e, 120)),
            (None, None, true) => "partial, continues next run".into(),
            (None, None, false) => "complete".into(),
        };
        let coverage = s.coverage.as_ref().map_or(String::new(), |c| {
            let canary = match c.canary {
                Some(true) => ", canary ok",
                Some(false) => ", canary FAILED",
                None => "",
            };
            format!("{}{canary}", c.line())
        });
        let _ = writeln!(
            t,
            "| {} | {} | {} | {} | {coverage} | {status} |",
            s.name, s.pulled, s.new, s.requests
        );
    }

    let tier = |x| a.tier_counts.get(&x).copied().unwrap_or(0);
    let with_indicator = a.results.iter().filter(|r| indicative(r)).count();
    let (above_noise, noise): (Vec<_>, Vec<_>) =
        a.clusters.iter().partition(|c| c.tier >= Tier::Suggestive);
    let _ = writeln!(
        t,
        "\n## Last {} days\n\n{} records, {} with an indicator beyond the relay or carrier they came through ({} significant, {} suggestive), {} clusters above noise{}.\n",
        d.window_days,
        a.total,
        with_indicator,
        tier(Tier::Significant),
        tier(Tier::Suggestive),
        above_noise.len(),
        if noise.is_empty() {
            String::new()
        } else {
            format!(
                " ({} noise-tier clusters listed under Noise-tier clusters)",
                noise.len()
            )
        }
    );

    let mut new_clusters = Vec::new();
    let mut escalated = Vec::new();
    for (k, c) in &next.clusters {
        if c.tier < Tier::Suggestive {
            continue;
        }
        match prev.clusters.get(k) {
            None => new_clusters.push(c),
            Some(p) if c.tier > p.tier => escalated.push((p.tier, c)),
            _ => {}
        }
    }
    let new_endpoints: Vec<(&String, &Endpoint)> = next
        .endpoints
        .iter()
        .filter(|(h, _)| !prev.endpoints.contains_key(*h))
        .collect();

    let none = |t: &mut String, empty: bool| {
        if empty {
            let _ = writeln!(t, "None.");
        }
    };
    let _ = writeln!(t, "## New clusters ({})\n", new_clusters.len());
    none(&mut t, new_clusters.is_empty());
    for c in &new_clusters {
        let _ = writeln!(t, "- {}", cluster_line(c));
    }
    let _ = writeln!(t, "\n## Tier changes ({})\n", escalated.len());
    none(&mut t, escalated.is_empty());
    for (from, c) in &escalated {
        let _ = writeln!(
            t,
            "- {} → {}: {}",
            from.label(),
            c.tier.label(),
            cluster_line(c)
        );
    }
    let _ = writeln!(t, "\n## Endpoints newly hit ({})\n", new_endpoints.len());
    none(&mut t, new_endpoints.is_empty());
    for (h, e) in &new_endpoints {
        let _ = writeln!(
            t,
            "- `{}` [{}] first seen {}, last {}",
            defang_host(&clean_host(h)),
            e.max_tier.label(),
            sc_core::fmt_ts(e.first_seen),
            sc_core::fmt_ts(e.last_seen)
        );
    }

    let mut targets: BTreeMap<String, usize> = BTreeMap::new();
    for r in &a.results {
        if r.tier >= Tier::Suggestive
            && d.new_ids.contains(&r.obs.id)
            && let Some(h) = &r.target_host
        {
            *targets.entry(clean_host(h)).or_default() += 1;
        }
    }
    let mut targets: Vec<_> = targets.into_iter().collect();
    targets.sort_by_key(|x| std::cmp::Reverse(x.1));
    let _ = writeln!(t, "\n## Top targets in new records\n");
    none(&mut t, targets.is_empty());
    for (h, n) in targets.iter().take(10) {
        let _ = writeln!(
            t,
            "- `{}`: {n} suggestive or significant",
            defang_host(&clean_host(h))
        );
    }

    lone_significant(&mut t, a, d.new_ids);
    model_suggestions(&mut t, d.leads, d.triage);

    // Descriptive only: a rerun is a lead for the admin, never a merge.
    let (runs, matches) = cluster_reruns(a, d.new_ids);
    let _ = writeln!(t, "\n## Possible reruns ({})\n", matches.len());
    none(&mut t, matches.is_empty());
    for m in &matches {
        let (e, l) = (&runs[m.earlier], &runs[m.later]);
        let _ = writeln!(
            t,
            "- {} repeats {}: {} shared hosts, Jaccard {:.2} (weighted {:.2}), order {:.2}; {}",
            run_label(l),
            run_label(e),
            m.shared.len(),
            m.jaccard,
            m.weighted_jaccard,
            m.order,
            m.shared
                .iter()
                .take(5)
                .map(|h| format!("`{}`", defang_host(h)))
                .collect::<Vec<_>>()
                .join(", ")
        );
    }

    leads(&mut t, a);
    noise_clusters(&mut t, a);

    let _ = writeln!(t, "\n## Archive bursts ({})\n", d.bursts.len());
    none(&mut t, d.bursts.is_empty());
    for b in d.bursts {
        // Counted here rather than taken from the burst: every capture of a
        // relay's host carries the relay's own rule.
        let with = a
            .results
            .iter()
            .filter(|r| r.obs.ts >= b.start && r.obs.ts <= b.end)
            .filter(|r| {
                r.target_host.as_deref().map(clean_host) == Some(clean_host(&b.host))
                    && indicative(r)
            })
            .count();
        let _ = writeln!(
            t,
            "- `{}`: {} captures {} → {} ({} distinct URLs, {with} with an indicator beyond the relay); usually {:.1}/day",
            defang_host(&clean_host(&b.host)),
            b.count,
            sc_core::fmt_ts(b.start),
            sc_core::fmt_ts(b.end),
            b.distinct_urls,
            b.baseline_per_day
        );
    }

    let _ = writeln!(t, "\n## Case status ({})\n", d.cases.lines.len());
    none(&mut t, d.cases.lines.is_empty());
    for l in &d.cases.lines {
        let _ = writeln!(t, "- {l}");
    }
    if !d.cases.lines.is_empty() {
        let _ = writeln!(
            t,
            "\nProposals only: nothing here changes a case or notice until you run the command."
        );
    }

    // A new lone record at L2 or higher is a lead the admin should see
    // now, like a new cluster.
    let lone_graded = d.leads.iter().any(|l| {
        l.kind == LeadKind::Record
            && l.tier == Tier::Significant
            && l.grade >= sc_core::agentness::AgentLevel::ModelWritten
    });
    let changed = d.cases.changed
        || lone_graded
        || !new_clusters.is_empty()
        || !escalated.is_empty()
        || !new_endpoints.is_empty()
        || !matches.is_empty()
        || !d.bursts.is_empty()
        || !health.alerts.is_empty()
        || d.autonomy.iter().any(|x| x.mode == Mode::On && x.acted());
    Digest { text: t, changed }
}

/// Queue lines the digest lists.
const QUEUE_LINES: usize = 8;

/// The head of the attention queue, and what the autonomy levels did or
/// would have done.
fn attention_queue(t: &mut String, q: &Queue, ds: &[Decision]) {
    let n = |b: Band| q.by_band.get(b.label()).copied().unwrap_or(0);
    let _ = writeln!(
        t,
        "## Attention queue: {} urgent, {} look, {} watch
",
        n(Band::Urgent),
        n(Band::Look),
        n(Band::Watch)
    );
    let top: Vec<_> = q.items.iter().filter(|i| i.band >= Band::Look).collect();
    if top.is_empty() {
        let _ = writeln!(
            t,
            "Nothing above watch: no cluster in the window combines grade L2 or higher with harmful targets, a scope finding or interaction.
"
        );
    }
    for i in top.iter().take(QUEUE_LINES) {
        let traj = match i.growth {
            Some(g) if g >= 1.5 => format!("{}, {g:.1}x in a day", i.trajectory.label()),
            _ => i.trajectory.label().to_string(),
        };
        let targets = i
            .targets
            .iter()
            .map(|h| format!("`{h}`"))
            .collect::<Vec<_>>()
            .join(", ");
        let _ = writeln!(
            t,
            "- {}: {} {} at {}, {} record(s), {traj}; {}{}; targets {}; momentum {}{}",
            if i.band == Band::Urgent {
                "**urgent**"
            } else {
                "look"
            },
            i.id,
            i.key,
            i.grade.code(),
            i.records,
            i.why.join("; "),
            if i.caps.is_empty() {
                String::new()
            } else {
                format!(" ({})", i.caps.join("; "))
            },
            if targets.is_empty() {
                "none".into()
            } else {
                targets
            },
            i.momentum,
            if i.cases.is_empty() {
                String::new()
            } else {
                format!("; in case {}", i.cases.join(", "))
            }
        );
    }
    if top.len() > QUEUE_LINES {
        let _ = writeln!(
            t,
            "- … {} more at urgent or look on the dashboard",
            top.len() - QUEUE_LINES
        );
    }
    if !top.is_empty() {
        let _ = writeln!(t);
    }
    let acted: Vec<&Decision> = ds.iter().collect();
    if !acted.is_empty() {
        let _ = writeln!(t, "Autonomy this run (a shadow line is what a level would have done; a level that is on acts only on this digest's priority):
");
        for d in acted {
            let _ = writeln!(
                t,
                "- {} {}: {} {}: {}; {} {}{}",
                d.mode.label(),
                d.level.label(),
                d.cluster,
                d.key,
                d.trigger,
                if d.mode == Mode::On && d.acted() {
                    "did:"
                } else {
                    "would:"
                },
                d.proposal,
                d.suppressed
                    .as_ref()
                    .map_or(String::new(), |s| format!(" (held back, {s})"))
            );
        }
        let _ = writeln!(t);
    }
}

/// The priority and the facts behind it, first in the digest.
fn needs_attention(t: &mut String, p: &Priority) {
    let _ = writeln!(t, "## Needs attention: {}\n", p.level.label());
    if p.reasons.is_empty() {
        let _ = writeln!(
            t,
            "No new significant lead, no lead at L2 or higher, no health alert and no case clock due.\n"
        );
        return;
    }
    for r in p.reasons.iter().take(LEAD_LINES) {
        let tag = match r.level {
            Level::High => "**high**",
            Level::Medium => "medium",
            Level::Low => "low",
        };
        let _ = writeln!(t, "- {tag}: {}", r.text);
    }
    if p.reasons.len() > LEAD_LINES {
        let _ = writeln!(t, "- … {} more below", p.reasons.len() - LEAD_LINES);
    }
    let _ = writeln!(
        t,
        "\nSet from the leads' tiers and agent grades, health alerts and case clocks; a model suggestion never sets it.\n"
    );
}

/// The model's suggestions on this run's leads, when triage is on:
/// suggestions, never labels.
fn model_suggestions(t: &mut String, leads: &[Lead], tr: &TriageReport) {
    if !tr.enabled {
        return;
    }
    let with: Vec<&Lead> = leads.iter().filter(|l| l.suggestion.is_some()).collect();
    let _ = writeln!(t, "\n## Model suggestions ({})\n", with.len());
    let model = if tr.model.is_empty() {
        String::new()
    } else {
        format!(" (`{}`)", one_line(&tr.model, 60))
    };
    let from = if tr.backend == super::triage::Backend::Claude.label() {
        format!(
            "From Claude through the admin's Claude Code login on the runner{model}, shown only leads from web archive indexes and urlquery, defanged and without IP addresses"
        )
    } else {
        format!("From a model on the admin's own machine or network{model}")
    };
    let _ = writeln!(
        t,
        "{from}: suggestions only, never labels. Review decides; they are saved in `labels/{}`.\n",
        tr.file()
    );
    if with.is_empty() {
        let _ = writeln!(t, "None.");
    }
    for l in with.iter().take(LEAD_LINES * 2) {
        let Some(s) = &l.suggestion else { continue };
        let _ = writeln!(
            t,
            "- {} [{}, {}]: suggests {}: {}{}",
            l.name(),
            l.tier.label(),
            l.grade.code(),
            s.label,
            one_line(&crate::suggest::defang_all(&s.reason), 160),
            if l.against_rule() {
                format!(
                    ". Against the labelling rule: agent needs L2 or higher, and this lead is {}, so unsure is the most it allows",
                    l.grade.code()
                )
            } else {
                String::new()
            }
        );
    }
    if with.len() > LEAD_LINES * 2 {
        let _ = writeln!(t, "- … {} more", with.len() - LEAD_LINES * 2);
    }
    let _ = writeln!(
        t,
        "\nAsked {}, answered {}, reused {}, not asked {}{}.{}",
        tr.asked,
        tr.answered,
        tr.reused,
        tr.left,
        if tr.withheld > 0 {
            format!(", withheld {} (not a hosted source)", tr.withheld)
        } else {
            String::new()
        },
        tr.note
            .as_ref()
            .map(|n| format!(" {}.", one_line(n, 200)))
            .unwrap_or_default()
    );
}

/// The host of a record's own URL, lowercased.
fn outer_host(url: &str) -> String {
    reqwest::Url::parse(url)
        .ok()
        .and_then(|u| u.host_str().map(str::to_ascii_lowercase))
        .unwrap_or_default()
}

/// Whether a hit shows what a request did rather than how it was sent: not
/// one of the kinds that describe the route (relay, cache buster, self-id,
/// header, outcome, as `sc_core`'s context kinds), and not a carrier rule
/// that only names the record's own host. Every watch source is a relay's
/// or carrier's own host with its own rule, so only these hits say more
/// than "this record came from the source it was pulled from".
fn indicative_hit(h: &Hit, host: &str) -> bool {
    match h.kind {
        k if sc_core::is_context_kind(k) => false,
        IndicatorKind::Carrier => {
            let m = h.matched.to_ascii_lowercase();
            m.is_empty() || !host.contains(&m)
        }
        _ => true,
    }
}

/// Whether a record has at least one [`indicative_hit`].
pub fn indicative(r: &ObsResult) -> bool {
    let host = outer_host(&r.obs.url);
    r.hits.iter().any(|h| indicative_hit(h, &host))
}

/// A host as printed: characters a host name cannot hold (quotes,
/// backticks, brackets, trailing punctuation from the text it was cut
/// from) trimmed from both ends, lowercased, so a printed host never
/// breaks out of its code span.
pub fn clean_host(h: &str) -> String {
    let ok = |c: char| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | ':');
    h.trim_matches(|c: char| !ok(c))
        .trim_end_matches('.')
        .to_ascii_lowercase()
}

/// How many significant records outside any cluster the digest lists.
const LONE_LINES: usize = 15;

/// Significant records that joined no cluster: without a cluster line they
/// would show only as a host elsewhere in the digest, with no rule context.
/// New records first.
fn lone_significant(t: &mut String, a: &Analysis, new_ids: &BTreeSet<String>) {
    let mut lone: Vec<&ObsResult> = a
        .results
        .iter()
        .filter(|r| r.tier == Tier::Significant && r.cluster.is_none())
        .collect();
    let fresh = lone.iter().filter(|r| new_ids.contains(&r.obs.id)).count();
    lone.sort_by(|x, y| {
        let new = |r: &ObsResult| !new_ids.contains(&r.obs.id);
        new(x)
            .cmp(&new(y))
            .then(y.score.cmp(&x.score))
            .then(y.obs.ts.cmp(&x.obs.ts))
    });
    let _ = writeln!(
        t,
        "\n## Significant records outside any cluster ({}, {fresh} new)\n",
        lone.len()
    );
    if lone.is_empty() {
        let _ = writeln!(t, "None.");
    }
    for r in lone.iter().take(LONE_LINES) {
        let host = r
            .target_host
            .clone()
            .unwrap_or_else(|| outer_host(&r.obs.url));
        let rules: BTreeSet<&str> = r.hits.iter().map(|h| h.rule_id.as_str()).collect();
        let _ = writeln!(
            t,
            "- `{}` [{}] score {}{}: {}; {} {}",
            defang_host(&clean_host(&host)),
            r.tier.label(),
            r.score,
            if new_ids.contains(&r.obs.id) {
                ", new"
            } else {
                ""
            },
            rules.into_iter().collect::<Vec<_>>().join(", "),
            r.obs.source,
            sc_core::fmt_ts(r.obs.ts)
        );
    }
    if lone.len() > LONE_LINES {
        let _ = writeln!(t, "- … {} more", lone.len() - LONE_LINES);
    }
}

/// Noise-tier clusters: listed for completeness, never counted in the
/// headline. Most are capture chains, one relay's captures of one page
/// joined by time with no indicator beyond the relay.
fn noise_clusters(t: &mut String, a: &Analysis) {
    let noise: Vec<_> = a
        .clusters
        .iter()
        .filter(|c| c.tier < Tier::Suggestive)
        .collect();
    let _ = writeln!(t, "\n## Noise-tier clusters ({})\n", noise.len());
    if noise.is_empty() {
        let _ = writeln!(t, "None.");
    }
    for c in noise.iter().take(LEAD_LINES) {
        let _ = writeln!(
            t,
            "- {}: {} records, {} → {}; targets {}; rules {}",
            cluster_ref(a, &c.id),
            c.members.len(),
            sc_core::fmt_ts(c.start),
            sc_core::fmt_ts(c.end),
            top_keys(&c.target_hosts, 3)
                .iter()
                .map(|h| format!("`{}`", defang_host(&clean_host(h))))
                .collect::<Vec<_>>()
                .join(", "),
            top_keys(&c.rules, 4).join(", ")
        );
    }
    if noise.len() > LEAD_LINES {
        let _ = writeln!(t, "- … {} more", noise.len() - LEAD_LINES);
    }
}

/// `C3 k-3f9a2c1b`: a cluster's number in this analysis and its stable key.
fn cluster_ref(a: &Analysis, id: &str) -> String {
    match a.cluster(id) {
        Some(c) if !c.key.is_empty() => format!("{} {}", c.id, c.key),
        _ => id.to_string(),
    }
}

/// How many lines each lead section shows.
const LEAD_LINES: usize = 10;

/// Candidate fleets, escalations and common features over the window:
/// descriptive leads for the admin, defanged, never merges.
fn leads(t: &mut String, a: &Analysis) {
    let more = |t: &mut String, n: usize| {
        if n > LEAD_LINES {
            let _ = writeln!(t, "- … {} more", n - LEAD_LINES);
        }
    };
    let _ = writeln!(t, "\n## Candidate fleets ({})\n", a.candidate_fleets.len());
    if a.candidate_fleets.is_empty() {
        let _ = writeln!(t, "None.");
    }
    for f in a.candidate_fleets.iter().take(LEAD_LINES) {
        let kinds: Vec<&str> = f.kinds.iter().map(|k| k.label()).collect();
        let _ = writeln!(
            t,
            "- {}: {}; {} soft link(s): {} (weakest pair {:.2})",
            f.id,
            f.clusters
                .iter()
                .map(|id| cluster_ref(a, id))
                .collect::<Vec<_>>()
                .join(", "),
            f.links,
            kinds.join(", "),
            f.strength
        );
    }
    more(t, a.candidate_fleets.len());
    if !a.candidate_fleets.is_empty() {
        let _ = writeln!(
            t,
            "\nProposals only: merge one in a case with `swarmchase case fleet merge <case> <key>...`."
        );
    }

    let _ = writeln!(t, "\n## Escalations ({})\n", a.escalations.len());
    if a.escalations.is_empty() {
        let _ = writeln!(t, "None.");
    }
    for e in a.escalations.iter().take(LEAD_LINES) {
        let clusters = if e.clusters.is_empty() {
            String::new()
        } else {
            format!(
                "; {}",
                e.clusters
                    .iter()
                    .map(|id| cluster_ref(a, id))
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        };
        let _ = writeln!(
            t,
            "- `{}`: {}, {} → {}{clusters}",
            sc_core::defang_hosts(&one_line(&format!("{}{}", e.host, e.path), 100)),
            e.route_line(),
            sc_core::fmt_ts(e.start),
            sc_core::fmt_ts(e.end)
        );
    }
    more(t, a.escalations.len());

    let _ = writeln!(t, "\n## Common features ({})\n", a.common_features.len());
    if a.common_features.is_empty() {
        let _ = writeln!(t, "None.");
    } else {
        let _ = writeln!(
            t,
            "Linking values shared too widely to link on: a popular or copied value, not one operator's.\n"
        );
    }
    for c in a.common_features.iter().take(LEAD_LINES) {
        let _ = writeln!(
            t,
            "- `{}`: {} records on {} hosts, {} → {}; {}",
            sc_core::defang_feature(&one_line(&c.feature.to_string(), 90)),
            c.records,
            c.hosts,
            sc_core::fmt_ts(c.start),
            sc_core::fmt_ts(c.end),
            sc_core::defang(&one_line(&c.reason, 120))
        );
    }
    more(t, a.common_features.len());
}

fn run_label(r: &ClusterRun) -> String {
    format!(
        "{} {} run at {} ({} records)",
        r.cluster,
        r.key,
        sc_core::fmt_ts(r.start),
        r.records
    )
}

fn cluster_line(c: &ClusterSummary) -> String {
    format!(
        "{}{} [{}] score {}, {} records, {} → {}; targets {}; rules {}",
        c.id,
        if c.key.is_empty() {
            String::new()
        } else {
            format!(" {}", c.key)
        },
        c.tier.label(),
        c.score,
        c.records,
        sc_core::fmt_ts(c.start),
        sc_core::fmt_ts(c.end),
        c.targets
            .iter()
            .map(|h| format!("`{}`", defang_host(h)))
            .collect::<Vec<_>>()
            .join(", "),
        c.rules.join(", ")
    )
}

#[cfg(test)]
mod tests {
    use super::super::DAY;
    use super::*;
    use sc_core::bursts::archive_bursts;
    use sc_core::{Observation, Rules, analyze};

    /// A digest of `a` with no source reports, bursts or case lines unless given.
    fn write(
        stamp: &str,
        a: &Analysis,
        prev: &Summary,
        next: &Summary,
        new_ids: &BTreeSet<String>,
        health: &Health,
        bursts: &[ArchiveBurst],
    ) -> Digest {
        digest(&DigestInput {
            stamp,
            analysis: a,
            prev,
            next,
            new_ids,
            health,
            bursts,
            cases: &CaseReport::default(),
            window_days: 30,
            leads: &[],
            triage: &TriageReport::default(),
            priority: &super::super::priority::assess(&[], &health.alerts, &[]),
            attention: &Default::default(),
            autonomy: &[],
        })
    }

    #[test]
    fn a_cluster_whose_earliest_record_left_the_window_is_not_new() {
        use super::super::ledger::Ledger;
        let rules = sc_core::Rules::default_rules();
        let t0 = 1_791_000_000;
        let all: Vec<sc_core::Observation> = (0..5)
            .map(|i| sc_core::Observation {
                id: format!("r{i}"),
                source: "wayback".into(),
                ts: t0 + i * 30,
                url: format!(
                    "https://r.jina.ai/https://portal.example.gov/q?id=1'%20OR%201=1--&uqtag=run7&n={i}"
                ),
                ..Default::default()
            })
            .collect();
        let ids: BTreeSet<String> = all.iter().map(|o| o.id.clone()).collect();
        let mut ledger = Ledger::new();
        let a1 = sc_core::analyze(all.clone(), &rules);
        let s1 = summarise(&a1, &Summary::default(), "2026-10-12T00:00:00Z".into());
        ledger.observe(&a1, "20261012T000000Z", t0, &ids);
        // The earliest record leaves the window: the summary's key changes.
        let a2 = sc_core::analyze(all[1..].to_vec(), &rules);
        let s2 = summarise(&a2, &s1, "2026-10-12T06:00:00Z".into());
        assert!(s2.clusters.keys().all(|k| !s1.clusters.contains_key(k)));
        let o2 = ledger.observe(&a2, "20261012T060000Z", t0 + 6 * 3600, &BTreeSet::new());
        let none = BTreeSet::new();
        // Against the bare summary it looks new; against its thread it is not.
        assert!(!super::super::triage::leads(&a2, &s1, &s2, &none).is_empty());
        let base = baseline(&s1, &s2, &ledger, &o2, "20261012T060000Z");
        let leads = super::super::triage::leads(&a2, &base, &s2, &none);
        assert!(leads.is_empty(), "{leads:?}");
        // A thread not seen on the previous run is still new.
        let mut stale = s1.clone();
        stale.generated = "2026-10-11T00:00:00Z".into();
        let base = baseline(&stale, &s2, &ledger, &o2, "20261012T060000Z");
        assert!(!super::super::triage::leads(&a2, &base, &s2, &none).is_empty());
    }

    #[test]
    fn digest_reports_new_clusters_and_endpoints_once() {
        let rules = Rules::default_rules();
        let obs: Vec<Observation> = (0..6)
            .map(|i| Observation {
                id: format!("r{i}"),
                ts: 1_791_000_000 + i * 30,
                url: format!(
                    "https://r.jina.ai/https://portal.example.gov/q?id=1'%20OR%201=1--&uqtag=run7&n={i}"
                ),
                ..Default::default()
            })
            .collect();
        let a = analyze(obs, &rules);
        assert!(!a.clusters.is_empty());
        let ids: BTreeSet<String> = a.results.iter().map(|r| r.obs.id.clone()).collect();
        let quiet = Health::default();

        let first = summarise(&a, &Summary::default(), "t1".into());
        let d1 = write("t1", &a, &Summary::default(), &first, &ids, &quiet, &[]);
        assert!(d1.changed, "{}", d1.text);
        assert!(d1.text.contains("portal[.]example[.]gov"));

        let second = summarise(&a, &first, "t2".into());
        let d2 = write("t2", &a, &first, &second, &BTreeSet::new(), &quiet, &[]);
        assert!(!d2.changed, "{}", d2.text);

        let alert = Health {
            alerts: vec!["`s` has failed 2 runs in a row".into()],
            ..Default::default()
        };
        let d3 = write("t3", &a, &second, &second, &BTreeSet::new(), &alert, &[]);
        assert!(
            d3.changed && d3.text.contains("## Health (1)"),
            "{}",
            d3.text
        );
    }

    #[test]
    fn digest_opens_with_priority_and_shows_suggestions_as_suggestions() {
        use crate::suggest::Suggestion;
        use sc_core::agentness::AgentLevel;
        let (a, ids) = super::super::triage::tests::analysis();
        let next = summarise(&a, &Summary::default(), "t1".into());
        let mut leads = super::super::triage::leads(&a, &Summary::default(), &next, &ids);
        assert!(!leads.is_empty());
        leads[0].grade = AgentLevel::SelfDescribed;
        leads[0].suggestion = Some(Suggestion {
            label: "agent".into(),
            reason: "relay via r.jina.ai plus SQLi".into(),
            model: "fake-local".into(),
        });
        let health = Health::default();
        let priority = super::super::priority::assess(&leads, &health.alerts, &[]);
        let triage = TriageReport {
            enabled: true,
            model: "fake-local".into(),
            asked: 2,
            answered: 1,
            ..Default::default()
        };
        let d = digest(&DigestInput {
            stamp: "t1",
            analysis: &a,
            prev: &Summary::default(),
            next: &next,
            new_ids: &ids,
            health: &health,
            bursts: &[],
            cases: &CaseReport::default(),
            window_days: 30,
            leads: &leads,
            triage: &triage,
            priority: &priority,
            attention: &Default::default(),
            autonomy: &[],
        });
        let first = d.text.find("## ").unwrap();
        assert!(
            d.text[first..].starts_with(&format!("## Needs attention: {}", priority.level.label())),
            "{}",
            d.text
        );
        assert!(d.text.find("## Needs attention").unwrap() < d.text.find("## Health").unwrap());
        assert!(d.text.contains("## Model suggestions (1)"), "{}", d.text);
        assert!(
            d.text.contains("suggestions only, never labels"),
            "{}",
            d.text
        );
        let line = d
            .text
            .lines()
            .find(|l| l.contains("suggests agent"))
            .unwrap();
        assert!(line.contains("r[.]jina[.]ai"), "{line}");
        assert!(
            line.contains("Against the labelling rule: agent needs L2 or higher"),
            "{line}"
        );
        assert!(d.text.contains("Asked 2, answered 1"), "{}", d.text);
        assert!(d.text.contains("labels/suggestions-local.ndjson"));

        // Claude through Claude Code: says so, its file, and what was withheld.
        let claude = TriageReport {
            backend: "claude".into(),
            model: "claude-opus-5-5".into(),
            withheld: 1,
            ..triage.clone()
        };
        let d = digest(&DigestInput {
            stamp: "t1",
            analysis: &a,
            prev: &Summary::default(),
            next: &next,
            new_ids: &ids,
            health: &health,
            bursts: &[],
            cases: &CaseReport::default(),
            window_days: 30,
            leads: &leads,
            triage: &claude,
            priority: &priority,
            attention: &Default::default(),
            autonomy: &[],
        });
        assert!(d.text.contains("Claude Code login"), "{}", d.text);
        assert!(d.text.contains("labels/suggestions-claude-watch.ndjson"));
        assert!(
            d.text.contains("withheld 1 (not a hosted source)"),
            "{}",
            d.text
        );

        // Triage off: no suggestions block; a quiet run is low priority.
        let quiet = write(
            "t2",
            &a,
            &next,
            &next,
            &BTreeSet::new(),
            &Health::default(),
            &[],
        );
        assert!(
            !quiet.text.contains("## Model suggestions"),
            "{}",
            quiet.text
        );
        assert!(
            quiet.text.contains("## Needs attention: low"),
            "{}",
            quiet.text
        );
    }

    #[test]
    fn a_failed_source_shows_a_short_reason() {
        let url = "https://web.archive.org/cdx/search/cdx?url=r.jina.ai/*&from=20261001&output=json&limit=5000";
        let gave_up =
            anyhow::anyhow!("GET {url}: HTTP 504 Gateway Timeout: <html>upstream timed out</html>")
                .context("gave up after 3 attempts");
        assert_eq!(short_reason(&gave_up), "HTTP 504 after 3 attempts");
        let refused = anyhow::anyhow!("tcp connect error: Connection refused")
            .context(format!("error sending request for url ({url})"))
            .context(format!("GET {url}"))
            .context("gave up after 2 attempts");
        assert_eq!(
            short_reason(&refused),
            "error sending request for url: tcp connect error: Connection refused after 2 attempts"
        );
        let fatal = anyhow::anyhow!("GET {url}: HTTP 403 Forbidden: denied");
        assert_eq!(short_reason(&fatal), "HTTP 403");
        let parse =
            anyhow::anyhow!("expected value at line 1 column 1").context("parsing a CDX page");
        assert_eq!(
            short_reason(&parse),
            "parsing a CDX page: expected value at line 1 column 1"
        );

        // In the digest's status cell, with no part of the URL.
        let a = analyze(Vec::new(), &Rules::default_rules());
        let mut rep = SourceReport::new("wayback-jina", "wayback");
        rep.requests = 3;
        rep.error = Some(short_reason(&gave_up));
        let health = Health {
            sources: vec![rep],
            ..Default::default()
        };
        let s = summarise(&a, &Summary::default(), "t1".into());
        let d = write("t1", &a, &s, &s, &BTreeSet::new(), &health, &[]);
        assert!(
            d.text
                .contains("| wayback-jina | 0 | 0 | 3 |  | error: HTTP 504 after 3 attempts |"),
            "{}",
            d.text
        );
        assert!(!d.text.contains("web.archive.org"), "{}", d.text);
        // The health block, first in the digest, says what the failure lost.
        let health_at = d.text.find("## Health").unwrap();
        assert!(health_at < d.text.find("## Sources").unwrap());
        assert!(
            d.text.contains(
                "`wayback-jina` failed (HTTP 504 after 3 attempts). Lost this run: archive captures"
            ),
            "{}",
            d.text
        );
    }

    #[test]
    fn health_block_names_lost_capability_coverage_and_quiet_sources() {
        let a = analyze(Vec::new(), &Rules::default_rules());
        let s = summarise(&a, &Summary::default(), "t1".into());
        let skipped = SourceReport {
            skipped: Some("skipped: URLQUERY_APIKEY not set".into()),
            ..SourceReport::new("urlquery-jina", "urlquery")
        };
        let gh = SourceReport {
            coverage: Some(Coverage {
                unit: "hours",
                read: 6,
                available: 60,
                skipped: 54,
                canary: Some(true),
                ..Default::default()
            }),
            quiet: Some((5, false)),
            ..SourceReport::new("gharchive-relays", "gharchive")
        };
        let stopped = SourceReport {
            pulled: 1000,
            stopped: Some("HTTP 503 after 7 attempts".into()),
            ..SourceReport::new("jina-reader", "wayback")
        };
        let health = Health {
            sources: vec![skipped, gh, stopped],
            ..Default::default()
        };
        let d = write("t1", &a, &s, &s, &BTreeSet::new(), &health, &[]);
        for want in [
            "**No submit-time source ran.** Timing links, pace, agent grades above L2 and interaction edges (S1–S6) are unavailable",
            "`urlquery-jina` skipped (URLQUERY_APIKEY not set). Lost: submit-time records",
            "`gharchive-relays` read 6 of 60 hours, 54 skipped",
            "`gharchive-relays` has pulled nothing in 5 runs and never has; its canary passed",
            "`jina-reader` stopped early (HTTP 503 after 7 attempts) after 1000 records",
            "| gharchive-relays | 0 | 0 | 0 | 6 of 60 hours, 54 skipped, canary ok | complete |",
            "| jina-reader | 1000 | 0 | 0 |  | stopped early: HTTP 503 after 7 attempts |",
        ] {
            assert!(d.text.contains(want), "missing {want:?} in\n{}", d.text);
        }
        // Lost capability alone does not mail the digest; alerts do.
        assert!(!d.changed, "{}", d.text);

        // A submit-time source that ran clears the run-wide line.
        let ran = SourceReport::new("urlquery-jina", "urlquery");
        let health = Health {
            sources: vec![ran],
            ..Default::default()
        };
        let d = write("t2", &a, &s, &s, &BTreeSet::new(), &health, &[]);
        assert!(!d.text.contains("No submit-time source"), "{}", d.text);
        assert!(d.text.contains("Every source ran."), "{}", d.text);
    }

    #[test]
    fn headline_counts_indicators_beyond_the_relay_and_lists_lone_records() {
        let rules = Rules::default_rules();
        let rec = |id: &str, ts: i64, url: &str| Observation {
            id: id.into(),
            source: "wayback".into(),
            ts,
            url: url.into(),
            ..Default::default()
        };
        let t0 = 1_791_000_000;
        let obs = vec![
            // The relay's own rule only.
            rec("plain", t0, "https://r.jina.ai/https://news.example/story"),
            // The carrier's own rule only.
            rec("echo", t0 + 5000, "https://httpbin.org/get?x=1"),
            // An exploit payload through the relay.
            rec(
                "sqli",
                t0 + 90_000,
                "https://r.jina.ai/https://portal.example.gov/q?id=1'%20OR%201=1--",
            ),
        ];
        let a = analyze(obs, &rules);
        let with: Vec<&str> = a
            .results
            .iter()
            .filter(|r| indicative(r))
            .map(|r| r.obs.id.as_str())
            .collect();
        assert_eq!(with, ["sqli"]);
        let s = summarise(&a, &Summary::default(), "t1".into());
        let ids = BTreeSet::from(["sqli".to_string()]);
        let d = write("t1", &a, &s, &s, &ids, &Health::default(), &[]);
        assert!(
            d.text
                .contains("3 records, 1 with an indicator beyond the relay or carrier"),
            "{}",
            d.text
        );
        assert!(!d.text.contains("flagged"), "{}", d.text);
        let lone: Vec<&ObsResult> = a
            .results
            .iter()
            .filter(|r| r.tier == Tier::Significant && r.cluster.is_none())
            .collect();
        assert_eq!(lone.len(), 1, "one significant record with nothing to join");
        assert!(
            d.text.contains(&format!(
                "## Significant records outside any cluster ({}, ",
                lone.len()
            )),
            "{}",
            d.text
        );
        for r in lone {
            let line = d
                .text
                .lines()
                .find(|l| {
                    l.contains(&defang_host(r.target_host.as_deref().unwrap()))
                        && l.contains("[significant] score")
                })
                .unwrap();
            assert!(
                line.contains("exploit.") && line.contains(", new:"),
                "{line}"
            );
        }
        assert!(d.text.contains("## Noise-tier clusters ("), "{}", d.text);
    }

    #[test]
    fn hosts_are_cleaned_before_printing_and_summarising() {
        assert_eq!(clean_host("example.com`"), "example.com");
        assert_eq!(clean_host("\"Example.COM\"),"), "example.com");
        assert_eq!(clean_host("a.example."), "a.example");
        assert_eq!(clean_host("`"), "");
        let e = |t| Endpoint {
            first_seen: t,
            last_seen: t,
            max_tier: Tier::Suggestive,
        };
        let prev = Summary {
            endpoints: BTreeMap::from([
                ("example.com`".to_string(), e(10)),
                ("example.com".to_string(), e(20)),
            ]),
            ..Default::default()
        };
        let a = analyze(Vec::new(), &Rules::default_rules());
        let s = summarise(&a, &prev, "t".into());
        assert_eq!(s.endpoints.len(), 1);
        let m = &s.endpoints["example.com"];
        assert_eq!((m.first_seen, m.last_seen), (10, 20));
    }

    #[test]
    fn digest_lists_candidate_fleets_by_key() {
        let mut rules = Rules::default_rules();
        rules.set.soft_links.fleet_min_lr = 1.5;
        let a = analyze(crate::case::fleet::tests::two_runs(), &rules);
        assert_eq!(a.candidate_fleets.len(), 1);
        let s = summarise(&a, &Summary::default(), "t1".into());
        let d = write("t1", &a, &s, &s, &BTreeSet::new(), &Health::default(), &[]);
        assert!(d.text.contains("## Candidate fleets (1)"), "{}", d.text);
        for c in &a.clusters {
            assert!(
                d.text.contains(&format!("{} {}", c.id, c.key)),
                "{}",
                d.text
            );
        }
        assert!(d.text.contains("case fleet merge"), "{}", d.text);
        assert!(d.text.contains("## Escalations ("), "{}", d.text);
        assert!(d.text.contains("## Common features ("), "{}", d.text);
        // A standing proposal alone is not news.
        assert!(!d.changed, "{}", d.text);
    }

    #[test]
    fn digest_reports_reruns_across_clusters() {
        let rules = Rules::default_rules();
        let hosts = ["a", "b", "c", "d", "e", "f"];
        let run = |tag: &str, start: i64| -> Vec<Observation> {
            hosts
                .iter()
                .enumerate()
                .map(|(i, h)| Observation {
                    id: format!("{tag}-{i}"),
                    ts: start + i as i64 * 40,
                    url: format!(
                        "https://r.jina.ai/https://{h}.portal.example/q?id=1'%20OR%201=1--&uqtag={tag}"
                    ),
                    ..Default::default()
                })
                .collect()
        };
        let mut obs = run("first7", 1_791_000_000);
        obs.extend(run("second9", 1_791_000_000 + 3 * DAY));
        let a = analyze(obs, &rules);
        assert!(a.clusters.len() >= 2, "{:?}", a.clusters.len());
        let new_ids: BTreeSet<String> = (0..hosts.len()).map(|i| format!("second9-{i}")).collect();
        let next = summarise(&a, &Summary::default(), "t1".into());
        let quiet = Health::default();
        let d = write("t1", &a, &next, &next, &new_ids, &quiet, &[]);
        assert!(d.changed, "{}", d.text);
        assert!(d.text.contains("## Possible reruns (1)"), "{}", d.text);
        assert!(d.text.contains("6 shared hosts"), "{}", d.text);
        assert!(d.text.contains("`a[.]portal[.]example`"), "{}", d.text);

        // The same records with nothing new: no rerun to report.
        let d = write("t2", &a, &next, &next, &BTreeSet::new(), &quiet, &[]);
        assert!(d.text.contains("## Possible reruns (0)"), "{}", d.text);
    }

    #[test]
    fn digest_reports_archive_bursts_on_sparse_hosts() {
        let rules = Rules::default_rules();
        let now = 1_791_000_000;
        let cap = |id: String, ts: i64, url: String| Observation {
            id,
            source: "wayback".into(),
            ts,
            url,
            ..Default::default()
        };
        let mut store = Vec::new();
        // A rarely captured host, then six captures within minutes.
        store.push(cap(
            "s-old1".into(),
            now - 50 * DAY,
            "https://sparse.example/".into(),
        ));
        store.push(cap(
            "s-old2".into(),
            now - 20 * DAY,
            "https://sparse.example/".into(),
        ));
        for i in 0..6 {
            store.push(cap(
                format!("s{i}"),
                now - 3600 + i * 60,
                format!("https://sparse.example/report?page={i}"),
            ));
        }
        // A host captured all day, every day: a burst there is normal.
        for d in 0..60 {
            for h in 0..24 {
                store.push(cap(
                    format!("b{d}-{h}"),
                    now - d * DAY - h * 3600 - 7200,
                    "https://busy.example/".into(),
                ));
            }
        }
        for i in 0..6 {
            store.push(cap(
                format!("b-new{i}"),
                now - 1800 + i * 30,
                "https://busy.example/".into(),
            ));
        }
        let new_ids: BTreeSet<String> = store
            .iter()
            .filter(|o| o.ts > now - 2 * 3600)
            .map(|o| o.id.clone())
            .collect();
        let bursts = archive_bursts(&store, &new_ids, &rules, now);
        assert_eq!(bursts.len(), 1, "{bursts:?}");
        assert_eq!(bursts[0].host, "sparse.example");
        assert_eq!((bursts[0].count, bursts[0].distinct_urls), (6, 6));

        // A burst already reported in an earlier run is not repeated.
        assert!(archive_bursts(&store, &BTreeSet::new(), &rules, now).is_empty());

        let a = analyze(Vec::new(), &rules);
        let s = Summary::default();
        let d = write("t1", &a, &s, &s, &new_ids, &Health::default(), &bursts);
        assert!(d.changed, "{}", d.text);
        assert!(d.text.contains("## Archive bursts (1)"), "{}", d.text);
        assert!(
            d.text.contains("`sparse[.]example`: 6 captures"),
            "{}",
            d.text
        );
        assert!(!d.text.contains("busy[.]example"), "{}", d.text);
    }

    #[test]
    fn a_burst_behind_a_relay_counts_the_target_captures_with_indicators() {
        let rules = Rules::default_rules();
        let now = 1_791_000_000;
        // Six captures through a relay of one sparse target, each carrying
        // an injection payload: the burst is the target's, not the relay's.
        let store: Vec<Observation> = (0..6)
            .map(|i| Observation {
                id: format!("j{i}"),
                source: "wayback".into(),
                ts: now - 3600 + i * 60,
                url: format!("https://r.jina.ai/https://sparse.example/q?id=1'%20OR%201=1--&p={i}"),
                ..Default::default()
            })
            .collect();
        let new_ids: BTreeSet<String> = store.iter().map(|o| o.id.clone()).collect();
        let bursts = archive_bursts(&store, &new_ids, &rules, now);
        assert_eq!(bursts.len(), 1, "{bursts:?}");
        assert_eq!(bursts[0].host, "sparse.example");
        let a = analyze(store, &rules);
        let s = Summary::default();
        let d = write("t1", &a, &s, &s, &new_ids, &Health::default(), &bursts);
        assert!(
            d.text
                .contains("6 distinct URLs, 6 with an indicator beyond the relay"),
            "{}",
            d.text
        );
    }

    #[test]
    fn a_deferred_source_is_lost_capability_not_an_error() {
        let r = SourceReport {
            deferred: true,
            ..SourceReport::new("late", "wayback")
        };
        assert_eq!(r.status(), "deferred");
        let lost = lost_lines(std::slice::from_ref(&r));
        assert!(
            lost.iter().any(|l| l.starts_with("`late` deferred")),
            "{lost:?}"
        );
        let a = analyze(Vec::new(), &Rules::default_rules());
        let s = Summary::default();
        let health = Health {
            sources: vec![r],
            ..Default::default()
        };
        let d = write("t1", &a, &s, &s, &BTreeSet::new(), &health, &[]);
        assert!(
            d.text
                .contains("| late | 0 | 0 | 0 |  | deferred: collection deadline reached |"),
            "{}",
            d.text
        );
        assert!(!d.changed, "a deferral alone is not mailed: {}", d.text);
    }

    #[test]
    fn a_source_error_without_an_alert_does_not_mark_the_run_changed() {
        let a = analyze(Vec::new(), &Rules::default_rules());
        let s = Summary::default();
        let health = Health {
            sources: vec![SourceReport {
                error: Some("HTTP 503".into()),
                ..SourceReport::new("down", "wayback")
            }],
            ..Default::default()
        };
        let d = write("t1", &a, &s, &s, &BTreeSet::new(), &health, &[]);
        assert!(d.text.contains("error: HTTP 503"), "{}", d.text);
        assert!(!d.changed, "{}", d.text);
    }
}
