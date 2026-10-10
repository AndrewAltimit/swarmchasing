//! The run digest: what changed since the previous run, how the sources
//! fared, and the leads (reruns, archive bursts, case status) for the admin.

use super::cases::CaseReport;
use crate::util::{one_line, top_keys};
use sc_core::bursts::ArchiveBurst;
use sc_core::recurrence::{ClusterRun, cluster_reruns};
use sc_core::{Analysis, Tier, defang_host};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

/// What the previous run knew, so the digest can say what changed.
#[derive(Debug, Default, Serialize, Deserialize)]
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
pub struct SourceReport {
    pub name: String,
    pub pulled: usize,
    pub new: usize,
    pub pending: bool,
    /// HTTP requests made, retries included.
    pub requests: usize,
    pub error: Option<String>,
    /// Why the source did not run (e.g. no API key). Not an error.
    pub skipped: Option<String>,
}

impl SourceReport {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            pulled: 0,
            new: 0,
            pending: false,
            requests: 0,
            error: None,
            skipped: None,
        }
    }
}

/// How the run's sources fared, with warnings. Any alert or source error
/// makes the run count as changed, so it is emailed.
#[derive(Default)]
pub struct Health {
    pub sources: Vec<SourceReport>,
    pub alerts: Vec<String>,
    pub notes: Vec<String>,
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
}

pub struct Digest {
    pub text: String,
    pub changed: bool,
}

pub fn summarise(a: &Analysis, prev: &Summary, generated: String) -> Summary {
    let mut s = Summary {
        generated,
        clusters: BTreeMap::new(),
        endpoints: prev.endpoints.clone(),
    };
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
        let Some(h) = &r.target_host else { continue };
        let e = s.endpoints.entry(h.clone()).or_insert(Endpoint {
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

pub fn digest(d: &DigestInput) -> Digest {
    let (a, prev, next, health) = (d.analysis, d.prev, d.next, d.health);
    let mut t = String::new();
    let _ = writeln!(t, "# Watch digest {}\n", d.stamp);
    let _ = writeln!(
        t,
        "Unverified leads from passive collection. Review before acting on anything here.\n"
    );

    let _ = writeln!(t, "## Sources\n");
    let _ = writeln!(
        t,
        "| Source | Pulled | New | Requests | Status |\n|---|---:|---:|---:|---|"
    );
    for s in &health.sources {
        let status = match (&s.error, s.pending) {
            _ if s.skipped.is_some() => s.skipped.clone().unwrap_or_default(),
            (Some(e), _) => format!("error: {}", one_line(e, 160)),
            (None, true) => "partial, continues next run".into(),
            (None, false) => "complete".into(),
        };
        let _ = writeln!(
            t,
            "| {} | {} | {} | {} | {status} |",
            s.name, s.pulled, s.new, s.requests
        );
    }

    let _ = writeln!(t, "\n## Health ({})\n", health.alerts.len());
    if health.alerts.is_empty() {
        let _ = writeln!(t, "No source collapses or rule drift.");
    }
    for x in &health.alerts {
        let _ = writeln!(t, "- {x}");
    }
    for x in &health.notes {
        let _ = writeln!(t, "\n{x}");
    }

    let tier = |x| a.tier_counts.get(&x).copied().unwrap_or(0);
    let _ = writeln!(
        t,
        "\n## Last {} days\n\n{} records, {} flagged ({} significant, {} suggestive), {} clusters.\n",
        d.window_days,
        a.total,
        a.flagged,
        tier(Tier::Significant),
        tier(Tier::Suggestive),
        a.clusters.len()
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
            defang_host(h),
            e.max_tier.label(),
            sc_core::fmt_ts(e.first_seen),
            sc_core::fmt_ts(e.last_seen)
        );
    }

    let mut targets: BTreeMap<&str, usize> = BTreeMap::new();
    for r in &a.results {
        if r.tier >= Tier::Suggestive
            && d.new_ids.contains(&r.obs.id)
            && let Some(h) = &r.target_host
        {
            *targets.entry(h.as_str()).or_default() += 1;
        }
    }
    let mut targets: Vec<_> = targets.into_iter().collect();
    targets.sort_by_key(|x| std::cmp::Reverse(x.1));
    let _ = writeln!(t, "\n## Top targets in new records\n");
    none(&mut t, targets.is_empty());
    for (h, n) in targets.iter().take(10) {
        let _ = writeln!(t, "- `{}`: {n} flagged", defang_host(h));
    }

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

    let _ = writeln!(t, "\n## Archive bursts ({})\n", d.bursts.len());
    none(&mut t, d.bursts.is_empty());
    for b in d.bursts {
        let _ = writeln!(
            t,
            "- `{}`: {} captures {} → {} ({} distinct URLs, {} flagged); usually {:.1}/day",
            defang_host(&b.host),
            b.count,
            sc_core::fmt_ts(b.start),
            sc_core::fmt_ts(b.end),
            b.distinct_urls,
            b.flagged,
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

    let errors = health.sources.iter().any(|s| s.error.is_some());
    let changed = d.cases.changed
        || !new_clusters.is_empty()
        || !escalated.is_empty()
        || !new_endpoints.is_empty()
        || !matches.is_empty()
        || !d.bursts.is_empty()
        || errors
        || !health.alerts.is_empty();
    Digest { text: t, changed }
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
            sc_core::defang(&one_line(&format!("{}{}", e.host, e.path), 100)),
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
            sc_core::defang(&one_line(&c.feature.to_string(), 90)),
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
        })
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
    fn digest_lists_candidate_fleets_by_key() {
        let mut rules = Rules::default_rules();
        rules.set.soft_links.fleet_min_strength = 0.3;
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
}
