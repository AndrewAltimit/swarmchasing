//! Provenance and plant review: who could have put a cluster's records where
//! they were found, and signs that someone placed them there to be found.
//!
//! Scan services and web archives take any URL from anyone; package
//! registries, GitHub and certificate logs publish whatever their users name.
//! A record from them shows that someone submitted or published it, not that
//! an agent sent it. Each cluster counts its members by [`Provenance`] and
//! says whether more than one kind of source stands behind it
//! ([`Corroboration`]). Plant signals ([`PlantSignal`]) are things a planted
//! cluster tends to show. All of it is for the admin's review: none of it
//! changes a score, a tier or a link, and none of it reaches a public notice.

use crate::analyze::{Analysis, Cluster, CommonFeature, ObsResult};
use crate::escalation::Escalation;
use crate::extract::defang;
use crate::model::{LinkFeature, Provenance, Tactic, Tier, truncate};
use crate::rules::Linking;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// How many independent kinds of source stand behind a cluster.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Corroboration {
    /// One kind of source at most (records of unknown provenance not
    /// counted): one person submitting URLs could have made all of it.
    #[default]
    SingleSource,
    /// Two or more kinds of source (submitted, published, observed).
    MultiSource,
    /// Logs an affected operator sent hold some of its records.
    OperatorConfirmed,
}

impl Corroboration {
    pub fn label(self) -> &'static str {
        match self {
            Self::SingleSource => "single source",
            Self::MultiSource => "several kinds of source",
            Self::OperatorConfirmed => "confirmed in operator logs",
        }
    }
}

/// What a plant signal points at.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlantSignalKind {
    /// Every record comes from a service anyone can submit a URL to.
    ProvenanceMonoculture,
    /// A value quoted in a public report: anyone who read it can copy it.
    BurnedIdentifier,
    /// Every record significant on three or more kinds of evidence, with
    /// nothing ordinary around it: no unflagged requests on its hosts, no
    /// route escalation, no task retrieval.
    TooPerfect,
    /// An identifier shared with an earlier cluster that worked differently
    /// (relay stacks, URL encodings or payload dialect with nothing in common).
    HabitMismatch,
    /// Its targets were fanned out to several scan services alike with
    /// ordinary links on other hosts around it: a mail gateway or security
    /// product that submits every link it sees made the records, on behalf
    /// of whoever sent the links ([`crate::crossservice`]).
    AutoSubmitted,
}

impl PlantSignalKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::ProvenanceMonoculture => "provenance monoculture",
            Self::BurnedIdentifier => "burned identifier",
            Self::TooPerfect => "too perfect",
            Self::HabitMismatch => "habit mismatch",
            Self::AutoSubmitted => "auto-submitted",
        }
    }

    /// Every kind, in report order.
    pub const ALL: [Self; 5] = [
        Self::ProvenanceMonoculture,
        Self::BurnedIdentifier,
        Self::TooPerfect,
        Self::HabitMismatch,
        Self::AutoSubmitted,
    ];
}

/// A sign that a cluster may have been planted. A prompt for review, never
/// a finding: never scored, never linked on, internal reports only.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PlantSignal {
    pub kind: PlantSignalKind,
    /// The records it rests on (indexes into `Analysis::results`).
    pub records: Vec<usize>,
    pub detail: String,
    /// The share of the analysis's clusters that carry this signal kind,
    /// set only when it is high enough to make the signal context: more
    /// than half of the clusters, and at least four clusters in all
    /// ([FM-5.11](../../docs/manual/05-linking.md)). A signal with a base
    /// rate is reported with it and does not count toward the plant-review
    /// threshold; one without (`None`) counts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_rate: Option<f64>,
}

impl PlantSignal {
    /// Whether this signal counts toward the plant-review threshold: one
    /// whose base rate marks it as context does not.
    pub fn counts(&self) -> bool {
        self.base_rate.is_none()
    }
}

/// Plant signals kept per cluster.
const MAX_SIGNALS: usize = 8;

/// A value quoted in a public report (`linking.published_tags`, ignoring
/// case).
pub(crate) fn burned(cfg: &Linking, value: &str) -> bool {
    cfg.published_tags
        .iter()
        .any(|t| t.eq_ignore_ascii_case(value))
}

/// Members by provenance.
pub(crate) fn provenance_counts(
    results: &[ObsResult],
    members: &[usize],
) -> BTreeMap<Provenance, usize> {
    let mut m = BTreeMap::new();
    for &i in members {
        *m.entry(results[i].obs.provenance()).or_default() += 1;
    }
    m
}

/// Operator-confirmed when an operator's logs hold a member; several kinds
/// of source when two or more known provenances are present. Reported
/// records (an outside submission) count as no kind: a submission alone
/// never makes a cluster multi-source.
pub(crate) fn corroboration(results: &[ObsResult], members: &[usize]) -> Corroboration {
    let mut kinds = 0u8;
    for &i in members {
        let o = &results[i].obs;
        if o.operator_supplied() {
            return Corroboration::OperatorConfirmed;
        }
        match o.provenance() {
            Provenance::Unknown | Provenance::Reported => {}
            p => kinds |= 1 << p as u8,
        }
    }
    if kinds.count_ones() > 1 {
        Corroboration::MultiSource
    } else {
        Corroboration::SingleSource
    }
}

/// The plant signals of every cluster, in cluster order. Reads the clusters'
/// ids, so it runs after numbering.
pub(crate) fn plant_signals(
    results: &[ObsResult],
    clusters: &[Cluster],
    escalations: &[Escalation],
    common: &[CommonFeature],
    cfg: &Linking,
) -> Vec<Vec<PlantSignal>> {
    let mut out: Vec<Vec<PlantSignal>> = clusters
        .iter()
        .map(|c| {
            let mut v = Vec::new();
            v.extend(monoculture(results, c));
            burned_in(results, c, cfg, &mut v);
            v.extend(too_perfect(results, c, escalations, cfg.window_secs));
            v.extend(auto_submitted(c));
            v
        })
        .collect();
    habit_mismatches(results, clusters, common, cfg, &mut out);
    base_rates(&mut out, clusters.len());
    for v in &mut out {
        v.truncate(MAX_SIGNALS);
    }
    out
}

/// At least this many clusters before a signal's base rate is read: below
/// it, "most clusters carry it" says too little.
const BASE_RATE_MIN_CLUSTERS: usize = 4;

/// Set each signal kind's base rate when it is context: the kind is on more
/// than half of the analysis's `clusters`, and there are at least
/// [`BASE_RATE_MIN_CLUSTERS`] of them. A signal carried by most clusters of
/// a collection tells the reviewer nothing about one cluster, so it is
/// reported with its base rate and does not count toward the review
/// threshold ([FM-5.11]).
fn base_rates(out: &mut [Vec<PlantSignal>], clusters: usize) {
    if clusters < BASE_RATE_MIN_CLUSTERS {
        return;
    }
    let mut carrying: BTreeMap<PlantSignalKind, usize> = BTreeMap::new();
    for v in out.iter() {
        for kind in v.iter().map(|p| p.kind).collect::<BTreeSet<_>>() {
            *carrying.entry(kind).or_default() += 1;
        }
    }
    for v in out.iter_mut() {
        for p in v.iter_mut() {
            let n = carrying.get(&p.kind).copied().unwrap_or(0);
            if n * 2 > clusters {
                p.base_rate = Some(n as f64 / clusters as f64);
            }
        }
    }
}

fn monoculture(results: &[ObsResult], c: &Cluster) -> Option<PlantSignal> {
    let all = c.members.len();
    if c.tier == Tier::Noise || c.origin.provenance.get(&Provenance::SubmitAnywhere) != Some(&all) {
        return None;
    }
    let mut sources: Vec<&str> = c
        .members
        .iter()
        .map(|&m| results[m].obs.source.as_str())
        .collect();
    crate::sort::sort(&mut sources);
    sources.dedup();
    Some(PlantSignal {
        kind: PlantSignalKind::ProvenanceMonoculture,
        records: c.members.clone(),
        detail: format!(
            "all {all} records come from services anyone can submit a URL to ({}); no server log or owner-published record stands behind them",
            sources.join(", ")
        ),
        base_rate: None,
    })
}

/// Burned identifiers among the members' linking features, one signal each.
fn burned_in(results: &[ObsResult], c: &Cluster, cfg: &Linking, out: &mut Vec<PlantSignal>) {
    let mut found: Vec<(&LinkFeature, usize)> = c
        .members
        .iter()
        .flat_map(|&m| results[m].features.iter().map(move |f| (f, m)))
        .filter(|(f, _)| burned(cfg, f.value()))
        .collect();
    crate::sort::sort(&mut found);
    found.dedup();
    for g in found.chunk_by(|a, b| a.0 == b.0) {
        out.push(PlantSignal {
            kind: PlantSignalKind::BurnedIdentifier,
            records: g.iter().map(|x| x.1).collect(),
            detail: format!(
                "`{}` on {} record(s) is quoted in a public report (linking.published_tags): anyone who read it can copy it",
                defang(&truncate(&g[0].0.to_string(), 90)),
                g.len()
            ),
            base_rate: None,
        });
    }
}

/// A cluster the cross-service fan-out marks as an auto-submitter
/// ([`crate::crossservice::CrossService::auto_submitter`]).
fn auto_submitted(c: &Cluster) -> Option<PlantSignal> {
    let x = &c.cross_service;
    if !x.auto_submitter {
        return None;
    }
    Some(PlantSignal {
        kind: PlantSignalKind::AutoSubmitted,
        records: c.members.clone(),
        detail: format!(
            "{} of its targets went to {} within {}s, and {} ordinary link(s) on other hosts were fanned out alike around it: something submits every link it sees, as a mail gateway or security product does, so whoever sent the links made these records",
            x.targets,
            x.service_list(),
            x.max_spread_secs,
            x.ambient
        ),
        base_rate: None,
    })
}

fn too_perfect(
    results: &[ObsResult],
    c: &Cluster,
    escalations: &[Escalation],
    window: i64,
) -> Option<PlantSignal> {
    let rich = |r: &ObsResult| {
        r.tier == Tier::Significant
            && r.hits
                .iter()
                .map(|h| h.kind)
                .filter(|&k| !crate::analyze::is_context_kind(k))
                .collect::<BTreeSet<_>>()
                .len()
                >= 3
    };
    if c.tier != Tier::Significant || !c.members.iter().all(|&m| rich(&results[m])) {
        return None;
    }
    let retrieval = c
        .members
        .iter()
        .flat_map(|&m| &results[m].hits)
        .any(|h| h.tactic == Some(Tactic::TaskRetrieval));
    let escalated = escalations.iter().any(|e| e.clusters.contains(&c.id));
    // Ordinary requests on its hosts around it: a real agent reads pages no
    // rule flags. Records without a time cannot be placed, so they count.
    let neighbours = results.iter().any(|r| {
        r.score == 0
            && r.target_host
                .as_ref()
                .is_some_and(|h| c.target_hosts.contains_key(h))
            && (c.start <= 0
                || r.obs.ts <= 0
                || (r.obs.ts >= c.start - window && r.obs.ts <= c.end + window))
    });
    if retrieval || escalated || neighbours {
        return None;
    }
    Some(PlantSignal {
        kind: PlantSignalKind::TooPerfect,
        records: c.members.clone(),
        detail: format!(
            "every one of its {} records is significant on three or more kinds of evidence, with no unflagged request on its hosts, no route escalation and no task retrieval: a textbook cluster, as a planted one would be",
            c.members.len()
        ),
        base_rate: None,
    })
}

/// A cluster carrying an identifier an earlier cluster also carries, whose
/// relay stacks, encodings or payload dialect share nothing with that
/// cluster's. Common and burned identifiers are left out: they are expected
/// on unrelated clusters.
fn habit_mismatches(
    results: &[ObsResult],
    clusters: &[Cluster],
    common: &[CommonFeature],
    cfg: &Linking,
    out: &mut [Vec<PlantSignal>],
) {
    let skip: BTreeSet<&LinkFeature> = common.iter().map(|c| &c.feature).collect();
    // (feature, cluster start, cluster): each feature's clusters, earliest first.
    let mut carriers: Vec<(&LinkFeature, i64, usize)> = Vec::new();
    for (ci, c) in clusters.iter().enumerate() {
        for &m in &c.members {
            for f in &results[m].features {
                if !skip.contains(f) && !burned(cfg, f.value()) {
                    carriers.push((f, c.start, ci));
                }
            }
        }
    }
    crate::sort::sort(&mut carriers);
    carriers.dedup();
    let mut seen: Vec<(usize, usize)> = Vec::new();
    for g in carriers.chunk_by(|a, b| a.0 == b.0) {
        let (f, first) = (g[0].0, &clusters[g[0].2]);
        for &(_, _, ci) in &g[1..] {
            if seen.contains(&(g[0].2, ci)) {
                continue;
            }
            seen.push((g[0].2, ci));
            let c = &clusters[ci];
            let differs = habits_differ(first, c);
            if differs.is_empty() {
                continue;
            }
            out[ci].push(PlantSignal {
                kind: PlantSignalKind::HabitMismatch,
                records: c
                    .members
                    .iter()
                    .copied()
                    .filter(|&m| results[m].features.contains(f))
                    .collect(),
                detail: format!(
                    "shares `{}` with the earlier {} but its {} have nothing in common with that cluster's: the identifier may have been copied",
                    defang(&truncate(&f.to_string(), 90)),
                    first.id,
                    differs.join(", ")
                ),
                base_rate: None,
            });
        }
    }
}

/// The habits on which two clusters both have data and share nothing.
fn habits_differ(a: &Cluster, b: &Cluster) -> Vec<&'static str> {
    let apart = |x: &BTreeMap<String, usize>, y: &BTreeMap<String, usize>| {
        !x.is_empty() && !y.is_empty() && x.keys().all(|k| !y.contains_key(k))
    };
    let mut v = Vec::new();
    if apart(&a.relay_stacks, &b.relay_stacks) {
        v.push("relay stacks");
    }
    if apart(&a.encodings, &b.encodings) {
        v.push("URL encodings");
    }
    if apart(&a.dialect.variants, &b.dialect.variants) {
        v.push("payload dialect");
    }
    v
}

/// One line on a cluster's provenance and corroboration, for internal and
/// provider reports.
pub(crate) fn provenance_line(c: &Cluster) -> Option<String> {
    if c.origin.provenance.is_empty() {
        return None;
    }
    let shown: Vec<String> = c
        .origin
        .provenance
        .iter()
        .map(|(p, n)| format!("{p} {n}"))
        .collect();
    let open = [Provenance::SubmitAnywhere, Provenance::PublishAnywhere]
        .iter()
        .any(|p| c.origin.provenance.contains_key(p));
    let caveat = if c.origin.corroboration == Corroboration::SingleSource && open {
        ": anyone can submit or publish such records, so they show that someone did, not who"
    } else {
        ""
    };
    Some(format!(
        "provenance: {} · {}{caveat}",
        shown.join(", "),
        c.origin.corroboration.label()
    ))
}

/// The internal report's plant review: each shown cluster's plant signals.
pub(crate) fn plant_review(s: &mut String, a: &Analysis, clusters: &[&Cluster]) {
    use std::fmt::Write;
    if clusters.iter().all(|c| c.origin.plant_signals.is_empty()) {
        return;
    }
    let _ = writeln!(
        s,
        "\n## Plant review\n\nSigns that a cluster's records were placed to be found. Prompts to check, never findings: none changes a score, a tier or a link.\n"
    );
    for c in clusters
        .iter()
        .filter(|c| !c.origin.plant_signals.is_empty())
    {
        let _ = writeln!(s, "- **{}** ({}):", c.id, c.origin.corroboration.label());
        for p in &c.origin.plant_signals {
            let ids: Vec<&str> = p
                .records
                .iter()
                .take(5)
                .map(|&i| a.results[i].obs.id.as_str())
                .filter(|id| !id.is_empty())
                .collect();
            let more = p.records.len().saturating_sub(5);
            let _ = write!(s, "  - {}: {}", p.kind.label(), p.detail);
            if let Some(rate) = p.base_rate {
                let _ = write!(
                    s,
                    " (base rate {:.0}% of clusters carry this signal: context, not counted toward the review threshold)",
                    rate * 100.0
                );
            }
            if !ids.is_empty() {
                let _ = write!(s, " (records `{}`", ids.join("`, `"));
                if more > 0 {
                    let _ = write!(s, " and {more} more");
                }
                s.push(')');
            }
            s.push('\n');
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Observation;
    use crate::rules::Rules;

    fn rec(id: &str, source: &str, ts: i64, url: &str) -> Observation {
        Observation {
            id: id.into(),
            source: source.into(),
            ts,
            url: url.into(),
            ..Default::default()
        }
    }

    const INBOX: &str = "https://webhook.site/0b6c1f0e-1111-4c2a-9a55-3f2e1d0c9b8a";

    #[test]
    fn provenance_follows_the_source() {
        for (s, p) in [
            ("urlquery", Provenance::SubmitAnywhere),
            ("wayback", Provenance::SubmitAnywhere),
            ("urlscan", Provenance::SubmitAnywhere),
            ("gharchive", Provenance::PublishAnywhere),
            ("ctlog", Provenance::PublishAnywhere),
            ("commoncrawl", Provenance::PublishAnywhere),
            ("access_log", Provenance::Observed),
            ("operator:e1", Provenance::Observed),
            ("submission", Provenance::Reported),
            ("manual", Provenance::Unknown),
            ("", Provenance::Unknown),
        ] {
            assert_eq!(Provenance::of_source(s), p, "{s}");
        }
    }

    #[test]
    fn clusters_count_provenance_and_corroboration_without_moving_tiers() {
        let obs = |second: &str| {
            vec![
                rec("a", "urlquery", 1000, &format!("{INBOX}?kind=headers0")),
                rec("b", second, 1040, &format!("{INBOX}?kind=body0-0")),
            ]
        };
        let rules = Rules::default_rules();
        let single = crate::analyze(obs("urlquery"), &rules);
        let multi = crate::analyze(obs("gharchive"), &rules);
        let op = crate::analyze(obs("operator:e1"), &rules);
        let unknown = crate::analyze(obs("manual"), &rules);
        let reported = crate::analyze(obs("submission"), &rules);
        let c = |a: &Analysis| a.clusters[0].clone();
        assert_eq!(c(&single).origin.corroboration, Corroboration::SingleSource);
        assert_eq!(
            c(&single)
                .origin
                .provenance
                .get(&Provenance::SubmitAnywhere),
            Some(&2)
        );
        assert_eq!(c(&multi).origin.corroboration, Corroboration::MultiSource);
        assert_eq!(
            c(&op).origin.corroboration,
            Corroboration::OperatorConfirmed
        );
        assert_eq!(
            c(&unknown).origin.corroboration,
            Corroboration::SingleSource
        );
        // A submission's own records never make a cluster multi-source.
        assert_eq!(
            c(&reported).origin.corroboration,
            Corroboration::SingleSource
        );
        for a in [&multi, &op, &unknown, &reported] {
            assert_eq!(
                (&c(a).members, c(a).tier, c(a).score),
                (&c(&single).members, c(&single).tier, c(&single).score)
            );
        }
        let kinds = |a: &Analysis| -> Vec<PlantSignalKind> {
            a.clusters[0]
                .origin
                .plant_signals
                .iter()
                .map(|p| p.kind)
                .collect()
        };
        assert!(kinds(&single).contains(&PlantSignalKind::ProvenanceMonoculture));
        assert!(!kinds(&multi).contains(&PlantSignalKind::ProvenanceMonoculture));
    }

    #[test]
    fn burned_identifiers_are_flagged_and_tie_nothing() {
        // One inbox joins each pair; both carry the published tag.
        let other = "https://webhook.site/7d2e4a10-2222-4b3c-8a66-4e3f2a1b0c9d";
        let day = 86_400;
        let obs = vec![
            rec(
                "a1",
                "urlquery",
                1000,
                &format!("https://a.example/?q=CHATGPTTEST1&cb={INBOX}"),
            ),
            rec(
                "a2",
                "urlquery",
                1060,
                &format!("https://a.example/x?cb={INBOX}"),
            ),
            rec(
                "b1",
                "urlquery",
                2 * day,
                &format!("https://b.example/?q=CHATGPTTEST1&cb={other}"),
            ),
            rec(
                "b2",
                "urlquery",
                2 * day + 60,
                &format!("https://b.example/y?cb={other}"),
            ),
        ];
        let a = crate::analyze(obs, &Rules::default_rules());
        assert_eq!(a.clusters.len(), 2, "{:?}", a.clusters);
        for c in &a.clusters {
            let burned: Vec<&PlantSignal> = c
                .origin
                .plant_signals
                .iter()
                .filter(|p| p.kind == PlantSignalKind::BurnedIdentifier)
                .collect();
            assert_eq!(burned.len(), 1, "{:?}", c.origin.plant_signals);
            assert!(burned[0].detail.contains("chatgpttest1"));
            assert_eq!(burned[0].records.len(), 1);
            assert!(
                c.origin
                    .plant_signals
                    .iter()
                    .all(|p| p.kind != PlantSignalKind::HabitMismatch)
            );
        }
        assert!(a.common_features.iter().all(|c| c.published));
        assert!(
            a.soft_links
                .iter()
                .all(|l| l.kind != crate::fleets::SoftLinkKind::CommonFeature),
            "{:?}",
            a.soft_links
        );
        // Unpublished, the same tag is a soft link between the two.
        let mut rules = Rules::default_rules();
        rules.set.linking.published_tags.clear();
        rules.set.linking.feature_max_hosts = 1;
        let b = crate::analyze(a.results.iter().map(|r| r.obs.clone()).collect(), &rules);
        assert!(
            b.soft_links
                .iter()
                .any(|l| l.kind == crate::fleets::SoftLinkKind::CommonFeature),
            "{:?}",
            b.soft_links
        );
    }

    #[test]
    fn a_reused_identifier_with_other_habits_is_a_habit_mismatch() {
        let day = 86_400;
        let obs = vec![
            // Months apart, one inbox: the first through a relay chain ...
            rec(
                "a1",
                "urlquery",
                1000,
                &format!("https://r.jina.ai/https://a.example/p?cb={INBOX}"),
            ),
            rec(
                "a2",
                "urlquery",
                1060,
                &format!("https://r.jina.ai/https://a.example/q?cb={INBOX}"),
            ),
            // ... the second through an echo carrier.
            rec(
                "b1",
                "urlquery",
                90 * day,
                &format!("https://httpbin.org/anything?u=https://b.example/&cb={INBOX}"),
            ),
            rec(
                "b2",
                "urlquery",
                90 * day + 60,
                &format!("https://httpbin.org/anything?u=https://b.example/x&cb={INBOX}"),
            ),
        ];
        let a = crate::analyze(obs, &Rules::default_rules());
        assert_eq!(a.clusters.len(), 2, "{:?}", a.clusters);
        let later = a.clusters.iter().max_by_key(|c| c.start).unwrap();
        let earlier = a.clusters.iter().min_by_key(|c| c.start).unwrap();
        let hm: Vec<&PlantSignal> = later
            .origin
            .plant_signals
            .iter()
            .filter(|p| p.kind == PlantSignalKind::HabitMismatch)
            .collect();
        assert_eq!(hm.len(), 1, "{:?}", later.origin.plant_signals);
        assert!(hm[0].detail.contains(&earlier.id) && hm[0].detail.contains("relay stacks"));
        assert_eq!(hm[0].records.len(), 2);
        assert!(
            earlier
                .origin
                .plant_signals
                .iter()
                .all(|p| p.kind != PlantSignalKind::HabitMismatch)
        );
    }

    #[test]
    fn a_textbook_cluster_with_nothing_around_it_is_too_perfect() {
        // Each record: an injection probe, a callback inbox and an echo
        // carrier, three kinds of evidence.
        let probe = |i: i64| {
            format!(
                "https://httpbin.org/anything?u=https://t.example/item%3Fid%3D{i}%2520UNION%2520SELECT%2520null--&hook={INBOX}"
            )
        };
        let mut obs: Vec<Observation> = (0..3)
            .map(|i| rec(&format!("p{i}"), "urlquery", 1000 + 30 * i, &probe(i)))
            .collect();
        let a = crate::analyze(obs.clone(), &Rules::default_rules());
        let kinds_of = |a: &Analysis| -> Vec<Vec<crate::model::IndicatorKind>> {
            a.results
                .iter()
                .map(|r| r.hits.iter().map(|h| h.kind).collect())
                .collect()
        };
        assert_eq!(a.clusters.len(), 1, "{:?}", kinds_of(&a));
        let perfect = |a: &Analysis| {
            a.clusters[0]
                .origin
                .plant_signals
                .iter()
                .any(|p| p.kind == PlantSignalKind::TooPerfect)
        };
        assert!(
            perfect(&a),
            "{:?} {:?}",
            kinds_of(&a),
            a.clusters[0].origin.plant_signals
        );
        // An ordinary request on the host in its span: not too perfect.
        obs.push(rec("n", "urlquery", 1010, "https://t.example/"));
        assert!(!perfect(&crate::analyze(obs, &Rules::default_rules())));
    }

    #[test]
    fn plant_review_is_internal_only_and_provenance_reaches_providers() {
        let obs = vec![
            rec(
                "a",
                "urlquery",
                1000,
                &format!("{INBOX}?kind=headers0&q=CHATGPTTEST1"),
            ),
            rec("b", "urlquery", 1040, &format!("{INBOX}?kind=body0-0")),
        ];
        let a = crate::analyze(obs, &Rules::default_rules());
        let md = |audience| {
            crate::report::render_markdown(
                &a,
                &crate::report::ReportOptions {
                    audience,
                    ..Default::default()
                },
            )
        };
        use crate::report::Audience;
        let internal = md(Audience::Internal);
        assert!(
            internal.contains("## Plant review")
                && internal.contains("burned identifier")
                && internal.contains("provenance monoculture")
                && internal.contains("provenance: submit-anywhere 2 · single source"),
            "{internal}"
        );
        let provider = md(Audience::Provider);
        assert!(
            provider.contains("provenance: submit-anywhere 2"),
            "{provider}"
        );
        for audience in [Audience::Provider, Audience::Affected, Audience::Public] {
            let r = md(audience);
            assert!(
                !r.contains("Plant review") && !r.contains("burned identifier"),
                "{r}"
            );
        }
        assert!(!md(Audience::Public).contains("provenance:"));
    }
}
