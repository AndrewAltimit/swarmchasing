//! The analysis as an ordered list of passes over one [`AnalysisCtx`].
//!
//! Each pass fills in part of the [`Analysis`] and names the passes whose
//! output it reads; [`PASSES`] lists them in an order where every pass comes
//! after those (a test and a debug assertion hold it to that). A new
//! per-cluster output is a field, a function in `hints` or its own module,
//! and one entry here.

use super::{Analysis, AsnSummary, Cluster, ObsResult, hints, link};
use crate::extract::extract;
use crate::model::{Observation, Tier};
use crate::rules::Rules;
use crate::timing::{
    SharedPauseOptions, infer_offset, max_concurrency, shared_pauses_family, timing,
};
use std::collections::BTreeMap;

/// What the passes share: the rules, the records not yet scored, the
/// flagged records and the analysis as built so far.
pub(super) struct AnalysisCtx<'r> {
    rules: &'r Rules,
    /// Taken by the `score` pass.
    observations: Vec<Observation>,
    /// Indexes of records with at least one hit (set by `link`).
    flagged: Vec<usize>,
    a: Analysis,
}

/// One step of the analysis.
pub(super) struct Pass {
    pub name: &'static str,
    /// Passes whose output this one reads; each comes earlier in [`PASSES`].
    pub after: &'static [&'static str],
    run: fn(&mut AnalysisCtx),
}

const fn pass(
    name: &'static str,
    after: &'static [&'static str],
    run: fn(&mut AnalysisCtx),
) -> Pass {
    Pass { name, after, run }
}

/// The passes, in the order they run.
pub(super) const PASSES: &[Pass] = &[
    pass("score", &[], score),
    // Only flagged records are linked: ordinary traffic to the same host
    // must not be swept into a cluster.
    pass("link", &["score"], link_clusters),
    // Per-cluster descriptions, before numbering (it sorts by span).
    pass("timing", &["link"], |cx| {
        let cfg = &cx.rules.set.linking;
        for c in &mut cx.a.clusters {
            hints::cluster_timing(c, &cx.a.results, cfg);
        }
    }),
    pass("fingerprints", &["link"], |cx| {
        each_cluster(cx, |c, results, _| hints::fingerprints(c, results))
    }),
    pass("paths", &["timing"], |cx| {
        let unflagged = hints::unflagged_by_host(&cx.a.results);
        for c in &mut cx.a.clusters {
            hints::paths(c, &cx.a.results, &unflagged, cx.rules);
        }
    }),
    pass("dialect", &["link"], |cx| each_cluster(cx, hints::dialect)),
    pass("fanout", &["link"], |cx| each_cluster(cx, hints::fanout)),
    // Reads the clusters' spans for the fan-outs around them.
    pass("cross_service", &["timing"], cross_service),
    pass("prose", &["link"], |cx| {
        each_cluster(cx, |c, results, _| hints::prose(c, results))
    }),
    pass("declared", &["link"], |cx| {
        each_cluster(cx, |c, results, _| hints::declared(c, results))
    }),
    pass("knowledge", &["link"], knowledge),
    pass("provenance", &["link"], |cx| {
        each_cluster(cx, |c, results, _| hints::provenance(c, results))
    }),
    // Ids and keys; record → cluster indexes.
    pass("number", &["timing"], |cx| {
        link::number(&mut cx.a.clusters, &mut cx.a.results)
    }),
    pass("escalations", &["number"], escalations),
    pass(
        "plant",
        &[
            "number",
            "escalations",
            "timing",
            "fingerprints",
            "dialect",
            "provenance",
            "cross_service",
        ],
        plant,
    ),
    pass(
        "agent",
        &[
            "timing",
            "fingerprints",
            "paths",
            "dialect",
            "fanout",
            "cross_service",
            "prose",
            "declared",
            "knowledge",
            "provenance",
            "plant",
            "escalations",
        ],
        agent,
    ),
    // Date tags are read from flagged records' parameters.
    pass("totals", &["number"], totals),
    pass("shared_pauses", &["number"], |cx| {
        let quiet: Vec<(String, Vec<i64>)> =
            cx.a.clusters
                .iter()
                .filter(|c| c.tier > Tier::Noise)
                .map(|c| {
                    let ts = c.members.iter().map(|&i| cx.a.results[i].obs.ts);
                    (c.id.clone(), ts.filter(|&t| t > 0).collect())
                })
                .collect();
        let (pauses, family) = shared_pauses_family(
            &quiet,
            &SharedPauseOptions::from_linking(&cx.rules.set.linking),
        );
        cx.a.shared_pauses = pauses;
        cx.a.multiplicity.push(family);
    }),
    pass("dialect_pairs", &["number", "dialect"], |cx| {
        cx.a.dialect_pairs = crate::dialect::dialect_pairs(
            &cx.a
                .clusters
                .iter()
                .filter(|c| c.tier > Tier::Noise)
                .map(|c| (c.id.as_str(), &c.dialect))
                .collect::<Vec<_>>(),
        );
    }),
    pass("trim_layers", &["paths", "dialect", "totals"], trim_layers),
    // Reads members' layers and parameters, which trimming keeps for
    // flagged records.
    pass("scaffolds", &["number", "trim_layers"], |cx| {
        let s = &cx.rules.set;
        let (pairs, family) = crate::scaffold::scaffold_pairs(
            &cx.a.clusters,
            &cx.a.results,
            s.soft_links.max_shared,
            &s.scaffold,
        );
        cx.a.scaffold_pairs = pairs;
        cx.a.multiplicity.push(family);
    }),
    pass("co_activity", &["number"], |cx| {
        let s = &cx.rules.set;
        let (pairs, family) = crate::coactivity::coactive_pairs(
            &cx.a.clusters,
            &cx.a.results,
            s.soft_links.max_shared,
            &s.co_activity,
        );
        cx.a.coactive_pairs = pairs;
        cx.a.multiplicity.push(family);
    }),
    pass("co_target", &["number"], |cx| {
        let s = &cx.rules.set;
        cx.a.cotarget_pairs = crate::cotarget::cotarget_pairs(
            &cx.a.clusters,
            &cx.a.results,
            s.soft_links.max_shared,
            &s.co_target,
        );
    }),
    pass(
        "fleets",
        &[
            "shared_pauses",
            "dialect_pairs",
            "escalations",
            "trim_layers",
            "scaffolds",
            "co_activity",
            "co_target",
        ],
        fleets,
    ),
    pass("swarm", &["number", "trim_layers"], |cx| {
        let (edges, families) = crate::swarm::swarm_edges(&cx.a.clusters, &cx.a.results, cx.rules);
        cx.a.swarm_edges = edges;
        cx.a.multiplicity.extend(families);
    }),
    pass(
        "scope",
        &["number", "escalations", "knowledge", "agent", "swarm"],
        scope,
    ),
    pass("summary", &["link", "timing"], summary),
];

/// Run every pass over `observations`.
pub(super) fn run(observations: Vec<Observation>, rules: &Rules) -> Analysis {
    let mut cx = AnalysisCtx {
        rules,
        observations,
        flagged: Vec::new(),
        a: Analysis::default(),
    };
    for (i, p) in PASSES.iter().enumerate() {
        debug_assert!(
            p.after
                .iter()
                .all(|d| PASSES[..i].iter().any(|q| q.name == *d)),
            "pass `{}` runs before what it reads",
            p.name
        );
        (p.run)(&mut cx);
    }
    cx.a
}

/// `f` over every cluster, with the records and rules.
fn each_cluster(cx: &mut AnalysisCtx, f: impl Fn(&mut Cluster, &[ObsResult], &Rules)) {
    for c in &mut cx.a.clusters {
        f(c, &cx.a.results, cx.rules);
    }
}

fn tier_for(score: i32, significant_hit: bool, rules: &Rules) -> Tier {
    let t = &rules.set.thresholds;
    if significant_hit || score >= t.significant {
        Tier::Significant
    } else if score >= t.suggestive {
        Tier::Suggestive
    } else {
        Tier::Noise
    }
}

/// Unwrap, match and score every record.
fn score(cx: &mut AnalysisCtx) {
    let rules = cx.rules;
    cx.a.results = std::mem::take(&mut cx.observations)
        .into_iter()
        .map(|obs| {
            let x = extract(&obs, rules);
            ObsResult {
                tier: tier_for(x.score, x.significant_hit, rules),
                score: x.score,
                hits: x.hits,
                layers: x.layers,
                target_host: x.target_host,
                features: x.features,
                cluster: None,
                agent: None,
                obs,
            }
        })
        .collect();
}

/// Link the flagged records into clusters, keeping the probe chains and the
/// features too common to link.
fn link_clusters(cx: &mut AnalysisCtx) {
    let results = &cx.a.results;
    cx.flagged = (0..results.len())
        .filter(|&i| results[i].score > 0)
        .collect();
    let links = link::link(results, &cx.flagged, cx.rules);
    let clusters = links
        .groups
        .into_iter()
        .map(|members| hints::base(results, members, &links.joined, cx.rules))
        .collect();
    cx.a.chains = links.chains;
    cx.a.common_features = links.common;
    cx.a.clusters = clusters;
}

/// Benchmark targets and stale knowledge.
fn knowledge(cx: &mut AnalysisCtx) {
    let results = &cx.a.results;
    let newest = crate::knowledge::newest_versions(results);
    for c in &mut cx.a.clusters {
        c.knowledge.benchmarks =
            crate::knowledge::benchmarks(results, &c.members, &cx.rules.benchmarks);
        c.knowledge.stale_knowledge =
            crate::knowledge::stale(results, &c.members, &cx.rules.stale, &newest);
    }
}

fn cluster_ids(clusters: &[Cluster]) -> Vec<String> {
    clusters.iter().map(|c| c.id.clone()).collect()
}

/// Route escalations, with the ids of the clusters they touch.
fn escalations(cx: &mut AnalysisCtx) {
    cx.a.escalations = crate::escalation::escalations(
        &cx.a.results,
        &cluster_ids(&cx.a.clusters),
        &cx.rules.set.escalation,
    );
}

/// Targets sent to several scan services, per cluster.
fn cross_service(cx: &mut AnalysisCtx) {
    let opts = &cx.rules.set.fanout;
    let fans = crate::crossservice::service_fans(&cx.a.results, opts);
    let window = cx.rules.set.linking.window_secs;
    crate::crossservice::describe_all(&mut cx.a.clusters, &cx.a.results, &fans, opts, window);
}

/// Plant signals per cluster.
fn plant(cx: &mut AnalysisCtx) {
    let a = &cx.a;
    let plants = crate::plant::plant_signals(
        &a.results,
        &a.clusters,
        &a.escalations,
        &a.common_features,
        &cx.rules.set.linking,
    );
    for (c, p) in cx.a.clusters.iter_mut().zip(plants) {
        c.origin.plant_signals = p;
    }
}

/// Each cluster's scope assessment (FM chapter 15).
fn scope(cx: &mut AnalysisCtx) {
    let a = &cx.a;
    let scopes: Vec<crate::scope::Scope> = a
        .clusters
        .iter()
        .map(|c| crate::scope::assess(c, &a.results, &a.escalations, &a.swarm_edges))
        .collect();
    for (c, sc) in cx.a.clusters.iter_mut().zip(scopes) {
        c.scope = sc;
    }
}

/// Each cluster's agent grade, and each flagged unclustered record's.
fn agent(cx: &mut AnalysisCtx) {
    let a = &mut cx.a;
    for c in a.clusters.iter_mut() {
        c.agent = crate::agentness::assess(
            c,
            &a.results,
            &a.chains,
            &a.escalations,
            &cx.rules.set.chains,
        );
    }
    for r in a
        .results
        .iter_mut()
        .filter(|r| r.cluster.is_none() && r.score > 0)
    {
        r.agent = Some(crate::agentness::assess_record(r));
    }
}

/// Records per tier and rule, flagged records per network, and the
/// operator clock the flagged records' date tags imply.
fn totals(cx: &mut AnalysisCtx) {
    let mut tier_counts = BTreeMap::new();
    let mut rule_counts = BTreeMap::new();
    let mut asn_counts: BTreeMap<u32, usize> = BTreeMap::new();
    let mut tag_samples = Vec::new();
    for r in &cx.a.results {
        *tier_counts.entry(r.tier).or_default() += 1;
        for h in &r.hits {
            *rule_counts.entry(h.rule_id.clone()).or_default() += 1;
        }
        if r.score > 0 {
            if let Some(a) = r.obs.asn {
                *asn_counts.entry(a).or_default() += 1;
            }
            tag_samples.extend(r.date_tag());
        }
    }
    let mut asns: Vec<AsnSummary> = asn_counts
        .into_iter()
        .map(|(asn, count)| AsnSummary {
            asn,
            org: cx.rules.asn_org(asn).map(str::to_string),
            count,
        })
        .collect();
    crate::sort::by_key(&mut asns, |a| std::cmp::Reverse(a.count));
    cx.a.tier_counts = tier_counts;
    cx.a.rule_counts = rule_counts;
    cx.a.asns = asns;
    cx.a.date_tags = infer_offset(&tag_samples);
}

/// Drop the one layer of an unflagged record that only repeats its URL.
fn trim_layers(cx: &mut AnalysisCtx) {
    for r in cx.a.results.iter_mut() {
        if r.score == 0 && r.layers.len() == 1 && r.layers[0].is_submitted() {
            r.layers.clear();
        }
    }
}

/// Soft links between clusters and the candidate fleets they suggest.
fn fleets(cx: &mut AnalysisCtx) {
    let a = &cx.a;
    let opts = &cx.rules.set.soft_links;
    let soft_links = crate::fleets::soft_links(
        &crate::fleets::Signals {
            clusters: &a.clusters,
            results: &a.results,
            shared_pauses: &a.shared_pauses,
            dialect_pairs: &a.dialect_pairs,
            escalations: &a.escalations,
            common_features: &a.common_features,
            scaffold_pairs: &a.scaffold_pairs,
            coactive_pairs: &a.coactive_pairs,
            cotarget_pairs: &a.cotarget_pairs,
        },
        opts,
    );
    cx.a.candidate_fleets =
        crate::fleets::candidate_fleets(&soft_links, &cluster_ids(&a.clusters), opts);
    cx.a.soft_links = soft_links;
}

/// Counts, the rules version and timing over every flagged record.
fn summary(cx: &mut AnalysisCtx) {
    let a = &mut cx.a;
    let flagged_ts: Vec<i64> = cx.flagged.iter().map(|&i| a.results[i].obs.ts).collect();
    a.rules_version = cx.rules.set.meta.version.clone();
    a.total = a.results.len();
    a.flagged = cx.flagged.len();
    a.timing = timing(&flagged_ts, &cx.rules.set.linking);
    a.max_concurrent_clusters = max_concurrency(
        &a.clusters
            .iter()
            .flat_map(|c| c.runs.iter().map(|r| (r.start, r.end)))
            .collect::<Vec<_>>(),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_pass_runs_after_what_it_reads() {
        for (i, p) in PASSES.iter().enumerate() {
            assert!(
                PASSES[..i].iter().all(|q| q.name != p.name),
                "`{}` is listed twice",
                p.name
            );
            for d in p.after {
                assert!(
                    PASSES[..i].iter().any(|q| q.name == *d),
                    "`{}` reads `{d}`, which does not run before it",
                    p.name
                );
            }
        }
    }
}
