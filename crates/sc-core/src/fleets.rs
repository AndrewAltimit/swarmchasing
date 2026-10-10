//! Soft links between clusters, and the candidate fleets they suggest.
//!
//! Clusters are joined only by what one operator would hold (an inbox, a run
//! tag), by timing against one target, and by probe chains. Many weaker
//! signals also tie clusters together: they go quiet together, rerun the
//! same target list, open hosts with the same recon requests, write URLs
//! the same way, climb routes to the same page. Each is shared by unrelated
//! clients too, so none merges clusters or changes a score. [`soft_links`]
//! collects them as weighted pairs, and [`candidate_fleets`] groups the
//! clusters whose combined links are strong: proposals for the admin to
//! check, never findings.

use crate::analyze::{Cluster, CommonFeature, ObsResult};
use crate::dialect::DialectPair;
use crate::escalation::Escalation;
use crate::model::{LinkFeature, Tier};
use crate::timing::SharedPause;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap};

/// What a soft link rests on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SoftLinkKind {
    /// Pauses that start and end together beyond chance.
    SharedPause,
    /// The same uncommon mix of canonical test payloads.
    Dialect,
    /// One run's target sequence repeated by another, on another day.
    Rerun,
    /// The same recon opening on their hosts.
    Preamble,
    /// The same unusual path set.
    PathSet,
    /// Every member's URL written in one encoding style.
    Encoding,
    /// The same parallel fan-out width.
    FanOut,
    /// Truncated URLs cut at the same length.
    CutLength,
    /// The same request header set.
    HeaderSet,
    /// Steps of one route escalation against one page.
    Escalation,
    /// A linking feature too common to link on.
    CommonFeature,
    /// The same redacted secret (`REDACTED-<hash>`) in both clusters' records.
    SharedSecret,
    /// The same chain of two or more relays and carriers to their targets.
    RelayStack,
    /// Inboxes on the same callback service (different inboxes; one inbox
    /// links outright).
    CallbackService,
}

impl SoftLinkKind {
    pub fn label(self) -> &'static str {
        match self {
            SoftLinkKind::SharedPause => "shared pauses",
            SoftLinkKind::Dialect => "payload dialect",
            SoftLinkKind::Rerun => "rerun target list",
            SoftLinkKind::Preamble => "recon preamble",
            SoftLinkKind::PathSet => "unusual path set",
            SoftLinkKind::Encoding => "encoding style",
            SoftLinkKind::FanOut => "fan-out width",
            SoftLinkKind::CutLength => "cut length",
            SoftLinkKind::HeaderSet => "header set",
            SoftLinkKind::Escalation => "route escalation",
            SoftLinkKind::CommonFeature => "common feature",
            SoftLinkKind::SharedSecret => "shared captured secret",
            SoftLinkKind::RelayStack => "relay stack",
            SoftLinkKind::CallbackService => "callback service",
        }
    }
}

/// Soft link settings (`[soft_links]` in the rules file): the weight of each
/// kind (a link's strength is its weight, times its own similarity where it
/// has one), when a shared value is too common to mean anything, and how
/// strong a pair must be to join a candidate fleet.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct SoftLinkOptions {
    /// Pairs whose combined strength reaches this join a candidate fleet.
    pub fleet_min_strength: f64,
    /// A value (preamble, encoding style, width, header set, common feature)
    /// shared by more clusters than this links none of them.
    pub max_shared: usize,
    pub shared_pause: f64,
    pub dialect: f64,
    pub rerun: f64,
    pub preamble: f64,
    pub path_set: f64,
    pub encoding: f64,
    pub fanout: f64,
    pub cut_length: f64,
    pub header_set: f64,
    pub escalation: f64,
    pub common_feature: f64,
    pub shared_secret: f64,
    pub relay_stack: f64,
    pub callback_service: f64,
}

impl Default for SoftLinkOptions {
    fn default() -> Self {
        Self {
            fleet_min_strength: 0.5,
            max_shared: 10,
            shared_pause: 0.6,
            dialect: 0.4,
            rerun: 0.6,
            preamble: 0.4,
            path_set: 0.4,
            encoding: 0.2,
            fanout: 0.2,
            cut_length: 0.3,
            header_set: 0.3,
            escalation: 0.6,
            common_feature: 0.3,
            shared_secret: 0.8,
            relay_stack: 0.3,
            callback_service: 0.3,
        }
    }
}

/// One descriptive tie between two clusters. Never a merge.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SoftLink {
    /// Cluster ids, `a` the stronger (lower-numbered).
    pub a: String,
    pub b: String,
    pub kind: SoftLinkKind,
    /// 0 to 1.
    pub strength: f64,
    pub detail: String,
}

/// Clusters whose soft links, combined, reach `fleet_min_strength`: a
/// proposal that one operator may run them all.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CandidateFleet {
    /// `F1`, `F2`, ... in this analysis.
    pub id: String,
    /// Cluster ids, strongest first.
    pub clusters: Vec<String>,
    /// Kinds of the soft links inside it.
    pub kinds: Vec<SoftLinkKind>,
    /// Soft links between its clusters.
    pub links: usize,
    /// The weakest combined pair strength that joined it.
    pub strength: f64,
}

/// What the soft links are read from.
pub(crate) struct Signals<'a> {
    pub clusters: &'a [Cluster],
    pub results: &'a [ObsResult],
    pub shared_pauses: &'a [SharedPause],
    pub dialect_pairs: &'a [DialectPair],
    pub escalations: &'a [Escalation],
    pub common_features: &'a [CommonFeature],
}

/// Soft links between clusters above noise, strongest first.
pub(crate) fn soft_links<'a>(s: &Signals<'a>, opts: &SoftLinkOptions) -> Vec<SoftLink> {
    let shown: Vec<&'a Cluster> = s.clusters.iter().filter(|c| c.tier > Tier::Noise).collect();
    let order: HashMap<&str, usize> = s
        .clusters
        .iter()
        .enumerate()
        .map(|(i, c)| (c.id.as_str(), i))
        .collect();
    let is_shown = |id: &str| shown.iter().any(|c| c.id == id);
    let mut out: Vec<SoftLink> = Vec::new();
    let mut push = |x: &str, y: &str, kind, strength: f64, detail: String| {
        if x == y || strength <= 0.0 || !is_shown(x) || !is_shown(y) {
            return;
        }
        let (a, b) = if order[x] <= order[y] { (x, y) } else { (y, x) };
        out.push(SoftLink {
            a: a.into(),
            b: b.into(),
            kind,
            strength: strength.min(1.0),
            detail,
        });
    };

    for p in s.shared_pauses {
        push(
            &p.a,
            &p.b,
            SoftLinkKind::SharedPause,
            opts.shared_pause,
            p.reason.clone(),
        );
    }
    for p in s.dialect_pairs {
        push(
            &p.a,
            &p.b,
            SoftLinkKind::Dialect,
            opts.dialect * p.jaccard,
            format!(
                "{} shared payload variants, Jaccard {:.2}",
                p.shared.len(),
                p.jaccard
            ),
        );
    }
    let (runs, matches) = crate::recurrence::reruns_across(s.clusters, s.results, &BTreeSet::new());
    for m in matches {
        let (x, y) = (&runs[m.earlier], &runs[m.later]);
        push(
            &x.cluster,
            &y.cluster,
            SoftLinkKind::Rerun,
            opts.rerun * m.weighted_jaccard,
            format!(
                "{} shared target hosts in the same order ({:.0}%), weighted Jaccard {:.2}",
                m.shared.len(),
                m.order * 100.0,
                m.weighted_jaccard
            ),
        );
    }
    for e in s.escalations {
        for (i, x) in e.clusters.iter().enumerate() {
            for y in &e.clusters[i + 1..] {
                push(
                    x,
                    y,
                    SoftLinkKind::Escalation,
                    opts.escalation,
                    format!("{} on {}{}", e.route_line(), e.host, e.path),
                );
            }
        }
    }

    // Values the clusters share: pair the clusters holding each, unless too
    // many do.
    let mut shared: BTreeMap<(SoftLinkKind, String), Vec<&str>> = BTreeMap::new();
    let mut add = |kind, value: String, id: &'a str| {
        shared.entry((kind, value)).or_default().push(id);
    };
    for c in &shown {
        for p in &c.paths.preambles {
            add(SoftLinkKind::Preamble, p.paths.join(" → "), &c.id);
        }
        if let Some(style) = only_value(&c.encodings, c.members.len()) {
            add(SoftLinkKind::Encoding, style.clone(), &c.id);
        }
        if let Some(w) = c.fanout.modal_width {
            add(SoftLinkKind::FanOut, format!("width {w}"), &c.id);
        }
        // One hop is every relay user's habit; a stack of two or more is not.
        for st in c
            .relay_stacks
            .keys()
            .filter(|s| s.matches(" → ").count() >= 2)
        {
            add(SoftLinkKind::RelayStack, st.clone(), &c.id);
        }
        // Inboxes on one callback service: a link rule's id names the
        // service (`exfil.webhook_site`).
        let services: BTreeSet<&str> = c
            .members
            .iter()
            .flat_map(|&m| &s.results[m].features)
            .map(LinkFeature::name)
            .filter(|n| n.starts_with("exfil."))
            .collect();
        for svc in services {
            add(SoftLinkKind::CallbackService, svc.to_string(), &c.id);
        }
        let with_headers: usize = c.header_sets.values().sum();
        if let Some(h) = only_value(&c.header_sets, with_headers) {
            add(SoftLinkKind::HeaderSet, h.clone(), &c.id);
        }
    }
    let common: BTreeSet<&LinkFeature> = s.common_features.iter().map(|c| &c.feature).collect();
    for c in &shown {
        let feats: BTreeSet<&LinkFeature> = c
            .members
            .iter()
            .flat_map(|&m| &s.results[m].features)
            .filter(|f| common.contains(f))
            .collect();
        for f in feats {
            add(SoftLinkKind::CommonFeature, f.to_string(), &c.id);
        }
    }
    let stock = stock_secrets();
    for c in &shown {
        let mut found = BTreeSet::new();
        for &m in &c.members {
            let r = &s.results[m];
            let o = &r.obs;
            let texts = [o.url.as_str(), o.final_url.as_deref().unwrap_or("")];
            let layers = r.layers.iter().map(|l| l.text.as_str());
            let headers = o.headers.values().map(String::as_str);
            for t in texts.into_iter().chain(layers).chain(headers) {
                redacted_in(t, &mut found);
            }
        }
        for h in found.into_iter().filter(|h| !stock.contains(*h)) {
            add(SoftLinkKind::SharedSecret, h.to_string(), &c.id);
        }
    }
    for ((kind, value), ids) in &shared {
        if ids.len() < 2 || ids.len() > opts.max_shared {
            continue;
        }
        let weight = match kind {
            SoftLinkKind::Preamble => opts.preamble,
            SoftLinkKind::Encoding => opts.encoding,
            SoftLinkKind::FanOut => opts.fanout,
            SoftLinkKind::HeaderSet => opts.header_set,
            SoftLinkKind::SharedSecret => opts.shared_secret,
            SoftLinkKind::RelayStack => opts.relay_stack,
            SoftLinkKind::CallbackService => opts.callback_service,
            _ => opts.common_feature,
        };
        for (i, x) in ids.iter().enumerate() {
            for y in &ids[i + 1..] {
                push(x, y, *kind, weight, format!("{}: {value}", kind.label()));
            }
        }
    }

    // Similar rather than equal: unusual path sets and cut lengths. A path
    // set close to more than `max_shared` others is common, like an equal
    // value shared that widely.
    let sets: Vec<BTreeSet<&str>> = shown.iter().map(|c| path_set(c)).collect();
    let mut similar: Vec<(usize, usize, f64)> = Vec::new();
    for i in 0..shown.len() {
        for k in i + 1..shown.len() {
            if !sets[i].is_empty() && !sets[k].is_empty() {
                let j = jaccard(&sets[i], &sets[k]);
                if j >= 0.6 {
                    similar.push((i, k, j));
                }
            }
        }
    }
    let mut partners = vec![0usize; shown.len()];
    for &(i, k, _) in &similar {
        partners[i] += 1;
        partners[k] += 1;
    }
    for (i, k, j) in similar {
        if partners[i] <= opts.max_shared && partners[k] <= opts.max_shared {
            push(
                &shown[i].id,
                &shown[k].id,
                SoftLinkKind::PathSet,
                opts.path_set * j,
                format!("unusual path sets overlap, Jaccard {j:.2}"),
            );
        }
    }
    for (i, x) in shown.iter().enumerate() {
        for y in &shown[i + 1..] {
            if let (Some(gx), Some(gy)) = (&x.cut_lengths.url, &y.cut_lengths.url)
                && gx.min <= gy.max + 2
                && gy.min <= gx.max + 2
            {
                push(
                    &x.id,
                    &y.id,
                    SoftLinkKind::CutLength,
                    opts.cut_length,
                    format!(
                        "URLs cut at {}–{} and {}–{} characters",
                        gx.min, gx.max, gy.min, gy.max
                    ),
                );
            }
        }
    }
    crate::sort::by(&mut out, |p, q| {
        q.strength
            .total_cmp(&p.strength)
            .then(order[p.a.as_str()].cmp(&order[q.a.as_str()]))
            .then(order[p.b.as_str()].cmp(&order[q.b.as_str()]))
            .then(p.kind.cmp(&q.kind))
    });
    out
}

/// Every `REDACTED-<12 hex>` replacement in `text`.
fn redacted_in<'t>(text: &'t str, out: &mut BTreeSet<&'t str>) {
    use crate::redact::MARK;
    let mut rest = text;
    while let Some(i) = rest.find(MARK) {
        let end = i + MARK.len() + 12;
        if let Some(tok) = rest.get(i..end)
            && tok[MARK.len()..].bytes().all(|b| b.is_ascii_hexdigit())
        {
            out.insert(tok);
        }
        rest = &rest[i + MARK.len()..];
    }
}

/// Hashes of stock passwords and test values that unrelated clients send
/// alike: a match on one of these is no tie.
fn stock_secrets() -> BTreeSet<String> {
    [
        "password", "admin", "123456", "12345678", "test", "secret", "changeme", "root", "guest",
        "demo", "letmein", "qwerty",
    ]
    .iter()
    .map(|s| crate::redact::hash_token(s))
    .collect()
}

/// The single value every one of `total` items has, when `total` is at
/// least two.
fn only_value(counts: &BTreeMap<String, usize>, total: usize) -> Option<&String> {
    match counts.iter().collect::<Vec<_>>()[..] {
        [(v, &n)] if n == total && n > 1 => Some(v),
        _ => None,
    }
}

fn path_set(c: &Cluster) -> BTreeSet<&str> {
    c.paths
        .shared_unusual_sets
        .iter()
        .flat_map(|s| s.paths.iter().map(String::as_str))
        .collect()
}

fn jaccard(a: &BTreeSet<&str>, b: &BTreeSet<&str>) -> f64 {
    let inter = a.intersection(b).count();
    inter as f64 / (a.len() + b.len() - inter).max(1) as f64
}

/// Groups of clusters whose pairs, each pair's links combined (`1 - Π(1 -
/// strength)`), reach `fleet_min_strength`: connected components over those
/// pairs. `order` is every cluster id, strongest first.
pub(crate) fn candidate_fleets(
    links: &[SoftLink],
    order: &[String],
    opts: &SoftLinkOptions,
) -> Vec<CandidateFleet> {
    let pos: HashMap<&str, usize> = order
        .iter()
        .enumerate()
        .map(|(i, id)| (id.as_str(), i))
        .collect();
    let mut pairs: BTreeMap<(usize, usize), f64> = BTreeMap::new();
    for l in links {
        let miss = pairs
            .entry((pos[l.a.as_str()], pos[l.b.as_str()]))
            .or_insert(1.0);
        *miss *= 1.0 - l.strength;
    }
    let mut parent: Vec<usize> = (0..order.len()).collect();
    fn find(p: &mut [usize], x: usize) -> usize {
        let mut r = x;
        while p[r] != r {
            r = p[r];
        }
        p[x] = r;
        r
    }
    let mut strong: Vec<((usize, usize), f64)> = Vec::new();
    for (&(a, b), &miss) in &pairs {
        let s = 1.0 - miss;
        if s >= opts.fleet_min_strength {
            strong.push(((a, b), s));
            let (ra, rb) = (find(&mut parent, a), find(&mut parent, b));
            parent[ra.max(rb)] = ra.min(rb);
        }
    }
    let mut groups: BTreeMap<usize, BTreeSet<usize>> = BTreeMap::new();
    for &((a, b), _) in &strong {
        let r = find(&mut parent, a);
        groups.entry(r).or_default().extend([a, b]);
    }
    groups
        .into_values()
        .enumerate()
        .map(|(n, members)| {
            let inside = |l: &&SoftLink| {
                members.contains(&pos[l.a.as_str()]) && members.contains(&pos[l.b.as_str()])
            };
            let kinds: BTreeSet<SoftLinkKind> =
                links.iter().filter(inside).map(|l| l.kind).collect();
            CandidateFleet {
                id: format!("F{}", n + 1),
                clusters: members.iter().map(|&i| order[i].clone()).collect(),
                kinds: kinds.into_iter().collect(),
                links: links.iter().filter(inside).count(),
                strength: strong
                    .iter()
                    .filter(|((a, _), _)| members.contains(a))
                    .map(|&(_, s)| s)
                    .fold(1.0, f64::min),
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyze::analyze;
    use crate::model::Observation;
    use crate::rules::Rules;

    fn link(a: &str, b: &str, kind: SoftLinkKind, strength: f64) -> SoftLink {
        SoftLink {
            a: a.into(),
            b: b.into(),
            kind,
            strength,
            detail: String::new(),
        }
    }

    #[test]
    fn weak_links_combine_and_strong_pairs_group() {
        let order: Vec<String> = ["C1", "C2", "C3", "C4", "C5"].map(String::from).to_vec();
        let links = vec![
            link("C1", "C2", SoftLinkKind::SharedPause, 0.6),
            // Two weak links that combine past the threshold (1 - 0.7 * 0.7).
            link("C2", "C3", SoftLinkKind::Encoding, 0.3),
            link("C2", "C3", SoftLinkKind::HeaderSet, 0.3),
            // One weak link alone stays out.
            link("C4", "C5", SoftLinkKind::FanOut, 0.2),
        ];
        let f = candidate_fleets(&links, &order, &SoftLinkOptions::default());
        assert_eq!(f.len(), 1, "{f:?}");
        assert_eq!(f[0].id, "F1");
        assert_eq!(f[0].clusters, ["C1", "C2", "C3"]);
        assert_eq!(f[0].links, 3);
        assert!((f[0].strength - 0.51).abs() < 1e-9, "{}", f[0].strength);
        assert_eq!(
            f[0].kinds,
            [
                SoftLinkKind::SharedPause,
                SoftLinkKind::Encoding,
                SoftLinkKind::HeaderSet
            ]
        );
    }

    fn o(id: &str, ts: i64, url: &str) -> Observation {
        Observation {
            id: id.into(),
            ts,
            url: url.into(),
            ..Default::default()
        }
    }

    #[test]
    fn a_captured_secret_in_two_clusters_is_a_strong_soft_link() {
        // Two inboxes a week apart, both replaying one captured token.
        let pair = |secret: &str| {
            let obs: Vec<Observation> = [
                "0b6c1f0e-1111-4c2a-9a55-3f2e1d0c9b8a",
                "7d2e4a10-2222-4b3c-8a66-4e3f2a1b0c9d",
            ]
            .iter()
            .enumerate()
            .flat_map(|(f, inbox)| {
                (0..2).map(move |k| {
                    o(
                        &format!("{f}{k}"),
                        1_791_000_000 + f as i64 * 7 * 86_400 + k * 60,
                        &format!(
                            "https://h{k}.example/api?{secret}&hook=https://webhook.site/{inbox}"
                        ),
                    )
                })
            })
            .map(|mut o| {
                crate::redact::redact_observation(&mut o);
                o
            })
            .collect();
            analyze(obs, &Rules::default_rules())
        };
        let a = pair("access_token=9f8e7d6c5b4a3f2e1d0c");
        assert_eq!(a.clusters.len(), 2, "{:?}", a.clusters);
        let l: Vec<&SoftLink> = a
            .soft_links
            .iter()
            .filter(|l| l.kind == SoftLinkKind::SharedSecret)
            .collect();
        assert_eq!(l.len(), 1, "{:?}", a.soft_links);
        assert!(l[0].detail.contains("REDACTED-"), "{}", l[0].detail);
        assert!((l[0].strength - 0.8).abs() < 1e-9);
        assert_eq!(a.candidate_fleets.len(), 1);
        // A stock password is sent by everyone.
        let b = pair("password=admin");
        assert!(
            b.soft_links
                .iter()
                .all(|l| l.kind != SoftLinkKind::SharedSecret),
            "{:?}",
            b.soft_links
        );
    }

    #[test]
    fn an_uncommon_relay_stack_in_two_clusters_is_a_soft_link() {
        let fleets = |prefix: &str| {
            let obs: Vec<Observation> = [
                "0b6c1f0e-1111-4c2a-9a55-3f2e1d0c9b8a",
                "7d2e4a10-2222-4b3c-8a66-4e3f2a1b0c9d",
            ]
            .iter()
            .enumerate()
            .flat_map(|(f, inbox)| {
                (0..2).map(move |k| {
                    o(
                        &format!("{f}{k}"),
                        1_791_000_000 + f as i64 * 7 * 86_400 + k * 60,
                        &format!("{prefix}/p{k}?hook=https://webhook.site/{inbox}"),
                    )
                })
            })
            .collect();
            analyze(obs, &Rules::default_rules())
        };
        let stack = "relay.jina → relay.translate_goog → target";
        let a = fleets("https://r.jina.ai/https://www-a-example.translate.goog");
        assert_eq!(a.clusters.len(), 2, "{:?}", a.clusters);
        for c in &a.clusters {
            assert_eq!(c.relay_stacks.get(stack), Some(&2), "{:?}", c.relay_stacks);
        }
        assert!(
            a.soft_links
                .iter()
                .any(|l| l.kind == SoftLinkKind::RelayStack && l.detail.contains(stack)),
            "{:?}",
            a.soft_links
        );
        // One relay hop is every relay user's habit: described, not linked.
        let b = fleets("https://r.jina.ai/https://a.example");
        assert_eq!(
            b.clusters[0].relay_stacks.get("relay.jina → target"),
            Some(&2)
        );
        assert!(
            b.soft_links
                .iter()
                .all(|l| l.kind != SoftLinkKind::RelayStack)
        );
    }

    #[test]
    fn soft_links_never_merge_clusters_or_move_tiers() {
        // Two fleets with different inboxes, a day apart, opening every host
        // with the same recon requests and climbing the same route.
        let mut obs = Vec::new();
        for (f, inbox) in [
            "0b6c1f0e-1111-4c2a-9a55-3f2e1d0c9b8a",
            "7d2e4a10-2222-4b3c-8a66-4e3f2a1b0c9d",
        ]
        .iter()
        .enumerate()
        {
            let t0 = 1_791_000_000 + f as i64 * 86_400;
            for (k, h) in ["a.example", "b.example", "c.example"].iter().enumerate() {
                let t = t0 + 60 * k as i64;
                for (j, p) in ["/robots.txt", "/.well-known/security.txt", "/.env"]
                    .iter()
                    .enumerate()
                {
                    obs.push(o(
                        &format!("{f}{k}{j}"),
                        t + j as i64,
                        &format!("https://{h}{p}"),
                    ));
                }
                obs.push(o(
                    &format!("{f}{k}x"),
                    t + 10,
                    &format!("https://{h}/q?hook=https://webhook.site/{inbox}"),
                ));
            }
        }
        // Both use webhook.site; set that tie aside to test the preamble.
        let mut base = Rules::default_rules();
        base.set.soft_links.callback_service = 0.0;
        let a = analyze(obs.clone(), &base);
        assert_eq!(a.clusters.len(), 2, "{:?}", a.clusters);
        assert!(
            a.soft_links.iter().any(|l| l.kind == SoftLinkKind::Preamble
                && (l.a.as_str(), l.b.as_str()) == ("C1", "C2")),
            "{:?}",
            a.soft_links
        );
        // A preamble alone is not enough for a fleet.
        assert!(a.candidate_fleets.is_empty(), "{:?}", a.candidate_fleets);

        // With the callback service too, the pair reaches a fleet.
        let both = analyze(obs.clone(), &Rules::default_rules());
        assert_eq!(both.candidate_fleets.len(), 1, "{:?}", both.soft_links);
        assert!(
            both.candidate_fleets[0]
                .kinds
                .contains(&SoftLinkKind::CallbackService)
        );

        let mut rules = base;
        rules.set.soft_links.fleet_min_strength = 0.3;
        let b = analyze(obs, &rules);
        assert_eq!(b.candidate_fleets.len(), 1);
        assert_eq!(b.candidate_fleets[0].clusters, ["C1", "C2"]);
        // Same clusters, same tiers, same scores.
        assert_eq!(a.clusters.len(), b.clusters.len());
        for (x, y) in a.clusters.iter().zip(&b.clusters) {
            assert_eq!((&x.members, x.tier, x.score), (&y.members, y.tier, y.score));
        }
        let internal = crate::report::render_markdown(
            &b,
            &crate::report::ReportOptions {
                audience: crate::report::Audience::Internal,
                ..Default::default()
            },
        );
        assert!(
            internal.contains("## Candidate fleets") && internal.contains("F1"),
            "{internal}"
        );
        let provider = crate::report::render_markdown(
            &b,
            &crate::report::ReportOptions {
                audience: crate::report::Audience::Provider,
                ..Default::default()
            },
        );
        assert!(!provider.contains("Candidate fleets"));
    }
}
