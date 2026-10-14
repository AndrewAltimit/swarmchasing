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
//!
//! **Evidence.** Each kind has a likelihood ratio in `[soft_links]`: how
//! much likelier the link is between two clusters of one operator than
//! between unrelated ones. A pair that passed a chance test (shared pauses,
//! scaffolds, scaffold lineage, prompt echoes, co-activity, co-targets,
//! ordered co-targets) carries its kind's ratio in full.
//! Any other link's ratio is the kind's raised to its similarity (where it
//! has one) times its rarity: a shared value held by
//! `n` of the `N` clusters above noise counts `ln(N / n) / ln(N / 2)` of
//! its kind, so a value two clusters hold counts in full and one every
//! cluster holds counts nothing. Kinds that read one underlying habit are
//! not independent, so they fall into four **families** ([`Family`]):
//! within a family a pair takes its strongest link only, and across
//! families the ratios multiply (their logs add). A link's `strength` is
//! `1 - 1 / ratio`, 0 to 1.
//!
//! **Fleets.** Pairs whose combined ratio reaches `fleet_min_lr` are the
//! edges of a graph of clusters, weighted by the log of the ratio. The
//! graph is reduced to its backbone and split into communities under the
//! constant Potts model ([`crate::community`]): a community keeps only
//! clusters tied to it more strongly than `fleet_density` of the threshold
//! per pair, so one cluster tied to two fleets cannot chain them together.

use crate::analyze::{Cluster, CommonFeature, ObsResult};
use crate::dialect::DialectPair;
use crate::escalation::Escalation;
use crate::model::{LinkFeature, Tier};
use crate::timing::SharedPause;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

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
    /// Requests of one structure, values aside, beyond chance
    /// ([`crate::scaffold`]).
    Scaffold,
    /// Active in the same minutes, or one trailing the other, beyond chance
    /// ([`crate::coactivity`]).
    CoActivity,
    /// The same rare targets worked in the same hours, beyond chance
    /// ([`crate::cotarget`]).
    CoTarget,
    /// Shared rare hosts first touched in the same order by concurrent
    /// clusters, beyond chance ([`crate::cotarget::ordered_pairs`]).
    OrderedCoTarget,
    /// Request templates one structural part apart, sharing none outright,
    /// beyond chance: one harness changed mid-fleet
    /// ([`crate::scaffold::lineage_pairs`]).
    ScaffoldLineage,
    /// Prose parameter values from one template, beyond chance
    /// ([`crate::prose::prompt_echo_pairs`]).
    PromptEcho,
}

/// Kinds that read one underlying habit: a pair counts only its strongest
/// link within a family.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Family {
    /// How requests are built: encoding, header set, relay stack,
    /// scaffold, scaffold lineage, prompt echo, payload dialect, cut
    /// length, fan-out width.
    Harness,
    /// When clusters are active: shared pauses, co-activity.
    Timeline,
    /// What they go after: reruns, path sets, recon preambles, co-targets,
    /// ordered co-targets, route escalations.
    Targets,
    /// What they hold: captured secrets, common features, callback
    /// services.
    Identifiers,
}

impl Family {
    pub fn label(self) -> &'static str {
        match self {
            Family::Harness => "harness",
            Family::Timeline => "timeline",
            Family::Targets => "targets",
            Family::Identifiers => "identifiers",
        }
    }
}

impl SoftLinkKind {
    /// Every kind.
    pub const ALL: [SoftLinkKind; 20] = {
        use SoftLinkKind::*;
        [
            SharedPause,
            Dialect,
            Rerun,
            Preamble,
            PathSet,
            Encoding,
            FanOut,
            CutLength,
            HeaderSet,
            Escalation,
            CommonFeature,
            SharedSecret,
            RelayStack,
            CallbackService,
            Scaffold,
            CoActivity,
            CoTarget,
            OrderedCoTarget,
            ScaffoldLineage,
            PromptEcho,
        ]
    };

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
            SoftLinkKind::Scaffold => "shared scaffold",
            SoftLinkKind::CoActivity => "co-activity",
            SoftLinkKind::CoTarget => "co-target",
            SoftLinkKind::OrderedCoTarget => "ordered co-target",
            SoftLinkKind::ScaffoldLineage => "scaffold lineage",
            SoftLinkKind::PromptEcho => "prompt echo",
        }
    }

    /// The family whose links it does not add to.
    pub fn family(self) -> Family {
        use SoftLinkKind::*;
        match self {
            Encoding | HeaderSet | RelayStack | Scaffold | ScaffoldLineage | PromptEcho
            | Dialect | CutLength | FanOut => Family::Harness,
            SharedPause | CoActivity => Family::Timeline,
            Rerun | PathSet | Preamble | CoTarget | OrderedCoTarget | Escalation => Family::Targets,
            SharedSecret | CommonFeature | CallbackService => Family::Identifiers,
        }
    }
}

/// Soft link settings (`[soft_links]` in the rules file): each kind's
/// likelihood ratio, when a link or a shared value is too weak or too
/// common to list, and how candidate fleets are drawn.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct SoftLinkOptions {
    /// Pairs whose combined likelihood ratio reaches this are edges of the
    /// fleet graph.
    pub fleet_min_lr: f64,
    /// The share of a threshold edge's weight (the log of `fleet_min_lr`)
    /// each pair in a fleet must hold on average: the CPM resolution.
    pub fleet_density: f64,
    /// Disparity-filter level for the fleet graph's backbone.
    pub backbone_alpha: f64,
    /// Jaccard overlap of two clusters' other neighbours that keeps their
    /// edge in the backbone however even its weight.
    pub backbone_overlap: f64,
    /// A link whose own ratio, after rarity, is below this is not listed.
    pub min_link_lr: f64,
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
    /// A pair kept by the scaffold chance model ([`crate::scaffold`]).
    pub scaffold: f64,
    /// A pair kept by the co-activity chance model ([`crate::coactivity`]).
    /// A pair already tied by shared pauses gets no co-activity link: both
    /// read one timeline.
    pub co_activity: f64,
    /// A pair kept by the co-target chance model ([`crate::cotarget`]).
    pub co_target: f64,
    /// A pair kept by the ordered co-target chance model
    /// ([`crate::cotarget::ordered_pairs`]).
    pub ordered_co_target: f64,
    /// A pair kept by the scaffold lineage chance model
    /// ([`crate::scaffold::lineage_pairs`]).
    pub scaffold_lineage: f64,
    /// A pair kept by the prompt echo chance model
    /// ([`crate::prose::prompt_echo_pairs`]).
    pub prompt_echo: f64,
}

impl Default for SoftLinkOptions {
    fn default() -> Self {
        Self {
            fleet_min_lr: 20.0,
            fleet_density: 0.5,
            backbone_alpha: 0.05,
            backbone_overlap: 0.5,
            min_link_lr: 2.0,
            max_shared: 10,
            shared_pause: 4.0,
            dialect: 2.0,
            rerun: 25.0,
            preamble: 3.0,
            path_set: 3.0,
            encoding: 1.0,
            fanout: 1.0,
            cut_length: 2.0,
            header_set: 2.0,
            escalation: 28.0,
            common_feature: 2.0,
            shared_secret: 50.0,
            relay_stack: 1.0,
            callback_service: 1.0,
            scaffold: 20.0,
            co_activity: 25.0,
            co_target: 34.0,
            ordered_co_target: 34.0,
            scaffold_lineage: 20.0,
            prompt_echo: 20.0,
        }
    }
}

impl SoftLinkOptions {
    /// The likelihood ratio of `kind` at full similarity and rarity.
    pub fn lr(&self, kind: SoftLinkKind) -> f64 {
        use SoftLinkKind::*;
        match kind {
            SharedPause => self.shared_pause,
            Dialect => self.dialect,
            Rerun => self.rerun,
            Preamble => self.preamble,
            PathSet => self.path_set,
            Encoding => self.encoding,
            FanOut => self.fanout,
            CutLength => self.cut_length,
            HeaderSet => self.header_set,
            Escalation => self.escalation,
            CommonFeature => self.common_feature,
            SharedSecret => self.shared_secret,
            RelayStack => self.relay_stack,
            CallbackService => self.callback_service,
            Scaffold => self.scaffold,
            CoActivity => self.co_activity,
            CoTarget => self.co_target,
            OrderedCoTarget => self.ordered_co_target,
            ScaffoldLineage => self.scaffold_lineage,
            PromptEcho => self.prompt_echo,
        }
    }

    /// Set the likelihood ratio of `kind`.
    pub fn set_lr(&mut self, kind: SoftLinkKind, lr: f64) {
        use SoftLinkKind::*;
        let f = match kind {
            SharedPause => &mut self.shared_pause,
            Dialect => &mut self.dialect,
            Rerun => &mut self.rerun,
            Preamble => &mut self.preamble,
            PathSet => &mut self.path_set,
            Encoding => &mut self.encoding,
            FanOut => &mut self.fanout,
            CutLength => &mut self.cut_length,
            HeaderSet => &mut self.header_set,
            Escalation => &mut self.escalation,
            CommonFeature => &mut self.common_feature,
            SharedSecret => &mut self.shared_secret,
            RelayStack => &mut self.relay_stack,
            CallbackService => &mut self.callback_service,
            Scaffold => &mut self.scaffold,
            CoActivity => &mut self.co_activity,
            CoTarget => &mut self.co_target,
            OrderedCoTarget => &mut self.ordered_co_target,
            ScaffoldLineage => &mut self.scaffold_lineage,
            PromptEcho => &mut self.prompt_echo,
        };
        *f = lr;
    }
}

/// One descriptive tie between two clusters. Never a merge.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SoftLink {
    /// Cluster ids, `a` the stronger (lower-numbered).
    pub a: String,
    pub b: String,
    pub kind: SoftLinkKind,
    /// `1 - 1 / lr`, 0 to 1.
    pub strength: f64,
    /// Its likelihood ratio: the kind's, raised to its similarity and
    /// rarity.
    #[serde(default = "one")]
    pub lr: f64,
    pub detail: String,
}

fn one() -> f64 {
    1.0
}

/// The strength of likelihood ratio `lr`: `1 - 1 / lr`, 0 at or below 1.
pub fn strength_of(lr: f64) -> f64 {
    if lr > 1.0 { 1.0 - 1.0 / lr } else { 0.0 }
}

/// Clusters a community of the fleet graph holds: a proposal that one
/// operator may run them all.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct CandidateFleet {
    /// `F1`, `F2`, ... in this analysis.
    pub id: String,
    /// Cluster ids, strongest first.
    pub clusters: Vec<String>,
    /// Kinds of the soft links inside it.
    pub kinds: Vec<SoftLinkKind>,
    /// Soft links between its clusters.
    pub links: usize,
    /// The weakest combined pair strength among its edges.
    pub strength: f64,
    /// The weakest combined likelihood ratio among its edges.
    #[serde(default)]
    pub min_lr: f64,
    /// Share of its pairs that are edges of the fleet graph.
    #[serde(default)]
    pub density: f64,
    /// Its weakest cut: the combined likelihood ratio of the edges that,
    /// removed, would split it, and the clusters on the smaller side.
    #[serde(default)]
    pub cut_lr: f64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cut: Vec<String>,
}

/// One pair's soft links combined: the strongest link of each family, and
/// the product of their ratios.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PairEvidence {
    pub a: String,
    pub b: String,
    /// Each family's strongest link: kind and ratio.
    pub families: Vec<(Family, SoftLinkKind, f64)>,
    /// Product of the families' ratios.
    pub lr: f64,
}

/// Every linked pair's combined evidence, by `(a, b)` as the links name
/// them.
pub fn pair_evidence(links: &[SoftLink]) -> BTreeMap<(String, String), PairEvidence> {
    let mut best: BTreeMap<(String, String), BTreeMap<Family, (SoftLinkKind, f64)>> =
        BTreeMap::new();
    for l in links {
        let fam = best.entry((l.a.clone(), l.b.clone())).or_default();
        let e = fam.entry(l.kind.family()).or_insert((l.kind, l.lr));
        if l.lr > e.1 {
            *e = (l.kind, l.lr);
        }
    }
    best.into_iter()
        .map(|((a, b), fam)| {
            let lr = fam.values().map(|x| x.1.max(1.0).ln()).sum::<f64>().exp();
            let families = fam.into_iter().map(|(f, (k, r))| (f, k, r)).collect();
            ((a.clone(), b.clone()), PairEvidence { a, b, families, lr })
        })
        .collect()
}

/// What the soft links are read from.
pub(crate) struct Signals<'a> {
    pub clusters: &'a [Cluster],
    pub results: &'a [ObsResult],
    pub shared_pauses: &'a [SharedPause],
    pub dialect_pairs: &'a [DialectPair],
    pub escalations: &'a [Escalation],
    pub common_features: &'a [CommonFeature],
    pub scaffold_pairs: &'a [crate::scaffold::ScaffoldPair],
    pub coactive_pairs: &'a [crate::coactivity::CoActivePair],
    pub cotarget_pairs: &'a [crate::cotarget::CoTargetPair],
    pub ordered_cotarget_pairs: &'a [crate::cotarget::OrderedCoTargetPair],
    pub lineage_pairs: &'a [crate::scaffold::LineagePair],
    pub prompt_echo_pairs: &'a [crate::prose::PromptEchoPair],
}

/// How much of its kind a value held by `n` of `total` clusters counts:
/// `ln(total / n) / ln(total / 2)`, 1 for a value two clusters hold, 0 for
/// one every cluster holds.
pub fn rarity(n: usize, total: usize) -> f64 {
    if total <= 2 || n <= 2 {
        return 1.0;
    }
    ((total as f64 / n as f64).ln() / (total as f64 / 2.0).ln()).clamp(0.0, 1.0)
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
    let shown_ids: HashSet<&str> = shown.iter().map(|c| c.id.as_str()).collect();
    let is_shown = |id: &str| shown_ids.contains(id);
    let total = shown.len();
    // Each link with its clusters' positions, to sort by.
    let mut out: Vec<(usize, usize, SoftLink)> = Vec::new();
    // `weight` is the share of the kind's ratio the link carries (its
    // similarity times its rarity), as an exponent.
    let mut push = |x: &str, y: &str, kind: SoftLinkKind, weight: f64, detail: String| {
        if x == y || !is_shown(x) || !is_shown(y) {
            return;
        }
        let base = opts.lr(kind);
        if base <= 1.0 || weight <= 0.0 {
            return;
        }
        let lr = base.powf(weight.min(1.0));
        if lr < opts.min_link_lr.max(1.0) || lr <= 1.0 {
            return;
        }
        let (ox, oy) = (order[x], order[y]);
        let ((a, oa), (b, ob)) = if ox <= oy {
            ((x, ox), (y, oy))
        } else {
            ((y, oy), (x, ox))
        };
        let link = SoftLink {
            a: a.into(),
            b: b.into(),
            kind,
            strength: strength_of(lr),
            lr,
            detail,
        };
        out.push((oa, ob, link));
    };

    for p in s.shared_pauses {
        push(&p.a, &p.b, SoftLinkKind::SharedPause, 1.0, p.reason.clone());
    }
    for p in s.dialect_pairs {
        push(
            &p.a,
            &p.b,
            SoftLinkKind::Dialect,
            p.jaccard,
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
            m.weighted_jaccard,
            format!(
                "{} shared target hosts in the same order ({:.0}%), weighted Jaccard {:.2}",
                m.shared.len(),
                m.order * 100.0,
                m.weighted_jaccard
            ),
        );
    }
    // Pairs that passed a chance test carry their kind's ratio in full: the
    // test, not the similarity, is the evidence.
    for p in s.scaffold_pairs {
        push(&p.a, &p.b, SoftLinkKind::Scaffold, 1.0, p.detail());
    }
    let paused: HashSet<(&str, &str)> = s
        .shared_pauses
        .iter()
        .flat_map(|q| [(q.a.as_str(), q.b.as_str()), (q.b.as_str(), q.a.as_str())])
        .collect();
    for p in s.coactive_pairs {
        if !paused.contains(&(p.a.as_str(), p.b.as_str())) {
            push(&p.a, &p.b, SoftLinkKind::CoActivity, 1.0, p.detail());
        }
    }
    for p in s.cotarget_pairs {
        push(&p.a, &p.b, SoftLinkKind::CoTarget, 1.0, p.detail());
    }
    for p in s.ordered_cotarget_pairs {
        push(&p.a, &p.b, SoftLinkKind::OrderedCoTarget, 1.0, p.detail());
    }
    for p in s.lineage_pairs {
        push(&p.a, &p.b, SoftLinkKind::ScaffoldLineage, 1.0, p.detail());
    }
    for p in s.prompt_echo_pairs {
        push(&p.a, &p.b, SoftLinkKind::PromptEcho, 1.0, p.detail());
    }
    for e in s.escalations {
        for (i, x) in e.clusters.iter().enumerate() {
            for y in &e.clusters[i + 1..] {
                push(
                    x,
                    y,
                    SoftLinkKind::Escalation,
                    rarity(e.clusters.len(), total),
                    format!("{} on {}{}", e.route_line(), e.host, e.path),
                );
            }
        }
    }

    // Values the clusters share: pair the clusters holding each, unless too
    // many do, each counting by its rarity.
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
    // A burned identifier (quoted in a public report) ties nothing: anyone
    // can copy it.
    let common: BTreeSet<&LinkFeature> = s
        .common_features
        .iter()
        .filter(|c| !c.published)
        .map(|c| &c.feature)
        .collect();
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
        let weight = rarity(ids.len(), total);
        for (i, x) in ids.iter().enumerate() {
            for y in &ids[i + 1..] {
                push(
                    x,
                    y,
                    *kind,
                    weight,
                    format!("{}: {value} ({} clusters)", kind.label(), ids.len()),
                );
            }
        }
    }

    // Similar rather than equal: unusual path sets and cut lengths. A path
    // set close to more than `max_shared` others is common, like an equal
    // value shared that widely; one close to fewer counts by its rarity.
    let sets: Vec<BTreeSet<&str>> = shown.iter().map(|c| path_set(c)).collect();
    let mut similar: Vec<(usize, usize, f64)> = Vec::new();
    // Jaccard 0.6 needs a shared path, so only sets sharing one are compared.
    for (i, k) in sharing_pairs(&sets) {
        let j = jaccard(&sets[i], &sets[k]);
        if j >= 0.6 {
            similar.push((i, k, j));
        }
    }
    let mut partners = vec![0usize; shown.len()];
    for &(i, k, _) in &similar {
        partners[i] += 1;
        partners[k] += 1;
    }
    for (i, k, j) in similar {
        if partners[i] <= opts.max_shared && partners[k] <= opts.max_shared {
            let holders = 1 + partners[i].max(partners[k]);
            push(
                &shown[i].id,
                &shown[k].id,
                SoftLinkKind::PathSet,
                j * rarity(holders, total),
                format!("unusual path sets overlap, Jaccard {j:.2}"),
            );
        }
    }
    let groups: Vec<Option<(usize, usize)>> = shown
        .iter()
        .map(|c| c.cut_lengths.url.map(|g| (g.min, g.max)))
        .collect();
    let near = near_ranges(&groups, 2);
    let mut partners = vec![0usize; shown.len()];
    for &(i, k) in &near {
        partners[i] += 1;
        partners[k] += 1;
    }
    for (i, k) in near {
        if partners[i] > opts.max_shared || partners[k] > opts.max_shared {
            continue;
        }
        let (x, y) = (shown[i], shown[k]);
        let (gx, gy) = (groups[i].unwrap_or_default(), groups[k].unwrap_or_default());
        push(
            &x.id,
            &y.id,
            SoftLinkKind::CutLength,
            rarity(1 + partners[i].max(partners[k]), total),
            format!(
                "URLs cut at {}–{} and {}–{} characters",
                gx.0, gx.1, gy.0, gy.1
            ),
        );
    }
    crate::sort::by(&mut out, |(pa, pb, p), (qa, qb, q)| {
        q.lr.total_cmp(&p.lr)
            .then(pa.cmp(qa))
            .then(pb.cmp(qb))
            .then(p.kind.cmp(&q.kind))
    });
    out.into_iter().map(|(_, _, l)| l).collect()
}

/// Every `REDACTED-<12 hex>` replacement in `text`.
pub(crate) fn redacted_in<'t>(text: &'t str, out: &mut BTreeSet<&'t str>) {
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
pub(crate) fn stock_secrets() -> BTreeSet<String> {
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

/// Every pair `(i, k)`, `i < k`, of non-empty sets sharing at least one
/// element, in that order.
fn sharing_pairs(sets: &[BTreeSet<&str>]) -> Vec<(usize, usize)> {
    let lists: Vec<Vec<&str>> = sets.iter().map(|s| s.iter().copied().collect()).collect();
    let counts = crate::dialect::SharedCounts::new(&lists);
    (0..sets.len())
        .flat_map(|i| counts.later(i, 1).into_iter().map(move |(k, _)| (i, k)))
        .collect()
}

/// Every pair `(i, k)`, `i < k`, of ranges `(min, max)` that overlap once
/// widened by `slack` (`min_i <= max_k + slack` and `min_k <= max_i +
/// slack`), in that order. `None` ranges pair with nothing.
fn near_ranges(ranges: &[Option<(usize, usize)>], slack: usize) -> Vec<(usize, usize)> {
    let mut by_min: Vec<(usize, usize, usize)> = ranges
        .iter()
        .enumerate()
        .filter_map(|(i, r)| r.map(|(lo, hi)| (lo, hi, i)))
        .collect();
    crate::sort::sort(&mut by_min);
    let mut out = Vec::new();
    for (n, &(lo, hi, i)) in by_min.iter().enumerate() {
        // Sorted by min, so `lo <= lo_k <= hi_k` already holds; the other
        // side holds for every later range up to the first that starts past
        // this one's widened end.
        for &(lo_k, hi_k, k) in &by_min[n + 1..] {
            if lo_k > hi + slack {
                break;
            }
            if lo <= hi_k + slack {
                out.push((i.min(k), i.max(k)));
            }
        }
    }
    crate::sort::sort(&mut out);
    out
}

fn jaccard(a: &BTreeSet<&str>, b: &BTreeSet<&str>) -> f64 {
    let inter = a.intersection(b).count();
    inter as f64 / (a.len() + b.len() - inter).max(1) as f64
}

/// Candidate fleets: pairs whose combined ratio ([`pair_evidence`]) reaches
/// `fleet_min_lr` are edges weighted by the log of the ratio; the graph is
/// reduced to its backbone and split into CPM communities at resolution
/// `fleet_density` times the log of `fleet_min_lr` ([`crate::community`]).
/// Each community of two or more clusters is a fleet. `order` is every
/// cluster id, strongest first.
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
    let min = opts.fleet_min_lr.max(1.0 + 1e-9);
    let mut edges: Vec<crate::community::Edge> = Vec::new();
    let mut edge_lr: BTreeMap<(usize, usize), f64> = BTreeMap::new();
    for ((a, b), e) in pair_evidence(links) {
        let (Some(&x), Some(&y)) = (pos.get(a.as_str()), pos.get(b.as_str())) else {
            continue;
        };
        // The product passes through logs: a ratio at the threshold may
        // come back a rounding below it.
        if e.lr >= min * (1.0 - 1e-9) {
            let (x, y) = (x.min(y), x.max(y));
            edges.push((x, y, e.lr.ln()));
            edge_lr.insert((x, y), e.lr);
        }
    }
    crate::sort::by(&mut edges, |p, q| (p.0, p.1).cmp(&(q.0, q.1)));
    let kept = crate::community::backbone(
        order.len(),
        &edges,
        opts.backbone_alpha,
        opts.backbone_overlap,
    );
    let gamma = opts.fleet_density.max(0.0) * min.ln();
    let labels = crate::community::leiden_cpm(order.len(), &kept, gamma);
    let mut groups: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
    for (v, &l) in labels.iter().enumerate() {
        groups.entry(l).or_default().push(v);
    }
    let mut fleets: Vec<Vec<usize>> = groups.into_values().filter(|g| g.len() >= 2).collect();
    // Strongest member first.
    crate::sort::by_key(&mut fleets, |g| g[0]);
    fleets
        .into_iter()
        .enumerate()
        .map(|(n, members)| {
            let set: BTreeSet<usize> = members.iter().copied().collect();
            let inside: Vec<crate::community::Edge> = kept
                .iter()
                .copied()
                .filter(|e| set.contains(&e.0) && set.contains(&e.1))
                .collect();
            let min_lr = inside
                .iter()
                .map(|e| edge_lr[&(e.0, e.1)])
                .fold(f64::INFINITY, f64::min);
            let min_lr = if min_lr.is_finite() { min_lr } else { 1.0 };
            let pairs = members.len() * (members.len() - 1) / 2;
            let (cut, side) = crate::community::min_cut(&members, &inside).unwrap_or_default();
            let mut kinds = BTreeSet::new();
            let mut count = 0;
            for l in links {
                if let (Some(a), Some(b)) = (pos.get(l.a.as_str()), pos.get(l.b.as_str()))
                    && set.contains(a)
                    && set.contains(b)
                {
                    kinds.insert(l.kind);
                    count += 1;
                }
            }
            CandidateFleet {
                id: format!("F{}", n + 1),
                clusters: members.iter().map(|&i| order[i].clone()).collect(),
                kinds: kinds.into_iter().collect(),
                links: count,
                strength: strength_of(min_lr),
                min_lr,
                density: inside.len() as f64 / pairs.max(1) as f64,
                cut_lr: cut.exp(),
                cut: side.into_iter().map(|i| order[i].clone()).collect(),
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

    fn link(a: &str, b: &str, kind: SoftLinkKind, lr: f64) -> SoftLink {
        SoftLink {
            a: a.into(),
            b: b.into(),
            kind,
            strength: strength_of(lr),
            lr,
            detail: String::new(),
        }
    }

    #[test]
    fn families_take_their_strongest_link_and_multiply() {
        let links = vec![
            // Two harness links: only the stronger counts.
            link("C2", "C3", SoftLinkKind::Encoding, 6.0),
            link("C2", "C3", SoftLinkKind::HeaderSet, 4.0),
            // A targets link multiplies in.
            link("C2", "C3", SoftLinkKind::Preamble, 5.0),
        ];
        let e = &pair_evidence(&links)[&("C2".to_string(), "C3".to_string())];
        assert!((e.lr - 30.0).abs() < 1e-9, "{e:?}");
        assert_eq!(
            e.families,
            [
                (Family::Harness, SoftLinkKind::Encoding, 6.0),
                (Family::Targets, SoftLinkKind::Preamble, 5.0)
            ]
        );
        // Every kind has a family, and the kinds list is complete.
        assert_eq!(SoftLinkKind::ALL.len(), 20);
        assert_eq!(SoftLinkKind::CoTarget.family(), Family::Targets);
        assert_eq!(SoftLinkKind::OrderedCoTarget.family(), Family::Targets);
        assert_eq!(SoftLinkKind::ScaffoldLineage.family(), Family::Harness);
        assert_eq!(SoftLinkKind::PromptEcho.family(), Family::Harness);
        let mut o = SoftLinkOptions::default();
        for k in SoftLinkKind::ALL {
            o.set_lr(k, 7.0);
            assert_eq!(o.lr(k), 7.0, "{k:?}");
        }
        assert_eq!(SoftLinkKind::CallbackService.family(), Family::Identifiers);
    }

    #[test]
    fn strong_pairs_group_and_weak_ones_stay_out() {
        let order: Vec<String> = ["C1", "C2", "C3", "C4", "C5"].map(String::from).to_vec();
        let links = vec![
            link("C1", "C2", SoftLinkKind::SharedPause, 30.0),
            // Two harness links count once; with a preamble they pass.
            link("C2", "C3", SoftLinkKind::Encoding, 6.0),
            link("C2", "C3", SoftLinkKind::HeaderSet, 6.0),
            link("C2", "C3", SoftLinkKind::Preamble, 5.0),
            // One weak link alone stays out.
            link("C4", "C5", SoftLinkKind::FanOut, 6.0),
        ];
        let f = candidate_fleets(&links, &order, &SoftLinkOptions::default());
        assert_eq!(f.len(), 1, "{f:?}");
        assert_eq!(f[0].id, "F1");
        assert_eq!(f[0].clusters, ["C1", "C2", "C3"]);
        assert_eq!(f[0].links, 4);
        assert!((f[0].min_lr - 30.0).abs() < 1e-9, "{f:?}");
        assert!((f[0].strength - (1.0 - 1.0 / 30.0)).abs() < 1e-9);
        assert!((f[0].density - 2.0 / 3.0).abs() < 1e-9);
        // It falls apart at one edge: either end of the chain.
        assert!((f[0].cut_lr - 30.0).abs() < 1e-6, "{}", f[0].cut_lr);
        assert_eq!(f[0].cut.len(), 1);
        assert_eq!(
            f[0].kinds,
            [
                SoftLinkKind::SharedPause,
                SoftLinkKind::Preamble,
                SoftLinkKind::Encoding,
                SoftLinkKind::HeaderSet
            ]
        );
    }

    #[test]
    fn a_hub_tied_to_two_fleets_chains_neither() {
        let order: Vec<String> = (1..=7).map(|i| format!("C{i}")).collect();
        let mut links = Vec::new();
        for g in [[1, 2, 3], [4, 5, 6]] {
            for (i, x) in g.iter().enumerate() {
                for y in &g[i + 1..] {
                    links.push(link(
                        &format!("C{x}"),
                        &format!("C{y}"),
                        SoftLinkKind::SharedSecret,
                        50.0,
                    ));
                }
            }
        }
        // C7 shares a scaffold with every member of both.
        for x in 1..=6 {
            links.push(link(&format!("C{x}"), "C7", SoftLinkKind::Scaffold, 25.0));
        }
        let f = candidate_fleets(&links, &order, &SoftLinkOptions::default());
        let groups: Vec<&[String]> = f.iter().map(|f| f.clusters.as_slice()).collect();
        assert_eq!(
            groups,
            [["C1", "C2", "C3"].as_slice(), ["C4", "C5", "C6"].as_slice()],
            "{f:?}"
        );
        for x in &f {
            assert_eq!(x.density, 1.0);
        }
    }

    #[test]
    fn rarity_counts_a_widely_held_value_for_less() {
        assert_eq!(rarity(2, 20), 1.0);
        assert_eq!(rarity(5, 2), 1.0);
        assert_eq!(rarity(20, 20), 0.0);
        let r = rarity(5, 20);
        assert!((r - (4f64).ln() / (10f64).ln()).abs() < 1e-12, "{r}");
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
        assert!((l[0].lr - 50.0).abs() < 1e-9, "{:?}", l[0]);
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
            let mut rules = Rules::default_rules();
            rules.set.soft_links.relay_stack = 3.0;
            analyze(obs, &rules)
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
        let rules = |callback: f64| {
            let mut r = Rules::default_rules();
            r.set.soft_links.preamble = 5.0;
            r.set.soft_links.callback_service = callback;
            r
        };
        let both_on = rules(5.0);
        let base = rules(0.0);
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

        // With the callback service too (another family), the pair reaches
        // a fleet.
        let both = analyze(obs.clone(), &both_on);
        assert_eq!(both.candidate_fleets.len(), 1, "{:?}", both.soft_links);
        assert!(
            both.candidate_fleets[0]
                .kinds
                .contains(&SoftLinkKind::CallbackService)
        );

        let mut rules = base;
        rules.set.soft_links.fleet_min_lr = 4.0;
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

    /// A small deterministic generator for the index tests.
    fn lcg(seed: &mut u64) -> u64 {
        *seed = seed
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        *seed >> 33
    }

    #[test]
    fn near_ranges_finds_every_overlapping_pair_once() {
        let mut seed = 3;
        let ranges: Vec<Option<(usize, usize)>> = (0..200)
            .map(|_| {
                let lo = (lcg(&mut seed) % 300) as usize;
                let w = (lcg(&mut seed) % 12) as usize;
                (!lcg(&mut seed).is_multiple_of(5)).then_some((lo, lo + w))
            })
            .collect();
        let mut brute = Vec::new();
        for i in 0..ranges.len() {
            for k in i + 1..ranges.len() {
                if let (Some(x), Some(y)) = (ranges[i], ranges[k])
                    && x.0 <= y.1 + 2
                    && y.0 <= x.1 + 2
                {
                    brute.push((i, k));
                }
            }
        }
        assert!(!brute.is_empty());
        assert_eq!(near_ranges(&ranges, 2), brute);
        assert!(near_ranges(&[None, Some((3, 4))], 2).is_empty());
        assert_eq!(near_ranges(&[Some((10, 12)), Some((14, 20))], 2), [(0, 1)]);
        assert!(near_ranges(&[Some((10, 12)), Some((15, 20))], 2).is_empty());
    }

    #[test]
    fn sharing_pairs_are_the_pairs_with_a_common_path() {
        let mut seed = 9;
        let names: Vec<String> = (0..40).map(|i| format!("/p{i}")).collect();
        let sets: Vec<BTreeSet<&str>> = (0..120)
            .map(|_| {
                let n = lcg(&mut seed) % 4;
                (0..n)
                    .map(|_| names[(lcg(&mut seed) % 40) as usize].as_str())
                    .collect()
            })
            .collect();
        let mut brute = Vec::new();
        for i in 0..sets.len() {
            for k in i + 1..sets.len() {
                if sets[i].intersection(&sets[k]).next().is_some() {
                    brute.push((i, k));
                }
            }
        }
        assert!(!brute.is_empty());
        assert_eq!(sharing_pairs(&sets), brute);
    }
}
