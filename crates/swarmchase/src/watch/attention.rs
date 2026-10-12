//! The attention queue: every cluster above noise in the window, ranked by
//! how much it needs the admin, with the reasons for its place.
//!
//! The rank is layered, never one weighted sum of everything:
//!
//! 1. **Band** (`urgent`, `look`, `watch`), set like the agent grade by the
//!    strongest *combination* of facts: grade, the worst class of target
//!    reached, the scope pass's finding, interaction edges, trajectory.
//!    Caps hold a band down: plant signals (other than provenance
//!    monoculture, which nearly every public record shows) and declared
//!    testing at `look`, benchmark targets alone at `watch`.
//! 2. Within a band: the grade (L1 counts as L0, since anyone can write a
//!    self-description), then the worst target class, then clusters no
//!    case covers before those a case does.
//! 3. Last, **momentum**: a 0 to 100 score from named, bounded parts
//!    (growth in a day, spread of targets, interaction, recency, novelty,
//!    volume), each shown with its points. It orders leads that the facts
//!    above leave tied; it never moves a lead across a band.
//!
//! Nothing here reads a model's suggestion, and nothing changes a score,
//! tier, grade or link. History comes from the ledger ([`super::ledger`]).

use super::digest::clean_host;
use super::ledger::{EventKind, Ledger, Observed, Thread, Trajectory, level_code};
use sc_core::agentness::AgentLevel;
use sc_core::scope::{ScopeFinding, TargetClass};
use sc_core::swarm::EdgeStrength;
use sc_core::{Analysis, Cluster, PlantSignalKind, Tier, defang_host};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// The file, in the run directory.
pub const FILE: &str = "attention.json";
/// The format's name and version.
pub const SCHEMA: &str = "swarmchase-attention/1";

/// Points in a thread's sparkline.
const SPARK_POINTS: usize = 28;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Band {
    Watch,
    Look,
    Urgent,
}

impl Band {
    pub fn label(self) -> &'static str {
        match self {
            Self::Watch => "watch",
            Self::Look => "look",
            Self::Urgent => "urgent",
        }
    }
}

/// The worst class of target a cluster reached, benchmarks aside.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Harm {
    /// Public content only, or not assessed.
    None,
    Interactive,
    /// Access-controlled endpoints or third-party channels.
    Elevated,
    /// Sensitive endpoints.
    High,
}

impl Harm {
    pub fn label(self) -> &'static str {
        match self {
            Self::None => "public content",
            Self::Interactive => "interactive",
            Self::Elevated => "access-controlled or third-party",
            Self::High => "sensitive",
        }
    }
}

fn harm_of(c: &TargetClass) -> Harm {
    match c {
        TargetClass::Sensitive => Harm::High,
        TargetClass::AccessControlled | TargetClass::ThirdPartyChannel => Harm::Elevated,
        TargetClass::Interactive => Harm::Interactive,
        TargetClass::PublicContent | TargetClass::Benchmark => Harm::None,
    }
}

/// One named part of the momentum score.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Factor {
    pub name: String,
    pub points: u32,
    pub max: u32,
    pub detail: String,
}

/// One cluster in the queue.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Item {
    /// 1 is the first.
    pub rank: usize,
    pub band: Band,
    /// The ledger thread.
    pub thread: String,
    /// The cluster's number this run (`C3`) and stable key.
    pub id: String,
    pub key: String,
    pub tier: Tier,
    #[serde(with = "level_code")]
    pub grade: AgentLevel,
    pub harm: Harm,
    pub trajectory: Trajectory,
    /// Records now over a day before, when the ledger has a day-old point.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub growth: Option<f64>,
    pub records: usize,
    /// Members this run collected.
    pub added: usize,
    pub target_count: usize,
    /// Up to three target hosts, defanged.
    pub targets: Vec<String>,
    /// Sources its records came from.
    pub sources: Vec<String>,
    pub swarm_edges: usize,
    /// Its candidate fleet in this analysis (`F2`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fleet: Option<String>,
    /// The facts that set the band, strongest first.
    pub why: Vec<String>,
    /// What held the band down.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub caps: Vec<String>,
    pub momentum: u32,
    pub factors: Vec<Factor>,
    /// Cases whose records include its members.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cases: Vec<String>,
    /// The run it was first seen on.
    pub first_run: String,
    /// Records on each of its recent runs, oldest first.
    pub spark: Vec<usize>,
}

/// `attention.json`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Queue {
    pub schema: String,
    pub stamp: String,
    pub by_band: BTreeMap<String, usize>,
    pub items: Vec<Item>,
}

impl Queue {
    /// Thread id to band, for the ledger.
    pub fn bands(&self) -> BTreeMap<String, &'static str> {
        self.items
            .iter()
            .map(|i| (i.thread.clone(), i.band.label()))
            .collect()
    }
}

/// What the queue is built from.
pub struct Input<'a> {
    pub analysis: &'a Analysis,
    /// The ledger after this run's [`Ledger::observe`].
    pub ledger: &'a Ledger,
    pub observed: &'a Observed,
    pub stamp: &'a str,
    /// The run's time, Unix seconds.
    pub now: i64,
    /// Thread id to the cases covering it.
    pub cases: &'a BTreeMap<String, Vec<String>>,
}

/// Rank the clusters above noise.
pub fn rank(i: &Input) -> Queue {
    let a = i.analysis;
    let mut edge_strength: BTreeMap<&str, EdgeStrength> = BTreeMap::new();
    for e in &a.swarm_edges {
        for k in [e.a.key.as_str(), e.b.key.as_str()] {
            let s = edge_strength.entry(k).or_insert(e.strength);
            *s = (*s).max(e.strength);
        }
    }
    let mut fleet_of: BTreeMap<&str, &str> = BTreeMap::new();
    for f in &a.candidate_fleets {
        for c in &f.clusters {
            fleet_of.insert(c.as_str(), f.id.as_str());
        }
    }
    let mut items: Vec<Item> = Vec::new();
    for c in a.clusters.iter().filter(|c| c.tier >= Tier::Suggestive) {
        let Some(tid) = i.observed.threads.get(&c.id) else {
            continue;
        };
        let Some(th) = i.ledger.threads.get(tid) else {
            continue;
        };
        items.push(item(
            i,
            c,
            th,
            edge_strength.get(c.key.as_str()).copied(),
            fleet_of.get(c.id.as_str()).map(|s| s.to_string()),
        ));
    }
    let grade_rank = |g: AgentLevel| match g {
        AgentLevel::SelfDescribed => AgentLevel::PayloadsOnly,
        g => g,
    };
    items.sort_by(|x, y| {
        y.band
            .cmp(&x.band)
            .then(grade_rank(y.grade).cmp(&grade_rank(x.grade)))
            .then(y.harm.cmp(&x.harm))
            .then(x.cases.is_empty().cmp(&y.cases.is_empty()).reverse())
            .then(y.momentum.cmp(&x.momentum))
            .then(x.thread.cmp(&y.thread))
    });
    let mut by_band: BTreeMap<String, usize> = BTreeMap::new();
    for (n, it) in items.iter_mut().enumerate() {
        it.rank = n + 1;
        *by_band.entry(it.band.label().to_string()).or_default() += 1;
    }
    Queue {
        schema: SCHEMA.into(),
        stamp: i.stamp.to_string(),
        by_band,
        items,
    }
}

fn item(
    i: &Input,
    c: &Cluster,
    th: &Thread,
    edge: Option<EdgeStrength>,
    fleet: Option<String>,
) -> Item {
    let a = i.analysis;
    let grade = c.agent.level;
    let (l2, l3) = (
        grade >= AgentLevel::ModelWritten,
        grade >= AgentLevel::Adaptive,
    );
    let classes = &c.scope.target_classes;
    let (worst_class, harm) = classes
        .keys()
        .map(|k| (Some(*k), harm_of(k)))
        .max_by_key(|x| x.1)
        .unwrap_or((None, Harm::None));
    let class_label = worst_class.map_or("public", |k| k.label());
    let trajectory = th.trajectory(i.stamp);
    let growth = th.growth();
    let g = format!("{} {}", grade.code(), grade.label());

    // The facts that raise the band; the strongest wins.
    let mut raised: Vec<(Band, String)> = Vec::new();
    if l3 && harm >= Harm::Elevated {
        raised.push((Band::Urgent, format!("{g} with {class_label} targets")));
    }
    if l2 && harm == Harm::High && !l3 {
        raised.push((Band::Urgent, format!("{g} with sensitive targets")));
    }
    if l2 && c.scope.finding == ScopeFinding::ScopeExceeded {
        raised.push((
            Band::Urgent,
            format!("{g}, and the scope pass found scope exceeded"),
        ));
    }
    if l2 && c.tier == Tier::Significant && edge.is_some_and(|e| e >= EdgeStrength::Moderate) {
        raised.push((
            Band::Urgent,
            format!(
                "{g}, significant, with a {} interaction edge",
                edge.map_or("", |e| e.label())
            ),
        ));
    }
    if l2 {
        raised.push((Band::Look, g.clone()));
    }
    if c.tier == Tier::Significant && harm >= Harm::Elevated {
        raised.push((
            Band::Look,
            format!("significant, with {class_label} targets"),
        ));
    }
    if c.tier == Tier::Significant
        && matches!(trajectory, Trajectory::Growing | Trajectory::Resurgent)
    {
        raised.push((
            Band::Look,
            format!("significant and {}", trajectory.label()),
        ));
    }
    let mut band = raised.iter().map(|r| r.0).max().unwrap_or(Band::Watch);

    let mut caps: Vec<(Band, String)> = Vec::new();
    if !classes.is_empty() && classes.keys().all(|k| *k == TargetClass::Benchmark) {
        caps.push((Band::Watch, "benchmark or practice targets only".into()));
    }
    // Provenance monoculture is left out: nearly every public record comes
    // from a service anyone can submit to, so it would hold every lead.
    let plants = c
        .origin
        .plant_signals
        .iter()
        .filter(|p| p.counts() && p.kind != PlantSignalKind::ProvenanceMonoculture)
        .count();
    if plants > 0 {
        caps.push((
            Band::Look,
            format!("{plants} plant signal(s): check the records were not placed to be found"),
        ));
    }
    if !c.declared.is_empty() {
        caps.push((Band::Look, "members declare testing or research".into()));
    }
    let mut cap_text = Vec::new();
    for (cap, text) in caps {
        if band > cap {
            band = cap;
            cap_text.push(format!("held at {}: {text}", cap.label()));
        } else {
            cap_text.push(text);
        }
    }
    raised.sort_by_key(|x| std::cmp::Reverse(x.0));
    let mut why: Vec<String> = raised.into_iter().map(|r| r.1).collect();
    why.dedup();
    if why.is_empty() {
        why.push(format!("{} at {}", c.tier.label(), grade.code()));
    }

    let point = th.latest();
    let factors = momentum(i, c, th, trajectory, growth, edge, fleet.is_some());
    let mut targets: Vec<(&String, &usize)> = c.target_hosts.iter().collect();
    targets.sort_by(|x, y| y.1.cmp(x.1).then(x.0.cmp(y.0)));
    let sources: BTreeSet<&str> = c
        .members
        .iter()
        .map(|&m| a.results[m].obs.source.as_str())
        .collect();
    Item {
        rank: 0,
        band,
        thread: th.id.clone(),
        id: c.id.clone(),
        key: c.key.clone(),
        tier: c.tier,
        grade,
        harm,
        trajectory,
        growth: growth.map(|g| (g * 100.0).round() / 100.0),
        records: c.members.len(),
        added: point.map_or(0, |p| p.added),
        target_count: c.target_hosts.len(),
        targets: targets
            .iter()
            .take(3)
            .map(|(h, _)| defang_host(&clean_host(h)))
            .collect(),
        sources: sources.into_iter().map(str::to_string).collect(),
        swarm_edges: point.map_or(0, |p| p.swarm_edges),
        fleet,
        why,
        caps: cap_text,
        momentum: factors.iter().map(|f| f.points).sum(),
        factors,
        cases: i.cases.get(&th.id).cloned().unwrap_or_default(),
        first_run: th.first_run.clone(),
        spark: th.sparkline(SPARK_POINTS),
    }
}

/// The momentum parts. Each is bounded; together they reach 100.
fn momentum(
    i: &Input,
    c: &Cluster,
    th: &Thread,
    trajectory: Trajectory,
    growth: Option<f64>,
    edge: Option<EdgeStrength>,
    in_fleet: bool,
) -> Vec<Factor> {
    let part = |name: &str, frac: f64, max: u32, detail: String| Factor {
        name: name.into(),
        points: (frac.clamp(0.0, 1.0) * max as f64).round() as u32,
        max,
        detail,
    };
    let mut out = Vec::new();
    out.push(match growth {
        Some(g) => part(
            "growth",
            g.max(1.0).log2() / 3.0,
            25,
            format!("{g:.1}x its records of a day before"),
        ),
        None => part("growth", 0.0, 25, "no point a day old yet".into()),
    });
    let n = c.target_hosts.len();
    out.push(part(
        "spread",
        (1.0 + n as f64).ln() / 21f64.ln(),
        15,
        format!("{n} target host(s)"),
    ));
    let e = match edge {
        Some(EdgeStrength::Strong) => 1.0,
        Some(EdgeStrength::Moderate) => 0.6,
        Some(EdgeStrength::Weak) => 0.3,
        None => 0.0,
    };
    let edges = th.latest().map_or(0, |p| p.swarm_edges);
    out.push(part(
        "interaction",
        e + if in_fleet { 0.3 } else { 0.0 },
        20,
        match (edge, in_fleet) {
            (Some(s), f) => format!(
                "{edges} interaction edge(s), strongest {}{}",
                s.label(),
                if f { ", in a candidate fleet" } else { "" }
            ),
            (None, true) => "in a candidate fleet".into(),
            (None, false) => "none".into(),
        },
    ));
    let hours = ((i.now - c.end).max(0)) as f64 / 3600.0;
    out.push(part(
        "recency",
        1.0 - (hours - 6.0).max(0.0) / (168.0 - 6.0),
        20,
        if hours < 48.0 {
            format!("latest record {hours:.0} hour(s) before the run")
        } else {
            format!("latest record {:.0} day(s) before the run", hours / 24.0)
        },
    ));
    let rose = th
        .events
        .iter()
        .any(|e| e.run == i.stamp && matches!(e.kind, EventKind::TierUp | EventKind::GradeUp));
    out.push(match trajectory {
        Trajectory::New | Trajectory::Resurgent => {
            part("novelty", 1.0, 15, trajectory.label().into())
        }
        _ if rose => part("novelty", 0.7, 15, "rose a tier or grade this run".into()),
        _ => part("novelty", 0.0, 15, format!("seen since {}", th.first_run)),
    });
    let r = c.members.len();
    out.push(part(
        "volume",
        (1.0 + r as f64).ln() / 201f64.ln(),
        5,
        format!("{r} record(s)"),
    ));
    out
}

/// Thread id to the ids of the cases whose records include its kept
/// members. Cases not read are skipped with a warning.
pub fn case_threads(
    cases_root: &std::path::Path,
    ledger: &Ledger,
) -> BTreeMap<String, Vec<String>> {
    let mut out: BTreeMap<String, Vec<String>> = BTreeMap::new();
    if !cases_root.is_dir() {
        return out;
    }
    let cases = match crate::case::all(cases_root) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("warning: cases not read for the attention queue: {e:#}");
            return out;
        }
    };
    for c in cases {
        let ids = match crate::case::record_ids(cases_root, &c.id) {
            Ok(ids) => ids,
            Err(e) => {
                eprintln!("warning: case {} records not read: {e:#}", c.id);
                continue;
            }
        };
        for t in ledger.threads_with(&ids) {
            out.entry(t).or_default().push(c.id.clone());
        }
    }
    out
}

#[cfg(test)]
pub(crate) mod tests;
