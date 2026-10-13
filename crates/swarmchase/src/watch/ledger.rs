//! `ledger.json`: each cluster's history across runs, past the analysis
//! window.
//!
//! Every run analyses its window afresh: cluster numbers change, and a
//! cluster's key changes when its earliest member leaves the window. The
//! ledger follows each cluster above noise as a **thread** from run to run,
//! by its key and, when the key changes, by the member records it shares
//! with a thread seen before. It keeps one [`Point`] per run the thread was
//! in the analysis, and the events between them: a new key, a merge, a
//! split, a rise in tier or grade, a return after a quiet spell.
//!
//! Linking features join records only within days of each other, so an
//! operator who uses the same inbox or run tag again weeks later starts a
//! new cluster. A new thread that carries a linking feature of an earlier
//! thread names it in `recurs`, and after a quiet week or more it counts as
//! a return. Neither merges the two.
//!
//! Candidate fleets are followed too ([`Ledger::observe_fleets`]): each
//! keeps an `FK-` key from its earliest member thread and continues the
//! earlier fleet whose threads it overlaps most, and each pair of threads
//! accumulates its soft-link evidence over windows that share no record,
//! decaying with time ([`sc_core::fleet_track`]). A pair that adds up past
//! the bound while no fleet holds it is listed in the digest
//! ([`super::fleet_threads`]).
//!
//! The ledger is descriptive. It never changes a score, tier, grade or
//! link; the attention queue ([`super::attention`]) and the shadow autonomy
//! log ([`super::autonomy`]) read it. It stays in the data directory, under
//! the watch's retention.

use sc_core::agentness::AgentLevel;
use sc_core::fleet_track::{self, PairTrack};
use sc_core::{Analysis, Tier};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// The file, in the data directory.
pub const FILE: &str = "ledger.json";
/// The format's name and version.
pub const SCHEMA: &str = "swarmchase-ledger/1";

/// Member record ids kept per thread to follow it when its key changes:
/// the latest by time.
const MEMBERS_KEPT: usize = 200;
/// Linking features kept per thread, to know it when it returns.
const FEATURES_KEPT: usize = 20;
/// A gap in a thread's activity at least this long, followed by new
/// records, is a return ([`EventKind::Resurgent`]).
pub const RESURGE_GAP_SECS: i64 = 7 * 86_400;
/// Growth is measured against the latest point at least this much older.
pub const GROWTH_SPAN_SECS: i64 = 86_400;

const DAY: i64 = 86_400;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Ledger {
    #[serde(default)]
    pub schema: String,
    /// By thread id.
    #[serde(default)]
    pub threads: BTreeMap<String, Thread>,
    /// Candidate fleets followed across runs, by key (`FK-...`). A key is
    /// never given to another fleet.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub fleets: BTreeMap<String, FleetThread>,
    /// Soft-link evidence per pair of threads, accumulated across runs.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pairs: Vec<PairTrack>,
}

/// One candidate fleet followed across runs ([`sc_core::fleet_track`]).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FleetThread {
    /// `FK-` and a hash of its earliest member thread when it began.
    pub id: String,
    /// Member thread ids on the latest run it was seen, sorted.
    pub members: Vec<String>,
    pub first_run: String,
    pub last_run: String,
    /// The latest run's time it was seen.
    pub last_t: i64,
    /// Runs it was seen on.
    pub runs: usize,
    /// Most member threads it has had.
    pub peak: usize,
    /// Its number on the latest run it was seen (`F2`).
    pub fleet: String,
    /// Soft-link kinds inside it on that run.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub kinds: Vec<String>,
    /// Its weakest edge's likelihood ratio and its density on that run.
    pub min_lr: f64,
    pub density: f64,
}

/// What one run's fleet observation found, for the digest.
#[derive(Debug, Default)]
pub struct FleetsObserved {
    /// Candidate fleet (`F1`) to its key.
    pub keys: BTreeMap<String, String>,
    /// Keys first seen on this run.
    pub new: BTreeSet<String>,
    /// Pairs whose accumulated evidence reaches the persistence bound and
    /// that no current candidate fleet holds together, strongest first.
    pub persistent: Vec<PairTrack>,
}

/// One cluster followed across runs.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Thread {
    /// The key the thread was first seen with; it keeps it when the
    /// cluster's key changes.
    pub id: String,
    /// The cluster's key on the latest run it was seen.
    pub key: String,
    /// Every key it has had, oldest first.
    #[serde(default)]
    pub keys: Vec<String>,
    pub first_run: String,
    pub last_run: String,
    /// Earliest and latest record time it has held.
    pub first_ts: i64,
    pub last_ts: i64,
    pub peak_tier: Tier,
    #[serde(with = "level_code")]
    pub peak_grade: AgentLevel,
    /// One per run it was in the analysis, oldest first.
    #[serde(default)]
    pub points: Vec<Point>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub events: Vec<Event>,
    /// The thread it was merged into, when its records joined another.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub merged_into: Option<String>,
    /// Up to [`MEMBERS_KEPT`] member record ids from the latest run it was
    /// seen, sorted.
    #[serde(default)]
    pub members: Vec<String>,
    /// Up to [`FEATURES_KEPT`] of its linking features, sorted.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub features: Vec<String>,
    /// An earlier thread it shares a linking feature with, when it began.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recurs: Option<String>,
}

/// A thread on one run.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Point {
    pub run: String,
    /// The run's time, Unix seconds.
    pub t: i64,
    /// The cluster's number in that run (`C3`).
    pub id: String,
    pub tier: Tier,
    #[serde(with = "level_code")]
    pub grade: AgentLevel,
    pub records: usize,
    /// Members that run collected.
    pub added: usize,
    pub targets: usize,
    /// Latest record time.
    pub end: i64,
    /// Interaction edges touching it that run.
    #[serde(default)]
    pub swarm_edges: usize,
    /// Its attention band that run (`urgent`, `look`, `watch`), set after
    /// ranking.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub band: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    /// The cluster's key changed (its earliest member left the window).
    Rekeyed,
    /// Another thread's records joined this one.
    Merged,
    /// It began as part of another thread.
    Split,
    TierUp,
    GradeUp,
    /// New records after a quiet spell of at least a week, in the thread
    /// or in an earlier thread it shares a linking feature with.
    Resurgent,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Event {
    pub run: String,
    pub kind: EventKind,
    pub detail: String,
}

/// Where a thread stands on the latest run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Trajectory {
    /// Not in the latest analysis.
    Dormant,
    /// In the analysis, nothing collected for it in the last day.
    Quiet,
    /// Records collected for it in the last day.
    Active,
    /// At least twice its records of a day before, and three more.
    Growing,
    /// New records after a quiet spell of a week or more, its own or an
    /// earlier thread's it shares a linking feature with.
    Resurgent,
    /// First seen on the latest run.
    New,
}

impl Trajectory {
    pub fn label(self) -> &'static str {
        match self {
            Self::Dormant => "dormant",
            Self::Quiet => "quiet",
            Self::Active => "active",
            Self::Growing => "growing",
            Self::Resurgent => "back after a quiet spell",
            Self::New => "new",
        }
    }
}

impl Thread {
    pub fn latest(&self) -> Option<&Point> {
        self.points.last()
    }

    /// Records now over records at the latest point at least a day older,
    /// when there is one with records.
    pub fn growth(&self) -> Option<f64> {
        let now = self.points.last()?;
        let base = self
            .points
            .iter()
            .rev()
            .find(|p| p.t <= now.t - GROWTH_SPAN_SECS && p.records > 0)?;
        Some(now.records as f64 / base.records as f64)
    }

    /// Where it stands on run `stamp`.
    pub fn trajectory(&self, stamp: &str) -> Trajectory {
        let Some(now) = self.points.last() else {
            return Trajectory::Dormant;
        };
        if now.run != stamp {
            return Trajectory::Dormant;
        }
        if self
            .events
            .iter()
            .any(|e| e.run == stamp && e.kind == EventKind::Resurgent)
        {
            return Trajectory::Resurgent;
        }
        if self.first_run == stamp {
            return Trajectory::New;
        }
        let base = self
            .points
            .iter()
            .rev()
            .find(|p| p.t <= now.t - GROWTH_SPAN_SECS && p.records > 0);
        if let Some(b) = base
            && now.records >= 2 * b.records
            && now.records >= b.records + 3
        {
            return Trajectory::Growing;
        }
        let active = self
            .points
            .iter()
            .rev()
            .take_while(|p| p.t > now.t - DAY)
            .any(|p| p.added > 0);
        if active {
            Trajectory::Active
        } else {
            Trajectory::Quiet
        }
    }

    /// Records per run, oldest first, over the last `n` points.
    pub fn sparkline(&self, n: usize) -> Vec<usize> {
        let skip = self.points.len().saturating_sub(n);
        self.points[skip..].iter().map(|p| p.records).collect()
    }

    /// Whether the band has been `band` on at least the last `n` points in
    /// a row, from the first of that run of points to the last at least
    /// `secs` apart.
    pub fn held(&self, band: &str, n: usize, secs: i64) -> bool {
        let run: Vec<&Point> = self
            .points
            .iter()
            .rev()
            .take_while(|p| p.band == band)
            .collect();
        match (run.first(), run.last()) {
            (Some(last), Some(first)) => n > 0 && run.len() >= n && last.t - first.t >= secs,
            _ => false,
        }
    }
}

/// What one run's observation did, for the caller.
#[derive(Debug, Default)]
pub struct Observed {
    /// Cluster id (`C3`) to thread id, for the clusters above noise.
    pub threads: BTreeMap<String, String>,
}

impl Ledger {
    pub fn new() -> Self {
        Self {
            schema: SCHEMA.into(),
            ..Default::default()
        }
    }

    /// The live thread `id` was merged into, following merges.
    fn resolve<'a>(&'a self, mut id: &'a str) -> &'a str {
        for _ in 0..64 {
            match self
                .threads
                .get(id)
                .and_then(|th| th.merged_into.as_deref())
            {
                Some(next) if next != id => id = next,
                _ => break,
            }
        }
        id
    }

    /// Follow analysis `a`'s candidate fleets and accumulate its soft-link
    /// evidence per pair of threads, after [`Ledger::observe`] on the same
    /// run returned `observed`.
    pub fn observe_fleets(
        &mut self,
        a: &Analysis,
        observed: &Observed,
        stamp: &str,
        t: i64,
    ) -> FleetsObserved {
        let mut out = FleetsObserved::default();
        let thread_of = |c: &str| observed.threads.get(c).cloned();
        // This run's fleets by member threads.
        let current: Vec<(&sc_core::CandidateFleet, BTreeSet<String>)> = a
            .candidate_fleets
            .iter()
            .map(|f| (f, f.clusters.iter().filter_map(|c| thread_of(c)).collect()))
            .filter(|(_, m): &(_, BTreeSet<String>)| m.len() >= 2)
            .collect();
        let earlier: Vec<(String, BTreeSet<String>)> = self
            .fleets
            .values()
            .filter(|f| f.last_run != stamp)
            .map(|f| {
                let m = f
                    .members
                    .iter()
                    .map(|x| self.resolve(x).to_string())
                    .collect();
                (f.id.clone(), m)
            })
            .collect();
        let cur_sets: Vec<BTreeSet<String>> = current.iter().map(|x| x.1.clone()).collect();
        let old_sets: Vec<BTreeSet<String>> = earlier.iter().map(|x| x.1.clone()).collect();
        let matched = fleet_track::match_fleets(&cur_sets, &old_sets, fleet_track::MATCH_JACCARD);
        for ((f, members), m) in current.iter().zip(matched) {
            let key = match m {
                Some(j) => earlier[j].0.clone(),
                None => {
                    let first = members
                        .iter()
                        .min_by_key(|th| {
                            (
                                self.threads.get(*th).map_or(i64::MAX, |x| x.first_ts),
                                th.to_string(),
                            )
                        })
                        .cloned()
                        .unwrap_or_default();
                    let base = fleet_track::fleet_key(&first);
                    let key = (1..)
                        .map(|n| {
                            if n == 1 {
                                base.clone()
                            } else {
                                format!("{base}-{n}")
                            }
                        })
                        .find(|k| !self.fleets.contains_key(k))
                        .expect("an unused suffix");
                    out.new.insert(key.clone());
                    key
                }
            };
            let e = self
                .fleets
                .entry(key.clone())
                .or_insert_with(|| FleetThread {
                    id: key.clone(),
                    first_run: stamp.to_string(),
                    ..Default::default()
                });
            e.members = members.iter().cloned().collect();
            e.last_run = stamp.to_string();
            e.last_t = t;
            e.runs += 1;
            e.peak = e.peak.max(members.len());
            e.fleet = f.id.clone();
            e.kinds = f.kinds.iter().map(|k| k.label().to_string()).collect();
            e.min_lr = f.min_lr;
            e.density = f.density;
            out.keys.insert(f.id.clone(), key);
        }

        // Evidence per pair of threads.
        let mut at: BTreeMap<(String, String), usize> = BTreeMap::new();
        for (i, p) in self.pairs.iter_mut().enumerate() {
            p.decay_to(t);
            at.insert((p.a.clone(), p.b.clone()), i);
        }
        for e in sc_core::fleets::pair_evidence(&a.soft_links).into_values() {
            let (Some(ta), Some(tb)) = (thread_of(&e.a), thread_of(&e.b)) else {
                continue;
            };
            if ta == tb || e.lr <= 1.0 {
                continue;
            }
            let span = |id: &str| a.cluster(id).map(|c| (c.start, c.end));
            let (Some(sa), Some(sb)) = (span(&e.a), span(&e.b)) else {
                continue;
            };
            let fresh = PairTrack::new(&ta, &tb);
            let i = *at
                .entry((fresh.a.clone(), fresh.b.clone()))
                .or_insert_with(|| {
                    self.pairs.push(fresh);
                    self.pairs.len() - 1
                });
            let p = &mut self.pairs[i];
            p.observe(e.lr.ln(), sa.0.min(sb.0), sa.1.max(sb.1), t);
            p.kinds = e.families.iter().map(|x| x.1.label().to_string()).collect();
        }
        self.pairs
            .sort_by(|x, y| (x.a.as_str(), x.b.as_str()).cmp(&(y.a.as_str(), y.b.as_str())));
        // Persistent pairs no current fleet holds together.
        let together =
            |a: &str, b: &str| current.iter().any(|(_, m)| m.contains(a) && m.contains(b));
        out.persistent = self
            .pairs
            .iter()
            .filter(|p| p.persistent(fleet_track::ALPHA) && !together(&p.a, &p.b))
            .cloned()
            .collect();
        out.persistent
            .sort_by(|x, y| y.total().total_cmp(&x.total()).then(x.a.cmp(&y.a)));
        out
    }

    /// Record run `stamp` (at `t`) of analysis `a`; `new_ids` are the
    /// records it collected.
    pub fn observe(
        &mut self,
        a: &Analysis,
        stamp: &str,
        t: i64,
        new_ids: &BTreeSet<String>,
    ) -> Observed {
        self.schema = SCHEMA.into();
        // Swarm edges per cluster key.
        let mut edges: BTreeMap<&str, usize> = BTreeMap::new();
        for e in &a.swarm_edges {
            *edges.entry(e.a.key.as_str()).or_default() += 1;
            if e.b.key != e.a.key {
                *edges.entry(e.b.key.as_str()).or_default() += 1;
            }
        }
        // Live threads by current key, and by member record.
        let live: Vec<&Thread> = self
            .threads
            .values()
            .filter(|th| th.merged_into.is_none())
            .collect();
        let by_key: BTreeMap<&str, &str> = live
            .iter()
            .map(|th| (th.key.as_str(), th.id.as_str()))
            .collect();
        let mut by_member: BTreeMap<&str, &str> = BTreeMap::new();
        for th in &live {
            for m in &th.members {
                by_member.insert(m.as_str(), th.id.as_str());
            }
        }

        let mut order: Vec<usize> = (0..a.clusters.len())
            .filter(|&i| a.clusters[i].tier >= Tier::Suggestive)
            .collect();
        order.sort_by(|&x, &y| {
            let (cx, cy) = (&a.clusters[x], &a.clusters[y]);
            cy.members
                .len()
                .cmp(&cx.members.len())
                .then(cx.key.cmp(&cy.key))
        });

        struct Claim {
            cluster: usize,
            thread: String,
            /// A thread this cluster split from.
            split_from: Option<String>,
            /// Other threads sharing members, by overlap.
            overlaps: BTreeMap<String, usize>,
        }
        let mut claims: Vec<Claim> = Vec::new();
        let mut claimed: BTreeSet<String> = BTreeSet::new();
        for &ci in &order {
            let c = &a.clusters[ci];
            let mut overlaps: BTreeMap<String, usize> = BTreeMap::new();
            for &m in &c.members {
                if let Some(th) = by_member.get(a.results[m].obs.id.as_str()) {
                    *overlaps.entry(th.to_string()).or_default() += 1;
                }
            }
            let primary = by_key
                .get(c.key.as_str())
                .map(|s| s.to_string())
                .or_else(|| {
                    overlaps
                        .iter()
                        .max_by(|x, y| x.1.cmp(y.1).then(y.0.cmp(x.0)))
                        .map(|(k, _)| k.clone())
                });
            let (thread, split_from) = match primary {
                Some(p) if !claimed.contains(&p) => (p, None),
                Some(p) => (self.fresh_id(&c.key, &claimed), Some(p)),
                None => (self.fresh_id(&c.key, &claimed), None),
            };
            claimed.insert(thread.clone());
            overlaps.remove(&thread);
            claims.push(Claim {
                cluster: ci,
                thread,
                split_from,
                overlaps,
            });
        }

        // A live thread no cluster claimed, whose members a cluster now
        // holds, was merged into the claiming thread with most of them.
        let mut merges: BTreeMap<String, (String, usize)> = BTreeMap::new();
        for cl in &claims {
            for (th, &n) in &cl.overlaps {
                if claimed.contains(th) {
                    continue;
                }
                let e = merges.entry(th.clone()).or_insert((cl.thread.clone(), 0));
                if n > e.1 {
                    *e = (cl.thread.clone(), n);
                }
            }
        }

        // Linking features of threads no cluster claimed, for returns.
        let mut by_feature: BTreeMap<String, (String, i64)> = BTreeMap::new();
        for th in self.threads.values().filter(|t| !claimed.contains(&t.id)) {
            for f in &th.features {
                let e = by_feature
                    .entry(f.clone())
                    .or_insert((th.id.clone(), th.last_ts));
                if th.last_ts > e.1 {
                    *e = (th.id.clone(), th.last_ts);
                }
            }
        }

        let mut out = Observed::default();
        for cl in claims {
            let c = &a.clusters[cl.cluster];
            let ids: Vec<(&str, i64)> = c
                .members
                .iter()
                .map(|&m| (a.results[m].obs.id.as_str(), a.results[m].obs.ts))
                .collect();
            let added: Vec<i64> = ids
                .iter()
                .filter(|(id, _)| new_ids.contains(*id))
                .map(|&(_, ts)| ts)
                .collect();
            let mut kept: Vec<(&str, i64)> = ids.clone();
            kept.sort_by(|x, y| y.1.cmp(&x.1).then(x.0.cmp(y.0)));
            kept.truncate(MEMBERS_KEPT);
            let mut members: Vec<String> = kept.iter().map(|(id, _)| id.to_string()).collect();
            members.sort();
            let point = Point {
                run: stamp.to_string(),
                t,
                id: c.id.clone(),
                tier: c.tier,
                grade: c.agent.level,
                records: c.members.len(),
                added: added.len(),
                targets: c.target_hosts.len(),
                end: c.end,
                swarm_edges: edges.get(c.key.as_str()).copied().unwrap_or(0),
                band: String::new(),
            };
            let mut features: Vec<String> = c.link_features.iter().map(|f| f.to_string()).collect();
            features.sort();
            features.dedup();
            features.truncate(FEATURES_KEPT);
            let is_new = !self.threads.contains_key(&cl.thread);
            // A new thread carrying an earlier thread's feature: the latest
            // such thread, and the feature's name (never its value).
            let earlier = if is_new && cl.split_from.is_none() {
                c.link_features
                    .iter()
                    .filter_map(|f| by_feature.get(&f.to_string()).map(|e| (f, e)))
                    .max_by(|x, y| x.1.1.cmp(&y.1.1).then(y.1.0.cmp(&x.1.0)))
                    .map(|(f, (id, last))| (f.name().to_string(), id.clone(), *last))
            } else {
                None
            };
            let th = self
                .threads
                .entry(cl.thread.clone())
                .or_insert_with(|| Thread {
                    id: cl.thread.clone(),
                    key: c.key.clone(),
                    keys: vec![c.key.clone()],
                    first_run: stamp.to_string(),
                    first_ts: c.start,
                    last_ts: c.end,
                    peak_tier: c.tier,
                    peak_grade: c.agent.level,
                    ..Default::default()
                });
            let ev = |kind, detail: String| Event {
                run: stamp.to_string(),
                kind,
                detail,
            };
            if let Some(from) = &cl.split_from {
                th.events.push(ev(
                    EventKind::Split,
                    format!("began as part of thread {from}"),
                ));
            }
            if let Some((name, id, last)) = earlier {
                th.recurs = Some(id.clone());
                if c.start - last >= RESURGE_GAP_SECS {
                    th.events.push(ev(
                        EventKind::Resurgent,
                        format!(
                            "shares a linking feature ({name}) with thread {id}, quiet {} days before",
                            (c.start - last) / DAY
                        ),
                    ));
                }
            }
            th.features = features;
            if th.key != c.key {
                th.events.push(ev(
                    EventKind::Rekeyed,
                    format!("key {} became {}", th.key, c.key),
                ));
                th.key = c.key.clone();
                if !th.keys.contains(&c.key) {
                    th.keys.push(c.key.clone());
                }
            }
            if let Some(prev) = th.points.last() {
                if c.tier > prev.tier {
                    th.events.push(ev(
                        EventKind::TierUp,
                        format!("{} to {}", prev.tier.label(), c.tier.label()),
                    ));
                }
                if c.agent.level > prev.grade {
                    th.events.push(ev(
                        EventKind::GradeUp,
                        format!("{} to {}", prev.grade.code(), c.agent.level.code()),
                    ));
                }
                if let Some(&first_new) = added.iter().min()
                    && first_new - prev.end >= RESURGE_GAP_SECS
                {
                    th.events.push(ev(
                        EventKind::Resurgent,
                        format!(
                            "new records after {} quiet days",
                            (first_new - prev.end) / DAY
                        ),
                    ));
                }
            }
            th.last_run = stamp.to_string();
            th.first_ts = th.first_ts.min(c.start);
            th.last_ts = th.last_ts.max(c.end);
            th.peak_tier = th.peak_tier.max(c.tier);
            th.peak_grade = th.peak_grade.max(c.agent.level);
            th.members = members;
            th.points.push(point);
            out.threads.insert(c.id.clone(), cl.thread);
        }
        for (from, (into, n)) in merges {
            if let Some(th) = self.threads.get_mut(&from) {
                th.merged_into = Some(into.clone());
            }
            if let Some(th) = self.threads.get_mut(&into) {
                th.events.push(Event {
                    run: stamp.to_string(),
                    kind: EventKind::Merged,
                    detail: format!("thread {from} joined it ({n} shared record(s))"),
                });
            }
        }
        out
    }

    /// A thread id for a new thread on key `key`: the key, or the key with
    /// a suffix when a thread already has it.
    fn fresh_id(&self, key: &str, claimed: &BTreeSet<String>) -> String {
        let base = if key.is_empty() { "k-unkeyed" } else { key };
        let taken = |s: &str| self.threads.contains_key(s) || claimed.contains(s);
        if !taken(base) {
            return base.to_string();
        }
        (2..)
            .map(|n| format!("{base}-{n}"))
            .find(|s| !taken(s))
            .expect("an unused suffix")
    }

    /// Set the band of each thread's point on run `stamp`.
    pub fn set_bands(&mut self, stamp: &str, bands: &BTreeMap<String, &'static str>) {
        for (thread, band) in bands {
            if let Some(p) = self
                .threads
                .get_mut(thread)
                .and_then(|th| th.points.last_mut())
                .filter(|p| p.run == stamp)
            {
                p.band = band.to_string();
            }
        }
    }

    /// Drop points from before `cutoff`, and threads left with none.
    /// Returns how many threads went.
    pub fn prune(&mut self, cutoff: i64) -> usize {
        let before = self.threads.len();
        for th in self.threads.values_mut() {
            th.points.retain(|p| p.t >= cutoff);
        }
        self.threads.retain(|_, th| !th.points.is_empty());
        let kept: BTreeSet<String> = self.threads.keys().cloned().collect();
        self.fleets.retain(|_, f| f.last_t >= cutoff);
        self.pairs
            .retain(|p| kept.contains(&p.a) && kept.contains(&p.b) && p.t >= cutoff);
        for th in self.threads.values_mut() {
            let first = th.points[0].run.clone();
            th.events.retain(|e| e.run >= first);
            if th.merged_into.as_ref().is_some_and(|m| !kept.contains(m)) {
                th.merged_into = None;
            }
        }
        before - self.threads.len()
    }

    /// Threads holding any of record ids `ids` among their kept members.
    pub fn threads_with(&self, ids: &BTreeSet<String>) -> BTreeSet<String> {
        self.threads
            .values()
            .filter(|th| th.members.iter().any(|m| ids.contains(m)))
            .map(|th| th.id.clone())
            .collect()
    }
}

/// An agent level written as its code (`L3`).
pub(crate) mod level_code {
    use sc_core::agentness::AgentLevel;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(l: &AgentLevel, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(l.code())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<AgentLevel, D::Error> {
        let s = String::deserialize(d)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests;
