//! Possible interaction between runs (SC-T9): hints that agents act on each
//! other's output, not only alongside each other.
//!
//! A fleet is many agents doing the same thing; a swarm is a fleet whose
//! agents interact (SC-FM 1.3). Public records rarely show interaction
//! directly, so each [`SwarmEdge`] is one weak-to-moderate signal between two
//! runs, and a claim of interaction needs several together and the admin's
//! review. Edges are never scored, never link records and never merge
//! clusters. The kinds:
//!
//! - **S1 shared sink**: runs, or strands of one run, that write to the same
//!   inbox or artifact but differ in how they send requests (relay route,
//!   user agent, network, header set, encoding). A shared inbox hard-links
//!   every writer into one cluster, so this also looks inside a cluster.
//! - **S2 hand-off**: an artifact (an inbox, a gist, a paste, a Space, a
//!   static-site subdomain) that one run writes to and a later run fetches.
//! - **S3 synchronized start**: runs of differently fingerprinted clusters
//!   that start and stop together, against a chance model.
//! - **S4 role sequence**: a run that only reads a set of hosts, then a
//!   differently fingerprinted run attacking the same hosts in the same order.
//! - **S5 disjoint partition**: runs started together that split one target
//!   family with almost no overlap. One scheduler sharding a list does the
//!   same, so alone it is a fleet signal.
//!
//! Only identifier strings already in the records are matched; nothing here
//! reads an artifact, an inbox or a callback channel.

use crate::analyze::{Analysis, Cluster, ObsResult, relay_stack};
use crate::eval::LabelSet;
use crate::extract::{defang, defang_host};
use crate::model::{IndicatorKind, Tier, truncate};
use crate::rules::Rules;
use crate::timing::poisson_at_least;
use serde::{Deserialize, Serialize};
use std::fmt::Write;

/// What an edge rests on, `S1` to `S5`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwarmEdgeKind {
    SharedSink,
    Handoff,
    SynchronizedStart,
    RoleSequence,
    DisjointPartition,
}

impl SwarmEdgeKind {
    pub const ALL: [SwarmEdgeKind; 5] = [
        SwarmEdgeKind::SharedSink,
        SwarmEdgeKind::Handoff,
        SwarmEdgeKind::SynchronizedStart,
        SwarmEdgeKind::RoleSequence,
        SwarmEdgeKind::DisjointPartition,
    ];

    /// `S1` to `S5`.
    pub fn id(self) -> &'static str {
        ["S1", "S2", "S3", "S4", "S5"][self as usize]
    }

    pub fn label(self) -> &'static str {
        [
            "shared sink",
            "hand-off",
            "synchronized start",
            "role sequence",
            "disjoint partition",
        ][self as usize]
    }

    /// The name case files and the CLI use (`shared_sink`).
    pub fn name(self) -> &'static str {
        [
            "shared_sink",
            "handoff",
            "synchronized_start",
            "role_sequence",
            "disjoint_partition",
        ][self as usize]
    }
}

impl std::str::FromStr for SwarmEdgeKind {
    type Err = String;
    /// `S2`, `handoff` or `hand-off`, any case.
    fn from_str(s: &str) -> Result<Self, String> {
        let s = s.trim().to_ascii_lowercase().replace('-', "_");
        let s = if s == "hand_off" { "handoff".into() } else { s };
        Self::ALL
            .into_iter()
            .find(|k| k.id().eq_ignore_ascii_case(&s) || k.name() == s)
            .ok_or_else(|| {
                format!("unknown interaction kind `{s}` (S1..S5 or a name such as handoff)")
            })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EdgeStrength {
    Weak,
    Moderate,
    Strong,
}

impl EdgeStrength {
    pub fn label(self) -> &'static str {
        ["weak", "moderate", "strong"][self as usize]
    }
}

/// One run, or one strand of a run (its records sent one way, when the run
/// holds records sent several ways), with the records an edge rests on.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RunRef {
    /// Cluster id (`C3`) and stable key.
    pub cluster: String,
    pub key: String,
    /// The run's number in its cluster, from 1 ([`Cluster::runs`]).
    pub run: usize,
    /// How the strand's records were sent, when the edge is between strands.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub strand: Option<String>,
    /// Ids of the records the edge rests on, earliest first (a few).
    pub records: Vec<String>,
}

impl RunRef {
    /// `C3#2`, with the strand when there is one.
    pub fn label(&self) -> String {
        match &self.strand {
            Some(s) => format!("{}#{} ({s})", self.cluster, self.run),
            None => format!("{}#{}", self.cluster, self.run),
        }
    }

    /// `k-3f9a2c1b#2`: the form case files keep.
    pub fn stable(&self) -> String {
        format!("{}#{}", self.key, self.run)
    }
}

/// A hint that two runs interacted. Never a score, a link or a merge.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SwarmEdge {
    pub kind: SwarmEdgeKind,
    /// For a hand-off, `a` writes and `b` fetches; otherwise `a` starts first.
    pub a: RunRef,
    pub b: RunRef,
    pub strength: EdgeStrength,
    /// The chance of what was seen under the edge's chance model, where it
    /// has one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chance: Option<f64>,
    pub detail: String,
}

/// Starts and ends this close together match (S3).
const START_TOLERANCE_SECS: i64 = 120;
/// A match on a clock hour counts for this much of one (S3).
const CLOCK_WEIGHT: f64 = 0.25;
/// Edges kept when their chance is at most this (S3, S4).
const MAX_CHANCE: f64 = 0.01;
/// Partitions kept when near-zero overlap is at most this likely (S5).
const MAX_PARTITION_CHANCE: f64 = 0.05;
/// Runs starting this close together can partition a list (S5).
const PARTITION_WINDOW_SECS: i64 = 600;
/// The attacking run starts at most this long after the reading run ends (S4).
const ROLE_WINDOW_SECS: i64 = 6 * 3600;
/// A fetch this soon after the write makes a strong hand-off (S2).
const QUICK_HANDOFF_SECS: i64 = 3600;
/// Hosts each side needs (S4, S5).
const MIN_HOSTS: usize = 3;
/// A sink or artifact written or read by more runs than this is common.
const MAX_SHARING: usize = 10;
/// Edges kept, strongest first.
const MAX_EDGES: usize = 200;
/// Record ids kept per side.
const MAX_RECORDS: usize = 3;

/// How a record was sent: relay route, user agent, network, header set,
/// encoding style. The first four also split a run into strands.
const DIMS: [&str; 5] = [
    "relay route",
    "user agent",
    "network",
    "header set",
    "encoding",
];

type Fp = [Vec<String>; 5];

fn dims(r: &ObsResult) -> [Option<String>; 5] {
    let enc = crate::fingerprint::encoding(&r.obs.url);
    [
        Some(relay_stack(r).unwrap_or_else(|| "direct".into())),
        r.obs.user_agent.clone(),
        r.obs.asn.map(|a| format!("AS{a}")),
        crate::fingerprint::header_set(&r.obs.headers).map(|h| h.hash),
        enc.informative().then_some(enc.style),
    ]
}

fn fp_of(results: &[ObsResult], members: &[usize]) -> Fp {
    let mut f: Fp = Default::default();
    for &m in members {
        for (i, d) in dims(&results[m]).into_iter().enumerate() {
            if let Some(d) = d
                && !f[i].contains(&d)
            {
                f[i].push(d);
            }
        }
    }
    f
}

/// The dimensions known on both sides and disjoint, or `None` when they
/// share a user agent, network or header set (one client, most likely).
fn differ(a: &Fp, b: &Fp) -> Option<Vec<&'static str>> {
    let mut out = Vec::new();
    for i in 0..DIMS.len() {
        if a[i].is_empty() || b[i].is_empty() {
            continue;
        }
        if !a[i].iter().any(|x| b[i].contains(x)) {
            out.push(DIMS[i]);
        } else if (1..=3).contains(&i) {
            return None;
        }
    }
    Some(out)
}

/// `(name, value)` pairs; one sort serves every list of them here.
type Keyed = Vec<(String, i64)>;

fn sort_keyed(v: &mut Keyed) {
    crate::sort::by(v, |a, b| a.0.cmp(&b.0));
}

/// Sorted by name, keeping each name's first value.
fn first_by_key(mut v: Keyed) -> Keyed {
    sort_keyed(&mut v);
    v.dedup_by(|b, a| a.0 == b.0);
    v
}

fn find(v: &[(String, i64)], k: &str) -> Option<i64> {
    v.binary_search_by(|x| x.0.as_str().cmp(k))
        .ok()
        .map(|i| v[i].1)
}

/// The indexes below `n` that `keep` admits.
fn indexes(n: usize, keep: &dyn Fn(usize) -> bool) -> Vec<usize> {
    (0..n).filter(|&i| keep(i)).collect()
}

/// One way of sending within a run: its label (when the run has several),
/// members and fingerprint.
struct Strand {
    label: Option<String>,
    members: Vec<usize>,
    fp: Fp,
}

/// One run of a cluster above noise.
struct Run {
    ci: usize,
    n: usize,
    members: Vec<usize>,
    start: i64,
    end: i64,
    fp: Fp,
    strands: Vec<Strand>,
    /// (target host, first time), by host: every member, and attacks only.
    hosts: Keyed,
    attacks: Keyed,
}

fn runs(clusters: &[Cluster], results: &[ObsResult]) -> Vec<Run> {
    let mut out = Vec::new();
    for (ci, c) in clusters.iter().enumerate() {
        if c.tier == Tier::Noise {
            continue;
        }
        for (k, span) in c.runs.iter().enumerate() {
            let mut members = Vec::new();
            let (mut keyed, mut hosts, mut attacks) = (Keyed::new(), Keyed::new(), Keyed::new());
            for &m in &c.members {
                let r = &results[m];
                if r.obs.ts < span.start || r.obs.ts > span.end {
                    continue;
                }
                members.push(m);
                let d = dims(r);
                let mut key = String::new();
                for x in &d[..4] {
                    key += x.as_deref().unwrap_or("");
                    key.push('|');
                }
                keyed.push((key, m as i64));
                if let Some(host) = &r.target_host {
                    hosts.push((host.clone(), r.obs.ts));
                    if r.hits.iter().any(|h| h.kind == IndicatorKind::Exploit) {
                        attacks.push((host.clone(), r.obs.ts));
                    }
                }
            }
            sort_keyed(&mut keyed);
            let multi = keyed.first().map(|f| &f.0) != keyed.last().map(|l| &l.0);
            let mut strands = Vec::new();
            for g in keyed.chunk_by(|a, b| a.0 == b.0) {
                let ms: Vec<usize> = g.iter().map(|x| x.1 as usize).collect();
                let label = multi.then(|| {
                    let parts: Vec<&str> = g[0].0.split('|').filter(|p| !p.is_empty()).collect();
                    truncate(&parts.join(" · "), 80)
                });
                strands.push(Strand {
                    label,
                    fp: fp_of(results, &ms),
                    members: ms,
                });
            }
            out.push(Run {
                ci,
                n: k + 1,
                fp: fp_of(results, &members),
                members,
                start: span.start,
                end: span.end,
                strands,
                hosts: first_by_key(hosts),
                attacks: first_by_key(attacks),
            });
        }
    }
    out
}

/// The artifacts one record names: (id, written). An inbox named by a
/// linking rule is written to unless the record reads it back (a
/// webhook.site token URL, an ntfy subscription). A gist, paste, Space or
/// static-site subdomain is fetched when it is the first host the record
/// reaches past relays and carriers, and written to (named as a destination)
/// otherwise.
fn artifacts(r: &ObsResult, rules: &Rules, out: &mut Vec<(String, bool)>) {
    let url = r.obs.url.to_ascii_lowercase();
    for f in &r.features {
        if f.name().starts_with("exfil.") {
            let v = f
                .value()
                .trim_start_matches(|c: char| !c.is_ascii_alphanumeric());
            let read = v.contains("/token/")
                || ["/json", "/sse", "/raw", "/ws"]
                    .iter()
                    .any(|s| url.contains(&format!("{v}{s}")));
            out.push((v.replace("/token/", "/"), !read));
        }
    }
    let mut fetched = None;
    for l in &r.layers {
        let Some(h) = l.host.as_deref() else {
            continue;
        };
        if fetched.is_none() && !rules.is_intermediary_host(h) {
            fetched = Some(h);
        }
        if let Some(id) = site_artifact(h, &l.text) {
            out.push((id, Some(h) != fetched));
        }
    }
}

/// Static-site hosts whose subdomain is one user's site.
const SITE_SUFFIXES: [&str; 12] = [
    "pages.dev",
    "vercel.app",
    "netlify.app",
    "workers.dev",
    "github.io",
    "glitch.me",
    "onrender.com",
    "fly.dev",
    "replit.app",
    "surge.sh",
    "herokuapp.com",
    "hf.space",
];

fn site_artifact(host: &str, text: &str) -> Option<String> {
    let h = host.to_ascii_lowercase();
    let rest = text.split_once("://").map_or(text, |(_, r)| r);
    let path = rest.find('/').map_or("", |i| &rest[i..]);
    let path = path.split(['?', '#']).next().unwrap_or("");
    let segs: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    let seg = |i: usize| segs.get(i).copied().unwrap_or("");
    let word = |s: &str| {
        s.len() >= 3
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    };
    let hex = |s: &str| s.len() >= 20 && s.bytes().all(|b| b.is_ascii_hexdigit());
    let (family, id) = match h.as_str() {
        "gist.github.com" | "gist.githubusercontent.com" => (
            "gist",
            if hex(seg(1)) { seg(1) } else { seg(0) }.to_ascii_lowercase(),
        ),
        "pastebin.com" => (
            "pastebin",
            if seg(0) == "raw" { seg(1) } else { seg(0) }.to_string(),
        ),
        "rentry.co" | "rentry.org" => ("rentry", seg(0).to_ascii_lowercase()),
        "huggingface.co" if seg(0) == "spaces" && !seg(2).is_empty() => (
            "hf_space",
            format!("{}-{}", seg(1), seg(2))
                .to_ascii_lowercase()
                .replace(['_', '.'], "-"),
        ),
        _ => {
            let s = SITE_SUFFIXES.iter().find(|s| {
                h.len() > s.len() && h.ends_with(*s) && h.as_bytes()[h.len() - s.len() - 1] == b'.'
            })?;
            let sub = &h[..h.len() - s.len() - 1];
            if sub == "www" {
                return None;
            }
            match *s {
                "hf.space" => ("hf_space", sub.to_string()),
                _ => ("site", h.clone()),
            }
        }
    };
    let ok = match family {
        "gist" => hex(&id),
        "pastebin" => id.len() == 8 && word(&id),
        "rentry" => word(&id) && !matches!(id.as_str(), "api" | "static" | "what" | "raw"),
        _ => true,
    };
    ok.then(|| format!("{family}/{id}"))
}

/// Possible interaction between the runs of clusters above noise, in kind
/// order (`S1` first).
pub(crate) fn swarm_edges(
    clusters: &[Cluster],
    results: &[ObsResult],
    rules: &Rules,
) -> Vec<SwarmEdge> {
    let runs = runs(clusters, results);
    // Every artifact each run names, by id; the value indexes `meta`
    // (run, strand, written, record).
    let (mut named, mut meta) = (Keyed::new(), Vec::new());
    let mut found = Vec::new();
    for (ri, run) in runs.iter().enumerate() {
        for (si, s) in run.strands.iter().enumerate() {
            for &m in &s.members {
                found.clear();
                artifacts(&results[m], rules, &mut found);
                for (id, w) in found.drain(..) {
                    named.push((id, meta.len() as i64));
                    meta.push((ri, si, w, m));
                }
            }
        }
    }
    sort_keyed(&mut named);
    let cx = Ctx {
        runs: &runs,
        cl: clusters,
        res: results,
    };
    let mut out = Vec::new();
    let groups: Vec<(&str, Vec<Meta>)> = named
        .chunk_by(|a, b| a.0 == b.0)
        .map(|g| {
            (
                g[0].0.as_str(),
                g.iter().map(|x| meta[x.1 as usize]).collect(),
            )
        })
        .collect();
    for (id, g) in &groups {
        cx.shared_sink(id, g, &mut out);
    }
    for (id, g) in &groups {
        cx.handoff(id, g, &mut out);
    }
    cx.synchronized(&mut out);
    cx.role_sequences(&mut out);
    cx.partitions(&mut out);
    out.truncate(MAX_EDGES);
    out
}

/// Where an artifact was named: (run, strand, written, record).
type Meta = (usize, usize, bool, usize);

struct Ctx<'a> {
    runs: &'a [Run],
    cl: &'a [Cluster],
    res: &'a [ObsResult],
}

/// One side of an edge: the run, its strand label, the records.
type Side<'a> = (&'a Run, Option<&'a String>, &'a [usize]);

impl Ctx<'_> {
    fn side(&self, s: Side) -> RunRef {
        let (run, strand, recs) = s;
        let c = &self.cl[run.ci];
        RunRef {
            cluster: c.id.clone(),
            key: c.key.clone(),
            run: run.n,
            strand: strand.cloned(),
            records: recs
                .iter()
                .take(MAX_RECORDS)
                .map(|&m| self.res[m].obs.id.clone())
                .collect(),
        }
    }

    fn push(
        &self,
        out: &mut Vec<SwarmEdge>,
        kind: SwarmEdgeKind,
        (x, y): (Side, Side),
        strength: EdgeStrength,
        chance: Option<f64>,
        detail: String,
    ) {
        out.push(SwarmEdge {
            kind,
            a: self.side(x),
            b: self.side(y),
            strength,
            chance,
            detail,
        });
    }

    /// S1: strands writing one sink that differ in at least two ways.
    fn shared_sink(&self, id: &str, g: &[Meta], out: &mut Vec<SwarmEdge>) {
        // (run, strand) → its records writing the sink.
        let mut w: Vec<(usize, usize, Vec<usize>)> = Vec::new();
        for &(ri, si, written, m) in g {
            if !written {
                continue;
            }
            match w.iter_mut().find(|x| x.0 == ri && x.1 == si) {
                Some(x) => x.2.push(m),
                None => {
                    // A one-record strand beside others is too thin to compare.
                    let s = &self.runs[ri].strands[si];
                    if s.label.is_none() || s.members.len() >= 2 {
                        w.push((ri, si, vec![m]));
                    }
                }
            }
        }
        if w.len() < 2 || w.len() > MAX_SHARING {
            return;
        }
        for (i, (ra, sa, xa)) in w.iter().enumerate() {
            for (rb, sb, xb) in &w[i + 1..] {
                let (x, y) = (&self.runs[*ra], &self.runs[*rb]);
                let (fa, fb) = (&x.strands[*sa], &y.strands[*sb]);
                let Some(d) = differ(&fa.fp, &fb.fp).filter(|d| d.len() >= 2) else {
                    continue;
                };
                self.push(
                    out,
                    SwarmEdgeKind::SharedSink,
                    ((x, fa.label.as_ref(), xa), (y, fb.label.as_ref(), xb)),
                    if d.len() >= 3 {
                        EdgeStrength::Moderate
                    } else {
                        EdgeStrength::Weak
                    },
                    None,
                    format!(
                        "both write to `{}`; their requests differ in {}: two agents on one sink, or one agent changing route",
                        defang_host(id),
                        d.join(", ")
                    ),
                );
            }
        }
    }

    /// S2: an artifact written by one run and fetched later by another.
    fn handoff(&self, id: &str, g: &[Meta], out: &mut Vec<SwarmEdge>) {
        // The earliest record of each (run, written).
        let ts = |m: usize| self.res[m].obs.ts;
        let mut first: Vec<(usize, bool, usize)> = Vec::new();
        for &(ri, _, w, m) in g {
            match first.iter_mut().find(|x| x.0 == ri && x.1 == w) {
                Some(x) => {
                    if ts(m) < ts(x.2) {
                        x.2 = m;
                    }
                }
                None => first.push((ri, w, m)),
            }
        }
        if first.len() > MAX_SHARING {
            return;
        }
        for &(wa, written, wm) in &first {
            for &(rb, read, rm) in &first {
                let (x, y) = (&self.runs[wa], &self.runs[rb]);
                let gap = ts(rm) - ts(wm);
                if !written || read || wa == rb || gap <= 0 {
                    continue;
                }
                let d = differ(&x.fp, &y.fp).unwrap_or_default();
                if x.ci == y.ci && d.is_empty() {
                    continue;
                }
                let differs = if d.is_empty() {
                    String::new()
                } else {
                    format!("; they differ in {}", d.join(", "))
                };
                self.push(
                    out,
                    SwarmEdgeKind::Handoff,
                    ((x, None, &[wm]), (y, None, &[rm])),
                    if gap <= QUICK_HANDOFF_SECS && !d.is_empty() {
                        EdgeStrength::Strong
                    } else {
                        EdgeStrength::Moderate
                    },
                    None,
                    format!(
                        "`{}` written by the first and fetched by the second {} min later{differs}",
                        defang_host(id),
                        gap / 60
                    ),
                );
            }
        }
    }

    /// Indexes of the runs `keep` admits, by start.
    fn by_start(&self, keep: &dyn Fn(&Run) -> bool) -> Vec<usize> {
        let mut v = indexes(self.runs.len(), &|i| keep(&self.runs[i]));
        crate::sort::by_key(&mut v, |&i| self.runs[i].start);
        v
    }

    /// S3: clusters whose runs start and end together beyond chance. The
    /// model is the shared-pause one: a run pair whose lengths differ by less
    /// than twice the tolerance matches by chance with probability `(2 tol -
    /// |length difference|) / W`, `W` the time the runs could start in.
    fn synchronized(&self, out: &mut Vec<SwarmEdge>) {
        let (runs, tol) = (self.runs, START_TOLERANCE_SECS);
        let timed = self.by_start(&|r| r.members.len() >= 3);
        let (Some(&lo), Some(hi)) = (timed.first(), timed.iter().map(|&i| runs[i].end).max())
        else {
            return;
        };
        let window = (hi - runs[lo].start).max(1) as f64;
        let mut pairs: Vec<(usize, usize)> = Vec::new();
        for (n, &i) in timed.iter().enumerate() {
            for &j in &timed[n + 1..] {
                let (x, y) = (&runs[i], &runs[j]);
                if y.start - x.start > tol {
                    break;
                }
                let p = (x.ci.min(y.ci), x.ci.max(y.ci));
                if x.ci != y.ci && (x.end - y.end).abs() <= tol && !pairs.contains(&p) {
                    pairs.push(p);
                }
            }
        }
        for (cx, cy) in pairs {
            let fx = fp_of(self.res, &self.cl[cx].members);
            let Some(d) = differ(&fx, &fp_of(self.res, &self.cl[cy].members)) else {
                continue;
            };
            if d.is_empty() {
                continue;
            }
            let (mut expected, mut matched) = (0.0, Vec::<(usize, usize)>::new());
            for &i in &timed {
                for &j in &timed {
                    let (x, y) = (&runs[i], &runs[j]);
                    if x.ci != cx || y.ci != cy {
                        continue;
                    }
                    let dd = ((x.end - x.start) - (y.end - y.start)).abs();
                    if dd < 2 * tol {
                        expected += ((2 * tol - dd) as f64 / window).min(1.0);
                    }
                    if (x.start - y.start).abs() <= tol
                        && (x.end - y.end).abs() <= tol
                        && !matched.iter().any(|m| m.1 == j)
                    {
                        matched.push((i, j));
                    }
                }
            }
            let hourly = |t: i64| {
                let r = t.rem_euclid(3600);
                r <= tol || r >= 3600 - tol
            };
            let mut weight = 0.0;
            for m in &matched {
                let x = &runs[m.0];
                weight += if hourly(x.start) || hourly(x.end) {
                    CLOCK_WEIGHT
                } else {
                    1.0
                };
            }
            let p = poisson_at_least(expected, weight as usize);
            if weight < 1.0 || p > MAX_CHANCE {
                continue;
            }
            let (x, y) = (&runs[matched[0].0], &runs[matched[0].1]);
            self.push(
                out,
                SwarmEdgeKind::SynchronizedStart,
                ((x, None, &x.members), (y, None, &y.members)),
                if matched.len() >= 2 && p <= 1e-4 {
                    EdgeStrength::Moderate
                } else {
                    EdgeStrength::Weak
                },
                Some(p),
                format!(
                    "{} run(s) start and end within {tol} s of each other, {expected:.3} expected by chance (p {p:.1e}); they differ in {}",
                    matched.len(),
                    d.join(", ")
                ),
            );
        }
    }

    /// Distinct target hosts over all runs, by host.
    fn all_hosts(&self) -> Keyed {
        let mut v = Keyed::new();
        for r in self.runs {
            v.extend(r.hosts.iter().cloned());
        }
        first_by_key(v)
    }

    /// S4: a run that only reads hosts, then a differently fingerprinted run
    /// attacking most of them, each after it was read. Chance: the attacked
    /// hosts drawn at random from every target host in the analysis.
    fn role_sequences(&self, out: &mut Vec<SwarmEdge>) {
        let n = self.all_hosts().len().max(1) as f64;
        for x in self.runs {
            if !x.attacks.is_empty() || x.hosts.len() < MIN_HOSTS {
                continue;
            }
            for y in self.runs {
                if y.attacks.len() < MIN_HOSTS
                    || y.start < x.start
                    || y.start > x.end + ROLE_WINDOW_SECS
                {
                    continue;
                }
                let Some(d) = differ(&x.fp, &y.fp) else {
                    continue;
                };
                let (mut shared, mut after) = (0, 0);
                for (h, t) in &x.hosts {
                    if let Some(ty) = find(&y.attacks, h) {
                        shared += 1;
                        after += usize::from(ty > *t);
                    }
                }
                let j = shared as f64 / (x.hosts.len() + y.attacks.len() - shared) as f64;
                if d.is_empty()
                    || shared < MIN_HOSTS
                    || j < 0.5
                    || (after as f64) < 0.8 * shared as f64
                {
                    continue;
                }
                let p = poisson_at_least((x.hosts.len() * y.attacks.len()) as f64 / n, shared);
                if p > MAX_CHANCE {
                    continue;
                }
                self.push(
                    out,
                    SwarmEdgeKind::RoleSequence,
                    ((x, None, &x.members), (y, None, &y.members)),
                    if j >= 0.7 && after == shared {
                        EdgeStrength::Moderate
                    } else {
                        EdgeStrength::Weak
                    },
                    Some(p),
                    format!(
                        "the first only reads {} hosts; the second attacks {shared} of them (Jaccard {j:.2}), {after} after the first read them; they differ in {} (p {p:.1e})",
                        x.hosts.len(),
                        d.join(", ")
                    ),
                );
            }
        }
    }

    /// S5: runs started together that split one host family with near-zero
    /// overlap. Chance: each run's hosts drawn at random from the family's
    /// hosts in the analysis; kept when so little overlap is unlikely.
    fn partitions(&self, out: &mut Vec<SwarmEdge>) {
        // Hosts as `family host`, so a sort groups them by family.
        let by_family = |hosts: &Keyed| -> Keyed {
            let mut v: Keyed = hosts
                .iter()
                .map(|(h, t)| (format!("{} {h}", family(h)), *t))
                .collect();
            sort_keyed(&mut v);
            v
        };
        let fam = |k: &str| k.split(' ').next().unwrap_or("").to_string();
        let all = by_family(&self.all_hosts());
        let per: Vec<Keyed> = self.runs.iter().map(|r| by_family(&r.hosts)).collect();
        let order = self.by_start(&|r| r.hosts.len() >= MIN_HOSTS);
        for (n, &i) in order.iter().enumerate() {
            for &k in &order[n + 1..] {
                let (x, y) = (&self.runs[i], &self.runs[k]);
                if y.start - x.start > PARTITION_WINDOW_SECS {
                    break;
                }
                let mut best: Option<(f64, String, usize, usize, usize)> = None;
                for gx in per[i].chunk_by(|a, b| fam(&a.0) == fam(&b.0)) {
                    let f = fam(&gx[0].0);
                    let in_f = |v: &[(String, i64)]| v.iter().filter(|h| fam(&h.0) == f).count();
                    let ny = in_f(&per[k]);
                    let m = gx.iter().filter(|h| find(&per[k], &h.0).is_some()).count();
                    if gx.len() < MIN_HOSTS || ny < MIN_HOSTS || m * 10 > gx.len().min(ny) {
                        continue;
                    }
                    let lambda = (gx.len() * ny) as f64 / in_f(&all).max(1) as f64;
                    let p = 1.0 - poisson_at_least(lambda, m + 1);
                    if p <= MAX_PARTITION_CHANCE && best.as_ref().is_none_or(|b| p < b.0) {
                        best = Some((p, f, gx.len(), ny, m));
                    }
                }
                let Some((p, f, nx, ny, m)) = best else {
                    continue;
                };
                self.push(
                    out,
                    SwarmEdgeKind::DisjointPartition,
                    ((x, None, &x.members), (y, None, &y.members)),
                    EdgeStrength::Weak,
                    Some(p),
                    format!(
                        "started {} s apart, they split `*.{}` ({nx} and {ny} hosts, {m} shared; p {p:.1e}). One scheduler sharding a list does the same: a fleet signal unless other edges join these runs",
                        y.start - x.start,
                        defang_host(&f)
                    ),
                );
            }
        }
    }
}

/// The registrable-looking part of a host: its last two labels.
fn family(host: &str) -> &str {
    let mut dots = host.rmatch_indices('.');
    dots.next();
    dots.next().map_or(host, |(i, _)| &host[i + 1..])
}

/// The "Possible interaction (SC-T9)" block of a report: the edges whose
/// two clusters `shown` allows, or nothing.
pub(crate) fn report_block(
    s: &mut String,
    edges: &[SwarmEdge],
    shown: &dyn Fn(&str, &str) -> bool,
) {
    let edges: Vec<&SwarmEdge> = edges
        .iter()
        .filter(|e| shown(&e.a.cluster, &e.b.cluster))
        .collect();
    if edges.is_empty() {
        return;
    }
    let _ = writeln!(
        s,
        "\n## Possible interaction (SC-T9)\n\nPairs of runs whose records suggest agents acting on each other's output. Each is a weak-to-moderate signal that coincidence, one scheduler or one agent changing route can also produce. None is scored or merges anything; together they are an Inference to review, not a finding. A grouping is called a swarm only once reviewed evidence of interaction is recorded.\n"
    );
    for e in edges.iter().take(12) {
        let recs: Vec<&str> =
            e.a.records
                .iter()
                .chain(&e.b.records)
                .map(String::as_str)
                .collect();
        let _ = writeln!(
            s,
            "- {} {} ({}): {} {} {}: {}. Records: {}",
            e.kind.id(),
            e.kind.label(),
            e.strength.label(),
            e.a.label(),
            if e.kind == SwarmEdgeKind::Handoff {
                "→"
            } else {
                "↔"
            },
            e.b.label(),
            truncate(&e.detail, 240),
            defang(&recs.join(", "))
        );
    }
    if edges.len() > 12 {
        let _ = writeln!(s, "- … and {} more", edges.len() - 12);
    }
}

/// Edges against records labelled with a `swarm` group (`none` for runs
/// known not to interact). Counts by kind are indexed `S1` to `S5`. Report
/// only: no gate reads it.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SwarmEval {
    pub edges: usize,
    pub by_kind: [usize; 5],
    /// Interacting groups labelled, and those with an edge inside them.
    pub groups: Vec<String>,
    pub found: Vec<String>,
    /// Edges inside one interacting group.
    pub on_groups: usize,
    /// Edges touching a run labelled `none`, by kind.
    pub on_non_swarm: [usize; 5],
    /// Edges between two different interacting groups.
    pub across_groups: usize,
}

pub fn swarm_eval(a: &Analysis, labels: &LabelSet) -> SwarmEval {
    let group = |r: &RunRef| -> Option<&str> {
        r.records
            .iter()
            .find_map(|id| labels.labels.get(id).and_then(|l| l.swarm.as_deref()))
    };
    let mut groups: Vec<String> = Vec::new();
    for l in labels.labels.values() {
        if let Some(g) = &l.swarm
            && g != "none"
            && !groups.contains(g)
        {
            groups.push(g.clone());
        }
    }
    crate::sort::sort(&mut groups);
    let mut out = SwarmEval {
        edges: a.swarm_edges.len(),
        ..Default::default()
    };
    let mut inside: Vec<&str> = Vec::new();
    for e in &a.swarm_edges {
        let k = e.kind as usize;
        out.by_kind[k] += 1;
        match (group(&e.a), group(&e.b)) {
            (Some("none"), _) | (_, Some("none")) => out.on_non_swarm[k] += 1,
            (Some(x), Some(y)) if x == y => {
                out.on_groups += 1;
                inside.push(x);
            }
            (Some(_), Some(_)) => out.across_groups += 1,
            _ => {}
        }
    }
    out.found = groups
        .iter()
        .filter(|g| inside.contains(&g.as_str()))
        .cloned()
        .collect();
    out.groups = groups;
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyze::analyze;
    use crate::model::Observation;

    const T0: i64 = 1_791_000_000;
    const INBOX: &str = "0b6c1f0e-1111-4c2a-9a55-3f2e1d0c9b8a";
    const GIST: &str = "3f9a2c1b7d4e5f60718293a4b5c6d7e8";

    fn o(id: &str, ts: i64, url: &str) -> Observation {
        Observation {
            id: id.into(),
            ts,
            url: url.into(),
            ..Default::default()
        }
    }

    fn with(mut x: Observation, ua: &str, asn: u32) -> Observation {
        x.user_agent = Some(ua.into());
        x.asn = Some(asn);
        x
    }

    fn edges(obs: Vec<Observation>, kind: SwarmEdgeKind) -> (Analysis, Vec<SwarmEdge>) {
        let a = analyze(obs, &Rules::default_rules());
        let e = a
            .swarm_edges
            .iter()
            .filter(|e| e.kind == kind)
            .cloned()
            .collect();
        (a, e)
    }

    #[test]
    fn kinds_parse_and_name() {
        for k in SwarmEdgeKind::ALL {
            assert_eq!(k.id().parse::<SwarmEdgeKind>(), Ok(k));
            assert_eq!(k.name().parse::<SwarmEdgeKind>(), Ok(k));
        }
        assert_eq!("hand-off".parse(), Ok(SwarmEdgeKind::Handoff));
        assert_eq!("Shared-Sink".parse(), Ok(SwarmEdgeKind::SharedSink));
        assert!("telepathy".parse::<SwarmEdgeKind>().is_err());
    }

    #[test]
    fn artifacts_are_named_by_string_only() {
        for (host, text, want) in [
            (
                "gist.github.com",
                "https://gist.github.com/u/ABCDEF0123456789abcd",
                Some("gist/abcdef0123456789abcd"),
            ),
            (
                "pastebin.com",
                "https://pastebin.com/raw/Xy12Ab34",
                Some("pastebin/Xy12Ab34"),
            ),
            (
                "huggingface.co",
                "https://huggingface.co/spaces/Some_User/My.App",
                Some("hf_space/some-user-my-app"),
            ),
            (
                "some-user-my-app.hf.space",
                "https://some-user-my-app.hf.space/run",
                Some("hf_space/some-user-my-app"),
            ),
            (
                "notes-7.pages.dev",
                "https://notes-7.pages.dev/x",
                Some("site/notes-7.pages.dev"),
            ),
            ("pages.dev", "https://pages.dev/", None),
            ("www.github.io", "https://www.github.io/", None),
            ("gist.github.com", "https://gist.github.com/discover", None),
            ("rentry.co", "https://rentry.co/api/new", None),
        ] {
            assert_eq!(site_artifact(host, text).as_deref(), want, "{text}");
        }
    }

    /// Two agents writing one inbox: one direct from a cloud network with a
    /// headless browser, one through a relay from another network.
    fn one_sink() -> Vec<Observation> {
        let mut obs = Vec::new();
        for i in 0..3 {
            obs.push(with(
                o(
                    &format!("d{i}"),
                    T0 + i * 120,
                    &format!("https://h{i}.city.example/q?id={i}&cb=https://webhook.site/{INBOX}"),
                ),
                "HeadlessChrome/124",
                16509,
            ));
            obs.push(with(
                o(&format!("r{i}"), T0 + 60 + i * 120, &format!("https://r.jina.ai/https://k{i}.city.example/p?hook=https://webhook.site/{INBOX}")),
                "python-httpx/0.27",
                14061,
            ));
        }
        obs
    }

    #[test]
    fn two_writers_inside_one_sink_cluster_are_a_shared_sink() {
        let (a, e) = edges(one_sink(), SwarmEdgeKind::SharedSink);
        assert_eq!(a.clusters.len(), 1, "{:?}", a.clusters);
        assert_eq!(e.len(), 1, "{:?}", a.swarm_edges);
        let e = &e[0];
        assert_eq!((e.a.cluster.as_str(), e.b.cluster.as_str()), ("C1", "C1"));
        assert!(e.a.strand.is_some() && e.a.strand != e.b.strand, "{e:?}");
        assert_eq!(e.strength, EdgeStrength::Moderate, "{}", e.detail);
        assert!(
            e.detail.contains("user agent") && e.detail.contains("webhook[.]site"),
            "{}",
            e.detail
        );
        // One client throughout: no edge.
        let same: Vec<Observation> = one_sink()
            .into_iter()
            .map(|x| with(x, "python-httpx/0.27", 14061))
            .collect();
        assert!(edges(same, SwarmEdgeKind::SharedSink).1.is_empty());
    }

    #[test]
    fn a_gist_written_then_fetched_is_a_handoff() {
        let note = format!("https://gist.github.com/fieldnotes/{GIST}");
        let mut obs = Vec::new();
        for i in 0..3 {
            obs.push(with(
                o(
                    &format!("w{i}"),
                    T0 + i * 60,
                    &format!(
                        "https://r.jina.ai/https://a{i}.agency.example/s?uqtag=scout7&notes={note}"
                    ),
                ),
                "ScoutBot/1",
                16509,
            ));
        }
        for i in 0..2 {
            obs.push(with(
                o(&format!("f{i}"), T0 + 1500 + i * 60, &format!("https://r.jina.ai/https://gist.githubusercontent.com/fieldnotes/{GIST}/raw?uqtag=exec4k&n={i}")),
                "python-requests/2.31",
                14061,
            ));
        }
        let (a, e) = edges(obs.clone(), SwarmEdgeKind::Handoff);
        assert_eq!(a.clusters.len(), 2, "{:?}", a.clusters);
        assert_eq!(e.len(), 1, "{:?}", a.swarm_edges);
        assert_eq!(e[0].strength, EdgeStrength::Strong);
        assert_eq!(e[0].a.records, ["w0"]);
        assert_eq!(e[0].b.records, ["f0"]);
        assert!(e[0].detail.contains("gist/"), "{}", e[0].detail);
        // Fetched before it was written: no hand-off.
        for x in obs.iter_mut().filter(|x| x.id.starts_with('f')) {
            x.ts -= 3000;
        }
        assert!(edges(obs, SwarmEdgeKind::Handoff).1.is_empty());
    }

    #[test]
    fn reading_hosts_then_attacking_them_is_a_role_sequence() {
        let hosts = ["a", "b", "c", "d", "e"];
        let mut obs = Vec::new();
        for (i, h) in hosts.iter().enumerate() {
            obs.push(with(
                o(
                    &format!("x{i}"),
                    T0 + i as i64 * 60,
                    &format!("https://r.jina.ai/https://{h}.registry.example/?uqtag=map31"),
                ),
                "MapAgent/2",
                16509,
            ));
            obs.push(with(
                o(
                    &format!("y{i}"),
                    T0 + 1800 + i as i64 * 60,
                    &format!("https://{h}.registry.example/item?id=1'%20OR%201=1--&uqtag=hit88"),
                ),
                "curl/8.5",
                14061,
            ));
        }
        // Unrelated hosts elsewhere make random overlap unlikely.
        for i in 0..40 {
            obs.push(o(
                &format!("z{i}"),
                T0 + 90_000 + i * 30,
                &format!(
                    "https://r.jina.ai/https://z{i}.other.example/?uqtag=bg{}",
                    i / 4
                ),
            ));
        }
        let (a, e) = edges(obs.clone(), SwarmEdgeKind::RoleSequence);
        assert_eq!(e.len(), 1, "{:?}", a.swarm_edges);
        assert_eq!(e[0].strength, EdgeStrength::Moderate);
        assert!(e[0].chance.unwrap() < 1e-3, "{:?}", e[0].chance);
        // The attack before the reading: no sequence.
        for x in obs.iter_mut().filter(|x| x.id.starts_with('y')) {
            x.ts -= 3600;
        }
        assert!(edges(obs, SwarmEdgeKind::RoleSequence).1.is_empty());
    }

    #[test]
    fn a_sharded_list_is_a_partition_and_nothing_else() {
        // One scheduler, one client, two shards of one list started together.
        let mut obs = Vec::new();
        for s in 0..2 {
            for i in 0..8 {
                obs.push(with(
                    o(
                        &format!("s{s}{i}"),
                        T0 + s * 40 + i * 50,
                        &format!(
                            "https://h{}.county.example/records?uqtag=shard{s}x&_=1",
                            s * 8 + i
                        ),
                    ),
                    "SchedBot/1",
                    16509,
                ));
            }
        }
        let a = analyze(obs, &Rules::default_rules());
        assert_eq!(a.clusters.len(), 2, "{:?}", a.clusters);
        let kinds: Vec<SwarmEdgeKind> = a.swarm_edges.iter().map(|e| e.kind).collect();
        assert_eq!(
            kinds,
            [SwarmEdgeKind::DisjointPartition],
            "{:?}",
            a.swarm_edges
        );
        assert_eq!(a.swarm_edges[0].strength, EdgeStrength::Weak);
        assert!(a.swarm_edges[0].detail.contains("fleet signal"));
    }

    #[test]
    fn runs_starting_and_stopping_together_beyond_chance() {
        // Two clients, two runs each, started and stopped within a minute of
        // each other, off the clock hour, two days apart.
        let mut obs = Vec::new();
        for (c, (ua, asn)) in [("SyncA/1", 16509), ("SyncB/1", 14061)].iter().enumerate() {
            for (k, day) in [0, 2].iter().enumerate() {
                let t = T0 + day * 86_400 + 1234 + c as i64 * 30;
                for i in 0..5 {
                    obs.push(with(
                        o(
                            &format!("c{c}k{k}i{i}"),
                            t + i * 300,
                            &format!("https://r.jina.ai/https://p{c}{i}.example{c}/?uqtag=sync{c}"),
                        ),
                        ua,
                        *asn,
                    ));
                }
            }
        }
        let (a, e) = edges(obs.clone(), SwarmEdgeKind::SynchronizedStart);
        assert_eq!(e.len(), 1, "{:?}", a.swarm_edges);
        assert!(e[0].chance.unwrap() <= MAX_CHANCE);
        assert!(e[0].detail.contains("2 run(s)"), "{}", e[0].detail);
        // On the clock hour, the same alignment is what crons do.
        for x in obs.iter_mut() {
            x.ts -= 1234;
        }
        assert!(edges(obs, SwarmEdgeKind::SynchronizedStart).1.is_empty());
    }

    #[test]
    fn edges_never_change_clusters_and_reach_only_internal_and_provider() {
        let a = analyze(one_sink(), &Rules::default_rules());
        assert!(!a.swarm_edges.is_empty());
        let mut b = a.clone();
        b.swarm_edges.clear();
        let render = |a: &Analysis, audience| {
            crate::report::render_markdown(
                a,
                &crate::report::ReportOptions {
                    audience,
                    ..Default::default()
                },
            )
        };
        use crate::report::Audience::*;
        for au in [Internal, Provider] {
            let md = render(&a, au);
            assert!(md.contains("## Possible interaction (SC-T9)"), "{md}");
            assert!(md.contains("write to `webhook[.]site/"), "defanged: {md}");
        }
        for au in [Affected, Public] {
            assert!(!render(&a, au).contains("Possible interaction"));
        }
        assert!(!render(&b, Internal).contains("Possible interaction"));
    }

    #[test]
    fn eval_counts_edges_against_swarm_groups() {
        let a = analyze(one_sink(), &Rules::default_rules());
        let lines: String = (0..3)
            .flat_map(|i| [format!("d{i}"), format!("r{i}")])
            .map(|id| format!("{{\"id\":\"{id}\",\"label\":\"agent\",\"swarm\":\"sink-1\"}}\n"))
            .collect();
        let e = swarm_eval(&a, &crate::eval::parse_labels(&lines));
        assert_eq!(e.groups, ["sink-1"]);
        assert_eq!(e.found, ["sink-1"]);
        assert_eq!(e.on_groups, 1);
        let none = lines.replace("sink-1", "none");
        let e = swarm_eval(&a, &crate::eval::parse_labels(&none));
        assert!(e.groups.is_empty());
        assert_eq!(e.on_non_swarm, [1, 0, 0, 0, 0]);
    }
}
