//! Runs and strands: the units edges join, and how their records were sent.

use crate::analyze::{Cluster, ObsResult, relay_stack};
use crate::model::{IndicatorKind, Tier, truncate};
use crate::timing::request_like;

/// How a record was sent: relay route, user agent, network, header set,
/// encoding style. The first four also split a run into strands.
const DIMS: [&str; 5] = [
    "relay route",
    "user agent",
    "network",
    "header set",
    "encoding",
];

pub(super) type Fp = [Vec<String>; 5];

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

/// Who sent a record: its user agent, network and header set, whatever
/// relay it went through. `None` when neither the user agent nor the network
/// is known, so no client can be told apart.
fn client_key(r: &ObsResult) -> Option<String> {
    let d = dims(r);
    let mut key = String::new();
    for x in &d[1..4] {
        key += x.as_deref().unwrap_or("");
        key.push('|');
    }
    (d[1].is_some() || d[2].is_some()).then_some(key)
}

pub(super) fn fp_of(results: &[ObsResult], members: &[usize]) -> Fp {
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
/// Clients known on neither side give an empty list: S3 counts those as
/// different, its timing tests carrying the edge; S6 requires a non-empty
/// list.
pub(super) fn differ(a: &Fp, b: &Fp) -> Option<Vec<&'static str>> {
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
pub(super) type Keyed = Vec<(String, i64)>;

pub(super) fn sort_keyed(v: &mut Keyed) {
    crate::sort::by(v, |a, b| a.0.cmp(&b.0));
}

/// Sorted by name, keeping each name's first value.
pub(super) fn first_by_key(mut v: Keyed) -> Keyed {
    sort_keyed(&mut v);
    v.dedup_by(|b, a| a.0 == b.0);
    v
}

pub(super) fn find(v: &[(String, i64)], k: &str) -> Option<i64> {
    v.binary_search_by(|x| x.0.as_str().cmp(k))
        .ok()
        .map(|i| v[i].1)
}

/// The indexes below `n` that `keep` admits.
pub(super) fn indexes(n: usize, keep: &dyn Fn(usize) -> bool) -> Vec<usize> {
    (0..n).filter(|&i| keep(i)).collect()
}

/// One way of sending within a run: its label (when the run has several),
/// members and fingerprint.
pub(super) struct Strand {
    pub(super) label: Option<String>,
    pub(super) members: Vec<usize>,
    pub(super) fp: Fp,
}

/// One run of a cluster above noise.
pub(super) struct Run {
    pub(super) ci: usize,
    pub(super) n: usize,
    pub(super) members: Vec<usize>,
    pub(super) start: i64,
    pub(super) end: i64,
    pub(super) fp: Fp,
    pub(super) strands: Vec<Strand>,
    /// (target host, first time), by host: every member, and attacks only.
    pub(super) hosts: Keyed,
    pub(super) attacks: Keyed,
    /// Distinct request and submit times of its members and of the
    /// unflagged records its clients sent within its span, earliest first.
    /// Capture times never count.
    pub(super) events: Vec<i64>,
}

pub(super) fn runs(clusters: &[Cluster], results: &[ObsResult]) -> Vec<Run> {
    let mut out = Vec::new();
    // Unflagged records with a known client, by client key then time.
    let mut loose: Vec<(String, i64)> = results
        .iter()
        .filter(|r| r.cluster.is_none() && r.obs.ts > 0 && request_like(r.obs.ts_kind))
        .filter_map(|r| client_key(r).map(|k| (k, r.obs.ts)))
        .collect();
    crate::sort::sort(&mut loose);
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
            let mut events: Vec<i64> = members
                .iter()
                .map(|&m| &results[m].obs)
                .filter(|o| o.ts > 0 && request_like(o.ts_kind))
                .map(|o| o.ts)
                .collect();
            let mut clients: Vec<String> = members
                .iter()
                .filter_map(|&m| client_key(&results[m]))
                .collect();
            crate::sort::sort(&mut clients);
            clients.dedup();
            for k in &clients {
                let from =
                    loose.partition_point(|x| (x.0.as_str(), x.1) < (k.as_str(), span.start));
                events.extend(
                    loose[from..]
                        .iter()
                        .take_while(|x| x.0 == *k && x.1 <= span.end)
                        .map(|x| x.1),
                );
            }
            crate::sort::sort(&mut events);
            events.dedup();
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
                events,
            });
        }
    }
    out
}

/// The registrable-looking part of a host: its last two labels.
pub(super) fn family(host: &str) -> &str {
    let mut dots = host.rmatch_indices('.');
    dots.next();
    dots.next().map_or(host, |(i, _)| &host[i + 1..])
}
