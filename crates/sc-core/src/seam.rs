//! Seams: where a cluster's link graph hangs on one record or one client.
//!
//! Linking is single-link: one record carrying two operators' identifiers,
//! or one client sending records with each, joins both operators' records
//! into one cluster. A cluster's link graph is its records and the ties that
//! joined them (a feature group, a run of close requests on one host, a
//! probe chain), each tie joining all of its records at once. A **joint** is
//! what the rest hangs on:
//!
//! - an articulation record: one record whose removal leaves the rest in
//!   pieces (Tarjan's algorithm over the graph of records and ties, linear
//!   in its size);
//! - a client strand: every record of one client (user agent, network and
//!   header set), when removing them leaves the rest in pieces. One client
//!   sending one operator's tag on some records and another's on others is
//!   a joint no single record shows. The smallest strands are read first,
//!   at most [`MAX_STRANDS`] per cluster.
//!
//! A joint is a **seam** when the two largest pieces each hold at least
//! `linking.seam_min_side` records and differ: their habits share nothing
//! (relay stacks, URL encodings or payload dialect, where both sides have
//! them), or no client (user agent, network and header set together) sent
//! records on both. A seam is a prompt for
//! the plant review ([`crate::plant`]): it never splits the cluster, changes
//! a score or links anything.

use crate::analyze::{ObsResult, Tie, TieWhy};
use crate::swarm::client_key;
use std::collections::{BTreeMap, BTreeSet, HashMap};

/// Client strands read per cluster, smallest first.
pub(crate) const MAX_STRANDS: usize = 32;
/// Seams kept per cluster, the most even split first.
const MAX_SEAMS: usize = 3;
/// Ties named per seam.
const MAX_VIA: usize = 4;

/// One seam in a cluster.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Seam {
    /// The joint's records (indexes into the results), in time order.
    pub joint: Vec<usize>,
    /// A client strand, rather than one record.
    pub strand: bool,
    /// The two largest pieces left without the joint, larger first, each
    /// in time order.
    pub sides: [Vec<usize>; 2],
    /// How the sides differ: habits on which they share nothing, then
    /// `clients`.
    pub differs: Vec<&'static str>,
    /// What ties the joint to the rest: its linking features (as written,
    /// not defanged), close requests on a host (defanged), a probe chain. A
    /// few.
    pub via: Vec<String>,
}

/// The cluster's link graph: records `0..n`, ties `n..`.
struct Graph {
    n: usize,
    adj: Vec<Vec<usize>>,
    /// The tie each node from `n` on stands for (an index into the ties).
    tie_of: Vec<usize>,
}

impl Graph {
    fn new(members: &[usize], ties: &[&Tie]) -> Self {
        let local: HashMap<usize, usize> =
            members.iter().enumerate().map(|(i, &m)| (m, i)).collect();
        let n = members.len();
        let mut adj: Vec<Vec<usize>> = vec![Vec::new(); n];
        let mut tie_of = Vec::new();
        for (ti, t) in ties.iter().enumerate() {
            let mut on: Vec<usize> = t
                .members
                .iter()
                .filter_map(|m| local.get(m).copied())
                .collect();
            on.sort_unstable();
            on.dedup();
            if on.len() < 2 {
                continue;
            }
            let node = adj.len();
            tie_of.push(ti);
            adj.push(on.clone());
            for r in on {
                adj[r].push(node);
            }
        }
        Self { n, adj, tie_of }
    }

    /// The ties of the `joint` records (local indexes) that reach a record
    /// outside it, described, in tie order and without repeats.
    fn via(&self, joint: &[usize], ties: &[&Tie]) -> Vec<String> {
        let inside: BTreeSet<usize> = joint.iter().copied().collect();
        let mut nodes: BTreeSet<usize> = BTreeSet::new();
        for &r in joint {
            for &t in &self.adj[r] {
                if self.adj[t].iter().any(|x| !inside.contains(x)) {
                    nodes.insert(t);
                }
            }
        }
        let mut out: Vec<String> = Vec::new();
        for t in nodes {
            let d = match &ties[self.tie_of[t - self.n]].why {
                TieWhy::Feature(f) => format!("`{f}`"),
                TieWhy::Timing(h) => {
                    format!("close requests on {}", crate::extract::defang_host(h))
                }
                TieWhy::Chain => "a probe chain".to_string(),
            };
            if !out.contains(&d) {
                out.push(d);
            }
        }
        out.truncate(MAX_VIA);
        out
    }

    /// Pieces of the graph without the `removed` records, each as its
    /// records (local indexes), largest first.
    fn pieces_without(&self, removed: &[bool]) -> Vec<Vec<usize>> {
        let mut seen = vec![false; self.adj.len()];
        let mut out = Vec::new();
        for s in 0..self.n {
            if removed[s] || seen[s] {
                continue;
            }
            let mut piece = Vec::new();
            let mut stack = vec![s];
            seen[s] = true;
            while let Some(v) = stack.pop() {
                if v < self.n {
                    piece.push(v);
                }
                for &w in &self.adj[v] {
                    if !seen[w] && !(w < self.n && removed[w]) {
                        seen[w] = true;
                        stack.push(w);
                    }
                }
            }
            piece.sort_unstable();
            out.push(piece);
        }
        crate::sort::by(&mut out, |a, b| b.len().cmp(&a.len()).then(a.cmp(b)));
        out
    }

    /// The record nodes whose removal disconnects the graph, each with the
    /// pieces left (records, local indexes), largest first. Iterative
    /// Tarjan from record 0; a piece below an articulation point is a
    /// contiguous run of the DFS preorder.
    fn articulations(&self) -> Vec<(usize, Vec<Vec<usize>>)> {
        let total = self.adj.len();
        if self.n < 3 {
            return Vec::new();
        }
        const NONE: usize = usize::MAX;
        let (mut disc, mut low) = (vec![NONE; total], vec![0usize; total]);
        let mut parent = vec![NONE; total];
        let mut size = vec![1usize; total];
        let mut order: Vec<usize> = Vec::with_capacity(total);
        // (node, next neighbour index)
        let mut stack: Vec<(usize, usize)> = vec![(0, 0)];
        disc[0] = 0;
        low[0] = 0;
        order.push(0);
        while let Some(&mut (v, ref mut next)) = stack.last_mut() {
            if *next < self.adj[v].len() {
                let w = self.adj[v][*next];
                *next += 1;
                if disc[w] == NONE {
                    disc[w] = order.len();
                    low[w] = disc[w];
                    parent[w] = v;
                    order.push(w);
                    stack.push((w, 0));
                } else if w != parent[v] {
                    low[v] = low[v].min(disc[w]);
                }
            } else {
                stack.pop();
                let p = parent[v];
                if p != NONE {
                    low[p] = low[p].min(low[v]);
                    size[p] += size[v];
                }
            }
        }
        // Children of each node in the DFS tree.
        let mut children: Vec<Vec<usize>> = vec![Vec::new(); total];
        for &w in &order[1..] {
            children[parent[w]].push(w);
        }
        let mut out = Vec::new();
        for v in 0..self.n {
            if disc[v] == NONE {
                continue;
            }
            let cut: Vec<usize> = children[v]
                .iter()
                .copied()
                .filter(|&c| low[c] >= disc[v])
                .collect();
            let root = parent[v] == NONE;
            if (root && cut.len() < 2) || (!root && cut.is_empty()) {
                continue;
            }
            let mut inside = vec![false; total];
            let mut pieces: Vec<Vec<usize>> = Vec::new();
            for &c in &cut {
                let range = &order[disc[c]..disc[c] + size[c]];
                for &x in range {
                    inside[x] = true;
                }
                pieces.push(range.iter().copied().filter(|&x| x < self.n).collect());
            }
            if !root {
                pieces.push(
                    (0..self.n)
                        .filter(|&x| x != v && !inside[x] && disc[x] != NONE)
                        .collect(),
                );
            }
            for p in &mut pieces {
                p.sort_unstable();
            }
            crate::sort::by(&mut pieces, |a, b| b.len().cmp(&a.len()).then(a.cmp(b)));
            out.push((v, pieces));
        }
        out
    }
}

/// The relay stacks, encoding styles and payload variants of `records`.
fn habits(results: &[ObsResult], records: &[usize]) -> [BTreeSet<String>; 3] {
    let mut h: [BTreeSet<String>; 3] = Default::default();
    for &m in records {
        let r = &results[m];
        if let Some(s) = crate::analyze::relay_stack(r) {
            h[0].insert(s);
        }
        let enc = crate::fingerprint::encoding(&r.obs.url);
        if enc.informative() {
            h[1].insert(enc.style);
        }
        h[2].extend(crate::analyze::payload_variants(r));
    }
    h
}

/// How two sides differ: the habits on which both have data and share
/// nothing ([`crate::plant::HABITS`]), then `clients` when both name
/// clients and no client (user agent, network and header set together)
/// sent records on both.
fn sides_differ(results: &[ObsResult], a: &[usize], b: &[usize]) -> Vec<&'static str> {
    let (ha, hb) = (habits(results, a), habits(results, b));
    let mut v = crate::plant::habits_apart(&ha, &hb);
    let clients = |s: &[usize]| -> BTreeSet<String> {
        s.iter().filter_map(|&m| client_key(&results[m])).collect()
    };
    let (ca, cb) = (clients(a), clients(b));
    if !ca.is_empty() && !cb.is_empty() && ca.is_disjoint(&cb) {
        v.push("clients");
    }
    v
}

/// The seams of the cluster of `members` (indexes into `results`, in time
/// order) joined by `ties`. Off when `min_side` is 0.
pub(crate) fn seams(
    results: &[ObsResult],
    members: &[usize],
    ties: &[&Tie],
    min_side: usize,
) -> Vec<Seam> {
    if min_side == 0 || members.len() < 2 * min_side + 1 {
        return Vec::new();
    }
    let g = Graph::new(members, ties);
    let global = |v: &[usize]| -> Vec<usize> { v.iter().map(|&x| members[x]).collect() };
    let mut out: Vec<Seam> = Vec::new();
    let mut consider = |joint: Vec<usize>, strand: bool, pieces: Vec<Vec<usize>>| {
        if pieces.len() < 2 || pieces[1].len() < min_side {
            return false;
        }
        let (a, b) = (global(&pieces[0]), global(&pieces[1]));
        let differs = sides_differ(results, &a, &b);
        if differs.is_empty() {
            return false;
        }
        let sides = [a, b];
        if out.iter().any(|s| s.sides == sides) {
            return false;
        }
        out.push(Seam {
            via: g.via(&joint, ties),
            joint: global(&joint),
            strand,
            sides,
            differs,
        });
        true
    };
    // Client strands of two or more records, smallest first; a strand of
    // one record is an articulation record or nothing.
    let mut strands: BTreeMap<String, Vec<usize>> = BTreeMap::new();
    for (i, &m) in members.iter().enumerate() {
        if let Some(k) = client_key(&results[m]) {
            strands.entry(k).or_default().push(i);
        }
    }
    // Records of a strand that is a seam: an articulation record among them
    // names a piece of the same split.
    let mut in_seam = vec![false; g.n];
    if strands.len() >= 2 {
        let mut by_size: Vec<Vec<usize>> = strands
            .into_values()
            .filter(|s| s.len() >= 2 && s.len() + 2 * min_side <= members.len())
            .collect();
        crate::sort::by(&mut by_size, |a, b| a.len().cmp(&b.len()).then(a.cmp(b)));
        for s in by_size.into_iter().take(MAX_STRANDS) {
            let mut removed = vec![false; g.n];
            for &x in &s {
                removed[x] = true;
            }
            if consider(s.clone(), true, g.pieces_without(&removed)) {
                for x in s {
                    in_seam[x] = true;
                }
            }
        }
    }
    for (v, pieces) in g.articulations() {
        if !in_seam[v] {
            consider(vec![v], false, pieces);
        }
    }
    crate::sort::by(&mut out, |a, b| {
        b.sides[1]
            .len()
            .cmp(&a.sides[1].len())
            .then(a.joint.len().cmp(&b.joint.len()))
            .then(a.joint.cmp(&b.joint))
    });
    out.truncate(MAX_SEAMS);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{LinkFeature, Observation};

    fn rec(ua: &str, asn: u32) -> ObsResult {
        ObsResult {
            obs: Observation {
                user_agent: Some(ua.into()),
                asn: Some(asn),
                url: "https://target.example/".into(),
                ..Default::default()
            },
            score: 1,
            tier: crate::model::Tier::Suggestive,
            hits: Vec::new(),
            layers: Vec::new(),
            target_host: None,
            features: Vec::new(),
            cluster: None,
            agent: None,
        }
    }

    fn tie(members: &[usize], tag: &str) -> Tie {
        Tie {
            members: members.to_vec(),
            why: TieWhy::Feature(LinkFeature::param("uqtag", tag)),
        }
    }

    /// Two clients' records, 0-3 and 5-8, each joined by its own tag.
    fn two_operators() -> Vec<ObsResult> {
        let mut r: Vec<ObsResult> = (0..4).map(|_| rec("python-httpx/0.27.0", 16509)).collect();
        r.push(rec("Mozilla/5.0 (X11; Linux x86_64) Firefox/126.0", 7922));
        r.extend((0..4).map(|_| rec("Go-http-client/2.0", 14061)));
        r
    }

    #[test]
    fn one_record_carrying_two_operators_tags_is_a_seam() {
        let results = two_operators();
        let members: Vec<usize> = (0..9).collect();
        // Record 4 carries both tags.
        let ties = [tie(&[0, 1, 2, 3, 4], "ra"), tie(&[4, 5, 6, 7, 8], "rb")];
        let refs: Vec<&Tie> = ties.iter().collect();
        let s = seams(&results, &members, &refs, 3);
        assert_eq!(s.len(), 1, "{s:?}");
        assert_eq!(s[0].joint, vec![4]);
        assert!(!s[0].strand);
        assert_eq!(s[0].sides, [vec![0, 1, 2, 3], vec![5, 6, 7, 8]]);
        assert_eq!(s[0].differs, vec!["clients"]);
        assert_eq!(s[0].via, vec!["`param:uqtag=ra`", "`param:uqtag=rb`"]);
        // Sides too small, or off.
        assert!(seams(&results, &members, &refs, 5).is_empty());
        assert!(seams(&results, &members, &refs, 0).is_empty());
    }

    #[test]
    fn one_client_alternating_two_tags_is_a_strand_seam() {
        let mut results = two_operators();
        // Records 9 and 10 from the planter's client: one with each tag.
        results.push(rec("Mozilla/5.0 (X11; Linux x86_64) Firefox/126.0", 7922));
        results.push(rec("Mozilla/5.0 (X11; Linux x86_64) Firefox/126.0", 7922));
        let members: Vec<usize> = [0, 1, 2, 3, 5, 6, 7, 8, 9, 10].to_vec();
        let ties = [
            tie(&[0, 1, 2, 3, 9], "ra"),
            tie(&[5, 6, 7, 8, 10], "rb"),
            tie(&[9, 10], "inbox"),
        ];
        let refs: Vec<&Tie> = ties.iter().collect();
        let s = seams(&results, &members, &refs, 3);
        assert_eq!(s.len(), 1, "{s:?}");
        assert!(s[0].strand);
        assert_eq!(s[0].joint, vec![9, 10]);
        assert_eq!(s[0].sides, [vec![0, 1, 2, 3], vec![5, 6, 7, 8]]);
    }

    #[test]
    fn one_client_or_one_shared_tag_is_no_seam() {
        // A single client's records hanging on one record: the sides do
        // not differ.
        let results: Vec<ObsResult> = (0..9).map(|_| rec("python-httpx/0.27.0", 16509)).collect();
        let members: Vec<usize> = (0..9).collect();
        let ties = [tie(&[0, 1, 2, 3, 4], "ra"), tie(&[4, 5, 6, 7, 8], "rb")];
        let refs: Vec<&Tie> = ties.iter().collect();
        assert!(seams(&results, &members, &refs, 3).is_empty());
        // Every record on one tag: no joint at all.
        let results = two_operators();
        let ties = [tie(&members, "inbox")];
        let refs: Vec<&Tie> = ties.iter().collect();
        assert!(seams(&results, &members, &refs, 3).is_empty());
    }

    #[test]
    fn articulations_match_removing_each_record() {
        // A path of ties with a cycle: 0-1-2, 2-3, 3-4-5, 5-2 (cycle 2..5),
        // 5-6, 6-7.
        let members: Vec<usize> = (0..8).collect();
        let ties = [
            tie(&[0, 1, 2], "a"),
            tie(&[2, 3], "b"),
            tie(&[3, 4, 5], "c"),
            tie(&[5, 2], "d"),
            tie(&[5, 6], "e"),
            tie(&[6, 7], "f"),
        ];
        let refs: Vec<&Tie> = ties.iter().collect();
        let g = Graph::new(&members, &refs);
        let fast: BTreeMap<usize, Vec<Vec<usize>>> = g.articulations().into_iter().collect();
        for v in 0..8 {
            let mut removed = vec![false; 8];
            removed[v] = true;
            let slow = g.pieces_without(&removed);
            if slow.len() > 1 {
                assert_eq!(fast.get(&v), Some(&slow), "record {v}");
            } else {
                assert!(!fast.contains_key(&v), "record {v}");
            }
        }
        assert_eq!(fast.keys().copied().collect::<Vec<_>>(), vec![2, 5, 6]);
    }
}
