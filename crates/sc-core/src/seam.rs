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
//! records on both while each side has a client sending two or more of its
//! records (one rotating its client on every request shares none anyway). A seam is a prompt for
//! the plant review ([`crate::plant`]): it never splits the cluster, changes
//! a score or links anything.

use crate::analyze::{ObsResult, Tie, TieWhy};
use crate::swarm::client_key;
use std::collections::{BTreeMap, BTreeSet, HashMap};

/// Client strands read per cluster, smallest first.
pub(crate) const MAX_STRANDS: usize = 32;
/// Seams kept per cluster, the most even split first.
const MAX_SEAMS: usize = 3;
/// Articulation records whose pieces are built and read per cluster, the
/// most even split first.
const MAX_JOINTS: usize = 32;
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

    /// A depth-first search from record 0 (iterative Tarjan): what finding
    /// the articulation records and their pieces needs.
    fn dfs(&self) -> Dfs {
        let total = self.adj.len();
        let (mut disc, mut low) = (vec![NONE; total], vec![0usize; total]);
        let mut parent = vec![NONE; total];
        let mut size = vec![1usize; total];
        let mut records: Vec<usize> = (0..total).map(|v| usize::from(v < self.n)).collect();
        let mut order: Vec<usize> = Vec::with_capacity(total);
        if self.n == 0 {
            return Dfs {
                disc,
                low,
                parent,
                size,
                records,
                order,
                children: vec![Vec::new(); total],
            };
        }
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
                    records[p] += records[v];
                }
            }
        }
        let mut children: Vec<Vec<usize>> = vec![Vec::new(); total];
        for &w in &order[1..] {
            children[parent[w]].push(w);
        }
        Dfs {
            disc,
            low,
            parent,
            size,
            records,
            order,
            children,
        }
    }

    /// The children of `v` in the DFS tree whose subtrees removing `v` cuts
    /// off.
    fn cut_children(&self, d: &Dfs, v: usize) -> Vec<usize> {
        d.children[v]
            .iter()
            .copied()
            .filter(|&c| d.low[c] >= d.disc[v])
            .collect()
    }

    /// The record nodes whose removal disconnects the graph, each with the
    /// record counts of the pieces left, largest first. Linear in the
    /// graph: the pieces themselves are built only for the joints read
    /// ([`Graph::pieces_at`]), since a long chained cluster has an
    /// articulation record at nearly every link and all their pieces would
    /// be quadratic.
    fn articulations(&self, d: &Dfs) -> Vec<(usize, Vec<usize>)> {
        if self.n < 3 {
            return Vec::new();
        }
        let reached = d.records[0];
        let mut out = Vec::new();
        for v in 0..self.n {
            if d.disc[v] == NONE {
                continue;
            }
            let cut = self.cut_children(d, v);
            let root = d.parent[v] == NONE;
            if (root && cut.len() < 2) || (!root && cut.is_empty()) {
                continue;
            }
            let mut sizes: Vec<usize> = cut.iter().map(|&c| d.records[c]).collect();
            if !root {
                sizes.push(reached - 1 - sizes.iter().sum::<usize>());
            }
            sizes.sort_unstable_by(|a, b| b.cmp(a));
            out.push((v, sizes));
        }
        out
    }

    /// The pieces left without articulation record `v` (local indexes),
    /// largest first; a piece below `v` is a contiguous run of the DFS
    /// preorder.
    fn pieces_at(&self, d: &Dfs, v: usize) -> Vec<Vec<usize>> {
        let total = self.adj.len();
        let cut = self.cut_children(d, v);
        let mut inside = vec![false; total];
        let mut pieces: Vec<Vec<usize>> = Vec::new();
        for &c in &cut {
            let range = &d.order[d.disc[c]..d.disc[c] + d.size[c]];
            for &x in range {
                inside[x] = true;
            }
            pieces.push(range.iter().copied().filter(|&x| x < self.n).collect());
        }
        if d.parent[v] != NONE {
            pieces.push(
                (0..self.n)
                    .filter(|&x| x != v && !inside[x] && d.disc[x] != NONE)
                    .collect(),
            );
        }
        for p in &mut pieces {
            p.sort_unstable();
        }
        crate::sort::by(&mut pieces, |a, b| b.len().cmp(&a.len()).then(a.cmp(b)));
        pieces
    }
}

const NONE: usize = usize::MAX;

/// A depth-first search of a cluster's link graph: discovery and low
/// numbers, parents, subtree sizes (all nodes, and records alone), the
/// preorder and each node's children in the tree.
struct Dfs {
    disc: Vec<usize>,
    low: Vec<usize>,
    parent: Vec<usize>,
    size: Vec<usize>,
    records: Vec<usize>,
    order: Vec<usize>,
    children: Vec<Vec<usize>>,
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
/// nothing ([`crate::plant::HABITS`]), then `clients` when each side has
/// a client sending two or more of its records and no client (user agent,
/// network and header set together) sent records on both.
fn sides_differ(results: &[ObsResult], a: &[usize], b: &[usize]) -> Vec<&'static str> {
    let (ha, hb) = (habits(results, a), habits(results, b));
    let mut v = crate::plant::habits_apart(&ha, &hb);
    let clients = |s: &[usize]| -> BTreeMap<String, usize> {
        let mut n = BTreeMap::new();
        for k in s.iter().filter_map(|&m| client_key(&results[m])) {
            *n.entry(k).or_insert(0) += 1;
        }
        n
    };
    let (ca, cb) = (clients(a), clients(b));
    // A side whose every record is a client of its own (an agent rotating
    // address and user agent on each request) has no client to share:
    // that its clients are not the other side's says nothing.
    let recurs = |c: &BTreeMap<String, usize>| c.values().any(|&n| n >= 2);
    if recurs(&ca) && recurs(&cb) && ca.keys().all(|k| !cb.contains_key(k)) {
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
    // Articulation records whose second piece is large enough, the most
    // even split first (as seams are ranked), pieces built for at most
    // MAX_JOINTS of them and only until MAX_SEAMS are kept: any later one
    // would rank below those.
    let d = g.dfs();
    let mut joints: Vec<(usize, usize)> = g
        .articulations(&d)
        .into_iter()
        .filter(|(v, sizes)| !in_seam[*v] && sizes.get(1).is_some_and(|&s| s >= min_side))
        .map(|(v, sizes)| (v, sizes[1]))
        .collect();
    crate::sort::by(&mut joints, |a, b| {
        b.1.cmp(&a.1).then(members[a.0].cmp(&members[b.0]))
    });
    let mut kept = 0;
    for (v, _) in joints.into_iter().take(MAX_JOINTS) {
        if kept == MAX_SEAMS {
            break;
        }
        if consider(vec![v], false, g.pieces_at(&d, v)) {
            kept += 1;
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
        // An agent rotating its client on every request: no two records
        // share a client, on either side or across, so the sides' clients
        // differing says nothing.
        let results: Vec<ObsResult> = (0..9)
            .map(|i| rec(&format!("agent-{i}/1.0"), 64_500 + i))
            .collect();
        assert!(seams(&results, &members, &refs, 3).is_empty());
        // Every record on one tag: no joint at all.
        let results = two_operators();
        let ties = [tie(&members, "inbox")];
        let refs: Vec<&Tie> = ties.iter().collect();
        assert!(seams(&results, &members, &refs, 3).is_empty());
    }

    #[test]
    fn a_long_chain_is_read_without_building_every_split() {
        // Twenty thousand records chained one to the next: nearly every
        // record is an articulation record. One client's records, then a
        // joint, then another's.
        let n = 20_001;
        let results: Vec<ObsResult> = (0..n)
            .map(|i| match i.cmp(&(n / 2)) {
                std::cmp::Ordering::Less => rec("agent-a/1.0", 64_500),
                std::cmp::Ordering::Equal => rec("agent-c/1.0", 64_502),
                std::cmp::Ordering::Greater => rec("agent-b/1.0", 64_501),
            })
            .collect();
        let members: Vec<usize> = (0..n).collect();
        let ties: Vec<Tie> = (0..n - 1)
            .map(|i| tie(&[i, i + 1], &format!("t{i}")))
            .collect();
        let refs: Vec<&Tie> = ties.iter().collect();
        let s = seams(&results, &members, &refs, 3);
        // The joint, and its neighbours, which also leave one client on
        // each side.
        let joints: Vec<&Vec<usize>> = s.iter().map(|x| &x.joint).collect();
        assert_eq!(joints, [&vec![n / 2], &vec![n / 2 - 1], &vec![n / 2 + 1]]);
        assert_eq!((s[0].sides[0].len(), s[0].sides[1].len()), (n / 2, n / 2));
        assert!(s[0].differs.contains(&"clients"), "{:?}", s[0].differs);
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
        let d = g.dfs();
        let fast: BTreeMap<usize, Vec<Vec<usize>>> = g
            .articulations(&d)
            .into_iter()
            .map(|(v, sizes)| {
                let pieces = g.pieces_at(&d, v);
                assert_eq!(pieces.iter().map(Vec::len).collect::<Vec<_>>(), sizes);
                (v, pieces)
            })
            .collect();
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
