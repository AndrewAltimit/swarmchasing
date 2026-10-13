//! Groups in a weighted graph of clusters, for candidate fleets.
//!
//! Connected components chain: one cluster tied to two fleets joins them.
//! Here the graph is first reduced to its **backbone**, then split into
//! communities by **Leiden** under the **constant Potts model** (CPM).
//!
//! - The backbone keeps an edge when it carries an unusual share of the
//!   weight of at least one endpoint (the disparity filter: under the null,
//!   a node of degree `k` splits its strength uniformly at random over its
//!   edges, and an edge holding share `p` has chance `(1 - p)^(k - 1)`), or
//!   when its endpoints share most of their other neighbours (a clique's
//!   edges are uniform, so the disparity filter alone would drop them). A
//!   node with one edge keeps it. An edge from a hub to a fleet it does not
//!   belong to is neither unusual for the hub nor embedded in the fleet.
//! - CPM scores a partition as the weight inside each community less
//!   `gamma` per pair of its members, so a community holds only nodes whose
//!   ties to it average more than `gamma` per pair. Two fleets joined by a
//!   hub stay apart: merging them adds many pairs and no weight.
//! - Leiden moves nodes greedily, refines each community so that only
//!   well-connected sub-communities are merged (no community comes out
//!   disconnected), aggregates, and repeats. Every choice is taken in a
//!   fixed order with ties to the lowest index, so the result is the same
//!   on every platform.
//!
//! [`min_cut`] gives the weakest cut of a community (Stoer-Wagner): how
//! easily it would fall apart. No I/O.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

/// An undirected edge `(i, j, weight)`, `i != j`, weight above zero.
pub type Edge = (usize, usize, f64);

/// Adjacency lists, each sorted by neighbour, parallel edges summed.
fn adjacency(n: usize, edges: &[Edge]) -> Vec<Vec<(usize, f64)>> {
    let mut m: Vec<BTreeMap<usize, f64>> = vec![BTreeMap::new(); n];
    for &(i, j, w) in edges {
        if i == j || w <= 0.0 || i >= n || j >= n {
            continue;
        }
        *m[i].entry(j).or_default() += w;
        *m[j].entry(i).or_default() += w;
    }
    m.into_iter().map(|x| x.into_iter().collect()).collect()
}

/// The backbone of `edges` over `n` nodes: each edge kept when the
/// disparity filter finds it significant at level `alpha` from either
/// endpoint (a node with one edge always does), or when the Jaccard
/// overlap of its endpoints' other neighbours is at least `overlap`.
pub fn backbone(n: usize, edges: &[Edge], alpha: f64, overlap: f64) -> Vec<Edge> {
    let adj = adjacency(n, edges);
    let strength: Vec<f64> = adj.iter().map(|a| a.iter().map(|x| x.1).sum()).collect();
    let significant = |i: usize, w: f64| {
        let k = adj[i].len();
        if k <= 1 {
            return true;
        }
        let p = w / strength[i];
        (1.0 - p).powi(k as i32 - 1) < alpha
    };
    let others = |i: usize, j: usize| -> BTreeSet<usize> {
        adj[i].iter().map(|x| x.0).filter(|&x| x != j).collect()
    };
    let mut out = Vec::new();
    for (i, a) in adj.iter().enumerate() {
        for &(j, w) in a.iter().filter(|x| x.0 > i) {
            let keep = significant(i, w) || significant(j, w) || {
                let (x, y) = (others(i, j), others(j, i));
                let union = x.union(&y).count();
                union > 0 && x.intersection(&y).count() as f64 / union as f64 >= overlap
            };
            if keep {
                out.push((i, j, w));
            }
        }
    }
    out
}

/// A weighted graph whose nodes may stand for several original nodes.
struct Graph {
    adj: Vec<Vec<(usize, f64)>>,
    /// Original nodes each node stands for.
    size: Vec<f64>,
}

impl Graph {
    fn len(&self) -> usize {
        self.adj.len()
    }
}

/// Community labels for `n` nodes under CPM with resolution `gamma`, by a
/// deterministic Leiden. Labels are dense, numbered by each community's
/// lowest node.
pub fn leiden_cpm(n: usize, edges: &[Edge], gamma: f64) -> Vec<usize> {
    let mut g = Graph {
        adj: adjacency(n, edges),
        size: vec![1.0; n],
    };
    // Original node to node of the current graph.
    let mut node_of: Vec<usize> = (0..n).collect();
    let mut part: Vec<usize> = (0..n).collect();
    for _ in 0..64 {
        move_nodes(&g, &mut part, gamma);
        let communities = dense(&part);
        if communities == g.len() {
            break;
        }
        let refined = refine(&g, &part, gamma);
        let nref = dense_into(&refined).1;
        // The aggregate graph's nodes are the refined communities; each
        // starts in the community of `part` holding it.
        let mut agg: Vec<BTreeMap<usize, f64>> = vec![BTreeMap::new(); nref];
        let mut size = vec![0.0; nref];
        let (rlabel, _) = dense_into(&refined);
        for v in 0..g.len() {
            size[rlabel[v]] += g.size[v];
            for &(u, w) in &g.adj[v] {
                if rlabel[u] != rlabel[v] {
                    *agg[rlabel[v]].entry(rlabel[u]).or_default() += w;
                }
            }
        }
        let (plabel, _) = dense_into(&part);
        let mut next_part = vec![0; nref];
        for v in 0..g.len() {
            next_part[rlabel[v]] = plabel[v];
        }
        for x in node_of.iter_mut() {
            *x = rlabel[*x];
        }
        let shrank = nref < g.len();
        g = Graph {
            adj: agg.into_iter().map(|m| m.into_iter().collect()).collect(),
            size,
        };
        part = next_part;
        if !shrank {
            break;
        }
    }
    let (labels, _) = dense_into(&part);
    let flat: Vec<usize> = node_of.iter().map(|&v| labels[v]).collect();
    dense_into(&flat).0
}

/// Communities in `part`.
fn dense(part: &[usize]) -> usize {
    part.iter().collect::<BTreeSet<_>>().len()
}

/// `part` relabelled 0, 1, ... in order of each label's first node, and
/// the number of labels.
fn dense_into(part: &[usize]) -> (Vec<usize>, usize) {
    let mut map: BTreeMap<usize, usize> = BTreeMap::new();
    let mut out = Vec::with_capacity(part.len());
    for &p in part {
        let next = map.len();
        out.push(*map.entry(p).or_insert(next));
    }
    let n = map.len();
    (out, n)
}

/// Leiden's fast local moving: visit nodes from a queue, move each to the
/// neighbouring community (or an empty one) that most improves CPM, and
/// queue its neighbours outside its new community.
fn move_nodes(g: &Graph, part: &mut [usize], gamma: f64) {
    let n = g.len();
    let mut csize: BTreeMap<usize, f64> = BTreeMap::new();
    for (&p, &s) in part.iter().zip(&g.size) {
        *csize.entry(p).or_default() += s;
    }
    let mut queue: VecDeque<usize> = (0..n).collect();
    let mut queued = vec![true; n];
    // A label no community uses, for moves to an empty community.
    let mut fresh = part.iter().copied().max().map_or(0, |m| m + 1);
    while let Some(v) = queue.pop_front() {
        queued[v] = false;
        let own = part[v];
        let mut ties: BTreeMap<usize, f64> = BTreeMap::new();
        for &(u, w) in &g.adj[v] {
            *ties.entry(part[u]).or_default() += w;
        }
        let sv = g.size[v];
        let own_rest = csize[&own] - sv;
        let stay = ties.get(&own).copied().unwrap_or(0.0) - gamma * sv * own_rest;
        // Leaving for an empty community scores 0.
        let (mut best, mut best_gain) = (own, stay);
        if own_rest > 0.0 && 0.0 > best_gain + 1e-12 {
            best = usize::MAX;
            best_gain = 0.0;
        }
        for (&c, &w) in &ties {
            if c == own {
                continue;
            }
            let gain = w - gamma * sv * csize.get(&c).copied().unwrap_or(0.0);
            if gain > best_gain + 1e-12 {
                best = c;
                best_gain = gain;
            }
        }
        if best == own {
            continue;
        }
        let target = if best == usize::MAX {
            fresh += 1;
            fresh - 1
        } else {
            best
        };
        *csize.get_mut(&own).expect("own community") -= sv;
        *csize.entry(target).or_default() += sv;
        part[v] = target;
        for &(u, _) in &g.adj[v] {
            if !queued[u] && part[u] != target {
                queued[u] = true;
                queue.push_back(u);
            }
        }
    }
}

/// Leiden's refinement: within each community of `part`, start from
/// singletons and merge a node still alone into the sub-community that
/// most improves CPM, when both are well connected to the rest of the
/// community. Returns the refined labels.
fn refine(g: &Graph, part: &[usize], gamma: f64) -> Vec<usize> {
    let n = g.len();
    let mut refined: Vec<usize> = (0..n).collect();
    let mut members: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
    for (v, &p) in part.iter().enumerate() {
        members.entry(p).or_default().push(v);
    }
    for vs in members.values() {
        let total: f64 = vs.iter().map(|&v| g.size[v]).sum();
        // Weight from each node to the rest of its community.
        let to_rest = |v: usize| -> f64 {
            g.adj[v]
                .iter()
                .filter(|x| part[x.0] == part[v])
                .map(|x| x.1)
                .sum()
        };
        let mut rsize: BTreeMap<usize, f64> = vs.iter().map(|&v| (v, g.size[v])).collect();
        // Weight from each sub-community to the rest of the community.
        let mut rext: BTreeMap<usize, f64> = vs.iter().map(|&v| (v, to_rest(v))).collect();
        let mut alone: BTreeSet<usize> = vs.iter().copied().collect();
        for &v in vs {
            if !alone.contains(&v) {
                continue;
            }
            let sv = g.size[v];
            if rext[&v] < gamma * sv * (total - sv) {
                continue;
            }
            let mut ties: BTreeMap<usize, f64> = BTreeMap::new();
            for &(u, w) in &g.adj[v] {
                if part[u] == part[v] && refined[u] != refined[v] {
                    *ties.entry(refined[u]).or_default() += w;
                }
            }
            let mut best: Option<(usize, f64)> = None;
            for (&c, &w) in &ties {
                let sc = rsize[&c];
                if rext[&c] < gamma * sc * (total - sc) {
                    continue;
                }
                let gain = w - gamma * sv * sc;
                if gain >= 0.0 && best.is_none_or(|b| gain > b.1 + 1e-12) {
                    best = Some((c, gain));
                }
            }
            if let Some((c, w_vc)) = best.map(|(c, _)| (c, ties[&c])) {
                refined[v] = c;
                alone.remove(&v);
                alone.remove(&c);
                let sc = rsize[&c];
                rsize.insert(c, sc + sv);
                // Edges between v and c become internal.
                let ext = rext[&c] + rext[&v] - 2.0 * w_vc;
                rext.insert(c, ext);
            }
        }
    }
    refined
}

/// The weakest cut of the graph on `nodes` (Stoer-Wagner): its weight and
/// the smaller side. `None` for fewer than two nodes. The graph need not
/// be connected; a disconnected one has a cut of weight 0.
pub fn min_cut(nodes: &[usize], edges: &[Edge]) -> Option<(f64, Vec<usize>)> {
    let n = nodes.len();
    if n < 2 {
        return None;
    }
    let pos: BTreeMap<usize, usize> = nodes.iter().enumerate().map(|(i, &v)| (v, i)).collect();
    let mut w = vec![vec![0.0f64; n]; n];
    for &(a, b, x) in edges {
        if let (Some(&i), Some(&j)) = (pos.get(&a), pos.get(&b))
            && i != j
        {
            w[i][j] += x;
            w[j][i] += x;
        }
    }
    // Each super-node's original members.
    let mut groups: Vec<Vec<usize>> = (0..n).map(|i| vec![i]).collect();
    let mut active: Vec<usize> = (0..n).collect();
    let mut best: Option<(f64, Vec<usize>)> = None;
    while active.len() > 1 {
        let mut added = vec![false; n];
        let mut key = vec![0.0f64; n];
        let (mut prev, mut last) = (active[0], active[0]);
        for step in 0..active.len() {
            let next = active
                .iter()
                .copied()
                .filter(|&v| !added[v])
                .fold(None::<usize>, |m, v| match m {
                    Some(b) if key[b] >= key[v] => Some(b),
                    _ => Some(v),
                })
                .expect("a node left");
            added[next] = true;
            if step + 1 == active.len() {
                prev = last;
                last = next;
            } else {
                last = next;
            }
            for &v in &active {
                if !added[v] {
                    key[v] += w[next][v];
                }
            }
        }
        let cut = key[last];
        let side = groups[last].clone();
        if best.as_ref().is_none_or(|b| cut < b.0 - 1e-12) {
            best = Some((cut, side));
        }
        // Merge `last` into `prev`.
        let moved = std::mem::take(&mut groups[last]);
        groups[prev].extend(moved);
        let row = w[last].clone();
        for (v, x) in row.into_iter().enumerate() {
            w[prev][v] += x;
            w[v][prev] = w[prev][v];
        }
        w[prev][prev] = 0.0;
        active.retain(|&v| v != last);
    }
    best.map(|(cut, side)| {
        let mut side: Vec<usize> = side.into_iter().map(|i| nodes[i]).collect();
        side.sort_unstable();
        if side.len() * 2 > n {
            let s: BTreeSet<usize> = side.into_iter().collect();
            side = nodes.iter().copied().filter(|v| !s.contains(v)).collect();
            side.sort_unstable();
        }
        (cut, side)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn clique(nodes: &[usize], w: f64) -> Vec<Edge> {
        let mut out = Vec::new();
        for (i, &a) in nodes.iter().enumerate() {
            for &b in &nodes[i + 1..] {
                out.push((a, b, w));
            }
        }
        out
    }

    #[test]
    fn two_cliques_joined_by_a_hub_stay_apart() {
        // Fleets {0,1,2} and {3,4,5}; hub 6 tied to every member of both.
        let mut e = clique(&[0, 1, 2], 3.0);
        e.extend(clique(&[3, 4, 5], 3.0));
        for v in 0..6 {
            e.push((6, v, 3.0));
        }
        let labels = leiden_cpm(7, &e, 1.5);
        assert_eq!(labels[0], labels[1]);
        assert_eq!(labels[1], labels[2]);
        assert_eq!(labels[3], labels[4]);
        assert_eq!(labels[4], labels[5]);
        assert_ne!(labels[0], labels[3], "{labels:?}");
        // The backbone drops the hub's edges: they are neither unusual for
        // the hub nor embedded in either fleet.
        let b = backbone(7, &e, 0.05, 0.5);
        assert!(b.iter().all(|&(i, j, _)| i != 6 && j != 6), "{b:?}");
        assert_eq!(b.len(), 6);
        let labels = leiden_cpm(7, &b, 1.5);
        assert_ne!(labels[6], labels[0]);
        assert_ne!(labels[6], labels[3]);
    }

    #[test]
    fn a_chain_is_cut_where_pairs_are_sparse() {
        // 0-1-2-3-4 in a line: half the pairs of any three are unlinked.
        let e: Vec<Edge> = (0..4).map(|i| (i, i + 1, 2.0)).collect();
        let labels = leiden_cpm(5, &e, 1.5);
        let groups: BTreeSet<usize> = labels.iter().copied().collect();
        assert!(groups.len() >= 2, "{labels:?}");
        // At a low resolution the line is one community.
        let labels = leiden_cpm(5, &e, 0.1);
        assert!(labels.iter().all(|&l| l == labels[0]), "{labels:?}");
    }

    #[test]
    fn leiden_is_deterministic_and_dense() {
        let mut e = clique(&[0, 1, 2, 3], 2.0);
        e.extend(clique(&[5, 6, 7], 2.0));
        e.push((3, 5, 0.5));
        let a = leiden_cpm(9, &e, 1.0);
        assert_eq!(a, leiden_cpm(9, &e, 1.0));
        assert_eq!(a[0], 0);
        assert_eq!(&a[..4], &[0, 0, 0, 0]);
        assert_eq!(a[4], 1, "an isolated node is its own community");
        assert_eq!(a[5], a[7]);
        assert_ne!(a[5], a[0]);
    }

    #[test]
    fn a_clique_survives_the_backbone() {
        let e = clique(&[0, 1, 2, 3, 4, 5], 2.0);
        assert_eq!(backbone(6, &e, 0.05, 0.5).len(), e.len());
        // A lone pair keeps its edge.
        assert_eq!(backbone(2, &[(0, 1, 1.0)], 0.05, 0.5).len(), 1);
    }

    #[test]
    fn min_cut_finds_the_bridge() {
        let mut e = clique(&[0, 1, 2], 3.0);
        e.extend(clique(&[3, 4, 5], 3.0));
        e.push((2, 3, 1.0));
        let (cut, side) = min_cut(&[0, 1, 2, 3, 4, 5], &e).unwrap();
        assert!((cut - 1.0).abs() < 1e-9, "{cut}");
        assert_eq!(side.len(), 3);
        let (cut, side) = min_cut(&[0, 1], &[(0, 1, 2.5)]).unwrap();
        assert!((cut - 2.5).abs() < 1e-9);
        assert_eq!(side.len(), 1);
        assert!(min_cut(&[4], &[]).is_none());
        // Disconnected: a cut of nothing.
        assert_eq!(min_cut(&[0, 1, 2], &[(0, 1, 1.0)]).unwrap().0, 0.0);
    }
}
