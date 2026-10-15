//! Dispatch trees: S6 stars chained where a follower leads a star of its
//! own.
//!
//! A planner that dispatches workers which dispatch workers of their own
//! leaves one star per dispatcher. Each kept dispatch star edge is an arrow
//! from leader to follower between clusters. An arrow `a → c` is dropped
//! when `a → b → c` also holds (a follower of a follower trails the root
//! too), so each cluster keeps its nearest leader; what is left, from each
//! cluster that follows none, is a tree. This is a description in the
//! terms of a Hawkes branching process (who set off whom, and how many
//! generations deep), not a fitted multivariate Hawkes model: no rates or
//! kernels are estimated, and the stars' own chances are the evidence.

use super::{SwarmEdge, SwarmEdgeKind};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write;

/// Chained dispatch stars, by cluster.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DispatchTree {
    /// The cluster that follows none in the tree.
    pub root: String,
    /// Clusters by generation, the root alone in the first.
    pub generations: Vec<Vec<String>>,
    /// Each other cluster and its nearest leader.
    pub parents: Vec<(String, String)>,
    /// Generations below the root: 2 or more for a tree.
    pub depth: usize,
    /// Share of the tree's clusters set off by another of them,
    /// `(size - 1) / size`: a Hawkes branching ratio read off one cascade.
    pub branching: f64,
}

impl DispatchTree {
    pub fn detail(&self) -> String {
        let gens: Vec<String> = self.generations.iter().map(|g| g.join(", ")).collect();
        format!(
            "{} generations below {} ({}), branching ratio {:.2}: {}",
            self.depth,
            self.root,
            self.generations.iter().map(Vec::len).sum::<usize>(),
            self.branching,
            gens.join(" → ")
        )
    }
}

/// Trees of two or more generations from the kept S6 edges.
pub(crate) fn dispatch_trees(edges: &[SwarmEdge]) -> Vec<DispatchTree> {
    let mut kids: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    for e in edges
        .iter()
        .filter(|e| e.kind == SwarmEdgeKind::DispatchStar)
    {
        if e.a.cluster != e.b.cluster {
            kids.entry(&e.a.cluster).or_default().insert(&e.b.cluster);
        }
    }
    // Transitive reduction: `a → c` goes when some child `b` of `a` leads
    // `c`.
    let mut direct: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    for (&a, cs) in &kids {
        let keep: BTreeSet<&str> = cs
            .iter()
            .copied()
            .filter(|c| {
                !cs.iter()
                    .any(|b| b != c && kids.get(b).is_some_and(|g| g.contains(c)))
            })
            .collect();
        direct.insert(a, keep);
    }
    // A cluster with two nearest leaders keeps the first by id.
    let mut parent: BTreeMap<&str, &str> = BTreeMap::new();
    for (&a, cs) in &direct {
        for &c in cs {
            parent.entry(c).or_insert(a);
        }
    }
    let mut out = Vec::new();
    for &root in direct.keys() {
        if parent.contains_key(root) {
            continue;
        }
        let mut generations = vec![vec![root.to_string()]];
        let mut parents = Vec::new();
        let mut seen: BTreeSet<&str> = BTreeSet::from([root]);
        let mut level = vec![root];
        loop {
            let mut next = Vec::new();
            for &a in &level {
                for &c in direct.get(a).into_iter().flatten() {
                    if parent.get(c) == Some(&a) && seen.insert(c) {
                        parents.push((c.to_string(), a.to_string()));
                        next.push(c);
                    }
                }
            }
            if next.is_empty() {
                break;
            }
            generations.push(next.iter().map(|s| s.to_string()).collect());
            level = next;
        }
        let depth = generations.len() - 1;
        if depth < 2 {
            continue;
        }
        let size = seen.len() as f64;
        out.push(DispatchTree {
            root: root.to_string(),
            generations,
            parents,
            depth,
            branching: (size - 1.0) / size,
        });
    }
    out
}

/// The "Dispatch trees" block of an internal report: trees whose clusters
/// `shown` allows, or nothing.
pub(crate) fn report_block(s: &mut String, trees: &[DispatchTree], shown: &dyn Fn(&str) -> bool) {
    let trees: Vec<&DispatchTree> = trees
        .iter()
        .filter(|t| t.generations.iter().flatten().any(|c| shown(c)))
        .collect();
    if trees.is_empty() {
        return;
    }
    let _ = writeln!(
        s,
        "\n## Dispatch trees\n\nDispatch stars (SC-T9) chained where a follower leads a star of its own: who set off whom, over two generations or more. A description of the cascade, not a fitted model; the stars' own chances are the evidence, and nothing here is scored or merges.\n"
    );
    for t in trees.iter().take(8) {
        let _ = writeln!(s, "- {}", t.detail());
    }
    if trees.len() > 8 {
        let _ = writeln!(s, "- … and {} more", trees.len() - 8);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::swarm::{EdgeStrength, RunRef};

    fn e(a: &str, b: &str) -> SwarmEdge {
        let side = |c: &str| RunRef {
            cluster: c.into(),
            key: format!("k-{c}"),
            run: 1,
            strand: None,
            records: Vec::new(),
        };
        SwarmEdge {
            kind: SwarmEdgeKind::DispatchStar,
            a: side(a),
            b: side(b),
            strength: EdgeStrength::Weak,
            chance: Some(0.001),
            tested: 1,
            detail: String::new(),
        }
    }

    #[test]
    fn stars_chain_into_a_tree_keeping_the_nearest_leader() {
        // The root leads both workers and, through them, their workers.
        let edges = [
            e("C1", "C2"),
            e("C1", "C3"),
            e("C1", "C4"),
            e("C1", "C5"),
            e("C2", "C4"),
            e("C3", "C5"),
        ];
        let t = dispatch_trees(&edges);
        assert_eq!(t.len(), 1, "{t:?}");
        assert_eq!(t[0].root, "C1");
        assert_eq!(t[0].depth, 2);
        assert_eq!(t[0].generations[1], ["C2", "C3"]);
        assert_eq!(t[0].generations[2], ["C4", "C5"]);
        assert!((t[0].branching - 0.8).abs() < 1e-12);
        assert!(t[0].detail().contains("2 generations below C1"));
        // One star alone is no tree.
        assert!(dispatch_trees(&edges[..2]).is_empty());
    }
}
