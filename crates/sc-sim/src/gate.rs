//! Floors and ceilings on a bench's measurement, for the CI gate.
//!
//! Precision floors read the measurement summed over every scenario:
//! interaction edges of any kind, soft links of any kind, and candidate
//! fleets. Ceilings read the null scenarios ([`Scenario::null`]), where no
//! two runs are related and every pair drawn between different runs is
//! false.

use crate::measure::{KindStat, Measurement};
use crate::scenario::{Scenario, ScenarioFile};
use serde::{Deserialize, Serialize};

/// What the null scenarios drew between different runs, summed over their
/// seeds: every pair is false.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct NullCounts {
    pub scenarios: usize,
    pub seeds: usize,
    pub edges: usize,
    pub links: usize,
    pub fleet_pairs: usize,
}

/// Pairs drawn between different runs that are not one swarm's (edges) or
/// one operator's (soft links, candidate fleets).
fn false_pairs(s: Option<&KindStat>) -> usize {
    s.map_or(0, |s| s.unrelated + s.same_operator)
}

/// The null scenarios' false pairs, from a bench's per-scenario results.
pub fn null_counts(results: &[(String, Measurement)], file: &ScenarioFile) -> NullCounts {
    let mut out = NullCounts::default();
    for (name, m) in results {
        let Some(s) = file
            .scenario
            .iter()
            .find(|s: &&Scenario| &s.name == name && s.null)
        else {
            continue;
        };
        out.scenarios += 1;
        out.seeds += s.seeds.max(1);
        out.edges += false_pairs(m.edges.get("any"));
        out.links += false_pairs(m.links.get("any"));
        out.fleet_pairs += false_pairs(m.links.get("candidate_fleet"));
    }
    out
}

/// The floors and ceilings to hold; each unset one is not checked.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Gate {
    pub min_edge_precision: Option<f64>,
    pub min_link_precision: Option<f64>,
    pub min_fleet_precision: Option<f64>,
    pub max_null_edges: Option<usize>,
    pub max_null_links: Option<usize>,
    pub max_null_fleet_pairs: Option<usize>,
}

/// One bound checked.
#[derive(Debug, Clone, PartialEq)]
pub struct Check {
    pub name: &'static str,
    pub value: String,
    pub bound: String,
    pub ok: bool,
}

impl Check {
    pub fn line(&self) -> String {
        format!(
            "{} {}: {} (bound {})",
            if self.ok { "ok  " } else { "FAIL" },
            self.name,
            self.value,
            self.bound
        )
    }
}

impl Gate {
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }

    /// Every set bound against `all` (summed over the scenarios) and the
    /// null scenarios' counts.
    pub fn check(&self, all: &Measurement, null: &NullCounts) -> Vec<Check> {
        let mut out = Vec::new();
        let floors = [
            (
                "edge precision",
                self.min_edge_precision,
                all.edges.get("any"),
            ),
            (
                "soft-link precision",
                self.min_link_precision,
                all.links.get("any"),
            ),
            (
                "candidate-fleet precision",
                self.min_fleet_precision,
                all.links.get("candidate_fleet"),
            ),
        ];
        for (name, floor, stat) in floors {
            let Some(floor) = floor else { continue };
            let (k, n) = stat.map_or((0, 0), |s| (s.correct, s.pairs));
            // Nothing drawn is no evidence of precision either way.
            let value = if n == 0 { 1.0 } else { k as f64 / n as f64 };
            out.push(Check {
                name,
                value: format!("{:.1}% ({k}/{n})", value * 100.0),
                bound: format!(">= {:.1}%", floor * 100.0),
                ok: value + 1e-12 >= floor,
            });
        }
        let ceilings = [
            ("null-scenario false edges", self.max_null_edges, null.edges),
            (
                "null-scenario false soft links",
                self.max_null_links,
                null.links,
            ),
            (
                "null-scenario false candidate-fleet pairs",
                self.max_null_fleet_pairs,
                null.fleet_pairs,
            ),
        ];
        for (name, ceiling, value) in ceilings {
            let Some(ceiling) = ceiling else { continue };
            out.push(Check {
                name,
                value: format!("{value} over {} seed(s)", null.seeds),
                bound: format!("<= {ceiling}"),
                ok: value <= ceiling,
            });
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stat(pairs: usize, correct: usize) -> KindStat {
        KindStat {
            pairs,
            correct,
            unrelated: pairs - correct,
            ..Default::default()
        }
    }

    #[test]
    fn floors_and_ceilings_are_checked() {
        let mut all = Measurement::default();
        all.edges.insert("any".into(), stat(10, 9));
        all.links.insert("any".into(), stat(10, 1));
        all.links.insert("candidate_fleet".into(), stat(0, 0));
        let null = NullCounts {
            scenarios: 1,
            seeds: 2,
            edges: 1,
            links: 5,
            fleet_pairs: 0,
        };
        let g = Gate {
            min_edge_precision: Some(0.9),
            min_link_precision: Some(0.2),
            min_fleet_precision: Some(0.5),
            max_null_edges: Some(0),
            max_null_links: Some(5),
            max_null_fleet_pairs: None,
        };
        let c = g.check(&all, &null);
        let ok: Vec<(&str, bool)> = c.iter().map(|c| (c.name, c.ok)).collect();
        assert_eq!(
            ok,
            [
                ("edge precision", true),
                ("soft-link precision", false),
                ("candidate-fleet precision", true),
                ("null-scenario false edges", false),
                ("null-scenario false soft links", true),
            ]
        );
        assert!(
            c[1].line()
                .starts_with("FAIL soft-link precision: 10.0% (1/10)")
        );
        assert!(Gate::default().is_empty() && Gate::default().check(&all, &null).is_empty());
    }

    #[test]
    fn null_counts_read_only_null_scenarios() {
        let file = ScenarioFile::parse(
            "[[scenario]]\nname = \"n\"\nnull = true\nseeds = 3\n[[scenario.actor]]\nkind = \"agent\"\n\
             [[scenario]]\nname = \"s\"\n[[scenario.actor]]\nkind = \"agent\"\n",
        )
        .unwrap();
        let mut m = Measurement::default();
        m.edges.insert("any".into(), stat(4, 1));
        m.links.insert("candidate_fleet".into(), stat(2, 0));
        let r = vec![("n".to_string(), m.clone()), ("s".to_string(), m)];
        let n = null_counts(&r, &file);
        assert_eq!(
            (n.scenarios, n.seeds, n.edges, n.links, n.fleet_pairs),
            (1, 3, 3, 0, 2)
        );
        // A null scenario relates no runs.
        assert!(
            ScenarioFile::parse(
                "[[scenario]]\nname = \"n\"\nnull = true\n[[scenario.actor]]\nkind = \"fleet\"\n"
            )
            .is_err()
        );
    }
}
