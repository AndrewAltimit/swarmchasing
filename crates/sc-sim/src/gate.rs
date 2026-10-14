//! Floors and ceilings on a bench's measurement, for the CI gate.
//!
//! Precision floors read the measurement summed over every scenario:
//! interaction edges of any kind, soft links of any kind, and candidate
//! fleets, each also between distinct runs only. Grade ceilings read the
//! same sum: benign and tool records in clusters graded L2 or above, and
//! people's records at L3 or above. Ceilings on false pairs read the null
//! scenarios ([`Scenario::null`]), where no two runs are related and every
//! pair drawn between different runs is false. Expectations read each
//! scenario's own measurement against what its `expect` table says it is
//! built to produce ([`Scenario::expect`]), so a kind that stops firing
//! fails even when the pooled numbers hold. A bound on a kind that drew
//! nothing fails: nothing drawn is no evidence of precision.

use crate::measure::{KindStat, Measurement};
use crate::scenario::{GRADE_KEYS, Scenario, ScenarioFile, expect_key};
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
    /// Soft links between distinct runs only.
    pub min_link_cross_run_precision: Option<f64>,
    /// Candidate-fleet pairs between distinct runs only.
    pub min_fleet_cross_run_precision: Option<f64>,
    pub max_null_edges: Option<usize>,
    pub max_null_links: Option<usize>,
    pub max_null_fleet_pairs: Option<usize>,
    /// Benign or tool records in clusters graded L2 or above.
    pub max_benign_high: Option<usize>,
    /// People's records in clusters graded L3 or above.
    pub max_human_high: Option<usize>,
    /// Hold each scenario's `expect` table.
    pub expect: bool,
}

/// One bound checked.
#[derive(Debug, Clone, PartialEq)]
pub struct Check {
    pub name: String,
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

/// `k` of `n` against a floor; nothing to count fails.
fn floor(name: String, k: usize, n: usize, floor: f64, nothing: &str) -> Check {
    if n == 0 {
        return Check {
            name,
            value: nothing.to_string(),
            bound: format!(">= {:.1}%", floor * 100.0),
            ok: false,
        };
    }
    let value = k as f64 / n as f64;
    Check {
        name,
        value: format!("{:.1}% ({k}/{n})", value * 100.0),
        bound: format!(">= {:.1}%", floor * 100.0),
        ok: value + 1e-12 >= floor,
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
        let any = all.links.get("any");
        let fleet = all.links.get("candidate_fleet");
        let plain = |s: Option<&KindStat>| s.map_or((0, 0), |s| (s.correct, s.pairs));
        let cross =
            |s: Option<&KindStat>| s.map_or((0, 0), |s| (s.cross_correct, s.pairs - s.same_run));
        let floors = [
            (
                "edge precision",
                self.min_edge_precision,
                plain(all.edges.get("any")),
            ),
            ("soft-link precision", self.min_link_precision, plain(any)),
            (
                "candidate-fleet precision",
                self.min_fleet_precision,
                plain(fleet),
            ),
            (
                "soft-link precision between distinct runs",
                self.min_link_cross_run_precision,
                cross(any),
            ),
            (
                "candidate-fleet precision between distinct runs",
                self.min_fleet_cross_run_precision,
                cross(fleet),
            ),
        ];
        for (name, bound, (k, n)) in floors {
            let Some(bound) = bound else { continue };
            out.push(floor(name.into(), k, n, bound, "nothing drawn"));
        }
        let ceilings = [
            (
                "null-scenario false edges",
                self.max_null_edges,
                null.edges,
                format!(" over {} seed(s)", null.seeds),
            ),
            (
                "null-scenario false soft links",
                self.max_null_links,
                null.links,
                format!(" over {} seed(s)", null.seeds),
            ),
            (
                "null-scenario false candidate-fleet pairs",
                self.max_null_fleet_pairs,
                null.fleet_pairs,
                format!(" over {} seed(s)", null.seeds),
            ),
            (
                "benign or tool records graded L2 or above",
                self.max_benign_high,
                all.benign_high,
                String::new(),
            ),
            (
                "people's records graded L3 or above",
                self.max_human_high,
                all.human_high,
                String::new(),
            ),
        ];
        for (name, ceiling, value, unit) in ceilings {
            let Some(ceiling) = ceiling else { continue };
            out.push(Check {
                name: name.into(),
                value: format!("{value}{unit}"),
                bound: format!("<= {ceiling}"),
                ok: value <= ceiling,
            });
        }
        out
    }

    /// Each scenario's expectations against its own measurement, when
    /// [`Gate::expect`] is set.
    pub fn check_scenarios(
        &self,
        results: &[(String, Measurement)],
        file: &ScenarioFile,
    ) -> Vec<Check> {
        let mut out = Vec::new();
        if !self.expect {
            return out;
        }
        for s in &file.scenario {
            let m = results.iter().find(|r| r.0 == s.name).map(|r| &r.1);
            for (kind, e) in &s.expect {
                let name = |what: &str| format!("{} {kind} {what}", s.name);
                if GRADE_KEYS.contains(&kind.as_str()) {
                    let value = m.map_or(0, |m| match kind.as_str() {
                        "human_high" => m.human_high,
                        _ => m.benign_high,
                    });
                    let most = e.max_records.unwrap_or(0);
                    out.push(Check {
                        name: name("records"),
                        value: value.to_string(),
                        bound: format!("<= {most}"),
                        ok: value <= most,
                    });
                    continue;
                }
                let stat = m.and_then(|m| {
                    let (key, edge) = expect_key(kind)?;
                    if edge {
                        m.edges.get(&key)
                    } else {
                        m.links.get(&key)
                    }
                });
                if let Some(most) = e.max_pairs {
                    let drawn = stat.map_or(0, |st| st.pairs);
                    out.push(Check {
                        name: name("pairs drawn"),
                        value: drawn.to_string(),
                        bound: format!("<= {most}"),
                        ok: drawn <= most,
                    });
                }
                let Some(st) = stat.filter(|st| st.pairs > 0) else {
                    if e.max_pairs.is_some() {
                        continue;
                    }
                    out.push(Check {
                        name: name("drawn"),
                        value: "nothing drawn".into(),
                        bound: "> 0 pairs".into(),
                        ok: false,
                    });
                    continue;
                };
                if let Some(b) = e.min_precision {
                    out.push(floor(name("precision"), st.correct, st.pairs, b, "-"));
                }
                if let Some(b) = e.min_recall {
                    out.push(floor(
                        name("recall"),
                        st.found,
                        st.of,
                        b,
                        "no reachable true pair",
                    ));
                }
                if let Some(b) = e.min_rejoined {
                    let split = m.map_or(0, |m| m.split_pairs);
                    out.push(floor(
                        name("split runs rejoined"),
                        st.rejoined,
                        split,
                        b,
                        "no split run",
                    ));
                }
            }
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
            cross_correct: correct,
            unrelated: pairs - correct,
            ..Default::default()
        }
    }

    #[test]
    fn floors_and_ceilings_are_checked() {
        let mut all = Measurement::default();
        all.edges.insert("any".into(), stat(10, 9));
        all.links.insert(
            "any".into(),
            KindStat {
                same_run: 2,
                cross_correct: 1,
                ..stat(10, 3)
            },
        );
        all.links.insert("candidate_fleet".into(), stat(0, 0));
        all.benign_high = 4;
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
            min_link_cross_run_precision: Some(0.2),
            max_null_edges: Some(0),
            max_null_links: Some(5),
            max_benign_high: Some(4),
            max_human_high: Some(0),
            ..Default::default()
        };
        let c = g.check(&all, &null);
        let ok: Vec<(&str, bool)> = c.iter().map(|c| (c.name.as_str(), c.ok)).collect();
        assert_eq!(
            ok,
            [
                ("edge precision", true),
                ("soft-link precision", true),
                // Nothing drawn is no evidence of precision.
                ("candidate-fleet precision", false),
                // Same-run pairs leave both counts: 1 of 8.
                ("soft-link precision between distinct runs", false),
                ("null-scenario false edges", false),
                ("null-scenario false soft links", true),
                ("benign or tool records graded L2 or above", true),
                ("people's records graded L3 or above", true),
            ]
        );
        assert!(
            c[3].line()
                .starts_with("FAIL soft-link precision between distinct runs: 12.5% (1/8)")
        );
        assert!(Gate::default().is_empty() && Gate::default().check(&all, &null).is_empty());
    }

    #[test]
    fn expected_kinds_must_draw_and_meet_their_bounds() {
        let file = ScenarioFile::parse(
            "[[scenario]]\nname = \"s\"\nexpect.S3 = { min_recall = 0.5 }\n\
             expect.co_target = { min_precision = 0.9 }\n\
             expect.escalation = { min_rejoined = 0.5 }\n\
             [[scenario.actor]]\nkind = \"agent\"\n",
        )
        .unwrap();
        let mut m = Measurement::default();
        m.edges.insert(
            "synchronized_start".into(),
            KindStat {
                found: 3,
                of: 4,
                ..stat(3, 3)
            },
        );
        m.links.insert("co_target".into(), stat(10, 8));
        m.split_pairs = 4;
        let results = vec![("s".to_string(), m.clone())];
        let g = Gate {
            expect: true,
            ..Default::default()
        };
        let lines: Vec<String> = g
            .check_scenarios(&results, &file)
            .iter()
            .map(Check::line)
            .collect();
        assert_eq!(lines.len(), 3, "{lines:?}");
        assert!(lines[0].starts_with("ok   s S3 recall: 75.0%"), "{lines:?}");
        assert!(
            lines[1].starts_with("FAIL s co_target precision"),
            "{lines:?}"
        );
        assert!(lines[2].starts_with("FAIL s escalation drawn"), "{lines:?}");
        // A kind switched off: S3 draws nothing, and the scenario fails.
        let mut off = m;
        off.edges
            .insert("synchronized_start".into(), KindStat::default());
        let c = g.check_scenarios(&[("s".to_string(), off)], &file);
        assert!(!c[0].ok && c[0].line().contains("nothing drawn"));
        // Not held unless asked for.
        assert!(Gate::default().check_scenarios(&results, &file).is_empty());
        // A kind built not to fire: drawing nothing passes, drawing fails.
        let none = ScenarioFile::parse(
            "[[scenario]]\nname = \"s\"\nexpect.S3 = { max_pairs = 0 }\n\
             [[scenario.actor]]\nkind = \"agent\"\n",
        )
        .unwrap();
        let mut quiet = Measurement::default();
        quiet
            .edges
            .insert("synchronized_start".into(), KindStat::default());
        let c = g.check_scenarios(&[("s".to_string(), quiet)], &none);
        assert_eq!(c.len(), 1);
        assert!(c[0].ok, "{}", c[0].line());
        let c = g.check_scenarios(&results, &none);
        assert!(
            !c[0].ok && c[0].line().contains("pairs drawn"),
            "{}",
            c[0].line()
        );
        // An expectation names a kind the measurement keys.
        assert!(
            ScenarioFile::parse(
                "[[scenario]]\nname = \"s\"\nexpect.S9 = {}\n[[scenario.actor]]\nkind = \"agent\"\n"
            )
            .is_err()
        );
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
