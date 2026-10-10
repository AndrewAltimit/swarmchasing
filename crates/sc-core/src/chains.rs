//! Probe chains: one client trying variant after variant of the same request.
//!
//! An agent working an endpoint tends to send a request, read the response,
//! change a parameter and try again. In public records that shows up as a run
//! of requests to one host and path, close in time, whose parameter values
//! keep changing. The pace hints at what chose each request: scanners fire
//! variants within a second or two, and a model in the loop takes seconds to
//! a minute or two per step. Slower chains can be a person or a model that
//! reasons longer. The pace is a hint, not evidence of who sent the requests.
//!
//! A step that follows an error response (status 400 or above) with a
//! changed request counts as a retry after an error. A scanner working
//! through a list keeps going whatever the response; a model reading the
//! error tends to change course. That too is a hint, not evidence.
//!
//! Chains do not change scores or tiers. The flagged requests in one chain
//! are joined into one cluster, and the chain also shows requests around an
//! attack that no rule flagged.

use crate::analyze::ObsResult;
use crate::timing::TimeBasis;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// Probe chain settings (`[chains]` in the rules file).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct ChainOptions {
    /// Requests further apart than this start a new chain.
    pub max_gap_secs: i64,
    /// A chain needs at least this many distinct variants.
    pub min_variants: usize,
    /// A median gap under this is tool pace.
    pub tool_pace_below_secs: i64,
    /// A median gap from the tool band up to this is model pace; slower is
    /// slow pace.
    pub model_pace_max_secs: i64,
}

impl Default for ChainOptions {
    fn default() -> Self {
        Self {
            max_gap_secs: 300,
            min_variants: 3,
            tool_pace_below_secs: 2,
            model_pace_max_secs: 120,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Pace {
    /// Median gap under `tool_pace_below_secs`: a scanner or script.
    Tool,
    /// Up to `model_pace_max_secs`: consistent with a model choosing each
    /// request.
    Model,
    /// Slower: a person, or a model that reasons longer per step.
    Slow,
}

impl Pace {
    pub fn of(median_gap: i64, opts: &ChainOptions) -> Self {
        match median_gap {
            g if g < opts.tool_pace_below_secs => Self::Tool,
            g if g <= opts.model_pace_max_secs => Self::Model,
            _ => Self::Slow,
        }
    }

    /// The pace as a report reads it, given what the times measure.
    pub fn describe(self, basis: TimeBasis) -> String {
        match basis {
            TimeBasis::Capture | TimeBasis::Mixed => {
                "capture times, not request times: pace not read".into()
            }
            TimeBasis::Submit => format!("{}, from submit times", self.label()),
            TimeBasis::Request | TimeBasis::Unknown => self.label().into(),
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Tool => "tool pace",
            Self::Model => "model pace",
            Self::Slow => "slow pace",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Chain {
    pub host: String,
    pub path: String,
    /// Indices into `Analysis::results`, by time.
    pub members: Vec<usize>,
    /// Parameters whose value changed along the chain.
    pub varied: Vec<String>,
    /// Distinct parameter sets.
    pub variants: usize,
    /// Members that some rule flagged.
    pub flagged: usize,
    pub start: i64,
    pub end: i64,
    pub median_gap_secs: i64,
    /// The pace the median gap falls in. Read it only when `time_basis` is
    /// request-like: from capture times it says nothing about the client.
    pub pace: Pace,
    /// What the members' timestamps measure.
    #[serde(default, skip_serializing_if = "TimeBasis::is_unknown")]
    pub time_basis: TimeBasis,
    /// Steps where the previous request got an error response (status 400
    /// or above) and this one changed the request.
    #[serde(default)]
    pub retries_after_error: usize,
}

type Params = Vec<(String, String)>;

/// Status codes at or above this are error responses.
pub const ERROR_STATUS: u16 = 400;

/// Host, path, parameters and raw text of the layer a record targets.
fn target_of(r: &ObsResult) -> Option<(String, String, Params, String)> {
    let host = r.target_host.as_deref()?;
    let layer = r
        .layers
        .iter()
        .rev()
        .find(|l| l.host.as_deref() == Some(host))?;
    let path = url::Url::parse(&layer.text)
        .map(|u| u.path().to_string())
        .unwrap_or_else(|_| "/".into());
    Some((
        host.to_string(),
        path,
        layer.params.clone(),
        layer.text.clone(),
    ))
}

/// Find probe chains that include at least one flagged record.
pub fn chains(results: &[ObsResult], opts: &ChainOptions) -> Vec<Chain> {
    let mut by_target: BTreeMap<(String, String), Vec<(usize, Params)>> = BTreeMap::new();
    for (i, r) in results.iter().enumerate() {
        if r.obs.ts <= 0 {
            continue;
        }
        if let Some((host, path, params, _)) = target_of(r)
            && !params.is_empty()
        {
            by_target.entry((host, path)).or_default().push((i, params));
        }
    }
    let mut out = Vec::new();
    for ((host, path), mut reqs) in by_target {
        crate::sort::by_key(&mut reqs, |(i, _)| (results[*i].obs.ts, *i));
        let mut seg: Vec<(usize, Params)> = Vec::new();
        let mut flush = |seg: &mut Vec<(usize, Params)>| {
            if let Some(c) = chain_of(results, &host, &path, seg, opts) {
                out.push(c);
            }
            seg.clear();
        };
        for req in reqs {
            if let Some((last, _)) = seg.last()
                && results[req.0].obs.ts - results[*last].obs.ts > opts.max_gap_secs
            {
                flush(&mut seg);
            }
            seg.push(req);
        }
        flush(&mut seg);
    }
    crate::sort::by(&mut out, |a, b| {
        a.start.cmp(&b.start).then(a.host.cmp(&b.host))
    });
    out
}

fn chain_of(
    results: &[ObsResult],
    host: &str,
    path: &str,
    seg: &[(usize, Params)],
    opts: &ChainOptions,
) -> Option<Chain> {
    let flagged = seg.iter().filter(|(i, _)| results[*i].score > 0).count();
    let variants: BTreeSet<Params> = seg.iter().map(|(_, p)| sorted(p)).collect();
    if flagged == 0 || variants.len() < opts.min_variants {
        return None;
    }
    let mut values: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    for (_, params) in seg {
        for (k, v) in params {
            values.entry(k).or_default().insert(v);
        }
    }
    let varied: Vec<String> = values
        .into_iter()
        .filter(|(_, v)| v.len() > 1)
        .map(|(k, _)| k.to_string())
        .collect();
    if varied.is_empty() {
        return None;
    }
    let ts: Vec<i64> = seg.iter().map(|(i, _)| results[*i].obs.ts).collect();
    // Within a chain every step is inside `max_gap_secs`. A change is a new
    // parameter value, or the same values encoded differently.
    let retries_after_error = seg
        .windows(2)
        .filter(|w| {
            let (prev, next) = (&results[w[0].0], &results[w[1].0]);
            prev.obs.status.is_some_and(|s| s >= ERROR_STATUS)
                && (sorted(&w[0].1) != sorted(&w[1].1)
                    || target_of(prev).map(|t| t.3) != target_of(next).map(|t| t.3))
        })
        .count();
    let mut gaps: Vec<i64> = ts.windows(2).map(|w| w[1] - w[0]).collect();
    crate::sort::sort(&mut gaps);
    let median = gaps.get(gaps.len() / 2).copied().unwrap_or(0);
    Some(Chain {
        host: host.to_string(),
        path: path.to_string(),
        members: seg.iter().map(|(i, _)| *i).collect(),
        varied,
        variants: variants.len(),
        flagged,
        start: ts[0],
        end: *ts.last().unwrap_or(&ts[0]),
        median_gap_secs: median,
        pace: Pace::of(median, opts),
        time_basis: TimeBasis::of(seg.iter().map(|(i, _)| results[*i].obs.ts_kind)),
        retries_after_error,
    })
}

fn sorted(p: &Params) -> Params {
    let mut p = p.clone();
    crate::sort::sort(&mut p);
    p
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyze::analyze;
    use crate::model::Observation;
    use crate::rules::Rules;

    fn obs(i: i64, ts: i64, q: &str) -> Observation {
        Observation {
            id: format!("r{i}"),
            ts,
            url: format!("https://portal.example.gov/item{q}"),
            ..Default::default()
        }
    }

    #[test]
    fn finds_the_chain_around_an_attack() {
        let t = 1_791_000_000;
        let a = analyze(
            vec![
                obs(0, t, "?id=1"),
                obs(1, t + 20, "?id=2"),
                obs(2, t + 45, "?id=1'"),
                obs(3, t + 70, "?id=1%20UNION%20SELECT%201"),
                obs(4, t + 90, "?id=1%20UNION%20SELECT%201,2"),
                // Same path, much later: a separate (unflagged) session.
                obs(5, t + 5_000, "?id=3"),
                obs(6, t + 5_010, "?id=4"),
                obs(7, t + 5_020, "?id=5"),
                // Another path with no flagged request.
                obs(8, t + 30, "s?page=1"),
            ],
            &Rules::default_rules(),
        );
        assert_eq!(a.chains.len(), 1, "{:?}", a.chains);
        let c = &a.chains[0];
        assert_eq!(c.members, vec![0, 1, 2, 3, 4]);
        assert_eq!(c.varied, vec!["id".to_string()]);
        assert_eq!(c.variants, 5);
        assert!(c.flagged >= 2 && c.flagged < 5, "{c:?}");
        assert_eq!(c.pace, Pace::Model);
        assert_eq!((c.path.as_str(), c.end - c.start), ("/item", 90));
        // Its flagged requests are one cluster even where the rules differ.
        let clusters: BTreeSet<Option<usize>> = c
            .members
            .iter()
            .filter(|&&m| a.results[m].score > 0)
            .map(|&m| a.results[m].cluster)
            .collect();
        assert_eq!(clusters.len(), 1, "{clusters:?}");
        assert!(clusters.iter().all(Option::is_some));
    }

    #[test]
    fn counts_changes_after_an_error() {
        let t = 1_791_000_000;
        let with = |o: Observation, status| Observation {
            status: Some(status),
            ..o
        };
        let a = analyze(
            vec![
                with(obs(0, t, "?id=1"), 200),
                // Error, then a changed request: counted.
                with(obs(1, t + 20, "?id=1'"), 500),
                with(obs(2, t + 45, "?id=1%20UNION%20SELECT%201"), 400),
                // Error, then the same values encoded differently: counted.
                with(obs(3, t + 70, "?id=1+UNION+SELECT+1"), 403),
                // Error, then the identical request: not a change.
                with(obs(4, t + 90, "?id=1+UNION+SELECT+1"), 200),
                // Success, then a change: not after an error.
                with(obs(5, t + 110, "?id=1%20UNION%20SELECT%201,2"), 200),
            ],
            &Rules::default_rules(),
        );
        assert_eq!(a.chains.len(), 1, "{:?}", a.chains);
        assert_eq!(a.chains[0].retries_after_error, 2, "{:?}", a.chains[0]);
    }

    #[test]
    fn pace() {
        let o = ChainOptions::default();
        assert_eq!(Pace::of(0, &o), Pace::Tool);
        assert_eq!(Pace::of(30, &o), Pace::Model);
        assert_eq!(Pace::of(600, &o), Pace::Slow);
    }
}
