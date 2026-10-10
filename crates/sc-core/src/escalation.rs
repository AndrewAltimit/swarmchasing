//! Escalation sequences: one client changing route to the same target.
//!
//! An agent that cannot read a page directly tends to try harder: a direct
//! request, then the same page through a relay (Jina Reader, allorigins,
//! a translate proxy), then a program carried to an echo service or a
//! `data:` URL, then a remote browser such as a code playground. In public
//! records that shows up as requests for one host and path, minutes apart,
//! whose route climbs. [`escalations`] finds those climbs.
//!
//! Nothing says the steps came from one client: two people reading the same
//! page by different routes look the same. An escalation is a hint on the
//! clusters it touches, and a link to check between them, never a merge.

use crate::analyze::{ObsResult, target_text};
use crate::rules::RuleDef;
use crate::timing::{TimeBasis, request_like};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// How a request reached its target, from plainest to most elaborate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Route {
    /// The target requested as itself.
    Direct,
    /// Through a fetch-through or conversion relay.
    Relay,
    /// A program carried to an echo service, or in a `data:` URL.
    Program,
    /// A remote browser or code playground running a program.
    RemoteBrowser,
}

impl Route {
    pub fn label(self) -> &'static str {
        match self {
            Route::Direct => "direct",
            Route::Relay => "relay",
            Route::Program => "program carrier",
            Route::RemoteBrowser => "remote browser",
        }
    }
}

/// Escalation settings (`[escalation]` in the rules file). The route lists
/// name rules by id; `prefix.*` names every rule whose id starts `prefix.`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct EscalationOptions {
    /// Requests for one target further apart than this start a new sequence.
    pub window_secs: i64,
    pub relay: Vec<String>,
    pub program: Vec<String>,
    pub remote_browser: Vec<String>,
}

impl Default for EscalationOptions {
    fn default() -> Self {
        let own = |v: &[&str]| v.iter().map(|s| s.to_string()).collect();
        Self {
            window_secs: 1800,
            relay: own(&["relay.*"]),
            program: own(&[
                "carrier.httpbin",
                "carrier.data_url_script",
                "carrier.inline_fetch_program",
                "carrier.form_post_program",
                "carrier.html_program",
            ]),
            remote_browser: own(&["carrier.livecodes", "carrier.codesandbox"]),
        }
    }
}

impl EscalationOptions {
    /// The route a rule's hit shows, if any.
    pub fn route_of(&self, rule_id: &str) -> Option<Route> {
        let named = |list: &[String]| {
            list.iter().any(|p| match p.strip_suffix('*') {
                Some(prefix) => rule_id.starts_with(prefix),
                None => p == rule_id,
            })
        };
        if named(&self.remote_browser) {
            Some(Route::RemoteBrowser)
        } else if named(&self.program) {
            Some(Route::Program)
        } else if named(&self.relay) {
            Some(Route::Relay)
        } else {
            None
        }
    }

    /// Route list entries that name no rule in `rules`.
    pub fn unknown_entries<'a>(&'a self, rules: &[RuleDef]) -> Vec<&'a str> {
        [&self.relay, &self.program, &self.remote_browser]
            .into_iter()
            .flatten()
            .filter(|p| {
                !rules.iter().any(|r| match p.strip_suffix('*') {
                    Some(prefix) => r.id.starts_with(prefix),
                    None => **p == r.id,
                })
            })
            .map(String::as_str)
            .collect()
    }
}

/// One step of an escalation: the first request at a new route.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EscalationStep {
    pub route: Route,
    /// Index into `Analysis::results`.
    pub record: usize,
    pub ts: i64,
}

/// Requests for one target whose route climbed within the window.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Escalation {
    pub host: String,
    /// Normalised path ([`crate::paths::normalize_path`]).
    pub path: String,
    /// At least two, routes strictly ascending, in time order.
    pub steps: Vec<EscalationStep>,
    pub start: i64,
    pub end: i64,
    /// Ids of the clusters the steps' records belong to.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub clusters: Vec<String>,
    #[serde(default, skip_serializing_if = "TimeBasis::is_unknown")]
    pub time_basis: TimeBasis,
}

impl Escalation {
    /// `direct → relay → program carrier`.
    pub fn route_line(&self) -> String {
        self.steps
            .iter()
            .map(|s| s.route.label())
            .collect::<Vec<_>>()
            .join(" → ")
    }
}

/// The route of one record: the most elaborate its hits show, or direct when
/// the submitted URL is the target itself. `None` when neither holds.
fn route(r: &ObsResult, opts: &EscalationOptions) -> Option<Route> {
    let host = r.target_host.as_deref()?;
    r.hits
        .iter()
        .filter_map(|h| opts.route_of(&h.rule_id))
        .max()
        .or_else(|| {
            r.layers
                .first()
                .and_then(|l| l.host.as_deref())
                .is_some_and(|h| h.eq_ignore_ascii_case(host))
                .then_some(Route::Direct)
        })
}

/// Escalations among `results`: per target host and path, requests in time
/// order, a gap over `window_secs` starting a new sequence; within one, the
/// first request and each later one whose route is higher than every route
/// before it. Capture-time records are left out: their order is the
/// archive's, not the client's. Cluster ids are filled from `cluster_ids`
/// (indexed like `ObsResult::cluster`).
pub fn escalations(
    results: &[ObsResult],
    cluster_ids: &[String],
    opts: &EscalationOptions,
) -> Vec<Escalation> {
    let mut by_target: BTreeMap<(&str, String), Vec<(usize, Route)>> = BTreeMap::new();
    for (i, r) in results.iter().enumerate() {
        if r.obs.ts <= 0 || !request_like(r.obs.ts_kind) {
            continue;
        }
        let (Some(host), Some(route)) = (r.target_host.as_deref(), route(r, opts)) else {
            continue;
        };
        let path = crate::paths::normalize_path(target_text(r));
        by_target.entry((host, path)).or_default().push((i, route));
    }
    let mut out = Vec::new();
    for ((host, path), mut reqs) in by_target {
        if !reqs.iter().any(|&(_, r)| r > Route::Direct) {
            continue;
        }
        crate::sort::by_key(&mut reqs, |&(i, _)| (results[i].obs.ts, i));
        let mut start = 0;
        for k in 1..=reqs.len() {
            let split = k == reqs.len()
                || results[reqs[k].0].obs.ts - results[reqs[k - 1].0].obs.ts > opts.window_secs;
            if split {
                if let Some(e) = climb(results, cluster_ids, host, &path, &reqs[start..k]) {
                    out.push(e);
                }
                start = k;
            }
        }
    }
    crate::sort::by(&mut out, |a, b| {
        a.start.cmp(&b.start).then(a.host.cmp(&b.host))
    });
    out
}

fn climb(
    results: &[ObsResult],
    cluster_ids: &[String],
    host: &str,
    path: &str,
    seq: &[(usize, Route)],
) -> Option<Escalation> {
    let mut steps: Vec<EscalationStep> = Vec::new();
    for &(i, route) in seq {
        if steps.last().is_none_or(|s| route > s.route) {
            steps.push(EscalationStep {
                route,
                record: i,
                ts: results[i].obs.ts,
            });
        }
    }
    if steps.len() < 2 {
        return None;
    }
    let mut clusters: Vec<String> = Vec::new();
    for s in &steps {
        if let Some(id) = results[s.record].cluster.and_then(|c| cluster_ids.get(c))
            && !clusters.contains(id)
        {
            clusters.push(id.clone());
        }
    }
    Some(Escalation {
        host: host.to_string(),
        path: path.to_string(),
        start: steps[0].ts,
        end: steps[steps.len() - 1].ts,
        time_basis: TimeBasis::of(steps.iter().map(|s| results[s.record].obs.ts_kind)),
        steps,
        clusters,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyze::analyze;
    use crate::model::{Observation, TsKind};
    use crate::rules::Rules;

    const T: i64 = 1_791_000_000;

    fn o(ts: i64, url: &str) -> Observation {
        Observation {
            id: format!("r{ts}"),
            ts,
            ts_kind: TsKind::Submit,
            url: url.into(),
            ..Default::default()
        }
    }

    const PAGE: &str = "https://data.portal.example/report/annual";

    fn program() -> String {
        use base64::Engine;
        let prog =
            format!("<script>fetch('{PAGE}').then(r=>r.text()).then(t=>document.title=t)</script>");
        format!(
            "https://httpbin.org/base64/{}",
            base64::engine::general_purpose::STANDARD.encode(prog)
        )
    }

    #[test]
    fn direct_then_relay_then_program() {
        let a = analyze(
            vec![
                o(T, PAGE),
                o(T + 60, &format!("https://r.jina.ai/{PAGE}")),
                o(
                    T + 90,
                    &format!("https://api.allorigins.win/raw?url={PAGE}"),
                ),
                o(T + 300, &program()),
                // Long after: a new sequence, with nothing to climb.
                o(T + 9_000, &format!("https://r.jina.ai/{PAGE}")),
            ],
            &Rules::default_rules(),
        );
        assert_eq!(a.escalations.len(), 1, "{:?}", a.escalations);
        let e = &a.escalations[0];
        assert_eq!(
            (e.host.as_str(), e.path.as_str()),
            ("data.portal.example", "/report/annual")
        );
        let routes: Vec<Route> = e.steps.iter().map(|s| s.route).collect();
        assert_eq!(routes, [Route::Direct, Route::Relay, Route::Program]);
        assert_eq!(
            e.steps.iter().map(|s| s.record).collect::<Vec<_>>(),
            [0, 1, 3]
        );
        assert_eq!((e.start, e.end), (T, T + 300));
        assert_eq!(e.route_line(), "direct → relay → program carrier");
        assert_eq!(e.time_basis, TimeBasis::Submit);
    }

    #[test]
    fn an_escalation_is_a_hint_on_its_clusters() {
        let hook = "hook=https://webhook.site/0b6c1f0e-1111-4c2a-9a55-3f2e1d0c9b8a";
        let a = analyze(
            vec![
                o(T, &format!("{PAGE}?{hook}")),
                o(T + 60, &format!("https://r.jina.ai/{PAGE}?{hook}")),
            ],
            &Rules::default_rules(),
        );
        assert_eq!(a.clusters.len(), 1);
        assert_eq!(a.escalations.len(), 1, "{:?}", a.escalations);
        assert_eq!(a.escalations[0].clusters, ["C1"]);
        let md = crate::report::render_markdown(&a, &Default::default());
        assert!(
            md.contains("route escalation on `data[.]portal[.]example/report/annual`: direct → relay over 60s; submit times"),
            "{md}"
        );
    }

    #[test]
    fn descending_or_flat_routes_are_not_escalations() {
        let rules = Rules::default_rules();
        let down = analyze(
            vec![
                o(T, &program()),
                o(T + 60, &format!("https://r.jina.ai/{PAGE}")),
                o(T + 120, PAGE),
            ],
            &rules,
        );
        assert!(down.escalations.is_empty(), "{:?}", down.escalations);
        let flat = analyze(
            vec![
                o(T, &format!("https://r.jina.ai/{PAGE}")),
                o(T + 60, &format!("https://r.jina.ai/{PAGE}?x=1")),
            ],
            &rules,
        );
        assert!(flat.escalations.is_empty());
        // Another path on the host is another target.
        let other = analyze(
            vec![
                o(T, "https://data.portal.example/about"),
                o(T + 60, &format!("https://r.jina.ai/{PAGE}")),
            ],
            &rules,
        );
        assert!(other.escalations.is_empty());
        // Steps further apart than the window are separate.
        let slow = analyze(
            vec![
                o(T, PAGE),
                o(T + 3_600, &format!("https://r.jina.ai/{PAGE}")),
            ],
            &rules,
        );
        assert!(slow.escalations.is_empty());
    }

    #[test]
    fn capture_times_do_not_order_an_escalation() {
        let cap = |x: Observation| Observation {
            ts_kind: TsKind::Capture,
            ..x
        };
        let a = analyze(
            vec![
                cap(o(T, PAGE)),
                cap(o(T + 60, &format!("https://r.jina.ai/{PAGE}"))),
            ],
            &Rules::default_rules(),
        );
        assert!(a.escalations.is_empty());
    }

    #[test]
    fn route_lists_name_rules() {
        let o = EscalationOptions::default();
        assert_eq!(o.route_of("relay.jina"), Some(Route::Relay));
        assert_eq!(o.route_of("carrier.httpbin"), Some(Route::Program));
        assert_eq!(o.route_of("carrier.livecodes"), Some(Route::RemoteBrowser));
        assert_eq!(o.route_of("exploit.xss"), None);
        let rules = Rules::default_rules();
        assert!(o.unknown_entries(&rules.set.rules).is_empty());
    }
}
