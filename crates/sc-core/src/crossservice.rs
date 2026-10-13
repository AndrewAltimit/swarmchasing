//! Cross-service fan-out: one target sent to several scan services within
//! seconds to a minute.
//!
//! A person checking a link uses one service, or a second one minutes later.
//! An agent's tool loop, or a script that sends each URL to every service it
//! has a key for, leaves the same target (after unwrapping) on several
//! services moments apart. So does a mail gateway or security product that
//! submits every link it sees, and then whoever mailed the link made the
//! records. [`service_fans`] finds the targets sent to at least
//! `cross_service_min` services within `cross_service_secs`; [`describe_all`]
//! says which of them touch a cluster, and counts the same fan-out on
//! ordinary links on other hosts around it, which is how an auto-submitter
//! shows itself.
//!
//! Only submit-anywhere services count, and only by request or submit
//! times: an archive capture time says when a crawler saved a URL, not when
//! anyone sent it. Descriptive: never scored, never linked on.

use crate::analyze::{Cluster, ObsResult, target_text};
use crate::fanout::FanOutOptions;
use crate::model::{Provenance, Tier, TsKind};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap};

/// One target's submissions to several services within the window.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct ServiceFan {
    /// Indexes into the results, by time.
    pub records: Vec<usize>,
    pub services: BTreeSet<&'static str>,
    pub start: i64,
    pub end: i64,
    /// Every record in it is noise: an ordinary link.
    pub ordinary: bool,
}

/// What a cluster's cross-service fan-out looks like.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct CrossService {
    /// Members' targets each sent to several services within the window.
    #[serde(default)]
    pub targets: usize,
    /// Members in those submissions.
    #[serde(default)]
    pub records: usize,
    /// Services, by how many of those targets went to each.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub services: BTreeMap<String, usize>,
    /// The longest time from a target's first submission to its last.
    #[serde(default)]
    pub max_spread_secs: i64,
    /// Ordinary targets on other hosts sent to several services alike within
    /// `linking.window_secs` of the cluster's span.
    #[serde(default)]
    pub ambient: usize,
    /// `ambient` reaches `fanout.cross_service_ambient`: something submits
    /// every link it sees, as a mail gateway or security product does.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub auto_submitter: bool,
}

impl CrossService {
    pub fn is_empty(&self) -> bool {
        self.targets == 0
    }

    /// Services as a report lists them: `urlquery, urlscan`.
    pub fn service_list(&self) -> String {
        self.services
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>()
            .join(", ")
    }
}

/// The record's service, when it is a submit-anywhere source timed by a
/// request or submit.
fn service(r: &ObsResult) -> Option<&'static str> {
    let o = &r.obs;
    let timed = o.ts > 0 && matches!(o.ts_kind, TsKind::Request | TsKind::Submit);
    (timed && o.provenance() == Provenance::SubmitAnywhere).then(|| o.source_kind().name())
}

/// A target as compared across services: no scheme or fragment, the host
/// part lower-cased, no trailing slash.
fn target_key(text: &str) -> String {
    let t = text.split('#').next().unwrap_or_default();
    let t = match t.find("://") {
        Some(i) if i <= 8 => &t[i + 3..],
        _ => t,
    };
    let cut = t.find(['/', '?']).unwrap_or(t.len());
    let mut k = t[..cut].to_ascii_lowercase();
    k.push_str(&t[cut..]);
    k.trim_end_matches('/').to_string()
}

/// Every target sent to at least `cross_service_min` services within
/// `cross_service_secs` of its first submission there, in time order.
pub(crate) fn service_fans(results: &[ObsResult], opts: &FanOutOptions) -> Vec<ServiceFan> {
    if opts.cross_service_min < 2 {
        return Vec::new();
    }
    let mut by_target: BTreeMap<String, Vec<(usize, &'static str)>> = BTreeMap::new();
    for (i, r) in results.iter().enumerate() {
        if r.target_host.is_none() {
            continue;
        }
        if let Some(s) = service(r) {
            by_target
                .entry(target_key(target_text(r)))
                .or_default()
                .push((i, s));
        }
    }
    let mut out = Vec::new();
    for subs in by_target.values_mut() {
        crate::sort::by_key(subs, |&(i, _)| (results[i].obs.ts, i));
        let ts = |k: usize| results[subs[k].0].obs.ts;
        // The window is `subs[a..e]`, its services counted in `counts`. Times
        // are sorted, so `e` only moves forward as `a` does.
        let (mut a, mut e) = (0, 0);
        let mut counts: BTreeMap<&'static str, usize> = BTreeMap::new();
        while a < subs.len() {
            if e < a {
                e = a;
                counts.clear();
            }
            let t0 = ts(a);
            while e < subs.len() && ts(e) - t0 <= opts.cross_service_secs {
                *counts.entry(subs[e].1).or_default() += 1;
                e += 1;
            }
            if counts.len() < opts.cross_service_min {
                if a < e {
                    let s = subs[a].1;
                    if let Some(n) = counts.get_mut(s) {
                        *n -= 1;
                        if *n == 0 {
                            counts.remove(s);
                        }
                    }
                }
                a += 1;
                continue;
            }
            let records: Vec<usize> = subs[a..e].iter().map(|&(i, _)| i).collect();
            out.push(ServiceFan {
                start: t0,
                end: results[records[records.len() - 1]].obs.ts,
                ordinary: records.iter().all(|&i| results[i].tier == Tier::Noise),
                records,
                services: counts.keys().copied().collect(),
            });
            counts.clear();
            a = e;
        }
    }
    crate::sort::by_key(&mut out, |f| (f.start, f.records[0]));
    out
}

/// Each cluster's cross-service fan-out among `fans` (as [`service_fans`]
/// orders them), with the ordinary fan-outs on other hosts within `window`
/// seconds of its span.
pub(crate) fn describe_all(
    clusters: &mut [Cluster],
    results: &[ObsResult],
    fans: &[ServiceFan],
    opts: &FanOutOptions,
    window: i64,
) {
    // The clusters holding each fanned-out record.
    let mut of_record: HashMap<usize, Vec<usize>> = fans
        .iter()
        .flat_map(|f| &f.records)
        .map(|&i| (i, Vec::new()))
        .collect();
    for (n, c) in clusters.iter().enumerate() {
        for m in &c.members {
            if let Some(v) = of_record.get_mut(m) {
                v.push(n);
            }
        }
    }
    let mut xs = vec![CrossService::default(); clusters.len()];
    // The clusters each fan-out touches.
    let mut touched: Vec<BTreeSet<usize>> = Vec::with_capacity(fans.len());
    for f in fans {
        let mut mine: BTreeMap<usize, usize> = BTreeMap::new();
        for m in &f.records {
            for &n in of_record.get(m).into_iter().flatten() {
                *mine.entry(n).or_default() += 1;
            }
        }
        for (&n, &k) in &mine {
            let x = &mut xs[n];
            x.targets += 1;
            x.records += k;
            x.max_spread_secs = x.max_spread_secs.max(f.end - f.start);
            for s in &f.services {
                *x.services.entry(s.to_string()).or_default() += 1;
            }
        }
        touched.push(mine.into_keys().collect());
    }
    for (n, (c, mut x)) in clusters.iter_mut().zip(xs).enumerate() {
        if c.start > 0 {
            let from = fans.partition_point(|f| f.start < c.start - window);
            let to = fans.partition_point(|f| f.start <= c.end + window);
            for (f, t) in fans.iter().zip(&touched).take(to.max(from)).skip(from) {
                if f.ordinary
                    && !t.contains(&n)
                    && f.records.iter().all(|&i| {
                        results[i]
                            .target_host
                            .as_ref()
                            .is_none_or(|h| !c.target_hosts.contains_key(h))
                    })
                {
                    x.ambient += 1;
                }
            }
        }
        x.auto_submitter = !x.is_empty()
            && opts.cross_service_ambient > 0
            && x.ambient >= opts.cross_service_ambient;
        c.cross_service = x;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agentness::{AgentLevel, SignalKind};
    use crate::model::Observation;
    use crate::rules::Rules;

    fn rec(id: &str, source: &str, ts: i64, url: &str) -> Observation {
        Observation {
            id: id.into(),
            source: source.into(),
            ts,
            ts_kind: TsKind::Submit,
            url: url.into(),
            ..Default::default()
        }
    }

    const T0: i64 = 1_791_000_007;

    /// Four variants of one residue-laden probe, 45 seconds apart, each sent
    /// to urlquery and, `lag` seconds later, to `second`.
    fn agent_run(second: &str, lag: i64) -> Vec<Observation> {
        (0..4)
            .flat_map(|i| {
                let url = format!(
                    "https://records.xs.example/search?q={i}%27%20OR%201=1--%20YOUR_API_KEY&page={i}&uqtag=xsv1"
                );
                let t = T0 + 45 * i;
                [
                    rec(&format!("q{i}"), "urlquery", t, &url),
                    rec(&format!("s{i}"), second, t + lag, &url),
                ]
            })
            .collect()
    }

    fn signals(a: &crate::Analysis) -> (Vec<SignalKind>, Vec<SignalKind>) {
        let g = &a.clusters[0].agent;
        (
            g.signals.iter().map(|s| s.kind).collect(),
            g.counter.iter().map(|s| s.kind).collect(),
        )
    }

    #[test]
    fn target_keys_ignore_scheme_case_and_trailing_slash() {
        assert_eq!(
            target_key("HTTPS://Shop.Example/a?b=C#frag"),
            target_key("http://shop.example/a?b=C/")
        );
        assert_ne!(
            target_key("https://shop.example/a?b=C"),
            target_key("https://shop.example/a?b=c")
        );
    }

    #[test]
    fn one_target_on_two_services_within_seconds_is_agent_likely() {
        let a = crate::analyze(agent_run("urlscan", 8), &Rules::default_rules());
        assert_eq!(a.clusters.len(), 1, "{:?}", a.clusters);
        let c = &a.clusters[0];
        let x = &c.cross_service;
        assert_eq!(
            (x.targets, x.records, x.max_spread_secs),
            (4, 8, 8),
            "{x:?}"
        );
        assert_eq!(x.service_list(), "urlquery, urlscan");
        assert!(!x.auto_submitter);
        assert!(
            signals(&a).0.contains(&SignalKind::CrossService),
            "{:?}",
            c.agent
        );
        assert_eq!(c.agent.level, AgentLevel::AgentLikely, "{:?}", c.agent);
    }

    #[test]
    fn one_service_twice_or_a_slow_second_service_is_no_fan_out() {
        for (second, lag) in [("urlquery", 8), ("urlscan", 180)] {
            let a = crate::analyze(agent_run(second, lag), &Rules::default_rules());
            let c = &a.clusters[0];
            assert!(
                c.cross_service.is_empty(),
                "{second} {lag}: {:?}",
                c.cross_service
            );
            assert_eq!(c.agent.level, AgentLevel::Adaptive, "{:?}", c.agent);
        }
    }

    #[test]
    fn capture_times_never_count() {
        let mut obs = agent_run("urlscan", 8);
        for o in obs.iter_mut().filter(|o| o.source == "urlscan") {
            o.source = "wayback".into();
            o.ts_kind = TsKind::Capture;
        }
        let a = crate::analyze(obs.clone(), &Rules::default_rules());
        assert!(a.clusters[0].cross_service.is_empty());
        // The same archive rows carrying submit times (an on-demand save
        // whose source records when it was asked for) do count.
        for o in obs.iter_mut().filter(|o| o.source == "wayback") {
            o.ts_kind = TsKind::Submit;
        }
        let a = crate::analyze(obs, &Rules::default_rules());
        assert_eq!(a.clusters[0].cross_service.targets, 4);
    }

    #[test]
    fn a_relay_wrapped_copy_is_the_same_target() {
        let url = "https://records.xs.example/search?q=1%27%20OR%201=1--&uqtag=xsv2";
        let obs = vec![
            rec("a", "urlquery", T0, url),
            rec("b", "urlscan", T0 + 5, &format!("https://r.jina.ai/{url}")),
        ];
        let a = crate::analyze(obs, &Rules::default_rules());
        assert_eq!(a.clusters[0].cross_service.targets, 1, "{:?}", a.clusters);
    }

    #[test]
    fn ordinary_links_fanned_out_alike_mark_an_auto_submitter() {
        let mut obs = agent_run("urlscan", 3);
        // A gateway sends every link in the mail it scans to both services.
        for k in 0..4 {
            let url = format!("https://news{k}.mail.example/issue/{k}?utm_source=newsletter");
            let t = T0 + 30 + 40 * k;
            obs.push(rec(&format!("gq{k}"), "urlquery", t, &url));
            obs.push(rec(&format!("gs{k}"), "urlscan", t + 2, &url));
        }
        let a = crate::analyze(obs, &Rules::default_rules());
        let c = &a.clusters[0];
        assert_eq!(c.cross_service.ambient, 4, "{:?}", c.cross_service);
        assert!(c.cross_service.auto_submitter);
        let (sig, counter) = signals(&a);
        assert!(!sig.contains(&SignalKind::CrossService), "{:?}", c.agent);
        assert!(
            counter.contains(&SignalKind::AutoSubmitter),
            "{:?}",
            c.agent
        );
        assert_eq!(c.agent.level, AgentLevel::Adaptive, "{:?}", c.agent);
        // The plant review names it.
        assert!(
            c.origin
                .plant_signals
                .iter()
                .any(|p| p.kind == crate::plant::PlantSignalKind::AutoSubmitted),
            "{:?}",
            c.origin.plant_signals
        );
        // The ordinary links are not flagged and form no cluster.
        assert_eq!(a.clusters.len(), 1, "{:?}", a.clusters);
    }

    #[test]
    fn settings_turn_it_off() {
        let mut rules = Rules::default_rules();
        rules.set.fanout.cross_service_min = 3;
        let a = crate::analyze(agent_run("urlscan", 8), &rules);
        assert!(a.clusters[0].cross_service.is_empty());
        rules.set.fanout.cross_service_min = 2;
        rules.set.fanout.cross_service_secs = 5;
        let a = crate::analyze(agent_run("urlscan", 8), &rules);
        assert!(a.clusters[0].cross_service.is_empty());
    }

    /// Fan-outs and per-cluster descriptions as a window rebuilt at every
    /// record and a scan of every fan-out per cluster would find them.
    fn naive(
        results: &[ObsResult],
        clusters: &[Cluster],
        opts: &FanOutOptions,
        window: i64,
    ) -> (Vec<ServiceFan>, Vec<CrossService>) {
        let mut by_target: BTreeMap<String, Vec<(usize, &'static str)>> = BTreeMap::new();
        for (i, r) in results.iter().enumerate() {
            if r.target_host.is_some()
                && let Some(s) = service(r)
            {
                by_target
                    .entry(target_key(target_text(r)))
                    .or_default()
                    .push((i, s));
            }
        }
        let mut fans = Vec::new();
        for subs in by_target.values_mut() {
            crate::sort::by_key(subs, |&(i, _)| (results[i].obs.ts, i));
            let mut a = 0;
            while a < subs.len() {
                let t0 = results[subs[a].0].obs.ts;
                let win: Vec<(usize, &'static str)> = subs[a..]
                    .iter()
                    .copied()
                    .take_while(|&(i, _)| results[i].obs.ts - t0 <= opts.cross_service_secs)
                    .collect();
                let services: BTreeSet<&'static str> = win.iter().map(|&(_, s)| s).collect();
                if services.len() < opts.cross_service_min {
                    a += 1;
                    continue;
                }
                let records: Vec<usize> = win.iter().map(|&(i, _)| i).collect();
                fans.push(ServiceFan {
                    start: t0,
                    end: results[records[records.len() - 1]].obs.ts,
                    ordinary: records.iter().all(|&i| results[i].tier == Tier::Noise),
                    records,
                    services,
                });
                a += win.len();
            }
        }
        crate::sort::by_key(&mut fans, |f| (f.start, f.records[0]));
        let described = clusters
            .iter()
            .map(|c| {
                let mut x = CrossService::default();
                for f in &fans {
                    let mine = f.records.iter().filter(|m| c.members.contains(m)).count();
                    if mine > 0 {
                        x.targets += 1;
                        x.records += mine;
                        x.max_spread_secs = x.max_spread_secs.max(f.end - f.start);
                        for s in &f.services {
                            *x.services.entry(s.to_string()).or_default() += 1;
                        }
                    } else if f.ordinary
                        && c.start > 0
                        && f.start >= c.start - window
                        && f.start <= c.end + window
                        && f.records.iter().all(|&i| {
                            results[i]
                                .target_host
                                .as_ref()
                                .is_none_or(|h| !c.target_hosts.contains_key(h))
                        })
                    {
                        x.ambient += 1;
                    }
                }
                x.auto_submitter = !x.is_empty()
                    && opts.cross_service_ambient > 0
                    && x.ambient >= opts.cross_service_ambient;
                x
            })
            .collect();
        (fans, described)
    }

    #[test]
    fn indexed_fan_outs_match_the_naive_scan() {
        let services = ["urlquery", "urlscan", "wayback"];
        let mut seed: u64 = 11;
        let mut next = |m: u64| {
            seed = seed
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            (seed >> 33) % m
        };
        let mut obs = Vec::new();
        for run in 0..6 {
            obs.extend(
                agent_run(services[run % 3], (run as i64) * 7)
                    .into_iter()
                    .map(|mut o| {
                        o.id = format!("r{run}{}", o.id);
                        o.ts += run as i64 * 400;
                        o.url = o.url.replace("xsv1", &format!("xsv{run}"));
                        o
                    }),
            );
        }
        for k in 0..300 {
            let url = format!("https://n{}.mail.example/issue?utm_source=x", next(40));
            let svc = services[next(3) as usize];
            obs.push(rec(&format!("g{k}"), svc, T0 + next(4000) as i64, &url));
        }
        let rules = Rules::default_rules();
        let a = crate::analyze(obs, &rules);
        let mut opts = rules.set.fanout.clone();
        for (min, secs) in [(2, opts.cross_service_secs), (3, 90), (2, 0), (2, -1)] {
            opts.cross_service_min = min;
            opts.cross_service_secs = secs;
            let window = rules.set.linking.window_secs;
            let (fans, want) = naive(&a.results, &a.clusters, &opts, window);
            assert_eq!(
                service_fans(&a.results, &opts),
                fans,
                "min {min}, secs {secs}"
            );
            let mut clusters = a.clusters.clone();
            describe_all(&mut clusters, &a.results, &fans, &opts, window);
            let got: Vec<CrossService> = clusters.into_iter().map(|c| c.cross_service).collect();
            assert_eq!(got, want, "min {min}, secs {secs}");
        }
        let (fans, want) = naive(&a.results, &a.clusters, &rules.set.fanout, 600);
        assert!(fans.len() > 10 && want.iter().any(|x| x.targets > 0 && x.ambient > 0));
    }
}
