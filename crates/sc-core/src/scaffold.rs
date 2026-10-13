//! Scaffold fingerprints: clusters whose requests share a structure, though
//! they share no identifier.
//!
//! A fleet built on one harness (one prompt, one tool wrapper, one request
//! builder) gives each agent its own inbox and tag, so nothing links its
//! clusters. Its requests still look alike in shape: the same relay route,
//! the same parameter names in the same order, values of the same kinds and
//! lengths, the same URL encoding, the same test payloads. [`template`]
//! reduces a record to that shape with every value replaced by its slot type,
//! and [`scaffold_pairs`] compares clusters' template mixes.
//!
//! Popular libraries and agent frameworks give unrelated operators one shape
//! too. Two guards answer that: a template held by many clusters weighs
//! little (IDF, as reruns weigh hosts) and one held by more than
//! `soft_links.max_shared` ties nothing; and each pair carries the chance
//! that two unrelated clusters of this analysis would both hold the rarest
//! template they share. Pairs are soft links: they never score, link or
//! merge.

use crate::analyze::{Cluster, ObsResult, payload_variants, relay_stack};
use crate::model::Tier;
use crate::weburl::WebUrl;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// Scaffold settings (`[scaffold]` in the rules file).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct ScaffoldOptions {
    /// A template ties clusters only with at least this many structural
    /// parts: relay hops, parameters, an informative encoding, test
    /// payloads, a cut. A bare search through one relay has two.
    pub min_specificity: usize,
    /// IDF-weighted similarity of the two clusters' template mixes, 0 to 1.
    pub min_similarity: f64,
    /// Kept only when two unrelated clusters would share the rarest common
    /// template at most this often.
    pub max_chance: f64,
}

impl Default for ScaffoldOptions {
    fn default() -> Self {
        Self {
            min_specificity: 3,
            min_similarity: 0.5,
            max_chance: 0.01,
        }
    }
}

/// Parameters kept per template, in the order sent.
const MAX_PARAMS: usize = 12;
/// Path segments kept per template.
const MAX_SEGMENTS: usize = 8;
/// Pairs kept, most unlikely first.
const MAX_PAIRS: usize = 200;

/// One record's request structure, values replaced by slot types.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Template {
    /// `relay.jina → target | /w/w.php ? q=payload&uqtag=w3 | enc sp20 | pay sqli_or`.
    pub key: String,
    /// Structural parts it carries (see [`ScaffoldOptions::min_specificity`]).
    pub specificity: usize,
}

/// Two clusters whose requests share a structure beyond chance.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScaffoldPair {
    /// Cluster ids, `a` the stronger.
    pub a: String,
    pub b: String,
    /// IDF-weighted Ruzicka similarity of the two template mixes.
    pub similarity: f64,
    /// Shared templates, most distinctive first (a few).
    pub shared: Vec<String>,
    /// Clusters above noise holding the rarest shared template, and all
    /// clusters above noise with a template.
    pub holders: usize,
    pub clusters: usize,
    /// Chance that two unrelated clusters both hold that template:
    /// `((holders - 1) / (clusters - 1))^2`, the pair itself left out.
    pub chance: f64,
    /// Pairs this unlikely expected among all the analysis's cluster pairs.
    pub expected_pairs: f64,
}

impl ScaffoldPair {
    pub fn detail(&self) -> String {
        format!(
            "similarity {:.2}, {} shared template(s), rarest in {} of {} clusters (chance {:.1e}, {:.1} such pairs expected): {}",
            self.similarity,
            self.shared.len(),
            self.holders,
            self.clusters,
            self.chance,
            self.expected_pairs,
            self.shared.first().map_or("", String::as_str)
        )
    }
}

/// The structure of `r`'s request on its target: relay route, path shape,
/// parameters as `name=slot` in the order sent, the encoding style, the
/// canonical payload variants and whether the URL was cut.
pub fn template(r: &ObsResult) -> Template {
    let mut spec = 0;
    let route = match relay_stack(r) {
        Some(s) => {
            spec += s.matches(" → ").count();
            s
        }
        None => "direct".into(),
    };
    // The target layer: the innermost naming the target host, else the URL.
    let layer = r.target_host.as_deref().and_then(|host| {
        r.layers.iter().rev().find(|l| {
            l.host
                .as_deref()
                .is_some_and(|x| x.eq_ignore_ascii_case(host))
        })
    });
    let text = layer.map_or(r.obs.url.as_str(), |l| l.text.as_str());
    let parsed = WebUrl::parse(text);
    let path = parsed
        .as_ref()
        .map_or(String::new(), |u| path_shape(&u.path_segments()));
    let mut params: Vec<(String, String)> = match layer {
        Some(l) => l.params.clone(),
        None => parsed.as_ref().map(|u| u.query_pairs()).unwrap_or_default(),
    };
    // Parameters a harness put on the outer URL (a tag after a relay's own
    // address), not already carried to the target.
    if let Some(outer) = r.layers.first().filter(|l| l.is_submitted())
        && layer.is_some_and(|l| !l.is_submitted())
    {
        for (n, v) in &outer.params {
            if value_class(v) != "url" && !params.iter().any(|(m, _)| m == n) {
                params.push((n.clone(), v.clone()));
            }
        }
    }
    let mut seen = BTreeSet::new();
    let slots: Vec<String> = params
        .iter()
        .filter(|(n, _)| seen.insert(n.to_ascii_lowercase()))
        .take(MAX_PARAMS)
        .map(|(n, v)| {
            let n: String = n.to_ascii_lowercase().chars().take(32).collect();
            format!("{n}={}", value_class(v))
        })
        .collect();
    spec += slots.len();
    let enc = crate::fingerprint::encoding(&r.obs.url);
    let enc = if enc.informative() {
        spec += 1;
        enc.style
    } else {
        "-".into()
    };
    let pay: Vec<String> = payload_variants(r).into_iter().collect();
    spec += usize::from(!pay.is_empty());
    let cut = if crate::dialect::looks_truncated(&r.obs.url) {
        spec += 1;
        format!(" | cut {}", r.obs.url.chars().count() / 8 * 8)
    } else {
        String::new()
    };
    Template {
        key: format!(
            "{route} | {path}?{} | enc {enc} | pay {}{cut}",
            slots.join("&"),
            if pay.is_empty() {
                "-".into()
            } else {
                pay.join(",")
            }
        ),
        specificity: spec,
    }
}

/// `/w/n/uuid.json`: each segment's slot type, a short extension kept.
fn path_shape(segs: &[&str]) -> String {
    let mut out = String::new();
    for (i, s) in segs.iter().enumerate() {
        if i == MAX_SEGMENTS {
            out.push_str("/…");
            break;
        }
        out.push('/');
        if s.is_empty() {
            continue;
        }
        match s.rsplit_once('.') {
            Some((stem, ext))
                if !stem.is_empty()
                    && (1..=5).contains(&ext.len())
                    && ext.bytes().all(|b| b.is_ascii_alphanumeric()) =>
            {
                out.push_str(slot(stem));
                out.push('.');
                out.push_str(&ext.to_ascii_lowercase());
            }
            _ => out.push_str(slot(s)),
        }
    }
    out
}

/// The slot type of a path segment or a value with no length class.
fn slot(v: &str) -> &'static str {
    let b = v.as_bytes();
    if b.is_empty() {
        "e"
    } else if b.iter().all(u8::is_ascii_digit) {
        "n"
    } else if is_uuid(v) {
        "uuid"
    } else if b.len() >= 8 && b.iter().all(u8::is_ascii_hexdigit) {
        "h"
    } else if b
        .iter()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_'))
    {
        let mixed = b.iter().any(u8::is_ascii_digit)
            && b.iter().any(u8::is_ascii_uppercase)
            && b.iter().any(u8::is_ascii_lowercase);
        if b.len() >= 16 && mixed { "b" } else { "w" }
    } else {
        "x"
    }
}

fn is_uuid(v: &str) -> bool {
    let parts: Vec<&str> = v.split('-').collect();
    parts.len() == 5
        && parts
            .iter()
            .zip([8, 4, 4, 4, 12])
            .all(|(p, n)| p.len() == n && p.bytes().all(|b| b.is_ascii_hexdigit()))
}

/// A parameter value's slot: what kind of value, and for plain tokens a
/// power-of-two length class (`w3`: 5 to 8 characters).
fn value_class(v: &str) -> String {
    let v = v.trim();
    let lower = v.to_ascii_lowercase();
    if v.is_empty() {
        return "e".into();
    }
    if v.starts_with(crate::redact::MARK) {
        return "secret".into();
    }
    if lower.contains("://") || lower.starts_with("data:") {
        return "url".into();
    }
    if v.contains(['\'', '"', '<', '>', ';', '(', ')', '`']) || v.contains("../") {
        return "payload".into();
    }
    if v.contains(char::is_whitespace) {
        return "text".into();
    }
    let s = slot(v);
    if s == "uuid" {
        return s.into();
    }
    let len = v.chars().count().next_power_of_two().trailing_zeros();
    format!("{s}{len}")
}

/// Pairs of clusters above noise whose template mixes are alike beyond
/// chance, most unlikely first. `max_shared` is `soft_links.max_shared`.
pub(crate) fn scaffold_pairs(
    clusters: &[Cluster],
    results: &[ObsResult],
    max_shared: usize,
    opts: &ScaffoldOptions,
) -> Vec<ScaffoldPair> {
    let shown: Vec<&Cluster> = clusters.iter().filter(|c| c.tier > Tier::Noise).collect();
    let n = shown.len();
    if n < 3 {
        return Vec::new();
    }
    let mut specific: BTreeMap<String, bool> = BTreeMap::new();
    let profiles: Vec<BTreeMap<String, f64>> = shown
        .iter()
        .map(|c| {
            let mut m: BTreeMap<String, f64> = BTreeMap::new();
            for &i in &c.members {
                let t = template(&results[i]);
                specific.insert(t.key.clone(), t.specificity >= opts.min_specificity);
                *m.entry(t.key).or_default() += 1.0;
            }
            let total = c.members.len().max(1) as f64;
            m.values_mut().for_each(|x| *x /= total);
            m
        })
        .collect();
    let mut holders: BTreeMap<&str, Vec<usize>> = BTreeMap::new();
    for (ci, p) in profiles.iter().enumerate() {
        for t in p.keys() {
            holders.entry(t.as_str()).or_default().push(ci);
        }
    }
    let df = |t: &str| holders.get(t).map_or(1, Vec::len);
    let weight = |t: &str| (1.0 + n as f64 / df(t) as f64).ln();
    // Candidate pairs: those sharing a specific template held by few
    // clusters. A pair sharing only common ones is never compared.
    let usable = |t: &str, ids: &[usize]| {
        specific.get(t).copied().unwrap_or(false) && ids.len() >= 2 && ids.len() <= max_shared
    };
    let mut candidates: BTreeSet<(usize, usize)> = BTreeSet::new();
    for (t, ids) in &holders {
        if usable(t, ids) {
            for (k, &x) in ids.iter().enumerate() {
                for &y in &ids[k + 1..] {
                    candidates.insert((x, y));
                }
            }
        }
    }
    let all_pairs = (n * (n - 1) / 2) as f64;
    let mut out = Vec::new();
    for (x, y) in candidates {
        let (px, py) = (&profiles[x], &profiles[y]);
        let (mut num, mut den) = (0.0, 0.0);
        for t in px.keys().chain(py.keys().filter(|t| !px.contains_key(*t))) {
            let (a, b) = (
                px.get(t).copied().unwrap_or(0.0),
                py.get(t).copied().unwrap_or(0.0),
            );
            num += weight(t) * a.min(b);
            den += weight(t) * a.max(b);
        }
        let similarity = if den > 0.0 { num / den } else { 0.0 };
        if similarity < opts.min_similarity {
            continue;
        }
        let mut shared: Vec<(&str, f64)> = px
            .iter()
            .filter(|(t, _)| py.contains_key(*t) && usable(t, &holders[t.as_str()]))
            .map(|(t, a)| (t.as_str(), weight(t) * a.min(py[t])))
            .collect();
        let Some(rarest) = shared.iter().map(|(t, _)| df(t)).min() else {
            continue;
        };
        let q = (rarest - 1) as f64 / (n - 1) as f64;
        let chance = q * q;
        if chance > opts.max_chance {
            continue;
        }
        crate::sort::by(&mut shared, |p, q| q.1.total_cmp(&p.1).then(p.0.cmp(q.0)));
        out.push(ScaffoldPair {
            a: shown[x].id.clone(),
            b: shown[y].id.clone(),
            similarity,
            shared: shared.iter().take(3).map(|(t, _)| t.to_string()).collect(),
            holders: rarest,
            clusters: n,
            chance,
            expected_pairs: chance * all_pairs,
        });
    }
    crate::sort::by(&mut out, |p, q| {
        p.chance
            .total_cmp(&q.chance)
            .then(q.similarity.total_cmp(&p.similarity))
    });
    out.truncate(MAX_PAIRS);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyze::analyze;
    use crate::model::Observation;
    use crate::rules::Rules;

    fn o(id: &str, ts: i64, url: &str) -> Observation {
        Observation {
            id: id.into(),
            ts,
            url: url.into(),
            ..Default::default()
        }
    }

    const T0: i64 = 1_791_000_000;

    /// `clusters` clusters of three records, each with its own run tag on
    /// its own hosts and day; `shape(cluster, record)` writes the URL.
    fn fleet(clusters: usize, shape: impl Fn(usize, usize) -> String) -> Vec<Observation> {
        let mut obs = Vec::new();
        for c in 0..clusters {
            for k in 0..3 {
                obs.push(o(
                    &format!("c{c}r{k}"),
                    T0 + c as i64 * 86_400 * 4 + k as i64 * 90,
                    &shape(c, k),
                ));
            }
        }
        obs
    }

    /// A harness shape: a relay, a payload, a run tag, a step counter and a
    /// timestamp, in that order.
    fn harness(c: usize, k: usize) -> String {
        format!(
            "https://r.jina.ai/https://h{k}.c{c}.example/item/{}/view?q=%27%20OR%201%3D1--&uqtag=fx{c}{c}q{c}&step={k}&ts=17724456{c}{k}",
            100 + k
        )
    }

    /// Distinct shapes for the background clusters: each its own parameter
    /// names.
    fn other(c: usize, k: usize) -> String {
        format!(
            "https://h{k}.o{c}.example/p{c}?name{c}=%3Cscript%3Ealert(1)%3C/script%3E&uqtag=bg{c}x{c}"
        )
    }

    #[test]
    fn templates_keep_structure_and_drop_values() {
        let a = analyze(fleet(1, harness), &Rules::default_rules());
        let t: Vec<Template> = a.results.iter().map(template).collect();
        assert_eq!(t[0].key, t[1].key, "{:?}", t);
        assert!(t[0].key.contains("relay.jina → target"), "{}", t[0].key);
        assert!(t[0].key.contains("/w/n/w?"), "{}", t[0].key);
        assert!(
            t[0].key.contains("q=payload&uqtag=w3&step=n0&ts=n4"),
            "{}",
            t[0].key
        );
        assert!(!t[0].key.contains("example"), "{}", t[0].key);
        assert!(t[0].specificity >= 5, "{}", t[0].specificity);
        assert_eq!(value_class("0b6c1f0e-1111-4c2a-9a55-3f2e1d0c9b8a"), "uuid");
        assert_eq!(value_class("https://webhook.site/x"), "url");
        assert_eq!(value_class("two words"), "text");
        assert_eq!(value_class("REDACTED-0123456789ab"), "secret");
    }

    #[test]
    fn one_scaffold_across_clusters_is_a_pair_with_its_chance() {
        // Three clusters on one harness, distinct tags, among twenty others.
        let mut obs = fleet(3, harness);
        for (i, mut x) in fleet(20, other).into_iter().enumerate() {
            x.id = format!("bg{i}");
            x.ts += 86_400 * 100;
            obs.push(x);
        }
        let a = analyze(obs, &Rules::default_rules());
        assert_eq!(a.clusters.len(), 23, "{:?}", a.clusters.len());
        let p = &a.scaffold_pairs;
        assert_eq!(p.len(), 3, "{p:?}");
        for x in p {
            assert_eq!((x.holders, x.clusters), (3, 23));
            assert!((x.chance - (2.0f64 / 22.0).powi(2)).abs() < 1e-12);
            assert!(x.similarity > 0.99);
        }
        let links: Vec<_> = a
            .soft_links
            .iter()
            .filter(|l| l.kind == crate::fleets::SoftLinkKind::Scaffold)
            .collect();
        assert_eq!(links.len(), 3, "{:?}", a.soft_links);
        assert!(!links[0].detail.contains("example"));
        // The three form one candidate fleet; nothing else moved.
        assert!(
            a.candidate_fleets.iter().any(|f| f.clusters.len() == 3
                && f.kinds.contains(&crate::fleets::SoftLinkKind::Scaffold)),
            "{:?}",
            a.candidate_fleets
        );
    }

    #[test]
    fn a_popular_shape_held_by_many_clusters_ties_none() {
        // Six operators on one framework's default shape, among four others:
        // the shape is too common to say anything about any pair.
        let mut obs = fleet(6, harness);
        for (i, mut x) in fleet(4, other).into_iter().enumerate() {
            x.id = format!("bg{i}");
            x.ts += 86_400 * 40;
            obs.push(x);
        }
        let a = analyze(obs, &Rules::default_rules());
        assert_eq!(a.clusters.len(), 10);
        assert!(a.scaffold_pairs.is_empty(), "{:?}", a.scaffold_pairs);
        // Past `max_shared` it is not even compared.
        let mut rules = Rules::default_rules();
        rules.set.scaffold.max_chance = 1.0;
        rules.set.soft_links.max_shared = 5;
        let b = analyze(fleet(6, harness), &rules);
        assert!(b.scaffold_pairs.is_empty(), "{:?}", b.scaffold_pairs);
    }

    #[test]
    fn a_bare_relay_search_is_not_specific_enough() {
        let bare = |c: usize, k: usize| {
            format!("https://r.jina.ai/https://h{k}.c{c}.example/search?uqtag=t{c}{c}{c}{c}")
        };
        let mut obs = fleet(2, bare);
        for (i, mut x) in fleet(12, other).into_iter().enumerate() {
            x.id = format!("bg{i}");
            x.ts += 86_400 * 60;
            obs.push(x);
        }
        let a = analyze(obs, &Rules::default_rules());
        assert!(a.scaffold_pairs.is_empty(), "{:?}", a.scaffold_pairs);
    }
}
