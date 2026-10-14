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
//! too. Four guards answer that: a template held by many clusters weighs
//! little (IDF, as reruns weigh hosts); one held by more than
//! `scaffold.max_holders` senders (clusters, and records outside them) is a
//! common default and ties nothing; each shared template has a base rate
//! among the comparable clusters (those sending a specific template at
//! all), its other holders counted with any outside records carrying it,
//! and a pair's chance is that two unrelated clusters both hold the rarest
//! template they share at its rate, corrected for the number of usable
//! templates they share; and the pairs are cut at a false discovery rate
//! over the pairs compared. Records outside the clusters only ever make a template more
//! common, so appending unrelated traffic cannot make a shape look rare.
//! Pairs are soft links: they never score, link or merge.
//!
//! [`lineage_pairs`] finds a fleet that exact templates split: one harness
//! changed mid-fleet, so the two halves' templates are one structural part
//! apart ([`lineage_keys`]), with the chance of a handover between them.

use crate::analyze::{Cluster, ObsResult, payload_variants, relay_stack};
use crate::chance::TestFamily;
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
    /// A template held by more than this many senders (clusters above
    /// noise, and records outside them) is a common default and ties none.
    pub max_holders: usize,
    /// Kept only when the pair's chance is at most this.
    pub max_chance: f64,
    /// Benjamini-Hochberg false discovery rate over the pairs compared.
    pub fdr: f64,
}

impl Default for ScaffoldOptions {
    fn default() -> Self {
        Self {
            min_specificity: 3,
            min_similarity: 0.5,
            max_holders: 5,
            max_chance: 0.01,
            fdr: 0.05,
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
    /// Its components in order: the relay route when it has hops, the path
    /// shape, each parameter slot, an informative encoding, the payloads
    /// and the cut. The lineage keys ([`lineage_keys`]) are read from them.
    pub parts: Vec<Part>,
}

/// One component of a [`Template`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Part {
    /// `route`, `path`, `parameter`, `encoding`, `payloads` or `cut`.
    pub kind: &'static str,
    pub text: String,
    /// Structural parts it counts for; the path shape counts none and is
    /// never dropped.
    pub weight: usize,
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
    /// Clusters above noise holding the least likely shared template, and
    /// the comparable clusters: those above noise sending a specific
    /// template at all.
    pub holders: usize,
    pub clusters: usize,
    /// Records outside the clusters carrying that template.
    #[serde(default)]
    pub outside: usize,
    /// That template's base rate: its other holders (one of the pair left
    /// out) and outside records carrying it, over the other comparable
    /// clusters.
    #[serde(default)]
    pub base_rate: f64,
    /// Usable templates the two share (the rarest is the one read).
    #[serde(default)]
    pub templates: usize,
    /// Chance that two unrelated clusters share a template this rare among
    /// that many: `1 - (1 - base_rate²)^templates`.
    pub chance: f64,
    /// Pairs compared, and pairs this unlikely expected among them.
    #[serde(default)]
    pub tested: usize,
    pub expected_pairs: f64,
}

impl ScaffoldPair {
    pub fn detail(&self) -> String {
        format!(
            "similarity {:.2}, {} shared template(s), the rarest in {} of {} comparable clusters and {} record(s) outside them, a base rate of {:.1e} (chance {:.1e} for the rarest of that many; {:.2} such pairs expected among {} compared): {}",
            self.similarity,
            self.templates.max(self.shared.len()),
            self.holders,
            self.clusters,
            self.outside,
            self.base_rate,
            self.chance,
            self.expected_pairs,
            self.tested,
            self.shared.first().map_or("", String::as_str)
        )
    }
}

/// The structure of `r`'s request on its target: relay route, path shape,
/// parameters as `name=slot` in the order sent, the encoding style, the
/// canonical payload variants and whether the URL was cut.
pub fn template(r: &ObsResult) -> Template {
    let mut spec = 0;
    let mut parts = Vec::new();
    let mut part = |kind: &'static str, text: &str, weight: usize| {
        parts.push(Part {
            kind,
            text: text.to_string(),
            weight,
        });
    };
    let route = match relay_stack(r) {
        Some(s) => {
            let hops = s.matches(" → ").count();
            spec += hops;
            part("route", &s, hops);
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
    part("path", &path, 0);
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
    for sl in &slots {
        part("parameter", sl, 1);
    }
    let enc = crate::fingerprint::encoding(&r.obs.url);
    let enc = if enc.informative() {
        spec += 1;
        part("encoding", &enc.style, 1);
        enc.style
    } else {
        "-".into()
    };
    let pay: Vec<String> = payload_variants(r).into_iter().collect();
    if !pay.is_empty() {
        spec += 1;
        part("payloads", &pay.join(","), 1);
    }
    let cut = if crate::dialect::looks_truncated(&r.obs.url) {
        spec += 1;
        let n = r.obs.url.chars().count() / 8 * 8;
        part("cut", &n.to_string(), 1);
        format!(" | cut {n}")
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
        parts,
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
/// chance, most unlikely first, and the family's multiplicity budget.
/// `max_shared` is `soft_links.max_shared`.
pub(crate) fn scaffold_pairs(
    clusters: &[Cluster],
    results: &[ObsResult],
    max_shared: usize,
    opts: &ScaffoldOptions,
) -> (Vec<ScaffoldPair>, TestFamily) {
    let shown: Vec<&Cluster> = clusters.iter().filter(|c| c.tier > Tier::Noise).collect();
    let n = shown.len();
    if n < 3 {
        return (Vec::new(), TestFamily::cut("scaffold", &[], 0, opts.fdr));
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
    // Records outside the clusters (unclustered, unflagged, in a noise
    // cluster) carrying a template some cluster holds. They count as more
    // holders, never as more population: unrelated traffic cannot dilute.
    let mut inside = vec![false; results.len()];
    for c in &shown {
        for &m in &c.members {
            inside[m] = true;
        }
    }
    let mut outside_with: BTreeMap<String, usize> = BTreeMap::new();
    for (i, r) in results.iter().enumerate() {
        if !inside[i] {
            let t = template(r);
            if holders.contains_key(t.key.as_str()) {
                *outside_with.entry(t.key).or_default() += 1;
            }
        }
    }
    let outside = |t: &str| outside_with.get(t).copied().unwrap_or(0);
    // The comparable clusters: those sending any specific template.
    let comparable = profiles
        .iter()
        .filter(|p| p.keys().any(|t| specific.get(t).copied().unwrap_or(false)))
        .count();
    // A template's base rate: its other holders and outside carriers over
    // the other comparable clusters, one holder of the pair left out.
    let rate = |t: &str| -> f64 {
        ((holders[t].len() - 1 + outside(t)) as f64 / comparable.saturating_sub(1).max(1) as f64)
            .min(1.0)
    };
    let df = |t: &str| holders.get(t).map_or(1, Vec::len);
    let weight = |t: &str| (1.0 + n as f64 / df(t) as f64).ln();
    // Candidate pairs: those sharing a specific template held by few
    // clusters. A pair sharing only common ones is never compared.
    let usable = |t: &str, ids: &[usize]| {
        specific.get(t).copied().unwrap_or(false)
            && ids.len() >= 2
            && ids.len() <= max_shared
            && ids.len() + outside(t) <= opts.max_holders
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
    let tested = candidates.len();
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
        let Some((rate, rarest, outside_t)) = shared
            .iter()
            .map(|(t, _)| (rate(t), df(t), outside(t)))
            .min_by(|a, b| a.0.total_cmp(&b.0).then(a.1.cmp(&b.1)))
        else {
            continue;
        };
        // The rarest of `templates` shared ones is read, so its chance is
        // that of the smallest of that many.
        let templates = shared.len();
        let chance = crate::chance::sidak(rate * rate, templates);
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
            clusters: comparable,
            outside: outside_t,
            base_rate: rate,
            templates,
            chance,
            tested,
            expected_pairs: chance * tested as f64,
        });
    }
    let ps: Vec<f64> = out.iter().map(|p| p.chance).collect();
    let family = TestFamily::cut("scaffold", &ps, tested, opts.fdr);
    out.retain(|p| family.keeps(p.chance));
    crate::sort::by(&mut out, |p, q| {
        p.chance
            .total_cmp(&q.chance)
            .then(q.similarity.total_cmp(&p.similarity))
    });
    out.truncate(MAX_PAIRS);
    (out, family)
}

/// A handover within this many seconds reads as within it: the placement
/// model is not trusted to the second.
const HANDOVER_MIN_GAP_SECS: i64 = 3600;

/// Two clusters whose templates are one structural part apart beyond
/// chance, sharing no template outright: one harness changed mid-fleet.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LineagePair {
    /// Cluster ids, `a` the stronger.
    pub a: String,
    pub b: String,
    /// Shared lineage keys, the rarest first (a few).
    pub shared: Vec<String>,
    /// Kinds of part the two differ in (`parameter`, `encoding`, ...).
    pub changed: Vec<String>,
    /// Clusters above noise holding the rarest shared key, the comparable
    /// clusters, and records outside them carrying it.
    pub holders: usize,
    pub clusters: usize,
    pub outside: usize,
    /// That key's base rate, as for a scaffold template.
    pub base_rate: f64,
    /// Usable keys the two share.
    pub keys: usize,
    /// The chance that an unrelated cluster shares as many usable key
    /// families with one side as the other does, each family at its base
    /// rate (a Poisson-binomial tail); the larger of the two sides.
    pub scaffold_chance: f64,
    /// Seconds from one cluster's last request to the other's first.
    pub handover_gap_secs: i64,
    /// Chance of a handover that close (an hour at least) under random
    /// placement of the two spans over the comparable clusters' span.
    pub handover_chance: f64,
    /// The two combined ([`crate::chance::product_chance`]).
    pub chance: f64,
    /// Pairs compared, and pairs this unlikely expected among them.
    pub tested: usize,
    pub expected_pairs: f64,
}

impl LineagePair {
    pub fn detail(&self) -> String {
        format!(
            "{} template(s) one {} apart, the rarest in {} of {} comparable clusters and {} record(s) outside them, a base rate of {:.1e}; one started {:.1} h after the other ended (chance {:.1e} under random placement); chance {:.1e} ({:.2} such pairs expected among {} compared): one harness changed mid-fleet: {}",
            self.keys,
            if self.changed.is_empty() {
                "part".to_string()
            } else {
                self.changed.join(" or ")
            },
            self.holders,
            self.clusters,
            self.outside,
            self.base_rate,
            self.handover_gap_secs as f64 / 3600.0,
            self.handover_chance,
            self.chance,
            self.expected_pairs,
            self.tested,
            self.shared.first().map_or("", String::as_str)
        )
    }
}

/// The deletion neighbourhood of a template: its own key when it is
/// specific (`min_specificity` parts or more), and, when it has at least one
/// part more, one key per structural part dropped that leaves it specific.
/// Each key comes with the kind of part dropped (`None` for its own).
/// Two templates one part apart (a parameter added, dropped or changed in
/// kind, another encoding, payload set, route or cut) share a key.
pub fn lineage_keys(t: &Template, min_specificity: usize) -> Vec<(String, Option<&'static str>)> {
    let fmt = |skip: Option<usize>| {
        t.parts
            .iter()
            .enumerate()
            .filter(|(i, _)| Some(*i) != skip)
            .map(|(_, p)| format!("{}:{}", part_tag(p.kind), p.text))
            .collect::<Vec<_>>()
            .join(" | ")
    };
    let mut out = Vec::new();
    if t.specificity < min_specificity {
        return out;
    }
    out.push((fmt(None), None));
    if t.specificity > min_specificity {
        for (i, p) in t.parts.iter().enumerate() {
            if p.weight > 0 && t.specificity - p.weight >= min_specificity {
                out.push((fmt(Some(i)), Some(p.kind)));
            }
        }
    }
    out
}

/// A part's short label in a lineage key.
fn part_tag(kind: &str) -> &'static str {
    match kind {
        "route" => "via",
        "path" => "path",
        "parameter" => "q",
        "encoding" => "enc",
        "payloads" => "pay",
        _ => "cut",
    }
}

/// The chance that two spans of `a` and `b` seconds, placed independently
/// and uniformly over `span` seconds, fall one after the other with at most
/// `gap` between them: `(2 g G - G²) / ((span - a)(span - b))` with
/// `g = span - a - b` the free room and `G = min(gap, g)`.
pub(crate) fn handover_chance(span: i64, a: i64, b: i64, gap: i64) -> f64 {
    let (s, a, b) = (span as f64, a.max(0) as f64, b.max(0) as f64);
    let g = s - a - b;
    if g <= 0.0 || s - a <= 0.0 || s - b <= 0.0 {
        return 1.0;
    }
    let gg = (gap.max(0) as f64).min(g);
    ((2.0 * g * gg - gg * gg) / ((s - a) * (s - b))).clamp(0.0, 1.0)
}

/// Pairs of clusters above noise that share a lineage key ([`lineage_keys`])
/// but no specific template, beyond chance, most unlikely first, and the
/// family's multiplicity budget. Only pairs where one cluster ended before
/// the other started are tested. The scaffold settings apply: a key's base
/// rate is read as a template's, the same `max_holders` and `max_shared`
/// caps, `max_chance` and `fdr`. The handover reads request and submit
/// times only.
pub(crate) fn lineage_pairs(
    clusters: &[Cluster],
    results: &[ObsResult],
    max_shared: usize,
    opts: &ScaffoldOptions,
) -> (Vec<LineagePair>, TestFamily) {
    let family = "scaffold_lineage";
    let shown: Vec<&Cluster> = clusters.iter().filter(|c| c.tier > Tier::Noise).collect();
    if shown.len() < 3 {
        return (Vec::new(), TestFamily::cut(family, &[], 0, opts.fdr));
    }
    let min = opts.min_specificity;
    // Each cluster's specific templates, and its lineage keys with the kinds
    // of part dropped to reach each.
    let mut exact: Vec<BTreeSet<String>> = Vec::new();
    let mut spaces: Vec<BTreeMap<String, BTreeSet<&'static str>>> = Vec::new();
    for c in &shown {
        let (mut e, mut sp) = (BTreeSet::new(), BTreeMap::<String, BTreeSet<&str>>::new());
        for &i in &c.members {
            let t = template(&results[i]);
            if t.specificity >= min {
                e.insert(t.key.clone());
            }
            for (k, dropped) in lineage_keys(&t, min) {
                let kinds = sp.entry(k).or_default();
                kinds.extend(dropped);
            }
        }
        exact.push(e);
        spaces.push(sp);
    }
    let comparable = exact.iter().filter(|e| !e.is_empty()).count();
    let mut holders: BTreeMap<&str, Vec<usize>> = BTreeMap::new();
    for (ci, sp) in spaces.iter().enumerate() {
        for k in sp.keys() {
            holders.entry(k.as_str()).or_default().push(ci);
        }
    }
    // Records outside the clusters count as more holders, as for scaffolds.
    let mut inside = vec![false; results.len()];
    for c in &shown {
        for &m in &c.members {
            inside[m] = true;
        }
    }
    let mut outside_with: BTreeMap<String, usize> = BTreeMap::new();
    for (i, r) in results.iter().enumerate() {
        if inside[i] {
            continue;
        }
        let keys: BTreeSet<String> = lineage_keys(&template(r), min)
            .into_iter()
            .map(|(k, _)| k)
            .filter(|k| holders.contains_key(k.as_str()))
            .collect();
        for k in keys {
            *outside_with.entry(k).or_default() += 1;
        }
    }
    let outside = |k: &str| outside_with.get(k).copied().unwrap_or(0);
    let usable = |k: &str, ids: &[usize]| {
        ids.len() >= 2 && ids.len() <= max_shared && ids.len() + outside(k) <= opts.max_holders
    };
    let rate = |k: &str| -> f64 {
        ((holders[k].len() - 1 + outside(k)) as f64 / comparable.saturating_sub(1).max(1) as f64)
            .min(1.0)
    };
    // Candidates: pairs sharing a usable key and no specific template (a
    // pair sharing one is the scaffold test's).
    let mut candidates: BTreeSet<(usize, usize)> = BTreeSet::new();
    for (k, ids) in &holders {
        if usable(k, ids) {
            for (n, &x) in ids.iter().enumerate() {
                for &y in &ids[n + 1..] {
                    if exact[x].is_disjoint(&exact[y]) {
                        candidates.insert((x, y));
                    }
                }
            }
        }
    }
    // Each cluster's request span, and the comparable clusters' together.
    let spans: Vec<Option<(i64, i64)>> = shown
        .iter()
        .map(|c| {
            let ts = c
                .members
                .iter()
                .map(|&i| &results[i].obs)
                .filter(|o| o.ts > 0 && crate::timing::request_like(o.ts_kind));
            ts.fold(None, |acc: Option<(i64, i64)>, o| {
                Some(acc.map_or((o.ts, o.ts), |(s, e)| (s.min(o.ts), e.max(o.ts))))
            })
        })
        .collect();
    let whole = spans
        .iter()
        .zip(&exact)
        .filter(|(_, e)| !e.is_empty())
        .filter_map(|(s, _)| *s)
        .fold(None, |acc: Option<(i64, i64)>, (s, e)| {
            Some(acc.map_or((s, e), |(a, b)| (a.min(s), b.max(e))))
        });
    // A lineage is one harness before and after a change: only pairs where
    // one cluster's requests end before the other's start are tested, and the
    // gap between them is read.
    let gaps: BTreeMap<(usize, usize), (i64, f64)> = candidates
        .iter()
        .filter_map(|&(x, y)| {
            let ((s1, e1), (s2, e2), (ws, we)) = (spans[x]?, spans[y]?, whole?);
            if !(e1 < s2 || e2 < s1) {
                return None;
            }
            let gap = if e1 < s2 { s2 - e1 } else { s1 - e2 };
            let p = handover_chance(we - ws, e1 - s1, e2 - s2, gap.max(HANDOVER_MIN_GAP_SECS));
            Some(((x, y), (gap, p)))
        })
        .collect();
    let tested = gaps.len();
    // Each cluster's usable keys as families: keys held by the same clusters
    // are one template's neighbourhood seen several times and count once,
    // at the family's highest base rate.
    let families: Vec<BTreeMap<&[usize], f64>> = spaces
        .iter()
        .map(|sp| {
            let mut fam: BTreeMap<&[usize], f64> = BTreeMap::new();
            for k in sp.keys() {
                let ids = holders[k.as_str()].as_slice();
                if usable(k, ids) {
                    let e = fam.entry(ids).or_insert(0.0);
                    *e = e.max(rate(k));
                }
            }
            fam
        })
        .collect();
    let mut out = Vec::new();
    for (&(x, y), &(gap, handover)) in &gaps {
        let (sx, sy) = (&spaces[x], &spaces[y]);
        let mut shared: Vec<(&str, f64)> = sx
            .keys()
            .filter(|k| sy.contains_key(*k) && usable(k, &holders[k.as_str()]))
            .map(|k| (k.as_str(), rate(k)))
            .collect();
        crate::sort::by(&mut shared, |p, q| p.1.total_cmp(&q.1).then(p.0.cmp(q.0)));
        let Some(&(rarest, r)) = shared.first() else {
            continue;
        };
        // Conditioned on one side's key families, the chance that an
        // unrelated cluster holds as many of them as the other does, each at
        // its base rate; the larger of the two sides is read.
        let both = |c: usize, o: usize| {
            let rates: Vec<f64> = families[c].values().copied().collect();
            let met = families[c].keys().filter(|ids| ids.contains(&o)).count();
            crate::chance::at_least(&rates, met.max(1))
        };
        let scaffold_chance = both(x, y).max(both(y, x));
        // The templates must stand on their own; the handover only adds.
        if scaffold_chance > opts.max_chance {
            continue;
        }
        let chance = crate::chance::product_chance(scaffold_chance, handover);
        if chance > opts.max_chance {
            continue;
        }
        let changed: BTreeSet<&str> = sx[rarest].iter().chain(&sy[rarest]).copied().collect();
        out.push(LineagePair {
            a: shown[x].id.clone(),
            b: shown[y].id.clone(),
            shared: shared.iter().take(3).map(|(k, _)| k.to_string()).collect(),
            changed: changed.into_iter().map(String::from).collect(),
            holders: holders[rarest].len(),
            clusters: comparable,
            outside: outside(rarest),
            base_rate: r,
            keys: shared.len(),
            scaffold_chance,
            handover_gap_secs: gap,
            handover_chance: handover,
            chance,
            tested,
            expected_pairs: chance * tested as f64,
        });
    }
    let ps: Vec<f64> = out.iter().map(|p| p.chance).collect();
    let fam = TestFamily::cut(family, &ps, tested, opts.fdr);
    out.retain(|p| fam.keeps(p.chance));
    crate::sort::by(&mut out, |p, q| {
        p.chance
            .total_cmp(&q.chance)
            .then(p.a.cmp(&q.a))
            .then(p.b.cmp(&q.b))
    });
    out.truncate(MAX_PAIRS);
    (out, fam)
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

    /// `n` unflagged page fetches: the traffic a base rate is read against.
    fn unflagged(n: usize) -> Vec<Observation> {
        (0..n)
            .map(|i| {
                o(
                    &format!("u{i}"),
                    T0 + 86_400 * 50 + i as i64 * 37,
                    &format!("https://www.site{}.example/page/{}", i % 97, i % 13),
                )
            })
            .collect()
    }

    /// Three clusters on one harness, distinct tags, among twenty others,
    /// and `background` unflagged records.
    fn harness_fleet(background: usize) -> Vec<Observation> {
        let mut obs = fleet(3, harness);
        for (i, mut x) in fleet(20, other).into_iter().enumerate() {
            x.id = format!("bg{i}");
            x.ts += 86_400 * 100;
            obs.push(x);
        }
        obs.extend(unflagged(background));
        obs
    }

    #[test]
    fn one_scaffold_across_clusters_is_a_pair_with_its_chance() {
        let a = analyze(harness_fleet(0), &Rules::default_rules());
        assert_eq!(a.clusters.len(), 23, "{:?}", a.clusters.len());
        let p = &a.scaffold_pairs;
        assert_eq!(p.len(), 3, "{p:?}");
        // The other two holders among the other 22 comparable clusters; the
        // three pairs sharing it are the pairs compared.
        let rate = 2.0 / 22.0;
        for x in p {
            assert_eq!((x.holders, x.clusters, x.outside, x.tested), (3, 23, 0, 3));
            assert!((x.base_rate - rate).abs() < 1e-12, "{x:?}");
            assert!((x.chance - rate * rate).abs() < 1e-15, "{x:?}");
            assert!((x.expected_pairs - 3.0 * rate * rate).abs() < 1e-12);
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
    fn the_rarest_of_several_shared_templates_is_corrected_for_their_number() {
        // The same harness with a second request shape on alternate records:
        // two shared templates, so the rarest is the least of two.
        let two = |c: usize, k: usize| {
            if k == 1 {
                format!(
                    "https://h{k}.c{c}.example/api/v2/{}?cmd=%3Bid&uqtag=fx{c}{c}q{c}&step={k}",
                    300 + k
                )
            } else {
                harness(c, k)
            }
        };
        let mut obs = fleet(3, two);
        for (i, mut x) in fleet(40, other).into_iter().enumerate() {
            x.id = format!("bg{i}");
            x.ts += 86_400 * 200;
            obs.push(x);
        }
        let a = analyze(obs.clone(), &Rules::default_rules());
        let p = &a.scaffold_pairs;
        assert_eq!(p.len(), 3, "{p:?}");
        let r2 = (2.0f64 / 42.0).powi(2);
        for x in p {
            assert_eq!(x.templates, 2, "{x:?}");
            assert!(
                (x.chance - (1.0 - (1.0 - r2).powi(2))).abs() < 1e-12,
                "{x:?}"
            );
            assert!(
                x.detail().contains("2 shared template(s)"),
                "{}",
                x.detail()
            );
        }
        let f = a.multiplicity.iter().find(|f| f.family == "scaffold");
        assert_eq!(f.map(|f| (f.kept, f.tested)), Some((3, 3)), "{f:?}");
        // Among twenty others, one shared template would pass at (2 / 22)^2;
        // the least of two does not.
        obs.retain(|o| !o.id.starts_with("bg") || o.id[2..].parse::<usize>().unwrap() < 60);
        let b = analyze(obs, &Rules::default_rules());
        assert!(b.scaffold_pairs.is_empty(), "{:?}", b.scaffold_pairs);
    }

    #[test]
    fn unrelated_traffic_appended_changes_nothing() {
        // The same fleet with 3000 unrelated records appended: the same
        // pairs, at the same chances.
        let rules = Rules::default_rules();
        let a = analyze(harness_fleet(0), &rules);
        let b = analyze(harness_fleet(3000), &rules);
        assert_eq!(a.scaffold_pairs, b.scaffold_pairs);
        // And a common default stays common however much traffic follows.
        let mut obs = fleet(6, harness);
        for (i, mut x) in fleet(14, other).into_iter().enumerate() {
            x.id = format!("bg{i}");
            x.ts += 86_400 * 40;
            obs.push(x);
        }
        obs.extend(unflagged(5000));
        let c = analyze(obs, &rules);
        assert!(c.scaffold_pairs.is_empty(), "{:?}", c.scaffold_pairs);
    }

    #[test]
    fn a_few_clusters_cannot_make_a_shape_rare() {
        // Two harness clusters among three: one other comparable cluster,
        // so the shape's rate is at least a half.
        let mut obs = fleet(2, harness);
        for (i, mut x) in fleet(1, other).into_iter().enumerate() {
            x.id = format!("bg{i}");
            x.ts += 86_400 * 30;
            obs.push(x);
        }
        obs.extend(unflagged(3000));
        let a = analyze(obs, &Rules::default_rules());
        assert!(a.scaffold_pairs.is_empty(), "{:?}", a.scaffold_pairs);
    }

    #[test]
    fn pairs_are_cut_at_the_false_discovery_rate() {
        let mut rules = Rules::default_rules();
        rules.set.scaffold.fdr = 1e-9;
        let a = analyze(harness_fleet(0), &rules);
        assert!(a.scaffold_pairs.is_empty(), "{:?}", a.scaffold_pairs);
    }

    #[test]
    fn a_popular_shape_held_by_many_clusters_ties_none() {
        // Six operators on one framework's default shape, among forty
        // others: more holders than `max_holders`, a common default.
        let mut obs = fleet(6, harness);
        for (i, mut x) in fleet(40, other).into_iter().enumerate() {
            x.id = format!("bg{i}");
            x.ts += 86_400 * 40;
            obs.push(x);
        }
        let a = analyze(obs, &Rules::default_rules());
        assert_eq!(a.clusters.len(), 46);
        assert!(a.scaffold_pairs.is_empty(), "{:?}", a.scaffold_pairs);
        // Among eighty others its chance alone, (5 / 85)^2, would pass.
        let mut rules = Rules::default_rules();
        rules.set.scaffold.max_holders = 10;
        let mut obs = fleet(6, harness);
        for (i, mut x) in fleet(80, other).into_iter().enumerate() {
            x.id = format!("bg{i}");
            x.ts += 86_400 * 40;
            obs.push(x);
        }
        assert!(!analyze(obs, &rules).scaffold_pairs.is_empty());
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

    #[test]
    fn lineage_keys_meet_one_part_apart() {
        let a = analyze(fleet(1, harness), &Rules::default_rules());
        let v2 = |c: usize, k: usize| format!("{}&v=2", harness(c, k));
        let b = analyze(fleet(1, v2), &Rules::default_rules());
        let (ta, tb) = (template(&a.results[0]), template(&b.results[0]));
        assert_ne!(ta.key, tb.key);
        assert_eq!(tb.specificity, ta.specificity + 1);
        let ka: BTreeSet<String> = lineage_keys(&ta, 3).into_iter().map(|k| k.0).collect();
        let kb: Vec<(String, Option<&str>)> = lineage_keys(&tb, 3);
        // The newer template less its added parameter is the older one.
        let met: Vec<&(String, Option<&str>)> = kb.iter().filter(|(k, _)| ka.contains(k)).collect();
        assert_eq!(met.len(), 1, "{ka:?} {kb:?}");
        assert_eq!(met[0].1, Some("parameter"));
        assert!(!met[0].0.contains("example"));
        // A template at the floor has only its own key.
        let floor = Template {
            key: String::new(),
            specificity: 3,
            parts: ta.parts.clone(),
        };
        assert_eq!(lineage_keys(&floor, 3).len(), 1);
        assert!(lineage_keys(&floor, 4).is_empty());
    }

    #[test]
    fn handover_chance_under_random_placement() {
        // Two points in a unit span: P(|u - v| <= 0.1) = 1 - 0.9^2.
        let p = handover_chance(1000, 0, 0, 100);
        assert!((p - (1.0 - 0.81)).abs() < 1e-12, "{p}");
        // Any gap at all: they never overlap, so it is certain.
        assert!((handover_chance(1000, 0, 0, 1000) - 1.0).abs() < 1e-12);
        assert_eq!(handover_chance(1000, 600, 600, 10), 1.0);
    }

    #[test]
    fn a_harness_upgraded_mid_fleet_is_a_lineage_pair() {
        // One agent on the harness, then one on it with a parameter added,
        // days later, among 120 others: the two share no template, so no
        // scaffold pair joins them.
        let up = |c: usize, k: usize| {
            if c >= 1 {
                format!("{}&v=2", harness(c, k))
            } else {
                harness(c, k)
            }
        };
        let with_others = |n: usize| {
            let mut obs = fleet(n, up);
            for (i, mut x) in fleet(120, other).into_iter().enumerate() {
                x.id = format!("bg{i}");
                x.ts += 86_400 * 100;
                obs.push(x);
            }
            obs
        };
        let a = analyze(with_others(2), &Rules::default_rules());
        assert_eq!(a.clusters.len(), 122);
        assert!(a.scaffold_pairs.is_empty(), "{:?}", a.scaffold_pairs);
        let p = &a.lineage_pairs;
        assert_eq!(p.len(), 1, "{p:?}");
        let x = &p[0];
        assert_eq!(x.changed, ["parameter"]);
        assert_eq!((x.holders, x.clusters, x.tested), (2, 122, 1), "{x:?}");
        assert!((x.scaffold_chance - 1.0 / 121.0).abs() < 1e-12, "{x:?}");
        // The second started days after the first ended.
        assert!(
            x.handover_gap_secs > 86_400 && x.handover_chance < 0.05,
            "{x:?}"
        );
        let want = crate::chance::product_chance(x.scaffold_chance, x.handover_chance);
        assert!((x.chance - want).abs() < 1e-15, "{x:?}");
        assert!(x.detail().contains("one parameter apart"), "{}", x.detail());
        assert!(!x.detail().contains("example"), "{}", x.detail());
        assert!(
            a.soft_links
                .iter()
                .any(|l| l.kind == crate::fleets::SoftLinkKind::ScaffoldLineage),
            "{:?}",
            a.soft_links
        );
        let f = a
            .multiplicity
            .iter()
            .find(|f| f.family == "scaffold_lineage");
        assert_eq!(f.map(|f| (f.kept, f.tested)), Some((1, 1)), "{f:?}");
        // Six clusters on the two shapes are a common default: no tie.
        assert!(
            analyze(with_others(6), &Rules::default_rules())
                .lineage_pairs
                .is_empty()
        );
    }
}
