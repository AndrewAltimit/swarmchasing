//! Each soft-link kind's likelihood ratio, from simulated truth.
//!
//! Every kind is switched on at a nominal ratio, so each link the analysis
//! can draw is drawn, and each pair of clusters above noise, placed on two
//! distinct true runs, is counted as one operator's or not (two clusters of
//! one run are not what a soft link asks about). A kind's ratio is the
//! share of one operator's pairs it links over the share of unrelated
//! pairs it links, each with half a pair added (so a kind that never fires
//! on one side has a finite ratio). The ratios are the defaults the rules
//! file starts from; the simulator only copies request content, so a kind
//! it cannot produce (a captured secret, a header set) has no estimate.
//!
//! Pooled over scenarios, the unrelated pairs of a few crowded scenarios
//! (hundreds of agents, hundreds of thousands of pairs) swamp the rest and
//! make every kind look rarer among unrelated pairs than it is where one
//! operator's pairs are (Simpson's effect). So each scenario is also a
//! stratum: [`stratified`] is a Mantel-Haenszel ratio over the scenarios
//! where the kind fired and both kinds of pair exist, with a
//! Greenland-Robins interval, and its lower bound is the conservative value
//! the bundled ratios must not exceed ([`check_rules`]). A kind that links
//! unrelated pairs but no pair of one operator, where both exist, is
//! measured against: its bundled ratio may not exceed 1.
//!
//! Families multiply as if independent, which they are not where one fact
//! (running at the same time) draws links in two. So each pair's set of
//! linking kinds is kept too ([`Calibration::combos`]), and for each pair of
//! families [`stratified_joint`] is the Mantel-Haenszel ratio of both
//! firing together, counting only the kinds the rules switch on. Its lower
//! bound is the most a `[soft_links.joint]` cap may be ([`check_joint`]).

use crate::measure::majority;
use crate::{Palette, ScenarioFile, Truth, generate, to_ndjson};
use sc_core::eval::stats::wilson;
use sc_core::fleets::JointCaps;
use sc_core::{
    Analysis, Family, FieldMap, Format, Rules, SoftLinkKind, Tier, analyze, parse_input,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write;

/// The kinds linking one pair of clusters, each with the family it counts
/// in.
pub type Combo = BTreeSet<(Family, SoftLinkKind)>;

/// Pairs one kind linked.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct KindPairs {
    /// Pairs of one operator it linked.
    pub same: usize,
    /// Unrelated pairs it linked.
    pub other: usize,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Calibration {
    /// Pairs of clusters above noise, both placed on distinct runs, of one
    /// operator.
    pub same_pairs: usize,
    /// Pairs of clusters above noise, both placed, of different operators.
    pub other_pairs: usize,
    /// By kind.
    pub kinds: BTreeMap<SoftLinkKind, KindPairs>,
    /// By the set of kinds (each with the family it counts in) that link a
    /// pair: what the joint ratios are read from.
    #[serde(skip)]
    pub combos: BTreeMap<Combo, KindPairs>,
}

impl Calibration {
    pub fn add(&mut self, o: &Self) {
        self.same_pairs += o.same_pairs;
        self.other_pairs += o.other_pairs;
        for (k, v) in &o.kinds {
            let e = self.kinds.entry(*k).or_default();
            e.same += v.same;
            e.other += v.other;
        }
        for (k, v) in &o.combos {
            let e = self.combos.entry(k.clone()).or_default();
            e.same += v.same;
            e.other += v.other;
        }
    }

    /// Pairs linked in both families `f` and `g` by kinds `on` accepts.
    pub fn joint(&self, f: Family, g: Family, on: &dyn Fn(SoftLinkKind) -> bool) -> KindPairs {
        let mut out = KindPairs::default();
        for (set, n) in &self.combos {
            let fired = |x: Family| set.iter().any(|&(fam, k)| fam == x && on(k));
            if fired(f) && fired(g) {
                out.same += n.same;
                out.other += n.other;
            }
        }
        out
    }

    /// The most families `f` and `g` multiply to on any pair they link
    /// together: on each such pair, each family's largest ratio among its
    /// kinds `lr` switches on (above 1), multiplied. 1 when they never
    /// fire together.
    pub fn joint_product(&self, f: Family, g: Family, lr: &dyn Fn(SoftLinkKind) -> f64) -> f64 {
        let mut most: f64 = 1.0;
        for set in self.combos.keys() {
            let best = |x: Family| {
                set.iter()
                    .filter(|&&(fam, _)| fam == x)
                    .map(|&(_, k)| lr(k))
                    .fold(1.0, f64::max)
            };
            let (a, b) = (best(f), best(g));
            if a > 1.0 && b > 1.0 {
                most = most.max(a * b);
            }
        }
        most
    }

    /// The kind's likelihood ratio, `None` when it linked no pair of one
    /// operator.
    pub fn lr(&self, kind: SoftLinkKind) -> Option<f64> {
        let k = self.kinds.get(&kind)?;
        if k.same == 0 {
            return None;
        }
        let hit = (k.same as f64 + 0.5) / (self.same_pairs as f64 + 1.0);
        let miss = (k.other as f64 + 0.5) / (self.other_pairs as f64 + 1.0);
        Some(hit / miss)
    }

    /// A conservative ratio: the lower 95% Wilson bound of the share of one
    /// operator's pairs linked over the upper bound of the share of
    /// unrelated pairs linked. `None` when it linked no pair of one
    /// operator.
    pub fn lr_low(&self, kind: SoftLinkKind) -> Option<f64> {
        let k = self.kinds.get(&kind)?;
        if k.same == 0 {
            return None;
        }
        let (hit, _) = wilson(k.same, self.same_pairs)?;
        let (_, miss) = wilson(k.other, self.other_pairs)?;
        Some(hit / miss.max(f64::MIN_POSITIVE))
    }
}

/// Rules with every soft-link kind on at a nominal ratio and every link
/// listed.
pub fn open_rules(rules: &Rules) -> Rules {
    let mut set = rules.set.clone();
    for k in SoftLinkKind::ALL {
        set.soft_links.set_lr(k, 2.0);
    }
    set.soft_links.min_link_lr = 1.0;
    Rules::compile(set).expect("rules that compiled once compile again")
}

/// One analysis's pairs against truth. `a` should come from
/// [`open_rules`].
pub fn count(a: &Analysis, truth: &Truth) -> Calibration {
    let mut out = Calibration::default();
    // Each placed cluster's run and operator.
    let placed: BTreeMap<usize, (&str, String)> = (0..a.clusters.len())
        .filter(|&c| a.clusters[c].tier > Tier::Noise)
        .filter_map(|c| {
            let ids = a.clusters[c]
                .members
                .iter()
                .map(|&m| a.results[m].obs.id.as_str());
            let run = majority(truth, ids)?;
            // Any record of the run names its operator.
            let row = truth.rows.values().find(|r| r.run == run)?;
            Some((c, (run, row.operator())))
        })
        .collect();
    // One run split in two clusters is not the question a soft link
    // answers: such pairs count on neither side.
    let side = |x: usize, y: usize| -> Option<bool> {
        let (px, py) = (placed.get(&x)?, placed.get(&y)?);
        (px.0 != py.0).then_some(px.1 == py.1)
    };
    let ids: Vec<usize> = placed.keys().copied().collect();
    for (i, &x) in ids.iter().enumerate() {
        for &y in &ids[i + 1..] {
            match side(x, y) {
                Some(true) => out.same_pairs += 1,
                Some(false) => out.other_pairs += 1,
                None => {}
            }
        }
    }
    let mut seen: BTreeMap<SoftLinkKind, BTreeSet<(usize, usize)>> = BTreeMap::new();
    let mut sets: BTreeMap<(usize, usize), (bool, Combo)> = BTreeMap::new();
    for l in &a.soft_links {
        let (Some(x), Some(y)) = (a.cluster_index(&l.a), a.cluster_index(&l.b)) else {
            continue;
        };
        let Some(same) = side(x, y) else {
            continue;
        };
        sets.entry((x.min(y), x.max(y)))
            .or_insert_with(|| (same, BTreeSet::new()))
            .1
            .insert((l.family(), l.kind));
        if !seen.entry(l.kind).or_default().insert((x.min(y), x.max(y))) {
            continue;
        }
        let e = out.kinds.entry(l.kind).or_default();
        if same {
            e.same += 1;
        } else {
            e.other += 1;
        }
    }
    for (same, set) in sets.into_values() {
        let e = out.combos.entry(set).or_default();
        if same {
            e.same += 1;
        } else {
            e.other += 1;
        }
    }
    out
}

/// Every scenario of `file` under each of its seeds, with every kind on,
/// summed per scenario.
pub fn calibrate_by_scenario(
    file: &ScenarioFile,
    palette: &Palette,
    rules: &Rules,
) -> Vec<(String, Calibration)> {
    let open = open_rules(rules);
    let mut out = Vec::new();
    for s in &file.scenario {
        let mut total = Calibration::default();
        for k in 0..s.seeds.max(1) {
            let text = to_ndjson(&generate(s, s.seed + k as u64, palette));
            let obs = parse_input(&text, Format::Auto, &FieldMap::default()).observations;
            total.add(&count(&analyze(obs, &open), &Truth::from_ndjson(&text)));
        }
        out.push((s.name.clone(), total));
    }
    out
}

/// Every scenario of `file` under each of its seeds, with every kind on,
/// pooled.
pub fn calibrate(file: &ScenarioFile, palette: &Palette, rules: &Rules) -> Calibration {
    pool(&calibrate_by_scenario(file, palette, rules))
}

/// The strata summed.
pub fn pool(strata: &[(String, Calibration)]) -> Calibration {
    let mut total = Calibration::default();
    for (_, c) in strata {
        total.add(c);
    }
    total
}

/// A kind's ratio over strata (scenarios).
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Stratified {
    /// Strata counted: the kind fired in them, and they hold pairs of one
    /// operator and unrelated pairs.
    pub strata: usize,
    /// The Mantel-Haenszel ratio, half a pair added to each linked count
    /// and one pair to each total in every stratum counted.
    pub lr: f64,
    /// Its lower 95% bound (Greenland-Robins variance of the log ratio).
    pub low: f64,
}

/// The Mantel-Haenszel ratio of `kind` over the strata where it can occur:
/// those where it linked a pair, with pairs of one operator and unrelated
/// pairs. `None` when it linked no pair of one operator in any of them.
pub fn stratified(strata: &[(String, Calibration)], kind: SoftLinkKind) -> Option<Stratified> {
    mantel_haenszel(strata.iter().map(|(_, c)| {
        let k = c.kinds.get(&kind).cloned().unwrap_or_default();
        (k, c.same_pairs, c.other_pairs)
    }))
}

/// Families `f` and `g` firing together on a pair, by kinds the rules
/// switch on (ratio above 1), stratified as [`stratified`] is.
pub fn stratified_joint(
    strata: &[(String, Calibration)],
    f: Family,
    g: Family,
    rules: &Rules,
) -> Option<Stratified> {
    let on = |k: SoftLinkKind| rules.set.soft_links.lr(k) > 1.0;
    mantel_haenszel(
        strata
            .iter()
            .map(|(_, c)| (c.joint(f, g, &on), c.same_pairs, c.other_pairs)),
    )
}

/// Unrelated pairs linked in strata where no pair of one operator was,
/// though both kinds of pair exist: evidence a ratio is at or below 1.
/// Zero when any stratum links a pair of one operator.
pub fn against(strata: &[(String, Calibration)], kind: SoftLinkKind) -> usize {
    let usable = |c: &Calibration| c.same_pairs > 0 && c.other_pairs > 0;
    let k = |c: &Calibration| c.kinds.get(&kind).cloned().unwrap_or_default();
    if strata.iter().any(|(_, c)| usable(c) && k(c).same > 0) {
        return 0;
    }
    strata
        .iter()
        .filter(|(_, c)| usable(c))
        .map(|(_, c)| k(c).other)
        .sum()
}

/// The Mantel-Haenszel ratio over strata of (pairs linked, pairs of one
/// operator, unrelated pairs).
fn mantel_haenszel(rows: impl Iterator<Item = (KindPairs, usize, usize)>) -> Option<Stratified> {
    let (mut r, mut s, mut v, mut n, mut hits) = (0.0, 0.0, 0.0, 0, 0);
    for (k, same_pairs, other_pairs) in rows {
        if k.same + k.other == 0 || same_pairs == 0 || other_pairs == 0 {
            continue;
        }
        n += 1;
        hits += k.same;
        let (a, b) = (k.same as f64 + 0.5, k.other as f64 + 0.5);
        let (n1, n0) = (same_pairs as f64 + 1.0, other_pairs as f64 + 1.0);
        let t = n1 + n0;
        r += a * n0 / t;
        s += b * n1 / t;
        v += (n1 * n0 * (a + b) / (t * t) - a * b / t).max(0.0);
    }
    if hits == 0 || r <= 0.0 || s <= 0.0 {
        return None;
    }
    let lr = r / s;
    let se = (v / (r * s)).sqrt();
    Some(Stratified {
        strata: n,
        lr,
        low: lr * (-sc_core::eval::stats::Z95 * se).exp(),
    })
}

/// One kind's bundled ratio against the stratified lower bound.
#[derive(Debug, Clone, PartialEq)]
pub struct RuleCheck {
    pub kind: SoftLinkKind,
    pub bundled: f64,
    /// The stratified lower bound; `None` when no scenario measures the
    /// kind.
    pub low: Option<f64>,
    /// The reason the calibration config gives for a ratio above 1 that no
    /// scenario measures.
    pub allowed: Option<String>,
    /// Unrelated pairs it linked where it linked no pair of one operator
    /// ([`against`]): measured, and against any ratio above 1.
    pub against: usize,
    pub ok: bool,
}

impl RuleCheck {
    /// Unmeasured, with a ratio above 1 and no reason given: a ratio the
    /// rules claim that nothing supports.
    pub fn unmeasured(&self) -> bool {
        self.low.is_none() && self.against == 0 && self.allowed.is_none()
    }

    /// The check as one line: `ok`, `FAIL` (above the bound), `UNMEASURED`
    /// or `allowed` (unmeasured, with its reason).
    pub fn line(&self) -> String {
        let name = kind_name(self.kind);
        if self.low.is_none() && self.against > 0 {
            return format!(
                "{} {name}: rules {:.2}, links {} unrelated pair(s) and no pair of one operator, so its ratio may not exceed 1",
                if self.ok { "ok  " } else { "FAIL" },
                self.bundled,
                self.against
            );
        }
        match (self.low, &self.allowed) {
            (Some(low), allowed) => format!(
                "{} {name}: rules {:.2}, stratified lower bound {low:.2}{}",
                if self.ok { "ok  " } else { "FAIL" },
                self.bundled,
                if allowed.is_some() {
                    " (measured now: drop it from calibration.unmeasured)"
                } else {
                    ""
                }
            ),
            (None, Some(why)) => format!(
                "allowed {name}: rules {:.2}, no scenario measures it ({why})",
                self.bundled
            ),
            (None, None) => format!(
                "UNMEASURED {name}: rules {:.2}, no scenario measures it and calibration.unmeasured gives no reason",
                self.bundled
            ),
        }
    }
}

/// Every kind the strata measure: its ratio in `rules` must be at or below
/// the stratified lower bound, so no bundled ratio claims more than the
/// simulation shows. Every kind with a ratio above 1 that no stratum
/// measures fails as unmeasured, unless `allowed` (the calibration config's
/// `unmeasured` table, kind name to reason) names it. A kind that links only
/// unrelated pairs ([`against`]) is measured: a ratio above 1 fails whatever
/// `allowed` says. A measured kind that `allowed` still names fails too:
/// the entry is stale and must be dropped.
pub fn check_rules(
    strata: &[(String, Calibration)],
    rules: &Rules,
    allowed: &BTreeMap<String, String>,
) -> Vec<RuleCheck> {
    SoftLinkKind::ALL
        .into_iter()
        .filter_map(|k| {
            let bundled = rules.set.soft_links.lr(k);
            let allowed = allowed.get(&kind_name(k)).cloned();
            match stratified(strata, k) {
                Some(st) => Some(RuleCheck {
                    kind: k,
                    bundled,
                    low: Some(st.low),
                    ok: bundled <= st.low + 1e-9 && allowed.is_none(),
                    allowed,
                    against: 0,
                }),
                None if bundled > 1.0 => {
                    let against = against(strata, k);
                    Some(RuleCheck {
                        kind: k,
                        bundled,
                        low: None,
                        ok: against == 0 && allowed.is_some(),
                        allowed,
                        against,
                    })
                }
                None => None,
            }
        })
        .collect()
}

/// One family pair's joint cap against the measured joint ratio.
#[derive(Debug, Clone, PartialEq)]
pub struct JointCheck {
    pub f: Family,
    pub g: Family,
    /// The cap `[soft_links.joint]` sets, if any.
    pub cap: Option<f64>,
    /// The most the two families multiply to without a cap on a pair the
    /// simulation links in both ([`Calibration::joint_product`]).
    pub product: f64,
    /// The stratified joint ratio; `None` when no scenario links a pair of
    /// one operator in both families.
    pub measured: Option<Stratified>,
    pub ok: bool,
}

impl JointCheck {
    /// The check as one line: `ok`, `FAIL` (a cap above the bound, or no
    /// cap where the product exceeds it), `note` (co-fires, no cap, the
    /// product within the bound) or `allowed` (a cap no scenario measures:
    /// it only lowers ratios).
    pub fn line(&self) -> String {
        let key = JointCaps::key(self.f, self.g);
        match (self.cap, self.measured) {
            (Some(cap), Some(st)) => format!(
                "{} joint {key}: cap {cap:.2}, stratified joint lower bound {:.2} ({} strata)",
                if self.ok { "ok  " } else { "FAIL" },
                st.low,
                st.strata
            ),
            (Some(cap), None) => format!(
                "allowed joint {key}: cap {cap:.2}, no scenario links a pair of one operator in both (a cap only lowers ratios)"
            ),
            (None, Some(st)) if self.ok => format!(
                "note joint {key}: co-fires with no cap; the independent product {:.2} is within the stratified joint lower bound {:.2}",
                self.product, st.low
            ),
            (None, Some(st)) => format!(
                "FAIL joint {key}: co-fires with no cap; the independent product {:.2} is above the stratified joint lower bound {:.2}: set [soft_links.joint] {key} at or below it",
                self.product, st.low
            ),
            (None, None) => format!("ok   joint {key}: no cap, never co-fires"),
        }
    }
}

/// Every family pair that co-fires on a pair of one operator, or has a cap:
/// a cap above the stratified joint lower bound fails, and so does a missing
/// cap where the two families' independent product on a pair they link
/// together ([`Calibration::joint_product`]) exceeds that bound,
/// since then the rules claim more than the simulation shows, as a kind's
/// ratio above its bound would. A missing cap the product stays within is
/// noted: a cap there would change nothing. A cap no scenario measures
/// passes, since a cap only lowers ratios.
pub fn check_joint(strata: &[(String, Calibration)], rules: &Rules) -> Vec<JointCheck> {
    let caps = &rules.set.soft_links.joint;
    let all = pool(strata);
    let lr = |k: SoftLinkKind| rules.set.soft_links.lr(k);
    let mut out = Vec::new();
    for (i, &f) in Family::ALL.iter().enumerate() {
        for &g in &Family::ALL[i + 1..] {
            let cap = caps.get(f, g);
            let measured = stratified_joint(strata, f, g, rules);
            if cap.is_none() && measured.is_none() {
                continue;
            }
            let product = all.joint_product(f, g, &lr);
            let ok = match (cap, measured) {
                (Some(c), Some(st)) => c <= st.low + 1e-9,
                (None, Some(st)) => product <= st.low + 1e-9,
                _ => true,
            };
            out.push(JointCheck {
                f,
                g,
                cap,
                product,
                measured,
                ok,
            });
        }
    }
    out
}

/// The serialised name of a kind (`co_target`).
fn kind_name(k: SoftLinkKind) -> String {
    serde_json::to_value(k)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_default()
}

/// The calibration as a table, with each kind's pooled ratio, its
/// stratified ratio over the scenarios where it can occur, and the ratio
/// `rules` sets now; then each kind's ratio per scenario.
pub fn render_stratified(strata: &[(String, Calibration)], rules: &Rules) -> String {
    let c = pool(strata);
    let mut s = render_calibration(&c, rules);
    let _ = writeln!(
        s,
        "\nStratified by scenario (Mantel-Haenszel over the scenarios where the kind fired and both kinds of pair exist; low: the lower 95% bound, the value no bundled ratio may exceed):\n"
    );
    let _ = writeln!(
        s,
        "  {:<18} {:>7} {:>10} {:>8} {:>8}",
        "kind", "strata", "ratio", "low", "rules"
    );
    for k in SoftLinkKind::ALL {
        let Some(st) = stratified(strata, k) else {
            continue;
        };
        let _ = writeln!(
            s,
            "  {:<18} {:>7} {:>10.1} {:>8.1} {:>8.1}",
            kind_name(k),
            st.strata,
            st.lr,
            st.low,
            rules.set.soft_links.lr(k)
        );
    }
    let _ = writeln!(
        s,
        "\nFamily pairs firing together, by kinds the rules switch on (stratified as above; cap: [soft_links.joint]; product: the most the two multiply to on a pair they link together, under the rules' ratios; then each scenario's one operator's pairs linked / pairs, unrelated linked / pairs):\n"
    );
    let _ = writeln!(
        s,
        "  {:<22} {:>6} {:>7} {:>7} {:>10} {:>8} {:>8} {:>9}",
        "families", "same", "other", "strata", "ratio", "low", "cap", "product"
    );
    let on = |k: SoftLinkKind| rules.set.soft_links.lr(k) > 1.0;
    let all = pool(strata);
    for (i, &f) in Family::ALL.iter().enumerate() {
        for &g in &Family::ALL[i + 1..] {
            let p = all.joint(f, g, &on);
            if p.same + p.other == 0 {
                continue;
            }
            let st = stratified_joint(strata, f, g, rules);
            let num = |x: Option<f64>| x.map_or_else(|| "-".to_string(), |x| format!("{x:.1}"));
            let _ = writeln!(
                s,
                "  {:<22} {:>6} {:>7} {:>7} {:>10} {:>8} {:>8} {:>9.1}",
                JointCaps::key(f, g),
                p.same,
                p.other,
                st.map_or(0, |x| x.strata),
                num(st.map(|x| x.lr)),
                num(st.map(|x| x.low)),
                num(rules.set.soft_links.joint.get(f, g)),
                all.joint_product(f, g, &|k| rules.set.soft_links.lr(k)),
            );
        }
    }
    for (i, &f) in Family::ALL.iter().enumerate() {
        for &g in &Family::ALL[i + 1..] {
            let rows: Vec<String> = strata
                .iter()
                .filter_map(|(name, c)| {
                    let p = c.joint(f, g, &on);
                    (p.same + p.other > 0).then(|| {
                        format!(
                            "{name} {}/{} {}/{}",
                            p.same, c.same_pairs, p.other, c.other_pairs
                        )
                    })
                })
                .collect();
            if !rows.is_empty() {
                let _ = writeln!(s, "  {}: {}", JointCaps::key(f, g), rows.join("; "));
            }
        }
    }
    let _ = writeln!(
        s,
        "\nPer scenario (one operator's pairs linked / pairs, unrelated linked / pairs, ratio):"
    );
    for k in SoftLinkKind::ALL {
        let rows: Vec<String> = strata
            .iter()
            .filter_map(|(name, c)| {
                let p = c.kinds.get(&k)?;
                if p.same + p.other == 0 {
                    return None;
                }
                let lr = c
                    .lr(k)
                    .map_or_else(|| "-".to_string(), |x| format!("{x:.1}"));
                Some(format!(
                    "{name} {}/{} {}/{} {lr}",
                    p.same, c.same_pairs, p.other, c.other_pairs
                ))
            })
            .collect();
        if !rows.is_empty() {
            let _ = writeln!(s, "  {}: {}", kind_name(k), rows.join("; "));
        }
    }
    s
}

/// The calibration as a table, with each kind's ratio and the ratio
/// `rules` sets now.
pub fn render_calibration(c: &Calibration, rules: &Rules) -> String {
    let mut s = String::new();
    let _ = writeln!(
        s,
        "Pairs of clusters above noise on distinct runs: {} of one operator, {} unrelated.\nRatio: share of one operator's pairs linked over share of unrelated pairs linked (half a pair added to each). Low: the lower 95% bound of the first share over the upper bound of the second, the value the rules start from.\n",
        c.same_pairs, c.other_pairs
    );
    let _ = writeln!(
        s,
        "  {:<18} {:<12} {:>6} {:>7} {:>10} {:>8} {:>8}",
        "kind", "family", "same", "other", "ratio", "low", "rules"
    );
    for k in SoftLinkKind::ALL {
        let p = c.kinds.get(&k).cloned().unwrap_or_default();
        let lr = c
            .lr(k)
            .map_or_else(|| "-".to_string(), |x| format!("{x:.1}"));
        let low = c
            .lr_low(k)
            .map_or_else(|| "-".to_string(), |x| format!("{x:.1}"));
        let _ = writeln!(
            s,
            "  {:<18} {:<12} {:>6} {:>7} {:>10} {:>8} {:>8}",
            kind_name(k),
            k.family().label(),
            p.same,
            p.other,
            lr,
            low,
            format!("{:.1}", rules.set.soft_links.lr(k)),
        );
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ratios_follow_the_counts() {
        let mut c = Calibration {
            same_pairs: 9,
            other_pairs: 99,
            ..Default::default()
        };
        c.kinds
            .insert(SoftLinkKind::CoTarget, KindPairs { same: 4, other: 0 });
        c.kinds
            .insert(SoftLinkKind::Encoding, KindPairs { same: 0, other: 30 });
        let lr = c.lr(SoftLinkKind::CoTarget).unwrap();
        assert!((lr - (4.5 / 10.0) / (0.5 / 100.0)).abs() < 1e-9, "{lr}");
        assert_eq!(c.lr(SoftLinkKind::Encoding), None);
        let low = c.lr_low(SoftLinkKind::CoTarget).unwrap();
        assert!(low > 1.0 && low < lr, "{low}");
        assert_eq!(c.lr(SoftLinkKind::Scaffold), None);
        let open = open_rules(&Rules::default_rules());
        assert_eq!(open.set.soft_links.lr(SoftLinkKind::RelayStack), 2.0);
        assert_eq!(open.set.soft_links.min_link_lr, 1.0);
    }

    fn stratum(same_pairs: usize, other_pairs: usize, same: usize, other: usize) -> Calibration {
        let mut c = Calibration {
            same_pairs,
            other_pairs,
            ..Default::default()
        };
        c.kinds
            .insert(SoftLinkKind::Dialect, KindPairs { same, other });
        c
    }

    #[test]
    fn a_crowded_stratum_does_not_inflate_the_stratified_ratio() {
        // One small scenario where the kind fires on a third of either kind
        // of pair (no evidence), and a crowd where it never fires.
        let strata = vec![
            ("small".to_string(), stratum(30, 300, 10, 100)),
            ("crowd".to_string(), stratum(3, 300_000, 0, 0)),
        ];
        let pooled = pool(&strata).lr(SoftLinkKind::Dialect).unwrap();
        assert!(pooled > 100.0, "{pooled}");
        let st = stratified(&strata, SoftLinkKind::Dialect).unwrap();
        assert_eq!(st.strata, 1);
        assert!((0.8..1.3).contains(&st.lr), "{st:?}");
        assert!(st.low < st.lr);
        // A kind that never fires on one operator's pairs has no estimate.
        let none = vec![("x".to_string(), stratum(30, 300, 0, 20))];
        assert_eq!(stratified(&none, SoftLinkKind::Dialect), None);
        assert_eq!(stratified(&strata, SoftLinkKind::Scaffold), None);
    }

    #[test]
    fn a_bundled_ratio_above_the_stratified_bound_fails() {
        let strata = vec![("s".to_string(), stratum(30, 300, 10, 100))];
        let mut set = Rules::default_rules().set.clone();
        // Every other kind off, so only the measured one is checked.
        for k in SoftLinkKind::ALL {
            set.soft_links.set_lr(k, 1.0);
        }
        set.soft_links.set_lr(SoftLinkKind::Dialect, 0.5);
        let none = BTreeMap::new();
        let low = Rules::compile(set.clone()).unwrap();
        let c = check_rules(&strata, &low, &none);
        assert_eq!(c.len(), 1);
        assert!(c[0].ok, "{c:?}");
        set.soft_links.set_lr(SoftLinkKind::Dialect, 20.0);
        let c = check_rules(&strata, &Rules::compile(set).unwrap(), &none);
        assert!(!c[0].ok, "{c:?}");
        assert!(c[0].line().starts_with("FAIL dialect"), "{}", c[0].line());
    }

    #[test]
    fn a_kind_linking_only_unrelated_pairs_is_measured_against() {
        // Fires on unrelated pairs only, where pairs of one operator exist.
        let strata = vec![
            ("s".to_string(), stratum(30, 300, 0, 12)),
            // No pairs of one operator here: says nothing.
            ("t".to_string(), stratum(0, 300, 0, 5)),
        ];
        assert_eq!(stratified(&strata, SoftLinkKind::Dialect), None);
        assert_eq!(against(&strata, SoftLinkKind::Dialect), 12);
        let mut set = Rules::default_rules().set.clone();
        for k in SoftLinkKind::ALL {
            set.soft_links.set_lr(k, 1.0);
        }
        set.soft_links.set_lr(SoftLinkKind::Dialect, 3.0);
        let mut allowed = BTreeMap::new();
        allowed.insert("dialect".to_string(), "a stale reason".to_string());
        let rules = Rules::compile(set.clone()).unwrap();
        let c = check_rules(&strata, &rules, &allowed);
        assert_eq!(c.len(), 1, "{c:?}");
        assert!(!c[0].ok && !c[0].unmeasured(), "{c:?}");
        assert!(c[0].line().starts_with("FAIL dialect"), "{}", c[0].line());
        assert!(c[0].line().contains("may not exceed 1"), "{}", c[0].line());
        // At 1 it is off and passes.
        set.soft_links.set_lr(SoftLinkKind::Dialect, 1.0);
        let c = check_rules(&strata, &Rules::compile(set).unwrap(), &allowed);
        assert!(c.iter().all(|c| c.ok), "{c:?}");
        // One pair of one operator anywhere makes it a measured ratio again.
        let mixed = vec![
            ("s".to_string(), stratum(30, 300, 0, 12)),
            ("u".to_string(), stratum(30, 300, 1, 0)),
        ];
        assert_eq!(against(&mixed, SoftLinkKind::Dialect), 0);
    }

    /// A stratum where `same` pairs of one operator and `other` unrelated
    /// pairs are linked by co-activity and co-targets together.
    fn joint_stratum(same: usize, other: usize) -> Calibration {
        let mut c = Calibration {
            same_pairs: 30,
            other_pairs: 3000,
            ..Default::default()
        };
        let set: BTreeSet<(Family, SoftLinkKind)> = [
            (Family::Timeline, SoftLinkKind::CoActivity),
            (Family::Targets, SoftLinkKind::CoTarget),
        ]
        .into();
        c.combos.insert(set, KindPairs { same, other });
        // A pair linked by co-targets alone does not count jointly.
        let one: BTreeSet<_> = [(Family::Targets, SoftLinkKind::CoTarget)].into();
        c.combos.insert(one, KindPairs { same: 5, other: 5 });
        c
    }

    #[test]
    fn joint_caps_are_checked_against_the_stratified_joint_ratio() {
        let strata = vec![("s".to_string(), joint_stratum(10, 3))];
        let mut set = Rules::default_rules().set.clone();
        set.soft_links.joint = JointCaps::default();
        let rules = Rules::compile(set.clone()).unwrap();
        let on = |k: SoftLinkKind| rules.set.soft_links.lr(k) > 1.0;
        let p = strata[0].1.joint(Family::Timeline, Family::Targets, &on);
        assert_eq!((p.same, p.other), (10, 3));
        let st = stratified_joint(&strata, Family::Targets, Family::Timeline, &rules).unwrap();
        assert!(st.low > 1.0 && st.low < 25.0 * 34.0, "{st:?}");
        // No cap, and the independent product is above the bound: fails.
        let c = check_joint(&strata, &rules);
        assert_eq!(c.len(), 1, "{c:?}");
        assert!((c[0].product - 25.0 * 34.0).abs() < 1e-9);
        assert!(!c[0].ok, "{c:?}");
        assert!(c[0].line().starts_with("FAIL joint timeline_targets"));
        // A cap at the bound passes; above it fails.
        set.soft_links
            .joint
            .set(Family::Timeline, Family::Targets, Some(st.low.floor()));
        let c = check_joint(&strata, &Rules::compile(set.clone()).unwrap());
        assert!(c[0].ok && c[0].line().starts_with("ok"), "{c:?}");
        set.soft_links
            .joint
            .set(Family::Timeline, Family::Targets, Some(st.low * 2.0));
        let c = check_joint(&strata, &Rules::compile(set.clone()).unwrap());
        assert!(!c[0].ok, "{c:?}");
        // With a kind switched off, the families never fire together: only
        // the cap is listed, and a cap nothing measures passes.
        set.soft_links.set_lr(SoftLinkKind::CoActivity, 1.0);
        let c = check_joint(&strata, &Rules::compile(set.clone()).unwrap());
        assert_eq!(c.len(), 1, "{c:?}");
        assert!(c[0].ok && c[0].measured.is_none(), "{c:?}");
        assert!(c[0].line().starts_with("allowed"), "{}", c[0].line());
        // Co-firing within the product: noted, not failed.
        let mut set = Rules::default_rules().set.clone();
        set.soft_links.joint = JointCaps::default();
        set.soft_links.co_activity = 2.0;
        set.soft_links.co_target = 2.0;
        let strata = vec![("s".to_string(), joint_stratum(20, 0))];
        let c = check_joint(&strata, &Rules::compile(set).unwrap());
        assert!(c[0].ok && c[0].line().starts_with("note"), "{c:?}");
        // The counts add across scenarios.
        let mut a = joint_stratum(1, 1);
        a.add(&joint_stratum(2, 3));
        let p = a.joint(Family::Timeline, Family::Targets, &|_| true);
        assert_eq!((p.same, p.other), (3, 4));
    }

    #[test]
    fn a_ratio_no_scenario_measures_fails_unless_a_reason_is_given() {
        let strata = vec![("s".to_string(), stratum(30, 300, 10, 100))];
        let mut set = Rules::default_rules().set.clone();
        for k in SoftLinkKind::ALL {
            set.soft_links.set_lr(k, 1.0);
        }
        set.soft_links.set_lr(SoftLinkKind::Dialect, 0.5);
        set.soft_links.set_lr(SoftLinkKind::Rerun, 25.0);
        set.soft_links.set_lr(SoftLinkKind::HeaderSet, 2.0);
        let rules = Rules::compile(set).unwrap();
        let mut allowed = BTreeMap::new();
        allowed.insert("header_set".to_string(), "no header sets".to_string());
        let c = check_rules(&strata, &rules, &allowed);
        let by = |k| c.iter().find(|c| c.kind == k).unwrap();
        // A kind at 1 or below is off: nothing to check.
        assert_eq!(c.len(), 3, "{c:?}");
        let rerun = by(SoftLinkKind::Rerun);
        assert!(!rerun.ok && rerun.unmeasured(), "{rerun:?}");
        assert!(rerun.line().starts_with("UNMEASURED rerun: rules 25.00"));
        let hs = by(SoftLinkKind::HeaderSet);
        assert!(hs.ok && !hs.unmeasured(), "{hs:?}");
        assert!(hs.line().contains("(no header sets)"), "{}", hs.line());
        // A measured kind is checked whatever the allow-list says, and an
        // allow-list entry for it is stale: it fails until dropped.
        allowed.insert("dialect".to_string(), "stale".to_string());
        let c = check_rules(&strata, &rules, &allowed);
        let d = c.iter().find(|c| c.kind == SoftLinkKind::Dialect).unwrap();
        assert!(
            !d.ok && d.line().starts_with("FAIL dialect"),
            "{}",
            d.line()
        );
        assert!(d.line().contains("drop it"), "{}", d.line());
    }
}
