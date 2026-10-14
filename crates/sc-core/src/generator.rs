//! Identifier generators: clusters whose generated identifiers come from one
//! machine, process or counter, though no identifier is shared.
//!
//! A fleet that gives each agent a fresh run tag defeats linking on the tag.
//! How the tags were generated often survives: a time-based UUID carries the
//! generating host's node id, a Snowflake id its worker and datacenter, a
//! time-ordered id (UUIDv7, ULID, KSUID) its generator's clock, and a counter
//! the next number. Each strong-parameter value, and each UUID-shaped
//! parameter value, is decoded:
//!
//! - **UUIDv1 and v6**: the node id and the timestamp. A node with the
//!   multicast bit set is random by RFC 9562, and one with the locally
//!   administered bit set is no vendor's assignment (a container bridge
//!   gives the first container on every host one address): neither ties
//!   anything.
//! - **UUIDv7, ULID, KSUID**: the embedded time.
//! - **Snowflake** (a 64-bit decimal): the 5-bit datacenter and 5-bit worker,
//!   read under the Twitter or Discord epoch when the embedded time falls
//!   within `max_skew_secs` of the record.
//! - **Counters** (a strong-parameter value ending in three or more digits,
//!   at least 100): the stem and the number.
//!
//! A ULID, KSUID or Snowflake whose embedded time is more than
//! `max_skew_secs` from its record's is not read as one: a random token of
//! that shape almost never decodes to a time so close.
//!
//! Four keys tie two clusters above noise:
//!
//! - **node**: one node id. Its chance between unrelated generators is
//!   `2^-47`; a node id on cloned images or a shared builder is carried by
//!   many, so a key carried by more than `max_holders` senders (clusters, and
//!   records outside them) ties none. A node id seen only in URLs of one
//!   target site, outside a strong parameter, is that site's own and ties
//!   none either.
//! - **worker**: one Snowflake datacenter and worker under one epoch, chance
//!   `2^-10`.
//! - **skew**: each cluster's clock skew, the embedded times minus the time
//!   each value was first seen, read from strong-parameter values only (an
//!   id in a path or an ordinary parameter may be one the target site
//!   minted, and agents fetching a fresh one would share its skew), when
//!   the cluster has values first seen at two or more times and every such
//!   value agrees within `skew_tolerance_secs`. One value, such as a single
//!   run tag, reads the clock offset plus the wait between minting it and
//!   first sending it, and a few minutes' wait looks like a few minutes'
//!   skew; readings at several times that agree are a constant offset, as
//!   a wait rarely is. Skews under `min_skew_secs` are ordinary
//!   clocks, and skews within the tolerance of a whole quarter hour are
//!   time-zone errors many machines share; neither ties. Two skews within
//!   the tolerance tie, at the chance of an unrelated skew landing that
//!   close under a fixed prior: magnitudes log-uniform between
//!   `min_skew_secs` and `max_skew_secs`, either sign, so a skew of minutes
//!   is commoner than one of hours and ties less.
//! - **counter**: one parameter and stem, the numbers of one cluster within
//!   `counter_max_gap` of the other's, at the chance of numbers of that many
//!   digits meeting that closely.
//!
//! A pair's chance is the smallest of its keys', corrected for the number
//! it shares (Sidak); kept at `max_chance` and cut at false discovery rate
//! `fdr` over the pairs compared: any two clusters with node ids, with
//! Snowflake workers or with skews, and any two counters on one stem. A
//! node id is a device identifier: the analysis never stores or shows it,
//! nor anything computed from it alone (a 48-bit id with a known vendor
//! prefix is few guesses from any short hash). It is shown as an ordinal
//! label, `node A`, `node B`, given in order of first appearance among the
//! analysis's records, so one node reads the same across pairs of one
//! analysis and means nothing outside it. Pairs are soft links: they never
//! score, link or merge.

use crate::analyze::{Cluster, ObsResult};
use crate::chance::TestFamily;
use crate::model::{LinkFeature, Tier};
use crate::timing::request_like;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// Generator settings (`[generator]` in the rules file).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct GeneratorOptions {
    /// An embedded time further than this from its record's is no time.
    pub max_skew_secs: i64,
    /// A clock skew under this is an ordinary clock.
    pub min_skew_secs: i64,
    /// Two skews within this are one clock.
    pub skew_tolerance_secs: i64,
    /// Counter numbers of two clusters at most this far apart are one
    /// counter's.
    pub counter_max_gap: u64,
    /// A key carried by more senders than this ties none.
    pub max_holders: usize,
    pub max_chance: f64,
    /// Benjamini-Hochberg false discovery rate over the pairs that could
    /// share a key.
    pub fdr: f64,
}

impl Default for GeneratorOptions {
    fn default() -> Self {
        Self {
            max_skew_secs: 172_800,
            min_skew_secs: 60,
            skew_tolerance_secs: 2,
            counter_max_gap: 3,
            max_holders: 10,
            max_chance: 0.01,
            fdr: 0.05,
        }
    }
}

/// Pairs kept, most unlikely first.
const MAX_PAIRS: usize = 200;
/// Snowflake epochs, Unix milliseconds.
const EPOCHS: [(&str, i64); 2] = [
    ("Twitter", 1_288_834_974_657),
    ("Discord", 1_420_070_400_000),
];
/// The KSUID epoch, Unix seconds.
const KSUID_EPOCH: i64 = 1_400_000_000;
/// 100-nanosecond intervals from the Gregorian epoch to the Unix epoch.
const GREGORIAN_OFFSET: i64 = 122_192_928_000_000_000;
/// Skews this close to a whole quarter hour are time-zone errors.
const ZONE_STEP_MS: i64 = 900_000;
/// Smallest counter number read: small numbers are where unrelated counters
/// start.
const COUNTER_MIN: u64 = 100;

/// Two clusters whose generated identifiers come from one generator beyond
/// chance.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GeneratorPair {
    /// Cluster ids, `a` the stronger.
    pub a: String,
    pub b: String,
    /// What they share, one line each: a node id's label in this analysis,
    /// a Snowflake worker, a clock skew, a counter's stem.
    pub keys: Vec<String>,
    /// The smallest key chance, corrected for the number shared.
    pub chance: f64,
    /// Pairs that could share a key, and pairs this unlikely expected among
    /// them.
    pub tested: usize,
    pub expected_pairs: f64,
}

impl GeneratorPair {
    pub fn detail(&self) -> String {
        format!(
            "{} (chance {:.1e}; {:.2} such pairs expected among {} compared): one identifier generator may serve both",
            self.keys.join("; "),
            self.chance,
            self.expected_pairs,
            self.tested
        )
    }
}

/// A value decoded.
#[derive(Debug, Clone, Copy, PartialEq)]
enum Decoded {
    /// UUIDv1 or v6: node id (48 bits), whether it is no globally unique
    /// address (the multicast or the locally administered bit set), Unix
    /// milliseconds.
    Node { node: u64, random: bool, ms: i64 },
    /// UUIDv7, ULID, KSUID: Unix milliseconds.
    Timed { ms: i64 },
    /// Snowflake: epoch index, datacenter, worker, Unix milliseconds.
    Snowflake {
        epoch: usize,
        dc: u8,
        worker: u8,
        ms: i64,
    },
}

impl Decoded {
    fn ms(&self) -> i64 {
        match *self {
            Decoded::Node { ms, .. } | Decoded::Timed { ms } | Decoded::Snowflake { ms, .. } => ms,
        }
    }
}

fn hex_digits(v: &str) -> Option<Vec<u8>> {
    v.bytes()
        .map(|b| (b as char).to_digit(16).map(|d| d as u8))
        .collect()
}

fn hex_value(h: &[u8]) -> u64 {
    h.iter().fold(0u64, |acc, &d| (acc << 4) | u64::from(d))
}

/// A UUID's version and fields, when `v` is one with the RFC 9562 variant.
fn uuid(v: &str) -> Option<Decoded> {
    let parts: Vec<&str> = v.split('-').collect();
    if parts.len() != 5
        || parts
            .iter()
            .zip([8, 4, 4, 4, 12])
            .any(|(p, n)| p.len() != n)
    {
        return None;
    }
    let h = hex_digits(&parts.concat())?;
    if !matches!(h[16], 8..=11) {
        return None;
    }
    let ms = |ticks: i64| (ticks - GREGORIAN_OFFSET) / 10_000;
    match h[12] {
        1 | 6 => {
            let ticks = if h[12] == 1 {
                (hex_value(&h[13..16]) << 48) | (hex_value(&h[8..12]) << 32) | hex_value(&h[0..8])
            } else {
                (hex_value(&h[0..8]) << 28) | (hex_value(&h[8..12]) << 12) | hex_value(&h[13..16])
            };
            let node = hex_value(&h[20..32]);
            Some(Decoded::Node {
                node,
                random: (node >> 40) & 0b11 != 0,
                ms: ms(ticks as i64),
            })
        }
        7 => Some(Decoded::Timed {
            ms: hex_value(&h[0..12]) as i64,
        }),
        _ => None,
    }
}

/// A ULID's time: 26 Crockford base-32 characters, the first ten the
/// milliseconds.
fn ulid(v: &str) -> Option<i64> {
    if v.len() != 26 {
        return None;
    }
    let digit = |c: u8| -> Option<u64> {
        let c = c.to_ascii_uppercase();
        let d = match c {
            b'0'..=b'9' => c - b'0',
            b'O' => 0,
            b'I' | b'L' => 1,
            b'A'..=b'H' => c - b'A' + 10,
            b'J' | b'K' => c - b'J' + 18,
            b'M' | b'N' => c - b'M' + 20,
            b'P'..=b'T' => c - b'P' + 22,
            b'V'..=b'Z' => c - b'V' + 27,
            _ => return None,
        };
        Some(u64::from(d))
    };
    let all: Vec<u64> = v.bytes().map(digit).collect::<Option<_>>()?;
    if all[0] > 7 {
        return None;
    }
    Some(all[..10].iter().fold(0u64, |acc, &d| (acc << 5) | d) as i64)
}

/// A KSUID's time: 27 base-62 characters, a 160-bit number whose top 32
/// bits are seconds since the KSUID epoch.
fn ksuid(v: &str) -> Option<i64> {
    if v.len() != 27 {
        return None;
    }
    // Six 32-bit limbs, least significant first.
    let mut n = [0u64; 6];
    for c in v.bytes() {
        let d = match c {
            b'0'..=b'9' => c - b'0',
            b'A'..=b'Z' => c - b'A' + 10,
            b'a'..=b'z' => c - b'a' + 36,
            _ => return None,
        };
        let mut carry = u64::from(d);
        for limb in &mut n {
            let x = *limb * 62 + carry;
            *limb = x & 0xffff_ffff;
            carry = x >> 32;
        }
        if carry != 0 {
            return None;
        }
    }
    if n[5] != 0 {
        return None;
    }
    Some((n[4] as i64 + KSUID_EPOCH) * 1000)
}

/// A Snowflake id: a decimal of 15 to 20 digits whose time, under one of
/// the known epochs, is within `max_ms` of `at_ms`.
fn snowflake(v: &str, at_ms: i64, max_ms: i64) -> Option<Decoded> {
    if !(15..=20).contains(&v.len()) || !v.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let x: u64 = v.parse().ok()?;
    EPOCHS.iter().enumerate().find_map(|(i, (_, e))| {
        let ms = (x >> 22) as i64 + e;
        ((ms - at_ms).abs() <= max_ms).then_some(Decoded::Snowflake {
            epoch: i,
            dc: ((x >> 17) & 31) as u8,
            worker: ((x >> 12) & 31) as u8,
            ms,
        })
    })
}

/// `v` decoded, seen first at `at` (Unix seconds, 0 when unknown).
fn decode(v: &str, at: i64, opts: &GeneratorOptions) -> Option<Decoded> {
    if let Some(d) = uuid(v) {
        return Some(d);
    }
    if at <= 0 {
        return None;
    }
    let (at_ms, max_ms) = (at * 1000, opts.max_skew_secs.max(0) * 1000);
    let near = |ms: i64| (ms - at_ms).abs() <= max_ms;
    if let Some(ms) = ulid(v).or_else(|| ksuid(v)).filter(|&ms| near(ms)) {
        return Some(Decoded::Timed { ms });
    }
    snowflake(v, at_ms, max_ms)
}

/// A counter tag's stem, digit count and number.
fn counter(v: &str) -> Option<(&str, usize, u64)> {
    let digits = v.bytes().rev().take_while(u8::is_ascii_digit).count();
    let stem = &v[..v.len() - digits];
    if !(3..=12).contains(&digits)
        || stem.len() < 2
        || !stem.bytes().any(|b| b.is_ascii_alphabetic())
    {
        return None;
    }
    let n: u64 = v[stem.len()..].parse().ok()?;
    (n >= COUNTER_MIN).then_some((stem, digits, n))
}

/// The label of the `k`th node id an analysis shows: `A` to `Z`, then
/// `AA`, `AB`, ... It carries nothing of the id.
fn node_label(k: usize) -> String {
    let mut k = k + 1;
    let mut out = Vec::new();
    while k > 0 {
        k -= 1;
        out.push(b'A' + (k % 26) as u8);
        k /= 26;
    }
    out.reverse();
    String::from_utf8(out).unwrap_or_default()
}

/// A key two clusters can share. Skews are compared within the tolerance,
/// so they are kept apart.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum Key {
    Node(u64),
    Worker(usize, u8, u8),
    /// Parameter name, stem, digit count.
    Counter(String, String, usize),
}

impl Key {
    fn kind(&self) -> usize {
        match self {
            Key::Node(_) => 0,
            Key::Worker(..) => 1,
            Key::Counter(..) => 2,
        }
    }
}

/// What one cluster's identifiers decode to.
#[derive(Default)]
struct Profile {
    keys: BTreeSet<Key>,
    /// Counter numbers per key.
    numbers: BTreeMap<Key, BTreeSet<u64>>,
    /// The cluster's clock skew in milliseconds, when stable and telling.
    skew: Option<i64>,
}

/// One identifier value a record carries: parameter name, value, and
/// whether it is a strong parameter's.
fn identifiers(r: &ObsResult) -> Vec<(String, String, bool)> {
    let mut out: Vec<(String, String, bool)> = Vec::new();
    for f in &r.features {
        if let LinkFeature::Param { name, value } = f {
            out.push((name.clone(), value.clone(), true));
        }
    }
    for l in &r.layers {
        for (k, v) in &l.params {
            if uuid(v).is_some() && !out.iter().any(|(_, x, _)| x == v) {
                out.push((k.to_ascii_lowercase(), v.clone(), false));
            }
        }
    }
    out
}

/// Pairs of clusters above noise whose generated identifiers come from one
/// generator beyond chance, most unlikely first, and the family's
/// multiplicity budget.
pub(crate) fn generator_pairs(
    clusters: &[Cluster],
    results: &[ObsResult],
    opts: &GeneratorOptions,
) -> (Vec<GeneratorPair>, TestFamily) {
    let shown: Vec<&Cluster> = clusters.iter().filter(|c| c.tier > Tier::Noise).collect();
    let mut owner: Vec<Option<usize>> = vec![None; results.len()];
    for (ci, c) in shown.iter().enumerate() {
        for &m in &c.members {
            owner[m] = Some(ci);
        }
    }
    // Every value's first sighting per holder (a cluster, or the outside),
    // and the target families a node id sits on outside strong parameters.
    let mut first: BTreeMap<(Option<usize>, String, String, bool), i64> = BTreeMap::new();
    for (i, r) in results.iter().enumerate() {
        let at = if r.obs.ts > 0 && request_like(r.obs.ts_kind) {
            r.obs.ts
        } else {
            0
        };
        for (name, value, strong) in identifiers(r) {
            let t = first.entry((owner[i], name, value, strong)).or_insert(at);
            if at > 0 && (*t <= 0 || at < *t) {
                *t = at;
            }
        }
    }
    let mut sites: BTreeMap<u64, BTreeSet<String>> = BTreeMap::new();
    for (i, r) in results.iter().enumerate() {
        let fam = r.target_host.as_deref().map(crate::knowledge::family);
        for (_, value, strong) in identifiers(r) {
            if let Some(Decoded::Node { node, .. }) = uuid(&value) {
                // A strong parameter's node is the client's: each record
                // counts as a site of its own.
                sites.entry(node).or_default().insert(if strong {
                    format!("strong:{i}")
                } else {
                    fam.unwrap_or("").to_string()
                });
            }
        }
    }
    let one_site = |node: u64| sites.get(&node).is_some_and(|s| s.len() <= 1);
    // Node ids by first appearance among the records: their labels.
    let mut labels: BTreeMap<u64, String> = BTreeMap::new();
    for r in results {
        for (_, value, _) in identifiers(r) {
            if let Some(Decoded::Node { node, .. }) = uuid(&value) {
                let next = labels.len();
                labels.entry(node).or_insert_with(|| node_label(next));
            }
        }
    }

    let mut profiles: Vec<Profile> = (0..shown.len()).map(|_| Profile::default()).collect();
    let mut outside: BTreeMap<Key, usize> = BTreeMap::new();
    // Each cluster's readings: when the value was first seen, and its skew.
    let mut skews: Vec<Vec<(i64, i64)>> = vec![Vec::new(); shown.len()];
    for ((holder, name, value, strong), at) in &first {
        let mut keys: Vec<(Key, Option<u64>)> = Vec::new();
        let d = decode(value, *at, opts);
        match d {
            Some(Decoded::Node { node, random, .. }) if !random && (*strong || !one_site(node)) => {
                keys.push((Key::Node(node), None));
            }
            Some(Decoded::Snowflake {
                epoch, dc, worker, ..
            }) => keys.push((Key::Worker(epoch, dc, worker), None)),
            None if *strong => {
                if let Some((stem, digits, n)) = counter(value) {
                    keys.push((
                        Key::Counter(name.clone(), stem.to_string(), digits),
                        Some(n),
                    ));
                }
            }
            _ => {}
        }
        match holder {
            Some(c) => {
                let p = &mut profiles[*c];
                for (k, n) in keys {
                    if let Some(n) = n {
                        p.numbers.entry(k.clone()).or_default().insert(n);
                    }
                    p.keys.insert(k);
                }
                // Skews from the agent's own values only: a site's ids
                // carry the site's clock.
                if let Some(d) = d
                    && *strong
                    && *at > 0
                    && (d.ms() - at * 1000).abs() <= opts.max_skew_secs.max(0) * 1000
                {
                    skews[*c].push((*at, d.ms() - at * 1000));
                }
            }
            None => {
                for (k, _) in keys {
                    *outside.entry(k).or_default() += 1;
                }
            }
        }
    }
    let tol = opts.skew_tolerance_secs.max(0) * 1000;
    for (p, readings) in profiles.iter_mut().zip(skews) {
        // A value minted once and first seen later reads its clock offset
        // plus the wait from minting to sending: one reading cannot tell
        // the two apart. Values first seen at two or more times that agree
        // read a constant offset, which a wait rarely is.
        let times: BTreeSet<i64> = readings.iter().map(|&(at, _)| at).collect();
        if times.len() < 2 {
            continue;
        }
        let mut s: Vec<i64> = readings.into_iter().map(|(_, x)| x).collect();
        s.sort_unstable();
        let mid = s[s.len() / 2];
        let zone = (mid.rem_euclid(ZONE_STEP_MS)).min(ZONE_STEP_MS - mid.rem_euclid(ZONE_STEP_MS));
        if s.iter().all(|x| (x - mid).abs() <= tol)
            && mid.abs() >= opts.min_skew_secs.max(0) * 1000
            && zone > tol
        {
            p.skew = Some(mid);
        }
    }

    // Holders of each key: clusters, then outside records.
    let mut holders: BTreeMap<&Key, Vec<usize>> = BTreeMap::new();
    for (c, p) in profiles.iter().enumerate() {
        for k in &p.keys {
            holders.entry(k).or_default().push(c);
        }
    }
    let common = |k: &Key, n: usize| n + outside.get(k).copied().unwrap_or(0) > opts.max_holders;
    // Pairs tested: any two clusters with a node id, a Snowflake worker or
    // a skew could share one; two counters are compared only on one stem.
    let mut by_kind = [0usize; 3];
    for p in &profiles {
        let kinds: BTreeSet<usize> = p.keys.iter().map(Key::kind).collect();
        for k in kinds.into_iter().filter(|&k| k < 2) {
            by_kind[k] += 1;
        }
        if p.skew.is_some() {
            by_kind[2] += 1;
        }
    }
    let pairs = |n: usize| n * n.saturating_sub(1) / 2;
    let stems: usize = holders
        .iter()
        .filter(|(k, _)| k.kind() == 2)
        .map(|(_, cs)| pairs(cs.len()))
        .sum();
    let tested: usize = by_kind.iter().map(|&n| pairs(n)).sum::<usize>() + stems;

    // Shared keys per pair, each with its chance and line.
    let mut shared: BTreeMap<(usize, usize), Vec<(f64, String)>> = BTreeMap::new();
    let gap = opts.counter_max_gap;
    for (k, cs) in &holders {
        if cs.len() < 2 || common(k, cs.len()) {
            continue;
        }
        for (i, &x) in cs.iter().enumerate() {
            for &y in &cs[i + 1..] {
                let entry = match k {
                    Key::Node(node) => Some((
                        2f64.powi(-47),
                        format!(
                            "one UUID node id in both (node {} of this analysis; a device identifier, never shown)",
                            labels.get(node).map_or("?", String::as_str)
                        ),
                    )),
                    Key::Worker(e, dc, w) => Some((
                        2f64.powi(-10),
                        format!(
                            "Snowflake datacenter {dc} worker {w} ({} epoch) in both",
                            EPOCHS[*e].0
                        ),
                    )),
                    Key::Counter(name, stem, digits) => {
                        let (nx, ny) = (&profiles[x].numbers[*k], &profiles[y].numbers[*k]);
                        let close = nx
                            .iter()
                            .any(|&a| ny.iter().any(|&b| a != b && a.abs_diff(b) <= gap));
                        close.then(|| {
                            let span = 10f64.powi(*digits as i32);
                            let p = ((2 * gap + 1) as f64 * (nx.len() * ny.len()) as f64 / span)
                                .min(1.0);
                            let stem: String = stem.chars().take(16).collect();
                            (
                                p,
                                format!(
                                    "one counter: {name}={stem} then {digits}-digit numbers within {gap} of each other"
                                ),
                            )
                        })
                    }
                };
                if let Some(e) = entry {
                    shared.entry((x, y)).or_default().push(e);
                }
            }
        }
    }
    let skewed: Vec<(usize, i64)> = profiles
        .iter()
        .enumerate()
        .filter_map(|(c, p)| p.skew.map(|s| (c, s)))
        .collect();
    // Unrelated skews under a fixed prior: magnitudes log-uniform between
    // the smallest skew read and the largest, either sign. The density at
    // `s` is `1 / (2 |s| ln(max / min))`, so a skew of minutes meets
    // another far more often than one of hours.
    let lo = opts.min_skew_secs.max(1) as f64 * 1000.0;
    let hi = (opts.max_skew_secs.max(0) as f64 * 1000.0).max(lo * std::f64::consts::E);
    let log_span = (hi / lo).ln();
    for (i, &(x, sx)) in skewed.iter().enumerate() {
        let near = |s: i64| skewed.iter().filter(|(_, t)| (t - s).abs() <= tol).count();
        for &(y, sy) in &skewed[i + 1..] {
            if (sx - sy).abs() > tol || near(sx).max(near(sy)) > opts.max_holders {
                continue;
            }
            let s = (sx.abs().min(sy.abs()) as f64).max(lo);
            let p = ((2 * tol + 1000) as f64 / (2.0 * s * log_span)).min(1.0);
            shared.entry((x, y)).or_default().push((
                p,
                format!(
                    "clocks {:+.1} s and {:+.1} s off, one skew",
                    sx as f64 / 1000.0,
                    sy as f64 / 1000.0
                ),
            ));
        }
    }

    let mut out = Vec::new();
    for ((x, y), keys) in shared {
        let least = keys.iter().map(|k| k.0).fold(1.0, f64::min);
        let chance = crate::chance::sidak(least, keys.len());
        if chance > opts.max_chance {
            continue;
        }
        out.push(GeneratorPair {
            a: shown[x].id.clone(),
            b: shown[y].id.clone(),
            keys: keys.into_iter().map(|k| k.1).collect(),
            chance,
            tested: 0,
            expected_pairs: 0.0,
        });
    }
    let ps: Vec<f64> = out.iter().map(|p| p.chance).collect();
    let family = TestFamily::cut("generator", &ps, tested, opts.fdr);
    out.retain(|p| family.keeps(p.chance));
    for p in &mut out {
        p.tested = family.tested;
        p.expected_pairs = p.chance * family.tested as f64;
    }
    crate::sort::by(&mut out, |p, q| {
        p.chance
            .total_cmp(&q.chance)
            .then(p.a.cmp(&q.a))
            .then(p.b.cmp(&q.b))
    });
    out.truncate(MAX_PAIRS);
    (out, family)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyze::analyze;
    use crate::model::Observation;
    use crate::rules::Rules;

    const T0: i64 = 1_791_000_000;

    /// A UUIDv1 for Unix second `t` with clock sequence `seq` on `node`.
    fn v1(t: i64, seq: u16, node: u64) -> String {
        let ticks = (t * 10_000_000 + GREGORIAN_OFFSET) as u64;
        format!(
            "{:08x}-{:04x}-1{:03x}-{:04x}-{:012x}",
            ticks & 0xffff_ffff,
            (ticks >> 32) & 0xffff,
            (ticks >> 48) & 0xfff,
            0x8000 | (seq & 0x3fff),
            node
        )
    }

    /// A ULID for Unix milliseconds `ms`, its random part from `r`.
    fn ulid_of(ms: i64, r: u64) -> String {
        const A: &[u8] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
        let mut s = String::new();
        for k in (0..10).rev() {
            s.push(A[((ms as u64 >> (5 * k)) & 31) as usize] as char);
        }
        let mut r = r;
        for _ in 0..16 {
            s.push(A[(r & 31) as usize] as char);
            r = r.rotate_right(5) ^ 0x9e37_79b9;
        }
        s
    }

    fn o(id: &str, ts: i64, url: &str) -> Observation {
        Observation {
            id: id.into(),
            ts,
            url: url.into(),
            ..Default::default()
        }
    }

    /// Clusters, one run tag each, a day apart, each probing hosts of its
    /// own with tag `tag(k)`.
    fn runs(n: usize, tag: impl Fn(usize, i64) -> String) -> Vec<Observation> {
        let mut obs = Vec::new();
        for k in 0..n {
            let t = T0 + k as i64 * 86_400;
            let tag = tag(k, t);
            for j in 0..3 {
                obs.push(o(
                    &format!("r{k}-{j}"),
                    t + j * 40,
                    &format!("https://h{j}.own{k}.example/q?id=1%27%20OR%201=1--&uqtag={tag}"),
                ));
            }
        }
        obs
    }

    #[test]
    fn decoders_read_each_shape() {
        let id = v1(T0, 77, 0x001a_2b3c_0002);
        match uuid(&id) {
            Some(Decoded::Node { node, random, ms }) => {
                assert_eq!((node, random, ms), (0x001a_2b3c_0002, false, T0 * 1000));
            }
            d => panic!("{d:?}"),
        }
        // Multicast bit: a random node.
        let r = v1(T0, 1, 0x0300_0000_0001);
        assert!(matches!(uuid(&r), Some(Decoded::Node { random: true, .. })));
        // A v4 is no generator's; v7 carries milliseconds.
        assert_eq!(uuid("0b6c1f0e-1111-4c2a-9a55-3f2e1d0c9b8a"), None);
        let ms = format!("{:012x}", T0 * 1000 + 5);
        let v7 = format!("{}-{}-7abc-8def-0123456789ab", &ms[..8], &ms[8..]);
        assert_eq!(uuid(&v7), Some(Decoded::Timed { ms: T0 * 1000 + 5 }));
        assert_eq!(ulid(&ulid_of(T0 * 1000 + 9, 3)), Some(T0 * 1000 + 9));
        // KSUID: "0ujtsYcgvSTl8PAuAdqWYSMnLOv" (raw 0669F7EF...) is
        // 2017-10-10T04:00:47Z.
        assert_eq!(
            ksuid("0ujtsYcgvSTl8PAuAdqWYSMnLOv"),
            Some((107_608_047 + KSUID_EPOCH) * 1000)
        );
        // Snowflake: 1.1e12 ms after the Twitter epoch, datacenter 3,
        // worker 9, sequence 5.
        let x: u64 = (1_100_000_000_000u64 << 22) | (3 << 17) | (9 << 12) | 5;
        let at = 1_288_834_974_657 + 1_100_000_000_000;
        assert_eq!(
            snowflake(&x.to_string(), at, 1000),
            Some(Decoded::Snowflake {
                epoch: 0,
                dc: 3,
                worker: 9,
                ms: at
            })
        );
        assert_eq!(snowflake(&x.to_string(), at + 10_000_000, 1000), None);
        assert_eq!(counter("batch-0417"), Some(("batch-", 4, 417)));
        assert_eq!(counter("run007"), None);
        assert_eq!(counter("4417"), None);
        assert_eq!(node_label(0), "A");
        assert_eq!(node_label(25), "Z");
        assert_eq!(node_label(26), "AA");
        assert_eq!(node_label(27), "AB");
    }

    #[test]
    fn one_machine_behind_fresh_uuid_tags_pairs_up() {
        let node = 0x001a_2b3c_0002;
        let a = analyze(
            runs(3, |k, t| v1(t, 100 + k as u16, node)),
            &Rules::default_rules(),
        );
        assert_eq!(a.clusters.len(), 3, "{:?}", a.clusters.len());
        assert_eq!(a.generator_pairs.len(), 3, "{:?}", a.generator_pairs);
        let d = a.generator_pairs[0].detail();
        assert!(d.contains("node A of this analysis"), "{d}");
        assert!(!d.contains("001a2b3c0002") && !d.contains("2b3c"), "{d}");
        // One node reads the same in every pair of the analysis.
        for p in &a.generator_pairs {
            assert!(p.keys[0].contains("node A "), "{:?}", p.keys);
        }
        assert!(
            a.soft_links
                .iter()
                .any(|l| l.kind == crate::fleets::SoftLinkKind::Generator),
            "{:?}",
            a.soft_links
        );
        // Each run its own machine: nothing.
        let b = analyze(
            runs(3, |k, t| v1(t, 100, 0x001a_2b3c_0010 + k as u64)),
            &Rules::default_rules(),
        );
        assert!(b.generator_pairs.is_empty(), "{:?}", b.generator_pairs);
        // Random (multicast) nodes tie nothing either.
        let c = analyze(
            runs(3, |k, t| v1(t, k as u16, 0x0300_0000_0001)),
            &Rules::default_rules(),
        );
        assert!(c.generator_pairs.is_empty(), "{:?}", c.generator_pairs);
    }

    #[test]
    fn a_locally_administered_node_ties_none() {
        // The default container bridge gives its first container
        // 02:42:ac:11:00:02 on every host: unrelated operators each minting
        // UUIDv1 tags in a fresh container carry one node.
        let docker = 0x0242_ac11_0002;
        assert!(matches!(
            uuid(&v1(T0, 1, docker)),
            Some(Decoded::Node { random: true, .. })
        ));
        let a = analyze(
            runs(3, |k, t| v1(t, 100 + k as u16, docker)),
            &Rules::default_rules(),
        );
        assert_eq!(a.clusters.len(), 3, "{:?}", a.clusters.len());
        assert!(a.generator_pairs.is_empty(), "{:?}", a.generator_pairs);
    }

    #[test]
    fn one_cloned_node_on_many_senders_ties_none() {
        let a = analyze(
            runs(12, |k, t| v1(t, k as u16, 0x001a_2b3c_0002)),
            &Rules::default_rules(),
        );
        assert_eq!(a.clusters.len(), 12);
        assert!(a.generator_pairs.is_empty(), "{:?}", a.generator_pairs);
    }

    /// Clusters a day apart, each on hosts of its own under one run tag,
    /// minting a fresh nonce per record with `tag(k, j, t)`.
    fn runs_fresh(n: usize, tag: impl Fn(usize, i64, i64) -> String) -> Vec<Observation> {
        let mut obs = Vec::new();
        for k in 0..n {
            for j in 0..3 {
                let t = T0 + k as i64 * 86_400 + j * 40;
                obs.push(o(
                    &format!("r{k}-{j}"),
                    t,
                    &format!(
                        "https://h{j}.own{k}.example/q?id=1%27%20OR%201=1--&uqtag=r{k}x{k}x{k}&nonce={}",
                        tag(k, j, t)
                    ),
                ));
            }
        }
        obs
    }

    #[test]
    fn one_skewed_clock_and_one_counter_pair_up() {
        // A clock 412 s fast behind ULID tags, three per cluster.
        let a = analyze(
            runs_fresh(3, |k, j, t| {
                ulid_of((t + 412) * 1000 + 250, (k * 3) as u64 + j as u64 + 1)
            }),
            &Rules::default_rules(),
        );
        assert_eq!(a.generator_pairs.len(), 3, "{:?}", a.generator_pairs);
        assert!(
            a.generator_pairs[0].keys[0].contains("+412"),
            "{:?}",
            a.generator_pairs
        );
        // One run tag per cluster is one reading: no clock, nothing.
        let one = analyze(
            runs(3, |k, t| ulid_of((t + 412) * 1000 + 250, k as u64 + 1)),
            &Rules::default_rules(),
        );
        assert!(one.generator_pairs.is_empty(), "{:?}", one.generator_pairs);
        // Readings of one cluster that disagree are no clock: nothing.
        let unstable = analyze(
            runs_fresh(3, |k, j, t| {
                ulid_of((t + 412 + 30 * j) * 1000, (k * 3) as u64 + j as u64 + 1)
            }),
            &Rules::default_rules(),
        );
        assert!(
            unstable.generator_pairs.is_empty(),
            "{:?}",
            unstable.generator_pairs
        );
        // A clock off by a whole hour is a time-zone error: nothing.
        let b = analyze(
            runs_fresh(3, |k, j, t| {
                ulid_of((t + 3600) * 1000, (k * 3) as u64 + j as u64 + 1)
            }),
            &Rules::default_rules(),
        );
        assert!(b.generator_pairs.is_empty(), "{:?}", b.generator_pairs);
        // A counter's successors.
        let c = analyze(
            runs(3, |k, _| format!("batch-{}", 4417 + k)),
            &Rules::default_rules(),
        );
        assert_eq!(c.generator_pairs.len(), 3, "{:?}", c.generator_pairs);
        let d = analyze(
            runs(3, |k, _| format!("batch-{}", 1000 + 2000 * k)),
            &Rules::default_rules(),
        );
        assert!(d.generator_pairs.is_empty(), "{:?}", d.generator_pairs);
    }

    #[test]
    fn one_tag_minted_before_the_first_request_is_no_clock() {
        // Two unrelated agents each mint one ULID tag about 90 s before
        // their first request, within 2 s of each other: the readings are
        // mint-to-request latency, not a clock offset, and tie nothing.
        let a = analyze(
            runs(2, |k, t| {
                ulid_of((t - 90) * 1000 - 1500 * k as i64, k as u64 + 1)
            }),
            &Rules::default_rules(),
        );
        assert_eq!(a.clusters.len(), 2, "{:?}", a.clusters.len());
        assert!(a.generator_pairs.is_empty(), "{:?}", a.generator_pairs);
        // Two tags per cluster, minted at different requests on one clock
        // 90 s slow: a clock offset, and the pair ties.
        let b = analyze(
            runs_fresh(2, |k, j, t| {
                ulid_of(
                    (t - 90) * 1000 - 1500 * k as i64,
                    (k * 3) as u64 + j as u64 + 1,
                )
            }),
            &Rules::default_rules(),
        );
        assert_eq!(b.generator_pairs.len(), 1, "{:?}", b.generator_pairs);
        // Two values first seen in one request are one reading.
        let c = analyze(
            runs(2, |k, t| {
                format!(
                    "{}&nonce={}",
                    ulid_of((t - 90) * 1000 - 1500 * k as i64, k as u64 + 1),
                    ulid_of((t - 90) * 1000 - 1500 * k as i64 + 7, k as u64 + 11)
                )
            }),
            &Rules::default_rules(),
        );
        assert!(c.generator_pairs.is_empty(), "{:?}", c.generator_pairs);
    }

    #[test]
    fn a_sites_own_uuids_tie_its_visitors_to_nothing() {
        // Three clusters reading pages of one site whose ids are the site's
        // UUIDv1s: one node, one site.
        let node = 0x001a_2b3c_0002;
        let mut obs = Vec::new();
        for k in 0..3 {
            for j in 0..3 {
                obs.push(o(
                    &format!("r{k}-{j}"),
                    T0 + k * 86_400 + j * 40,
                    &format!(
                        "https://shop.example/item?id={}&q=1%27%20OR%201=1--&uqtag=r{k}x{k}x{k}",
                        v1(T0 - 1000 * (j + 3 * k), 5, node)
                    ),
                ));
            }
        }
        let a = analyze(obs, &Rules::default_rules());
        assert!(a.generator_pairs.is_empty(), "{:?}", a.generator_pairs);
    }

    #[test]
    fn a_sites_fresh_time_ordered_ids_give_its_visitors_no_skew() {
        // Unrelated agents fetch an article the site minted a UUIDv7 for a
        // few minutes before, each within a second or two of the others'
        // skew: the site's clock, not theirs.
        let minted = T0 - 300;
        let ms = format!("{:012x}", minted * 1000);
        let id = |j: i64| format!("{}-{}-7abc-8def-{:012x}", &ms[..8], &ms[8..], j);
        let mut obs = Vec::new();
        for k in 0..3 {
            for j in 0..3 {
                obs.push(o(
                    &format!("r{k}-{j}"),
                    T0 + k + j * 40,
                    &format!(
                        "https://news{k}.example/a?article={}&q=1%27%20OR%201=1--&uqtag=r{k}x{k}x{k}",
                        id(j)
                    ),
                ));
            }
        }
        let a = analyze(obs, &Rules::default_rules());
        assert!(a.generator_pairs.is_empty(), "{:?}", a.generator_pairs);
    }
}
