//! Matching sightings across parties: which clusters more than one party
//! saw, and on what shared features.
//!
//! A match is a proposal for the admin. It never merges clusters, never
//! changes a tier or a grade, and counts as corroboration only between
//! parties whose standing the admin established ([`Standing::counts`]). A
//! sighting is `observed` provenance only if its sender is who it says it
//! is, and a file cannot vouch for itself: anyone holding the published
//! epoch key can hash a value read from a public record, so an unverified
//! sighting that matches the watch shows only that its sender can read
//! public records.

use super::{FeatureKind, Sighting, Sightings};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// How far a party's sightings can be taken at their word. Set by the
/// admin (the CLI's `--vouch`), never read from the document.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Standing {
    /// Arrived with nothing tying it to a known operator.
    Unverified,
    /// Names a case, but the case records no report sent to an affected
    /// operator: the sender is not known to be that operator.
    Claimed,
    /// Tied to a case whose affected operator we reported to, and sent back
    /// through that channel.
    Contacted,
    /// The watch store's own clusters, from public records.
    Watch,
}

impl Standing {
    pub fn label(self) -> &'static str {
        match self {
            Self::Unverified => "unverified",
            Self::Claimed => "claimed",
            Self::Contacted => "contacted",
            Self::Watch => "watch",
        }
    }

    /// Whether a match with this party counts toward independent
    /// corroboration.
    pub fn counts(self) -> bool {
        matches!(self, Self::Contacted | Self::Watch)
    }
}

/// One party's document and the standing the admin gave it.
#[derive(Debug, Clone)]
pub struct Party {
    /// Who the party is to the admin: a case id, `watch`, or a file name for
    /// an unverified sender. Two parties with one name are one party.
    pub name: String,
    pub standing: Standing,
    pub doc: Sightings,
}

/// One sighting of one party.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SightingRef {
    pub party: String,
    pub standing: Standing,
    /// The sighting's id in its document (`S1`).
    pub sighting: String,
}

/// A feature two sightings share, by kind and name; the hash itself is
/// left out of reports.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Shared {
    pub kind: FeatureKind,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub name: String,
    pub epoch: String,
}

/// Two sightings of different parties sharing at least one linking
/// feature or captured secret.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Pair {
    pub a: SightingRef,
    pub b: SightingRef,
    pub shared: Vec<Shared>,
    /// Hours both saw records in.
    pub overlap_hours: usize,
    /// Hours between the nearest records of the two, 0 when they overlap.
    pub gap_hours: i64,
    /// Scaffold both share (relay stacks, payload variants, header sets,
    /// networks), as `kind:value`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scaffold: Vec<String>,
    /// Both parties count ([`Standing::counts`]).
    pub corroborating: bool,
}

/// Sightings joined by pairs: one swarm, perhaps, seen by several parties.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Group {
    pub members: Vec<SightingRef>,
    /// Distinct parties among the members.
    pub parties: usize,
    /// Distinct parties whose standing counts.
    pub independent: usize,
    /// Two or more counting parties share a feature: corroborated, for the
    /// admin to review. Still never a merge.
    pub corroborated: bool,
    /// Members that join sightings sharing nothing with each other, through
    /// different features: the shape a planted sighting needs to make two
    /// swarms look like one.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub bridges: Vec<SightingRef>,
}

/// Two sightings of different parties with no shared feature, active in
/// the same hours on alike scaffold. A weak hint, never corroboration.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScaffoldPair {
    pub a: SightingRef,
    pub b: SightingRef,
    pub overlap_hours: usize,
    pub scaffold: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct MatchReport {
    pub pairs: Vec<Pair>,
    pub groups: Vec<Group>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scaffold_pairs: Vec<ScaffoldPair>,
}

/// A keyed feature by kind, name, epoch and hash.
type FeatureKey<'a> = (FeatureKind, &'a str, &'a str, &'a str);

/// Scaffold kinds two sightings must share, in common hours, to be a
/// scaffold pair.
const SCAFFOLD_MIN: usize = 2;
/// Most scaffold pairs reported.
const SCAFFOLD_MAX: usize = 50;

/// Match every party's sightings against every other party's.
pub fn match_sightings(parties: &[Party]) -> MatchReport {
    // One standing per party name: the weakest given, so a name cannot be
    // raised by repeating it.
    let mut standing: BTreeMap<&str, Standing> = BTreeMap::new();
    for p in parties {
        standing
            .entry(&p.name)
            .and_modify(|s| *s = (*s).min(p.standing))
            .or_insert(p.standing);
    }
    let all: Vec<(SightingRef, &Sighting)> = parties
        .iter()
        .flat_map(|p| {
            let s = standing[p.name.as_str()];
            p.doc.sightings.iter().map(move |x| {
                (
                    SightingRef {
                        party: p.name.clone(),
                        standing: s,
                        sighting: x.id.clone(),
                    },
                    x,
                )
            })
        })
        .collect();

    // Sightings by feature, so only sightings sharing one are compared.
    let mut by_feature: BTreeMap<FeatureKey, Vec<usize>> = BTreeMap::new();
    for (i, (_, x)) in all.iter().enumerate() {
        for f in &x.features {
            by_feature
                .entry((f.kind, f.name.as_str(), f.epoch.as_str(), f.hash.as_str()))
                .or_default()
                .push(i);
        }
    }
    let mut shared: BTreeMap<(usize, usize), BTreeSet<FeatureKey>> = BTreeMap::new();
    for (key, ix) in &by_feature {
        for (n, &i) in ix.iter().enumerate() {
            for &j in &ix[n + 1..] {
                if all[i].0.party != all[j].0.party {
                    shared.entry((i.min(j), i.max(j))).or_default().insert(*key);
                }
            }
        }
    }

    let mut pairs = Vec::new();
    for (&(i, j), feats) in &shared {
        let (overlap, gap) = timing(all[i].1, all[j].1);
        let mut s: Vec<Shared> = feats
            .iter()
            .map(|&(kind, name, epoch, _)| Shared {
                kind,
                name: name.into(),
                epoch: epoch.into(),
            })
            .collect();
        s.dedup();
        pairs.push(Pair {
            a: all[i].0.clone(),
            b: all[j].0.clone(),
            shared: s,
            overlap_hours: overlap,
            gap_hours: gap,
            scaffold: scaffold_shared(all[i].1, all[j].1),
            corroborating: all[i].0.standing.counts() && all[j].0.standing.counts(),
        });
    }

    let groups = groups(&all, &shared);

    let mut scaffold_pairs = Vec::new();
    for i in 0..all.len() {
        for j in i + 1..all.len() {
            if all[i].0.party == all[j].0.party || shared.contains_key(&(i, j)) {
                continue;
            }
            let (overlap, _) = timing(all[i].1, all[j].1);
            if overlap == 0 {
                continue;
            }
            let sc = scaffold_shared(all[i].1, all[j].1);
            let kinds: BTreeSet<&str> = sc.iter().filter_map(|s| s.split(':').next()).collect();
            if kinds.len() >= SCAFFOLD_MIN {
                scaffold_pairs.push(ScaffoldPair {
                    a: all[i].0.clone(),
                    b: all[j].0.clone(),
                    overlap_hours: overlap,
                    scaffold: sc,
                });
            }
        }
    }
    crate::sort::by(&mut scaffold_pairs, |p, q| {
        q.scaffold
            .len()
            .cmp(&p.scaffold.len())
            .then(q.overlap_hours.cmp(&p.overlap_hours))
    });
    scaffold_pairs.truncate(SCAFFOLD_MAX);

    MatchReport {
        pairs,
        groups,
        scaffold_pairs,
    }
}

/// Connected sightings over the pairs, with their parties and bridges.
fn groups(
    all: &[(SightingRef, &Sighting)],
    shared: &BTreeMap<(usize, usize), BTreeSet<FeatureKey>>,
) -> Vec<Group> {
    let mut adj: BTreeMap<usize, BTreeSet<usize>> = BTreeMap::new();
    for &(i, j) in shared.keys() {
        adj.entry(i).or_default().insert(j);
        adj.entry(j).or_default().insert(i);
    }
    let feats = |i: usize, j: usize| &shared[&(i.min(j), i.max(j))];
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for &start in adj.keys() {
        if !seen.insert(start) {
            continue;
        }
        let mut comp = vec![start];
        let mut k = 0;
        while k < comp.len() {
            for &n in &adj[&comp[k]] {
                if seen.insert(n) {
                    comp.push(n);
                }
            }
            k += 1;
        }
        comp.sort();
        let parties: BTreeSet<&str> = comp.iter().map(|&i| all[i].0.party.as_str()).collect();
        let independent: BTreeSet<&str> = comp
            .iter()
            .filter(|&&i| all[i].0.standing.counts())
            .map(|&i| all[i].0.party.as_str())
            .collect();
        let corroborated = comp.iter().any(|&i| {
            adj[&i]
                .iter()
                .any(|&j| all[i].0.standing.counts() && all[j].0.standing.counts())
        });
        let bridges = comp
            .iter()
            .filter(|&&x| {
                let ns: Vec<usize> = adj[&x].iter().copied().collect();
                ns.iter().enumerate().any(|(n, &y)| {
                    ns[n + 1..]
                        .iter()
                        .any(|&z| !adj[&y].contains(&z) && feats(x, y).is_disjoint(feats(x, z)))
                })
            })
            .map(|&x| all[x].0.clone())
            .collect();
        out.push(Group {
            members: comp.iter().map(|&i| all[i].0.clone()).collect(),
            parties: parties.len(),
            independent: independent.len(),
            corroborated,
            bridges,
        });
    }
    crate::sort::by(&mut out, |p, q| {
        q.corroborated
            .cmp(&p.corroborated)
            .then(q.independent.cmp(&p.independent))
            .then(q.members.len().cmp(&p.members.len()))
    });
    out
}

/// Hours both sightings saw records in, and the hours between their
/// nearest records (0 when they overlap; -1 when either has no hours).
fn timing(a: &Sighting, b: &Sighting) -> (usize, i64) {
    let ha: BTreeSet<i64> = a.hours.iter().filter_map(|h| hour(h)).collect();
    let hb: BTreeSet<i64> = b.hours.iter().filter_map(|h| hour(h)).collect();
    if ha.is_empty() || hb.is_empty() {
        return (0, -1);
    }
    let overlap = ha.intersection(&hb).count();
    if overlap > 0 {
        return (overlap, 0);
    }
    let gap = ha
        .iter()
        .filter_map(|x| {
            let after = hb.range(x..).next().map(|y| y - x);
            let before = hb.range(..x).next_back().map(|y| x - y);
            after.into_iter().chain(before).min()
        })
        .min()
        .unwrap_or(-1);
    (0, gap)
}

/// `yyyy-mm-ddThhZ` as hours since the epoch.
fn hour(h: &str) -> Option<i64> {
    let t = h.strip_suffix('Z')?;
    chrono::NaiveDateTime::parse_from_str(&format!("{t}:00:00"), "%Y-%m-%dT%H:%M:%S")
        .ok()
        .map(|d| d.and_utc().timestamp() / 3600)
}

/// Scaffold both sightings carry, as `kind:value`.
fn scaffold_shared(a: &Sighting, b: &Sighting) -> Vec<String> {
    let (x, y) = (&a.scaffold, &b.scaffold);
    let mut out = Vec::new();
    for s in x
        .relay_stacks
        .keys()
        .filter(|s| y.relay_stacks.contains_key(*s))
    {
        out.push(format!("relay_stack:{s}"));
    }
    let dx: BTreeSet<&String> = x.dialect.iter().collect();
    let dy: BTreeSet<&String> = y.dialect.iter().collect();
    let both = dx.intersection(&dy).count();
    let either = dx.union(&dy).count();
    if both >= 2 && both * 2 >= either {
        out.push(format!("dialect:{both} of {either} payload variants"));
    }
    for h in x.header_sets.iter().filter(|h| y.header_sets.contains(h)) {
        out.push(format!("header_set:{h}"));
    }
    for asn in x.asns.keys().filter(|a| y.asns.contains_key(*a)) {
        out.push(format!("asn:AS{asn}"));
    }
    out
}
