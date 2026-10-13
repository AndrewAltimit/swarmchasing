//! Triage: which submissions reach the admin's attention.
//!
//! A submission is assumed fabricated until its evidence says otherwise.
//! Each item gets an [`EvidenceClass`]; the records the toolkit itself found
//! (by verification, or already in the watch store) form the **standing**
//! set, and only they are graded for the verdict. The submitter's own
//! records (log lines, URLs as stated) are graded too, but only to show what
//! the submission claims.
//!
//! The verdict:
//!
//! - **examine**: the standing set holds a record the watch held
//!   independently, or the admin checked a third party's signature on an
//!   item, or at least `min_predating` records are verified to predate the
//!   submission by `predate_secs`; the standing set reaches `min_tier` under
//!   the rules (the submitter's records, when a checked signature covers
//!   them);
//!   its clusters carry fewer than `max_plant_signals` counted plant signals;
//!   and a claim larger than the evidence has at least `inflated_min_strong`
//!   strong items.
//! - **discard**: nothing in it can be checked (only assertions), most of its
//!   references are contradicted, or nothing it holds flags under the rules
//!   and nothing is left to verify.
//! - **hold**: everything else. Kept and listed with `inbox triage --all`.
//!
//! Instruction-shaped text is reported in the reasons and never moves the
//! verdict either way.

use crate::evidence::{
    EvidenceClass, SUBMISSION_SOURCE, claimed_records, classify, same_record, same_url,
};
use crate::inert::inert;
use crate::intake::Intake;
use crate::spec::{ClaimKind, Evidence, IndicatorKind};
use crate::verify::{Verification, span};
use sc_core::{Analysis, Observation, Rules, Tier, analyze};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// The triage thresholds. Every one is a setting
/// (`<data>/inbox/settings.toml`, `[triage]`).
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TriageSettings {
    /// How much older than the submission a verified record must be to
    /// count as predating it.
    pub predate_secs: i64,
    /// How far a claimed record time may be from the record's own.
    pub ts_tolerance_secs: i64,
    /// Verified predating records needed for examine without a
    /// corroborated one.
    pub min_predating: usize,
    /// The tier the standing records must reach.
    pub min_tier: Tier,
    /// Counted plant signals on one standing cluster that hold a submission.
    pub max_plant_signals: usize,
    /// Strong items a claim larger than its evidence needs.
    pub inflated_min_strong: usize,
    /// Share of public-record references contradicted that discards.
    pub discard_contradicted_share: f64,
    /// Shortest indicator value matched against the watch store.
    pub min_indicator_chars: usize,
    /// An indicator in more watch records than this is too common to
    /// corroborate anything.
    pub max_indicator_matches: usize,
}

impl Default for TriageSettings {
    fn default() -> Self {
        Self {
            predate_secs: 48 * 3600,
            ts_tolerance_secs: 120,
            min_predating: 2,
            min_tier: Tier::Suggestive,
            max_plant_signals: 2,
            inflated_min_strong: 3,
            discard_contradicted_share: 0.5,
            min_indicator_chars: 8,
            max_indicator_matches: 50,
        }
    }
}

/// The triage verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Examine,
    Hold,
    Discard,
}

impl Verdict {
    pub fn label(self) -> &'static str {
        match self {
            Self::Examine => "examine",
            Self::Hold => "hold",
            Self::Discard => "discard",
        }
    }
}

impl std::str::FromStr for Verdict {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        match s {
            "examine" => Ok(Self::Examine),
            "hold" => Ok(Self::Hold),
            "discard" => Ok(Self::Discard),
            _ => Err(format!("{s}: expected examine, hold or discard")),
        }
    }
}

/// Which items the watch held when the submission arrived, and the records
/// that show it.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Corroboration {
    pub items: BTreeSet<usize>,
    pub records: Vec<Observation>,
}

/// Records kept per corroborated indicator.
const MAX_HELD_PER_ITEM: usize = 50;

/// Match a submission's items against `store`, the watch's records when the
/// submission arrived. A public record matches the same record; a URL
/// matches the same URL; a log item matches when one of its requests'
/// URLs is in the store; an indicator matches records whose URL or user
/// agent carries it, when it is long enough, not a published tag, and not
/// in more than `max_indicator_matches` records.
pub fn corroborate(
    intake: &Intake,
    store: &[Observation],
    rules: &Rules,
    s: &TriageSettings,
) -> Corroboration {
    let mut out = Corroboration::default();
    let mut ids = BTreeSet::new();
    let claimed = claimed_records(&intake.id, &intake.submission.evidence);
    let unmapped: &[usize] = intake
        .converted_from
        .as_ref()
        .map_or(&[], |c| c.unmapped.as_slice());
    for (i, e) in intake.submission.evidence.iter().enumerate() {
        // A value a conversion could not map stays an assertion: it never
        // matches the store.
        if unmapped.contains(&i) {
            continue;
        }
        let hits: Vec<&Observation> = match e {
            Evidence::PublicRecord(r) => store
                .iter()
                .filter(|o| same_record(r, o, s.ts_tolerance_secs))
                .collect(),
            Evidence::LogLines(_) => {
                let urls: Vec<&str> = claimed
                    .iter()
                    .filter(|(j, _)| *j == i)
                    .map(|(_, o)| o.url.as_str())
                    .collect();
                store
                    .iter()
                    .filter(|o| urls.iter().any(|u| same_url(u, &o.url)))
                    .collect()
            }
            Evidence::Indicator(x) => {
                let v = x.value.trim();
                let burned = rules
                    .set
                    .linking
                    .published_tags
                    .iter()
                    .any(|t| t.eq_ignore_ascii_case(v));
                if v.chars().count() < s.min_indicator_chars || burned || v.contains("REDACTED-") {
                    Vec::new()
                } else {
                    let lv = v.to_lowercase();
                    let m: Vec<&Observation> = store
                        .iter()
                        .filter(|o| match x.kind {
                            IndicatorKind::Url => same_url(v, &o.url),
                            IndicatorKind::UserAgent => {
                                o.user_agent.as_deref().is_some_and(|u| u == v)
                            }
                            IndicatorKind::Ip => o.ip.as_deref() == Some(v),
                            _ => o.url.to_lowercase().contains(&lv),
                        })
                        .collect();
                    if m.len() > s.max_indicator_matches {
                        Vec::new()
                    } else {
                        m
                    }
                }
            }
            Evidence::Signed(_) => Vec::new(),
        };
        if !hits.is_empty() {
            out.items.insert(i);
            for o in hits.into_iter().take(MAX_HELD_PER_ITEM) {
                if ids.insert(o.id.clone()) {
                    out.records.push(o.clone());
                }
            }
        }
    }
    out
}

/// One item's class, with what decided it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ItemAssessment {
    pub item: usize,
    pub kind: String,
    pub class: EvidenceClass,
    pub detail: String,
}

/// What a set of records grades to.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Grade {
    pub records: usize,
    pub flagged: usize,
    pub tier: Tier,
    /// Clusters above noise.
    pub clusters: usize,
    /// The highest agent grade among them (`L0` to `L4`).
    pub agent: String,
    /// The most counted plant signals on one cluster above noise.
    pub plant_signals: usize,
    /// SC-T tactics the hits show (`SC-T3`).
    pub tactics: Vec<String>,
    /// First and last record times.
    pub span: Option<(i64, i64)>,
}

impl Grade {
    fn of(a: &Analysis) -> Self {
        let tier = a
            .results
            .iter()
            .map(|r| r.tier)
            .max()
            .unwrap_or(Tier::Noise);
        let above: Vec<_> = a.clusters.iter().filter(|c| c.tier > Tier::Noise).collect();
        let agent = above
            .iter()
            .map(|c| c.agent.level)
            .chain(
                a.results
                    .iter()
                    .filter_map(|r| r.agent.as_ref().map(|g| g.level)),
            )
            .max()
            .unwrap_or_default();
        let plant_signals = above
            .iter()
            .map(|c| c.origin.plant_signals.iter().filter(|p| p.counts()).count())
            .max()
            .unwrap_or(0);
        let tactics: BTreeSet<String> = a
            .results
            .iter()
            .flat_map(|r| r.hits.iter().filter_map(|h| h.tactic))
            .map(|t| format!("SC-{}", t.id()))
            .collect();
        let times: Vec<i64> = a
            .results
            .iter()
            .map(|r| r.obs.ts)
            .filter(|t| *t > 0)
            .collect();
        Self {
            records: a.total,
            flagged: a.flagged,
            tier,
            clusters: above.len(),
            agent: agent.code().to_string(),
            plant_signals,
            tactics: tactics.into_iter().collect(),
            span: times
                .iter()
                .min()
                .zip(times.iter().max())
                .map(|(a, b)| (*a, *b)),
        }
    }
}

/// A submission's triage.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Assessment {
    pub id: String,
    pub verdict: Verdict,
    /// Why, one line each, inert.
    pub reasons: Vec<String>,
    /// What fabricating the evidence would have taken, one line.
    pub cost: String,
    pub items: Vec<ItemAssessment>,
    pub counts: BTreeMap<EvidenceClass, usize>,
    /// The records the toolkit found itself, graded.
    pub standing: Grade,
    /// Everything, the submitter's own records included, graded.
    pub claimed: Grade,
    /// Ways the claim is larger than the standing evidence.
    pub inflation: Vec<String>,
    /// For ordering: higher first.
    pub score: i64,
}

/// What has been checked about a submission since it arrived.
#[derive(Debug, Clone, Copy)]
pub struct Checks<'a> {
    /// Lookups of its public-record references (`inbox verify`).
    pub verifications: &'a [Verification],
    /// The records those lookups found.
    pub found: &'a [Observation],
    /// What the watch held when it arrived.
    pub held: &'a Corroboration,
    /// The admin's signature checks, by item: valid and by a signer other
    /// than the submitter (true), or not (false).
    pub signatures: &'a BTreeMap<usize, bool>,
}

/// Triage `intake` given what has been checked.
pub fn assess(intake: &Intake, checks: Checks, rules: &Rules, s: &TriageSettings) -> Assessment {
    let Checks {
        verifications,
        found,
        held,
        signatures,
    } = checks;
    let sub = &intake.submission;
    let by_item: BTreeMap<usize, &Verification> =
        verifications.iter().map(|v| (v.item, v)).collect();
    let mut items = Vec::new();
    let mut counts: BTreeMap<EvidenceClass, usize> = BTreeMap::new();
    for (i, e) in sub.evidence.iter().enumerate() {
        let v = by_item.get(&i).copied();
        let class = classify(e, v, held.items.contains(&i), signatures.get(&i).copied());
        let detail = match (class, v) {
            (EvidenceClass::Corroborated, _) => {
                "the watch held it when the submission arrived".into()
            }
            (EvidenceClass::SignedChecked, _) => {
                "the admin checked the signature: a signer other than the submitter".into()
            }
            (EvidenceClass::Contradicted, None) => {
                "the admin found the signature invalid, or the submitter's own".into()
            }
            (_, Some(v)) => inert(&v.detail, 160),
            (EvidenceClass::Unverified, None) => "not looked up yet (`inbox verify`)".into(),
            (EvidenceClass::OperatorOnly, _) => "only the submitter can check these".into(),
            (EvidenceClass::Signed, _) => "signature not checked by the tool".into(),
            _ => "nothing to check it against".into(),
        };
        *counts.entry(class).or_default() += 1;
        items.push(ItemAssessment {
            item: i,
            kind: e.kind().into(),
            class,
            detail,
        });
    }
    let n = |c: EvidenceClass| counts.get(&c).copied().unwrap_or(0);

    // Standing records: found by lookups of verified items, and held by
    // the watch. Never the submitter's own.
    let verified: BTreeSet<&str> = verifications
        .iter()
        .filter(|v| v.status == crate::verify::Status::Verified)
        .filter_map(|v| v.record.as_deref())
        .collect();
    let mut seen = BTreeSet::new();
    let standing_recs: Vec<Observation> = found
        .iter()
        .filter(|o| verified.contains(o.id.as_str()))
        .chain(held.records.iter())
        .filter(|o| o.source != SUBMISSION_SOURCE && seen.insert(o.id.clone()))
        .cloned()
        .collect();
    let mut all = standing_recs.clone();
    all.extend(
        claimed_records(&intake.id, &sub.evidence)
            .into_iter()
            .map(|(_, o)| o),
    );
    let standing = Grade::of(&analyze(standing_recs, rules));
    let claimed = Grade::of(&analyze(all, rules));

    let signed = n(EvidenceClass::SignedChecked);
    let strong = n(EvidenceClass::Corroborated) + signed + n(EvidenceClass::VerifiedPredating);
    let inflation = inflation(intake, &standing);
    let mut reasons = Vec::new();
    let refs = sub
        .evidence
        .iter()
        .filter(|e| matches!(e, Evidence::PublicRecord(_)))
        .count()
        + signatures.len();
    let contradicted = n(EvidenceClass::Contradicted);
    let pending = n(EvidenceClass::Unverified);

    let verdict = if items.iter().all(|i| i.class == EvidenceClass::Assertion) {
        reasons.push("nothing in it can be checked: assertions only".into());
        Verdict::Discard
    } else if refs > 0
        && contradicted as f64 / refs as f64 >= s.discard_contradicted_share
        && strong == 0
    {
        reasons.push(format!(
            "{contradicted} of {refs} public-record references are contradicted: missing, different, or newer than the submission"
        ));
        Verdict::Discard
    } else if claimed.flagged == 0 && strong == 0 && pending == 0 {
        reasons.push("nothing in it flags under the rules, and nothing is left to verify".into());
        Verdict::Discard
    } else {
        let enough = n(EvidenceClass::Corroborated) > 0
            || signed > 0
            || n(EvidenceClass::VerifiedPredating) >= s.min_predating;
        if !enough {
            reasons.push(match (n(EvidenceClass::VerifiedPredating), n(EvidenceClass::VerifiedRecent)) {
                (0, 0) if pending > 0 => format!(
                    "{pending} reference(s) not verified yet; nothing the watch held"
                ),
                (0, 0) => "no record the toolkit can find itself: nothing verified, nothing the watch held".into(),
                (p, r) => format!(
                    "{p} verified record(s) predate the submission by {} (needs {}), {r} are newer and could have been submitted just before reporting",
                    span(s.predate_secs),
                    s.min_predating
                ),
            });
        }
        // A checked third-party signature vouches for the submitter's own
        // records; otherwise only what the toolkit found counts.
        let graded = if signed > 0 { &claimed } else { &standing };
        let tier_ok = graded.tier >= s.min_tier;
        if enough && !tier_ok {
            reasons.push(format!(
                "the records found grade {}, below {}",
                graded.tier.label(),
                s.min_tier.label()
            ));
        }
        let planted = standing.plant_signals >= s.max_plant_signals;
        if planted {
            reasons.push(format!(
                "{} plant signals on one cluster of the records found: plant review first",
                standing.plant_signals
            ));
        }
        let inflated = !inflation.is_empty() && strong < s.inflated_min_strong;
        if inflated {
            reasons.push(format!(
                "the claim is larger than the evidence and only {strong} item(s) are strong (needs {})",
                s.inflated_min_strong
            ));
        }
        if let Some(d) = &intake.duplicate_of {
            reasons.push(format!("repeats most of {d}"));
        }
        if enough && tier_ok && !planted && !inflated && intake.duplicate_of.is_none() {
            reasons.insert(
                0,
                format!(
                    "{strong} strong item(s); the records grade {} ({} cluster(s), agent grade {})",
                    graded.tier.label(),
                    graded.clusters,
                    graded.agent
                ),
            );
            Verdict::Examine
        } else {
            Verdict::Hold
        }
    };
    if contradicted > 0 && verdict != Verdict::Discard {
        reasons.push(format!("{contradicted} reference(s) contradicted"));
    }
    for f in &intake.injection {
        reasons.push(format!(
            "instruction-shaped text in {}{}: {} (data, not instructions)",
            f.field,
            if f.in_evidence {
                " (evidence; may be the agent's own payload)"
            } else {
                ""
            },
            f.matched
        ));
    }
    if let Some(c) = &intake.converted_from {
        reasons.push(format!(
            "converted from {}; {} value(s) could not be mapped and are kept as assertions",
            inert(&c.describe(), 40),
            c.unmapped_values
        ));
    }
    let cost = cost(&items, verifications, held, s);
    let standing_tier = standing.tier;
    let score = match verdict {
        Verdict::Examine => 1000,
        Verdict::Hold => 0,
        Verdict::Discard => -1000,
    } + 50 * strong as i64
        + 20 * standing_tier as i64
        + 5 * claimed.tier as i64;
    Assessment {
        id: intake.id.clone(),
        verdict,
        reasons,
        cost,
        items,
        counts,
        standing,
        claimed,
        inflation,
        score,
    }
}

/// Ways the claim outruns what was found.
fn inflation(intake: &Intake, standing: &Grade) -> Vec<String> {
    let c = &intake.submission.claim;
    let mut out = Vec::new();
    if matches!(c.kind, ClaimKind::Swarm | ClaimKind::Fleet) && standing.clusters < 2 {
        out.push(format!(
            "claims a {}; the records found show {} run(s) above noise",
            c.kind.label(),
            standing.clusters
        ));
    }
    if let Some(a) = c.agents
        && a as usize > 5 * standing.clusters.max(1)
    {
        out.push(format!(
            "claims {a} agents; the records found show {} run(s)",
            standing.clusters
        ));
    }
    let shown: BTreeSet<&str> = standing.tactics.iter().map(String::as_str).collect();
    let unshown: Vec<&str> = c
        .tactics
        .iter()
        .map(String::as_str)
        .filter(|t| !shown.contains(t))
        .collect();
    if !unshown.is_empty() {
        out.push(format!(
            "claims {}, which no record found shows",
            unshown.join(", ")
        ));
    }
    if let (Some(f), Some(l)) = (
        c.first_seen.as_deref().and_then(sc_core::parse_ts),
        c.last_seen.as_deref().and_then(sc_core::parse_ts),
    ) {
        let claimed = l - f;
        let shown = standing.span.map_or(0, |(a, b)| b - a);
        if claimed > 86_400 && claimed > 10 * shown.max(1) {
            out.push(format!(
                "claims activity over {}; the records found span {}",
                span(claimed),
                span(shown)
            ));
        }
    }
    out
}

/// What fabricating the evidence would have taken.
fn cost(
    items: &[ItemAssessment],
    verifications: &[Verification],
    held: &Corroboration,
    s: &TriageSettings,
) -> String {
    let lead = verifications
        .iter()
        .filter(|v| v.status == crate::verify::Status::Verified)
        .filter_map(|v| v.lead_secs)
        .max();
    let has = |c: EvidenceClass| items.iter().any(|i| i.class == c);
    if has(EvidenceClass::Corroborated) {
        format!(
            "high: the watch held {} of its records before it arrived",
            held.records.len()
        )
    } else if has(EvidenceClass::SignedChecked) {
        "high: a signature by a key the submitter does not hold covers it".into()
    } else if has(EvidenceClass::VerifiedPredating) {
        format!(
            "raised: its oldest verified record is {} older than the submission, so a fabricator planned that far ahead",
            span(lead.unwrap_or(0))
        )
    } else if has(EvidenceClass::VerifiedRecent) {
        format!(
            "low: every verified record is under {} older than the submission; anyone could have made them just before reporting",
            span(s.predate_secs)
        )
    } else if has(EvidenceClass::Unverified) {
        "unknown until verified".into()
    } else {
        "none: nothing in it is checkable by anyone but the submitter".into()
    }
}

#[cfg(test)]
mod tests;
