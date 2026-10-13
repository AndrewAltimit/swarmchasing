//! Taking a submission in: validate, redact, fingerprint, flag, and the
//! anti-abuse checks (duplicates and rate limits per submitter).
//!
//! What is kept is the redacted document only; the bytes as received are
//! hashed for duplicate detection and dropped.

use crate::evidence::item_key;
use crate::inert::{InjectionFlag, injection_flags};
use crate::spec::{Caps, Evidence, Submission, parse};
use sc_core::redact::{redact_decoded, redact_url};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

/// A submission as the inbox keeps it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Intake {
    /// `sub-<yyyymmdd>-<8 hex>`: the receipt date and the content hash.
    pub id: String,
    /// Unix seconds when the inbox received it: the time every timing check
    /// reads. The document's own `submitted` is never trusted.
    pub received: i64,
    /// How it arrived (`email`, `github-pvr`, `drop`, `manual`).
    pub via: String,
    /// Who sent it as the transport saw them (an address, an account),
    /// when known. Private: never shown outside `inbox show`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
    /// SHA-256 of the bytes as received.
    pub sha256: String,
    /// SHA-256 of the redacted evidence, order-free: the same evidence
    /// sent twice, reformatted or reordered, has the same fingerprint.
    pub fingerprint: String,
    /// Values redacted at ingest.
    pub redacted: usize,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub injection: Vec<InjectionFlag>,
    /// An earlier submission most of whose evidence this one repeats.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duplicate_of: Option<String>,
    pub submission: Submission,
}

impl Intake {
    /// The key rate limits and duplicate checks group by: the transport's
    /// sender when known, else the submitter's own key or contact, else
    /// `anonymous`. Lower-cased.
    pub fn submitter_key(&self) -> String {
        submitter_key(self.from.as_deref(), &self.submission)
    }
}

/// See [`Intake::submitter_key`].
pub fn submitter_key(from: Option<&str>, s: &Submission) -> String {
    from.or(s.submitter.key.as_deref())
        .or(s.submitter.contact.as_deref())
        .map(|k| k.trim().to_lowercase())
        .filter(|k| !k.is_empty())
        .unwrap_or_else(|| "anonymous".into())
}

/// Why a document was not taken in.
#[derive(Debug, Clone, PartialEq)]
pub enum Refused {
    Invalid(Vec<String>),
    /// The same evidence is already in the inbox.
    Duplicate(String),
    /// The submitter sent `max` already in the last day.
    RateLimited {
        key: String,
        max: usize,
    },
}

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid(e) => write!(f, "invalid: {}", e.join("; ")),
            Self::Duplicate(id) => write!(f, "duplicate of {id}"),
            Self::RateLimited { key, max } => write!(
                f,
                "rate limited: {max} submissions from {} in the last 24 hours",
                crate::inert::inert(key, 60)
            ),
        }
    }
}

/// What intake needs to know about the submissions already held.
#[derive(Debug, Clone, Default)]
pub struct Prior {
    pub id: String,
    pub received: i64,
    pub key: String,
    pub sha256: String,
    pub fingerprint: String,
    /// [`item_key`]s of its evidence.
    pub items: BTreeSet<String>,
}

impl Prior {
    pub fn of(i: &Intake) -> Self {
        Self {
            id: i.id.clone(),
            received: i.received,
            key: i.submitter_key(),
            sha256: i.sha256.clone(),
            fingerprint: i.fingerprint.clone(),
            items: i.submission.evidence.iter().map(item_key).collect(),
        }
    }
}

/// Settings for intake.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct IntakeSettings {
    pub caps: Caps,
    /// Submissions one key may make in 24 hours.
    pub max_per_key_per_day: usize,
    /// Share of a submission's evidence that, found in one earlier
    /// submission, marks it a repeat of that one.
    pub repeat_share: f64,
}

impl Default for IntakeSettings {
    fn default() -> Self {
        Self {
            caps: Caps::default(),
            max_per_key_per_day: 5,
            repeat_share: 0.8,
        }
    }
}

/// Take `text` in, received at `received` by `via` from `from`.
pub fn intake(
    text: &str,
    received: i64,
    via: &str,
    from: Option<&str>,
    prior: &[Prior],
    settings: &IntakeSettings,
) -> Result<Intake, Refused> {
    let mut s = parse(text, &settings.caps).map_err(Refused::Invalid)?;
    let sha256 = hex(&Sha256::digest(text.as_bytes()));
    let key = submitter_key(from, &s);
    let recent = prior
        .iter()
        .filter(|p| p.key == key && (received - p.received).abs() < 86_400)
        .count();
    // Anonymous submissions share one bucket; that is the price of not
    // giving a key.
    if recent >= settings.max_per_key_per_day {
        return Err(Refused::RateLimited {
            key,
            max: settings.max_per_key_per_day,
        });
    }
    let flags = injection_flags(fields(&s));
    let redacted = redact(&mut s);
    let fingerprint = fingerprint(&s);
    if let Some(p) = prior
        .iter()
        .find(|p| p.sha256 == sha256 || p.fingerprint == fingerprint)
    {
        return Err(Refused::Duplicate(p.id.clone()));
    }
    let items: BTreeSet<String> = s.evidence.iter().map(item_key).collect();
    let duplicate_of = prior
        .iter()
        .filter(|_| !items.is_empty())
        .map(|p| {
            let shared = items.intersection(&p.items).count();
            (shared as f64 / items.len() as f64, p)
        })
        .filter(|(share, _)| *share >= settings.repeat_share)
        .max_by(|a, b| a.0.total_cmp(&b.0))
        .map(|(_, p)| p.id.clone());
    let day = sc_core::fmt_ts(received)
        .get(..10)
        .unwrap_or("0000-00-00")
        .replace('-', "");
    Ok(Intake {
        id: format!("sub-{day}-{}", &fingerprint[..8]),
        received,
        via: via.to_string(),
        from: from.map(str::to_string),
        sha256,
        fingerprint,
        redacted,
        injection: flags,
        duplicate_of,
        submission: s,
    })
}

/// Every free-text and evidence string of `s`: (path, text, is evidence).
pub fn fields(s: &Submission) -> Vec<(String, &str, bool)> {
    let mut v: Vec<(String, &str, bool)> = Vec::new();
    let sub = &s.submitter;
    for (p, t) in [
        ("submitter.name", &sub.name),
        ("submitter.operator", &sub.operator),
        ("submitter.model", &sub.model),
        ("submitter.contact", &sub.contact),
        ("submitter.key", &sub.key),
    ] {
        if let Some(t) = t {
            v.push((p.into(), t, false));
        }
    }
    v.push(("claim.summary".into(), &s.claim.summary, false));
    for (i, e) in s.evidence.iter().enumerate() {
        if let Some(n) = e.note() {
            v.push((format!("evidence[{i}].note"), n, false));
        }
        match e {
            Evidence::PublicRecord(r) => {
                if let Some(u) = &r.url {
                    v.push((format!("evidence[{i}].url"), u, true));
                }
            }
            Evidence::LogLines(l) => {
                for (j, line) in l.lines.iter().enumerate() {
                    v.push((format!("evidence[{i}].lines[{j}]"), line, true));
                }
            }
            Evidence::Signed(g) => v.push((format!("evidence[{i}].content"), &g.content, true)),
            Evidence::Indicator(x) => v.push((format!("evidence[{i}].value"), &x.value, true)),
        }
    }
    v
}

/// Redact secrets everywhere in `s`, as ingest does for records: URLs by
/// [`redact_url`], other text by [`redact_decoded`]. Returns how many
/// values changed.
pub fn redact(s: &mut Submission) -> usize {
    let mut n = 0;
    let mut text = |t: &mut String| {
        let r = redact_decoded(t);
        if r != *t {
            n += 1;
            *t = r;
        }
    };
    text(&mut s.claim.summary);
    for t in [&mut s.submitter.name, &mut s.submitter.operator]
        .into_iter()
        .flatten()
    {
        text(t);
    }
    for e in &mut s.evidence {
        match e {
            Evidence::PublicRecord(r) => {
                if let Some(nt) = &mut r.note {
                    text(nt);
                }
            }
            Evidence::LogLines(l) => {
                for line in &mut l.lines {
                    text(line);
                }
                if let Some(nt) = &mut l.note {
                    text(nt);
                }
            }
            Evidence::Signed(g) => {
                text(&mut g.content);
                if let Some(nt) = &mut g.note {
                    text(nt);
                }
            }
            Evidence::Indicator(x) => {
                text(&mut x.value);
                if let Some(nt) = &mut x.note {
                    text(nt);
                }
            }
        }
    }
    for e in &mut s.evidence {
        let url = match e {
            Evidence::PublicRecord(r) => r.url.as_mut(),
            Evidence::Indicator(x) if x.value.contains("://") => Some(&mut x.value),
            _ => None,
        };
        if let Some(u) = url {
            *u = redact_url(u, &mut n);
        }
    }
    n
}

/// SHA-256 over the sorted [`item_key`]s and the claim.
fn fingerprint(s: &Submission) -> String {
    let mut keys: Vec<String> = s.evidence.iter().map(item_key).collect();
    keys.sort();
    let mut h = Sha256::new();
    h.update(s.claim.summary.trim().as_bytes());
    for k in keys {
        h.update([0u8]);
        h.update(k.as_bytes());
    }
    hex(&h.finalize())
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn doc(key: &str, tag: &str) -> String {
        let fake = "sk-live-1234567890abcdef"; // secret-scan: fixture
        format!(
            r#"{{"spec":"SC-Submission v1","submitter":{{"ai_agent":false,"key":"{key}"}},
            "claim":{{"summary":"probes","kind":"run"}},
            "evidence":[{{"type":"indicator","kind":"run_tag","value":"{tag}"}},
                        {{"type":"indicator","kind":"url","value":"https://a.example/?api_key={fake}"}}]}}"#
        )
    }

    #[test]
    fn redacts_and_refuses_duplicates_and_floods() {
        let s = IntakeSettings::default();
        let a = intake(&doc("k1", "t1"), 1_000_000, "drop", None, &[], &s).unwrap();
        assert!(a.id.starts_with("sub-19700112-"));
        assert!(a.redacted >= 1);
        let Evidence::Indicator(x) = &a.submission.evidence[1] else {
            panic!()
        };
        assert!(x.value.contains("REDACTED-"), "{}", x.value);
        let prior = vec![Prior::of(&a)];
        // Same evidence, reformatted: a duplicate.
        let again = doc("k1", "t1").replace('\n', " ");
        assert_eq!(
            intake(&again, 1_000_100, "drop", None, &prior, &s).unwrap_err(),
            Refused::Duplicate(a.id.clone())
        );
        // A sixth from one key in a day is refused.
        let prior: Vec<Prior> = (0..5)
            .map(|n| Prior {
                id: format!("p{n}"),
                received: 1_000_000,
                key: "k2".into(),
                ..Prior::default()
            })
            .collect();
        assert!(matches!(
            intake(&doc("k2", "t2"), 1_000_500, "drop", None, &prior, &s),
            Err(Refused::RateLimited { .. })
        ));
        // The transport's sender outranks the self-declared key.
        assert!(
            intake(
                &doc("k2", "t2"),
                1_000_500,
                "email",
                Some("x@b.example"),
                &prior,
                &s
            )
            .is_ok()
        );
    }

    #[test]
    fn a_repeat_of_most_evidence_is_marked() {
        let s = IntakeSettings::default();
        let a = intake(&doc("k1", "t1"), 1_000_000, "drop", None, &[], &s).unwrap();
        let more = doc("k3", "t1").replace("probes", "probes again");
        let b = intake(&more, 1_000_100, "drop", None, &[Prior::of(&a)], &s).unwrap();
        assert_eq!(b.duplicate_of.as_deref(), Some(a.id.as_str()));
    }
}
