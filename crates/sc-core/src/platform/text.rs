//! Text and name sketches: per-instance values become slots, the rest is
//! hashed. A sketch keeps a MinHash signature of word shingles, a hash of the
//! slotted text (its template), and a short excerpt of the slotted text, so
//! URLs, addresses, mentions, numbers and identifiers never reach storage.

use crate::rules::Rules;
use serde::{Deserialize, Serialize};

/// MinHash functions per signature.
pub const MINHASH: usize = 32;
/// LSH bands over the signature; `MINHASH / BANDS` rows each. Eight bands
/// of four rows catch pairs above about 0.6 similarity.
pub const BANDS: usize = 8;
/// Words of the slotted text the template hash covers.
const SKELETON_WORDS: usize = 48;
/// Characters of slotted text kept as the excerpt.
const EXCERPT_CHARS: usize = 160;

/// What a collector keeps of an event's text.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct TextSketch {
    /// Words after slotting.
    pub words: u32,
    /// Hash of the first words of the slotted text: equal for texts that
    /// differ only in slot values.
    pub skeleton: u64,
    /// MinHash signature over word 3-shingles (2-shingles for short texts).
    pub minhash: Vec<u32>,
    /// The start of the slotted text.
    pub excerpt: String,
    /// Residue rule ids that fire on the raw text ([`super::residue`]).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub residue: Vec<String>,
    /// Coding-harness self-identification on the raw text
    /// ([`super::residue::self_id`]): weak context, not residue.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub self_id: Vec<String>,
}

impl TextSketch {
    /// Estimated Jaccard similarity of the two texts' shingle sets.
    pub fn similarity(&self, other: &TextSketch) -> f64 {
        let n = self.minhash.len().min(other.minhash.len());
        if n == 0 {
            return 0.0;
        }
        let same = (0..n)
            .filter(|&i| self.minhash[i] == other.minhash[i])
            .count();
        same as f64 / n as f64
    }

    /// Hash of LSH band `b`.
    pub fn band(&self, b: usize) -> Option<u64> {
        let rows = MINHASH / BANDS;
        let s = self.minhash.get(b * rows..(b + 1) * rows)?;
        let mut h = FNV_OFFSET ^ b as u64;
        for v in s {
            h = fnv_step(h, &v.to_le_bytes());
        }
        Some(h)
    }
}

/// Sketch `text`. `context` holds per-instance words (owner, repository
/// name, login) that become a slot. `None` for text with no words.
pub fn sketch(text: &str, context: &[&str], rules: &Rules) -> Option<TextSketch> {
    let tokens = slot_tokens(text, context);
    let mut out = token_sketch(&tokens)?;
    out.residue = super::residue::text_residue(text, rules);
    out.self_id = super::residue::self_id(text);
    Some(out)
}

/// The sketch of slotted `tokens` ([`slot_tokens`]): words, template hash,
/// MinHash signature and excerpt, with no residue read. `None` when there
/// are no tokens.
pub fn token_sketch(tokens: &[String]) -> Option<TextSketch> {
    if tokens.is_empty() {
        return None;
    }
    let k = if tokens.len() >= 8 { 3 } else { 2 };
    let shingles: Vec<u64> = if tokens.len() < k {
        vec![fnv(tokens.join(" ").as_bytes())]
    } else {
        tokens
            .windows(k)
            .map(|w| fnv(w.join(" ").as_bytes()))
            .collect()
    };
    let minhash = (0..MINHASH)
        .map(|i| {
            let seed = splitmix(i as u64 + 1);
            shingles
                .iter()
                .map(|&s| (splitmix(s ^ seed) >> 32) as u32)
                .min()
                .unwrap_or(u32::MAX)
        })
        .collect();
    let head: Vec<&str> = tokens
        .iter()
        .take(SKELETON_WORDS)
        .map(String::as_str)
        .collect();
    let joined = tokens.join(" ");
    let mut excerpt: String = joined.chars().take(EXCERPT_CHARS).collect();
    if joined.chars().count() > EXCERPT_CHARS {
        excerpt.push('…');
    }
    Some(TextSketch {
        words: tokens.len() as u32,
        skeleton: fnv(head.join(" ").as_bytes()),
        minhash,
        excerpt: crate::redact::redact_decoded(&excerpt),
        residue: Vec::new(),
        self_id: Vec::new(),
    })
}

/// The words of `text`, lower-cased, with per-instance values as slots:
/// `<url>`, `<email>`, `<user>` (a mention or a context word), `<path>`,
/// `<num>`, `<hex>` and `<id>` (a token mixing letters and digits). Runs of
/// one slot collapse to one.
pub fn slot_tokens(text: &str, context: &[&str]) -> Vec<String> {
    let ctx: Vec<String> = context
        .iter()
        .map(|c| c.to_lowercase())
        .filter(|c| c.len() >= 3)
        .collect();
    let mut out: Vec<String> = Vec::new();
    let push = |t: String, out: &mut Vec<String>| {
        if t.starts_with('<') && out.last() == Some(&t) {
            return;
        }
        out.push(t);
    };
    for raw in text.split_whitespace() {
        let lower = raw.to_lowercase().replace('\u{2019}', "'");
        let trimmed = lower.trim_matches(|c: char| !c.is_alphanumeric() && c != '@' && c != '/');
        if trimmed.is_empty() {
            continue;
        }
        if lower.contains("://") || trimmed.starts_with("www.") {
            push("<url>".into(), &mut out);
            continue;
        }
        if let Some((a, b)) = trimmed.split_once('@')
            && !a.is_empty()
            && b.contains('.')
        {
            push("<email>".into(), &mut out);
            continue;
        }
        if trimmed.starts_with('@') {
            push("<user>".into(), &mut out);
            continue;
        }
        if trimmed.trim_matches('/').contains('/') {
            push("<path>".into(), &mut out);
            continue;
        }
        if ctx
            .iter()
            .any(|c| c == trimmed || c == possessive_base(trimmed))
        {
            push("<user>".into(), &mut out);
            continue;
        }
        for w in trimmed.split(|c: char| !c.is_alphanumeric() && c != '\'') {
            let w = w.trim_matches('\'');
            if w.is_empty() {
                continue;
            }
            push(word_slot(w, &ctx), &mut out);
        }
    }
    out
}

/// `w` without a possessive ending (`'s`, or `'` after an `s`).
fn possessive_base(w: &str) -> &str {
    w.strip_suffix("'s")
        .or_else(|| w.strip_suffix('\'').filter(|b| b.ends_with('s')))
        .unwrap_or(w)
}

/// A word, or the slot it stands for. A context word slots in its
/// possessive too (`acmecorp's`).
fn word_slot(w: &str, ctx: &[String]) -> String {
    if ctx.iter().any(|c| c == w || c == possessive_base(w)) {
        return "<user>".into();
    }
    let digits = w.chars().filter(char::is_ascii_digit).count();
    let letters = w.chars().filter(|c| c.is_alphabetic()).count();
    if digits > 0 && letters == 0 {
        "<num>".into()
    } else if w.len() >= 7 && digits > 0 && w.chars().all(|c| c.is_ascii_hexdigit()) {
        "<hex>".into()
    } else if digits > 0 && w.len() >= 5 || w.len() > 30 {
        "<id>".into()
    } else {
        w.to_string()
    }
}

/// A created item's name with per-instance parts as slots: `<num>`, `<hex>`,
/// `<id>` and `<owner>` (the owner's own name inside the item's). `None`
/// unless the name keeps a literal word of three letters or more and has at
/// least one slot: a plain name ("portfolio", "test") is shared by chance,
/// a template with a counter is not.
pub fn name_template(name: &str, owner: &str) -> Option<String> {
    let owner = owner.trim_start_matches('@').to_lowercase();
    let name = name.to_lowercase();
    let mut parts: Vec<String> = Vec::new();
    let (mut literal, mut slot) = (false, false);
    for p in name.split(['-', '_', '.', ' ', '/']) {
        if p.is_empty() {
            continue;
        }
        let t = if !owner.is_empty() && p == owner {
            "<owner>".to_string()
        } else {
            word_slot(p, &[])
        };
        if t.starts_with('<') {
            slot = true;
        } else if t.chars().filter(|c| c.is_alphabetic()).count() >= 3 {
            literal = true;
        }
        parts.push(t);
    }
    (literal && slot).then(|| parts.join("-"))
}

/// A wiki page title with per-instance parts as slots: the editing user's
/// own name as `<user>`, and the [`name_template`] slots in each part
/// (split on `/`, `_`, `-` and spaces). The namespace prefix stays
/// (`User:<user>/sandbox`, `Draft:probe-<num>`). `None` under the same rule
/// as [`name_template`]: a literal word and a slot.
pub fn wiki_title_template(title: &str, user: &str) -> Option<String> {
    let norm = |s: &str| s.replace('_', " ").to_lowercase();
    let title = norm(title);
    let user = norm(user);
    let (ns, rest) = match title.split_once(':') {
        Some((ns, rest)) if !ns.is_empty() && !ns.contains(' ') => (Some(ns), rest),
        _ => (None, title.as_str()),
    };
    let mut out = String::new();
    let (mut literal, mut slot) = (ns.is_some_and(|n| n.len() >= 3), false);
    for (i, seg) in rest.split('/').enumerate() {
        if i > 0 {
            out.push('/');
        }
        if !user.is_empty() && seg.trim() == user {
            out.push_str("<user>");
            slot = true;
            continue;
        }
        let parts: Vec<String> = seg
            .split(['-', ' '])
            .filter(|p| !p.is_empty())
            .map(|p| {
                let t = word_slot(p, &[]);
                if t.starts_with('<') {
                    slot = true;
                } else if t.chars().filter(|c| c.is_alphabetic()).count() >= 3 {
                    literal = true;
                }
                t
            })
            .collect();
        out.push_str(&parts.join("-"));
    }
    (literal && slot).then(|| match ns {
        Some(ns) => format!("{ns}:{out}"),
        None => out,
    })
}

const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;

fn fnv_step(mut h: u64, bytes: &[u8]) -> u64 {
    for &b in bytes {
        h ^= b as u64;
        h = h.wrapping_mul(0x0100_0000_01b3);
    }
    h
}

/// FNV-1a: stable across runs and platforms, unlike the std hasher.
pub(crate) fn fnv(bytes: &[u8]) -> u64 {
    fnv_step(FNV_OFFSET, bytes)
}

pub(crate) fn splitmix(mut x: u64) -> u64 {
    x = x.wrapping_add(0x9e37_79b9_7f4a_7c15);
    x = (x ^ (x >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    x ^ (x >> 31)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slots_replace_per_instance_values() {
        let t = slot_tokens(
            "Hi @maintainer, see https://x.example/a?b=1 or mail me@x.example. Version 1.2.3 in src/lib.rs, commit deadbeef12, token tok9xyz42q. Thanks, octo-repo",
            &["octo-repo"],
        );
        let s = t.join(" ");
        assert_eq!(
            s,
            "hi <user> see <url> or mail <email> version <num> in <path> commit <hex> token <id> thanks <user>"
        );
    }

    #[test]
    fn texts_differing_in_slots_share_a_skeleton() {
        let r = Rules::default_rules();
        let a = sketch("I found a critical vulnerability in repo-one at line 42. Please review https://a.example/x and fix it urgently.", &["repo-one"], &r).unwrap();
        let b = sketch("I found a critical vulnerability in alpha-lib at line 7. Please review https://b.example/y and fix it urgently.", &["alpha-lib"], &r).unwrap();
        let c = sketch("The build fails on Windows with a linker error when the feature flag is on; logs attached below for reference.", &[], &r).unwrap();
        assert_eq!(a.skeleton, b.skeleton);
        assert!(a.similarity(&b) > 0.9);
        assert!(a.similarity(&c) < 0.2);
        assert!(!a.excerpt.contains("example"), "{}", a.excerpt);
        assert_eq!(a.minhash.len(), MINHASH);
        assert!((0..BANDS).all(|i| a.band(i) == b.band(i)));
    }

    #[test]
    fn name_templates_need_a_word_and_a_slot() {
        assert_eq!(
            name_template("agent-probe-0042", "x").as_deref(),
            Some("agent-probe-<num>")
        );
        assert_eq!(
            name_template("helper_a9f3b21c", "x").as_deref(),
            Some("helper-<hex>")
        );
        assert_eq!(
            name_template("demo-octocat", "octocat").as_deref(),
            Some("demo-<owner>")
        );
        assert_eq!(name_template("portfolio", "x"), None);
        assert_eq!(name_template("v2-1", "x"), None);
    }

    #[test]
    fn wiki_titles_slot_the_editor_and_counters() {
        assert_eq!(
            wiki_title_template("User:Fresh_Editor42/sandbox", "Fresh Editor42").as_deref(),
            Some("user:<user>/sandbox")
        );
        assert_eq!(
            wiki_title_template("Draft:Probe-page_0042", "someone").as_deref(),
            Some("draft:probe-page-<num>")
        );
        assert_eq!(wiki_title_template("Paris", "someone"), None);
        assert_eq!(wiki_title_template("Talk:Paris", "someone"), None);
    }
}
