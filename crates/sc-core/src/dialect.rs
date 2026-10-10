//! Payload dialect and cut lengths: habits in what a client writes.
//!
//! Two hints, none of them evidence on its own:
//!
//! - **Payload dialect.** Language models and the tools built on them reach
//!   for a small, stable set of canonical test payloads: `<script>alert(1)
//!   </script>` rather than `<svg onload=…>`, `' OR 1=1--` rather than
//!   `' OR '1'='1`, three `../` rather than six. [`variants`] names the
//!   canonical payloads in one record's decoded text, [`dialect`] counts them
//!   over a cluster, and [`dialect_pairs`] finds clusters that favour the same
//!   uncommon mix. Every public cheat sheet lists the same payloads, so a
//!   shared dialect is a link to check, never a merge.
//! - **Cut lengths.** A URL cut off mid escape or in an ellipsis was cut by
//!   something with an output limit. [`cut_lengths`] finds several such URLs
//!   cut at nearly the same length, as a model's or tool's fixed limit would.
//!   Scan services shorten long URLs too, so the source's own display limit
//!   has to be ruled out before reading anything into it.

use percent_encoding::percent_decode_str;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;

/// Variants two clusters must share before their dialects are compared.
pub const PAIR_MIN_SHARED: usize = 3;
/// Jaccard similarity of two clusters' variant sets at which they are paired.
pub const PAIR_MIN_JACCARD: f64 = 0.6;
/// Deepest `../` run named on its own; deeper runs share one variant.
pub const MAX_TRAVERSAL_DEPTH: usize = 12;
/// Cut-length settings (`[cut_lengths]` in the rules file).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct CutOptions {
    /// Truncated records that must share a cut length before it is reported.
    pub min_records: usize,
    /// Lengths within this many characters of a common centre count as one
    /// cut length.
    pub tolerance: usize,
    /// The rule whose hit marks a URL as cut off.
    pub rule: String,
}

impl Default for CutOptions {
    fn default() -> Self {
        Self {
            min_records: 3,
            tolerance: 2,
            rule: "marker.truncated_output".into(),
        }
    }
}

/// Canonical test payloads a cluster's records carry.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Dialect {
    /// Records carrying each variant, by `family.variant` id
    /// (`xss.script_alert`, `traversal.depth3`).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub variants: BTreeMap<String, usize>,
    /// Records carrying at least one variant.
    #[serde(default)]
    pub records: usize,
    /// Variants in the order they first appear (records in time order; within
    /// one record, by id).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub first_seen: Vec<String>,
    /// 8 hex digits over the sorted variant ids; empty when there are none.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub signature: String,
}

impl Dialect {
    pub fn is_empty(&self) -> bool {
        self.variants.is_empty()
    }

    /// Variants grouped by family (`xss`, `sqli`, `traversal`, `ssti`, `cmd`),
    /// each as (variant name without the family, records).
    pub fn families(&self) -> BTreeMap<&str, Vec<(&str, usize)>> {
        let mut out: BTreeMap<&str, Vec<(&str, usize)>> = BTreeMap::new();
        for (id, &n) in &self.variants {
            let (fam, var) = id.split_once('.').unwrap_or((id.as_str(), ""));
            out.entry(fam).or_default().push((var, n));
        }
        out
    }
}

/// Two clusters whose records favour the same mix of canonical payloads.
/// A link to check, never a merge.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DialectPair {
    pub a: String,
    pub b: String,
    /// Variant ids both clusters carry, sorted.
    pub shared: Vec<String>,
    /// Shared variants over all variants either cluster carries.
    pub jaccard: f64,
}

fn payload_res() -> &'static [(&'static str, Regex)] {
    static RE: OnceLock<Vec<(&'static str, Regex)>> = OnceLock::new();
    RE.get_or_init(|| {
        // Commands an injection test runs, and what may follow them.
        let cmd = r"(?:id|whoami|uname(?:\s+-a)?|hostname|cat\s+/etc/passwd)";
        let end = r#"(?:$|[\s;&|#'"`)])"#;
        let comment = r"(?:\s|/\*[^*]*\*/)+";
        [
            (
                "xss.script_alert",
                r"<script[^>]*>\s*(?:alert|prompt|confirm)\s*[(`]".to_string(),
            ),
            ("xss.img_onerror", r"<img\b[^>]*?\bonerror\s*=".into()),
            ("xss.svg_onload", r"<svg\b[^>]*?\bonload\s*=".into()),
            (
                "xss.js_uri",
                r"javascript:\s*(?:alert|prompt|confirm|eval|print)\s*[(`]".into(),
            ),
            (
                "xss.attr_breakout",
                r#"["']\s*>\s*<(?:script|img|svg)\b"#.into(),
            ),
            ("sqli.quote_or_1eq1", r"'\s*\)?\s*or\s+1\s*=\s*1\b".into()),
            ("sqli.quote_or_quoted", r"'\s*or\s*'1'\s*=\s*'1".into()),
            ("sqli.numeric_or", r"\b\d+\s+or\s+1\s*=\s*1\b".into()),
            (
                "sqli.union_select",
                format!(r"\bunion{comment}(?:all{comment})?select\b"),
            ),
            ("sqli.sleep", r"\b(?:pg_)?sleep\s*\(\s*\d+\s*\)".into()),
            ("sqli.waitfor", r"\bwaitfor\s+delay\b".into()),
            ("ssti.double_brace", r"\{\{\s*\d+\s*\*\s*\d+\s*\}\}".into()),
            ("ssti.dollar_brace", r"\$\{\s*\d+\s*\*\s*\d+\s*\}".into()),
            ("ssti.erb", r"<%=?\s*\d+\s*\*\s*\d+\s*%>".into()),
            ("ssti.hash_brace", r"#\{\s*\d+\s*\*\s*\d+\s*\}".into()),
            ("cmd.semicolon", format!(r";\s*{cmd}{end}")),
            ("cmd.pipe", format!(r"\|\|?\s*{cmd}{end}")),
            ("cmd.backtick", format!(r"`\s*{cmd}\s*`")),
            ("cmd.subshell", format!(r"\$\(\s*{cmd}\s*\)")),
            ("traversal.backslash", r"\.\.\\".into()),
            ("traversal.nested", r"\.\.\.\.//|\.\.\./\./".into()),
            ("traversal.enc_dots", r"%2e%2e|\.%2e|%2e\.".into()),
            (
                "traversal.overlong",
                r"%c0%ae|%c0%af|%c1%9c|%e0%80%ae".into(),
            ),
        ]
        .into_iter()
        .map(|(id, re)| (id, Regex::new(&re).unwrap()))
        .collect()
    })
}

fn traversal_run_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?:\.\.[/\\])+").unwrap())
}

/// `..%2f` or `..%5c` still encoded after the layer's own decoding: the slash
/// was encoded on purpose, not by a wrapper.
fn enc_slash_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\.\.%(?:2f|5c)").unwrap())
}

/// Canonical payload variants in one record. `raw` is the submitted URL as
/// recorded; `decoded` are its unwrapped layers' texts and parameter values
/// ([`crate::extract::Layer`]). Each text is also read once more decoded and
/// with `+` as a space, so double-encoded and form-encoded payloads count.
pub fn variants<'a>(raw: &str, decoded: impl IntoIterator<Item = &'a str>) -> BTreeSet<String> {
    let raw = raw.to_ascii_lowercase();
    let mut texts: Vec<String> = Vec::new();
    for t in decoded {
        let t = t.to_ascii_lowercase();
        if t.contains('%') {
            let again = percent_decode_str(&t).decode_utf8_lossy().into_owned();
            if again != t {
                texts.push(again);
            }
        }
        if t.contains('+') {
            texts.push(t.replace('+', " "));
        }
        texts.push(t);
    }
    let mut out = BTreeSet::new();
    for (id, re) in payload_res() {
        // Encodings are read from the record as submitted too: decoding the
        // outermost layer already turned them into plain characters.
        let in_raw =
            matches!(*id, "traversal.enc_dots" | "traversal.overlong") && re.is_match(&raw);
        if in_raw || texts.iter().any(|t| re.is_match(t)) {
            out.insert((*id).to_string());
        }
    }
    let raw_path = raw.split(['?', '#']).next().unwrap_or("");
    if enc_slash_re().is_match(raw_path) || texts.iter().any(|t| enc_slash_re().is_match(t)) {
        out.insert("traversal.enc_slash".into());
    }
    // `....//` and `..././` become `../` once a filter strips `../` from them.
    let depth = texts
        .iter()
        .map(|t| t.replace("....//", "../").replace("..././", "../"))
        .flat_map(|t| {
            traversal_run_re()
                .find_iter(&t)
                .map(|m| m.as_str().len() / 3)
                .max()
        })
        .max()
        .unwrap_or(0);
    if depth > 0 {
        out.insert(format!("traversal.depth{}", depth.min(MAX_TRAVERSAL_DEPTH)));
        if texts.iter().any(|t| t.contains("etc/passwd")) {
            out.insert("traversal.etc_passwd".into());
        }
        if texts
            .iter()
            .any(|t| t.contains("win.ini") || t.contains("boot.ini"))
        {
            out.insert("traversal.win_ini".into());
        }
    }
    out
}

/// A cluster's dialect from its records' variants, records in time order.
pub fn dialect(records: &[BTreeSet<String>]) -> Dialect {
    let mut d = Dialect::default();
    let mut seen = BTreeSet::new();
    for r in records {
        if r.is_empty() {
            continue;
        }
        d.records += 1;
        for v in r {
            *d.variants.entry(v.clone()).or_default() += 1;
            if seen.insert(v.clone()) {
                d.first_seen.push(v.clone());
            }
        }
    }
    if !d.variants.is_empty() {
        let ids: Vec<&str> = d.variants.keys().map(String::as_str).collect();
        d.signature = crate::fingerprint::short_hash(&ids.join(","));
    }
    d
}

/// Pairs of clusters (id, dialect) sharing at least [`PAIR_MIN_SHARED`]
/// variants with Jaccard similarity at least [`PAIR_MIN_JACCARD`]. One
/// common payload (`alert(1)` alone) never makes a pair.
pub fn dialect_pairs(clusters: &[(&str, &Dialect)]) -> Vec<DialectPair> {
    let mut out = Vec::new();
    for (i, (a, da)) in clusters.iter().enumerate() {
        if da.variants.len() < PAIR_MIN_SHARED {
            continue;
        }
        for (b, db) in &clusters[i + 1..] {
            let shared: Vec<String> = da
                .variants
                .keys()
                .filter(|k| db.variants.contains_key(*k))
                .cloned()
                .collect();
            if shared.len() < PAIR_MIN_SHARED {
                continue;
            }
            let union = da.variants.len() + db.variants.len() - shared.len();
            let jaccard = shared.len() as f64 / union as f64;
            if jaccard >= PAIR_MIN_JACCARD {
                out.push(DialectPair {
                    a: (*a).to_string(),
                    b: (*b).to_string(),
                    shared,
                    jaccard,
                });
            }
        }
    }
    out
}

/// Several truncated URLs cut at nearly the same length.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CutGroup {
    /// Shortest and longest length in the group, in characters.
    pub min: usize,
    pub max: usize,
    pub records: usize,
}

/// Cut lengths over a cluster's truncated records.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CutLengths {
    /// Distinct truncated URLs.
    #[serde(default)]
    pub truncated: usize,
    /// The largest group of whole-URL lengths, when it has at least
    /// `min_records` records.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<CutGroup>,
    /// The same over the length of the last (cut) parameter value, as recorded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<CutGroup>,
}

impl CutLengths {
    pub fn is_empty(&self) -> bool {
        self.truncated == 0
    }
}

/// A URL that ends mid escape (`%`, `%2`) or in an ellipsis.
pub fn looks_truncated(url: &str) -> bool {
    let u = url.trim_end();
    let b = u.as_bytes();
    u.ends_with('\u{2026}')
        || b.last() == Some(&b'%')
        || (b.len() >= 2 && b[b.len() - 2] == b'%' && b[b.len() - 1].is_ascii_hexdigit())
}

/// `urls`: (URL as recorded, whether the truncation rule fired on it). URLs
/// that look truncated by either test are measured, each distinct URL once.
pub fn cut_lengths(urls: &[(&str, bool)], opts: &CutOptions) -> CutLengths {
    let distinct: BTreeSet<&str> = urls
        .iter()
        .filter(|&&(u, fired)| fired || looks_truncated(u))
        .map(|&(u, _)| u.trim_end())
        .collect();
    let url_lens: Vec<usize> = distinct.iter().map(|u| u.chars().count()).collect();
    let value_lens: Vec<usize> = distinct
        .iter()
        .filter_map(|u| {
            let (_, q) = u.split_once('?')?;
            let last = q.rsplit('&').next()?;
            Some(
                last.split_once('=')
                    .map_or(last, |(_, v)| v)
                    .chars()
                    .count(),
            )
        })
        .collect();
    CutLengths {
        truncated: distinct.len(),
        url: cut_group(url_lens, opts),
        value: cut_group(value_lens, opts),
    }
}

/// The largest set of lengths within `tolerance` of a common centre.
fn cut_group(mut lens: Vec<usize>, opts: &CutOptions) -> Option<CutGroup> {
    crate::sort::sort(&mut lens);
    let mut best: Option<CutGroup> = None;
    for (i, &lo) in lens.iter().enumerate() {
        let n = lens[i..]
            .iter()
            .take_while(|&&l| l - lo <= 2 * opts.tolerance)
            .count();
        if best.is_none_or(|b| n > b.records) {
            best = Some(CutGroup {
                min: lo,
                max: lens[i + n - 1],
                records: n,
            });
        }
    }
    best.filter(|b| b.records >= opts.min_records)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::extract::unwrap_layers;

    /// Variants of a URL, read the way the analysis reads a record.
    fn of(url: &str) -> BTreeSet<String> {
        let layers = unwrap_layers(url);
        let texts: Vec<&str> = layers
            .iter()
            .flat_map(|l| {
                std::iter::once(l.text.as_str()).chain(l.params.iter().map(|(_, v)| v.as_str()))
            })
            .collect();
        variants(url, texts)
    }

    fn ids(v: &[&str]) -> BTreeSet<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn names_canonical_payloads() {
        let cases = [
            (
                "https://a.example/s?q=%3Cscript%3Ealert(1)%3C/script%3E",
                &["xss.script_alert"][..],
            ),
            (
                "https://a.example/s?q=%22%3E%3Cscript%3Ealert(document.domain)%3C/script%3E",
                &["xss.attr_breakout", "xss.script_alert"],
            ),
            (
                "https://a.example/s?q=%3Cimg+src%3Dx+onerror%3Dalert(1)%3E",
                &["xss.img_onerror"],
            ),
            (
                "https://a.example/s?q=<svg/onload=alert(1)>",
                &["xss.svg_onload"],
            ),
            (
                "https://a.example/r?next=javascript:alert(1)",
                &["xss.js_uri"],
            ),
            (
                "https://a.example/i?id=1'%20OR%201=1--",
                &["sqli.quote_or_1eq1"],
            ),
            (
                "https://a.example/i?id=x'+or+'1'='1",
                &["sqli.quote_or_quoted"],
            ),
            ("https://a.example/i?id=1%20OR%201=1", &["sqli.numeric_or"]),
            (
                "https://a.example/i?id=1%20UNION/**/SELECT%20null",
                &["sqli.union_select"],
            ),
            ("https://a.example/i?id=1%20AND%20SLEEP(5)", &["sqli.sleep"]),
            ("https://a.example/t?name={{7*7}}", &["ssti.double_brace"]),
            (
                "https://a.example/t?name=%24%7B7*7%7D",
                &["ssti.dollar_brace"],
            ),
            (
                "https://a.example/t?name=%3C%25%3D%207*7%20%25%3E",
                &["ssti.erb"],
            ),
            (
                "https://a.example/t?name=%23%7B7*7%7D",
                &["ssti.hash_brace"],
            ),
            ("https://a.example/p?host=127.0.0.1;id", &["cmd.semicolon"]),
            ("https://a.example/p?host=x%7Cwhoami", &["cmd.pipe"]),
            ("https://a.example/p?host=%60id%60", &["cmd.backtick"]),
            ("https://a.example/p?host=%24(id)", &["cmd.subshell"]),
            (
                "https://a.example/f?file=../../../etc/passwd",
                &["traversal.depth3", "traversal.etc_passwd"],
            ),
            (
                "https://a.example/f?file=%2e%2e%2f%2e%2e%2fwin.ini",
                &[
                    "traversal.depth2",
                    "traversal.enc_dots",
                    "traversal.win_ini",
                ],
            ),
            (
                "https://a.example/f?file=..%252f..%252fx",
                &["traversal.depth2", "traversal.enc_slash"],
            ),
            (
                "https://a.example/f?file=....//....//x",
                &["traversal.depth2", "traversal.nested"],
            ),
        ];
        for (url, want) in cases {
            assert_eq!(of(url), ids(want), "{url}");
        }
    }

    #[test]
    fn ordinary_requests_carry_no_dialect() {
        for url in [
            "https://a.example/search?q=how+to+alert+users&page=2",
            "https://a.example/docs/../index.html",
            "https://a.example/s?q=select+a+union+rep",
            "https://a.example/p?a=1;b=2&id=7",
            "https://a.example/math?q=7*7",
            "https://a.example/blog/2024/10/01/union-select-committee",
        ] {
            let v = of(url);
            assert!(
                v.is_empty() || v == ids(&["traversal.depth1"]),
                "{url}: {v:?}"
            );
        }
    }

    #[test]
    fn dialect_counts_and_orders() {
        let recs = vec![
            ids(&["sqli.union_select"]),
            BTreeSet::new(),
            ids(&["xss.script_alert", "sqli.union_select"]),
            ids(&["traversal.depth3"]),
        ];
        let d = dialect(&recs);
        assert_eq!(d.records, 3);
        assert_eq!(d.variants.get("sqli.union_select"), Some(&2));
        assert_eq!(
            d.first_seen,
            ["sqli.union_select", "xss.script_alert", "traversal.depth3"]
        );
        assert_eq!(d.signature.len(), 8);
        let mut shuffled = recs.clone();
        shuffled.reverse();
        assert_eq!(dialect(&shuffled).signature, d.signature);
        let fams = d.families();
        assert_eq!(fams["sqli"], [("union_select", 2)]);
        assert!(dialect(&[BTreeSet::new()]).is_empty());
    }

    #[test]
    fn pairs_need_a_shared_uncommon_mix() {
        let mix = dialect(&[ids(&[
            "xss.img_onerror",
            "sqli.quote_or_1eq1",
            "traversal.depth4",
            "ssti.double_brace",
        ])]);
        let same = dialect(&[ids(&[
            "xss.img_onerror",
            "sqli.quote_or_1eq1",
            "traversal.depth4",
        ])]);
        let alert = dialect(&[ids(&["xss.script_alert"])]);
        let other = dialect(&[ids(&[
            "xss.img_onerror",
            "sqli.quote_or_1eq1",
            "traversal.depth4",
            "cmd.pipe",
            "cmd.subshell",
            "sqli.sleep",
            "ssti.erb",
        ])]);
        let p = dialect_pairs(&[("C1", &mix), ("C2", &same), ("C3", &alert), ("C4", &other)]);
        assert_eq!(p.len(), 1, "{p:?}");
        assert_eq!((p[0].a.as_str(), p[0].b.as_str()), ("C1", "C2"));
        assert_eq!(p[0].shared.len(), 3);
        assert!((p[0].jaccard - 0.75).abs() < 1e-9);
        // One person pasting one payload in two places is no pair.
        assert!(dialect_pairs(&[("C1", &alert), ("C2", &alert)]).is_empty());
    }

    #[test]
    fn repeated_cut_lengths() {
        let base = "https://a.example/w?url=https%3A%2F%2Fb.example%2F&note=";
        let urls: Vec<String> = [40, 41, 43, 90]
            .iter()
            .map(|&n| format!("{base}{}%2", "x".repeat(n)))
            .collect();
        let mut input: Vec<(&str, bool)> = urls.iter().map(|u| (u.as_str(), false)).collect();
        input.push(("https://a.example/ok?q=1", false));
        input.push((urls[0].as_str(), true)); // the same URL twice counts once
        let c = cut_lengths(&input, &CutOptions::default());
        assert_eq!(c.truncated, 4);
        let v = c.value.unwrap();
        assert_eq!((v.min, v.max, v.records), (42, 45, 3));
        assert_eq!(c.url.unwrap().records, 3);

        // Cut at scattered lengths: nothing to report.
        let spread: Vec<String> = [10, 30, 60]
            .iter()
            .map(|&n| format!("{base}{}\u{2026}", "x".repeat(n)))
            .collect();
        let input: Vec<(&str, bool)> = spread.iter().map(|u| (u.as_str(), false)).collect();
        let c = cut_lengths(&input, &CutOptions::default());
        assert_eq!(c.truncated, 3);
        assert_eq!((c.url, c.value), (None, None));

        assert!(looks_truncated("https://a.example/?q=a%"));
        assert!(!looks_truncated("https://a.example/?q=50%25"));
        assert!(
            cut_lengths(&[("https://a.example/?q=1", false)], &CutOptions::default()).is_empty()
        );
    }
}
