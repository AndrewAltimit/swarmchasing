//! Outside reports in other standard formats, converted into an
//! SC-Submission so the same validation, redaction, verification and triage
//! apply unchanged.
//!
//! - [`stix`]: a STIX 2.1 bundle.
//! - [`xarf`]: an X-ARF report (v4, and the older v3 layout).
//! - [`iodef`]: an IODEF v2 document (RFC 7970), read by [`xml`].
//!
//! [`detect`] tells the format from the content. [`convert`] maps what it
//! can onto SC-Submission evidence, and keeps everything else as a weak,
//! unverifiable claim: an `other` indicator the triage classes an assertion
//! and corroboration never matches. Nothing is dropped silently and nothing
//! is upgraded: a value becomes a checkable public-record reference only
//! when it names a record by its id in a source the inbox looks up.
//!
//! Hostile input is refused before mapping: a document over the byte cap,
//! nested deeper than [`Caps::max_depth`], holding a string longer than
//! [`Caps::max_chars`], or (XML) declaring a DOCTYPE or an entity. No URL in
//! a document is ever fetched; references are parsed from their text.

pub mod iodef;
pub mod stix;
pub mod xarf;
pub mod xml;

#[cfg(test)]
mod tests;

use crate::evidence::item_key;
use crate::spec::{
    Caps, Claim, Evidence, Indicator, IndicatorKind, LogFormat, LogLines, PublicRecord,
    RecordSource, SPEC, Submission, Submitter, is_host, validate,
};
use sc_core::redact::{redact_decoded, redact_url};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeSet;

/// The formats `inbox add` takes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Format {
    /// SC-Submission v1 JSON, taken as it is.
    Submission,
    /// A STIX 2.1 bundle.
    Stix,
    /// An X-ARF report (JSON): v4, or the v3 layout.
    Xarf,
    /// An IODEF v2 document (XML, RFC 7970).
    Iodef,
}

impl Format {
    pub fn label(self) -> &'static str {
        match self {
            Self::Submission => SPEC,
            Self::Stix => "STIX",
            Self::Xarf => "X-ARF",
            Self::Iodef => "IODEF",
        }
    }

    /// The extension the redacted original is stored under.
    pub fn extension(self) -> &'static str {
        match self {
            Self::Submission => "json",
            Self::Stix => "stix.json",
            Self::Xarf => "xarf.json",
            Self::Iodef => "iodef.xml",
        }
    }
}

impl std::str::FromStr for Format {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        match s {
            "submission" | "sc-submission" => Ok(Self::Submission),
            "stix" => Ok(Self::Stix),
            "xarf" | "x-arf" => Ok(Self::Xarf),
            "iodef" => Ok(Self::Iodef),
            _ => Err(format!("{s}: expected submission, stix, xarf or iodef")),
        }
    }
}

/// The format of `text`, from its content: XML is IODEF; a JSON object with
/// `type: bundle` is STIX, one with `xarf_version` (or v3's `Report`) is
/// X-ARF; anything else is read as an SC-Submission, whose parser says what
/// is wrong with it.
pub fn detect(text: &str) -> Format {
    let t = text.trim_start_matches('\u{feff}').trim_start();
    if t.starts_with('<') {
        return Format::Iodef;
    }
    if !t.starts_with('{') {
        return Format::Submission;
    }
    let Ok(top) = serde_json::from_str::<serde_json::Map<String, Value>>(t) else {
        return Format::Submission;
    };
    if top.contains_key("spec") {
        Format::Submission
    } else if top.get("type").and_then(Value::as_str) == Some("bundle") {
        Format::Stix
    } else if top.contains_key("xarf_version")
        || top.contains_key("ReporterInfo")
        || top.get("Report").is_some_and(Value::is_object)
    {
        Format::Xarf
    } else {
        Format::Submission
    }
}

/// Where a converted submission came from, kept with it so the admin sees
/// its provenance.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ConvertedFrom {
    pub format: Format,
    /// The version the document states (`2.1`, `4.0.0`, `2.00`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// Objects, reports or elements read.
    pub objects: usize,
    /// Evidence items that hold values the converter could not map: kept
    /// as assertions, never matched against the watch store.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unmapped: Vec<usize>,
    /// Unmapped values in all (several may share one item).
    #[serde(default)]
    pub unmapped_values: usize,
    /// What the conversion did that the admin should know: structural
    /// objects read but not mapped, values shortened, references read.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
    /// Values redacted in the stored original.
    #[serde(default)]
    pub original_redacted: usize,
}

impl ConvertedFrom {
    /// The format and the version the document states: `STIX 2.1`.
    pub fn describe(&self) -> String {
        match &self.version {
            Some(v) => format!("{} {}", self.format.label(), short(v, 20)),
            None => self.format.label().to_string(),
        }
    }
}

/// A converted document.
#[derive(Debug, Clone, PartialEq)]
pub struct Converted {
    pub submission: Submission,
    pub from: ConvertedFrom,
}

/// Convert `text`, in `format`, into a validated SC-Submission. Errors say
/// what was refused; every one is listed.
pub fn convert(text: &str, format: Format, caps: &Caps) -> Result<Converted, Vec<String>> {
    if text.len() > caps.max_bytes {
        return Err(vec![format!(
            "document is {} bytes; the cap is {}",
            text.len(),
            caps.max_bytes
        )]);
    }
    let c = match format {
        Format::Submission => {
            return Err(vec![
                "an SC-Submission is parsed, not converted".to_string(),
            ]);
        }
        Format::Stix => stix::convert(&json(text, caps)?, caps),
        Format::Xarf => xarf::convert(&json(text, caps)?, caps),
        Format::Iodef => iodef::convert(&xml::parse(text, caps)?, caps),
    }?;
    let errs = validate(&c.submission, caps);
    if errs.is_empty() {
        Ok(c)
    } else {
        Err(errs
            .into_iter()
            .map(|e| format!("converted from {}: {e}", format.label()))
            .collect())
    }
}

/// Parse a JSON document under the caps: nesting no deeper than
/// `max_depth`, no string (key or value) longer than `max_chars`.
pub(crate) fn json(text: &str, caps: &Caps) -> Result<Value, Vec<String>> {
    let d = depth(text);
    if d > caps.max_depth {
        return Err(vec![format!(
            "nested {d} levels deep; the cap is {}",
            caps.max_depth
        )]);
    }
    let v: Value = serde_json::from_str(text).map_err(|e| vec![format!("not valid JSON: {e}")])?;
    let mut errs = Vec::new();
    long_strings(&v, "$", caps.max_chars, &mut errs);
    if errs.is_empty() { Ok(v) } else { Err(errs) }
}

/// The deepest nesting of `[` and `{` outside strings.
fn depth(text: &str) -> usize {
    let (mut d, mut max, mut in_str, mut esc) = (0usize, 0usize, false, false);
    for b in text.bytes() {
        if in_str {
            match b {
                _ if esc => esc = false,
                b'\\' => esc = true,
                b'"' => in_str = false,
                _ => {}
            }
            continue;
        }
        match b {
            b'"' => in_str = true,
            b'[' | b'{' => {
                d += 1;
                max = max.max(d);
            }
            b']' | b'}' => d = d.saturating_sub(1),
            _ => {}
        }
    }
    max
}

fn long_strings(v: &Value, path: &str, max: usize, errs: &mut Vec<String>) {
    if errs.len() >= 20 {
        return;
    }
    match v {
        Value::String(s) if s.chars().count() > max => {
            errs.push(format!("{path} is longer than {max} characters"));
        }
        Value::Array(a) => {
            for (i, x) in a.iter().enumerate() {
                long_strings(x, &format!("{path}[{i}]"), max, errs);
            }
        }
        Value::Object(o) => {
            for (k, x) in o {
                if k.chars().count() > max {
                    errs.push(format!("a key in {path} is longer than {max} characters"));
                }
                long_strings(x, &format!("{path}.{}", short(k, 40)), max, errs);
            }
        }
        _ => {}
    }
}

/// The original, redacted for storage: every string value of a JSON
/// document (URLs by [`redact_url`], other text by [`redact_decoded`];
/// X-ARF payloads decoded, redacted and encoded again, or replaced by their
/// hash when they are not text), or the whole text of an XML document.
/// Returns the text and how many values changed.
pub fn redact_original(text: &str, format: Format) -> (String, usize) {
    match format {
        Format::Iodef => {
            let r = redact_decoded(text);
            let n = usize::from(r != text);
            (r, n)
        }
        _ => match serde_json::from_str::<Value>(text) {
            Ok(mut v) => {
                let mut n = 0;
                redact_value(&mut v, false, &mut n);
                (serde_json::to_string_pretty(&v).unwrap_or_default(), n)
            }
            Err(_) => {
                let r = redact_decoded(text);
                let n = usize::from(r != text);
                (r, n)
            }
        },
    }
}

fn redact_value(v: &mut Value, payload: bool, n: &mut usize) {
    match v {
        Value::String(s) => {
            let r = if payload {
                match decode_b64(s) {
                    Some(bytes) => match String::from_utf8(bytes) {
                        Ok(t) => {
                            let r = redact_decoded(&t);
                            if r == t {
                                s.clone()
                            } else {
                                encode_b64(r.as_bytes())
                            }
                        }
                        Err(e) => format!("sha256:{}", sha256_hex(e.as_bytes())),
                    },
                    None => redact_decoded(s),
                }
            } else {
                redact_text(s, n)
            };
            if r != *s {
                if payload {
                    *n += 1;
                }
                *s = r;
            }
        }
        Value::Array(a) => a.iter_mut().for_each(|x| redact_value(x, payload, n)),
        Value::Object(o) => {
            for (k, x) in o.iter_mut() {
                redact_value(x, matches!(k.as_str(), "payload" | "Payload"), n);
            }
        }
        _ => {}
    }
}

/// One string redacted as ingest redacts: a bare URL by [`redact_url`],
/// other text by [`redact_decoded`]. Counts a change in `n`.
pub(crate) fn redact_text(s: &str, n: &mut usize) -> String {
    let bare_url =
        (s.starts_with("http://") || s.starts_with("https://")) && !s.contains(char::is_whitespace);
    if bare_url {
        redact_url(s, n)
    } else {
        let r = redact_decoded(s);
        if r != s {
            *n += 1;
        }
        r
    }
}

pub(crate) fn decode_b64(s: &str) -> Option<Vec<u8>> {
    use base64::Engine;
    let clean: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    base64::engine::general_purpose::STANDARD.decode(clean).ok()
}

fn encode_b64(b: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(b)
}

pub(crate) fn sha256_hex(b: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(b)
        .iter()
        .map(|x| format!("{x:02x}"))
        .collect()
}

/// At most `max` characters of `s`, with an ellipsis when cut.
pub(crate) fn short(s: &str, max: usize) -> String {
    if s.chars().count() > max {
        let cut: String = s.chars().take(max.saturating_sub(1)).collect();
        format!("{cut}…")
    } else {
        s.to_string()
    }
}

/// The longest an unmapped value is kept in its claim; the original keeps
/// all of it.
const UNMAPPED_CHARS: usize = 500;
/// Claim targets kept.
const MAX_TARGETS: usize = 50;

/// What a converter collects, and how it becomes a submission.
pub(crate) struct Builder {
    format: Format,
    pub version: Option<String>,
    pub objects: usize,
    pub submitter: Submitter,
    summary: Vec<String>,
    pub submitted: Option<String>,
    first: Option<i64>,
    last: Option<i64>,
    targets: BTreeSet<String>,
    tactics: BTreeSet<String>,
    evidence: Vec<Evidence>,
    keys: BTreeSet<String>,
    unmapped: Vec<String>,
    notes: Vec<String>,
    shortened: usize,
}

impl Builder {
    pub fn new(format: Format) -> Self {
        Self {
            format,
            version: None,
            objects: 0,
            submitter: Submitter::default(),
            summary: Vec::new(),
            submitted: None,
            first: None,
            last: None,
            targets: BTreeSet::new(),
            tactics: BTreeSet::new(),
            evidence: Vec::new(),
            keys: BTreeSet::new(),
            unmapped: Vec::new(),
            notes: Vec::new(),
            shortened: 0,
        }
    }

    /// A part of the claim's summary.
    pub fn summary(&mut self, s: &str) {
        let s = s.trim();
        if !s.is_empty() && !self.summary.iter().any(|x| x == s) {
            self.summary.push(s.to_string());
        }
    }

    /// The activity was seen at `ts` (any time [`sc_core::parse_ts`] reads).
    /// Returns whether it was a time.
    pub fn seen(&mut self, ts: &str) -> bool {
        let Some(t) = sc_core::parse_ts(ts) else {
            return false;
        };
        self.first = Some(self.first.map_or(t, |f| f.min(t)));
        self.last = Some(self.last.map_or(t, |l| l.max(t)));
        true
    }

    /// A target host, when it is a plain host name.
    pub fn target(&mut self, host: &str) {
        let h = host.trim().trim_end_matches('.').to_ascii_lowercase();
        if is_host(&h) && self.targets.len() < MAX_TARGETS {
            self.targets.insert(h);
        }
    }

    /// An SC-T tactic id, when it is one.
    pub fn tactic(&mut self, t: &str) -> bool {
        let t = t.trim().to_ascii_uppercase();
        let ok = t
            .strip_prefix("SC-T")
            .and_then(|n| n.parse::<u8>().ok())
            .is_some_and(|n| (1..=9).contains(&n));
        if ok {
            self.tactics.insert(t);
        }
        ok
    }

    pub fn note(&mut self, s: String) {
        if !self.notes.contains(&s) {
            self.notes.push(s);
        }
    }

    /// An evidence item, once.
    pub fn push(&mut self, e: Evidence) {
        if self.keys.insert(item_key(&e)) {
            self.evidence.push(e);
        }
    }

    pub fn indicator(&mut self, kind: IndicatorKind, value: &str, note: Option<String>) {
        let value = value.trim();
        if value.is_empty() {
            return;
        }
        self.push(Evidence::Indicator(Indicator {
            kind,
            value: value.to_string(),
            note,
        }));
    }

    /// Log lines, the format told from the lines themselves.
    pub fn lines(&mut self, lines: Vec<String>, host: Option<String>, note: Option<String>) {
        let lines: Vec<String> = lines
            .into_iter()
            .map(|l| l.trim_end_matches('\r').to_string())
            .filter(|l| !l.trim().is_empty())
            .collect();
        if lines.is_empty() {
            return;
        }
        self.push(Evidence::LogLines(LogLines {
            format: log_format(&lines),
            host: host.filter(|h| is_host(h)),
            lines,
            note,
        }));
    }

    /// A value that cannot be mapped, kept as an unverifiable claim.
    pub fn unmapped(&mut self, path: &str, value: &str) {
        let value = value.trim();
        if value.is_empty() {
            return;
        }
        let one_line: String = value
            .chars()
            .map(|c| if c.is_control() { ' ' } else { c })
            .collect();
        if one_line.chars().count() > UNMAPPED_CHARS {
            self.shortened += 1;
        }
        let s = format!("{path}: {}", short(&one_line, UNMAPPED_CHARS));
        if !self.unmapped.contains(&s) {
            self.unmapped.push(s);
        }
    }

    /// A reference to a record elsewhere: a public record the inbox can
    /// look up, when it names one by its id; otherwise an unmapped value.
    pub fn reference(
        &mut self,
        path: &str,
        source: Option<&str>,
        id: Option<&str>,
        url: Option<&str>,
        note: Option<String>,
    ) {
        match public_record(source, id, url) {
            Some(mut r) => {
                r.note = note;
                self.push(Evidence::PublicRecord(r));
            }
            None => {
                let what: Vec<&str> = [source, id, url].into_iter().flatten().collect();
                self.unmapped(path, &what.join(" "));
            }
        }
    }

    /// The submission, its unmapped values last. When they would push the
    /// evidence over `max_items`, the rest share one item that says how
    /// many there are; the stored original holds them all.
    pub fn finish(mut self, caps: &Caps) -> Result<Converted, Vec<String>> {
        let label = self.format.label();
        let mut summary = String::new();
        for part in &self.summary {
            if !summary.is_empty() {
                if !summary.ends_with(['.', '!', '?', ':']) {
                    summary.push('.');
                }
                summary.push(' ');
            }
            summary.push_str(part);
        }
        if summary.trim().is_empty() {
            summary = format!("A {label} report with no description.");
        }
        if summary.chars().count() > caps.max_chars {
            summary = short(&summary, caps.max_chars);
            self.notes
                .push("the summary was shortened to the character cap".into());
        }
        if self.shortened > 0 {
            self.notes.push(format!(
                "{} unmapped value(s) shortened to {UNMAPPED_CHARS} characters in their claims; the original keeps them whole",
                self.shortened
            ));
        }
        let mapped = self.evidence.len();
        let from = match &self.version {
            Some(v) => format!("{label} {}", short(v, 20)),
            None => label.to_string(),
        };
        let note = format!("not mappable from {from}: kept as an unverifiable claim");
        let budget = caps.max_items.saturating_sub(mapped).max(1);
        let total = self.unmapped.len();
        let mut values = std::mem::take(&mut self.unmapped);
        let rest = if values.len() > budget {
            values.split_off(budget - 1)
        } else {
            Vec::new()
        };
        let mut unmapped = Vec::new();
        for v in values {
            unmapped.push(self.evidence.len());
            self.evidence.push(Evidence::Indicator(Indicator {
                kind: IndicatorKind::Other,
                value: v,
                note: Some(note.clone()),
            }));
        }
        if !rest.is_empty() {
            let names: Vec<String> = rest
                .iter()
                .take(20)
                .map(|v| v.split(": ").next().unwrap_or("").to_string())
                .collect();
            unmapped.push(self.evidence.len());
            self.evidence.push(Evidence::Indicator(Indicator {
                kind: IndicatorKind::Other,
                value: short(
                    &format!(
                        "{} more unmapped value(s), in the stored original: {}",
                        rest.len(),
                        names.join(", ")
                    ),
                    caps.max_chars,
                ),
                note: Some(note.clone()),
            }));
        }
        let submission = Submission {
            spec: SPEC.to_string(),
            submitted: self
                .submitted
                .as_deref()
                .and_then(sc_core::parse_ts)
                .map(rfc3339),
            submitter: self.submitter,
            claim: Claim {
                summary,
                kind: Default::default(),
                first_seen: self.first.map(rfc3339),
                last_seen: self.last.map(rfc3339),
                agents: None,
                targets: self.targets.into_iter().collect(),
                tactics: self.tactics.into_iter().collect(),
            },
            evidence: self.evidence,
        };
        Ok(Converted {
            submission,
            from: ConvertedFrom {
                format: self.format,
                version: self.version,
                objects: self.objects,
                unmapped,
                unmapped_values: total,
                notes: self.notes,
                original_redacted: 0,
            },
        })
    }
}

/// How log lines are written: access-log lines, JSON records, or URLs.
fn log_format(lines: &[String]) -> LogFormat {
    let clf = |l: &str| {
        let l = l.trim();
        l.contains(" [") && l.contains("] \"") && l.split('"').count() >= 3
    };
    if lines.iter().all(|l| clf(l)) {
        LogFormat::AccessLog
    } else if lines.iter().all(|l| l.trim_start().starts_with('{')) {
        LogFormat::Ndjson
    } else {
        LogFormat::Lines
    }
}

/// A reference to a record in a public source the inbox looks up by id,
/// from a source name, an id and a URL as an outside format gives them.
/// The URL is parsed as text, never opened. `None` when the reference does
/// not name such a record.
pub fn public_record(
    source: Option<&str>,
    id: Option<&str>,
    url: Option<&str>,
) -> Option<PublicRecord> {
    let src = source.unwrap_or("").trim().to_ascii_lowercase();
    let id = id.map(str::trim).filter(|s| !s.is_empty());
    let url = url.map(str::trim).filter(|s| !s.is_empty());
    let (host, path) = url.map(split_url).unwrap_or_default();
    let blank = |source| PublicRecord {
        source,
        id: None,
        url: None,
        timestamp: None,
        crawl: None,
        package: None,
        version: None,
        domain: None,
        note: None,
    };
    let by_id = |source: RecordSource, prefix: &str| {
        let from_url = path
            .strip_prefix(prefix)
            .map(|p| p.trim_end_matches('/').to_string())
            .filter(|p| !p.is_empty() && !p.contains('/'));
        id.map(str::to_string).or(from_url).map(|i| PublicRecord {
            id: Some(i),
            ..blank(source)
        })
    };
    let capture = |source: RecordSource, prefix: &str| {
        let rest = path.strip_prefix(prefix)?;
        let (ts, inner) = rest.split_once('/')?;
        let digits: String = ts.chars().take_while(char::is_ascii_digit).collect();
        if digits.len() != 14 || !(inner.starts_with("http://") || inner.starts_with("https://")) {
            return None;
        }
        Some(PublicRecord {
            url: Some(inner.to_string()),
            timestamp: Some(digits),
            ..blank(source)
        })
    };
    if src.contains("urlscan") || host == "urlscan.io" {
        by_id(RecordSource::Urlscan, "/result/")
    } else if src.contains("urlquery") || host == "urlquery.net" {
        by_id(RecordSource::Urlquery, "/report/")
    } else if src.contains("wayback")
        || src.contains("internet archive")
        || host == "web.archive.org"
    {
        capture(RecordSource::Wayback, "/web/")
    } else if src.contains("arquivo") || host == "arquivo.pt" {
        capture(RecordSource::Arquivo, "/wayback/")
    } else if src == "npm" || src == "pypi" {
        let (package, version) = id?
            .rsplit_once("==")
            .or_else(|| id?.rsplit_once('@'))
            .filter(|(p, v)| !p.is_empty() && !v.is_empty())?;
        Some(PublicRecord {
            package: Some(package.to_string()),
            version: Some(version.to_string()),
            ..blank(if src == "npm" {
                RecordSource::Npm
            } else {
                RecordSource::Pypi
            })
        })
    } else {
        None
    }
}

/// The lower-cased host of a URL and its path (with query), as text.
fn split_url(u: &str) -> (String, String) {
    let rest = u.split_once("://").map_or(u, |(_, r)| r);
    let (host, path) = match rest.find('/') {
        Some(i) => rest.split_at(i),
        None => (rest, ""),
    };
    let host = host.rsplit('@').next().unwrap_or(host);
    let host = host.split(':').next().unwrap_or(host);
    (host.to_ascii_lowercase(), path.to_string())
}

/// The host of an absolute http(s) URL, lower case.
pub(crate) fn url_host(u: &str) -> Option<String> {
    if !(u.starts_with("http://") || u.starts_with("https://")) {
        return None;
    }
    let (h, _) = split_url(u);
    (!h.is_empty()).then_some(h)
}

/// Unix seconds as RFC 3339 (`2026-10-09T18:00:00Z`).
fn rfc3339(ts: i64) -> String {
    let t = sc_core::fmt_ts(ts);
    format!("{}Z", t.trim_end_matches(" UTC").replacen(' ', "T", 1))
}

/// A value of `v` as display text: a string as it is, anything else as
/// compact JSON.
pub(crate) fn text_of(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

/// Indicator kind of an IP address literal.
pub(crate) fn is_ip(s: &str) -> bool {
    s.trim().parse::<std::net::IpAddr>().is_ok()
}
