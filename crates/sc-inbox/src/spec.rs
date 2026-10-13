//! The SC-Submission v1 document ([spec](../../../docs/specs/submission-v1.md),
//! [schema](../../../schemas/sc-submission-v1.json)) and its validation.
//!
//! [`parse`] reads a document and checks what the schema checks, plus the
//! size caps in [`Caps`]. Unknown fields are refused, so a typo is an error
//! rather than evidence silently dropped.

use serde::{Deserialize, Serialize};

/// The value of a document's `spec` field.
pub const SPEC: &str = "SC-Submission v1";

/// One outside report of AI agent activity.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Submission {
    pub spec: String,
    /// When the submitter says it wrote the report. Never trusted: the inbox
    /// records its own receipt time, and every timing check reads that.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub submitted: Option<String>,
    pub submitter: Submitter,
    pub claim: Claim,
    pub evidence: Vec<Evidence>,
}

/// Who is reporting, as they describe themselves. Nothing here is checked;
/// none of it is ever published.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Submitter {
    /// Whether the submitter is an AI agent (true) or a person or
    /// organisation (false).
    pub ai_agent: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<Role>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// For an AI agent: who deploys it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operator: Option<String>,
    /// For an AI agent: the model it runs on, as it describes itself.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    /// How to reach the submitter. Optional; a report may be anonymous.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contact: Option<String>,
    /// A stable name the submitter chooses for itself across reports, used
    /// for rate limits and duplicate checks when the transport gives none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
}

/// The submitter's relation to what it saw.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    /// Runs a system the activity reached.
    Operator,
    Researcher,
    /// Works at an AI provider.
    Provider,
    /// Came across it.
    Bystander,
    Other,
}

/// What the submitter says it saw.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Claim {
    pub summary: String,
    pub kind: ClaimKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_seen: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_seen: Option<String>,
    /// How many agents the submitter thinks took part.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agents: Option<u32>,
    /// Target hosts, plain (`www.example.org`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub targets: Vec<String>,
    /// SC-T tactic ids (`SC-T3`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tactics: Vec<String>,
}

/// The suspected kind of activity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimKind {
    /// Several agents interacting.
    Swarm,
    /// Several runs by one operator.
    Fleet,
    /// One agent run.
    Run,
    #[default]
    Unknown,
}

impl ClaimKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::Swarm => "swarm",
            Self::Fleet => "fleet",
            Self::Run => "run",
            Self::Unknown => "unknown",
        }
    }
}

/// One item of evidence, typed by how it can be checked.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Evidence {
    /// A record in a third-party public source, by its id there.
    PublicRecord(PublicRecord),
    /// Log lines the submitter holds.
    LogLines(LogLines),
    /// A signed artifact: a DKIM-signed message, an HTTP message signature.
    Signed(Signed),
    /// A value: an inbox id, a run tag, a payload, a user agent.
    Indicator(Indicator),
}

impl Evidence {
    pub fn kind(&self) -> &'static str {
        match self {
            Self::PublicRecord(_) => "public_record",
            Self::LogLines(_) => "log_lines",
            Self::Signed(_) => "signed",
            Self::Indicator(_) => "indicator",
        }
    }

    pub fn note(&self) -> Option<&str> {
        match self {
            Self::PublicRecord(r) => r.note.as_deref(),
            Self::LogLines(l) => l.note.as_deref(),
            Self::Signed(s) => s.note.as_deref(),
            Self::Indicator(i) => i.note.as_deref(),
        }
    }
}

/// The public sources a record may be referenced in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecordSource {
    Urlquery,
    Urlscan,
    Wayback,
    Arquivo,
    Commoncrawl,
    Gharchive,
    Npm,
    Pypi,
    /// A Certificate Transparency entry, by its crt.sh id.
    Ctlog,
}

impl RecordSource {
    /// The `source` name sc-core records carry.
    pub fn name(self) -> &'static str {
        match self {
            Self::Urlquery => "urlquery",
            Self::Urlscan => "urlscan",
            Self::Wayback => "wayback",
            Self::Arquivo => "arquivo",
            Self::Commoncrawl => "commoncrawl",
            Self::Gharchive => "gharchive",
            Self::Npm => "npm",
            Self::Pypi => "pypi",
            Self::Ctlog => "ctlog",
        }
    }

    /// The fields a reference to this source needs.
    pub fn required(self) -> &'static [&'static str] {
        match self {
            Self::Urlquery | Self::Urlscan => &["id"],
            Self::Wayback | Self::Arquivo => &["url", "timestamp"],
            Self::Commoncrawl => &["url", "timestamp", "crawl"],
            Self::Gharchive => &["id", "timestamp"],
            Self::Npm | Self::Pypi => &["package", "version"],
            Self::Ctlog => &["id", "domain"],
        }
    }
}

/// A record in a third-party public source.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicRecord {
    pub source: RecordSource,
    /// The record's id there: a urlquery report id, a urlscan uuid, a GH
    /// Archive event id, a crt.sh certificate id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// The URL the record is of. Never fetched.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// The record's time: a capture timestamp (14 digits) or RFC 3339.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<String>,
    /// Common Crawl: the crawl (`CC-MAIN-2026-39`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub crawl: Option<String>,
    /// npm and PyPI: the package name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub package: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// CT: a DNS name on the certificate, to find it by.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

impl PublicRecord {
    fn field(&self, name: &str) -> Option<&str> {
        match name {
            "id" => self.id.as_deref(),
            "url" => self.url.as_deref(),
            "timestamp" => self.timestamp.as_deref(),
            "crawl" => self.crawl.as_deref(),
            "package" => self.package.as_deref(),
            "version" => self.version.as_deref(),
            "domain" => self.domain.as_deref(),
            _ => None,
        }
        .filter(|v| !v.trim().is_empty())
    }

    /// The claimed time, Unix seconds.
    pub fn ts(&self) -> Option<i64> {
        self.timestamp.as_deref().and_then(sc_core::parse_ts)
    }
}

/// How log lines are written.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LogFormat {
    /// Common or Combined Log Format.
    AccessLog,
    /// One JSON record per line, in the toolkit's record shape.
    Ndjson,
    /// One URL per line, optionally after a timestamp.
    Lines,
}

/// Log lines the submitter holds: unverifiable by anyone but their holder.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogLines {
    pub format: LogFormat,
    /// The host the log belongs to, when the lines do not name it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    pub lines: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// Signature schemes a signed artifact may carry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignScheme {
    /// A mail message with its DKIM-Signature header (RFC 6376).
    Dkim,
    /// An HTTP request with Signature-Input and Signature headers (RFC 9421).
    HttpMessageSignature,
    Other,
}

/// A signed artifact, as text: the headers and body the signature covers.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Signed {
    pub scheme: SignScheme,
    pub content: String,
    /// Who signed it, as the signature names them (`d=` domain, key id).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// Kinds of indicator value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IndicatorKind {
    /// A callback inbox or topic id. Data only: never contacted.
    Inbox,
    RunTag,
    Payload,
    UserAgent,
    Url,
    Ip,
    Other,
}

/// A value the submitter saw.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Indicator {
    pub kind: IndicatorKind,
    pub value: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// Size caps on one document. Anything larger is refused, not cut.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Caps {
    /// Bytes of the document as received.
    pub max_bytes: usize,
    pub max_items: usize,
    /// Log lines over every `log_lines` item.
    pub max_lines: usize,
    /// Characters in one string (a line, a value, a summary).
    pub max_chars: usize,
}

impl Default for Caps {
    fn default() -> Self {
        Self {
            max_bytes: 256 * 1024,
            max_items: 200,
            max_lines: 5000,
            max_chars: 8192,
        }
    }
}

/// Parse and validate a document. The errors say what to fix; every one is
/// listed, not only the first.
pub fn parse(text: &str, caps: &Caps) -> Result<Submission, Vec<String>> {
    if text.len() > caps.max_bytes {
        return Err(vec![format!(
            "document is {} bytes; the cap is {}",
            text.len(),
            caps.max_bytes
        )]);
    }
    let s: Submission = serde_json::from_str(text).map_err(|e| vec![format!("not valid: {e}")])?;
    let errs = validate(&s, caps);
    if errs.is_empty() { Ok(s) } else { Err(errs) }
}

/// The checks the schema states, plus the caps.
pub fn validate(s: &Submission, caps: &Caps) -> Vec<String> {
    let mut e = Vec::new();
    if s.spec != SPEC {
        e.push(format!("spec is {:?}; expected {SPEC:?}", s.spec));
    }
    let mut long = |path: &str, v: &str| {
        if v.chars().count() > caps.max_chars {
            e.push(format!(
                "{path} is longer than {} characters",
                caps.max_chars
            ));
        }
    };
    for (path, v) in [
        ("submitter.name", &s.submitter.name),
        ("submitter.operator", &s.submitter.operator),
        ("submitter.model", &s.submitter.model),
        ("submitter.contact", &s.submitter.contact),
        ("submitter.key", &s.submitter.key),
        ("claim.first_seen", &s.claim.first_seen),
        ("claim.last_seen", &s.claim.last_seen),
        ("submitted", &s.submitted),
    ] {
        if let Some(v) = v {
            long(path, v);
        }
    }
    long("claim.summary", &s.claim.summary);
    for (i, ev) in s.evidence.iter().enumerate() {
        if let Some(n) = ev.note() {
            long(&format!("evidence[{i}].note"), n);
        }
        match ev {
            Evidence::PublicRecord(r) => {
                for v in [
                    &r.id,
                    &r.url,
                    &r.timestamp,
                    &r.crawl,
                    &r.package,
                    &r.version,
                    &r.domain,
                ]
                .into_iter()
                .flatten()
                {
                    long(&format!("evidence[{i}]"), v);
                }
            }
            Evidence::LogLines(l) => {
                for (j, line) in l.lines.iter().enumerate() {
                    long(&format!("evidence[{i}].lines[{j}]"), line);
                }
            }
            Evidence::Signed(g) => long(&format!("evidence[{i}].content"), &g.content),
            Evidence::Indicator(x) => long(&format!("evidence[{i}].value"), &x.value),
        }
    }
    if s.claim.summary.trim().is_empty() {
        e.push("claim.summary is empty".into());
    }
    for (path, v) in [
        ("claim.first_seen", &s.claim.first_seen),
        ("claim.last_seen", &s.claim.last_seen),
        ("submitted", &s.submitted),
    ] {
        if let Some(v) = v
            && sc_core::parse_ts(v).is_none()
        {
            e.push(format!("{path} is not a date or time: {v:?}"));
        }
    }
    for t in &s.claim.tactics {
        let ok = t
            .strip_prefix("SC-T")
            .and_then(|n| n.parse::<u8>().ok())
            .is_some_and(|n| (1..=9).contains(&n));
        if !ok {
            e.push(format!("claim.tactics: {t:?} is not SC-T1 to SC-T9"));
        }
    }
    for h in &s.claim.targets {
        if !is_host(h) {
            e.push(format!("claim.targets: {h:?} is not a plain host name"));
        }
    }
    if s.evidence.is_empty() {
        e.push("evidence is empty".into());
    }
    if s.evidence.len() > caps.max_items {
        e.push(format!(
            "{} evidence items; the cap is {}",
            s.evidence.len(),
            caps.max_items
        ));
    }
    let mut lines = 0;
    for (i, ev) in s.evidence.iter().enumerate() {
        match ev {
            Evidence::PublicRecord(r) => {
                for f in r.source.required() {
                    if r.field(f).is_none() {
                        e.push(format!(
                            "evidence[{i}]: a {} record needs `{f}`",
                            r.source.name()
                        ));
                    }
                }
                if r.timestamp.is_some() && r.ts().is_none() {
                    e.push(format!("evidence[{i}].timestamp is not a time"));
                }
                if let Some(u) = &r.url
                    && !(u.starts_with("http://") || u.starts_with("https://"))
                {
                    e.push(format!(
                        "evidence[{i}].url must start with http:// or https://"
                    ));
                }
                if matches!(r.source, RecordSource::Urlquery | RecordSource::Urlscan)
                    && let Some(id) = &r.id
                    && !is_uuidish(id)
                {
                    e.push(format!("evidence[{i}].id is not a report uuid"));
                }
                if let Some(c) = &r.crawl
                    && !is_crawl(c)
                {
                    e.push(format!(
                        "evidence[{i}].crawl is not a crawl id (CC-MAIN-yyyy-ww)"
                    ));
                }
                if let Some(d) = &r.domain
                    && !is_host(d)
                {
                    e.push(format!("evidence[{i}].domain is not a plain host name"));
                }
                if matches!(r.source, RecordSource::Gharchive | RecordSource::Ctlog)
                    && let Some(id) = &r.id
                    && !id.chars().all(|c| c.is_ascii_digit())
                {
                    e.push(format!("evidence[{i}].id must be digits"));
                }
            }
            Evidence::LogLines(l) => {
                if l.lines.is_empty() {
                    e.push(format!("evidence[{i}].lines is empty"));
                }
                lines += l.lines.len();
                if let Some(h) = &l.host
                    && !is_host(h)
                {
                    e.push(format!("evidence[{i}].host is not a plain host name"));
                }
            }
            Evidence::Signed(g) => {
                if g.content.trim().is_empty() {
                    e.push(format!("evidence[{i}].content is empty"));
                }
            }
            Evidence::Indicator(x) => {
                if x.value.trim().is_empty() {
                    e.push(format!("evidence[{i}].value is empty"));
                }
            }
        }
    }
    if lines > caps.max_lines {
        e.push(format!("{lines} log lines; the cap is {}", caps.max_lines));
    }
    e
}

/// Lower-case letters, digits, dots and hyphens, with a dot.
pub fn is_host(h: &str) -> bool {
    !h.is_empty()
        && h.len() <= 253
        && h.contains('.')
        && h.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-')
}

/// `CC-MAIN-2026-39`.
fn is_crawl(s: &str) -> bool {
    let Some(rest) = s.strip_prefix("CC-MAIN-") else {
        return false;
    };
    let b = rest.as_bytes();
    b.len() == 7
        && b[4] == b'-'
        && b.iter()
            .enumerate()
            .all(|(i, c)| i == 4 || c.is_ascii_digit())
}

fn is_uuidish(s: &str) -> bool {
    let s = s.split_once(':').map_or(s, |(_, rest)| rest);
    (8..=64).contains(&s.len()) && s.chars().all(|c| c.is_ascii_hexdigit() || c == '-')
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(crate) const MINIMAL: &str = r#"{
      "spec": "SC-Submission v1",
      "submitter": {"ai_agent": true, "model": "example-model"},
      "claim": {"summary": "relay probes", "kind": "run"},
      "evidence": [{"type": "indicator", "kind": "run_tag", "value": "tag-0001"}]
    }"#;

    #[test]
    fn a_minimal_document_parses() {
        let s = parse(MINIMAL, &Caps::default()).unwrap();
        assert!(s.submitter.ai_agent);
        assert_eq!(s.evidence.len(), 1);
    }

    #[test]
    fn the_committed_example_parses() {
        let text = include_str!("../../../samples/submissions/sc-submission-v1-example.json");
        let s = parse(text, &Caps::default()).unwrap();
        assert_eq!(s.evidence.len(), 6);
        assert_eq!(s.claim.kind, ClaimKind::Fleet);
    }

    #[test]
    fn unknown_fields_and_missing_reference_fields_are_refused() {
        let extra = MINIMAL.replace(
            "\"kind\": \"run\"",
            "\"kind\": \"run\", \"verdict\": \"examine\"",
        );
        assert!(parse(&extra, &Caps::default()).is_err());
        let bad = MINIMAL.replace(
            r#"{"type": "indicator", "kind": "run_tag", "value": "tag-0001"}"#,
            r#"{"type": "public_record", "source": "wayback", "url": "https://a.example/"}"#,
        );
        let errs = parse(&bad, &Caps::default()).unwrap_err();
        assert!(
            errs.iter().any(|e| e.contains("needs `timestamp`")),
            "{errs:?}"
        );
        let extra_item = MINIMAL.replace("\"value\": \"tag-0001\"", "\"value\": \"t\", \"x\": 1");
        assert!(parse(&extra_item, &Caps::default()).is_err());
    }

    #[test]
    fn caps_refuse_oversized_documents() {
        let caps = Caps {
            max_bytes: 100,
            ..Caps::default()
        };
        assert!(parse(MINIMAL, &caps).unwrap_err()[0].contains("bytes"));
        let caps = Caps {
            max_chars: 4,
            ..Caps::default()
        };
        let errs = parse(MINIMAL, &caps).unwrap_err();
        assert!(errs.iter().any(|e| e.contains("claim.summary is longer")));
    }
}
