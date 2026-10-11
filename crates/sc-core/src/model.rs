//! Core data model shared by every tool in the workspace.

use chrono::{DateTime, NaiveDate, NaiveDateTime, Utc};
use serde::{Deserialize, Deserializer, Serialize};
use std::collections::BTreeMap;

/// One publicly recorded request/scan/capture. Everything we analyse is
/// normalised into this shape regardless of where it was collected.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(from = "StoredObservation")]
pub struct Observation {
    /// Source-specific identifier (scan UUID, CDX timestamp+digest, ...).
    #[serde(default)]
    pub id: String,
    /// Where the record came from: `urlquery`, `wayback`, `arquivo`, `manual`, ...
    #[serde(default)]
    pub source: String,
    /// Unix seconds, UTC. `0` means unknown.
    #[serde(default, deserialize_with = "de_ts")]
    pub ts: i64,
    /// What `ts` is the time of.
    #[serde(default, skip_serializing_if = "TsKind::is_unknown")]
    pub ts_kind: TsKind,
    /// The URL that was requested / submitted.
    pub url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
    /// The network the request came from (the client's).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asn: Option<u32>,
    /// The target's network, where a source records it (a scan service's
    /// scanner reaching the submitted URL). Says nothing about who sent the
    /// request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_asn: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_agent: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub headers: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    /// Where the page ended up (e.g. `about:neterror`, a Cloudflare challenge).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub final_url: Option<String>,
    /// Link to the public record this observation was taken from.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reference: Option<String>,
}

/// What an observation's timestamp is the time of.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TsKind {
    /// When the request reached a server (an access log line).
    Request,
    /// When an archive captured the URL (Wayback, Arquivo.pt).
    Capture,
    /// When the URL was submitted to a scan service (urlquery).
    Submit,
    #[default]
    Unknown,
}

impl TsKind {
    pub fn is_unknown(&self) -> bool {
        *self == Self::Unknown
    }

    /// The kind a record from `source` carries, for records stored before
    /// they said. Only a bare source name counts (`wayback`, not
    /// `wayback:x`), except operator logs, which always carry an evidence id.
    pub fn of_source(source: &str) -> Self {
        let bare = !source.contains(':');
        match SourceKind::of(source) {
            SourceKind::Wayback | SourceKind::Arquivo if bare => Self::Capture,
            SourceKind::Urlquery if bare => Self::Submit,
            SourceKind::AccessLog if bare => Self::Request,
            SourceKind::Operator if !bare => Self::Request,
            _ => Self::Unknown,
        }
    }
}

/// The sources the analysis knows, read from [`Observation::source`]: the
/// part before any `:` (`operator:e1` is [`SourceKind::Operator`]). The
/// field itself stays the string the record carries, since imports and
/// field maps can name any source; this is where its known values are
/// matched.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SourceKind {
    /// A server's access log (`access_log`).
    AccessLog,
    /// Logs an affected operator sent ([`OPERATOR_SOURCE`]).
    Operator,
    Urlquery,
    Urlscan,
    Wayback,
    Arquivo,
    Memento,
    Gharchive,
    Npm,
    Pypi,
    Ctlog,
    Commoncrawl,
    /// Any other source (`manual`, `lines`, an import, a fixture, none).
    Other,
}

impl SourceKind {
    const NAMED: [(SourceKind, &'static str); 12] = [
        (Self::AccessLog, "access_log"),
        (Self::Operator, OPERATOR_SOURCE),
        (Self::Urlquery, "urlquery"),
        (Self::Urlscan, "urlscan"),
        (Self::Wayback, "wayback"),
        (Self::Arquivo, "arquivo"),
        (Self::Memento, "memento"),
        (Self::Gharchive, "gharchive"),
        (Self::Npm, "npm"),
        (Self::Pypi, "pypi"),
        (Self::Ctlog, "ctlog"),
        (Self::Commoncrawl, "commoncrawl"),
    ];

    /// The kind of `source`, by the part before any `:`.
    pub fn of(source: &str) -> Self {
        let name = source.split(':').next().unwrap_or_default();
        Self::NAMED
            .iter()
            .find(|(_, n)| *n == name)
            .map_or(Self::Other, |(k, _)| *k)
    }

    /// The source name records carry (`wayback`); empty for `Other`.
    pub fn name(self) -> &'static str {
        Self::NAMED
            .iter()
            .find(|(k, _)| *k == self)
            .map_or("", |(_, n)| n)
    }
}

/// Who can put a record into its source, which says how hard it is to plant.
/// Derived from [`Observation::source`] (never stored), beside
/// [`TsKind::of_source`]. Written as its [`Provenance::label`]. Ordered by
/// label, so maps keyed by it keep the order they had keyed by the label.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Provenance {
    /// A server recorded the request itself: an access log, logs an affected
    /// operator sent.
    Observed,
    /// Anyone can publish the record under a name of their choosing: GH
    /// Archive events, npm and PyPI packages, Certificate Transparency
    /// entries, and Common Crawl, which crawls what any page links to.
    PublishAnywhere,
    /// Anyone can submit any URL: scan services (urlquery, urlscan) and web
    /// archives, whose index cannot tell an on-demand save (Save Page Now)
    /// from a crawl without opening the capture, so every archive row counts
    /// as submitted.
    SubmitAnywhere,
    /// A source this list does not know (`manual`, an import, a fixture).
    Unknown,
}

impl Provenance {
    /// The provenance of a record from `source`.
    pub fn of_source(source: &str) -> Self {
        use SourceKind::*;
        match SourceKind::of(source) {
            AccessLog | Operator => Self::Observed,
            Urlquery | Urlscan | Wayback | Arquivo | Memento => Self::SubmitAnywhere,
            Gharchive | Npm | Pypi | Ctlog | Commoncrawl => Self::PublishAnywhere,
            Other => Self::Unknown,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Observed => "observed",
            Self::SubmitAnywhere => "submit-anywhere",
            Self::PublishAnywhere => "publish-anywhere",
            Self::Unknown => "unknown",
        }
    }
}

impl std::fmt::Display for Provenance {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.label())
    }
}

/// An observation as stored, which may predate `ts_kind` and `target_asn`.
#[derive(Deserialize)]
struct StoredObservation {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub source: String,
    #[serde(default, deserialize_with = "de_ts")]
    pub ts: i64,
    #[serde(default)]
    pub ts_kind: TsKind,
    pub url: String,
    #[serde(default)]
    pub ip: Option<String>,
    #[serde(default)]
    pub asn: Option<u32>,
    #[serde(default)]
    pub target_asn: Option<u32>,
    #[serde(default)]
    pub user_agent: Option<String>,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    #[serde(default)]
    pub status: Option<u16>,
    #[serde(default)]
    pub final_url: Option<String>,
    #[serde(default)]
    pub reference: Option<String>,
}

impl From<StoredObservation> for Observation {
    fn from(o: StoredObservation) -> Self {
        let mut out = Observation {
            id: o.id,
            source: o.source,
            ts: o.ts,
            ts_kind: o.ts_kind,
            url: o.url,
            ip: o.ip,
            asn: o.asn,
            target_asn: o.target_asn,
            user_agent: o.user_agent,
            headers: o.headers,
            status: o.status,
            final_url: o.final_url,
            reference: o.reference,
        };
        out.upgrade();
        out
    }
}

/// `Observation::source` of logs an affected operator sent us, as
/// `operator:<evidence id>`. They are case evidence, not public records.
pub const OPERATOR_SOURCE: &str = "operator";

impl Observation {
    /// Bring a record stored before `ts_kind` and `target_asn` up to date:
    /// the timestamp kind follows from the source, and a urlquery record's
    /// `asn` was its target's network, never the client's.
    pub fn upgrade(&mut self) {
        if self.ts_kind.is_unknown() {
            self.ts_kind = TsKind::of_source(&self.source);
        }
        if self.source == SourceKind::Urlquery.name() && self.target_asn.is_none() {
            self.target_asn = self.asn.take();
        }
    }

    /// Who can put this record into its source ([`Provenance::of_source`]).
    pub fn provenance(&self) -> Provenance {
        Provenance::of_source(&self.source)
    }

    /// What kind of source the record came from ([`SourceKind::of`]).
    pub fn source_kind(&self) -> SourceKind {
        SourceKind::of(&self.source)
    }

    pub fn operator_supplied(&self) -> bool {
        self.source_kind() == SourceKind::Operator
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IndicatorKind {
    /// Fetch-through / conversion relays (r.jina.ai, allorigins, translate.goog, ...).
    Relay,
    /// Echo or code-hosting services used to carry requests (httpbin, LiveCodes, ...).
    Carrier,
    /// Attack payloads: SQLi, traversal, XSS, command/template injection.
    Exploit,
    /// Tags agents put in URLs (`uqtag=`, `CHATGPTTEST1`, `tok=expt`).
    AgentMarker,
    /// Cache-busting parameters.
    CacheBuster,
    /// Strings where the agent names its model or developer. Weak evidence.
    SelfId,
    /// Disposable inboxes, notification topics, paste bins used for exfil/callbacks.
    Exfil,
    /// Header-level fingerprints (proxy `Via`, normalised `Accept-Encoding`).
    Header,
    /// Outcome states (`about:neterror`, bot challenges).
    Outcome,
    /// Anti-bot token generation / bypass.
    AntiBot,
    /// Hosting infrastructure (ASN, sandbox hostnames).
    Infra,
}

/// What an indicator shows an agent doing: the swarmchasing tactic
/// vocabulary, `T1` to `T9` in rules files and JSON. Descriptive; it never
/// changes a score.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Tactic {
    /// Fetching the page or data the task is about, often through relays.
    #[serde(rename = "T1")]
    TaskRetrieval,
    /// Reaching for more capable tools: carriers, programs, remote browsers.
    #[serde(rename = "T2")]
    ToolEscalation,
    /// Getting past anti-bot and other access controls.
    #[serde(rename = "T3")]
    AccessControlCircumvention,
    /// Probing for vulnerabilities with attack payloads.
    #[serde(rename = "T4")]
    VulnerabilityProbing,
    /// Acquiring accounts, inboxes or identities.
    #[serde(rename = "T5")]
    AccountAcquisition,
    /// Reusing credentials, cookies or tokens.
    #[serde(rename = "T6")]
    CredentialReuse,
    /// Sending results out through callbacks or side channels.
    #[serde(rename = "T7")]
    CallbackChannels,
    /// Reaching targets outside the task.
    #[serde(rename = "T8")]
    OffTaskTargets,
    /// Coordinating with other agents of a fleet.
    #[serde(rename = "T9")]
    InterAgentCoordination,
}

impl Tactic {
    pub const ALL: [Tactic; 9] = [
        Tactic::TaskRetrieval,
        Tactic::ToolEscalation,
        Tactic::AccessControlCircumvention,
        Tactic::VulnerabilityProbing,
        Tactic::AccountAcquisition,
        Tactic::CredentialReuse,
        Tactic::CallbackChannels,
        Tactic::OffTaskTargets,
        Tactic::InterAgentCoordination,
    ];

    /// `T1` to `T9`.
    pub fn id(self) -> &'static str {
        match self {
            Tactic::TaskRetrieval => "T1",
            Tactic::ToolEscalation => "T2",
            Tactic::AccessControlCircumvention => "T3",
            Tactic::VulnerabilityProbing => "T4",
            Tactic::AccountAcquisition => "T5",
            Tactic::CredentialReuse => "T6",
            Tactic::CallbackChannels => "T7",
            Tactic::OffTaskTargets => "T8",
            Tactic::InterAgentCoordination => "T9",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Tactic::TaskRetrieval => "task retrieval",
            Tactic::ToolEscalation => "tool escalation",
            Tactic::AccessControlCircumvention => "access-control circumvention",
            Tactic::VulnerabilityProbing => "vulnerability probing",
            Tactic::AccountAcquisition => "account or identity acquisition",
            Tactic::CredentialReuse => "credential reuse",
            Tactic::CallbackChannels => "callback or side channels",
            Tactic::OffTaskTargets => "off-task targets",
            Tactic::InterAgentCoordination => "inter-agent coordination",
        }
    }
}

impl std::fmt::Display for Tactic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.id())
    }
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, Default,
)]
#[serde(rename_all = "snake_case")]
pub enum Tier {
    #[default]
    Noise,
    Suggestive,
    Significant,
}

impl Tier {
    pub fn label(self) -> &'static str {
        match self {
            Tier::Noise => "noise",
            Tier::Suggestive => "suggestive",
            Tier::Significant => "significant",
        }
    }
}

/// A rule that matched an observation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Hit {
    pub rule_id: String,
    pub kind: IndicatorKind,
    pub weight: i32,
    /// The text that matched (truncated).
    pub matched: String,
    /// 0 = the submitted URL; higher = an unwrapped inner layer.
    pub layer: usize,
    /// The rule's tactic, if it has one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tactic: Option<Tactic>,
    /// The rule only shows that a model wrote the request.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub artifact: bool,
}

/// Something only one operator would hold, which links the records that
/// carry it into one cluster.
///
/// Serialised as a string, `param:<name>=<value>` or `<rule id>:<text>`, the
/// form analysis JSON, case files and evidence bundles have always used.
/// Ordered by that string.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum LinkFeature {
    /// The value of a strong linking parameter (`[linking] strong_params`).
    /// The name is lowercased; the value is kept as written.
    Param { name: String, value: String },
    /// Text a `link = true` rule matched, lowercased.
    Rule { rule: String, value: String },
}

impl LinkFeature {
    pub fn param(name: &str, value: &str) -> Self {
        Self::Param {
            name: name.to_ascii_lowercase(),
            value: value.to_string(),
        }
    }

    pub fn rule(rule: &str, matched: &str) -> Self {
        Self::Rule {
            rule: rule.to_string(),
            value: matched.to_ascii_lowercase(),
        }
    }

    /// The parameter name or the rule id.
    pub fn name(&self) -> &str {
        match self {
            Self::Param { name, .. } => name,
            Self::Rule { rule, .. } => rule,
        }
    }

    /// The identifying text: the parameter's value or what the rule matched.
    pub fn value(&self) -> &str {
        match self {
            Self::Param { value, .. } | Self::Rule { value, .. } => value,
        }
    }
}

impl std::fmt::Display for LinkFeature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Param { name, value } => write!(f, "param:{name}={value}"),
            Self::Rule { rule, value } => write!(f, "{rule}:{value}"),
        }
    }
}

impl std::str::FromStr for LinkFeature {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        if let Some(p) = s.strip_prefix("param:") {
            let (name, value) = p.split_once('=').unwrap_or((p, ""));
            return Ok(Self::Param {
                name: name.into(),
                value: value.into(),
            });
        }
        match s.split_once(':') {
            Some((rule, value)) if !rule.is_empty() => Ok(Self::Rule {
                rule: rule.into(),
                value: value.into(),
            }),
            _ => Err(format!(
                "linking feature `{s}` is neither `param:<name>=<value>` nor `<rule>:<text>`"
            )),
        }
    }
}

impl Ord for LinkFeature {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        let parts = |f: &Self| (matches!(f, Self::Rule { .. }), f.name().to_string());
        self.to_string()
            .cmp(&other.to_string())
            .then_with(|| parts(self).cmp(&parts(other)))
            .then_with(|| self.value().cmp(other.value()))
    }
}

impl PartialOrd for LinkFeature {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Serialize for LinkFeature {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for LinkFeature {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        String::deserialize(d)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

/// Accepts unix seconds (int/float, seconds or millis), RFC 3339, `YYYY-MM-DD HH:MM:SS`,
/// or 14-digit CDX timestamps.
pub fn parse_ts(s: &str) -> Option<i64> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    // CDX timestamps and their prefixes (yyyy, yyyyMM, yyyyMMdd, yyyyMMddhhmm,
    // yyyyMMddhhmmss). Ten digits stays epoch seconds: that is what it always is in practice.
    if matches!(s.len(), 4 | 6 | 8 | 12 | 14) && s.bytes().all(|b| b.is_ascii_digit()) {
        let padded = format!("{s}{}", &"0101000000"[s.len() - 4..]);
        return NaiveDateTime::parse_from_str(&padded, "%Y%m%d%H%M%S")
            .ok()
            .map(|d| d.and_utc().timestamp());
    }
    if let Ok(n) = s.parse::<f64>() {
        return Some(normalise_epoch(n));
    }
    if let Ok(d) = DateTime::parse_from_rfc3339(s) {
        return Some(d.timestamp());
    }
    for fmt in [
        "%Y-%m-%d %H:%M:%S%.f",
        "%Y-%m-%dT%H:%M:%S%.f",
        "%Y-%m-%d %H:%M",
        "%Y/%m/%d %H:%M:%S",
    ] {
        if let Ok(d) = NaiveDateTime::parse_from_str(s, fmt) {
            return Some(d.and_utc().timestamp());
        }
    }
    NaiveDate::parse_from_str(s, "%Y-%m-%d")
        .ok()
        .and_then(|d| d.and_hms_opt(0, 0, 0))
        .map(|d| d.and_utc().timestamp())
}

fn normalise_epoch(n: f64) -> i64 {
    // Anything past year ~5000 in seconds is almost certainly milliseconds.
    if n > 1e11 {
        (n / 1000.0) as i64
    } else {
        n as i64
    }
}

pub fn fmt_ts(ts: i64) -> String {
    if ts <= 0 {
        return "unknown".into();
    }
    DateTime::<Utc>::from_timestamp(ts, 0)
        .map(|d| d.format("%Y-%m-%d %H:%M:%S UTC").to_string())
        .unwrap_or_else(|| ts.to_string())
}

fn de_ts<'de, D: Deserializer<'de>>(d: D) -> Result<i64, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Raw {
        I(i64),
        F(f64),
        S(String),
        N(()),
    }
    Ok(match Raw::deserialize(d)? {
        Raw::I(i) => normalise_epoch(i as f64),
        Raw::F(f) => normalise_epoch(f),
        Raw::S(s) => parse_ts(&s).unwrap_or(0),
        Raw::N(()) => 0,
    })
}

/// The `n` largest counts, largest first, ties in key order.
pub fn top_counts<K: ToString>(m: &BTreeMap<K, usize>, n: usize) -> Vec<(String, usize)> {
    let mut v: Vec<(String, usize)> = m.iter().map(|(k, c)| (k.to_string(), *c)).collect();
    crate::sort::by(&mut v, |a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    v.truncate(n);
    v
}

pub(crate) fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let mut t: String = s.chars().take(max).collect();
        t.push('…');
        t
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamps() {
        assert_eq!(parse_ts("20261004081000"), Some(1791101400));
        assert_eq!(parse_ts("2026-10-04T08:10:00Z"), Some(1791101400));
        assert_eq!(parse_ts("2026-10-04 08:10:00"), Some(1791101400));
        assert_eq!(parse_ts("1791101400000"), Some(1791101400));
        assert_eq!(parse_ts("1791101400"), Some(1791101400));
        assert_eq!(parse_ts("202610040810"), Some(1791101400));
        assert_eq!(parse_ts("20261004"), Some(1791072000));
        assert_eq!(parse_ts("202610"), parse_ts("2026-10-01"));
        assert_eq!(parse_ts("2026"), parse_ts("2026-01-01"));
        assert_eq!(parse_ts("nope"), None);
    }

    #[test]
    fn link_features_keep_their_string_form() {
        for s in [
            "param:uqtag=zz9",
            "param:tok=a=b:c",
            "exfil.webhook_site:webhook.site/0b6c1f0e-1111-4c2a-9a55-3f2e1d0c9b8a",
            "marker.oai_tag:zz=oai17816834089056622",
        ] {
            let f: LinkFeature = s.parse().unwrap();
            assert_eq!(f.to_string(), s);
            let json = serde_json::to_string(&f).unwrap();
            assert_eq!(json, serde_json::to_string(s).unwrap());
            assert_eq!(serde_json::from_str::<LinkFeature>(&json).unwrap(), f);
        }
        let f: LinkFeature = "param:tok=a=b:c".parse().unwrap();
        assert_eq!((f.name(), f.value()), ("tok", "a=b:c"));
        assert_eq!(LinkFeature::rule("r.x", "AbC").value(), "abc");
        assert!("no-colon".parse::<LinkFeature>().is_err());
        let mut v: Vec<LinkFeature> = ["relay.x:a", "param:b=1", "exfil.y:c"]
            .iter()
            .map(|s| s.parse().unwrap())
            .collect();
        v.sort();
        let order: Vec<String> = v.iter().map(ToString::to_string).collect();
        assert_eq!(order, ["exfil.y:c", "param:b=1", "relay.x:a"]);
    }

    #[test]
    fn source_kinds_read_the_name_before_the_colon() {
        for k in SourceKind::NAMED.iter().map(|x| x.0) {
            assert_eq!(SourceKind::of(k.name()), k);
        }
        assert_eq!(SourceKind::of("operator:e1"), SourceKind::Operator);
        assert_eq!(SourceKind::of("manual"), SourceKind::Other);
        assert_eq!(SourceKind::of(""), SourceKind::Other);
        assert_eq!(SourceKind::Other.name(), "");
        // Timestamp kinds read bare names; operator logs always carry an id.
        assert_eq!(TsKind::of_source("wayback"), TsKind::Capture);
        assert_eq!(TsKind::of_source("wayback:x"), TsKind::Unknown);
        assert_eq!(TsKind::of_source("urlquery"), TsKind::Submit);
        assert_eq!(TsKind::of_source("operator:e1"), TsKind::Request);
        assert_eq!(TsKind::of_source("operator"), TsKind::Unknown);
        assert_eq!(Provenance::of_source("operator"), Provenance::Observed);
    }

    #[test]
    fn provenance_orders_and_writes_as_its_label() {
        let all = [
            Provenance::Observed,
            Provenance::SubmitAnywhere,
            Provenance::PublishAnywhere,
            Provenance::Unknown,
        ];
        for p in all {
            let json = serde_json::to_string(&p).unwrap();
            assert_eq!(json, format!("\"{}\"", p.label()));
            assert_eq!(serde_json::from_str::<Provenance>(&json).unwrap(), p);
        }
        // Maps keyed by it keep the order they had keyed by its label.
        let mut by_value = all;
        by_value.sort();
        let mut by_label = all;
        by_label.sort_by_key(|p| p.label());
        assert_eq!(by_value, by_label);
    }
}
