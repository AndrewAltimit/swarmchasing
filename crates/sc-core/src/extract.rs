//! URL unwrapping and indicator matching for a single observation.
//!
//! Agents rarely hit a target directly: they wrap it in relays
//! (`r.jina.ai/https://...`), carriers (`httpbin.org/anything?url=...`),
//! `data:` URLs carrying fetch programs, or base64 parameters. We peel
//! those layers so rules can see every hop and the real target.

use crate::model::{Hit, LinkFeature, Observation, truncate};
use crate::rules::{Matcher, Rules, Target, host_matches, is_intermediary_kind};
use crate::weburl::WebUrl;
use base64::Engine;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::sync::OnceLock;

const MAX_LAYERS: usize = 16;

/// [`Layer::via`] of the outermost layer: the URL as submitted.
pub const VIA_SUBMITTED: &str = "submitted";
const MAX_DEPTH: usize = 6;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Layer {
    /// How this layer was found: `submitted`, `path`, `query`, `param:<name>`, `base64:<name>`, `data-url`, `embedded`, `translate.goog`, `doubled-scheme`.
    pub via: String,
    pub depth: usize,
    /// Host if this layer is a URL.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    /// Decoded text the `url` rules run against.
    pub text: String,
    #[serde(skip)]
    pub params: Vec<(String, String)>,
}

impl Layer {
    /// The outermost layer: the URL as submitted, not one found inside it.
    pub fn is_submitted(&self) -> bool {
        self.via == VIA_SUBMITTED
    }
}

fn embedded_url_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r#"https?://[^\s"'<>()\\`]+"#).unwrap())
}

fn b64_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^[A-Za-z0-9+/_-]{16,}={0,2}$").unwrap())
}

fn pct_decode(s: &str) -> String {
    percent_encoding::percent_decode_str(s)
        .decode_utf8_lossy()
        .into_owned()
}

/// Decode base64 the way it arrives in the wild: either alphabet (payloads
/// mix `+/` with `-_`), padded or not, and often cut short because scan
/// services truncate long URLs. The longest decodable prefix is used. Text
/// only counts if it is mostly printable and has letters, so random IDs (which
/// decode to binary) are rejected.
pub(crate) fn try_b64(s: &str) -> Option<String> {
    if !b64_re().is_match(s) {
        return None;
    }
    let mut norm: String = s
        .trim_end_matches('=')
        .chars()
        .map(|c| match c {
            '-' => '+',
            '_' => '/',
            c => c,
        })
        .collect();
    norm.truncate(norm.len() - norm.len() % 4);
    let bytes = base64::engine::general_purpose::STANDARD_NO_PAD
        .decode(&norm)
        .ok()?;
    // A cut can split a UTF-8 sequence; lossy decoding keeps the rest.
    let text = String::from_utf8_lossy(&bytes).into_owned();
    let total = text.chars().count();
    let printable = text
        .chars()
        .filter(|&c| (!c.is_control() || c.is_whitespace()) && c != char::REPLACEMENT_CHARACTER)
        .count();
    (printable * 10 >= total * 9 && text.chars().any(|c| c.is_ascii_alphabetic())).then_some(text)
}

/// `www-example-com.translate.goog` -> `www.example.com`
fn untranslate_host(host: &str) -> Option<String> {
    let prefix = host.strip_suffix(".translate.goog")?;
    let mut out = String::new();
    let mut chars = prefix.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '-' {
            if chars.peek() == Some(&'-') {
                chars.next();
                out.push('-');
            } else {
                out.push('.');
            }
        } else {
            out.push(c);
        }
    }
    Some(out)
}

/// A host that is really a URL scheme left over from a doubled scheme.
fn is_scheme_name(host: &str) -> bool {
    matches!(host, "http" | "https" | "hxxp" | "hxxps")
}

/// The URL after a doubled scheme: `https://https://a.example/x` and
/// `http://https//a.example/x` give `https://a.example/x`.
fn after_doubled_scheme(decoded: &str) -> Option<String> {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| Regex::new(r"(?i)^[a-z]+:/*(https?)[:/]+(.+)$").unwrap());
    let c = re.captures(decoded.trim())?;
    Some(format!("{}://{}", c[1].to_ascii_lowercase(), &c[2]))
}

/// Peel every layer we can find, breadth first.
///
/// Decoding can expose secrets ingest never saw (a token inside a base64
/// program, an API key in a percent-encoded inner URL), so every layer's
/// text and parameters are redacted as they are decoded
/// ([`crate::redact::redact_decoded`]), before any rule or output sees them.
pub fn unwrap_layers(url: &str) -> Vec<Layer> {
    use crate::redact::{redact_decoded, redact_param, redact_url};
    let mut layers: Vec<Layer> = Vec::new();
    let mut queue: std::collections::VecDeque<(String, String, usize)> = Default::default();
    let mut seen = BTreeSet::new();
    queue.push_back((url.trim().to_string(), VIA_SUBMITTED.into(), 0));

    while let Some((raw, via, depth)) = queue.pop_front() {
        let raw = if raw.starts_with("data:") {
            raw
        } else {
            redact_url(&raw, &mut 0)
        };
        if layers.len() >= MAX_LAYERS || !seen.insert(raw.clone()) {
            continue;
        }
        let mut children: Vec<(String, String)> = Vec::new();
        let inner = (!raw.starts_with("data:"))
            .then(|| after_doubled_scheme(&pct_decode(&raw)))
            .flatten();
        let doubled = inner.is_some();
        if let Some(inner) = inner {
            children.push((inner, "doubled-scheme".into()));
        }

        if let Some(rest) = raw.strip_prefix("data:") {
            let (meta, body) = rest.split_once(',').unwrap_or(("", rest));
            let content = redact_decoded(&if meta.ends_with(";base64") {
                try_b64(body.trim()).unwrap_or_else(|| pct_decode(body))
            } else {
                pct_decode(body)
            });
            for m in embedded_url_re().find_iter(&content) {
                children.push((m.as_str().to_string(), "embedded".into()));
            }
            layers.push(Layer {
                via,
                depth,
                host: None,
                text: format!("data:{meta},{content}"),
                params: vec![],
            });
        } else if let Some(parsed) = WebUrl::parse(&raw) {
            // `https://https://a.example/` parses with the host `https`: a
            // scheme written twice. The URL after it is the real one.
            // Quotes, backticks and punctuation a model wrote around the URL
            // are not part of the host ([`crate::weburl::normalise_host`]).
            let host = parsed
                .host
                .clone()
                .filter(|h| !doubled || !is_scheme_name(h.trim_end_matches("%3a")));
            let pairs = parsed.query_pairs();
            let sas = pairs.iter().any(|(k, _)| k == "sv");
            let params: Vec<(String, String)> = pairs
                .into_iter()
                .map(|(k, v)| {
                    let v = redact_param(&k, v, sas);
                    (k, v)
                })
                .collect();

            // Embedded URL in the path: r.jina.ai/https://target/...
            let path = pct_decode(&parsed.path);
            if let Some(i) = path.find("http://").or_else(|| path.find("https://")) {
                let mut inner = path[i..].to_string();
                if let Some(q) = parsed.query {
                    inner.push('?');
                    inner.push_str(q);
                }
                children.push((inner, "path".into()));
            }
            // Base64 in a path segment: `httpbin.org/base64/<payload>` echoes the
            // decoded payload back, which is how programs were delivered to a
            // remote browser. Only decodings that look like a URL or a program
            // count, so ordinary opaque IDs in paths are left alone.
            // Standard base64 contains `/`, so the payload can span several
            // segments: try the rest of the path from each segment on, and stop
            // at the first decoding that looks like a URL or a program.
            let segs: Vec<String> = parsed.path_segments().into_iter().map(pct_decode).collect();
            for i in 0..segs.len() {
                let Some(decoded) = try_b64(&segs[i..].join("/")).map(|d| redact_decoded(&d))
                else {
                    continue;
                };
                let d = decoded.trim();
                if d.starts_with("http://") || d.starts_with("https://") || d.starts_with("data:") {
                    children.push((d.to_string(), "base64:path".into()));
                    break;
                }
                if d.contains('<') || d.contains("://") || d.contains("fetch(") {
                    for m in embedded_url_re().find_iter(d) {
                        children.push((m.as_str().to_string(), "embedded".into()));
                    }
                    if layers.len() + 1 < MAX_LAYERS {
                        layers.push(Layer {
                            via: "base64:path".into(),
                            depth: depth + 1,
                            host: None,
                            text: decoded.clone(),
                            params: vec![],
                        });
                    }
                    break;
                }
            }
            // A whole query that is a URL: `corsproxy.io/?https://target/...`.
            if let Some(q) = parsed.query.map(pct_decode)
                && (q.starts_with("http://") || q.starts_with("https://"))
            {
                children.push((q, "query".into()));
            }
            if let Some(h) = host.as_deref().and_then(untranslate_host) {
                let mut inner = format!("https://{h}{}", parsed.path);
                if let Some(q) = parsed.query {
                    inner.push('?');
                    inner.push_str(q);
                }
                children.push((inner, "translate.goog".into()));
            }
            for (k, v) in &params {
                let v = v.trim();
                if v.starts_with("http://") || v.starts_with("https://") || v.starts_with("data:") {
                    children.push((v.to_string(), format!("param:{k}")));
                } else if let Some(decoded) = try_b64(v).map(|d| redact_decoded(&d)) {
                    let d = decoded.trim();
                    if d.starts_with("http://")
                        || d.starts_with("https://")
                        || d.starts_with("data:")
                    {
                        children.push((d.to_string(), format!("base64:{k}")));
                    } else {
                        // Program text: keep as a layer of its own and look inside it.
                        for m in embedded_url_re().find_iter(d) {
                            children.push((m.as_str().to_string(), "embedded".into()));
                        }
                        if layers.len() + 1 < MAX_LAYERS {
                            layers.push(Layer {
                                via: format!("base64:{k}"),
                                depth: depth + 1,
                                host: None,
                                text: decoded.clone(),
                                params: vec![],
                            });
                        }
                    }
                }
            }
            layers.push(Layer {
                via,
                depth,
                host,
                text: redact_decoded(&pct_decode(&raw)),
                params,
            });
        } else {
            // Not a URL we can parse; still scan it as text.
            let text = redact_decoded(&raw);
            for m in embedded_url_re().find_iter(&text) {
                children.push((m.as_str().to_string(), "embedded".into()));
            }
            layers.push(Layer {
                via,
                depth,
                host: None,
                text,
                params: vec![],
            });
        }

        if depth < MAX_DEPTH {
            for (u, v) in children {
                queue.push_back((u, v, depth + 1));
            }
        }
    }
    layers
}

/// Everything we learned about one observation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Extracted {
    pub layers: Vec<Layer>,
    pub hits: Vec<Hit>,
    pub score: i32,
    pub significant_hit: bool,
    /// The innermost host that is not a known relay/carrier/inbox.
    pub target_host: Option<String>,
    /// Linking features (inbox IDs, unique tags).
    pub features: Vec<LinkFeature>,
}

pub fn extract(obs: &Observation, rules: &Rules) -> Extracted {
    let layers = unwrap_layers(&obs.url);
    let mut hits: Vec<Hit> = Vec::new();
    let mut features = BTreeSet::new();
    let mut fired = BTreeSet::new();
    let mut significant_hit = false;

    // Layers whose own host is a relay/carrier/inbox, so they are not the real target.
    let mut intermediary = vec![false; layers.len()];

    let mut push = |hits: &mut Vec<Hit>,
                    features: &mut BTreeSet<LinkFeature>,
                    r: &crate::rules::CompiledRule,
                    m: &str,
                    layer: usize| {
        if r.def.link {
            features.insert(LinkFeature::rule(&r.def.id, m));
        }
        if fired.insert(r.def.id.clone()) {
            significant_hit |= r.def.significant;
            hits.push(Hit {
                rule_id: r.def.id.clone(),
                kind: r.def.kind,
                weight: r.def.weight,
                matched: truncate(m, 160),
                layer,
                tactic: r.def.tactic,
                artifact: r.def.artifact,
            });
        }
    };

    let ua = obs.user_agent.as_deref().or_else(|| {
        obs.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("user-agent"))
            .map(|(_, v)| v.as_str())
    });
    for (i, layer) in layers.iter().enumerate() {
        if let Some(host) = &layer.host {
            for r in rules.of_target(Target::Host) {
                if let Matcher::HostSuffix(s) = &r.matcher
                    && host_matches(host, s)
                {
                    if is_intermediary_kind(r.def.kind) {
                        intermediary[i] = true;
                    }
                    push(&mut hits, &mut features, r, host, i);
                }
            }
        }
        for r in rules.matching(Target::Url, &layer.text) {
            if let Matcher::Re(re) = &r.matcher
                && let Some(m) = kept_match(re, &layer.text)
            {
                // A URL rule marks the layer as an intermediary only when it matched the host part.
                let host_end = layer
                    .host
                    .as_deref()
                    .and_then(|h| layer.text.find(h).map(|p| p + h.len()));
                if is_intermediary_kind(r.def.kind) && host_end.is_some_and(|e| m.start() < e) {
                    intermediary[i] = true;
                }
                push(&mut hits, &mut features, r, m.as_str(), i);
            }
        }
        for (k, v) in &layer.params {
            for r in rules.matching(Target::ParamName, k) {
                push(&mut hits, &mut features, r, &format!("{k}={v}"), i);
            }
            for r in rules.matching(Target::ParamValue, v) {
                if let Matcher::Re(re) = &r.matcher
                    && let Some(m) = kept_match(re, v)
                    && r.def.check.is_none_or(|c| c.passes(v, ua))
                {
                    push(
                        &mut hits,
                        &mut features,
                        r,
                        &format!("{k}={}", m.as_str()),
                        i,
                    );
                }
            }
            if rules
                .set
                .linking
                .strong_params
                .iter()
                .any(|p| p.eq_ignore_ascii_case(k))
                && v.len() >= 3
            {
                features.insert(LinkFeature::param(k, v));
            }
        }
    }

    let header_lines: Vec<String> = obs
        .headers
        .iter()
        .map(|(k, v)| format!("{}: {}", k.to_ascii_lowercase(), v.trim()))
        .collect();
    for r in rules.of_target(Target::Header) {
        if let Matcher::Re(re) = &r.matcher
            && let Some(line) = header_lines
                .iter()
                .find(|l| re.is_match(l) && r.def.check.is_none_or(|c| c.passes(l, ua)))
        {
            push(&mut hits, &mut features, r, line, 0);
        }
    }
    if let Some(ua) = ua {
        for r in rules.matching(Target::UserAgent, ua) {
            if let Matcher::Re(re) = &r.matcher
                && let Some(m) = kept_match(re, ua)
            {
                push(&mut hits, &mut features, r, m.as_str(), 0);
            }
        }
    }
    if let Some(fin) = &obs.final_url {
        for r in rules.matching(Target::FinalUrl, fin) {
            if let Matcher::Re(re) = &r.matcher
                && let Some(m) = kept_match(re, fin)
            {
                push(&mut hits, &mut features, r, m.as_str(), 0);
            }
        }
    }

    let score = rules.score(hits.iter().map(|h| h.rule_id.as_str()));
    let target_host = layers
        .iter()
        .enumerate()
        .rev()
        .filter(|(i, _)| !intermediary[*i])
        .filter_map(|(_, l)| l.host.as_deref())
        .find(|h| !rules.is_intermediary_host(h))
        .map(str::to_string);

    Extracted {
        layers,
        hits,
        score,
        significant_hit,
        target_host,
        features: features.into_iter().collect(),
    }
}

/// Hosts in `obs` that a relay, carrier or callback rule matched by the
/// host itself: a reader service, a carrier, or an agent's inbox or side
/// channel. None of them is the target, and a callback host is the agent's
/// own channel, so nothing is ever fetched from one (contact discovery
/// included).
pub fn intermediary_hosts(obs: &Observation, rules: &Rules) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for layer in unwrap_layers(&obs.url) {
        let Some(host) = layer.host.as_deref() else {
            continue;
        };
        if layer_is_intermediary(&layer, host, rules) {
            out.insert(host.to_ascii_lowercase());
        }
    }
    out
}

/// True when `host` is a relay, carrier or callback host by the rules
/// alone: a host suffix of one of those kinds, or a URL pattern of one that
/// matches the host as a URL's authority (`https://<host>/`). A callback
/// rule that needs a path (an inbox id) is only seen in a record; see
/// [`intermediary_hosts`].
pub fn is_intermediary_host(rules: &Rules, host: &str) -> bool {
    let host = host.to_ascii_lowercase();
    if rules.is_intermediary_host(&host) {
        return true;
    }
    unwrap_layers(&format!("https://{host}/"))
        .first()
        .is_some_and(|l| layer_is_intermediary(l, &host, rules))
}

/// The marking [`extract`] makes: a relay, carrier or callback rule matched
/// this layer's own host.
fn layer_is_intermediary(layer: &Layer, host: &str, rules: &Rules) -> bool {
    let by_suffix = rules.of_target(Target::Host).any(|r| {
        is_intermediary_kind(r.def.kind)
            && matches!(&r.matcher, Matcher::HostSuffix(s) if host_matches(host, s))
    });
    if by_suffix || rules.is_intermediary_host(host) {
        return true;
    }
    let host_end = layer.text.find(host).map(|p| p + host.len());
    rules.matching(Target::Url, &layer.text).any(|r| {
        is_intermediary_kind(r.def.kind)
            && matches!(&r.matcher, Matcher::Re(re)
                if re.find(&layer.text).is_some_and(|m| host_end.is_some_and(|e| m.start() < e)))
    })
}

/// A host name made safe to print: `example[.]com`.
pub fn defang_host(host: &str) -> String {
    host.replace('.', "[.]")
}

/// Make URLs safe to paste into a report: `hxxps://example[.]com/...`.
/// Every embedded URL is defanged, not just the outermost, and so is a
/// host after `//` without a scheme (`//a.example`, `%2F%2Fa.example`).
/// Within a URL (from its scheme or `//` to the next space or quote) every
/// host name or address is defanged wherever it sits: in a path, a query
/// value (`site%3Aa.example`, `user%40a.example`) or a fragment. Text
/// outside a URL is left as it is, so a rule id (`relay.jina`) stays
/// readable; [`defang_hosts`] defangs bare hosts there too.
pub fn defang(s: &str) -> String {
    static RE: OnceLock<Regex> = OnceLock::new();
    static BARE: OnceLock<Regex> = OnceLock::new();
    static SPAN: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| Regex::new(r"(?i)(h)tt(ps?)://([^/?#\s]+)").unwrap());
    let bare = BARE.get_or_init(|| {
        Regex::new(r"(?i)(//|%2f%2f)([a-z0-9][a-z0-9-]*(?:\.[a-z0-9-]+)+)").unwrap()
    });
    let span = SPAN.get_or_init(|| Regex::new(r#"(?i)(?://|%2f%2f)[^\s"'<>`]*"#).unwrap());
    // A scheme glued to the one before it (`https://https://a.example`) is
    // read as that one's host, so the pass repeats until no scheme is left;
    // each pass removes at least one.
    let mut s = s.to_string();
    while re.is_match(&s) {
        s = re
            .replace_all(&s, |c: &regex::Captures| {
                format!(
                    "{}xx{}://{}",
                    &c[1],
                    &c[2],
                    c[3].replace("[.]", ".").replace('.', "[.]")
                )
            })
            .into_owned();
    }
    let s = bare.replace_all(&s, |c: &regex::Captures| {
        format!("{}{}", &c[1], c[2].replace('.', "[.]"))
    });
    span.replace_all(&s, |c: &regex::Captures| defang_bare(&c[0]))
        .into_owned()
}

/// Text made safe to print wherever a host may sit outside a URL (a link
/// feature, a soft-link detail, an identifier): URLs defanged as [`defang`]
/// does, then every bare host name left (`a.example`, `1.2.3.4`) written
/// `a[.]example`. A run of letters, digits, dots and hyphens counts as a
/// host when its labels are all non-empty and its last is two or more
/// letters (not a file suffix such as `php`), or when it is four numbers of
/// at most 255 not following a product name (`Chrome/138.0.0.0`); so
/// `0.52`, `e.g`, `v1.2` and `index.html` stay as they are.
pub fn defang_hosts(s: &str) -> String {
    defang_bare(&defang(s))
}

/// The bare-host pass of [`defang`]: every host name or address left in
/// `s` written `a[.]example`.
fn defang_bare(s: &str) -> String {
    /// File name suffixes that are no top-level domain, so `d.php` or
    /// `robots.txt` cannot be a host and stays readable. A suffix that is
    /// also a TLD (`.zip`, `.sh`, `.md`) is not listed.
    const FILE_SUFFIXES: &[&str] = &[
        "asp", "aspx", "bak", "cfg", "cgi", "css", "csv", "exe", "gif", "gz", "htm", "html", "ico",
        "ini", "jpeg", "jpg", "js", "json", "jsp", "log", "pdf", "php", "png", "svg", "tar",
        "toml", "txt", "wasm", "webp", "woff", "woff2", "xml", "yaml", "yml",
    ];
    let hosty = |c: char| c.is_ascii_alphanumeric() || c == '.' || c == '-';
    let mut out = String::with_capacity(s.len() + 8);
    let mut word = String::new();
    let flush = |word: &mut String, out: &mut String| {
        // Dots at either end belong to the text around the host.
        let core = word.trim_matches('.');
        let start = word.len() - word.trim_start_matches('.').len();
        let labels: Vec<&str> = core.split('.').collect();
        let named = labels.len() > 1
            && labels.iter().all(|l| !l.is_empty())
            && labels
                .last()
                .is_some_and(|l| l.len() > 1 && l.chars().all(|c| c.is_ascii_alphabetic()))
            && !labels
                .last()
                .is_some_and(|l| FILE_SUFFIXES.contains(&l.to_ascii_lowercase().as_str()));
        // `Chrome/138.0.0.0` is a version, not an address.
        let mut before = out.chars().rev();
        let version =
            before.next() == Some('/') && before.next().is_some_and(|c| c.is_alphanumeric());
        let ip = labels.len() == 4
            && !version
            && labels
                .iter()
                .all(|l| !l.is_empty() && l.len() <= 3 && l.parse::<u16>().is_ok_and(|n| n < 256));
        if named || ip {
            out.push_str(&word[..start]);
            out.push_str(&defang_host(core));
            out.push_str(&word[start + core.len()..]);
        } else {
            out.push_str(word);
        }
        word.clear();
    };
    for c in s.chars() {
        if hosty(c) {
            word.push(c);
        } else {
            flush(&mut word, &mut out);
            out.push(c);
        }
    }
    flush(&mut word, &mut out);
    out
}

/// Defanged text cut to `max` characters, with `…` when cut. Defang
/// first and cut after (`clip_defanged(&defang_hosts(s), 90)`): a host
/// cut before defanging (`a.example.n`) no longer reads as one. A cut
/// never ends inside a `[.]`.
pub fn clip_defanged(defanged: &str, max: usize) -> String {
    if defanged.chars().count() <= max {
        return defanged.to_string();
    }
    let mut t: String = defanged.chars().take(max).collect();
    if t.ends_with("[.") {
        t.truncate(t.len() - 2);
    } else if t.ends_with('[') && defanged[t.len()..].starts_with(".]") {
        t.truncate(t.len() - 1);
    }
    t.push('…');
    t
}

/// A linking feature's text (`<rule>:<value>` or `param:<name>=<value>`)
/// made safe to print: the rule id or parameter name kept as it is, since
/// `exfil.requestbin` names a rule, not a host, and the value defanged by
/// [`defang_hosts`]. Text of neither form is defanged whole.
pub fn defang_feature(s: &str) -> String {
    let split = if let Some(p) = s.strip_prefix("param:") {
        p.find('=').map(|i| "param:".len() + i + 1)
    } else {
        s.find(':')
            .filter(|&i| i > 0 && !s[..i].contains(|c: char| c.is_whitespace() || c == '/'))
            .map(|i| i + 1)
    };
    match split {
        Some(i) => format!("{}{}", &s[..i], defang_hosts(&s[i..])),
        None => defang_hosts(s),
    }
}

/// Where `re` matches `text`: the group named `m` when the pattern has one,
/// else the whole match. The group lets a pattern see context it does not
/// keep (`(^|[^a-z])(?P<m>agenttest\d*)`: no letter before the tag), since
/// the matched text is what a linking rule links on.
fn kept_match<'t>(re: &regex::Regex, text: &'t str) -> Option<regex::Match<'t>> {
    if re.capture_names().any(|n| n == Some("m")) {
        let c = re.captures(text)?;
        c.name("m").or_else(|| c.get(0))
    } else {
        re.find(text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn obs(url: &str) -> Observation {
        Observation {
            url: url.into(),
            ts: 1,
            ..Default::default()
        }
    }

    #[test]
    fn unwraps_relay_chain() {
        let l = unwrap_layers(
            "https://r.jina.ai/https://api.allorigins.win/raw?url=https%3A%2F%2Fdata.portal.example%2Fq%3Fid%3D5",
        );
        let hosts: Vec<_> = l.iter().filter_map(|l| l.host.clone()).collect();
        assert_eq!(
            hosts,
            vec!["r.jina.ai", "api.allorigins.win", "data.portal.example"]
        );
    }

    #[test]
    fn a_callback_inbox_is_never_the_target() {
        let rules = Rules::default_rules();
        for (url, target, inbox) in [
            (
                "https://c3k9q2x7v1.oast.fun/x?d=1",
                None,
                "c3k9q2x7v1.oast.fun",
            ),
            (
                "https://eo1a2b3c4d5e6f.m.pipedream.net/",
                None,
                "eo1a2b3c4d5e6f.m.pipedream.net",
            ),
            (
                "https://webhook.site/0f1e2d3c-4b5a-6978-8a9b-0c1d2e3f4a5b",
                None,
                "webhook.site",
            ),
            (
                "https://r.jina.ai/https://shop.a.example/p?cb=https://zz91k.oast.pro/q",
                Some("shop.a.example"),
                "zz91k.oast.pro",
            ),
        ] {
            let o = obs(url);
            let x = extract(&o, &rules);
            assert_eq!(x.target_host.as_deref(), target, "{url}: {:?}", x.layers);
            let hosts = intermediary_hosts(&o, &rules);
            assert!(hosts.contains(inbox), "{url}: {hosts:?}");
            if let Some(t) = target {
                assert!(!hosts.contains(t), "{url}: {hosts:?}");
            }
        }
        assert!(is_intermediary_host(&rules, "c3k9q2x7v1.oast.fun"));
        assert!(is_intermediary_host(&rules, "abc.requestcatcher.com"));
        assert!(is_intermediary_host(&rules, "r.jina.ai"));
        assert!(!is_intermediary_host(&rules, "shop.a.example"));
    }

    /// A scraping API carries its target in `url`: the target is the inner
    /// URL, the API key is redacted, and the API host is never the target.
    /// Tunnels, sandboxes and hosted-browser connect hosts are the agent's
    /// own channels, so never the target either.
    #[test]
    fn scrape_apis_tunnels_and_sandboxes_are_not_targets() {
        let rules = Rules::default_rules();
        for (url, target, via) in [
            (
                "https://app.scrapingbee.com/api/v1/?api_key=9f8e7d6c5b4a3f2e1d0c&url=https%3A%2F%2Fshop.a.example%2Fitem%3Fid%3D1%2527&premium_proxy=true",
                Some("shop.a.example"),
                "app.scrapingbee.com",
            ),
            (
                "https://api.scraperapi.com/?api_key=9f8e7d6c5b4a3f2e1d0c&url=https://records.b.example/q?x=1&ultra_premium=true",
                Some("records.b.example"),
                "api.scraperapi.com",
            ),
            (
                "https://api.zenrows.com/v1/?apikey=9f8e7d6c5b4a3f2e1d0c&url=https%3A%2F%2Fc.example%2F&js_render=true",
                Some("c.example"),
                "api.zenrows.com",
            ),
            (
                "https://seasonal-deck-organisms-sf.trycloudflare.com/collect?d=1",
                None,
                "seasonal-deck-organisms-sf.trycloudflare.com",
            ),
            (
                "https://3000-i62mff4ahtrdfdkyn2esc.e2b.app/",
                None,
                "3000-i62mff4ahtrdfdkyn2esc.e2b.app",
            ),
            (
                "https://d.example/form?next=https://ab12-34cd.ngrok-free.app/cb",
                Some("d.example"),
                "ab12-34cd.ngrok-free.app",
            ),
        ] {
            let o = obs(url);
            let x = extract(&o, &rules);
            assert_eq!(x.target_host.as_deref(), target, "{url}: {:?}", x.layers);
            let hosts = intermediary_hosts(&o, &rules);
            assert!(hosts.contains(via), "{url}: {hosts:?}");
            let json = serde_json::to_string(&x).unwrap();
            assert!(!json.contains("9f8e7d6c5b4a"), "{json}");
        }
        assert!(is_intermediary_host(&rules, "api.zenrows.com"));
        assert!(is_intermediary_host(&rules, "ab12-34cd.ngrok-free.app"));
        assert!(!is_intermediary_host(&rules, "docs.zenrows.com"));
        // The tunnel and sandbox labels link records.
        let ids = |u: &str| {
            extract(&obs(u), &rules)
                .features
                .iter()
                .map(|f| f.name().to_string())
                .collect::<Vec<_>>()
        };
        assert!(
            ids("https://a.example/?cb=https://ab12-34cd.ngrok-free.app/x")
                .contains(&"exfil.tunnel".to_string())
        );
        assert!(
            ids("https://3000-i62mff4ahtrdfdkyn2esc.e2b.app/")
                .contains(&"carrier.agent_sandbox".to_string())
        );
    }

    #[test]
    fn platform_hint_against_the_user_agent() {
        let rules = Rules::default_rules();
        let fires = |ua: &str, hint: &str| {
            let mut o = obs("https://a.example/");
            o.user_agent = Some(ua.into());
            o.headers.insert("Sec-CH-UA-Platform".into(), hint.into());
            extract(&o, &rules)
                .hits
                .iter()
                .any(|h| h.rule_id == "header.ua_platform_mismatch")
        };
        let mac = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36";
        assert!(fires(mac, "\"Linux\""));
        assert!(!fires(mac, "\"macOS\""));
        // No user agent: nothing to compare.
        let mut o = obs("https://a.example/");
        o.headers
            .insert("sec-ch-ua-platform".into(), "\"Linux\"".into());
        assert!(extract(&o, &rules).hits.is_empty());
    }

    #[test]
    fn a_doubled_scheme_is_not_a_host() {
        let rules = Rules::default_rules();
        for (url, target) in [
            (
                "https://r.jina.ai/https://https://records.a.example/staff?uqtag=r7k2",
                "records.a.example",
            ),
            (
                "https://api.microlink.io/?url=http%3A%2F%2Fhttps%3A%2F%2Fdata.b.example%2Fapi",
                "data.b.example",
            ),
            ("https://https//c.example/x", "c.example"),
            ("http://https%3A//d.example/", "d.example"),
        ] {
            let x = extract(&obs(url), &rules);
            assert_eq!(x.target_host.as_deref(), Some(target), "{url}");
            assert!(
                x.layers.iter().all(|l| l.host.as_deref() != Some("https")),
                "{url}: {:?}",
                x.layers
            );
            // The last one does not parse as a URL, so its text is not decoded.
            assert!(
                url.starts_with("http://https%3A")
                    || x.hits.iter().any(|h| h.rule_id == "marker.doubled_scheme"),
                "{url}: {:?}",
                x.layers
            );
        }
        // Two records on different real hosts no longer share the host `https`.
        let a = crate::analyze(
            vec![
                obs("https://r.jina.ai/https://https://e.example/p?q=%5Bx%5D(https://e.example)"),
                obs("https://r.jina.ai/https://https://f.example/p?q=%5Bx%5D(https://f.example)"),
            ],
            &rules,
        );
        assert!(a.clusters.is_empty(), "{:?}", a.clusters);
    }

    #[test]
    fn quotes_around_a_url_are_not_part_of_its_host() {
        let rules = Rules::default_rules();
        for url in [
            "https://r.jina.ai/https://example.com%60",
            "https://r.jina.ai/https://example.com%22/x",
            "https://r.jina.ai/https://example.com'",
        ] {
            let x = extract(&obs(url), &rules);
            assert_eq!(x.target_host.as_deref(), Some("example.com"), "{url}");
        }
    }

    #[test]
    fn unwraps_translate_goog() {
        let l = unwrap_layers("https://www-stats--office-example.translate.goog/t?a=1");
        assert_eq!(l[1].host.as_deref(), Some("www.stats-office.example"));
    }

    #[test]
    fn decodes_data_url_program() {
        use base64::Engine;
        let prog = "<script>fetch('https://data.portal.example/api?id=1').then(r=>r.text()).then(t=>document.title=t)</script>";
        let url = format!(
            "data:text/html;base64,{}",
            base64::engine::general_purpose::STANDARD.encode(prog)
        );
        let rules = Rules::default_rules();
        let x = extract(&obs(&url), &rules);
        let ids: Vec<_> = x.hits.iter().map(|h| h.rule_id.as_str()).collect();
        assert!(ids.contains(&"carrier.data_url_script"), "{ids:?}");
        assert!(ids.contains(&"marker.title_write"), "{ids:?}");
        assert_eq!(x.target_host.as_deref(), Some("data.portal.example"));
    }

    #[test]
    fn exploit_and_inbox() {
        let rules = Rules::default_rules();
        let x = extract(
            &obs(
                "https://data.portal.example/view?id=1%20UNION%20SELECT%20null,version()--&cb=https://webhook.site/0b6c1f0e-1111-4c2a-9a55-3f2e1d0c9b8a",
            ),
            &rules,
        );
        assert!(x.significant_hit);
        assert!(x.features.iter().any(|f| f.name() == "exfil.webhook_site"));
        assert_eq!(x.target_host.as_deref(), Some("data.portal.example"));
    }

    #[test]
    fn plain_url_is_quiet() {
        let rules = Rules::default_rules();
        let x = extract(&obs("https://www.example.org/about"), &rules);
        assert_eq!(x.score, 0);
    }

    #[test]
    fn reading_a_vendor_site_through_a_relay_is_not_self_id() {
        let rules = Rules::default_rules();
        let x = extract(&obs("https://r.jina.ai/https://claude.ai/"), &rules);
        assert!(x.hits.iter().all(|h| h.rule_id != "selfid.vendor_name"));
        assert!(x.score < 3, "score {}", x.score);
        let y = extract(
            &obs("https://r.jina.ai/https://a.example/?agent=claude"),
            &rules,
        );
        assert!(y.hits.iter().any(|h| h.rule_id == "selfid.vendor_name"));
    }

    fn rule_ids(url: &str) -> Vec<String> {
        extract(&obs(url), &Rules::default_rules())
            .hits
            .into_iter()
            .map(|h| h.rule_id)
            .collect()
    }

    #[test]
    fn base64_program_in_a_path_segment() {
        use base64::Engine;
        let prog = "<script>fetch('https://target.example/api').then(r=>r.text()).then(t=>document.title=t)</script>";
        let url = format!(
            "https://eu.httpbin.org/base64/{}",
            base64::engine::general_purpose::STANDARD.encode(prog)
        );
        let ids = rule_ids(&url);
        assert!(
            ids.iter().any(|i| i == "carrier.inline_fetch_program"),
            "{ids:?}"
        );
        // As seen on urlquery: a `/` inside the payload, the URL-safe alphabet,
        // and the tail cut off by the scan service.
        let prog = "<html><body><script>fetch('https://target.example/a?b=1').then(r=>r.text()).then(t=>document.title=t)</script><p>???>>>"
            .repeat(2);
        let enc = base64::engine::general_purpose::STANDARD.encode(&prog);
        assert!(enc.contains('/'), "test payload must contain a slash");
        let cut = &enc[..enc.len() - 7];
        for p in [cut.to_string(), cut.replace('+', "-").replace('/', "_")] {
            let ids = rule_ids(&format!("https://httpbin.org/base64/{p}"));
            assert!(
                ids.iter().any(|i| i == "carrier.inline_fetch_program"),
                "{p}: {ids:?}"
            );
        }
        // An opaque ID in a path is not decoded into anything.
        assert_eq!(
            rule_ids("https://a.example/files/dGhpc2lzYW5vcGFxdWVpZDEy/x"),
            Vec::<String>::new()
        );
    }

    // Request shapes quoted in published incident reports.
    #[test]
    fn published_probe_shapes() {
        let has = |url: &str, id: &str| rule_ids(url).iter().any(|i| i == id);
        assert!(has(
            "https://d.example.gov/api?State_Id=1%20OR%201=1",
            "exploit.sqli_boolean"
        ));
        assert!(!has(
            "https://www.example.com/search?q=why+does+1%3D1+in+sql",
            "exploit.sqli_boolean"
        ));
        assert!(has(
            "https://d.example.gov/x/..%2Fy/z.asp",
            "exploit.traversal_single"
        ));
        assert!(has(
            "https://d.example.gov/Record?IdNumber=%27",
            "exploit.sqli_quote"
        ));
        assert!(!has(
            "https://d.example.gov/s?q=O%27Brien+family",
            "exploit.sqli_quote"
        ));
        for url in [
            "https://d.example/q?id=1%20UNION%20SELECT%20null,null--",
            "https://d.example/q?id=-1+union+all+select+1,2,3",
            "https://d.example/q?id=1%20UNION/**/SELECT/**/user,password%20FROM%20users",
            "https://d.example/q?id=1'%20union%20select%20version()--",
        ] {
            assert!(has(url, "exploit.sqli_union"), "{url}");
        }
        for url in [
            "https://www.labor.example/search?q=labor+union+selection+process",
            "https://www.jobs.example/q?t=credit%20union%20selected%20branches",
            "https://www.example.com/search?q=union+select+a+band",
        ] {
            assert!(!has(url, "exploit.sqli_union"), "{url}");
        }
        assert!(has("https://ntfy.sh/covrun7results", "exfil.ntfy"));
        assert!(has(
            "https://a.example/?cb=ntfy.sh/covrun7results",
            "exfil.ntfy"
        ));
        assert!(!has("https://docs.ntfy.sh/publish/", "exfil.ntfy"));
        assert!(has(
            "https://d.example.gov/api?a=1&zz=oai17816834089056622",
            "marker.oai_tag"
        ));
        assert!(has(
            "https://markdown.new/https://p.example.gov/doc.html?uniq3",
            "cache.buster"
        ));
    }

    // Program shapes seen in urlquery reports: base64 split across path
    // segments, mixed alphabets, truncated payloads.
    #[test]
    fn programs_seen_in_urlquery_reports() {
        use base64::Engine;
        let via_httpbin = |prog: &str| {
            rule_ids(&format!(
                "https://httpbin.org/base64/{}",
                base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(prog)
            ))
        };
        let form = via_httpbin(
            "<!doctype html><html><body onload=\"document.forms[0].submit()\"><form method=\"POST\" action=\"https://api.example.org/v1/facts\"><input name=q value=1></form>",
        );
        assert!(
            form.iter().any(|i| i == "carrier.form_post_program"),
            "{form:?}"
        );
        let relative = via_httpbin(
            "<pre id=o></pre><script>(async()=>{t=await(await fetch('//r.jina.ai/https://www.example.com/x')).text()})()</script>",
        );
        assert!(
            relative.iter().any(|i| i == "carrier.inline_fetch_program"),
            "{relative:?}"
        );
        assert!(
            relative.iter().any(|i| i == "carrier.html_program"),
            "{relative:?}"
        );
        // A search form on an ordinary page link is not a program.
        assert!(rule_ids("https://www.example.com/?q=how+to+submit+a+form").is_empty());
    }

    #[test]
    fn secrets_in_decoded_layers_are_redacted() {
        use base64::Engine;
        let b64 = |s: &str| base64::engine::general_purpose::STANDARD.encode(s);
        let key = "sk-abcdefghijklmnopqrstuvwxyz0123"; // secret-scan: fixture (fake key)
        let prog = format!(
            "<script>fetch('https://api.target.example/v1?access_token=s3cr3tvalue&q=1',{{headers:{{a:'{key}'}}}}).then(r=>r.text()).then(t=>document.title=t)</script>"
        );
        let urls = [
            format!("https://httpbin.org/base64/{}", b64(&prog)),
            format!("data:text/html;base64,{}", b64(&prog)),
            format!("https://r.jina.ai/https://a.example/?p={}", b64(&prog)),
            "https://r.jina.ai/https://a.example/?next=https%3A%2F%2Fb.example%2F%3Ftoken%3D9f8e7d6c5b4a3f2e1d0c%26api_key%3Dzz9secret".to_string(),
            "https://a.example/?next=%3Fpassword%3Dhunter2xyz".to_string(),
        ];
        for url in urls {
            let rules = Rules::default_rules();
            let a = crate::analyze(vec![obs(&url)], &rules);
            let json = serde_json::to_string(&a).unwrap();
            for secret in [
                "s3cr3tvalue",
                key,
                "9f8e7d6c5b4a3f2e1d0c",
                "zz9secret",
                "hunter2xyz",
            ] {
                // The submitted URL is the caller's; ingest redacts it.
                let shown = json.replacen(&serde_json::to_string(&url).unwrap(), "", 1);
                assert!(!shown.contains(secret), "{secret} in {shown}");
            }
        }
        // Placeholders a model left in a program are evidence, not secrets.
        let l = unwrap_layers(&format!(
            "https://httpbin.org/base64/{}",
            b64("<script>fetch('https://api.example/?api_key=YOUR_API_KEY')</script>")
        ));
        assert!(
            l.iter().any(|l| l.text.contains("api_key=YOUR_API_KEY")),
            "{l:?}"
        );
    }

    #[test]
    fn defangs() {
        assert_eq!(
            defang("https://a.b.example/x.y?z=1.2"),
            "hxxps://a[.]b[.]example/x.y?z=1.2"
        );
        assert_eq!(
            defang("https://r.jina.ai/http://t.example/"),
            "hxxps://r[.]jina[.]ai/hxxp://t[.]example/"
        );
        // A scheme glued to the text before it is still a link to a reader.
        assert_eq!(
            defang("q=%28https://t.example/)"),
            "q=%28hxxps://t[.]example/)"
        );
        // A host after `//` is one, with or without a scheme.
        assert_eq!(
            defang("https://https://a.example/x?u=%2F%2Fb.example%2F&c=//c.example/d.php"),
            "hxxps://hxxps://a[.]example/x?u=%2F%2Fb[.]example%2F&c=//c[.]example/d.php"
        );
        // A host anywhere in a URL is defanged: after an encoded `:` or
        // `@`, after `=`, in a path or a fragment.
        assert_eq!(
            defang("https://s.jina.ai/site%3Aportal.agency.example%20admin"),
            "hxxps://s[.]jina[.]ai/site%3Aportal[.]agency[.]example%20admin"
        );
        assert_eq!(
            defang("https://f.example/s?email=user%40example.com&n=a.example.org#b.example"),
            "hxxps://f[.]example/s?email=user%40example[.]com&n=a[.]example[.]org#b[.]example"
        );
        assert_eq!(
            defang("https://f.example/go/t.example/x"),
            "hxxps://f[.]example/go/t[.]example/x"
        );
        // Defanged text defangs to itself.
        for s in [
            "https://r.jina.ai/https://https://a.example/p?q=b.example",
            "q=%2F%2Fa.example and //b.example/x.php",
        ] {
            assert_eq!(defang(&defang(s)), defang(s), "{s}");
            assert_eq!(defang_hosts(&defang_hosts(s)), defang_hosts(s), "{s}");
        }
        // Text outside a URL keeps its dotted names (rule ids).
        assert_eq!(
            defang("relay.jina on https://a.example/p?q=b.example"),
            "relay.jina on hxxps://a[.]example/p?q=b[.]example"
        );
    }

    #[test]
    fn clips_after_defanging() {
        let f = "exfil.oast:id.oast.pipedream.net";
        let d = defang_feature(f);
        assert_eq!(clip_defanged(&d, 28), "exfil.oast:id[.]oast[.]piped…");
        // Never inside a `[.]`.
        assert_eq!(clip_defanged("a[.]example", 2), "a…");
        assert_eq!(clip_defanged("a[.]example", 3), "a…");
        assert_eq!(clip_defanged("a[.]example", 4), "a[.]…");
        assert_eq!(clip_defanged("a[.]b", 9), "a[.]b");
    }

    #[test]
    fn defangs_bare_hosts() {
        assert_eq!(
            defang_hosts("exfil.requestbin:c0ve7x9.m.pipedream.net"),
            "exfil[.]requestbin:c0ve7x9[.]m[.]pipedream[.]net"
        );
        assert_eq!(
            defang_hosts("program on portal.example.gov/q and https://x.example/a"),
            "program on portal[.]example[.]gov/q and hxxps://x[.]example/a"
        );
        assert_eq!(defang_hosts("_dmarc.a.example."), "_dmarc[.]a[.]example.");
        assert_eq!(
            defang_hosts("from 10.0.0.12, then"),
            "from 10[.]0[.]0[.]12, then"
        );
        assert_eq!(
            defang_hosts("q=%2F%2Fa.example%2F and //b.example/"),
            "q=%2F%2Fa[.]example%2F and //b[.]example/"
        );
        // Numbers, abbreviations and versions are not hosts.
        for s in [
            "Jaccard 0.52, width 4",
            "e.g. a run",
            "v1.2 at 999.1.1.1",
            "Chrome/138.0.0.0 Safari/537.36",
        ] {
            assert_eq!(defang_hosts(s), s);
        }
        assert_eq!(
            defang_feature("exfil.requestbin:c0ve7x9.m.pipedream.net"),
            "exfil.requestbin:c0ve7x9[.]m[.]pipedream[.]net"
        );
        assert_eq!(
            defang_feature("param:cb=https://hook.example/x"),
            "param:cb=hxxps://hook[.]example/x"
        );
        assert_eq!(
            defang_feature("close requests on a.example"),
            "close requests on a[.]example"
        );
        // Already defanged text stays as it is.
        let once = defang_hosts("a.example and https://b.example/");
        assert_eq!(defang_hosts(&once), once);
    }
}
