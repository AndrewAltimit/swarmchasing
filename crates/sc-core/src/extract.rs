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
                && let Some(m) = re.find(&layer.text)
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
                    && let Some(m) = re.find(v)
                    && r.def.check.is_none_or(|c| c.passes(v))
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
            && let Some(line) = header_lines.iter().find(|l| re.is_match(l))
        {
            push(&mut hits, &mut features, r, line, 0);
        }
    }
    let ua = obs.user_agent.as_deref().or_else(|| {
        obs.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("user-agent"))
            .map(|(_, v)| v.as_str())
    });
    if let Some(ua) = ua {
        for r in rules.matching(Target::UserAgent, ua) {
            if let Matcher::Re(re) = &r.matcher
                && let Some(m) = re.find(ua)
            {
                push(&mut hits, &mut features, r, m.as_str(), 0);
            }
        }
    }
    if let Some(fin) = &obs.final_url {
        for r in rules.matching(Target::FinalUrl, fin) {
            if let Matcher::Re(re) = &r.matcher
                && let Some(m) = re.find(fin)
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

/// A host name made safe to print: `example[.]com`.
pub fn defang_host(host: &str) -> String {
    host.replace('.', "[.]")
}

/// Make URLs safe to paste into a report: `hxxps://example[.]com/...`.
/// Every embedded URL is defanged, not just the outermost.
pub fn defang(s: &str) -> String {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| Regex::new(r"(?i)(h)tt(ps?)://([^/?#\s]+)").unwrap());
    re.replace_all(s, |c: &regex::Captures| {
        format!("{}xx{}://{}", &c[1], &c[2], c[3].replace('.', "[.]"))
    })
    .into_owned()
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
    }
}
