//! URL unwrapping and indicator matching for a single observation.
//!
//! Agents rarely hit a target directly: they wrap it in relays
//! (`r.jina.ai/https://...`), carriers (`httpbin.org/anything?url=...`),
//! `data:` URLs carrying fetch programs, or base64 parameters. We peel
//! those layers so rules can see every hop and the real target.

use crate::model::{Hit, IndicatorKind, Observation, truncate};
use crate::rules::{Matcher, Rules, Target, host_matches};
use base64::Engine;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::sync::OnceLock;

const MAX_LAYERS: usize = 16;
const MAX_DEPTH: usize = 6;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Layer {
    /// How this layer was found: `submitted`, `path`, `param:<name>`, `base64:<name>`, `data-url`, `embedded`, `translate.goog`.
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
fn try_b64(s: &str) -> Option<String> {
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

/// Peel every layer we can find, breadth first.
pub fn unwrap_layers(url: &str) -> Vec<Layer> {
    let mut layers: Vec<Layer> = Vec::new();
    let mut queue: std::collections::VecDeque<(String, String, usize)> = Default::default();
    let mut seen = BTreeSet::new();
    queue.push_back((url.trim().to_string(), "submitted".into(), 0));

    while let Some((raw, via, depth)) = queue.pop_front() {
        if layers.len() >= MAX_LAYERS || !seen.insert(raw.clone()) {
            continue;
        }
        let mut children: Vec<(String, String)> = Vec::new();

        if let Some(rest) = raw.strip_prefix("data:") {
            let (meta, body) = rest.split_once(',').unwrap_or(("", rest));
            let content = if meta.ends_with(";base64") {
                try_b64(body.trim()).unwrap_or_else(|| pct_decode(body))
            } else {
                pct_decode(body)
            };
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
        } else if let Ok(parsed) = url::Url::parse(&raw) {
            let host = parsed.host_str().map(|h| h.to_ascii_lowercase());
            let params: Vec<(String, String)> = parsed
                .query_pairs()
                .map(|(k, v)| (k.into_owned(), v.into_owned()))
                .collect();

            // Embedded URL in the path: r.jina.ai/https://target/...
            let path = pct_decode(parsed.path());
            if let Some(i) = path.find("http://").or_else(|| path.find("https://")) {
                let mut inner = path[i..].to_string();
                if let Some(q) = parsed.query() {
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
            let segs: Vec<String> = parsed
                .path_segments()
                .into_iter()
                .flatten()
                .map(pct_decode)
                .collect();
            for i in 0..segs.len() {
                let Some(decoded) = try_b64(&segs[i..].join("/")) else {
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
            if let Some(h) = host.as_deref().and_then(untranslate_host) {
                let mut inner = format!("https://{h}{}", parsed.path());
                if let Some(q) = parsed.query() {
                    inner.push('?');
                    inner.push_str(q);
                }
                children.push((inner, "translate.goog".into()));
            }
            for (k, v) in &params {
                let v = v.trim();
                if v.starts_with("http://") || v.starts_with("https://") || v.starts_with("data:") {
                    children.push((v.to_string(), format!("param:{k}")));
                } else if let Some(decoded) = try_b64(v) {
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
                text: pct_decode(&raw),
                params,
            });
        } else {
            // Not a URL we can parse; still scan it as text.
            for m in embedded_url_re().find_iter(&raw) {
                children.push((m.as_str().to_string(), "embedded".into()));
            }
            layers.push(Layer {
                via,
                depth,
                host: None,
                text: raw.clone(),
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
    pub features: Vec<String>,
}

pub fn extract(obs: &Observation, rules: &Rules) -> Extracted {
    let layers = unwrap_layers(&obs.url);
    let mut hits: Vec<Hit> = Vec::new();
    let mut features = BTreeSet::new();
    let mut fired = BTreeSet::new();

    // Layers whose own host is a relay/carrier/inbox, so they are not the real target.
    let mut intermediary = vec![false; layers.len()];

    let mut push = |hits: &mut Vec<Hit>,
                    features: &mut BTreeSet<String>,
                    r: &crate::rules::CompiledRule,
                    m: &str,
                    layer: usize| {
        if r.def.link {
            features.insert(format!("{}:{}", r.def.id, m.to_ascii_lowercase()));
        }
        if fired.insert(r.def.id.clone()) {
            hits.push(Hit {
                rule_id: r.def.id.clone(),
                kind: r.def.kind,
                weight: r.def.weight,
                matched: truncate(m, 160),
                layer,
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
        for r in rules.of_target(Target::Url) {
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
            for r in rules.of_target(Target::ParamName) {
                if let Matcher::Re(re) = &r.matcher
                    && re.is_match(k)
                {
                    push(&mut hits, &mut features, r, &format!("{k}={v}"), i);
                }
            }
            for r in rules.of_target(Target::ParamValue) {
                if let Matcher::Re(re) = &r.matcher
                    && let Some(m) = re.find(v)
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
                features.insert(format!("param:{}={}", k.to_ascii_lowercase(), v));
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
        for r in rules.of_target(Target::UserAgent) {
            if let Matcher::Re(re) = &r.matcher
                && let Some(m) = re.find(ua)
            {
                push(&mut hits, &mut features, r, m.as_str(), 0);
            }
        }
    }
    if let Some(fin) = &obs.final_url {
        for r in rules.of_target(Target::FinalUrl) {
            if let Matcher::Re(re) = &r.matcher
                && let Some(m) = re.find(fin)
            {
                push(&mut hits, &mut features, r, m.as_str(), 0);
            }
        }
    }

    let score = hits.iter().map(|h| h.weight).sum();
    let significant_hit = hits.iter().any(|h| {
        rules
            .compiled
            .iter()
            .any(|r| r.def.id == h.rule_id && r.def.significant)
    });
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

fn is_intermediary_kind(k: IndicatorKind) -> bool {
    matches!(
        k,
        IndicatorKind::Relay | IndicatorKind::Carrier | IndicatorKind::Exfil
    )
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
        assert!(
            x.features
                .iter()
                .any(|f| f.starts_with("exfil.webhook_site:"))
        );
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
