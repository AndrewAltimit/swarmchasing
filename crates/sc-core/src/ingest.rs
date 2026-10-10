//! Turn whatever export you have into `Observation`s.
//!
//! Supported shapes (auto-detected):
//! - NDJSON, one object per line
//! - a JSON array of objects, or an object with an array under `results`/`data`/`items`/`reports`
//! - CDX JSON (array of arrays, header row first), as returned by Wayback `output=json`,
//!   and CDX objects one per line, as Arquivo.pt returns them; both become the
//!   same captures the collectors produce (see [`crate::capture`])
//! - urlquery.net search responses and reports (see [`crate::urlquery`])
//! - plain text: one URL per line, optionally preceded by a timestamp
//!
//! Field names are guessed from common spellings; override them with a
//! [`FieldMap`] using dotted paths (`page.url`, `meta.submitted_at`).

use crate::capture::{Archive, capture};
use crate::model::{Observation, TsKind, parse_ts};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FieldMap {
    pub ts: Option<String>,
    pub url: Option<String>,
    pub id: Option<String>,
    pub ip: Option<String>,
    pub asn: Option<String>,
    pub user_agent: Option<String>,
    pub final_url: Option<String>,
    pub reference: Option<String>,
    pub headers: Option<String>,
    pub source: Option<String>,
    /// Access logs: the host the log belongs to, when the lines do not name it.
    pub host: Option<String>,
}

impl FieldMap {
    /// Parse `ts=submitted_at,url=page.url`.
    pub fn parse(spec: &str) -> Result<Self, String> {
        let mut m = FieldMap::default();
        for part in spec.split(',').map(str::trim).filter(|p| !p.is_empty()) {
            let (k, v) = part
                .split_once('=')
                .ok_or_else(|| format!("bad mapping `{part}` (want field=path)"))?;
            let v = Some(v.trim().to_string());
            match k.trim() {
                "ts" => m.ts = v,
                "url" => m.url = v,
                "id" => m.id = v,
                "ip" => m.ip = v,
                "asn" => m.asn = v,
                "user_agent" | "ua" => m.user_agent = v,
                "final_url" => m.final_url = v,
                "reference" | "ref" => m.reference = v,
                "headers" => m.headers = v,
                "source" => m.source = v,
                "host" => m.host = v,
                other => return Err(format!("unknown field `{other}`")),
            }
        }
        Ok(m)
    }

    fn is_empty(&self) -> bool {
        [
            &self.ts,
            &self.url,
            &self.id,
            &self.ip,
            &self.asn,
            &self.user_agent,
            &self.final_url,
            &self.reference,
            &self.headers,
            &self.source,
        ]
        .iter()
        .all(|f| f.is_none())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Format {
    #[default]
    Auto,
    Ndjson,
    Json,
    Lines,
    /// Web server access logs (Common / Combined Log Format, optionally with
    /// a leading virtual host): an operator checking its own logs.
    AccessLog,
}

impl std::str::FromStr for Format {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        match s {
            "auto" | "" => Ok(Self::Auto),
            "ndjson" | "jsonl" => Ok(Self::Ndjson),
            "json" => Ok(Self::Json),
            "lines" | "txt" | "urls" => Ok(Self::Lines),
            "access_log" | "access-log" | "log" | "clf" | "combined" => Ok(Self::AccessLog),
            _ => Err(format!(
                "unknown format `{s}` (auto|ndjson|json|lines|access_log)"
            )),
        }
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Parsed {
    pub observations: Vec<Observation>,
    pub warnings: Vec<String>,
    /// Secret values replaced with hashes at ingest (see [`crate::redact`]).
    #[serde(default)]
    pub redacted: usize,
}

const TS_KEYS: &[&str] = &[
    "ts",
    "timestamp",
    "time",
    "date",
    "datetime",
    "submitted",
    "submitted_at",
    "created_at",
    "created",
    "scan_date",
    "first_seen",
];
const URL_KEYS: &[&str] = &[
    "url",
    "page_url",
    "submitted_url",
    "target",
    "original",
    "uri",
    "request_url",
    "task.url",
    "page.url",
];
const ID_KEYS: &[&str] = &["id", "uuid", "report_id", "scan_id", "_id"];
const IP_KEYS: &[&str] = &["ip", "client_ip", "src_ip", "source_ip"];
const ASN_KEYS: &[&str] = &["asn", "as_number", "client_asn"];
const UA_KEYS: &[&str] = &["user_agent", "useragent", "ua", "userAgent"];
const FINAL_KEYS: &[&str] = &["final_url", "effective_url", "landing_url", "finalUrl"];
const REF_KEYS: &[&str] = &["reference", "report_url", "permalink", "link"];

fn get_path<'a>(v: &'a Value, path: &str) -> Option<&'a Value> {
    path.split('.').try_fold(v, |cur, k| match cur {
        Value::Object(m) => m.get(k),
        Value::Array(a) => k.parse::<usize>().ok().and_then(|i| a.get(i)),
        _ => None,
    })
}

fn pick<'a>(v: &'a Value, explicit: &Option<String>, candidates: &[&str]) -> Option<&'a Value> {
    match explicit {
        Some(p) => get_path(v, p),
        None => candidates
            .iter()
            .find_map(|k| get_path(v, k))
            .filter(|x| !x.is_null()),
    }
}

fn as_string(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

fn obj_to_obs(v: &Value, map: &FieldMap, default_source: &str) -> Option<Observation> {
    // A known source shape wins over guessing, unless the user mapped fields themselves.
    if map.is_empty() && crate::urlquery::is_report(v) {
        return crate::urlquery::report_to_obs(v);
    }
    if map.is_empty()
        && let Some(o) = cdx_object(v)
    {
        return Some(o);
    }
    let url = pick(v, &map.url, URL_KEYS).and_then(as_string)?;
    let ts = pick(v, &map.ts, TS_KEYS)
        .and_then(as_string)
        .and_then(|s| parse_ts(&s))
        .unwrap_or(0);
    let asn = pick(v, &map.asn, ASN_KEYS)
        .and_then(as_string)
        .and_then(|s| s.trim_start_matches(['A', 'S', 'a', 's']).parse().ok());
    let mut headers = std::collections::BTreeMap::new();
    if let Some(Value::Object(h)) = pick(v, &map.headers, &["headers", "request_headers"]) {
        for (k, val) in h {
            if let Some(s) = as_string(val) {
                headers.insert(k.clone(), s);
            }
        }
    }
    let status = v
        .get("status")
        .or_else(|| v.get("statuscode"))
        .and_then(as_string)
        .and_then(|s| s.parse().ok());
    let mut o = Observation {
        id: pick(v, &map.id, ID_KEYS)
            .and_then(as_string)
            .unwrap_or_default(),
        source: pick(v, &map.source, &["source"])
            .and_then(as_string)
            .unwrap_or_else(|| default_source.to_string()),
        ts,
        // Records this toolkit wrote say what their timestamp is.
        ts_kind: v
            .get("ts_kind")
            .cloned()
            .and_then(|k| serde_json::from_value(k).ok())
            .unwrap_or_default(),
        url,
        ip: pick(v, &map.ip, IP_KEYS).and_then(as_string),
        asn,
        target_asn: v
            .get("target_asn")
            .and_then(Value::as_u64)
            .and_then(|n| u32::try_from(n).ok()),
        user_agent: pick(v, &map.user_agent, UA_KEYS).and_then(as_string),
        headers,
        status,
        final_url: pick(v, &map.final_url, FINAL_KEYS).and_then(as_string),
        reference: pick(v, &map.reference, REF_KEYS).and_then(as_string),
    };
    o.upgrade();
    Some(o)
}

fn cdx_table(rows: &[Value], out: &mut Parsed) {
    let header: Vec<String> = rows[0]
        .as_array()
        .map(|a| a.iter().filter_map(as_string).collect())
        .unwrap_or_default();
    let col = |name: &str| header.iter().position(|h| h == name);
    let (Some(ti), Some(ui)) = (col("timestamp"), col("original").or_else(|| col("url"))) else {
        out.warnings
            .push("array-of-arrays without timestamp/original header".into());
        return;
    };
    let si = col("statuscode").or_else(|| col("status"));
    let di = col("digest");
    let named: Vec<usize> = ["filename", "collection"]
        .iter()
        .filter_map(|c| col(c))
        .collect();
    for row in &rows[1..] {
        let Some(r) = row.as_array() else { continue };
        let (Some(t), Some(u)) = (r.get(ti).and_then(as_string), r.get(ui).and_then(as_string))
        else {
            continue;
        };
        let field = |i: Option<usize>| i.and_then(|i| r.get(i)).and_then(as_string);
        let names: Vec<String> = named.iter().filter_map(|&i| field(Some(i))).collect();
        out.observations.push(capture(
            Archive::detect(names.iter().map(String::as_str)),
            &t,
            &u,
            field(si).and_then(|s| s.parse().ok()),
            &field(di).unwrap_or_default(),
        ));
    }
}

/// A CDX record as an object (Arquivo.pt's and pywb's NDJSON output): a
/// 14-digit `timestamp`, a `digest` and a `urlkey` beside the URL.
fn cdx_object(v: &Value) -> Option<Observation> {
    let s = |k: &str| v.get(k).and_then(as_string);
    let ts = s("timestamp").filter(|t| t.len() == 14 && t.bytes().all(|b| b.is_ascii_digit()))?;
    let digest = s("digest")?;
    s("urlkey")?;
    let url = s("url").or_else(|| s("original"))?;
    let names = [s("filename"), s("collection")];
    Some(capture(
        Archive::detect(names.iter().flatten().map(String::as_str)),
        &ts,
        &url,
        s("status")
            .or_else(|| s("statuscode"))
            .and_then(|x| x.parse().ok()),
        &digest,
    ))
}

fn json_value(v: &Value, map: &FieldMap, out: &mut Parsed) {
    match v {
        Value::Array(rows) if rows.first().is_some_and(Value::is_array) => cdx_table(rows, out),
        Value::Array(rows) => {
            for (i, r) in rows.iter().enumerate() {
                match obj_to_obs(r, map, "import") {
                    Some(o) => out.observations.push(o),
                    None => out.warnings.push(format!("item {i}: no url field")),
                }
            }
        }
        Value::Object(m) => {
            if let Some(inner) = ["results", "data", "items", "reports", "observations"]
                .iter()
                .find_map(|k| m.get(*k))
                .filter(|x| x.is_array())
            {
                json_value(inner, map, out);
            } else if let Some(o) = obj_to_obs(v, map, "import") {
                out.observations.push(o);
            } else {
                out.warnings
                    .push("object has no url field and no results array".into());
            }
        }
        _ => out.warnings.push("unsupported JSON value".into()),
    }
}

pub fn parse_input(text: &str, format: Format, map: &FieldMap) -> Parsed {
    let mut out = Parsed::default();
    let trimmed = text.trim_start_matches('\u{feff}').trim();
    if trimmed.is_empty() {
        return out;
    }
    let format = match format {
        Format::Auto if trimmed.starts_with('[') => Format::Json,
        Format::Auto if trimmed.starts_with('{') => {
            if serde_json::from_str::<Value>(trimmed).is_ok() {
                Format::Json
            } else {
                Format::Ndjson
            }
        }
        Format::Auto if looks_like_access_log(trimmed) => Format::AccessLog,
        Format::Auto => Format::Lines,
        f => f,
    };
    match format {
        Format::Json => match serde_json::from_str::<Value>(trimmed) {
            Ok(v) => json_value(&v, map, &mut out),
            Err(e) => out.warnings.push(format!("JSON: {e}")),
        },
        Format::Ndjson => {
            for (n, line) in trimmed.lines().enumerate() {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }
                match serde_json::from_str::<Value>(line) {
                    Ok(v) => match obj_to_obs(&v, map, "import") {
                        Some(o) => out.observations.push(o),
                        None => out.warnings.push(format!("line {}: no url field", n + 1)),
                    },
                    Err(e) => out.warnings.push(format!("line {}: {e}", n + 1)),
                }
            }
        }
        Format::AccessLog => access_log(trimmed, map, &mut out),
        Format::Lines | Format::Auto => {
            for (n, line) in trimmed.lines().enumerate() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                let Some((prefix, url)) = split_url_line(line) else {
                    out.warnings.push(format!("line {}: no URL", n + 1));
                    continue;
                };
                // Timestamp: everything before the URL, joined (handles "2026-10-04 08:10:00 https://...").
                let prefix: Vec<&str> = prefix
                    .split(['\t', ',', ' '])
                    .filter(|t| !t.is_empty())
                    .collect();
                let ts = if prefix.is_empty() {
                    0
                } else {
                    parse_ts(&prefix.join(" ")).unwrap_or(0)
                };
                out.observations.push(Observation {
                    id: format!("line-{}", n + 1),
                    source: "lines".into(),
                    ts,
                    url: url.to_string(),
                    ..Default::default()
                });
            }
        }
    }
    for o in &mut out.observations {
        out.redacted += crate::redact::redact_observation(o);
    }
    out
}

/// Split a URL-list line into what precedes the URL and the URL itself. The
/// URL starts at the first token (split on tab, comma or space) that has a
/// scheme, and runs to the end of the line, or to the next tab on a
/// tab-separated line. It is kept exactly as written: payloads carry spaces
/// and commas.
fn split_url_line(line: &str) -> Option<(&str, &str)> {
    let mut pos = 0;
    for tok in line.split(['\t', ',', ' ']) {
        if tok.contains("://") || tok.starts_with("data:") {
            let rest = &line[pos..];
            let url = rest.split('\t').next().unwrap_or(rest).trim_end();
            return Some((&line[..pos], url));
        }
        pos += tok.len() + 1;
    }
    None
}

fn access_log_re() -> &'static regex::Regex {
    static R: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    R.get_or_init(|| {
        regex::Regex::new(
            r#"^(?:(?P<vhost>[A-Za-z0-9.-]+(?::\d+)?)\s+)?(?P<ip>[0-9A-Fa-f:.]+)\s+\S+\s+\S+\s+\[(?P<time>[^\]]+)\]\s+"(?P<method>[A-Z]+)\s+(?P<target>\S+)(?:\s+HTTP/[0-9.]+)?"\s+(?P<status>\d{3})\s+\S+(?:\s+"(?P<referer>(?:[^"\\]|\\.)*)"\s+"(?P<ua>(?:[^"\\]|\\.)*)")?"#,
        )
        .unwrap()
    })
}

/// Most of the first lines parse as access log lines.
fn looks_like_access_log(text: &str) -> bool {
    let lines: Vec<&str> = text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .take(5)
        .collect();
    let hits = lines.iter().filter(|l| access_log_re().is_match(l)).count();
    hits > 0 && hits * 2 > lines.len()
}

fn access_log(text: &str, map: &FieldMap, out: &mut Parsed) {
    let re = access_log_re();
    let default_host = map.host.as_deref().unwrap_or("log.invalid");
    if map.host.is_none() {
        out.warnings.push(
            "access log: lines without a virtual host are shown under `log.invalid`; set the host with the field map (host=www.example.org)".into(),
        );
    }
    for (n, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some(c) = re.captures(line) else {
            out.warnings
                .push(format!("line {}: not an access log line", n + 1));
            continue;
        };
        let target = &c["target"];
        let url = if target.contains("://") {
            target.to_string()
        } else {
            let host = c
                .name("vhost")
                .map(|v| v.as_str().split(':').next().unwrap_or_default())
                .filter(|h| !h.is_empty() && h.contains('.'))
                .unwrap_or(default_host);
            format!("https://{host}{target}")
        };
        let ts = chrono::DateTime::parse_from_str(&c["time"], "%d/%b/%Y:%H:%M:%S %z")
            .map(|t| t.timestamp())
            .unwrap_or(0);
        let mut headers = std::collections::BTreeMap::new();
        if let Some(r) = c
            .name("referer")
            .map(|m| m.as_str())
            .filter(|r| *r != "-" && !r.is_empty())
        {
            headers.insert("referer".to_string(), r.to_string());
        }
        out.observations.push(Observation {
            id: format!("log-{}", n + 1),
            ts_kind: TsKind::Request,
            source: map.source.clone().unwrap_or_else(|| "access_log".into()),
            ts,
            url,
            ip: Some(c["ip"].to_string()),
            user_agent: c
                .name("ua")
                .map(|m| m.as_str().to_string())
                .filter(|u| u != "-" && !u.is_empty()),
            headers,
            status: c["status"].parse().ok(),
            ..Default::default()
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn access_logs() {
        let log = r#"203.0.113.9 - - [04/Oct/2026:08:10:00 +0200] "GET /q?id=1%20UNION%20SELECT%201&uqtag=zz9 HTTP/1.1" 200 512 "-" "python-httpx/0.27"
portal.example.gov:443 198.51.100.7 - - [04/Oct/2026:06:11:00 +0000] "GET /login?next=x HTTP/2.0" 302 0 "https://r.jina.ai/" "Mozilla/5.0 (X11) HeadlessChrome/126.0"
2001:db8::1 - frank [04/Oct/2026:06:12:00 +0000] "POST /api HTTP/1.1" 500 12
garbage"#;
        let p = parse_input(
            log,
            Format::Auto,
            &FieldMap::parse("host=www.example.org").unwrap(),
        );
        assert_eq!(p.observations.len(), 3, "{:?}", p.warnings);
        assert_eq!(p.warnings.len(), 1);
        let o = &p.observations;
        assert_eq!(
            o[0].url,
            "https://www.example.org/q?id=1%20UNION%20SELECT%201&uqtag=zz9"
        );
        assert_eq!(o[0].ts, o[1].ts - 60, "timezone applied");
        assert_eq!(o[0].user_agent.as_deref(), Some("python-httpx/0.27"));
        assert_eq!(o[1].url, "https://portal.example.gov/login?next=x");
        assert_eq!(
            o[1].headers.get("referer").map(String::as_str),
            Some("https://r.jina.ai/")
        );
        assert_eq!(o[1].status, Some(302));
        assert_eq!(o[1].ts_kind, TsKind::Request);
        assert_eq!(o[2].ip.as_deref(), Some("2001:db8::1"));
        assert_eq!(o[2].user_agent, None);
        assert!(!looks_like_access_log(
            "https://a.example/x\nhttps://b.example/y"
        ));
        let a = crate::analyze(p.observations, &crate::Rules::default_rules());
        assert!(a.results[0].tier >= crate::Tier::Suggestive);
    }

    #[test]
    fn auto_formats() {
        let nd = "{\"url\":\"https://a.example/\",\"timestamp\":\"2026-10-04T00:00:00Z\"}\n{\"scan\":{\"href\":\"https://b.example/\"}}";
        let p = parse_input(nd, Format::Auto, &FieldMap::default());
        assert_eq!(p.observations.len(), 1);
        assert_eq!(p.warnings.len(), 1);
        let p = parse_input(nd, Format::Auto, &FieldMap::parse("url=scan.href").unwrap());
        assert_eq!(p.observations.len(), 1);
        assert_eq!(p.observations[0].url, "https://b.example/");

        let cdx = r#"[["urlkey","timestamp","original","statuscode"],["x","20261004081000","https://c.example/","200"]]"#;
        let p = parse_input(cdx, Format::Auto, &FieldMap::default());
        assert_eq!(p.observations[0].ts, 1791101400);
        assert_eq!(p.observations[0].status, Some(200));
        assert!(p.observations[0].id.starts_with("wayback:20261004081000::"));
        assert_eq!(p.observations[0].source, "wayback");

        let lines = "2026-10-04 08:10:00 https://d.example/?a=1\nhttps://e.example/\n# comment";
        let p = parse_input(lines, Format::Auto, &FieldMap::default());
        assert_eq!(p.observations.len(), 2);
        assert_eq!(p.observations[0].ts, 1791101400);
    }

    #[test]
    fn cdx_imports_match_collector_ids() {
        let wayback = r#"[["urlkey","timestamp","original","statuscode","digest"],["x","20261004081000","https://c.example/","200","AAA"]]"#;
        let o = &parse_input(wayback, Format::Auto, &FieldMap::default()).observations[0];
        assert!(o.id.starts_with("wayback:20261004081000:AAA:"), "{}", o.id);
        assert_eq!(
            o.reference.as_deref(),
            Some("https://web.archive.org/web/20261004081000/https://c.example/")
        );
        let arquivo = r#"{"urlkey":"example,c)/","timestamp":"20261004081000","url":"https://c.example/","mime":"text/html","status":"200","digest":"D","filename":"AWP29-20261004.warc.gz","collection":"AWP29"}"#;
        let o = &parse_input(arquivo, Format::Auto, &FieldMap::default()).observations[0];
        assert!(o.id.starts_with("arquivo:20261004081000:D:"), "{}", o.id);
        assert_eq!(o.ts_kind, TsKind::Capture);
        assert_eq!(o.source, "arquivo");
        assert_eq!(o.status, Some(200));
        assert!(
            o.reference
                .as_deref()
                .unwrap()
                .starts_with("https://arquivo.pt/wayback/")
        );
    }

    #[test]
    fn url_lines_keep_the_url_as_written() {
        let lines = "2026-10-04 08:10:00 https://d.example/?id=1 UNION SELECT 1,2\n\
                     https://e.example/?q=a,b  c\n\
                     2026-10-04T08:10:00Z\thttps://f.example/?q=x y,z\tnote\n\
                     1791101400,https://g.example/?a=1,2";
        let p = parse_input(lines, Format::Lines, &FieldMap::default());
        let urls: Vec<&str> = p.observations.iter().map(|o| o.url.as_str()).collect();
        assert_eq!(
            urls,
            [
                "https://d.example/?id=1 UNION SELECT 1,2",
                "https://e.example/?q=a,b  c",
                "https://f.example/?q=x y,z",
                "https://g.example/?a=1,2",
            ]
        );
        let ts: Vec<i64> = p.observations.iter().map(|o| o.ts).collect();
        assert_eq!(ts, [1791101400, 0, 1791101400, 1791101400]);
    }

    #[test]
    fn stored_records_round_trip_their_timestamp_kind() {
        let nd = r#"{"id":"a","source":"wayback","ts":1791101400,"url":"https://a.example/"}
{"id":"b","source":"urlquery","ts":1791101400,"url":"https://b.example/","asn":64500}
{"id":"c","source":"import","ts":1791101400,"ts_kind":"request","url":"https://c.example/","target_asn":64501}"#;
        let o = parse_input(nd, Format::Ndjson, &FieldMap::default()).observations;
        let kinds: Vec<TsKind> = o.iter().map(|o| o.ts_kind).collect();
        assert_eq!(kinds, [TsKind::Capture, TsKind::Submit, TsKind::Request]);
        assert_eq!((o[1].asn, o[1].target_asn), (None, Some(64500)));
        assert_eq!(o[2].target_asn, Some(64501));
        for (line, o) in nd.lines().zip(&o) {
            let back: Observation = serde_json::from_str(line).unwrap();
            assert_eq!(&back, o);
        }
        let plain = serde_json::to_string(&Observation::default()).unwrap();
        assert!(
            !plain.contains("ts_kind") && !plain.contains("target_asn"),
            "{plain}"
        );
    }

    #[test]
    fn urlquery_search_response() {
        let body = r#"{"query":"r.jina.ai","total_hits":2,"limit":2,"offset":0,"reports":[
          {"report_id":"a1","date":"2026-10-04T08:10:00Z","url":{"schema":"https","addr":"https://r.jina.ai/https://x.example/?access_token=abc123secret"},"ip":{"addr":"203.0.113.7","asn":64500}},
          {"report_id":"a2","date":"2026-10-04T08:11:00Z","url":{"schema":"https","addr":"https://y.example/"}}]}"#;
        let p = parse_input(body, Format::Auto, &FieldMap::default());
        assert_eq!(p.observations.len(), 2, "{:?}", p.warnings);
        assert_eq!(p.observations[0].id, "urlquery:a1");
        assert_eq!(p.observations[0].target_asn, Some(64500));
        assert_eq!(p.observations[0].asn, None);
        assert_eq!(p.redacted, 1);
        assert!(!p.observations[0].url.contains("abc123secret"));
    }
}
