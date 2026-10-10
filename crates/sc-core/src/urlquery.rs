//! urlquery.net report records → [`Observation`]s.
//!
//! The public API (`api.urlquery.net/public/v1`, key in an `X-APIKEY` header)
//! returns `ReportOverview` objects from search, and full reports by ID. Both
//! carry the submitted URL as an object rather than a string:
//!
//! ```json
//! {"report_id": "5e08…", "date": "2026-10-04T08:10:00Z",
//!  "url": {"schema": "https", "addr": "r.jina.ai/https://…", "fqdn": "r.jina.ai", "domain": "jina.ai"},
//!  "ip": {"addr": "203.0.113.7", "asn": 64500, "as": "…", "country_code": "US"},
//!  "final": {"url": {"addr": "about:neterror"}, "title": "…"},
//!  "settings": {"useragent": "…", "exit_node": "…"}}
//! ```
//!
//! The generic field guesser cannot read that, so ingest recognises the shape and
//! maps it here: search responses (`{"reports": [...]}`), single reports, and
//! NDJSON of either. This is the import path for a urlquery export when there is
//! no API key, and the parser the `sc-collect` client uses when there is.
//!
//! `ip` is where urlquery's scanner reached the target, so it describes the
//! *target's* hosting, not the agent. It is kept because the target host is what
//! the endpoint view and operator notices are about. The scanner's own user agent
//! (`settings.useragent`) is chosen per submission and is recorded as an
//! `x-urlquery-useragent` header rather than as the record's user agent, so the
//! header rules do not mistake urlquery's default browser for an agent's.

use crate::model::{Observation, parse_ts};
use serde_json::Value;

pub const SOURCE: &str = "urlquery";
pub const REPORT_BASE: &str = "https://urlquery.net/report/";

/// True for an object shaped like a urlquery report or report overview.
pub fn is_report(v: &Value) -> bool {
    v.get("report_id").is_some_and(Value::is_string) && v.get("url").is_some_and(Value::is_object)
}

/// A urlquery URL object (`{"schema", "addr", "fqdn", ...}`) as a URL string.
fn url_of(v: &Value) -> Option<String> {
    let addr = v.get("addr").and_then(Value::as_str).map(str::trim)?;
    if addr.is_empty() {
        return None;
    }
    // The API sends `addr` without a scheme (`r.jina.ai/https://target/...`), so
    // only a scheme at the very start counts; an inner URL in the path does not.
    let has_scheme = addr.split_once("://").is_some_and(|(s, _)| {
        !s.is_empty()
            && s.chars()
                .all(|c| c.is_ascii_alphanumeric() || "+.-".contains(c))
    });
    if has_scheme || addr.starts_with("about:") || addr.starts_with("data:") {
        return Some(addr.to_string());
    }
    let schema = v
        .get("schema")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .unwrap_or("http");
    Some(format!("{schema}://{addr}"))
}

/// Map one urlquery report (or report overview) to an observation. The caller
/// redacts it.
pub fn report_to_obs(v: &Value) -> Option<Observation> {
    if !is_report(v) {
        return None;
    }
    let id = v.get("report_id")?.as_str()?.to_string();
    let url = url_of(v.get("url")?)?;
    let ip = v.get("ip");
    let mut headers = std::collections::BTreeMap::new();
    if let Some(ua) = v
        .pointer("/settings/useragent")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
    {
        headers.insert("x-urlquery-useragent".to_string(), ua.to_string());
    }
    Some(Observation {
        ts: v
            .get("date")
            .and_then(Value::as_str)
            .and_then(parse_ts)
            .unwrap_or(0),
        url,
        ip: ip
            .and_then(|i| i.get("addr"))
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .map(str::to_string),
        asn: ip
            .and_then(|i| i.get("asn"))
            .and_then(Value::as_u64)
            .filter(|&n| n > 0)
            .and_then(|n| u32::try_from(n).ok()),
        headers,
        final_url: v.pointer("/final/url").and_then(url_of),
        reference: Some(format!("{REPORT_BASE}{id}")),
        id: format!("urlquery:{id}"),
        source: SOURCE.to_string(),
        ..Default::default()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Value {
        serde_json::json!({
            "report_id": "5e085255-6d43-4dfb-a2cf-add81f84a67d",
            "date": "2026-10-04T08:10:00Z",
            "tags": [],
            "url": {"schema": "https", "addr": "https://r.jina.ai/https://data.portal.example/?q=1", "fqdn": "r.jina.ai"},
            "ip": {"addr": "203.0.113.7", "port": 443, "asn": 64500, "as": "EXAMPLE-AS", "country_code": "US"},
            "final": {"url": {"schema": "", "addr": "about:neterror"}, "title": ""},
            "settings": {"useragent": "Mozilla/5.0 (X11; Linux x86_64)", "access": "public"}
        })
    }

    #[test]
    fn maps_a_report_overview() {
        let o = report_to_obs(&sample()).unwrap();
        assert_eq!(o.id, "urlquery:5e085255-6d43-4dfb-a2cf-add81f84a67d");
        assert_eq!(o.source, "urlquery");
        assert_eq!(o.ts, 1791101400);
        assert_eq!(o.url, "https://r.jina.ai/https://data.portal.example/?q=1");
        assert_eq!(o.ip.as_deref(), Some("203.0.113.7"));
        assert_eq!(o.asn, Some(64500));
        assert_eq!(o.final_url.as_deref(), Some("about:neterror"));
        assert_eq!(o.user_agent, None);
        assert!(o.headers.contains_key("x-urlquery-useragent"));
        assert_eq!(
            o.reference.as_deref(),
            Some("https://urlquery.net/report/5e085255-6d43-4dfb-a2cf-add81f84a67d")
        );
    }

    // The API's shape: no scheme in `addr`, even
    // when the path holds a full inner URL.
    #[test]
    fn schemeless_addr_with_inner_url() {
        let mut v = sample();
        v["url"] = serde_json::json!({"schema": "https", "addr": "r.jina.ai/https://t.example/p", "fqdn": "r.jina.ai"});
        assert_eq!(
            report_to_obs(&v).unwrap().url,
            "https://r.jina.ai/https://t.example/p"
        );
    }

    #[test]
    fn bare_host_addr_gets_its_schema() {
        let mut v = sample();
        v["url"] = serde_json::json!({"schema": "http", "addr": "portal.example/x"});
        assert_eq!(report_to_obs(&v).unwrap().url, "http://portal.example/x");
    }

    #[test]
    fn ordinary_objects_are_not_reports() {
        assert!(!is_report(
            &serde_json::json!({"url": "https://a.example/", "id": "1"})
        ));
    }
}
