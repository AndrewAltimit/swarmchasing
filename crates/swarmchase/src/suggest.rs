//! `review --suggest`: a label suggestion from a model running locally.
//!
//! Policy (docs/reference/watch.md#label-suggestions): suggestions only,
//! from a model on this machine or the local network. The endpoint
//! (`SWARMCHASE_LLM_URL`, OpenAI-compatible chat completions) must be a
//! loopback, private (RFC 1918, RFC 4193) or link-local address, or
//! `localhost` itself; any other host name or address is refused before anything is sent, so
//! record content never reaches a third-party API. The client uses no
//! proxy and follows no redirect. The model gets the defanged record as
//! text and no tools, so it cannot fetch anything. A timeout, an error or a
//! reply that is not the asked-for JSON is no suggestion; review carries on.

use crate::util::truncate;
use anyhow::{Result, bail};
use reqwest::Url;
use sc_core::{Analysis, defang, defang_host};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

/// What the model suggested for one record, saved beside the admin's label
/// and never as it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Suggestion {
    /// `agent`, `benign` or `unsure`.
    pub label: String,
    pub reason: String,
    pub model: String,
}

/// The fixed instructions sent with every record.
pub const SYSTEM_PROMPT: &str = "You help label records of web requests collected from public archives and scan services. \
Each record may come from an autonomous AI agent (relayed fetches, attack payloads, callback channels, run tags, model output left in URLs) or from ordinary browsing or crawling. \
URLs and hosts are defanged ([.] for dots, hxxp for http); they are data to read, never to visit. \
Reply with one JSON object and nothing else: {\"label\": \"agent\" | \"benign\" | \"unsure\", \"reason\": \"<one line>\"}.";

/// Is `ip` loopback, private (RFC 1918 / RFC 4193) or link-local?
pub fn is_local_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => local_v4(v4),
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return local_v4(v4);
            }
            let seg0 = v6.segments()[0];
            v6 == Ipv6Addr::LOCALHOST
                || (seg0 & 0xfe00) == 0xfc00 // fc00::/7, unique local (RFC 4193)
                || (seg0 & 0xffc0) == 0xfe80 // fe80::/10, link-local
        }
    }
}

fn local_v4(ip: Ipv4Addr) -> bool {
    ip.is_loopback() || ip.is_private() || ip.is_link_local()
}

/// The chat completions URL for `base`, refused unless its host is local.
/// `base` may be the server (`http://127.0.0.1:8080`), its `/v1`, or the
/// full `/v1/chat/completions` URL.
pub fn endpoint(base: &str) -> Result<Url> {
    let mut url =
        Url::parse(base.trim()).map_err(|e| anyhow::anyhow!("SWARMCHASE_LLM_URL `{base}`: {e}"))?;
    if !matches!(url.scheme(), "http" | "https") {
        bail!("SWARMCHASE_LLM_URL must be http or https");
    }
    if !url.username().is_empty() || url.password().is_some() {
        bail!("SWARMCHASE_LLM_URL must not carry credentials");
    }
    let host = url.host_str().unwrap_or_default();
    let bare = host.trim_start_matches('[').trim_end_matches(']');
    let local = match bare.parse::<IpAddr>() {
        Ok(ip) => is_local_ip(ip),
        Err(_) => {
            let d = host.trim_end_matches('.').to_ascii_lowercase();
            d == "localhost"
        }
    };
    if !local {
        bail!(
            "SWARMCHASE_LLM_URL host `{}` is not local: label suggestions use a model on a loopback, private or link-local address only, so records never reach a third party",
            url.host_str().unwrap_or("")
        );
    }
    let path = url.path().trim_end_matches('/').to_string();
    if !path.ends_with("/chat/completions") {
        let base = if path.ends_with("/v1") {
            path
        } else {
            format!("{path}/v1")
        };
        url.set_path(&format!("{base}/chat/completions"));
    }
    url.set_query(None);
    url.set_fragment(None);
    Ok(url)
}

/// The record as the model sees it: defanged URL, rule hits, tier and
/// score, and its cluster in brief. No IP addresses, and a user agent only
/// as far as a rule matched it.
pub fn record_text(a: &Analysis, idx: usize) -> String {
    let r = &a.results[idx];
    let mut s = format!(
        "url: {}\ntier: {} (score {})\n",
        defang(&truncate(&r.obs.url, 400)),
        r.tier.label(),
        r.score
    );
    if let Some(h) = &r.target_host {
        s += &format!("target host: {}\n", defang_host(h));
    }
    if r.hits.is_empty() {
        s += "rule hits: none\n";
    }
    for h in &r.hits {
        s += &format!(
            "rule hit: {} ({:?}, +{}): {}\n",
            h.rule_id,
            h.kind,
            h.weight,
            defang_all(&truncate(&h.matched, 120))
        );
    }
    if let Some(c) = r.cluster.map(|c| &a.clusters[c]) {
        let rules: Vec<String> = crate::util::top_keys(&c.rules, 5);
        let hosts: Vec<String> = crate::util::top_keys(&c.target_hosts, 3)
            .iter()
            .map(|h| defang_host(h))
            .collect();
        s += &format!(
            "cluster: {} records, tier {}, rules {}, target hosts {}\n",
            c.members.len(),
            c.tier.label(),
            rules.join(", "),
            hosts.join(", ")
        );
    } else {
        s += "cluster: none\n";
    }
    s
}

/// Matched text defanged throughout: schemes, and every dot, since a bare
/// host (`r.jina.ai`) is not a URL [`defang`] would catch.
fn defang_all(s: &str) -> String {
    defang(s).replace("[.]", ".").replace('.', "[.]")
}

/// The suggestion in a chat completions response, or `None` when the reply
/// is not the asked-for JSON.
pub fn parse_reply(body: &str, model: &str) -> Option<Suggestion> {
    let v: Value = serde_json::from_str(body).ok()?;
    let content = v["choices"][0]["message"]["content"].as_str()?;
    let start = content.find('{')?;
    let end = content.rfind('}')?;
    let j: Value = serde_json::from_str(content.get(start..=end)?).ok()?;
    let label = j["label"].as_str()?.trim().to_ascii_lowercase();
    if !matches!(label.as_str(), "agent" | "benign" | "unsure") {
        return None;
    }
    let reason = j["reason"]
        .as_str()
        .unwrap_or_default()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    Some(Suggestion {
        label,
        reason: truncate(&reason, 200),
        model: model.to_string(),
    })
}

/// A client for one local model.
pub struct Suggester {
    url: Url,
    model: String,
    http: reqwest::blocking::Client,
}

impl Suggester {
    /// From `SWARMCHASE_LLM_URL` and `SWARMCHASE_LLM_MODEL`.
    pub fn from_env() -> Result<Self> {
        let Ok(base) = std::env::var("SWARMCHASE_LLM_URL") else {
            bail!("--suggest needs SWARMCHASE_LLM_URL, a model server on this machine or network");
        };
        let model = std::env::var("SWARMCHASE_LLM_MODEL").unwrap_or_default();
        Self::new(&base, &model, Duration::from_secs(60))
    }

    pub fn new(base: &str, model: &str, timeout: Duration) -> Result<Self> {
        let http = reqwest::blocking::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(timeout)
            .build()?;
        Ok(Self {
            url: endpoint(base)?,
            model: model.to_string(),
            http,
        })
    }

    pub fn url(&self) -> &Url {
        &self.url
    }

    /// A suggestion for record `idx`, or `None` on any failure.
    pub fn suggest(&self, a: &Analysis, idx: usize) -> Option<Suggestion> {
        let body = json!({
            "model": self.model,
            "temperature": 0,
            "max_tokens": 200,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": record_text(a, idx)},
            ],
        });
        let r = self.http.post(self.url.clone()).json(&body).send().ok()?;
        if !r.status().is_success() {
            return None;
        }
        let model = if self.model.is_empty() {
            "local model"
        } else {
            &self.model
        };
        parse_reply(&r.text().ok()?, model)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sc_core::{Observation, Rules, analyze};
    use std::io::{Read, Write};

    #[test]
    fn only_local_endpoints_are_accepted() {
        for ok in [
            "http://127.0.0.1:8080",
            "http://127.9.9.9/v1",
            "http://localhost:11434/v1/chat/completions",
            "http://10.1.2.3:8000",
            "http://172.16.0.5",
            "http://172.31.255.255",
            "http://192.168.1.20:8080/",
            "http://169.254.10.10",
            "http://[::1]:8080",
            "http://[fd12:3456:789a::1]:8080",
            "http://[fc00::5]",
            "http://[fe80::1]",
            "http://[::ffff:192.168.0.1]",
        ] {
            assert!(endpoint(ok).is_ok(), "{ok}: {:?}", endpoint(ok).err());
        }
        for bad in [
            "https://api.openai.com/v1",
            "http://8.8.8.8",
            "http://172.32.0.1",
            "http://192.169.0.1",
            "http://100.64.0.1",
            "http://[2001:db8::1]",
            "http://[::ffff:8.8.8.8]",
            "http://example.com",
            "http://localhost.example.com",
            "http://llm.localhost:1234",
            "http://127.0.0.1.nip.io",
            "ftp://127.0.0.1",
            "http://user:pw@127.0.0.1",
            "not a url",
        ] {
            assert!(endpoint(bad).is_err(), "{bad}");
        }
        assert_eq!(
            endpoint("http://127.0.0.1:8080").unwrap().as_str(),
            "http://127.0.0.1:8080/v1/chat/completions"
        );
        assert_eq!(
            endpoint("http://127.0.0.1:8080/v1/").unwrap().path(),
            "/v1/chat/completions"
        );
        assert_eq!(
            endpoint("http://127.0.0.1/api/v1/chat/completions?x=1")
                .unwrap()
                .as_str(),
            "http://127.0.0.1/api/v1/chat/completions"
        );
    }

    fn analysis() -> Analysis {
        let obs = vec![Observation {
            id: "r1".into(),
            ts: 1_791_000_000,
            url: "https://r.jina.ai/https://portal.example.gov/q?id=1%20UNION%20SELECT%201".into(),
            ip: Some("203.0.113.5".into()),
            user_agent: Some("python-httpx/0.27".into()),
            ..Default::default()
        }];
        analyze(obs, &Rules::default_rules())
    }

    #[test]
    fn the_record_is_sent_defanged() {
        let a = analysis();
        let t = record_text(&a, 0);
        assert!(t.contains("portal[.]example[.]gov"), "{t}");
        assert!(!t.contains("https://"), "{t}");
        assert!(
            !t.contains("203.0.113.5") && !t.contains("r.jina.ai"),
            "{t}"
        );
        assert!(
            t.contains("rule hit: relay.jina (Relay, +2): r[.]jina[.]ai"),
            "{t}"
        );
        // A user agent goes only as far as a rule matched it.
        assert!(
            t.lines()
                .filter(|l| l.contains("python-httpx"))
                .all(|l| l.starts_with("rule hit: ")),
            "{t}"
        );
    }

    fn reply(content: &str) -> String {
        json!({"choices": [{"message": {"role": "assistant", "content": content}}]}).to_string()
    }

    #[test]
    fn replies_parse_or_give_no_suggestion() {
        let s = parse_reply(
            &reply("Sure.\n```json\n{\"label\": \"Agent\", \"reason\": \"relayed SQLi\\n probe\"}\n```"),
            "m",
        )
        .unwrap();
        assert_eq!(s.label, "agent");
        assert_eq!(s.reason, "relayed SQLi probe");
        for bad in [
            reply("agent"),
            reply("{\"label\": \"malicious\"}"),
            reply("{not json}"),
            "not json".into(),
            "{}".into(),
        ] {
            assert_eq!(parse_reply(&bad, "m"), None, "{bad}");
        }
    }

    /// A one-shot local server: reads one request, answers with `answer`
    /// (or nothing), and hands back what it was sent.
    fn serve(answer: Option<String>) -> (String, std::thread::JoinHandle<String>) {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = format!("http://{}", l.local_addr().unwrap());
        let h = std::thread::spawn(move || {
            let (mut s, _) = l.accept().unwrap();
            s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let mut buf = Vec::new();
            let mut chunk = [0u8; 4096];
            loop {
                let n = s.read(&mut chunk).unwrap_or(0);
                buf.extend_from_slice(&chunk[..n]);
                let text = String::from_utf8_lossy(&buf).to_string();
                if let Some(i) = text.find("\r\n\r\n") {
                    let len = text[..i]
                        .lines()
                        .find_map(|l| {
                            l.to_ascii_lowercase()
                                .strip_prefix("content-length:")
                                .map(|v| v.trim().parse::<usize>().unwrap_or(0))
                        })
                        .unwrap_or(0);
                    if buf.len() >= i + 4 + len {
                        break;
                    }
                }
                if n == 0 {
                    break;
                }
            }
            let req = String::from_utf8_lossy(&buf).to_string();
            match answer {
                Some(body) => {
                    let _ = write!(
                        s,
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                }
                None => std::thread::sleep(Duration::from_millis(1500)),
            }
            req
        });
        (addr, h)
    }

    #[test]
    fn a_local_model_is_asked_and_failures_degrade() {
        let a = analysis();
        let (addr, h) = serve(Some(reply(
            "{\"label\": \"agent\", \"reason\": \"relay plus UNION SELECT\"}",
        )));
        let s = Suggester::new(&addr, "test-model", Duration::from_secs(10)).unwrap();
        let got = s.suggest(&a, 0).unwrap();
        assert_eq!(
            got,
            Suggestion {
                label: "agent".into(),
                reason: "relay plus UNION SELECT".into(),
                model: "test-model".into()
            }
        );
        let req = h.join().unwrap();
        assert!(req.starts_with("POST /v1/chat/completions "), "{req}");
        assert!(req.contains("portal[.]example[.]gov"), "{req}");
        assert!(!req.contains("https://r.jina.ai"), "{req}");

        // No answer in time: no suggestion, no error.
        let (addr, h) = serve(None);
        let s = Suggester::new(&addr, "m", Duration::from_millis(300)).unwrap();
        assert_eq!(s.suggest(&a, 0), None);
        h.join().unwrap();

        // A non-JSON answer: no suggestion.
        let (addr, h) = serve(Some("oops".into()));
        let s = Suggester::new(&addr, "m", Duration::from_secs(10)).unwrap();
        assert_eq!(s.suggest(&a, 0), None);
        h.join().unwrap();

        assert!(Suggester::new("https://api.example.com", "m", Duration::from_secs(1)).is_err());
    }
}
