//! CVE records and security advisories for the platform pass (`cve`):
//! bursts of near-identical or templated vulnerability reports, such as a
//! batch of fabricated CVEs against one project, grouped like any other
//! platform's posts. Two endpoints:
//!
//! - `unreviewed` (the default), `reviewed` or `malware`: the GitHub
//!   Advisory Database's REST listing (`api.github.com/advisories`) of that
//!   type, oldest first from the checkpoint (the newest publication time
//!   read), a hundred a request, at most `scan` requests. Unreviewed
//!   advisories mirror the CVE records the NVD publishes, so this reads
//!   nearly every new CVE with its description and references.
//! - `cvelist`: the CVE Program's own list (`CVEProject/cvelistV5`), whose
//!   `cves/deltaLog.json` names the records published in the last month.
//!   A pull reads the log, then fetches the records new since its
//!   checkpoint, oldest first, at most `scan` of them, from the list's own
//!   repository only. This sees records the NVD has not published, and
//!   rejected ones, at the cost of one request per record.
//!
//! An event keeps the summary and description as a sketch, the time, the
//! public link, and as its target the first source repository its
//! references name (`owner/repo` on GitHub), else the vendor's host or the
//! affected product. The account is the credited finder where the record
//! credits one (a GitHub login or a name), as a keyed hash; most records
//! credit no one, and their groups are floods, as on PyPI. Reference URLs
//! are matched as text and never fetched; nothing reads a repository to
//! learn its age.
//!
//! Terms: the GitHub REST API (<https://docs.github.com/en/rest/security-advisories/global-advisories>)
//! allows 60 unauthenticated requests an hour; the Advisory Database is
//! published under CC-BY 4.0 (<https://github.com/github/advisory-database>),
//! and GitHub's Acceptable Use Policies apply as for GH Archive. The CVE
//! List is published under the CVE Program's terms of use
//! (<https://www.cve.org/Legal/TermsOfUse>), which grant a free licence to
//! reproduce and distribute CVE records with the CVE Program credited.

use crate::pager::Coverage;
use crate::platform::PlatformPull;
use crate::{CdxQuery, Client, parse_date};
use anyhow::{Context, Result, bail};
use sc_core::Rules;
use sc_core::platform::{Action, Platform, PlatformEvent, actor_key};
use serde_json::Value;
use std::collections::BTreeSet;

const GHSA: &str = "https://api.github.com/advisories";
const DELTA_LOG: &str =
    "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/deltaLog.json";
const CVELIST_RAW: &str = "https://raw.githubusercontent.com/CVEProject/cvelistV5/";
/// Advisories per GitHub request: the API's maximum.
const GHSA_PAGE: usize = 100;
/// GitHub requests one pull makes unless `scan` says otherwise.
const DEFAULT_GHSA_REQUESTS: usize = 3;
/// CVE records one `cvelist` pull fetches unless `scan` says otherwise.
const DEFAULT_CVELIST_RECORDS: usize = 30;
/// Without a checkpoint a pull starts this far back.
const FRESH_SECS: i64 = 6 * 3600;
/// A checkpoint further back than this is skipped to [`FRESH_SECS`].
const MAX_BACKLOG_SECS: i64 = 24 * 3600;

/// The target a set of reference URLs points at: the first GitHub
/// repository (`owner/repo`) that is not an advisory page, else the first
/// reference's host.
pub fn reference_target<'a>(refs: impl IntoIterator<Item = &'a str>) -> Option<String> {
    let mut host = None;
    for r in refs {
        let Ok(u) = url::Url::parse(r) else { continue };
        let Some(h) = u
            .host_str()
            .map(|h| h.trim_start_matches("www.").to_ascii_lowercase())
        else {
            continue;
        };
        if h == "github.com" {
            let segs: Vec<&str> = u
                .path_segments()
                .map(|s| s.filter(|x| !x.is_empty()).collect())
                .unwrap_or_default();
            if segs.len() >= 2 && segs[0] != "advisories" {
                return Some(format!(
                    "{}/{}",
                    segs[0].to_ascii_lowercase(),
                    segs[1].to_ascii_lowercase()
                ));
            }
            continue;
        }
        if matches!(
            h.as_str(),
            "nvd.nist.gov" | "www.cve.org" | "cve.org" | "cve.mitre.org" | "osv.dev"
        ) {
            continue;
        }
        host.get_or_insert(h);
    }
    host
}

/// Platform events from a GitHub advisory listing, and the advisories it held.
pub fn ghsa_events(body: &str, rules: &Rules) -> Result<(Vec<PlatformEvent>, usize)> {
    let v: Value = serde_json::from_str(body).context("GitHub advisories: not JSON")?;
    let list = v.as_array().context("GitHub advisories: not an array")?;
    let mut out = Vec::new();
    for a in list {
        let s = |k: &str| a.get(k).and_then(Value::as_str);
        let (Some(id), Some(ts)) = (s("ghsa_id"), s("published_at").and_then(parse_date)) else {
            continue;
        };
        if s("withdrawn_at").is_some() {
            continue;
        }
        let refs: Vec<&str> = a
            .get("references")
            .and_then(Value::as_array)
            .map(|r| r.iter().filter_map(Value::as_str).collect())
            .unwrap_or_default();
        let target = s("source_code_location")
            .filter(|l| !l.is_empty())
            .into_iter()
            .chain(refs.iter().copied());
        let target = reference_target(target).unwrap_or_else(|| s("cve_id").unwrap_or(id).into());
        let finder = a
            .get("credits")
            .and_then(Value::as_array)
            .and_then(|c| c.iter().find_map(|x| x.pointer("/user/login")?.as_str()));
        let (owner, repo) = target.split_once('/').unwrap_or(("", ""));
        let text = format!(
            "{}\n{}",
            s("summary").unwrap_or(""),
            s("description").unwrap_or("")
        );
        out.push(
            PlatformEvent {
                id: format!("ghsa:{id}"),
                platform: Platform::Cve,
                action: Action::AdvisoryPublished,
                ts,
                actor: finder
                    .map(|l| actor_key(Platform::Cve, &format!("github/{}", l.to_lowercase())))
                    .unwrap_or_default(),
                link: s("html_url")
                    .filter(|u| u.starts_with("https://github.com/advisories/"))
                    .map_or_else(
                        || format!("https://github.com/advisories/{id}"),
                        str::to_string,
                    ),
                target: target.clone(),
                ..Default::default()
            }
            .with_text(&text, &[owner, repo, finder.unwrap_or("")], rules),
        );
    }
    Ok((out, list.len()))
}

fn iso(ts: i64) -> String {
    chrono::DateTime::from_timestamp(ts, 0)
        .unwrap_or_default()
        .format("%Y-%m-%dT%H:%M:%SZ")
        .to_string()
}

fn pull_ghsa(
    client: &Client,
    q: &CdxQuery,
    kind: &str,
    mark: Option<u64>,
    rules: &Rules,
    max: usize,
) -> Result<PlatformPull> {
    let now = crate::client::now_secs();
    let fresh = now - FRESH_SECS;
    let (start, skipped) = match mark.map(|m| m as i64) {
        Some(m) if m >= now - MAX_BACKLOG_SECS => (m, 0),
        Some(m) => (fresh, (fresh - m).max(0)),
        None => (fresh, 0),
    };
    let requests = q.scan.unwrap_or(DEFAULT_GHSA_REQUESTS).clamp(1, 20);
    let mut out = PlatformPull::default();
    let mut seen = BTreeSet::new();
    // The first request takes what came strictly after the checkpoint;
    // later ones repeat the last second read, whose ties may run on.
    let (mut since, mut op, mut reached, mut done, mut read) = (start, ">", start, false, 0usize);
    for i in 0..requests {
        let mut u = url::Url::parse(GHSA)?;
        u.query_pairs_mut()
            .append_pair("type", kind)
            .append_pair("sort", "published")
            .append_pair("direction", "asc")
            .append_pair("per_page", &GHSA_PAGE.to_string())
            .append_pair("published", &format!("{op}{}", iso(since)));
        let body = match client.get(u.as_str()) {
            Ok(b) => b,
            Err(e) if i == 0 => return Err(e),
            Err(_) => break,
        };
        let (events, n) = ghsa_events(&body, rules)?;
        read += n;
        let last = events.iter().map(|e| e.ts).max();
        for e in events {
            if seen.insert(e.id.clone()) && out.events.len() < max {
                out.events.push(e);
            }
        }
        if let Some(l) = last {
            reached = reached.max(l);
        }
        if n < GHSA_PAGE {
            done = true;
            break;
        }
        // A full page of one second: step past it rather than loop.
        (since, op) = match last {
            Some(l) if l > since || op == ">" && l >= since => (l, ">="),
            _ => (since + 1, ">="),
        };
    }
    let m = |s: i64| (s.max(0) / 60) as u64;
    let to = if done { now } else { reached };
    out.coverage = Coverage {
        unit: "minutes",
        read: m(to - start),
        available: m(now - start) + m(skipped),
        skipped: m(skipped),
        next: Some(if done { reached.max(start) } else { reached } as u64),
        canary: Some(read > 0 || done),
    };
    Ok(out)
}

/// The records new since `after` (ms) in a CVE List delta log, oldest
/// first, as (update ms, CVE id, record URL), only URLs in the list's own
/// repository.
pub fn delta_log_new(body: &str, after: i64) -> Result<Vec<(i64, String, String)>> {
    let v: Value = serde_json::from_str(body).context("CVE delta log: not JSON")?;
    let log = v.as_array().context("CVE delta log: not an array")?;
    let mut out: Vec<(i64, String, String)> = Vec::new();
    let mut seen = BTreeSet::new();
    for d in log {
        let Some(new) = d.get("new").and_then(Value::as_array) else {
            continue;
        };
        for n in new {
            let s = |k: &str| n.get(k).and_then(Value::as_str);
            let (Some(id), Some(link), Some(ms)) = (
                s("cveId"),
                s("githubLink"),
                s("dateUpdated")
                    .and_then(|d| chrono::DateTime::parse_from_rfc3339(d).ok())
                    .map(|d| d.timestamp_millis()),
            ) else {
                continue;
            };
            if ms > after && link.starts_with(CVELIST_RAW) && seen.insert(id.to_string()) {
                out.push((ms, id.to_string(), link.to_string()));
            }
        }
    }
    out.sort();
    Ok(out)
}

/// A CVE JSON 5 record as a platform event; `None` without an id or time.
pub fn cve_record_event(body: &str, rules: &Rules) -> Result<Option<PlatformEvent>> {
    let v: Value = serde_json::from_str(body).context("CVE record: not JSON")?;
    let s = |p: &str| v.pointer(p).and_then(Value::as_str);
    let (Some(id), Some(ts)) = (
        s("/cveMetadata/cveId"),
        s("/cveMetadata/datePublished")
            .or_else(|| s("/cveMetadata/dateUpdated"))
            .and_then(parse_date),
    ) else {
        return Ok(None);
    };
    let cna = v.pointer("/containers/cna");
    let arr = |k: &str| {
        cna.and_then(|c| c.get(k))
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default()
    };
    let refs: Vec<String> = arr("references")
        .iter()
        .filter_map(|r| r.get("url")?.as_str().map(str::to_string))
        .collect();
    let affected = arr("affected");
    let product = affected.first().map(|a| {
        let f = |k: &str| {
            a.get(k)
                .and_then(Value::as_str)
                .unwrap_or("")
                .trim()
                .to_string()
        };
        (f("vendor"), f("product"))
    });
    let target = reference_target(refs.iter().map(String::as_str))
        .or_else(|| {
            product
                .as_ref()
                .filter(|(v, p)| !v.is_empty() || !p.is_empty())
                .map(|(v, p)| format!("{v} {p}").trim().to_lowercase())
        })
        .unwrap_or_else(|| id.to_string());
    let description = arr("descriptions")
        .iter()
        .find(|d| {
            d.get("lang")
                .and_then(Value::as_str)
                .is_some_and(|l| l.starts_with("en"))
        })
        .and_then(|d| d.get("value")?.as_str().map(str::to_string))
        .unwrap_or_default();
    let title = cna
        .and_then(|c| c.get("title"))
        .and_then(Value::as_str)
        .unwrap_or("");
    let finder = arr("credits")
        .iter()
        .find_map(|c| c.get("value")?.as_str().map(|x| x.trim().to_lowercase()))
        .filter(|f| !f.is_empty());
    let (vendor, prod) = product.unwrap_or_default();
    let (owner, repo) = target.split_once('/').unwrap_or(("", ""));
    Ok(Some(
        PlatformEvent {
            id: format!("cve:{id}"),
            platform: Platform::Cve,
            action: Action::AdvisoryPublished,
            ts,
            actor: finder
                .as_deref()
                .map(|f| actor_key(Platform::Cve, &format!("credit/{f}")))
                .unwrap_or_default(),
            link: format!("https://www.cve.org/CVERecord?id={id}"),
            target: target.clone(),
            ..Default::default()
        }
        .with_text(
            &format!("{title}\n{description}"),
            &[owner, repo, &vendor, &prod],
            rules,
        ),
    ))
}

fn pull_cvelist(
    client: &Client,
    q: &CdxQuery,
    mark: Option<u64>,
    rules: &Rules,
    max: usize,
) -> Result<PlatformPull> {
    let now_ms = crate::client::now_secs() * 1000;
    let fresh = now_ms - FRESH_SECS * 1000;
    let (start, skipped_ms) = match mark.map(|m| m as i64) {
        Some(m) if m >= now_ms - MAX_BACKLOG_SECS * 1000 => (m, 0),
        Some(m) => (fresh, (fresh - m).max(0)),
        None => (fresh, 0),
    };
    let log = client.get(DELTA_LOG).context("CVE delta log")?;
    let new = delta_log_new(&log, start)?;
    let budget = q.scan.unwrap_or(DEFAULT_CVELIST_RECORDS).clamp(1, 200);
    let mut out = PlatformPull::default();
    let (mut next, mut fetched) = (start, 0u64);
    for (i, (ms, _, url)) in new.iter().enumerate() {
        if i >= budget || out.events.len() >= max {
            break;
        }
        let body = match client.get(url) {
            Ok(b) => b,
            Err(e) if i == 0 => return Err(e),
            Err(_) => break,
        };
        fetched += 1;
        next = *ms;
        if let Some(e) = cve_record_event(&body, rules)? {
            out.events.push(e);
        }
    }
    let skipped_records = if skipped_ms > 0 { 1 } else { 0 };
    out.coverage = Coverage {
        unit: "records",
        read: fetched,
        available: new.len() as u64 + skipped_records,
        skipped: skipped_records,
        next: Some(next.max(0) as u64),
        canary: Some(fetched > 0 || new.is_empty()),
    };
    Ok(out)
}

/// Pull a `cve` source: `endpoint` is a GitHub advisory type
/// (`unreviewed`, `reviewed`, `malware`) or `cvelist`.
pub(crate) fn pull_platform(
    client: &Client,
    q: &CdxQuery,
    mark: Option<u64>,
    rules: &Rules,
    max: usize,
) -> Result<PlatformPull> {
    match q.endpoint.as_deref().unwrap_or("unreviewed") {
        k @ ("unreviewed" | "reviewed" | "malware") => pull_ghsa(client, q, k, mark, rules, max),
        "cvelist" => pull_cvelist(client, q, mark, rules, max),
        e => {
            bail!("unknown cve endpoint `{e}` (expected unreviewed, reviewed, malware or cvelist)")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Every advisory, project, finder and text below is invented.

    #[test]
    fn advisories_become_events_grouped_by_reference_repository() {
        let rules = Rules::default_rules();
        let body = r#"[
          {"ghsa_id":"GHSA-aaaa-bbbb-cccc","cve_id":"CVE-2026-90001","html_url":"https://github.com/advisories/GHSA-aaaa-bbbb-cccc","summary":"Heap overflow in libprobe parse_header","description":"A heap overflow in libprobe 3.1 parse_header allows remote attackers to execute code via a crafted header.","source_code_location":"","references":["https://nvd.nist.gov/vuln/detail/CVE-2026-90001","https://github.com/Probe-Org/LibProbe/issues/7","https://github.com/advisories/GHSA-aaaa-bbbb-cccc"],"published_at":"2026-10-13T15:32:28Z","withdrawn_at":null,"credits":[{"user":{"login":"Finder-1"},"type":"reporter"}]},
          {"ghsa_id":"GHSA-dddd-eeee-ffff","summary":"Input validation in router","description":"","references":["https://www.vendor.example/support/r7000"],"published_at":"2026-10-13T15:33:00Z","credits":[]},
          {"ghsa_id":"GHSA-gone-gone-gone","published_at":"2026-10-13T15:34:00Z","withdrawn_at":"2026-10-13T16:00:00Z"}
        ]"#;
        let (ev, n) = ghsa_events(body, &rules).unwrap();
        assert_eq!((ev.len(), n), (2, 3));
        assert_eq!(ev[0].id, "ghsa:GHSA-aaaa-bbbb-cccc");
        assert_eq!(ev[0].target, "probe-org/libprobe");
        assert_eq!(ev[0].action, Action::AdvisoryPublished);
        assert!(ev[0].actor.starts_with("acct:"));
        assert!(ev[0].text.is_some());
        let json = serde_json::to_string(&ev[0]).unwrap();
        assert!(
            !json.contains("Finder-1") && !json.contains("finder-1"),
            "{json}"
        );
        assert_eq!(ev[1].target, "vendor.example");
        assert!(ev[1].actor.is_empty());
        assert!(ghsa_events("{}", &rules).is_err());
    }

    #[test]
    fn the_delta_log_names_new_records_from_the_list_only() {
        let log = r#"[
          {"fetchTime":"2026-10-13T18:01:46Z","new":[
            {"cveId":"CVE-2026-90002","githubLink":"https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2026/90xxx/CVE-2026-90002.json","dateUpdated":"2026-10-13T17:56:31.399Z"},
            {"cveId":"CVE-2026-90003","githubLink":"https://elsewhere.example/CVE-2026-90003.json","dateUpdated":"2026-10-13T17:57:00Z"}
          ],"updated":[]},
          {"fetchTime":"2026-10-13T17:01:46Z","new":[
            {"cveId":"CVE-2026-90001","githubLink":"https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2026/90xxx/CVE-2026-90001.json","dateUpdated":"2026-10-13T16:00:00Z"}
          ]}
        ]"#;
        let after = chrono::DateTime::parse_from_rfc3339("2026-10-13T15:00:00Z")
            .unwrap()
            .timestamp_millis();
        let new = delta_log_new(log, after).unwrap();
        let ids: Vec<&str> = new.iter().map(|x| x.1.as_str()).collect();
        assert_eq!(ids, ["CVE-2026-90001", "CVE-2026-90002"]);
        assert_eq!(delta_log_new(log, i64::MAX).unwrap().len(), 0);
    }

    #[test]
    fn a_cve_record_becomes_an_event() {
        let rules = Rules::default_rules();
        let rec = r#"{"dataType":"CVE_RECORD","cveMetadata":{"cveId":"CVE-2026-90002","assignerShortName":"Example_CNA","state":"PUBLISHED","datePublished":"2026-10-13T17:56:31.399Z"},
          "containers":{"cna":{"title":"Buffer overflow in probe-tool","descriptions":[{"lang":"en","value":"A buffer overflow in probe-tool 2.0 allows attackers to crash the service via a long argument."}],
          "affected":[{"vendor":"probe","product":"probe-tool"}],"references":[{"url":"https://github.com/probe/probe-tool/pull/3"}],"credits":[{"lang":"en","value":"Jane Finder","type":"finder"}]}}}"#;
        let e = cve_record_event(rec, &rules).unwrap().unwrap();
        assert_eq!(e.id, "cve:CVE-2026-90002");
        assert_eq!(e.target, "probe/probe-tool");
        assert_eq!(e.link, "https://www.cve.org/CVERecord?id=CVE-2026-90002");
        assert!(e.actor.starts_with("acct:"));
        assert!(
            !serde_json::to_string(&e)
                .unwrap()
                .to_lowercase()
                .contains("jane")
        );
        assert!(cve_record_event("{}", &rules).unwrap().is_none());
        assert_eq!(
            reference_target(["https://nvd.nist.gov/x", "https://cve.org/y"]),
            None
        );
    }
}
