//! Declared, then undeclared: a declared agent's requests are blocked, and
//! undeclared browser-like requests for the same pages follow within
//! minutes (FM-7.11). Cloudflare's published analysis of undeclared
//! crawling (blog.cloudflare.com) describes this shape: a declared crawler
//! is refused, and requests with a generic browser user agent from other
//! addresses fetch the same pages.
//!
//! It is a pattern to check, never a score, a tier or a link: the same
//! sequence is what an unrelated visitor reading the page after the agent
//! looks like, and an operator log alone cannot tell them apart. The hint
//! names no provider beyond what the blocked requests declare, and never
//! the undeclared requests' sender.
//!
//! The pipeline finds it from the rules alone (a declared product in the
//! user agent, or Web Bot Auth headers), so the browser workbench shows it.
//! With the providers' range files held, [`super::annotate`] finds it again
//! and leaves out undeclared requests from inside the declared product's
//! published ranges: those are the provider's own systems, not a fallback.

use super::{Catalog, IdentityData};
use crate::analyze::{Analysis, ObsResult};
use crate::model::TsKind;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// How long after a blocked request an undeclared one still counts.
pub const WINDOW_SECS: i64 = 600;
/// Paths listed on the hint.
const MAX_PATHS: usize = 5;

/// A cluster's declared requests that were blocked, and the undeclared
/// requests for the same pages that followed them.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Fallback {
    /// What the blocked requests declared: the product token in their user
    /// agent, or `a Web Bot Auth signature`.
    pub declared: String,
    /// Target host, defanged (`a[.]b`).
    pub host: String,
    /// Normalised paths both asked for ([`crate::paths::normalize_path`]).
    pub paths: Vec<String>,
    /// Blocked declared requests followed by an undeclared one.
    pub blocked: usize,
    /// Undeclared browser-like requests that followed.
    pub undeclared: usize,
    /// The longest wait from a blocked request to the first undeclared one
    /// for the same page.
    pub within_secs: i64,
    /// Whether the declared product's range files were held, so that
    /// undeclared requests from inside them were left out.
    #[serde(default)]
    pub ranges_checked: bool,
}

impl Fallback {
    /// One line for reports and the workbench. Hosts are already defanged.
    pub fn detail(&self) -> String {
        format!(
            "a pattern to check: {} blocked request(s) declaring {} on {} were followed within {} min by {} undeclared browser-like request(s) for the same page(s) ({}){}. An agent falling back to an undeclared client after a block looks like this; so does an unrelated visitor reading the same page. It is never scored, and says nothing about who sent the undeclared requests",
            self.blocked,
            self.declared,
            self.host,
            ((self.within_secs + 59) / 60).max(1),
            self.undeclared,
            self.paths.join(", "),
            if self.ranges_checked {
                ", from outside the declared product's published ranges"
            } else {
                "; the declared product's ranges were not held, so the undeclared requests may come from its own systems"
            }
        )
    }
}

/// A refusal: 403 or 429, or a challenge page or header.
fn blocked(r: &ObsResult) -> bool {
    let o = &r.obs;
    matches!(o.status, Some(403 | 429))
        || o.final_url
            .as_deref()
            .is_some_and(|u| u.to_ascii_lowercase().contains("challenge"))
        || o.headers.iter().any(|(k, v)| {
            k.eq_ignore_ascii_case("cf-mitigated") && v.eq_ignore_ascii_case("challenge")
        })
}

/// What a record declares: a product token in its user agent (the
/// `header.agent_ua` match) or a Web Bot Auth signature.
fn declares(r: &ObsResult) -> Option<String> {
    r.hits
        .iter()
        .find(|h| h.rule_id == "header.agent_ua")
        .map(|h| h.matched.clone())
        .or_else(|| {
            r.hits
                .iter()
                .any(|h| h.rule_id == "selfid.signature_agent")
                .then(|| "a Web Bot Auth signature".to_string())
        })
}

/// A generic browser user agent: `Mozilla/5.0` and a browser engine, with
/// no bot, crawler or `compatible;` product in it.
fn browser_like(ua: &str) -> bool {
    let l = ua.to_ascii_lowercase();
    l.starts_with("mozilla/5.0")
        && ["chrome/", "safari/", "firefox/", "edg/"]
            .iter()
            .any(|e| l.contains(e))
        && !["bot", "crawl", "spider", "compatible;", "headless"]
            .iter()
            .any(|w| l.contains(w))
}

/// A server-side request with a time and a target.
fn request(r: &ObsResult) -> Option<(&str, i64)> {
    (r.obs.ts_kind == TsKind::Request && r.obs.ts > 0)
        .then_some(())
        .and(r.target_host.as_deref())
        .map(|h| (h, r.obs.ts))
}

/// The fallback hint of each cluster that has one, by cluster index.
/// `ranges`, when given, leaves out undeclared requests from inside the
/// declared product's held range files.
pub fn fallbacks(
    a: &Analysis,
    ranges: Option<(&Catalog, &IdentityData)>,
) -> BTreeMap<usize, Fallback> {
    // Undeclared browser-like requests by (host, path), in time order.
    let mut undeclared: BTreeMap<(String, String), Vec<(i64, usize)>> = BTreeMap::new();
    for (i, r) in a.results.iter().enumerate() {
        let Some((host, ts)) = request(r) else {
            continue;
        };
        if declares(r).is_some() || !r.obs.user_agent.as_deref().is_some_and(browser_like) {
            continue;
        }
        let key = (
            host.to_ascii_lowercase(),
            crate::paths::normalize_path(&r.obs.url),
        );
        undeclared.entry(key).or_default().push((ts, i));
    }
    for v in undeclared.values_mut() {
        v.sort();
    }

    let mut out = BTreeMap::new();
    for (ci, c) in a.clusters.iter().enumerate() {
        // (declared, host) -> (paths, blocked, followers, longest wait, checked)
        type Acc = (BTreeSet<String>, usize, BTreeSet<usize>, i64, bool);
        let mut by: BTreeMap<(String, String), Acc> = BTreeMap::new();
        for &m in &c.members {
            let r = &a.results[m];
            let (Some((host, ts)), Some(declared)) = (request(r), declares(r)) else {
                continue;
            };
            if !blocked(r) {
                continue;
            }
            // The declared product's held ranges, when the caller has them.
            let held: Option<Vec<_>> = ranges.and_then(|(cat, data)| {
                let agent = cat.agent_in_ua(r.obs.user_agent.as_deref()?)?;
                let t: Vec<_> = agent
                    .ranges
                    .iter()
                    .filter_map(|id| data.ranges.get(id))
                    .collect();
                (!t.is_empty()).then_some(t)
            });
            let path = crate::paths::normalize_path(&r.obs.url);
            let key = (host.to_ascii_lowercase(), path.clone());
            let follow: Vec<(i64, usize)> = undeclared
                .get(&key)
                .into_iter()
                .flatten()
                .filter(|&&(t, i)| t >= ts && t - ts <= WINDOW_SECS && !c.members.contains(&i))
                .filter(|&&(_, i)| {
                    let ip = a.results[i].obs.ip.as_deref();
                    held.as_ref().is_none_or(|tables| {
                        !ip.is_some_and(|ip| tables.iter().any(|t| t.contains(ip)))
                    })
                })
                .copied()
                .collect();
            let Some(&(first, _)) = follow.first() else {
                continue;
            };
            let e = by.entry((declared, key.0)).or_default();
            e.0.insert(path);
            e.1 += 1;
            e.2.extend(follow.iter().map(|&(_, i)| i));
            e.3 = e.3.max(first - ts);
            e.4 |= held.is_some();
        }
        // The pair with the most blocked requests speaks for the cluster.
        if let Some(((declared, host), (paths, blocked, followers, wait, checked))) =
            by.into_iter().max_by_key(|(_, v)| (v.1, v.2.len()))
        {
            out.insert(
                ci,
                Fallback {
                    declared: crate::extract::defang(&declared),
                    host: crate::extract::defang_host(&host),
                    paths: paths.into_iter().take(MAX_PATHS).collect(),
                    blocked,
                    undeclared: followers.len(),
                    within_secs: wait,
                    ranges_checked: checked,
                },
            );
        }
    }
    out
}

/// Set each cluster's fallback hint, clearing stale ones.
pub fn mark(a: &mut Analysis, ranges: Option<(&Catalog, &IdentityData)>) {
    let mut found = fallbacks(a, ranges);
    for (i, c) in a.clusters.iter_mut().enumerate() {
        c.identity.fallback = found.remove(&i);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Observation;
    use crate::rules::Rules;

    const T: i64 = 1_791_000_000;
    const DECLARED: &str = "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; ChatGPT-User/1.0; +https://openai.com/bot";
    const BROWSER: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36";

    fn req(id: &str, ts: i64, path: &str, ua: &str, ip: &str, status: u16) -> Observation {
        Observation {
            id: id.into(),
            source: "access_log".into(),
            ts,
            ts_kind: TsKind::Request,
            url: format!("https://shop.example{path}"),
            ip: Some(ip.into()),
            user_agent: Some(ua.into()),
            status: Some(status),
            ..Default::default()
        }
    }

    fn records() -> Vec<Observation> {
        vec![
            req(
                "d1",
                T,
                "/pricing?id=1%20UNION%20SELECT%201",
                DECLARED,
                "192.0.2.9",
                403,
            ),
            req(
                "d2",
                T + 20,
                "/docs/17?id=2%20UNION%20SELECT%202",
                DECLARED,
                "192.0.2.9",
                403,
            ),
            // Undeclared, from elsewhere, for the same pages, minutes later.
            req("u1", T + 90, "/pricing", BROWSER, "203.0.113.50", 200),
            req("u2", T + 200, "/docs/42", BROWSER, "203.0.113.51", 200),
            // Too late, another page, and a declared bot: none count.
            req("u3", T + 5_000, "/pricing", BROWSER, "203.0.113.52", 200),
            req("u4", T + 100, "/about", BROWSER, "203.0.113.53", 200),
            req(
                "u5",
                T + 100,
                "/pricing",
                "Googlebot/2.1",
                "203.0.113.54",
                200,
            ),
        ]
    }

    #[test]
    fn a_blocked_declared_agent_then_undeclared_browsers() {
        let mut a = crate::analyze(records(), &Rules::default_rules());
        let (ci, f) = fallbacks(&a, None).into_iter().next().expect("a hint");
        assert!(
            a.clusters[ci]
                .members
                .iter()
                .all(|&m| a.results[m].obs.user_agent.as_deref() == Some(DECLARED))
        );
        assert_eq!(f.declared, "ChatGPT-User");
        assert_eq!(f.host, "shop[.]example");
        assert_eq!(f.paths, ["/docs/{n}", "/pricing"]);
        assert_eq!((f.blocked, f.undeclared), (2, 2));
        assert_eq!(f.within_secs, 180);
        assert!(!f.ranges_checked);
        let line = f.detail();
        assert!(line.starts_with("a pattern to check: 2 blocked"), "{line}");
        assert!(line.contains("within 3 min"), "{line}");
        assert!(!line.contains("OpenAI"), "names no provider: {line}");
        // The pipeline sets it, and nothing is scored on it.
        assert_eq!(a.clusters[ci].identity.fallback.as_ref(), Some(&f));
        let score = a.clusters[ci].score;
        mark(&mut a, None);
        assert_eq!(a.clusters[ci].score, score);
        // Case notes show it; a provider report does not.
        let report = |audience| {
            let opts = crate::report::ReportOptions {
                audience,
                cluster: Some(a.clusters[ci].id.clone()),
                ..Default::default()
            };
            crate::report::render_markdown(&a, &opts)
        };
        let notes = report(crate::report::Audience::Internal);
        assert!(
            notes.contains("  - declared, then undeclared: a pattern to check: 2 blocked request(s) declaring ChatGPT-User on shop[.]example"),
            "{notes}"
        );
        assert!(!report(crate::report::Audience::Provider).contains("a pattern to check"));
    }

    #[test]
    fn not_blocked_or_inside_the_declared_ranges_is_no_hint() {
        let mut rs = records();
        for o in rs.iter_mut().filter(|o| o.id.starts_with('d')) {
            o.status = Some(200);
        }
        let a = crate::analyze(rs, &Rules::default_rules());
        assert!(fallbacks(&a, None).is_empty());

        // A challenge page counts as a block.
        let mut rs = records();
        for o in rs.iter_mut().filter(|o| o.id.starts_with('d')) {
            o.status = Some(200);
            o.final_url = Some("https://shop.example/cdn-cgi/challenge-platform/h/b".into());
        }
        let a = crate::analyze(rs, &Rules::default_rules());
        assert_eq!(fallbacks(&a, None).len(), 1);

        // Undeclared requests from the product's own published range are
        // the provider's systems: with the file held, no hint.
        let mut rs = records();
        for o in rs.iter_mut().filter(|o| o.id.starts_with('u')) {
            o.ip = Some("192.0.2.10".into());
        }
        let a = crate::analyze(rs, &Rules::default_rules());
        let mut d = IdentityData::default();
        d.ranges.insert(
            "openai.chatgpt-user".into(),
            super::super::ranges::RangeTable::parse(
                "openai.chatgpt-user",
                r#"{"prefixes":[{"ipv4Prefix":"192.0.2.0/28"}]}"#,
            )
            .unwrap(),
        );
        let cat = Catalog::bundled();
        assert_eq!(fallbacks(&a, None).len(), 1);
        assert!(fallbacks(&a, Some((&cat, &d))).is_empty());
    }
}
