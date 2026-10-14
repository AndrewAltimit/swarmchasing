//! Path fingerprints: what a client asked for on each host, independent of how.
//!
//! Three hints, none of them evidence on its own:
//!
//! - **Recon preamble.** Many automated clients open every host the same way:
//!   `/robots.txt`, `/.well-known/security.txt`, `/.env`, in a fixed order.
//!   [`shared_preambles`] finds one such opening repeated across hosts.
//!   Fetching `/robots.txt` and `/sitemap.xml` first is what every polite
//!   crawler does, so an opening counts only when it goes beyond them.
//! - **Unusual path sets.** [`shared_unusual_sets`] finds the same set of
//!   uncommon paths requested on several hosts. Records rarely say whether a
//!   path existed, so it is "the same unusual path set", not "the same
//!   hallucinated paths"; where records carry a status, 404s are counted.
//! - **Fabricated identifiers.** [`fabricated_ids`] finds UUID-shaped values
//!   that no UUID generator produces (wrong version or variant nibble,
//!   `12345678-1234-…`) and hex "hashes" that are obviously typed by hand.
//!   Language models write such placeholders when they invent a resource.

use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;

/// Path hint settings and path lists (`[paths]` in the rules file).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct PathOptions {
    /// Requests per host that make up its preamble.
    pub preamble_len: usize,
    /// Hosts that must share a preamble or a path set before it is reported.
    pub min_hosts: usize,
    /// Smallest unusual path set worth comparing.
    pub min_paths: usize,
    /// Jaccard similarity at which two hosts' unusual path sets are "the same".
    pub min_jaccard: f64,
    /// Paths polite crawlers fetch first; an opening of only these is ordinary.
    pub crawler: Vec<String>,
    /// Well-known files a client fetches to learn about a host before using
    /// it. Anything under `/.well-known/` counts too.
    pub recon: Vec<String>,
    /// Paths requested on nearly every site, which say nothing about a client.
    pub common: Vec<String>,
}

impl Default for PathOptions {
    fn default() -> Self {
        let own = |v: &[&str]| v.iter().map(|s| s.to_string()).collect();
        Self {
            preamble_len: 5,
            min_hosts: 3,
            min_paths: 3,
            min_jaccard: 0.6,
            crawler: own(&[
                "/",
                "/robots.txt",
                "/sitemap.xml",
                "/sitemap_index.xml",
                "/favicon.ico",
                "/ads.txt",
                "/manifest.json",
            ]),
            recon: own(&[
                "/security.txt",
                "/humans.txt",
                "/llms.txt",
                "/llms-full.txt",
                "/.git/head",
                "/.git/config",
                "/.env",
                "/.ds_store",
                "/crossdomain.xml",
                "/clientaccesspolicy.xml",
                "/server-status",
                "/openapi.json",
                "/swagger.json",
                "/api-docs",
                "/version",
                "/health",
            ]),
            common: own(&[
                "/index.html",
                "/index.php",
                "/index.htm",
                "/home",
                "/about",
                "/contact",
                "/login",
                "/search",
                "/admin",
                "/api",
                "/wp-admin",
                "/wp-login.php",
            ]),
        }
    }
}

impl PathOptions {
    fn is_crawler_path(&self, p: &str) -> bool {
        self.crawler.iter().any(|x| x == p)
    }

    /// True for a well-known recon path (crawler files included).
    pub fn is_recon_path(&self, p: &str) -> bool {
        self.is_crawler_path(p)
            || self.recon.iter().any(|x| x == p)
            || p.starts_with("/.well-known/")
    }

    /// True for a path that is neither a recon file nor one every site serves.
    pub fn is_unusual_path(&self, p: &str) -> bool {
        !self.is_recon_path(p)
            && !self.common.iter().any(|x| x == p)
            && !p.trim_end_matches('/').is_empty()
    }
}

/// One path request on one host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathRequest {
    pub host: String,
    /// Unix seconds; `0` sorts first.
    pub ts: i64,
    /// Normalised with [`normalize_path`].
    pub path: String,
    pub status: Option<u16>,
}

impl PathRequest {
    /// `url` may be a full URL or a bare path.
    pub fn new(host: &str, ts: i64, url: &str, status: Option<u16>) -> Self {
        PathRequest {
            host: host.to_ascii_lowercase(),
            ts,
            path: normalize_path(url),
            status,
        }
    }
}

/// A recon opening seen on several hosts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SharedPreamble {
    /// The opening, in request order.
    pub paths: Vec<String>,
    /// 8 hex digits over `paths`.
    pub hash: String,
    pub hosts: usize,
}

/// One set of uncommon paths requested on several hosts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SharedPathSet {
    /// Paths requested on every host of the group, sorted.
    pub paths: Vec<String>,
    pub hosts: usize,
    /// Requests for those paths whose record says 404 or 410.
    pub not_found: usize,
}

/// Path hints for one cluster. Descriptive: never scored, never linked on.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PathStats {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub preambles: Vec<SharedPreamble>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub shared_unusual_sets: Vec<SharedPathSet>,
    /// Records carrying at least one fabricated-looking identifier.
    #[serde(default)]
    pub fabricated_ids: usize,
    /// Findings by [`FabricatedReason`] label.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub fabricated_reasons: BTreeMap<String, usize>,
    /// Fabricated values its members carry that other clusters carry too:
    /// one model family's habit of inventing the same value, not an
    /// operator link. Internal reports only.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub shared_invention: Vec<SharedInvention>,
}

impl PathStats {
    pub fn is_empty(&self) -> bool {
        self.preambles.is_empty() && self.shared_unusual_sets.is_empty() && self.fabricated_ids == 0
    }
}

/// A fabricated identifier ([`fabricated_ids`]) carried by two or more
/// clusters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SharedInvention {
    pub value: String,
    pub shape: IdShape,
    /// Clusters carrying it, this one included.
    pub clusters: usize,
}

/// Reduce a URL or path to its path: no scheme, host, query or fragment,
/// lowercased, with identifier segments collapsed (`{n}`, `{uuid}`, `{hex}`,
/// `{id}`) so `/user/17` and `/user/42` compare equal. Always starts with `/`.
pub fn normalize_path(url: &str) -> String {
    let head = url.split(['?', '#']).next().unwrap_or("");
    let path = match head.split_once("://") {
        Some((_, rest)) => rest.find('/').map_or("", |i| &rest[i..]),
        None => head,
    };
    let path = path.to_ascii_lowercase();
    let segs: Vec<String> = path
        .trim_start_matches('/')
        .split('/')
        .map(collapse_segment)
        .collect();
    format!("/{}", segs.join("/"))
}

fn collapse_segment(s: &str) -> String {
    let hex = |c: char| c.is_ascii_hexdigit();
    if !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()) {
        "{n}".into()
    } else if uuid_re()
        .find(s)
        .is_some_and(|m| m.as_str().len() == s.len())
    {
        "{uuid}".into()
    } else if s.len() >= 16 && s.chars().all(hex) && s.bytes().any(|b| b.is_ascii_digit()) {
        "{hex}".into()
    } else if s.len() >= 20
        && s.bytes().all(|b| b.is_ascii_alphanumeric())
        && s.bytes().any(|b| b.is_ascii_digit())
        && s.bytes().any(|b| b.is_ascii_alphabetic())
    {
        "{id}".into()
    } else {
        s.to_string()
    }
}

/// The first `k` distinct paths requested on each host, in time order.
pub fn host_preambles(reqs: &[PathRequest], k: usize) -> BTreeMap<String, Vec<String>> {
    let mut sorted: Vec<&PathRequest> = reqs.iter().collect();
    crate::sort::by_key(&mut sorted, |r| r.ts);
    let mut out: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for r in sorted {
        let v = out.entry(r.host.clone()).or_default();
        if v.len() < k && !v.contains(&r.path) {
            v.push(r.path.clone());
        }
    }
    out
}

/// The recon opening of a preamble: its leading run of recon paths, when
/// that run holds at least two recon files and one beyond what crawlers fetch.
pub fn recon_opening(preamble: &[String], opts: &PathOptions) -> Option<Vec<String>> {
    let open: Vec<String> = preamble
        .iter()
        .take_while(|p| opts.is_recon_path(p))
        .cloned()
        .collect();
    let recon = open.iter().filter(|p| p.as_str() != "/").count();
    let beyond = open.iter().any(|p| !opts.is_crawler_path(p));
    (recon >= 2 && beyond).then_some(open)
}

/// Recon openings of the first `preamble_len` paths shared by at least
/// `min_hosts` hosts, most hosts first.
pub fn shared_preambles(reqs: &[PathRequest], opts: &PathOptions) -> Vec<SharedPreamble> {
    let mut by_open: BTreeMap<Vec<String>, usize> = BTreeMap::new();
    for pre in host_preambles(reqs, opts.preamble_len).values() {
        if let Some(open) = recon_opening(pre, opts) {
            *by_open.entry(open).or_default() += 1;
        }
    }
    let mut out: Vec<SharedPreamble> = by_open
        .into_iter()
        .filter(|(_, n)| *n >= opts.min_hosts)
        .map(|(paths, hosts)| SharedPreamble {
            hash: crate::fingerprint::short_hash(&paths.join(" ")),
            paths,
            hosts,
        })
        .collect();
    crate::sort::by(&mut out, |a, b| {
        b.hosts.cmp(&a.hosts).then(a.paths.cmp(&b.paths))
    });
    out
}

fn jaccard(a: &BTreeSet<&str>, b: &BTreeSet<&str>) -> f64 {
    let inter = a.intersection(b).count();
    let union = a.len() + b.len() - inter;
    if union == 0 {
        0.0
    } else {
        inter as f64 / union as f64
    }
}

/// Groups of at least `min_hosts` hosts whose unusual path sets have Jaccard
/// similarity of at least `min_jaccard` with the group's first host, and share
/// at least `min_paths` paths. The caller picks the time window by choosing
/// which requests to pass. Each host joins at most one group.
pub fn shared_unusual_sets(reqs: &[PathRequest], opts: &PathOptions) -> Vec<SharedPathSet> {
    let (min_jaccard, min_paths, min_hosts) = (opts.min_jaccard, opts.min_paths, opts.min_hosts);
    let mut sets: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    for r in reqs.iter().filter(|r| opts.is_unusual_path(&r.path)) {
        sets.entry(&r.host).or_default().insert(&r.path);
    }
    sets.retain(|_, s| s.len() >= min_paths);
    let hosts: Vec<&str> = sets.keys().copied().collect();
    let mut taken: BTreeSet<&str> = BTreeSet::new();
    let mut out = Vec::new();
    for &seed in &hosts {
        if taken.contains(seed) {
            continue;
        }
        let group: Vec<&str> = hosts
            .iter()
            .copied()
            .filter(|h| !taken.contains(h) && jaccard(&sets[seed], &sets[h]) >= min_jaccard)
            .collect();
        if group.len() < min_hosts {
            continue;
        }
        let core: BTreeSet<&str> = group.iter().skip(1).fold(sets[seed].clone(), |acc, h| {
            acc.intersection(&sets[h]).copied().collect()
        });
        if core.len() < min_paths {
            continue;
        }
        let not_found = reqs
            .iter()
            .filter(|r| group.contains(&r.host.as_str()) && core.contains(r.path.as_str()))
            .filter(|r| matches!(r.status, Some(404 | 410)))
            .count();
        taken.extend(group.iter().copied());
        out.push(SharedPathSet {
            paths: core.into_iter().map(str::to_string).collect(),
            hosts: group.len(),
            not_found,
        });
    }
    crate::sort::by(&mut out, |a, b| {
        b.hosts.cmp(&a.hosts).then(a.paths.cmp(&b.paths))
    });
    out
}

/// What an identifier looks like.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdShape {
    /// `8-4-4-4-12` hex.
    Uuid,
    /// 32, 40 or 64 hex digits (MD5, SHA-1, SHA-256 length).
    Hash,
}

/// Why an identifier looks invented rather than generated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FabricatedReason {
    /// Four or fewer distinct hex digits (`aaaaaaaa-…`, `0000…`).
    LowDiversity,
    /// Six or more consecutive digits in hex order (`123456`, `abcdef`).
    Sequential,
    /// Built from a repeated unit or repeated UUID groups (`1234-1234-1234`).
    Repeated,
    /// UUID whose version nibble is not 1 to 8.
    BadVersion,
    /// UUID whose variant nibble is not 8, 9, a or b.
    BadVariant,
}

impl FabricatedReason {
    pub fn label(self) -> &'static str {
        match self {
            FabricatedReason::LowDiversity => "low_diversity",
            FabricatedReason::Sequential => "sequential",
            FabricatedReason::Repeated => "repeated",
            FabricatedReason::BadVersion => "bad_version",
            FabricatedReason::BadVariant => "bad_variant",
        }
    }
}

/// One identifier in a record that looks invented.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FabricatedId {
    pub value: String,
    pub shape: IdShape,
    pub reason: FabricatedReason,
}

fn uuid_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b").unwrap()
    })
}

fn hex_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)\b[0-9a-f]{32,64}\b").unwrap())
}

/// Identifiers in `text` (a URL or decoded layer) that look invented. The nil
/// and max UUIDs are standard values and are not reported.
pub fn fabricated_ids(text: &str) -> Vec<FabricatedId> {
    let mut out = Vec::new();
    for m in uuid_re().find_iter(text) {
        let v = m.as_str().to_ascii_lowercase();
        let hex: String = v.chars().filter(|&c| c != '-').collect();
        if hex.bytes().all(|b| b == b'0') || hex.bytes().all(|b| b == b'f') {
            continue;
        }
        let groups: Vec<&str> = v.split('-').collect();
        let b = hex.as_bytes();
        let reason = patterned(&hex)
            .or_else(|| {
                let (g1, g2, g3, g4) = (groups[0], groups[1], groups[2], groups[3]);
                (g2 == g3 || g3 == g4 || g2 == g4 || g1 == format!("{g2}{g2}"))
                    .then_some(FabricatedReason::Repeated)
            })
            .or_else(|| (!(b'1'..=b'8').contains(&b[12])).then_some(FabricatedReason::BadVersion))
            .or_else(|| {
                (!matches!(b[16], b'8' | b'9' | b'a' | b'b'))
                    .then_some(FabricatedReason::BadVariant)
            });
        if let Some(reason) = reason {
            out.push(FabricatedId {
                value: v,
                shape: IdShape::Uuid,
                reason,
            });
        }
    }
    for m in hex_re().find_iter(text) {
        let v = m.as_str().to_ascii_lowercase();
        if !matches!(v.len(), 32 | 40 | 64) {
            continue;
        }
        if let Some(reason) = patterned(&v) {
            out.push(FabricatedId {
                value: v,
                shape: IdShape::Hash,
                reason,
            });
        }
    }
    out
}

/// Fabricated identifiers across several texts of one record, each value once.
pub fn fabricated_in<'a>(texts: impl IntoIterator<Item = &'a str>) -> Vec<FabricatedId> {
    let mut seen = BTreeSet::new();
    texts
        .into_iter()
        .flat_map(fabricated_ids)
        .filter(|f| seen.insert(f.value.clone()))
        .collect()
}

/// Patterns no random generator produces, checked on lowercase hex digits.
fn patterned(hex: &str) -> Option<FabricatedReason> {
    let b = hex.as_bytes();
    if b.iter().collect::<BTreeSet<_>>().len() <= 4 {
        return Some(FabricatedReason::LowDiversity);
    }
    if longest_sequence(b) >= 6 {
        return Some(FabricatedReason::Sequential);
    }
    let repeats = (1..=b.len() / 2)
        .filter(|&u| b.len().is_multiple_of(u))
        .any(|u| b.chunks(u).all(|c| c == &b[..u]));
    repeats.then_some(FabricatedReason::Repeated)
}

/// Longest run of digits stepping by one in hex order, either direction. `9`
/// followed by `0` continues an ascending run, as in `1234567890`.
fn longest_sequence(b: &[u8]) -> usize {
    let val = |c: u8| match c {
        b'0'..=b'9' => i32::from(c - b'0'),
        _ => i32::from(c - b'a') + 10,
    };
    let (mut best, mut up, mut down) = (1, 1, 1);
    for w in b.windows(2) {
        let (x, y) = (val(w[0]), val(w[1]));
        up = if y == x + 1 || (x == 9 && y == 0) {
            up + 1
        } else {
            1
        };
        down = if y == x - 1 { down + 1 } else { 1 };
        best = best.max(up).max(down);
    }
    best
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(host: &str, ts: i64, path: &str) -> PathRequest {
        PathRequest::new(host, ts, path, None)
    }

    fn crawl(host: &str, t0: i64, paths: &[&str]) -> Vec<PathRequest> {
        paths
            .iter()
            .enumerate()
            .map(|(i, p)| req(host, t0 + i as i64, p))
            .collect()
    }

    #[test]
    fn normalises_paths() {
        assert_eq!(normalize_path("https://A.example"), "/");
        assert_eq!(
            normalize_path("https://a.example/Robots.TXT?x=1#f"),
            "/robots.txt"
        );
        assert_eq!(normalize_path("/user/17/posts"), "/user/{n}/posts");
        assert_eq!(
            normalize_path("https://a.example/o/6f1c2a9e-8b7d-4e3f-a1b2-c3d4e5f60718"),
            "/o/{uuid}"
        );
        assert_eq!(
            normalize_path("http://a.example/blob/9fceb02d0ae598e95dc970b74767f19372d61af8/x"),
            "/blob/{hex}/x"
        );
        assert_eq!(normalize_path("/t/AbC123dEf456gHi789jKl0"), "/t/{id}");
        assert_eq!(
            normalize_path("/docs/getting-started"),
            "/docs/getting-started"
        );
    }

    #[test]
    fn recon_opening_shared_across_hosts() {
        let open = ["/robots.txt", "/.well-known/security.txt", "/.env"];
        let mut reqs = Vec::new();
        for (i, h) in ["a.example", "b.example", "c.example"].iter().enumerate() {
            let mut p = open.to_vec();
            p.push(["/api/v1/users", "/checkout", "/blog"][i]);
            reqs.extend(crawl(h, 100 * i as i64, &p));
        }
        // A fourth host opened differently.
        reqs.extend(crawl("d.example", 0, &["/", "/about", "/robots.txt"]));
        let s = shared_preambles(&reqs, &PathOptions::default());
        assert_eq!(s.len(), 1, "{s:?}");
        assert_eq!(s[0].paths, open);
        assert_eq!(s[0].hosts, 3);
        assert_eq!(s[0].hash.len(), 8);
        // Two hosts are not enough.
        assert!(shared_preambles(&reqs[..8], &PathOptions::default()).is_empty());
    }

    #[test]
    fn ordinary_crawl_is_not_a_recon_preamble() {
        let mut reqs = Vec::new();
        for (i, h) in ["a.example", "b.example", "c.example", "d.example"]
            .iter()
            .enumerate()
        {
            reqs.extend(crawl(
                h,
                100 * i as i64,
                &["/robots.txt", "/sitemap.xml", "/", "/about", "/products/12"],
            ));
        }
        assert!(shared_preambles(&reqs, &PathOptions::default()).is_empty());
        // Order matters: the same files in another order are another opening.
        let mut mixed = Vec::new();
        for (i, h) in ["a.example", "b.example", "c.example"].iter().enumerate() {
            let p: &[&str] = if i == 0 {
                &["/.env", "/robots.txt"]
            } else {
                &["/robots.txt", "/.env"]
            };
            mixed.extend(crawl(h, 0, p));
        }
        assert!(shared_preambles(&mixed, &PathOptions::default()).is_empty());
    }

    #[test]
    fn same_unusual_path_set_across_hosts() {
        let set = [
            "/api/v2/export-all",
            "/internal/debug/config",
            "/backup/db.sql",
        ];
        let mut reqs = Vec::new();
        for (i, h) in ["a.example", "b.example", "c.example"].iter().enumerate() {
            for (j, p) in set.iter().enumerate() {
                let status = (i == 0).then_some(404);
                reqs.push(PathRequest::new(h, j as i64, p, status));
            }
            // Common and recon paths never count.
            reqs.push(req(h, 10, "/"));
            reqs.push(req(h, 11, "/robots.txt"));
            reqs.push(req(h, 12, "/login"));
        }
        // One extra path on one host keeps Jaccard at 0.75.
        reqs.push(req("c.example", 20, "/api/v2/import-all"));
        let s = shared_unusual_sets(&reqs, &PathOptions::default());
        assert_eq!(s.len(), 1, "{s:?}");
        assert_eq!(s[0].hosts, 3);
        assert_eq!(s[0].not_found, 3);
        let mut want: Vec<String> = set.iter().map(|p| p.to_string()).collect();
        want.sort();
        assert_eq!(s[0].paths, want);
    }

    #[test]
    fn different_sites_do_not_share_a_path_set() {
        let mut reqs = Vec::new();
        reqs.extend(crawl(
            "a.example",
            0,
            &["/shop/cart", "/shop/item/4", "/faq"],
        ));
        reqs.extend(crawl(
            "b.example",
            0,
            &["/news/today", "/news/sport", "/faq"],
        ));
        reqs.extend(crawl(
            "c.example",
            0,
            &["/docs/install", "/docs/api", "/faq"],
        ));
        assert!(shared_unusual_sets(&reqs, &PathOptions::default()).is_empty());
        // Too few paths per host.
        let mut small = Vec::new();
        for h in ["a.example", "b.example", "c.example"] {
            small.extend(crawl(h, 0, &["/x-one", "/x-two"]));
        }
        assert!(shared_unusual_sets(&small, &PathOptions::default()).is_empty());
    }

    fn reasons(text: &str) -> Vec<FabricatedReason> {
        fabricated_ids(text).into_iter().map(|f| f.reason).collect()
    }

    #[test]
    fn fabricated_uuids() {
        use FabricatedReason::*;
        assert_eq!(
            reasons("https://a.example/o/12345678-1234-1234-1234-123456789abc"),
            [Sequential]
        );
        assert_eq!(
            reasons("/o/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"),
            [LowDiversity]
        );
        assert_eq!(
            reasons("/o/9c4e7f1a-5d2b-4b3c-5d2b-71e09a3f6c8d"),
            [Repeated]
        );
        assert_eq!(
            reasons("/o/9c4e7f1a-5d2b-c1e3-8a7d-71e09a3f6c8d"),
            [BadVersion]
        );
        assert_eq!(
            reasons("/o/9c4e7f1a-5d2b-4c1e-3a7d-71e09a3f6c8d"),
            [BadVariant]
        );
        let f = &fabricated_ids("?id=12345678-1234-1234-1234-123456789ABC")[0];
        assert_eq!(f.shape, IdShape::Uuid);
        assert_eq!(f.value, "12345678-1234-1234-1234-123456789abc");
    }

    #[test]
    fn real_uuids_are_not_flagged() {
        for u in [
            "6f1c2a9e-8b7d-4e3f-a1b2-c3d4e5f60718",
            "0b6c1f0e-1111-4c2a-9a55-3f2e1d0c9b8a",
            "7d2e4a10-2222-4b3c-8a66-4e3f2a1b0c9d",
            "f47ac10b-58cc-4372-a567-0e02b2c3d479",
            "c232ab00-9414-11ec-b3c8-9f6bdeced846",
            "017f22e2-79b0-7cc3-98c4-dc0c0c07398f",
            "00000000-0000-0000-0000-000000000000",
            "ffffffff-ffff-ffff-ffff-ffffffffffff",
        ] {
            assert!(
                fabricated_ids(&format!("https://webhook.site/{u}")).is_empty(),
                "{u}"
            );
        }
    }

    #[test]
    fn fabricated_hashes() {
        use FabricatedReason::*;
        assert_eq!(
            reasons("/c/0000000000000000000000000000000000000000"),
            [LowDiversity]
        );
        assert_eq!(
            reasons("?sha=1234567890abcdef1234567890abcdef12345678"),
            [Sequential]
        );
        assert_eq!(reasons("?md5=deadbeefdeadbeefdeadbeefdeadbeef"), [Repeated]);
        assert_eq!(
            fabricated_ids("?md5=deadbeefdeadbeefdeadbeefdeadbeef")[0].shape,
            IdShape::Hash
        );
        // Real digests and other lengths pass.
        for h in [
            "9fceb02d0ae598e95dc970b74767f19372d61af8",
            "d41d8cd98f00b204e9800998ecf8427e",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "0123456789abcdef0123",
        ] {
            assert!(fabricated_ids(&format!("/x/{h}")).is_empty(), "{h}");
        }
    }

    #[test]
    fn fabricated_in_dedups_across_layers() {
        let u = "12345678-1234-1234-1234-123456789abc";
        let a = format!("https://r.example/https://t.example/o/{u}");
        let b = format!("https://t.example/o/{u}");
        assert_eq!(fabricated_in([a.as_str(), b.as_str()]).len(), 1);
    }
}
