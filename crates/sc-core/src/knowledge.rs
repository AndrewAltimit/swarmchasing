//! What a cluster's targets and clients say about where its knowledge came
//! from, from lists kept in the rules file:
//!
//! - **benchmarks** (`[[benchmark]]`): public benchmark and practice targets
//!   (intentionally vulnerable demo sites, benchmark environments). A
//!   cluster hitting them is likely evaluation or training activity, not
//!   malice.
//! - **stale knowledge** (`[[stale]]`): retired API endpoints and old client
//!   versions, repeated across a cluster's targets, as a model writes from
//!   what its training data knew. Also API path versions below the newest
//!   one seen on the same host family.
//!
//! Both are hints: they never score, link or change a tier.

use crate::analyze::ObsResult;
use regex::{RegexSet, RegexSetBuilder};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap};

/// What a listed pattern reads.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KnownTarget {
    /// The request on the target host (its URL).
    #[default]
    Url,
    /// The user agent.
    UserAgent,
}

/// One `[[benchmark]]` or `[[stale]]` entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KnownPattern {
    pub id: String,
    #[serde(default)]
    pub target: KnownTarget,
    /// Case-insensitive regex.
    pub pattern: String,
    /// What a match means, for reports.
    #[serde(default)]
    pub note: String,
}

/// A list of patterns compiled into one set.
#[derive(Default)]
pub(crate) struct KnownSet {
    pub defs: Vec<KnownPattern>,
    set: Option<RegexSet>,
}

impl KnownSet {
    pub fn compile(defs: &[KnownPattern], what: &str) -> Result<Self, String> {
        let set = if defs.is_empty() {
            None
        } else {
            Some(
                RegexSetBuilder::new(defs.iter().map(|d| d.pattern.as_str()))
                    .case_insensitive(true)
                    .size_limit(1 << 22)
                    .build()
                    .map_err(|e| format!("{what}: {e}"))?,
            )
        };
        Ok(Self {
            defs: defs.to_vec(),
            set,
        })
    }

    /// Indexes of the entries one record matches.
    fn matches(&self, url: &str, ua: Option<&str>) -> BTreeSet<usize> {
        let Some(set) = &self.set else {
            return BTreeSet::new();
        };
        let mut out: BTreeSet<usize> = set
            .matches(url)
            .into_iter()
            .filter(|&i| self.defs[i].target == KnownTarget::Url)
            .collect();
        if let Some(ua) = ua {
            out.extend(
                set.matches(ua)
                    .into_iter()
                    .filter(|&i| self.defs[i].target == KnownTarget::UserAgent),
            );
        }
        out
    }
}

/// One stale-knowledge entry seen in a cluster.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StaleUse {
    pub id: String,
    pub note: String,
    pub records: usize,
    /// Distinct target hosts among them.
    pub hosts: usize,
}

/// Id of the derived entry for API versions below the newest seen.
pub const OLDER_API_VERSION: &str = "older_api_version";

/// A stale entry counts when this many members carry it.
const STALE_MIN_RECORDS: usize = 2;

fn ua(r: &ObsResult) -> Option<&str> {
    r.obs.user_agent.as_deref().or_else(|| {
        r.obs
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("user-agent"))
            .map(|(_, v)| v.as_str())
    })
}

/// Whether record `r` hits any entry of `set`.
pub(crate) fn hits_any(r: &ObsResult, set: &KnownSet) -> bool {
    !set.matches(crate::analyze::target_text(r), ua(r))
        .is_empty()
}

/// Benchmark entries the members hit: id → records.
pub(crate) fn benchmarks(
    results: &[ObsResult],
    members: &[usize],
    set: &KnownSet,
) -> BTreeMap<String, usize> {
    let mut out = BTreeMap::new();
    for &m in members {
        let r = &results[m];
        for i in set.matches(crate::analyze::target_text(r), ua(r)) {
            *out.entry(set.defs[i].id.clone()).or_default() += 1;
        }
    }
    out
}

/// The registrable-looking part of a host: its last two labels.
pub(crate) fn family(host: &str) -> &str {
    let mut dots = host.rmatch_indices('.');
    dots.next();
    match dots.next() {
        Some((i, _)) => &host[i + 1..],
        None => host,
    }
}

/// The API version in a URL's path (`/v2/`, `/api/v1.0/`), if any.
fn api_version(url: &str) -> Option<u32> {
    let path = url.split_once("://").map_or(url, |(_, r)| r);
    let path = &path[path.find('/')?..];
    let path = path.split(['?', '#']).next().unwrap_or("");
    path.split('/').find_map(|seg| {
        let digits = seg.strip_prefix(['v', 'V'])?;
        let major = digits.split('.').next()?;
        (!major.is_empty() && major.len() <= 3 && major.bytes().all(|b| b.is_ascii_digit()))
            .then(|| major.parse().ok())
            .flatten()
    })
}

/// The newest API version seen per host family, over every record.
pub(crate) fn newest_versions(results: &[ObsResult]) -> HashMap<String, u32> {
    let mut out: HashMap<String, u32> = HashMap::new();
    for r in results {
        if let (Some(h), Some(v)) = (
            r.target_host.as_deref(),
            api_version(crate::analyze::target_text(r)),
        ) {
            let e = out.entry(family(h).to_string()).or_insert(v);
            *e = (*e).max(v);
        }
    }
    out
}

/// Stale entries carried by at least [`STALE_MIN_RECORDS`] members.
pub(crate) fn stale(
    results: &[ObsResult],
    members: &[usize],
    set: &KnownSet,
    newest: &HashMap<String, u32>,
) -> Vec<StaleUse> {
    let mut seen: BTreeMap<usize, (usize, BTreeSet<&str>)> = BTreeMap::new();
    let older = set.defs.len();
    for &m in members {
        let r = &results[m];
        let text = crate::analyze::target_text(r);
        let host = r.target_host.as_deref().unwrap_or("");
        let mut hit = set.matches(text, ua(r));
        if let Some(v) = api_version(text)
            && newest.get(family(host)).is_some_and(|&n| v < n)
        {
            hit.insert(older);
        }
        for i in hit {
            let e = seen.entry(i).or_default();
            e.0 += 1;
            e.1.insert(host);
        }
    }
    seen.into_iter()
        .filter(|(_, (n, _))| *n >= STALE_MIN_RECORDS)
        .map(|(i, (records, hosts))| {
            let (id, note) = match set.defs.get(i) {
                Some(d) => (d.id.clone(), d.note.clone()),
                None => (
                    OLDER_API_VERSION.to_string(),
                    "an API version below the newest seen on the same host family".to_string(),
                ),
            };
            StaleUse {
                id,
                note,
                records,
                hosts: hosts.len(),
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions_and_families() {
        assert_eq!(
            api_version("https://api.a.example/v1/items?x=/v9/"),
            Some(1)
        );
        assert_eq!(api_version("https://a.example/api/v2.0/GetX"), Some(2));
        assert_eq!(api_version("https://a.example/video/vintage"), None);
        assert_eq!(api_version("https://a.example/"), None);
        assert_eq!(family("api.data.a.example"), "a.example");
        assert_eq!(family("localhost"), "localhost");
    }
}
