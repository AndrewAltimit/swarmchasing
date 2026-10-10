//! Data-driven indicator rules (see `rules/default.toml`).

use crate::model::IndicatorKind;
use regex::{Regex, RegexBuilder, RegexSet, RegexSetBuilder};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};

pub const DEFAULT_RULES: &str = include_str!("../../../rules/default.toml");

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Target {
    Host,
    Url,
    ParamName,
    ParamValue,
    Header,
    UserAgent,
    FinalUrl,
}

impl Target {
    const ALL: [Target; 7] = [
        Target::Host,
        Target::Url,
        Target::ParamName,
        Target::ParamValue,
        Target::Header,
        Target::UserAgent,
        Target::FinalUrl,
    ];

    fn slot(self) -> usize {
        self as usize
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleDef {
    pub id: String,
    pub kind: IndicatorKind,
    pub target: Target,
    pub pattern: String,
    #[serde(default = "one")]
    pub weight: i32,
    #[serde(default)]
    pub significant: bool,
    #[serde(default)]
    pub link: bool,
    #[serde(default)]
    pub description: String,
}

fn one() -> i32 {
    1
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Thresholds {
    pub suggestive: i32,
    pub significant: i32,
}

impl Default for Thresholds {
    fn default() -> Self {
        Self {
            suggestive: 3,
            significant: 6,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Linking {
    pub strong_params: Vec<String>,
    pub window_secs: i64,
    pub run_gap_secs: i64,
    pub burst_gap_secs: i64,
    pub burst_min: usize,
    pub pause_min_secs: i64,
    pub archive_burst_gap_secs: i64,
    pub archive_burst_min: usize,
    pub archive_burst_ratio: f64,
}

impl Default for Linking {
    fn default() -> Self {
        Self {
            strong_params: vec![],
            window_secs: 600,
            run_gap_secs: 900,
            burst_gap_secs: 5,
            burst_min: 5,
            pause_min_secs: 600,
            archive_burst_gap_secs: 180,
            archive_burst_min: 5,
            archive_burst_ratio: 10.0,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Meta {
    #[serde(default)]
    pub version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AsnDef {
    pub asn: u32,
    pub org: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RuleSet {
    #[serde(default)]
    pub meta: Meta,
    #[serde(default)]
    pub thresholds: Thresholds,
    #[serde(default)]
    pub linking: Linking,
    #[serde(default)]
    pub chains: crate::chains::ChainOptions,
    #[serde(default)]
    pub fanout: crate::fanout::FanOutOptions,
    #[serde(default)]
    pub cut_lengths: crate::dialect::CutOptions,
    #[serde(default)]
    pub paths: crate::paths::PathOptions,
    #[serde(default, rename = "rule")]
    pub rules: Vec<RuleDef>,
    #[serde(default, rename = "asn")]
    pub asns: Vec<AsnDef>,
}

pub(crate) enum Matcher {
    HostSuffix(String),
    Re(Regex),
}

pub(crate) struct CompiledRule {
    pub def: RuleDef,
    pub matcher: Matcher,
}

/// The regex rules of one target, compiled once more as a set so one pass
/// over a text says which of them match.
pub(crate) struct TargetSet {
    set: Option<RegexSet>,
    /// Indexes into `Rules::compiled`, in set order.
    rules: Vec<usize>,
}

/// A rule set ready for matching.
pub struct Rules {
    pub set: RuleSet,
    pub(crate) compiled: Vec<CompiledRule>,
    pub(crate) asn_orgs: BTreeMap<u32, String>,
    /// Per target ([`Target::slot`]).
    by_target: Vec<TargetSet>,
    by_id: HashMap<String, usize>,
    /// Host suffixes and URL patterns of relay, carrier and callback rules.
    intermediary_suffixes: Vec<String>,
    intermediary_urls: Option<RegexSet>,
}

impl Rules {
    pub fn default_rules() -> Self {
        Self::from_toml(DEFAULT_RULES).expect("bundled rules/default.toml must be valid")
    }

    pub fn from_toml(text: &str) -> Result<Self, String> {
        let set: RuleSet = toml::from_str(text).map_err(|e| format!("rules: {e}"))?;
        Self::compile(set)
    }

    pub fn compile(set: RuleSet) -> Result<Self, String> {
        let mut seen = std::collections::HashSet::new();
        let mut compiled = Vec::with_capacity(set.rules.len());
        for def in &set.rules {
            if !seen.insert(def.id.clone()) {
                return Err(format!("duplicate rule id `{}`", def.id));
            }
            let matcher = match def.target {
                Target::Host => Matcher::HostSuffix(def.pattern.to_ascii_lowercase()),
                _ => Matcher::Re(
                    RegexBuilder::new(&def.pattern)
                        .case_insensitive(true)
                        .size_limit(1 << 22)
                        .build()
                        .map_err(|e| format!("rule `{}`: {e}", def.id))?,
                ),
            };
            compiled.push(CompiledRule {
                def: def.clone(),
                matcher,
            });
        }
        let by_target = Target::ALL
            .iter()
            .map(|&t| {
                let rules: Vec<usize> = (0..compiled.len())
                    .filter(|&i| compiled[i].def.target == t && t != Target::Host)
                    .collect();
                let patterns = rules.iter().map(|&i| compiled[i].def.pattern.as_str());
                TargetSet {
                    set: regex_set(patterns),
                    rules,
                }
            })
            .collect();
        let by_id = (0..compiled.len())
            .map(|i| (compiled[i].def.id.clone(), i))
            .collect();
        let intermediary = || compiled.iter().filter(|r| is_intermediary_kind(r.def.kind));
        let intermediary_suffixes = intermediary()
            .filter_map(|r| match &r.matcher {
                Matcher::HostSuffix(s) => Some(s.clone()),
                Matcher::Re(_) => None,
            })
            .collect();
        let intermediary_urls = regex_set(
            intermediary()
                .filter(|r| r.def.target == Target::Url)
                .map(|r| r.def.pattern.as_str()),
        );
        let asn_orgs = set.asns.iter().map(|a| (a.asn, a.org.clone())).collect();
        Ok(Self {
            set,
            compiled,
            asn_orgs,
            by_target,
            by_id,
            intermediary_suffixes,
            intermediary_urls,
        })
    }

    /// The rule with this id.
    pub fn rule(&self, id: &str) -> Option<&RuleDef> {
        self.by_id.get(id).map(|&i| &self.compiled[i].def)
    }

    pub fn asn_org(&self, asn: u32) -> Option<&str> {
        self.asn_orgs.get(&asn).map(String::as_str)
    }

    pub(crate) fn of_target(&self, t: Target) -> impl Iterator<Item = &CompiledRule> {
        self.compiled.iter().filter(move |r| r.def.target == t)
    }

    /// The regex rules of target `t` that match `text`, in rule order. The
    /// set says which rules match in one pass; only those run on their own.
    pub(crate) fn matching<'a>(
        &'a self,
        t: Target,
        text: &str,
    ) -> Box<dyn Iterator<Item = &'a CompiledRule> + 'a> {
        let ts = &self.by_target[t.slot()];
        match &ts.set {
            Some(set) => Box::new(
                set.matches(text)
                    .into_iter()
                    .map(move |k| &self.compiled[ts.rules[k]]),
            ),
            None => Box::new(ts.rules.iter().map(move |&i| &self.compiled[i])),
        }
    }

    /// True if `host` is a known relay/carrier host (i.e. not the real target).
    pub(crate) fn is_intermediary_host(&self, host: &str) -> bool {
        self.intermediary_suffixes
            .iter()
            .any(|s| host_matches(host, s))
            || self
                .intermediary_urls
                .as_ref()
                .is_some_and(|set| set.is_match(host))
    }
}

pub(crate) fn is_intermediary_kind(k: IndicatorKind) -> bool {
    matches!(
        k,
        IndicatorKind::Relay | IndicatorKind::Carrier | IndicatorKind::Exfil
    )
}

/// The patterns as one case-insensitive set, or `None` when there are none
/// or the set is too large to build (callers then try each rule in turn).
fn regex_set<'a>(patterns: impl IntoIterator<Item = &'a str>) -> Option<RegexSet> {
    let patterns: Vec<&str> = patterns.into_iter().collect();
    if patterns.is_empty() {
        return None;
    }
    RegexSetBuilder::new(patterns)
        .case_insensitive(true)
        .size_limit(1 << 26)
        .build()
        .ok()
}

pub(crate) fn host_matches(host: &str, suffix: &str) -> bool {
    host == suffix
        || (host.len() > suffix.len()
            && host.ends_with(suffix)
            && host.as_bytes()[host.len() - suffix.len() - 1] == b'.')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundled_rules_compile() {
        let r = Rules::default_rules();
        assert!(r.compiled.len() > 30);
        assert_eq!(r.asn_org(132203), Some("Tencent Cloud"));
    }

    /// A rules file without these sections (one a case pinned earlier) gets
    /// the same settings as the bundled file.
    #[test]
    fn bundled_settings_match_the_defaults() {
        let s = Rules::default_rules().set;
        assert_eq!(s.chains, crate::chains::ChainOptions::default());
        assert_eq!(s.fanout, crate::fanout::FanOutOptions::default());
        assert_eq!(s.cut_lengths, crate::dialect::CutOptions::default());
        assert_eq!(s.paths, crate::paths::PathOptions::default());
    }

    #[test]
    fn suffix() {
        assert!(host_matches(
            "www-example-com.translate.goog",
            "translate.goog"
        ));
        assert!(host_matches("r.jina.ai", "r.jina.ai"));
        assert!(!host_matches("evilr.jina.ai", "r.jina.ai"));
    }

    /// Ids of the bundled `marker.*` residue rules that fire on `url`.
    fn residue_hits(rules: &Rules, url: &str) -> Vec<String> {
        let o = crate::model::Observation {
            url: url.into(),
            ..Default::default()
        };
        crate::extract::extract(&o, rules)
            .hits
            .into_iter()
            .map(|h| h.rule_id)
            .filter(|id| {
                [
                    "marker.md_link",
                    "marker.md_url_wrapper",
                    "marker.placeholder",
                    "marker.template_unrendered",
                    "marker.example_host_value",
                    "marker.tool_call_markup",
                    "marker.tool_call_json",
                    "marker.json_quote_residue",
                    "marker.escaped_newline",
                    "marker.truncated_output",
                    "marker.chat_opener",
                    "marker.doubled_scheme",
                    "marker.garbled_scheme",
                    "marker.impossible_date",
                    "marker.placeholder_identity",
                ]
                .contains(&id.as_str())
            })
            .collect()
    }

    #[test]
    fn model_output_residue_matches() {
        let r = Rules::default_rules();
        for (url, id) in [
            (
                "https://r.jina.ai/https://a.example/p%5D%28https://a.example/p%29",
                "marker.md_link",
            ),
            (
                "https://markdown.new/%60https://a.example/x%60",
                "marker.md_url_wrapper",
            ),
            ("https://a.example/docs/page)", "marker.md_url_wrapper"),
            ("https://a.example/p**", "marker.md_url_wrapper"),
            (
                "https://r.jina.ai/%3Chttps://a.example/x%3E",
                "marker.md_url_wrapper",
            ),
            (
                "https://a.example/v1?appid=YOUR_API_KEY",
                "marker.placeholder",
            ),
            (
                "https://a.example/v1?token=%3Cyour-token%3E",
                "marker.placeholder",
            ),
            (
                "https://a.example/u/INSERT_USER_ID_HERE",
                "marker.placeholder",
            ),
            ("https://a.example/q?h=%3CTARGET%3E", "marker.placeholder"),
            (
                "https://a.example/q?h=%7B%7Btarget%7D%7D",
                "marker.template_unrendered",
            ),
            (
                "https://a.example/q?h=%24%7BHOST%7D",
                "marker.template_unrendered",
            ),
            (
                "https://a.example/login?next=https%3A%2F%2Fexample.com%2F",
                "marker.example_host_value",
            ),
            (
                "https://a.example/c%3C/parameter%3E%3C/invoke%3E",
                "marker.tool_call_markup",
            ),
            (
                "https://a.example/q?s=x%3Ctool_call%3E",
                "marker.tool_call_markup",
            ),
            (
                "https://a.example/q?s=%3Cfunction=fetch%3E",
                "marker.tool_call_markup",
            ),
            (
                "https://httpbin.org/anything?i=%7B%22url%22%3A%22https%3A%2F%2Fa.example%22%7D",
                "marker.tool_call_json",
            ),
            (
                "https://a.example/q?a=%7B%22name%22%3A%22f%22%2C%22arguments%22%3A%7B%7D%7D",
                "marker.tool_call_json",
            ),
            (
                "https://a.example/q?a=%7B%5C%22query%5C%22%3A%5C%22x%5C%22%7D",
                "marker.tool_call_json",
            ),
            (
                "https://a.example/p?f=json%22%7D",
                "marker.json_quote_residue",
            ),
            (
                "https://api.microlink.io/?url=%22https%3A%2F%2Fa.example%2F",
                "marker.json_quote_residue",
            ),
            ("https://a.example/p?f=json%5Cn", "marker.escaped_newline"),
            (
                "https://a.example/search?q=permits%2",
                "marker.truncated_output",
            ),
            (
                "https://a.example/reports/annual-summ%E2%80%A6",
                "marker.truncated_output",
            ),
        ] {
            let hits = residue_hits(&r, url);
            assert!(
                hits.iter().any(|h| h == id),
                "{url}: want {id}, got {hits:?}"
            );
        }
    }

    #[test]
    fn model_output_residue_skips_ordinary_urls() {
        let r = Rules::default_rules();
        for url in [
            // JSON in the query string of ordinary GET APIs.
            "https://search.a.example/_search?source=%7B%22query%22%3A%7B%22match_all%22%3A%7B%7D%7D%7D",
            "https://a.example/graphql?query=%7Bitem%7Bname%7D%7D&variables=%7B%22input%22%3A%7B%22id%22%3A1%7D%7D",
            "https://a.example/api/items?filter=%7B%22where%22%3A%7B%22name%22%3A%22lamp%22%7D%7D",
            // Parentheses, backticks and Markdown in ordinary pages and searches.
            "https://en.wikipedia.org/wiki/Mercury_(planet)",
            "https://github.com/search?q=%60unwrap_or_default%60&type=code",
            "https://stackoverflow.com/search?q=%5Btext%5D(url)+markdown+link",
            "https://www.a.example/catalog%22%3E",
            "https://a.example/a/b/**/c",
            // Placeholder words in prose, and example.com outside a redirect.
            "https://docs.a.example/guides/how-to-find-your-api-key",
            "https://duckduckgo.com/?q=example.com+reserved+domain",
            "https://api.microlink.io/?url=https://www.example.com/",
            "https://en.wikipedia.org/wiki/Example.com",
            // An HTML program's attributes are not quoted URL parameters.
            "data:text/html,<a href=\"https://a.example/\">x</a>",
            // Backslashes in Windows paths, encoded percent signs, trailing dots.
            "https://a.example/view?path=C%3A%5CUsers%5Cnadia%5Cnotes.txt",
            "https://a.example/sale?discount=50%25",
            "https://www.google.com/search?q=wait+for+it...",
            "https://fr.wikipedia.org/wiki/Caf%C3%A9",
            "https://r.jina.ai/https://docs.a.example/tool-use/implement-tool-use",
        ] {
            let hits = residue_hits(&r, url);
            assert!(hits.is_empty(), "{url}: {hits:?}");
        }
    }

    #[test]
    fn chat_scheme_date_and_identity_residue_matches() {
        let r = Rules::default_rules();
        for (url, id) in [
            (
                "https://r.jina.ai/Sure,%20here%20is%20the%20page:%20https://a.example/p",
                "marker.chat_opener",
            ),
            (
                "https://api.microlink.io/?url=Certainly!%20Here%20is%20the%20URL%3A%20https%3A%2F%2Fa.example%2F",
                "marker.chat_opener",
            ),
            (
                "https://a.example/q?s=I%E2%80%99ll%20fetch%20https%3A%2F%2Fa.example%2Fx",
                "marker.chat_opener",
            ),
            (
                "https://a.example/q?s=Here%27s+the+query%3A+%22permits%22",
                "marker.chat_opener",
            ),
            (
                "https://httpbin.org/anything?n=As%20an%20AI%2C%20I%20cannot%20open%20https%3A%2F%2Fa.example",
                "marker.chat_opener",
            ),
            (
                "https://r.jina.ai/https://https://a.example/staff",
                "marker.doubled_scheme",
            ),
            (
                "https://api.microlink.io/?url=http%3A%2F%2Fhttps%3A%2F%2Fa.example%2F",
                "marker.doubled_scheme",
            ),
            (
                "https://a.example/http://https//b.example/",
                "marker.doubled_scheme",
            ),
            (
                "https://httpbin.org/redirect-to?url=https//a.example/login",
                "marker.garbled_scheme",
            ),
            (
                "https://r.jina.ai/hxxps://a.example/c",
                "marker.garbled_scheme",
            ),
            (
                "https://api.microlink.io/?url=hxxps[:]//a.example/",
                "marker.garbled_scheme",
            ),
            (
                "https://a.example/r?from=2026-02-30&to=2026-03-01",
                "marker.impossible_date",
            ),
            (
                "https://a.example/r?date=2026-04-31",
                "marker.impossible_date",
            ),
            (
                "https://a.example/r?date=2026-13-04",
                "marker.impossible_date",
            ),
            (
                "https://a.example/r?filter[start_date]=2026-01-32T00:00:00Z",
                "marker.impossible_date",
            ),
            (
                "https://a.example/r?since=06/31/2026",
                "marker.impossible_date",
            ),
            (
                "https://a.example/r?until=30%2F02%2F2026",
                "marker.impossible_date",
            ),
            (
                "https://a.example/c?email=john.doe%40example.com",
                "marker.placeholder_identity",
            ),
            (
                "https://a.example/c?email=Jane_Doe%40corp.example",
                "marker.placeholder_identity",
            ),
            (
                "https://a.example/c?email=user%40example.com",
                "marker.placeholder_identity",
            ),
            (
                "https://a.example/c?user=test123",
                "marker.placeholder_identity",
            ),
            (
                "https://a.example/c?site=https%3A%2F%2Fyour-domain.com%2F",
                "marker.placeholder_identity",
            ),
            (
                "https://a.example/c?addr=123+Main+Street",
                "marker.placeholder_identity",
            ),
            (
                "https://a.example/c?phone=%28212%29+555-0142",
                "marker.placeholder_identity",
            ),
        ] {
            let hits = residue_hits(&r, url);
            assert!(
                hits.iter().any(|h| h == id),
                "{url}: want {id}, got {hits:?}"
            );
        }
    }

    #[test]
    fn chat_scheme_date_and_identity_residue_skips_ordinary_urls() {
        let r = Rules::default_rules();
        for url in [
            // Searches and slugs that start like a chat reply.
            "https://www.google.com/search?q=here+is+the+news+lyrics",
            "https://duckduckgo.com/?q=i%27ll+be+there+for+you+chords",
            "https://www.bing.com/search?q=as+an+ai+language+model+meme",
            "https://www.bing.com/search?q=certainly!+synonyms",
            "https://r.jina.ai/https://blog.a.example/posts/here-is-the-plan",
            // One scheme in a redirect parameter, scheme-like hosts and paths.
            "https://a.example/login?next=https%3A%2F%2Fb.example%2Fx%3Fr%3Dhttps%253A%252F%252Fc.example",
            "https://web.archive.org/web/2024/https://a.example/",
            "https://https-portal.a.example/http.cat/404",
            // Defanged indicators searched by analysts, and broken crawled hrefs.
            "https://intel.a.example/search?q=hxxps%3A%2F%2Fbad.example%2Fdrop",
            "https://www.a.example/partners/http//b.example/",
            // Dates that exist, and date-shaped versions and IDs.
            "https://a.example/e?date=2024-02-29&to=2026-04-30&end=2026-12-31",
            "https://a.example/e?from=31/12/2026&until=12/31/2026&day=13/05/2026",
            "https://a.example/v2/changelog?version=2024-13-01&build=2026-02-31",
            "https://a.example/orders?id=2026-02-30",
            "https://a.example/archive/2026/02/30/",
            // Near misses for placeholder identities.
            "https://a.example/c?email=john.doe.fan%40mail.example",
            "https://a.example/c?user=test1234",
            "https://a.example/c?site=https%3A%2F%2Fmydomain.example%2F",
            "https://a.example/c?addr=1234+Main+St",
            "https://a.example/c?phone=15550123456",
        ] {
            let hits = residue_hits(&r, url);
            assert!(hits.is_empty(), "{url}: {hits:?}");
        }
    }

    #[test]
    fn placeholder_identities_alone_stay_noise() {
        // Documentation links, QA logins and real street searches use the same
        // stock values; on their own they must not reach the suggestive tier.
        let r = Rules::default_rules();
        for url in [
            "https://docs.mail.example/api/send?to=user%40example.com&subject=Hello",
            "https://qa.a.example/login?user=test123",
            "https://maps.a.example/search?q=123+Main+St+Springfield",
        ] {
            let o = crate::model::Observation {
                url: url.into(),
                ..Default::default()
            };
            let x = crate::extract::extract(&o, &r);
            assert!(x.score < r.set.thresholds.suggestive, "{url}: {}", x.score);
        }
    }
}
