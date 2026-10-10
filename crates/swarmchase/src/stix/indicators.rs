//! Indicators: STIX patterns for the run tags, callback channels, agent
//! markers and flagged user agents in a record.

use sc_core::notice::{PublicView, TAG_PARAMS};
use sc_core::{IndicatorKind, LinkFeature, ObsResult, Tier};
use std::collections::{BTreeMap, BTreeSet};

/// One indicator, gathered over every record and cluster it came from.
pub(super) struct Draft {
    pub name: String,
    pub label: String,
    pub tier: Tier,
    pub valid_from: i64,
    pub clusters: BTreeSet<usize>,
}

/// The indicators one record yields, keyed by STIX pattern. Only patterns
/// that match the record they came from are kept.
pub(super) fn indicators(
    r: &ObsResult,
    kinds: &BTreeMap<&str, IndicatorKind>,
    ua_rules: &BTreeSet<&str>,
    public: bool,
    url_shown: bool,
    view: &mut PublicView,
) -> Vec<(String, Draft)> {
    let url = r.obs.url.to_ascii_lowercase();
    let mut out = Vec::new();
    let mut seen = BTreeSet::new();
    let mut url_like = |out: &mut Vec<(String, Draft)>, value: &str, name: String, label: &str| {
        let lower = value.to_ascii_lowercase();
        if value.is_empty() || value.ends_with('…') || !url.contains(&lower) {
            return;
        }
        if seen.insert(format!("url:{lower}")) {
            out.push((
                format!("[url:value LIKE '%{}%']", lit(value)),
                draft(name, label.to_string()),
            ));
        }
    };
    let mut domains = BTreeSet::new();

    for f in &r.features {
        if public && view.feature(f) != f.to_string() {
            continue;
        }
        let what = feature_kind(f, kinds);
        let (rule, value) = match f {
            LinkFeature::Param { .. } => {
                let p = f.to_string();
                let p = p.trim_start_matches("param:");
                url_like(&mut out, p, format!("{what} {p}"), "param");
                continue;
            }
            LinkFeature::Rule { rule, value } => (rule.as_str(), value.as_str()),
        };
        match kinds.get(rule) {
            Some(IndicatorKind::Exfil) if !value.contains('/') && url.contains(value) => {
                if domains.insert(value.to_string()) {
                    out.push((
                        format!("[domain-name:value = '{}']", lit(value)),
                        draft(format!("Callback channel {value}"), rule.to_string()),
                    ));
                }
            }
            Some(IndicatorKind::Exfil) => {
                url_like(&mut out, value, format!("Callback channel {value}"), rule)
            }
            _ => url_like(&mut out, value, format!("Agent marker {value}"), rule),
        }
    }
    // Agent markers that are not linking features (a tag parameter's name
    // and value, a test string).
    if !public || url_shown {
        for h in r
            .hits
            .iter()
            .filter(|h| h.kind == IndicatorKind::AgentMarker)
        {
            let f = LinkFeature::rule(&h.rule_id, &h.matched);
            if public && view.feature(&f) != f.to_string() {
                continue;
            }
            url_like(
                &mut out,
                &h.matched,
                format!("Agent marker {}", h.matched),
                &h.rule_id,
            );
        }
    }
    if !public
        && r.hits.iter().any(|h| ua_rules.contains(h.rule_id.as_str()))
        && let Some(ua) = r.obs.user_agent.as_deref().or_else(|| {
            r.obs
                .headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("user-agent"))
                .map(|(_, v)| v.as_str())
        })
    {
        out.push((
            format!(
                "[network-traffic:extensions.'http-request-ext'.request_header.'User-Agent' = '{}']",
                lit(ua)
            ),
            draft(format!("User agent {ua}"), "user-agent".into()),
        ));
    }
    out
}

/// What a linking feature names, as indicators label it: a run tag or other
/// linking parameter, a callback channel, or an agent marker.
pub(crate) fn feature_kind(f: &LinkFeature, kinds: &BTreeMap<&str, IndicatorKind>) -> &'static str {
    match f {
        LinkFeature::Param { name, .. } if TAG_PARAMS.contains(&name.as_str()) => "Run tag",
        LinkFeature::Param { .. } => "Linking parameter",
        LinkFeature::Rule { rule, .. } => match kinds.get(rule.as_str()) {
            Some(IndicatorKind::Exfil) => "Callback channel",
            _ => "Agent marker",
        },
    }
}

fn draft(name: String, label: String) -> Draft {
    Draft {
        name,
        label,
        tier: Tier::Noise,
        valid_from: i64::MAX,
        clusters: BTreeSet::new(),
    }
}

/// The STIX confidence of an indicator from a cluster at tier `t`.
pub(super) fn confidence(t: Tier) -> u8 {
    match t {
        Tier::Significant => 85,
        Tier::Suggestive => 50,
        Tier::Noise => 15,
    }
}

/// A string literal inside a STIX pattern.
fn lit(s: &str) -> String {
    s.replace('\\', "\\\\").replace('\'', "\\'")
}
