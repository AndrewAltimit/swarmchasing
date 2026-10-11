//! Small helpers the commands share: output, text, and the urlquery key.

use anyhow::{Context, Result};
use sc_core::{Analysis, Tier, fmt_ts};
use std::collections::BTreeMap;
use std::path::Path;

/// Environment variable holding the urlquery.net API key (same name as urlquery-cli).
pub const URLQUERY_KEY_ENV: &str = "URLQUERY_APIKEY";

/// The urlquery API key, if one is set.
pub fn urlquery_key() -> Option<String> {
    std::env::var(URLQUERY_KEY_ENV)
        .ok()
        .map(|k| k.trim().to_string())
        .filter(|k| !k.is_empty())
}

/// The urlquery API key, or an error saying how to set it.
pub fn require_urlquery_key() -> Result<String> {
    urlquery_key().with_context(|| format!("set {URLQUERY_KEY_ENV} to a urlquery.net API key"))
}

pub use sc_case::text::{audience_id, one_line, truncate};

/// Today's date (UTC), `yyyy-mm-dd`.
pub fn today() -> String {
    chrono::Utc::now().format("%Y-%m-%d").to_string()
}

pub fn print_summary(a: &Analysis) {
    let t = |x| a.tier_counts.get(&x).copied().unwrap_or(0);
    println!(
        "{} records · {} flagged · {} significant · {} suggestive · {} clusters (max {} concurrent runs)",
        a.total,
        a.flagged,
        t(Tier::Significant),
        t(Tier::Suggestive),
        a.clusters.len(),
        a.max_concurrent_clusters
    );
    if a.timing.count > 0 {
        println!(
            "window {} → {}",
            fmt_ts(a.timing.start),
            fmt_ts(a.timing.end)
        );
    }
    if a.date_tags.consistent && a.date_tags.ahead > 0 {
        println!(
            "date tags ahead of UTC in {}/{} records → operator clock UTC{:+}..UTC{:+}",
            a.date_tags.ahead,
            a.date_tags.tagged,
            a.date_tags.min_hours.unwrap_or(0.0),
            a.date_tags.max_hours.unwrap_or(0.0)
        );
    }
    for s in a.asns.iter().take(5) {
        println!(
            "AS{} {}: {} flagged",
            s.asn,
            s.org.as_deref().unwrap_or("(unknown)"),
            s.count
        );
    }
}

/// The `n` most frequent keys, as `key×count`.
pub fn top_counted<K: ToString>(m: &BTreeMap<K, usize>, n: usize) -> Vec<String> {
    sc_core::top_counts(m, n)
        .into_iter()
        .map(|(k, c)| format!("{k}×{c}"))
        .collect()
}

/// The `n` most frequent keys.
pub fn top_keys<K: ToString>(m: &BTreeMap<K, usize>, n: usize) -> Vec<String> {
    sc_core::top_counts(m, n)
        .into_iter()
        .map(|(k, _)| k)
        .collect()
}

/// Write `text` to `path` (creating its directory), or print it.
pub fn write_out(path: Option<&Path>, text: &str) -> Result<()> {
    match path {
        Some(p) => {
            if let Some(dir) = p.parent().filter(|d| !d.as_os_str().is_empty()) {
                std::fs::create_dir_all(dir)?;
            }
            std::fs::write(p, text).with_context(|| format!("writing {}", p.display()))?;
            eprintln!("wrote {}", p.display());
        }
        None => print!("{text}"),
    }
    Ok(())
}
