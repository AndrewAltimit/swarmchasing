//! What a provider can search its own logs for, per cluster: the window and
//! what its times measure, the identifiers that linked the cluster, and the
//! captured secrets as their redaction hashes. A provider holding a key it
//! issued finds it by hashing the key, without our ever keeping the key.
//! Case notes and provider reports only.

use super::{Audience, ReportOptions};
use crate::analyze::{Analysis, Cluster};
use crate::extract::defang_feature;
use crate::model::fmt_ts;
use crate::timing::TimeBasis;
use std::collections::BTreeSet;
use std::fmt::Write;

/// At most this many identifiers or secrets per cluster.
const MAX_PER_CLUSTER: usize = 8;

pub(super) fn section(s: &mut String, a: &Analysis, clusters: &[&Cluster], opts: &ReportOptions) {
    if !matches!(opts.audience, Audience::Provider | Audience::Internal) || clusters.is_empty() {
        return;
    }
    let stock = crate::fleets::stock_secrets();
    let mut any_secret = false;
    let mut lines = Vec::new();
    for c in clusters {
        let mut found = BTreeSet::new();
        for &m in &c.members {
            let r = &a.results[m];
            let o = &r.obs;
            let texts = [o.url.as_str(), o.final_url.as_deref().unwrap_or("")];
            let layers = r.layers.iter().map(|l| l.text.as_str());
            let headers = o.headers.values().map(String::as_str);
            for t in texts.into_iter().chain(layers).chain(headers) {
                crate::fleets::redacted_in(t, &mut found);
            }
        }
        let secrets: Vec<&str> = found
            .into_iter()
            .filter(|h| !stock.contains(*h))
            .take(MAX_PER_CLUSTER)
            .collect();
        any_secret |= !secrets.is_empty();
        let mut line = format!(
            "- **{}**: {} to {}, {}",
            c.id,
            fmt_ts(c.start),
            fmt_ts(c.end),
            accuracy(c.time_basis)
        );
        let feats: Vec<String> = c
            .link_features
            .iter()
            .take(MAX_PER_CLUSTER)
            .map(|f| format!("`{}`", defang_feature(&f.to_string())))
            .collect();
        if !feats.is_empty() {
            let _ = write!(line, "\n  - identifiers: {}", feats.join(", "));
        }
        if !secrets.is_empty() {
            let list: Vec<String> = secrets.iter().map(|h| format!("`{h}`")).collect();
            let _ = write!(line, "\n  - captured secrets: {}", list.join(", "));
        }
        lines.push(line);
    }
    let _ = writeln!(s, "## Matching against your logs\n");
    let _ = writeln!(
        s,
        "For each cluster, the window to search, what its times measure, and the strings to look for in your request or response logs. A string here and a time inside the window together are the strongest join we can offer; the network a request came from may be a proxy.\n"
    );
    for l in lines {
        let _ = writeln!(s, "{l}");
    }
    if any_secret {
        let _ = writeln!(
            s,
            "\nA captured secret is listed only as `REDACTED-` and the first 12 hex digits of the SHA-256 of its value. If your platform issued a key or token, the SHA-256 of it as issued starts with those digits when it is the one captured; we keep nothing else about it."
        );
    }
    let _ = writeln!(s);
}

/// What a cluster's times say about when its requests were sent.
fn accuracy(b: TimeBasis) -> &'static str {
    match b {
        TimeBasis::Request => "request times from a server log",
        TimeBasis::Submit => {
            "times a scan service received each URL; the request to the target followed within seconds to minutes"
        }
        TimeBasis::Capture => {
            "archive capture times: when an archive saved each URL, which may be long after it was sent"
        }
        TimeBasis::Mixed => {
            "request or submit times, with archive capture times (which may be long after the request) alongside"
        }
        TimeBasis::Unknown => "times of unknown kind",
    }
}
