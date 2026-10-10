//! Bursts of archive captures: one host captured many times within minutes,
//! when the archives otherwise rarely capture it. Someone, or something,
//! submitted those URLs for capture. A lead for the admin; it scores nothing
//! and links nothing.

use crate::extract::extract;
use crate::model::{Observation, TsKind};
use crate::rules::{Linking, Rules};
use crate::timing::timing;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

const DAY: i64 = 86_400;

/// A cluster of archive captures of one host within minutes, against a host
/// that is otherwise rarely captured.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ArchiveBurst {
    pub host: String,
    pub start: i64,
    pub end: i64,
    pub count: usize,
    pub distinct_urls: usize,
    /// Captures in the burst that matched at least one rule.
    pub flagged: usize,
    /// The host's captures per day across the store, this burst excluded.
    pub baseline_per_day: f64,
}

/// Bursts of archive captures per target host that contain a record in
/// `new_ids`, where the host is normally sparse in `store`. `now` ends the
/// span the baseline is taken over. The thresholds are the `archive_burst_*`
/// settings in the rules' `[linking]`.
pub fn archive_bursts(
    store: &[Observation],
    new_ids: &BTreeSet<String>,
    rules: &Rules,
    now: i64,
) -> Vec<ArchiveBurst> {
    struct Capture<'a> {
        ts: i64,
        id: &'a str,
        url: &'a str,
        flagged: bool,
    }
    let mut by_host: BTreeMap<String, Vec<Capture>> = BTreeMap::new();
    let mut first = i64::MAX;
    for o in store {
        let capture =
            o.ts_kind == TsKind::Capture || TsKind::of_source(&o.source) == TsKind::Capture;
        if !capture || o.ts <= 0 {
            continue;
        }
        let x = extract(o, rules);
        // A capture of a relay or carrier page with no target behind it
        // (`corsproxy.io/`) is the service's own traffic, not a target's.
        let Some(host) = x.target_host else {
            continue;
        };
        first = first.min(o.ts);
        by_host.entry(host).or_default().push(Capture {
            ts: o.ts,
            id: &o.id,
            url: &o.url,
            flagged: x.score > 0,
        });
    }
    let days = ((now - first) as f64 / DAY as f64).max(1.0);
    let l = &rules.set.linking;
    let cfg = Linking {
        burst_gap_secs: l.archive_burst_gap_secs,
        burst_min: l.archive_burst_min,
        ..Default::default()
    };

    let mut out = Vec::new();
    for (host, caps) in &by_host {
        if !caps.iter().any(|c| new_ids.contains(c.id)) {
            continue;
        }
        let ts: Vec<i64> = caps.iter().map(|c| c.ts).collect();
        for b in timing(&ts, &cfg).bursts {
            let inside: Vec<&Capture> = caps
                .iter()
                .filter(|c| c.ts >= b.start && c.ts <= b.end)
                .collect();
            if !inside.iter().any(|c| new_ids.contains(c.id)) {
                continue;
            }
            let baseline = (caps.len() - b.count) as f64 / days;
            if (b.count as f64) < l.archive_burst_ratio * baseline {
                continue;
            }
            out.push(ArchiveBurst {
                host: host.clone(),
                start: b.start,
                end: b.end,
                count: b.count,
                distinct_urls: inside.iter().map(|c| c.url).collect::<BTreeSet<_>>().len(),
                flagged: inside.iter().filter(|c| c.flagged).count(),
                baseline_per_day: baseline,
            });
        }
    }
    crate::sort::by(&mut out, |x, y| {
        y.count.cmp(&x.count).then_with(|| x.start.cmp(&y.start))
    });
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bursts_on_sparse_hosts_only() {
        let rules = Rules::default_rules();
        let now = 1_791_000_000;
        let cap = |id: String, ts: i64, url: &str| Observation {
            id,
            ts,
            ts_kind: TsKind::Capture,
            url: url.into(),
            ..Default::default()
        };
        let mut store = vec![
            cap("old1".into(), now - 50 * DAY, "https://sparse.example/"),
            cap("old2".into(), now - 20 * DAY, "https://sparse.example/"),
        ];
        for i in 0..6 {
            store.push(cap(
                format!("s{i}"),
                now - 3600 + i * 60,
                "https://sparse.example/r",
            ));
        }
        for d in 0..60 {
            for h in 0..24 {
                let ts = now - d * DAY - h * 3600 - 7200;
                store.push(cap(format!("b{d}-{h}"), ts, "https://busy.example/"));
            }
        }
        for i in 0..6 {
            store.push(cap(
                format!("bn{i}"),
                now - 1800 + i * 30,
                "https://busy.example/",
            ));
        }
        let new_ids: BTreeSet<String> = store
            .iter()
            .filter(|o| o.ts > now - 2 * 3600)
            .map(|o| o.id.clone())
            .collect();
        let b = archive_bursts(&store, &new_ids, &rules, now);
        assert_eq!(b.len(), 1, "{b:?}");
        assert_eq!(
            (b[0].host.as_str(), b[0].count, b[0].distinct_urls),
            ("sparse.example", 6, 1)
        );
        assert!(archive_bursts(&store, &BTreeSet::new(), &rules, now).is_empty());
        // Records that are not captures never count.
        let requests: Vec<Observation> = store
            .into_iter()
            .map(|o| Observation {
                ts_kind: TsKind::Request,
                ..o
            })
            .collect();
        assert!(archive_bursts(&requests, &new_ids, &rules, now).is_empty());
    }

    #[test]
    fn a_relay_is_never_the_burst_target() {
        let rules = Rules::default_rules();
        let now = 1_791_000_000;
        let store: Vec<Observation> = (0..12)
            .map(|i| Observation {
                id: format!("c{i}"),
                ts: now - 3600 + i * 30,
                ts_kind: TsKind::Capture,
                // Half the relay's own page, half a target read through it.
                url: if i % 2 == 0 {
                    "https://corsproxy.io/".into()
                } else {
                    format!("https://corsproxy.io/?https://t.example/p{i}")
                },
                ..Default::default()
            })
            .collect();
        let ids: BTreeSet<String> = store.iter().map(|o| o.id.clone()).collect();
        let b = archive_bursts(&store, &ids, &rules, now);
        assert_eq!(b.len(), 1, "{b:?}");
        assert_eq!((b[0].host.as_str(), b[0].count), ("t.example", 6));
    }
}
