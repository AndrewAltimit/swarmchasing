//! What earlier runs tell [`super::detect_with`]: how long each platform was
//! read, the burst chances of the groups weighed before, and the families
//! (name templates, text templates) seen bursting before.
//!
//! A run reads a stretch of each platform's stream, often minutes of a
//! firehose. A burst is only weighed over time actually read, and only once
//! the platform has been read for [`MIN_READ_SECS`]. On a busy platform
//! fresh stories draw templated reposts in bursts all day; the model's burst
//! chance is never taken below the share of earlier groups on the platform
//! that burst as tightly. A family that burst in an earlier window and bursts
//! again (a vendor's release train, a weather office's scheduled posts) is
//! not a fresh burst.

use super::{Platform, PlatformEvent};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Read time a platform needs, within the carry window, before a burst is
/// weighed: in a shorter stretch a burst cannot be told from steady posting.
pub const MIN_READ_SECS: i64 = 3600;
/// Groups weighed in earlier runs a platform needs before their bursts set a
/// floor under the model's chance.
pub const MIN_EARLIER: usize = 50;
/// Earlier burst chances kept per platform, the newest.
pub const MAX_EARLIER: usize = 2000;
/// Family keys recorded per group.
const MAX_KEYS: usize = 64;

/// What earlier runs saw, kept by the watch in `platform/baseline.json`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Baseline {
    /// Per platform ([`Platform::name`]): the stretches read, as
    /// non-overlapping `(from, to)` Unix seconds in order.
    #[serde(default)]
    pub read: BTreeMap<String, Vec<(i64, i64)>>,
    /// Per platform: each group weighed, by candidate id, with its model
    /// burst chance.
    #[serde(default)]
    pub bursts: BTreeMap<String, BTreeMap<String, Earlier>>,
    /// Family keys ([`family_key`]) of the members in a burst, with the
    /// latest burst window they were seen in.
    #[serde(default)]
    pub families: BTreeMap<String, Sighting>,
}

/// One earlier group's burst chance.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Earlier {
    pub p: f64,
    /// When it was weighed (Unix seconds).
    pub ts: i64,
}

/// The latest burst window a family key was seen in.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Sighting {
    pub start: i64,
    pub end: i64,
    /// When it was recorded (Unix seconds).
    pub ts: i64,
}

/// A group weighed in this run, for [`Baseline::record`].
#[derive(Debug, Clone, PartialEq)]
pub struct Weighed {
    pub platform: Platform,
    pub id: String,
    /// The model's burst chance over the time read, before any floor.
    pub model_chance: f64,
    /// The densest window.
    pub window: (i64, i64),
    /// Family keys of the members in the densest window; empty unless the
    /// model's burst chance is at most the reporting limit.
    pub keys: Vec<String>,
}

/// The family an event belongs to across runs: its created item's name
/// template, else its text template. Text-less events have none: a repository
/// that drew a burst of stars before is no release train.
pub fn family_key(e: &PlatformEvent, min_words: u32) -> Option<String> {
    let p = e.platform.name();
    if let Some(nt) = e.name_template.as_deref().filter(|_| e.action.creates()) {
        return Some(format!("{p}:name:{}:{nt}", e.action.label()));
    }
    e.text
        .as_ref()
        .filter(|t| t.words >= min_words)
        .map(|t| format!("{p}:text:{:016x}", t.skeleton))
}

impl Baseline {
    /// Note that `platform` was read from `from` to `to`.
    pub fn add_read(&mut self, platform: Platform, from: i64, to: i64) {
        if to < from {
            return;
        }
        let v = self.read.entry(platform.name().to_string()).or_default();
        v.push((from, to));
        v.sort_unstable();
        let mut out: Vec<(i64, i64)> = Vec::with_capacity(v.len());
        for &(a, b) in v.iter() {
            match out.last_mut() {
                Some(last) if a <= last.1 => last.1 = last.1.max(b),
                _ => out.push((a, b)),
            }
        }
        *v = out;
    }

    /// Seconds of `platform` read, or `None` when no stretch is recorded.
    pub fn read_secs(&self, platform: Platform) -> Option<i64> {
        let v = self.read.get(platform.name()).filter(|v| !v.is_empty())?;
        Some(v.iter().map(|(a, b)| b - a).sum())
    }

    /// Whether `ts` falls in a stretch of `platform` read.
    pub fn was_read(&self, platform: Platform, ts: i64) -> bool {
        self.read
            .get(platform.name())
            .is_some_and(|v| v.iter().any(|&(a, b)| a <= ts && ts <= b))
    }

    /// Of the groups weighed on `platform` in earlier runs (`id` left out),
    /// how many had a model burst chance at most `p`, and how many there
    /// were; `None` under [`MIN_EARLIER`].
    pub fn earlier_share(&self, platform: Platform, id: &str, p: f64) -> Option<(usize, usize)> {
        let m = self.bursts.get(platform.name())?;
        let others = m.iter().filter(|(k, _)| k.as_str() != id);
        let (mut k, mut n) = (0, 0);
        for (_, e) in others {
            n += 1;
            k += usize::from(e.p <= p);
        }
        (n >= MIN_EARLIER).then_some((k, n))
    }

    /// Whether family `key` burst in a window that ended before `start`.
    pub fn burst_before(&self, key: &str, start: i64) -> bool {
        self.families.get(key).is_some_and(|s| s.end < start)
    }

    /// Record this run's weighed groups, at `now`.
    pub fn record(&mut self, weighed: &[Weighed], now: i64) {
        for w in weighed {
            self.bursts
                .entry(w.platform.name().to_string())
                .or_default()
                .insert(
                    w.id.clone(),
                    Earlier {
                        p: w.model_chance,
                        ts: now,
                    },
                );
            for k in w.keys.iter().take(MAX_KEYS) {
                let s = self.families.entry(k.clone()).or_insert(Sighting {
                    start: w.window.0,
                    end: w.window.1,
                    ts: now,
                });
                if w.window.1 >= s.end {
                    *s = Sighting {
                        start: w.window.0,
                        end: w.window.1,
                        ts: now,
                    };
                }
            }
        }
    }

    /// Drop stretches read and groups weighed before `read_from`, families
    /// recorded before `family_from`, and all but the newest
    /// [`MAX_EARLIER`] groups per platform.
    pub fn prune(&mut self, read_from: i64, family_from: i64) {
        for v in self.read.values_mut() {
            v.retain(|&(_, b)| b >= read_from);
            for r in v.iter_mut() {
                r.0 = r.0.max(read_from);
            }
        }
        self.read.retain(|_, v| !v.is_empty());
        for m in self.bursts.values_mut() {
            m.retain(|_, e| e.ts >= read_from);
            if m.len() > MAX_EARLIER {
                let mut by_age: Vec<(i64, String)> =
                    m.iter().map(|(k, e)| (e.ts, k.clone())).collect();
                by_age.sort_unstable_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
                for (_, k) in by_age.into_iter().skip(MAX_EARLIER) {
                    m.remove(&k);
                }
            }
        }
        self.bursts.retain(|_, m| !m.is_empty());
        self.families.retain(|_, s| s.ts >= family_from);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_stretches_merge_and_prune() {
        let mut b = Baseline::default();
        b.add_read(Platform::Bluesky, 100, 200);
        b.add_read(Platform::Bluesky, 150, 300);
        b.add_read(Platform::Bluesky, 1000, 1100);
        assert_eq!(b.read_secs(Platform::Bluesky), Some(300));
        assert!(b.was_read(Platform::Bluesky, 250));
        assert!(!b.was_read(Platform::Bluesky, 500));
        assert_eq!(b.read_secs(Platform::Github), None);
        b.prune(250, 0);
        assert_eq!(b.read["bluesky"], [(250, 300), (1000, 1100)]);
    }

    #[test]
    fn earlier_bursts_need_enough_groups_and_leave_the_group_out() {
        let mut b = Baseline::default();
        let w = |i: usize, p: f64| Weighed {
            platform: Platform::Bluesky,
            id: format!("PS-{i}"),
            model_chance: p,
            window: (0, 900),
            keys: vec![],
        };
        let some: Vec<Weighed> = (0..10).map(|i| w(i, 1e-4)).collect();
        b.record(&some, 10);
        assert_eq!(b.earlier_share(Platform::Bluesky, "PS-x", 1e-3), None);
        let more: Vec<Weighed> = (10..60).map(|i| w(i, 0.5)).collect();
        b.record(&more, 10);
        assert_eq!(
            b.earlier_share(Platform::Bluesky, "PS-x", 1e-3),
            Some((10, 60))
        );
        assert_eq!(
            b.earlier_share(Platform::Bluesky, "PS-0", 1e-3),
            Some((9, 59))
        );
        // Bounded per platform, newest kept.
        let many: Vec<Weighed> = (0..MAX_EARLIER + 5).map(|i| w(1000 + i, 0.5)).collect();
        b.record(&many, 20);
        b.prune(0, 0);
        assert_eq!(b.bursts["bluesky"].len(), MAX_EARLIER);
        assert!(b.bursts["bluesky"].values().all(|e| e.ts == 20));
    }

    #[test]
    fn a_family_burst_before_a_later_window_only() {
        let mut b = Baseline::default();
        b.record(
            &[Weighed {
                platform: Platform::Nuget,
                id: "PS-1".into(),
                model_chance: 1e-9,
                window: (1000, 1900),
                keys: vec!["nuget:name:packages published:vendorsdk-<id>".into()],
            }],
            2000,
        );
        let k = "nuget:name:packages published:vendorsdk-<id>";
        assert!(!b.burst_before(k, 1000), "the same window is not earlier");
        assert!(b.burst_before(k, 90_000));
        assert!(!b.burst_before("nuget:name:packages published:other-<id>", 90_000));
        b.prune(0, 2001);
        assert!(b.families.is_empty());
    }
}
