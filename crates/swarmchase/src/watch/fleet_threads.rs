//! The digest's fleet threads: candidate fleets by their key across runs,
//! and pairs of threads whose soft links add up over windows
//! ([`super::ledger::Ledger::observe_fleets`]).
//!
//! Descriptive, like the candidate fleets section: thread keys, link kinds
//! and numbers only, no host or value. It never makes a run count as
//! changed.

use super::ledger::{FleetsObserved, Ledger};
use sc_core::Analysis;
use sc_core::fleet_track::{ALPHA, HALF_LIFE_SECS, bound};
use std::fmt::Write;

/// Lines each list shows.
const LINES: usize = 10;

/// A thread by its current cluster when it has one (`C3 k-3f9a2c1b`).
fn thread_ref(a: &Analysis, l: &Ledger, id: &str) -> String {
    let key = l.threads.get(id).map_or(id, |th| th.key.as_str());
    match a.clusters.iter().find(|c| c.key == key) {
        Some(c) => format!("{} {key}", c.id),
        None => key.to_string(),
    }
}

/// The `## Fleet threads` section.
pub fn section(a: &Analysis, l: &Ledger, fo: &FleetsObserved) -> String {
    let mut t = String::new();
    let _ = writeln!(t, "\n## Fleet threads ({})\n", fo.keys.len());
    if fo.keys.is_empty() {
        let _ = writeln!(t, "No candidate fleet this run.");
    }
    for (fid, key) in fo.keys.iter().take(LINES) {
        let Some(f) = l.fleets.get(key) else {
            continue;
        };
        let members: Vec<String> = f.members.iter().map(|m| thread_ref(a, l, m)).collect();
        let since = if fo.new.contains(key) {
            "new".to_string()
        } else {
            format!("{} runs since {}", f.runs, f.first_run)
        };
        let _ = writeln!(
            t,
            "- {key} ({fid}, {since}): {}; weakest edge ratio {:.0}, density {:.2}",
            members.join(", "),
            f.min_lr,
            f.density
        );
    }
    if fo.keys.len() > LINES {
        let _ = writeln!(t, "- … {} more", fo.keys.len() - LINES);
    }
    let _ = writeln!(
        t,
        "\n### Persistent pairs ({})\n\nPairs of threads whose soft links add up across windows that do not overlap (log ratio {:.1} or more, halving every {} days), held together by no candidate fleet now. Proposals only.\n",
        fo.persistent.len(),
        bound(ALPHA),
        HALF_LIFE_SECS / 86_400
    );
    if fo.persistent.is_empty() {
        let _ = writeln!(t, "None.");
    }
    for p in fo.persistent.iter().take(LINES) {
        let _ = writeln!(
            t,
            "- {} ↔ {}: log ratio {:.1} over {} window(s), linked on {} run(s): {}",
            thread_ref(a, l, &p.a),
            thread_ref(a, l, &p.b),
            p.total(),
            p.independent,
            p.seen,
            p.kinds.join(", ")
        );
    }
    if fo.persistent.len() > LINES {
        let _ = writeln!(t, "- … {} more", fo.persistent.len() - LINES);
    }
    t
}
