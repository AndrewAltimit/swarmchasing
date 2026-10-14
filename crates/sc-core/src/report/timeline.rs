//! The timeline: one entry per cluster with its runs and pauses, then a line
//! per hint (probe chains, route escalations, rhythm, links, habits,
//! knowledge, prose, declared testing).

use super::hints::{
    cross_service_line, cut_line, dialect_line, fanout_line, rhythm_line, stale_dates_line,
};
use super::{Audience, Report, basis_note, dur, touches_exposed};
use crate::analyze::Cluster;
use crate::extract::{defang, defang_feature, defang_host};
use crate::model::{fmt_ts, truncate};
use crate::notice::PublicView;
use std::fmt::Write;

impl Report<'_> {
    pub(super) fn timeline(&self, s: &mut String, mut view: Option<&mut PublicView>) {
        let _ = writeln!(s, "## Timeline\n");
        for c in &self.clusters {
            self.cluster_entry(s, c);
            self.chains(s, c, view.as_deref());
            self.escalations(s, c, view.as_deref());
            if let Some(line) = rhythm_line(&c.timing.rhythm) {
                let _ = writeln!(s, "  - {line}{}", basis_note(c));
            }
            if let Some(line) = stale_dates_line(&c.timing.stale_dates) {
                let _ = writeln!(s, "  - {line}");
            }
            link_features(s, c, view.as_deref_mut());
            // Provenance and corroboration (crate::plant): case notes and providers.
            if matches!(self.opts.audience, Audience::Internal | Audience::Provider)
                && let Some(line) = crate::plant::provenance_line(c)
            {
                let _ = writeln!(s, "  - {line}");
            }
            // Scope (FM chapter 15): internal and provider reports only.
            if matches!(self.opts.audience, Audience::Internal | Audience::Provider) {
                scope_line(s, c);
            }
            // Cross-service fan-out names the scan services: internal and
            // provider reports only.
            if matches!(self.opts.audience, Audience::Internal | Audience::Provider)
                && let Some(line) = cross_service_line(&c.cross_service)
            {
                let _ = writeln!(s, "  - {line}");
            }
            habits(s, c, view.as_deref());
            knowledge(s, c);
            prose(s, c);
            // A named contact is for the admin to check, not for a recipient.
            if self.opts.audience == Audience::Internal {
                declared(s, c);
                shared_inventions(s, c);
            }
        }
    }

    /// The cluster's line, its longest pauses and its build artifacts.
    fn cluster_entry(&self, s: &mut String, c: &Cluster) {
        let med = c
            .timing
            .median_gap_secs
            .map(|g| format!(", median gap {}", dur(g as i64)))
            .unwrap_or_default();
        let _ = writeln!(
            s,
            "- **{}** ({}): {} records, {} run(s), {} → {}{med}",
            c.id,
            c.tier.label(),
            c.members.len(),
            c.runs.len(),
            fmt_ts(c.start),
            fmt_ts(c.end)
        );
        for p in c.timing.pauses.iter().take(3) {
            let _ = writeln!(
                s,
                "  - pause {} → {} ({})",
                fmt_ts(p.start),
                fmt_ts(p.end),
                dur(p.end - p.start)
            );
        }
        if c.artifacts > 0 && matches!(self.opts.audience, Audience::Internal | Audience::Provider)
        {
            let _ = writeln!(
                s,
                "  - artifacts: {} of {} records carry a trace of how the agent was built (model-output residue, run tags, self-identification, client headers)",
                c.artifacts,
                c.members.len()
            );
        }
    }

    /// Probe chains touching the cluster, except on hosts a public notice
    /// withholds.
    fn chains(&self, s: &mut String, c: &Cluster, view: Option<&PublicView>) {
        for ch in self
            .a
            .chains
            .iter()
            .filter(|ch| ch.members.iter().any(|m| c.members.contains(m)))
        {
            if view.is_some_and(|v| v.exposed(&ch.host) || !v.named(&ch.host)) {
                continue;
            }
            let varied: Vec<String> = ch.varied.iter().map(|p| format!("`{p}`")).collect();
            let unflagged = ch.members.len() - ch.flagged;
            let retries = match ch.retries_after_error {
                0 => String::new(),
                1 => "; 1 variant followed an error response".into(),
                n => format!("; {n} variants followed an error response"),
            };
            let _ = writeln!(
                s,
                "  - iterative probing: {} variants of {} on `{}{}` over {} (median gap {}, {}){}{retries}",
                ch.variants,
                varied.join(", "),
                defang_host(&ch.host),
                truncate(&ch.path, 60),
                dur(ch.end - ch.start),
                dur(ch.median_gap_secs),
                ch.pace.describe(ch.time_basis),
                if unflagged > 0 {
                    format!("; {unflagged} of its requests matched no rule")
                } else {
                    String::new()
                }
            );
        }
    }

    /// Route escalations touching the cluster, except on hosts a public
    /// notice withholds.
    fn escalations(&self, s: &mut String, c: &Cluster, view: Option<&PublicView>) {
        for e in self
            .a
            .escalations
            .iter()
            .filter(|e| e.clusters.contains(&c.id))
        {
            if view.is_some_and(|v| v.exposed(&e.host) || !v.named(&e.host)) {
                continue;
            }
            let basis = e
                .time_basis
                .note()
                .map(|n| format!("; {n}"))
                .unwrap_or_default();
            let _ = writeln!(
                s,
                "  - route escalation on `{}{}`: {} over {}{basis}. One client changing route to reach a page is consistent with an agent working around a failure; two people reading it by different routes look the same (a hint, not evidence)",
                defang_host(&e.host),
                truncate(&e.path, 60),
                e.route_line(),
                dur(e.end - e.start)
            );
        }
    }
}

/// The cluster's scope finding and the FM-15.3 tests that failed, with the
/// records each rests on. Internal and provider reports only.
fn scope_line(s: &mut String, c: &Cluster) {
    let sc = &c.scope;
    if sc.is_default() {
        return;
    }
    let failed: Vec<String> = sc
        .tests
        .iter()
        .filter(|t| t.outcome == crate::scope::ScopeOutcome::Fail)
        .map(|t| format!("{} ({})", t.id, t.detail))
        .collect();
    let tail = if failed.is_empty() {
        String::new()
    } else {
        format!("; failed: {}", failed.join("; "))
    };
    let _ = writeln!(
        s,
        "  - scope: {} · task class {}{tail}",
        sc.finding.label(),
        sc.task_class.label()
    );
}

/// The features that joined the cluster, as a public notice may show them.
fn link_features(s: &mut String, c: &Cluster, mut view: Option<&mut PublicView>) {
    if c.link_features.is_empty() {
        return;
    }
    let shown: Vec<String> = c
        .link_features
        .iter()
        .take(5)
        .map(|f| match view.as_deref_mut() {
            Some(v) => v.feature(f),
            None => f.to_string(),
        })
        .map(|f| format!("`{}`", defang_feature(&truncate(&f, 90))))
        .collect();
    let _ = writeln!(s, "  - linked by: {}", shown.join(", "));
}

/// One client's habits: URL encoding, recon openings, path sets, invented
/// identifiers, payload dialect, fan-out, cut lengths, relay stacks.
fn habits(s: &mut String, c: &Cluster, view: Option<&PublicView>) {
    if let [(style, &n)] = c.encodings.iter().collect::<Vec<_>>()[..]
        && n == c.members.len()
        && n > 1
    {
        let _ = writeln!(
            s,
            "  - all {n} records share one URL encoding style (`{style}`): consistent with one client, not evidence on its own"
        );
    }
    for p in &c.paths.preambles {
        let _ = writeln!(
            s,
            "  - {} hosts opened with the same recon requests (`{}`): consistent with one client, not evidence on its own",
            p.hosts,
            p.paths.join(" → ")
        );
    }
    for set in &c.paths.shared_unusual_sets {
        let nf = if set.not_found > 0 {
            format!("; {} of those requests got 404/410", set.not_found)
        } else {
            String::new()
        };
        let shown: Vec<String> = set
            .paths
            .iter()
            .take(8)
            .map(|p| format!("`{}`", defang(&truncate(p, 60))))
            .collect();
        let _ = writeln!(
            s,
            "  - {} hosts were asked for the same unusual path set ({}){nf}",
            set.hosts,
            shown.join(", ")
        );
    }
    if c.paths.fabricated_ids > 0 {
        let _ = writeln!(
            s,
            "  - {} records carry identifiers no generator produces (patterned or invalid UUIDs, hand-typed hashes), consistent with invented placeholders",
            c.paths.fabricated_ids
        );
    }
    // Payload details stay out of a public notice for compromised endpoints.
    if !touches_exposed(view, c)
        && let Some(line) = dialect_line(&c.dialect)
    {
        let _ = writeln!(s, "  - {line}");
    }
    if let Some(line) = fanout_line(&c.fanout) {
        let _ = writeln!(s, "  - {line}{}", basis_note(c));
    }
    if let Some(line) = cut_line(&c.cut_lengths) {
        let _ = writeln!(s, "  - {line}");
    }
    for (st, n) in c
        .relay_stacks
        .iter()
        .filter(|(st, _)| st.matches(" → ").count() >= 2)
    {
        let _ = writeln!(
            s,
            "  - relay stack `{st}` on {n} records: one client's habit, not evidence on its own"
        );
    }
}

/// Benchmark targets and stale knowledge.
fn knowledge(s: &mut String, c: &Cluster) {
    let k = &c.knowledge;
    if !k.benchmarks.is_empty() {
        let shown: Vec<String> = k
            .benchmarks
            .iter()
            .map(|(id, n)| format!("`{id}` ×{n}"))
            .collect();
        let _ = writeln!(
            s,
            "  - benchmark or practice targets: {}. Evaluation or training activity is likely, not malice (a hint)",
            shown.join(", ")
        );
    }
    for u in &k.stale_knowledge {
        let _ = writeln!(
            s,
            "  - stale knowledge `{}` on {} records, {} hosts ({}): consistent with a model writing from old training data; old scripts do the same (a hint)",
            u.id, u.records, u.hosts, u.note
        );
    }
}

/// Prose in parameter values and its languages.
fn prose(s: &mut String, c: &Cluster) {
    if c.prose.is_empty() {
        return;
    }
    let langs: Vec<String> = c
        .prose
        .languages
        .iter()
        .map(|(l, n)| format!("{l} ×{n}"))
        .collect();
    let off = match c.prose.mismatched {
        0 => String::new(),
        n => format!(
            "; {n} in a language other than their target's country domain, as an agent working from a prompt in its own language writes"
        ),
    };
    let _ = writeln!(
        s,
        "  - prose in parameters: {} values ({}){off} (a hint, not evidence)",
        c.prose.values,
        if langs.is_empty() {
            "language unclear".to_string()
        } else {
            langs.join(", ")
        }
    );
}

/// Members declaring testing, with the contact they name.
fn declared(s: &mut String, c: &Cluster) {
    for d in &c.declared {
        let contact = d
            .contact
            .as_ref()
            .map(|x| format!(", contact `{x}`"))
            .unwrap_or_default();
        let _ = writeln!(
            s,
            "  - declares testing on {} records: `{}`{contact}. Check it with its owner before treating the cluster as authorised; anyone can write this",
            d.records,
            defang(&d.text)
        );
    }
}

/// Fabricated values other clusters carry too: case notes only. A model
/// family's habit, never a tie between operators.
fn shared_inventions(s: &mut String, c: &Cluster) {
    if c.paths.shared_invention.is_empty() {
        return;
    }
    let shown: Vec<String> = c
        .paths
        .shared_invention
        .iter()
        .map(|x| format!("`{}` ({} clusters)", truncate(&x.value, 64), x.clusters))
        .collect();
    let _ = writeln!(
        s,
        "  - shared invention: the same fabricated identifier in other clusters, {}: one model family's habit, not an operator link",
        shown.join(", ")
    );
}
