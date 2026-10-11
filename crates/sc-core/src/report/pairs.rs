//! Hints that tie clusters together (shared pauses, payload dialects,
//! candidate fleets, interaction edges), the common features left unlinked,
//! and the operator clock the date tags imply.

use super::{Audience, Report, touches_exposed};
use crate::analyze::Cluster;
use crate::extract::defang;
use crate::model::{fmt_ts, truncate};
use crate::notice::PublicView;
use std::fmt::Write;

impl Report<'_> {
    fn selected(&self, id: &str) -> bool {
        self.clusters.iter().any(|c| c.id == id)
    }

    /// Whether a hint on the pair `x`, `y` is shown. A pair hint names both
    /// clusters. Outside case notes it appears only when the report covers
    /// both, so a report on one cluster never names another (which may be
    /// someone else's).
    fn pair_shown(&self, x: &str, y: &str) -> bool {
        if self.opts.audience == Audience::Internal {
            self.selected(x) || self.selected(y)
        } else {
            self.selected(x) && self.selected(y)
        }
    }

    /// Everything after the timeline that ties clusters together.
    pub(super) fn ties(&self, s: &mut String, view: Option<&PublicView>) {
        self.pair_hints(s, view);
        self.fleets(s);
        if matches!(self.opts.audience, Audience::Internal | Audience::Provider) {
            crate::swarm::report_block(s, &self.a.swarm_edges, &|x, y| self.pair_shown(x, y));
        }
        self.common_features(s);
        self.date_tags(s);
    }

    /// Clusters that went quiet together, or favour the same payloads.
    fn pair_hints(&self, s: &mut String, view: Option<&PublicView>) {
        let a = self.a;
        for sp in a
            .shared_pauses
            .iter()
            .filter(|sp| self.pair_shown(&sp.a, &sp.b))
        {
            let _ = writeln!(
                s,
                "\n**{}** and **{}** went quiet together: {}. Their records share no identifier; a link to check, not a merge.",
                sp.a, sp.b, sp.reason
            );
        }
        for p in a
            .dialect_pairs
            .iter()
            .filter(|p| self.pair_shown(&p.a, &p.b))
        {
            let pair: Vec<&Cluster> = a
                .clusters
                .iter()
                .filter(|c| c.id == p.a || c.id == p.b)
                .collect();
            let list = if pair.iter().any(|c| touches_exposed(view, c)) {
                String::new()
            } else {
                let shown: Vec<String> = p.shared.iter().map(|v| format!("`{v}`")).collect();
                format!(" ({})", shown.join(", "))
            };
            let _ = writeln!(
                s,
                "\n**{}** and **{}** favour the same canonical test payloads: {} shared variants{list}, Jaccard {:.2}. \
                 Their records share no identifier and these payloads are in every public cheat sheet; a link to check, not a merge.",
                p.a,
                p.b,
                p.shared.len(),
                p.jaccard
            );
        }
    }

    /// Candidate fleets touching the report's clusters: case notes only.
    fn fleets(&self, s: &mut String) {
        let a = self.a;
        let fleets: Vec<&crate::fleets::CandidateFleet> = a
            .candidate_fleets
            .iter()
            .filter(|f| f.clusters.iter().any(|id| self.selected(id)))
            .collect();
        if self.opts.audience != Audience::Internal || fleets.is_empty() {
            return;
        }
        let _ = writeln!(
            s,
            "\n## Candidate fleets\n\nClusters tied by soft links (shared pauses, reruns, recon openings, encoding and the like). Each tie is shared by unrelated clients too: a proposal to check, never a merge.\n"
        );
        for f in fleets {
            let kinds: Vec<&str> = f.kinds.iter().map(|k| k.label()).collect();
            let _ = writeln!(
                s,
                "- **{}**: {} — {} soft link(s): {} (weakest pair {:.2})",
                f.id,
                f.clusters.join(", "),
                f.links,
                kinds.join(", "),
                f.strength
            );
            for l in a
                .soft_links
                .iter()
                .filter(|l| f.clusters.contains(&l.a) && f.clusters.contains(&l.b))
                .take(8)
            {
                let _ = writeln!(
                    s,
                    "  - {} ↔ {}: {} ({:.2}): {}",
                    l.a,
                    l.b,
                    l.kind.label(),
                    l.strength,
                    defang(&truncate(&l.detail, 160))
                );
            }
        }
    }

    /// Features too common to link: case notes only.
    fn common_features(&self, s: &mut String) {
        let a = self.a;
        if self.opts.audience != Audience::Internal || a.common_features.is_empty() {
            return;
        }
        let _ = writeln!(
            s,
            "\nCommon features, not used to link (a popular or copied value, not one operator's):\n"
        );
        for c in a.common_features.iter().take(10) {
            let _ = writeln!(
                s,
                "- `{}`: {} records, {} → {}, {}",
                defang(&truncate(&c.feature.to_string(), 90)),
                c.records,
                fmt_ts(c.start),
                fmt_ts(c.end),
                c.reason
            );
        }
    }

    /// The operator clock the date tags imply, when they agree.
    fn date_tags(&self, s: &mut String) {
        let d = &self.a.date_tags;
        if d.consistent && d.ahead > 0 {
            let _ = writeln!(
                s,
                "\nDate tags in the requests ran ahead of UTC in {} of {} tagged records, consistent with an operator clock between UTC{:+} and UTC{:+}.",
                d.ahead,
                d.tagged,
                d.min_hours.unwrap_or(0.0),
                d.max_hours.unwrap_or(0.0)
            );
        }
    }
}
