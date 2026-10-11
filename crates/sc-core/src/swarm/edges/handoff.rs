//! S2 hand-off.

use super::{Ctx, MAX_SHARING, Meta};
use crate::extract::defang_host;
use crate::swarm::runs::differ;
use crate::swarm::{EdgeStrength, SwarmEdge, SwarmEdgeKind};

/// A fetch this soon after the write makes a strong hand-off (S2).
const QUICK_HANDOFF_SECS: i64 = 3600;

impl Ctx<'_> {
    /// S2: an artifact written by one run and fetched later by another.
    pub(super) fn handoff(&self, id: &str, g: &[Meta], out: &mut Vec<SwarmEdge>) {
        // The earliest record of each (run, written).
        let ts = |m: usize| self.res[m].obs.ts;
        let mut first: Vec<(usize, bool, usize)> = Vec::new();
        for &(ri, _, w, m) in g {
            match first.iter_mut().find(|x| x.0 == ri && x.1 == w) {
                Some(x) => {
                    if ts(m) < ts(x.2) {
                        x.2 = m;
                    }
                }
                None => first.push((ri, w, m)),
            }
        }
        if first.len() > MAX_SHARING {
            return;
        }
        for &(wa, written, wm) in &first {
            for &(rb, read, rm) in &first {
                let (x, y) = (&self.runs[wa], &self.runs[rb]);
                let gap = ts(rm) - ts(wm);
                if !written || read || wa == rb || gap <= 0 {
                    continue;
                }
                let d = differ(&x.fp, &y.fp).unwrap_or_default();
                if x.ci == y.ci && d.is_empty() {
                    continue;
                }
                let differs = if d.is_empty() {
                    String::new()
                } else {
                    format!("; they differ in {}", d.join(", "))
                };
                self.push(
                    out,
                    SwarmEdgeKind::Handoff,
                    ((x, None, &[wm]), (y, None, &[rm])),
                    if gap <= QUICK_HANDOFF_SECS && !d.is_empty() {
                        EdgeStrength::Strong
                    } else {
                        EdgeStrength::Moderate
                    },
                    None,
                    format!(
                        "`{}` written by the first and fetched by the second {} min later{differs}",
                        defang_host(id),
                        gap / 60
                    ),
                );
            }
        }
    }
}
