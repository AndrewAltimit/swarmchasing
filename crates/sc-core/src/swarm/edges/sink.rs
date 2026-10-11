//! S1 shared sink.

use super::{Ctx, MAX_SHARING, Meta};
use crate::extract::defang_host;
use crate::swarm::runs::differ;
use crate::swarm::{EdgeStrength, SwarmEdge, SwarmEdgeKind};

impl Ctx<'_> {
    /// S1: strands writing one sink that differ in at least two ways.
    pub(super) fn shared_sink(&self, id: &str, g: &[Meta], out: &mut Vec<SwarmEdge>) {
        // (run, strand) → its records writing the sink.
        let mut w: Vec<(usize, usize, Vec<usize>)> = Vec::new();
        for &(ri, si, written, m) in g {
            if !written {
                continue;
            }
            match w.iter_mut().find(|x| x.0 == ri && x.1 == si) {
                Some(x) => x.2.push(m),
                None => {
                    // A one-record strand beside others is too thin to compare.
                    let s = &self.runs[ri].strands[si];
                    if s.label.is_none() || s.members.len() >= 2 {
                        w.push((ri, si, vec![m]));
                    }
                }
            }
        }
        if w.len() < 2 || w.len() > MAX_SHARING {
            return;
        }
        for (i, (ra, sa, xa)) in w.iter().enumerate() {
            for (rb, sb, xb) in &w[i + 1..] {
                let (x, y) = (&self.runs[*ra], &self.runs[*rb]);
                let (fa, fb) = (&x.strands[*sa], &y.strands[*sb]);
                let Some(d) = differ(&fa.fp, &fb.fp).filter(|d| d.len() >= 2) else {
                    continue;
                };
                self.push(
                    out,
                    SwarmEdgeKind::SharedSink,
                    ((x, fa.label.as_ref(), xa), (y, fb.label.as_ref(), xb)),
                    if d.len() >= 3 {
                        EdgeStrength::Moderate
                    } else {
                        EdgeStrength::Weak
                    },
                    None,
                    format!(
                        "both write to `{}`; their requests differ in {}: two agents on one sink, or one agent changing route",
                        defang_host(id),
                        d.join(", ")
                    ),
                );
            }
        }
    }
}
