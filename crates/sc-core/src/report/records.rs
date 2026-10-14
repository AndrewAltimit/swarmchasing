//! The end of a report: representative records, method and limitations.

use super::Report;
use crate::extract::{clip_defanged, defang_host, defang_hosts};
use crate::model::fmt_ts;
use crate::notice::PublicView;
use std::fmt::Write;

impl Report<'_> {
    /// The strongest records, defanged; a public notice leaves out records
    /// on hosts it does not name and withholds requests it must.
    pub(super) fn records(&self, s: &mut String, mut view: Option<&mut PublicView>) {
        let a = self.a;
        let _ = writeln!(s, "## Representative records\n");
        let _ = writeln!(
            s,
            "URLs are defanged. Records are listed by evidence strength.\n"
        );
        let mut ev: Vec<usize> = self
            .clusters
            .iter()
            .flat_map(|c| c.members.iter().copied())
            .collect();
        crate::sort::by(&mut ev, |&x, &y| {
            a.results[y]
                .score
                .cmp(&a.results[x].score)
                .then(a.results[x].obs.ts.cmp(&a.results[y].obs.ts))
        });
        if let Some(v) = view.as_deref() {
            ev.retain(|&i| {
                a.results[i]
                    .target_host
                    .as_deref()
                    .is_none_or(|h| v.named(h))
            });
        }
        ev.truncate(self.opts.max_evidence);
        for i in ev {
            let r = &a.results[i];
            let rules: Vec<&str> = r.hits.iter().map(|h| h.rule_id.as_str()).collect();
            let url = match view.as_deref_mut() {
                Some(v) => v.record_url(r),
                None => Some(r.obs.url.clone()),
            };
            match &url {
                Some(u) => {
                    let _ = writeln!(
                        s,
                        "1. {}: `{}`",
                        fmt_ts(r.obs.ts),
                        clip_defanged(&defang_hosts(u), 240)
                    );
                }
                None => {
                    let _ = writeln!(
                        s,
                        "1. {}: `{}` (request withheld from the public notice; sent to the affected parties)",
                        fmt_ts(r.obs.ts),
                        defang_host(r.target_host.as_deref().unwrap_or("unknown host"))
                    );
                }
            }
            let _ = writeln!(s, "   - rules: {}", rules.join(", "));
            if r.obs.operator_supplied() {
                let _ = writeln!(
                    s,
                    "   - source: server logs provided by the affected operator"
                );
            }
            if let (Some(rf), Some(_)) = (&r.obs.reference, &url) {
                let _ = writeln!(s, "   - public record: {rf}");
            }
        }
        let _ = writeln!(s);
    }

    /// How the records were collected and linked, and what that cannot show.
    pub(super) fn method(&self, s: &mut String) {
        let _ = writeln!(s, "## Method and limitations\n");
        let _ = writeln!(
            s,
            "- Collected passively from public records (scan services, web archives, certificate logs). We did not open the submitted URLs, interact with the targets, or read or post to any callback channels.\n\
             - Records were linked by shared unique identifiers (inbox IDs, tags), by timing against the same target, and by probe chains (variants of one request to the same host and path, minutes apart). Linking is probabilistic.\n\
             - Model names inside requests are **not** reliable attribution: agents misreport who built them.\n\
             - Network attribution (ASN) identifies the hosting provider, not necessarily the developer of the agent.\n\
             - Public records cover a fraction of activity. Private or account-linked scans are invisible to us."
        );
        if self.a.results.iter().any(|r| r.obs.operator_supplied()) {
            let _ = writeln!(
                s,
                "- Some records come from server logs an affected operator provided after our report. They are not public records and are marked as provided by the operator."
            );
        }
        let _ = writeln!(s);
    }
}
