//! The landing page: the mission, a run timeline drawn from the synthetic
//! example, the latest notices, and where to go next.

use super::html::{esc, pill, table};
use super::svg::{Lane, swimlanes};
use crate::file::NoticeFile;
use sc_core::Analysis;
use std::fmt::Write;

/// The example's clusters as swim-lanes, strongest first, and the run table.
fn timeline(a: &Analysis) -> (String, String) {
    let lanes: Vec<Lane> = a
        .clusters
        .iter()
        .filter(|c| c.runs.iter().any(|r| r.start > 0))
        .take(8)
        .map(|c| Lane {
            label: c.id.clone(),
            tier: c.tier.label().to_string(),
            runs: c
                .runs
                .iter()
                .filter(|r| r.start > 0)
                .map(|r| (r.start, r.end, r.count))
                .collect(),
        })
        .collect();
    let pauses: Vec<(i64, i64)> = a.timing.pauses.iter().map(|p| (p.start, p.end)).collect();
    let svg = swimlanes(
        &lanes,
        &pauses,
        "Synthetic example: runs of each linked cluster over time, UTC",
    );
    let rows: Vec<Vec<String>> = lanes
        .iter()
        .flat_map(|l| {
            l.runs.iter().map(move |r| {
                vec![
                    esc(&l.label),
                    pill(&l.tier),
                    esc(&sc_core::fmt_ts(r.0)),
                    esc(&sc_core::fmt_ts(r.1)),
                    r.2.to_string(),
                ]
            })
        })
        .collect();
    (
        svg,
        table(
            "",
            &["Cluster", "Tier", "Run start", "Run end", "Records"],
            &rows,
        ),
    )
}

pub fn body(example: &Analysis, notices: &[NoticeFile]) -> String {
    let (svg, runs) = timeline(example);
    let mut s = String::new();
    s.push_str(
        "<section class=\"hero\" aria-labelledby=\"mission\"><h1 id=\"mission\">Swarmchasing</h1>\
<p class=\"mission\">Swarmchasing finds misaligned AI agent swarms in public records (URL scanners, web archives, certificate logs) and links their requests into runs and fleets. Each confirmed incident is reported to the AI provider responsible and to the affected operators, and a public notice goes out at the same time.</p>\
<p class=\"ctas\"><a class=\"button primary\" href=\"notices/\">Read the notices</a> <a class=\"button\" href=\"operators/\">Check your own logs</a> <a class=\"button\" href=\"analyze/\">Open the workbench</a> <a class=\"button ghost\" href=\"methodology/\">How it works</a></p></section>\n",
    );
    let _ = writeln!(
        s,
        "<section class=\"card\" aria-labelledby=\"looks\"><h2 id=\"looks\">What a swarm looks like</h2>\
<p class=\"hint\"><strong>Synthetic example.</strong> These records were written to exercise the rules and were never collected; the hosts are placeholders. Each lane is a cluster of linked records and each bar one run of activity; shaded bands are pauses across the whole input.</p>\
<p class=\"legend\"><span><span class=\"key k-sig\"></span>significant</span> <span><span class=\"key k-sug\"></span>suggestive</span> <span><span class=\"key k-pause\"></span>pause</span></p><figure class=\"chart-box scroll-x\">{svg}<figcaption>{} records, {} flagged, {} clusters. <a href=\"analyze/#try=example\">Open this example in the workbench</a>.</figcaption></figure>\
<details class=\"as-table\"><summary>View as table</summary>{runs}</details></section>",
        example.total,
        example.flagged,
        example.clusters.len(),
    );
    s.push_str("<section aria-labelledby=\"latest\"><h2 id=\"latest\">Latest notices</h2>");
    if notices.is_empty() {
        s.push_str(
            "<div class=\"card empty\"><p><strong>No notices yet.</strong> A notice is published only when reports go to the AI provider and the affected operators, after a lead has been reviewed and linked into a case. Unreviewed leads never appear here.</p>\
<p><a href=\"notices/feed.xml\">Subscribe to the Atom feed</a> to hear about the first one.</p></div>",
        );
    } else {
        s.push_str("<ul class=\"notice-cards\">");
        for n in notices.iter().take(5) {
            let m = &n.meta;
            let _ = write!(
                s,
                "<li class=\"card\"><a href=\"notices/{}/\"><strong>{}</strong></a><p class=\"meta\">{} updated {}</p></li>",
                esc(&m.id),
                esc(&m.title),
                pill(m.status.label()),
                esc(&m.updated)
            );
        }
        s.push_str("</ul><p><a href=\"notices/\">All notices</a> · <a href=\"notices/feed.xml\">Atom feed</a></p>");
    }
    s.push_str("</section>\n");
    s.push_str(
        "<section aria-labelledby=\"how\"><h2 id=\"how\">How it works</h2><ol class=\"steps-list\">\
<li><strong>Unwrap</strong> each URL through relays, carriers, <code>data:</code> programs and base64 to the real target.</li>\
<li><strong>Match</strong> the <a href=\"rules/\">indicator rules</a> and grade each record: significant, suggestive or noise. A single relay hit is never enough.</li>\
<li><strong>Link</strong> records into clusters by shared inbox IDs and tags, close timing against one target, and probe chains; time each cluster's runs and pauses.</li>\
<li><strong>Report</strong> to the AI provider and the affected operators, and publish the notice at the same time.</li></ol>\
<p>Ground rules: collection is passive (no URL an agent submitted is ever opened), model names in requests are weak evidence, and a developer is named only when the evidence reaches the naming threshold. Details: <a href=\"methodology/\">methodology</a>, <a href=\"docs/policies/\">policies</a>.</p></section>\n",
    );
    s
}
