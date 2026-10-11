//! The landing page: the mission, then the method walked through one
//! synthetic incident (the showcase set), step by step, each step with a
//! figure drawn here so the page needs no script; then the latest notices,
//! or an example notice from the same records until there is a real one.
//!
//! Only the showcase is drawn, and only what a public page may carry:
//! plant signals and declared-testing contacts never appear here.

use super::html::{esc, pill, table};
use super::svg::{Lane, swimlanes};
use super::walk::{
    GEdge, GNode, LadderCol, RunEdge, RunNode, UrlLayer, cluster_graph, disclosure_flow, ladder,
    layer_bands, layer_stack, score_bar, swarm_arcs,
};
use crate::file::NoticeFile;
use crate::markdown::md_blocks;
use sc_core::{AgentLevel, Analysis, Cluster, ObsResult, Rules, Tier};
use std::collections::BTreeMap;
use std::fmt::Write;

/// Where each Field Manual section is published, by id (`FM-4.1` →
/// `docs/manual/04-indicators/#fm-41-grading-records`), relative to the
/// site root.
pub type FmLinks = BTreeMap<String, String>;

/// The date the example notice is stamped with: fixed, so a rebuild of the
/// same inputs gives the same page.
const EXAMPLE_DATE: &str = "2026-09-16";

fn fm(links: &FmLinks, ids: &[&str]) -> String {
    let parts: Vec<String> = ids
        .iter()
        .map(|id| match links.get(*id) {
            Some(href) => format!("<a href=\"{}\">{}</a>", esc(href), esc(id)),
            None => esc(id),
        })
        .collect();
    format!(
        "<p class=\"fm-ref\"><span class=\"badge\">SC-FM</span> {}</p>",
        parts.join(" · ")
    )
}

/// A serde enum as its snake_case name.
fn name<T: serde::Serialize>(v: &T) -> String {
    serde_json::to_value(v)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_default()
}

fn rows_table(head: &[&str], rows: &[Vec<String>]) -> String {
    format!(
        "<details class=\"as-table\"><summary>View as table</summary>{}</details>",
        table("", head, rows)
    )
}

/// One step: number, title, prose, the figure and its caption, the table.
struct Step<'a> {
    id: &'a str,
    n: usize,
    title: &'a str,
    prose: String,
    figure: String,
    caption: String,
    table: String,
    refs: String,
}

fn step(s: &Step) -> String {
    format!(
        "<li class=\"walk-step\" id=\"step-{id}\" aria-labelledby=\"step-{id}-h\">\
<div class=\"step-text\"><p class=\"step-n\">Step {n}</p><h3 id=\"step-{id}-h\">{title}</h3>{prose}{refs}</div>\
<figure class=\"chart-box walk-fig\" data-static=\"{id}\">{fig}<figcaption>{cap}</figcaption>{table}</figure>\
<div class=\"live-slot\" data-live-slot=\"{id}\" hidden></div></li>",
        id = s.id,
        n = s.n,
        title = esc(s.title),
        prose = s.prose,
        refs = s.refs,
        fig = s.figure,
        cap = s.caption,
        table = s.table,
    )
}

/// The record with the most layers (then the highest score): what step 1
/// unwraps.
fn deepest(a: &Analysis) -> Option<&ObsResult> {
    a.results
        .iter()
        .filter(|r| r.tier > Tier::Noise)
        .max_by_key(|r| (r.layers.len(), r.score, std::cmp::Reverse(r.obs.id.clone())))
}

/// The record with the most rule hits (then the highest score).
fn richest(a: &Analysis) -> Option<&ObsResult> {
    a.results
        .iter()
        .filter(|r| r.tier > Tier::Noise)
        .max_by_key(|r| (r.hits.len(), r.score, std::cmp::Reverse(r.obs.id.clone())))
}

fn unwrap_step(a: &Analysis, links: &FmLinks) -> String {
    let Some(r) = deepest(a) else {
        return String::new();
    };
    let layers: Vec<UrlLayer> = r
        .layers
        .iter()
        .map(|l| UrlLayer {
            via: l.via.clone(),
            depth: l.depth,
            text: sc_core::defang(&l.text),
        })
        .collect();
    let rows: Vec<Vec<String>> = layers
        .iter()
        .enumerate()
        .map(|(i, l)| {
            vec![
                i.to_string(),
                esc(&l.via),
                format!("<code>{}</code>", esc(&l.text)),
            ]
        })
        .collect();
    step(&Step {
        id: "unwrap",
        n: 1,
        title: "Unwrap",
        prose: "<p>Agents fetch pages through readers, relays and code runners, so the URL a scan service records is often a wrapper. Each one is peeled into layers (relay paths, URL-valued parameters, base64, <code>data:</code> programs) down to the real target. The text is decoded, never opened.</p>".into(),
        figure: layer_stack(&layers, "Synthetic example: the layers inside one recorded URL"),
        caption: format!(
            "One synthetic URL, {} layers deep, outermost first. Text is defanged and cut to fit.",
            layers.len()
        ),
        table: rows_table(&["Layer", "Found via", "Text (defanged)"], &rows),
        refs: fm(links, &["FM-4.1", "FM-14.14"]),
    })
}

fn match_step(a: &Analysis, rules: &Rules, links: &FmLinks) -> String {
    let Some(r) = richest(a) else {
        return String::new();
    };
    let t = &rules.set.thresholds;
    let hits: Vec<(String, i32)> = r
        .hits
        .iter()
        .map(|h| (h.rule_id.clone(), h.weight))
        .collect();
    let rows: Vec<Vec<String>> = r
        .hits
        .iter()
        .map(|h| {
            vec![
                format!("<code>{}</code>", esc(&h.rule_id)),
                format!("+{}", h.weight),
                h.tactic.map_or_else(|| "–".into(), |t| esc(t.id())),
                format!("<code>{}</code>", esc(&sc_core::defang(&h.matched))),
            ]
        })
        .collect();
    step(&Step {
        id: "match",
        n: 2,
        title: "Match",
        prose: format!(
            "<p>The <a href=\"rules/\">indicator rules</a> run on every layer. Each rule counts once per record and adds its weight; the sum grades the record <strong>suggestive</strong> at {} and <strong>significant</strong> at {}, and some rules are significant on their own. A relay alone is never enough. This record is graded {}.</p><p class=\"rec-url\"><code>{}</code></p>",
            t.suggestive,
            t.significant,
            pill(r.tier.label()),
            esc(&sc_core::defang(&r.obs.url))
        ),
        figure: score_bar(
            &hits,
            t.suggestive,
            t.significant,
            "Synthetic example: one record's rule weights against the thresholds",
        ),
        caption: format!(
            "Score {} from {} rules. The tactic (SC-T) says what the match shows the agent doing.",
            r.score,
            r.hits.len()
        ),
        table: rows_table(&["Rule", "Weight", "Tactic", "Matched (defanged)"], &rows),
        refs: fm(links, &["FM-4.2", "FM-4.3"]),
    })
}

fn link_step(a: &Analysis, links: &FmLinks) -> String {
    let idx: BTreeMap<&str, usize> = a
        .clusters
        .iter()
        .enumerate()
        .map(|(i, c)| (c.id.as_str(), i))
        .collect();
    let nodes: Vec<GNode> = a
        .clusters
        .iter()
        .map(|c| GNode {
            label: c.id.clone(),
            tier: c.tier.label().to_string(),
            size: c.members.len(),
        })
        .collect();
    let mut edges = Vec::new();
    let mut rows = Vec::new();
    for s in &a.soft_links {
        if let (Some(&x), Some(&y)) = (idx.get(s.a.as_str()), idx.get(s.b.as_str())) {
            let kind = name(&s.kind);
            edges.push(GEdge {
                a: x,
                b: y,
                class: format!("soft sk-{}", kind.replace('_', "-")),
                label: format!("Soft link, {}: {} and {}", s.kind.label(), s.a, s.b),
            });
            rows.push(vec![
                esc(s.kind.label()),
                esc(&s.a),
                esc(&s.b),
                format!("{:.2}", s.strength),
            ]);
        }
    }
    for f in &a.candidate_fleets {
        let Some(&first) = f.clusters.first().and_then(|c| idx.get(c.as_str())) else {
            continue;
        };
        for c in f.clusters.iter().skip(1) {
            if let Some(&y) = idx.get(c.as_str()) {
                edges.push(GEdge {
                    a: first,
                    b: y,
                    class: "fleet".into(),
                    label: format!("Candidate fleet {}: {}", f.id, f.clusters.join(", ")),
                });
            }
        }
        rows.push(vec![
            format!("candidate fleet {}", esc(&f.id)),
            esc(&f.clusters.join(", ")),
            String::new(),
            format!("{:.2}", f.strength),
        ]);
    }
    let fleets: Vec<String> = a
        .candidate_fleets
        .iter()
        .map(|f| format!("{} ({})", f.id, f.clusters.join(", ")))
        .collect();
    step(&Step {
        id: "link",
        n: 3,
        title: "Link",
        prose: format!(
            "<p>Records join into a <strong>cluster</strong> on hard links: a shared inbox ID or tag only one operator would hold, close timing against one target, or a probe chain. Weaker ties between clusters (a rerun of the same host list, one encoding style, a shared relay stack) are <strong>soft links</strong>: they never merge anything. Strong enough together, they propose a <strong>candidate fleet</strong> for review{}.</p>",
            if fleets.is_empty() {
                String::new()
            } else {
                format!(": here {}", esc(&fleets.join("; ")))
            }
        ),
        figure: cluster_graph(
            &nodes,
            &edges,
            "Synthetic example: clusters and the soft links between them",
        ),
        caption: format!(
            "{} clusters from {} records. Node area is the record count; colour the tier; a thick grey edge joins a candidate fleet.",
            a.clusters.len(),
            a.total
        ),
        table: rows_table(&["Link", "From", "To", "Strength"], &rows),
        refs: fm(links, &["FM-5.1", "FM-5.7", "FM-5.8"]),
    })
}

fn time_step(a: &Analysis, links: &FmLinks) -> String {
    let lanes: Vec<Lane> = a
        .clusters
        .iter()
        .filter(|c| c.runs.iter().any(|r| r.start > 0))
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
    let swim = swimlanes(
        &lanes,
        &pauses,
        "Synthetic example: runs of each cluster over time, UTC",
    );
    // Interaction hints between runs.
    let mut lane_of: BTreeMap<String, usize> = BTreeMap::new();
    let mut slanes: Vec<(String, String)> = Vec::new();
    let mut nodes: Vec<RunNode> = Vec::new();
    let mut node_of: BTreeMap<String, usize> = BTreeMap::new();
    let mut node = |c: &Cluster, run: usize, strand: Option<&String>| -> usize {
        let lane = *lane_of.entry(c.id.clone()).or_insert_with(|| {
            slanes.push((c.id.clone(), c.tier.label().to_string()));
            slanes.len() - 1
        });
        let key = format!("{}#{run}|{}", c.id, strand.map_or("", |s| s.as_str()));
        if let Some(&i) = node_of.get(&key) {
            return i;
        }
        let t = c
            .runs
            .get(run.saturating_sub(1))
            .map_or(c.start, |r| (r.start + r.end) / 2);
        nodes.push(RunNode {
            lane,
            t,
            label: match strand {
                Some(s) => format!("{}#{run} ({})", c.id, sc_core::defang(s)),
                None => format!("{}#{run}", c.id),
            },
        });
        node_of.insert(key, nodes.len() - 1);
        nodes.len() - 1
    };
    let mut edges = Vec::new();
    let mut rows = Vec::new();
    for e in &a.swarm_edges {
        let (Some(ca), Some(cb)) = (a.cluster(&e.a.key), a.cluster(&e.b.key)) else {
            continue;
        };
        let x = node(ca, e.a.run, e.a.strand.as_ref());
        let y = node(cb, e.b.run, e.b.strand.as_ref());
        let label = format!(
            "{} {} ({}): {} → {}",
            e.kind.id(),
            e.kind.label(),
            e.strength.label(),
            e.a.label(),
            e.b.label()
        );
        rows.push(vec![
            format!("{} {}", esc(e.kind.id()), esc(e.kind.label())),
            esc(e.strength.label()),
            esc(&sc_core::defang(&e.a.label())),
            esc(&sc_core::defang(&e.b.label())),
            e.chance.map_or_else(|| "–".into(), |p| format!("{p:.1e}")),
        ]);
        edges.push(RunEdge {
            a: x,
            b: y,
            kind: name(&e.kind),
            strength: name(&e.strength),
            label: sc_core::defang(&label),
        });
    }
    let kinds: Vec<String> = {
        let mut k: Vec<&str> = a.swarm_edges.iter().map(|e| e.kind.id()).collect();
        k.sort_unstable();
        k.dedup();
        k.into_iter().map(str::to_string).collect()
    };
    let arcs = swarm_arcs(
        &slanes,
        &nodes,
        &edges,
        "Synthetic example: runs and the interaction hints between them",
    );
    let mut legend = String::from("<p class=\"legend\">");
    for e in sc_core::SwarmEdgeKind::ALL {
        if kinds.iter().any(|k| k == e.id()) {
            let _ = write!(
                legend,
                "<span><svg class=\"chart key-line\" viewBox=\"0 0 26 10\" width=\"26\" height=\"10\" aria-hidden=\"true\"><path class=\"sedge sk-{} st-moderate\" d=\"M1,5 L25,5\"/></svg>{} {}</span>",
                name(&e),
                esc(e.id()),
                esc(e.label())
            );
        }
    }
    legend.push_str("</p>");
    let run_rows: Vec<Vec<String>> = lanes
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
    step(&Step {
        id: "time",
        n: 4,
        title: "Time",
        prose: "<p>Each cluster's records fall into <strong>runs</strong>: stretches of activity without a long pause. Runs give pace, rhythm and concurrency, and they are where agents show they act on each other: one run writing what another reads, runs starting together, a reader mapping hosts before a striker attacks them. Those are <strong>interaction hints</strong> (S1 to S5), each weak alone; a swarm claim needs several and review.</p>".into(),
        figure: format!(
            "<div class=\"scroll-x\">{swim}</div><p class=\"legend\"><span><span class=\"key k-sig\"></span>significant</span> <span><span class=\"key k-sug\"></span>suggestive</span> <span><span class=\"key k-pause\"></span>pause</span></p>{legend}<div class=\"scroll-x\">{arcs}</div>"
        ),
        caption: format!(
            "Top: one lane per cluster, one bar per run. Bottom: runs as dots and the {} interaction hints between them, by kind ({}).",
            a.swarm_edges.len(),
            esc(&kinds.join(", "))
        ),
        table: format!(
            "{}{}",
            rows_table(&["Cluster", "Tier", "Run start", "Run end", "Records"], &run_rows),
            rows_table(&["Hint", "Strength", "From", "To", "Chance"], &rows)
        ),
        refs: fm(links, &["FM-5.5", "FM-6.2", "FM-5.12"]),
    })
}

fn grade_step(a: &Analysis, links: &FmLinks) -> String {
    let rungs: Vec<(&str, &str)> = AgentLevel::ALL
        .iter()
        .map(|l| (l.code(), l.label()))
        .collect();
    let cols: Vec<LadderCol> = a
        .clusters
        .iter()
        .map(|c| LadderCol {
            label: c.id.clone(),
            tier: c.tier.label().to_string(),
            level: c.agent.level as usize,
            reach: c
                .agent
                .signals
                .iter()
                .filter_map(|s| s.kind.level())
                .map(|l| l as usize)
                .max()
                .unwrap_or(0)
                .max(c.agent.level as usize),
        })
        .collect();
    let rows: Vec<Vec<String>> = a
        .clusters
        .iter()
        .map(|c| {
            let signals: Vec<&str> = c.agent.signals.iter().map(|s| s.kind.label()).collect();
            let caps: Vec<&str> = c.agent.caps.iter().map(|k| k.label()).collect();
            vec![
                esc(&c.id),
                format!(
                    "{} {}",
                    esc(c.agent.level.code()),
                    esc(c.agent.level.label())
                ),
                esc(&signals.join("; ")),
                esc(&caps.join("; ")),
            ]
        })
        .collect();
    let capped = cols.iter().filter(|c| c.reach > c.level).count();
    step(&Step {
        id: "grade",
        n: 5,
        title: "Grade agent likelihood",
        prose: format!(
            "<p>A detected cluster is not yet an agent: a person pasting model output, or a scanner, can leave the same records. Each cluster gets a rung on a ladder from L0 (attack payloads only) to L4 (adaptive, model-written requests at a pace beyond one person); only case work reaches L5. Caps hold a grade down when the evidence cannot show more, such as archive capture times, which say nothing of pace{}. <span class=\"badge\">unmeasured on held-out data</span></p>",
            if capped > 0 {
                format!(" (a ring marks where {capped} cluster's signals reach)")
            } else {
                String::new()
            }
        ),
        figure: ladder(&cols, &rungs, "Synthetic example: each cluster's agent-likelihood grade"),
        caption: "A dot per cluster at its grade, coloured by tier. Descriptive: the grade is never scored, never linked on, and is not yet measured against held-out labels.".into(),
        table: rows_table(&["Cluster", "Grade", "Signals", "Caps"], &rows),
        refs: fm(links, &["FM-7.10", "FM-14.7"]),
    })
}

/// The cluster steps 6 and 7 follow: the first in a candidate fleet seen
/// by a server (observed), else the strongest.
fn focus(a: &Analysis) -> Option<&Cluster> {
    let fleet: Vec<&str> = a
        .candidate_fleets
        .iter()
        .flat_map(|f| f.clusters.iter().map(String::as_str))
        .collect();
    a.clusters
        .iter()
        .find(|c| fleet.contains(&c.id.as_str()) && c.provenance.contains_key("observed"))
        .or_else(|| a.clusters.first())
}

fn attribute_step(a: &Analysis, links: &FmLinks) -> String {
    let Some(c) = focus(a) else {
        return String::new();
    };
    let claims = sc_core::attribute(a, c);
    let layers = sc_core::attribution::summaries(&claims, sc_core::Evidence::default());
    let heads = [
        ("developer", "Developer and operator"),
        ("host", "Hosting and runtime"),
        ("harness", "Harness and framework"),
        ("model_family", "Model family"),
    ];
    let mut bands = Vec::new();
    let mut rows = Vec::new();
    for (id, heading) in heads {
        let mine: Vec<_> = layers.iter().filter(|l| name(&l.layer) == id).collect();
        match mine.first() {
            Some(l) => bands.push((heading, sc_core::defang(&l.party), name(&l.label))),
            None => bands.push((heading, String::new(), String::new())),
        }
        for l in mine {
            rows.push(vec![
                esc(heading),
                esc(&sc_core::defang(&l.party)),
                esc(&name(&l.label)),
                esc(&name(&l.evidence)),
                esc(&name(&l.tag)),
            ]);
        }
    }
    step(&Step {
        id: "attribute",
        n: 6,
        title: "Attribute",
        prose: format!(
            "<p>Who is behind cluster {} is answered in four layers: the developer or operator, the hosting network, the harness, the model family. Each claim carries a label (Confirmed, Suspected, Possible) that follows its evidence. A network names a host, not a developer; a model's name inside a request names no one. A developer is named only at the naming gate.</p>",
            esc(&c.id)
        ),
        figure: layer_bands(
            &bands,
            "Synthetic example: what the records support at each attribution layer",
        ),
        caption: "The networks here are documentation ASNs (RFC 5398): no real company is named."
            .into(),
        table: rows_table(
            &["Layer", "Party or candidate", "Label", "Evidence", "Tag"],
            &rows,
        ),
        refs: fm(links, &["FM-7.1", "FM-7.7", "FM-7.8"]),
    })
}

fn report_step(links: &FmLinks) -> String {
    let steps = [
        ("Report drafted", "admin reviews"),
        ("AI provider", "first, 0 h"),
        ("Operators", "4–12 h, 24 h if compromised"),
        ("Public notice", "after every clock runs"),
    ];
    step(&Step {
        id: "report",
        n: 7,
        title: "Report, then publish",
        prose: "<p>The tools draft; a person sends. Reports go to the AI provider responsible and to the affected operators, and the public notice follows on a fixed lead time that nothing a recipient says extends. A notice informs without enabling: it withholds working payloads, inbox and tag values, and anything that would help repeat the attack. The example notice below is drafted from these synthetic records.</p>".into(),
        figure: disclosure_flow(&steps, "Who hears first, and when the notice may follow"),
        caption: "Lead times from the publication policy.".into(),
        table: rows_table(
            &["Party", "Lead time"],
            &steps
                .iter()
                .map(|(a, b)| vec![esc(a), esc(b)])
                .collect::<Vec<_>>(),
        ),
        refs: fm(links, &["FM-10.2", "FM-11.4"]),
    })
}

/// The public notice the engine drafts for the focus cluster: summary and
/// attribution shown, the rest behind a disclosure.
fn example_notice(a: &Analysis) -> String {
    let Some(c) = focus(a) else {
        return String::new();
    };
    let opts = sc_core::ReportOptions {
        cluster: Some(c.key.clone()),
        generated: Some(EXAMPLE_DATE.into()),
        ..Default::default()
    };
    let n = sc_core::render_notice(a, &opts);
    let blocks = md_blocks(&n.markdown);
    // Up to the second section: title, banner, facts and the summary.
    let cut = blocks
        .iter()
        .enumerate()
        .filter(|(_, b)| matches!(b, crate::markdown::Block::Heading { level: 2, .. }))
        .nth(1)
        .map_or(blocks.len(), |(i, _)| i);
    let head = super::notices::body_html(&blocks[..cut]);
    let rest = super::notices::body_html(&blocks[cut..]);
    format!(
        "<article class=\"card example-notice\" aria-labelledby=\"example-notice-h\">\
<p class=\"synthetic-banner\"><strong>Example notice, synthetic.</strong> Drafted by the engine from the showcase records above, never sent and never published. Real notices appear here once a reviewed incident has been reported.</p>\
<h3 id=\"example-notice-h\">What a notice looks like</h3><div class=\"notice-body\">{head}</div>\
<details class=\"more\"><summary>The rest of the example notice</summary><div class=\"notice-body\">{rest}</div></details></article>"
    )
}

fn notices_section(notices: &[NoticeFile], a: &Analysis) -> String {
    let mut s = String::from(
        "<section class=\"latest\" aria-labelledby=\"latest\"><h2 id=\"latest\">Latest notices</h2>",
    );
    if notices.is_empty() {
        s.push_str("<p class=\"hint\">No notices yet. A notice is published only after a lead has been reviewed, linked into a case and reported to the AI provider and the affected operators. Unreviewed leads never appear here. <a href=\"notices/feed.xml\">Subscribe to the Atom feed</a> to hear about the first one.</p>");
        s.push_str(&example_notice(a));
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
    s
}

const STEPS: [(&str, &str); 7] = [
    ("unwrap", "Unwrap"),
    ("match", "Match"),
    ("link", "Link"),
    ("time", "Time"),
    ("grade", "Grade"),
    ("attribute", "Attribute"),
    ("report", "Report"),
];

pub fn body(a: &Analysis, rules: &Rules, notices: &[NoticeFile], links: &FmLinks) -> String {
    let mut s = String::new();
    s.push_str(
        "<section class=\"hero\" aria-labelledby=\"mission\"><p class=\"eyebrow\">Passive detection · coordinated disclosure · an open method</p><h1 id=\"mission\">Swarmchasing</h1>\
<p class=\"mission\">Swarmchasing finds misaligned AI agent swarms in public records (URL scanners, web archives, certificate logs), links their requests into runs and fleets, and reports each confirmed incident to the AI provider responsible and to the affected operators. A public notice follows on a fixed lead time.</p>\
<p class=\"ctas\"><a class=\"button primary\" href=\"#walk\">See the method</a> <a class=\"button\" href=\"operators/\">Check your own logs</a> <a class=\"button\" href=\"analyze/\">Open the workbench</a> <a class=\"button ghost\" href=\"docs/manual/\">Read the Field Manual</a></p>",
    );
    s.push_str("<nav aria-label=\"The method\"><ol class=\"method-strip\">");
    for (i, (id, label)) in STEPS.iter().enumerate() {
        let _ = write!(
            s,
            "<li><a href=\"#step-{id}\"><span class=\"n\">{}</span>{label}</a></li>",
            i + 1
        );
    }
    s.push_str("</ol></nav></section>\n");
    let _ = write!(
        s,
        "<section class=\"walk\" id=\"walk\" aria-labelledby=\"walk-h\"><div class=\"walk-head\"><h2 id=\"walk-h\">The method, on one synthetic incident</h2>\
<p class=\"synthetic-banner\"><strong>Synthetic example.</strong> Every record on this page was written to show the method; none was collected. Target hosts are reserved placeholders (<code>*.example</code>) and networks are documentation ASNs. {} records, {} flagged, {} clusters.</p>\
<div class=\"live-box\" data-live-box hidden><button type=\"button\" class=\"primary\" data-live>Run it live in this page</button> <a class=\"button\" href=\"analyze/#try=example\">Open it in the workbench</a>\
<p class=\"hint\" data-engine-status aria-live=\"polite\"></p><p class=\"hint\" data-live-out aria-live=\"polite\"></p></div></div><ol class=\"walk-steps\">",
        a.total,
        a.flagged,
        a.clusters.len()
    );
    s.push_str(&unwrap_step(a, links));
    s.push_str(&match_step(a, rules, links));
    s.push_str(&link_step(a, links));
    s.push_str(&time_step(a, links));
    s.push_str(&grade_step(a, links));
    s.push_str(&attribute_step(a, links));
    s.push_str(&report_step(links));
    s.push_str("</ol><p class=\"walk-foot\">Ground rules: collection is passive (no URL an agent submitted is ever opened), model names in requests are weak evidence, and a developer is named only when the evidence reaches the naming gate. Details: <a href=\"methodology/\">methodology</a>, <a href=\"docs/policies/\">policies</a>, the <a href=\"docs/manual/\">Field Manual</a>.</p></section>\n");
    s.push_str(&notices_section(notices, a));
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn showcase() -> Analysis {
        let text = include_str!("../../../../samples/showcase/showcase.ndjson");
        let rules = Rules::default_rules();
        sc_core::analyze(
            sc_core::parse_input(text, sc_core::Format::Ndjson, &sc_core::FieldMap::default())
                .observations,
            &rules,
        )
    }

    #[test]
    fn every_step_renders_and_nothing_internal_leaks() {
        let a = showcase();
        let mut links = FmLinks::new();
        links.insert(
            "FM-4.1".into(),
            "docs/manual/04-indicators/#fm-41-grading-records".into(),
        );
        let html = body(&a, &Rules::default_rules(), &[], &links);
        for (id, _) in STEPS {
            assert!(
                html.contains(&format!("id=\"step-{id}\"")),
                "step {id} missing"
            );
        }
        assert!(html.contains("href=\"docs/manual/04-indicators/#fm-41-grading-records\""));
        assert!(html.contains("Example notice, synthetic."));
        assert!(!html.contains(" style="), "a style attribute");
        // Plant signals and declared-testing contacts stay off public pages.
        for c in &a.clusters {
            for p in &c.plant_signals {
                assert!(
                    !html.contains(&p.detail),
                    "plant signal on the landing page"
                );
            }
        }
        assert!(!html.to_ascii_lowercase().contains("plant signal"));
        // Hosts are defanged wherever they appear.
        assert!(
            !html.contains("utility-portal.example"),
            "an undefanged host"
        );
    }
}
