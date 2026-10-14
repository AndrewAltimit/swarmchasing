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
    GEdge, GNode, LadderCol, RunEdge, RunNode, ScopeRow, ScorePart, UrlLayer, cluster_graph,
    disclosure_flow, ladder, layer_bands, layer_stack, scope_grid, score_bar, swarm_arcs,
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

/// How a step's figure fits a phone screen.
#[derive(Clone, Copy, PartialEq)]
enum Fit {
    /// Text-heavy: kept at a readable minimum width and scrolled sideways
    /// rather than shrunk (`.walk-fig.wide-min`).
    WideMin,
    /// Wide by nature (graphs, grids): scrolled sideways, and its short
    /// table opens by default on a phone (`data-phone-table`).
    Scroll,
    /// Wide, with tables too long to open by default (the runs).
    ScrollOnly,
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
    fit: Fit,
}

/// Shown on narrow screens only (the stylesheet hides it otherwise).
const SCROLL_HINT: &str = "<p class=\"scroll-hint\">Scroll the figure sideways, or open <em>View as table</em> below it.</p>";

/// Every figure after the first sits in a fold, open as built; on a phone
/// the page script closes it (`details.fig-fold`), so the walk reads as
/// text first.
fn step(s: &Step) -> String {
    let (fold, end) = if s.n > 1 {
        (
            "<details class=\"fig-fold\" open><summary>Show the figure</summary>",
            "</details>",
        )
    } else {
        ("", "")
    };
    format!(
        "<li class=\"walk-step\" id=\"step-{id}\" aria-labelledby=\"step-{id}-h\">\
<div class=\"step-text\"><p class=\"step-n\">Step {n}</p><h3 id=\"step-{id}-h\">{title}</h3>{prose}{refs}</div>\
{fold}<figure class=\"chart-box walk-fig{class}\" data-static=\"{id}\"{phone}>{SCROLL_HINT}{fig}<figcaption>{cap}</figcaption>{table}</figure>{end}\
<div class=\"live-slot\" data-live-slot=\"{id}\" hidden></div></li>",
        id = s.id,
        n = s.n,
        title = esc(s.title),
        prose = s.prose,
        refs = s.refs,
        class = if s.fit == Fit::WideMin {
            " wide-min"
        } else {
            ""
        },
        phone = if s.fit == Fit::Scroll {
            " data-phone-table"
        } else {
            ""
        },
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
        fit: Fit::WideMin,
    })
}

/// A record's score as its contributions ([`Rules::score`]): each
/// independence group once, at its heaviest rule that fired; each
/// ungrouped rule at its weight; context kinds together capped one below
/// suggestive. Evidence first, then context, each in hit order.
pub(crate) fn score_parts(r: &ObsResult, rules: &Rules) -> Vec<ScorePart> {
    // A group (or one ungrouped rule) and its members: (rule id, weight, context).
    type Unit = (Option<String>, Vec<(String, i32, bool)>);
    let mut units: Vec<Unit> = Vec::new();
    for h in &r.hits {
        let group = rules.rule(&h.rule_id).and_then(|d| d.group.clone());
        let member = (h.rule_id.clone(), h.weight.max(0), h.kind.is_context());
        match units.iter_mut().find(|(g, _)| g.is_some() && *g == group) {
            Some((_, m)) => m.push(member),
            None => units.push((group, vec![member])),
        }
    }
    let mut parts: Vec<(ScorePart, bool)> = units
        .into_iter()
        .map(|(group, members)| {
            // The heaviest member counts; a non-context member wins a tie.
            let best = members
                .iter()
                .enumerate()
                .max_by_key(|(i, m)| (m.1, !m.2, std::cmp::Reverse(*i)))
                .map_or(0, |(i, _)| i);
            let (id, weight, ctx) = members[best].clone();
            let others: Vec<String> = members
                .iter()
                .enumerate()
                .filter(|(i, _)| *i != best)
                .map(|(_, m)| format!("{} +{}", m.0, m.1))
                .collect();
            let label = match &group {
                Some(g) if members.len() > 1 => format!("{id} (group {g})"),
                _ => id,
            };
            let part = ScorePart {
                label,
                counted: weight,
                dropped: members.iter().map(|m| m.1).sum::<i32>() - weight,
                note: if others.is_empty() {
                    String::new()
                } else {
                    format!("{} in the same group", others.join(", "))
                },
            };
            (part, ctx)
        })
        .collect();
    parts.sort_by_key(|(_, ctx)| *ctx);
    let mut room = (rules.set.thresholds.suggestive - 1).max(0);
    for (p, _) in parts.iter_mut().filter(|(_, ctx)| *ctx) {
        let keep = p.counted.min(room);
        if keep < p.counted {
            p.dropped += p.counted - keep;
            p.note = if p.note.is_empty() {
                "context cap".into()
            } else {
                format!("{}; context cap", p.note)
            };
            p.counted = keep;
        }
        room -= keep;
    }
    parts.into_iter().map(|(p, _)| p).collect()
}

fn match_step(a: &Analysis, rules: &Rules, links: &FmLinks) -> String {
    // The richest record whose score grouping or the context cap changes,
    // else the richest.
    let changed = a
        .results
        .iter()
        .filter(|r| r.tier > Tier::Noise)
        .filter(|r| score_parts(r, rules).iter().any(|p| p.dropped > 0))
        .max_by_key(|r| (r.hits.len(), r.score, std::cmp::Reverse(r.obs.id.clone())));
    let Some(r) = changed.or_else(|| richest(a)) else {
        return String::new();
    };
    let t = &rules.set.thresholds;
    let parts = score_parts(r, rules);
    let rows: Vec<Vec<String>> = r
        .hits
        .iter()
        .map(|h| {
            let group = rules.rule(&h.rule_id).and_then(|d| d.group.as_deref());
            vec![
                format!("<code>{}</code>", esc(&h.rule_id)),
                format!("+{}", h.weight),
                group.map_or_else(|| "–".into(), |g| format!("<code>{}</code>", esc(g))),
                if h.kind.is_context() {
                    "context"
                } else {
                    "evidence"
                }
                .into(),
                h.tactic.map_or_else(|| "–".into(), |t| esc(t.id())),
                format!("<code>{}</code>", esc(&sc_core::defang(&h.matched))),
            ]
        })
        .collect();
    let raw: i32 = r.hits.iter().map(|h| h.weight.max(0)).sum();
    step(&Step {
        id: "match",
        n: 2,
        title: "Match",
        prose: format!(
            "<p>The <a href=\"rules/\">indicator rules</a> run on every layer, and each counts once per record. Rules that read the same artifact (one program, one fetch route, one tag) share an <strong>independence group</strong>, which counts once, at its heaviest rule that fired. Context hits (relays, cache-busters, self-identification, headers, outcomes) together count at most {}, one below suggestive, so context alone is never enough. The score grades the record <strong>suggestive</strong> at {} and <strong>significant</strong> at {}, and some rules are significant on their own. This record is graded {}.</p><p class=\"rec-url\"><code>{}</code></p>",
            (t.suggestive - 1).max(0),
            t.suggestive,
            t.significant,
            pill(r.tier.label()),
            esc(&sc_core::defang(&r.obs.url))
        ),
        figure: score_bar(
            &parts,
            t.suggestive,
            t.significant,
            "Synthetic example: one record's score contributions against the thresholds",
        ),
        caption: format!(
            "Score {} from {} rules{}. One segment per contribution; weight that fired but does not count is dashed. The tactic (SC-T) says what the match shows the agent doing.",
            r.score,
            r.hits.len(),
            if raw != r.score {
                format!(", whose weights add to {raw}")
            } else {
                String::new()
            }
        ),
        table: rows_table(
            &[
                "Rule",
                "Weight",
                "Group",
                "Counts as",
                "Tactic",
                "Matched (defanged)",
            ],
            &rows,
        ),
        refs: fm(links, &["FM-4.2", "FM-4.11", "FM-4.3"]),
        fit: Fit::WideMin,
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
        fit: Fit::Scroll,
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
        prose: "<p>Each cluster's records fall into <strong>runs</strong>: stretches of activity without a long pause. Runs give pace, rhythm and concurrency, and they are where agents show they act on each other: one run writing what another reads, runs starting together, a reader mapping hosts before a striker attacks them. Those are <strong>interaction hints</strong> (S1 to S6), each weak alone; a swarm claim needs several and review.</p>".into(),
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
        fit: Fit::ScrollOnly,
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
        fit: Fit::WideMin,
    })
}

/// The scope tests by code, under the scope table (FM-15.3).
const SCOPE_TESTS: &str = "<p class=\"legend scope-tests\"><span>S1 off-task target</span> <span>S2 getting past a block</span> <span>S3 sensitive paths</span> <span>S4 unsanctioned probing</span> <span>S5 identities and credentials</span> <span>S6 data sent out</span> <span>S7 coordination that widens any of them</span></p>";

/// What the agent question reads: a cluster counts as an agent present
/// only from L4 on the grade ladder (step 5), and says so when no cluster
/// here gets there.
fn agent_note(assessed: &[&Cluster]) -> String {
    let likely = assessed.iter().filter(|c| c.scope.agent_present).count();
    let head = "<p><strong>Agent likely (L4+)</strong> reads yes only from L4 on the grade ladder: adaptive, model-written requests at a pace or scale beyond one person. The rungs below it (L1 a model or tag named, L2 model-written text, L3 requests that change with the responses) say what the records carry, not that an agent sent them.";
    if likely == 0 {
        format!(
            "{head} None of the synthetic clusters reaches L4, so the column reads no throughout: L4 needs a pace or scale signal (machine pace, fan-out over many targets, several services, activity round the clock), and these runs are short and small, written to show the other steps.</p>"
        )
    } else {
        format!("{head}</p>")
    }
}

fn scope_step(a: &Analysis, links: &FmLinks) -> String {
    let assessed: Vec<&Cluster> = a
        .clusters
        .iter()
        .filter(|c| !c.scope.is_default())
        .collect();
    if assessed.is_empty() {
        return String::new();
    }
    let grid: Vec<ScopeRow> = assessed
        .iter()
        .map(|c| ScopeRow {
            label: c.id.clone(),
            tier: c.tier.label().to_string(),
            questions: [
                c.scope.payload_present,
                c.scope.agent_present,
                c.scope.out_of_scope,
                c.scope.coordinated,
            ],
            tests: c
                .scope
                .tests
                .iter()
                .map(|t| (t.id.clone(), name(&t.outcome)))
                .collect(),
            finding: c.scope.finding.label().to_string(),
        })
        .collect();
    let yes = |b: bool| if b { "yes" } else { "no" };
    let rows: Vec<Vec<String>> = assessed
        .iter()
        .map(|c| {
            let s = &c.scope;
            let failed: Vec<String> = s
                .tests
                .iter()
                .filter(|t| t.outcome == sc_core::scope::ScopeOutcome::Fail)
                .map(|t| t.id.clone())
                .collect();
            vec![
                esc(&c.id),
                pill(c.tier.label()),
                yes(s.payload_present).into(),
                yes(s.agent_present).into(),
                yes(s.out_of_scope).into(),
                yes(s.coordinated).into(),
                esc(s.task_class.label()),
                esc(s.finding.label()),
                if failed.is_empty() {
                    "–".into()
                } else {
                    esc(&failed.join(", "))
                },
            ]
        })
        .collect();
    let in_scope_payload = assessed
        .iter()
        .filter(|c| c.scope.payload_present && !c.scope.out_of_scope)
        .count();
    step(&Step {
        id: "scope",
        n: 6,
        title: "Assess scope",
        prose: format!(
            "<p>A tier measures payloads and tool use; a grade, how likely an agent is. Neither says the activity went beyond its task. Each cluster answers four separate questions: is a <strong>payload present</strong> (observed), is an <strong>agent present</strong>, is it <strong>out of scope</strong> (an inference from seven tests: off-task targets, getting past a block, sensitive paths, unsanctioned probing, identities and credentials, data sent out, coordination that widens any of them), and is it <strong>coordinated</strong>. Tool use alone fails no test: a fetch program through an echo service is how agents read, not misbehaviour{}.</p>{}",
            if in_scope_payload > 0 {
                format!(
                    ". Here {in_scope_payload} cluster{} with a payload present {} in scope",
                    if in_scope_payload == 1 { "" } else { "s" },
                    if in_scope_payload == 1 { "is" } else { "are" }
                )
            } else {
                String::new()
            },
            agent_note(&assessed)
        ),
        figure: format!(
            "<div class=\"scroll-x\">{}</div><p class=\"legend\"><span><svg class=\"chart key-line\" viewBox=\"0 0 14 14\" width=\"14\" height=\"14\" aria-hidden=\"true\"><circle class=\"sqm q-payload\" cx=\"7\" cy=\"7\" r=\"6\"/></svg>payload present (observed)</span> <span><svg class=\"chart key-line\" viewBox=\"0 0 14 14\" width=\"14\" height=\"14\" aria-hidden=\"true\"><rect class=\"sqm q-scope\" x=\"1\" y=\"1\" width=\"12\" height=\"12\" rx=\"2\"/></svg>out of scope (inferred)</span> <span><svg class=\"chart key-line\" viewBox=\"0 0 14 14\" width=\"14\" height=\"14\" aria-hidden=\"true\"><rect class=\"tc fail\" x=\"2\" y=\"2\" width=\"10\" height=\"10\" rx=\"2\"/></svg>test failed</span> <span><svg class=\"chart key-line\" viewBox=\"0 0 14 14\" width=\"14\" height=\"14\" aria-hidden=\"true\"><circle class=\"tc pass\" cx=\"7\" cy=\"7\" r=\"5\"/></svg>passed</span> <span><svg class=\"chart key-line\" viewBox=\"0 0 14 14\" width=\"14\" height=\"14\" aria-hidden=\"true\"><circle class=\"tc not-assessable\" cx=\"7\" cy=\"7\" r=\"5\"/></svg>not assessable</span></p>",
            scope_grid(&grid, "Synthetic example: each cluster's four questions and scope tests")
        ),
        caption: "A row per cluster. An inference for review: the finding never changes a score, a tier or a link, and the admin decides the incident.".into(),
        table: rows_table(
            &[
                "Cluster",
                "Tier",
                "Payload",
                "Agent likely (L4+)",
                "Out of scope",
                "Coordinated",
                "Task",
                "Finding",
                "Failed tests",
            ],
            &rows,
        )
        .replace("</details>", &format!("{SCOPE_TESTS}</details>")),
        refs: fm(links, &["FM-15.1", "FM-15.3", "FM-15.4"]),
        fit: Fit::ScrollOnly,
    })
}

/// The cluster steps 7 and 8 follow: the first in a candidate fleet seen
/// by a server (observed), else the strongest.
fn focus(a: &Analysis) -> Option<&Cluster> {
    let fleet: Vec<&str> = a
        .candidate_fleets
        .iter()
        .flat_map(|f| f.clusters.iter().map(String::as_str))
        .collect();
    a.clusters
        .iter()
        .find(|c| {
            fleet.contains(&c.id.as_str())
                && c.origin
                    .provenance
                    .contains_key(&sc_core::model::Provenance::Observed)
        })
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
        n: 7,
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
        fit: Fit::WideMin,
    })
}

fn report_step(links: &FmLinks) -> String {
    let steps = [
        ("Reports", "provider and operators"),
        ("Second review", "of the exact draft"),
        ("Indicator notice", "0 h; 24 h if compromised"),
        ("Naming update", "3 or 10 working days"),
    ];
    step(&Step {
        id: "report",
        n: 8,
        title: "Report, then publish",
        prose: "<p>The tools draft; a person sends, and a second person reviews every notice before it is published. Reports go to the AI provider responsible and to the affected operators first. An indicator notice follows on a short fixed clock that nothing a recipient says extends: it describes the activity and names no affected party. Operators are named in a later update, 3 working days after their report (10 if compromised), or earlier with their consent. A notice informs without enabling: it withholds working payloads, inbox and tag values, and anything that would help repeat the attack. The example indicator notice below is drafted from these synthetic records.</p>".into(),
        figure: disclosure_flow(&steps, "Who hears first, and when the notice may follow"),
        caption: "The two clocks of the <a href=\"docs/policies/#lead-times\">publication policy</a>, each counted from a party's latest report; an operator whose systems were compromised waits 10 working days to be named. Working days are Monday to Friday, UTC. Nothing a recipient says moves the indicator clock; only consent names an operator sooner.".into(),
        table: rows_table(
            &["Stage", "When"],
            &steps
                .iter()
                .map(|(a, b)| vec![esc(a), esc(b)])
                .collect::<Vec<_>>(),
        ),
        refs: fm(links, &["FM-10.2", "FM-11.4"]),
        fit: Fit::Scroll,
    })
}

/// How the example notice describes a showcase host's organisation, by the
/// label before `.example`: a class, never a name.
const TARGET_CLASSES: &[(&str, &str)] = &[
    ("utility-portal", "a utility customer portal"),
    ("county-records", "a county records office"),
    ("transit-authority", "a transit authority"),
    ("permits-office", "a permits office"),
    ("agency", "a government agency"),
    ("portal", "a public data portal"),
];

/// The class a showcase host is described by in the indicator notice.
fn target_class(host: &str) -> &'static str {
    let org = host
        .trim_end_matches(".example")
        .rsplit('.')
        .next()
        .unwrap_or("");
    TARGET_CLASSES
        .iter()
        .find(|(k, _)| *k == org)
        .map_or("an affected organisation", |(_, v)| v)
}

/// The indicator notice the engine drafts for the focus cluster, as stage
/// one publishes it: every affected host described by class, so it names
/// and locates no affected party, and without the CLI's draft banner. The
/// title and facts show; the rest is behind a disclosure.
fn example_notice(a: &Analysis) -> String {
    let Some(c) = focus(a) else {
        return String::new();
    };
    let described: BTreeMap<String, String> = c
        .target_hosts
        .keys()
        .map(|h| (h.to_ascii_lowercase(), target_class(h).to_string()))
        .collect();
    let opts = sc_core::ReportOptions {
        cluster: Some(c.key.clone()),
        generated: Some(EXAMPLE_DATE.into()),
        target_descriptions: Some(described),
        ..Default::default()
    };
    let n = sc_core::render_notice(a, &opts);
    let blocks = md_blocks(&crate::file::strip_draft_banner(&n.markdown));
    // Up to the first section: the title and the facts.
    let cut = blocks
        .iter()
        .position(|b| matches!(b, crate::markdown::Block::Heading { level: 2, .. }))
        .unwrap_or(blocks.len());
    let head = super::notices::body_html(&blocks[..cut]);
    let rest = super::notices::body_html(&blocks[cut..]);
    format!(
        "<article class=\"card example-notice\" id=\"example-notice\" aria-labelledby=\"example-notice-h\">\
<p class=\"synthetic-banner\"><strong>Example notice, synthetic.</strong> Drafted by the engine from the showcase records above, never sent and never published. Real notices appear here once a reviewed incident has been reported.</p>\
<h3 id=\"example-notice-h\">What an indicator notice looks like</h3>\
<p class=\"hint\">The first stage: what the activity was and how to recognise it. Affected organisations appear by class only; their names follow in a naming update.</p><div class=\"notice-body\">{head}</div>\
<details class=\"more\"><summary>The rest of the example notice</summary><div class=\"notice-body\">{rest}</div></details></article>"
    )
}

/// The latest notices, or the empty state with the example notice. Once
/// any notice exists it sits right under the hero (`.latest-notices`);
/// until then the empty state closes the page.
fn notices_section(notices: &[NoticeFile], a: &Analysis) -> String {
    let mut s = format!(
        "<section class=\"latest{}\" aria-labelledby=\"latest\"><h2 id=\"latest\">Latest notices</h2>",
        if notices.is_empty() {
            ""
        } else {
            " latest-notices"
        }
    );
    if notices.is_empty() {
        s.push_str("<p class=\"hint\">No notices yet. A notice is published only after a lead has been reviewed, linked into a case and reported to the AI provider and the affected operators. Unreviewed leads never appear here. <a href=\"notices/feed.xml\">Subscribe to the Atom feed</a> to hear about the first one.</p>");
        s.push_str(&example_notice(a));
    } else {
        s.push_str("<ul class=\"notice-cards\">");
        for n in notices.iter().take(3) {
            let m = &n.meta;
            let _ = write!(
                s,
                "<li class=\"card\"><a href=\"notices/{}/\"><strong>{}</strong></a><p class=\"meta\">{} updated {}</p><p class=\"meta\">{}</p></li>",
                esc(&m.id),
                esc(&m.title),
                pill(m.status.label()),
                esc(&m.updated),
                super::notices::stage_html(m),
            );
        }
        s.push_str("</ul><p><a href=\"notices/\">All notices</a> · <a href=\"notices/feed.xml\">Atom feed</a></p>");
    }
    s.push_str("</section>\n");
    s
}

const STEPS: [(&str, &str); 8] = [
    ("unwrap", "Unwrap"),
    ("match", "Match"),
    ("link", "Link"),
    ("time", "Time"),
    ("grade", "Grade"),
    ("scope", "Scope"),
    ("attribute", "Attribute"),
    ("report", "Report"),
];

/// One audience card: (heading, what is there, links as (href, label);
/// the first link is the main one).
type Audience = (
    &'static str,
    &'static str,
    &'static [(&'static str, &'static str)],
);

/// Who the site is for, each with where to start.
const AUDIENCES: [Audience; 5] = [
    (
        "You received a report about your site, or found it in a notice",
        "What the report means, what becomes public and when, how to check your own logs, and how to reach us privately.",
        &[
            ("operators/", "For operators"),
            ("analyze/#preset=access-log", "Check a log in your browser"),
        ],
    ),
    (
        "You handle reports at an AI provider",
        "What a provider report holds, how to check its evidence bundle, what the STIX and MISP exports carry, and how you are named.",
        &[
            ("providers/", "For providers"),
            ("tools/", "Check a bundle"),
        ],
    ),
    (
        "You research agent detection",
        "Run the engine on your own exports, read every rule and its evaluation, and cite the method by section.",
        &[
            ("docs/guides/for-researchers/", "For researchers"),
            ("analyze/", "Workbench"),
            ("eval/", "Evaluation"),
        ],
    ),
    (
        "You are an AI agent, or you run one",
        "What the project is in plain text, and how an agent or its operator reports a swarm, or an agent's own harmful action, privately.",
        &[
            ("submit/", "Report a swarm"),
            ("llms.txt", "llms.txt"),
            ("docs/specs/submission-v1/", "SC-Submission spec"),
        ],
    ),
    (
        "You follow AI safety, or report on it",
        "What a notice says, why the organisations affected are named only later, and how to hear about each new notice.",
        &[
            ("notices/#how-notices-work", "How notices work"),
            ("notices/feed.xml", "Subscribe"),
            ("notices/", "All notices"),
        ],
    ),
];

/// The notices at a glance, right under the hero: how many, the latest
/// update, where to subscribe and how notices work. From the committed
/// notices only.
fn notice_strip(notices: &[NoticeFile]) -> String {
    let latest = notices.iter().map(|n| n.meta.updated.as_str()).max();
    let state = match (notices.len(), latest) {
        (0, _) | (_, None) => "No notices published yet.".to_string(),
        (n, Some(d)) => format!(
            "<strong>{n} notice{}</strong> · latest update <time datetime=\"{d}\">{d}</time>",
            if n == 1 { "" } else { "s" },
            d = esc(d)
        ),
    };
    format!(
        "<section class=\"notice-strip\" aria-label=\"Notices at a glance\"><p class=\"ns-state\">{state}</p>\
<p class=\"ns-links\"><a href=\"notices/\">All notices</a> <a href=\"notices/feed.xml\">Atom feed</a> <a href=\"notices/index.json\">JSON index</a> <a href=\"notices/#how-notices-work\">How notices work</a></p></section>\n"
    )
}

fn audiences() -> String {
    let mut s = String::from("<ul class=\"audiences\" aria-label=\"Start here\">");
    for (i, (head, what, links)) in AUDIENCES.iter().enumerate() {
        // The last card, the public's, spans the row under the others.
        let wide = if i + 1 == AUDIENCES.len() {
            " audience-wide"
        } else {
            ""
        };
        let _ = write!(
            s,
            "<li class=\"audience card{wide}\"><h2 id=\"aud-{i}\">{}</h2><p>{}</p><p class=\"ctas\">",
            esc(head),
            esc(what)
        );
        // Two buttons at most, so a card's row fits a phone; any further
        // link is plain text.
        for (k, (href, label)) in links.iter().enumerate() {
            let class = match k {
                0 => " class=\"button primary\"",
                1 => " class=\"button\"",
                _ => "",
            };
            let _ = write!(
                s,
                "{}<a{class} href=\"{href}\">{}</a>",
                if k > 0 { " " } else { "" },
                esc(label)
            );
        }
        s.push_str("</p></li>");
    }
    s.push_str("</ul>");
    s
}

pub fn body(a: &Analysis, rules: &Rules, notices: &[NoticeFile], links: &FmLinks) -> String {
    let mut s = String::new();
    s.push_str(
        "<section class=\"hero\" aria-labelledby=\"mission\"><p class=\"eyebrow\">Passive detection · coordinated disclosure · an open method</p><h1 id=\"mission\">Swarmchasing</h1>\
<p class=\"mission\">Swarmchasing finds AI agent activity in public records, links it into runs and fleets, and reports each confirmed incident that harms or endangers others to the AI provider responsible and the affected operators. A public notice follows: indicators first, naming no one affected, then names after 3 working days (10 if compromised).</p>",
    );
    s.push_str(&audiences());
    s.push_str("<p class=\"hero-more\"><a href=\"#walk\">See the method</a>, walked through one synthetic incident below, or read the <a href=\"docs/manual/\">Field Manual</a>.</p></section>\n");
    s.push_str(&notice_strip(notices));
    if !notices.is_empty() {
        s.push_str(&notices_section(notices, a));
    }
    s.push_str(
        "<section class=\"walk\" id=\"walk\" aria-labelledby=\"walk-h\"><div class=\"walk-head\"><h2 id=\"walk-h\">The method, on one synthetic incident</h2>",
    );
    s.push_str("<nav aria-label=\"The method's steps\"><ol class=\"method-strip\">");
    for (i, (id, label)) in STEPS.iter().enumerate() {
        let _ = write!(
            s,
            "<li><a href=\"#step-{id}\"><span class=\"n\">{}</span>{label}</a></li>",
            i + 1
        );
    }
    s.push_str("</ol></nav>");
    let _ = write!(
        s,
        "<p class=\"synthetic-banner\"><strong>Synthetic example.</strong> Every record on this page was written to show the method; none was collected. Target hosts are reserved placeholders (<code>*.example</code>) and networks are documentation ASNs. {} records, {} flagged, {} clusters.</p>\
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
    s.push_str(&scope_step(a, links));
    s.push_str(&attribute_step(a, links));
    s.push_str(&report_step(links));
    s.push_str("</ol><p class=\"walk-foot\">Ground rules: collection is passive (no URL an agent submitted is ever opened), model names in requests are weak evidence, and a developer is named only when the evidence reaches the naming gate. Details: <a href=\"methodology/\">methodology</a>, <a href=\"docs/policies/\">policies</a>, the <a href=\"docs/manual/\">Field Manual</a>.</p></section>\n");
    if notices.is_empty() {
        s.push_str(&notices_section(notices, a));
    }
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
    fn the_hero_routes_each_audience_and_notices_follow_it_once_any_exist() {
        let a = showcase();
        let rules = Rules::default_rules();
        let empty = body(&a, &rules, &[], &FmLinks::new());
        for href in ["operators/", "providers/", "docs/guides/for-researchers/"] {
            assert!(
                empty.contains(&format!("class=\"button primary\" href=\"{href}\"")),
                "{href}"
            );
        }
        assert_eq!(empty.matches("<li class=\"audience card\">").count(), 4);
        assert_eq!(
            empty
                .matches("<li class=\"audience card audience-wide\">")
                .count(),
            1
        );
        // The public's path: how notices work, and the feed.
        assert!(empty.contains("class=\"button primary\" href=\"notices/#how-notices-work\""));
        // The strip under the hero says there is no notice yet, and links
        // the feed and the JSON index.
        let strip = empty.find("class=\"notice-strip\"").unwrap();
        assert!(strip < empty.find("id=\"walk\"").unwrap());
        assert!(empty.contains("No notices published yet."));
        assert!(empty.contains("<a href=\"notices/index.json\">JSON index</a>"));
        assert!(empty.contains("class=\"button primary\" href=\"submit/\""));
        assert!(empty.contains(" <a href=\"docs/specs/submission-v1/\">SC-Submission spec</a>"));
        // No notices: the empty state and the example close the page.
        assert!(empty.find("id=\"walk\"") < empty.find("id=\"latest\""));
        assert!(!empty.contains("latest-notices"));
        let n = crate::parse_notice(include_str!(
            "../../tests/fixtures/notices/synthetic-portal-probe.md"
        ))
        .unwrap();
        let some = body(&a, &rules, &[n], &FmLinks::new());
        let latest = some.find("class=\"latest latest-notices\"").unwrap();
        assert!(latest < some.find("id=\"walk\"").unwrap());
        assert!(some.find("class=\"notice-strip\"").unwrap() < latest);
        assert!(some.contains("<strong>1 notice</strong> · latest update <time"));
        assert_eq!(some.matches("id=\"latest\"").count(), 1);
        assert!(!some.contains("Example notice, synthetic."));
        // The text-heavy figures keep a readable width; the wide ones open
        // their tables on a phone.
        assert!(empty.contains("class=\"chart-box walk-fig wide-min\" data-static=\"match\""));
        assert!(empty.contains("data-static=\"link\" data-phone-table"));
        assert!(!empty.contains("data-static=\"scope\" data-phone-table"));
        assert!(!empty.contains("Lead times from the publication policy"));
        // Every figure after the first folds on a phone.
        assert_eq!(
            empty.matches("<details class=\"fig-fold\" open>").count(),
            STEPS.len() - 1
        );
        assert!(!empty.contains("class=\"fig-fold\" open><summary>Show the figure</summary><figure class=\"chart-box walk-fig wide-min\" data-static=\"unwrap\""));
        // The researchers' third link is text, not a third button.
        assert!(empty.contains(" <a href=\"eval/\">Evaluation</a>"));
    }

    #[test]
    fn latest_notices_show_their_stage() {
        let a = showcase();
        let rules = Rules::default_rules();
        let ns: Vec<NoticeFile> = [
            include_str!("../../tests/fixtures/notices/synthetic-indicator-only.md"),
            include_str!("../../tests/fixtures/notices/synthetic-named-later.md"),
            include_str!("../../tests/fixtures/notices/synthetic-portal-probe.md"),
            include_str!("../../tests/fixtures/notices/synthetic-clinic-scan.md"),
        ]
        .iter()
        .map(|t| crate::parse_notice(t).unwrap())
        .collect();
        let html = body(&a, &rules, &ns, &FmLinks::new());
        assert_eq!(
            html.matches("<li class=\"card\"><a href=\"notices/")
                .count(),
            3
        );
        assert!(html.contains(
            "<span class=\"notice-stage\">Indicators published; affected organisations not named yet</span>"
        ));
        assert!(html.contains("Affected organisations named on 2026-09-25"));
    }

    #[test]
    fn the_example_is_an_indicator_notice_that_names_no_host() {
        let a = showcase();
        let html = example_notice(&a);
        assert!(html.contains("What an indicator notice looks like"));
        assert!(!html.contains("DRAFT"), "the CLI's draft banner");
        // No affected host, defanged or not: hosts appear by class only.
        let c = focus(&a).unwrap();
        assert!(!c.target_hosts.is_empty());
        for h in c.target_hosts.keys() {
            assert!(!html.contains(h.as_str()), "{h}");
            assert!(!html.contains(&sc_core::defang_host(h)), "{h}");
        }
        assert!(!html.contains("[.]example"), "a host in the example");
        assert!(html.contains(target_class(c.target_hosts.keys().next().unwrap())));
    }

    #[test]
    fn score_parts_add_up_to_the_engine_score() {
        let a = showcase();
        let rules = Rules::default_rules();
        let mut changed = 0;
        for r in &a.results {
            let parts = score_parts(r, &rules);
            let counted: i32 = parts.iter().map(|p| p.counted).sum();
            assert_eq!(counted, r.score, "{}", r.obs.id);
            if parts.iter().any(|p| p.dropped > 0) {
                changed += 1;
            }
        }
        assert!(changed > 0, "no showcase record shows grouping or the cap");
    }

    #[test]
    fn scope_step_keeps_payload_and_scope_apart() {
        let a = showcase();
        // The showcase holds both: a payload in scope, and scope exceeded.
        assert!(
            a.clusters
                .iter()
                .any(|c| c.scope.payload_present && !c.scope.out_of_scope)
        );
        assert!(a.clusters.iter().any(|c| c.scope.out_of_scope));
        let html = scope_step(&a, &FmLinks::new());
        assert!(html.contains("id=\"step-scope\""));
        assert!(html.contains("class=\"sqm q-payload\""));
        assert!(html.contains("class=\"sqm q-scope\""));
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
            for p in &c.origin.plant_signals {
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
