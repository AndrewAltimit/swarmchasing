//! The evaluation dashboard, from `sc_core::summarize` over the committed
//! labelled set with the bundled rules, computed at build time: precision
//! and recall per tier with Wilson intervals, the confusion matrices, hits
//! and coverage per rule, recall per class and per tactic, false positives
//! per benign class, and the cluster-level numbers. The page recomputes the
//! tier numbers in the browser with edited rules.

use super::html::{esc, table};
use super::rules::tactic_label;
use super::svg::{BarRow, hbars};
use sc_core::Summary;
use sc_core::eval::stats::Proportion;
use std::fmt::Write;

fn pc(p: &Proportion) -> String {
    p.value
        .map_or_else(|| "n/a".into(), |v| format!("{:.1}%", v * 100.0))
}

fn ci(p: &Proportion) -> String {
    match (p.lo, p.hi) {
        (Some(lo), Some(hi)) => format!("{:.1}–{:.1}%", lo * 100.0, hi * 100.0),
        _ => "n/a".into(),
    }
}

fn opt(x: Option<f64>) -> String {
    x.map_or_else(|| "n/a".into(), |v| format!("{:.1}%", v * 100.0))
}

/// The dashboard body. `files` names the labelled files.
pub fn body(s: &Summary, files: &[String]) -> String {
    let mut o = String::new();
    let _ = writeln!(
        o,
        "<header class=\"page-head\"><h1>Evaluation</h1>\
<p class=\"lede\">How the bundled rules (version <code>{}</code>) score on the committed labelled set: {} labelled records, {} agent and {} benign, from {}. The numbers are computed when the site is built; the same summary is in <a href=\"../assets/eval-summary.json\">eval-summary.json</a>.</p>\
<p class=\"callout\" role=\"note\"><strong>A regression floor, not a precision estimate.</strong> The rules were written and tuned against these records, and the tiers score records, not clusters: a cluster of ten flagged records counts ten times. Real-world precision is lower. Intervals are 95% Wilson score intervals. See <a href=\"../docs/reference/evaluation/\">evaluation</a> for the held-out measurement.</p></header>",
        esc(&s.rules_version),
        s.labelled,
        s.agents,
        s.benign,
        esc(&files.join(", ")),
    );

    o.push_str("<section aria-labelledby=\"tiers\"><h2 id=\"tiers\">Precision and recall by tier</h2><div class=\"tier-grid\">");
    for t in &s.tiers {
        let tier = t.tier.label();
        let _ = write!(
            o,
            "<article class=\"card tier-card\"><h3>{} or above</h3>\
<dl class=\"stats\"><div><dt>Precision</dt><dd class=\"big\">{}</dd><dd class=\"hint\">95% CI {} · {} of {} flagged</dd></div>\
<div><dt>Recall</dt><dd class=\"big\">{}</dd><dd class=\"hint\">95% CI {} · {} of {} agent records</dd></div></dl>\
<table class=\"confusion\"><caption>Confusion matrix, {} or above</caption>\
<thead><tr><td></td><th scope=\"col\">Flagged</th><th scope=\"col\">Not flagged</th></tr></thead>\
<tbody><tr><th scope=\"row\">Agent</th><td class=\"tp\">{} <span>true positive</span></td><td class=\"fn\">{} <span>false negative</span></td></tr>\
<tr><th scope=\"row\">Benign</th><td class=\"fp\">{} <span>false positive</span></td><td class=\"tn\">{} <span>true negative</span></td></tr></tbody></table></article>",
            esc(tier),
            pc(&t.precision),
            ci(&t.precision),
            t.precision.k,
            t.precision.n,
            pc(&t.recall),
            ci(&t.recall),
            t.recall.k,
            t.recall.n,
            esc(tier),
            t.tp,
            t.fn_,
            t.fp,
            t.tn
        );
    }
    o.push_str("</div></section>\n");

    // Hits per rule: agent records and benign records, on one scale.
    let mut rules: Vec<_> = s.rules.iter().filter(|x| x.tp + x.fp > 0).collect();
    rules.sort_by(|a, b| {
        (b.tp + b.fp)
            .cmp(&(a.tp + a.fp))
            .then(a.rule_id.cmp(&b.rule_id))
    });
    let max = rules
        .iter()
        .map(|x| (x.tp + x.fp) as f64)
        .fold(0.0, f64::max);
    let rows: Vec<BarRow> = rules
        .iter()
        .map(|x| BarRow {
            label: x.rule_id.clone(),
            segments: vec![(x.tp as f64, "s-agent"), (x.fp as f64, "s-benign")],
            note: format!(
                "{} / {}{}",
                x.tp,
                x.fp,
                x.precision
                    .value
                    .map(|p| format!(" · {:.0}%", p * 100.0))
                    .unwrap_or_default()
            ),
        })
        .collect();
    let c = &s.coverage;
    let _ = write!(
        o,
        "<section aria-labelledby=\"per-rule\"><h2 id=\"per-rule\">Hits per rule</h2>\
<p class=\"hint\">Labelled records each rule matched, agent then benign, with the rule's own precision. A rule with benign hits is a candidate for a lower weight. Coverage: {} of {} rules have an agent example{}{}.</p>\
<p class=\"legend\"><span><span class=\"key s-agent\"></span>agent records</span> <span><span class=\"key s-benign\"></span>benign records</span></p>\
<figure class=\"chart-box\">{}</figure>",
        c.covered,
        c.rules,
        if c.allowed > 0 {
            format!(", {} more are allowed to go without one", c.allowed)
        } else {
            String::new()
        },
        if c.uncovered.is_empty() {
            String::new()
        } else {
            format!(
                "; without one: {}",
                c.uncovered
                    .iter()
                    .map(|r| esc(r))
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        },
        hbars(
            &rows,
            max,
            "Labelled records matched per rule, agent and benign",
            240.0
        )
    );
    let trows: Vec<Vec<String>> = s
        .rules
        .iter()
        .map(|x| {
            vec![
                format!("<code>{}</code>", esc(&x.rule_id)),
                esc(&x
                    .tactics
                    .iter()
                    .map(|t| tactic_label(t))
                    .collect::<Vec<_>>()
                    .join(", ")),
                x.tp.to_string(),
                x.fp.to_string(),
                format!(
                    "{} <span class=\"hint\">{}</span>",
                    pc(&x.precision),
                    ci(&x.precision)
                ),
                if x.hard_negatives > 0 {
                    format!("{}/{}", x.hard_negatives_fired, x.hard_negatives)
                } else {
                    "–".into()
                },
                if x.covered {
                    "yes".into()
                } else {
                    x.allowed
                        .as_deref()
                        .map_or_else(|| "no".into(), |r| format!("allowed: {}", esc(r)))
                },
            ]
        })
        .collect();
    let _ = writeln!(
        o,
        "<details class=\"as-table\"><summary>View as table (every rule)</summary>{}</details></section>",
        table(
            "",
            &[
                "Rule",
                "Tactic",
                "Agent",
                "Benign",
                "Precision",
                "Hard negatives fired",
                "Agent example"
            ],
            &trows
        )
    );

    recall_section(
        &mut o,
        "per-class",
        "Recall by class",
        "Agent records of each labelled class, by the tier the rules gave them. A class the rules cannot see from one record shows as missed rather than dragging down one averaged number.",
        &s.agent_classes,
        |n| n.to_string(),
    );
    recall_section(
        &mut o,
        "per-tactic",
        "Recall by tactic",
        "Agent records grouped by the tactic of the rules that fired on them (a record counts under each tactic it touches). It shows how strongly each tactic's evidence scores; what the rules miss is under no rule fired.",
        &s.tactics,
        |n| match n {
            "no_rule_fired" => "no rule fired".into(),
            "untagged" => "untagged rules".into(),
            t => tactic_label(t),
        },
    );

    if !s.benign_classes.is_empty() {
        let rows: Vec<Vec<String>> = s
            .benign_classes
            .iter()
            .map(|b| {
                vec![
                    esc(&b.name),
                    b.n.to_string(),
                    format!(
                        "{} {} <span class=\"hint\">{}</span>",
                        b.suggestive.k,
                        pc(&b.suggestive),
                        ci(&b.suggestive)
                    ),
                    format!(
                        "{} {} <span class=\"hint\">{}</span>",
                        b.significant.k,
                        pc(&b.significant),
                        ci(&b.significant)
                    ),
                ]
            })
            .collect();
        let _ = writeln!(
            o,
            "<section aria-labelledby=\"benign\"><h2 id=\"benign\">False positives by benign class</h2>\
<p class=\"hint\">Benign records of each class the rules flagged, with the rate and its interval. Hard negatives are benign records written to sit next to a rule's pattern.</p>{}</section>",
            table(
                "",
                &[
                    "Class",
                    "Records",
                    "Flagged suggestive or above",
                    "Flagged significant"
                ],
                &rows
            )
        );
    }

    let cl = &s.clusters;
    let merges: Vec<Vec<String>> = cl
        .false_merges
        .iter()
        .map(|m| {
            vec![
                format!("<code>{}</code>", esc(&m.cluster)),
                m.members.to_string(),
                esc(&m.runs.join(", ")),
                if m.mixes_labels { "yes" } else { "no" }.into(),
            ]
        })
        .collect();
    let _ = write!(
        o,
        "<section aria-labelledby=\"linking\"><h2 id=\"linking\">Linking</h2>\
<p class=\"hint\">Records labelled with the run they belong to measure how well clusters recover runs. Reported, never gated.</p>\
<dl class=\"stats wide\"><div><dt>B-cubed precision</dt><dd class=\"big\">{}</dd></div><div><dt>B-cubed recall</dt><dd class=\"big\">{}</dd></div><div><dt>B-cubed F1</dt><dd class=\"big\">{}</dd></div><div><dt>False merges</dt><dd class=\"big\">{}</dd><dd class=\"hint\">{} of {} clusters with labelled members</dd></div></dl>\
<p class=\"hint\">{} run-labelled records in {} runs. Runs split across clusters: {}.</p>",
        opt(cl.bcubed_precision),
        opt(cl.bcubed_recall),
        opt(cl.bcubed_f1),
        opt(cl.false_merge_rate),
        cl.false_merges.len(),
        cl.clusters_checked,
        cl.run_labelled,
        cl.runs,
        if cl.false_splits.is_empty() {
            "none".to_string()
        } else {
            esc(&cl.false_splits.join(", "))
        },
    );
    if !merges.is_empty() {
        o.push_str(&table(
            "",
            &[
                "Cluster",
                "Members",
                "Runs joined",
                "Mixes agent and benign",
            ],
            &merges,
        ));
    }
    o.push_str("</section>\n");

    o.push_str(
        "<section class=\"card\" aria-labelledby=\"live\"><h2 id=\"live\">Recompute with edited rules</h2>\
<p class=\"hint\">Scores the bundled rules and the rules edited on the <a href=\"../rules/#edit\">rules page</a> (kept in this browser) side by side, in this page, and lists the records whose tier changed. Nothing leaves the browser.</p>\
<div class=\"row\"><button type=\"button\" class=\"primary\" data-act=\"recompute\">Recompute</button><span class=\"hint\" data-engine-status aria-live=\"polite\"></span><span class=\"hint\" id=\"rules-source\"></span></div>\
<div id=\"eval-out\" class=\"detail\"></div></section>\n",
    );
    o
}

fn recall_section(
    o: &mut String,
    id: &str,
    title: &str,
    hint: &str,
    rows: &[sc_core::eval::summary::RecallRow],
    name: impl Fn(&str) -> String,
) {
    if rows.is_empty() {
        return;
    }
    let bars: Vec<BarRow> = rows
        .iter()
        .map(|r| BarRow {
            label: name(&r.name),
            segments: vec![
                (r.significant.k as f64, "s-sig"),
                (
                    r.suggestive.k.saturating_sub(r.significant.k) as f64,
                    "s-sug",
                ),
                (r.n.saturating_sub(r.suggestive.k) as f64, "s-miss"),
            ],
            note: format!("{} of {}", r.suggestive.k, r.n),
        })
        .collect();
    let max = rows.iter().map(|r| r.n as f64).fold(0.0, f64::max);
    let trows: Vec<Vec<String>> = rows
        .iter()
        .map(|r| {
            vec![
                esc(&name(&r.name)),
                r.n.to_string(),
                format!(
                    "{} <span class=\"hint\">{}</span>",
                    pc(&r.suggestive),
                    ci(&r.suggestive)
                ),
                format!(
                    "{} <span class=\"hint\">{}</span>",
                    pc(&r.significant),
                    ci(&r.significant)
                ),
            ]
        })
        .collect();
    let _ = writeln!(
        o,
        "<section aria-labelledby=\"{id}\"><h2 id=\"{id}\">{}</h2><p class=\"hint\">{}</p>\
<p class=\"legend\"><span><span class=\"key s-sig\"></span>significant</span> <span><span class=\"key s-sug\"></span>suggestive</span> <span><span class=\"key s-miss\"></span>missed (noise)</span></p>\
<figure class=\"chart-box\">{}</figure><details class=\"as-table\"><summary>View as table</summary>{}</details></section>",
        esc(title),
        esc(hint),
        hbars(&bars, max, title, 230.0),
        table(
            "",
            &[
                "Name",
                "Agent records",
                "Recall, suggestive or above",
                "Recall, significant"
            ],
            &trows
        )
    );
}
