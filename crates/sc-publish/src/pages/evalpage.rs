//! The evaluation dashboard, computed at build time from the committed
//! labelled set with the bundled rules: precision and recall per tier with
//! Wilson intervals, the confusion matrices, hits per rule and recall per
//! class. The page recomputes it in the browser with edited rules.

use super::html::{esc, pct, table, wilson};
use super::svg::{BarRow, hbars};
use sc_core::eval::EvalReport;
use std::fmt::Write;

fn interval(k: usize, n: usize) -> String {
    match wilson(k, n) {
        Some((lo, hi)) => format!("{:.1}–{:.1}%", lo * 100.0, hi * 100.0),
        None => "n/a".into(),
    }
}

/// The dashboard body. `files` names the labelled files.
pub fn body(r: &EvalReport, files: &[String]) -> String {
    let mut s = String::new();
    let _ = writeln!(
        s,
        "<header class=\"page-head\"><h1>Evaluation</h1>\
<p class=\"lede\">How the bundled rules (version <code>{}</code>) score on the committed labelled set: {} labelled records, {} agent and {} benign, from {}. The numbers are computed when the site is built.</p>\
<p class=\"callout\" role=\"note\"><strong>A regression floor, not a precision estimate.</strong> The rules were written and tuned against these records, and <code>eval</code> scores records, not clusters: a cluster of ten flagged records counts ten times. Real-world precision is lower. The intervals are 95% Wilson score intervals over records. See <a href=\"../docs/reference/evaluation/\">evaluation</a> for the held-out measurement.</p></header>",
        esc(&r.rules_version),
        r.labelled,
        r.agents,
        r.benign,
        esc(&files.join(", ")),
    );
    s.push_str("<section aria-labelledby=\"tiers\"><h2 id=\"tiers\">Precision and recall by tier</h2><div class=\"tier-grid\">");
    for t in &r.thresholds {
        let tier = t.tier.label();
        let flagged = t.tp + t.fp;
        let agents = t.tp + t.fn_;
        let _ = write!(
            s,
            "<article class=\"card tier-card\"><h3>{} or above</h3>\
<dl class=\"stats\"><div><dt>Precision</dt><dd class=\"big\">{}</dd><dd class=\"hint\">95% CI {} · {} of {} flagged</dd></div>\
<div><dt>Recall</dt><dd class=\"big\">{}</dd><dd class=\"hint\">95% CI {} · {} of {} agent records</dd></div></dl>",
            esc(tier),
            pct(t.precision),
            interval(t.tp, flagged),
            t.tp,
            flagged,
            pct(t.recall),
            interval(t.tp, agents),
            t.tp,
            agents,
        );
        let _ = write!(
            s,
            "<table class=\"confusion\"><caption>Confusion matrix, {} or above</caption>\
<thead><tr><td></td><th scope=\"col\">Flagged</th><th scope=\"col\">Not flagged</th></tr></thead>\
<tbody><tr><th scope=\"row\">Agent</th><td class=\"tp\">{} <span>true positive</span></td><td class=\"fn\">{} <span>false negative</span></td></tr>\
<tr><th scope=\"row\">Benign</th><td class=\"fp\">{} <span>false positive</span></td><td class=\"tn\">{} <span>true negative</span></td></tr></tbody></table></article>",
            esc(tier),
            t.tp,
            t.fn_,
            t.fp,
            t.tn
        );
    }
    s.push_str("</div></section>\n");

    // Hits per rule: agent records and benign records, on one scale.
    let mut rules: Vec<_> = r
        .rules
        .iter()
        .filter(|x| x.on_agent + x.on_benign > 0)
        .collect();
    rules.sort_by(|a, b| {
        (b.on_agent + b.on_benign)
            .cmp(&(a.on_agent + a.on_benign))
            .then(a.rule_id.cmp(&b.rule_id))
    });
    let max = rules
        .iter()
        .map(|x| (x.on_agent + x.on_benign) as f64)
        .fold(0.0, f64::max);
    let rows: Vec<BarRow> = rules
        .iter()
        .map(|x| BarRow {
            label: x.rule_id.clone(),
            segments: vec![
                (x.on_agent as f64, "s-agent"),
                (x.on_benign as f64, "s-benign"),
            ],
            note: format!(
                "{} / {}{}",
                x.on_agent,
                x.on_benign,
                x.precision
                    .map(|p| format!(" · {:.0}%", p * 100.0))
                    .unwrap_or_default()
            ),
        })
        .collect();
    let _ = write!(
        s,
        "<section aria-labelledby=\"per-rule\"><h2 id=\"per-rule\">Hits per rule</h2>\
<p class=\"hint\">Labelled records each rule matched, agent then benign, with the rule's own precision. A rule with benign hits is a candidate for a lower weight.</p>\
<p class=\"legend\"><span class=\"key s-agent\"></span>agent records <span class=\"key s-benign\"></span>benign records</p>\
<figure class=\"chart-box\">{}</figure>",
        hbars(
            &rows,
            max,
            "Labelled records matched per rule, agent and benign",
            240.0
        )
    );
    let trows: Vec<Vec<String>> = rules
        .iter()
        .map(|x| {
            vec![
                format!("<code>{}</code>", esc(&x.rule_id)),
                x.on_agent.to_string(),
                x.on_benign.to_string(),
                pct(x.precision),
            ]
        })
        .collect();
    let _ = writeln!(
        s,
        "<details class=\"as-table\"><summary>View as table</summary>{}</details></section>",
        table("", &["Rule", "Agent", "Benign", "Precision"], &trows)
    );

    // Recall per class.
    if !r.classes.is_empty() {
        let rows: Vec<BarRow> = r
            .classes
            .iter()
            .map(|c| BarRow {
                label: c.class.clone(),
                segments: vec![
                    (c.significant as f64, "s-sig"),
                    ((c.suggestive_or_above - c.significant) as f64, "s-sug"),
                    ((c.agents - c.suggestive_or_above) as f64, "s-miss"),
                ],
                note: format!("{} of {}", c.suggestive_or_above, c.agents),
            })
            .collect();
        let max = r
            .classes
            .iter()
            .map(|c| c.agents as f64)
            .fold(0.0, f64::max);
        let _ = write!(
            s,
            "<section aria-labelledby=\"per-class\"><h2 id=\"per-class\">Recall by class</h2>\
<p class=\"hint\">Agent records of each labelled class, by the tier the rules gave them. A class the rules cannot see from one record shows as missed rather than dragging down one averaged number.</p>\
<p class=\"legend\"><span class=\"key s-sig\"></span>significant <span class=\"key s-sug\"></span>suggestive <span class=\"key s-miss\"></span>missed (noise)</p>\
<figure class=\"chart-box\">{}</figure>",
            hbars(&rows, max, "Agent records per class by tier", 200.0)
        );
        let trows: Vec<Vec<String>> = r
            .classes
            .iter()
            .map(|c| {
                vec![
                    esc(&c.class),
                    c.agents.to_string(),
                    c.suggestive_or_above.to_string(),
                    c.significant.to_string(),
                    pct((c.agents > 0).then(|| c.suggestive_or_above as f64 / c.agents as f64)),
                ]
            })
            .collect();
        let _ = writeln!(
            s,
            "<details class=\"as-table\"><summary>View as table</summary>{}</details></section>",
            table(
                "",
                &[
                    "Class",
                    "Agent records",
                    "Suggestive or above",
                    "Significant",
                    "Recall"
                ],
                &trows
            )
        );
    }

    s.push_str(
        "<section class=\"card\" aria-labelledby=\"live\"><h2 id=\"live\">Recompute with edited rules</h2>\
<p class=\"hint\">Scores the bundled rules and the rules edited on the <a href=\"../rules/#edit\">rules page</a> (kept in this browser) side by side, in this page, and lists the records whose tier changed. Nothing leaves the browser.</p>\
<div class=\"row\"><button type=\"button\" class=\"primary\" data-act=\"recompute\" data-needs-engine-lazy>Recompute</button><span class=\"hint\" data-engine-status aria-live=\"polite\"></span><span class=\"hint\" id=\"rules-source\"></span></div>\
<div id=\"eval-out\" class=\"detail\"></div></section>\n",
    );
    s
}
