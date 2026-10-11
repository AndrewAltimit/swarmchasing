//! The evaluation dashboard, from `sc_core::summarize` over the committed
//! labelled set with the bundled rules, computed at build time: precision
//! and recall per tier with Wilson intervals, the confusion matrices, hits
//! and coverage per rule, recall per class and per tactic, false positives
//! per benign class, and the cluster-level numbers. Each tier card puts the
//! non-synthetic records beside all records, and forest plots show every
//! slice the summary carries (record and cluster units, synthetic or not,
//! by provenance, source and file) with its interval; a slice the summary
//! does not carry is left out. The page recomputes the tier numbers in the
//! browser with edited rules.

use super::html::{esc, table};
use super::rules::tactic_label;
use super::svg::{BarRow, hbars};
use sc_core::Summary;
use sc_core::eval::stats::Proportion;
use sc_core::eval::summary::TierSummary;
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
<tr><th scope=\"row\">Benign</th><td class=\"fp\">{} <span>false positive</span></td><td class=\"tn\">{} <span>true negative</span></td></tr></tbody></table>{}</article>",
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
            t.tn,
            non_synthetic_block(s, t)
        );
    }
    o.push_str("</div></section>\n");
    o.push_str(&forest_section(s));

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

/// The same tier on the records that are not synthetic, as prominent as
/// the numbers above it, or nothing when the summary has none.
fn non_synthetic_block(s: &Summary, t: &TierSummary) -> String {
    let ns = &s.non_synthetic;
    let Some(n) = ns.tiers.iter().find(|x| x.tier == t.tier) else {
        return String::new();
    };
    if ns.labelled == 0 {
        return String::new();
    }
    format!(
        "<div class=\"non-synthetic\"><h4>Non-synthetic records only ({} labelled: {} agent, {} benign)</h4>\
<dl class=\"stats\"><div><dt>Precision</dt><dd class=\"big\">{}</dd><dd class=\"hint\">95% CI {} · {} of {}</dd></div>\
<div><dt>Recall</dt><dd class=\"big\">{}</dd><dd class=\"hint\">95% CI {} · {} of {}</dd></div></dl></div>",
        ns.labelled,
        ns.agents,
        ns.benign,
        pc(&n.precision),
        ci(&n.precision),
        n.precision.k,
        n.precision.n,
        pc(&n.recall),
        ci(&n.recall),
        n.recall.k,
        n.recall.n
    )
}

/// One row of a forest plot: a label and a proportion with its interval.
struct ForestRow {
    group: String,
    label: String,
    p: Proportion,
}

/// A forest plot: a point and its 95% interval per row, 0 to 100%.
fn forest(rows: &[ForestRow], title: &str) -> String {
    let (w, rh, l, r, t) = (960.0, 22.0, 330.0, 150.0, 26.0);
    let h = t + 8.0 + rh * rows.len() as f64;
    let x = |v: f64| l + v.clamp(0.0, 1.0) * (w - l - r);
    let mut s = format!(
        "<svg class=\"chart forest\" viewBox=\"0 0 {w} {h}\" role=\"img\" aria-label=\"{0}\"><title>{0}</title><g class=\"grid\">",
        esc(title)
    );
    for i in 0..=4 {
        let v = i as f64 / 4.0;
        let _ = write!(
            s,
            "<line x1=\"{0:.1}\" x2=\"{0:.1}\" y1=\"{1}\" y2=\"{2:.1}\"/>",
            x(v),
            t - 6.0,
            h - 4.0
        );
    }
    s.push_str("</g><g class=\"axis\">");
    for i in 0..=4 {
        let v = i as f64 / 4.0;
        let _ = write!(
            s,
            "<text x=\"{:.1}\" y=\"14\" text-anchor=\"middle\">{}%</text>",
            x(v),
            i * 25
        );
    }
    s.push_str("</g>");
    let mut last = "";
    for (i, row) in rows.iter().enumerate() {
        let y = t + rh * i as f64 + rh / 2.0;
        if row.group != last {
            last = &row.group;
            if i > 0 {
                let _ = write!(
                    s,
                    "<line class=\"sep\" x1=\"8\" x2=\"{:.1}\" y1=\"{1:.1}\" y2=\"{1:.1}\"/>",
                    w - 8.0,
                    y - rh / 2.0
                );
            }
        }
        let _ = write!(
            s,
            "<text class=\"label\" x=\"{:.1}\" y=\"{:.1}\" text-anchor=\"end\">{}</text>",
            l - 12.0,
            y + 4.0,
            esc(&format!("{} · {}", row.group, row.label))
        );
        if let (Some(v), Some(lo), Some(hi)) = (row.p.value, row.p.lo, row.p.hi) {
            let _ = write!(
                s,
                "<line class=\"ci\" x1=\"{:.1}\" x2=\"{:.1}\" y1=\"{y:.1}\" y2=\"{y:.1}\"/>\
<line class=\"ci\" x1=\"{0:.1}\" x2=\"{0:.1}\" y1=\"{2:.1}\" y2=\"{3:.1}\"/><line class=\"ci\" x1=\"{1:.1}\" x2=\"{1:.1}\" y1=\"{2:.1}\" y2=\"{3:.1}\"/>\
<circle class=\"pt\" cx=\"{4:.1}\" cy=\"{y:.1}\" r=\"4.5\"><title>{5}</title></circle>",
                x(lo),
                x(hi),
                y - 5.0,
                y + 5.0,
                x(v),
                esc(&format!(
                    "{} · {}: {} (95% CI {}), {} of {}",
                    row.group,
                    row.label,
                    pc(&row.p),
                    ci(&row.p),
                    row.p.k,
                    row.p.n
                ))
            );
        }
        let _ = write!(
            s,
            "<text class=\"note\" x=\"{:.1}\" y=\"{:.1}\">{} · n={}</text>",
            w - r + 10.0,
            y + 4.0,
            esc(&pc(&row.p)),
            row.p.n
        );
    }
    s.push_str("</svg>");
    s
}

/// The slices the summary carries, as (name, record-unit tiers,
/// cluster-unit tiers); empty ones left out.
fn slices(s: &Summary) -> Vec<(String, &[TierSummary], &[TierSummary])> {
    let mut out: Vec<(String, &[TierSummary], &[TierSummary])> =
        vec![("All records".into(), &s.tiers, &s.cluster_tiers)];
    if s.non_synthetic.labelled > 0 {
        out.push((
            "Non-synthetic".into(),
            &s.non_synthetic.tiers,
            &s.non_synthetic.cluster_tiers,
        ));
    }
    for (kind, list) in [
        ("provenance", &s.by_provenance),
        ("source", &s.by_source),
        ("file", &s.by_file),
    ] {
        for x in list.iter().filter(|x| x.labelled > 0) {
            out.push((format!("{kind}: {}", x.name), &x.tiers, &x.cluster_tiers));
        }
    }
    out
}

fn forest_rows(
    s: &Summary,
    pick: impl Fn(&TierSummary) -> &Proportion,
    cluster: bool,
) -> Vec<ForestRow> {
    let mut rows = Vec::new();
    for (name, rec, cl) in slices(s) {
        let tiers = if cluster { cl } else { rec };
        for t in tiers {
            let p = pick(t);
            if p.n > 0 {
                rows.push(ForestRow {
                    group: name.clone(),
                    label: format!("{} or above", t.tier.label()),
                    p: p.clone(),
                });
            }
        }
    }
    rows
}

fn forest_section(s: &Summary) -> String {
    let mut o = String::from(
        "<section aria-labelledby=\"forest\"><h2 id=\"forest\">Every slice, with its interval</h2>\
<p class=\"hint\">Each point is a rate and each bar its 95% Wilson interval, so a slice with few records shows a wide bar. Synthetic records were written to match the rules; the non-synthetic rows are the closer guide to real data. The record unit counts every flagged record; the cluster unit counts each cluster once.</p>",
    );
    let mut any = false;
    for (unit, cluster) in [("record unit", false), ("cluster unit", true)] {
        for (what, prec) in [("Precision", true), ("Recall", false)] {
            let rows = forest_rows(s, |t| if prec { &t.precision } else { &t.recall }, cluster);
            if rows.is_empty() {
                continue;
            }
            any = true;
            let title = format!("{what}, {unit}");
            let trows: Vec<Vec<String>> = rows
                .iter()
                .map(|r| {
                    vec![
                        esc(&r.group),
                        esc(&r.label),
                        pc(&r.p),
                        ci(&r.p),
                        format!("{} of {}", r.p.k, r.p.n),
                    ]
                })
                .collect();
            let _ = write!(
                o,
                "<h3>{}</h3><figure class=\"chart-box scroll-x\">{}</figure><details class=\"as-table\"><summary>View as table</summary>{}</details>",
                esc(&title),
                forest(&rows, &title),
                table(
                    "",
                    &["Slice", "Threshold", "Rate", "95% CI", "Count"],
                    &trows
                )
            );
        }
    }
    let cal = &s.calibration;
    for (title, list) in [
        ("Precision at each record tier", &cal.by_tier),
        ("Precision at each agent grade", &cal.by_agent_level),
    ] {
        let rows: Vec<ForestRow> = list
            .iter()
            .filter(|r| r.precision.n > 0)
            .map(|r| ForestRow {
                group: "calibration".into(),
                label: r.name.clone(),
                p: r.precision.clone(),
            })
            .collect();
        if rows.is_empty() {
            continue;
        }
        any = true;
        let _ = write!(
            o,
            "<h3>{}</h3><p class=\"hint\">The share of agent records among records at exactly this {}: how far each step can be trusted.</p><figure class=\"chart-box scroll-x\">{}</figure>",
            esc(title),
            if title.contains("grade") {
                "grade (records graded by their cluster; unmeasured on held-out data)"
            } else {
                "tier"
            },
            forest(&rows, title)
        );
    }
    o.push_str("</section>\n");
    if any { o } else { String::new() }
}
