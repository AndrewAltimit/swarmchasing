//! Static SVG figures for the landing page's walk through the method: the
//! layers of one URL, a record's score against the thresholds, clusters and
//! the hints between them, runs and their interaction hints, the
//! agent-likelihood ladder, attribution layers, and the disclosure clock.
//!
//! Like [`super::svg`]: attributes only, no `style`, every label escaped.
//! Each figure stands on its own without JavaScript; the page script only
//! adds a live re-run.

use super::html::{esc, slug_class};
use std::fmt::Write;

/// `text` cut to `n` characters, with an ellipsis when cut.
fn cut(text: &str, n: usize) -> String {
    if text.chars().count() <= n {
        text.to_string()
    } else {
        let mut s: String = text.chars().take(n.saturating_sub(1)).collect();
        s.push('…');
        s
    }
}

fn open(class: &str, w: f64, h: f64, label: &str) -> String {
    format!(
        "<svg class=\"chart {class}\" viewBox=\"0 0 {w} {h}\" role=\"img\" aria-label=\"{0}\"><title>{0}</title>",
        esc(label)
    )
}

/// One layer of a URL: how it was found, its depth, its text (defanged).
pub struct UrlLayer {
    pub via: String,
    pub depth: usize,
    pub text: String,
}

/// The layers of one URL as nested boxes, outermost first.
pub fn layer_stack(layers: &[UrlLayer], label: &str) -> String {
    let (w, rh, gap, pad) = (720.0, 46.0, 8.0, 18.0);
    let h = pad + layers.len() as f64 * (rh + gap);
    let mut s = open("layers-fig", w, h, label);
    for (i, l) in layers.iter().enumerate() {
        let x = 8.0 + 22.0 * l.depth.min(6) as f64;
        let y = 8.0 + i as f64 * (rh + gap);
        let bw = w - x - 8.0;
        let chars = ((bw - 24.0) / 7.4).max(10.0) as usize;
        let _ = write!(
            s,
            "<rect class=\"lbox d{}\" x=\"{x:.1}\" y=\"{y:.1}\" width=\"{bw:.1}\" height=\"{rh}\" rx=\"6\"/>\
<text class=\"via\" x=\"{:.1}\" y=\"{:.1}\">{} · layer {}</text>\
<text class=\"mono\" x=\"{:.1}\" y=\"{:.1}\">{}</text>",
            l.depth.min(6),
            x + 12.0,
            y + 17.0,
            esc(&l.via),
            i,
            x + 12.0,
            y + 36.0,
            esc(&cut(&l.text, chars))
        );
        if i + 1 < layers.len() {
            let nx = 8.0 + 22.0 * layers[i + 1].depth.min(6) as f64;
            let _ = write!(
                s,
                "<path class=\"arrow\" d=\"M{:.1},{:.1} V{:.1} H{:.1}\"/>",
                x + 6.0,
                y + rh,
                y + rh + gap / 2.0 + 2.0,
                nx + 6.0
            );
        }
    }
    s.push_str("</svg>");
    s
}

/// A record's rule hits as one stacked bar against the two thresholds.
/// `hits`: (rule id, weight).
pub fn score_bar(hits: &[(String, i32)], suggestive: i32, significant: i32, label: &str) -> String {
    let total: i32 = hits.iter().map(|h| h.1.max(0)).sum();
    let max = (total.max(significant) as f64 * 1.15).max(1.0);
    let (w, l, r) = (720.0, 12.0, 12.0);
    let rows = hits.len().div_ceil(2);
    let h = 96.0 + rows as f64 * 20.0;
    let x = |v: f64| l + v / max * (w - l - r);
    let mut s = open("score-fig", w, h, label);
    let _ = write!(
        s,
        "<rect class=\"track\" x=\"{l}\" y=\"30\" width=\"{:.1}\" height=\"26\" rx=\"5\"/>",
        w - l - r
    );
    let mut at = 0.0;
    for (i, (id, wt)) in hits.iter().enumerate() {
        let v = (*wt).max(0) as f64;
        if v <= 0.0 {
            continue;
        }
        let (x0, x1) = (x(at), x(at + v));
        let _ = write!(
            s,
            "<rect class=\"seg s{}\" x=\"{:.1}\" y=\"30\" width=\"{:.1}\" height=\"26\" rx=\"3\"><title>{} +{wt}</title></rect>",
            i % 3 + 1,
            x0 + if i > 0 { 1.0 } else { 0.0 },
            (x1 - x0 - if i > 0 { 1.0 } else { 0.0 }).max(1.0),
            esc(id)
        );
        if x1 - x0 > 26.0 {
            let _ = write!(
                s,
                "<text class=\"seg-v\" x=\"{:.1}\" y=\"47\" text-anchor=\"middle\">+{wt}</text>",
                (x0 + x1) / 2.0
            );
        }
        at += v;
    }
    for (v, name, cls) in [
        (suggestive, "suggestive", "th-sug"),
        (significant, "significant", "th-sig"),
    ] {
        let tx = x(v as f64);
        let _ = write!(
            s,
            "<line class=\"threshold {cls}\" x1=\"{tx:.1}\" x2=\"{tx:.1}\" y1=\"20\" y2=\"64\"/>\
<text x=\"{tx:.1}\" y=\"14\" text-anchor=\"middle\">{name} ≥ {v}</text>"
        );
    }
    let _ = write!(
        s,
        "<text class=\"label\" x=\"{:.1}\" y=\"78\" text-anchor=\"end\">score {total}</text>",
        w - r
    );
    for (i, (id, wt)) in hits.iter().enumerate() {
        let (col, row) = (i % 2, i / 2);
        let kx = l + col as f64 * 360.0;
        let ky = 92.0 + row as f64 * 20.0;
        let _ = write!(
            s,
            "<rect class=\"seg s{}\" x=\"{kx:.1}\" y=\"{:.1}\" width=\"10\" height=\"10\" rx=\"2\"/>\
<text class=\"mono-sm\" x=\"{:.1}\" y=\"{:.1}\">{} +{wt}</text>",
            i % 3 + 1,
            ky - 9.0,
            kx + 16.0,
            ky,
            esc(&cut(id, 40))
        );
    }
    s.push_str("</svg>");
    s
}

/// A node of a cluster graph.
pub struct GNode {
    pub label: String,
    pub tier: String,
    pub size: usize,
}

/// A hint between two nodes: indexes, an edge class and a label.
pub struct GEdge {
    pub a: usize,
    pub b: usize,
    pub class: String,
    pub label: String,
}

/// Clusters on a circle (in the order given), area by record count, with
/// the hints between them.
pub fn cluster_graph(nodes: &[GNode], edges: &[GEdge], label: &str) -> String {
    let (w, h) = (720.0, 380.0);
    let (cx, cy, rad) = (w / 2.0, h / 2.0, h / 2.0 - 46.0);
    let max = nodes.iter().map(|n| n.size).max().unwrap_or(1).max(1) as f64;
    let n = nodes.len().max(1) as f64;
    let pos: Vec<(f64, f64, f64)> = nodes
        .iter()
        .enumerate()
        .map(|(i, nd)| {
            let a = i as f64 / n * std::f64::consts::TAU - std::f64::consts::FRAC_PI_2;
            let r = if nodes.len() == 1 { 0.0 } else { rad };
            (
                cx + r * 1.45 * a.cos(),
                cy + r * a.sin(),
                7.0 + 15.0 * (nd.size as f64 / max).sqrt(),
            )
        })
        .collect();
    let mut s = open("fleet", w, h, label);
    let mut seen: Vec<(usize, usize)> = Vec::new();
    for e in edges {
        let (Some(p), Some(q)) = (pos.get(e.a), pos.get(e.b)) else {
            continue;
        };
        let pair = (e.a.min(e.b), e.a.max(e.b));
        let k = seen.iter().filter(|x| **x == pair).count() as f64;
        seen.push(pair);
        let (mx, my) = ((p.0 + q.0) / 2.0, (p.1 + q.1) / 2.0);
        let (dx, dy) = (q.0 - p.0, q.1 - p.1);
        let len = dx.hypot(dy).max(1.0);
        let bow = if k == 0.0 {
            0.0
        } else {
            (if k as usize % 2 == 1 { -1.0 } else { 1.0 }) * (k / 2.0).ceil() * 16.0
        };
        let _ = write!(
            s,
            "<path class=\"edge {}\" d=\"M{:.1},{:.1} Q{:.1},{:.1} {:.1},{:.1}\"><title>{}</title></path>",
            esc(&e.class),
            p.0,
            p.1,
            mx - dy / len * bow,
            my + dx / len * bow,
            q.0,
            q.1,
            esc(&e.label)
        );
    }
    for (nd, p) in nodes.iter().zip(&pos) {
        let below = if p.1 > cy { 1.0 } else { -1.0 };
        let _ = write!(
            s,
            "<circle class=\"node tier-{}\" cx=\"{:.1}\" cy=\"{:.1}\" r=\"{:.1}\"><title>{}: {}, {} records</title></circle>\
<text class=\"node-label\" x=\"{:.1}\" y=\"{:.1}\" text-anchor=\"middle\">{}</text>",
            esc(&slug_class(&nd.tier)),
            p.0,
            p.1,
            p.2,
            esc(&nd.label),
            esc(&nd.tier),
            nd.size,
            p.0,
            p.1 + below * (p.2 + 12.0) + if below > 0.0 { 0.0 } else { 4.0 },
            esc(&nd.label)
        );
    }
    s.push_str("</svg>");
    s
}

/// A run in the swarm figure: its lane (cluster), time and label.
pub struct RunNode {
    pub lane: usize,
    pub t: i64,
    pub label: String,
}

/// An interaction hint between two runs: kind id (`shared_sink`), strength
/// (`weak`), label.
pub struct RunEdge {
    pub a: usize,
    pub b: usize,
    pub kind: String,
    pub strength: String,
    pub label: String,
}

/// Runs on a time axis, a lane per cluster, interaction hints as arcs.
/// `lanes`: (label, tier).
pub fn swarm_arcs(
    lanes: &[(String, String)],
    nodes: &[RunNode],
    edges: &[RunEdge],
    label: &str,
) -> String {
    let t0 = nodes.iter().map(|n| n.t).min().unwrap_or(0);
    let t1 = nodes.iter().map(|n| n.t).max().unwrap_or(1);
    let span = (t1 - t0).max(60) as f64;
    let (w, lh, l, r, t, b) = (960.0, 44.0, 64.0, 24.0, 40.0, 28.0);
    let h = t + b + lh * lanes.len().max(1) as f64;
    let x = |v: i64| l + 12.0 + (v - t0) as f64 / span * (w - l - r - 24.0);
    let y = |lane: usize| t + lh * lane as f64 + lh / 2.0;
    // Nodes at one place (strands of one run) fan out.
    let mut pos: Vec<(f64, f64)> = Vec::with_capacity(nodes.len());
    for (i, n) in nodes.iter().enumerate() {
        let same = nodes[..i]
            .iter()
            .filter(|m| m.lane == n.lane && (x(m.t) - x(n.t)).abs() < 8.0)
            .count();
        let off = if same == 0 {
            0.0
        } else {
            (if same % 2 == 1 { 1.0 } else { -1.0 }) * (same as f64 / 2.0).ceil() * 18.0
        };
        pos.push((x(n.t) + off, y(n.lane)));
    }
    let mut s = open("swarm", w, h, label);
    s.push_str("<g class=\"grid\">");
    for i in 0..=4 {
        let v = t0 + ((t1 - t0) as f64 * i as f64 / 4.0) as i64;
        let _ = write!(
            s,
            "<line x1=\"{0:.1}\" x2=\"{0:.1}\" y1=\"{1:.1}\" y2=\"{2:.1}\"/>",
            x(v),
            t - 12.0,
            h - b
        );
    }
    s.push_str("</g><g class=\"axis\">");
    for i in 0..=4 {
        let v = t0 + ((t1 - t0) as f64 * i as f64 / 4.0) as i64;
        let anchor = ["start", "middle", "middle", "middle", "end"][i];
        let ts = sc_core::fmt_ts(v);
        let _ = write!(
            s,
            "<text x=\"{:.1}\" y=\"{:.1}\" text-anchor=\"{anchor}\">{}</text>",
            x(v),
            h - 8.0,
            esc(ts.get(5..16).unwrap_or(&ts))
        );
    }
    for (i, (lab, _)) in lanes.iter().enumerate() {
        let _ = write!(
            s,
            "<text class=\"lane-label\" x=\"{:.1}\" y=\"{:.1}\" text-anchor=\"end\">{}</text>",
            l - 8.0,
            y(i) + 4.0,
            esc(lab)
        );
    }
    s.push_str("</g>");
    for i in 0..lanes.len() {
        let (x2, yy) = (w - r, y(i));
        let _ = write!(
            s,
            "<line class=\"lane\" x1=\"{l}\" x2=\"{x2:.1}\" y1=\"{yy:.1}\" y2=\"{yy:.1}\"/>"
        );
    }
    let mut seen: Vec<(usize, usize)> = Vec::new();
    for e in edges {
        let (Some(p), Some(q)) = (pos.get(e.a), pos.get(e.b)) else {
            continue;
        };
        let pair = (e.a.min(e.b), e.a.max(e.b));
        let k = seen.iter().filter(|x| **x == pair).count() as f64;
        seen.push(pair);
        let lift = 16.0
            + ((q.0 - p.0).abs() * 0.16).min(54.0)
            + k * 10.0
            + if (q.1 - p.1).abs() < 1.0 { 8.0 } else { 0.0 };
        let _ = write!(
            s,
            "<path class=\"sedge sk-{} st-{}\" d=\"M{:.1},{:.1} Q{:.1},{:.1} {:.1},{:.1}\"><title>{}</title></path>",
            esc(&slug_class(&e.kind).replace('-', "_")),
            esc(&slug_class(&e.strength)),
            p.0,
            p.1,
            (p.0 + q.0) / 2.0,
            (p.1.min(q.1) - lift).max(4.0),
            q.0,
            q.1,
            esc(&e.label)
        );
    }
    for (n, p) in nodes.iter().zip(&pos) {
        let tier = lanes.get(n.lane).map_or("noise", |l| l.1.as_str());
        let _ = write!(
            s,
            "<circle class=\"node tier-{}\" cx=\"{:.1}\" cy=\"{:.1}\" r=\"6.5\"><title>{}</title></circle>",
            esc(&slug_class(tier)),
            p.0,
            p.1,
            esc(&n.label)
        );
    }
    s.push_str("</svg>");
    s
}

/// One cluster on the ladder: label, tier, level and the rung its signals
/// reach (0 = L0 .. 5 = L5).
pub struct LadderCol {
    pub label: String,
    pub tier: String,
    pub level: usize,
    pub reach: usize,
}

/// The agent-likelihood ladder: a row per rung (L5 at the top), a column
/// per cluster, a dot at its grade and a ring where its signals reach when
/// a cap holds it lower. `rungs`: (code, label), L0 first.
pub fn ladder(cols: &[LadderCol], rungs: &[(&str, &str)], label: &str) -> String {
    let (l, r, t, b) = (190.0, 12.0, 10.0, 30.0);
    let rh = 34.0;
    let cw = ((720.0 - l - r) / cols.len().max(1) as f64).clamp(34.0, 90.0);
    let w = l + r + cw * cols.len().max(1) as f64;
    let h = t + b + rh * rungs.len() as f64;
    let y = |lv: usize| t + rh * (rungs.len() - 1 - lv.min(rungs.len() - 1)) as f64 + rh / 2.0;
    let mut s = open("ladder-fig", w.max(720.0), h, label);
    for (i, (code, name)) in rungs.iter().enumerate() {
        let yy = y(i);
        let _ = write!(
            s,
            "<rect class=\"rung-band r{i}\" x=\"{l}\" y=\"{:.1}\" width=\"{:.1}\" height=\"{:.1}\"/>\
<text class=\"rung-code\" x=\"8\" y=\"{:.1}\">{}</text><text class=\"label\" x=\"40\" y=\"{:.1}\">{}</text>",
            yy - rh / 2.0 + 1.0,
            cw * cols.len().max(1) as f64,
            rh - 2.0,
            yy + 4.0,
            esc(code),
            yy + 4.0,
            esc(name)
        );
    }
    for (i, c) in cols.iter().enumerate() {
        let x = l + cw * i as f64 + cw / 2.0;
        if c.reach > c.level {
            let _ = write!(
                s,
                "<line class=\"cap-line\" x1=\"{x:.1}\" x2=\"{x:.1}\" y1=\"{:.1}\" y2=\"{:.1}\"/>\
<circle class=\"reach\" cx=\"{x:.1}\" cy=\"{:.1}\" r=\"7\"><title>{}: signals reach {}, capped at {}</title></circle>",
                y(c.reach) + 7.0,
                y(c.level) - 8.0,
                y(c.reach),
                esc(&c.label),
                esc(rungs.get(c.reach).map_or("?", |r| r.0)),
                esc(rungs.get(c.level).map_or("?", |r| r.0))
            );
        }
        let _ = write!(
            s,
            "<circle class=\"node tier-{}\" cx=\"{x:.1}\" cy=\"{:.1}\" r=\"8\"><title>{}: {}</title></circle>\
<text class=\"node-label\" x=\"{x:.1}\" y=\"{:.1}\" text-anchor=\"middle\">{}</text>",
            esc(&slug_class(&c.tier)),
            y(c.level),
            esc(&c.label),
            esc(rungs.get(c.level).map_or("?", |r| r.0)),
            h - 10.0,
            esc(&c.label)
        );
    }
    s.push_str("</svg>");
    s
}

/// Attribution layers as four bands: (layer heading, party or empty,
/// label word such as `suspected`, or empty for no candidate).
pub fn layer_bands(rows: &[(&str, String, String)], label: &str) -> String {
    let (w, rh) = (720.0, 40.0);
    let h = 8.0 + rh * rows.len() as f64;
    let mut s = open("bands-fig", w, h, label);
    for (i, (heading, party, word)) in rows.iter().enumerate() {
        let y = 4.0 + rh * i as f64;
        let cls = if word.is_empty() {
            "none".to_string()
        } else {
            slug_class(word)
        };
        let _ = write!(
            s,
            "<rect class=\"band-row {}\" x=\"200\" y=\"{y:.1}\" width=\"{:.1}\" height=\"{:.1}\" rx=\"6\"/>\
<text class=\"label\" x=\"190\" y=\"{:.1}\" text-anchor=\"end\">{}</text>\
<text class=\"band-text\" x=\"214\" y=\"{:.1}\">{}</text>",
            esc(&cls),
            w - 208.0,
            rh - 6.0,
            y + rh / 2.0 + 1.0,
            esc(heading),
            y + rh / 2.0 + 1.0,
            esc(&if word.is_empty() {
                "no candidate in these records".to_string()
            } else {
                format!("{} · {}", cut(party, 48), word)
            })
        );
    }
    s.push_str("</svg>");
    s
}

/// The disclosure clock: who hears first, and when the notice may follow.
/// `steps`: (who, when).
pub fn disclosure_flow(steps: &[(&str, &str)], label: &str) -> String {
    let (w, h) = (720.0, 120.0);
    let n = steps.len().max(1) as f64;
    let bw = (w - 16.0 - 18.0 * (n - 1.0)) / n;
    let mut s = open("flow-fig", w, h, label);
    for (i, (who, when)) in steps.iter().enumerate() {
        let x = 8.0 + i as f64 * (bw + 18.0);
        let _ = write!(
            s,
            "<rect class=\"flow-box f{i}\" x=\"{x:.1}\" y=\"20\" width=\"{bw:.1}\" height=\"72\" rx=\"8\"/>\
<text class=\"flow-who\" x=\"{:.1}\" y=\"50\" text-anchor=\"middle\">{}</text>\
<text class=\"flow-when\" x=\"{:.1}\" y=\"72\" text-anchor=\"middle\">{}</text>",
            x + bw / 2.0,
            esc(who),
            x + bw / 2.0,
            esc(when)
        );
        if i + 1 < steps.len() {
            let ax = x + bw + 2.0;
            let _ = write!(
                s,
                "<path class=\"arrow\" d=\"M{ax:.1},56 h12 m-5,-5 l5,5 l-5,5\"/>"
            );
        }
    }
    s.push_str("</svg>");
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn figures_escape_labels_and_carry_no_style() {
        let p = "<script>\"x";
        let figs = [
            layer_stack(
                &[UrlLayer {
                    via: p.into(),
                    depth: 0,
                    text: p.into(),
                }],
                p,
            ),
            score_bar(&[(p.into(), 3)], 3, 5, p),
            cluster_graph(
                &[GNode {
                    label: p.into(),
                    tier: p.into(),
                    size: 1,
                }],
                &[],
                p,
            ),
            swarm_arcs(
                &[(p.into(), p.into())],
                &[RunNode {
                    lane: 0,
                    t: 1,
                    label: p.into(),
                }],
                &[],
                p,
            ),
            ladder(
                &[LadderCol {
                    label: p.into(),
                    tier: p.into(),
                    level: 1,
                    reach: 3,
                }],
                &[("L0", p), ("L1", p), ("L2", p), ("L3", p)],
                p,
            ),
            layer_bands(&[(p, p.into(), p.into())], p),
            disclosure_flow(&[(p, p)], p),
        ];
        for f in figs {
            assert!(!f.contains("<script") && !f.contains("style="), "{f}");
            assert!(f.contains("&lt;script&gt;"), "{f}");
        }
        assert_eq!(cut("abcdef", 4), "abc…");
    }
}
