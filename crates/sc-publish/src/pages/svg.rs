//! Static SVG charts for generated pages: run swim-lanes and horizontal
//! bars. Attributes only, no `style`, so they pass the page's CSP; every
//! label is escaped. The browser's `site/js/lib/charts.js` draws the same
//! forms for live data.

use super::html::{esc, slug_class};
use std::fmt::Write;

/// One swim-lane: a cluster and its runs.
pub struct Lane {
    pub label: String,
    pub tier: String,
    /// (start, end, records) per run, Unix seconds.
    pub runs: Vec<(i64, i64, usize)>,
}

fn utc(t: i64) -> String {
    sc_core::fmt_ts(t)
}

fn hhmm(t: i64) -> String {
    let s = utc(t);
    // "2026-07-02 10:00:00 UTC" -> "07-02 10:00"
    s.get(5..16).unwrap_or(&s).to_string()
}

/// Run swim-lanes: one lane per cluster, a bar per run, `pauses` shaded.
pub fn swimlanes(lanes: &[Lane], pauses: &[(i64, i64)], label: &str) -> String {
    let t0 = lanes
        .iter()
        .flat_map(|l| l.runs.iter().map(|r| r.0))
        .min()
        .unwrap_or(0);
    let t1 = lanes
        .iter()
        .flat_map(|l| l.runs.iter().map(|r| r.1))
        .max()
        .unwrap_or(1);
    let span = (t1 - t0).max(60) as f64;
    let (w, lh, l, r, t, b) = (960.0, 30.0, 64.0, 12.0, 8.0, 28.0);
    let h = t + b + lh * lanes.len() as f64;
    let x = |v: i64| l + (v - t0) as f64 / span * (w - l - r);
    let mut s = String::new();
    let _ = write!(
        s,
        "<svg class=\"chart swim\" viewBox=\"0 0 {w} {h}\" role=\"img\" aria-label=\"{}\"><title>{}</title>",
        esc(label),
        esc(label)
    );
    for &(ps, pe) in pauses {
        // Only the part inside the drawn span.
        let (ps, pe) = (ps.max(t0), pe.min(t1));
        if pe <= ps {
            continue;
        }
        let _ = write!(
            s,
            "<rect class=\"pause\" x=\"{:.1}\" y=\"{t}\" width=\"{:.1}\" height=\"{:.1}\"/>",
            x(ps),
            (x(pe) - x(ps)).max(1.0),
            h - t - b
        );
    }
    s.push_str("<g class=\"grid\">");
    for i in 0..=4 {
        let v = t0 + ((t1 - t0) as f64 * i as f64 / 4.0) as i64;
        let _ = write!(
            s,
            "<line x1=\"{0:.1}\" x2=\"{0:.1}\" y1=\"{t}\" y2=\"{1:.1}\"/>",
            x(v),
            h - b
        );
    }
    s.push_str("</g><g class=\"axis\">");
    for i in 0..=4 {
        let v = t0 + ((t1 - t0) as f64 * i as f64 / 4.0) as i64;
        let anchor = match i {
            0 => "start",
            4 => "end",
            _ => "middle",
        };
        let _ = write!(
            s,
            "<text x=\"{:.1}\" y=\"{:.1}\" text-anchor=\"{anchor}\">{}</text>",
            x(v),
            h - 8.0,
            esc(&hhmm(v))
        );
    }
    for (i, lane) in lanes.iter().enumerate() {
        let y = t + lh * i as f64;
        let _ = write!(
            s,
            "<text x=\"{:.1}\" y=\"{:.1}\" text-anchor=\"end\">{}</text>",
            l - 8.0,
            y + lh / 2.0 + 4.0,
            esc(&lane.label)
        );
    }
    s.push_str("</g>");
    for (i, lane) in lanes.iter().enumerate() {
        let y = t + lh * i as f64;
        let _ = write!(
            s,
            "<line class=\"lane\" x1=\"{l}\" x2=\"{:.1}\" y1=\"{:.1}\" y2=\"{:.1}\"/>",
            w - r,
            y + lh / 2.0,
            y + lh / 2.0
        );
        for &(rs, re, n) in &lane.runs {
            let _ = write!(
                s,
                "<rect class=\"run tier-{}\" x=\"{:.1}\" y=\"{:.1}\" width=\"{:.1}\" height=\"{:.1}\" rx=\"4\"><title>{}: {} to {}, {} record(s)</title></rect>",
                esc(&slug_class(&lane.tier)),
                x(rs),
                y + 7.0,
                (x(re) - x(rs)).max(6.0),
                lh - 14.0,
                esc(&lane.label),
                esc(&utc(rs)),
                esc(&utc(re)),
                n
            );
        }
    }
    s.push_str("</svg>");
    s
}

/// One bar row: label, then (value, series class) segments laid end to end.
pub struct BarRow {
    pub label: String,
    pub segments: Vec<(f64, &'static str)>,
    /// Text after the bar.
    pub note: String,
}

/// Horizontal stacked bars on one scale, `max` at full width.
pub fn hbars(rows: &[BarRow], max: f64, label: &str, label_width: f64) -> String {
    let (w, rh, r, t) = (960.0, 22.0, 150.0, 4.0);
    let l = label_width;
    let h = t * 2.0 + rh * rows.len() as f64;
    let scale = |v: f64| {
        if max > 0.0 {
            v / max * (w - l - r)
        } else {
            0.0
        }
    };
    let mut s = String::new();
    let _ = write!(
        s,
        "<svg class=\"chart bars\" viewBox=\"0 0 {w} {h}\" role=\"img\" aria-label=\"{}\"><title>{}</title>",
        esc(label),
        esc(label)
    );
    for (i, row) in rows.iter().enumerate() {
        let y = t + rh * i as f64;
        let _ = write!(
            s,
            "<text class=\"label\" x=\"{:.1}\" y=\"{:.1}\" text-anchor=\"end\">{}</text>",
            l - 8.0,
            y + rh / 2.0 + 4.0,
            esc(&row.label)
        );
        let mut x = l;
        for (j, &(v, class)) in row.segments.iter().enumerate() {
            if v <= 0.0 {
                continue;
            }
            // A 2px surface gap between stacked segments.
            let gap = if j > 0 { 2.0 } else { 0.0 };
            let bw = (scale(v) - gap).max(1.0);
            let _ = write!(
                s,
                "<rect class=\"{class}\" x=\"{:.1}\" y=\"{:.1}\" width=\"{bw:.1}\" height=\"{:.1}\" rx=\"3\"/>",
                x + gap,
                y + 4.0,
                rh - 8.0
            );
            x += gap + bw;
        }
        let _ = write!(
            s,
            "<text class=\"note\" x=\"{:.1}\" y=\"{:.1}\">{}</text>",
            x + 6.0,
            y + rh / 2.0 + 4.0,
            esc(&row.note)
        );
    }
    s.push_str("</svg>");
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn charts_escape_labels_and_carry_no_style() {
        let lanes = [Lane {
            label: "<script>".into(),
            tier: "significant\"><x".into(),
            runs: vec![(1_780_000_000, 1_780_000_600, 3)],
        }];
        let s = swimlanes(&lanes, &[(1_780_000_100, 1_780_000_200)], "a<b");
        assert!(!s.contains("<script") && !s.contains("style="), "{s}");
        assert!(s.contains("tier-significant---x"));
        let b = hbars(
            &[BarRow {
                label: "x\"y".into(),
                segments: vec![(2.0, "s1"), (1.0, "s2")],
                note: "<n>".into(),
            }],
            3.0,
            "bars",
            120.0,
        );
        assert!(b.contains("x&quot;y") && b.contains("&lt;n&gt;") && !b.contains("style="));
    }
}
