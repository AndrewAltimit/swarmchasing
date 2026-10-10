//! Escaping for generated HTML. Every string that reaches a page goes
//! through [`esc`] (text and attribute values alike); nothing here inserts
//! markup from its input.

use std::fmt::Write;

/// Escape text for an HTML text node or a double- or single-quoted
/// attribute value. Control characters other than tab and newline are
/// dropped.
pub fn esc(s: &str) -> String {
    let mut o = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        match c {
            '&' => o.push_str("&amp;"),
            '<' => o.push_str("&lt;"),
            '>' => o.push_str("&gt;"),
            '"' => o.push_str("&quot;"),
            '\'' => o.push_str("&#39;"),
            c if (c as u32) < 0x20 && !matches!(c, '\n' | '\t') => {}
            c => o.push(c),
        }
    }
    o
}

/// `<tag class="…">text</tag>`, the text escaped.
pub fn tag(name: &str, class: &str, text: &str) -> String {
    if class.is_empty() {
        format!("<{name}>{}</{name}>", esc(text))
    } else {
        format!("<{name} class=\"{}\">{}</{name}>", esc(class), esc(text))
    }
}

/// A status or tier pill: a dot and its label.
pub fn pill(kind: &str) -> String {
    format!(
        "<span class=\"pill {}\">{}</span>",
        esc(&slug_class(kind)),
        esc(kind)
    )
}

/// A value safe as a single class name: lowercase ASCII letters, digits and
/// hyphens.
pub fn slug_class(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect()
}

/// A table from a header row and body rows of HTML cells (already escaped).
pub fn table(class: &str, head: &[&str], rows: &[Vec<String>]) -> String {
    let mut s = String::new();
    let _ = write!(
        s,
        "<div class=\"scroll\"><table{}><thead><tr>",
        if class.is_empty() {
            String::new()
        } else {
            format!(" class=\"{}\"", esc(class))
        }
    );
    for h in head {
        let _ = write!(s, "<th scope=\"col\">{}</th>", esc(h));
    }
    s.push_str("</tr></thead><tbody>");
    for r in rows {
        s.push_str("<tr>");
        for c in r {
            let _ = write!(s, "<td>{c}</td>");
        }
        s.push_str("</tr>");
    }
    s.push_str("</tbody></table></div>");
    s
}

/// A percentage with one decimal, or "n/a".
pub fn pct(x: Option<f64>) -> String {
    x.map_or_else(|| "n/a".to_string(), |v| format!("{:.1}%", v * 100.0))
}

/// The Wilson score interval for `k` successes in `n` trials at 95%.
pub fn wilson(k: usize, n: usize) -> Option<(f64, f64)> {
    if n == 0 {
        return None;
    }
    let (k, n) = (k as f64, n as f64);
    let z = 1.959_963_984_540_054_f64;
    let p = k / n;
    let d = 1.0 + z * z / n;
    let c = (p + z * z / (2.0 * n)) / d;
    let h = z * ((p * (1.0 - p) / n) + z * z / (4.0 * n * n)).sqrt() / d;
    Some(((c - h).max(0.0), (c + h).min(1.0)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_markup_and_quotes() {
        assert_eq!(
            esc(r#"<img src=x onerror="a('b')">&"#),
            "&lt;img src=x onerror=&quot;a(&#39;b&#39;)&quot;&gt;&amp;"
        );
        assert_eq!(esc("a\u{7}b\nc"), "ab\nc");
        assert_eq!(slug_class("Status\"><x"), "status---x");
    }

    #[test]
    fn wilson_brackets_the_rate() {
        let (lo, hi) = wilson(45, 50).unwrap();
        assert!(lo < 0.9 && hi > 0.9 && hi <= 1.0, "{lo} {hi}");
        let (lo, hi) = wilson(10, 10).unwrap();
        assert!(lo > 0.65 && (hi - 1.0).abs() < 1e-9, "{lo} {hi}");
        assert!(wilson(0, 0).is_none());
    }
}
