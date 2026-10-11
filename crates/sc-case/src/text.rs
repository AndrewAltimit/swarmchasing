//! Small text helpers the case code and the CLI share.

use sc_core::Audience;

/// `s` cut to `n` characters, with `…` when cut.
pub fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.into()
    } else {
        format!("{}…", s.chars().take(n).collect::<String>())
    }
}

/// `s` on one line, safe in a Markdown table cell, cut to `n` characters.
pub fn one_line(s: &str, n: usize) -> String {
    truncate(&s.replace(['\n', '|'], " "), n)
}

/// A line trimmed and cut to 90 characters, for quoting in a problem.
pub fn short(l: &str) -> String {
    truncate(l.trim(), 90)
}

/// `a`, `a and b`, `a, b and c`.
pub fn and_list(items: &[String]) -> String {
    match items {
        [] => String::new(),
        [one] => one.clone(),
        [init @ .., last] => format!("{} and {last}", init.join(", ")),
    }
}

/// The audience as it appears in file names and ids: its serialised name.
pub fn audience_id(a: Audience) -> String {
    serde_json::to_value(a)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_default()
}

/// Today's date in RFC 3339 text (`yyyy-mm-dd`) from a Unix time.
pub fn date_of(ts: i64) -> String {
    crate::model::rfc3339(ts).chars().take(10).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn helpers() {
        assert_eq!(truncate("abcdef", 3), "abc…");
        assert_eq!(truncate("abc", 3), "abc");
        assert_eq!(one_line("a|b\nc", 10), "a b c");
        assert_eq!(
            and_list(&["x".into(), "y".into(), "z".into()]),
            "x, y and z"
        );
        for (a, id) in [
            (Audience::Provider, "provider"),
            (Audience::Affected, "affected"),
            (Audience::Internal, "internal"),
            (Audience::Public, "public"),
        ] {
            assert_eq!(audience_id(a), id);
            assert_eq!(id.parse::<Audience>().unwrap(), a);
        }
        assert_eq!(date_of(1_791_000_000), "2026-10-03");
    }
}
