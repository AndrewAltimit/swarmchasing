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

/// The candidate closest to `word` (ignoring case), when one is close
/// enough to be a likely typo: within a third of the word's length in
/// edits (at least 2), or the only candidate that contains it.
pub fn closest<'a>(word: &str, candidates: impl IntoIterator<Item = &'a str>) -> Option<&'a str> {
    let w = word.to_lowercase();
    let mut best: Option<(usize, &str)> = None;
    let mut containing = Vec::new();
    for c in candidates {
        let lc = c.to_lowercase();
        if lc == w {
            continue;
        }
        if !w.is_empty() && lc.contains(&w) {
            containing.push(c);
        }
        let d = edit_distance(&w, &lc);
        if best.is_none_or(|(b, _)| d < b) {
            best = Some((d, c));
        }
    }
    let limit = (w.chars().count() / 3).max(2);
    match best {
        Some((d, c)) if d <= limit => Some(c),
        _ if containing.len() == 1 => Some(containing[0]),
        _ => None,
    }
}

/// `; did you mean `x`?` for [`closest`], or nothing.
pub fn did_you_mean<'a>(word: &str, candidates: impl IntoIterator<Item = &'a str>) -> String {
    closest(word, candidates)
        .map(|c| format!("; did you mean `{c}`?"))
        .unwrap_or_default()
}

/// Levenshtein distance over characters.
fn edit_distance(a: &str, b: &str) -> usize {
    let b: Vec<char> = b.chars().collect();
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    for (i, ca) in a.chars().enumerate() {
        let mut cur = vec![i + 1; b.len() + 1];
        for (j, cb) in b.iter().enumerate() {
            cur[j + 1] = (prev[j] + usize::from(ca != *cb))
                .min(prev[j + 1] + 1)
                .min(cur[j] + 1);
        }
        prev = cur;
    }
    prev[b.len()]
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

    #[test]
    fn a_likely_typo_gets_a_suggestion() {
        let ids = ["2026-10-portal", "2026-09-relay", "2026-10-mirror"];
        assert_eq!(closest("2026-10-portl", ids), Some("2026-10-portal"));
        assert_eq!(closest("2026-10-PORTAL", ids), None, "same, not a typo");
        assert_eq!(closest("portal", ids), Some("2026-10-portal"));
        assert_eq!(closest("something-else-entirely", ids), None);
        assert_eq!(closest("x", Vec::<&str>::new()), None);
        let hosts = ["portal.example.gov", "data.example.gov"];
        assert_eq!(
            did_you_mean("portal.exmaple.gov", hosts),
            "; did you mean `portal.example.gov`?"
        );
        assert_eq!(did_you_mean("nowhere.example", hosts), "");
        assert_eq!(edit_distance("kitten", "sitting"), 3);
    }
}
