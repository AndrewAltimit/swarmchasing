//! An Atom feed with one entry per notice update.

use crate::file::{NoticeFile, NoticeUpdate};
use std::fmt::Write;

fn xml(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => o.push_str("&amp;"),
            '<' => o.push_str("&lt;"),
            '>' => o.push_str("&gt;"),
            '"' => o.push_str("&quot;"),
            '\'' => o.push_str("&apos;"),
            c if (c as u32) < 0x20 && !matches!(c, '\n' | '\t' | '\r') => {}
            c => o.push(c),
        }
    }
    o
}

/// What the feed says about itself, under its title.
pub const FEED_SUBTITLE: &str = "Public notices of AI agent incidents that harmed or endangered others: indicators first, affected parties named in a later update. One entry per update.";

/// An Atom feed with one entry per notice update, newest first. `base` is
/// the site's URL, ending in `/`. The feed's `updated` is its newest
/// entry's date, or `fallback` (`YYYY-MM-DD`, the build's commit date)
/// while there is no entry.
pub fn atom_feed(notices: &[NoticeFile], base: &str, fallback: &str) -> String {
    let mut entries: Vec<(&NoticeFile, usize, &NoticeUpdate)> = notices
        .iter()
        .flat_map(|n| {
            n.meta
                .updates
                .iter()
                .enumerate()
                .map(move |(i, u)| (n, i, u))
        })
        .collect();
    entries.sort_by(|a, b| {
        b.2.date
            .cmp(&a.2.date)
            .then(a.0.meta.id.cmp(&b.0.meta.id))
            .then(b.1.cmp(&a.1))
    });
    let newest = entries
        .first()
        .map(|e| e.2.date.as_str())
        .unwrap_or(fallback);
    let mut s = String::new();
    let _ = writeln!(s, r#"<?xml version="1.0" encoding="utf-8"?>"#);
    let _ = writeln!(s, r#"<feed xmlns="http://www.w3.org/2005/Atom">"#);
    let _ = writeln!(s, "  <title>Swarmchasing notices</title>");
    let _ = writeln!(s, "  <subtitle>{}</subtitle>", xml(FEED_SUBTITLE));
    let _ = writeln!(s, "  <id>{}notices/feed.xml</id>", xml(base));
    let _ = writeln!(
        s,
        r#"  <link rel="self" href="{}notices/feed.xml"/>"#,
        xml(base)
    );
    let _ = writeln!(s, r#"  <link href="{}"/>"#, xml(base));
    let _ = writeln!(s, "  <updated>{}T00:00:00Z</updated>", xml(newest));
    let _ = writeln!(s, "  <author><name>swarmchasing</name></author>");
    for (n, i, u) in entries {
        let link = format!("{base}notices/{}/", n.meta.id);
        let _ = writeln!(s, "  <entry>");
        let _ = writeln!(
            s,
            "    <title>{}: {}</title>",
            xml(u.kind.label()),
            xml(&n.meta.title)
        );
        let _ = writeln!(s, "    <id>{}#{i}</id>", xml(&link));
        let _ = writeln!(s, r#"    <link href="{}"/>"#, xml(&link));
        let _ = writeln!(s, "    <updated>{}T00:00:00Z</updated>", xml(&u.date));
        let from = u
            .from
            .as_deref()
            .map(|f| format!("Statement from {f}: "))
            .unwrap_or_default();
        let _ = writeln!(
            s,
            r#"    <content type="text">{}{}</content>"#,
            xml(&from),
            xml(&u.text)
        );
        let _ = writeln!(s, "  </entry>");
    }
    let _ = writeln!(s, "</feed>");
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_empty_feed_is_dated_by_its_fallback_and_says_what_it_carries() {
        let f = atom_feed(&[], "https://example.github.io/swarmchasing/", "2026-10-01");
        assert!(f.contains("<updated>2026-10-01T00:00:00Z</updated>"), "{f}");
        assert!(!f.contains("1970"));
        assert!(f.contains("<subtitle>Public notices"));
        assert!(!f.contains("<entry>"));
    }
}
