//! The Field Manual as a reference: a previous/next pager on each of its
//! pages, a page listing every `FM-n.m` section, and the JSON index the
//! section search reads (no WASM: plain text matched in the page).

use super::docs::{Doc, FmSection};
use super::html::esc;
use super::layout::rel_root;
use std::fmt::Write;

/// Previous and next in reading order, and the way to the section index.
pub fn pager(d: &Doc, order: &[&Doc]) -> String {
    let Some(i) = order.iter().position(|x| x.src == d.src) else {
        return String::new();
    };
    let root = rel_root(&format!("{}index.html", d.url));
    let link = |x: &Doc, rel: &str, label: &str| {
        format!(
            "<a class=\"pager-{rel}\" rel=\"{rel}\" href=\"{}{}\"><span class=\"hint\">{label}</span>{}</a>",
            esc(&root),
            esc(&x.url),
            esc(&x.title)
        )
    };
    let mut s = String::from("<nav class=\"pager\" aria-label=\"Field Manual pages\">");
    if i > 0 {
        s.push_str(&link(order[i - 1], "prev", "Previous"));
    } else {
        s.push_str("<span></span>");
    }
    if let Some(n) = order.get(i + 1) {
        s.push_str(&link(n, "next", "Next"));
    }
    let _ = write!(
        s,
        "</nav><p class=\"hint pager-index\"><a href=\"{}docs/manual/sections/\">Every section by id, with search</a></p>",
        esc(&root)
    );
    s
}

#[derive(serde::Serialize)]
struct Entry<'a> {
    id: &'a str,
    title: &'a str,
    chapter: &'a str,
    text: &'a str,
}

/// `assets/fm-index.json`: every section's id, title, chapter and text.
pub fn search_index(sections: &[FmSection]) -> String {
    let entries: Vec<Entry> = sections
        .iter()
        .map(|f| Entry {
            id: &f.id,
            title: &f.title,
            chapter: &f.chapter,
            text: &f.text,
        })
        .collect();
    serde_json::to_string(&entries).unwrap_or_else(|_| "[]".into())
}

/// The section index: every section by chapter, filtered by the search.
pub fn sections_page(sections: &[FmSection], order: &[&Doc]) -> String {
    let root = rel_root("docs/manual/sections/index.html");
    let mut s = String::from(
        "<header class=\"page-head\"><p class=\"crumbs\"><a href=\"../\">Field Manual</a></p><h1>Field Manual sections</h1>\
<p class=\"lede\">Every section of the Swarmchasing Field Manual (SC-FM) by its id. Cite a section as <code>SC-FM 1.0 §FM-3.2</code>. Search matches ids, titles and the sections' text; it runs in this page.</p></header>\
<form class=\"filters card fm-search\" role=\"search\" aria-label=\"Search the Field Manual\" data-fm-search>\
<label class=\"grow\">Search the manual<input name=\"q\" type=\"search\" spellcheck=\"false\" placeholder=\"e.g. capture time, naming gate, FM-7\" autocomplete=\"off\"></label>\
<p class=\"hint\" data-fm-count aria-live=\"polite\"></p></form>",
    );
    let mut chapter = "";
    let mut open = false;
    for f in sections {
        if f.chapter != chapter {
            if open {
                s.push_str("</ol></section>");
            }
            chapter = &f.chapter;
            let url = order
                .iter()
                .find(|d| d.title == f.chapter)
                .map_or(f.url.as_str(), |d| d.url.as_str());
            let _ = write!(
                s,
                "<section class=\"fm-chapter\" data-fm-chapter><h2><a href=\"{}{}\">{}</a></h2><ol class=\"fm-list\">",
                esc(&root),
                esc(url),
                esc(&f.chapter)
            );
            open = true;
        }
        let _ = write!(
            s,
            "<li data-fm=\"{}\"><a href=\"{}{}#{}\"><span class=\"fm-id\">{}</span> {}</a></li>",
            esc(&f.id),
            esc(&root),
            esc(&f.url),
            esc(&f.anchor),
            esc(&f.id),
            esc(&f.title)
        );
    }
    if open {
        s.push_str("</ol></section>");
    }
    s.push_str("<p class=\"hint\" data-fm-none hidden>No section matches.</p>");
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn section(id: &str, chapter: &str) -> FmSection {
        FmSection {
            id: id.into(),
            title: "A <b>title</b>".into(),
            chapter: chapter.into(),
            url: "docs/manual/01-scope/".into(),
            anchor: "fm-11-scope".into(),
            text: "text \"quoted\"".into(),
        }
    }

    #[test]
    fn the_index_escapes_and_links_every_section() {
        let secs = [section("FM-1.1", "1. Scope"), section("FM-1.2", "1. Scope")];
        let page = sections_page(&secs, &[]);
        assert!(page.contains("href=\"../../../docs/manual/01-scope/#fm-11-scope\""));
        assert!(page.contains("A &lt;b&gt;title&lt;/b&gt;") && !page.contains("<b>"));
        assert_eq!(page.matches("data-fm=").count(), 2);
        let json: serde_json::Value = serde_json::from_str(&search_index(&secs)).unwrap();
        assert_eq!(json[1]["id"], "FM-1.2");
    }
}
