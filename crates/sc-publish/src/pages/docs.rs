//! The committed docs (`docs/**/*.md`) as site pages: a small Markdown
//! renderer that escapes every character of its input and emits only the
//! markup it writes itself (headings, paragraphs, lists, quotes, tables,
//! code, emphasis, links). Raw HTML in a doc shows as text.
//!
//! Links to other docs go to their site pages; links to other repository
//! files go to GitHub; `http(s)` links stay as they are; any other scheme
//! is shown as text, never as a link.

use super::html::esc;
use super::layout::rel_root;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write;

/// A heading in a doc's table of contents: (level, anchor, text).
pub type TocEntry = (u8, String, String);

/// One rendered doc.
#[derive(Debug, Clone)]
pub struct Doc {
    /// The repository path, e.g. `docs/guides/for-operators.md`.
    pub src: String,
    /// The page's directory under the site root, e.g. `operators/`.
    pub url: String,
    /// The first heading's text.
    pub title: String,
    /// The first paragraph's text, for the page description.
    pub summary: String,
    /// The body after its first heading.
    pub html: String,
    pub toc: Vec<TocEntry>,
}

/// Where a doc is published: `docs/README.md` is the docs index, the
/// methodology and the operators' guide have their own sections, and every
/// other doc sits under `docs/` at its own path.
pub fn doc_url(src: &str) -> String {
    let rel = src.strip_prefix("docs/").unwrap_or(src);
    match rel {
        "README.md" => "docs/".into(),
        "methodology.md" => "methodology/".into(),
        "guides/for-operators.md" => "operators/".into(),
        _ => {
            let stem = rel.strip_suffix(".md").unwrap_or(rel);
            let stem = stem
                .strip_suffix("/README")
                .or_else(|| (stem == "README").then_some(""))
                .unwrap_or(stem);
            if stem.is_empty() {
                "docs/".into()
            } else {
                format!("docs/{stem}/")
            }
        }
    }
}

/// GitHub's heading anchor: lowercase, punctuation dropped, spaces to
/// hyphens (as `scripts/ci/check-md-links.py` computes it).
pub fn slug(heading: &str) -> String {
    let plain = strip_inline(heading).to_lowercase();
    plain
        .chars()
        .filter(|c| c.is_alphanumeric() || *c == '-' || *c == ' ' || *c == '_')
        .map(|c| if c == ' ' { '-' } else { c })
        .collect()
}

/// Inline Markdown reduced to its text: code ticks and emphasis markers
/// dropped, links reduced to their text.
pub fn strip_inline(s: &str) -> String {
    let mut out = String::new();
    let b = s.as_bytes();
    let mut i = 0;
    while i < s.len() {
        let c = b[i];
        if c == b'['
            && let Some((text, _, end)) = parse_link(s, i)
        {
            out.push_str(&strip_inline(text));
            i = end;
            continue;
        }
        if c == b'`' || c == b'*' {
            i += 1;
            continue;
        }
        let ch = s[i..].chars().next().unwrap_or(' ');
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

/// What the renderer needs to resolve links.
pub struct Links<'a> {
    /// Every doc's repository path.
    pub docs: &'a BTreeSet<String>,
    /// `https://github.com/<owner>/<repo>`.
    pub repo: &'a str,
}

struct Ctx<'a> {
    src: &'a str,
    page: String,
    links: &'a Links<'a>,
    ids: BTreeMap<String, usize>,
    toc: Vec<TocEntry>,
}

/// Render one doc.
pub fn render_doc(src: &str, text: &str, links: &Links) -> Doc {
    let url = doc_url(src);
    let mut ctx = Ctx {
        src,
        page: format!("{url}index.html"),
        links,
        ids: BTreeMap::new(),
        toc: Vec::new(),
    };
    let lines: Vec<&str> = text.lines().collect();
    // The first level-1 heading is the page title, not part of the body.
    let mut title = String::new();
    let mut body_lines = Vec::with_capacity(lines.len());
    for l in &lines {
        if title.is_empty()
            && body_lines.iter().all(|x: &&str| x.trim().is_empty())
            && let Some(t) = l.strip_prefix("# ")
        {
            title = strip_inline(t.trim());
            continue;
        }
        body_lines.push(*l);
    }
    let summary = body_lines
        .iter()
        .skip_while(|l| l.trim().is_empty())
        .take_while(|l| !l.trim().is_empty())
        .copied()
        .collect::<Vec<_>>()
        .join(" ");
    let html = blocks(&body_lines, &mut ctx);
    Doc {
        src: src.to_string(),
        url,
        title: if title.is_empty() {
            src.to_string()
        } else {
            title
        },
        summary: strip_inline(&summary),
        html,
        toc: ctx.toc,
    }
}

fn is_fence(t: &str) -> Option<&'static str> {
    if t.starts_with("```") {
        Some("```")
    } else if t.starts_with("~~~") {
        Some("~~~")
    } else {
        None
    }
}

fn heading(t: &str) -> Option<(u8, &str)> {
    let n = t.chars().take_while(|&c| c == '#').count();
    if (1..=6).contains(&n) && t[n..].starts_with(' ') {
        Some((n as u8, t[n..].trim().trim_end_matches('#').trim()))
    } else {
        None
    }
}

fn is_rule(t: &str) -> bool {
    let t: String = t.chars().filter(|c| !c.is_whitespace()).collect();
    t.len() >= 3 && (t.chars().all(|c| c == '-') || t.chars().all(|c| c == '*'))
}

/// A list marker: (indent, ordered, content column, start number).
fn list_item(line: &str) -> Option<(usize, bool, usize)> {
    let indent = line.len() - line.trim_start_matches(' ').len();
    let t = &line[indent..];
    if let Some(r) = t.strip_prefix("- ").or_else(|| t.strip_prefix("* ")) {
        let pad = r.len() - r.trim_start_matches(' ').len();
        return Some((indent, false, indent + 2 + pad));
    }
    let digits = t.chars().take_while(|c| c.is_ascii_digit()).count();
    if digits > 0
        && digits < 10
        && let Some(r) = t[digits..].strip_prefix(". ")
    {
        let pad = r.len() - r.trim_start_matches(' ').len();
        return Some((indent, true, indent + digits + 2 + pad));
    }
    None
}

fn is_table_sep(l: &str) -> bool {
    let t = l.trim();
    t.starts_with('|')
        && t.len() > 2
        && t.chars().all(|c| matches!(c, '|' | '-' | ':' | ' '))
        && t.contains('-')
}

fn blocks(lines: &[&str], ctx: &mut Ctx) -> String {
    let mut out = String::new();
    let mut i = 0;
    let mut para: Vec<&str> = Vec::new();
    while i < lines.len() {
        let line = lines[i];
        let t = line.trim();
        let starts_block = t.is_empty()
            || is_fence(t).is_some()
            || heading(t).is_some()
            || t.starts_with('>')
            || (t.starts_with('|') && lines.get(i + 1).is_some_and(|n| is_table_sep(n)))
            || t.starts_with("<!--")
            || list_item(line).is_some_and(|(ind, _, _)| ind < 4)
            || (is_rule(t) && para.is_empty());
        if starts_block && !para.is_empty() {
            flush_para(&mut para, &mut out, ctx);
        }
        if t.is_empty() {
            i += 1;
        } else if let Some(fence) = is_fence(t) {
            let lang = t[fence.len()..].trim();
            let mut code = Vec::new();
            i += 1;
            while i < lines.len() && !lines[i].trim_start().starts_with(fence) {
                code.push(lines[i]);
                i += 1;
            }
            i += 1;
            let _ = writeln!(
                out,
                "<pre class=\"code\"{}><code>{}</code></pre>",
                if lang.is_empty() {
                    String::new()
                } else {
                    format!(" data-lang=\"{}\"", esc(lang))
                },
                esc(&code.join("\n"))
            );
        } else if t.starts_with("<!--") {
            while i < lines.len() && !lines[i].contains("-->") {
                i += 1;
            }
            i += 1;
        } else if let Some((level, text)) = heading(t) {
            let base = slug(text);
            let n = ctx.ids.entry(base.clone()).or_insert(0);
            let id = if *n == 0 {
                base.clone()
            } else {
                format!("{base}-{n}")
            };
            *n += 1;
            let level = level.clamp(2, 6);
            if level <= 3 {
                ctx.toc.push((level, id.clone(), strip_inline(text)));
            }
            let _ = writeln!(
                out,
                "<h{level} id=\"{}\">{}<a class=\"anchor\" href=\"#{}\" aria-label=\"Link to this section\">#</a></h{level}>",
                esc(&id),
                inline(text, ctx),
                esc(&id)
            );
            i += 1;
        } else if is_rule(t) {
            out.push_str("<hr>\n");
            i += 1;
        } else if t.starts_with('>') {
            let mut q = Vec::new();
            while i < lines.len() && lines[i].trim_start().starts_with('>') {
                let l = lines[i].trim_start().trim_start_matches('>');
                q.push(l.strip_prefix(' ').unwrap_or(l));
                i += 1;
            }
            let inner = blocks(&q, ctx);
            let _ = writeln!(out, "<blockquote>{inner}</blockquote>");
        } else if t.starts_with('|') && lines.get(i + 1).is_some_and(|n| is_table_sep(n)) {
            let head = cells(t);
            i += 2;
            let mut rows = Vec::new();
            while i < lines.len() && lines[i].trim().starts_with('|') {
                rows.push(cells(lines[i].trim()));
                i += 1;
            }
            out.push_str("<div class=\"scroll\"><table><thead><tr>");
            for h in &head {
                let _ = write!(out, "<th scope=\"col\">{}</th>", inline(h, ctx));
            }
            out.push_str("</tr></thead><tbody>");
            for r in &rows {
                out.push_str("<tr>");
                for c in r {
                    let _ = write!(out, "<td>{}</td>", inline(c, ctx));
                }
                out.push_str("</tr>");
            }
            out.push_str("</tbody></table></div>\n");
        } else if let Some((indent, ordered, _)) = list_item(line).filter(|l| l.0 < 4) {
            i = list(lines, i, indent, ordered, &mut out, ctx);
        } else {
            para.push(t);
            i += 1;
        }
    }
    flush_para(&mut para, &mut out, ctx);
    out
}

fn flush_para(para: &mut Vec<&str>, out: &mut String, ctx: &mut Ctx) {
    if !para.is_empty() {
        let _ = writeln!(out, "<p>{}</p>", inline(&para.join(" "), ctx));
        para.clear();
    }
}

/// One list starting at `lines[i]`; returns the index after it.
fn list(
    lines: &[&str],
    mut i: usize,
    indent: usize,
    ordered: bool,
    out: &mut String,
    ctx: &mut Ctx,
) -> usize {
    let start = if ordered {
        lines[i]
            .trim_start()
            .chars()
            .take_while(|c| c.is_ascii_digit())
            .collect::<String>()
            .parse::<u32>()
            .unwrap_or(1)
    } else {
        1
    };
    let mut items: Vec<Vec<String>> = Vec::new();
    let mut loose = false;
    while i < lines.len() {
        let line = lines[i];
        match list_item(line) {
            Some((ind, o, col)) if ind == indent && o == ordered => {
                items.push(vec![line.get(col..).unwrap_or("").to_string()]);
                i += 1;
            }
            _ => {
                let t = line.trim();
                let ind = line.len() - line.trim_start_matches(' ').len();
                if t.is_empty() {
                    // A blank line continues the item when indented text follows.
                    let next = lines[i + 1..].iter().find(|l| !l.trim().is_empty());
                    let cont = next.is_some_and(|n| {
                        let ni = n.len() - n.trim_start_matches(' ').len();
                        ni > indent
                            || list_item(n).is_some_and(|(x, o, _)| x == indent && o == ordered)
                    });
                    if !cont {
                        break;
                    }
                    if next.is_some_and(|n| {
                        let ni = n.len() - n.trim_start_matches(' ').len();
                        ni == indent
                    }) {
                        loose = true;
                    }
                    if let Some(last) = items.last_mut() {
                        last.push(String::new());
                    }
                    i += 1;
                } else if ind > indent && !items.is_empty() {
                    let strip = (indent + 2).min(ind);
                    if let Some(last) = items.last_mut() {
                        last.push(line[strip..].to_string());
                    }
                    i += 1;
                } else if list_item(line).is_none()
                    && !items.is_empty()
                    && i > 0
                    && !lines[i - 1].trim().is_empty()
                    && heading(t).is_none()
                    && !t.starts_with('|')
                    && !t.starts_with('>')
                    && is_fence(t).is_none()
                {
                    // A lazy continuation line of the item's paragraph.
                    if let Some(last) = items.last_mut() {
                        last.push(t.to_string());
                    }
                    i += 1;
                } else {
                    break;
                }
            }
        }
    }
    let tag = if ordered { "ol" } else { "ul" };
    if ordered && start != 1 {
        let _ = write!(out, "<{tag} start=\"{start}\">");
    } else {
        let _ = write!(out, "<{tag}>");
    }
    for item in &items {
        let refs: Vec<&str> = item.iter().map(String::as_str).collect();
        let html = blocks(&refs, ctx);
        // In a tight list an item's first paragraph renders without its <p>.
        let html = if !loose && html.starts_with("<p>") {
            match html.find("</p>") {
                Some(end) => format!("{}{}", &html[3..end], &html[end + 4..]),
                None => html,
            }
        } else {
            html
        };
        let _ = write!(out, "<li>{}</li>", html.trim_end());
    }
    let _ = writeln!(out, "</{tag}>");
    i
}

fn cells(line: &str) -> Vec<String> {
    let inner = line.trim().trim_start_matches('|');
    let inner = inner.strip_suffix('|').unwrap_or(inner);
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut code = false;
    let mut chars = inner.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\\' if chars.peek() == Some(&'|') => {
                cur.push('|');
                chars.next();
            }
            '`' => {
                code = !code;
                cur.push(c);
            }
            '|' if !code => out.push(std::mem::take(&mut cur).trim().to_string()),
            c => cur.push(c),
        }
    }
    out.push(cur.trim().to_string());
    out
}

/// `[text](href)` at byte `i`: (text, href, end).
fn parse_link(s: &str, i: usize) -> Option<(&str, &str, usize)> {
    let rest = &s[i..];
    if !rest.starts_with('[') {
        return None;
    }
    let mut depth = 0usize;
    let mut close = None;
    let mut in_code = false;
    for (k, c) in rest.char_indices() {
        match c {
            '`' => in_code = !in_code,
            '[' if !in_code => depth += 1,
            ']' if !in_code => {
                depth -= 1;
                if depth == 0 {
                    close = Some(k);
                    break;
                }
            }
            _ => {}
        }
    }
    let close = close?;
    let after = &rest[close + 1..];
    if !after.starts_with('(') {
        return None;
    }
    let end = after.find(')')?;
    let href = after[1..end].trim();
    let href = href.split_whitespace().next().unwrap_or("");
    Some((&rest[1..close], href, i + close + 1 + end + 1))
}

/// Resolve `href` from the doc `src` to a site URL, a GitHub URL, or
/// nothing (shown as text).
fn resolve(href: &str, ctx: &Ctx) -> Option<String> {
    let lower = href.to_ascii_lowercase();
    if lower.starts_with("https://") || lower.starts_with("http://") {
        return Some(href.to_string());
    }
    if let Some(frag) = href.strip_prefix('#') {
        return Some(format!("#{}", frag));
    }
    if lower.contains(':') || href.starts_with("//") || href.is_empty() {
        return None;
    }
    let (path, frag) = match href.split_once('#') {
        Some((p, f)) => (p, Some(f)),
        None => (href, None),
    };
    let target = join(ctx.src, path)?;
    let frag = frag.map(|f| format!("#{f}")).unwrap_or_default();
    if ctx.links.docs.contains(&target) {
        return Some(format!("{}{}{frag}", rel_root(&ctx.page), doc_url(&target)));
    }
    let kind = if path.ends_with('/') || !target.rsplit('/').next().unwrap_or("").contains('.') {
        "tree"
    } else {
        "blob"
    };
    Some(format!("{}/{kind}/main/{target}{frag}", ctx.links.repo))
}

/// A repository path from a doc's path and a relative link. `None` when it
/// leaves the repository.
fn join(src: &str, rel: &str) -> Option<String> {
    let mut parts: Vec<&str> = src.split('/').collect();
    parts.pop();
    for seg in rel.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                parts.pop()?;
            }
            s => parts.push(s),
        }
    }
    Some(parts.join("/"))
}

/// Inline Markdown to HTML: every character of `s` is escaped, and the only
/// markup is what this function writes.
fn inline(s: &str, ctx: &Ctx) -> String {
    let mut out = String::new();
    let b = s.as_bytes();
    let mut i = 0;
    while i < s.len() {
        let c = b[i];
        match c {
            b'\\' if i + 1 < s.len() && b[i + 1].is_ascii_punctuation() => {
                out.push_str(&esc(&s[i + 1..i + 2]));
                i += 2;
                continue;
            }
            b'`' => {
                let n = s[i..].bytes().take_while(|&x| x == b'`').count();
                let fence = &s[i..i + n];
                if let Some(end) = s[i + n..].find(fence) {
                    let code = s[i + n..i + n + end].trim();
                    let _ = write!(out, "<code>{}</code>", esc(code));
                    i += n + end + n;
                    continue;
                }
                out.push_str(fence);
                i += n;
                continue;
            }
            b'*' if s[i..].starts_with("**") => {
                if let Some(end) = s[i + 2..].find("**").filter(|&e| e > 0) {
                    let _ = write!(
                        out,
                        "<strong>{}</strong>",
                        inline(&s[i + 2..i + 2 + end], ctx)
                    );
                    i += end + 4;
                    continue;
                }
            }
            b'*' | b'_' => {
                let prev_word = i > 0 && (b[i - 1] as char).is_alphanumeric();
                let next_space = s[i + 1..].starts_with(' ') || i + 1 >= s.len();
                if !prev_word && !next_space {
                    let m = &s[i..i + 1];
                    if let Some(end) = s[i + 1..].find(m).filter(|&e| e > 0) {
                        let after = s[i + 1 + end + 1..].chars().next();
                        if c == b'*' || !after.is_some_and(char::is_alphanumeric) {
                            let _ = write!(out, "<em>{}</em>", inline(&s[i + 1..i + 1 + end], ctx));
                            i += end + 2;
                            continue;
                        }
                    }
                }
            }
            b'[' => {
                if let Some((text, href, end)) = parse_link(s, i) {
                    let label = inline(text, ctx);
                    match resolve(href, ctx) {
                        Some(url) => {
                            let ext = url.starts_with("http");
                            let _ = write!(
                                out,
                                "<a href=\"{}\"{}>{label}</a>",
                                esc(&url),
                                if ext {
                                    " rel=\"noopener noreferrer\""
                                } else {
                                    ""
                                }
                            );
                        }
                        None => out.push_str(&label),
                    }
                    i = end;
                    continue;
                }
            }
            b'<' => {
                // An autolink <https://...>; anything else is text.
                if let Some(end) = s[i..].find('>') {
                    let inner = &s[i + 1..i + end];
                    let l = inner.to_ascii_lowercase();
                    if (l.starts_with("https://") || l.starts_with("http://"))
                        && !inner.contains(char::is_whitespace)
                    {
                        let _ = write!(
                            out,
                            "<a href=\"{0}\" rel=\"noopener noreferrer\">{0}</a>",
                            esc(inner)
                        );
                        i += end + 1;
                        continue;
                    }
                }
            }
            _ => {}
        }
        let ch = s[i..].chars().next().unwrap_or(' ');
        out.push_str(&esc(ch.encode_utf8(&mut [0; 4])));
        i += ch.len_utf8();
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn render(src: &str, text: &str) -> Doc {
        let docs: BTreeSet<String> = [
            "docs/methodology.md",
            "docs/guides/for-operators.md",
            "docs/reference/cases.md",
        ]
        .into_iter()
        .map(String::from)
        .collect();
        render_doc(
            src,
            text,
            &Links {
                docs: &docs,
                repo: "https://github.com/o/r",
            },
        )
    }

    #[test]
    fn urls_and_slugs() {
        assert_eq!(doc_url("docs/README.md"), "docs/");
        assert_eq!(doc_url("docs/methodology.md"), "methodology/");
        assert_eq!(doc_url("docs/guides/for-operators.md"), "operators/");
        assert_eq!(doc_url("docs/reference/cases.md"), "docs/reference/cases/");
        assert_eq!(doc_url("docs/manual/README.md"), "docs/manual/");
        assert_eq!(slug("What `case.toml` holds"), "what-casetoml-holds");
        assert_eq!(
            slug("Attribution levels and the naming gate"),
            "attribution-levels-and-the-naming-gate"
        );
        assert_eq!(slug("[urlquery.net](x)"), "urlquerynet");
    }

    #[test]
    fn renders_the_subset_and_escapes_everything() {
        let d = render(
            "docs/reference/cases.md",
            "# Cases <x>\n\nIntro with `<b>` and **bold** and *em*.\n\n## A <script>alert(1)</script>\n\n\
- one [m](../methodology.md#known-limits)\n- two [src](../../crates/sc-core/src/lib.rs)\n  - nested [js](javascript:alert(1))\n\n\
1. first\n2. second <img src=x onerror=alert(1)>\n\n| a | b |\n|---|---|\n| `x\\|y` | [w](https://example.org/) |\n\n\
```sh\necho \"<script>\"\n```\n\n> quoted <i>\n\n## A <script>alert(1)</script>\n",
        );
        assert_eq!(d.title, "Cases <x>");
        assert_eq!(d.summary, "Intro with <b> and bold and em.");
        let h = &d.html;
        assert!(
            !h.contains("<script")
                && !h.contains("<img")
                && !h.contains("<i>")
                && !h.contains("<b>"),
            "{h}"
        );
        assert!(h.contains("<code>&lt;b&gt;</code>"));
        assert!(h.contains("<strong>bold</strong>") && h.contains("<em>em</em>"));
        assert!(
            h.contains("href=\"../../../methodology/#known-limits\""),
            "{h}"
        );
        assert!(
            h.contains("href=\"https://github.com/o/r/blob/main/crates/sc-core/src/lib.rs\""),
            "{h}"
        );
        assert!(!h.contains("javascript:alert(1)\""), "{h}");
        assert!(
            h.contains("<li>nested js</li>") || h.contains("nested js"),
            "{h}"
        );
        assert!(h.contains("<ol><li>first</li>"), "{h}");
        assert!(h.contains("<td><code>x|y</code></td>"), "{h}");
        assert!(h.contains("rel=\"noopener noreferrer\""));
        assert!(h.contains("echo &quot;&lt;script&gt;&quot;"));
        assert!(h.contains("<blockquote><p>quoted &lt;i&gt;</p>"));
        assert_eq!(d.toc.len(), 2);
        assert_eq!(d.toc[1].1, "a-scriptalert1script-1");
    }

    #[test]
    fn lists_nest_and_continue() {
        let d = render(
            "docs/methodology.md",
            "# T\n\n- a\n  continued\n- b\n\n  second para\n\n1. x\n   - y\n2. z\n",
        );
        let h = &d.html.replace('\n', "");
        assert!(h.contains("<li>a continued</li>"), "{h}");
        assert!(h.contains("<p>second para</p>"), "{h}");
        assert!(
            h.contains("<ol><li>x<ul><li>y</li></ul></li><li>z</li></ol>"),
            "{h}"
        );
    }
}
