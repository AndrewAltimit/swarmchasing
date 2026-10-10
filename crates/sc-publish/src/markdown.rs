//! A notice body parsed into plain blocks, the subset the report renderer
//! writes. The site renders each span as text, never as HTML.

use serde::Serialize;

/// Inline Markdown, as plain text spans. The page inserts each as text.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "t", content = "v", rename_all = "snake_case")]
pub enum Inline {
    Text(String),
    Strong(String),
    Code(String),
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ListItem {
    pub c: Vec<Inline>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub sub: Vec<Vec<Inline>>,
}

/// The block subset the report renderer writes.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum Block {
    Heading {
        level: u8,
        c: Vec<Inline>,
    },
    Para {
        c: Vec<Inline>,
    },
    Quote {
        lines: Vec<Vec<Inline>>,
    },
    List {
        ordered: bool,
        items: Vec<ListItem>,
    },
    Table {
        head: Vec<Vec<Inline>>,
        rows: Vec<Vec<Vec<Inline>>>,
    },
}

pub fn md_inline(s: &str) -> Vec<Inline> {
    let mut out = Vec::new();
    let mut text = String::new();
    let mut rest = s;
    while !rest.is_empty() {
        let (marker, ctor): (&str, fn(String) -> Inline) = if rest.starts_with("**") {
            ("**", Inline::Strong)
        } else if rest.starts_with('`') {
            ("`", Inline::Code)
        } else {
            let ch = rest.chars().next().unwrap_or_default();
            text.push(ch);
            rest = &rest[ch.len_utf8()..];
            continue;
        };
        match rest[marker.len()..].find(marker) {
            Some(end) => {
                if !text.is_empty() {
                    out.push(Inline::Text(std::mem::take(&mut text)));
                }
                out.push(ctor(rest[marker.len()..marker.len() + end].to_string()));
                rest = &rest[marker.len() * 2 + end..];
            }
            None => {
                text.push_str(marker);
                rest = &rest[marker.len()..];
            }
        }
    }
    if !text.is_empty() {
        out.push(Inline::Text(text));
    }
    out
}

fn table_cells(line: &str) -> Vec<Vec<Inline>> {
    let inner = line.trim().trim_start_matches('|');
    let inner = inner.strip_suffix('|').unwrap_or(inner);
    let mut cells = Vec::new();
    let mut cur = String::new();
    let mut chars = inner.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\\' if chars.peek() == Some(&'|') => {
                cur.push('|');
                chars.next();
            }
            '|' => cells.push(std::mem::take(&mut cur)),
            c => cur.push(c),
        }
    }
    cells.push(cur);
    cells.iter().map(|c| md_inline(c.trim())).collect()
}

fn list_marker(line: &str) -> Option<(usize, bool, &str)> {
    let indent = line.len() - line.trim_start().len();
    let t = line.trim_start();
    if let Some(r) = t.strip_prefix("- ") {
        return Some((indent, false, r));
    }
    let digits = t.chars().take_while(|c| c.is_ascii_digit()).count();
    if digits > 0
        && let Some(r) = t[digits..].strip_prefix(". ")
    {
        return Some((indent, true, r));
    }
    None
}

/// Parse a notice body into blocks.
pub fn md_blocks(body: &str) -> Vec<Block> {
    let lines: Vec<&str> = body.lines().collect();
    let mut out = Vec::new();
    let mut i = 0;
    let mut para: Vec<&str> = Vec::new();
    let flush = |para: &mut Vec<&str>, out: &mut Vec<Block>| {
        if !para.is_empty() {
            out.push(Block::Para {
                c: md_inline(&para.join(" ")),
            });
            para.clear();
        }
    };
    while i < lines.len() {
        let line = lines[i];
        let t = line.trim();
        if t.is_empty() {
            flush(&mut para, &mut out);
            i += 1;
        } else if t.starts_with("<!--") {
            flush(&mut para, &mut out);
            while i < lines.len() && !lines[i].contains("-->") {
                i += 1;
            }
            i += 1;
        } else if let Some(level) = (1..=4).find(|&n| t.starts_with(&format!("{} ", "#".repeat(n))))
        {
            flush(&mut para, &mut out);
            out.push(Block::Heading {
                level: level as u8,
                c: md_inline(t[level + 1..].trim()),
            });
            i += 1;
        } else if t.starts_with('>') {
            flush(&mut para, &mut out);
            let mut q = Vec::new();
            while i < lines.len() && lines[i].trim().starts_with('>') {
                let l = lines[i].trim().trim_start_matches('>').trim();
                q.push(md_inline(l));
                i += 1;
            }
            out.push(Block::Quote { lines: q });
        } else if t.starts_with('|') {
            flush(&mut para, &mut out);
            let head = table_cells(t);
            i += 1;
            if lines.get(i).is_some_and(|l| {
                let l = l.trim();
                l.starts_with("|-") || l.starts_with("|:")
            }) {
                i += 1;
            }
            let mut rows = Vec::new();
            while i < lines.len() && lines[i].trim().starts_with('|') {
                rows.push(table_cells(lines[i]));
                i += 1;
            }
            out.push(Block::Table { head, rows });
        } else if let Some((0, ordered, _)) = list_marker(line) {
            flush(&mut para, &mut out);
            let mut items: Vec<ListItem> = Vec::new();
            while i < lines.len() {
                match list_marker(lines[i]) {
                    Some((0, o, r)) if o == ordered => items.push(ListItem {
                        c: md_inline(r),
                        sub: Vec::new(),
                    }),
                    Some((n, _, r)) if n > 0 && !items.is_empty() => {
                        if let Some(last) = items.last_mut() {
                            last.sub.push(md_inline(r));
                        }
                    }
                    _ => break,
                }
                i += 1;
            }
            out.push(Block::List { ordered, items });
        } else {
            para.push(t);
            i += 1;
        }
    }
    flush(&mut para, &mut out);
    out
}
