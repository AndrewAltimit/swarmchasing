//! The notice index and one static page per notice. Every field of a notice
//! is escaped; affected hosts are defanged.

use super::html::{esc, pill};
use crate::file::{NoticeFile, UpdateKind};
use crate::markdown::{Block, Inline, md_blocks};
use std::collections::BTreeSet;
use std::fmt::Write;

fn spans(c: &[Inline]) -> String {
    c.iter()
        .map(|s| match s {
            Inline::Text(t) => esc(t),
            Inline::Strong(t) => format!("<strong>{}</strong>", esc(t)),
            Inline::Code(t) => format!("<code>{}</code>", esc(t)),
        })
        .collect()
}

/// A notice body's blocks as HTML. Headings drop one level below the page
/// title.
pub fn body_html(blocks: &[Block]) -> String {
    let mut s = String::new();
    for b in blocks {
        match b {
            Block::Heading { level, c } => {
                let l = (level + 1).clamp(2, 6);
                let _ = writeln!(s, "<h{l}>{}</h{l}>", spans(c));
            }
            Block::Para { c } => {
                let _ = writeln!(s, "<p>{}</p>", spans(c));
            }
            Block::Quote { lines } => {
                s.push_str("<blockquote>");
                for l in lines {
                    let _ = write!(s, "<p>{}</p>", spans(l));
                }
                s.push_str("</blockquote>\n");
            }
            Block::List { ordered, items } => {
                let tag = if *ordered { "ol" } else { "ul" };
                let _ = write!(s, "<{tag}>");
                for it in items {
                    let _ = write!(s, "<li>{}", spans(&it.c));
                    if !it.sub.is_empty() {
                        s.push_str("<ul>");
                        for sub in &it.sub {
                            let _ = write!(s, "<li>{}</li>", spans(sub));
                        }
                        s.push_str("</ul>");
                    }
                    s.push_str("</li>");
                }
                let _ = writeln!(s, "</{tag}>");
            }
            Block::Table { head, rows } => {
                s.push_str("<div class=\"scroll\"><table><thead><tr>");
                for h in head {
                    let _ = write!(s, "<th scope=\"col\">{}</th>", spans(h));
                }
                s.push_str("</tr></thead><tbody>");
                for r in rows {
                    s.push_str("<tr>");
                    for c in r {
                        let _ = write!(s, "<td>{}</td>", spans(c));
                    }
                    s.push_str("</tr>");
                }
                s.push_str("</tbody></table></div>\n");
            }
        }
    }
    s
}

/// `research` as "Research".
fn sector_label(s: &str) -> String {
    let mut c = s.chars();
    c.next()
        .map(|f| f.to_uppercase().chain(c).collect())
        .unwrap_or_default()
}

fn host(h: &str) -> String {
    sc_core::defang_host(h)
}

fn kind_class(k: UpdateKind) -> &'static str {
    match k {
        UpdateKind::Published => "published",
        UpdateKind::Update => "update",
        UpdateKind::Status => "status",
        UpdateKind::Correction => "correction",
        UpdateKind::Reply => "statement",
        UpdateKind::Retraction => "retraction",
    }
}

/// The notices index: a filterable table, or the empty state.
pub fn index_body(notices: &[NoticeFile]) -> String {
    let mut s = String::new();
    s.push_str(
        "<header class=\"page-head\"><h1>Notices</h1>\
<p class=\"lede\">One public notice per confirmed incident. A notice is published at the same moment the reports go to the AI provider and the affected operators: there is no embargo, because a swarm is an active incident. Each notice keeps its dated updates, corrections and statements in place.</p>\
<p class=\"lede\">Notices withhold callback channels, captured credentials and the details of weaknesses that may still be open. Hosts are defanged (<code>a[.]b</code>).</p>\
<p><a class=\"button\" href=\"feed.xml\">Atom feed</a></p></header>\n",
    );
    if notices.is_empty() {
        s.push_str(
            "<section class=\"card empty\" aria-labelledby=\"none-yet\"><h2 id=\"none-yet\">No notices yet</h2>\
<p>Notices appear here only when reports go out: after a lead has been reviewed, linked into a case, and reported to the AI provider and the affected operators. Unreviewed leads are never published.</p>\
<p>Subscribe to the <a href=\"feed.xml\">Atom feed</a> to hear about the first one. How a lead becomes a notice is in the <a href=\"../methodology/\">methodology</a> and the <a href=\"../docs/policies/\">policies</a>.</p></section>\n",
        );
        return s;
    }
    let providers: BTreeSet<&str> = notices
        .iter()
        .flat_map(|n| n.meta.providers.iter().map(String::as_str))
        .collect();
    let sectors: BTreeSet<&str> = notices
        .iter()
        .filter_map(|n| n.meta.sector.as_deref())
        .collect();
    // Progressive enhancement: the table below is the whole index; the form
    // shows only when the page script runs and keeps its state in the hash.
    s.push_str("<form class=\"filters card\" data-notice-filters role=\"search\" aria-label=\"Filter notices\">");
    s.push_str("<label>Status<select name=\"status\"><option value=\"\">Any</option><option value=\"active\">Active</option><option value=\"contained\">Contained</option><option value=\"historical\">Historical</option></select></label>");
    s.push_str("<label>Provider<select name=\"provider\"><option value=\"\">Any</option>");
    for p in &providers {
        let _ = write!(s, "<option value=\"{0}\">{0}</option>", esc(p));
    }
    s.push_str("</select></label>");
    if !sectors.is_empty() {
        s.push_str("<label>Sector<select name=\"sector\"><option value=\"\">Any</option>");
        for x in &sectors {
            let _ = write!(
                s,
                "<option value=\"{}\">{}</option>",
                esc(x),
                esc(&sector_label(x))
            );
        }
        s.push_str("</select></label>");
    }
    s.push_str("<label>Affected organisation or host<input name=\"host\" type=\"search\" spellcheck=\"false\" placeholder=\"example[.]org\"></label>");
    s.push_str("<label>Text<input name=\"q\" type=\"search\" placeholder=\"Title or id\"></label>");
    s.push_str("<label>Updated from<input name=\"from\" type=\"date\"></label>");
    s.push_str("<label>to<input name=\"to\" type=\"date\"></label>");
    s.push_str("<p class=\"filter-actions\"><button type=\"reset\">Clear filters</button></p>");
    s.push_str("<p class=\"hint\" data-notice-count aria-live=\"polite\"></p></form>\n");
    s.push_str("<div class=\"scroll\"><table class=\"notice-table\"><thead><tr><th scope=\"col\">Notice</th><th scope=\"col\">Status</th><th scope=\"col\">Provider</th><th scope=\"col\">Affected</th><th scope=\"col\">Sector</th><th scope=\"col\">Updated</th></tr></thead><tbody>");
    for n in notices {
        let m = &n.meta;
        let has = |k| m.updates.iter().any(|u| u.kind == k);
        let flag = if has(UpdateKind::Retraction) {
            "<span class=\"flag retraction\">retracted</span>"
        } else if has(UpdateKind::Correction) {
            "<span class=\"flag correction\">corrected</span>"
        } else {
            ""
        };
        let hosts: Vec<String> = m.affected.iter().map(|h| host(h)).collect();
        let _ = write!(
            s,
            "<tr data-status=\"{}\" data-sector=\"{}\" data-providers=\"{}\" data-hosts=\"{}\" data-text=\"{}\" data-updated=\"{}\">\
<td><a href=\"{}/\">{}</a> {flag}<div class=\"hint\">{}</div></td><td data-label=\"Status\">{}</td><td data-label=\"Provider\">{}</td><td data-label=\"Affected\">{}</td><td data-label=\"Sector\">{}</td><td class=\"nowrap\" data-label=\"Updated\">{}</td></tr>",
            esc(m.status.label()),
            esc(m.sector.as_deref().unwrap_or("")),
            esc(&m.providers.join("\n")),
            esc(&format!("{}\n{}", hosts.join("\n"), m.affected.join("\n"))),
            esc(&format!("{} {}", m.title, m.id)),
            esc(&m.updated),
            esc(&m.id),
            esc(&m.title),
            esc(&m.id),
            pill(m.status.label()),
            if m.providers.is_empty() {
                "–".to_string()
            } else {
                esc(&m.providers.join(", "))
            },
            hosts
                .iter()
                .map(|h| format!("<span class=\"chip\">{}</span>", esc(h)))
                .collect::<String>(),
            m.sector
                .as_deref()
                .map_or_else(|| "–".to_string(), |x| esc(&sector_label(x))),
            esc(&m.updated),
        );
    }
    s.push_str("</tbody></table></div>\n<p class=\"hint\" data-notice-none hidden>No notices match these filters.</p>\n");
    s
}

/// One notice's page body.
pub fn page_body(n: &NoticeFile) -> String {
    let m = &n.meta;
    let mut s = String::new();
    let retracted = m.updates.iter().any(|u| u.kind == UpdateKind::Retraction);
    let _ = write!(
        s,
        "<nav class=\"crumbs\" aria-label=\"Breadcrumb\"><a href=\"../\">Notices</a> / <span>{}</span></nav>\n\
<article class=\"notice{}\">\n<header class=\"page-head\"><h1>{}</h1>\n<p class=\"meta\">{} Published {} · updated {}</p>\n",
        esc(&m.id),
        if retracted { " retracted" } else { "" },
        esc(&m.title),
        pill(m.status.label()),
        esc(&m.published),
        esc(&m.updated),
    );
    if retracted {
        s.push_str("<p class=\"banner retraction\" role=\"note\"><strong>Retracted.</strong> This notice was withdrawn; the retraction below says why. It stays published so the record is complete.</p>\n");
    }
    s.push_str("<dl class=\"kv\">");
    let _ = write!(
        s,
        "<dt>Provider</dt><dd>{}</dd><dt>Affected</dt><dd>{}</dd>{}<dt>Method</dt><dd>rules {} · toolkit {} · <a href=\"../../methodology/\">methodology</a></dd>",
        if m.providers.is_empty() {
            "not named (the evidence has not reached the naming threshold)".to_string()
        } else {
            esc(&m.providers.join(", "))
        },
        if m.affected.is_empty() {
            "–".to_string()
        } else {
            m.affected
                .iter()
                .map(|h| format!("<span class=\"chip\">{}</span>", esc(&host(h))))
                .collect()
        },
        m.sector.as_deref().map_or_else(String::new, |x| format!(
            "<dt>Sector</dt><dd>{}</dd>",
            esc(&sector_label(x))
        )),
        esc(&m.rules_version),
        esc(&m.toolkit),
    );
    s.push_str("</dl></header>\n");
    s.push_str("<section aria-labelledby=\"timeline\"><h2 id=\"timeline\">Timeline</h2><ol class=\"timeline\">");
    for u in &m.updates {
        let k = kind_class(u.kind);
        let flagged = matches!(u.kind, UpdateKind::Correction | UpdateKind::Retraction);
        let _ = write!(
            s,
            "<li class=\"t-{k}{}\"><span class=\"t-dot\" aria-hidden=\"true\"></span><p class=\"t-head\"><time datetime=\"{}\">{}</time> <span class=\"t-kind\">{}</span></p>",
            if flagged { " flagged" } else { "" },
            esc(&u.date),
            esc(&u.date),
            esc(u.kind.label()),
        );
        if u.kind == UpdateKind::Reply {
            let _ = write!(
                s,
                "<figure class=\"statement\"><blockquote class=\"verbatim\">{}</blockquote><figcaption>Statement from {}, quoted verbatim</figcaption></figure>",
                esc(&u.text),
                esc(u.from.as_deref().unwrap_or("an unnamed party")),
            );
        } else {
            let _ = write!(s, "<p class=\"verbatim\">{}</p>", esc(&u.text));
        }
        s.push_str("</li>");
    }
    s.push_str("</ol></section>\n<section class=\"notice-body\" aria-label=\"Notice\">\n");
    s.push_str(&body_html(&md_blocks(&n.body)));
    let _ = write!(
        s,
        "</section>\n<p class=\"hint\">Machine-readable: <a href=\"../{}.json\">{}.json</a> · <a href=\"../feed.xml\">Atom feed</a></p>\n</article>\n",
        esc(&m.id),
        esc(&m.id),
    );
    s
}
