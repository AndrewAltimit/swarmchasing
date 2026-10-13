//! The notice index and one static page per notice. Every field of a notice
//! is escaped; affected hosts are defanged.
//!
//! A notice is published in two stages: the indicator notice, which names
//! and locates no affected party, then naming updates. Until its first
//! naming update a notice shows no affected host anywhere (the linter
//! refuses one that lists any), and each page says which stage it is in.

use super::html::{esc, pill};
use crate::file::{NoticeFile, NoticeMeta, UpdateKind};
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

/// The date of the notice's latest naming update; `None` while it is an
/// indicator notice.
pub fn named_on(m: &NoticeMeta) -> Option<&str> {
    m.updates
        .iter()
        .rev()
        .find(|u| u.kind == UpdateKind::Naming)
        .map(|u| u.date.as_str())
}

/// The affected hosts a page may show: none before a naming update.
pub fn shown_affected(m: &NoticeMeta) -> &[String] {
    if named_on(m).is_some() {
        &m.affected
    } else {
        &[]
    }
}

/// Which stage the notice is in, as one line.
pub fn stage_text(m: &NoticeMeta) -> String {
    match named_on(m) {
        Some(d) => format!("Affected organisations named on {d}"),
        None => "Indicators published; affected organisations not named yet".into(),
    }
}

/// The stage line as markup (`.notice-stage`).
pub fn stage_html(m: &NoticeMeta) -> String {
    format!(
        "<span class=\"notice-stage\">{}</span>",
        esc(&stage_text(m))
    )
}

/// How the timeline labels an update: the first is the indicator notice.
fn update_label(k: UpdateKind) -> &'static str {
    match k {
        UpdateKind::Published => "Indicator notice published",
        k => k.label(),
    }
}

fn kind_class(k: UpdateKind) -> &'static str {
    match k {
        UpdateKind::Published => "published",
        UpdateKind::Update => "update",
        UpdateKind::Status => "status",
        UpdateKind::Correction => "correction",
        UpdateKind::Naming => "naming",
        UpdateKind::Reply => "statement",
        UpdateKind::Retraction => "retraction",
    }
}

/// The notices index: a filterable table, or the empty state.
pub fn index_body(notices: &[NoticeFile]) -> String {
    let mut s = String::new();
    s.push_str(
        "<header class=\"page-head\"><h1>Notices</h1>\
<p class=\"lede\">One public notice per confirmed incident, in two stages: first the indicators, which name and locate no affected organisation, then the names in dated updates once each operator's naming clock has run. Notices withhold callback channels, credentials and open weaknesses, and hosts are defanged (<code>a[.]b</code>). <a href=\"../docs/policies/#two-stages\">How notices work</a>.</p>\
<p><a class=\"button\" href=\"feed.xml\">Atom feed</a></p></header>\n",
    );
    if notices.is_empty() {
        s.push_str(
            "<section class=\"card empty\" aria-labelledby=\"none-yet\"><h2 id=\"none-yet\">No notices yet</h2>\
<p>Notices appear here only when reports go out: after a lead has been reviewed, linked into a case, and reported to the AI provider and the affected operators. Unreviewed leads are never published.</p>\
<p>Subscribe to the <a href=\"feed.xml\">Atom feed</a> to hear about the first one. To see what one looks like, read the <a href=\"../#example-notice\">synthetic example notice</a> on the home page, drafted by the engine from the showcase records. How a lead becomes a notice is in the <a href=\"../methodology/\">methodology</a> and the <a href=\"../docs/policies/\">policies</a>.</p></section>\n",
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
    // `details.filters-fold`: hidden until the page script runs, which
    // shows it, closed on a phone unless the address carries filters.
    s.push_str("<details class=\"filters-fold\" open hidden><summary>Filter notices</summary><form class=\"filters card\" data-notice-filters role=\"search\" aria-label=\"Filter notices\">");
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
    // The two dates are one control: a fieldset keeps them on one row.
    s.push_str("<fieldset class=\"dates\"><legend>Updated</legend><label>From<input name=\"from\" type=\"date\"></label><label>To<input name=\"to\" type=\"date\"></label></fieldset>");
    s.push_str("<p class=\"filter-actions\"><button type=\"reset\">Clear filters</button></p>");
    s.push_str("<p class=\"hint\" data-notice-count aria-live=\"polite\"></p></form></details>\n");
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
        let named = shown_affected(m);
        let hosts: Vec<String> = named.iter().map(|h| host(h)).collect();
        let _ = write!(
            s,
            "<tr data-status=\"{}\" data-sector=\"{}\" data-providers=\"{}\" data-hosts=\"{}\" data-text=\"{}\" data-updated=\"{}\">\
<td><a href=\"{}/\">{}</a> {flag}<div class=\"hint\">{}</div></td><td data-label=\"Status\">{} {}</td><td data-label=\"Provider\">{}</td><td data-label=\"Affected\">{}</td><td data-label=\"Sector\">{}</td><td class=\"nowrap\" data-label=\"Updated\">{}</td></tr>",
            esc(m.status.label()),
            esc(m.sector.as_deref().unwrap_or("")),
            esc(&m.providers.join("\n")),
            esc(&format!("{}\n{}", hosts.join("\n"), named.join("\n"))),
            esc(&format!("{} {}", m.title, m.id)),
            esc(&m.updated),
            esc(&m.id),
            esc(&m.title),
            esc(&m.id),
            pill(m.status.label()),
            stage_html(m),
            if m.providers.is_empty() {
                "<span class=\"hint\">not named</span>".to_string()
            } else {
                esc(&m.providers.join(", "))
            },
            if hosts.is_empty() {
                "<span class=\"hint\">not named yet</span>".to_string()
            } else {
                hosts
                    .iter()
                    .map(|h| format!("<span class=\"chip\">{}</span>", esc(h)))
                    .collect::<String>()
            },
            m.sector
                .as_deref()
                .map_or_else(|| "–".to_string(), |x| esc(&sector_label(x))),
            esc(&m.updated),
        );
    }
    s.push_str("</tbody></table></div>\n<p class=\"hint\" data-notice-none hidden>No notices match these filters.</p>\n");
    s
}

/// What a notice page tells the people it concerns: where operators and
/// providers start, and the private way to reach the project; before the
/// first naming update, also when an operator's name may appear. Paths are
/// from `notices/<id>/`.
fn notice_aside(named: bool) -> String {
    format!(
        "<aside class=\"notice-aside\" aria-labelledby=\"concerns\"><h2 id=\"concerns\">If this notice concerns you</h2><ul>{}\
<li><strong>You run a site or service.</strong> <a href=\"../../operators/\">For operators</a> explains what a notice means, what becomes public and when, and how to check your own logs.</li>\
<li><strong>You work at an AI provider.</strong> <a href=\"../../providers/\">For providers</a> covers the report you were sent, checking its evidence and how you are named.</li>\
<li><strong>To ask for the full report, send a statement or point out an error,</strong> use the <a href=\"../../operators/#contact\">private contact</a>. Please do not open a public issue about an affected host or organisation: it would name it before its naming update.</li>\
</ul></aside>\n",
        if named {
            ""
        } else {
            "<li><strong>Received a report about this incident?</strong> Your organisation is not named here until its naming update, 3 working days after your report (10 if your systems were compromised), or sooner only with your consent.</li>"
        }
    )
}

/// The notice body without its own top heading: the page title stands for
/// it.
fn body_without_title(body: &str) -> String {
    let mut blocks = md_blocks(body);
    if matches!(blocks.first(), Some(Block::Heading { level: 1, .. })) {
        blocks.remove(0);
    }
    body_html(&blocks)
}

/// One notice's page body: the header with its stage, who to turn to, the
/// notice itself, then its dated updates.
pub fn page_body(n: &NoticeFile) -> String {
    let m = &n.meta;
    let mut s = String::new();
    let retracted = m.updates.iter().any(|u| u.kind == UpdateKind::Retraction);
    let named = shown_affected(m);
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
        "<dt>Stage</dt><dd>{}</dd><dt>Provider</dt><dd>{}</dd><dt>Affected</dt><dd>{}</dd>{}<dt>Method</dt><dd>rules {} · toolkit {} · <a href=\"../../methodology/\">methodology</a></dd>",
        stage_html(m),
        if m.providers.is_empty() {
            "not named (the evidence has not reached the naming threshold)".to_string()
        } else {
            esc(&m.providers.join(", "))
        },
        if named.is_empty() {
            "not named yet".to_string()
        } else {
            named
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
    s.push_str(&notice_aside(named_on(m).is_some()));
    s.push_str("<section class=\"notice-body\" aria-label=\"Notice\">\n");
    s.push_str(&body_without_title(&n.body));
    s.push_str("</section>\n<section aria-labelledby=\"timeline\"><h2 id=\"timeline\">Timeline</h2><ol class=\"timeline\">");
    for u in &m.updates {
        let k = kind_class(u.kind);
        let flagged = matches!(u.kind, UpdateKind::Correction | UpdateKind::Retraction);
        let _ = write!(
            s,
            "<li class=\"t-{k}{}\"><span class=\"t-dot\" aria-hidden=\"true\"></span><p class=\"t-head\"><time datetime=\"{}\">{}</time> <span class=\"t-kind\">{}</span></p>",
            if flagged { " flagged" } else { "" },
            esc(&u.date),
            esc(&u.date),
            esc(update_label(u.kind)),
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
    let _ = write!(
        s,
        "</ol></section>\n<p class=\"hint\">Machine-readable: <a href=\"../{}.json\">{}.json</a> · <a href=\"../feed.xml\">Atom feed</a></p>\n</article>\n",
        esc(&m.id),
        esc(&m.id),
    );
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(text: &str) -> NoticeFile {
        crate::parse_notice(text).unwrap()
    }

    fn fixture() -> NoticeFile {
        parse(include_str!(
            "../../tests/fixtures/notices/synthetic-portal-probe.md"
        ))
    }

    fn indicator_only() -> NoticeFile {
        parse(include_str!(
            "../../tests/fixtures/notices/synthetic-indicator-only.md"
        ))
    }

    fn named_later() -> NoticeFile {
        parse(include_str!(
            "../../tests/fixtures/notices/synthetic-named-later.md"
        ))
    }

    #[test]
    fn a_notice_page_tells_the_people_it_concerns_where_to_start() {
        let p = page_body(&fixture());
        let aside = p.find("<aside class=\"notice-aside\"").unwrap();
        assert!(aside < p.find("id=\"timeline\"").unwrap());
        for href in [
            "../../operators/",
            "../../providers/",
            "../../operators/#contact",
        ] {
            assert!(p.contains(&format!("href=\"{href}\"")), "{href}");
        }
        // The notice reads before its timeline, without a second title.
        assert!(p.find("class=\"notice-body\"").unwrap() < p.find("id=\"timeline\"").unwrap());
        assert!(!p.contains("<h2>Synthetic test notice</h2>"));
    }

    #[test]
    fn an_indicator_notice_names_and_locates_no_affected_host() {
        let n = indicator_only();
        assert!(crate::check_notice(&n, &sc_core::Rules::default_rules()).is_empty());
        let page = page_body(&n);
        let idx = index_body(std::slice::from_ref(&n));
        for html in [&page, &idx] {
            assert!(!html.contains("[.]example"), "a host in stage 1: {html}");
            assert!(html.contains(
                "<span class=\"notice-stage\">Indicators published; affected organisations not named yet</span>"
            ));
        }
        assert!(page.contains("<dt>Affected</dt><dd>not named yet</dd>"));
        assert!(page.contains("Received a report about this incident?"));
        assert!(page.contains("Indicator notice published"));
        assert!(idx.contains("data-hosts=\"\n\""));
        assert!(idx.contains(
            "<td data-label=\"Affected\"><span class=\"hint\">not named yet</span></td>"
        ));
        assert!(
            idx.contains("<td data-label=\"Provider\"><span class=\"hint\">not named</span></td>")
        );

        // Hosts listed before a naming update are refused by the linter,
        // and the pages still show none of them.
        let mut early = n.clone();
        early.meta.affected = vec!["portal.data.example".into()];
        assert!(!crate::check_notice(&early, &sc_core::Rules::default_rules()).is_empty());
        assert!(!page_body(&early).contains("portal[.]data[.]example"));
        assert!(!index_body(&[early]).contains("portal[.]data[.]example"));
    }

    #[test]
    fn a_naming_update_names_the_hosts_and_says_when() {
        let n = named_later();
        assert!(crate::check_notice(&n, &sc_core::Rules::default_rules()).is_empty());
        let page = page_body(&n);
        assert!(page.contains("<span class=\"chip\">lab[.]university[.]example</span>"));
        assert!(page.contains(
            "<span class=\"notice-stage\">Affected organisations named on 2026-09-25</span>"
        ));
        assert!(page.contains("<span class=\"t-kind\">Affected organisations named</span>"));
        assert!(!page.contains("Received a report about this incident?"));
        let idx = index_body(&[n]);
        assert!(idx.contains("library[.]university[.]example"));
    }

    #[test]
    fn the_date_filters_share_one_fieldset() {
        let idx = index_body(&[fixture()]);
        assert!(idx.contains(
            "<fieldset class=\"dates\"><legend>Updated</legend><label>From<input name=\"from\" type=\"date\"></label><label>To<input name=\"to\" type=\"date\"></label></fieldset>"
        ));
        assert!(idx.contains("<details class=\"filters-fold\""));
    }
}
