//! The public site as files: every page, generated from committed inputs
//! only (notices, docs, the bundled rules and the labelled samples), plus
//! the notice JSON, the feed, the sitemap and the files the browser fetches.
//! Text in, text out: the `sc-site` binary reads the inputs and writes the
//! output.
//!
//! Every value from an input is escaped ([`html::esc`]); pages carry the
//! strict policy in [`layout::CSP`] and no inline script or style.

pub mod docs;
pub mod evalpage;
pub mod home;
pub mod html;
pub mod layout;
pub mod manual;
pub mod notices;
pub mod rules;
pub mod shells;
pub mod svg;
pub mod walk;

use crate::file::NoticeFile;
use crate::site::build_site;
use layout::{Page, rel_root, render};
use sc_core::{FieldMap, Format, Rules};
use std::collections::BTreeSet;
use std::fmt::Write;

/// The showcase set the landing page walks through and the workbench's
/// "Try an example" loads (`samples/showcase/`). Every record in it must be
/// marked synthetic.
pub const EXAMPLE_FILE: &str = "showcase.ndjson";

/// Fields of a labelled record that carry the answer, stripped from the
/// example the workbench loads.
const LABEL_FIELDS: [&str; 5] = ["label", "class", "cite", "hard_negative_for", "run"];

/// What the site is built from. Every field holds committed text.
pub struct SiteInputs {
    pub notices: Vec<NoticeFile>,
    /// (repository path, text) of every `docs/**/*.md`.
    pub docs: Vec<(String, String)>,
    /// `rules/default.toml`.
    pub rules_toml: String,
    /// (file name, NDJSON) of every `samples/eval/*.ndjson`.
    pub eval_set: Vec<(String, String)>,
    /// `samples/showcase/showcase.ndjson`: synthetic records for the landing
    /// page and the workbench's example.
    pub showcase: String,
    /// `samples/eval/coverage-allow.txt`, or empty.
    pub coverage_allow: String,
    /// The site's public URL.
    pub base_url: String,
    /// `https://github.com/<owner>/<repo>`.
    pub repo: String,
    pub version: String,
    /// Size of the engine module in bytes, when it was built first.
    pub engine_bytes: Option<u64>,
    /// Size of the tools module (reports, bundle check, eval) in bytes.
    pub tools_bytes: Option<u64>,
}

/// Values every page's shell shows.
pub struct Ctx {
    pub version: String,
    pub rules_version: String,
    pub repo: String,
    /// "1.3 MB", for the engine's loading message.
    pub engine_size: String,
    /// The same for the tools module.
    pub tools_size: String,
}

/// The example records for the workbench: the example file without its
/// label fields. Refuses a record not marked synthetic.
pub fn example_records(ndjson: &str) -> Result<String, String> {
    let mut out = Vec::new();
    for (n, line) in ndjson.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let mut v: serde_json::Value = serde_json::from_str(line)
            .map_err(|e| format!("{EXAMPLE_FILE} line {}: {e}", n + 1))?;
        let m = v
            .as_object_mut()
            .ok_or_else(|| format!("{EXAMPLE_FILE} line {}: not an object", n + 1))?;
        if m.get("synthetic") != Some(&serde_json::Value::Bool(true)) {
            return Err(format!(
                "{EXAMPLE_FILE} line {}: not marked synthetic; the example may hold only synthetic records",
                n + 1
            ));
        }
        for k in LABEL_FIELDS {
            m.remove(k);
        }
        out.push(v.to_string());
    }
    Ok(out.join("\n") + "\n")
}

fn page(path: &str, nav: &'static str, title: &str, description: &str, body: String) -> Page {
    Page {
        path: path.to_string(),
        nav,
        title: title.to_string(),
        description: description.to_string(),
        body,
        scripts: Vec::new(),
        wide: false,
        engine: false,
    }
}

fn docs_sidebar(all: &[docs::Doc], current: &str) -> String {
    let mut s =
        String::from("<nav class=\"doc-nav\" aria-label=\"Docs\"><p class=\"nav-h\">Docs</p><ul>");
    let mut groups: Vec<(&str, Vec<&docs::Doc>)> = Vec::new();
    for d in all {
        let rel = d.src.strip_prefix("docs/").unwrap_or(&d.src);
        let group = rel.split_once('/').map_or("", |(g, _)| g);
        match groups.iter_mut().find(|(g, _)| *g == group) {
            Some((_, v)) => v.push(d),
            None => groups.push((group, vec![d])),
        }
    }
    groups.sort_by_key(|(g, _)| (!g.is_empty(), *g));
    for (g, ds) in groups {
        if !g.is_empty() {
            let _ = write!(
                s,
                "</ul><p class=\"nav-h\">{}</p><ul>",
                html::esc(&title_case(g))
            );
        }
        for d in ds {
            let cur = if d.src == current {
                " aria-current=\"page\""
            } else {
                ""
            };
            let _ = write!(
                s,
                "<li><a href=\"{}{}\"{cur}>{}</a></li>",
                rel_root(&format!("{}index.html", docs::doc_url(current))),
                html::esc(&d.url),
                html::esc(&d.title)
            );
        }
    }
    s.push_str("</ul></nav>");
    s
}

fn title_case(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
        None => String::new(),
    }
}

fn doc_body(d: &docs::Doc, all: &[docs::Doc], repo: &str, before: &str, after: &str) -> String {
    let mut toc = String::new();
    if d.toc.len() > 2 {
        toc.push_str("<nav class=\"toc\" aria-label=\"On this page\"><p class=\"nav-h\">On this page</p><ol>");
        for (level, id, text) in &d.toc {
            let _ = write!(
                toc,
                "<li class=\"l{level}\"><a href=\"#{}\">{}</a></li>",
                html::esc(id),
                html::esc(text)
            );
        }
        toc.push_str("</ol></nav>");
    }
    format!(
        "<div class=\"doc-layout\">{}<article class=\"doc prose\"><header class=\"page-head\"><h1>{}</h1></header>{before}{}{after}<p class=\"hint doc-src\">Source: <a href=\"{}/blob/main/{}\">{}</a></p></article>{toc}</div>",
        docs_sidebar(all, &d.src),
        html::esc(&d.title),
        d.html,
        html::esc(repo),
        html::esc(&d.src),
        html::esc(&d.src),
    )
}

fn module_size(bytes: Option<u64>) -> String {
    match bytes {
        Some(b) => format!("{:.1} MB", b as f64 / 1_048_576.0),
        None => "1.5 MB".into(),
    }
}

/// The manual's pages in reading order: the index, the chapters, then the
/// glossary and the references.
fn manual_pages(docs: &[docs::Doc]) -> Vec<&docs::Doc> {
    let mut m: Vec<&docs::Doc> = docs
        .iter()
        .filter(|d| d.src.starts_with("docs/manual/"))
        .collect();
    let rank = |d: &docs::Doc| {
        let name = d.src.rsplit('/').next().unwrap_or("").to_string();
        let r = match name.as_str() {
            "README.md" => 0,
            "glossary.md" => 2,
            "references.md" => 3,
            _ => 1,
        };
        (r, name)
    };
    m.sort_by_key(|d| rank(d));
    m
}

/// What the docs auto-link: section ids, tactic ids, glossary terms.
fn manual_terms(first: &[docs::Doc], sources: &[(String, String)]) -> docs::Terms {
    let mut t = docs::Terms::default();
    for f in docs::fm_sections(first) {
        if f.id == "FM-4.3" {
            for n in 1..=9 {
                t.tactics
                    .insert(format!("SC-T{n}"), format!("{}#sc-t{n}", f.url));
            }
        }
        t.fm.insert(f.id, format!("{}#{}", f.url, f.anchor));
    }
    if let Some((src, text)) = sources.iter().find(|(p, _)| p == "docs/manual/glossary.md") {
        let url = docs::doc_url(src);
        t.gloss = docs::glossary_terms(text)
            .into_iter()
            // Multi-word terms only: single words (case, record, agent)
            // are too often used in their ordinary sense.
            .filter(|(term, _)| term.contains(' '))
            .map(|(term, def)| {
                let href = format!("{url}#{}", docs::term_anchor(&term));
                (term, def, href)
            })
            .collect();
        t.gloss
            .sort_by(|a, b| b.0.len().cmp(&a.0.len()).then(a.0.cmp(&b.0)));
    }
    t
}

/// Every file of the site except the static assets (`site/` is copied as
/// it is) and the WASM package: (path under the site root, contents).
/// Refuses when a notice fails its check or an input does not parse.
pub fn build_pages(inp: &mut SiteInputs) -> Result<Vec<(String, String)>, String> {
    let rules = Rules::from_toml(&inp.rules_toml)?;
    let base = if inp.base_url.ends_with('/') {
        inp.base_url.clone()
    } else {
        format!("{}/", inp.base_url)
    };
    let ctx = Ctx {
        version: inp.version.clone(),
        rules_version: rules.set.meta.version.clone(),
        repo: inp.repo.clone(),
        engine_size: module_size(inp.engine_bytes),
        tools_size: module_size(inp.tools_bytes),
    };
    let mut out: Vec<(String, String)> = Vec::new();
    // Notice data (newest first) as the CLI's `notice build` writes it.
    for (name, text) in build_site(&mut inp.notices, &base, &rules)? {
        out.push((format!("notices/{name}"), text));
    }
    let mut pages: Vec<Page> = Vec::new();

    // The showcase (the landing page's walk and the workbench's example),
    // the eval data, the precomputed eval.
    inp.eval_set.sort_by(|a, b| a.0.cmp(&b.0));
    if inp.showcase.trim().is_empty() {
        return Err(format!(
            "samples/showcase/{EXAMPLE_FILE} is empty or missing"
        ));
    }
    let example = example_records(&inp.showcase)?;
    let example_analysis = sc_core::analyze(
        sc_core::parse_input(&example, Format::Ndjson, &FieldMap::default()).observations,
        &rules,
    );
    out.push(("assets/example.ndjson".into(), example));
    let files: Vec<String> = inp.eval_set.iter().map(|(n, _)| n.clone()).collect();
    let mut set = String::new();
    for (_, t) in &inp.eval_set {
        set.push_str(t.trim_end());
        set.push('\n');
    }
    // Labels per file, each marked with its file name, as `swarmchase eval`
    // reads them: the summary's per-file slices need the origin.
    let mut labels = sc_core::LabelSet::default();
    for (name, text) in &inp.eval_set {
        let mut l = sc_core::parse_labels(text);
        for v in l.labels.values_mut() {
            v.origin = Some(name.clone());
        }
        labels.skipped += l.skipped;
        labels.labels.extend(l.labels);
        labels.actors.extend(l.actors);
        labels.provenance.extend(l.provenance);
        labels.warnings.extend(l.warnings);
    }
    let eval_analysis = sc_core::analyze(
        sc_core::parse_input(&set, Format::Ndjson, &FieldMap::default()).observations,
        &rules,
    );
    let (report, _, summary) = sc_core::summarize(
        &eval_analysis,
        &labels,
        &inp.rules_toml,
        &inp.coverage_allow,
    )?;
    out.push((
        "assets/eval-summary.json".into(),
        serde_json::to_string(&summary).map_err(|e| e.to_string())?,
    ));
    out.push((
        "assets/eval-set.json".into(),
        serde_json::json!({ "files": files, "ndjson": set }).to_string(),
    ));

    // Notices.
    let mut idx = page(
        "notices/index.html",
        "notices",
        "Notices",
        "Public notices of confirmed incidents, with their dated updates, corrections and statements.",
        notices::index_body(&inp.notices),
    );
    idx.scripts.push("js/pages/notices.js");
    pages.push(idx);
    for n in &inp.notices {
        pages.push(page(
            &format!("notices/{}/index.html", n.meta.id),
            "notices",
            &n.meta.title,
            &format!(
                "Notice {}: status {}, updated {}.",
                n.meta.id,
                n.meta.status.label(),
                n.meta.updated
            ),
            notices::page_body(n),
        ));
    }

    // Docs, twice: the first pass finds the Field Manual's sections and
    // the glossary's terms, the second links them in running text.
    let srcs: BTreeSet<String> = inp.docs.iter().map(|(p, _)| p.clone()).collect();
    let plain = docs::Links {
        docs: &srcs,
        repo: &inp.repo,
        terms: None,
    };
    let first: Vec<docs::Doc> = inp
        .docs
        .iter()
        .map(|(p, t)| docs::render_doc(p, t, &plain))
        .collect();
    let terms = manual_terms(&first, &inp.docs);
    let links = docs::Links {
        docs: &srcs,
        repo: &inp.repo,
        terms: Some(&terms),
    };
    let mut rendered: Vec<docs::Doc> = inp
        .docs
        .iter()
        .map(|(p, t)| docs::render_doc(p, t, &links))
        .collect();
    rendered.sort_by(|a, b| {
        let key = |d: &docs::Doc| {
            let rel = d.src.strip_prefix("docs/").unwrap_or(&d.src).to_string();
            // Each directory's README (its index) leads its group.
            let (dir, file) = rel.rsplit_once('/').unwrap_or(("", &rel));
            (
                rel != "README.md",
                rel.contains('/'),
                dir.to_string(),
                file != "README.md",
                rel.clone(),
            )
        };
        key(a).cmp(&key(b))
    });
    let sections = docs::fm_sections(&rendered);
    let manual_order = manual_pages(&rendered);
    let mut seen = BTreeSet::new();
    for d in &rendered {
        if !seen.insert(d.url.clone()) {
            return Err(format!("{}: two docs publish at {}", d.src, d.url));
        }
        let nav = match d.url.as_str() {
            "methodology/" => "methodology",
            "operators/" => "operators",
            u if u.starts_with("docs/manual/") => "manual",
            _ => "docs",
        };
        let before = if nav == "operators" {
            shells::OPERATORS_PANEL
        } else {
            ""
        };
        let after = if nav == "manual" {
            manual::pager(d, &manual_order)
        } else {
            String::new()
        };
        let mut p = page(
            &format!("{}index.html", d.url),
            nav,
            &d.title,
            &d.summary.chars().take(200).collect::<String>(),
            doc_body(d, &rendered, &inp.repo, before, &after),
        );
        p.wide = true;
        pages.push(p);
    }
    if !sections.is_empty() {
        out.push((
            "assets/fm-index.json".into(),
            manual::search_index(&sections),
        ));
        let mut p = page(
            "docs/manual/sections/index.html",
            "manual",
            "Field Manual sections",
            "Every section of the Swarmchasing Field Manual by id, with search.",
            manual::sections_page(&sections, &manual_order),
        );
        p.wide = true;
        p.scripts.push("js/pages/manual.js");
        pages.push(p);
    }

    // Landing.
    let fm_links: home::FmLinks = terms
        .fm
        .iter()
        .chain(terms.tactics.iter())
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    let mut home = page(
        "index.html",
        "home",
        "",
        "Passive detection of AI agent activity in public records: the method walked through a synthetic incident, notices, and browser tools.",
        home::body(&example_analysis, &rules, &inp.notices, &fm_links),
    );
    home.title = String::new();
    home.scripts.push("js/pages/home.js");
    pages.push(home);

    // Rules, evaluation, and the tools.
    let mut p = page(
        "rules/index.html",
        "rules",
        "Rules",
        "The indicator rules every analysis runs, with their weights, patterns and scores on the labelled set.",
        rules::body(&inp.rules_toml, &report.rules, &fm_links)?,
    );
    p.scripts.push("js/pages/rules.js");
    pages.push(p);
    let mut p = page(
        "eval/index.html",
        "eval",
        "Evaluation",
        "Precision and recall of the bundled rules on the committed labelled set.",
        evalpage::body(&summary, &files),
    );
    p.scripts.push("js/pages/eval.js");
    pages.push(p);
    let mut p = page(
        "analyze/index.html",
        "analyze",
        "Analyze",
        "Grade, link and time records in the browser with the same rules as the CLI.",
        shells::ANALYZE.to_string(),
    );
    p.scripts.push("js/pages/analyze.js");
    p.engine = true;
    p.wide = true;
    pages.push(p);
    let mut p = page(
        "unwrap/index.html",
        "unwrap",
        "Unwrap a URL",
        "The layers inside one URL and the rules each triggers, without opening it.",
        shells::UNWRAP.to_string(),
    );
    p.scripts.push("js/pages/unwrap.js");
    p.engine = true;
    pages.push(p);
    let mut p = page(
        "tools/index.html",
        "tools",
        "Tools",
        "Check an evidence bundle, read a security.txt, defang URLs.",
        shells::TOOLS.to_string(),
    );
    p.scripts.push("js/pages/tools.js");
    p.engine = true;
    pages.push(p);

    let mut sitemap = String::from(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<urlset xmlns=\"http://www.sitemaps.org/schemas/sitemap/0.9\">\n",
    );
    for p in &pages {
        let loc = p.path.strip_suffix("index.html").unwrap_or(&p.path);
        let _ = writeln!(
            sitemap,
            "  <url><loc>{}{}</loc></url>",
            html::esc(&base),
            html::esc(loc)
        );
    }
    sitemap.push_str("</urlset>\n");
    out.push(("sitemap.xml".into(), sitemap));
    out.push((
        "robots.txt".into(),
        format!("User-agent: *\nAllow: /\nSitemap: {base}sitemap.xml\n"),
    ));

    for p in &pages {
        out.push((p.path.clone(), render(p, &ctx, &rel_root(&p.path))));
    }
    // The 404 page is served at any depth, so it reaches the root by path.
    let root_path = base
        .split_once("://")
        .and_then(|(_, rest)| rest.find('/').map(|i| rest[i..].to_string()))
        .unwrap_or_else(|| "/".into());
    let nf = page(
        "404.html",
        "",
        "Page not found",
        "Nothing is published at this address.",
        format!(
            "{}<p><a class=\"button primary\" href=\"{root}\">Home</a> <a class=\"button\" href=\"{root}notices/\">Notices</a> <a class=\"button\" href=\"{root}docs/\">Docs</a></p>",
            shells::NOT_FOUND,
            root = html::esc(&root_path)
        ),
    );
    out.push(("404.html".into(), render(&nf, &ctx, &root_path)));
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::file::{NoticeMeta, NoticeStatus, NoticeUpdate, UpdateKind};

    const P: &str = "<script>alert(1)</script><img src=x onerror=alert(2)>";

    fn inputs() -> SiteInputs {
        let notice = NoticeFile {
            meta: NoticeMeta {
                id: "n-xss".into(),
                title: P.into(),
                status: NoticeStatus::Active,
                published: "2026-10-16".into(),
                updated: "2026-10-17".into(),
                providers: vec![P.into()],
                affected: vec![format!("a.example\"{P}")],
                sector: None,
                scope: None,
                agent_grade: None,
                rules_version: P.into(),
                toolkit: P.into(),
                updates: vec![
                    NoticeUpdate {
                        date: "2026-10-16".into(),
                        kind: UpdateKind::Published,
                        from: None,
                        text: P.into(),
                    },
                    NoticeUpdate {
                        date: "2026-10-17".into(),
                        kind: UpdateKind::Reply,
                        from: Some(P.into()),
                        text: P.into(),
                    },
                ],
            },
            body: format!("# {P}\n\n- **{P}** `{P}`\n\n> {P}\n\n| {P} |\n|---|\n| {P} |\n"),
        };
        SiteInputs {
            notices: vec![notice],
            docs: vec![
                (
                    "docs/README.md".into(),
                    format!(
                        "# Docs\n\nSee [m](methodology.md) and [x](javascript:alert(1)). {P}\n"
                    ),
                ),
                (
                    "docs/methodology.md".into(),
                    format!("# Method\n\n## A\n\n## B\n\n## C {P}\n"),
                ),
            ],
            rules_toml: sc_core::DEFAULT_RULES.into(),
            eval_set: vec![
                (
                    "llm-residue.ndjson".into(),
                    include_str!("../../../../samples/eval/llm-residue.ndjson").into(),
                ),
                (
                    "published-patterns.ndjson".into(),
                    include_str!("../../../../samples/eval/published-patterns.ndjson").into(),
                ),
            ],
            coverage_allow: String::new(),
            showcase: include_str!("../../../../samples/showcase/showcase.ndjson").into(),
            base_url: "https://example.github.io/swarmchasing".into(),
            repo: "https://github.com/o/r".into(),
            version: "0.1.0".into(),
            engine_bytes: Some(1_300_000),
            tools_bytes: Some(1_500_000),
        }
    }

    #[test]
    fn every_page_carries_the_policy_and_no_content_markup() {
        let files = build_pages(&mut inputs()).unwrap();
        let pages: Vec<_> = files.iter().filter(|(p, _)| p.ends_with(".html")).collect();
        for want in [
            "index.html",
            "notices/index.html",
            "notices/n-xss/index.html",
            "docs/index.html",
            "methodology/index.html",
            "rules/index.html",
            "eval/index.html",
            "analyze/index.html",
            "404.html",
        ] {
            assert!(pages.iter().any(|(p, _)| p == want), "{want} missing");
        }
        for (path, html) in &pages {
            assert!(html.contains(layout::CSP), "{path}: no CSP");
            assert!(
                !html.contains("<img") && !html.contains("<script>"),
                "{path}: markup from content"
            );
            assert!(
                !html.contains("javascript:alert(1)\""),
                "{path}: a javascript: link"
            );
            assert!(!html.contains(" style="), "{path}: a style attribute");
        }
        let notice = &files
            .iter()
            .find(|(p, _)| p == "notices/n-xss/index.html")
            .unwrap()
            .1;
        assert!(notice.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
        assert!(notice.contains("a[.]example&quot;"));
        let sitemap = &files.iter().find(|(p, _)| p == "sitemap.xml").unwrap().1;
        assert!(sitemap.contains("https://example.github.io/swarmchasing/notices/n-xss/"));
        let nf = &files.iter().find(|(p, _)| p == "404.html").unwrap().1;
        assert!(nf.contains("href=\"/swarmchasing/css/site.css\""));
        assert!(files.iter().any(|(p, _)| p == "assets/eval-summary.json"));
    }

    /// The synthetic notices in `tests/fixtures/notices/` (never under
    /// `notices/`): one per status, three sectors, two providers.
    fn synthetic_notices() -> Vec<NoticeFile> {
        [
            include_str!("../../tests/fixtures/notices/synthetic-portal-probe.md"),
            include_str!("../../tests/fixtures/notices/synthetic-clinic-scan.md"),
            include_str!("../../tests/fixtures/notices/synthetic-course-relay.md"),
        ]
        .iter()
        .map(|t| crate::parse_notice(t).unwrap())
        .collect()
    }

    #[test]
    fn the_notice_index_carries_every_filter() {
        let rules = Rules::default_rules();
        for n in synthetic_notices() {
            assert!(crate::check_notice(&n, &rules).is_empty(), "{}", n.meta.id);
        }
        let mut inp = inputs();
        inp.notices = synthetic_notices();
        let files = build_pages(&mut inp).unwrap();
        let get = |p: &str| &files.iter().find(|(f, _)| f == p).unwrap().1;
        let idx = get("notices/index.html");
        for want in [
            "name=\"status\"",
            "name=\"provider\"",
            "name=\"sector\"",
            "name=\"host\"",
            "name=\"from\"",
            "name=\"to\"",
            "<option value=\"health\">Health</option>",
            "<option value=\"Placeholder Models\">",
            "data-sector=\"education\"",
            "booking[.]clinic[.]example",
        ] {
            assert!(idx.contains(want), "{want} missing from the index");
        }
        // Newest update first.
        let at = |id: &str| idx.find(&format!("href=\"{id}/\"")).unwrap();
        assert!(at("synthetic-portal-probe") < at("synthetic-clinic-scan"));
        assert!(at("synthetic-clinic-scan") < at("synthetic-course-relay"));
        assert!(
            get("notices/synthetic-clinic-scan/index.html")
                .contains("<dt>Sector</dt><dd>Health</dd>")
        );
        let json = get("notices/index.json");
        assert!(json.contains("\"sector\":\"government\""), "{json}");

        // Without sectors there is no sector filter.
        let mut inp = inputs();
        let idx = build_pages(&mut inp)
            .unwrap()
            .into_iter()
            .find(|(f, _)| f == "notices/index.html")
            .unwrap()
            .1;
        assert!(!idx.contains("name=\"sector\""));
    }

    #[test]
    fn an_unknown_sector_fails_the_check() {
        let mut n = synthetic_notices().remove(0);
        n.meta.sector = Some("Government".into());
        let p = crate::check_notice(&n, &Rules::default_rules());
        assert!(p.iter().any(|x| x.starts_with("unknown sector")), "{p:?}");
        let text = crate::write_notice(&synthetic_notices()[0]);
        assert!(text.contains("sector = \"government\""), "{text}");
    }

    #[test]
    fn the_example_is_synthetic_and_unlabelled() {
        let ex =
            example_records(include_str!("../../../../samples/showcase/showcase.ndjson")).unwrap();
        for l in ex.lines() {
            let v: serde_json::Value = serde_json::from_str(l).unwrap();
            for k in LABEL_FIELDS {
                assert!(v.get(k).is_none(), "{k} left in {l}");
            }
        }
        assert!(example_records("{\"id\":\"x\",\"url\":\"u\"}").is_err());
    }
}
