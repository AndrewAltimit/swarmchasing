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
pub mod notices;
pub mod rules;
pub mod shells;
pub mod svg;

use crate::file::NoticeFile;
use crate::site::build_site;
use layout::{Page, rel_root, render};
use sc_core::{FieldMap, Format, Rules};
use std::collections::BTreeSet;
use std::fmt::Write;

/// The labelled file whose records the landing page and "Try an example"
/// use. Every record in it must be marked synthetic.
pub const EXAMPLE_FILE: &str = "llm-residue.ndjson";

/// Fields of a labelled record that carry the answer, stripped from the
/// example the workbench loads.
const LABEL_FIELDS: [&str; 3] = ["label", "class", "cite"];

/// What the site is built from. Every field holds committed text.
pub struct SiteInputs {
    pub notices: Vec<NoticeFile>,
    /// (repository path, text) of every `docs/**/*.md`.
    pub docs: Vec<(String, String)>,
    /// `rules/default.toml`.
    pub rules_toml: String,
    /// (file name, NDJSON) of every `samples/eval/*.ndjson`.
    pub eval_set: Vec<(String, String)>,
    /// The site's public URL.
    pub base_url: String,
    /// `https://github.com/<owner>/<repo>`.
    pub repo: String,
    pub version: String,
    /// Size of the WASM module in bytes, when it was built first.
    pub engine_bytes: Option<u64>,
}

/// Values every page's shell shows.
pub struct Ctx {
    pub version: String,
    pub rules_version: String,
    pub repo: String,
    /// "1.5 MB", for the engine's loading message.
    pub engine_size: String,
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

fn doc_body(d: &docs::Doc, all: &[docs::Doc], repo: &str, before: &str) -> String {
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
        "<div class=\"doc-layout\">{}<article class=\"doc prose\"><header class=\"page-head\"><h1>{}</h1></header>{before}{}<p class=\"hint doc-src\">Source: <a href=\"{}/blob/main/{}\">{}</a></p></article>{toc}</div>",
        docs_sidebar(all, &d.src),
        html::esc(&d.title),
        d.html,
        html::esc(repo),
        html::esc(&d.src),
        html::esc(&d.src),
    )
}

fn engine_size(bytes: Option<u64>) -> String {
    match bytes {
        Some(b) => format!("{:.1} MB", b as f64 / 1_048_576.0),
        None => "1.5 MB".into(),
    }
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
        engine_size: engine_size(inp.engine_bytes),
    };
    let mut out: Vec<(String, String)> = Vec::new();
    // Notice data (newest first) as the CLI's `notice build` writes it.
    for (name, text) in build_site(&mut inp.notices, &base, &rules)? {
        out.push((format!("notices/{name}"), text));
    }
    let mut pages: Vec<Page> = Vec::new();

    // The labelled set: the example, the eval data, the precomputed eval.
    inp.eval_set.sort_by(|a, b| a.0.cmp(&b.0));
    let example_src = inp
        .eval_set
        .iter()
        .find(|(n, _)| n == EXAMPLE_FILE)
        .map(|(_, t)| t.as_str())
        .ok_or_else(|| format!("samples/eval/{EXAMPLE_FILE} not found"))?;
    let example = example_records(example_src)?;
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
    let labels = sc_core::parse_labels(&set);
    let eval_analysis = sc_core::analyze(
        sc_core::parse_input(&set, Format::Ndjson, &FieldMap::default()).observations,
        &rules,
    );
    let report = sc_core::evaluate(&eval_analysis, &labels);
    out.push((
        "assets/eval-set.json".into(),
        serde_json::json!({ "files": files, "ndjson": set }).to_string(),
    ));

    // Landing.
    let mut home = page(
        "index.html",
        "home",
        "",
        "Passive detection of misaligned AI agent swarms in public records: notices, methodology and browser tools.",
        home::body(&example_analysis, &inp.notices),
    );
    home.title = String::new();
    pages.push(home);

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

    // Docs.
    let srcs: BTreeSet<String> = inp.docs.iter().map(|(p, _)| p.clone()).collect();
    let links = docs::Links {
        docs: &srcs,
        repo: &inp.repo,
    };
    let mut rendered: Vec<docs::Doc> = inp
        .docs
        .iter()
        .map(|(p, t)| docs::render_doc(p, t, &links))
        .collect();
    rendered.sort_by(|a, b| {
        let key = |d: &docs::Doc| {
            let rel = d.src.strip_prefix("docs/").unwrap_or(&d.src).to_string();
            (rel != "README.md", rel.contains('/'), rel)
        };
        key(a).cmp(&key(b))
    });
    let mut seen = BTreeSet::new();
    for d in &rendered {
        if !seen.insert(d.url.clone()) {
            return Err(format!("{}: two docs publish at {}", d.src, d.url));
        }
        let nav = match d.url.as_str() {
            "methodology/" => "methodology",
            "operators/" => "operators",
            _ => "docs",
        };
        let before = if nav == "operators" {
            shells::OPERATORS_PANEL
        } else {
            ""
        };
        let mut p = page(
            &format!("{}index.html", d.url),
            nav,
            &d.title,
            &d.summary.chars().take(200).collect::<String>(),
            doc_body(d, &rendered, &inp.repo, before),
        );
        p.wide = true;
        pages.push(p);
    }

    // Rules, evaluation, and the tools.
    let mut p = page(
        "rules/index.html",
        "rules",
        "Rules",
        "The indicator rules every analysis runs, with their weights, patterns and scores on the labelled set.",
        rules::body(&inp.rules_toml, &report.rules)?,
    );
    p.scripts.push("js/pages/rules.js");
    pages.push(p);
    let mut p = page(
        "eval/index.html",
        "eval",
        "Evaluation",
        "Precision and recall of the bundled rules on the committed labelled set.",
        evalpage::body(&report, &files),
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
    p.wide = true;
    pages.push(p);
    let mut p = page(
        "unwrap/index.html",
        "tools",
        "Unwrap a URL",
        "The layers inside one URL and the rules each triggers, without opening it.",
        shells::UNWRAP.to_string(),
    );
    p.scripts.push("js/pages/unwrap.js");
    pages.push(p);
    let mut p = page(
        "tools/index.html",
        "tools",
        "Tools",
        "Check an evidence bundle, read a security.txt, defang URLs.",
        shells::TOOLS.to_string(),
    );
    p.scripts.push("js/pages/tools.js");
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
