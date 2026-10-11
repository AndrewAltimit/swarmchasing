//! The shared page shell: head with the Content Security Policy, header
//! navigation, footer. Every generated page goes through [`render`].

use super::Ctx;
use super::html::esc;
use std::fmt::Write;

/// The policy every page carries. The site renders attack payloads, so only
/// same-origin scripts, styles and the WASM module run, and nothing is sent
/// anywhere. `scripts/ci/check-site.py` checks it on every page.
pub const CSP: &str = "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; form-action 'none'";

/// One entry of a nav group: (key, label, path under the site root, what
/// it is).
pub type NavItem = (&'static str, &'static str, &'static str, &'static str);

/// The notices, then three groups, in nav order: (group label, items). A
/// page's [`Page::nav`] key marks its item and its group current.
pub const NAV_NOTICES: (&str, &str, &str) = ("notices", "Notices", "notices/");
pub const NAV: &[(&str, &[NavItem])] = &[
    (
        "Learn",
        &[
            (
                "manual",
                "Field Manual",
                "docs/manual/",
                "The method as a citable standard",
            ),
            (
                "methodology",
                "Methodology",
                "methodology/",
                "How this toolkit implements it",
            ),
            (
                "operators",
                "For operators",
                "operators/",
                "Your site was named: what to do",
            ),
        ],
    ),
    (
        "Investigate",
        &[
            (
                "analyze",
                "Workbench",
                "analyze/",
                "Grade, link and time records in the browser",
            ),
            (
                "unwrap",
                "Unwrap a URL",
                "unwrap/",
                "The layers inside one URL",
            ),
            (
                "tools",
                "Tools",
                "tools/",
                "Check a bundle, read security.txt, defang",
            ),
        ],
    ),
    (
        "Reference",
        &[
            (
                "rules",
                "Rules",
                "rules/",
                "Every indicator rule, with a URL tester",
            ),
            (
                "eval",
                "Evaluation",
                "eval/",
                "Precision and recall on the labelled set",
            ),
            ("docs", "Docs", "docs/", "Guides and reference"),
        ],
    ),
];

/// One generated page.
pub struct Page {
    /// Output path under the site root, e.g. `notices/index.html`.
    pub path: String,
    /// The [`NAV`] key marked current, or empty.
    pub nav: &'static str,
    pub title: String,
    pub description: String,
    /// The `<main>` content, already escaped.
    pub body: String,
    /// Page modules, as paths under the site root (`js/pages/analyze.js`).
    pub scripts: Vec<&'static str>,
    /// Full-width main area (the workbench) instead of the reading width.
    pub wide: bool,
    /// The page loads the analysis module on arrival: preload it with the
    /// stylesheet so it downloads alongside the scripts.
    pub engine: bool,
}

/// The relative prefix from a page to the site root (`./`, `../`, ...).
pub fn rel_root(path: &str) -> String {
    let depth = path.matches('/').count();
    if depth == 0 {
        "./".to_string()
    } else {
        "../".repeat(depth)
    }
}

/// The full HTML of a page. `root` is how the page reaches the site root:
/// relative for every page, an absolute path for the 404 page (served at
/// any depth).
pub fn render(p: &Page, ctx: &Ctx, root: &str) -> String {
    let root = &esc(root);
    let mut s = String::with_capacity(p.body.len() + 4096);
    let title = if p.title.is_empty() {
        "Swarmchasing".to_string()
    } else {
        format!("{} · Swarmchasing", p.title)
    };
    let _ = write!(
        s,
        "<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n\
<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n\
<meta http-equiv=\"Content-Security-Policy\" content=\"{CSP}\">\n\
<meta name=\"referrer\" content=\"no-referrer\">\n\
<title>{}</title>\n<meta name=\"description\" content=\"{}\">\n\
<link rel=\"icon\" href=\"{root}favicon.svg\" type=\"image/svg+xml\">\n\
<link rel=\"stylesheet\" href=\"{root}css/site.css\">\n\
<link rel=\"alternate\" type=\"application/atom+xml\" title=\"Swarmchasing notices\" href=\"{root}notices/feed.xml\">\n\
<script src=\"{root}js/theme.js\"></script>\n",
        esc(&title),
        esc(&p.description),
    );
    if p.engine {
        // Matches the module's own fetch (same-origin, CORS mode), so the
        // browser reuses the preloaded response.
        let _ = writeln!(
            s,
            "<link rel=\"preload\" href=\"{root}pkg/sc_wasm_bg.wasm\" as=\"fetch\" type=\"application/wasm\" crossorigin>"
        );
    }
    let _ = writeln!(
        s,
        "<script type=\"module\" src=\"{root}js/site.js\"></script>"
    );
    for m in &p.scripts {
        let _ = writeln!(s, "<script type=\"module\" src=\"{root}{m}\"></script>");
    }
    let _ = write!(
        s,
        "</head>\n<body data-root=\"{root}\" data-engine-size=\"{}\" data-tools-size=\"{}\">\n\
<a class=\"skip\" href=\"#main\">Skip to content</a>\n\
<header class=\"site-head\"><div class=\"wrap head-row\">\n\
<a class=\"brand\" href=\"{root}\"{}><span class=\"brand-mark\" aria-hidden=\"true\"></span>Swarmchasing</a>\n\
<nav class=\"site-nav\" aria-label=\"Site\"><ul>",
        esc(&ctx.engine_size),
        esc(&ctx.tools_size),
        if p.nav == "home" {
            " aria-current=\"page\""
        } else {
            ""
        },
    );
    {
        let (key, label, href) = NAV_NOTICES;
        let cur = if key == p.nav {
            " aria-current=\"page\""
        } else {
            ""
        };
        let _ = write!(s, "<li><a href=\"{root}{href}\"{cur}>{label}</a></li>");
    }
    // Groups open as menus: <details>, so they work without the script,
    // which only closes one when another opens or focus leaves.
    for (group, items) in NAV {
        let here = items.iter().any(|(k, ..)| *k == p.nav);
        let _ = write!(
            s,
            "<li class=\"nav-group\"><details data-nav-menu><summary{}>{group}</summary><ul class=\"nav-menu\">",
            if here { " class=\"current\"" } else { "" }
        );
        for (key, label, href, what) in *items {
            let cur = if *key == p.nav {
                " aria-current=\"page\""
            } else {
                ""
            };
            let _ = write!(
                s,
                "<li><a href=\"{root}{href}\"{cur}><strong>{label}</strong><span>{what}</span></a></li>"
            );
        }
        s.push_str("</ul></details></li>");
    }
    let _ = write!(
        s,
        "</ul></nav>\n<button type=\"button\" class=\"theme-toggle\" data-theme-toggle aria-label=\"Switch between light and dark theme\" title=\"Theme\"><span aria-hidden=\"true\"></span></button>\n\
</div></header>\n<main id=\"main\" class=\"{}\" tabindex=\"-1\">\n{}\n</main>\n",
        if p.wide { "wrap wide" } else { "wrap" },
        p.body
    );
    let _ = write!(
        s,
        "<footer class=\"site-foot\"><div class=\"wrap foot-row\">\n\
<p>Passive detection of AI agent activity in public records. Analysis on this site runs in your browser; nothing you paste is uploaded.</p>\n\
<p><a href=\"{root}notices/feed.xml\">Atom feed</a> · <a href=\"{}\">Source</a> · <a href=\"{root}docs/\">Docs</a> · toolkit {} · rules {}</p>\n\
</div></footer>\n<div id=\"tip\" class=\"tip\" role=\"tooltip\" hidden></div>\n</body>\n</html>\n",
        esc(&ctx.repo),
        esc(&ctx.version),
        esc(&ctx.rules_version),
    );
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_prefix_follows_depth() {
        assert_eq!(rel_root("index.html"), "./");
        assert_eq!(rel_root("notices/index.html"), "../");
        assert_eq!(rel_root("notices/x/index.html"), "../../");
    }
}
