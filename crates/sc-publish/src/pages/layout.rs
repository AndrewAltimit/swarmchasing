//! The shared page shell: head with the Content Security Policy, header
//! navigation, footer. Every generated page goes through [`render`].

use super::Ctx;
use super::html::esc;
use std::fmt::Write;

/// The policy every page carries. The site renders attack payloads, so only
/// same-origin scripts, styles and the WASM module run, nothing is sent
/// anywhere, and Trusted Types make every HTML and script sink refuse a
/// plain string (the page scripts use none). `scripts/ci/check-site.py` checks it on every page.
pub const CSP: &str = "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; form-action 'none'; require-trusted-types-for 'script'";

/// One entry of a nav group: (key, label, path under the site root, what
/// it is).
pub type NavItem = (&'static str, &'static str, &'static str, &'static str);

/// The notices, then three groups, then the report page, in nav order: (group label, items). A
/// page's [`Page::nav`] key marks its item and its group current.
pub const NAV_NOTICES: (&str, &str, &str) = ("notices", "Notices", "notices/");
/// The last top-level item, after the groups: how anyone, an agent among
/// them, reports a swarm.
pub const NAV_REPORT: (&str, &str, &str) = ("submit", "Report a swarm", "submit/");
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
                "You received a report: what to do",
            ),
            (
                "providers",
                "For providers",
                "providers/",
                "Reports to an AI provider: verify, reply",
            ),
            (
                "researchers",
                "For researchers",
                "docs/guides/for-researchers/",
                "Run the engine, read the rules, cite the method",
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
                "checklog",
                "Check my logs",
                "check-logs/",
                "Your access log: flagged requests, spoofed agents",
            ),
            (
                "unwrap",
                "Unwrap a URL",
                "unwrap/",
                "The layers inside one URL",
            ),
            (
                "identity",
                "Agent identity",
                "identity/",
                "Check declared agents in your log against providers' files",
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
    /// The date (`YYYY-MM-DD`) its content last changed, for the sitemap:
    /// a notice's latest update, a doc's last commit. `None` leaves it out.
    pub lastmod: Option<String>,
    /// Structured data for the head, as JSON-LD ([`json_ld`]).
    pub ld: Option<serde_json::Value>,
    /// Shared as an article (`og:type`), not as a page of the site.
    pub article: bool,
}

/// The preview image every page names for link cards (`site/og-image.png`).
pub const OG_IMAGE: &str = "og-image.png";

/// The preview image's text alternative, for `og:image:alt` and
/// `twitter:image:alt`.
pub const OG_IMAGE_ALT: &str =
    "Swarmchasing: passive detection of AI agent activity in public records";

/// A JSON-LD block. The CSP does not apply to it: a script element of a
/// data type is never run. `<`, `>` and `&` are escaped inside the JSON
/// strings, so no value can close the element.
pub fn json_ld(v: &serde_json::Value) -> String {
    let text = serde_json::to_string(v).unwrap_or_default();
    format!(
        "<script type=\"application/ld+json\">{}</script>\n",
        text.replace('<', "\\u003c")
            .replace('>', "\\u003e")
            .replace('&', "\\u0026")
    )
}

/// The page's public URL under the site's base URL (`…/notices/`).
pub fn page_url(base: &str, path: &str) -> String {
    format!("{base}{}", path.strip_suffix("index.html").unwrap_or(path))
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
<title>{}</title>\n<meta name=\"description\" content=\"{}\">\n{}\
<link rel=\"icon\" href=\"{root}favicon.svg\" type=\"image/svg+xml\">\n\
<link rel=\"stylesheet\" href=\"{root}css/site.css\">\n\
<link rel=\"alternate\" type=\"application/atom+xml\" title=\"Swarmchasing notices\" href=\"{root}notices/feed.xml\">\n\
<link rel=\"alternate\" type=\"text/plain\" title=\"llms.txt\" href=\"{root}llms.txt\">\n\
<script src=\"{root}js/theme.js\"></script>\n",
        esc(&title),
        esc(&p.description),
        social(p, ctx),
    );
    if let Some(ld) = &p.ld {
        s.push_str(&json_ld(ld));
    }
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
    {
        let (key, label, href) = NAV_REPORT;
        let cur = if key == p.nav {
            " aria-current=\"page\""
        } else {
            ""
        };
        let _ = write!(
            s,
            "<li class=\"nav-report\"><a href=\"{root}{href}\"{cur}>{label}</a></li>"
        );
    }
    s.push_str("</ul></nav>\n");
    {
        // The same link again, shown on phones only (the nav's is hidden
        // there), so it shares the brand's row and the header is two rows.
        let (key, label, href) = NAV_REPORT;
        let cur = if key == p.nav {
            " aria-current=\"page\""
        } else {
            ""
        };
        let _ = writeln!(
            s,
            "<a class=\"head-report\" href=\"{root}{href}\"{cur}>{label}</a>"
        );
    }
    let _ = write!(
        s,
        "<button type=\"button\" class=\"theme-toggle\" data-theme-toggle aria-label=\"Switch between light and dark theme\" title=\"Theme\"><span aria-hidden=\"true\"></span></button>\n\
</div></header>\n<main id=\"main\" class=\"{}\" tabindex=\"-1\">\n{}\n</main>\n",
        if p.wide { "wrap wide" } else { "wrap" },
        p.body
    );
    let _ = write!(
        s,
        "<footer class=\"site-foot\"><div class=\"wrap foot-row\">\n\
<p>Passive detection of AI agent activity in public records. Analysis on this site runs in your browser; nothing you paste is uploaded.</p>\n\
<p class=\"page-ref\">Page reference {canary}: identifies this page and the month it was published (<a href=\"{root}docs/reference/browser-toolkit/#page-references\">what this is</a>).</p>\n\
<p><a href=\"{root}contact/\">Contact</a> · <a href=\"{root}notices/feed.xml\">Atom feed</a> · <a href=\"{}\">Source</a> · <a href=\"{root}docs/\">Docs</a> · For agents: <a href=\"{root}llms.txt\">llms.txt</a>, <a href=\"{root}submit/\">report a swarm</a>, <a href=\"{root}.well-known/security.txt\">security.txt</a> · toolkit {} · rules {}</p>\n\
</div></footer>\n<div id=\"tip\" class=\"tip\" role=\"tooltip\" hidden></div>\n</body>\n</html>\n",
        esc(&ctx.repo),
        esc(&ctx.version),
        esc(&ctx.rules_version),
        canary = sc_core::canary::PLACEHOLDER,
    );
    s
}

/// Link-card and search metadata: the canonical URL, Open Graph and the
/// Twitter card. Absolute URLs need an https base, so a local build (on
/// `http://localhost`) carries the title and description only.
fn social(p: &Page, ctx: &Ctx) -> String {
    let title = if p.title.is_empty() {
        "Swarmchasing"
    } else {
        &p.title
    };
    let mut s = format!(
        "<meta property=\"og:site_name\" content=\"Swarmchasing\">\n\
<meta property=\"og:title\" content=\"{}\">\n\
<meta property=\"og:description\" content=\"{}\">\n\
<meta property=\"og:type\" content=\"{}\">\n\
<meta name=\"twitter:card\" content=\"summary_large_image\">\n",
        esc(title),
        esc(&p.description),
        if p.article { "article" } else { "website" },
    );
    if ctx.base.starts_with("https://") {
        let base = esc(&ctx.base);
        if p.path != "404.html" {
            let url = esc(&page_url(&ctx.base, &p.path));
            let _ = write!(
                s,
                "<link rel=\"canonical\" href=\"{url}\">\n<meta property=\"og:url\" content=\"{url}\">\n"
            );
        }
        let _ = write!(
            s,
            "<meta property=\"og:image\" content=\"{base}{OG_IMAGE}\">\n\
<meta property=\"og:image:width\" content=\"1200\">\n<meta property=\"og:image:height\" content=\"630\">\n\
<meta property=\"og:image:alt\" content=\"{OG_IMAGE_ALT}\">\n\
<meta name=\"twitter:image\" content=\"{base}{OG_IMAGE}\">\n\
<meta name=\"twitter:image:alt\" content=\"{OG_IMAGE_ALT}\">\n"
        );
    }
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

    #[test]
    fn json_ld_cannot_close_its_element() {
        let v = serde_json::json!({ "name": "</script><script>alert(1)</script>&" });
        let html = json_ld(&v);
        assert!(html.starts_with("<script type=\"application/ld+json\">"));
        assert_eq!(html.matches("</script>").count(), 1, "{html}");
        let inner = &html[html.find('>').unwrap() + 1..html.rfind("</script>").unwrap()];
        let back: serde_json::Value = serde_json::from_str(inner).unwrap();
        assert_eq!(back, v);
    }
}
