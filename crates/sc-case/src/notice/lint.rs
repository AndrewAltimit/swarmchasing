//! The notice linter: one set of checks for every notice, whoever runs it.
//! `swarmchase notice lint`, the site build (`sc-publish`), `notice add`
//! and the self-review checklist all call these functions.
//!
//! - [`front_matter`]: no DRAFT banner, a first update, updates in date
//!   order, `updated` matching the last update, a known sector.
//! - [`leaks`]: nothing a notice withholds anywhere it publishes text (body,
//!   updates, title): callback channels, addresses, credentials
//!   ([`sc_core::notice::lint_public`]).
//! - [`wording`]: what the wording rules check from the notice alone:
//!   attribution statements with a layer, label and tag, likelihood words
//!   within their labels, and no provider in the title that the notice does
//!   not name as a developer.
//!
//! [`withholding`] is the first two, the scan the checklist reports as its
//! own item; [`lint_notice`] is all three.

use super::file::{NoticeFile, SECTORS};
use super::wording as w;
use crate::providers::Directory;
use sc_core::Rules;
use sc_core::notice::lint_public;
use std::fmt::Write;
use std::sync::OnceLock;

/// Front matter and update problems.
pub fn front_matter(n: &NoticeFile) -> Vec<String> {
    let mut out = Vec::new();
    if n.body.contains("**DRAFT**") {
        out.push("still carries the DRAFT banner".into());
    }
    if n.meta.updates.is_empty() {
        out.push("has no updates (the first is `published`)".into());
    }
    if n.meta
        .updates
        .windows(2)
        .any(|w| w[1].date.as_str() < w[0].date.as_str())
    {
        out.push("updates are not in date order".into());
    }
    if let Some(last) = n.meta.updates.last()
        && last.date != n.meta.updated
    {
        out.push(format!(
            "`updated` is {}, the last update is {}",
            n.meta.updated, last.date
        ));
    }
    if let Some(s) = &n.meta.sector
        && !SECTORS.contains(&s.as_str())
    {
        out.push(format!("unknown sector `{s}` ({})", SECTORS.join("|")));
    }
    out
}

/// Everything the notice publishes as text: the body, every update (a
/// statement is quoted verbatim, but it is still published) and the title.
pub fn published_text(n: &NoticeFile) -> String {
    let mut text = n.body.clone();
    for u in &n.meta.updates {
        let _ = writeln!(text, "\n{}", u.text);
    }
    let _ = writeln!(text, "\n{}", n.meta.title);
    text
}

/// What a notice must not carry, found anywhere it publishes text.
pub fn leaks(n: &NoticeFile, rules: &Rules) -> Vec<String> {
    lint_public(&published_text(n), rules)
}

/// [`front_matter`] and [`leaks`]: the scan that gates publication.
pub fn withholding(n: &NoticeFile, rules: &Rules) -> Vec<String> {
    let mut out = front_matter(n);
    out.extend(leaks(n, rules));
    out
}

/// The wording checks a notice supports on its own.
pub fn wording(n: &NoticeFile, dir: &Directory) -> Vec<String> {
    let text = format!("{}\n{}", n.meta.title, n.body);
    let mut out = w::claim_problems(&n.body);
    out.extend(w::likelihood_problems(&text));
    out.extend(w::title_problems(&n.meta.title, &n.meta.providers, dir));
    out
}

/// Every problem with a notice, against the built-in provider directory.
/// Empty means it may be published.
pub fn lint_notice(n: &NoticeFile, rules: &Rules) -> Vec<String> {
    static DIR: OnceLock<Directory> = OnceLock::new();
    lint_notice_with(n, rules, DIR.get_or_init(Directory::builtin))
}

/// Every problem with a notice, against provider directory `dir`.
pub fn lint_notice_with(n: &NoticeFile, rules: &Rules, dir: &Directory) -> Vec<String> {
    let mut out = withholding(n, rules);
    for p in wording(n, dir) {
        if !out.contains(&p) {
            out.push(p);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::notice::{NoticeMeta, NoticeStatus, NoticeUpdate, UpdateKind, parse_notice};

    fn notice() -> NoticeFile {
        NoticeFile {
            meta: NoticeMeta {
                id: "2026-10-portal".into(),
                title: "Portal <probe> & co".into(),
                status: NoticeStatus::Active,
                published: "2026-10-20".into(),
                updated: "2026-10-22".into(),
                providers: vec![],
                affected: vec!["portal.example.gov".into()],
                sector: None,
                rules_version: "2026-10-12".into(),
                toolkit: "0.1.0".into(),
                updates: vec![
                    NoticeUpdate {
                        date: "2026-10-20".into(),
                        kind: UpdateKind::Published,
                        from: None,
                        text: "Initial notice.".into(),
                    },
                    NoticeUpdate {
                        date: "2026-10-22".into(),
                        kind: UpdateKind::Correction,
                        from: None,
                        text: "The window started a day later.".into(),
                    },
                ],
            },
            body: "# Notice\n\nPlain text.\n".into(),
        }
    }

    #[test]
    fn front_matter_and_leaks() {
        let rules = Rules::default_rules();
        let n = notice();
        assert!(lint_notice(&n, &rules).is_empty());
        let mut bad = n.clone();
        bad.body.push_str("\n> **DRAFT** — x\n");
        bad.meta.updated = "2026-10-21".into();
        bad.meta.updates[1].text = "inbox is ntfy.sh/agent-run-77".into();
        assert_eq!(lint_notice(&bad, &rules).len(), 3);
        let mut odd = n.clone();
        odd.meta.sector = Some("Government".into());
        assert!(
            front_matter(&odd)
                .iter()
                .any(|x| x.starts_with("unknown sector"))
        );
    }

    #[test]
    fn wording_is_checked_with_the_rest() {
        let n = parse_notice(
            "+++\nid = \"n-1\"\ntitle = \"Claude agents probe a portal\"\nstatus = \"active\"\npublished = \"2026-10-16\"\nupdated = \"2026-10-16\"\nrules_version = \"r\"\ntoolkit = \"0\"\n\n[[update]]\ndate = \"2026-10-16\"\nkind = \"published\"\ntext = \"Published.\"\n+++\n\n# Notice\n\n## Attribution\n\n- Anthropic ran it. Label: Possible; tag: Inference.\n- Suspected: almost certain operated by **Anthropic**. Tag: Conclusion.\n",
        )
        .unwrap();
        let p = wording(&n, &Directory::builtin());
        assert_eq!(p.len(), 3, "{p:?}");
        assert!(p.iter().any(|x| x.contains("without a layer")), "{p:?}");
        assert!(
            p.iter()
                .any(|x| x.contains("`almost certain` is stronger than Suspected")),
            "{p:?}"
        );
        assert!(
            p.iter().any(|x| x.contains("the title names `claude`")),
            "{p:?}"
        );
        assert_eq!(lint_notice(&n, &Rules::default_rules()), p);
    }
}
