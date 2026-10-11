//! The notice file (`notices/<id>.md`): TOML front matter with the status
//! and the dated updates, then the notice body in Markdown.
//!
//! The format and the linter live in `sc-case` ([`sc_case::notice`]), so the
//! CLI, the self-review checklist and the site build share them;
//! [`check_notice`] is the linter as the site build runs it.

pub use sc_case::notice::{
    NoticeFile, NoticeMeta, NoticeStatus, NoticeUpdate, SECTORS, UpdateKind, is_slug, parse_notice,
    strip_draft_banner, write_notice,
};
use sc_core::Rules;

/// Problems that keep a notice file from being published: front matter,
/// anything a notice withholds, and wording ([`sc_case::notice::lint`]).
pub fn check_notice(n: &NoticeFile, rules: &Rules) -> Vec<String> {
    sc_case::notice::lint_notice(n, rules)
}
