//! Public notices: the file format ([`file`]), the wording checks
//! ([`wording`]), the one linter every caller runs ([`lint`]), and the text
//! of the first update ([`published_text`]).
//!
//! What a notice may carry at all, the withholding view and the leak scan
//! over finished text ([`sc_core::notice`]), stays in `sc-core`, because
//! reports and the browser need it too.

pub mod file;
pub mod lint;
pub mod wording;

pub use file::{
    NoticeFile, NoticeMeta, NoticeStatus, NoticeUpdate, SECTORS, UpdateKind, is_slug, parse_notice,
    strip_draft_banner, write_notice,
};
pub use lint::{lint_notice, lint_notice_with};

use crate::model::Case;
use crate::text::and_list;
use sc_core::Reported;

/// What a stage's update says about its review. The reviewer is not named.
pub const REVIEWED: &str = "A second reviewer reviewed it before publication.";

/// The first update's text: published, who the recorded sends reached
/// before it, the parties no contact was found for, that affected
/// organisations are named only in later updates, and the second review.
pub fn published_text(r: &Reported, unreached: &[String]) -> String {
    let mut s = match r.parties() {
        Some(p) => format!(
            "Indicator notice published. Reports went to {p} before publication, each with the fixed lead time of our disclosure policy."
        ),
        None => "Indicator notice published.".into(),
    };
    if !unreached.is_empty() {
        s += &format!(
            " No contact could be found for {}; contact was attempted.",
            and_list(unreached)
        );
    }
    s += " It names no affected organisation; names may follow in dated updates. ";
    s += REVIEWED;
    s
}

/// A naming update's published text: the draft's text and the review.
pub fn naming_text(draft: &str) -> String {
    format!("{} {REVIEWED}", draft.trim())
}

/// The parties recorded as having no contact, as the indicator notice
/// states them: the AI provider, and affected operators counted, never
/// named.
pub fn unreached(c: &Case) -> Vec<String> {
    let open: Vec<&str> = c
        .no_contact
        .iter()
        .filter(|n| {
            !c.sent
                .iter()
                .any(|s| s.recipient.eq_ignore_ascii_case(&n.party))
        })
        .map(|n| n.party.as_str())
        .collect();
    let mut operators: Vec<String> = open
        .iter()
        .filter(|p| c.endpoint(p).is_some())
        .map(|p| p.to_ascii_lowercase())
        .collect();
    operators.sort();
    operators.dedup();
    let mut v = Vec::new();
    if open.iter().any(|p| c.endpoint(p).is_none()) {
        v.push("the AI provider".to_string());
    }
    match operators.len() {
        0 => {}
        1 => v.push("one affected operator".into()),
        n => v.push(format!("{n} affected operators")),
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn published_text_names_only_the_parties_sent() {
        let r = |provider, operators, others| Reported {
            provider,
            operators,
            others,
        };
        let lead = "before publication, each with the fixed lead time of our disclosure policy.";
        let tail = format!(
            " It names no affected organisation; names may follow in dated updates. {REVIEWED}"
        );
        assert_eq!(
            published_text(&r(false, false, false), &[]),
            format!("Indicator notice published.{tail}")
        );
        assert_eq!(
            published_text(&r(false, true, false), &[]),
            format!(
                "Indicator notice published. Reports went to the affected operators {lead}{tail}"
            )
        );
        assert_eq!(
            published_text(&r(true, true, true), &[]),
            format!(
                "Indicator notice published. Reports went to the AI provider, the affected operators and other responders {lead}{tail}"
            )
        );
        let unreached = ["one affected operator".to_string()];
        assert_eq!(
            published_text(&r(true, false, false), &unreached),
            format!(
                "Indicator notice published. Reports went to the AI provider {lead} No contact could be found for one affected operator; contact was attempted.{tail}"
            )
        );
    }

    #[test]
    fn unreached_operators_are_counted_not_named() {
        let mut c = Case::new("u-1", "U", "d", None);
        for h in ["a.example", "b.example"] {
            c.endpoints.push(crate::model::CaseEndpoint {
                host: h.into(),
                state: crate::model::EndpointState::Targeted,
                ..Default::default()
            });
            c.no_contact.push(crate::model::NoContact {
                party: h.into(),
                searched: "rdap".into(),
                at: "2026-10-07T10:00:00Z".into(),
            });
        }
        assert_eq!(unreached(&c), ["2 affected operators"]);
        c.no_contact.push(crate::model::NoContact {
            party: "provider".into(),
            searched: "directory".into(),
            at: "2026-10-07T10:00:00Z".into(),
        });
        assert_eq!(unreached(&c), ["the AI provider", "2 affected operators"]);
    }

    #[test]
    fn banner_is_stripped() {
        let b = "# T\n\n> **DRAFT**: generated by swarmchase. Verify.\n\n- **Window:** x\n";
        assert_eq!(strip_draft_banner(b), "# T\n\n- **Window:** x\n");
    }
}
