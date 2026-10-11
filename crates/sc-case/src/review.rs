//! The second review: every indicator notice and every naming update needs
//! an approval from a second person, of the exact draft, before it is
//! written (docs/policies.md, SC-FM 10.9).
//!
//! A review records the reviewer, the time, the verdict, a note, the stage
//! and the SHA-256 of the draft it read. An edit to the draft voids it. An
//! objection blocks the stage until a later approval of the current draft;
//! both stay in the case. The reviewer may not be the case's admin, and a
//! draft whose checklist still fails cannot be reviewed. Corrections,
//! retractions, statements and status changes need no review. There is no
//! override: with no second reviewer, nothing is published.

use crate::checklist::Item;
use crate::model::*;
use crate::{Result, bail};

/// The checklist item a stage's review fills.
pub const ITEM: &str = "an approved second review of the current draft";

/// Whether two names are the same person: trimmed, ignoring case.
pub fn same_person(a: &str, b: &str) -> bool {
    a.trim().eq_ignore_ascii_case(b.trim())
}

/// Record who decides and publishes for the case (`case set --admin`).
pub fn set_admin(c: &mut Case, name: &str, today: &str) -> Result<()> {
    if name.trim().is_empty() {
        bail!("--admin: the name of the person who decides and publishes for the case");
    }
    c.admin = Some(name.trim().to_string());
    c.log(today, format!("admin: {}", name.trim()));
    Ok(())
}

/// Where a stage's review stands for the draft whose hash is `sha`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum State {
    /// No review of this stage recorded.
    None,
    /// The latest review approved this exact draft.
    Approved { reviewer: String, at: String },
    /// The latest review approved another version of the draft.
    Stale { reviewer: String },
    /// The latest review objected; it blocks until a later approval.
    Objected {
        reviewer: String,
        note: Option<String>,
    },
}

impl State {
    pub fn approved(&self) -> bool {
        matches!(self, Self::Approved { .. })
    }

    /// Where it stands, in a few words.
    pub fn describe(&self) -> String {
        match self {
            Self::None => "no second review recorded".into(),
            Self::Approved { reviewer, at } => format!("approved by {reviewer} at {at}"),
            Self::Stale { reviewer } => {
                format!("approved by {reviewer}, but the draft changed since; the review is void")
            }
            Self::Objected { reviewer, note } => format!(
                "objection by {reviewer}{}: blocked until a later approval of the current draft",
                note.as_deref()
                    .map(|n| format!(" ({n})"))
                    .unwrap_or_default()
            ),
        }
    }
}

/// The review state of `stage` for the draft whose hash is `sha` (`None`
/// when there is no draft).
pub fn state(c: &Case, stage: Stage, sha: Option<&str>) -> State {
    let Some(r) = c.reviews.iter().rev().find(|r| r.stage == stage) else {
        return State::None;
    };
    match r.verdict {
        Verdict::Object => State::Objected {
            reviewer: r.reviewer.clone(),
            note: r.note.clone(),
        },
        Verdict::Approve if Some(r.sha256.as_str()) == sha => State::Approved {
            reviewer: r.reviewer.clone(),
            at: r.at.clone(),
        },
        Verdict::Approve => State::Stale {
            reviewer: r.reviewer.clone(),
        },
    }
}

/// The checklist item for `stage`'s review of the draft `sha`.
pub fn item(c: &Case, stage: Stage, sha: Option<&str>) -> Item {
    let s = state(c, stage, sha);
    let flag = if stage == Stage::Naming {
        " --naming"
    } else {
        ""
    };
    let detail = if s.approved() {
        vec![s.describe()]
    } else {
        vec![format!(
            "{}: hand the draft to a second reviewer (`swarmchase case review-packet {}{flag}`), then `swarmchase case review {} --reviewer \"<name>\" --verdict approve|object`",
            s.describe(),
            c.id,
            c.id,
        )]
    };
    Item {
        name: ITEM,
        ok: s.approved(),
        detail,
    }
}

/// The checklist items that keep a draft from being reviewed: every failing
/// item except the review itself and the clocks, which may still be
/// running while the reviewer reads.
pub fn blockers(items: &[Item]) -> Vec<&'static str> {
    items
        .iter()
        .filter(|i| {
            !i.ok
                && !matches!(
                    i.name,
                    ITEM | crate::checklist::CLOCK_ITEM | crate::checklist::NAMING_CLOCK_ITEM
                )
        })
        .map(|i| i.name)
        .collect()
}

/// One review as `case review` takes it.
#[derive(Debug, Clone)]
pub struct Input<'a> {
    pub stage: Stage,
    pub reviewer: &'a str,
    pub verdict: Verdict,
    pub note: Option<&'a str>,
    /// The SHA-256 of the draft as the reviewer read it.
    pub sha: &'a str,
}

/// Record a second review. Refused when the reviewer is the case's admin
/// (or no admin is recorded), and when `blockers` (the stage's failing
/// checklist items, [`blockers`]) is not empty. Returns a line for the admin.
pub fn record(c: &mut Case, x: Input, blockers: &[&str], now: i64) -> Result<String> {
    let reviewer = x.reviewer.trim();
    if reviewer.is_empty() {
        bail!("--reviewer: the second reviewer's name");
    }
    let Some(admin) = c.admin.clone() else {
        bail!(
            "case {} records no admin, so a second review cannot be told apart from the admin's own: `swarmchase case set {} --admin \"<name>\"`",
            c.id,
            c.id
        );
    };
    if same_person(reviewer, &admin) {
        bail!("{reviewer} is the case's admin; the second review must come from someone else");
    }
    if !blockers.is_empty() {
        bail!(
            "the {} checklist fails ({}); fix the draft and the case before review",
            x.stage.label(),
            blockers.join("; ")
        );
    }
    let note = x.note.map(str::trim).filter(|n| !n.is_empty());
    c.reviews.push(Review {
        stage: x.stage,
        reviewer: reviewer.to_string(),
        verdict: x.verdict,
        note: note.map(str::to_string),
        sha256: x.sha.to_string(),
        at: rfc3339(now),
    });
    let today = crate::text::date_of(now);
    c.log(
        &today,
        format!(
            "second review of the {} draft (sha256 {}): {} by {reviewer}{}",
            x.stage.label(),
            x.sha.get(..12).unwrap_or(x.sha),
            x.verdict.label(),
            note.map(|n| format!(" ({n})")).unwrap_or_default()
        ),
    );
    Ok(match x.verdict {
        Verdict::Approve => format!(
            "approval of the current {} draft recorded; an edit to it voids the approval",
            x.stage.label()
        ),
        Verdict::Object => format!(
            "objection recorded; the {} is blocked until a later approval of the current draft",
            x.stage.label()
        ),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const T0: i64 = 1_791_367_200;

    fn case() -> Case {
        let mut c = Case::new("r-1", "R", "2026-10-07", None);
        c.admin = Some("Ada Admin".into());
        c
    }

    fn input<'a>(reviewer: &'a str, verdict: Verdict, sha: &'a str) -> Input<'a> {
        Input {
            stage: Stage::Indicators,
            reviewer,
            verdict,
            note: None,
            sha,
        }
    }

    #[test]
    fn the_admin_cannot_review_their_own_draft() {
        let mut c = case();
        for me in ["Ada Admin", "  ada admin ", "ADA ADMIN"] {
            assert!(record(&mut c, input(me, Verdict::Approve, "s1"), &[], T0).is_err());
        }
        assert!(record(&mut c, input(" ", Verdict::Approve, "s1"), &[], T0).is_err());
        let mut none = Case::new("r-2", "R", "d", None);
        let e = record(&mut none, input("Rae", Verdict::Approve, "s1"), &[], T0).unwrap_err();
        assert!(e.0.contains("--admin"), "{e}");
        assert!(c.reviews.is_empty());
        record(
            &mut c,
            input("Rae Reviewer", Verdict::Approve, "s1"),
            &[],
            T0,
        )
        .unwrap();
        assert!(state(&c, Stage::Indicators, Some("s1")).approved());
    }

    #[test]
    fn an_edit_voids_the_approval() {
        let mut c = case();
        assert_eq!(state(&c, Stage::Indicators, Some("s1")), State::None);
        record(&mut c, input("Rae", Verdict::Approve, "s1"), &[], T0).unwrap();
        assert!(state(&c, Stage::Indicators, Some("s1")).approved());
        assert!(matches!(
            state(&c, Stage::Indicators, Some("s2")),
            State::Stale { .. }
        ));
        assert!(!state(&c, Stage::Indicators, None).approved());
        // The other stage is not reviewed by it.
        assert_eq!(state(&c, Stage::Naming, Some("s1")), State::None);
        assert!(!item(&c, Stage::Indicators, Some("s2")).ok);
        assert!(item(&c, Stage::Indicators, Some("s1")).ok);
    }

    #[test]
    fn an_objection_blocks_until_a_later_approval() {
        let mut c = case();
        record(&mut c, input("Rae", Verdict::Approve, "s1"), &[], T0).unwrap();
        let mut obj = input("Sam", Verdict::Object, "s1");
        obj.note = Some("the summary overstates the grade");
        record(&mut c, obj, &[], T0 + 60).unwrap();
        let s = state(&c, Stage::Indicators, Some("s1"));
        assert!(matches!(s, State::Objected { .. }), "{s:?}");
        assert!(s.describe().contains("overstates"));
        // An approval of an older draft does not lift it.
        record(&mut c, input("Rae", Verdict::Approve, "s0"), &[], T0 + 120).unwrap();
        assert!(!state(&c, Stage::Indicators, Some("s2")).approved());
        record(&mut c, input("Rae", Verdict::Approve, "s2"), &[], T0 + 180).unwrap();
        assert!(state(&c, Stage::Indicators, Some("s2")).approved());
        // Both stay on record.
        assert_eq!(c.reviews.len(), 4);
        assert!(c.decisions.iter().any(|d| d.text.contains("object by Sam")));
    }

    #[test]
    fn a_failing_checklist_cannot_be_reviewed() {
        let mut c = case();
        let e = record(
            &mut c,
            input("Rae", Verdict::Approve, "s1"),
            &["every endpoint is classified"],
            T0,
        )
        .unwrap_err();
        assert!(e.0.contains("every endpoint is classified"), "{e}");
        let items = vec![
            Item {
                name: ITEM,
                ok: false,
                detail: vec![],
            },
            Item {
                name: crate::checklist::CLOCK_ITEM,
                ok: false,
                detail: vec![],
            },
            Item {
                name: "the withholding scan passes",
                ok: false,
                detail: vec![],
            },
        ];
        assert_eq!(blockers(&items), ["the withholding scan passes"]);
    }
}
