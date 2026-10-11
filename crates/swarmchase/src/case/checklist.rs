//! The self-review checklist's inputs, read from the case directory, and
//! the re-read the checklist asks for. The checklist itself is
//! [`sc_case::checklist`].

use super::{Case, NOTICE_DRAFT, Pinned, Scope, case_dir, update};
use anyhow::Result;
use sc_case::checklist::Inputs;
use sc_case::notice::NoticeFile;
use sc_case::providers::Directory;
use std::path::Path;

pub use sc_case::checklist::{
    Item, failing, print, print_titled, single_source_hosts, single_source_line,
};

/// The SHA-256 of the case's notice draft as it is on disk.
pub fn draft_sha(root: &Path, id: &str) -> Result<String> {
    let p = case_dir(root, id)?.join(NOTICE_DRAFT);
    let bytes = std::fs::read(&p).map_err(|e| {
        anyhow::anyhow!(
            "reading {}: {e}; run `swarmchase case notice {id}`",
            p.display()
        )
    })?;
    Ok(sc_case::bundle::sha256_hex(&bytes))
}

/// Record that the admin re-read the notice draft as it is now. Returns
/// what to tell the admin.
pub fn reread(root: &Path, id: &str, today: &str, now: i64) -> Result<String> {
    let sha = draft_sha(root, id)?;
    let mut msg = String::new();
    update(root, id, |c| {
        msg = sc_case::checklist::reread(c, &sha, today, now);
        Ok(())
    })?;
    Ok(msg)
}

/// The checklist for case `c` and the notice `n` it is about to add.
/// `withholding` is what the withholding scan found; `now` the clock.
pub fn checklist(
    root: &Path,
    c: &Case,
    n: &NoticeFile,
    withholding: Vec<String>,
    now: i64,
) -> Result<Vec<Item>> {
    let pinned = Pinned::new(root, c)?;
    let all = pinned.analysis(&Scope::All)?;
    let public = pinned.analysis(&Scope::Public)?;
    let claims = sc_case::report::all_claims(c, &all);
    let sha = draft_sha(root, &c.id).ok();
    Ok(sc_case::checklist::checklist(Inputs {
        case: c,
        notice: n,
        all: &all,
        public: &public,
        claims: &claims,
        directory: &Directory::builtin(),
        draft_sha: sha.as_deref(),
        withholding,
        now,
    }))
}

#[cfg(test)]
mod tests {
    use super::super::test_support::*;
    use super::super::{load, new_case, save, update};
    use super::*;
    use crate::pinning::RulesText;
    use sc_case::actions::classify;
    use sc_case::model::{EndpointState, PlantReview};
    use sc_core::Observation;

    /// Records from a scan service only, on one host, carrying a run tag
    /// that a public report quoted, and naming a model.
    fn submitted() -> Vec<Observation> {
        (0..4)
            .map(|i| Observation {
                id: format!("s{i}"),
                source: "urlquery".into(),
                ts: 1_791_000_000 + i * 40,
                url: format!(
                    "https://r.jina.ai/https://portal.example.gov/q?id={i}%20UNION%20SELECT%201&uqtag=chatgpttest1&agent=hunyuan"
                ),
                ..Default::default()
            })
            .collect()
    }

    fn named<'a>(items: &'a [Item], name: &str) -> &'a Item {
        items.iter().find(|i| i.name.starts_with(name)).unwrap()
    }

    fn items(root: &Path, now: i64) -> Vec<Item> {
        crate::notice::checklist_for(root, "s-1", now).unwrap()
    }

    #[test]
    fn checklist_items_follow_the_case_record() {
        let root = scratch("checklist");
        let rules = RulesText::load(None).unwrap();
        new_case(
            &root,
            "s-1",
            "Hunyuan agents probe a portal",
            submitted(),
            &rules,
            "2026-10-12",
        )
        .unwrap();
        let t0 = 1_791_500_000;
        let host = ["portal.example.gov".to_string()];
        update(&root, "s-1", |c| {
            Ok(classify(
                c,
                &host,
                EndpointState::Targeted,
                None,
                None,
                None,
                "d",
            )?)
        })
        .unwrap();
        let (_, review) =
            crate::notice::notice_draft(&root, "s-1", false, "2026-10-15", t0).unwrap();
        assert!(
            review.flags.iter().any(|f| f.contains("submit-anywhere")),
            "{:?}",
            review.flags
        );
        let i = items(&root, t0);
        // The indicator notice names no one, so nothing to name yet.
        assert!(named(&i, "the indicator notice names").ok, "{i:?}");
        assert!(!i.iter().any(|x| x.name.starts_with("single-source")));
        // The vendor is self-identified only: it stays out of the title.
        let title = named(&i, "no provider in the title");
        assert!(
            !title.ok && title.detail.iter().any(|d| d.contains("Tencent")),
            "{title:?}"
        );
        // A monoculture and a burned tag: two plant signals to review.
        assert!(!named(&i, "plant signals").ok, "{i:?}");

        update(&root, "s-1", |c| {
            classify(
                c,
                &host,
                EndpointState::Targeted,
                None,
                None,
                Some("the operator confirmed the requests by phone"),
                "d",
            )?;
            c.title = "Agents probe a portal".into();
            let a = super::super::analysis(&root, c, &Scope::All)?;
            c.plant_reviews.push(PlantReview {
                cluster: a.clusters[0].key.clone(),
                note: "tag copied from the report, but the payload dialect matches".into(),
                date: "d".into(),
            });
            Ok(())
        })
        .unwrap();
        let (p, _) = crate::notice::notice_draft(&root, "s-1", true, "2026-10-15", t0).unwrap();
        let md = std::fs::read_to_string(&p).unwrap();
        assert!(
            !md.contains("portal[.]example") && !md.contains("example.gov"),
            "{md}"
        );
        // The naming update carries the fixed submit-anywhere wording.
        let c = load(&root, "s-1").unwrap();
        let d = sc_case::naming::draft(&c, &host, &host);
        assert!(
            d.text.contains("URLs targeting portal[.]example[.]gov's hosts were submitted to public scan services."),
            "{}",
            d.text
        );
        assert!(
            md.contains("identify themselves as using `hunyuan` from Tencent"),
            "{md}"
        );
        let i = items(&root, t0);
        for n in [
            "the indicator notice names",
            "\"misaligned\"",
            "no provider in the title",
            "plant signals",
            "no likelihood",
            "every attribution",
        ] {
            assert!(named(&i, n).ok, "{n}: {i:?}");
        }

        // A host or "misaligned" written into the draft by hand fails.
        let draft = std::fs::read_to_string(&p).unwrap();
        std::fs::write(
            &p,
            draft.replace(
                "## Indicators",
                "The misaligned agents hit hxxps://portal[.]example[.]gov/login.\n\n## Indicators",
            ),
        )
        .unwrap();
        let i = items(&root, t0);
        let no_party = named(&i, "the indicator notice names");
        assert!(
            !no_party.ok && no_party.detail[0].contains("portal[.]example[.]gov"),
            "{no_party:?}"
        );
        assert!(!named(&i, "\"misaligned\"").ok, "{i:?}");
        // With the admin's scope finding and an L3 grade, the word may stay.
        update(&root, "s-1", |c| {
            let a = super::super::analysis(&root, c, &Scope::All)?;
            for cl in a
                .clusters
                .iter()
                .filter(|cl| cl.tier > sc_core::Tier::Noise)
            {
                sc_case::actions::scope(
                    c,
                    &cl.key,
                    sc_core::scope::ScopeFinding::ScopeExceeded,
                    &["S4".into()],
                    "SQL injection on a portal",
                    "d",
                )?;
            }
            sc_case::actions::grade(c, sc_core::AgentLevel::Adaptive, Some("retries"), "d")?;
            Ok(())
        })
        .unwrap();
        assert!(named(&items(&root, t0), "\"misaligned\"").ok);
        std::fs::write(&p, draft).unwrap();

        // "compromised" needs a basis beyond the inbound requests.
        let mut c = load(&root, "s-1").unwrap();
        classify(
            &mut c,
            &host,
            EndpointState::Compromised,
            None,
            Some("operator: shell found"),
            None,
            "d",
        )
        .unwrap();
        c.endpoints[0].basis = None;
        save(&root, &c).unwrap();
        crate::notice::notice_draft(&root, "s-1", true, "2026-10-15", t0).unwrap();
        assert!(!named(&items(&root, t0), "\"compromised\"").ok);
        cleanup(&root);
    }
}
