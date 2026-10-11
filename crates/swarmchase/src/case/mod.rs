//! `swarmchase case`: case files for incidents the admin has decided to pursue.
//!
//! A case lives in `<data>/cases/<id>/`, outside git, like the watch data:
//!
//! ```text
//! case.toml            status, pinned rules, endpoints, attribution claims, contacts,
//!                      decisions, sends
//! raw/records.ndjson   the redacted records the case rests on, copied out of the
//!                      watch store before retention deletes them
//! reports/             drafts rendered from the records and case.toml
//! bundles/<date>/      evidence bundles (records, analysis, stamp, manifest)
//! outbox/              unsent e-mail drafts and paste-ready text for the admin
//! exports/             STIX, MISP and incident-framework drafts
//! evidence/<eid>.ndjson  logs affected operators sent us (`case evidence`)
//! notice.md            the public notice draft (`case notice`), edited by the
//!                      admin, then added to notices/ with `swarmchase notice add`
//! ```
//!
//! What a case is and every decision on it are in the `sc-case` crate; this
//! module reads and writes the files. The rules a case was opened with are
//! pinned ([`crate::pinning`]), and every analysis of a case goes through
//! [`Pinned`], so its reports, notice and bundles do not change when the
//! bundled rules do.
//!
//! Cases stay private until the admin publishes: an open case names
//! organisations on unconfirmed evidence, and private reports include details
//! that public notices withhold (docs/policies.md).
//!
//! [`cli`] holds the subcommands, one module per group; [`select`] picks
//! records, [`status`] shows a case, [`report`] drafts reports and e-mail
//! drafts, [`checklist`] gathers the self-review checklist's inputs,
//! [`incident`] the incident-framework drafts, and [`indicators`] is what
//! the watch matches new records against.

pub mod checklist;
mod cli;
pub mod fleet;
pub mod incident;
mod indicators;
mod report;
mod select;
pub(crate) mod status;

pub use cli::{CaseArgs, run};
pub(crate) use indicators::{CaseIndicators, indicators};
#[cfg(test)]
pub(crate) use report::{draft, report};
pub use sc_case::evidence::Scope;
pub use sc_case::model::*;
pub use sc_case::report::{affected_hosts, report_options, reported};
#[cfg(test)]
pub(crate) use status::status;

use crate::pinning::{RulesText, case_rules, pin_rules};
use crate::store::{read_json, write_json};
use anyhow::{Context, Result, bail};
use sc_case::bundle::to_ndjson;
use sc_core::{Analysis, Audience, Observation, Rules, analyze};
use std::collections::BTreeSet;
use std::io::Write;
use std::path::{Path, PathBuf};

pub fn case_dir(root: &Path, id: &str) -> Result<PathBuf> {
    check_id(id)?;
    Ok(root.join(id))
}

pub fn load(root: &Path, id: &str) -> Result<Case> {
    let p = case_dir(root, id)?.join("case.toml");
    let text =
        std::fs::read_to_string(&p).with_context(|| format!("no case at {}", p.display()))?;
    Case::parse(&text).with_context(|| format!("parsing {}", p.display()))
}

pub(crate) fn save(root: &Path, c: &Case) -> Result<()> {
    let dir = case_dir(root, &c.id)?;
    std::fs::create_dir_all(&dir)?;
    let p = dir.join("case.toml");
    let tmp = dir.join("case.toml.tmp");
    std::fs::write(&tmp, c.to_toml()?)?;
    std::fs::rename(&tmp, &p).with_context(|| format!("writing {}", p.display()))
}

pub fn update(root: &Path, id: &str, f: impl FnOnce(&mut Case) -> Result<()>) -> Result<()> {
    let mut c = load(root, id)?;
    f(&mut c)?;
    save(root, &c)?;
    println!("updated {}", root.join(id).join("case.toml").display());
    Ok(())
}

/// Which operator evidence a report for `audience` may use
/// ([`Scope::for_audience`]).
pub(crate) fn scope(audience: Audience, to: Option<&Contact>) -> Scope<'_> {
    Scope::for_audience(audience, to)
}

/// The case's records plus the operator evidence `scope` allows.
pub fn case_records(root: &Path, c: &Case, scope: &Scope) -> Result<Vec<Observation>> {
    let mut all = load_records(root, &c.id)?;
    let dir = case_dir(root, &c.id)?;
    for e in c.evidence.iter().filter(|e| e.in_scope(scope)) {
        let p = crate::evidence::file(&dir, &e.id);
        let text =
            std::fs::read_to_string(&p).with_context(|| format!("reading {}", p.display()))?;
        for l in text.lines().filter(|l| !l.trim().is_empty()) {
            all.push(serde_json::from_str(l).with_context(|| format!("parsing {}", p.display()))?);
        }
    }
    Ok(all)
}

/// A case with the rules it is pinned to. Every analysis of a case is made
/// here, so each one renders under the same rules.
pub struct Pinned<'a> {
    pub root: &'a Path,
    pub case: &'a Case,
    pub rules: Rules,
}

impl<'a> Pinned<'a> {
    /// Load the rules case `c` is pinned to.
    pub fn new(root: &'a Path, c: &'a Case) -> Result<Self> {
        Ok(Self {
            root,
            case: c,
            rules: case_rules(root, c)?,
        })
    }

    /// The analysis of the records `scope` allows.
    pub fn analysis(&self, scope: &Scope) -> Result<Analysis> {
        Ok(analyze(
            case_records(self.root, self.case, scope)?,
            &self.rules,
        ))
    }
}

/// The case's analysis of the records `scope` allows, under its pinned rules.
pub fn analysis(root: &Path, c: &Case, scope: &Scope) -> Result<Analysis> {
    Pinned::new(root, c)?.analysis(scope)
}

/// Every case under `root`, by ID. A case file that does not parse is an error.
pub(crate) fn all(root: &Path) -> Result<Vec<Case>> {
    let mut cases = Vec::new();
    if let Ok(entries) = std::fs::read_dir(root) {
        for e in entries {
            let p = e?.path();
            if p.join("case.toml").is_file() {
                let id = p.file_name().unwrap_or_default().to_string_lossy();
                cases.push(load(root, &id)?);
            }
        }
    }
    cases.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(cases)
}

/// Append a decision log entry without printing anything.
pub(crate) fn log_entry(root: &Path, id: &str, today: &str, text: impl Into<String>) -> Result<()> {
    let mut c = load(root, id)?;
    c.log(today, text);
    save(root, &c)
}

fn records_path(root: &Path, id: &str) -> Result<PathBuf> {
    Ok(case_dir(root, id)?.join("raw").join("records.ndjson"))
}

fn load_records(root: &Path, id: &str) -> Result<Vec<Observation>> {
    let p = records_path(root, id)?;
    let text = std::fs::read_to_string(&p).with_context(|| format!("reading {}", p.display()))?;
    text.lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).with_context(|| format!("parsing {}", p.display())))
        .collect()
}

/// Open a case from `records`, pinned to `rules`.
pub(crate) fn new_case(
    root: &Path,
    id: &str,
    title: &str,
    records: Vec<Observation>,
    rules: &RulesText,
    today: &str,
) -> Result<Analysis> {
    let dir = case_dir(root, id)?;
    if dir.join("case.toml").exists() {
        bail!("case {id} already exists; use `case add` to add records");
    }
    if records.is_empty() {
        bail!("no records selected");
    }
    std::fs::create_dir_all(dir.join("raw"))?;
    let pin = pin_rules(root, rules)?;
    std::fs::write(records_path(root, id)?, to_ndjson(&records))?;
    let a = analyze(records, &rules.rules);
    let mut c = Case::new(id, title, today, Some(pin.clone()));
    c.add_endpoints(&a);
    c.log(
        today,
        format!(
            "opened with {} records ({} flagged), rules {pin}",
            a.total, a.flagged
        ),
    );
    save(root, &c)?;
    Ok(a)
}

/// Add the records the case does not hold yet, and any new endpoints they
/// bring, judged by the case's pinned rules.
pub(crate) fn add_records(
    root: &Path,
    id: &str,
    records: Vec<Observation>,
    today: &str,
) -> Result<(usize, usize)> {
    let mut c = load(root, id)?;
    let mut all = load_records(root, id)?;
    let have: BTreeSet<String> = all.iter().map(|o| o.id.clone()).collect();
    let fresh: Vec<Observation> = records
        .into_iter()
        .filter(|o| !have.contains(&o.id))
        .collect();
    if fresh.is_empty() {
        return Ok((0, 0));
    }
    let mut f = std::fs::OpenOptions::new()
        .append(true)
        .open(records_path(root, id)?)?;
    f.write_all(to_ndjson(&fresh).as_bytes())?;
    let n = fresh.len();
    all.extend(fresh);
    // The case's own records only: an operator's logs add no endpoints.
    let a = analyze(all, &Pinned::new(root, &c)?.rules);
    let hosts = c.add_endpoints(&a);
    c.log(
        today,
        format!("added {n} record(s), {hosts} new endpoint(s)"),
    );
    save(root, &c)?;
    Ok((n, hosts))
}

/// Give case `old` the ID `new`: move its directory, change the ID in
/// case.toml, log it, and carry the watch's hits for it over in
/// `<data>/state.json`. Refused once a notice is published, because the
/// notice's ID is public.
pub(crate) fn rename(root: &Path, old: &str, new: &str, today: &str) -> Result<()> {
    let mut c = load(root, old)?;
    let to = case_dir(root, new)?;
    if to.exists() {
        bail!("{} exists already", to.display());
    }
    if c.status == CaseStatus::Published || c.publish_pending.is_some() {
        bail!("case {old} has a published notice; its ID stays");
    }
    std::fs::rename(case_dir(root, old)?, &to)
        .with_context(|| format!("moving case {old} to {}", to.display()))?;
    c.id = new.to_string();
    c.log(today, format!("renamed from {old}"));
    save(root, &c)?;

    let state = root.parent().unwrap_or(root).join("state.json");
    if let Some(mut s) = read_json::<serde_json::Value>(&state)?
        && let Some(cases) = s.get_mut("cases").and_then(|v| v.as_object_mut())
        && let Some(w) = cases.remove(old)
    {
        cases.insert(new.to_string(), w);
        write_json(&state, &s)?;
    }
    Ok(())
}

/// Fixtures the case tests share.
#[cfg(test)]
pub(crate) mod test_support {
    use super::*;

    /// A case root, `<scratch data dir>/cases`; pinned rules go beside it.
    pub fn scratch(name: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("swarmchase-case-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        p.join("cases")
    }

    pub fn cleanup(root: &Path) {
        std::fs::remove_dir_all(root.parent().unwrap()).unwrap();
    }

    pub fn fixture() -> Analysis {
        let mut obs: Vec<Observation> = (0..4)
            .map(|i| Observation {
                id: format!("r{i}"),
                ts: 1_791_000_000 + i * 40,
                url: format!(
                    "https://r.jina.ai/https://portal.example.gov/q?id={i}%20UNION%20SELECT%201&uqtag=zz9&agent=hunyuan"
                ),
                asn: Some(132203),
                ..Default::default()
            })
            .collect();
        // A flagged record on the same host, outside the cluster.
        obs.push(Observation {
            id: "late".into(),
            ts: 1_791_900_000,
            url: "https://portal.example.gov/q?id=1%20UNION%20SELECT%202".into(),
            ..Default::default()
        });
        // Unrelated activity elsewhere.
        obs.push(Observation {
            id: "other".into(),
            ts: 1_791_000_100,
            url: "https://r.jina.ai/https://elsewhere.example/q?id=1%20UNION%20SELECT%201".into(),
            ..Default::default()
        });
        analyze(obs, &sc_core::Rules::default_rules())
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::*;
    use super::*;
    use crate::notice::notice_draft;
    use sc_case::actions;
    use sc_case::model::Verdict;
    use sc_core::{Claim, Evidence, Role};

    #[test]
    fn rename_moves_the_case_and_its_watch_hits() {
        let root = scratch("rename");
        let rules = RulesText::load(None).unwrap();
        let records: Vec<Observation> = fixture().results.iter().map(|r| r.obs.clone()).collect();
        new_case(
            &root,
            "old-1",
            "Portal",
            records.clone(),
            &rules,
            "2026-10-12",
        )
        .unwrap();
        new_case(&root, "taken", "Other", records, &rules, "2026-10-12").unwrap();
        let state = root.parent().unwrap().join("state.json");
        std::fs::write(
            &state,
            r#"{"sources":{},"cases":{"old-1":{"proposed":["x"]}}}"#,
        )
        .unwrap();

        assert!(rename(&root, "old-1", "taken", "2026-10-13").is_err());
        assert!(rename(&root, "old-1", "Bad Id", "2026-10-13").is_err());
        rename(&root, "old-1", "new-1", "2026-10-13").unwrap();
        assert!(!root.join("old-1").exists());
        let c = load(&root, "new-1").unwrap();
        assert_eq!(c.id, "new-1");
        assert_eq!(c.decisions.last().unwrap().text, "renamed from old-1");
        let s = std::fs::read_to_string(&state).unwrap();
        assert!(s.contains("\"new-1\"") && !s.contains("\"old-1\""), "{s}");

        // A published notice's ID is public, so its case keeps it.
        update(&root, "new-1", |c| {
            c.status = CaseStatus::Published;
            Ok(())
        })
        .unwrap();
        assert!(rename(&root, "new-1", "newer-1", "2026-10-14").is_err());
        cleanup(&root);
    }

    #[test]
    fn case_lifecycle() {
        let root = scratch("life");
        let rules = RulesText::load(None).unwrap();
        let a = fixture();
        let records: Vec<Observation> = a
            .results
            .iter()
            .filter(|r| r.obs.id != "other")
            .map(|r| r.obs.clone())
            .collect();
        new_case(&root, "t-1", "Portal probe", records, &rules, "2026-10-12").unwrap();
        assert!(
            new_case(&root, "t-1", "again", vec![], &rules, "2026-10-12").is_err(),
            "no overwrite"
        );

        let c = load(&root, "t-1").unwrap();
        assert_eq!(c.status, CaseStatus::Open);
        assert_eq!(c.endpoints.len(), 1);
        assert_eq!(c.endpoints[0].host, "portal.example.gov");
        assert_eq!(c.endpoints[0].state, EndpointState::Unreviewed);

        // Adding records dedupes and picks up new hosts.
        let other: Vec<Observation> = a.results.iter().map(|r| r.obs.clone()).collect();
        assert_eq!(
            add_records(&root, "t-1", other, "2026-10-13").unwrap(),
            (1, 1)
        );
        assert_eq!(load_records(&root, "t-1").unwrap().len(), 6);

        // Self-identification plus a same-company network is not enough to
        // name a developer at the default threshold; a case claim is.
        let mut buf = Vec::new();
        status(&root, "t-1", &mut buf).unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("Tencent (Developer)"), "{s}");
        assert!(s.contains("no developer can be named yet"), "{s}");
        assert!(s.contains("classify 2 endpoint(s)"), "{s}");

        update(&root, "t-1", |c| {
            c.claims.push(Claim {
                details: vec!["uqtag zz9 also in a confirmed incident".into()],
                ..Claim::new("Tencent", Role::Developer, Evidence::SharedIdentifiers)
            });
            c.endpoints[0].state = EndpointState::Targeted;
            Ok(())
        })
        .unwrap();
        let md = report(&root, "t-1", Audience::Provider, None, None, "2026-10-14").unwrap();
        assert!(md.contains("**Tencent** (developer)"), "{md}");

        // Drafts go only to listed contacts, and never as case notes.
        assert!(draft(&root, "t-1", Audience::Affected, "x@y.example", None, "d").is_err());
        update(&root, "t-1", |c| {
            c.contacts.push(Contact {
                org: "portal.example.gov".into(),
                role: ContactRole::Affected,
                endpoint: Some("portal.example.gov".into()),
                channel: "email".into(),
                address: "security@portal.example.gov".into(),
                source: "https://portal.example.gov/.well-known/security.txt".into(),
                confidence: "medium".into(),
                found_on: "2026-10-14".into(),
                purpose: None,
            });
            Ok(())
        })
        .unwrap();
        assert!(
            draft(
                &root,
                "t-1",
                Audience::Internal,
                "security@portal.example.gov",
                None,
                "d"
            )
            .is_err()
        );
        let p = draft(
            &root,
            "t-1",
            Audience::Affected,
            "SECURITY@portal.example.gov",
            None,
            "2026-10-14",
        )
        .unwrap();
        let eml = std::fs::read_to_string(&p).unwrap();
        assert!(eml.contains("To: security@portal.example.gov\r\n"));
        assert!(eml.contains("filename=\"MANIFEST.sha256\""));
        let bundle = root.join("t-1").join("bundles").join("2026-10-14");
        assert!(
            crate::bundle::verify(&bundle, &rules.rules)
                .unwrap()
                .is_empty()
        );
        let c = load(&root, "t-1").unwrap();
        assert_eq!(c.decisions.len(), 2);
        assert!(c.to_toml().unwrap().contains("[[claim]]"));
        assert!(
            draft(
                &root,
                "t-1",
                Audience::Public,
                "security@portal.example.gov",
                None,
                "d"
            )
            .is_err(),
            "notices are published, not sent"
        );

        // The indicator notice: drafted in the case, blocked by the
        // self-review checklist and the second review until every item
        // passes, then added to notices/ without its draft banner.
        const H: i64 = 3600;
        let t0 = 1_791_500_000;
        let (p, review) = notice_draft(&root, "t-1", false, "2026-10-15", t0).unwrap();
        assert!(review.lint.is_empty(), "{:?}", review.lint);
        assert_eq!(review.unreviewed, vec!["elsewhere.example".to_string()]);
        assert!(
            notice_draft(&root, "t-1", false, "2026-10-15", t0).is_err(),
            "keeps edits"
        );
        let md = std::fs::read_to_string(&p).unwrap();
        assert!(md.contains("providers = [\"Tencent\"]"), "{md}");
        assert!(md.contains("affected = []"), "{md}");
        assert!(!md.contains("portal[.]example"), "{md}");
        let notices = root.join("notices");
        let rules = sc_core::Rules::default_rules();
        let add =
            |now| crate::notice::add_for_test(&root, "t-1", &notices, &rules, "2026-10-09", now);
        let e = add(t0 + 30 * H).unwrap_err().to_string();
        assert!(e.contains("every endpoint is classified"), "{e}");
        assert!(e.contains("alternative explanations"), "{e}");
        assert!(e.contains("every party was sent"), "{e}");
        assert!(e.contains("an approved second review"), "{e}");
        update(&root, "t-1", |c| {
            c.admin = Some("Ada Admin".into());
            c.endpoints[1].state = EndpointState::NotAffected;
            actions::classify(
                c,
                &["portal.example.gov".into()],
                EndpointState::Compromised,
                None,
                Some("operator statement: a web shell was found"),
                None,
                "2026-10-15",
            )?;
            actions::describe(
                c,
                &["portal.example.gov".into()],
                "a national government data portal",
                "2026-10-15",
            )?;
            actions::sent(
                c,
                "security@portal.example.gov",
                "email",
                None,
                Some(&rfc3339(t0 + 60)),
                None,
                t0 + 120,
            )?;
            actions::no_contact(
                c,
                sc_case::lead::ANY_PROVIDER,
                "no directory entry for the self-named vendor",
                t0 + 60,
            )?;
            for k in AlternativeKind::ALL {
                actions::alternative(c, k, Some("checked; see case notes"), None, "2026-10-15")?;
            }
            Ok(())
        })
        .unwrap();
        // The draft predates the sends, so it cannot say who was reported.
        let e = add(t0 + 30 * H).unwrap_err().to_string();
        assert!(e.contains("the draft was written after every send"), "{e}");
        notice_draft(&root, "t-1", true, "2026-10-15", t0 + 120).unwrap();
        let md = std::fs::read_to_string(&p).unwrap();
        assert!(md.contains("a national government data portal"), "{md}");
        assert!(!md.contains("portal[.]example"), "{md}");
        // A re-read inside the cooling-off does not count.
        checklist::reread(&root, "t-1", "2026-10-15", t0 + 120 + H / 2).unwrap();
        let e = add(t0 + 30 * H).unwrap_err().to_string();
        assert!(e.contains("re-read at least an hour"), "{e}");
        checklist::reread(&root, "t-1", "2026-10-15", t0 + 120 + H).unwrap();
        // The compromised endpoint's operator has 24 hours; no override.
        let e = add(t0 + 3 * H).unwrap_err().to_string();
        assert!(e.contains("The lead time runs until"), "{e}");
        assert!(e.contains(&show_time(t0 + 60 + 24 * H)), "{e}");
        // An edit after the re-read needs another re-read.
        let draft = std::fs::read_to_string(&p).unwrap();
        std::fs::write(
            &p,
            draft.replace("## Indicators", "Edited.\n\n## Indicators"),
        )
        .unwrap();
        assert!(add(t0 + 7 * H).unwrap_err().to_string().contains("re-read"));
        checklist::reread(&root, "t-1", "2026-10-15", t0 + 7 * H).unwrap();

        // The second review: never the admin, and of the exact draft.
        let review = |reviewer: &str, verdict, now| {
            let items = crate::notice::checklist_for(&root, "t-1", now).unwrap();
            let blockers = sc_case::review::blockers(&items);
            let sha = checklist::draft_sha(&root, "t-1").unwrap();
            let mut c = load(&root, "t-1").unwrap();
            let r = sc_case::review::record(
                &mut c,
                sc_case::review::Input {
                    stage: Stage::Indicators,
                    reviewer,
                    verdict,
                    note: None,
                    sha: &sha,
                },
                &blockers,
                now,
            );
            save(&root, &c).unwrap();
            r
        };
        assert!(review(" ada admin", Verdict::Approve, t0 + 7 * H).is_err());
        review("Rae Reviewer", Verdict::Approve, t0 + 7 * H).unwrap();
        // Still inside the lead.
        assert!(add(t0 + 8 * H).is_err());
        let added = add(t0 + 25 * H).unwrap();
        let text = std::fs::read_to_string(&added).unwrap();
        assert!(!text.contains("DRAFT"), "{text}");
        assert!(text.contains("kind = \"published\""), "{text}");
        assert!(
            text.contains("Reports went to the affected operators before publication")
                && text.contains(
                    "No contact could be found for the AI provider; contact was attempted."
                )
                && text.contains(sc_case::notice::REVIEWED)
                && !text.contains("Rae"),
            "{text}"
        );
        assert!(
            !text.contains("portal[.]example") && !text.contains("portal.example"),
            "{text}"
        );
        // Added is not published: reported, with the push pending.
        let c = load(&root, "t-1").unwrap();
        assert_eq!(c.status, CaseStatus::Reported);
        assert_eq!(c.publish_pending.as_deref(), Some("2026-10-09"));
        let mut buf = Vec::new();
        status(&root, "t-1", &mut buf).unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("publish pending"), "{s}");
        assert!(s.contains("Stage 2, naming"), "{s}");
        assert!(add(t0 + 26 * H).is_err());

        // Names: the compromised endpoint's operator waits 10 working days,
        // unless it consents.
        let naming = |now| crate::notice::naming_draft(&root, "t-1", true, "2026-10-10", now);
        let e = naming(t0 + 26 * H).unwrap_err().to_string();
        assert!(e.contains("may be named from"), "{e}");
        update(&root, "t-1", |c| {
            Ok(sc_case::naming::consent(
                c,
                "portal.example.gov",
                "operator e-mail agreeing to be named",
                t0 + 26 * H,
            )?)
        })
        .unwrap();
        let (np, hosts) = naming(t0 + 26 * H).unwrap();
        assert_eq!(hosts, ["portal.example.gov"]);
        let add_naming = |now| {
            crate::notice::add_naming_for_test(&root, "t-1", &notices, &rules, "2026-10-10", now)
        };
        let e = add_naming(t0 + 27 * H).unwrap_err().to_string();
        assert!(e.contains("an approved second review"), "{e}");
        // An objection blocks until a later approval of the current draft.
        let naming_review = |reviewer: &str, verdict| {
            let items =
                crate::notice::naming_checklist_for(&root, "t-1", &notices, t0 + 27 * H).unwrap();
            let blockers = sc_case::review::blockers(&items);
            let sha = crate::notice::naming_sha(&root, "t-1").unwrap();
            let mut c = load(&root, "t-1").unwrap();
            assert_eq!(c.stage(), Stage::Naming);
            sc_case::review::record(
                &mut c,
                sc_case::review::Input {
                    stage: Stage::Naming,
                    reviewer,
                    verdict,
                    note: Some("checked"),
                    sha: &sha,
                },
                &blockers,
                t0 + 27 * H,
            )
            .unwrap();
            save(&root, &c).unwrap();
        };
        naming_review("Rae Reviewer", Verdict::Approve);
        naming_review("Sam Second", Verdict::Object);
        assert!(add_naming(t0 + 27 * H).is_err());
        naming_review("Rae Reviewer", Verdict::Approve);
        // An edit voids the approval.
        let nd = std::fs::read_to_string(&np).unwrap();
        std::fs::write(&np, nd.replace("was affected", "was affected (edited)")).unwrap();
        assert!(add_naming(t0 + 27 * H).is_err());
        std::fs::write(&np, &nd).unwrap();
        let after = add_naming(t0 + 27 * H).unwrap();
        let text = std::fs::read_to_string(&after).unwrap();
        assert!(text.contains("kind = \"naming\""), "{text}");
        assert!(
            text.contains("affected = [\"portal.example.gov\"]"),
            "{text}"
        );
        assert!(text.contains("`portal[.]example[.]gov`"), "{text}");
        assert!(
            crate::notice::lint_file_for_test(&after, &rules).is_empty(),
            "{text}"
        );
        let c = load(&root, "t-1").unwrap();
        assert_eq!(c.named.len(), 1);
        assert!(naming(t0 + 28 * H).is_err(), "nobody left to name");

        // Not on any remote (no repository here): refused unless forced.
        let e = crate::notice::published_for_test(&root, &notices, "t-1", false, "2026-10-17");
        assert!(e.unwrap_err().to_string().contains("not on origin yet"));
        crate::notice::published_for_test(&root, &notices, "t-1", true, "2026-10-17").unwrap();
        let c = load(&root, "t-1").unwrap();
        assert_eq!((c.status, c.publish_pending), (CaseStatus::Published, None));
        assert!(crate::notice::published_for_test(&root, &notices, "t-1", true, "d").is_err());
        cleanup(&root);
    }
}
