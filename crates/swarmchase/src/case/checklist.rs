//! The self-review checklist `notice add` runs before it writes a notice.
//! One admin decides and publishes, so the checks a second reviewer would
//! make are made here, against the case record, and printed as a pass/fail
//! list. Every item must pass; none has an override.

use super::lead;
use super::model::*;
use super::{Case, case_dir, case_records};
use crate::evidence::Scope;
use crate::pinning::case_rules;
use crate::wording;
use anyhow::Result;
use sc_core::{Analysis, Evidence, Provenance, Role, Tier, analyze};
use sc_publish::NoticeFile;
use std::collections::BTreeMap;
use std::path::Path;

/// The cooling-off between writing a notice draft and the re-read that
/// clears it, in seconds.
pub const COOLING_OFF: i64 = 3600;

/// Plant signals on one cluster that require a recorded review.
pub const PLANT_SIGNALS: usize = 2;

/// One checklist item.
#[derive(Debug, Clone)]
pub struct Item {
    pub name: &'static str,
    pub ok: bool,
    /// Why it fails, or what it rests on.
    pub detail: Vec<String>,
}

fn item(name: &'static str, problems: Vec<String>) -> Item {
    Item {
        name,
        ok: problems.is_empty(),
        detail: problems,
    }
}

/// Print the checklist as a pass/fail list.
pub fn print(items: &[Item], out: &mut impl std::io::Write) -> std::io::Result<()> {
    writeln!(out, "Self-review checklist")?;
    for i in items {
        writeln!(out, "  [{}] {}", if i.ok { "pass" } else { "FAIL" }, i.name)?;
        for d in &i.detail {
            writeln!(out, "         {d}")?;
        }
    }
    Ok(())
}

/// The SHA-256 of the case's notice draft as it is on disk.
pub fn draft_sha(root: &Path, id: &str) -> Result<String> {
    let p = case_dir(root, id)?.join(NOTICE_DRAFT);
    let bytes = std::fs::read(&p).map_err(|e| {
        anyhow::anyhow!(
            "reading {}: {e}; run `swarmchase case notice {id}`",
            p.display()
        )
    })?;
    Ok(crate::bundle::sha256_hex(&bytes))
}

/// Record that the admin re-read the notice draft as it is now. Returns
/// what to tell the admin: a re-read within the cooling-off is recorded but
/// does not clear the checklist.
pub fn reread(root: &Path, id: &str, today: &str, now: i64) -> Result<String> {
    let sha = draft_sha(root, id)?;
    let mut msg = String::new();
    super::update(root, id, |c| {
        let drafted = c.drafted.as_ref().and_then(|d| parse_time(&d.at));
        c.reread = Some(DraftStamp {
            sha256: sha.clone(),
            at: rfc3339(now),
        });
        c.log(
            today,
            format!("notice draft re-read (sha256 {})", &sha[..12]),
        );
        msg = match drafted {
            Some(d) if now < d + COOLING_OFF => format!(
                "re-read recorded, but less than an hour after the draft was written ({}); read it again from {} and record that",
                show_time(d),
                show_time(d + COOLING_OFF)
            ),
            Some(_) => "re-read of the current draft recorded".into(),
            None => format!(
                "re-read recorded; the draft has no recorded write time, so redraft it with `swarmchase case notice {id} --force`"
            ),
        };
        Ok(())
    })?;
    Ok(msg)
}

/// The organisation an endpoint belongs to, as a notice names it.
pub fn org_of(c: &Case, host: &str) -> String {
    let org = c
        .contacts
        .iter()
        .find(|x| {
            x.role == "affected"
                && x.endpoint
                    .as_deref()
                    .is_some_and(|h| h.eq_ignore_ascii_case(host))
        })
        .map(|x| x.org.clone())
        .unwrap_or_else(|| host.to_string());
    if org.contains('.') && !org.contains(' ') {
        sc_core::defang_host(&org)
    } else {
        org
    }
}

/// The fixed wording for an endpoint every record of which is
/// submit-anywhere: the records show a submission, not a request reaching
/// the operator.
pub fn single_source_line(c: &Case, host: &str) -> String {
    format!(
        "URLs targeting {}'s hosts were submitted to public scan services.",
        org_of(c, host)
    )
}

/// Affected endpoints every record of which comes from a service anyone can
/// submit a URL to.
pub fn single_source_hosts(c: &Case, a: &Analysis) -> Vec<String> {
    let mut by_host: BTreeMap<String, (usize, usize)> = BTreeMap::new();
    for r in &a.results {
        if let Some(h) = r.target_host.as_deref() {
            let e = by_host.entry(h.to_ascii_lowercase()).or_default();
            e.0 += 1;
            e.1 += usize::from(r.obs.provenance() == Provenance::SubmitAnywhere);
        }
    }
    super::affected_hosts(c)
        .into_iter()
        .filter(|h| {
            by_host
                .get(&h.to_ascii_lowercase())
                .is_some_and(|&(all, sub)| all > 0 && all == sub)
        })
        .collect()
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
    let rules = case_rules(root, c)?;
    let all = analyze(case_records(root, c, &Scope::All)?, &rules);
    let public = analyze(case_records(root, c, &Scope::Public)?, &rules);
    let claims = super::cli::all_claims(root, c)?;
    let body = &n.body;
    let text = format!("{}\n{body}", n.meta.title);
    let mut items = Vec::new();

    let unreviewed: Vec<String> = c
        .endpoints
        .iter()
        .filter(|e| e.state == EndpointState::Unreviewed)
        .map(|e| format!("unreviewed: {}", sc_core::defang_host(&e.host)))
        .collect();
    items.push(item("every endpoint is classified", unreviewed));

    let mut p = wording::claim_problems(body);
    for cl in &c.claims {
        let problems = cl.problems();
        if !problems.is_empty() {
            p.push(format!("case claim {}: {}", cl.party, problems.join("; ")));
        }
    }
    items.push(item(
        "every attribution claim has a layer, a label and a tag",
        p,
    ));
    items.push(item(
        "no likelihood word is stronger than its label allows",
        wording::likelihood_problems(&text),
    ));

    let mut p = wording::title_problems(
        &n.meta.title,
        &n.meta.providers,
        &crate::contacts::Directory::builtin(),
    );
    // Each self-named developer's best evidence, and every name it goes by:
    // its own, the directory's aliases, the model names in the requests.
    let dir = crate::contacts::Directory::builtin();
    let mut best: BTreeMap<String, (Evidence, Vec<String>)> = BTreeMap::new();
    for cl in claims.iter().filter(|x| x.role == Role::Developer) {
        let e = best
            .entry(cl.party.clone())
            .or_insert((cl.evidence, vec![cl.party.clone()]));
        e.0 = e.0.max(cl.evidence);
        if let Some(d) = dir.find(&cl.party) {
            e.1.push(d.name.clone());
            e.1.extend(d.aliases.iter().cloned());
        }
        e.1.extend(
            cl.details
                .iter()
                .filter_map(|d| d.split_once(" name `")?.1.split('`').next())
                .map(str::to_string),
        );
    }
    for (party, (e, aliases)) in &best {
        if let (true, Some(a)) = (
            *e < Evidence::SharedIdentifiers,
            aliases.iter().find(|a| wording::names(&n.meta.title, a)),
        ) {
            p.push(format!(
                "the title names `{a}` ({party}), whose evidence is {}: below shared identifiers a provider stays out of the title",
                e.describe()
            ));
        }
    }
    p.dedup();
    items.push(item("no provider in the title below shared identifiers", p));

    let affected = super::affected_hosts(c);
    let compromised: Vec<String> = c
        .endpoints
        .iter()
        .filter(|e| e.state == EndpointState::Compromised)
        .filter(|e| e.basis.as_deref().is_some_and(|b| !b.trim().is_empty()))
        .map(|e| e.host.clone())
        .collect();
    let mut p: Vec<String> = c
        .endpoints
        .iter()
        .filter(|e| e.state == EndpointState::Compromised && !compromised.contains(&e.host))
        .map(|e| {
            format!(
                "{} is classified compromised with no basis beyond the inbound requests: `swarmchase case endpoint {} {} compromised --basis \"…\"`",
                sc_core::defang_host(&e.host),
                c.id,
                e.host
            )
        })
        .collect();
    let others: Vec<String> = affected
        .iter()
        .filter(|h| !compromised.contains(h))
        .cloned()
        .collect();
    p.extend(wording::compromised_problems(&text, &compromised, &others));
    items.push(item(
        "\"compromised\" only for endpoints classified so with a recorded basis",
        p,
    ));
    items.push(item(
        "each named organisation is described as targeted or affected",
        wording::accusation_problems(&text, &affected),
    ));

    let mut p = Vec::new();
    for h in single_source_hosts(c, &all) {
        let e = c.endpoints.iter().find(|e| e.host.eq_ignore_ascii_case(&h));
        if e.and_then(|e| e.single_source.as_deref()).is_none() {
            p.push(format!(
                "every record on {} is submit-anywhere: naming its operator needs `swarmchase case endpoint {} {h} <state> --single-source-reason \"…\"`, or mark it not-affected",
                sc_core::defang_host(&h),
                c.id
            ));
        } else if !body.contains(&single_source_line(c, &h)) {
            p.push(format!(
                "the notice must say \"{}\" (redraft with `case notice --force`)",
                single_source_line(c, &h)
            ));
        }
    }
    items.push(item(
        "single-source endpoints are named only with a logged reason and the fixed wording",
        p,
    ));

    let mut p = Vec::new();
    for k in AlternativeKind::ALL {
        match c.alternatives.iter().rev().find(|x| x.kind == k) {
            None => p.push(format!(
                "{}: not decided (`swarmchase case alternative {} {} --rejected \"…\"`)",
                k.id(),
                c.id,
                k.id()
            )),
            Some(x) if x.verdict == "accepted" && !wording::names(body, "authorised test") => p
                .push(format!(
                    "{}: accepted, so the notice must say it was an authorised test",
                    k.id()
                )),
            Some(_) => {}
        }
    }
    items.push(item("alternative explanations are recorded as rejected", p));

    let p: Vec<String> = public
        .clusters
        .iter()
        .filter(|cl| cl.tier > Tier::Noise && cl.plant_signals.len() >= PLANT_SIGNALS)
        .filter(|cl| !c.plant_reviews.iter().any(|r| r.cluster == cl.key))
        .map(|cl| {
            format!(
                "{} {} has {} plant signals: `swarmchase case plant-review {} {} --note \"…\"`",
                cl.id,
                cl.key,
                cl.plant_signals.len(),
                c.id,
                cl.key
            )
        })
        .collect();
    items.push(item("plant signals are reviewed", p));

    let clock = lead::clock(c);
    items.push(item(
        "every party was sent its report or recorded as having no contact",
        clock
            .missing
            .iter()
            .map(|m| {
                format!(
                    "{m}: no send recorded (`swarmchase case sent {} --to … --at …`, or `swarmchase case no-contact {} <host|org> --searched \"…\"`)",
                    c.id, c.id
                )
            })
            .collect(),
    ));
    let mut lead_item = item(
        "the lead time has passed",
        match clock.not_before {
            None => vec!["unknown until every party is accounted for".into()],
            Some(t) if t > now => vec![format!(
                "the notice may be added from {} ({})",
                show_time(t),
                lead::summary(c)
            )],
            Some(_) => Vec::new(),
        },
    );
    if lead_item.ok
        && let Some(t) = clock.not_before
    {
        lead_item
            .detail
            .push(format!("not before {} (passed)", show_time(t)));
    }
    items.push(lead_item);

    let drafted = c.drafted.as_ref().and_then(|d| parse_time(&d.at));
    let last_send = clock.parties.iter().filter_map(lead::Party::recorded).max();
    let p = match (drafted, last_send) {
        (None, _) => vec![format!(
            "no draft time recorded: `swarmchase case notice {} --force`",
            c.id
        )],
        (Some(d), Some(s)) if d < s => vec![format!(
            "the draft ({}) is older than the last send ({}), so it does not say who was reported: `swarmchase case notice {} --force`",
            show_time(d),
            show_time(s),
            c.id
        )],
        _ => Vec::new(),
    };
    items.push(item("the draft was written after every send", p));

    let sha = draft_sha(root, &c.id).ok();
    let p = match (&c.reread, drafted) {
        (None, _) => vec![format!(
            "no re-read recorded: read the draft again, then `swarmchase case reread {}`",
            c.id
        )],
        (Some(r), _) if Some(&r.sha256) != sha.as_ref() => vec![format!(
            "the draft changed after the last re-read: read it again, then `swarmchase case reread {}`",
            c.id
        )],
        (Some(r), Some(d)) => match parse_time(&r.at) {
            Some(t) if t >= d + COOLING_OFF => Vec::new(),
            _ => vec![format!(
                "the re-read must come at least an hour after the draft was written: from {}",
                show_time(d + COOLING_OFF)
            )],
        },
        (Some(_), None) => vec!["no draft time recorded".into()],
    };
    items.push(item(
        "the current draft was re-read at least an hour after it was written",
        p,
    ));
    items.push(item("the withholding scan passes", withholding));
    Ok(items)
}

/// The failing items' names, for an error message.
pub fn failing(items: &[Item]) -> Vec<&'static str> {
    items.iter().filter(|i| !i.ok).map(|i| i.name).collect()
}

#[cfg(test)]
mod tests {
    use super::super::cli::{alternative, classify};
    use super::super::test_support::*;
    use super::super::{load, new_case, update};
    use super::*;
    use crate::pinning::RulesText;
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
        update(&root, "s-1", |c| {
            classify(
                c,
                &["portal.example.gov".into()],
                EndpointState::Targeted,
                None,
                None,
                None,
                "d",
            )
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
        // Every record is submit-anywhere: naming needs a logged reason.
        assert!(!named(&i, "single-source").ok, "{i:?}");
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
                &["portal.example.gov".into()],
                EndpointState::Targeted,
                None,
                None,
                Some("the operator confirmed the requests by phone"),
                "d",
            )?;
            c.title = "Agents probe a portal".into();
            let a = crate::case::cli::case_analysis(&root, c)?;
            c.plant_reviews.push(PlantReview {
                cluster: a.clusters[0].key.clone(),
                note: "tag copied from the report, but the payload dialect matches".into(),
                date: "d".into(),
            });
            Ok(())
        })
        .unwrap();
        let (p, _) = crate::notice::notice_draft(&root, "s-1", true, "2026-10-15", t0).unwrap();
        let md = std::fs::read_to_string(p).unwrap();
        assert!(
            md.contains("URLs targeting portal[.]example[.]gov's hosts were submitted to public scan services."),
            "{md}"
        );
        assert!(
            md.contains("identify themselves as using `hunyuan` from Tencent"),
            "{md}"
        );
        let i = items(&root, t0);
        for n in [
            "single-source",
            "no provider in the title",
            "plant signals",
            "no likelihood",
            "every attribution",
        ] {
            assert!(named(&i, n).ok, "{n}: {i:?}");
        }

        // "compromised" needs a basis beyond the inbound requests.
        let mut c = load(&root, "s-1").unwrap();
        let host = ["portal.example.gov".to_string()];
        assert!(
            classify(
                &mut c,
                &host,
                EndpointState::Compromised,
                None,
                None,
                None,
                "d"
            )
            .is_err()
        );
        assert!(
            classify(
                &mut c,
                &host,
                EndpointState::Targeted,
                None,
                Some("x"),
                None,
                "d"
            )
            .is_err()
        );
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
        classify(
            &mut c,
            &host,
            EndpointState::Compromised,
            Some("again"),
            None,
            None,
            "d",
        )
        .unwrap();
        assert_eq!(
            c.endpoints[0].basis.as_deref(),
            Some("operator: shell found")
        );
        c.endpoints[0].basis = None;
        super::super::save(&root, &c).unwrap();
        crate::notice::notice_draft(&root, "s-1", true, "2026-10-15", t0).unwrap();
        assert!(!named(&items(&root, t0), "\"compromised\"").ok);

        // Only an authorised test can be accepted; the rest are rejected.
        assert!(alternative(&mut c, AlternativeKind::Honeypot, None, Some("x"), "d").is_err());
        assert!(alternative(&mut c, AlternativeKind::Honeypot, None, None, "d").is_err());
        alternative(
            &mut c,
            AlternativeKind::AuthorisedTest,
            None,
            Some("owner confirmed: <link>"),
            "d",
        )
        .unwrap();
        assert_eq!(c.alternatives[0].verdict, "accepted");
        cleanup(&root);
    }
}
