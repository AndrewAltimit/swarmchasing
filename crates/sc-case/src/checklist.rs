//! The self-review checklist `notice add` runs before it writes a notice.
//! One admin decides and publishes, so the checks a second reviewer would
//! make are made here, against the case record, and printed as a pass/fail
//! list. Every item must pass; none has an override.
//!
//! The caller gathers the inputs (the case, the notice it is about to add,
//! the case's analyses under its pinned rules, the draft's hash on disk and
//! the withholding scan) and [`checklist`] decides.

use crate::lead;
use crate::model::*;
use crate::notice::{NoticeFile, wording};
use crate::providers::Directory;
use crate::report::affected_hosts;
use sc_core::{Analysis, Claim, Evidence, Provenance, Role, Tier};
use std::collections::BTreeMap;

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

/// The failing items' names, for an error message.
pub fn failing(items: &[Item]) -> Vec<&'static str> {
    items.iter().filter(|i| !i.ok).map(|i| i.name).collect()
}

/// Record that the admin re-read the notice draft whose hash is `sha`.
/// Returns what to tell the admin: a re-read within the cooling-off is
/// recorded but does not clear the checklist.
pub fn reread(c: &mut Case, sha: &str, today: &str, now: i64) -> String {
    let drafted = c.drafted.as_ref().and_then(|d| parse_time(&d.at));
    c.reread = Some(DraftStamp {
        sha256: sha.to_string(),
        at: rfc3339(now),
    });
    c.log(
        today,
        format!(
            "notice draft re-read (sha256 {})",
            sha.get(..12).unwrap_or(sha)
        ),
    );
    match drafted {
        Some(d) if now < d + COOLING_OFF => format!(
            "re-read recorded, but less than an hour after the draft was written ({}); read it again from {} and record that",
            show_time(d),
            show_time(d + COOLING_OFF)
        ),
        Some(_) => "re-read of the current draft recorded".into(),
        None => format!(
            "re-read recorded; the draft has no recorded write time, so redraft it with `swarmchase case notice {} --force`",
            c.id
        ),
    }
}

/// The organisation an endpoint belongs to, as a notice names it.
pub fn org_of(c: &Case, host: &str) -> String {
    let org = c
        .contacts_in(ContactRole::Affected)
        .find(|x| x.is_for(host))
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
    affected_hosts(c)
        .into_iter()
        .filter(|h| {
            by_host
                .get(&h.to_ascii_lowercase())
                .is_some_and(|&(all, sub)| all > 0 && all == sub)
        })
        .collect()
}

/// What the checklist is decided on.
pub struct Inputs<'a> {
    pub case: &'a Case,
    /// The notice `notice add` would write.
    pub notice: &'a NoticeFile,
    /// The case's analysis over all its records, under its pinned rules.
    pub all: &'a Analysis,
    /// The analysis of what the notice may use ([`crate::Scope::Public`]).
    pub public: &'a Analysis,
    /// The case's claims with the records' own ([`crate::report::all_claims`]).
    pub claims: &'a [Claim],
    /// The provider directory, for the names a title may not carry.
    pub directory: &'a Directory,
    /// The SHA-256 of the draft as it is on disk, if it can be read.
    pub draft_sha: Option<&'a str>,
    /// What the withholding scan found ([`crate::notice::lint::withholding`]).
    pub withholding: Vec<String>,
    pub now: i64,
}

/// The checklist for the case and the notice it is about to add.
pub fn checklist(x: Inputs) -> Vec<Item> {
    let c = x.case;
    let n = x.notice;
    let body = &n.body;
    let text = format!("{}\n{body}", n.meta.title);
    let mut items = Vec::new();

    let unreviewed: Vec<String> = c
        .unreviewed()
        .into_iter()
        .map(|h| format!("unreviewed: {}", sc_core::defang_host(h)))
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

    let mut p = wording::title_problems(&n.meta.title, &n.meta.providers, x.directory);
    // Each self-named developer's best evidence, and every name it goes by:
    // its own, the directory's aliases, the model names in the requests.
    let mut best: BTreeMap<String, (Evidence, Vec<String>)> = BTreeMap::new();
    for cl in x.claims.iter().filter(|x| x.role == Role::Developer) {
        let e = best
            .entry(cl.party.clone())
            .or_insert((cl.evidence, vec![cl.party.clone()]));
        e.0 = e.0.max(cl.evidence);
        if let Some(d) = x.directory.find(&cl.party) {
            e.1.extend(d.names().cloned());
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

    let affected = affected_hosts(c);
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
    for h in single_source_hosts(c, x.all) {
        if c.endpoint(&h)
            .and_then(|e| e.single_source.as_deref())
            .is_none()
        {
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

    let p: Vec<String> = x
        .public
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
            Some(t) if t > x.now => vec![format!(
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

    let p = match (&c.reread, drafted) {
        (None, _) => vec![format!(
            "no re-read recorded: read the draft again, then `swarmchase case reread {}`",
            c.id
        )],
        (Some(r), _) if Some(r.sha256.as_str()) != x.draft_sha => vec![format!(
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
    items.push(item("the withholding scan passes", x.withholding));
    items
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_reread_inside_the_cooling_off_is_recorded_but_does_not_clear() {
        let mut c = Case::new("r-1", "R", "d", None);
        let t0 = 1_791_000_000;
        assert!(reread(&mut c, "abcdef0123456789", "d", t0).contains("no recorded write time"));
        c.drafted = Some(DraftStamp {
            sha256: "abcdef0123456789".into(),
            at: rfc3339(t0),
        });
        assert!(reread(&mut c, "abcdef0123456789", "d", t0 + 60).contains("less than an hour"));
        assert_eq!(
            reread(&mut c, "abcdef0123456789", "d", t0 + COOLING_OFF),
            "re-read of the current draft recorded"
        );
        assert_eq!(c.reread.as_ref().unwrap().at, rfc3339(t0 + COOLING_OFF));
        assert!(c.decisions.last().unwrap().text.ends_with("abcdef012345)"));
    }
}
