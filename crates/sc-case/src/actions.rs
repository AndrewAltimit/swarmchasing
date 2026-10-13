//! The admin's decisions on a case. Each checks what it is given, changes
//! the case only when every check passes, and logs what it did in the
//! decision log. None reads or writes a file; the caller saves the case.

use crate::lead::ANY_PROVIDER;
use crate::model::*;
use crate::{Result, bail};
use sc_core::{AgentLevel, Claim, Evidence, GradeDecision, Role, Tag};

fn given(s: Option<&str>) -> Option<&str> {
    s.map(str::trim).filter(|s| !s.is_empty())
}

/// Classify `hosts`. Every host is found before anything changes, so a typo
/// changes nothing. `compromised` needs a basis beyond the inbound requests,
/// given now or recorded before.
pub fn classify(
    c: &mut Case,
    hosts: &[String],
    state: EndpointState,
    note: Option<&str>,
    basis: Option<&str>,
    single_source: Option<&str>,
    today: &str,
) -> Result<()> {
    let id = c.id.clone();
    let mut found = Vec::new();
    for host in hosts {
        match c
            .endpoints
            .iter()
            .position(|e| e.host.eq_ignore_ascii_case(host))
        {
            Some(i) => found.push(i),
            None => bail!(
                "no endpoint `{host}` in case {id}{}",
                crate::text::did_you_mean(host, c.endpoints.iter().map(|e| e.host.as_str()))
            ),
        }
    }
    if basis.is_some() && state != EndpointState::Compromised {
        bail!("--basis is for compromised endpoints");
    }
    if state == EndpointState::Compromised && given(basis).is_none() {
        let missing: Vec<&str> = found
            .iter()
            .filter(|&&i| c.endpoints[i].basis.is_none())
            .map(|&i| c.endpoints[i].host.as_str())
            .collect();
        if !missing.is_empty() {
            bail!(
                "compromised needs --basis \"…\": what shows the attack succeeded beyond the inbound requests (an operator's statement, its logs, a leaked artifact), for {}",
                missing.join(", ")
            );
        }
    }
    for (host, i) in hosts.iter().zip(found) {
        let e = &mut c.endpoints[i];
        e.state = state;
        e.note = note.map(str::to_string).or(e.note.take());
        if state != EndpointState::Compromised {
            e.basis = None;
        } else if let Some(b) = given(basis) {
            e.basis = Some(b.to_string());
        }
        if let Some(r) = given(single_source) {
            e.single_source = Some(r.to_string());
        }
        let mut text = format!("endpoint {host}: {}", state.label());
        for (what, v) in [
            ("", note),
            ("basis: ", given(basis)),
            (
                "named on submit-anywhere records only: ",
                given(single_source),
            ),
        ] {
            if let Some(v) = v {
                text += &format!(" ({what}{v})");
            }
        }
        c.log(today, text);
    }
    Ok(())
}

/// Set how the indicator notice describes `hosts` without identifying them
/// (`case endpoint --sector`). Every host is found before anything changes.
pub fn describe(c: &mut Case, hosts: &[String], sector: &str, today: &str) -> Result<()> {
    let sector = sector.trim();
    if sector.is_empty() {
        bail!(
            "--sector: how the notice describes the target, e.g. \"a national government data portal\""
        );
    }
    for host in hosts {
        if c.endpoint(host).is_none() {
            bail!(
                "no endpoint `{host}` in case {}{}",
                c.id,
                crate::text::did_you_mean(host, c.endpoints.iter().map(|e| e.host.as_str()))
            );
        }
    }
    for host in hosts {
        if let Some(e) = c
            .endpoints
            .iter_mut()
            .find(|e| e.host.eq_ignore_ascii_case(host))
        {
            e.sector = Some(sector.to_string());
        }
        c.log(today, format!("endpoint {host}: described as \"{sector}\""));
    }
    Ok(())
}

/// Record the admin's scope finding for cluster `key` (`case scope`).
/// `tests` are the failed scope tests (`S1`..`S7`); scope exceeded needs at
/// least one, and in scope none.
pub fn scope(
    c: &mut Case,
    key: &str,
    finding: sc_core::scope::ScopeFinding,
    tests: &[String],
    note: &str,
    today: &str,
) -> Result<()> {
    use sc_core::scope::ScopeFinding as F;
    let mut ids: Vec<String> = Vec::new();
    for t in tests.iter().flat_map(|t| t.split(',')) {
        let t = t.trim().to_ascii_uppercase();
        if t.is_empty() {
            continue;
        }
        let ok = t.len() == 2
            && t.starts_with('S')
            && ('1'..='7').contains(&t.chars().nth(1).unwrap_or('0'));
        if !ok {
            bail!("unknown scope test `{t}` (S1..S7)");
        }
        if !ids.contains(&t) {
            ids.push(t);
        }
    }
    ids.sort();
    match finding {
        F::ScopeExceeded if ids.is_empty() => {
            bail!("a finding of scope exceeded needs --tests: the failed tests, e.g. S2,S4")
        }
        F::InScope if !ids.is_empty() => bail!("in scope means no test failed; drop --tests"),
        _ => {}
    }
    if note.trim().is_empty() {
        bail!("--note: what the finding rests on, with the records");
    }
    c.scope_findings.push(ScopeDecision {
        cluster: key.to_string(),
        finding,
        tests: ids.clone(),
        note: note.to_string(),
        date: today.to_string(),
    });
    c.log(
        today,
        format!(
            "scope finding for {key}: {}{} ({note})",
            finding.label(),
            if ids.is_empty() {
                String::new()
            } else {
                format!(" ({})", ids.join(", "))
            }
        ),
    );
    Ok(())
}

/// Record that no contact was found for `party`: an endpoint's host, a
/// provider organisation among the contacts, or [`ANY_PROVIDER`].
pub fn no_contact(c: &mut Case, party: &str, searched: &str, now: i64) -> Result<()> {
    let is_host = c.endpoint(party).is_some();
    let is_provider = party.eq_ignore_ascii_case(ANY_PROVIDER)
        || c.contacts_in(ContactRole::Provider)
            .any(|x| x.org.eq_ignore_ascii_case(party));
    if !(is_host || is_provider) {
        bail!(
            "`{party}` is neither an endpoint nor a provider organisation in case {}",
            c.id
        );
    }
    if searched.trim().is_empty() {
        bail!("--searched: what was tried (security.txt, RDAP, the provider directory, …)");
    }
    let addresses: Vec<&str> = c
        .contacts
        .iter()
        .filter(|x| {
            x.is_for(party)
                || (x.role == ContactRole::Provider && x.org.eq_ignore_ascii_case(party))
        })
        .map(|x| x.address.as_str())
        .collect();
    if !addresses.is_empty() {
        bail!(
            "case {} lists a contact for `{party}` ({}); send it the report, or remove a contact that does not work with `case contact rm`",
            c.id,
            addresses.join(", ")
        );
    }
    c.no_contact.push(NoContact {
        party: party.to_string(),
        searched: searched.to_string(),
        at: rfc3339(now),
    });
    let today = crate::text::date_of(now);
    c.log(
        &today,
        format!("no contact found for {party} (searched: {searched}); the notice says contact was attempted"),
    );
    Ok(())
}

/// Record the admin's decision on one alternative explanation.
pub fn alternative(
    c: &mut Case,
    kind: AlternativeKind,
    rejected: Option<&str>,
    accepted: Option<&str>,
    today: &str,
) -> Result<()> {
    let (verdict, why) = match (rejected, accepted) {
        (Some(w), None) => ("rejected", w),
        (None, Some(w)) if kind == AlternativeKind::AuthorisedTest => ("accepted", w),
        (None, Some(_)) => bail!(
            "only an authorised test is accepted here (its owner confirmed it); if another explanation holds, the case is not an incident: close it"
        ),
        _ => bail!("give --rejected \"why\" (or, for authorised-test, --accepted \"link\")"),
    };
    if why.trim().is_empty() {
        bail!("say why, with links");
    }
    c.alternatives.push(Alternative {
        kind,
        verdict: verdict.into(),
        why: why.to_string(),
        date: today.to_string(),
    });
    c.log(
        today,
        format!("alternative {}: {verdict} ({why})", kind.id()),
    );
    Ok(())
}

/// Record a send. `at` (RFC 3339) or `date` (`YYYY-MM-DD`) say when;
/// default now. A send time or date in the future, or a date that does not
/// parse, is refused: the lead time runs from the real send. Returns a line
/// for the admin, with a warning when `to` is none of the case's contacts
/// (such a send counts for no party).
pub fn sent(
    c: &mut Case,
    to: &str,
    channel: &str,
    report: Option<String>,
    at: Option<&str>,
    date: Option<&str>,
    now: i64,
) -> Result<String> {
    let at = match (at, date) {
        (Some(a), _) => match parse_time(a) {
            Some(t) => Some(t),
            None => bail!("--at `{a}`: give an RFC 3339 time, e.g. 2026-10-12T14:05:00Z"),
        },
        (None, Some(d)) => {
            if chrono::NaiveDate::parse_from_str(d.trim(), "%Y-%m-%d").is_err() {
                bail!("--date `{d}`: give a date as YYYY-MM-DD, e.g. 2026-10-12");
            }
            if d.trim() > crate::text::date_of(now).as_str() {
                bail!("a send cannot be recorded in the future");
            }
            None
        }
        (None, None) => Some(now),
    };
    if at.is_some_and(|t| t > now + 300) {
        bail!("a send cannot be recorded in the future");
    }
    let date = date.map(str::trim);
    let known = c
        .contacts
        .iter()
        .any(|x| x.address.trim().eq_ignore_ascii_case(to.trim()));
    let date = at
        .map(crate::text::date_of)
        .or(date.map(str::to_string))
        .unwrap_or_default();
    c.sent.push(Sent {
        date: date.clone(),
        recipient: to.to_string(),
        channel: channel.to_string(),
        report,
        at: at.map(rfc3339),
    });
    let when = at.map(show_time).unwrap_or_else(|| date.clone());
    c.log(&date, format!("sent to {to} by {channel} at {when}"));
    if c.status == CaseStatus::Open {
        c.status = CaseStatus::Reported;
        c.log(&date, "status: reported");
    }
    let mut line = format!("send to {to} at {when}");
    if !known {
        line.push_str(&format!(
            " (warning: {to} is not one of this case's contacts, so the send counts for no party; add it with `case contact add` if it is one)"
        ));
    }
    Ok(line)
}

/// A claim from case work, as `case claim` takes it.
#[derive(Debug, Clone)]
pub struct ClaimInput {
    pub party: String,
    pub layer: Role,
    pub evidence: Option<Evidence>,
    pub tag: Option<Tag>,
    pub likelihood: Option<f64>,
    pub accuracy: Option<f64>,
    pub corpus_size: Option<usize>,
    pub details: Vec<String>,
}

/// Record an attribution claim established by case work. Developer and
/// host claims need their evidence; harness and model-family claims default
/// to self-identification.
pub fn claim(c: &mut Case, x: ClaimInput, today: &str) -> Result<()> {
    let evidence = match (x.evidence, x.layer) {
        (Some(e), _) => e,
        (None, Role::Harness | Role::ModelFamily) => Evidence::SelfId,
        (None, _) => bail!("a {} claim needs --evidence", x.layer.id()),
    };
    let claim = Claim {
        party: x.party.clone(),
        role: x.layer,
        evidence,
        details: x.details,
        tag: x.tag,
        records: 0,
        likelihood: x.likelihood,
        accuracy: x.accuracy,
        corpus_size: x.corpus_size,
    };
    let problems = claim.problems();
    if !problems.is_empty() {
        bail!("claim not recorded: {}", problems.join("; "));
    }
    c.log(
        today,
        format!(
            "claim: {} ({} layer, {}, {}) on {}",
            x.party,
            x.layer.id(),
            claim.label().label(),
            claim.tag().label(),
            evidence.describe()
        ),
    );
    c.claims.push(claim);
    Ok(())
}

/// Record the admin's agent grade, with what it rests on.
pub fn grade(c: &mut Case, level: AgentLevel, note: Option<&str>, today: &str) -> Result<()> {
    let Some(note) = given(note) else {
        bail!("an agent grade needs --note: what it rests on, with links");
    };
    c.log(
        today,
        format!("agent grade: {} {} ({note})", level.code(), level.label()),
    );
    c.agent_grade = Some(GradeDecision {
        level,
        date: today.to_string(),
        note: note.to_string(),
    });
    Ok(())
}

/// Remove the admin's agent grade.
pub fn clear_grade(c: &mut Case, today: &str) -> Result<()> {
    if c.agent_grade.take().is_none() {
        bail!("case {} has no agent grade to clear", c.id);
    }
    c.log(today, "agent grade cleared");
    Ok(())
}

/// Record that the admin reviewed the plant signals on cluster `key`
/// (`signals` of them), replacing an earlier review of it.
pub fn plant_review(
    c: &mut Case,
    key: &str,
    signals: usize,
    note: &str,
    today: &str,
) -> Result<()> {
    if note.trim().is_empty() {
        bail!("--note: what you checked and why the cluster stands");
    }
    c.plant_reviews.retain(|r| r.cluster != key);
    c.plant_reviews.push(PlantReview {
        cluster: key.to_string(),
        note: note.to_string(),
        date: today.to_string(),
    });
    c.log(
        today,
        format!("plant signals reviewed on {key} ({signals} signal(s)): {note}"),
    );
    Ok(())
}

/// A contact found by hand, as `case contact add` takes it.
#[derive(Debug, Clone)]
pub struct ContactInput {
    pub role: ContactRole,
    pub org: String,
    /// email | form | web_form | portal | phone
    pub channel: String,
    pub address: String,
    pub source: String,
    /// low | medium | high
    pub confidence: String,
    pub endpoint: Option<String>,
}

/// Add a contact found by hand. Every contact needs the link it was found
/// at, a channel its address fits, and, for an endpoint, an endpoint of the
/// case.
pub fn add_contact(c: &mut Case, x: ContactInput, today: &str) -> Result<()> {
    let channel = crate::providers::case_channel(&x.channel)?;
    if !matches!(x.confidence.as_str(), "low" | "medium" | "high") {
        bail!("confidence `{}`: low|medium|high", x.confidence);
    }
    if !(x.source.starts_with("https://") || x.source.starts_with("http://")) {
        bail!("--source must be the link the contact was found at");
    }
    let is_email = x.address.contains('@') && !x.address.contains('/');
    if (channel == "email") != is_email {
        bail!("`{}` does not fit channel {channel}", x.address);
    }
    if let Some(h) = &x.endpoint
        && c.endpoint(h).is_none()
    {
        bail!(
            "no endpoint `{h}` in case {}{}",
            c.id,
            crate::text::did_you_mean(h, c.endpoints.iter().map(|e| e.host.as_str()))
        );
    }
    if c.contacts
        .iter()
        .any(|y| y.address.eq_ignore_ascii_case(&x.address) && y.endpoint == x.endpoint)
    {
        bail!("`{}` is already a contact in case {}", x.address, c.id);
    }
    c.log(
        today,
        format!(
            "contact added: {} ({}) {channel} {}",
            x.org, x.role, x.address
        ),
    );
    c.contacts.push(Contact {
        org: x.org,
        role: x.role,
        endpoint: x.endpoint,
        channel: channel.into(),
        address: x.address,
        source: x.source,
        confidence: x.confidence,
        found_on: today.to_string(),
        purpose: None,
    });
    Ok(())
}

/// Remove every contact with `address`.
pub fn remove_contact(c: &mut Case, address: &str, today: &str) -> Result<()> {
    let before = c.contacts.len();
    c.contacts
        .retain(|x| !x.address.eq_ignore_ascii_case(address));
    if before == c.contacts.len() {
        bail!(
            "`{address}` is not a contact in case {}{}",
            c.id,
            crate::text::did_you_mean(address, c.contacts.iter().map(|x| x.address.as_str()))
        );
    }
    c.log(today, format!("contact removed: {address}"));
    Ok(())
}

/// The case settings `case set` changes.
#[derive(Debug, Clone, Default)]
pub struct Settings {
    pub status: Option<CaseStatus>,
    pub notice: Option<NoticeStatus>,
    pub min_named: Option<Evidence>,
    /// The naming lead in working days ([`crate::naming::set_days`]).
    pub naming_days: Option<u32>,
    pub admin: Option<String>,
}

/// Change the case or notice status, the developer naming threshold, the
/// naming lead or the admin. The naming threshold never goes below
/// [`Evidence::FLOOR`]; the naming lead only lengthens.
pub fn set(c: &mut Case, s: Settings, today: &str) -> Result<()> {
    if let Some(n) = s.naming_days {
        crate::naming::set_days(c, n, today)?;
    }
    if let Some(a) = &s.admin {
        crate::review::set_admin(c, a, today)?;
    }
    if let Some(st) = s.status {
        c.status = st;
        c.log(today, format!("status: {}", st.label()));
    }
    if let Some(n) = s.notice {
        c.notice = n;
        c.log(today, format!("notice status: {}", n.label()));
    }
    if let Some(m) = s.min_named {
        let m = m.max(Evidence::FLOOR);
        c.min_named = m;
        c.log(today, format!("developers named at: {}", m.describe()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn case() -> Case {
        let mut c = Case::new("s-1", "T", "2026-10-12", None);
        c.endpoints.push(CaseEndpoint {
            host: "portal.example.gov".into(),
            ..Default::default()
        });
        c
    }

    #[test]
    fn compromised_needs_a_basis_and_keeps_it() {
        let mut c = case();
        let host = ["portal.example.gov".to_string()];
        let classify = |c: &mut Case, s, note, basis| classify(c, &host, s, note, basis, None, "d");
        assert!(classify(&mut c, EndpointState::Compromised, None, None).is_err());
        assert!(classify(&mut c, EndpointState::Targeted, None, Some("x")).is_err());
        classify(
            &mut c,
            EndpointState::Compromised,
            None,
            Some("operator: shell found"),
        )
        .unwrap();
        classify(&mut c, EndpointState::Compromised, Some("again"), None).unwrap();
        assert_eq!(
            c.endpoints[0].basis.as_deref(),
            Some("operator: shell found")
        );
        // A typo changes nothing.
        let two = ["portal.example.gov".to_string(), "nope.example".to_string()];
        assert!(
            super::classify(&mut c, &two, EndpointState::Targeted, None, None, None, "d").is_err()
        );
        assert_eq!(c.endpoints[0].state, EndpointState::Compromised);
    }

    #[test]
    fn only_an_authorised_test_is_accepted() {
        let mut c = case();
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
    }

    #[test]
    fn sends_are_never_in_the_future() {
        let mut c = case();
        let now = 1_791_000_000;
        assert!(
            sent(
                &mut c,
                "a@b.example",
                "email",
                None,
                Some("tomorrow"),
                None,
                now
            )
            .is_err()
        );
        let late = rfc3339(now + 3600);
        assert!(sent(&mut c, "a@b.example", "email", None, Some(&late), None, now).is_err());
        sent(
            &mut c,
            "a@b.example",
            "email",
            None,
            None,
            Some("2026-10-02"),
            now,
        )
        .unwrap();
        assert_eq!(c.status, CaseStatus::Reported);
        assert_eq!(c.sent[0].at, None);
        // A date that does not parse, or is after today, is refused.
        for bad in ["2026-13-40", "last week", "2026-10-30"] {
            assert!(
                sent(&mut c, "a@b.example", "email", None, None, Some(bad), now).is_err(),
                "{bad}"
            );
        }
        assert_eq!(c.sent.len(), 1);
    }

    #[test]
    fn a_send_to_no_known_contact_is_flagged() {
        let mut c = case();
        let now = 1_791_000_000;
        let line = sent(&mut c, "who@else.example", "email", None, None, None, now).unwrap();
        assert!(line.contains("warning"), "{line}");
        c.contacts.push(Contact {
            org: "Portal".into(),
            role: ContactRole::Affected,
            endpoint: Some("portal.example.gov".into()),
            channel: "email".into(),
            address: "Security@Portal.example.gov".into(),
            source: "https://portal.example.gov/.well-known/security.txt".into(),
            confidence: "high".into(),
            found_on: "d".into(),
            purpose: None,
        });
        let line = sent(
            &mut c,
            "security@portal.example.gov",
            "email",
            None,
            None,
            None,
            now,
        )
        .unwrap();
        assert!(!line.contains("warning"), "{line}");
    }

    #[test]
    fn contacts_need_a_source_and_a_fitting_channel() {
        let mut c = case();
        let input = |address: &str, channel: &str, source: &str| ContactInput {
            role: ContactRole::Affected,
            org: "Portal".into(),
            channel: channel.into(),
            address: address.into(),
            source: source.into(),
            confidence: "medium".into(),
            endpoint: Some("portal.example.gov".into()),
        };
        let src = "https://portal.example.gov/.well-known/security.txt";
        assert!(add_contact(&mut c, input("a@portal.example.gov", "email", "nope"), "d").is_err());
        assert!(add_contact(&mut c, input("https://x.example/f", "email", src), "d").is_err());
        add_contact(&mut c, input("a@portal.example.gov", "email", src), "d").unwrap();
        assert!(add_contact(&mut c, input("A@portal.example.gov", "email", src), "d").is_err());
        assert!(no_contact(&mut c, "portal.example.gov", "rdap", 1_791_000_000).is_err());
        remove_contact(&mut c, "a@portal.example.gov", "d").unwrap();
        no_contact(&mut c, "portal.example.gov", "rdap", 1_791_000_000).unwrap();
        assert!(no_contact(&mut c, "elsewhere.example", "rdap", 1_791_000_000).is_err());
    }

    #[test]
    fn scope_findings_need_their_tests() {
        use sc_core::scope::ScopeFinding as F;
        let mut c = case();
        let t = |s: &str| vec![s.to_string()];
        assert!(scope(&mut c, "k-1", F::ScopeExceeded, &[], "n", "d").is_err());
        assert!(scope(&mut c, "k-1", F::ScopeExceeded, &t("S9"), "n", "d").is_err());
        assert!(scope(&mut c, "k-1", F::InScope, &t("S2"), "n", "d").is_err());
        assert!(scope(&mut c, "k-1", F::ScopeExceeded, &t("S4"), " ", "d").is_err());
        scope(
            &mut c,
            "k-1",
            F::ScopeExceeded,
            &t("s4, S2,S4"),
            "relays",
            "d",
        )
        .unwrap();
        assert_eq!(c.scope_finding("k-1").unwrap().tests, ["S2", "S4"]);
        scope(&mut c, "k-1", F::NotAssessable, &[], "too few records", "d").unwrap();
        assert_eq!(c.scope_finding("k-1").unwrap().finding, F::NotAssessable);
        assert_eq!(c.scope_findings.len(), 2, "both stay on record");
    }

    #[test]
    fn settings_lengthen_the_naming_lead_and_name_the_admin() {
        let mut c = case();
        let s = |n| Settings {
            naming_days: Some(n),
            ..Default::default()
        };
        assert!(set(&mut c, s(2), "d").is_err());
        set(&mut c, s(7), "d").unwrap();
        assert_eq!(c.naming_days, Some(7));
        set(
            &mut c,
            Settings {
                admin: Some(" Ada ".into()),
                ..Default::default()
            },
            "d",
        )
        .unwrap();
        assert_eq!(c.admin.as_deref(), Some("Ada"));
        assert!(describe(&mut c, &["nope.example".into()], "a portal", "d").is_err());
        describe(
            &mut c,
            &["portal.example.gov".into()],
            "a government portal",
            "d",
        )
        .unwrap();
        assert_eq!(
            c.endpoints[0].sector.as_deref(),
            Some("a government portal")
        );
    }

    #[test]
    fn grades_need_a_note() {
        let mut c = case();
        assert!(grade(&mut c, AgentLevel::Documented, Some(" "), "d").is_err());
        grade(&mut c, AgentLevel::Documented, Some("ticket"), "d").unwrap();
        assert!(
            c.decisions
                .last()
                .unwrap()
                .text
                .starts_with("agent grade: L5")
        );
        clear_grade(&mut c, "d").unwrap();
        assert!(clear_grade(&mut c, "d").is_err());
    }
}
