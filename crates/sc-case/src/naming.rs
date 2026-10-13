//! The naming clock: when an affected organisation's name and host may be
//! added to a published indicator notice (docs/policies.md, SC-FM 10.2).
//!
//! The indicator notice names no affected party ([`crate::lead`]); names
//! follow in dated naming updates, per operator. Each operator's clock runs
//! in UTC working days (Monday to Friday) from the latest report to it, or
//! from the recorded missing contact: 3 working days for a targeted or
//! historical endpoint's operator, 10 for a compromised one's. The admin may
//! lengthen it per case (3 to 20; compromised stays at least 10) and never
//! shorten it. An operator's written consent is the only thing that lets it
//! be named sooner. The admin may also decide never to name an operator,
//! with a logged reason.
//!
//! This module also holds the naming draft (`naming.md`) and the check that
//! a text identifies no affected party it may not name.

use crate::checklist::org_of;
use crate::lead;
use crate::model::*;
use crate::{Result, bail};
use serde::{Deserialize, Serialize};

/// The naming lead for targeted and historical endpoints' operators, and
/// the least the admin may set, in working days.
pub const MIN_DAYS: u32 = 3;
/// The most the admin may set, in working days.
pub const MAX_DAYS: u32 = 20;
/// The least naming lead for compromised endpoints' operators.
pub const COMPROMISED_DAYS: u32 = 10;

const DAY: i64 = 86_400;

/// Saturday or Sunday, UTC.
fn weekend(ts: i64) -> bool {
    // 1970-01-01 was a Thursday: Monday is 0, Saturday 5, Sunday 6.
    (ts.div_euclid(DAY) + 3).rem_euclid(7) >= 5
}

/// The time `n` UTC working days after `t`. A time on a weekend counts from
/// the following Monday 00:00 UTC; the clock ends at the same time of day
/// once `n` weekdays have passed.
pub fn working_days_after(t: i64, n: u32) -> i64 {
    let mut at = t;
    if weekend(at) {
        at = at.div_euclid(DAY) * DAY;
        while weekend(at) {
            at += DAY;
        }
    }
    let mut left = n;
    while left > 0 {
        at += DAY;
        if !weekend(at) {
            left -= 1;
        }
    }
    at
}

/// The naming lead for an endpoint in `state`, in working days.
pub fn days(c: &Case, state: EndpointState) -> u32 {
    let n = c.naming_days.unwrap_or(MIN_DAYS).clamp(MIN_DAYS, MAX_DAYS);
    match state {
        EndpointState::Compromised => n.max(COMPROMISED_DAYS),
        _ => n,
    }
}

/// Lengthen the naming lead for the case (`case set --naming-days`).
pub fn set_days(c: &mut Case, n: u32, today: &str) -> Result<()> {
    if !(MIN_DAYS..=MAX_DAYS).contains(&n) {
        bail!(
            "the naming lead is {MIN_DAYS} to {MAX_DAYS} working days; it cannot be set to {n} (it is never shorter than {MIN_DAYS})"
        );
    }
    c.naming_days = Some(n);
    c.log(
        today,
        format!(
            "naming lead: {n} working days for targeted and historical endpoints' operators, {} for compromised",
            n.max(COMPROMISED_DAYS)
        ),
    );
    Ok(())
}

/// One affected operator and where its naming stands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Operator {
    pub host: String,
    pub state: EndpointState,
    /// Its naming lead, in working days.
    pub days: u32,
    /// The latest report to it, or the recorded missing contact.
    pub from: Option<i64>,
    /// When its name may be published without consent.
    pub not_before: Option<i64>,
    /// When it consented in writing to earlier naming.
    pub consent: Option<i64>,
    /// Why the admin decided not to name it.
    pub withheld: Option<String>,
    /// When a published naming update named it.
    pub named: Option<String>,
}

impl Operator {
    /// Whether a naming update may name it at `now`.
    pub fn may_name(&self, now: i64) -> bool {
        self.named.is_none()
            && self.withheld.is_none()
            && (self.consent.is_some() || self.not_before.is_some_and(|t| t <= now))
    }

    /// Where it stands, in a few words.
    pub fn status(&self, now: i64) -> String {
        if let Some(d) = &self.named {
            return format!("named {d}");
        }
        if let Some(r) = &self.withheld {
            return format!("not to be named ({r})");
        }
        if let Some(t) = self.consent {
            return format!("may be named now (consented {})", show_time(t));
        }
        match (self.from, self.not_before) {
            (Some(f), Some(t)) if t <= now => format!(
                "reported {} → may be named from {} (passed)",
                show_time(f),
                show_time(t)
            ),
            (Some(f), Some(t)) => format!(
                "reported {} → may be named from {}",
                show_time(f),
                show_time(t)
            ),
            _ => "not reported yet: no naming clock".into(),
        }
    }
}

fn same(a: &str, b: &str) -> bool {
    a.trim().eq_ignore_ascii_case(b.trim())
}

/// Every affected operator of case `c` and its naming clock.
pub fn operators(c: &Case) -> Vec<Operator> {
    lead::parties(c)
        .into_iter()
        .filter_map(|p| {
            let (host, state) = (p.host.clone()?, p.state?);
            let days = days(c, state);
            let from = p.recorded();
            Some(Operator {
                not_before: from.map(|t| working_days_after(t, days)),
                consent: c
                    .consents
                    .iter()
                    .filter(|x| same(&x.party, &host))
                    .filter_map(|x| parse_time(&x.at))
                    .max(),
                withheld: c
                    .naming_withheld
                    .iter()
                    .rev()
                    .find(|x| same(&x.party, &host))
                    .map(|x| x.reason.clone()),
                named: c
                    .named
                    .iter()
                    .find(|x| same(&x.party, &host))
                    .map(|x| x.date.clone()),
                host,
                state,
                days,
                from,
            })
        })
        .collect()
}

/// The hosts a naming update may name at `now`.
pub fn ready(c: &Case, now: i64) -> Vec<String> {
    operators(c)
        .into_iter()
        .filter(|o| o.may_name(now))
        .map(|o| o.host)
        .collect()
}

/// The affected endpoint `party` names: its host, or the organisation of
/// the operator contact listed for it.
fn affected_endpoint<'a>(c: &'a Case, party: &str) -> Result<&'a CaseEndpoint> {
    let by_org = || {
        let hosts: Vec<&str> = c
            .contacts_in(ContactRole::Affected)
            .filter(|x| same(&x.org, party))
            .filter_map(|x| x.endpoint.as_deref())
            .collect();
        match hosts[..] {
            [one] => c.endpoint(one),
            _ => None,
        }
    };
    match c.endpoint(party).or_else(by_org) {
        Some(e) if e.state.affected() => Ok(e),
        Some(e) => bail!(
            "{} is classified {}; only an affected endpoint's operator is named",
            party,
            e.state.label()
        ),
        None => bail!(
            "no endpoint `{party}` in case {}{}",
            c.id,
            crate::text::did_you_mean(party, c.endpoints.iter().map(|e| e.host.as_str()))
        ),
    }
}

/// Record an operator's written consent to be named before its clock runs
/// (`case consent`).
pub fn consent(c: &mut Case, party: &str, note: &str, now: i64) -> Result<()> {
    let host = affected_endpoint(c, party)?.host.clone();
    if note.trim().is_empty() {
        bail!("--note: what the operator said in writing, and where it is kept");
    }
    c.consents.push(Consent {
        party: host.clone(),
        note: note.to_string(),
        at: rfc3339(now),
    });
    let today = crate::text::date_of(now);
    c.log(
        &today,
        format!("consent to earlier naming from the operator of {host}: {note}"),
    );
    Ok(())
}

/// Decide not to name an operator (`case naming --withhold`).
pub fn withhold(c: &mut Case, party: &str, reason: &str, today: &str) -> Result<()> {
    let host = affected_endpoint(c, party)?.host.clone();
    if reason.trim().is_empty() {
        bail!("--reason: why this operator is not to be named");
    }
    if c.named.iter().any(|x| same(&x.party, &host)) {
        bail!("the operator of {host} is already named in the published notice");
    }
    c.naming_withheld.push(NamingWithheld {
        party: host.clone(),
        reason: reason.to_string(),
        date: today.to_string(),
    });
    c.log(
        today,
        format!("the operator of {host} is not to be named: {reason}"),
    );
    Ok(())
}

/// Record that a published naming update named `hosts`.
pub fn mark_named(c: &mut Case, hosts: &[String], today: &str) {
    for h in hosts {
        if !c.named.iter().any(|x| same(&x.party, h)) {
            c.named.push(Named {
                party: h.clone(),
                date: today.to_string(),
            });
        }
    }
    c.log(
        today,
        format!(
            "naming update added: {}",
            hosts
                .iter()
                .map(|h| sc_core::defang_host(h))
                .collect::<Vec<_>>()
                .join(", ")
        ),
    );
}

/// The naming clocks in one line.
pub fn summary(c: &Case) -> String {
    format!(
        "{} working days for targeted and historical endpoints' operators, {} for compromised, Monday to Friday UTC",
        days(c, EndpointState::Targeted),
        days(c, EndpointState::Compromised)
    )
}

/// `case status`'s naming block.
pub fn show(c: &Case, now: i64, out: &mut impl std::io::Write) -> std::io::Result<()> {
    writeln!(out, "\nStage 2, naming ({})", summary(c))?;
    let ops = operators(c);
    if ops.is_empty() {
        writeln!(out, "  no affected operator")?;
    }
    for o in &ops {
        writeln!(
            out,
            "  {:<52} {}",
            format!(
                "operator of {} ({})",
                sc_core::defang_host(&o.host),
                o.state.label()
            ),
            o.status(now)
        )?;
    }
    Ok(())
}

/// The naming draft (`naming.md`): which hosts it names, then the update's
/// text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NamingDraft {
    pub hosts: Vec<String>,
    #[serde(skip)]
    pub text: String,
}

const FENCE: &str = "+++";

impl NamingDraft {
    pub fn parse(text: &str) -> Result<NamingDraft> {
        let text = text.strip_prefix('\u{feff}').unwrap_or(text);
        let Some(rest) = text
            .strip_prefix(FENCE)
            .and_then(|r| r.strip_prefix('\n').or_else(|| r.strip_prefix("\r\n")))
        else {
            bail!("a naming draft starts with `+++` front matter listing `hosts`");
        };
        let Some(end) = rest.find("\n+++") else {
            bail!("the naming draft's front matter is not closed with `+++`");
        };
        let mut d: NamingDraft =
            toml::from_str(&rest[..end]).map_err(|e| crate::Error(format!("naming draft: {e}")))?;
        d.text = rest[end + 4..].trim().to_string();
        if d.hosts.is_empty() {
            bail!("the naming draft names no host");
        }
        if d.text.is_empty() {
            bail!("the naming draft has no text");
        }
        Ok(d)
    }

    pub fn write(&self) -> String {
        let meta = toml::to_string_pretty(self).unwrap_or_default();
        format!("{FENCE}\n{meta}{FENCE}\n\n{}\n", self.text.trim_end())
    }
}

/// How a naming update states one operator: its organisation and defanged
/// host, and what happened to it in the words the naming rules allow
/// ("compromised" only with a recorded basis, the fixed wording for an
/// endpoint seen only in submit-anywhere records).
pub fn line(c: &Case, host: &str, single_source: bool) -> String {
    let org = org_of(c, host);
    let h = sc_core::defang_host(host);
    let who = if org == h {
        format!("`{h}`")
    } else {
        format!("{org} (`{h}`)")
    };
    let e = c.endpoint(host);
    let what = match e.map(|e| e.state) {
        Some(EndpointState::Compromised)
            if e.and_then(|e| e.basis.as_deref())
                .is_some_and(|b| !b.trim().is_empty()) =>
        {
            "was affected: its systems were compromised"
        }
        Some(EndpointState::Historical) => "was targeted earlier in the window",
        Some(EndpointState::Compromised) => "was affected",
        _ => "was targeted",
    };
    let mut s = format!("{who} {what}.");
    if single_source {
        s += &format!(" {}", crate::checklist::single_source_line(c, host));
    }
    s
}

/// A naming draft for the operators `hosts`, in order. `single_source` are
/// the hosts every record of which is submit-anywhere.
pub fn draft(c: &Case, hosts: &[String], single_source: &[String]) -> NamingDraft {
    let lines: Vec<String> = hosts
        .iter()
        .map(|h| {
            line(
                c,
                h,
                single_source.iter().any(|s| s.eq_ignore_ascii_case(h)),
            )
        })
        .collect();
    NamingDraft {
        hosts: hosts.to_vec(),
        text: format!(
            "Affected organisations named. The activity this notice describes reached the following organisations' systems. {}",
            lines.join(" ")
        ),
    }
}

/// The registrable-looking part of a host: its last two labels, or three
/// under a two-letter country code with a short second level (`co.uk`).
fn registrable(host: &str) -> Option<String> {
    let labels: Vec<&str> = host.split('.').filter(|l| !l.is_empty()).collect();
    if labels.len() < 2 || labels.iter().all(|l| l.chars().all(|c| c.is_ascii_digit())) {
        return None;
    }
    let n = labels.len();
    let take = if n >= 3 && labels[n - 1].len() == 2 && labels[n - 2].len() <= 3 {
        3
    } else {
        2
    };
    Some(labels[n.saturating_sub(take)..].join("."))
}

/// Whether `needle` appears in `hay` as a whole host or domain (not inside
/// a longer label).
fn has_host(hay: &str, needle: &str) -> bool {
    let edge = |c: Option<char>| c.is_none_or(|c| !(c.is_ascii_alphanumeric() || c == '-'));
    hay.match_indices(needle)
        .any(|(i, m)| edge(hay[..i].chars().next_back()) && edge(hay[i + m.len()..].chars().next()))
}

/// What in `text` identifies an affected party the text may not name:
/// the host of any affected endpoint not in `allowed`, defanged or not,
/// its registrable domain, or its operator's organisation name. One line
/// per party, naming the defanged host (for the admin, never published).
pub fn identifies(c: &Case, text: &str, allowed: &[String]) -> Vec<String> {
    let plain = text
        .replace("hxxp", "http")
        .replace("[.]", ".")
        .replace("[:]", ":")
        .to_ascii_lowercase();
    // Hosts that may appear (named ones, endpoints not affected) do not
    // count toward a shared domain.
    let mut known = plain.clone();
    let mut may: Vec<String> = c
        .endpoints
        .iter()
        .filter(|e| !e.state.affected())
        .map(|e| e.host.to_ascii_lowercase())
        .chain(allowed.iter().map(|h| h.to_ascii_lowercase()))
        .collect();
    may.sort_by_key(|h| std::cmp::Reverse(h.len()));
    for h in &may {
        known = known.replace(h.as_str(), " ");
    }
    let mut out = Vec::new();
    for e in c.endpoints.iter().filter(|e| e.state.affected()) {
        if allowed.iter().any(|h| same(h, &e.host)) {
            continue;
        }
        let host = e.host.to_ascii_lowercase();
        let d = sc_core::defang_host(&e.host);
        let mut what = Vec::new();
        if has_host(&plain, &host) {
            what.push("its host".to_string());
        } else if let Some(r) = registrable(&host)
            && has_host(&known, &r)
        {
            what.push(format!("its domain `{}`", sc_core::defang_host(&r)));
        }
        for x in c
            .contacts_in(ContactRole::Affected)
            .filter(|x| x.is_for(&e.host))
        {
            let org = x.org.trim();
            let hostlike = org.contains('.') && !org.contains(' ');
            // Names of two letters or fewer read as ordinary words.
            if !hostlike && org.chars().count() > 2 && crate::notice::wording::names(text, org) {
                what.push(format!("its organisation `{org}`"));
            }
        }
        what.dedup();
        if !what.is_empty() {
            out.push(format!(
                "names the operator of {d} ({}), which may not be named here",
                what.join(", ")
            ));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lead::tests::{T0, case, send};

    const H: i64 = 3600;

    fn at(s: &str) -> i64 {
        parse_time(s).unwrap()
    }

    #[test]
    fn working_days_skip_weekends() {
        // Wednesday 10:00 + 3 → Monday 10:00.
        assert_eq!(T0, at("2026-10-07T10:00:00Z"));
        assert_eq!(working_days_after(T0, 3), at("2026-10-12T10:00:00Z"));
        // Friday 15:00 + 3 → Wednesday 15:00.
        let fri = at("2026-10-09T15:00:00Z");
        assert_eq!(working_days_after(fri, 3), at("2026-10-14T15:00:00Z"));
        // A Saturday send counts from Monday 00:00.
        let sat = at("2026-10-10T18:30:00Z");
        assert_eq!(working_days_after(sat, 3), at("2026-10-15T00:00:00Z"));
        let sun = at("2026-10-11T23:59:59Z");
        assert_eq!(working_days_after(sun, 3), at("2026-10-15T00:00:00Z"));
        // Ten working days is two calendar weeks from a weekday.
        assert_eq!(working_days_after(T0, 10), at("2026-10-21T10:00:00Z"));
        assert_eq!(working_days_after(T0, 0), T0);
        assert_eq!(working_days_after(sat, 0), at("2026-10-12T00:00:00Z"));
    }

    #[test]
    fn each_operator_runs_its_naming_clock() {
        let mut c = case();
        assert!(ready(&c, T0).is_empty());
        send(&mut c, "security@a.example.org", T0);
        send(&mut c, "abuse@reg.example", T0);
        let ops = operators(&c);
        assert_eq!(ops.len(), 2, "{ops:?}");
        assert_eq!(ops[0].not_before, Some(at("2026-10-12T10:00:00Z")));
        assert_eq!(ops[1].days, COMPROMISED_DAYS);
        assert_eq!(ops[1].not_before, Some(at("2026-10-21T10:00:00Z")));
        assert!(ready(&c, at("2026-10-12T09:59:00Z")).is_empty());
        assert_eq!(ready(&c, at("2026-10-12T10:00:00Z")), ["a.example.org"]);
        // A later send restarts the clock.
        send(&mut c, "A", at("2026-10-09T15:00:00Z"));
        assert!(ready(&c, at("2026-10-12T10:00:00Z")).is_empty());
        assert_eq!(ready(&c, at("2026-10-14T15:00:00Z")), ["a.example.org"]);
    }

    #[test]
    fn consent_is_the_only_shortcut() {
        let mut c = case();
        send(&mut c, "abuse@reg.example", T0);
        assert!(
            consent(&mut c, "c.example.org", "yes", T0).is_err(),
            "not affected"
        );
        assert!(consent(&mut c, "b.example.org", " ", T0).is_err());
        consent(&mut c, "b.example.org", "e-mail of 2026-10-07", T0 + H).unwrap();
        assert_eq!(ready(&c, T0 + 2 * H), ["b.example.org"]);
        // A consent before any report still lets it be named; the party may
        // be given by its organisation.
        assert!(consent(&mut c, "Nobody", "x", T0).is_err());
        consent(&mut c, "A", "phone note", T0).unwrap();
        assert_eq!(c.consents.last().unwrap().party, "a.example.org");
        assert_eq!(ready(&c, T0 + 2 * H).len(), 2);
        // Withheld, it is not named, consent or not.
        assert!(withhold(&mut c, "a.example.org", "", "d").is_err());
        withhold(&mut c, "a.example.org", "the operator is a hospital", "d").unwrap();
        assert_eq!(ready(&c, T0 + 2 * H), ["b.example.org"]);
        mark_named(&mut c, &["b.example.org".to_string()], "2026-10-08");
        assert!(ready(&c, T0 + 2 * H).is_empty());
        assert!(withhold(&mut c, "b.example.org", "late", "d").is_err());
    }

    #[test]
    fn the_naming_lead_only_lengthens() {
        let mut c = case();
        for bad in [0, 1, 2, 21, 100] {
            assert!(set_days(&mut c, bad, "d").is_err(), "{bad}");
        }
        assert_eq!(days(&c, EndpointState::Targeted), 3);
        assert_eq!(days(&c, EndpointState::Compromised), 10);
        set_days(&mut c, 5, "d").unwrap();
        assert_eq!(days(&c, EndpointState::Historical), 5);
        assert_eq!(days(&c, EndpointState::Compromised), 10);
        set_days(&mut c, 20, "d").unwrap();
        assert_eq!(days(&c, EndpointState::Compromised), 20);
        // A hand-edited case file below the floor still waits the floor.
        c.naming_days = Some(1);
        assert_eq!(days(&c, EndpointState::Targeted), MIN_DAYS);
        send(&mut c, "security@a.example.org", T0);
        assert_eq!(
            operators(&c)[0].not_before,
            Some(at("2026-10-12T10:00:00Z"))
        );
    }

    #[test]
    fn a_text_identifies_an_affected_party() {
        let c = case();
        assert!(identifies(&c, "a government data portal (12 records)", &[]).is_empty());
        let p = identifies(&c, "requests to `a[.]example[.]org` and b.example.org", &[]);
        assert_eq!(p.len(), 2, "{p:?}");
        assert!(p[0].contains("a[.]example[.]org"), "{p:?}");
        // The registrable domain identifies it too; a longer label does not.
        assert_eq!(identifies(&c, "see example.org", &[]).len(), 2);
        assert!(identifies(&c, "see myexample.org.net", &[]).is_empty());
        // The organisation's name, as a whole word.
        let mut c = c;
        c.contacts[2].org = "Acme Water Board".into();
        let p = identifies(&c, "the Acme Water Board portal", &[]);
        assert_eq!(p.len(), 1, "{p:?}");
        // Allowed hosts may be named; the not-affected one never counts.
        assert!(
            identifies(
                &c,
                "c.example.org and a.example.org",
                &["a.example.org".into()]
            )
            .is_empty()
        );
        assert_eq!(
            registrable("x.y.example.co.uk").as_deref(),
            Some("example.co.uk")
        );
        assert_eq!(registrable("10.0.0.1"), None);
    }

    #[test]
    fn a_naming_draft_round_trips() {
        let mut c = case();
        c.endpoints[1].basis = Some("operator statement".into());
        let d = draft(
            &c,
            &["a.example.org".into(), "b.example.org".into()],
            &["a.example.org".into()],
        );
        assert!(
            d.text.contains("A (`a[.]example[.]org`) was targeted."),
            "{}",
            d.text
        );
        assert!(d.text.contains("were compromised"), "{}", d.text);
        assert!(
            d.text.contains("URLs targeting A's hosts were submitted"),
            "{}",
            d.text
        );
        let back = NamingDraft::parse(&d.write()).unwrap();
        assert_eq!(back, d);
        assert!(NamingDraft::parse("no front matter").is_err());
        assert!(NamingDraft::parse("+++\nhosts = []\n+++\n\ntext\n").is_err());
    }
}
