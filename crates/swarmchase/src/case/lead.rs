//! Lead time: how long after its report each party has before the public
//! notice may be added (docs/policies.md, SC-FM 10.2).
//!
//! The AI provider gets none: its report and the notice may go the same
//! hour. Operators of targeted and historical endpoints get 4 to 12 hours
//! (6 unless the admin sets the case otherwise), operators of compromised
//! endpoints 24. Each party's clock runs from the latest recorded send to
//! it. Nothing a recipient says lengthens it, and nothing shortens it: the
//! tool has no override. A party no contact was found for (`case
//! no-contact`) has no clock, and the notice says contact was attempted.

use super::model::{Case, EndpointState, show_time};
use anyhow::{Result, bail};

/// The AI provider's lead time, in hours.
pub const PROVIDER: u32 = 0;
/// The bounds and default of the lead for targeted and historical
/// endpoints' operators, in hours.
pub const OPERATOR_MIN: u32 = 4;
pub const OPERATOR_MAX: u32 = 12;
pub const OPERATOR_DEFAULT: u32 = 6;
/// The lead for compromised endpoints' operators, in hours.
pub const COMPROMISED: u32 = 24;

/// The provider party named in `case no-contact` when the case has no
/// provider contact at all.
pub const ANY_PROVIDER: &str = "provider";

/// One party the reports go to, and where its clock stands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Party {
    /// `provider Example AI`, `operator of portal[.]example[.]gov (targeted)`.
    pub name: String,
    pub provider: bool,
    pub lead_hours: u32,
    /// The latest recorded send to it.
    pub sent: Option<i64>,
    /// When the admin recorded that no contact was found.
    pub no_contact: Option<i64>,
}

impl Party {
    /// When the notice may be added as far as this party goes; `None` while
    /// nothing was sent to it and no missing contact is recorded.
    pub fn not_before(&self) -> Option<i64> {
        match (self.sent, self.no_contact) {
            (Some(t), _) => Some(t + i64::from(self.lead_hours) * 3600),
            (None, Some(_)) => Some(0),
            (None, None) => None,
        }
    }

    /// The latest time anything was recorded for it.
    pub fn recorded(&self) -> Option<i64> {
        self.sent.max(self.no_contact)
    }
}

/// Every party's clock, and the earliest time the notice may be added.
#[derive(Debug, Clone)]
pub struct Clock {
    pub parties: Vec<Party>,
    /// Parties with neither a send nor a missing-contact record.
    pub missing: Vec<String>,
    /// `None` while anything is missing.
    pub not_before: Option<i64>,
}

/// The lead for targeted and historical endpoints' operators.
pub fn operator_lead(c: &Case) -> u32 {
    c.lead_hours.unwrap_or(OPERATOR_DEFAULT)
}

/// Set the operator lead, within its bounds.
pub fn set_operator_lead(c: &mut Case, hours: u32, today: &str) -> Result<()> {
    if !(OPERATOR_MIN..=OPERATOR_MAX).contains(&hours) {
        bail!(
            "the lead time for targeted endpoints' operators is {OPERATOR_MIN} to {OPERATOR_MAX} hours; it cannot be set to {hours}"
        );
    }
    c.lead_hours = Some(hours);
    c.log(
        today,
        format!("lead time for targeted and historical endpoints' operators: {hours} h"),
    );
    Ok(())
}

/// A party's lead for an endpoint in `state`, if its operator is a party.
pub fn endpoint_lead(c: &Case, state: EndpointState) -> Option<u32> {
    match state {
        EndpointState::Compromised => Some(COMPROMISED),
        EndpointState::Targeted | EndpointState::Historical => Some(operator_lead(c)),
        EndpointState::Unreviewed | EndpointState::NotAffected => None,
    }
}

fn same(a: &str, b: &str) -> bool {
    a.trim().eq_ignore_ascii_case(b.trim())
}

/// The latest send whose recipient is one of `contacts` (by address or
/// organisation).
fn latest_send<'a>(
    c: &Case,
    contacts: impl Iterator<Item = &'a super::Contact> + Clone,
) -> Option<i64> {
    c.sent
        .iter()
        .filter(|s| {
            contacts
                .clone()
                .any(|x| same(&x.address, &s.recipient) || same(&x.org, &s.recipient))
        })
        .filter_map(|s| s.time())
        .max()
}

fn no_contact(c: &Case, party: &str) -> Option<i64> {
    c.no_contact
        .iter()
        .filter(|n| same(&n.party, party))
        .filter_map(|n| super::model::parse_time(&n.at))
        .max()
}

/// The parties of case `c`: each provider organisation among its contacts
/// (or one unnamed provider when it has none), and the operator of each
/// endpoint classified compromised, targeted or historical.
pub fn parties(c: &Case) -> Vec<Party> {
    let mut out = Vec::new();
    let mut orgs: Vec<&str> = c
        .contacts
        .iter()
        .filter(|x| x.role == "provider")
        .map(|x| x.org.as_str())
        .collect();
    orgs.sort_by_key(|o| o.to_ascii_lowercase());
    orgs.dedup_by(|a, b| same(a, b));
    for org in &orgs {
        let contacts = c
            .contacts
            .iter()
            .filter(|x| x.role == "provider" && same(&x.org, org));
        out.push(Party {
            name: format!("provider {org}"),
            provider: true,
            lead_hours: PROVIDER,
            sent: latest_send(c, contacts),
            no_contact: no_contact(c, org),
        });
    }
    if orgs.is_empty() {
        out.push(Party {
            name: "the AI provider (no provider contact in the case)".into(),
            provider: true,
            lead_hours: PROVIDER,
            sent: None,
            no_contact: no_contact(c, ANY_PROVIDER),
        });
    }
    for e in &c.endpoints {
        let Some(lead) = endpoint_lead(c, e.state) else {
            continue;
        };
        let contacts = c.contacts.iter().filter(|x| {
            x.role != "provider"
                && x.endpoint
                    .as_deref()
                    .is_some_and(|h| h.eq_ignore_ascii_case(&e.host))
        });
        out.push(Party {
            name: format!(
                "operator of {} ({})",
                sc_core::defang_host(&e.host),
                e.state.label()
            ),
            provider: false,
            lead_hours: lead,
            sent: latest_send(c, contacts),
            no_contact: no_contact(c, &e.host),
        });
    }
    out
}

pub fn clock(c: &Case) -> Clock {
    let parties = parties(c);
    let missing: Vec<String> = parties
        .iter()
        .filter(|p| p.not_before().is_none())
        .map(|p| p.name.clone())
        .collect();
    let not_before = if missing.is_empty() {
        parties.iter().filter_map(Party::not_before).max()
    } else {
        None
    };
    Clock {
        parties,
        missing,
        not_before,
    }
}

/// When the notice is scheduled, as a report draft states it: each party's
/// lead from its latest send, or from `now` for a party not sent to yet.
pub fn scheduled(c: &Case, now: i64) -> i64 {
    parties(c)
        .iter()
        .filter(|p| p.no_contact.is_none() || p.sent.is_some())
        .map(|p| p.sent.unwrap_or(now) + i64::from(p.lead_hours) * 3600)
        .max()
        .unwrap_or(now)
        .max(now)
}

/// The lead times of case `c` in one line.
pub fn summary(c: &Case) -> String {
    format!(
        "the AI provider {PROVIDER} h, operators of targeted and historical endpoints {} h, operators of compromised endpoints {COMPROMISED} h",
        operator_lead(c)
    )
}

/// The "Publication" section of a report draft: when the notice is
/// scheduled, that the time is fixed, and that a statement is appended
/// verbatim.
pub fn publication_section(c: &Case, now: i64) -> String {
    format!(
        "## Publication\n\n\
         A public notice on this incident is scheduled for **{}**. The time is fixed by our disclosure policy's lead times ({}, each counted from the report's send); nothing in a reply moves it. \
         This is not an embargo: no condition is attached to it and it is not negotiated. \
         If you send a statement for the notice, it is appended verbatim as a dated update (SC-FM 10.5). The notice withholds callback channels, credentials and the attack details of compromised endpoints.\n",
        show_time(scheduled(c, now)),
        summary(c)
    )
}

/// `case status`'s lead-time block.
pub fn show(c: &Case, now: i64, out: &mut impl std::io::Write) -> std::io::Result<()> {
    let k = clock(c);
    writeln!(out, "\nLead time ({})", summary(c))?;
    for p in &k.parties {
        let state = match (p.sent, p.no_contact) {
            (Some(t), _) => format!(
                "sent {} → notice not before {}",
                show_time(t),
                show_time(t + i64::from(p.lead_hours) * 3600)
            ),
            (None, Some(t)) => format!("no contact found (recorded {})", show_time(t)),
            (None, None) => "not sent".into(),
        };
        writeln!(out, "  {:<52} {state}", p.name)?;
    }
    match k.not_before {
        Some(t) if t <= now => writeln!(out, "  publish not before: {} (passed)", show_time(t)),
        Some(t) => writeln!(out, "  publish not before: {}", show_time(t)),
        None => writeln!(
            out,
            "  publish not before: unknown until every party is sent its report or recorded as having no contact"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::super::model::*;
    use super::*;

    const T0: i64 = 1_791_000_000;

    fn case() -> Case {
        let mut c: Case = toml::from_str(
            "id = \"t\"\ntitle = \"T\"\nstatus = \"open\"\nnotice = \"active\"\nopened = \"2026-10-12\"\n",
        )
        .unwrap();
        for (h, s) in [
            ("a.example.org", EndpointState::Targeted),
            ("b.example.org", EndpointState::Compromised),
            ("c.example.org", EndpointState::NotAffected),
        ] {
            c.endpoints.push(CaseEndpoint {
                host: h.into(),
                state: s,
                ..Default::default()
            });
        }
        for (org, role, endpoint, address) in [
            ("Example AI", "provider", None, "security@ai.example"),
            ("Example AI", "provider", None, "abuse@ai.example"),
            (
                "A",
                "affected",
                Some("a.example.org"),
                "security@a.example.org",
            ),
            ("B", "registrar", Some("b.example.org"), "abuse@reg.example"),
        ] {
            c.contacts.push(Contact {
                org: org.into(),
                role: role.into(),
                endpoint: endpoint.map(str::to_string),
                channel: "email".into(),
                address: address.into(),
                source: String::new(),
                confidence: "medium".into(),
                found_on: "2026-10-12".into(),
                purpose: None,
            });
        }
        c
    }

    fn send(c: &mut Case, to: &str, at: i64) {
        c.sent.push(Sent {
            date: "2026-10-12".into(),
            recipient: to.into(),
            channel: "email".into(),
            at: Some(rfc3339(at)),
            ..Default::default()
        });
    }

    #[test]
    fn each_party_runs_its_own_clock() {
        let mut c = case();
        let k = clock(&c);
        assert_eq!(k.parties.len(), 3, "{k:?}");
        assert_eq!(k.missing.len(), 3);
        assert_eq!(k.not_before, None);

        send(&mut c, "security@ai.example", T0);
        send(&mut c, "security@a.example.org", T0);
        let k = clock(&c);
        assert_eq!(
            k.missing,
            vec!["operator of b[.]example[.]org (compromised)"]
        );
        // A compromised endpoint's operator gets 24 hours.
        send(&mut c, "abuse@reg.example", T0 + 600);
        assert_eq!(clock(&c).not_before, Some(T0 + 600 + 24 * 3600));
        // A later send restarts that party's clock.
        send(&mut c, "A", T0 + 30 * 3600);
        assert_eq!(clock(&c).not_before, Some(T0 + 36 * 3600));
    }

    #[test]
    fn the_operator_lead_is_bounded() {
        let mut c = case();
        assert_eq!(operator_lead(&c), OPERATOR_DEFAULT);
        for bad in [0, 3, 13, 48] {
            assert!(set_operator_lead(&mut c, bad, "d").is_err(), "{bad}");
        }
        set_operator_lead(&mut c, 12, "d").unwrap();
        c.endpoints[1].state = EndpointState::Historical;
        send(&mut c, "abuse@ai.example", T0);
        send(&mut c, "security@a.example.org", T0);
        send(&mut c, "abuse@reg.example", T0);
        assert_eq!(clock(&c).not_before, Some(T0 + 12 * 3600));
    }

    #[test]
    fn a_party_with_no_contact_has_no_clock() {
        let mut c = case();
        c.contacts.retain(|x| x.role != "provider");
        send(&mut c, "security@a.example.org", T0);
        c.endpoints[1].state = EndpointState::Targeted;
        c.no_contact.push(NoContact {
            party: "b.example.org".into(),
            searched: "security.txt, RDAP".into(),
            at: rfc3339(T0),
        });
        let k = clock(&c);
        assert_eq!(k.missing.len(), 1, "no provider contact: {k:?}");
        c.no_contact.push(NoContact {
            party: ANY_PROVIDER.into(),
            searched: "self-identified vendor unknown".into(),
            at: rfc3339(T0),
        });
        assert_eq!(clock(&c).not_before, Some(T0 + 6 * 3600));
        // A draft made before the sends states the full lead from now.
        assert_eq!(scheduled(&case(), T0), T0 + 24 * 3600);
        assert!(publication_section(&case(), T0).contains("not an embargo"));
    }

    #[test]
    fn a_date_only_send_counts_from_the_end_of_its_day() {
        let s = Sent {
            date: "2026-10-12".into(),
            ..Default::default()
        };
        assert_eq!(s.time(), parse_time("2026-10-12T23:59:59Z"));
    }
}
