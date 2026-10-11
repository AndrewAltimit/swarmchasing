//! Lead time: how long after its report each party has before the indicator
//! notice may be added (docs/policies.md, SC-FM 10.2).
//!
//! The indicator notice names no affected organisation or host, so the
//! clock is short: the AI provider and the operators of targeted and
//! historical endpoints get none beyond their report going first, operators
//! of compromised endpoints 24 hours. Each party's clock runs from the
//! latest recorded send to it. Nothing a recipient says lengthens it, and
//! nothing shortens it: the tool has no override. A party no contact was
//! found for (`case no-contact`) has no clock, and the notice says contact
//! was attempted. Names wait longer, on the naming clock ([`crate::naming`]).

use crate::model::{Case, Contact, ContactRole, EndpointState, parse_time, show_time};
use crate::naming;

/// The AI provider's lead time, in hours.
pub const PROVIDER: u32 = 0;
/// The lead for targeted and historical endpoints' operators, in hours: the
/// report reaches them before the indicator notice does.
pub const OPERATOR: u32 = 0;
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
    /// For an operator: its endpoint's host and state.
    pub host: Option<String>,
    pub state: Option<EndpointState>,
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

/// A party's lead for an endpoint in `state`, if its operator is a party.
pub fn endpoint_lead(state: EndpointState) -> Option<u32> {
    match state {
        EndpointState::Compromised => Some(COMPROMISED),
        EndpointState::Targeted | EndpointState::Historical => Some(OPERATOR),
        EndpointState::Unreviewed | EndpointState::NotAffected => None,
    }
}

fn same(a: &str, b: &str) -> bool {
    a.trim().eq_ignore_ascii_case(b.trim())
}

/// The latest send whose recipient is one of `contacts` (by address or
/// organisation).
fn latest_send<'a>(c: &Case, contacts: impl Iterator<Item = &'a Contact> + Clone) -> Option<i64> {
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
        .filter_map(|n| parse_time(&n.at))
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
        .filter(|x| x.role == ContactRole::Provider)
        .map(|x| x.org.as_str())
        .collect();
    orgs.sort_by_key(|o| o.to_ascii_lowercase());
    orgs.dedup_by(|a, b| same(a, b));
    for org in &orgs {
        let contacts = c
            .contacts
            .iter()
            .filter(|x| x.role == ContactRole::Provider && same(&x.org, org));
        out.push(Party {
            name: format!("provider {org}"),
            provider: true,
            host: None,
            state: None,
            lead_hours: PROVIDER,
            sent: latest_send(c, contacts),
            no_contact: no_contact(c, org),
        });
    }
    if orgs.is_empty() {
        out.push(Party {
            name: "the AI provider (no provider contact in the case)".into(),
            provider: true,
            host: None,
            state: None,
            lead_hours: PROVIDER,
            sent: None,
            no_contact: no_contact(c, ANY_PROVIDER),
        });
    }
    for e in &c.endpoints {
        let Some(lead) = endpoint_lead(e.state) else {
            continue;
        };
        let contacts = c
            .contacts
            .iter()
            .filter(|x| x.role != ContactRole::Provider && x.is_for(&e.host));
        out.push(Party {
            name: format!(
                "operator of {} ({})",
                sc_core::defang_host(&e.host),
                e.state.label()
            ),
            provider: false,
            host: Some(e.host.clone()),
            state: Some(e.state),
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

/// When the indicator notice is scheduled, as a report draft states it:
/// each party's lead from its latest send, or from `now` for a party not
/// sent to yet.
pub fn scheduled(c: &Case, now: i64) -> i64 {
    parties(c)
        .iter()
        .filter(|p| p.no_contact.is_none() || p.sent.is_some())
        .map(|p| p.sent.unwrap_or(now) + i64::from(p.lead_hours) * 3600)
        .max()
        .unwrap_or(now)
        .max(now)
}

/// The indicator notice's lead times in one line.
pub fn summary() -> String {
    format!(
        "the AI provider {PROVIDER} h, operators of targeted and historical endpoints {OPERATOR} h, operators of compromised endpoints {COMPROMISED} h"
    )
}

/// The "Publication" section of a report draft: when the indicator notice
/// is scheduled, that it will not name or locate the recipient, from when
/// an operator may be named and how to consent to earlier naming, that the
/// times are fixed, and that a statement is appended verbatim. `to` is the
/// recipient; for an endpoint's operator the section gives its own naming
/// time, counted from now when no report to it is recorded yet.
pub fn publication_section(c: &Case, to: Option<&Contact>, now: i64) -> String {
    let lead = |state| naming::days(c, state);
    let own = to
        .filter(|x| x.role.for_endpoint())
        .and_then(|x| x.endpoint.as_deref())
        .and_then(|h| c.endpoint(h))
        .filter(|e| e.state.affected())
        .map(|e| {
            let from = parties(c)
                .into_iter()
                .find(|p| p.host.as_deref() == Some(e.host.as_str()))
                .and_then(|p| p.recorded())
                .unwrap_or(now);
            format!(
                "You may be named, with your host, in a later dated update from **{}** ({} working days, Monday to Friday UTC, after this report), not before.",
                show_time(naming::working_days_after(from, lead(e.state))),
                lead(e.state)
            )
        })
        .unwrap_or_else(|| {
            format!(
                "Affected operators may be named, with their hosts, in a later dated update: no earlier than {} working days (Monday to Friday, UTC) after the report to each, {} for an operator whose systems were compromised.",
                lead(EndpointState::Targeted),
                lead(EndpointState::Compromised)
            )
        });
    format!(
        "## Publication\n\n\
         A public notice on this incident is published in two stages.\n\n\
         1. **Indicators**, not before **{}**: what the activity was and how to recognise it. This stage will not name or locate you or any other affected organisation; it describes targets by kind only (for example \"a government data portal\"). The time is fixed by our disclosure policy's lead times ({}, each counted from the report's send); nothing in a reply moves it.\n\
         2. **Names**: {own} If you agree to be named earlier, tell us so in writing (a reply to this report is enough); your name may then go in the next update. That is the only thing that shortens the wait. A request to wait longer is recorded and considered, but does not bind us.\n\n\
         This is not an embargo: no condition is attached to it and it is not negotiated. \
         A second reviewer checks each stage before it is published. \
         If you send a statement for the notice, it is appended verbatim as a dated update (SC-FM 10.5). The notice withholds callback channels, credentials and the attack details of compromised endpoints.\n",
        show_time(scheduled(c, now)),
        summary(),
    )
}

/// `case status`'s lead-time block for the indicator notice.
pub fn show(c: &Case, now: i64, out: &mut impl std::io::Write) -> std::io::Result<()> {
    let k = clock(c);
    writeln!(
        out,
        "\nStage 1, indicator notice: lead time ({})",
        summary()
    )?;
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
pub(crate) mod tests {
    use super::*;
    use crate::model::*;

    /// Wednesday 2026-10-07, 10:00 UTC.
    pub const T0: i64 = 1_791_367_200;

    pub fn case() -> Case {
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
            (
                "Example AI",
                ContactRole::Provider,
                None,
                "security@ai.example",
            ),
            (
                "Example AI",
                ContactRole::Provider,
                None,
                "abuse@ai.example",
            ),
            (
                "A",
                ContactRole::Affected,
                Some("a.example.org"),
                "security@a.example.org",
            ),
            (
                "B",
                ContactRole::Registrar,
                Some("b.example.org"),
                "abuse@reg.example",
            ),
        ] {
            c.contacts.push(Contact {
                org: org.into(),
                role,
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

    pub fn send(c: &mut Case, to: &str, at: i64) {
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
        // A targeted endpoint's operator only needs its report first.
        c.endpoints[1].state = EndpointState::Targeted;
        assert_eq!(clock(&c).not_before, Some(T0 + 600));
        // A later send restarts that party's clock.
        send(&mut c, "A", T0 + 30 * 3600);
        assert_eq!(clock(&c).not_before, Some(T0 + 30 * 3600));
    }

    #[test]
    fn a_party_with_no_contact_has_no_clock() {
        let mut c = case();
        c.contacts.retain(|x| x.role != ContactRole::Provider);
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
        assert_eq!(clock(&c).not_before, Some(T0));
        // A draft made before the sends states the full lead from now.
        assert_eq!(scheduled(&case(), T0), T0 + 24 * 3600);
        let p = publication_section(&case(), None, T0);
        assert!(p.contains("not an embargo"), "{p}");
        assert!(p.contains("no earlier than 3 working days"), "{p}");
        assert!(p.contains("10 for an operator"), "{p}");
        assert!(p.contains("will not name or locate you"), "{p}");
        // An operator's report gives its own naming time.
        let c = case();
        let p = publication_section(&c, Some(&c.contacts[2]), T0);
        assert!(
            p.contains("from **2026-10-12 10:00 UTC** (3 working days"),
            "{p}"
        );
        let p = publication_section(&c, Some(&c.contacts[3]), T0);
        assert!(p.contains("(10 working days"), "{p}");
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
