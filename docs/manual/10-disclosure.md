# 10. Disclosure

[Manual index](README.md) · Previous: [9. Evaluation](09-evaluation.md) · Next: [11. Notice standard](11-notices.md)

## FM-10.1 Parties

Each incident is reported to:

| Party | Why | Receives |
|---|---|---|
| **Provider** | It can stop its agents, find the account or deployment, and fix the behaviour. | The full evidence for its attribution, every cluster, the affected hosts. |
| **Each affected operator** | It can check its logs, block, patch and judge its own exposure. | The activity against its own hosts, in full, including payloads and timing. Never another operator's logs. |
| **National CSIRT**, where relevant | When an affected operator is public-sector or critical infrastructure, or has no reachable security contact. | What the affected operator receives, for the operators in its constituency. |
| **The public** | Others targeted, other providers and researchers can check their own exposure. | The notice ([chapter 11](11-notices.md)). |

Where the declared owner of an "authorised test" is identified, it is a party too ([FM-10.6](#fm-106-authorised-testing)). Toolkit: the toolkit finds operator contacts and proposes the national team for each affected host's country from a directory built from the [FIRST team directory](references.md#disclosure), each entry with its source and the date it was verified.

## FM-10.2 Lead times

Reports go out first. The public notice follows on a fixed clock that starts at the latest report sent to each party:

| Party | Lead time |
|---|---|
| Provider | 0 hours. |
| Operator of a targeted or historical endpoint | 4 to 12 hours, set per case; 6 by default. |
| Operator of a compromised endpoint | 24 hours. |

The notice **must not** be published before every party's clock has run. The clock **must not** be lengthened: nothing a recipient says, asks or offers extends it, and a practitioner cannot set it beyond these bounds for any reason. Each report states the publication time.

A party for which no contact can be found after the search in [FM-10.4](#fm-104-contacts-and-channels) does not hold the notice back. The practitioner records what was tried, and the notice says contact was attempted.

Why these times: an agent swarm is an active incident, not a latent vulnerability. Each day of private coordination is a day the agents keep running against the affected operators and against others nobody has found yet, and those others can only protect themselves once the notice is public. The provider can stop its agents within hours and needs no fix window, so it gets none. An operator gets hours: enough to read its logs, block the clients and check a weakness before readers of the notice can look for it. The operator of a compromised endpoint gets a day, since its weakness may still be open; the notice also withholds that endpoint's attack details ([FM-11.4](11-notices.md#fm-114-what-a-notice-withholds)).

**Not an embargo.** An embargo is a negotiated period whose end depends on the parties: a fix, an agreed date, an extension on request. The lead time is fixed before any report is sent, carries no condition and is never negotiated. A recipient cannot buy delay with cooperation or silence, so the clock cannot become a way to keep an incident quiet.

## FM-10.3 Relation to vulnerability disclosure standards

The method borrows the structure of coordinated vulnerability disclosure and departs from its default timing.

| Source | What the method takes | Where it departs |
|---|---|---|
| [ISO/IEC 29147:2018](references.md#disclosure) Vulnerability disclosure | Receiving and sending reports through published contacts; advisories with what is affected and what to do. | Disclosure waits only for the fixed lead time, not for a remediation; there is no vendor fix to wait for. |
| [ISO/IEC 30111:2019](references.md#disclosure) Vulnerability handling processes | Tracked handling: each case has a record of decisions and sends. | The finder, not a vendor, runs the process. |
| [ISO/IEC TR 5895:2022](references.md#disclosure) Multi-party coordinated vulnerability disclosure and handling | Several parties reported in one coordinated action, each with its role, before public disclosure. | The pre-release period is a fixed lead time of at most a day per party, not a negotiated coordination period, and no party can extend it. |
| [FIRST multi-party guidelines](references.md#disclosure) | Its guidance gives an embargo by default only absent evidence of prior public disclosure, including active exploitation, and recognises that active exploitation may lead a finder or coordinator to disclose before remediation. | The method treats every confirmed incident as active, so it applies that exception as the rule, keeping only a short fixed notice to the parties. |

A practitioner who follows this manual says so in reports, so recipients used to embargoes know what to expect.

## FM-10.4 Contacts and channels

For each affected host, the contact is the first published security contact found: the host's or a parent domain's `security.txt` ([RFC 9116](references.md#disclosure)), else the registrar's abuse address from RDAP. Each contact is recorded with its source link and date. Email is preferred; when an organisation has only a web form or a CERT portal, that is used. Every send is recorded in the case.

## FM-10.5 Right of reply

A provider's or affected operator's statement is appended to the notice verbatim, as a dated update, when they ask. Each report says so. Replies never delay publication ([FM-10.2](#fm-102-lead-times)) and are never edited, except to withhold what any notice withholds ([FM-11.4](11-notices.md#fm-114-what-a-notice-withholds)), with the withholding marked.

## FM-10.6 Authorised testing

A cluster that declares itself an authorised red-team or research evaluation is handled as a normal incident: a declaration in a request is self-identification and is not checked by being believed. Its declared owner is contacted with the provider. If the owner confirms the test was authorised and in scope, the notice is published as "authorised test, closed". It is not withheld: other operators saw the same traffic and need to know what it was.

Toolkit: a cluster whose requests declare a test lists the declaring text and the contact it names, in case notes only ([FM-4.9](04-indicators.md#fm-49-benchmark-targets-and-declared-testing)). The admin adds the owner it names with `case contact add --party declared-owner`.

## FM-10.7 Operator-supplied logs

An affected operator may send its own logs after a report. They become evidence in the case and in private reports to the provider. They are the operator's to publish:

- a notice uses them only after the operator agrees, and the agreement is recorded with how it was given;
- the notice marks them as provided by the operator;
- agreement can be withdrawn, and later updates stop using them;
- a report to one operator never carries another operator's logs.

Only what the case needs is kept (flagged requests, the same clients' other requests, probe chains), redacted at ingest, with a hash of the original file ([cases](../reference/cases.md#operator-evidence)).

## FM-10.8 The admin gate and the case record

Tools draft reports, find contacts and prepare notices. They never send or publish. The admin reads every draft, sends it from their own client or the recipient's form, and records the send. The case record holds, for each incident:

- the records, copied out of collection so retention cannot delete them;
- the rules version pinned ([FM-4.8](04-indicators.md#fm-48-rule-versions-and-pinning));
- each endpoint and the admin's decision on it (compromised, targeted, historical, not affected);
- every attribution claim with its evidence level;
- every merge and split ([FM-5.8](05-linking.md#fm-58-candidate-fleets-merge-and-split));
- every contact, every send with its time, every party no contact was found for, and every reply, dated;
- the self-review below.

An evidence bundle sent with a report holds the records, their analysis, a stamp with the rules and toolkit versions, and a hash manifest, so a recipient can re-run the analysis and check every tier ([evidence bundles](../reference/cases.md#evidence-bundles)).

## FM-10.9 Self-review

Where one practitioner both decides and publishes, no second reviewer reads the notice. A written checklist stands in for one. Before publication, every item **must** pass, and each is recorded in the case:

1. Every attribution claim has its layer, label and tag ([FM-7.6](07-attribution.md#fm-76-claim-tags), [FM-7.7](07-attribution.md#fm-77-attribution-labels)), and no likelihood word is stronger than its label allows ([FM-8.3](08-confidence.md#fm-83-usage-rules)).
2. Each named organisation is described as targeted or affected, never as the actor. "Compromised" is used only for an endpoint classified compromised on a recorded basis beyond the requests it received.
3. An endpoint every record of which comes from a service anyone can submit a URL to is named only with a logged reason, and the notice says "URLs targeting <organisation>'s hosts were submitted to public scan services", not that requests reached it ([FM-5.11](05-linking.md#fm-511-provenance-and-planted-records)).
4. No provider appears in the title, or as more than the notified party, below shared identifiers ([FM-11.2](11-notices.md#fm-112-structure)).
5. Each alternative explanation is recorded as rejected, with the reason: an authorised test ([FM-10.6](#fm-106-authorised-testing)), a honeypot, a research scanner, spoofed self-identification ([FM-7.9](07-attribution.md#fm-79-false-flag-reasoning)), planted records.
6. A cluster with two or more plant signals has a recorded review ([FM-5.11](05-linking.md#fm-511-provenance-and-planted-records)).
7. Every party was sent its report or recorded as having no contact, and the lead time has run ([FM-10.2](#fm-102-lead-times)).
8. The withholding scan passes ([FM-11.5](11-notices.md#fm-115-lint)).
9. **Cooling-off re-read.** The practitioner re-reads the exact final draft at least an hour after it was drafted. A change after the re-read needs another. The hour fits inside the operators' lead time.

Toolkit: `notice add` prints the checklist as a pass/fail list and writes nothing while an item fails; `case reread` records the draft's SHA-256 and the time; `notice lint` checks the items a committed notice shows on its own ([cases](../reference/cases.md#self-review-checklist)).
