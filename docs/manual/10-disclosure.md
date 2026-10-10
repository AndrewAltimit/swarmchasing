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

## FM-10.2 Simultaneous release

Reports to every party and the public notice go out together, as soon as the admin judges the evidence sufficient. There is no embargo.

Why: an agent swarm is an active incident, not a latent vulnerability. Each day of private coordination is a day the agents keep running against the affected operators and against others nobody has found yet. Those others can only protect themselves if the notice is public. The provider can stop its agents within hours, so it does not need a fix window the way a software vendor does. And the notice withholds what would let a reader reuse the swarm's channels or exploit an unfixed weakness ([FM-11.4](11-notices.md#fm-114-what-a-notice-withholds)), which is the part of an embargo's purpose that still applies.

## FM-10.3 Relation to vulnerability disclosure standards

The method borrows the structure of coordinated vulnerability disclosure and departs from its default timing.

| Source | What the method takes | Where it departs |
|---|---|---|
| [ISO/IEC 29147:2018](references.md#disclosure) Vulnerability disclosure | Receiving and sending reports through published contacts; advisories with what is affected and what to do. | Disclosure does not wait for a remediation; there is no vendor fix to wait for. |
| [ISO/IEC 30111:2019](references.md#disclosure) Vulnerability handling processes | Tracked handling: each case has a record of decisions and sends. | The finder, not a vendor, runs the process. |
| [ISO/IEC TR 5895:2022](references.md#disclosure) Multi-party coordinated vulnerability disclosure and handling | Several parties reported in one coordinated action, each with its role. | No pre-release coordination period. |
| [FIRST multi-party guidelines](references.md#disclosure) | Its guidance gives an embargo by default only absent evidence of prior public disclosure, including active exploitation, and recognises that active exploitation may lead a finder or coordinator to disclose before remediation. | The method treats every confirmed incident as active, so it applies that exception as the rule. |

A practitioner who follows this manual says so in reports, so recipients used to embargoes know what to expect.

## FM-10.4 Contacts and channels

For each affected host, the contact is the first published security contact found: the host's or a parent domain's `security.txt` ([RFC 9116](references.md#disclosure)), else the registrar's abuse address from RDAP. Each contact is recorded with its source link and date. Email is preferred; when an organisation has only a web form or a CERT portal, that is used. Every send is recorded in the case.

## FM-10.5 Right of reply

A provider's or affected operator's statement is appended to the notice verbatim, as a dated update, when they ask. Replies never delay publication and are never edited, except to withhold what any notice withholds ([FM-11.4](11-notices.md#fm-114-what-a-notice-withholds)), with the withholding marked.

## FM-10.6 Authorised testing

A cluster that declares itself an authorised red-team or research evaluation is handled as a normal incident: a declaration in a request is self-identification and is not checked by being believed. Its declared owner is contacted at the same time as the provider. If the owner confirms the test was authorised and in scope, the notice is published as "authorised test, closed". It is not withheld: other operators saw the same traffic and need to know what it was.

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
- every contact, every send and every reply, dated.

An evidence bundle sent with a report holds the records, their analysis, a stamp with the rules and toolkit versions, and a hash manifest, so a recipient can re-run the analysis and check every tier ([evidence bundles](../reference/cases.md#evidence-bundles)).
