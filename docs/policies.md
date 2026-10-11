# Policies

How swarmchasing collects, reports and publishes. These apply to every tool in this repository and to everyone who operates it.

How the analysis works is in [methodology.md](methodology.md). What an operator who receives a report can do is in [for-operators.md](guides/for-operators.md).

## Collection

- **Passive only.** We read indexes and public records. We never open URLs that agents submitted, never read from or post to their callback channels (inboxes, notification topics, paste sites), and never probe suspected agent infrastructure.
- **Public records only.** No authenticated, account-linked or otherwise non-public data. Public records include scan services, web archives, certificate logs, package registry metadata and GitHub's public event stream. The toolkit also reads web server access logs, so operators can check their own logs in the browser or the CLI. Those logs are never a watch source.
- **Operator-supplied logs.** An operator's own logs, sent to us after a report, may become evidence in its case and in the private reports. Logs are the operator's to publish, so a notice uses them only after we ask and the operator agrees. A notice cites them as provided by the operator. A report to one operator never carries another operator's logs. See [for-operators.md](guides/for-operators.md#send-logs-back).
- **Redact at ingest.** Records can carry exfiltrated cookies, tokens and keys. Secret-looking values are replaced with hashes before anything is stored, so links between records survive and the secrets do not.
- **Raw data stays out of git.** Collector output, watch runs and case working files live in gitignored directories. Only curated, redacted samples and published notices are committed. Case files, including the reports drafted in them, stay in the data directory.
- **Retention.** Watch data (run directories and the record store) is deleted after 180 days by capture time; `swarmchase watch` enforces this on every run (`retain_days` in [`watchlist.toml`](../watchlist.toml)). Records a case needs are copied into the case first (`swarmchase case new` / `case add`). Case files live with the watch data, outside git: an open case names organisations on unconfirmed evidence. A case's records are kept while the case is open, plus one year. Reviewed records (`swarmchase review`) are kept as the evaluation set.
- **Backups.** Cases, reviewed labels, pinned rules and the watch state are backed up encrypted to a public key, so the runner holds no key that can read them ([backups](reference/configuration.md#backups)). The identity that decrypts them is kept off the runner and away from the backup drive. Backups follow the same retention: `--keep` bounds how many exist, and a restored case keeps its own retention clock.
- **Source terms.** We follow each source's terms of use. urlquery.net reports are cited by link and never quoted or redistributed.

## Evidence and attribution

- **Evidence over narrative.** Every claim traces to a public record link and a rule ID.
- **Calibrated attribution.** Self-identification (a model or vendor name in a request) is weak evidence: agents misreport who built them, and anyone can submit such a string to a public scanner. An ASN names a host, not a developer. Every attribution states the strongest class of evidence it rests on, weakest first:
  1. self-identification;
  2. hosting network, which names a developer only when the network belongs to the company the requests name;
  3. identifiers shared with a confirmed incident;
  4. infrastructure owned by the provider;
  5. confirmation by the provider.

  Reports and notices name a developer only at or above the level the admin sets for the case (`swarmchase report --min-named`, default: shared identifiers), and never on self-identification alone. Case notes list every claim.
- **Four layers.** Developer, hosting network, harness and model family are attributed separately ([SC-FM 7](manual/07-attribution.md)). A host is named as a host. Harness and model-family candidates are ranked in private reports and never named in public; a model-family claim needs a held-out measurement of its method.
- **Tags and labels.** Every attribution claim is tagged Observed, Documented, Inference or Conclusion, and labelled Confirmed, Suspected, Possible or Unattributed by its evidence. No statement uses a likelihood word stronger than its label allows.
- **Four findings, kept apart.** Whether the records carry payloads (the tier), whether an agent sent them (the agent grade), whether the activity went beyond its task (the scope finding) and whether agents coordinated are separate findings ([SC-FM 15](manual/15-misalignment.md)). A tier alone does not make an incident: before a case is reported, the admin records the scope finding with the tests that failed. Activity that stayed within its task is not reported, whatever its tier. We call agents misaligned only when an agent is present and the activity went out of scope, and the tooling enforces it ([Wording](#wording)).
- **Words follow measurement.** A public notice says what the records contain. It says that the activity is an agent's, or rates how likely, only as strongly as a held-out measurement of that kind of finding supports ([SC-FM 9.12](manual/09-evaluation.md#fm-912-calibrated-public-language)).
- **Neutral fleet names.** A fleet's identifier never contains a provider, model, country or organisation name, and is never reused ([SC-FM 5.13](manual/05-linking.md#fm-513-cluster-lifecycle-and-identifiers)).

- **Machine help with labelling.** A language model may suggest labels for leads under review. A model on infrastructure the admin controls (a loopback or private-network endpoint) may see any record. A hosted model may see only public records from web archive indexes (Wayback, Arquivo, Memento, Common Crawl) and urlquery.net, as `review --export-hosted` writes them: defanged and without IP addresses. This is private labelling, not redistribution: what the model sees is never published, and suggestions stay in the data directory. Operator logs and any other source are never sent to a hosted model. No model fetches URLs, and a suggestion is stored apart from the admin's label, never as it.

  The scheduled watch may ask a hosted model the same way, through the admin's own Claude Code login on the runner, about each run's new leads from those public sources only; its suggestions stay in the data directory and are never labels.

## Reporting and publication

| Topic | Policy |
|---|---|
| **Publication** | Every confirmed incident gets a public notice on the site, in two stages: indicators first, names later. Updates are appended as dated entries, and the page shows its status. See [Two stages](#two-stages). |
| **Timing** | Reports go first. Indicators follow on a short fixed clock; an operator is named 3 working days after its report, 10 if compromised, unless it consents earlier. Not an embargo. See [Lead times](#lead-times). |
| **Admin gate** | Tools and agents draft reports, find contacts and prepare notices. Only the admin decides when evidence is sufficient, which endpoints are compromised or targeted, and sends reports and publishes notices. |
| **Review** | Every indicator notice and naming update passes the admin's written checklist and an approved review of the exact draft by a second person. See [Self-review and second review](#self-review-and-second-review). |
| **Channels** | Email is preferred. When an organisation has no email contact, the admin uses its web form or CERT portal. |
| **Naming** | Affected organisations are named as targets, in a naming update after their clock. A provider below shared identifiers is named only as the party that was notified. See [Naming](#naming). |
| **Wording** | Notices and reports describe suspected AI agent activity. "Misaligned" appears only on a recorded scope-exceeded finding and an admin agent grade of L3 or higher. See [Wording](#wording). |
| **What notices withhold** | Anything that lets a reader take over or reuse the swarm's channels, or exploit an unfixed weakness. See [What notices withhold](#what-notices-withhold). |
| **Corrections** | Notices are versioned. Corrections and retractions are appended as dated updates on the notice and in the feed. Earlier entries are never rewritten. |
| **Right of reply** | A provider's or affected operator's statement is appended verbatim to the notice as a dated update when they ask. It never delays publication. See [for-operators.md](guides/for-operators.md#right-of-reply-and-corrections). |
| **Authorised testing** | A cluster that declares itself an authorised red-team or research evaluation is handled as a normal incident, and its declared owner is contacted with the provider. If the owner confirms it was authorised and in scope, the notice is published as "authorised test, closed". It is not withheld. |
| **Independence** | We work independently and do not depend on other groups or services for permission to publish. |

### Two stages

A notice is published in two stages.

1. **Indicator notice.** What the activity was and how to recognise it: relays, carriers, payload families and shapes, run tags already published elsewhere, the kinds of callback service used (never a channel identifier), the time window, cluster tiers, attribution and the scope finding. It names and locates no affected party: no organisation, host, registrable domain, IP address or network of a target, and no target URL or path that contains an affected host. Targets are described by class only, such as "a national government data portal" or "two university research sites".
2. **Naming updates.** Dated updates appended to the published notice, each adding the names and defanged hosts of the affected organisations whose naming clock has run or who consented. One update may name some operators while others are still pending; a later update names the rest.

Naming is the default once allowed. The admin may decide never to name an operator, with the reason logged in the case.

### Lead times

Each party's clocks start at the latest report sent to it, or at the recorded no-contact for a party with none.

| Party | Indicator notice | Naming |
|---|---|---|
| The AI provider | 0 hours | Named per the attribution rules below |
| The operator of a targeted or historical endpoint | 0 hours | 3 working days |
| The operator of a compromised endpoint | 24 hours | 10 working days |

The indicator notice may be published once every party was sent its report or recorded as having no contact, so operators hear privately before anything is public, and every party's indicator clock has run. Others the swarm targets can protect themselves only once the indicators are out, so that clock is short.

Working days are Monday to Friday in UTC; Saturdays and Sundays never count. A report sent on a weekend counts from the following Monday 00:00 UTC. The naming clock ends at the same UTC time of day once the working days have passed. The naming lead gives an operator time to check its logs, patch and prepare before its name is public.

- **Not an embargo.** Indicators are published on a fixed, short clock regardless of what anyone says; only names wait. Every clock is fixed in advance, attached to no condition and never negotiated. Recipients are told the times in their report.
- **Lengthening.** The admin may lengthen the naming lead for a case, from 3 to 20 working days; a compromised endpoint's operator then waits the longer of 10 and that lead. Nothing shortens it below these bounds.
- **Consent.** An operator that says in writing it may be named earlier is recorded, and may then be named in the next naming update with no wait. Consent is the only thing that shortens the naming clock.
- **Requests.** Nothing a recipient says, asks or offers changes the indicator clock. A request to delay naming is recorded; the admin may lengthen the naming lead within the bounds above, and is not bound by the request.
- **No contact.** When no contact can be found for a party, the admin records what was tried. That party does not hold the indicator notice back, its naming clock runs from the record, and the notice says contact was attempted.
- **Replies.** A statement sent for publication is appended verbatim to the notice as a dated update. It never moves a clock.

### Self-review and second review

Before the tooling writes an indicator notice or a naming update, two reviews pass, both recorded in the case.

The admin's self-review checklist:

- every attribution claim states its layer, label and tag, and no likelihood word is stronger than its label allows;
- each named organisation is described as targeted or affected; "compromised" is used only for an endpoint classified compromised on a recorded basis beyond the requests it received;
- each alternative explanation (authorised test, honeypot, research scanner, spoofed self-identification, planted records) is recorded as rejected, with the reason;
- a cluster with two or more plant signals has a recorded review;
- every party was sent its report or recorded as having no contact, and the stage's clock has run;
- the withholding scan passes, and the indicator notice names and locates no affected party;
- the admin re-read the exact final draft at least an hour after it was drafted;
- a second person approved the exact draft, as below.

The second review:

- **A second person.** A reviewer other than the admin reads the exact draft and approves or objects. The review records the reviewer, the time, the verdict, the stage and the SHA-256 of the draft.
- **Exact draft.** Any edit to the draft after the review invalidates it. An objection blocks publication until a later approval of the current draft; the objection and the response stay in the case log.
- **No bypass.** The tooling has no override. With no reviewer available, nothing is published.
- **Not a gate on corrections.** Corrections, retractions, right-of-reply statements and status changes need no second review, so a correction is never blocked.
- **Anonymous in public.** The notice says it was reviewed by a second reviewer before publication, without the reviewer's name.

### Naming

- **Affected organisations** are named as targets, in a naming update once their clock has run or they consented. When every record on an endpoint comes from a service anyone can submit a URL to, its operator is named only with the admin's reason logged in the case. The update then says "URLs targeting <organisation>'s hosts were submitted to public scan services", not that requests reached them.
- **Withholding a name.** The admin may decide never to name an operator; the decision and its reason are logged in the case.
- **Providers below shared identifiers** are named as the party notified, never as the operator: "Requests in this cluster identify themselves as using <model> from <provider>. Self-identification is the weakest evidence we use. We have not confirmed that <provider> operated, deployed or authorised them. <provider> has been sent the full evidence." No such provider appears in a notice title.
- **Provider infrastructure** shows whose systems the requests came from: the notice says they came from infrastructure the provider operates, and treats who deployed the agents as a separate question.

### Wording

Reports and notices describe what is detected: suspected AI agent activity in public records, linked into runs and fleets, reported when it harms or endangers others. Their titles are "Report of suspected AI agent activity" and "Public notice: suspected AI agent activity".

"Misaligned" in any form appears in a report or notice only when the case records both an admin scope finding of scope exceeded for the clusters it covers and an admin agent grade of L3 or higher ([SC-FM 15](manual/15-misalignment.md)). The notice front matter records both, and the notice linter rejects the word without them.

### What notices withhold

- **Channels.** Live inbox or topic identifiers, and anything else that lets a reader take over or reuse the swarm's channels.
- **Secrets.** Captured credentials and cookies.
- **Affected parties, until named.** The indicator notice names and locates no affected party ([Two stages](#two-stages)).
- **Unfixed weaknesses.** Details of a weakness at an affected endpoint that is not yet fixed. Endpoints marked compromised have their attack details withheld.
- **Anything unclassified.** The notice draft withholds whatever it cannot classify and flags it for the admin.

Every committed notice is checked for channel identifiers, addresses and credential shapes. Reports sent privately to the affected parties include everything. The full list of what the tooling withholds is in [the notices reference](reference/notices.md#what-a-notice-withholds).
