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
- **Four findings, kept apart.** Whether the records carry payloads (the tier), whether an agent sent them (the agent grade), whether the activity went beyond its task (the scope finding) and whether agents coordinated are separate findings ([SC-FM 15](manual/15-misalignment.md)). A tier alone does not make an incident: before a case is reported, the admin records the scope finding with the tests that failed. Activity that stayed within its task is not reported, whatever its tier. We call agents misaligned only when an agent is present and the activity went out of scope.
- **Words follow measurement.** A public notice says what the records contain. It says that the activity is an agent's, or rates how likely, only as strongly as a held-out measurement of that kind of finding supports ([SC-FM 9.12](manual/09-evaluation.md#fm-912-calibrated-public-language)).
- **Neutral fleet names.** A fleet's identifier never contains a provider, model, country or organisation name, and is never reused ([SC-FM 5.13](manual/05-linking.md#fm-513-cluster-lifecycle-and-identifiers)).

- **Machine help with labelling.** A language model may suggest labels for leads under review only when it runs on infrastructure the admin controls (a loopback or private-network endpoint). Record content is never sent to a third-party model API, the model never fetches URLs, and a suggestion is stored apart from the admin's label, never as it.

## Reporting and publication

| Topic | Policy |
|---|---|
| **Publication** | Every confirmed incident gets a public notice on the site, one page per incident. Updates are appended as dated entries, and the page shows its status: active, contained or historical. |
| **Timing** | Reports go first; the notice follows on a fixed lead time: 0 hours for the AI provider, 4 to 12 hours for the operator of a targeted endpoint, 24 hours for the operator of a compromised one. Nothing a recipient says extends it. It is not an embargo. See [Lead times](#lead-times). |
| **Admin gate** | Tools and agents draft reports, find contacts and prepare notices. Only the admin decides when evidence is sufficient, which endpoints are compromised or targeted, and sends reports and publishes notices. |
| **Self-review** | One admin decides and publishes, so every notice passes a written checklist and a re-read at least an hour after drafting. See [Self-review](#self-review). |
| **Channels** | Email is preferred. When an organisation has no email contact, the admin uses its web form or CERT portal. |
| **Naming** | Public notices name the affected organisations as targets. A provider below shared identifiers is named only as the party that was notified. See [Naming](#naming). |
| **What notices withhold** | Anything that lets a reader take over or reuse the swarm's channels, or exploit an unfixed weakness. See [What notices withhold](#what-notices-withhold). |
| **Corrections** | Notices are versioned. Corrections and retractions are appended as dated updates on the notice and in the feed. Earlier entries are never rewritten. |
| **Right of reply** | A provider's or affected operator's statement is appended verbatim to the notice as a dated update when they ask. It never delays publication. See [for-operators.md](guides/for-operators.md#right-of-reply-and-corrections). |
| **Authorised testing** | A cluster that declares itself an authorised red-team or research evaluation is handled as a normal incident, and its declared owner is contacted with the provider. If the owner confirms it was authorised and in scope, the notice is published as "authorised test, closed". It is not withheld. |
| **Independence** | We work independently and do not depend on other groups or services for permission to publish. |

### Lead times

The public notice follows the reports on a fixed clock. Each party's clock starts at the latest report sent to it:

| Party | Lead time |
|---|---|
| The AI provider | 0 hours |
| The operator of a targeted or historical endpoint | 4 to 12 hours; 6 unless the admin sets the case otherwise |
| The operator of a compromised endpoint | 24 hours |

The notice may be published once every party's clock has run. The lead time gives an operator hours to check its logs and patch before the notice is public. It is short because a swarm is an active incident: others it targets can protect themselves only once the notice is out.

- **No extension.** Nothing a recipient says, asks or offers lengthens the clock, and the admin cannot set it beyond these bounds. The tooling has no override.
- **Not an embargo.** The clock is fixed in advance, attached to no condition and never negotiated. Recipients are told the publication time in their report.
- **No contact.** When no contact can be found for a party, the admin records what was tried. That party does not hold the notice back, and the notice says contact was attempted.
- **Replies.** A statement sent for publication is appended verbatim to the notice as a dated update. It never moves the time.

### Self-review

No second person reviews a notice. Before the tooling writes one, every item of a checklist passes, recorded in the case:

- every attribution claim states its layer, label and tag, and no likelihood word is stronger than its label allows;
- each named organisation is described as targeted or affected; "compromised" is used only for an endpoint classified compromised on a recorded basis beyond the requests it received;
- each alternative explanation (authorised test, honeypot, research scanner, spoofed self-identification, planted records) is recorded as rejected, with the reason;
- a cluster with two or more plant signals has a recorded review;
- every party was sent its report or recorded as having no contact, and the lead time has run;
- the withholding scan passes;
- the admin re-read the exact final draft at least an hour after it was drafted.

### Naming

- **Affected organisations** are named as targets. When every record on an endpoint comes from a service anyone can submit a URL to, its operator is named only with the admin's reason logged in the case. The notice then says "URLs targeting <organisation>'s hosts were submitted to public scan services", not that requests reached them.
- **Providers below shared identifiers** are named as the party notified, never as the operator: "Requests in this cluster identify themselves as using <model> from <provider>. Self-identification is the weakest evidence we use. We have not confirmed that <provider> operated, deployed or authorised them. <provider> has been sent the full evidence." No such provider appears in a notice title.
- **Provider infrastructure** shows whose systems the requests came from: the notice says they came from infrastructure the provider operates, and treats who deployed the agents as a separate question.

### What notices withhold

- **Channels.** Live inbox or topic identifiers, and anything else that lets a reader take over or reuse the swarm's channels.
- **Secrets.** Captured credentials and cookies.
- **Unfixed weaknesses.** Details of a weakness at an affected endpoint that is not yet fixed. Endpoints marked compromised have their attack details withheld.
- **Anything unclassified.** The notice draft withholds whatever it cannot classify and flags it for the admin.

Every committed notice is checked for channel identifiers, addresses and credential shapes. Reports sent privately to the affected parties include everything. The full list of what the tooling withholds is in [the notices reference](reference/notices.md#what-a-notice-withholds).
