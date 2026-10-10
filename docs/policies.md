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

## Reporting and publication

| Topic | Policy |
|---|---|
| **Publication** | Every confirmed incident gets a public notice on the site, one page per incident. Updates are appended as dated entries, and the page shows its status: active, contained or historical. |
| **Timing** | No embargo. Swarms are active incidents. Reports to the AI provider and the affected operators and the public notice go out together, as soon as the admin judges the evidence sufficient. |
| **Admin gate** | Tools and agents draft reports, find contacts and prepare notices. Only the admin decides when evidence is sufficient, which endpoints are compromised or targeted, and sends reports and publishes notices. |
| **Channels** | Email is preferred. When an organisation has no email contact, the admin uses its web form or CERT portal. |
| **Naming** | Public notices name the affected organisations. |
| **What notices withhold** | Anything that lets a reader take over or reuse the swarm's channels, or exploit an unfixed weakness. See [What notices withhold](#what-notices-withhold). |
| **Corrections** | Notices are versioned. Corrections and retractions are appended as dated updates on the notice and in the feed. Earlier entries are never rewritten. |
| **Right of reply** | A provider's or affected operator's statement is appended verbatim to the notice as a dated update when they ask. It never delays publication. See [for-operators.md](guides/for-operators.md#right-of-reply-and-corrections). |
| **Authorised testing** | A cluster that declares itself an authorised red-team or research evaluation is handled as a normal incident, and its declared owner is contacted at the same time as the provider. If the owner confirms it was authorised and in scope, the notice is published as "authorised test, closed". It is not withheld. |
| **Independence** | We work independently and do not depend on other groups or services for permission to publish. |

### What notices withhold

- **Channels.** Live inbox or topic identifiers, and anything else that lets a reader take over or reuse the swarm's channels.
- **Secrets.** Captured credentials and cookies.
- **Unfixed weaknesses.** Details of a weakness at an affected endpoint that is not yet fixed. Endpoints marked compromised have their attack details withheld.
- **Anything unclassified.** The notice draft withholds whatever it cannot classify and flags it for the admin.

Every committed notice is checked for channel identifiers, addresses and credential shapes. Reports sent privately to the affected parties include everything. The full list of what the tooling withholds is in [the notices reference](reference/notices.md#what-a-notice-withholds).
