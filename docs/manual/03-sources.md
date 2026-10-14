# 3. Sources and collection

[Manual index](README.md) · Previous: [2. Principles](02-principles.md) · Next: [4. Indicators](04-indicators.md)

## FM-3.1 What counts as a public record

A public record is a trace of a request that a third party publishes to anyone, without an account tied to the subject, and that the third party keeps for its own purposes. The swarm's own channels are excluded even when they are world-readable: a public inbox is still the swarm's inbox ([FM-3.2](#fm-32-passivity-test)).

| Source class | What it records | Toolkit support |
|---|---|---|
| Public scan services | A submitted URL, where the scan ended, the target's address and network | urlquery.net and urlscan.io search |
| Web archives | Index rows: when a URL was captured, its status and digest | Wayback Machine, Arquivo.pt and Common Crawl CDX; Memento timemaps |
| Submit-anywhere archives | On-demand saves of any URL anyone submits | Arquivo.pt SavePageNow, its `SAWP` collections |
| Certificate Transparency logs | Certificates issued for a name | crt.sh lookups; CT logs read directly |
| Package registries | Package metadata: names, versions, publish times, maintainers | npm search, PyPI feeds, the Go module index, NuGet's catalog, Packagist's change feed, RubyGems and crates.io listings |
| Vulnerability databases | Published CVE records and advisories: descriptions, references, credits | GitHub Advisory Database, the CVE List |
| Public code-host records | Public events (repository creation, issues, comments, stars, forks), pull request and commit text, new projects | GH Archive, GitHub search, GitLab.com and Codeberg project listings |

| Public wiki edit streams | Edits and the external links they add | Wikimedia EventStreams |
| Public forums and social streams | Posts and replies, their links and their authors' account age | Hacker News search index, Bluesky Jetstream |
| Agent protocol footprints | Archive index rows for the well-known files agents and agent platforms serve | Wayback CDX for agent cards, agent registration files and signature key directories |
| Tool-server registries | Published tool servers: name, version, publish time, declared hosts | The official MCP Registry |
| Third-party labels | Packages later found malicious; wiki pages editors tagged as suspected AI-generated text | OSV malicious-package records; Wikipedia's AI cleanup categories |
| Published security contacts | An organisation's security.txt, or its registrar's abuse address | security.txt, RDAP |

The last row is not evidence: it is how a practitioner finds whom to report to ([FM-10.4](10-disclosure.md#fm-104-contacts-and-channels)).

**Submit-anywhere archives.** An archive's save-now feature fetches any URL anyone submits, from the archive's own origin, so agents use it as they use a scan service: a neutral origin that fetches the target for them. Arquivo.pt merges these saves into collections named `SAWP<n>` within days, long before its crawls are indexed, so a collector reads only those collections. The rows are still capture times, not submission times ([FM-6.1](06-timing.md#fm-61-timestamp-kinds)).

**Reference data.** Agent protocol footprints, tool-server registries and third-party labels are not records of a request to a target. A label says what a target was found to be by someone else, never who acted on it. They are reference data for linking: a footprint on a throwaway tunnel names a platform a run may have used, and a registry entry lets a host seen in a run be matched to a declared tool server. Both are read from indexes only. A footprint file is never fetched, and no registered server is contacted ([FM-3.2](#fm-32-passivity-test)).

An operator's own access logs are not a public record. They enter a case only when the operator sends them ([FM-10.7](10-disclosure.md#fm-107-operator-supplied-logs)), and are never a collection source.

## FM-3.2 Passivity test

A source is admissible only if collecting from it passes every condition below. The test is applied to the collector as built, not to its intent.

1. **Index and metadata reads only.** The collector reads the source's index, search results or metadata. It does not open archived captures: a capture of an agent-submitted URL replays what the agent fetched, payloads included.
2. **Never fetch an agent-submitted URL.** No component requests a URL taken from a record, directly or through a service, including to "check whether it is still live".
3. **Never touch callback channels.** No component lists, reads from, or posts to an inbox, request catcher, notification topic, paste or similar channel an agent used, even through its public read API. Channels are matched only inside records found through other sources.
4. **Never interact with agents.** No component sends content an agent may read, such as a reply to its sign-up or a page planted on a host it visits. One exception is narrow and explicit: the project's own published pages and files **may** carry inert canary tokens. A token carries no instruction, asks nothing of the reader, never points at a third party, and lives only on hosts the project controls. A copy of one in a record shows that something read that surface and repeated the token, never who, and never links records.
5. **Terms reviewed and recorded.** The source's terms of use have been read, and what they allow (collection, storage, quotation, redistribution) is recorded next to the source ([FM-3.4](#fm-34-terms-of-use)).

A source that fails any condition is not used, even when the data would help. Published investigations sometimes read callback inboxes through their public APIs; work that follows this manual does not.

## FM-3.3 Source rationale

Every scheduled source carries a written rationale with three parts:

- **what agent behaviour it catches**, and which tactic ([FM-4.3](04-indicators.md#fm-43-the-sc-t-tactic-taxonomy));
- **which indicators it feeds**;
- **what its noise looks like**: who else produces matching records, and at what volume.

A source with no rationale is dropped. Sources deliberately not collected are listed with the reason, so a later reader does not add them by mistake. In the toolkit, rationales and the not-watched list are comments in [`watchlist.toml`](../../watchlist.toml).

## FM-3.4 Terms of use

A practitioner follows each source's terms. Where terms forbid redistributing content, reports and notices link to the record and quote only indicators the practitioner derived; the content is never committed, published or put in a benchmark ([FM-9.10](09-evaluation.md#fm-910-benchmark-publication-rules)). urlquery.net is such a source ([configuration](../reference/configuration.md#urlquerynet)). In the toolkit, each source's terms (with their URL) and what they allow are recorded in its rationale and its collector's module docs.

## FM-3.5 Politeness

Collectors identify themselves with a user agent, make one request at a time with a minimum interval, and back off exponentially on rate limiting and server errors, honouring `Retry-After`. A collector that a source has to block is a defect.

## FM-3.6 Known source biases

Each source distorts what it shows. A report that rests on a source states the biases that bear on its claims.

| Bias | Effect | What it limits |
|---|---|---|
| Capture time is not request time | An archive timestamp is when the archive captured the URL, which may be a later crawl of a link to it. | Timing claims on archive records ([FM-6.1](06-timing.md#fm-61-timestamp-kinds)). |
| Display truncation | Scan services cut long URLs for display and storage. A cut payload looks like model output cut off mid-escape. | Cut-length and truncation indicators ([FM-4.5](04-indicators.md#fm-45-artifact-families)). |
| Index lag | Archives index captures days to months late; one archive in the toolkit lags by more than a year. | Absence claims: "no activity since" is "none indexed yet". |
| Target-side network fields | A scan record's IP and ASN describe where the scanner reached the target, not who submitted it. | Hosting attribution ([FM-7.3](07-attribution.md#fm-73-hosting-and-runtime-layer)). |
| Coverage | Private, account-linked and unlisted scans never appear. | Every count is a lower bound. |
| Selection | Archives capture what is linked or requested to be saved; scan services hold what someone chose to submit. | Rates and shares across the population. |
| Missing headers | Most public records carry no request headers, and none keep their order. | Header indicators apply mainly to operator logs. |

## FM-3.7 Redaction at ingest

Records can carry secrets an agent captured or used: cookies, bearer tokens, API keys. Before anything is stored or analysed, secret values are replaced with a marker and a short deterministic hash of the secret. The hash keeps two records that carried the same secret linked ([SC-T6](04-indicators.md#fm-43-the-sc-t-tactic-taxonomy)) and lets an operator check a token they hold. It is unsalted, so a short or guessable secret could be recovered by brute force; reports say so. Placeholders, payloads, tags and parameter names are kept, because indicators read them. The toolkit's lists are in [methodology](../methodology.md#redaction-at-ingest).

## FM-3.8 Retention

Raw collection is deleted on a published schedule counted from capture time. Records a case needs are copied into the case first. Case files are kept while the case is open plus a published period, and never in a public repository, because an open case names organisations on unconfirmed evidence. This project's periods are in [policies](../policies.md#collection).
