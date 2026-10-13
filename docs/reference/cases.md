# Case files

A case is one incident's working directory under `<data>/cases/<id>/`: its records, `case.toml`, reports, drafts, evidence bundles and exports. Cases never go into git, because an open case names organisations on unconfirmed evidence and private reports carry details that public notices withhold. The day-to-day flow is in the [admin workflow](../guides/admin-workflow.md).

The CLI reads and writes the files; what a case holds and every decision on it are in [`sc-case`](../../crates/sc-case/README.md), and the STIX and MISP builders in [`sc-stix`](../../crates/sc-stix/README.md), so the browser toolkit can share them.

## Opening a case

```sh
swarmchase case new <id> --title "…" --cluster C1 [--record ID] [--host-hits] [files…]
```

`case new` copies the selected records into `raw/records.ndjson`, so watch retention cannot delete them, and writes `case.toml`. Records come from the watch store, or from files given as arguments. From the store it analyses the last `--days` days, by default the `analysis_window_days` of `--watchlist` (`watchlist.toml`, else 30), the window the digest analyses, so a cluster number from the digest names the same cluster; a stable key (`k-3f9a2c1b`) names it whatever the window. A line of `raw/records.ndjson` that cannot be read is skipped with a warning. `--host-hits` also takes every flagged record on the same hosts, including other clusters. `review` can open a case from a lead too ([review](watch.md#reviewing-leads)).

## What `case.toml` holds

- the case status (`open`, `reported`, `published`, `closed`), the notice status (`active`, `contained`, `historical`), and the date a notice was added while its publication is pending;
- the admin's name (`admin`), set by `case new` from `SWARMCHASE_ADMIN`, else `git config user.name`, and changed with `case set --admin`;
- each endpoint and the admin's decision on it: `compromised` (with its basis), `targeted`, `historical`, `not-affected`, or still `unreviewed`, any sector description for the notice, and any reason for naming an endpoint seen only in submit-anywhere records;
- attribution claims established by case work, each with its layer, evidence and tag;
- contacts;
- fleets: clusters the admin treats as one operator's, by stable key, each with any interaction evidence the admin accepted ([swarms](#swarms));
- the admin's agent grade, with its date and basis ([agent grade](#agent-grade));
- the admin's scope finding per cluster, with the failed tests and a note ([scope finding](#scope-finding));
- a dated decision log;
- the reports sent, each with its time, and the parties no contact was found for;
- the naming lead, if the admin lengthened it, and each operator's consent to earlier naming or the decision never to name it ([lead times](#lead-times));
- the self-review: the decisions on alternative explanations, plant reviews, and each draft's hash and time when written and when re-read ([self-review checklist](#self-review-checklist));
- the second reviews, each with its reviewer, time, verdict, note, stage and draft hash ([second review](#second-review)).

Each change is logged with its date.

## Subcommands

| Command | What it does |
|---|---|
| `case status [<id>]` | Lists cases (a case.toml that does not load is skipped with a warning), or shows one case and what it still needs. |
| `case endpoint <id> <host>... <state> [--note …] [--basis …] [--single-source-reason …] [--sector "…"]` | Classifies one or more endpoints; `compromised` needs `--basis`. A host not in the case changes nothing. |
| `case rename <id> <new-id>` | Gives a case a new ID, carrying over its watch hits, under the data directory's lock. Refused once its notice is published, or while a watch runs. |
| `case claim <id> --party … [--layer …] --evidence … [--tag …] --detail …` | Records an attribution claim ([attribution claims](#attribution-claims)). |
| `case set <id> --status … --notice … --min-named … --naming-days N --admin "…"` | Changes the status, the developer naming threshold, the naming lead (3 to 20 working days) or the admin's name. |
| `case grade <id> [<L0..L5> --note … \| --clear]` | Shows each cluster's agent grade, or records the admin's ([agent grade](#agent-grade)). |
| `case scope <id> --cluster <key> --finding in-scope\|exceeded\|not-assessable --tests S2,S4 --note "…"` | Records the admin's scope finding for a cluster ([scope finding](#scope-finding)). |
| `case note <id> "…"` | Adds a dated entry to the decision log. |
| `case fleet merge\|split\|show <id> …` | Groups soft-linked clusters into one fleet, splits one off, or lists fleets and candidates ([fleets](#fleets)). |
| `case fleet interaction\|withdraw <id> <fleet> …` | Records reviewed interaction between a fleet's runs, or withdraws it ([swarms](#swarms)). |
| `case add <id> …` | Adds new records. |
| `case contacts <id> [--providers-only] [--country CC]` | Adds provider contacts from the directory, proposes national CSIRTs, then finds a contact for each compromised, targeted or historical endpoint, never reading a relay, carrier or callback host ([contacts](#contacts)). |
| `case contact add\|rm <id> …` | Adds or removes a contact by hand ([contacts](#contacts)). |
| `case report <id> --audience …` | Drafts a report into `reports/`, applying the case's claims and naming threshold. |
| `case draft <id> --audience provider\|affected --to <contact>` | Writes the report for one listed contact into `outbox/` ([drafts](#drafts)). |
| `case bundle <id>` | Writes an evidence bundle without drafting a report, signed when there is a signing key ([signing](#signed-bundles)). |
| `case verify <bundle> [--key <file>]` | Checks the signature, the manifest, re-runs the analysis and fails if the signature is invalid or any tier or cluster differs. |
| `case sent <id> --to … --channel … [--at <time>]` | Records a send the admin made, with its time, and moves an open case to reported ([lead times](#lead-times)). |
| `case no-contact <id> <host\|org\|provider> --searched …` | Records that no contact was found for a party ([lead times](#lead-times)). |
| `case consent <id> --party <p> --note "…"` | Records an operator's written consent to be named before its naming lead runs ([lead times](#lead-times)). |
| `case naming <id> --party <p> --withhold --reason "…"` | Records the decision never to name an operator ([lead times](#lead-times)). |
| `case notice <id> [--naming]` | Drafts the indicator notice into `notice.md`, or the next naming update into `naming.md` ([notices](notices.md)). |
| `case alternative <id> [<kind> --rejected …]` | Records why an alternative explanation does not hold, or lists the decisions ([self-review](#self-review-checklist)). |
| `case plant-review <id> <cluster> --note …` | Records the review of a cluster's plant signals. |
| `case reread <id>` | Records a re-read of the notice draft as it is now, by its SHA-256. |
| `case checklist <id>` | Prints the self-review checklist `notice add` runs. |
| `case review-packet <id> [--naming]` | Writes the draft, checklist output and internal report into `outbox/review/` for the second reviewer ([second review](#second-review)). |
| `case review <id> --reviewer "…" --verdict approve\|object [--note "…"]` | Records a second review of the current draft ([second review](#second-review)). |
| `case rules <id> [--update]` | Shows the pinned rules version against the current one and the records whose tier would change. |
| `case export <id> --format stix\|misp --audience … [--to <contact>]` | Writes the case as a STIX 2.1 bundle or a MISP event ([STIX export](#stix-export), [MISP export](#misp-export)). |
| `case export <id> --format oecd\|aiid [--site-url …]` | Writes a draft for an AI incident database or reporting framework ([incident database drafts](#incident-database-drafts)). |
| `case evidence add <id> <log> --org … --host …` | Adds logs an affected operator sent back ([operator evidence](#operator-evidence)). |
| `case evidence consent <id> <eid> --how …` | Records the operator's agreement to the notice using its logs; `withdraw` reverses it. |

## Attribution claims

A claim is about one of four layers ([SC-FM 7.1](../manual/07-attribution.md#fm-71-four-layers)): `developer` (the default), `host`, `harness` or `model_family`. Developer and host claims need `--evidence` on the ladder; `--tag observed|documented|inference|conclusion` overrides the derived tag. A model-family claim needs `--likelihood`, `--accuracy` (the method's, on a held-out set) and `--corpus-size`, and is refused without them.

Each claim's label (Confirmed, Suspected, Possible, Unattributed) follows from its layer and evidence ([SC-FM 7.7](../manual/07-attribution.md#fm-77-attribution-labels)). The records add their own claims on every report: self-identified developers, client networks and runtime markers as hosts, and harness candidates from user agents and header and encoding fingerprints. Harness and model-family candidates are ranked in private reports and never named in a notice or a public export, whatever their evidence. Case files written before layers and tags existed read unchanged.

## Agent grade

Every cluster carries a computed agent grade from L0 (payloads only) to L4 (agent likely), with the signals, counter-signals and caps behind it ([methodology](../methodology.md#agent-likelihood), [SC-FM 7.10](../manual/07-attribution.md#fm-710-agent-likelihood)). `case grade <id>` lists them for the case's clusters above noise, and the decision if there is one; `case status` shows each cluster's grade.

```sh
swarmchase case grade <id>                                      # computed grades and their signals
swarmchase case grade <id> L5 --note "provider confirmed: <link>"
swarmchase case grade <id> --clear
```

The decision is the admin's, stored as `agent_grade` (level, date, note) in `case.toml` and logged. It needs `--note`, what it rests on with links. It is the only way to L5 (documented: operator logs matching an agent harness, or the provider's confirmation), and it may also set a lower grade than the records reach, such as L0 for a confirmed human tester. Case notes and provider reports show it beside the computed grades; the note appears in case notes only. A notice's front matter records the admin's grade, which the linter reads for the word "misaligned" ([scope finding](#scope-finding)); its body prints no grade.

## Scope finding

Each cluster carries a computed scope assessment ([SC-FM 15](../manual/15-misalignment.md)): its task class, the target classes reached and the S1 to S7 tests. That pass is a suggestion. The admin records the finding:

```sh
swarmchase case scope <id> --cluster k-3f9a2c1b --finding exceeded --tests S2,S4 --note "relays after a challenge, then SQL injection on the login form: <links>"
swarmchase case scope <id> --cluster C2 --finding in-scope --note "schedule retrieval only"
```

`--finding` is `in-scope`, `exceeded` or `not-assessable`; `--tests` lists the failed tests. The finding is stored by cluster key in `case.toml` and logged. Notices state the admin's finding, and the notice front matter records it for the clusters the notice covers.

"Misaligned" in any form may appear in a report or notice only when every cluster it covers has an admin finding of `exceeded` and the admin's agent grade is L3 or higher ([SC-FM 15.4](../manual/15-misalignment.md#fm-154-stating-a-scope-finding)). Without both, `notice add`, `notice update` and `notice lint` reject it ([lint](notices.md#lint)).

## Fleets

The analysis proposes candidate fleets from soft links between clusters and never merges them ([SC-FM 5.8](../manual/05-linking.md#fm-58-candidate-fleets-merge-and-split)). The admin decides:

```sh
swarmchase case fleet show <id>                          # fleets, and candidates with the command that merges them
swarmchase case fleet merge <id> k-3f9a2c1b k-77d0e2aa [--why "…"]
swarmchase case fleet split <id> k-77d0e2aa [--why "…"]
```

Clusters are named by stable key (or C-number in the case's analysis) and stored as keys under `[[fleet]]` in `case.toml`. A merge takes in any fleet already holding one of the clusters. The decision log records the clusters, the soft links between them with their strength and detail, the candidate fleet that proposed it, the reason, and the command that reverses it. A merge with no soft link between the clusters needs `--why`. A split takes one cluster out; a fleet left with one cluster is dissolved.

Reports then carry a *Fleets* section, with soft-link details in case notes only, and STIX exports a `grouping` per fleet ([STIX export](#stix-export)). `case status` shows each cluster's key, corroboration, fleet and any plant signals ([provenance and plant review](../methodology.md#provenance-and-plant-review)).

## Swarms

A fleet is a swarm only when the case records evidence that its runs interact ([SC-FM 1.3](../manual/01-scope.md#fm-13-groupings)). The analysis lists possible interaction between runs as edges ([SC-FM 5.12](../manual/05-linking.md#fm-512-interaction-edges)); `case fleet show` prints those between a fleet's clusters. None of them makes a swarm. The admin reads the records and records what they show:

```sh
swarmchase case fleet interaction <id> fleet-1 --kind handoff --run C1#1 --run k-77d0e2aa#2 --note "…"
swarmchase case fleet withdraw <id> fleet-1 1 [--why "…"]
```

`--kind` is one of `shared_sink`, `handoff`, `synchronized_start`, `role_sequence` and `disjoint_partition` (or `S1` to `S5`). Each `--run` is `<cluster>#<run>`, a C-number or stable key and the run's number in its cluster, and must belong to the fleet; it is stored by key. `--note` is required. The entry goes under `[[fleet.swarm_evidence]]` with its date, and the decision log records it with the matching analysis edges and the command that withdraws it. Splitting a cluster out of the fleet sets aside the entries that name it.

While a fleet has an entry, reports call it a swarm and list each entry as an Inference (the note in case notes and provider reports only), the notice draft gains a short *Swarm* section naming the clusters and kinds without keys or notes, and the STIX `grouping` is named a swarm. Without one, the grouping is a fleet everywhere and the notice says nothing about it.

## Contacts

`case contacts` first adds the provider directory's channels for every provider a developer or host claim names (by name or alias). It then proposes national CSIRTs ([below](#national-csirts)). Last, it looks up a contact for each endpoint classified compromised, targeted or historical: the first security.txt on the host or its parent domains, else the registrar's abuse address from RDAP. Each domain is read once a run, whether the read succeeds or not, so endpoints under one registered domain (by the Public Suffix List) share its security.txt and RDAP reads. `--providers-only` skips the CSIRTs and the lookups. Each contact has a source link, a confidence and a date.

Unreviewed endpoints are counted and left until classified with `case endpoint`. A host that a relay, carrier or callback rule matches is never read, nor is a parent domain that such a rule matches: an inbox's security.txt would be on the agent's own callback channel. The rules are the case's pinned rules and the current ones, against the host alone and against every host in the case's records (an inbox id on a request catcher matches only in a record).

Each contact has a role: `provider`, `affected` (an operator), `registrar`, `host`, `csirt` or `declared_owner`. A role this toolkit version does not know reads as `other`.

`case contact add <id> --party provider|operator|csirt|declared-owner --org … --channel email|form|portal --address … --source <link>` adds a contact found by hand, such as a sector CSIRT or an authorised test's declared owner; `case contact rm <id> <address>` removes one. `case status` lists a missing provider contact and a missing notice draft under *Needs*.

### The provider directory

[`contacts/providers.toml`](../../contacts/providers.toml) lists the security and abuse channels of AI providers and agent hosts. Each entry records the page its address was read from and the date. `swarmchase contacts list` prints it. `swarmchase contacts verify [--draft <file>]` re-reads every source, reports addresses its source no longer lists, sources that cannot be read and new security.txt contacts, and writes an updated copy for the admin to review and commit. It never changes the directory itself.

### National CSIRTs

[`contacts/csirts.toml`](../../contacts/csirts.toml) lists one national CSIRT per country, each address read from the team's page in [FIRST's team directory](https://www.first.org/members/teams/) on its `verified` date. Teams whose page lists no address, or only a named person's, are left out.

`case contacts` reads each endpoint's country from its host's country-code TLD (`.uk` is GB; `.gov` and `.mil` are US). `--country CC` sets the country for every endpoint, for hosts under generic TLDs such as `.com`. It proposes one contact per team, with role `csirt`, and logs which endpoints it covers. A host with no country, or a country with no team listed, is reported and skipped. A CSIRT is relevant when an operator is public-sector or critical infrastructure, or has no reachable contact ([SC-FM 10](../manual/10-disclosure.md)); remove the others with `case contact rm`.

`swarmchase contacts list --csirts` prints the directory; `swarmchase contacts verify --csirts [--draft <file>]` re-reads every source like the provider directory's check.

## Drafts

`case draft` writes the report for one listed contact into `outbox/`. For an email contact it is an unsent `.eml` with a fresh evidence bundle attached; otherwise it is paste-ready text for a web form or CERT portal. Nothing is ever sent by the tool. After the admin sends a draft, `case sent` records it.

Provider and affected reports end with a *Publication* section: the time the indicator notice is scheduled for, that it will not name or locate the recipient, the time from which the recipient may be named, that both are fixed and not an embargo, how to consent to earlier naming, and that a statement sent for the notice is appended verbatim. The times assume every party not yet sent its report is sent it now; send the drafts as soon as they are read.

## Lead times

The notice follows the reports in two stages, on the fixed clocks in [policies](../policies.md#lead-times). Each clock runs from the latest send to that party, or from its recorded no-contact.

| Party | Indicator notice | Naming |
|---|---|---|
| Provider | 0 hours | Through the developer naming gate |
| Operator of a targeted or historical endpoint | 0 hours | 3 working days, or `--naming-days` |
| Operator of a compromised endpoint | 24 hours | The longer of 10 working days and `--naming-days` |

- **Parties.** Each provider organisation among the case's contacts (or one unnamed provider when there is none), and the operator of each endpoint classified compromised, targeted or historical. A send counts for an operator when its recipient is a contact listed for that endpoint.
- **Send times.** `case sent` records the time of the send: now, or `--at` (RFC 3339, such as `2026-10-12T14:05:00Z`) for a send recorded afterwards. A time in the future is refused. A send recorded with `--date` (`YYYY-MM-DD`; a date that does not parse or is after today is refused) only counts from the end of that day. A `--to` that is none of the case's contacts is recorded with a warning: the send counts for no party until the address is a listed contact.
- **Working days.** The naming clock counts Monday to Friday in UTC. A send on a Saturday or Sunday counts from the following Monday 00:00 UTC; the clock ends at the same UTC time of day once the working days have passed.
- **Lengthening.** `case set <id> --naming-days N`, N from 3 to 20, lengthens the naming lead for the case. Nothing shortens it below the bounds, and nothing changes the indicator clock.
- **Consent.** `case consent <id> --party <p> --note "…"` records an operator's written consent to earlier naming, with how it was given. Its name may then go in the next naming update with no wait.
- **Never naming.** `case naming <id> --party <p> --withhold --reason "…"` records the decision never to name an operator. Naming updates leave it out, and the reason stays in the case log.
- **No contact.** `case no-contact <id> <party> --searched "…"` records what was tried for a party with no contact (an endpoint's host, a provider organisation, or `provider`). It is refused while the case lists a contact for that party. The party then does not hold the indicator notice back, its naming clock runs from the record, and the notice's first update says contact was attempted.
- **Requests.** A recipient's request to delay naming is recorded with `case note`; it changes no clock unless the admin lengthens the lead.

`case status` lists each party's clocks, the time the indicator notice may be added from, and the time each operator may be named from.

## Self-review checklist

`notice add` and `notice update --naming` run a checklist against the case and the stage's draft, print it as a pass/fail list, and write nothing while any item fails. `case checklist <id>` prints it without adding. The items, and what clears each:

| Item | Cleared by |
|---|---|
| Every endpoint classified | `case endpoint` |
| Attribution statements carry a layer, a label and a tag | The draft's generated lines; hand edits keep the form |
| No likelihood word stronger than its label allows | Editing the draft ([SC-FM 8](../manual/08-confidence.md)) |
| No provider in the title below shared identifiers | Editing the draft's `title` |
| "Compromised" only with a recorded basis | `case endpoint <id> <host> compromised --basis "…"` |
| Named organisations described as targets | Editing the draft |
| Submit-anywhere endpoints named only with a reason and the fixed wording | `--single-source-reason "…"`, then `case notice --force` |
| Alternative explanations decided | `case alternative <id> <kind> --rejected "…"` for each kind |
| Clusters with two or more plant signals reviewed | `case plant-review <id> <cluster> --note "…"` |
| Every party sent or recorded without a contact | `case sent`, `case no-contact` |
| The stage's clock has run for each party it covers | Waiting, or `case consent` for naming |
| The draft written after every send | `case notice --force` after the sends |
| A re-read of the exact draft an hour or more after it was written | `case reread` |
| The withholding scan passes | Editing the draft |
| The indicator notice names and locates no affected party | Editing the draft; describe targets by class or `--sector` |
| "Misaligned" only with a scope-exceeded finding and an admin grade of L3 or higher | `case scope`, `case grade`, or editing the draft |
| An approved second review of the current draft | `case review` ([second review](#second-review)) |

The kinds of alternative explanation are `authorised-test`, `honeypot`, `research-scanner`, `spoofed-self-id` and `planted-records`. Only `authorised-test` can be `--accepted` (its owner confirmed it, with the link); the notice must then say it was an authorised test ([SC-FM 10.6](../manual/10-disclosure.md#fm-106-authorised-testing)).

`case notice` records the draft's SHA-256 and the time it was written; `case reread` records the SHA-256 of the draft as it is and the time. Any edit after a re-read changes the hash and needs another re-read. The re-read counts only an hour or more after the draft was written, so a notice is never added within an hour of its draft.

## Second review

Every indicator notice and naming update needs an approved review of the exact draft by a second person before `notice add` or `notice update --naming` writes it. There is no override: with no reviewer available, nothing is published.

```sh
swarmchase case review-packet <id>                 # outbox/review/: notice.md, the checklist output, the internal report
swarmchase case review-packet <id> --naming        # the same for naming.md
swarmchase case review <id> --reviewer "R. Reviewer" --verdict approve --note "read the draft and the internal report"
swarmchase case review <id> --reviewer "R. Reviewer" --verdict object --note "the summary names a university by its city"
```

- **Packet.** `case review-packet` writes the stage's draft, the checklist output and the internal report into `<case>/outbox/review/`, for the admin to hand to the reviewer. Nothing is sent.
- **Record.** `case review` records the reviewer, the time, the verdict, the note, the stage (`indicators` or `naming`) and the SHA-256 of the current draft for that stage (`notice.md` or `naming.md`).
- **Refusals.** A review is refused when the reviewer is the case's admin (compared trimmed and without case) or when the stage's checklist has failing items.
- **Exact draft.** An edit to the draft changes its hash and invalidates the review. An `object` blocks until a later `approve` of the current draft; both stay in the log.
- **Exempt.** Corrections, retractions, replies and status changes need no review.

The published notice says it was reviewed by a second reviewer before publication, without the reviewer's name.

## Evidence bundles

An evidence bundle holds:

- the records;
- their analysis;
- a stamp with the rules version, the toolkit version and commit, the method version it follows (SC-FM), the rules' precision and recall on the committed evaluation set at stamp time, and the tier of every flagged record and cluster;
- a SHA-256 manifest of those files;
- with a signing key, `MANIFEST.sha256.sig`, the manifest's Ed25519 signature ([signed bundles](#signed-bundles)).

`case verify` checks the signature, the manifest, re-runs the analysis and compares both it and the bundle's own `analysis.json` with the stamp. It prints the method version and evaluation figures the stamp carries; bundles stamped before those fields existed verify the same way. The evaluation set is found at `SWARMCHASE_EVAL_DIR`, else `samples/eval/` in the working directory or the checkout the CLI was built from; without it the stamp has no figures. A recipient can run the same check without installing anything, in the browser toolkit's Case tab ([for operators](../guides/for-operators.md#verify-an-evidence-bundle)).

### Signed bundles

Signing is off until `SWARMCHASE_SIGNING_KEY` holds the secret seed ([configuration](configuration.md#bundle-signing)). With it set, `case bundle` and `case draft` write `MANIFEST.sha256.sig` beside the manifest, and the draft attaches it. A value that is not a key fails the bundle rather than leaving it unsigned.

```text
algorithm: ed25519
key-id: <first 16 hex digits of the SHA-256 of the public key>
signature: <Ed25519 signature of the manifest's bytes, base64>
```

`case verify` reads the published keys from `--key`, else `SWARMCHASE_SIGNING_PUBLIC`, else `keys/bundle-signing.pub` in the working directory or the checkout the CLI was built from. That file holds one `ed25519 <base64 key> <key id>` line per key; a retired key stays listed so its bundles keep verifying. The outcome is one of:

| Outcome | Meaning | Check |
|---|---|---|
| `signed by key <id>` | Valid under a published key | Passes |
| `signature invalid` | Altered, malformed, or by a key not published | Fails |
| `unsigned` | No signature file | Passes, and says so |
| `not checked` | Signed, but no published key file | Passes, and says so |

The signature covers every file through the manifest, and the case id through `stamp.json`; it does not cover the email body. The site's showcase bundle is synthetic and never signed.

## Pinned rules

Each case keeps the rules it was opened with in `<data>/rules/<version>.toml`. Its reports, notice draft, exports and bundles use those rules rather than the current ones, so a rules change between drafting and sending cannot silently change a tier. `case rules <id>` shows which records would change tier under the current rules; `--update` re-pins and logs the change.

## STIX export

`case export --format stix` writes the case as a STIX 2.1 bundle (indicators, observed data per cluster, relationships, report) for recipients' tooling. It is scoped like the matching report:

- an affected export carries only that operator's own logs;
- a public export withholds what the notice withholds, names only the hosts the notice names (not the domains or target networks of hosts not classified affected), and is linted.

Ids are deterministic.

Each exported cluster is also an `x-sc-agent-run` object: its cluster key, span and timestamp kind, the SC-T tactics of the rules its records hit (each rule's `tactic`), the artifact families seen, how wide its parallel batches were, its tier, attribution per layer and its `observed-data`. The bundle carries the `extension-definition` (type `new-sdo`) that defines it; the schema is [`schemas/stix/x-sc-agent-run.json`](../../schemas/stix/x-sc-agent-run.json). A public export's runs carry developers through the naming gate and hosts only.

Indicators and runs carry their SC-T tactics as `external_references`, each followed by the MITRE ATLAS and ATT&CK techniques the Field Manual's cross-walk maps it to ([SC-FM 4.6](../manual/04-indicators.md#fm-46-cross-walk-to-mitre-atlas-and-attck)) and the agent-specific ATLAS techniques and OWASP Top 10 for Agentic Applications entries (`ASI01` to `ASI10`) of its crosswalk to agent-security frameworks ([SC-FM 12.4](../manual/12-interoperability.md#fm-124-crosswalk-to-agent-security-frameworks)). Indicators also carry them as `kill_chain_phases` of the `swarmchasing-sc-t` kill chain. The rules carry only the SC-T tactic; the cross-walk is a table in `sc-stix`.

Each case fleet with at least two exported runs is a `grouping` (context `suspicious-activity`) whose `object_refs` are its runs and their `observed-data`, plus a `related-to` relationship between two of its runs for each soft link, named by kind ([SC-FM 12.2](../manual/12-interoperability.md)). Candidate fleets the admin has not merged are not exported.

## MISP export

`case export --format misp` writes the STIX export for the same audience as a MISP event (MISP core format), so it withholds exactly what that export withholds:

- run tags and agent markers as `text` attributes, callback channel domains as `domain` and flagged user agents as `user-agent` (both marked for IDS);
- the observed URLs, domains, client addresses (`ip-src`) and networks (`AS`), not for IDS;
- each agent run as a `swarmchasing-agent-run` object with its cluster key, tier, record count and tactics;
- tags for the export's TLP, `swarmchasing:draft`, and each tactic as a `swarmchasing:tactic` machine tag with galaxy-style tags for its ATLAS and ATT&CK techniques and OWASP entries.

The event is unpublished, with distribution "your organisation only". Sharing it is the admin's decision in their own MISP instance; the tool never connects to one.

## Incident database drafts

`case export --format aiid` drafts an AI Incident Database submission (title, description, date, alleged developer, deployer and harmed parties, the notice as the report, public record links). `--format oecd` drafts the OECD common reporting framework's criteria the case can fill and lists the mandatory ones it cannot (`missing_mandatory`: harm type and severity are the admin's judgment).

The OECD draft also carries an `eu_ai_act_article_73` section: a serious-incident report laid out as Article 73 of the EU AI Act asks of the provider of a high-risk AI system, with the fields the case cannot fill (the system and its classification, the incident category, corrective measures) listed under `missing`. The duty to report under Article 73 rests on that provider, and the case does not establish that the agent is a high-risk system; the section is labelled a draft, not a filing, for the admin to pass to the provider or an authority.

Both drafts follow the naming stage. An affected organisation appears by host only once a published naming update has named it, and until then by its description (`case endpoint --sector`, else "an affected organisation"). Public record links that would show an unnamed operator's host are left out. The draft is refused if its text still identifies an operator no naming update has named. Draft again after each naming update.

All of these are JSON files in `exports/` for the admin to complete and submit by hand after the notice is public ([SC-FM 12.3](../manual/12-interoperability.md#fm-123-ai-incident-databases)); the tool never submits anything.

Both take the public scope: the notice's withholding, developers only through the naming gate with their label and likelihood word, no harness or model-family candidates. They are refused while an endpoint is unreviewed or when the lint finds anything a notice must not carry. The notice link needs `--site-url` (or `SWARMCHASE_SITE_URL`); the text is the committed notice, else the case's draft.

## Operator evidence

`case evidence add` adds logs an affected operator sent back. Only flagged requests, the same clients' other requests and probe chains are kept, redacted; the file itself is not kept, only its SHA-256. Until `case evidence consent` records the operator's agreement, those records appear in private reports only. The operator's side is in [for operators](../guides/for-operators.md#send-logs-back).
