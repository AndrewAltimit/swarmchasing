# Case files

A case is one incident's working directory under `<data>/cases/<id>/`: its records, `case.toml`, reports, drafts, evidence bundles and exports. Cases never go into git, because an open case names organisations on unconfirmed evidence and private reports carry details that public notices withhold. The day-to-day flow is in the [admin workflow](../guides/admin-workflow.md).

## Opening a case

```sh
swarmchase case new <id> --title "…" --cluster C1 [--record ID] [--host-hits] [files…]
```

`case new` copies the selected records into `raw/records.ndjson`, so watch retention cannot delete them, and writes `case.toml`. Records come from the watch store, or from files given as arguments. `--host-hits` also takes every flagged record on the same hosts, including other clusters. `review` can open a case from a lead too ([review](watch.md#reviewing-leads)).

## What `case.toml` holds

- the case status (`open`, `reported`, `published`, `closed`) and the notice status (`active`, `contained`, `historical`);
- each endpoint and the admin's decision on it: `compromised`, `targeted`, `historical`, `not-affected`, or still `unreviewed`;
- attribution claims established by case work, each with its layer, evidence and tag;
- contacts;
- a dated decision log;
- the reports sent.

Each change is logged with its date.

## Subcommands

| Command | What it does |
|---|---|
| `case status [<id>]` | Lists cases, or shows one case and what it still needs. |
| `case endpoint <id> <host>... <state> [--note …]` | Classifies one or more endpoints; a host not in the case changes nothing. |
| `case rename <id> <new-id>` | Gives a case a new ID, carrying over its watch hits. Refused once its notice is published. |
| `case claim <id> --party … [--layer …] --evidence … [--tag …] --detail …` | Records an attribution claim ([attribution claims](#attribution-claims)). |
| `case set <id> --status … --notice … --min-named …` | Changes the status or the naming threshold. |
| `case note <id> "…"` | Adds a dated entry to the decision log. |
| `case add <id> …` | Adds new records. |
| `case contacts <id> [--providers-only]` | Adds provider contacts from the directory, then finds a contact for each endpoint not marked not-affected ([contacts](#contacts)). |
| `case contact add\|rm <id> …` | Adds or removes a contact by hand ([contacts](#contacts)). |
| `case report <id> --audience …` | Drafts a report into `reports/`, applying the case's claims and naming threshold. |
| `case draft <id> --audience provider\|affected --to <contact>` | Writes the report for one listed contact into `outbox/` ([drafts](#drafts)). |
| `case bundle <id>` | Writes an evidence bundle without drafting a report. |
| `case verify <bundle>` | Checks the manifest, re-runs the analysis and fails if any tier or cluster differs. |
| `case sent <id> --to … --channel …` | Records a send the admin made, and moves an open case to reported. |
| `case notice <id>` | Drafts the public notice into `notice.md` ([notices](notices.md)). |
| `case rules <id> [--update]` | Shows the pinned rules version against the current one and the records whose tier would change. |
| `case export <id> --format stix --audience … [--to <contact>]` | Writes the case as a STIX 2.1 bundle ([STIX export](#stix-export)). |
| `case evidence add <id> <log> --org … --host …` | Adds logs an affected operator sent back ([operator evidence](#operator-evidence)). |
| `case evidence consent <id> <eid> --how …` | Records the operator's agreement to the notice using its logs; `withdraw` reverses it. |

## Attribution claims

A claim is about one of four layers ([SC-FM 7.1](../manual/07-attribution.md#fm-71-four-layers)): `developer` (the default), `host`, `harness` or `model_family`. Developer and host claims need `--evidence` on the ladder; `--tag observed|documented|inference|conclusion` overrides the derived tag. A model-family claim needs `--likelihood`, `--accuracy` (the method's, on a held-out set) and `--corpus-size`, and is refused without them.

Each claim's label (Confirmed, Suspected, Possible, Unattributed) follows from its layer and evidence ([SC-FM 7.7](../manual/07-attribution.md#fm-77-attribution-labels)). The records add their own claims on every report: self-identified developers, client networks and runtime markers as hosts, and harness candidates from user agents and header and encoding fingerprints. Harness and model-family candidates are ranked in private reports and never named in a notice or a public export, whatever their evidence. Case files written before layers and tags existed read unchanged.

## Contacts

`case contacts` first adds the provider directory's channels for every provider a developer or host claim names (by name or alias). It then looks up a contact for each endpoint not marked not-affected: the first security.txt on the host or its parent domains, else the registrar's abuse address from RDAP. `--providers-only` skips the lookups. Each contact has a source link, a confidence and a date.

`case contact add <id> --party provider|operator|csirt|declared-owner --org … --channel email|form|portal --address … --source <link>` adds a contact found by hand, such as a CSIRT from the [FIRST directory](../manual/references.md#disclosure) or an authorised test's declared owner; `case contact rm <id> <address>` removes one. `case status` lists a missing provider contact and a missing notice draft under *Needs*.

### The provider directory

[`contacts/providers.toml`](../../contacts/providers.toml) lists the security and abuse channels of AI providers and agent hosts. Each entry records the page its address was read from and the date. `swarmchase contacts list` prints it. `swarmchase contacts verify [--draft <file>]` re-reads every source, reports addresses its source no longer lists, sources that cannot be read and new security.txt contacts, and writes an updated copy for the admin to review and commit. It never changes the directory itself.

## Drafts

`case draft` writes the report for one listed contact into `outbox/`. For an email contact it is an unsent `.eml` with a fresh evidence bundle attached; otherwise it is paste-ready text for a web form or CERT portal. Nothing is ever sent by the tool. After the admin sends a draft, `case sent` records it.

## Evidence bundles

An evidence bundle holds:

- the records;
- their analysis;
- a stamp with the rules version, the toolkit version and commit, the method version it follows (SC-FM), the rules' precision and recall on the committed evaluation set at stamp time, and the tier of every flagged record and cluster;
- a SHA-256 manifest of those files.

`case verify` checks the manifest, re-runs the analysis and compares both it and the bundle's own `analysis.json` with the stamp. It prints the method version and evaluation figures the stamp carries; bundles stamped before those fields existed verify the same way. The evaluation set is found at `SWARMCHASE_EVAL_DIR`, else `samples/eval/` in the working directory or the checkout the CLI was built from; without it the stamp has no figures. A recipient can run the same check without installing anything, in the browser toolkit's Case tab ([for operators](../guides/for-operators.md#verify-an-evidence-bundle)).

## Pinned rules

Each case keeps the rules it was opened with in `<data>/rules/<version>.toml`. Its reports, notice draft, exports and bundles use those rules rather than the current ones, so a rules change between drafting and sending cannot silently change a tier. `case rules <id>` shows which records would change tier under the current rules; `--update` re-pins and logs the change.

## STIX export

`case export --format stix` writes the case as a STIX 2.1 bundle (indicators, observed data per cluster, relationships, report) for recipients' tooling. It is scoped like the matching report:

- an affected export carries only that operator's own logs;
- a public export withholds what the notice withholds and is linted.

Ids are deterministic.

## Operator evidence

`case evidence add` adds logs an affected operator sent back. Only flagged requests, the same clients' other requests and probe chains are kept, redacted; the file itself is not kept, only its SHA-256. Until `case evidence consent` records the operator's agreement, those records appear in private reports only. The operator's side is in [for operators](../guides/for-operators.md#send-logs-back).
