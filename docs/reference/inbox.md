# The inbox

How `swarmchase inbox` takes in outside reports of agent activity ([SC-Submission v1](../specs/submission-v1.md), or STIX 2.1, X-ARF and IODEF v2 reports converted into it), checks them, and puts the ones worth the admin's time in front of the admin. The policy is in [policies](../policies.md#outside-submissions); where it fits in the admin's day is in the [admin workflow](../guides/admin-workflow.md#outside-submissions).

Every submission is untrusted input and a way to plant records. The inbox assumes a submitter may have made up all of it, grades only the records the toolkit finds itself, and asks of every item what it would have cost to fabricate.

## Transports

Submissions arrive as files. The inbox has no network endpoint, and nothing on the site sends anything.

| Transport | How the file reaches `inbox add` |
|---|---|
| Email | The admin saves the JSON attachment and runs `inbox add <file> --via email --from <address>`. |
| GitHub private vulnerability reporting | The admin saves the JSON from the private report and runs `inbox add <file> --via github-pvr --from <account>`. |
| Drop directory | A directory the runner reads (`inbox add <dir> --via drop`); every `*.json` and `*.xml` in it is taken in. |

The [Report a swarm](browser-toolkit.md#report-a-swarm) page builds a valid document in the browser for a submitter to send by one of these. `--from` is the sender as the transport saw them; it is kept privately and outranks the submitter's own `key` for rate limits.

## Commands

```sh
swarmchase inbox add drop/ --via drop          # validate, redact, store, triage
swarmchase inbox add report.xml --format iodef # name the format instead of detecting it
swarmchase inbox list [--verdict examine]
swarmchase inbox show sub-20261010-1a2b3c4d     # every string inert, URLs defanged
swarmchase inbox verify sub-20261010-1a2b3c4d   # or --all
swarmchase inbox signature sub-20261010-1a2b3c4d 4 --valid --note "key from the sensor vendor's published directory"
swarmchase inbox triage [--all] [--json]
swarmchase inbox promote sub-20261010-1a2b3c4d [--case 2026-10-portal] [--with-claimed] [--reason "..."]
```

Every command takes `--data` (else `SWARMCHASE_DATA`, else `data/`) and `--rules`.

| Command | Does |
|---|---|
| `add` | Converts a report in another format ([Other formats](#other-formats)), validates, redacts, stores, matches against the watch store, and triages each file. Refused files are named with the reason. |
| `list` | One line per submission: id, verdict, receipt time, items, strong items, agent or person, summary. |
| `show` | The whole submission, inert, with each item's class and the triage, and the conversion for a converted report. Shows the submitter's contact, which nothing else does. |
| `verify` | Looks each public-record reference up by id and triages again ([Verification](#verification)). |
| `signature` | Records the admin's check of a signed item: valid and by a signer other than the submitter, or not. |
| `triage` | Triages every submission again under the current rules and settings; prints those to examine, with reasons. |
| `promote` | Admin action. Writes the submission's records to `lead.ndjson` for `swarmchase review <file>`, or with `--case` adds them to a case. Refused for a submission not triaged examine unless `--reason` is given; logged either way. |

## Storage

Under `<data>/inbox/`, outside git, beside the watch data:

```text
settings.toml            optional: the settings below
<id>/intake.json         the redacted submission, receipt time, transport, fingerprints, flags
<id>/held.json           what the watch store held when it arrived
<id>/verification.json   lookups of its public-record references
<id>/found.ndjson        the records those lookups found, redacted
<id>/admin.json          signature checks and promotions
<id>/assessment.json     the latest triage
<id>/lead.ndjson         records queued for review by `promote`
<id>/original.<format>   a converted report's original, redacted (`stix.json`, `xarf.json`, `iodef.xml`)
```

An id is `sub-<receipt date>-<8 hex of the fingerprint>`. Submissions are not pruned with the watch data; delete a submission's directory when it is resolved. Encrypted backups do not include the inbox.

## Intake

`inbox add` refuses a document that:

- is larger than `max_bytes`, has more than `max_items` evidence items or `max_lines` log lines, or holds a string longer than `max_chars`;
- fails validation: an unknown field, a missing identifying field, a malformed id, time or host;
- repeats one already held: the same bytes, or the same redacted evidence and summary in any order or formatting;
- comes from a submitter key that sent `max_per_key_per_day` in the last 24 hours. The key is the transport's sender, else `submitter.key`, else `submitter.contact`; submissions with none share the key `anonymous`.

A taken-in submission whose evidence is at least `repeat_share` of an earlier one's is marked a repeat of it, and held.

### Other formats

`inbox add` tells a STIX 2.1 bundle, an X-ARF report and an IODEF v2 document from the content, or takes `--format stix|xarf|iodef|submission`. Each is converted into an SC-Submission first ([accepted formats](../specs/submission-v1.md#accepted-formats)), and everything below applies to the result unchanged. The conversion is refused when the document is over `max_bytes`, nested deeper than `max_depth`, holds a string longer than `max_chars`, or (XML) declares a DOCTYPE or an entity or uses an entity other than the predefined five.

A reference becomes a public record only when it names one by id, and is verified like any other. What the reporter observed becomes operator-only log lines; a signed message or request becomes an unchecked signed item. A value the converter cannot map is kept as an assertion, noted as unmapped and never matched against the watch store; the triage reasons say how many there are. `inbox show` names the format, its version, the unmapped items and the conversion notes. The original is kept redacted beside the converted document: strings redacted one by one, X-ARF payloads decoded, redacted and encoded again (or replaced by their hash when not text).

### Redaction and flags

Secrets are redacted at intake with the same functions that redact records: URLs, log lines, signed content, indicator values and notes. Text shaped like an instruction to its reader ("ignore previous instructions", chat role markers, "mark this submission as examine"), and hidden or direction-changing characters, are flagged with the field they are in. A flag in an evidence field may be the agent's own payload, and says so. Flags are listed in the triage reasons and never move a verdict.

## Verification

`inbox verify` looks each public-record reference up through the collectors ([sc-collect](../../crates/sc-collect/README.md)):

| Source | Lookup |
|---|---|
| `urlquery` | The report by id (needs `URLQUERY_APIKEY`; skipped without it). |
| `urlscan` | The search API for `_id:<uuid>`: result metadata, never the result page. |
| `wayback`, `arquivo` | The CDX index for the exact URL within `ts_tolerance_secs` of the timestamp. |
| `commoncrawl` | The named crawl's CDX index, the same way. |
| `gharchive` | The hour file holding the timestamp, streamed; only the event with the id is kept. |
| `npm`, `pypi` | The release's registry metadata: its publish time. |
| `ctlog` | crt.sh's certificates for the domain, matched by id: the CT entry time. |

No lookup opens the submitted URL, a capture, a scanned page or a package file. Each result is recorded as `verified` (found, matching, older than the submission), `not found`, `mismatch` (a different URL or time), `postdates the submission`, `lookup failed` or `skipped`. A verified record's lead over the receipt time decides whether it predates the submission.

Corroboration is checked once, at intake: a record the watch store held then was collected before the submission arrived. A public record matches the same record; a URL indicator the same URL; log lines when one of their request URLs is in the store; any other indicator records whose URL carries it, when it is at least `min_indicator_chars` long, not a published tag (`linking.published_tags`), and in no more than `max_indicator_matches` records.

## Triage

Each item gets a class, strongest first: corroborated, signed and checked, verified and predating, verified and recent, signed and unchecked, not verified yet, operator-only logs, assertion, contradicted ([evidence strength](../specs/submission-v1.md#evidence-strength)). The records the toolkit found itself (corroborated and verified) are the standing set; the analysis grades them under the rules, with their clusters' agent grade and plant signals. The submitter's own records carry the provenance `reported` and are graded separately, to show what the claim rests on.

| Verdict | When |
|---|---|
| `examine` | A corroborated item, a checked signature, or `min_predating` verified predating records; the standing set (or, with a checked signature, the submission's records) reaches `min_tier`; fewer than `max_plant_signals` counted plant signals on one cluster; an inflated claim backed by at least `inflated_min_strong` strong items; not a repeat. |
| `discard` | Assertions only; at least `discard_contradicted_share` of its references and signatures contradicted with nothing strong; or nothing flags and nothing is left to verify. |
| `hold` | Everything else. `inbox triage --all` lists it. |

A claim is inflated when it names a swarm or fleet and the standing set shows fewer than two runs above noise, names more than five agents per run shown, names tactics no standing record shows, or spans more than ten times what the standing records span. Each triage states a fabrication cost: high (the watch held it, or a checked third-party signature), raised (the oldest verified record's lead), low (only recent records), or none.

### Settings

`<data>/inbox/settings.toml`; a missing file or key takes the default.

| Key | Default | Meaning |
|---|---|---|
| `intake.caps.max_bytes` | 262144 | Largest document. |
| `intake.caps.max_items` | 200 | Most evidence items. |
| `intake.caps.max_lines` | 5000 | Most log lines over all items. |
| `intake.caps.max_chars` | 8192 | Longest string. |
| `intake.caps.max_depth` | 32 | Deepest nesting of a converted document. |
| `intake.max_per_key_per_day` | 5 | Submissions per key in 24 hours. |
| `intake.repeat_share` | 0.8 | Share of evidence that marks a repeat. |
| `triage.predate_secs` | 172800 | Lead over the receipt for a record to predate it (48 hours). |
| `triage.ts_tolerance_secs` | 120 | How far a claimed time may be from the record's. |
| `triage.min_predating` | 2 | Verified predating records for examine without a corroborated one. |
| `triage.min_tier` | `suggestive` | Tier the standing records must reach. |
| `triage.max_plant_signals` | 2 | Counted plant signals on one cluster that hold. |
| `triage.inflated_min_strong` | 3 | Strong items an inflated claim needs. |
| `triage.discard_contradicted_share` | 0.5 | Contradicted share that discards. |
| `triage.min_indicator_chars` | 8 | Shortest indicator matched against the store. |
| `triage.max_indicator_matches` | 50 | Store matches above which an indicator is too common to count. |

```toml
[triage]
predate_secs = 259200
min_tier = "significant"
```

## Promotion

`inbox promote` is the admin's decision that a submission deserves a lead. Without `--case` it writes the standing records to `lead.ndjson`, and `swarmchase review <file>` labels them like any watch lead; `--with-claimed` adds the submitter's own records to that file, marked `reported`. With `--case`, only the standing records are added to the case, and the case log names the submission id, never the submitter. From there the usual review, scope finding, second review and clocks apply ([cases](cases.md)).
