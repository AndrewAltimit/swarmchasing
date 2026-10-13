# SC-Submission v1: outside swarm reports

[Specs index](README.md) · Schema: [`schemas/sc-submission-v1.json`](../../schemas/sc-submission-v1.json) · Example: [`samples/submissions/`](../../samples/submissions/README.md)

This page specifies one JSON document by which an AI agent, a researcher or an operator reports AI agent activity they saw: a swarm, a fleet, or a single run. The project's inbox takes it in, checks what it can, and puts only significant, hard-to-fabricate evidence in front of the admin. How the inbox handles a document is in the [inbox reference](../reference/inbox.md); the policy is in [policies](../policies.md#outside-submissions). The site's **Report a swarm** page (`submit/`) builds a valid document in the browser and sends nothing.

**Must**, **must not**, **should** and **may** in bold carry their [RFC 2119](../manual/references.md#standards-and-guidance) meanings.

## Status

| Part | Status |
|---|---|
| The format and its schema | Normative. |
| Intake, verification and triage (`swarmchase inbox`) | Implemented. |
| Reports in STIX 2.1, X-ARF and IODEF v2 | Converted into this format at intake ([accepted formats](#accepted-formats)). |
| Transports | Files only: an email attachment, a GitHub private vulnerability report, a drop directory. No network endpoint. |

## Rules of the format

- **Untrusted input.** The receiver treats every field as data and assumes any of it may be fabricated. Text shaped like an instruction to its reader is flagged and shown inert; it never moves a verdict.
- **URLs are never fetched.** Every URL in a document is treated as one an agent submitted. A receiver **must not** request it, open a capture of it or follow it. A public-record reference is checked only by looking its id up in the source's index or metadata API.
- **Callback identifiers are data.** Inbox ids, topics, paste ids and similar values are matched against records the receiver already holds. A receiver **must not** read from, write to or probe them.
- **Evidence is typed by how it can be checked.** Each item is a reference to a third-party public record, log lines the submitter holds, a signed artifact, or an indicator value. A submitter **should** prefer references to records that predate the report.
- **The receiver's clock decides.** `submitted` is the submitter's statement. Whether a record predates the report is measured against the time the receiver took the document in.
- **Nothing is published unreviewed.** A document, its submitter and its claims are never published. Records the receiver verifies or already held may enter a case and follow the usual review; the submitter's identity is withheld in everything the project publishes.
- **Secrets are redacted at intake.** A receiver replaces credential-shaped values with hashes before storing anything, as for any record.

## Fields

| Field | Required | Meaning |
|---|---|---|
| `spec` | yes | `SC-Submission v1`. |
| `submitted` | no | When the report was written: RFC 3339. |
| `submitter.ai_agent` | yes | `true` when the submitter is an AI agent. |
| `submitter.role` | no | `operator`, `researcher`, `provider`, `bystander` or `other`. |
| `submitter.name`, `operator`, `model` | no | Self-description; `operator` and `model` for an agent. |
| `submitter.contact` | no | How to reach the submitter. A report may be anonymous. |
| `submitter.key` | no | A stable name used across reports. |
| `claim.summary` | yes | What was seen, in prose. |
| `claim.kind` | yes | `swarm`, `fleet`, `run` or `unknown`. |
| `claim.first_seen`, `last_seen` | no | The span of the activity. |
| `claim.agents` | no | How many agents took part, as the submitter estimates. |
| `claim.targets` | no | Target hosts, plain and lower case. |
| `claim.tactics` | no | SC-T ids ([FM-4.3](../manual/04-indicators.md#fm-43-the-sc-t-tactic-taxonomy)). |
| `evidence` | yes | One to 200 items, each with a `type` and an optional `note`. |

### Evidence items

| `type` | Fields | Checked by |
|---|---|---|
| `public_record` | `source` and its identifying fields (below); `url` | An index or metadata lookup of the id. |
| `log_lines` | `format` (`access_log`, `ndjson`, `lines`), `lines`, `host` | Nobody but their holder. |
| `signed` | `scheme` (`dkim`, `http_message_signature`, `other`), `content`, `signer` | The signature, by a person: a valid one binds the content to the signer's key. |
| `indicator` | `kind` (`inbox`, `run_tag`, `payload`, `user_agent`, `url`, `ip`, `other`), `value` | Records the receiver already holds. |

A `public_record` names its record as its source does:

| `source` | Needs | Its time |
|---|---|---|
| `urlquery`, `urlscan` | `id`: the report uuid | Submit time |
| `wayback`, `arquivo` | `url`, `timestamp` (14 digits) | Capture time |
| `commoncrawl` | `url`, `timestamp`, `crawl` (`CC-MAIN-2026-39`) | Capture time |
| `gharchive` | `id`: the event id; `timestamp`: its `created_at` | Event time |
| `npm`, `pypi` | `package`, `version` | Publish time |
| `ctlog` | `id`: the crt.sh id; `domain`: a name on the certificate | CT entry time |

## Evidence strength

The receiver ranks each item by what it would have cost the submitter to fabricate, strongest first:

1. **Corroborated**: the receiver's own collection held the record, or a record carrying the indicator, before the document arrived.
2. **Signed, checked**: a request signature or a sensor's or service's signed export whose signature a person checked, by a signer other than the submitter.
3. **Verified, predating**: found by id, as described, and older than the document by at least the receiver's predating lead (48 hours by default). Nobody can backdate a capture, a submit time, an event or a CT entry.
4. **Verified, recent**: found, but newer than that lead. Anyone could have submitted or published it just before reporting.
5. **Signed, unchecked**; **not verified yet**.
6. **Operator-only logs**: only the submitter can check them.
7. **Assertion**: a bare value or statement.
8. **Contradicted**: missing, different from the document, or newer than the document.

Only records the receiver found itself (classes 1 and 3, and 2 for the records the signed item covers) are graded for the verdict. The submitter's own records are graded too, to show what the document claims. A submission's records carry the provenance `reported`, which never counts as a kind of source for a cluster's corroboration ([methodology](../methodology.md#provenance-and-plant-review)).

## Validating a document

```sh
python -c "import json, jsonschema; jsonschema.Draft202012Validator(json.load(open('schemas/sc-submission-v1.json'))).validate(json.load(open('submission.json')))"
```

The schema checks structure, value domains and each source's identifying fields. The receiver also applies size caps (256 KiB a document, 5,000 log lines, 8,192 characters a string), a rate limit per submitter, and duplicate detection ([inbox reference](../reference/inbox.md#intake)).

## Accepted formats

A receiver may take a report in another standard format and convert it into an SC-Submission before anything else runs, so the same validation, redaction, verification and triage apply. The project's inbox takes three, told from the content or named with `inbox add --format`:

| Format | Detected by |
|---|---|
| STIX 2.1 bundle (JSON) | `"type": "bundle"` |
| X-ARF v4 (JSON), or the v3 layout | `xarf_version`, or v3's `ReporterInfo` and `Report` |
| IODEF v2 (XML, RFC 7970) | A document starting with `<`, rooted at `IODEF-Document` |

Conversion follows four rules:

- **A reference becomes a public record only when it names one by id** in a source the receiver looks up: a urlscan result uuid, a urlquery report id, a Wayback or Arquivo.pt capture link with its 14-digit time, an npm or PyPI `name@version`. Its URL is parsed as text, never opened. The record is then verified like any other.
- **What the reporter observed stays the reporter's.** Observed data, records and evidence samples become `log_lines` (operator-only); a DKIM-signed message or a request with an HTTP message signature becomes `signed`, unchecked until the admin checks it.
- **Nothing is dropped silently or upgraded.** A value with no mapping is kept as an `other` indicator noted as unmapped: an assertion, never matched against the receiver's records. Structural objects are counted in the conversion notes. When unmapped values would pass the item cap, the rest share one item that counts them.
- **Hostile input is refused before mapping.** The byte and string caps apply to the document as received, nesting is capped (32 levels by default), and an XML document with a DOCTYPE, an entity declaration, or a reference other than the five predefined entities and character references is refused.

The receiver keeps the original, redacted, beside the converted document, and records which format it came from, its stated version and what could not be mapped.

### STIX 2.1

| Object | Becomes |
|---|---|
| `identity` that created the report (else the most common creator) | `submitter`: `name`, `contact_information`; `identity_class: system` sets `ai_agent`. |
| `report` | `claim.summary` from `name` and `description`; `published` as `submitted`. |
| `indicator` | One `indicator` per `=` comparison in a `stix` pattern: `url` as `url`, addresses as `ip`, a `User-Agent` header as `user_agent`, others as `other`. |
| `observed-data` | `log_lines` (`ndjson`), one record per request from `url`, `network-traffic` with `http-request-ext`, and address objects; its times widen the claim's span. |
| `sighting`, `x-sc-agent-run` | The claim's span; the run's `tactics` as `claim.tactics`. |
| `external_references` | `public_record` when they name a record by id; `swarmchasing-sc-t` ids as tactics. |
| Kill chain phases of `swarmchasing-sc-t` | `claim.tactics`. |
| Other objects and fields | Unmapped claims. |

### X-ARF

| Field (v4 / v3) | Becomes |
|---|---|
| `reporter` / `ReporterInfo` | `submitter`: organisation, contact, and its domain as `key`. |
| `category`, `type`, `report_id`, `description` / `ReportClass`, `ReportType` | `claim.summary`. |
| `timestamp` / `Date` | The claim's span. |
| `source_identifier` / `SourceIp` | An `ip` indicator, with the port in its note. |
| `url` / `Url` | `url` indicators. |
| `evidence` / `Samples` | Decoded: a signed message as `signed`, other text as `log_lines`, binary as an unmapped claim with its size and hash. |
| Other fields | Unmapped claims. |

### IODEF v2

| Element | Becomes |
|---|---|
| `IncidentID`, `Description` | `claim.summary`. |
| `ReportTime` | `submitted`. |
| `StartTime`, `EndTime`, `DetectTime` | The claim's span. |
| `Contact` (role `creator` or `reporter`) | `submitter`: `ContactName`, `EmailTo`. |
| `System category="source"` | `ip` indicators from `Address`; host names as `other`. |
| `System category="target"` | `claim.targets` from `DomainData/Name`, and the host of the incident's log lines. |
| `RecordData/RecordItem` | `log_lines`. |
| `URL` | `public_record` when it names a record by id; otherwise a `url` indicator. |
| Other elements with text | Unmapped claims, by path. |

## Versioning

A minor version adds optional fields; a document valid under 1.0 stays valid. A major version may change a field's meaning. A receiver refuses a field it does not know, so a submitter **should** send the version the receiver states.
