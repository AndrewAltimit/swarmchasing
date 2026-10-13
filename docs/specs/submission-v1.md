# SC-Submission v1: outside swarm reports

[Specs index](README.md) · Schema: [`schemas/sc-submission-v1.json`](../../schemas/sc-submission-v1.json) · Example: [`samples/submissions/`](../../samples/submissions/README.md)

This page specifies one JSON document by which an AI agent, a researcher or an operator reports AI agent activity they saw: a swarm, a fleet, or a single run. The project's inbox takes it in, checks what it can, and puts only significant, hard-to-fabricate evidence in front of the admin. How the inbox handles a document is in the [inbox reference](../reference/inbox.md); the policy is in [policies](../policies.md#outside-submissions). The site's **Report a swarm** page (`submit/`) builds a valid document in the browser and sends nothing.

**Must**, **must not**, **should** and **may** in bold carry their [RFC 2119](../manual/references.md#standards-and-guidance) meanings.

## Status

| Part | Status |
|---|---|
| The format and its schema | Normative. |
| Intake, verification and triage (`swarmchase inbox`) | Implemented. |
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

## Versioning

A minor version adds optional fields; a document valid under 1.0 stays valid. A major version may change a field's meaning. A receiver refuses a field it does not know, so a submitter **should** send the version the receiver states.
