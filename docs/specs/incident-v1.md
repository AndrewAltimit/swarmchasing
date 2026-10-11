# SC-Incident v1: incident interchange format

[Specs index](README.md) · Schema: [`schemas/sc-incident-v1.json`](../../schemas/sc-incident-v1.json)

This page specifies one JSON document per published incident, so that other groups, incident databases and feeds can read an incident without parsing a notice page. It carries what the public notice carries, as fields, and nothing a notice withholds. The notice it describes follows the [notice standard](../manual/11-notices.md).

**Must**, **must not**, **should** and **may** in bold carry their [RFC 2119](../manual/references.md#standards-and-guidance) meanings.

## Status

| Part | Status |
|---|---|
| The format and its schema | Normative. |
| A toolkit export of the document | Planned. Today the same facts are in the notice front matter, the case file and the STIX export. |

## Rules of the format

- **Public profile only.** A document **must not** carry anything the notice withholds ([FM-11.4](../manual/11-notices.md#fm-114-what-a-notice-withholds)): channel identifiers, credentials, the attack details of a compromised endpoint, personal data, operator logs without consent, or content from a source whose terms forbid redistribution. A document is produced after the notice is public, and is linted as the notice is.
- **Plain hosts, defanged display.** Host names are plain, for machines. Anything that shows them to a person defangs them (`a[.]b`), and record links are never made clickable.
- **The gate travels with the claim.** An attribution entry carries its layer, evidence level, label and tag. A developer below the naming gate appears only as `named_as: notified`. Harness and model-family candidates are never in the document ([FM-7.8](../manual/07-attribution.md#fm-78-the-naming-gate)).
- **Words within their caps.** A likelihood word is absent for Unattributed and never stronger than its label allows ([FM-7.7](../manual/07-attribution.md#fm-77-attribution-labels)); the schema enforces both.
- **Measured grades only.** `agent_grade` appears only with a reference to its held-out measurement ([FM-7.10](../manual/07-attribution.md#fm-710-agent-likelihood)).
- **Append-only updates.** `updates` are in date order, oldest first; the first is `published`, and a `reply` names who it is from. A later document for the same id keeps every earlier update ([FM-11.6](../manual/11-notices.md#fm-116-corrections-and-retractions)).

## Fields

| Field | Required | Meaning | Source in this toolkit |
|---|---|---|---|
| `spec` | yes | `SC-Incident v1`. | constant |
| `id` | yes | The notice id, a slug. | notice `id` |
| `title` | yes | The notice title. | notice `title` |
| `url` | no | The published notice. | site address |
| `status` | yes | `active`, `contained` or `historical` ([FM-11.3](../manual/11-notices.md#fm-113-status-lifecycle)). | notice `status` |
| `retracted` | no | The central claim was withdrawn. | a `retraction` update |
| `published`, `updated` | yes | Dates, `YYYY-MM-DD`. | notice `published`, `updated` |
| `sector` | no | The affected operators' sector, from a fixed list. | notice `sector` |
| `method` | yes | The Field Manual version, `SC-FM 1.1`. | the toolkit's method stamp |
| `departures` | no | Manual sections not followed, with what was done. | case notes |
| `rules_version` | yes | The rules version the case is pinned to. | notice `rules_version` |
| `toolkit` | no | The toolkit version. | notice `toolkit` |
| `affected` | yes | Each endpoint's host and state; `single_source` when only submit-anywhere records show it. | case `[[endpoint]]` (`state`, `single_source`); notice `affected` |
| `attribution` | no | Developer and host claims as the notice states them. | case `[[claim]]` and derived claims |
| `tier` | no | The strongest cluster tier. | the analysis |
| `tactics` | no | SC-T tactics, in order of first appearance; T8 and T9 only as findings. | the analysis; reviewer findings |
| `scope` | no | The scope finding and failed tests ([FM-15.4](../manual/15-misalignment.md#fm-154-stating-a-scope-finding)). | case notes |
| `agent_grade` | no | Level and where its measurement is published. | case `agent_grade` |
| `groupings` | no | Fleets and swarms, with aliases and interaction kinds. | case `[[fleet]]` |
| `timeline` | no | Spans, each with its timestamp kind ([FM-6.1](../manual/06-timing.md#fm-61-timestamp-kinds)). | the analysis |
| `withheld` | no | Categories withheld. | the notice's Withheld section |
| `records` | no | Links to public records. | the analysis |
| `updates` | yes | Dated updates: `published`, `update`, `status`, `correction`, `reply`, `retraction`. | notice `[[update]]` |

The `layer` of an attribution entry is `developer` or `host`, matching the case's claim roles. Grouping ids are a case fleet (`fleet-<n>`) or a named fleet (`SCF-<n>`) ([FM-5.13](../manual/05-linking.md#fm-513-cluster-lifecycle-and-identifiers)); a swarm lists at least one interaction kind ([FM-4.10](../manual/04-indicators.md#fm-410-interaction-signals)).

## Mapping to other formats

Where each field goes in STIX 2.1, MISP, the OECD reporting framework and the AI Incident Database is the crosswalk in [FM-12.4](../manual/12-interoperability.md#fm-124-crosswalk-to-agent-security-frameworks). The STIX export carries more detail for machine use ([FM-12.1](../manual/12-interoperability.md#fm-121-stix-21-export-profile)); this document is the summary a feed or a database reads first.

## Validating a document

```sh
python -c "import json, jsonschema; jsonschema.Draft202012Validator(json.load(open('schemas/sc-incident-v1.json')), format_checker=jsonschema.FormatChecker()).validate(json.load(open('incident.json')))"
```

The schema checks structure, value domains, and the caps that are visible in one document: likelihood words against labels, measured grades, swarms with interaction evidence, replies with a sender. It cannot check the withholding rules; the notice lint does ([FM-11.5](../manual/11-notices.md#fm-115-lint)).

## Versioning

A minor version adds optional fields; a document valid under 1.0 stays valid. A major version may change a field's meaning. A consumer **should** ignore a document whose `spec` names a major version it does not know.
