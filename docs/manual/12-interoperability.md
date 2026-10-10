# 12. Interoperability

[Manual index](README.md) · Previous: [11. Notice standard](11-notices.md) · Next: [13. Case study](13-case-study.md)

Findings reach other people's tools in two forms: machine-readable threat intelligence for providers and operators, and entries in AI incident databases. Both are drafts the admin reviews and submits. No tool submits to an outside database or service on its own ([FM-2.4](02-principles.md#fm-24-admin-gate)).

## FM-12.1 STIX 2.1 export profile

A case exports as a [STIX 2.1](references.md#interoperability) bundle. The profile:

| STIX object | Carries |
|---|---|
| `identity` | The reporter. |
| `indicator` | One per run tag, callback channel, agent marker and flagged user agent, with a STIX pattern. |
| `observed-data` | One per cluster: its URLs, domains, addresses and networks as cyber-observable objects, first and last seen, record count. |
| `relationship` | `based-on` from each indicator to the observed data it came from. |
| `report` | Wraps the case, with its title and the objects it references. |
| `marking-definition` | The audience the export is scoped to. |

Rules of the profile:

- **Scoped like the report.** A provider export carries the provider's evidence; an affected-operator export carries only that operator's own logs; a public export withholds what the notice withholds and is linted the same way ([FM-11.4](11-notices.md#fm-114-what-a-notice-withholds)).
- **Deterministic ids.** Object ids are UUIDv5 of the content (cyber-observable ids follow the STIX recipe), so the same case exports byte for byte the same and recipients can de-duplicate.
- **Real values.** STIX patterns hold real, not defanged, values: they are for machines. The public export therefore carries no IP addresses or user agents.
- **Confidence.** An indicator's `confidence` follows the tier of the evidence behind it.

The toolkit implements this profile ([STIX export](../reference/cases.md#stix-export)).

## FM-12.2 The `x-sc-agent-run` extension

STIX has no object for "a run of an autonomous agent". The planned extension defines one as a new STIX Domain Object, through an `extension-definition` with extension type `new-sdo` (STIX 2.1 §7.3). The type name keeps the `x-` prefix, which the specification recommends for objects outside the standard so a future version cannot collide with them.

Planned properties:

| Property | Meaning |
|---|---|
| `cluster_key` | The stable cluster key the run belongs to. |
| `first_seen`, `last_seen` | The run's span. |
| `timestamp_kind` | `request`, `submit` or `capture` ([FM-6.1](06-timing.md#fm-61-timestamp-kinds)). |
| `tactics` | SC-T ids observed, in order of first appearance ([FM-5.9](05-linking.md#fm-59-escalation-sequences)). |
| `artifact_families` | Artifact families observed ([FM-4.5](04-indicators.md#fm-45-artifact-families)). |
| `tier` | The run's evidence tier. |
| `attribution` | Per layer: party or candidate, label, likelihood word, evidence level. |
| `observed_data_refs` | The `observed-data` objects holding its records. |

A fleet is a STIX `grouping` whose `object_refs` list its runs. Soft links between runs are `related-to` relationships whose description names the link type ([FM-5.7](05-linking.md#fm-57-soft-links)). The schema will be published with the extension definition; until then, exports use the standard objects above.

## FM-12.3 AI incident databases

Confirmed incidents may also be submitted to AI incident databases, so they enter the public record on AI harms. The toolkit drafts (`case export --format aiid` and `--format oecd`); the admin submits. A submission links to the published notice, carries only what the notice carries, and is made after the notice is public.

| Database | Its format | What a draft maps |
|---|---|---|
| [AI Incident Database (AIID)](references.md#interoperability) | Reports (title, author, submitter, text, linked incident) attached to incidents (title, date, description, developer, deployer, harmed or nearly harmed parties). | The notice as the report; developer and deployer only at or above the naming gate ([FM-7.8](07-attribution.md#fm-78-the-naming-gate)); affected operators as harmed parties. |
| [OECD AI Incidents and Hazards Monitor (AIM)](references.md#interoperability) | The OECD common reporting framework for AI incidents, 29 criteria. AIM's open submission process is being developed and will follow it. | Incident description, dates, harm type and severity, affected parties, the AI system as attributed. A near miss maps to a hazard. |
| [AI Vulnerability Database (AVID)](references.md#interoperability) | Reports of failure modes, typed by evidence (issue, advisory, measurement, detection), tagged against AVID's taxonomy. | A fleet's behaviour as an advisory (several incidents) or issue (one), with the notice as reference. |

Mapping rules:

- the attribution label and likelihood words travel with every named party;
- a database's field for "AI system" or "developer" gets a model family or harness only as a ranked candidate in free text, never in the structured field ([FM-7.5](07-attribution.md#fm-75-model-family-layer));
- corrections to the notice are sent to each database that holds the incident.
