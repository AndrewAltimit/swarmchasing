# Specs

Formats other groups can implement to exchange rules, incidents and reports with this project, each with a JSON Schema, and how a group adopts the method. The method itself is the [Field Manual](../manual/README.md); these pages fix the formats it uses.

| Spec | Covers | Schema |
|---|---|---|
| [SC-Rules v1](rules-v1.md) | The indicator rules file: fields, targets, matching, scoring, conformance vectors. | [`schemas/sc-rules-v1.json`](../../schemas/sc-rules-v1.json) |
| [SC-Incident v1](incident-v1.md) | One JSON document per published incident, public profile only. | [`schemas/sc-incident-v1.json`](../../schemas/sc-incident-v1.json) |
| [SC-Sightings v1](sightings-v1.md) | What a swarm left in one operator's logs, as keyed hashes and scaffold, for matching across operators. | [`schemas/sc-sightings-v1.json`](../../schemas/sc-sightings-v1.json) |
| [SC-Submission v1](submission-v1.md) | An outside report of agent activity, with evidence typed by how it can be checked. | [`schemas/sc-submission-v1.json`](../../schemas/sc-submission-v1.json) |
| [Adopting the method](adopting.md) | What to take, the steps, stating conformance, sharing rules and results. | none |

The STIX 2.1 extension for agent runs is specified in [FM-12.2](../manual/12-interoperability.md#fm-122-the-x-sc-agent-run-extension), with its schema at [`schemas/stix/x-sc-agent-run.json`](../../schemas/stix/x-sc-agent-run.json).

Each spec has a version of its own, independent of the manual's. A minor version adds optional fields or makes a reserved one normative, and keeps earlier documents valid; a major version may change a field's meaning.
