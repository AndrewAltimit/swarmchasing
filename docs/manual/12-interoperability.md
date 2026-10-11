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

STIX has no object for "a run of an autonomous agent". The extension defines one as a new STIX Domain Object, through an `extension-definition` with extension type `new-sdo` (STIX 2.1, section 7.3). The type name keeps the `x-` prefix, which the specification recommends for objects outside the standard so a future version cannot collide with them.

Properties:

| Property | Meaning |
|---|---|
| `cluster_key` | The stable cluster key the run belongs to. |
| `first_seen`, `last_seen` | The run's span. |
| `timestamp_kind` | `request`, `submit`, `capture` or `unknown`, or `mixed` ([FM-6.1](06-timing.md#fm-61-timestamp-kinds)). |
| `tactics` | SC-T ids observed, in order of first appearance ([FM-5.9](05-linking.md#fm-59-escalation-sequences)). |
| `artifact_families` | Artifact families observed ([FM-4.5](04-indicators.md#fm-45-artifact-families)). |
| `concurrency` | Parallel batches, their modal and largest width, and the number of runs ([FM-6.3](06-timing.md#fm-63-concurrency-and-fan-out)). |
| `tier` | The run's evidence tier. |
| `record_count` | How many records the run holds. |
| `attribution` | Per layer: party or candidate, label, likelihood word, evidence level. |
| `observed_data_refs` | The `observed-data` objects holding its records. |

The extension is version 1.1.0. The toolkit writes one run object per exported cluster, so `concurrency.runs` counts the runs inside it. The JSON schema is committed at [`schemas/stix/x-sc-agent-run.json`](../../schemas/stix/x-sc-agent-run.json), and every export carries the `extension-definition` that points to it.

Runs and indicators carry their tactics twice more, for tools that do not read the extension: as `external_references`, each SC-T id followed by the ATLAS, ATT&CK and OWASP entries the crosswalk maps it to ([FM-12.4](#fm-124-crosswalk-to-agent-security-frameworks)), and, on indicators, as `kill_chain_phases` of the `swarmchasing-sc-t` kill chain.

The same bundle also exports as a MISP event (`case export <id> --format misp`), with the tactics and crosswalk entries as tags; it withholds exactly what the STIX export for that audience withholds ([MISP export](../reference/cases.md#misp-export)). A public export's `attribution` carries developers through the naming gate and hosts only.

A merged fleet as a STIX `grouping` whose `object_refs` list its runs, and soft links between runs as `related-to` relationships whose description names the link type ([FM-5.7](05-linking.md#fm-57-soft-links)), are built.

## FM-12.3 AI incident databases

Confirmed incidents may also be submitted to AI incident databases, so they enter the public record on AI harms. The toolkit drafts (`case export --format aiid` and `--format oecd`); the admin submits. The OECD draft also carries a serious-incident section laid out as Article 73 of the EU AI Act asks ([FM-12.5](#fm-125-regulatory-incident-reports)), with what the case cannot fill listed. A submission links to the published notice, carries only what the notice carries, and is made after the notice is public.

| Database | Its format | What a draft maps |
|---|---|---|
| [AI Incident Database (AIID)](references.md#interoperability) | Reports (title, author, submitter, text, linked incident) attached to incidents (title, date, description, developer, deployer, harmed or nearly harmed parties). | The notice as the report; developer and deployer only at or above the naming gate ([FM-7.8](07-attribution.md#fm-78-the-naming-gate)); affected operators as harmed parties. |
| [OECD AI Incidents and Hazards Monitor (AIM)](references.md#interoperability) | The OECD common reporting framework for AI incidents, 29 criteria. AIM's open submission process is being developed and will follow it. | Incident description, dates, harm type and severity, affected parties, the AI system as attributed. A near miss maps to a hazard. |
| [AI Vulnerability Database (AVID)](references.md#interoperability) | Reports of failure modes, typed by evidence (issue, advisory, measurement, detection), tagged against AVID's taxonomy. | A fleet's behaviour as an advisory (several incidents) or issue (one), with the notice as reference. |

Mapping rules:

- the attribution label and likelihood words travel with every named party;
- a database's field for "AI system" or "developer" gets a model family or harness only as a ranked candidate in free text, never in the structured field ([FM-7.5](07-attribution.md#fm-75-model-family-layer));
- corrections to the notice are sent to each database that holds the incident.

## FM-12.4 Crosswalk to agent-security frameworks

Groups that receive a report file it under their own vocabularies. The tables below say where each swarmchasing term lands, so a finding keeps its meaning when it moves. A mapping says what the agent did, in the other framework's words; it never says that anyone intended it ([FM-4.6](04-indicators.md#fm-46-cross-walk-to-mitre-atlas-and-attck)).

**Tactics.** The [OWASP Top 10 for Agentic Applications](references.md#threat-frameworks) names risks in the systems that build agents (ASI01 to ASI10); a column entry is the risk which, realised, produces the behaviour. The ATLAS column adds the agent-specific techniques to the mapping in [FM-4.6](04-indicators.md#fm-46-cross-walk-to-mitre-atlas-and-attck); ids are from ATLAS data version 2026.09.

| SC-T | OWASP ASI | ATLAS, agent techniques |
|---|---|---|
| SC-T1 Task retrieval | none | AML.T0116 Autonomous Reconnaissance |
| SC-T2 Tool escalation | ASI02 Tool Misuse and Exploitation; ASI05 Unexpected Code Execution | AML.T0053 AI Agent Tool Invocation; AML.T0117 Autonomous Attack-Path Adaptation |
| SC-T3 Access-control circumvention | ASI02 Tool Misuse and Exploitation | AML.T0117 Autonomous Attack-Path Adaptation |
| SC-T4 Vulnerability probing | ASI10 Rogue Agents; ASI01 Agent Goal Hijack, when injected content set the goal | AML.T0049 Exploit Public-Facing Application; AML.T0006 Active Scanning |
| SC-T5 Account and identity acquisition | ASI03 Identity and Privilege Abuse | AML.T0021 Establish Accounts; AML.T0125 Create Account |
| SC-T6 Credential reuse | ASI03 Identity and Privilege Abuse | AML.T0012 Valid Accounts; AML.T0091 Use Alternate Authentication Material |
| SC-T7 Callback and side channels | ASI02 Tool Misuse and Exploitation | AML.T0086 Exfiltration via AI Agent Tool Invocation; AML.T0072 Cyber Communication Channel |
| SC-T8 Off-task targets | ASI01 Agent Goal Hijack; ASI10 Rogue Agents | none |
| SC-T9 Inter-agent coordination | ASI07 Insecure Inter-Agent Communication; ASI08 Cascading Failures | AML.T0118 Autonomous AI Agent Communication; AML.T0124 Autonomous Attack Orchestration |

OWASP and ATLAS describe the agent's builder or an adversary using it. From public records the method cannot tell an agent whose goal was hijacked (ASI01) from one that drifted (ASI10) or one that was told to do it; the scope assessment ([chapter 15](15-misalignment.md)) records the behaviour, and the cause stays an open hypothesis ([FM-7.12](07-attribution.md#fm-712-competing-hypotheses)).

**Fields.** Where each incident field goes in the common exchange formats. The incident fields are those of [SC-Incident v1](../specs/incident-v1.md).

| SC-Incident field | STIX 2.1 ([FM-12.1](#fm-121-stix-21-export-profile)) | MISP | OECD framework dimension | AIID |
|---|---|---|---|---|
| `id`, `title` | `report.name` | Event `info` | Metadata | Incident title |
| `published`, `updated` | `report.published`, `modified` | Event `date` | Metadata | Incident date |
| `status` | `report` label | Event tag | Other information | Description |
| `affected` (hosts) | `domain-name` objects | `domain` attributes | Harm details; People and planet | Harmed parties |
| `sector` | `identity.sectors` | Event tag | Economic context | Harmed parties |
| `providers`, `attribution` | `x-sc-agent-run.attribution` | Event tag with label | AI model | Developer and deployer |
| `tactics` | `x-sc-agent-run.tactics` | Event tags (`swarmchasing:tactic="SC-T4"`) | Task and output | Description |
| `tier`, `agent_grade` | `indicator.confidence`; run `tier` | Event `threat_level_id` | Harm details | Description |
| `scope` | none | Event tag | Task and output | Description |
| `fleets` | `grouping` | Event per fleet, related | Other information | Linked incidents |
| `method`, `rules_version` | `report` external reference | Event tag | Other information | Report text |

STIX patterns carry real values and MISP attributes do too; a public export or event withholds what a notice withholds ([FM-11.4](11-notices.md#fm-114-what-a-notice-withholds)). Toolkit: STIX, MISP events and the AIID and OECD drafts are built ([FM-12.2](#fm-122-the-x-sc-agent-run-extension), [FM-12.3](#fm-123-ai-incident-databases)); the SC-Incident document is (planned). The export's crosswalk is the two tables, SC-FM 4.6 and this one, and a test fails when it differs from them.

## FM-12.5 Regulatory incident reports

Some recipients of a report have their own reporting duties. Under the EU AI Act, a provider of a high-risk AI system reports a serious incident to the market surveillance authority within fifteen days of becoming aware of it, within two days for a widespread infringement or a serious disruption of critical infrastructure, and within ten days of a death (Article 73, [EU AI Act](references.md#standards-and-guidance)). A swarmchasing report to a provider is not such a report and does not stand in for one, but it can be how the provider becomes aware of an incident. Reports therefore state their date and evidence plainly, so the recipient can judge its own duties.

The OECD draft's Article 73 section ([FM-12.3](#fm-123-ai-incident-databases)) lays the case out in that report's shape for the provider or the authority to use; it does not establish that the agent is a high-risk system.

The method's lead times ([FM-10.2](10-disclosure.md#fm-102-lead-times)) are not set by any regulatory clock and do not wait for one.
