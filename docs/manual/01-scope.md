# 1. Scope and definitions

[Manual index](README.md) · Next: [2. Principles](02-principles.md)

## FM-1.1 Scope

This manual covers the observation of AI agent activity that crosses the public internet and leaves traces in public records. It covers finding that activity, linking it, attributing it, and disclosing it.

It applies to agents whose activity is **misaligned** (the agent pursues a goal by means its operator or the affected party would not sanction, such as probing for vulnerabilities while on a research task) or **unsupervised** (the activity continues with no sign of a person checking it). Both are findings with their own evidence, made by the scope assessment ([chapter 15](15-misalignment.md)), not read off a tier. It does not cover:

- red-teaming, jailbreaking or otherwise interacting with an agent or model;
- private telemetry, such as a provider's own logs, except where a provider or operator supplies it for a case ([FM-10.7](10-disclosure.md#fm-107-operator-supplied-logs));
- the safety evaluation of models in a lab.

## FM-1.2 Units of observation

| Term | Definition |
|---|---|
| **Agent** | A software system in which a model chooses actions, such as tool calls and HTTP requests, toward a goal, with some autonomy over which action comes next. |
| **Request** | One action an agent takes that reaches a third party: an HTTP request, a scan submission, an account sign-up, a package publish. |
| **Record** | A public, third-party trace of a request: a scan-service report, an archive index row, a certificate log entry, registry metadata, a public event. A record is evidence that the request happened; it is not the request. |
| **Timestamp kind** | What a record's time measures: the request itself, an archive capture, or a scan submission ([FM-6.1](06-timing.md#fm-61-timestamp-kinds)). |
| **Indicator** | A rule that matches a feature of a record and contributes to its grade ([chapter 4](04-indicators.md)). |
| **Link feature** | A matched value that only one operator would plausibly hold, such as a per-user callback inbox or a run tag ([FM-5.2](05-linking.md#fm-52-shared-link-features)). |

## FM-1.3 Groupings

From the smallest to the largest:

| Term | Definition |
|---|---|
| **Run** | Records of one cluster with no gap between consecutive records longer than a set run gap. A run approximates one working session of one agent or one batch. |
| **Cluster** | Records joined by hard links ([FM-5.1](05-linking.md#fm-51-hard-and-soft-links)). A cluster is a machine grouping and claims only that its records share the evidence that joined them. |
| **Candidate fleet** | Two or more clusters joined by soft links and awaiting a decision. A candidate fleet is never treated as one operator until it is merged ([FM-5.8](05-linking.md#fm-58-candidate-fleets-merge-and-split)). |
| **Fleet** | Clusters that a reviewer merged, on recorded evidence, as one operator's agents doing the same kind of task in parallel or in sequence. |
| **Swarm** | A fleet with evidence that its agents interact: they exchange information, divide work, or act on each other's output ([SC-T9](04-indicators.md#fm-43-the-sc-t-tactic-taxonomy)). |

**Fleet or swarm.** Many agents doing the same thing do not make a swarm. A report calls a grouping a swarm only when it cites evidence of interaction, such as one run reading what another wrote to a shared artifact, targets divided without overlap across runs that started together, or one run handing a lead to another. Without such evidence it is a fleet. This follows the distinction drawn in published fleet reporting ([swarmcha.se](references.md#incident-reports)) and the separate treatment of agent communication (AML.T0118) and orchestration (AML.T0124) in [MITRE ATLAS](references.md#threat-frameworks).

The evidence is a reviewer's reading of the records, not a detector's output. The signals that point to interaction ([FM-4.10](04-indicators.md#fm-410-interaction-signals)) are each weak or moderate, and each has an innocent explanation, so a swarm claim rests on several of them together, is tagged Inference ([FM-7.6](07-attribution.md#fm-76-claim-tags)) and lists them. Toolkit: the analysis lists possible interaction as edges between runs and never calls anything a swarm; a case fleet becomes a swarm, in reports, the notice and exports, only once the admin records the interaction they reviewed, and stops being one when that record is withdrawn ([cases](../reference/cases.md#swarms)).

## FM-1.4 Casework terms

| Term | Definition |
|---|---|
| **Lead** | A cluster or candidate fleet that no reviewer has yet examined. |
| **Incident** | Agent activity that a reviewer has confirmed and judged to harm, or put at risk, at least one affected operator. |
| **Case** | The private working file for one incident: its records, decisions, claims, contacts, drafts and sends ([FM-10.8](10-disclosure.md#fm-108-the-admin-gate-and-the-case-record)). |
| **Affected operator** | The organisation that runs a host the agents targeted. |
| **Provider** | The organisation whose model or agent product is attributed as the source, at the strength stated ([chapter 7](07-attribution.md)). |
| **Admin** | The person who decides what is true, and who sends reports and publishes notices. Tools and assistants draft; the admin decides ([FM-2.4](02-principles.md#fm-24-admin-gate)). |
| **Report** | A private message to one party about an incident, with the evidence that party may receive. |
| **Notice** | The public page for one incident ([chapter 11](11-notices.md)). |

## FM-1.5 Evidence tiers

Each record, and each cluster, is graded into one tier:

| Tier | Meaning |
|---|---|
| **Significant** | An unambiguous indicator fired (such as an attack payload), or the record's score reached the significant threshold ([FM-4.11](04-indicators.md#fm-411-independence-groups-and-the-context-cap)). |
| **Suggestive** | The record's score reached the suggestive threshold. |
| **Noise** | Anything below; including records with some weight. |

A tier says how strongly a record's contents look like agent activity under the rules: payloads, programs, channels, residue. It does not say who sent it, whether an agent was present ([FM-7.10](07-attribution.md#fm-710-agent-likelihood)), whether the activity went beyond its task ([FM-15.1](15-misalignment.md#fm-151-four-questions)), or that the request succeeded. A cluster's tier is the highest tier among its members, raised one step only when independent members corroborate each other ([FM-14.9](14-limits.md#fm-149-stacking-across-a-cluster)).

The tier names match those in the [Transluce release](references.md#incident-reports), so results can be compared against its labels.

## FM-1.6 Evidence classes in a claim

Every statement in a report or notice is one of four kinds ([FM-7.6](07-attribution.md#fm-76-claim-tags)): **Observed** (in a record), **Documented** (in a cited public source), **Inference** (reasoned from the first two), **Conclusion** (the judgment the report rests on). Attribution adds a label (**Confirmed**, **Suspected**, **Possible**; [FM-7.7](07-attribution.md#fm-77-attribution-labels)) and likelihood words from [chapter 8](08-confidence.md).
