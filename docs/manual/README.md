# Swarmchasing Field Manual (SC-FM 1.0)

Swarmchasing is the practice of finding misaligned or unsupervised AI agents in public records, linking their activity into runs, fleets and swarms, attributing it with stated confidence, and disclosing it to the AI provider, the affected operators and the public at the same time.

This manual is the method as a standard. It is written so that any group can apply it with its own tools, and cite it when it does. The [methodology](../methodology.md) page describes how this repository's toolkit implements it, setting by setting.

## How to cite

Cite the version and the section id:

> SC-FM 1.0 §FM-3.2

Every section heading starts with its id (`FM-<chapter>.<section>`). Ids are stable within a major version:

- an id is never reused for a different meaning;
- a section whose meaning changes gets a new id, and the old one stays as a stub that points to it;
- a minor version (1.1) adds sections and clarifies wording; a major version (2.0) may change requirements.

Tactic ids (`SC-T1` to `SC-T9`, [FM-4.3](04-indicators.md#fm-43-the-sc-t-tactic-taxonomy)) and attribution labels ([FM-7.7](07-attribution.md#fm-77-attribution-labels)) are stable in the same way.

## Requirement words

**Must**, **must not**, **should**, **should not** and **may**, written in bold, carry the meanings that [RFC 2119 and RFC 8174](references.md#standards-and-guidance) give their capitalised forms. The same words in plain text are ordinary English.

A group that applies this manual says which sections it follows and where it departs. A report that cites a section and departs from it says so in the report.

## Tool support

The manual describes the method as a standard. Where this repository's toolkit does not yet implement a part, the section marks it **(planned)**. The method still applies: a practitioner does that step by hand and records it in the case.

## Chapters

| Chapter | Covers |
|---|---|
| [1. Scope and definitions](01-scope.md) | Agent, record, run, cluster, fleet, swarm, incident, case, notice; evidence tiers. |
| [2. Principles](02-principles.md) | The eight rules every step follows. |
| [3. Sources and collection](03-sources.md) | What counts as a public record, the passivity test, source rationale, source biases. |
| [4. Indicators](04-indicators.md) | Rule anatomy, the SC-T tactics, artifact families, ATLAS and ATT&CK cross-walk, rule-writing standard, interaction signals. |
| [5. Linking](05-linking.md) | Hard links, soft links, candidate fleets, merge and split, escalation sequences, reruns, interaction edges. |
| [6. Timing and concurrency](06-timing.md) | Timestamp kinds, cadence, bursts, rhythm, clock offset, stale dates, shared pauses. |
| [7. Attribution](07-attribution.md) | Four attribution layers, the evidence ladder, claim tags, labels, the naming gate, false flags. |
| [8. Confidence language](08-confidence.md) | The words-to-probability table every report uses. |
| [9. Evaluation](09-evaluation.md) | Evaluation sets, metrics, agreement, what to publish with a number, benchmarks. |
| [10. Disclosure](10-disclosure.md) | Parties, simultaneous release, relation to ISO/IEC and FIRST guidance, reply, consent. |
| [11. Notice standard](11-notices.md) | Notice structure, status lifecycle, withholding, lint, corrections. |
| [12. Interoperability](12-interoperability.md) | STIX 2.1 profile, the `x-sc-agent-run` extension, AI incident databases. |
| [13. Case study template](13-case-study.md) | The template, a worked example on synthetic records, and three published incidents read with it. |
| [14. Known limits and traps](14-limits.md) | Conclusions that look sound and are not. |
| [Glossary](glossary.md) | Every defined term, with the section that defines it. |
| [References](references.md) | Every source the manual cites. |

## Relation to the rest of the docs

| Doc | Role |
|---|---|
| [`policies.md`](../policies.md) | This project's policies. The manual's principles ([chapter 2](02-principles.md)) generalise them. |
| [`methodology.md`](../methodology.md) | The toolkit's implementation: settings, thresholds, code. |
| [`guides/admin-workflow.md`](../guides/admin-workflow.md) | The admin's day with this toolkit. |
| [`guides/for-operators.md`](../guides/for-operators.md) | For an operator who received a report. |
| [`guides/for-researchers.md`](../guides/for-researchers.md) | For a researcher applying, citing or checking the method. |
