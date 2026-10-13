# Docs

Every committed doc, by what it is for. The CLI's commands are in the [CLI README](../crates/swarmchase/README.md); each crate has its own README.

## Guides

Task-oriented: how to do one job end to end.

| Doc | Covers |
|---|---|
| [`guides/admin-workflow.md`](guides/admin-workflow.md) | The admin's day: watch digest, review, case, contacts, drafts, send, notice, updates. |
| [`guides/ai-assistance.md`](guides/ai-assistance.md) | Where a model helps (suggestions, triage, rule upkeep, drafting, monitoring), what it may see, what stays human. |
| [`guides/evaluating-leads.md`](guides/evaluating-leads.md) | Labelling leads well: what each label means, deciding a group, the traps, worked examples. |
| [`guides/for-operators.md`](guides/for-operators.md) | For a site that received a report: what it means, telling it is genuine, checking logs, sending logs back, replies, verifying a bundle, private contact. |
| [`guides/for-providers.md`](guides/for-providers.md) | For an AI provider that received a report: what it holds, checking the bundle, STIX and MISP exports, the publication clock, how it is named, replies. |
| [`guides/for-researchers.md`](guides/for-researchers.md) | For outside researchers: the workbench on your own exports, rules and tactics, citing the manual, reproducing the evaluation, what is never shared. |
| [`guides/writing-rules.md`](guides/writing-rules.md) | Adding or changing a rule: fields, weights, links, hard negatives, the evaluation and the gate. |

## Reference

What each part does and how it is configured.

| Doc | Covers |
|---|---|
| [`reference/watch.md`](reference/watch.md) | The data directory, incremental collection, the digest, retention, reviewing leads. |
| [`reference/cases.md`](reference/cases.md) | Case files: `case.toml`, every `case` subcommand, contacts, drafts, bundles, pinned rules, STIX and MISP exports, incident drafts, operator evidence. |
| [`reference/notices.md`](reference/notices.md) | Drafting, adding and updating notices; what they withhold; lint and build. |
| [`reference/evaluation.md`](reference/evaluation.md) | `swarmchase eval`, the CI eval gate and its floors, the held-out measurement. |
| [`reference/browser-toolkit.md`](reference/browser-toolkit.md) | The Pages site: how it is built, each page, the workbench, and how it keeps payloads inert. |
| [`reference/configuration.md`](reference/configuration.md) | `env.list`, environment variables, the urlquery.net key and terms. |
| [`reference/runner.md`](reference/runner.md) | The workflows, secrets and variables, caches outside the checkout, runner requirements. |

## Method and policy

| Doc | Covers |
|---|---|
| [`methodology.md`](methodology.md) | How records become tiers, clusters, hints and claims, and the known limits. |
| [`policies.md`](policies.md) | Collection, attribution, reporting and publication. |
| [`manual/README.md`](manual/README.md) | The Swarmchasing Field Manual (SC-FM): the method as a citable standard, with stable section ids. |

## Specs

Formats other groups can implement, each with a JSON Schema under `schemas/`.

| Doc | Covers |
|---|---|
| [`specs/README.md`](specs/README.md) | Index of the specs and their versions. |
| [`specs/rules-v1.md`](specs/rules-v1.md) | SC-Rules v1: the indicator rules file, scoring semantics and conformance vectors. |
| [`specs/incident-v1.md`](specs/incident-v1.md) | SC-Incident v1: one JSON document per published incident. |
| [`specs/sightings-v1.md`](specs/sightings-v1.md) | SC-Sightings v1: an operator's sightings of a swarm, shared without its logs, and matching across operators. |
| [`specs/adopting.md`](specs/adopting.md) | How another group adopts the method and states conformance. |
| [`schemas/sc-bench-v1.json`](../schemas/sc-bench-v1.json) | SC-Bench v1: a labelled set, by record id, that other detectors are scored against ([evaluation](reference/evaluation.md#sc-bench)). |

## Elsewhere

| Doc | Covers |
|---|---|
| [`CONTRIBUTING.md`](../CONTRIBUTING.md) | The hard rule, the gates, conventions, contributing a rule. |
| [`scripts/README.md`](../scripts/README.md) | Every script and gate, and where each runs. |
| [`samples/eval/README.md`](../samples/eval/README.md) | The labelled evaluation set and the held-out Transluce steps. |
| [`samples/showcase/README.md`](../samples/showcase/README.md) | The synthetic set the landing page walks through. |
