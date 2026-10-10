# Glossary

[Manual index](README.md) · Previous: [14. Known limits](14-limits.md) · Next: [References](references.md)

Each term links to the section that defines it.

| Term | Short definition | Defined in |
|---|---|---|
| Admin | The person who decides, sends and publishes. | [FM-1.4](01-scope.md#fm-14-casework-terms), [FM-2.4](02-principles.md#fm-24-admin-gate) |
| Affected operator | The organisation running a targeted host. | [FM-1.4](01-scope.md#fm-14-casework-terms) |
| Agent | A system in which a model chooses actions toward a goal. | [FM-1.2](01-scope.md#fm-12-units-of-observation) |
| Artifact family | A class of build traces, such as model-output residue. | [FM-4.5](04-indicators.md#fm-45-artifact-families) |
| Attribution label | Confirmed, Suspected, Possible or Unattributed. | [FM-7.7](07-attribution.md#fm-77-attribution-labels) |
| Attribution layer | Developer and operator, hosting, harness, model family. | [FM-7.1](07-attribution.md#fm-71-four-layers) |
| Benchmark target | A public site or environment built to be tested against. | [FM-4.9](04-indicators.md#fm-49-benchmark-targets-and-declared-testing) |
| Burst | Many records each seconds after the last. | [FM-6.2](06-timing.md#fm-62-cadence-bursts-and-pauses) |
| Candidate fleet | Clusters joined by soft links, awaiting a decision. | [FM-1.3](01-scope.md#fm-13-groupings), [FM-5.8](05-linking.md#fm-58-candidate-fleets-merge-and-split) |
| Case | The private working file for one incident. | [FM-1.4](01-scope.md#fm-14-casework-terms), [FM-10.8](10-disclosure.md#fm-108-the-admin-gate-and-the-case-record) |
| Claim tag | Observed, Documented, Inference or Conclusion. | [FM-7.6](07-attribution.md#fm-76-claim-tags) |
| Cluster | Records joined by hard links. | [FM-1.3](01-scope.md#fm-13-groupings) |
| Commonness cap | The limit above which a link feature only soft-links. | [FM-5.2](05-linking.md#fm-52-shared-link-features) |
| Confidence level | High, moderate or low: the basis for a judgment. | [FM-8.2](08-confidence.md#fm-82-confidence-levels) |
| Declared testing | Request text announcing a test; checked, never believed. | [FM-4.9](04-indicators.md#fm-49-benchmark-targets-and-declared-testing), [FM-10.6](10-disclosure.md#fm-106-authorised-testing) |
| Escalation sequence | The order in which tactics appear in a run or fleet. | [FM-5.9](05-linking.md#fm-59-escalation-sequences) |
| Evidence level | A rung of the developer ladder, `self_id` to `provider_confirmed`. | [FM-7.2](07-attribution.md#fm-72-developer-and-operator-ladder) |
| False-merge rate | Share of predicted clusters spanning more than one true group. | [FM-9.6](09-evaluation.md#fm-96-cluster-metrics) |
| Fleet | Clusters merged on evidence as one operator's agents. | [FM-1.3](01-scope.md#fm-13-groupings) |
| Hard link | A link that joins records into a cluster. | [FM-5.1](05-linking.md#fm-51-hard-and-soft-links) |
| Incident | Confirmed agent activity that harms or risks an operator. | [FM-1.4](01-scope.md#fm-14-casework-terms) |
| Indicator | A rule that matches a feature of a record. | [FM-1.2](01-scope.md#fm-12-units-of-observation), [FM-4.2](04-indicators.md#fm-42-rule-anatomy) |
| Lead | A cluster or candidate fleet nobody has reviewed. | [FM-1.4](01-scope.md#fm-14-casework-terms) |
| Likelihood word | A term from the ICD 203 table. | [FM-8.1](08-confidence.md#fm-81-likelihood-table) |
| Link feature | A matched value one operator would hold. | [FM-1.2](01-scope.md#fm-12-units-of-observation), [FM-5.2](05-linking.md#fm-52-shared-link-features) |
| Naming gate | The evidence threshold for naming a developer. | [FM-7.8](07-attribution.md#fm-78-the-naming-gate) |
| Notice | The public page for one incident. | [FM-1.4](01-scope.md#fm-14-casework-terms), [chapter 11](11-notices.md) |
| Passivity test | The conditions every source must pass. | [FM-3.2](03-sources.md#fm-32-passivity-test) |
| Pause | A gap long in absolute terms and against the median gap. | [FM-6.2](06-timing.md#fm-62-cadence-bursts-and-pauses) |
| Probe chain | One client trying variants of one request. | [FM-5.4](05-linking.md#fm-54-probe-chains) |
| Provider | The organisation whose agents are attributed. | [FM-1.4](01-scope.md#fm-14-casework-terms) |
| Public record | A third-party trace of a request, published to anyone. | [FM-3.1](03-sources.md#fm-31-what-counts-as-a-public-record) |
| Published tag | A tag quoted in a public report; never a hard link. | [FM-5.2](05-linking.md#fm-52-shared-link-features), [FM-14.5](14-limits.md#fm-145-tags-get-copied-after-publication) |
| Record | A public trace of one request. | [FM-1.2](01-scope.md#fm-12-units-of-observation) |
| Relay stack | The chain of relays and carriers a request went through. | [FM-4.5](04-indicators.md#fm-45-artifact-families) |
| Rerun | A later run repeating an earlier run's targets in order. | [FM-5.10](05-linking.md#fm-510-reruns) |
| Rhythm | A cluster's hour-of-day profile. | [FM-6.4](06-timing.md#fm-64-rhythm) |
| Run | Records of a cluster with no gap longer than the run gap. | [FM-1.3](01-scope.md#fm-13-groupings), [FM-5.5](05-linking.md#fm-55-runs) |
| SC-T | The swarmchasing tactic ids, SC-T1 to SC-T9. | [FM-4.3](04-indicators.md#fm-43-the-sc-t-tactic-taxonomy) |
| Shared pause | Two clusters going quiet together beyond chance. | [FM-6.7](06-timing.md#fm-67-shared-pauses) |
| Soft link | A proposed link between clusters; never joins them. | [FM-5.1](05-linking.md#fm-51-hard-and-soft-links), [FM-5.7](05-linking.md#fm-57-soft-links) |
| Stale date | A "today" tag well behind the observed date. | [FM-6.6](06-timing.md#fm-66-stale-dates) |
| Stale knowledge | Retired endpoints or old clients a model still writes. | [FM-4.5](04-indicators.md#fm-45-artifact-families) |
| Swarm | A fleet with evidence its agents interact. | [FM-1.3](01-scope.md#fm-13-groupings) |
| Tier | Significant, suggestive or noise. | [FM-1.5](01-scope.md#fm-15-evidence-tiers) |
| Timestamp kind | Request, submit, capture or unknown. | [FM-6.1](06-timing.md#fm-61-timestamp-kinds) |
| Wilson interval | The interval given with every proportion. | [FM-9.5](09-evaluation.md#fm-95-detection-metrics) |
