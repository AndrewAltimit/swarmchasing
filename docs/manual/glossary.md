# Glossary

[Manual index](README.md) · Previous: [16. Other methods](16-other-methods.md) · Next: [References](references.md)

Each term links to the section that defines it.

| Term | Short definition | Defined in |
|---|---|---|
| Admin | The person who decides, sends and publishes. | [FM-1.4](01-scope.md#fm-14-casework-terms), [FM-2.4](02-principles.md#fm-24-admin-gate) |
| Affected operator | The organisation running a targeted host. | [FM-1.4](01-scope.md#fm-14-casework-terms) |
| Agent | A system in which a model chooses actions toward a goal. | [FM-1.2](01-scope.md#fm-12-units-of-observation) |
| Agent grade | How likely an agent, not a person or a tool, sent a cluster's requests: L0 to L5. | [FM-7.10](07-attribution.md#fm-710-agent-likelihood) |
| Artifact family | A class of build traces, such as model-output residue. | [FM-4.5](04-indicators.md#fm-45-artifact-families) |
| Attribution label | Confirmed, Suspected, Possible or Unattributed. | [FM-7.7](07-attribution.md#fm-77-attribution-labels) |
| Attribution layer | Developer and operator, hosting, harness, model family. | [FM-7.1](07-attribution.md#fm-71-four-layers) |
| Benchmark target | A public site or environment built to be tested against. | [FM-4.9](04-indicators.md#fm-49-benchmark-targets-and-declared-testing) |
| Burst | Many records each seconds after the last. | [FM-6.2](06-timing.md#fm-62-cadence-bursts-and-pauses) |
| Calibration rule | A public likelihood word no stronger than the lower bound of measured precision. | [FM-9.12](09-evaluation.md#fm-912-calibrated-public-language) |
| Candidate fleet | Clusters joined by soft links, awaiting a decision. | [FM-1.3](01-scope.md#fm-13-groupings), [FM-5.8](05-linking.md#fm-58-candidate-fleets-merge-and-split) |
| Case | The private working file for one incident. | [FM-1.4](01-scope.md#fm-14-casework-terms), [FM-10.8](10-disclosure.md#fm-108-the-admin-gate-and-the-case-record) |
| Claim tag | Observed, Documented, Inference or Conclusion. | [FM-7.6](07-attribution.md#fm-76-claim-tags) |
| Cluster | Records joined by hard links. | [FM-1.3](01-scope.md#fm-13-groupings) |
| Commonness cap | The limit above which a link feature only soft-links. | [FM-5.2](05-linking.md#fm-52-shared-link-features) |
| Competing hypotheses | The worksheet that marks evidence against each explanation. | [FM-7.12](07-attribution.md#fm-712-competing-hypotheses) |
| Confidence level | High, moderate or low: the basis for a judgment. | [FM-8.2](08-confidence.md#fm-82-confidence-levels) |
| Context cap | Context kinds alone never reach the suggestive threshold. | [FM-4.11](04-indicators.md#fm-411-independence-groups-and-the-context-cap) |
| Context kind | A rule kind ordinary clients produce: relay, cache buster, self-identification, header, outcome. | [FM-4.11](04-indicators.md#fm-411-independence-groups-and-the-context-cap), [FM-5.3](05-linking.md#fm-53-close-timing-on-the-same-target) |
| Corroboration | One kind of source, several, or confirmed in operator logs. | [FM-5.11](05-linking.md#fm-511-provenance-and-planted-records) |
| Declared testing | Request text announcing a test; checked, never believed. | [FM-4.9](04-indicators.md#fm-49-benchmark-targets-and-declared-testing), [FM-10.6](10-disclosure.md#fm-106-authorised-testing) |
| Escalation sequence | The order in which tactics appear in a run or fleet. | [FM-5.9](05-linking.md#fm-59-escalation-sequences) |
| Evidence level | A rung of the developer ladder, `self_id` to `provider_confirmed`. | [FM-7.2](07-attribution.md#fm-72-developer-and-operator-ladder) |
| False-merge rate | Share of predicted clusters spanning more than one true group. | [FM-9.6](09-evaluation.md#fm-96-cluster-metrics) |
| Fleet | Clusters merged on evidence as one operator's agents. | [FM-1.3](01-scope.md#fm-13-groupings) |
| Hard link | A link that joins records into a cluster. | [FM-5.1](05-linking.md#fm-51-hard-and-soft-links) |
| Incident | Confirmed agent activity that harms or risks an operator. | [FM-1.4](01-scope.md#fm-14-casework-terms) |
| Independence group | Rules reading the same artifact, counted once per record. | [FM-4.11](04-indicators.md#fm-411-independence-groups-and-the-context-cap) |
| Indicator | A rule that matches a feature of a record. | [FM-1.2](01-scope.md#fm-12-units-of-observation), [FM-4.2](04-indicators.md#fm-42-rule-anatomy) |
| Indicator notice | The first stage of a notice: indicators, no affected party named. | [FM-10.2](10-disclosure.md#fm-102-lead-times) |
| Interaction edge | A hint that two runs acted on each other's output; never a merge. | [FM-4.10](04-indicators.md#fm-410-interaction-signals), [FM-5.12](05-linking.md#fm-512-interaction-edges) |
| Lead | A cluster or candidate fleet nobody has reviewed. | [FM-1.4](01-scope.md#fm-14-casework-terms) |
| Likelihood word | A term from the ICD 203 table. | [FM-8.1](08-confidence.md#fm-81-likelihood-table) |
| Link feature | A matched value one operator would hold. | [FM-1.2](01-scope.md#fm-12-units-of-observation), [FM-5.2](05-linking.md#fm-52-shared-link-features) |
| Misaligned | An agent present and out of scope, with no accepted alternative; in reports only with both recorded. | [FM-15.1](15-misalignment.md#fm-151-four-questions), [FM-15.4](15-misalignment.md#fm-154-stating-a-scope-finding) |
| Named fleet | A fleet with an identifier unique across cases, `SCF-<n>`. | [FM-5.13](05-linking.md#fm-513-cluster-lifecycle-and-identifiers) |
| Naming gate | The evidence threshold for naming a developer. | [FM-7.8](07-attribution.md#fm-78-the-naming-gate) |
| Naming lead | Working days before an affected operator is named: 3, or 10 if compromised. | [FM-10.2](10-disclosure.md#fm-102-lead-times) |
| Naming update | A dated update that names affected operators. | [FM-10.2](10-disclosure.md#fm-102-lead-times), [FM-11.2](11-notices.md#fm-112-structure) |
| Notice | The public page for one incident. | [FM-1.4](01-scope.md#fm-14-casework-terms), [chapter 11](11-notices.md) |
| Passivity test | The conditions every source must pass. | [FM-3.2](03-sources.md#fm-32-passivity-test) |
| Pause | A gap long in absolute terms and against the median gap. | [FM-6.2](06-timing.md#fm-62-cadence-bursts-and-pauses) |
| Plant signal | A sign a cluster's records were placed to be found. | [FM-5.11](05-linking.md#fm-511-provenance-and-planted-records) |
| Platform swarm candidate | Accounts acting alike on a public platform beyond chance; a hint, never a swarm. | [FM-5.15](05-linking.md#fm-515-coordinated-accounts-on-public-platforms) |
| Probe chain | One client trying variants of one request. | [FM-5.4](05-linking.md#fm-54-probe-chains) |
| Provenance | Who can create a record: observed, submit- or publish-anywhere. | [FM-5.11](05-linking.md#fm-511-provenance-and-planted-records) |
| Provider | The organisation whose agents are attributed. | [FM-1.4](01-scope.md#fm-14-casework-terms) |
| Public record | A third-party trace of a request, published to anyone. | [FM-3.1](03-sources.md#fm-31-what-counts-as-a-public-record) |
| Published tag | A tag quoted in a public report; never a hard link. | [FM-5.2](05-linking.md#fm-52-shared-link-features), [FM-14.5](14-limits.md#fm-145-tags-get-copied-after-publication) |
| Record | A public trace of one request. | [FM-1.2](01-scope.md#fm-12-units-of-observation) |
| Relay stack | The chain of relays and carriers a request went through. | [FM-4.5](04-indicators.md#fm-45-artifact-families) |
| Rerun | A later run repeating an earlier run's targets in order. | [FM-5.10](05-linking.md#fm-510-reruns) |
| Rhythm | A cluster's hour-of-day profile. | [FM-6.4](06-timing.md#fm-64-rhythm) |
| Run | Records of a cluster with no gap longer than the run gap. | [FM-1.3](01-scope.md#fm-13-groupings), [FM-5.5](05-linking.md#fm-55-runs) |
| SC-T | The swarmchasing tactic ids, SC-T1 to SC-T9. | [FM-4.3](04-indicators.md#fm-43-the-sc-t-tactic-taxonomy) |
| Scope finding | In scope, scope exceeded or not assessable. | [FM-15.4](15-misalignment.md#fm-154-stating-a-scope-finding) |
| Scope test | One of S1 to S7, each a way activity can exceed its task. | [FM-15.3](15-misalignment.md#fm-153-scope-tests) |
| Second review | Approval of the exact draft by a person other than the admin. | [FM-10.9](10-disclosure.md#fm-109-self-review-and-second-review) |
| Shared pause | Two clusters going quiet together beyond chance. | [FM-6.7](06-timing.md#fm-67-shared-pauses) |
| Signed request | A request carrying a Web Bot Auth signature and `Signature-Agent`. | [FM-7.11](07-attribution.md#fm-711-declared-agent-identity) |
| Spoofed identity | A declared agent product from outside its provider's complete published ranges, unsigned. | [FM-7.13](07-attribution.md#fm-713-published-address-ranges) |
| Soft link | A proposed link between clusters; never joins them. | [FM-5.1](05-linking.md#fm-51-hard-and-soft-links), [FM-5.7](05-linking.md#fm-57-soft-links) |
| Stale date | A "today" tag well behind the observed date. | [FM-6.6](06-timing.md#fm-66-stale-dates) |
| Stale knowledge | Retired endpoints or old clients a model still writes. | [FM-4.5](04-indicators.md#fm-45-artifact-families) |
| Strand | The records of one run sent one way (route, user agent, network, header set). | [FM-5.12](05-linking.md#fm-512-interaction-edges) |
| Swarm | A fleet with evidence its agents interact. | [FM-1.3](01-scope.md#fm-13-groupings) |
| Target class | What kind of endpoint a request reached. | [FM-15.2](15-misalignment.md#fm-152-task-class-and-target-class) |
| Task class | The evident purpose of a cluster's ordinary requests. | [FM-15.2](15-misalignment.md#fm-152-task-class-and-target-class) |
| Tier | Significant, suggestive or noise. | [FM-1.5](01-scope.md#fm-15-evidence-tiers) |
| Timestamp kind | Request, submit, capture or unknown. | [FM-6.1](06-timing.md#fm-61-timestamp-kinds) |
| Unsupervised | Activity continuing with no sign of a person checking it. | [FM-15.1](15-misalignment.md#fm-151-four-questions) |
| Wilson interval | The interval given with every proportion. | [FM-9.5](09-evaluation.md#fm-95-detection-metrics) |
