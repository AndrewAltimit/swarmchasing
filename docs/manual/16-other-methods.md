# 16. Relation to other methods

[Manual index](README.md) · Previous: [15. Misalignment and scope](15-misalignment.md) · Next: [Glossary](glossary.md)

Other groups find and report agent activity with methods of their own. This chapter says what each does, where this manual agrees, and where it departs, so that a reader can compare findings across groups and a group can say which parts of this manual it already follows. Each description rests on the cited publication only.

## FM-16.1 Published incident investigations

**Transluce, agent activity on urlquery.net** ([Transluce](references.md#incident-reports)). Scan-service reports graded as *significant* or *suggestive* evidence of agent-like activity, a timeline drawn with higher- and moderate-confidence evidence, organisations linked to the activity individually, and an overall attribution worded as what "the attribution evidence available suggests". The provider and the affected organisations were contacted one to two days before publication.

**Transluce, government targets** ([Transluce](references.md#incident-reports)). urlquery.net reports and Arquivo.pt captures, including captures requested through the archive's ArchivePageNow feature. Candidates were found by a combination of regular-expression matching, a language model as judge, investigation by a coding agent, and manual human investigation. The report declines to attribute the traffic as a whole, or each incident, to one provider.

**swarmcha.se, an agent fleet against a UN statistics API** ([swarmcha.se](references.md#incident-reports)). A scan service used as a GET proxy, with a self-submitting form turning a GET into a POST; reader and CORS relays; answers carried out in echo-service URLs; double-encoded path segments; field names and many spellings of a key's name tried in turn. Attribution rests on network addresses shared with accounts that edited wikis in a separately reported swarm.

**swarmcha.se, a fleet on one cloud provider** ([swarmcha.se](references.md#incident-reports)). A proxy fingerprint and a cloud network, with inbox logs read through the inbox service's public API, a dated changelog, and an explicit finding of no evidence of coordination.

| Practice | This manual | Where it departs |
|---|---|---|
| Two evidence grades named significant and suggestive | Same names ([FM-1.5](01-scope.md#fm-15-evidence-tiers)), so labels compare. | The grade is a payload and tool-use measure only; agent presence and scope are separate findings ([FM-15.1](15-misalignment.md#fm-151-four-questions)). |
| Disclosure to provider and organisations before publication | Same order, with a fixed lead time per party ([FM-10.2](10-disclosure.md#fm-102-lead-times)). | The lead time is set in advance and cannot be extended. |
| Model-assisted triage (a model as judge, an agent investigating) | Allowed for suggesting labels on infrastructure the reviewer controls ([policies](../policies.md#evidence-and-attribution)). | A model's output is never a label, never a finding, and never fetches a URL. |
| Declining per-incident attribution | Matches the label Unattributed when the evidence is self-identification ([FM-7.7](07-attribution.md#fm-77-attribution-labels)). | Attribution is still made per layer where the evidence reaches it. |
| Attribution by shared network addresses with another swarm | A shared identifier, the third rung ([FM-7.2](07-attribution.md#fm-72-developer-and-operator-ladder)), if the other incident is confirmed. | A network address names a host first ([FM-14.2](14-limits.md#fm-142-an-asn-names-a-host)); shared cloud addresses are a soft link unless the address is exclusive. |
| Reading an inbox through its public API | Not done ([FM-3.2](03-sources.md#fm-32-passivity-test)). | Channels are matched only as strings inside records. |
| A dated changelog of corrections | Same principle ([FM-11.6](11-notices.md#fm-116-corrections-and-retractions)). | Corrections are typed updates in the notice and its feed. |
| An explicit finding of no coordination | Same: a fleet is not a swarm without evidence ([FM-1.3](01-scope.md#fm-13-groupings)). | None. |

Case studies reading three of these write-ups with the template are in [FM-13.4](13-case-study.md#fm-134-case-study-urlquerynet-agent-activity) to [FM-13.6](13-case-study.md#fm-136-case-study-an-agent-fleet-reading-a-map-service).

## FM-16.2 Provider threat reports

AI providers publish reports on misuse of their own models, such as OpenAI's threat report series and Anthropic's account of an espionage campaign run largely through an agent ([provider reports](references.md#incident-reports)). They rest on the provider's own account and usage data, which outside groups do not have, and attribute actors with confidence words ("high confidence").

This manual is the outside view of the same activity. It starts from public traces, cannot see accounts, and so attributes more weakly; a provider's confirmation is the top of its ladder ([FM-7.2](07-attribution.md#fm-72-developer-and-operator-ladder)). The two meet in disclosure: the provider receives the outside evidence, and its statement is appended to the notice verbatim ([FM-10.5](10-disclosure.md#fm-105-right-of-reply)). Confidence words are used as this manual defines them ([FM-8.2](08-confidence.md#fm-82-confidence-levels)), which may differ from a provider's own scale.

## FM-16.3 Analytic and coordination frameworks

| Framework | What it contributes | Where it sits in this manual |
|---|---|---|
| Diamond Model of intrusion analysis ([Caltagirone et al.](references.md#attribution-practice)) | Every event has an adversary, a capability, infrastructure and a victim. | The attribution layers: operator, harness and model, hosting, and the affected operator ([FM-7.1](07-attribution.md#fm-71-four-layers)). |
| Analysis of Competing Hypotheses ([Heuer](references.md#attribution-practice)) | Judge by evidence against each hypothesis, not evidence for one. | The worksheets of [FM-7.12](07-attribution.md#fm-712-competing-hypotheses). |
| Mandiant's uncategorised clusters ([Mandiant](references.md#attribution-practice)) | Provisional clusters that merge, split and graduate. | The cluster lifecycle ([FM-5.13](05-linking.md#fm-513-cluster-lifecycle-and-identifiers)). |
| ICD 203 ([ODNI](references.md#standards-and-guidance)) | Likelihood terms and confidence kept apart. | [Chapter 8](08-confidence.md), and the calibration rule ([FM-9.12](09-evaluation.md#fm-912-calibrated-public-language)). |
| Coordinated inauthentic behaviour detection ([EU DisinfoLab](references.md#coordination-research), [DFRLab](references.md#coordination-research)) | Separate assessments of coordination, source, impact and authenticity; attribution and intent coded apart. | Coordination is SC-T9, authenticity the agent grade, impact the scope finding, source the attribution layers. |

## FM-16.4 Research on agent coordination and fingerprints

Two lines of research bear on signals the manual uses.

- **Coordination comes in short bursts.** A dataset of an agent social network finds coordination episodes bursty and short-lived, nearly all under a day ([MoltGraph](references.md#coordination-research)). This supports judging synchronized starts and partitions over runs, not whole clusters ([FM-5.12](05-linking.md#fm-512-interaction-edges)), and expecting interaction evidence to be brief. It comes from a platform where agents post, not from web requests, so it informs the method's expectations, not its thresholds.
- **Timing and interaction traces can fingerprint models.** A passive tracker on a website identified which model drove a browser agent from its interaction traces, across many models; random delays reduced accuracy and a retrained classifier largely recovered it ([Lugoloobi et al.](references.md#coordination-research)). That needs instrumented pages, which public records are not, so it belongs to the model-family layer with operator-supplied data and a held-out measurement ([FM-7.5](07-attribution.md#fm-75-model-family-layer)), never to collection.

## FM-16.5 Standards work on agents

Several bodies are writing standards that will change what evidence exists. The IETF Web Bot Auth drafts let an agent sign its requests ([FM-7.11](07-attribution.md#fm-711-declared-agent-identity)). NIST's Center for AI Standards and Innovation runs an AI Agent Standards Initiative covering agent standards, open protocols, and agent security and identity ([NIST](references.md#agent-identity)). The Coalition for Secure AI publishes an incident response framework for AI systems, written for the defenders of a deployed system ([CoSAI](references.md#disclosure)). This manual covers what none of them does: observing other people's agents from outside, with public records only, and disclosing what is found.
