# 7. Attribution

[Manual index](README.md) · Previous: [6. Timing](06-timing.md) · Next: [8. Confidence language](08-confidence.md)

## FM-7.1 Four layers

"Whose agents are these?" has four separate answers. Each layer is attributed on its own evidence, and evidence for one layer is not evidence for another.

| Layer | Question | May be named in public |
|---|---|---|
| **Developer and operator** | Who built or runs the agents? | Yes, through the naming gate ([FM-7.8](#fm-78-the-naming-gate)). |
| **Hosting and runtime** | Whose network or platform did the requests come from? | Yes, as a host only. |
| **Harness and framework** | Which agent framework or product drove the model? | No; ranked candidates only. |
| **Model family** | Which family of model chose the actions? | No; ranked likelihoods only. |

A hosting network running a developer's agents does not make the host the developer. A model family does not identify who deployed it: many operators run the same model.

## FM-7.2 Developer and operator ladder

Every developer or operator claim states the strongest class of evidence it rests on, weakest first:

| Level | Id | Evidence |
|---|---|---|
| 1 | `self_id` | A model or vendor name in a request. Agents misreport who built them, and anyone can submit such a string. |
| 2 | `hosting_asn` | The client network the requests came from. Names a developer only when the network belongs to the company the requests name themselves after. |
| 3 | `shared_identifiers` | Link features (inboxes, run tags) shared with an incident the developer has confirmed. |
| 4 | `provider_infrastructure` | Infrastructure documented as the provider's own: its sandbox hostnames, its egress ranges, its tools' published user agents. |
| 5 | `provider_confirmed` | The provider confirms the activity is its agents', publicly or to the practitioner in writing. |

Levels 1 and 2 come from the records. Levels 3 to 5 come from casework and are entered as claims with their evidence. The toolkit implements this ladder ([methodology](../methodology.md#attribution-levels-and-the-naming-gate)).

## FM-7.3 Hosting and runtime layer

The hosting layer rests on the **client** network: the network the request came from. Evidence includes the client ASN in an operator's logs, sandbox hostnames in records, proxy headers that name a runtime, and an agent checking its own egress address through an echo service.

The network fields of a scan-service record usually describe the **target**: where the scanner reached the submitted URL's host, which for a relayed URL is often the relay's network ([FM-14.3](14-limits.md#fm-143-a-scan-services-asn-is-the-targets)). Records keep client and target networks apart; a hosting claim cites which one it uses. An ASN names a host. It is never by itself evidence about the developer.

## FM-7.4 Harness and framework layer

The harness is the software around the model: the agent framework, the fetch tool, the browser automation, the product. Its traces include tool-call markup dialects, the user agent of a fetch tool, which relays and carriers it reaches for, fixed fan-out widths, and parameter conventions.

Harness traces are reported as ranked candidates with the traces for each, tagged Inference. A harness is never named as the source in public: open-source frameworks are used by many operators, and their traces are easy to imitate. Toolkit: private reports rank one candidate per client product in the records' user agents (a coding harness's own token, such as Gemini CLI's or Aider's, names the product even inside a Mozilla-compatible user agent), by records, with the header fingerprints, header-name sets and URL encoding style they share; public notices leave harness candidates out.

## FM-7.5 Model family layer

Model-family attribution reads traces of the model itself: output residue, formatting habits, stale dates and stale knowledge from a training cut-off ([FM-4.5](04-indicators.md#fm-45-artifact-families)), payload preferences, code style. Its rules:

- **Ranked likelihoods only.** The result is a ranked list of families with likelihood words ([chapter 8](08-confidence.md)), never a single answer.
- **Measured method.** Each ranking states the method's accuracy on a held-out set and the size of the corpus it was trained or tuned on ([FM-9.7](09-evaluation.md#fm-97-attribution-calibration)). A method without a held-out measurement is not used.
- **Never naming-eligible.** A model family never names a developer, an operator or a provider in public, whatever its likelihood.
- **Exclusions are claims too.** "Not family X" needs the same evidence as "family X".

Model-family claims are fragile. One published fleet report removed a model-family exclusion, and a claim about how often one family used its own name in tags, in a dated changelog after publication ([swarmcha.se](references.md#incident-reports)). Small self-identification tests and style comparisons do not support exclusions. Toolkit: a model-family result is entered as a case claim with its likelihood, the method's held-out accuracy and its corpus size (`case claim --layer model_family`); a claim without the measurement is refused. Reports rank the families by likelihood and never name one. The toolkit has no model-family method of its own.

## FM-7.6 Claim tags

Every statement in a report or notice that bears on what happened or who did it carries one tag:

| Tag | What it is | Must cite |
|---|---|---|
| **Observed** | What a record shows. | The record link and the rule id. |
| **Documented** | What a cited public document states: a provider statement, an incident report, a network's registration. | The document. |
| **Inference** | Reasoning from Observed and Documented claims. | The claims it rests on, and its assumption. |
| **Conclusion** | The judgment the report asks the reader to act on. | Its label ([FM-7.7](#fm-77-attribution-labels)) and likelihood words ([chapter 8](08-confidence.md)). |

The tags follow the [ICD 203](references.md#standards-and-guidance) standard of distinguishing underlying information from assumptions and judgments. Toolkit: every attribution claim in a draft carries its tag, given with `case claim --tag` or derived (a network seen in the records is Observed, a provider's statement or documented infrastructure is Documented, the rest Inference), and each developer named through the gate gets a Conclusion line with its label and likelihood word. Statements outside the attribution section are tagged by hand, as in the case study template ([chapter 13](13-case-study.md)).

## FM-7.7 Attribution labels

A developer or operator attribution carries one label, set by the strongest evidence level reached:

| Label | Evidence level reached | Strongest likelihood word allowed |
|---|---|---|
| **Confirmed** | `provider_confirmed` | almost certain |
| **Suspected** | `provider_infrastructure` or `shared_identifiers` | very likely |
| **Possible** | `hosting_asn`, where the network is the self-named company's | likely |
| **Unattributed** | `self_id` only, or nothing | none; report what the records say ("requests named Claude") without attributing |

The label is about evidence, and the likelihood word about probability. A report gives both ("Suspected: very likely operated by Example AI"), and never a likelihood word stronger than its label allows.

Hosting claims take the same labels, except that a network seen in the records is Suspected (requests can be relayed). Harness and model-family candidates are never stronger than Possible, and a model-family claim without a held-out measurement is Unattributed. The toolkit derives every label from the layer and the evidence.

## FM-7.8 The naming gate

A report or notice names a developer or operator only at or above the threshold set for the case:

- the default threshold is **Suspected** (`shared_identifiers`);
- the admin may raise it, or lower it to **Possible** with the reason logged in the case, and the notice then prints the label next to the name;
- whatever the setting, a developer is never named on self-identification alone;
- below shared identifiers, a public notice names the provider only as the party notified: what the requests say about themselves, that this is the weakest evidence, that the provider's operation, deployment or authorisation is not confirmed, and that it was sent the evidence ([FM-11.2](11-notices.md#fm-112-structure)); its name stays out of the title;
- at `provider_infrastructure`, a notice says the requests came from infrastructure the provider operates; who deployed the agents is a separate claim;
- a network operator may be named as a host, because that is what an ASN shows;
- harness and model-family candidates are never named ([FM-7.4](#fm-74-harness-and-framework-layer), [FM-7.5](#fm-75-model-family-layer)).

Case notes list every claim, named or not, with its evidence. The toolkit enforces the threshold and the hosting floor ([methodology](../methodology.md#attribution-levels-and-the-naming-gate)).

## FM-7.9 False-flag reasoning

Before a claim is published, the reviewer asks of each piece of evidence: what would someone need to do to plant it, and what would it cost?

| Evidence | Cost to forge | Reading |
|---|---|---|
| Self-identification | Nothing: type a name into a URL. | Never attributes. |
| Run tag or inbox in a published report | Nothing: copy it. | Soft after publication ([FM-14.5](14-limits.md#fm-145-tags-get-copied-after-publication)). |
| Hosting network | Low: rent from the same cloud. | Names a host. |
| Model residue and style | Low: run the same model, or paste its output. | Ranked, never named. |
| Provider-documented infrastructure | High: requires access to the provider's systems. | Strong. |
| Provider confirmation | Not forgeable by a third party. | Strongest. |

Also look for inconsistency between layers: a cluster that names one vendor while showing another harness's markup, or a provider's sandbox hostname on a network the provider does not use. Inconsistency is reported, not resolved by picking the more convenient reading. An agent can also be instructed to name a vendor, so a self-identification can be deliberate misdirection by its operator.

## FM-7.10 Agent likelihood

Before any layer is attributed, a report states how likely it is that an agent sent the requests at all. A penetration tester or a conventional scanner sending the same payloads through the same services leaves the same records ([FM-14.7](14-limits.md#fm-147-humans-look-the-same)). The grade is set by the strongest combination of signals present, never by summing weak ones:

| Grade | Name | Evidence |
|---|---|---|
| L0 | Payloads only | Attack payloads, nothing more. |
| L1 | Self-described | A model or vendor name, or an agent test tag. Costs nothing to write ([FM-7.9](#fm-79-false-flag-reasoning)); worded like L0. |
| L2 | Model-written | Model-output residue, prose, invented identifiers, a repeated output cut length, stale knowledge or stale dates ([FM-4.5](04-indicators.md#fm-45-artifact-families)). |
| L3 | Adaptive | L2, and behaviour that answers responses: a changed request after an error, a route escalation, variants at model pace. Read from request or submit times only. |
| L4 | Agent likely | L3, and a pace or scale beyond one person: adapting at machine speed, fixed parallel fan-out, cross-service fan-out with no auto-submitter around it ([FM-6.3](06-timing.md#fm-63-concurrency-and-fan-out)), activity round the clock, or a machine fetch tool's habit (robots.txt read again before every page, a client-side rate ceiling held again and again). No working-hours rhythm against it. |
| L5 | Documented | Casework only: operator logs matching an agent harness, or the provider's confirmation. |

Caps:

- **must** stop at L2 when every timestamp is an archive capture ([FM-6.1](06-timing.md#fm-61-timestamp-kinds));
- **must** stop at L2 when a working-hours rhythm meets slow pace, and the report says the activity is possibly human-operated with model help;
- **should** stop at L3 under any working-hours rhythm.

A referral tag **must not** count as self-description: an assistant's citation tag (`utm_source=chatgpt.com`) names where the link came from, and anyone following or copying the link sends it.

Page-borne residue **must not** set L2 on its own. Residue a page carries in its own links, such as an unrendered front-end template (`{{item.slug}}` in a path), is sent by every crawler, preview bot and feed poller that follows the link; it shows a link was followed, not who wrote it. It is reported beside the L2 evidence and counts only where another L2 signal already holds.

Declared testing and benchmark targets ([FM-4.9](04-indicators.md#fm-49-benchmark-targets-and-declared-testing)) are reported as counter-signals and do not move the grade: anyone can declare a test. A declared agent product from outside its provider's published ranges is a counter-signal too, and a verified provider identity supports L1 and nothing higher ([FM-7.13](#fm-713-published-address-ranges)).

The rungs are ordered by the kind of evidence, not by measured likelihood. Nothing guarantees that a higher rung is more often an agent: a person working a request by hand through a repeater tool changes requests after errors and sends variants at model pace, which is the adaptive rung's evidence, and labelled human runs do reach L3. A grade is therefore read with the competing hypotheses it leaves open ([FM-7.12](#fm-712-competing-hypotheses)), and is a probability only once measured ([FM-9.12](09-evaluation.md#fm-912-calibrated-public-language)).

A grade without a held-out measurement **must not** appear in a public notice. Until one exists, a notice says at most that attack payloads were present and that this alone does not show what sent them. Measuring the grade needs records whose actor is known: synthetic human and tool runs as hard negatives, and a negative control of records from before capable agents existed, which no agent sent ([FM-9.11](09-evaluation.md#fm-911-agent-grade-evaluation)).

A record in no cluster is graded from its own hits: self-description is L1 and model-output residue L2, and with no pace, retries or rhythm to read it stops there.

Toolkit: every cluster, and every flagged record in none, carries its grade, signals, counter-signals and caps; case notes and provider reports list them, and `case grade` records the admin's decision, the only way to L5 ([methodology](../methodology.md#agent-likelihood)).

## FM-7.11 Declared agent identity

Some agents now declare who operates them in a form that costs something to forge. The IETF Web Bot Auth working group specifies HTTP message signatures for automated traffic: the client signs each request, a `Signature-Agent` header gives an `https` URI where the signer's keys can be found (by default a well-known key directory), and the signature covers that header, its creation and expiry times, and a key id ([Web Bot Auth](references.md#agent-identity)). A companion draft describes a signature agent card, a document in which the signer describes itself.

A verified signature shows that the request was signed with a key the signer publishes. It does not show who directed the agent: a provider's agent product signs on behalf of every customer who uses it.

| Observation | Reading | Layer and level |
|---|---|---|
| Valid signature, key in a directory the provider documents as its own | The request came from the provider's signing infrastructure. | Developer: `provider_infrastructure` ([FM-7.2](#fm-72-developer-and-operator-ladder)); who deployed it is a separate claim ([FM-7.8](#fm-78-the-naming-gate)). |
| Valid signature, key in a directory nobody has documented | Someone signs with that key. | A link feature: the same key id across clusters is a hard link within its bounds ([FM-5.2](05-linking.md#fm-52-shared-link-features)). Names nobody. |
| A user agent naming a product that signs its requests, with no signature | The claim is unsupported where support was expected. | Self-identification at most ([FM-14.1](14-limits.md#fm-141-self-identification-is-forgeable)), and a counter-signal against that product; reported as Observed with the product's published signing practice as Documented. |
| An invalid or expired signature | A replay, a broken client or a forgery. | Reported as Observed; never attributes. |

Passivity limits verification. The `Signature-Agent` URI comes from a request, and a practitioner **must not** fetch it ([FM-2.1](02-principles.md#fm-21-passive-only)): it is an address the agent supplied. Keys are checked only against directories the practitioner already holds from the signer's own documentation, fetched from the address that documentation gives. Public records rarely carry request headers ([FM-3.6](03-sources.md#fm-36-known-source-biases)), so in practice this evidence comes from operator-supplied logs ([FM-10.7](10-disclosure.md#fm-107-operator-supplied-logs)).

Toolkit: `selfid.signature_agent` reads the `Signature-Agent` and `Signature-Input` headers as attribution evidence, and `header.agent_ua` flags a known agent product in the user agent. The key directories a provider documents are held from that documentation's addresses (`swarmchase identity refresh`), and the identity check verifies an Ed25519 Web Bot Auth signature against them; a signer whose directory is not held stays unverified, and the URI a request names is never fetched ([identity](../reference/identity.md)).

## FM-7.12 Competing hypotheses

A grade and a label say what evidence was reached. They do not say what else the evidence fits. Before a Conclusion, the reviewer fills a worksheet in the manner of Analysis of Competing Hypotheses ([Heuer](references.md#attribution-practice)): list every reasonable hypothesis, mark each piece of evidence against each, and keep the hypothesis with the least evidence against it, not the one with the most for it. Evidence consistent with every hypothesis is not diagnostic and does not count.

Two worksheets are standard. The first asks what sent the requests, and sets the agent grade's wording ([FM-7.10](#fm-710-agent-likelihood)):

| Evidence | H1 Unsupervised agent | H2 Supervised agent | H3 Person with model help | H4 Scanner or script | H5 Declared test | H6 Planted records |
|---|---|---|---|---|---|---|
| Attack payload present | C | C | C | C | C | C |
| Model residue | C | C | C | I | N | N |
| Adaptive retries at model pace | C | C | C | I | N | I |
| Machine pace with retries, fixed fan-out | C | C | I | C | N | N |
| Round-the-clock rhythm | C | I | I | C | N | N |
| Working-hours rhythm | I | C | C | N | C | N |
| Declared-test text | N | N | N | N | C | N |
| Only submit-anywhere records | N | N | N | N | N | C |

C is consistent, I inconsistent, N neutral or not diagnostic. The table shows the default reading; the reviewer overrides a cell with a reason. The payload row is consistent with everything, which is why a tier alone never says an agent was present ([FM-14.7](14-limits.md#fm-147-humans-look-the-same)).

The second asks who operates the agents, and sets the developer label's wording ([FM-7.7](#fm-77-attribution-labels)). Its hypotheses are: the named provider's own agents (A1); another operator using the provider's model or product (A2); another operator naming the provider falsely (A3); a researcher or tester (A4); planted records (A5). Its evidence rows are the ladder's levels ([FM-7.2](#fm-72-developer-and-operator-ladder)), each read with its cost to forge ([FM-7.9](#fm-79-false-flag-reasoning)): self-identification is consistent with A1 to A5; a hosting network the provider runs is inconsistent with A3 only when the network is not shared; provider infrastructure is inconsistent with A3 and A5; provider confirmation settles it.

Reading the worksheet:

- The surviving hypothesis sets the claim; the label and likelihood word still come from the evidence level, and the worksheet never raises them ([FM-8.3](08-confidence.md#fm-83-usage-rules)).
- Where two hypotheses survive with no evidence against either, the Conclusion names both and uses no likelihood word stronger than "roughly even chance" between them.
- Each rejected hypothesis is recorded with the evidence against it. These are the alternatives the self-review checks ([FM-10.9](10-disclosure.md#fm-109-self-review-and-second-review)).
- The report says which evidence would change the result ([FM-8.3](08-confidence.md#fm-83-usage-rules)).

Toolkit: the case records each rejected alternative (authorised test, honeypot, research scanner, spoofed self-identification, planted records) with its reason, and the self-review refuses a notice until each is recorded ([cases](../reference/cases.md#self-review-checklist)). The worksheet itself is kept in case notes by hand; recording it in the case is (planned).

## FM-7.13 Published address ranges

Providers publish files listing the addresses their agent products and crawlers send from, beside the user agent each product declares (`ChatGPT-User`, `Claude-User`, `Perplexity-User`, `Google-Agent`), and some publish the keys their products sign with ([FM-7.11](#fm-711-declared-agent-identity)). An address in an operator's log can be read against these files ([provider pages](references.md#agent-identity)).

| Observation | Reading | Layer and level |
|---|---|---|
| A declared product, from an address in its provider's file | The provider's systems sent the request. | Developer: `provider_infrastructure` ([FM-7.2](#fm-72-developer-and-operator-ladder)); who directed the agent is a separate claim. |
| An address in a provider's file, no declaration | The provider's systems sent it; which product is not shown. | Developer: `provider_infrastructure`, the product unnamed. |
| A declared product from outside a file the provider presents as complete, with no valid signature | The declaration is false: a spoofed identity. | No claim on the provider; Observed, and a counter-signal on the grade. |
| A declared product from outside a file not presented as complete | Unlisted, not shown false. | Self-identification at most ([FM-14.1](14-limits.md#fm-141-self-identification-is-forgeable)). |

A valid signature outranks the address: a product may sign from addresses its file does not list. A spoofed declaration is evidence about whoever sent it, not about the provider it names: a scanner or another operator's agent dressed in a well-known user agent.

Rules for reading:

- the files are the provider's own publications, read from the addresses its documentation gives, like a security contact ([FM-2.1](02-principles.md#fm-21-passive-only)); an address taken from a request is never fetched;
- a file changes over time: a verdict names the file and the date it was fetched, and a log much older than the file is read with that gap stated;
- the address must be the client's: a log behind a proxy or load balancer records the proxy unless the operator logs the forwarded client address;
- an address in a shared cloud range shows the provider rented it at the file's date, not that it still does.

A verified identity shows a provider's agent platform sent the request. It does not show that a model chose the payload: a user can ask a fetch tool to request a URL they wrote, and the platform then relays a person's request as a relay service does ([FM-14.7](14-limits.md#fm-147-humans-look-the-same)). It therefore supports the self-described rung of the agent grade and no higher ([FM-7.10](#fm-710-agent-likelihood)), and never L5, which stays casework.

Toolkit: `swarmchase identity refresh` holds the range files and directories the catalog names, `identity check` classes each record (signature verified, address verified, in range, signature present, claimed, signature failed, spoofed), and the analysis commands add each cluster's identity line, a counter-signal for spoofs and a suggested `provider_infrastructure` claim the admin records or not ([identity](../reference/identity.md)).
