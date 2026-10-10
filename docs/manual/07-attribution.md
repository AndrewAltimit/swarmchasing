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

Harness traces are reported as ranked candidates with the traces for each, tagged Inference. A harness is never named as the source in public: open-source frameworks are used by many operators, and their traces are easy to imitate. Toolkit support for harness ranking is (planned).

## FM-7.5 Model family layer

Model-family attribution reads traces of the model itself: output residue, formatting habits, stale dates from a training cut-off, payload preferences, code style. Its rules:

- **Ranked likelihoods only.** The result is a ranked list of families with likelihood words ([chapter 8](08-confidence.md)), never a single answer.
- **Measured method.** Each ranking states the method's accuracy on a held-out set and the size of the corpus it was trained or tuned on ([FM-9.7](09-evaluation.md#fm-97-attribution-calibration)). A method without a held-out measurement is not used.
- **Never naming-eligible.** A model family never names a developer, an operator or a provider in public, whatever its likelihood.
- **Exclusions are claims too.** "Not family X" needs the same evidence as "family X".

Model-family claims are fragile. One published fleet report removed a model-family exclusion, and a claim about how often one family used its own name in tags, in a dated changelog after publication ([swarmcha.se](references.md#incident-reports)). Small self-identification tests and style comparisons do not support exclusions. Toolkit support for model-family ranking is (planned).

## FM-7.6 Claim tags

Every statement in a report or notice that bears on what happened or who did it carries one tag:

| Tag | What it is | Must cite |
|---|---|---|
| **Observed** | What a record shows. | The record link and the rule id. |
| **Documented** | What a cited public document states: a provider statement, an incident report, a network's registration. | The document. |
| **Inference** | Reasoning from Observed and Documented claims. | The claims it rests on, and its assumption. |
| **Conclusion** | The judgment the report asks the reader to act on. | Its label ([FM-7.7](#fm-77-attribution-labels)) and likelihood words ([chapter 8](08-confidence.md)). |

The tags follow the [ICD 203](references.md#standards-and-guidance) standard of distinguishing underlying information from assumptions and judgments. Toolkit support for tagging claims in drafts is (planned); the case study template applies it by hand ([chapter 13](13-case-study.md)).

## FM-7.7 Attribution labels

A developer or operator attribution carries one label, set by the strongest evidence level reached:

| Label | Evidence level reached | Strongest likelihood word allowed |
|---|---|---|
| **Confirmed** | `provider_confirmed` | almost certain |
| **Suspected** | `provider_infrastructure` or `shared_identifiers` | very likely |
| **Possible** | `hosting_asn`, where the network is the self-named company's | likely |
| **Unattributed** | `self_id` only, or nothing | none; report what the records say ("requests named Claude") without attributing |

The label is about evidence, and the likelihood word about probability. A report gives both ("Suspected: very likely operated by Example AI"), and never a likelihood word stronger than its label allows.

## FM-7.8 The naming gate

A report or notice names a developer or operator only at or above the threshold set for the case:

- the default threshold is **Suspected** (`shared_identifiers`);
- the admin may raise it, or lower it to **Possible** with the reason logged in the case, and the notice then prints the label next to the name;
- whatever the setting, a developer is never named on self-identification alone;
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
