# 13. Case study template

[Manual index](README.md) · Previous: [12. Interoperability](12-interoperability.md) · Next: [14. Known limits](14-limits.md)

## FM-13.1 Template

A case study, whether a published write-up or the reasoning behind a notice, uses these parts in this order. Each claim carries its tag ([FM-7.6](07-attribution.md#fm-76-claim-tags)).

1. **Header.** Case id; method version (SC-FM 1.0) and any departures; rules version; toolkit version; the period covered; each source with its timestamp kind ([FM-6.1](06-timing.md#fm-61-timestamp-kinds)).
2. **Conclusions first.** Each Conclusion with its label ([FM-7.7](07-attribution.md#fm-77-attribution-labels)) and likelihood words or confidence level ([chapter 8](08-confidence.md)).
3. **Observed.** A table: claim, record link, rule id.
4. **Documented.** A table: claim, cited source.
5. **Inference.** A table: claim, the claims it rests on, the assumption it needs.
6. **Linking decisions.** Hard links used, soft links considered, and every merge or split with its reason ([FM-5.8](05-linking.md#fm-58-candidate-fleets-merge-and-split)).
7. **Tactics.** SC-T tactics observed and the escalation sequence, if any ([FM-5.9](05-linking.md#fm-59-escalation-sequences)).
8. **Attribution by layer.** One entry per layer ([FM-7.1](07-attribution.md#fm-71-four-layers)), including "no evidence".
9. **What would change the conclusion.** The evidence that would raise or lower each likelihood.
10. **Limits.** The [chapter 14](14-limits.md) entries that apply, by id.

## FM-13.2 Worked example (synthetic)

**Every record in this example is synthetic.** The records were written by hand to exercise the rules, use reserved `.example` hosts, and were never collected. They are the toolkit's example records ([`llm-residue.ndjson`](../../samples/eval/llm-residue.ndjson)), which the browser toolkit loads under *Try an example*. Their times and groupings are artefacts of how they were written. Results below are as the toolkit grades them at rules version 2026-10-15; a later rules version may grade them differently.

**Header.** Case: synthetic example. Method: SC-FM 1.0. Source: hand-written records with no timestamp kind (unknown).

**Conclusions.**

- The records very likely show agent-built requests: several carry text a model writes around a URL.
- There is no attribution: Unattributed. No record names a vendor, and none carries a client network.
- It is too little to report. One record carries an injection attempt, nothing links that record to the tagged runs, and the timing that groups most records is unusable.

**Observed.**

| Claim | Record | Rule |
|---|---|---|
| A relayed URL carries a Markdown link around the target. | `eval:llm-md-link-relay` | `marker.md_link` |
| A relayed URL ends in closing function-call markup. | `eval:llm-invoke-close` | `marker.tool_call_markup` |
| A request to the target carries tool-call markup and run tag `uqtag=r7k2`. | `eval:llm-tool-call-tag` | `marker.tool_call_markup`, `marker.uq_tags` |
| A relayed URL with a doubled scheme carries the same tag `uqtag=r7k2`. | `eval:llm-doubled-scheme-relay` | `marker.doubled_scheme`, `marker.uq_tags` |
| A search carries a chat-reply opener and a different tag, `uqtag=k3m9`. | `eval:llm-opener-tagged` | `marker.chat_opener`, `marker.uq_tags` |
| A sign-up request uses a stock identity and a script payload in a name field. | `eval:llm-placeholder-identity-xss` | `marker.placeholder_identity`, `exploit.xss` |

**Documented.** None. The records are synthetic, so no public document describes them. In a real case this part holds provider statements, prior incident reports and network registrations.

**Inference.**

| Claim | Rests on | Assumption |
|---|---|---|
| The two `r7k2` records are one run. | The shared run tag (a hard link, [FM-5.2](05-linking.md#fm-52-shared-link-features)). | The tag is not a common value or a copied one. |
| The `r7k2` and `k3m9` records are two runs, not one. | Different values of the same tag parameter. | Each run sets its own tag. |
| The two runs may share an operator. | Same target, same relay, same tag parameter name, overlapping in time. | Soft links only; not merged ([FM-5.7](05-linking.md#fm-57-soft-links)). |
| The sign-up with a script payload is account acquisition with probing (SC-T5, SC-T4). | The stock identity and the payload in one request. | The request was sent, not only drafted. |

**Linking decisions.** The toolkit forms four clusters from these records. The `r7k2` tag anchors one of them; every other link in all four is close timing on the same target, which this manual requires to rest on request or submission times ([FM-5.3](05-linking.md#fm-53-close-timing-on-the-same-target)). These records have no timestamp kind, so under the standard those timing links are discarded and only the `r7k2` tag link is hard. One record joins the first cluster through the target host `https`, which a doubled scheme produced: a bogus host, so that link is discarded too ([FM-5.6](05-linking.md#fm-56-cluster-hygiene)). The `r7k2` and `k3m9` runs form a candidate fleet; the reviewer does not merge them, and logs that decision with the reason "soft links only".

**Tactics.** SC-T1 (relayed retrieval of the target's pages) in both runs; SC-T5 and SC-T4 in the sign-up request. No escalation sequence is claimed: with unknown timestamps, order is not evidence ([FM-6.1](06-timing.md#fm-61-timestamp-kinds)). No SC-T9 evidence, so even a merged group would be a fleet, not a swarm ([FM-1.3](01-scope.md#fm-13-groupings)).

**Attribution by layer.**

| Layer | Finding |
|---|---|
| Developer and operator | Unattributed: no self-identification, no client network, no shared identifier with a confirmed incident. |
| Hosting and runtime | No evidence: no client network in the records. |
| Harness and framework | No ranking: function-call markup and tool-call JSON are shared by many frameworks. |
| Model family | No ranking: no measured method was applied ([FM-7.5](07-attribution.md#fm-75-model-family-layer)). |

**What would change the conclusion.** Request or submission timestamps would allow the timing links and an escalation sequence. A provider statement, or the `r7k2` tag in a confirmed incident, would allow a Suspected attribution. A record showing one run reading another's output would make the group a swarm.

**Limits.** [FM-14.1](14-limits.md#fm-141-self-identification-is-forgeable) does not arise (no self-identification). [FM-14.4](14-limits.md#fm-144-capture-time-is-not-request-time), [FM-14.6](14-limits.md#fm-146-common-features-cause-giant-clusters) and [FM-14.10](14-limits.md#fm-1410-malformed-urls-make-bogus-targets) apply.
