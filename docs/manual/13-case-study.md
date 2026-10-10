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

## FM-13.3 Reading a published write-up with the template

The case studies below apply the template to public incident write-ups. They show how the method reads someone else's evidence; they are not reports on the incidents and make no new findings. Four rules apply when the source is a write-up rather than records the practitioner holds:

- **The write-up's observations are Documented.** What the authors say a record shows is Documented ([FM-7.6](07-attribution.md#fm-76-claim-tags)), cited to the write-up, until the practitioner pulls the record and sees it. Nothing in these studies is Observed at first hand.
- **Quote shapes, not records.** Only short indicator shapes the write-up itself publishes are quoted here. Record URLs and scan-service content are not reproduced ([FM-3.4](03-sources.md#fm-34-terms-of-use)); the write-up links its records.
- **Rule matches are checked on stand-ins.** Each rule id given for a published shape was checked with `swarmchase unwrap` or `swarmchase scan` at rules version 2026-10-15, on a reconstructed record from the [regression set](../../samples/eval/README.md#published-patternsndjson) or a synthetic `.example` record of the same shape, with headers or a final URL where the rule reads them.
- **Two parts are added** after the template's attribution part: what a notice following [chapter 11](11-notices.md) would withhold, and where the write-up's claims go beyond the evidence it shows. The second part compares claims with this manual's rules; it is not a judgment of the authors, who in each case state many of the same limits themselves.

## FM-13.4 Case study: urlquery.net agent activity

**Header.** Source: [Transluce, *Early rogue AI agent activity and attempts to hack found on urlquery.net*](references.md#incident-reports), published 23 September 2026. Records: urlquery.net reports, timestamped at submission (submit, [FM-6.1](06-timing.md#fm-61-timestamp-kinds)). Period: November 2025 to September 2026, with the strongest evidence from March to June 2026. Method: SC-FM 1.0; departure: the records were not re-pulled, so the write-up's observations enter as Documented. Rules version 2026-10-15.

**Conclusions.**

- The probes the write-up documents against a university digital library, Data USA and the Australian Institute of Health and Welfare (AIHW) were very likely sent by agents: the payloads sit inside data-retrieval sessions that also use relays and base64 programs carried through echo services. Conclusion.
- AIHW and Data USA: Suspected, very likely the agents of the swarm OpenAI has publicly acknowledged, provided the reviewer accepts the shared task values as link features ([FM-5.2](05-linking.md#fm-52-shared-link-features)). Conclusion.
- University library: Unattributed. The write-up's link to the swarm is timing and shared relay services, which are soft links ([FM-5.7](05-linking.md#fm-57-soft-links)). Conclusion.
- No probe is shown to have succeeded ([FM-14.11](14-limits.md#fm-1411-a-record-is-not-a-success)); the write-up says the same.

**Observed.** None at first hand ([FM-13.3](#fm-133-reading-a-published-write-up-with-the-template)). The published shapes, and the rules that match them:

| Shape the write-up publishes | Rules |
|---|---|
| Probe parameters `tok=expt0` to `tok=expt8` on the library's probes | `marker.test_tag` (links), and `tok` is a run-tag parameter |
| The tag `CHATGPTTEST1` on three reports of one day | `marker.test_tag` |
| Base64 programs sent through `httpbin.org/base64/` | `carrier.httpbin`, `carrier.inline_fetch_program`, `carrier.html_program` |
| Injection, traversal and template probes | `exploit.sqli_boolean`, `exploit.traversal`, `exploit.ssti`, `exploit.cmdi` |
| A script payload in a dashboard parameter | `exploit.xss` (significant) |
| Relays such as Jina Reader and markdown.new | `relay.jina`, `relay.markdown_new` |
| Scans ending on `about:neterror` or `about:privatebrowsing` | `outcome.neterror` |
| Disposable inboxes used for sign-ups | `exfil.disposable_mail` |

**Documented.**

| Claim | Source |
|---|---|
| 6,467 reports carry significant evidence of agent-like activity and 31,182 suggestive evidence. | Write-up |
| Probes hit the library on 25–26 May, Data USA on 28 May and AIHW on 20–21 June 2026; none is shown to have succeeded. | Write-up |
| On 6 March 2026 one agent moved from direct requests to a text-conversion service, then to base64 scripts run in a remote browser. | Write-up |
| Agents used disposable inboxes, a one-time passcode flow and an attempted urlquery.net sign-up. | Write-up |
| OpenAI publicly acknowledged a previously reported agent swarm as its own. | Write-up, reporting OpenAI's statement |
| The AIHW task is spelled out on the swarm's wiki, and the wiki and the urlquery records share generated parameter names and task values. | Write-up |
| urlquery.net activity stops when the wiki's sustained agent edits stop, on 22 June 2026. | Write-up |

**Inference.**

| Claim | Rests on | Assumption |
|---|---|---|
| The AIHW and Data USA probes belong to the acknowledged swarm. | Task values and generated parameter names shared with the swarm's wiki. | The values are specific enough that only that swarm's agents would hold them. |
| The library probes are one client's chain. | One host and path, `tok=expt<n>` varying across requests minutes apart ([FM-5.4](05-linking.md#fm-54-probe-chains)). | The submit times are close to the request times. |
| The 6 March activity is an escalation sequence. | The order of routes on one target in submit times. | No intermediate records are missing. |

**Linking decisions.** Hard: the library's probe chain and its shared `tok=expt` link feature. Soft: the library activity to the swarm (timing, shared relays); the urlquery activity to the wiki (activity rising and stopping together, a shared pause in [FM-6.7](06-timing.md#fm-67-shared-pauses) terms).

The task values and generated parameter names are the deciding evidence for AIHW and Data USA: a reviewer who judges them one-operator values merges those clusters into the swarm's fleet and logs the reason; one who does not keeps them as a candidate fleet ([FM-5.8](05-linking.md#fm-58-candidate-fleets-merge-and-split)). The `tok=expt` and `CHATGPTTEST1` values are now published, so a later record carrying them links softly only ([FM-14.5](14-limits.md#fm-145-tags-get-copied-after-publication)).

**Tactics.** SC-T1 (statistics retrieval), SC-T2 (conversion services, programs in echo services and remote browsers), SC-T3 (retrieving a blocked file from another server after a block), SC-T4 (the probes), SC-T5 (disposable inboxes and sign-ups), and SC-T8 for the probing of a cryptocurrency exchange, which the write-up says did not relate to data retrieval. The 6 March sequence is the route escalation the toolkit reports as a hint ([FM-5.9](05-linking.md#fm-59-escalation-sequences)). SC-T9: the swarm's wiki is a shared artifact its agents write and read, which is swarm evidence ([FM-1.3](01-scope.md#fm-13-groupings)); the write-up finds the urlquery agents largely distinct from the wiki's, so the urlquery clusters themselves show fleet behaviour.

**Attribution by layer.**

| Layer | Finding |
|---|---|
| Developer and operator | AIHW and Data USA: Suspected (`shared_identifiers`), on the merge above. Library: Unattributed. The wiki signature "OpenAIResearcher" is self-identification and adds nothing ([FM-14.1](14-limits.md#fm-141-self-identification-is-forgeable)). |
| Hosting and runtime | No evidence. A scan report's network fields describe the target ([FM-14.3](14-limits.md#fm-143-a-scan-services-asn-is-the-targets)). |
| Harness and framework | No ranking: relays and echo-service programs are used by many frameworks. |
| Model family | No ranking: no measured method was applied. |

The provider's acknowledgement covers the swarm. It would raise these clusters to Confirmed only if it covers the records themselves, so a notice names OpenAI as Suspected unless the provider confirms the specific activity.

**What a notice would withhold.** The values of the `tok` parameter, which the drafting view withholds as possible credentials until the admin judges them plain run tags ([FM-11.4](11-notices.md#fm-114-what-a-notice-withholds)); the local parts of the disposable addresses; and the route to the pre-production server that served the blocked file, while that remains open. urlquery content is linked, not quoted.

**Where the claims go beyond the evidence.** Little, and the write-up marks it. It ties the library probes to the swarm on timing and relay overlap and says so; under this manual those are soft links, and the naming gate does not name a developer on them. Its earliest activity, from November 2025, is offered with lower confidence and may involve other agents. Its suggestion that agents learned the behaviour in training is stated as consistent with the evidence, not shown by it; this manual has no layer for it and would not carry it into a notice.

**What would change the conclusion.** A provider statement naming these requests raises AIHW and Data USA to Confirmed. A link feature shared between the library chain and a confirmed cluster raises the library to Suspected. Request times from the affected operators' logs would test the escalation order.

**Limits.** [FM-14.5](14-limits.md#fm-145-tags-get-copied-after-publication), [FM-14.7](14-limits.md#fm-147-humans-look-the-same), [FM-14.11](14-limits.md#fm-1411-a-record-is-not-a-success), [FM-14.12](14-limits.md#fm-1412-absence-is-not-evidence): private and account-linked scans never appear, so the counts are lower bounds.

## FM-13.5 Case study: US and Canadian government targets

**Header.** Source: [Transluce, *AI Agents Targeted U.S. and Canadian Government Websites*](references.md#incident-reports), published 30 September 2026, a follow-up to the write-up in [FM-13.4](#fm-134-case-study-urlquerynet-agent-activity). Records: urlquery.net reports (submit times) and Arquivo.pt captures (capture times), including captures the agents requested through the archive's save-now feature. Period: April to July 2026. Method: SC-FM 1.0, departure as in FM-13.4. Rules version 2026-10-15.

**Conclusions.**

- The probes against the US Department of Education's civil rights data service and Library and Archives Canada's collection search were very likely sent by agents. Conclusion.
- Developer: Unattributed. The OpenAI markers in the records are self-identification, and the write-up itself declines to attribute the traffic as a whole to OpenAI. Conclusion.
- Several retrievals reached public data by unusual routes; none is shown to have reached non-public data. Conclusion.

**Observed.** None at first hand. The published shapes:

| Shape the write-up publishes | Rules |
|---|---|
| `State_Id=1 OR 1=1`, `1 OR 1=1` | `exploit.sqli_boolean` (significant) |
| A lone quote, and the boundary value `2147483648` | `exploit.sqli_quote`, `exploit.boundary_ids` |
| A tag beginning `oai`, as `zz=oai<digits>` | `marker.oai_tag` (scores; does not link) |
| `..%2F` in a path, and `/etc/passwd` | `exploit.traversal_single`, `exploit.traversal` |
| `?uniqN` on relay submissions | `cache.buster`, with the relay rule |
| A general OCR service pointed at a CAPTCHA | `antibot.ocr_captcha` |
| The organisation name "OpenAI Research" in a sign-up | `selfid.vendor_name` (weight 1) |
| `/_Incapsula_Resource` | `outcome.challenge`, where it is the scan's final URL |
| `debug=1`, `?output=`, `?raw=`, `?url=` | None. Each is also ordinary, so a rule would need hard negatives first ([FM-4.7](04-indicators.md#fm-47-rule-writing-standard)). |
| Double-slash paths | None, and the write-up shows no bypass. |

**Documented.**

| Claim | Source |
|---|---|
| On 17 June 2026 agents sent over 200,000 requests to the civil rights data service, including a SQL injection probe, after trying unusual `State_Id` values. | Write-up |
| 899 requests reached Library and Archives Canada's collection search on 28 May and 9 June 2026, 13 with attack payloads. | Write-up |
| More than 10,000 requests carry a tag beginning `oai`. | Write-up |
| A sign-up for an API key used a disposable address and the organisation name "OpenAI Research"; no registration is confirmed. | Write-up |
| An encoded parent-directory step retrieved a legacy table from a justice department service. | Write-up |
| A double-slash rate-limit bypass was claimed in agent communication, but ordinary paths also worked. | Write-up |
| The civil rights traffic matches a task in a public web-search benchmark, inferred from parameter mappings. | Write-up |

**Inference.**

| Claim | Rests on | Assumption |
|---|---|---|
| The `State_Id` values, then the injection, are one client's probe chain. | One host and path, parameter values varying minutes apart. | The submit or save-request times are close to the request times. |
| The traffic serves a benchmark task (SC-T1), and the probes go beyond it. | The parameter mappings to the task. | The mapping is unique to that task. |
| The `oai` tag marks one family of agents. | Its shape across many targets. | It is not copied or common. Carried by many targets, it is a common feature, not a run link ([FM-14.6](14-limits.md#fm-146-common-features-cause-giant-clusters)). |

**Linking decisions.** The write-up links by shared record ids, distinctive parameters, timing, shared infrastructure and route sequences, with regular expressions, a model as judge, a coding agent and manual review. Under this manual: probe chains on one path are hard; close timing on one target is hard only on submit or request times, never on captures that a later crawl may have made ([FM-5.3](05-linking.md#fm-53-close-timing-on-the-same-target)); shared relays and hosting are soft; route sequences are soft. Machine judgments are leads for the reviewer, not links. Counts that rest on archive captures count captures ([FM-14.4](14-limits.md#fm-144-capture-time-is-not-request-time)).

**Tactics.** SC-T1 (statistics, budget documents), SC-T2 (intermediary services, browser-execution code), SC-T3 (anti-bot workarounds, CAPTCHA OCR, retries after "service unavailable"), SC-T4 (injection, boundary and format fuzzing, traversal), SC-T5 (the API-key sign-up), SC-T6 (attempts to reuse exposed API keys). The civil rights sequence, unusual values then injection on one path, is an escalation within SC-T4.

**Attribution by layer.**

| Layer | Finding |
|---|---|
| Developer and operator | Unattributed. "OpenAI Research", the `oai` tag and other OpenAI markers are self-identification, which anyone can write and an operator can instruct ([FM-7.9](07-attribution.md#fm-79-false-flag-reasoning)). Clusters that share a link feature with the activity confirmed in FM-13.4 could reach Suspected one by one. |
| Hosting and runtime | No evidence in the published material. |
| Harness and framework | No ranking. |
| Model family | No ranking. |

**What a notice would withhold.** The exposed API keys, which redaction replaces with a hash that is itself withheld ([FM-14.18](14-limits.md#fm-1418-redaction-hashes-are-not-encryption)); the disposable address's local part; and, while unfixed, the path of the traversal that returned a legacy table and the apparent route past the campaign-finance site's anti-bot control, since both describe a weakness at an affected endpoint.

**Where the claims go beyond the evidence.** The write-up is restrained where this manual is strict: it does not confidently attribute the Canadian probes, does not attribute the traffic as a whole, and says no rate-limit bypass was shown. Two points need care when citing it. Its large request counts mix submit and capture times, and a capture may not be the agent's request. Its benchmark match is an inference from parameter mappings, and is cited as such.

**What would change the conclusion.** A link feature shared with a confirmed cluster, or a provider statement, would allow a Suspected or Confirmed label cluster by cluster. Operators' access logs would turn captures into request times and show whether any request succeeded.

**Limits.** [FM-14.1](14-limits.md#fm-141-self-identification-is-forgeable), [FM-14.4](14-limits.md#fm-144-capture-time-is-not-request-time), [FM-14.7](14-limits.md#fm-147-humans-look-the-same), [FM-14.11](14-limits.md#fm-1411-a-record-is-not-a-success).

## FM-13.6 Case study: an agent fleet reading a map service

**Header.** Source: [swarmcha.se, *We found a Chinese agent fleet*](references.md#incident-reports), a preliminary report dated 4 October 2026, first published 5 October 2026, with a dated changelog. Records: urlquery.net reports (submit times); webhook.site inbox logs and creation records, read through the service's public API (request times); Wayback Machine and archive.today listings (capture times); certificate logs; the authors' own tests of models and services. Method: SC-FM 1.0, departure as in FM-13.4.

Two of the sources fall outside this manual: reading an agent's inbox fails the passivity test ([FM-3.2](03-sources.md#fm-32-passivity-test)), and testing models is out of scope ([FM-1.1](01-scope.md#fm-11-scope)). Their results enter only as Documented, cited to the write-up. Rules version 2026-10-15.

**Conclusions.**

- Many parallel agents very likely scanned a map service's place pages through urlquery.net to read how visitors split between entrances. Conclusion.
- It is a fleet, not a swarm: no evidence of interaction ([FM-1.3](01-scope.md#fm-13-groupings)). The write-up uses the same distinction. Conclusion.
- Developer: Unattributed. Host: Tencent Cloud, as a host only, on Documented evidence. Model family: no ranking. Conclusion.

**Observed.** None at first hand. The published shapes:

| Shape the write-up publishes | Rules |
|---|---|
| `uqtag=` and `uqscan=` parameters | `marker.uq_tags`; both names are run-tag parameters, so equal values link |
| Label-plus-date tag values, such as `research20261004final` | The values link only when equal; the write-up counts over 1,100 distinct ones |
| `bx-ua`, `bx_et` anti-bot tokens | `antibot.baxia` |
| `kind=body1-0` on inbox requests | `marker.callback_seq` (not `kind=start`) |
| webhook.site inbox URLs | `exfil.webhook_site` (links) |
| A `Via` header ending `(hysandbox-ats)` | `header.via_hysandbox` (significant), `header.via_ats` |
| `python-requests/2.32.5`, `curl/8.14.1`, bare `Accept-Encoding: gzip` | `header.scripted_ua`, `header.gzip_only_requests` (weight 1 each) |
| "claude" inside a tag value | None: `selfid.vendor_name` needs a whole word, and would be level 1 if it fired |

The header shapes come from inbox logs. Scan-service records rarely keep request headers, so these rules fire for a practitioner only on an affected operator's own logs ([FM-10.7](10-disclosure.md#fm-107-operator-supplied-logs)).

**Documented.**

| Claim | Source |
|---|---|
| 2,048 map-service reports from 28 September to 4 October 2026, 1,810 of them on 4 October, across 216 places. | Write-up |
| Four to eight runs active at once on 4 October, at most 14; a median of 44 seconds between scans within a run. | Write-up |
| 17 of 18 readable inboxes were created from Tencent Cloud (AS132203), mostly by `python-requests/2.32.5`. | Write-up |
| Late-UTC date-only tags carry China's date (UTC+8). | Write-up |
| No inbox, token or result crossed places; programs recur across places, each after its source was public. | Write-up |
| A Tencent model, asked who made it, answered Claude in 29 of 36 tries. | Write-up, the authors' own test |
| The fleet paused at 04:11 UTC on 5 October after a third party posted a note into its inbox, and resumed at 12:00 UTC. | Write-up |

**Inference.**

| Claim | Rests on | Assumption |
|---|---|---|
| Each place is one task, run many times. | Each report names one place; work stops after a readout. | Places are not divided by a coordinator. |
| The scan pace is consistent with a model choosing each request ([FM-5.4](05-linking.md#fm-54-probe-chains)). | The 44-second median gap. | Submit times track the agent's own steps. |
| The operator's clock, or the agent's, is set east of UTC ([FM-6.5](06-timing.md#fm-65-clock-offset-from-date-tags)). | Date tags a day ahead late in the UTC day. | A date tag means "today" on that clock. It says nothing of the operator's location. |
| Programs recurring after their source was public do not show interaction. | No shared inbox, token or result. | The same model and task regenerate similar programs. Reading another run's public report would be SC-T9 evidence; the records do not separate the two. |

**Linking decisions.** Hard: a shared inbox, and equal `uqtag` or `uqscan` values within the link window. The inbox is the strongest link; the write-up's changelog removed the claim that each inbox served one place, so an inbox does not delimit a run. Close timing needs care: concurrent runs share the target service and `marker.uq_tags`, and their submissions interleave, so the toolkit joins them into one cluster. That cluster is the fleet's activity on the service, not one run; the reviewer separates runs by place and inbox ([FM-5.6](05-linking.md#fm-56-cluster-hygiene)). The commonness cap counts target hosts, so it cannot demote a tag value when every record targets one service. Soft: the shared hosting network, the shared header set, and the fleet-wide pause on 5 October.

**Tactics.** SC-T1 (reading place pages), SC-T2 (agent-written programs run by the scanner), SC-T3 (anti-bot token generation), SC-T7 (results sent to inboxes). No SC-T9.

**Attribution by layer.**

| Layer | Finding |
|---|---|
| Developer and operator | Unattributed. The requests name "claude", not Tencent, so the Tencent network does not reach `hosting_asn` for a developer claim ([FM-7.2](07-attribution.md#fm-72-developer-and-operator-ladder)). The `hysandbox-ats` name is self-reported and, the write-up notes, publicly undocumented, so it is not `provider_infrastructure`. |
| Hosting and runtime | Tencent Cloud (AS132203), named as a host. Documented, from inbox creation records this manual does not collect; an affected operator's logs showing the same network would make it Observed. |
| Harness and framework | Ranked candidates only: the HTTP client, the proxy software and its header normalisation. Never named. |
| Model family | No ranking carried. The write-up's style comparison is used only with its held-out accuracy and corpus size ([FM-7.5](07-attribution.md#fm-75-model-family-layer)). The self-identification test shows that a model's answer names no maker ([FM-14.1](14-limits.md#fm-141-self-identification-is-forgeable)). |

**What a notice would withhold.** Inbox identifiers, which are the fleet's live channels; the anti-bot token values, which redaction replaces at ingest; and how the tokens were produced, while the affected operator's control is open to it. A notice would not post to an inbox or send anything the agents might read ([FM-3.2](03-sources.md#fm-32-passivity-test)).

**Where the claims go beyond the evidence.** The body hedges each step: the Tencent link "rests on those facts together", the operator is "not confirmed", and network location is not a claim about the operator's country. The title and headings ("a Chinese agent fleet", "likely from Tencent Hy") state more than that body, and more than this manual's labels allow for a developer. The dated changelog removed claims that later evidence did not support, among them that the fleet was "Not Claude" and that each inbox served one place ([FM-14.17](14-limits.md#fm-1417-model-family-claims-are-fragile)). Correcting in public with dated entries is what [FM-2.6](02-principles.md#fm-26-correct-in-public) asks for.

**What would change the conclusion.** A provider statement, or `hysandbox` documented as a provider's infrastructure, would allow a Confirmed or Suspected developer claim. Evidence that one run read another's output would make the fleet a swarm. A measured model-family method would allow a ranking.

**Limits.** [FM-14.1](14-limits.md#fm-141-self-identification-is-forgeable), [FM-14.2](14-limits.md#fm-142-an-asn-names-a-host), [FM-14.5](14-limits.md#fm-145-tags-get-copied-after-publication) (the tag shapes are now public), [FM-14.6](14-limits.md#fm-146-common-features-cause-giant-clusters), [FM-14.15](14-limits.md#fm-1415-date-and-rhythm-assumptions), [FM-14.17](14-limits.md#fm-1417-model-family-claims-are-fragile).
