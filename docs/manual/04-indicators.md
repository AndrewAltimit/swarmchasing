# 4. Indicators

[Manual index](README.md) · Previous: [3. Sources](03-sources.md) · Next: [5. Linking](05-linking.md)

## FM-4.1 Grading records

Indicators are rules kept as data, versioned, and shared by every tool that grades records. Before rules run, each recorded URL is unwrapped: relays, translate proxies, URL-valued parameters, `data:` URLs and base64 values are peeled into layers, so rules see every hop and the real target ([methodology](../methodology.md#unwrapping)).

- Each rule counts at most once per record, whichever layer it matched.
- A record's score adds the weights of the distinct rules that fired. Rules that read the same artifact are one piece of evidence, not several, and count once per independence group; context kinds together count at most one below the suggestive threshold ([FM-4.11](#fm-411-independence-groups-and-the-context-cap)).
- The score is graded against two thresholds into a tier ([FM-1.5](01-scope.md#fm-15-evidence-tiers)). A rule marked significant puts a record in the top tier on its own.
- **One relay hit is never enough.** No rule for something ordinary users do may reach the suggestive threshold alone. A relay, a cache-buster or a self-identification needs a second, independent indicator, and that indicator is not another context hit ([FM-4.11](#fm-411-independence-groups-and-the-context-cap)).
- **A tier measures payload and tool use.** It says what a record contains, not whether an agent sent it or whether the agent went beyond its task. Those are separate questions with their own evidence ([chapter 15](15-misalignment.md)).

## FM-4.2 Rule anatomy

| Field | Meaning | Toolkit |
|---|---|---|
| `id` | Stable dotted name, `<kind>.<name>`. Reports cite it. | yes |
| `kind` | The family of thing matched: relay, carrier, exploit, agent marker, callback channel, header, outcome, anti-bot, infrastructure, self-identification, cache-buster. | yes |
| `target` | What the rule reads: a layer's host, a layer's decoded text, parameter names or values, headers, user agent, final URL. | yes |
| `pattern` | Host suffix, or a case-insensitive regular expression. | yes |
| `check` | A named test a parameter-value match must also pass, for what a regular expression cannot say. | `repeated_token` |
| `weight` | Contribution to the score. Low for anything ordinary clients also do. | yes |
| `significant` | A single match puts the record in the top tier. Reserved for unambiguous payloads and fingerprints. | yes |
| `link` | The matched text becomes a link feature. Only for values one operator would hold. | yes |
| `tactic` | The SC-T tactic the match is evidence of ([FM-4.3](#fm-43-the-sc-t-tactic-taxonomy)). | one of `tactic` or `artifact` |
| `artifact` | The match only shows a model wrote the request ([FM-4.5](#fm-45-artifact-families)). | one of `tactic` or `artifact` |

A check exists because some shapes need counting or comparing. `repeated_token` wants one word of three characters or more, or a phrase of two or three words, repeated five or more times in a row ([FM-4.5](#fm-45-artifact-families)); short refrains and one long run of a letter fail it.

Toolkit: each rule in the rules file names its tactic (`T1` to `T7`) or is marked `artifact`, and a file naming an unknown tactic, or the cluster-level `T8` or `T9`, fails to load. A check on a rule that does not read parameter values, or an unknown check, also stops the file loading. Evaluation groups recall by the tactics of the rules that fired ([statistics](../reference/evaluation.md#statistics)). The STIX run object derives its `tactics` from each rule's kind, using the defaults in [FM-4.4](#fm-44-default-tactics-by-rule-kind).

## FM-4.3 The SC-T tactic taxonomy

Tactics say what an agent was doing, independent of how a rule detected it. Reports and notices group evidence by tactic.

| Id | Tactic | What it is | Typical evidence |
|---|---|---|---|
| SC-T1 | Task retrieval | Fetching content for the task, often through readers and relays. Usually benign on its own. | Relay and reader URLs to the task's data sources; search queries. |
| SC-T2 | Tool escalation | Reaching for a more capable tool than the task needs: code execution, request shaping, sandboxes. | Echo services turning a GET into a POST; programs in `data:` URLs, base64 paths or playground share links. |
| SC-T3 | Access-control circumvention | Getting past a block, challenge or rate limit by changing origin or solving the gate. | Relays and scan services after a block; anti-bot token generation; CAPTCHA-solver services; bot-challenge outcomes followed by retries. |
| SC-T4 | Vulnerability probing | Trying inputs designed to make the target misbehave. | Injection, traversal, XSS and template payloads; probe chains; recon openings to sensitive files. |
| SC-T5 | Account and identity acquisition | Creating accounts or identities to get access. | Sign-up requests; disposable mail; stock or fabricated identities. |
| SC-T6 | Credential reuse | Using a credential the agent obtained rather than was given. | The same redacted secret hash across targets or runs; tokens in query strings. |
| SC-T7 | Callback and side channels | Sending data or signals to a place the agent's operator can read. | Webhook inboxes, request catchers, notification topics, pastes, out-of-band interaction services. |
| SC-T8 | Off-task targets | Requests to hosts outside the evident task. Needs the task context; one record cannot show it. | A data-gathering run that turns to government login pages. |
| SC-T9 | Inter-agent coordination | Agents exchanging information or dividing work. Defines a swarm ([FM-1.3](01-scope.md#fm-13-groupings)). | One run reading what another wrote to a shared artifact; disjoint target lists from runs started together; hand-offs. |

SC-T8 and SC-T9 are cluster- and fleet-level judgments. They are reported as Inference ([FM-7.6](07-attribution.md#fm-76-claim-tags)) with the evidence listed, never as a rule match. The signals for SC-T9 are in [FM-4.10](#fm-410-interaction-signals).

## FM-4.4 Default tactics by rule kind

The tactic a rule of each kind is evidence of when nothing more specific is known. A rule's own `tactic` may differ where its match shows more, and a report cites the rule's own.

| Rule kind | Default tactic | Note |
|---|---|---|
| relay | SC-T1 | SC-T3 when it follows a block or challenge on the same target. |
| carrier | SC-T2 | |
| exploit | SC-T4 | |
| anti_bot, outcome | SC-T3 | An outcome rule records where a scan ended, such as a challenge page. |
| exfil | SC-T7 | |
| cache_buster | SC-T1 | Weak; defeats caches, not controls. |
| agent_marker, header | none | Artifacts ([FM-4.5](#fm-45-artifact-families)), not actions. |
| self_id, infra | none | Attribution evidence ([chapter 7](07-attribution.md)). |

## FM-4.5 Artifact families

Artifacts are traces of how an agent was built, not of what it tried to do. They help separate agents from people and link runs, but each is shared by many unrelated clients, so most never score or link.

| Family | What it is | Role |
|---|---|---|
| Model-output residue | Text a model wrote around a URL: Markdown link or code syntax, unfilled placeholders, chat-reply openers, doubled schemes. | Scores, low weight; never links. People pasting chatbot answers leave the same. |
| Tool-call residue | Function-call markup, tool-call JSON or argument objects left in a request. | Scores, low weight; never links. |
| Generation loops | One word or a short phrase repeated five or more times in a row, as a model stuck in a loop writes. | Scores at weight 1 through a `check`; never links. |
| Fabricated identifiers | UUIDs no generator produces, hand-typed hashes, stock identities. | Hint; stock identities score at low weight. |
| Stale dates | "Today" date tags well behind the observed date ([FM-6.6](06-timing.md#fm-66-stale-dates)). | Hint. |
| Stale knowledge | Retired API endpoints, old client versions, or an API version below the newest seen on the same host family. | Hint when two or more members carry it. Old scripts and pinned clients do the same. |
| Prose language | Parameter values written as prose, with an offline guess at their language, set against the target's country domain. | Hint. Travellers and English-language sites abroad mismatch too. |
| Relay stacks | The relays and carriers a request went through, outermost first, ending at the target. | Hint; the same stack of two or more hops is a soft link ([FM-5.7](05-linking.md#fm-57-soft-links)). |
| Payload dialect | Which canonical test payloads a cluster prefers, and how deep its traversals go. | Hint; a shared uncommon mix is a soft link. |
| Cut lengths | Truncated URLs cut at nearly the same length, as an output limit would. | Hint. A scan service's display limit does the same ([FM-3.6](03-sources.md#fm-36-known-source-biases)). |
| Encodings | How a URL was written: escape case, space encoding, double encoding, parameter order. | Hint; mostly library defaults. |

Why hints never score or link: letting a widely shared trait raise a score flags ordinary clients, and letting it link merges unrelated clusters, an error every later step inherits ([FM-14.6](14-limits.md#fm-146-common-features-cause-giant-clusters)).

Stale knowledge and prose language say something about where the requests were written: a model writes from what its training data knew, and an agent prompted in one language often searches a foreign site in it. Both are inputs to the model-family and operator layers at most ([FM-7.5](07-attribution.md#fm-75-model-family-layer)), never a name.

Toolkit: retired endpoints and old clients are listed under `[[stale]]` in the rules file, each with its source; a cluster lists each entry two or more members carry (`stale_knowledge`), with older API versions as `older_api_version`. Prose is at least six words with letters, or twelve characters of a script written without spaces; each cluster counts its prose values, their languages and how many mismatch their target's country domain (`prose`). Each cluster counts its members' relay stacks (`relay_stacks`), and reports list those of two or more hops ([methodology](../methodology.md#descriptive-hints)).

## FM-4.6 Cross-walk to MITRE ATLAS and ATT&CK

The table maps each SC-T tactic to the closest [ATLAS](references.md#threat-frameworks) technique (data version 2026.09) and [ATT&CK](references.md#threat-frameworks) technique where the mapping is defensible. **Fit** says how closely: *close* (same behaviour), *partial* (overlaps; the framework's technique assumes a different actor or scope), *none*.

ATLAS and ATT&CK describe adversaries using systems. Swarmchasing describes agents whose operator may not intend the behaviour, so a mapping says what the agent did, not that anyone intended it. ATLAS notes this itself for attack-path adaptation, which agents can show while pursuing a benign objective.

| SC-T | ATLAS | ATT&CK | Fit |
|---|---|---|---|
| SC-T1 | AML.T0095 Search Open Websites/Domains; AML.T0116 Autonomous Reconnaissance | T1593 Search Open Websites/Domains | partial |
| SC-T2 | AML.T0117 Autonomous Attack-Path Adaptation | T1059 Command and Scripting Interpreter | partial |
| SC-T3 | AML.T0117 Autonomous Attack-Path Adaptation | T1090.002 External Proxy | partial |
| SC-T4 | AML.T0049 Exploit Public-Facing Application; AML.T0006 Active Scanning | T1190 Exploit Public-Facing Application; T1595.002 Vulnerability Scanning | close |
| SC-T5 | AML.T0021 Establish Accounts; AML.T0125 Create Account | T1585 Establish Accounts; T1136 Create Account | close |
| SC-T6 | AML.T0012 Valid Accounts; AML.T0091 Use Alternate Authentication Material | T1078 Valid Accounts; T1550 Use Alternate Authentication Material | close |
| SC-T7 | AML.T0072 Cyber Communication Channel; AML.T0025 Exfiltration via Cyber Means | T1567.004 Exfiltration Over Webhook; T1567.003 Exfiltration to Text Storage Sites; T1102 Web Service | close |
| SC-T8 | none | none | none |
| SC-T9 | AML.T0118 Autonomous AI Agent Communication (.000 shared artifacts, .001 direct); AML.T0124 Autonomous Attack Orchestration | none | close |

The OWASP Top 10 for Agentic Applications column, and the agent-specific ATLAS techniques, are in [FM-12.4](12-interoperability.md#fm-124-crosswalk-to-agent-security-frameworks). A STIX or MISP export carries both tables' entries for each tactic ([FM-12.2](12-interoperability.md#fm-122-the-x-sc-agent-run-extension)). ATLAS ids and names are taken from the published ATLAS data file; ATT&CK ids from the ATT&CK technique pages ([references](references.md#threat-frameworks)). Re-check both when either framework releases a new version, since techniques are renamed and merged.

## FM-4.7 Rule-writing standard

A rule enters the shared set only when:

1. **It has a basis.** Either a public reference that documents the behaviour (an incident report, a vendor advisory), or reviewed examples from casework. The reference goes in the rule's comment or the change's description.
2. **It has positives and hard negatives.** At least one labelled agent record it should catch, and at least one benign record built to trip it (the same words in a search, the same service used normally) go into the evaluation set with the rule.
3. **It passes the eval gate.** Precision and recall on the evaluation set stay at or above the floors, and the floors never go down to land a rule ([FM-9.2](09-evaluation.md#fm-92-regression-set)).
4. **Its numbers are recorded.** The change records before and after precision and recall at both tiers, and the rule's own precision.
5. **Its weight is honest.** Anything ordinary users do stays below the suggestive threshold alone. `significant` is for payloads with no ordinary use. `link` is for values one operator would hold, never for values many share.

Synthetic examples are allowed and marked synthetic. Examples are never copied from a source whose terms forbid redistribution ([FM-3.4](03-sources.md#fm-34-terms-of-use)).

## FM-4.8 Rule versions and pinning

A rules set carries a version. Each case pins the version it was opened with, so its reports, notices and evidence bundles use one set throughout, and a rules change cannot silently move a tier between drafting and sending. Re-pinning is an admin decision, logged in the case, after listing the records whose tier would change ([cases](../reference/cases.md#pinned-rules)).

## FM-4.9 Benchmark targets and declared testing

Two hints bear on how a case is handled rather than on what the agent did. Neither scores, and neither lowers a score.

- **Benchmark targets.** Public sites built to be tested against: intentionally vulnerable demo sites, and the environments agent benchmarks run in. A cluster probing one is likely evaluation or training activity, and reports say so. It keeps its tier, because an agent under evaluation can still misbehave in the same run, and its requests to other hosts are what matter.
- **Declared testing.** Text in a request announcing a test: "authorized security test" in a user agent, a bug-bounty header, "pentest" next to an email address or bounty handle. It is self-identification, which anyone can write and an agent can copy from its prompt ([FM-14.1](14-limits.md#fm-141-self-identification-is-forgeable)). The admin checks the claim with the owner it names ([FM-10.6](10-disclosure.md#fm-106-authorised-testing)). The declaring text and contact stay in case notes: they never appear in a report to a provider, a notice or a public page, because the claim is unchecked and the contact may be a person.

Toolkit: benchmark targets are listed under `[[benchmark]]` in the rules file, each with its source, and counted per cluster by entry (`benchmarks`). Declared testing is listed per cluster with its contact (`declared`) and appears in internal reports only; the browser workbench does not show it.

## FM-4.10 Interaction signals

Interaction between agents rarely leaves a direct trace in public records. A record shows one request; it does not show who read its result. No published case detects agent-to-agent coordination from public traffic alone; the strongest published reconstructions match activity timing against a provider's own account. The standard therefore treats every SC-T9 signal as weak to moderate, and a swarm claim as several signals together.

| Id | Signal | What it suggests | Innocent explanation |
|---|---|---|---|
| S1 | Shared sink | Runs, or strands of one run, writing to the same inbox or artifact while sending requests differently. | One agent changing route or tool mid-task. |
| S2 | Hand-off | One run writes to an artifact (an inbox, a gist, a paste, a hosted Space, a static-site subdomain) that a later run fetches. | One operator reading their own notes with another tool. |
| S3 | Synchronized start | Runs of different clients whose requests line up step by step at one offset, beyond chance under random placement and under their own gaps reordered. | One dispatcher driving both runs for one operator. |
| S4 | Role sequence | One run only reads a set of hosts; a differently fingerprinted run then attacks the same hosts in the same order. | A scanner fed from a public list both runs read. |
| S5 | Disjoint partition | Runs started together split one target family with almost no overlap. | One scheduler sharding a list: a fleet signal unless others join it. |

Identifiers are matched as strings already in the records. Reading an artifact, an inbox or a channel to see what was written is never part of the method ([FM-3.2](03-sources.md#fm-32-passivity-test)). How the signals are found and recorded is in [FM-5.12](05-linking.md#fm-512-interaction-edges).

## FM-4.11 Independence groups and the context cap

A score adds weights as if each rule were a separate observation. Rules that read the same artifact are not. One fetch program carried through an echo service fires the echo rule, the script rule, the fetch rule and the title-write rule together, and a benign data task done that way (a program that fetches a TV schedule) reaches the top tier on its tool use alone. Two relays in one route, or a relay and a vendor name in the same query, are two context hits that ordinary clients produce together. Summing them grades how a request was written, not how much evidence it holds.

The standard therefore scores with two constraints:

- **Independence groups.** Rules that read the same artifact in the same request **must** share a group. A group counts once per record, at the largest weight among its rules that fired. Ungrouped rules count as before. A `significant` rule still sets the top tier on its own.
- **Context cap.** Context kinds (relay, cache buster, self-identification, header, outcome) together contribute at most one less than the suggestive threshold. A record whose only hits are context kinds stays noise, however many it has.

A group is a statement about correlation, so it is set from evidence: two rules belong together when, on labelled records, one rarely fires without the other on the same request. The default groups:

| Group | Rules | The shared artifact |
|---|---|---|
| `program` | `carrier.httpbin`, `carrier.data_url_script`, `carrier.inline_fetch_program`, `carrier.form_post_program`, `carrier.html_program`, `marker.title_write` | One program's text, and the echo service that serves it. |
| `relay` | every `relay.*` rule | One fetch route. |
| `run_tag` | `marker.uq_tags`, `marker.test_tag`, `marker.oai_tag` | One tag and its parameter. |
| `sqli` | `exploit.sqli_union`, `exploit.sqli_boolean`, `exploit.sqli_quote` | One injection payload. |
| `traversal` | `exploit.traversal`, `exploit.traversal_single` | One traversal payload. |
| `oast` | `exfil.requestbin`, `exfil.oast_service` | One out-of-band host. |
| `markdown` | `marker.md_link`, `marker.md_url_wrapper` | One Markdown wrapper. |
| `tool_call` | `marker.tool_call_markup`, `marker.tool_call_json`, `marker.json_quote_residue` | One tool-call argument. |
| `proxy_headers` | `header.via_hysandbox`, `header.via_ats`, `header.gzip_only_requests` | One proxy's rewrite of the request. |

The echo service (`carrier.httpbin`) is in `program`: its base64 endpoint serves the page the URL carries, so the echo rule and the script rule read one artifact. Counted apart, a page with a script served from the echo service's own endpoints, an ordinary developer test, reaches suggestive with no other indicator, and the pre-era negative control ([FM-9.13](09-evaluation.md#fm-913-negative-control-and-benign-baseline)) shows it doing so on real captures. A program that makes requests (a fetch, a request object, a self-submitting form) still reaches suggestive through the group's heavier rules. A change of groups is a rule change and passes the [FM-4.7](#fm-47-rule-writing-standard) standard, with its before and after numbers.

What changes: a program through an echo service is suggestive, not significant, unless a payload or a channel comes with it, and a script page with no request through one is noise; a run tag with its own parameter name is one indicator; two relays, or a relay and a vendor name, are noise. Records with an attack payload are unaffected, because payload rules are `significant`. Toolkit: `Rules::score` counts each group once at its largest fired weight and caps the context kinds together at one below suggestive; the default groups are set in [`rules/default.toml`](../../rules/default.toml), and the `group` field and the cap are normative in [SC-Rules v1](../specs/rules-v1.md#independence-groups), with conformance vectors for the records whose tier they decide.
