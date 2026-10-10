# 14. Known limits and traps

[Manual index](README.md) · Previous: [13. Case study](13-case-study.md) · Next: [Glossary](glossary.md)

Each entry is a conclusion that looks sound and is not, with what to do instead. Cite them by id in a case study's limits ([FM-13.1](13-case-study.md#fm-131-template)). Do not walk these paths again.

## FM-14.1 Self-identification is forgeable

A vendor or model name in a request (`?agent=claude`) costs nothing to write. Anyone can submit it to a public scanner, an operator can instruct an agent to use another vendor's name, and agents misreport who built them. It never names a developer ([FM-7.2](07-attribution.md#fm-72-developer-and-operator-ladder)).

## FM-14.2 An ASN names a host

The network a request came from names the company that runs the network. Many tenants share a cloud network. It names a developer only when the network belongs to the company the requests name themselves after, and even then the label is Possible ([FM-7.7](07-attribution.md#fm-77-attribution-labels)).

## FM-14.3 A scan service's ASN is the target's

A scan-service record's address and network usually describe where the scanner reached the submitted URL's host: the target, or the relay in front of it. They say nothing about who submitted the URL. Keep client and target networks apart and never read a target network as the sender's ([FM-7.3](07-attribution.md#fm-73-hosting-and-runtime-layer)).

## FM-14.4 Capture time is not request time

An archive timestamp is when the archive saved the URL. That may be the agent's own save request, or a crawl days later of a page linking to it. Cadence, pauses, rhythm, clock offset and the order of steps cannot rest on capture times ([FM-6.1](06-timing.md#fm-61-timestamp-kinds)).

## FM-14.5 Tags get copied after publication

A run tag or marker quoted in a published report can be reused by anyone who read it, by imitation, testing or mischief. After publication, the tag is a soft link, not a hard one, and a new cluster carrying it is not evidence of the original operator ([FM-5.2](05-linking.md#fm-52-shared-link-features)). Generic tag values (`test`, `1`) collide by chance.

## FM-14.6 Common features cause giant clusters

A feature many unrelated clients share (a popular relay, a common tag value, a library's encoding style, a popular target) joins unrelated records when allowed to link, and links are transitive, so one such feature can merge hundreds of clusters. Only values one operator would hold may hard-link; everything else is a soft link at most ([FM-5.1](05-linking.md#fm-51-hard-and-soft-links)). Two people reading the same popular page through the same relay within minutes look like one client.

## FM-14.7 Humans look the same

A security researcher, a penetration tester or a conventional scanner sending the same payloads through the same services produces the same records. A significant tier means an attack payload was present, not that an agent sent it. Residue, rhythm, escalation and casework separate the two.

## FM-14.8 Model residue comes from people too

A person who pastes a chatbot's answer into a scan form leaves the same Markdown, placeholders and tool-call text an agent does. Residue is weak evidence of an agent and never links records ([FM-4.5](04-indicators.md#fm-45-artifact-families)).

## FM-14.9 Stacking across a cluster

Summing weak rules across a cluster's members lets a large cluster of individually weak records reach a tier no member reached, so the tier never comes from a summed score. A cluster takes its strongest member's tier and rises one step only when at least two members at suggestive or above each carry an indicator kind the other lacks, excluding kinds ordinary clients also produce (relays, cache busters, self-identification, headers, outcomes). Even so, list the member tiers and rules so a reader can see how it got there, and check the links first ([FM-5.6](05-linking.md#fm-56-cluster-hygiene)): a false link also stacks false evidence.

## FM-14.10 Malformed URLs make bogus targets

A doubled scheme (`https://https://…`) or a missing colon can parse to a target host such as `https`. Unrelated records that share the bogus host then look like activity against one target and can be timing-linked. Check each target is a real host before using it ([FM-5.6](05-linking.md#fm-56-cluster-hygiene)).

## FM-14.11 A record is not a success

A record shows that a URL was submitted or captured. It does not show that the request reached the target, or that a payload worked. Reports say "attempted" unless the affected operator's logs or the operator's own statement show more.

## FM-14.12 Absence is not evidence

Archives index late, scan services hold only what someone submitted, and private scans never appear. "No activity since" means "none in the records yet". A notice moves to contained on a set period without matching records and the admin's judgment, not on silence alone ([FM-11.3](11-notices.md#fm-113-status-lifecycle)).

## FM-14.13 Display truncation looks like model truncation

Scan services cut long URLs. A cut payload looks like output an agent's model cut off mid-escape, and repeated cut lengths can be the service's limit, not the model's ([FM-3.6](03-sources.md#fm-36-known-source-biases)).

## FM-14.14 Decoding is heuristic

Base64 detection and unwrapping are heuristics. Truncated payloads decode partly, and an opaque id can rarely decode to text that becomes a layer. Check a decoded layer before resting a claim on it.

## FM-14.15 Date and rhythm assumptions

Clock-offset inference assumes a date tag means "today" on the operator's clock; the rhythm reading assumes an ordinary working day. A fleet scheduled to a fixed UTC window, or an operator with unusual hours, misleads both ([FM-6.4](06-timing.md#fm-64-rhythm), [FM-6.5](06-timing.md#fm-65-clock-offset-from-date-tags)).

## FM-14.16 Cron jobs share pauses

Unrelated scheduled jobs stop and start on the hour together. A shared pause on a clock hour is weak; the chance model down-weights it ([FM-6.7](06-timing.md#fm-67-shared-pauses)).

## FM-14.17 Model-family claims are fragile

Style comparisons and small self-identification tests do not support naming, or excluding, a model family. Published exclusions have been withdrawn after publication ([FM-7.5](07-attribution.md#fm-75-model-family-layer)).

## FM-14.18 Redaction hashes are not encryption

A redacted secret's short hash is unsalted. A short or guessable secret can be recovered by brute force, so a notice **should** withhold them like the secrets they stand for ([FM-11.4](11-notices.md#fm-114-what-a-notice-withholds), [FM-3.7](03-sources.md#fm-37-redaction-at-ingest)).

## FM-14.19 Rules change

A new rules version can move a record between tiers. A case pins its version, and an evidence bundle records it, so anyone can re-run the analysis and get the same tiers ([FM-4.8](04-indicators.md#fm-48-rule-versions-and-pinning)).
