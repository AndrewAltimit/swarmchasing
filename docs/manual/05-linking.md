# 5. Linking

[Manual index](README.md) · Previous: [4. Indicators](04-indicators.md) · Next: [6. Timing](06-timing.md)

## FM-5.1 Hard and soft links

Linking decides which records belong to one operator. It is the step whose errors cost most: a false merge attributes one operator's activity to another, and every later claim inherits it.

| Link | Effect | Examples |
|---|---|---|
| **Hard** | Joins records into one cluster, automatically. | A shared link feature within its bounds; close timing on the same target with a rule in common; a probe chain. |
| **Soft** | Proposes that clusters may be one operator. Never joins them. | Shared pauses; shared payload dialect; reruns; the same uncommon path set or recon opening; the same hosting network; the same captured secret. |

Only flagged records (score above zero) are linked. Ordinary traffic to the same host is never swept into a cluster. A cluster needs at least two records, and hard links are transitive: if A links to B and B to C, all three are one cluster. Each cluster lists the features and links that joined it, so a reader can check them.

## FM-5.2 Shared link features

Two records that carry the same link feature are hard-linked. A link feature is the matched text of a rule marked `link`, or the value of a parameter named as a run-tag parameter (`uqtag`, `run`, `session` and similar), at least three characters long.

The standard bounds this link two ways:

- **Time bound.** The two records fall within a set interval of each other. Beyond it, the shared feature is a soft link: an inbox reused months later may have changed hands, or the value may have been copied.
- **Commonness cap.** A feature carried by more distinct targets or clusters than a set cap, or quoted in a published report, is demoted to a soft link. Common values (`test`, `1`, a tag a report made famous) are not identifiers ([FM-14.5](14-limits.md#fm-145-tags-get-copied-after-publication)).

Toolkit: shared features link only within `feature_link_window_secs` of each other, and a feature carried by more than `feature_max_hosts` target hosts is listed as a common feature instead of linking (both in the rules file's `[linking]` table). A tag quoted in a public report is listed under `published_tags` in the same table, each with its source; a feature whose value is one of them (ignoring case) never links, however few hosts carry it, and is listed as a common feature with that reason. A quoted tag missing from the list still links, so the reviewer adds a tag when a report quotes it.

## FM-5.3 Close timing on the same target

Consecutive flagged records to the same target host, at most a set window apart, that share at least one rule are hard-linked. The shared rule keeps two unrelated clients who happened to hit the same host in the same minutes apart, unless they also share an indicator.

Records that name two different clients **must not** be joined this way: a site in the news draws many unrelated agents within minutes. Two records name different clients when both carry addresses and they differ, or when neither carries one and their user agents differ. A run behind rotating proxies sends each request from an address it never uses again, so two addresses each seen on one record alone could still be one client. Toolkit: each record joins the latest earlier record on the host that could be its own client's, so another client's requests in between do not cut a run; probe chains ([FM-5.4](#fm-54-probe-chains)) keep the same rule.

The shared rule **must not** be a context indicator: a relay, a cache buster, self-identification, a header or an outcome, the kinds ordinary clients produce too ([FM-14.9](14-limits.md#fm-149-stacking-across-a-cluster)). Every reader of a page through a popular relay shares the relay rule, and a record submitted beside a real cluster needs nothing more to join it ([FM-5.11](#fm-511-provenance-and-planted-records)). Toolkit: only non-context rules count for this link.

Close timing is only as good as the timestamps. It **should** use request or submission times; capture times say when an archive saved a URL, not when an agent sent it ([FM-6.1](06-timing.md#fm-61-timestamp-kinds)). Toolkit: only request and submit times link this way, with times of unknown kind read as requests; two archive captures minutes apart are never joined by timing ([FM-6.1](06-timing.md#fm-61-timestamp-kinds)). Popular targets read through popular relays are the usual false merge here ([FM-14.6](14-limits.md#fm-146-common-features-cause-giant-clusters)).

## FM-5.4 Probe chains

A probe chain is one client trying variants of one request: requests to the same host and path, each within a few minutes of the last, with at least three distinct parameter sets and at least one parameter whose value changes. The flagged requests in a chain are hard-linked even when different rules fired on each, because the chain itself is the evidence of one client.

A chain's gaps are timing, so they rest on what the timestamps measure ([FM-6.1](06-timing.md#fm-61-timestamp-kinds)). A chain **must** be timed by request or submit times to hard-link: two archive captures minutes apart say when a crawler saved two URLs, not that one client sent them in sequence. A chain timed by capture times is listed as a hint, and its records join only through a shared identifier or another hard link. Toolkit: a chain hard-links its flagged records only when its time basis is request or submit (`TimeBasis::is_request_like`); a capture-timed chain is reported with its basis and reads no pace, and joins nothing on its own.

A chain also carries description that never changes a link: its pace (median gap) and its retries after an error. A sub-second pace reads as a script or scanner; seconds to minutes is consistent with a model choosing each request; a changed request sent right after an error response suggests a reader of the error. Both are hints ([methodology](../methodology.md#linking-into-clusters)).

## FM-5.5 Runs

Within a cluster, a gap longer than a set run gap starts a new run. A run approximates one working session. Runs are the unit for rerun detection ([FM-5.10](#fm-510-reruns)), escalation sequences ([FM-5.9](#fm-59-escalation-sequences)) and concurrency ([FM-6.3](06-timing.md#fm-63-concurrency-and-fan-out)).

## FM-5.6 Cluster hygiene

Before a cluster is used in a report, the reviewer checks:

- **What joined it.** Every link feature and every timing link. A cluster held together by one weak timing link between two otherwise separate groups is two clusters with a soft link.
- **Size against spread.** A cluster that grows across many unrelated targets, sources and days usually rests on a common feature. Find it and treat it as soft.
- **Targets.** Malformed URLs (a doubled scheme, a missing colon) can yield a bogus target host, and a bogus host shared by unrelated records produces timing links. Check that each target is a real host.
- **Provenance.** Which kinds of source stand behind it, and whether any record could not have been submitted by anyone ([FM-5.11](#fm-511-provenance-and-planted-records)).

## FM-5.7 Soft links

Soft links are leads for a reviewer, listed with the evidence for each:

| Soft link | What it suggests | Why it is not hard |
|---|---|---|
| Shared pauses | One scheduler, quota or operator behind two clusters. | Cron jobs share stop times; tested against a chance model ([FM-6.7](06-timing.md#fm-67-shared-pauses)). |
| Payload dialect | The same uncommon mix of test payloads. | Payload lists are copied widely. |
| Same unusual path set or recon opening | The same task script or model habit. | Popular targets attract the same paths; polite crawlers share openings. |
| Rerun | One task run again on another day ([FM-5.10](#fm-510-reruns)). | Two tasks can target the same list. |
| Shared hosting network | One runtime. | Many tenants share a cloud network. |
| Link feature outside its bounds | Same operator, later. | Copied or reassigned values ([FM-5.2](#fm-52-shared-link-features)). |
| Archive burst | Something drove many captures of one host at once. | Crawlers and readers burst too. |
| Shared captured secret | One client's captured token used again by another cluster. The strongest soft link. | A token can leak or be published. Stock passwords are sent by everyone and do not count. |
| Same relay stack | The same chain of two or more relays and carriers: one harness's route. | Tools and tutorials share routes. A single relay is every relay user's habit and does not count. |
| Same callback service | A fresh inbox per run on one service: one operator's habit. | Many clients use the same service. The same inbox is a hard link ([FM-5.2](#fm-52-shared-link-features)). |
| Shared scaffold | One harness behind clusters with separate inboxes and tags ([FM-5.14](#fm-514-scaffold-fingerprints)). | Popular libraries and frameworks give unrelated operators one request shape. |
| Co-activity | One dispatcher starting both, or one starting the other ([FM-6.9](06-timing.md#fm-69-co-activity)). | One scheduler drives unrelated jobs; busy clusters overlap. |
| Co-target | One target list worked by several agents in the same hours, each in its own order ([FM-5.16](#fm-516-co-targets)). | A story or a disclosed flaw sends unrelated agents to one site at once. |
| Ordered co-target | One ordered target list worked by several agents at once, each at its own pace ([FM-5.19](#fm-519-ordered-co-targets)). | A public ranked or sorted list gives every reader one order. |
| Scaffold lineage | One harness changed mid-fleet: templates one part apart ([FM-5.20](#fm-520-scaffold-lineage)). | A framework release changes every user's template the same way. |
| Prompt echo | Queries written from one prompt, each naming its own target ([FM-5.21](#fm-521-prompt-echo)). | Published query and dork lists give unrelated users one wording. |
| Co-group | Three or more clusters on the same rare sites or templates, past the pairwise caps ([FM-5.22](#fm-522-co-groups)). | A story naming several sites, or a framework's default templates, reaches many operators at once. |
| Identifier generator | One machine, clock or counter behind fresh run tags ([FM-5.23](#fm-523-identifier-generators)). | Cloned images and published tag schemes give unrelated operators one generator. |
| Playbook | One harness's probe steps in one order on each host ([FM-5.24](#fm-524-playbook-alignment)). | A scanner's default order and cheat sheets give unrelated operators one order. |

A soft link or edge with a chance model is one test of many: an analysis of `n` clusters compares up to `n(n-1)/2` pairs, and a 1% chance per pair gives one false pair in every hundred compared. Each such family of tests (shared pauses, scaffolds, scaffold lineage, prompt echoes, co-activity, ordered co-targets, co-groups, identifier generators, each interaction signal, platform candidates) **must** count the pairs it tested, keep only pairs that survive a false-discovery-rate cut over all of them, and state how many pairs that unlikely chance alone would give among them, so a reviewer reads a kept pair against its family's budget.

## FM-5.8 Candidate fleets, merge and split

Clusters joined by soft links form a **candidate fleet**. A candidate fleet is never merged automatically. The admin decides, and the decision is a dated entry in the case with:

- the clusters merged or split, by stable key (a name that survives renumbering, taken from the cluster's earliest record, so a record added later cannot change it);
- the evidence for the decision, by link and record;
- what would reverse it.

Merges and splits are reversible and both are logged. A fleet grows, merges with another or breaks apart as evidence arrives. This mirrors how threat-intelligence teams handle uncategorised activity clusters, which "can grow, merge with, or break off from other clusters" before they are named ([Mandiant](references.md#attribution-practice)).

Soft links are weighed before they are grouped ([FM-5.17](#fm-517-weighing-soft-links)). A candidate fleet **should** be a group whose clusters are tied to each other, not a chain: when one cluster is tied to two groups that share no tie, the two groups are two proposals, and the cluster joins at most one of them. A proposal states how dense it is and its weakest cut, the ties whose loss would split it, so the reviewer sees where it is thin.

Toolkit: the analysis lists soft links between clusters with a kind and a likelihood ratio (shared pauses, dialect pairs, reruns, path sets, encodings, fan-out width, cut lengths, header sets, escalations, common features, captured secrets, relay stacks, callback services, shared scaffolds, scaffold lineage, prompt echoes, co-activity, co-targets, ordered co-targets, co-groups, identifier generators), and groups strongly soft-linked clusters into candidate fleets by community detection, each with its density and weakest cut, shown in internal reports ([methodology](../methodology.md#descriptive-hints)). Candidate fleets never merge clusters or change a tier.

The admin records a merge or split with `case fleet merge` / `case fleet split`, which logs the soft links behind it in the case's decision log; reports and exports then treat the merged clusters as one fleet.

## FM-5.9 Escalation sequences

An escalation sequence is the order in which tactics appear within a run, or across a fleet's runs: for example task retrieval (SC-T1), then circumvention after a block (SC-T3), then probing (SC-T4), then a callback channel (SC-T7). The sequence is evidence of intent forming during the task rather than given at its start, and of how far the agent went.

A report states the sequence with the first record of each step. It is an Inference ([FM-7.6](07-attribution.md#fm-76-claim-tags)): records can be missing, and capture times can reorder steps ([FM-6.1](06-timing.md#fm-61-timestamp-kinds)). Toolkit: route escalation (a direct request, then a relay, then a program carrier, then a remote browser, for one host and path within a set window) is reported as a hint on the clusters it touches and as a soft link between them, leaving capture-time records out ([methodology](../methodology.md#descriptive-hints)). A page another cluster asked for within a day is a crowd's, where who climbed is unknown, and draws none.

The STIX run object lists a run's tactics in order of first appearance ([FM-12.2](12-interoperability.md#fm-122-the-x-sc-agent-run-extension)). The reviewer states the tactic sequence and its first records by hand.

## FM-5.10 Reruns

A rerun is a later run that repeats an earlier run's target hosts in nearly the same order, on another day, in a different cluster. Hosts that many runs share count for little, and a list more than a few clusters walk is a published one, not one operator's task, and draws no rerun. A rerun is a soft link between the two clusters, and is evidence that a task is scheduled or repeated, which bears on whether an incident is still active ([FM-11.3](11-notices.md#fm-113-status-lifecycle)). The toolkit's thresholds are in [methodology](../methodology.md#descriptive-hints).

## FM-5.11 Provenance and planted records

A public record shows that someone put a URL into a source, not that an agent sent it. Classify each record by who can do that:

| Provenance | Who can create the record | Examples |
|---|---|---|
| Observed | Only the server that received the request. | Access logs, logs an affected operator sends. |
| Submit-anywhere | Anyone, for any URL. | Scan services; web archives, whose on-demand saves an index row cannot tell from crawls. |
| Publish-anywhere | Anyone, under a name they choose. | Package registries, public code events, certificate logs, crawls of what pages link to. |

A cluster **should** state its provenance and its corroboration: one kind of source, several kinds, or confirmed in an operator's logs. Several scan services are one kind: whoever submits to one can submit to all. Provenance **must not** raise or lower a tier ([FM-4.1](04-indicators.md#fm-41-grading-records)), because nearly every public cluster is single-source; it tells the reader what the records can show.

Someone who wants a false incident found, or a real cluster attributed elsewhere, can plant records. Linking **must** resist the cheap plants: a record joins a cluster only through a shared identifier, a shared non-context rule within the window ([FM-5.3](#fm-53-close-timing-on-the-same-target)), or a probe chain, and a cluster's stable key comes from its earliest record, so a later record cannot rename it. Before a report, the reviewer checks the plant signals:

- **Provenance monoculture.** Every record is submit-anywhere and nothing was observed.
- **Burned identifier.** An identifier quoted in a published report ([FM-14.5](14-limits.md#fm-145-tags-get-copied-after-publication)).
- **Too perfect.** Every record significant on several kinds of evidence, with no ordinary requests around it, no escalation and no task retrieval.
- **Habit mismatch.** An identifier shared with an earlier cluster whose relay routes, URL encodings or payloads share nothing with this one's.
- **Auto-submitted.** Its targets went to several scan services within seconds, and ordinary links on other hosts were fanned out the same way around it: a mail gateway or security product submitted them, and whoever sent the links made the records.
- **Seam.** The cluster hangs on one record, or on the records of one client: without it, two groups of at least a few records each fall apart, and their habits (relay routes, URL encodings, payloads) or their clients have nothing in common. Hard links are transitive, so one record carrying two operators' identifiers merges them; the seam names that record and both sides.

A plant signal is informative only against its base rate. Provenance monoculture fires on every cluster built from one scan service, which is most clusters in such a collection; a signal that fires on nearly every cluster of a source tells the reviewer nothing about this one. Each signal **should** be reported with its base rate: the share of the analysis's clusters from the same source kinds that carry it. A signal carried by more than half of them is context, listed but not counted towards the plant review threshold ([FM-10.9](10-disclosure.md#fm-109-self-review-and-second-review)).

A seam is read on the cluster's link graph, where each shared feature, run of close requests and probe chain joins its records at once, so a record is a joint only when nothing else holds the two sides together. A joint is a single record (an articulation point of that graph) or every record of one client taken out together. The seam **must not** split the cluster: the reviewer decides whether the sides are two operators ([FM-5.6](#fm-56-cluster-hygiene)).

Toolkit: each plant signal carries its kind's base rate across the clusters; a kind on more than half (with at least four) is reported with that rate and does not count toward the threshold (`PlantSignal::counts()`).

Each is a prompt, never a finding, and stays out of reports to providers and operators and out of notices. Toolkit: `provenance`, `corroboration` and `plant_signals` on each cluster; provider and internal reports carry the provenance line, and case notes a *Plant review* section ([methodology](../methodology.md#provenance-and-plant-review)).

## FM-5.12 Interaction edges

An interaction edge joins two runs that may have acted on each other's output, on one of the signals in [FM-4.10](04-indicators.md#fm-410-interaction-signals). It is a hint like a soft link, with two differences: it is between runs, not clusters, and it never proposes a fleet. Edges are never scored and never merge clusters.

Hard links can hide interaction. A shared inbox joins every record that writes to it into one cluster, so two agents reporting to one sink become one cluster and their exchange is invisible at cluster level. The standard therefore splits each run into **strands** by how its records were sent (relay route, user agent, network, header set) and compares strands, inside a cluster as well as across clusters. Two strands count as different clients only when they differ on at least two of those dimensions or their encoding style, and share no user agent, network or header set.

Where a signal has a chance model it is stated with the edge: synchronized starts weigh requests lined up step by step against the shorter run placed at random over the analysis span and against its own gaps reordered, and report the larger chance, so two jobs that start together at a steady rate do not qualify; role sequences and partitions draw hosts at random from the analysis's target hosts or target family, and a partition whose hosts split their sorted list in a stride or in blocks is weighed against every split of those hosts into parts of those sizes.

A dispatch star weighs each follower's lagged co-activity with the leader as co-activity does ([FM-6.9](06-timing.md#fm-69-co-activity)), and **must** also show the direction: the follower's nearest requests fall after the leader's more often than chance allows at even odds, since clusters set off together by one trigger, or busy in the same minutes, fall either side alike. A follower's chance is the larger of the two. It requires the followers' own lags to agree with their lags to the leader, counts as different clients only clients that differ in a way of sending known on both sides, and combines the followers' chances, corrected for the candidates the leader had and for which run of the star leads.

Followers of different clients do not rule out a common trigger, whose audience is many clients. So after a star passes, every other cluster active in the leader's hours is scored as a stand-in leader of the same followers, and the leader's rank among them is the star's chance: under one trigger many clusters lead the followers about equally well, and only a leader no other cluster leads them as well as survives. A follower that is itself a leader chains the stars into a **dispatch tree**, a description of who set off whom in the terms of a Hawkes branching process, not a fitted model.

Each such signal is tested on many pairs of runs, so it **must** be cut at a false discovery rate over every pair it read, and the edge states how many pairs that unlikely chance alone would give among them ([FM-5.7](#fm-57-soft-links)).

A reviewer who accepts an edge records it in the case with what the records show; until then the grouping is a fleet ([FM-1.3](01-scope.md#fm-13-groupings)). Toolkit: thresholds are in [methodology](../methodology.md#interaction-between-runs); internal and provider reports list edges under *Possible interaction (SC-T9)*, and affected-operator reports and notices never do.

## FM-5.13 Cluster lifecycle and identifiers

Activity moves through stages, each with its own identifier and its own bar. The stages follow how threat-intelligence teams handle uncategorised activity: a cluster is created from an anchoring characteristic, can grow, merge or break off, and "graduates" into a named group only on substantial evidence ([Mandiant](references.md#attribution-practice)).

| Stage | Identifier | Who sets it | Bar to enter |
|---|---|---|---|
| **Cluster** (provisional) | Stable key `k-` plus 8 hex digits; a display number (`C1`) that changes between analyses. | The analysis. | Two flagged records joined by hard links ([FM-5.1](#fm-51-hard-and-soft-links)). |
| **Candidate fleet** | A display number (`F1`) per analysis; `FK-` plus 8 hex digits across watch runs ([FM-5.18](#fm-518-fleets-across-windows)). | The analysis. | Soft links between clusters above a set strength ([FM-5.8](#fm-58-candidate-fleets-merge-and-split)). |
| **Case fleet** | `fleet-<n>`, unique within one case. | The admin. | A recorded merge decision with its evidence and what would reverse it. |
| **Named fleet** | `SCF-<n>`, unique across all cases and never reused. | The admin. | Published in a notice, or seen in two cases, with the merge evidence reviewed again. |
| **Swarm** | The fleet's identifier, unchanged. | The admin. | Reviewed interaction evidence ([FM-1.3](01-scope.md#fm-13-groupings)). |

Rules for identifiers:

- **Stable from the earliest record.** A cluster key is derived from the cluster's earliest record, so later records, retries or plants cannot rename it ([FM-5.11](#fm-511-provenance-and-planted-records)).
- **Merge.** When two named fleets merge, the older identifier survives and the other becomes its alias. Notices that used the alias get a dated update naming the survivor.
- **Split.** When a fleet splits, the part holding the earliest record keeps the identifier and the other part takes a new one. Both decisions are logged with the links that changed.
- **Never reused.** A withdrawn or merged identifier is retired, never given to new activity.
- **Neutral names.** A fleet identifier carries no provider, model, country or organisation name. A name is not an attribution, and a neutral one cannot become a false one when the attribution changes.

Moving back is allowed at every stage: a swarm whose interaction record is withdrawn is a fleet again, and a named fleet whose merge evidence fails review is split, with the reason logged. Toolkit: cluster keys, candidate fleets and their `FK-` keys, case fleets (`case fleet merge`, `case fleet split`) and swarm records are built ([cases](../reference/cases.md#swarms)). Named fleets, aliases and cross-case identifiers are (planned); until then a notice refers to a fleet by its case and `fleet-<n>`.

## FM-5.14 Scaffold fingerprints

A fleet built on one harness (one prompt, one tool wrapper, one request builder) can give every agent its own inbox and run tag, so no identifier joins its clusters. Its requests still share a structure. A **scaffold fingerprint** reduces each record, after unwrapping, to a template with every value replaced by its slot type:

- the relay and carrier route, outermost first;
- the path's shape: each segment's type (word, number, hex, UUID, token), with a short file extension kept;
- the parameters in the order sent, each as its name and the kind of its value (a URL, a payload, prose, a secret, or a number, word or token with a length class); a name that is itself a URL is a slot, since it names a host;
- the URL's encoding choices ([FM-5.7](#fm-57-soft-links));
- the canonical test payloads it carries, and whether it was cut off.

Two clusters are compared by their mixes of templates, each template weighted down by how many clusters hold it and counted once per target host, so a retried request is one request. Two guards keep a popular library or framework, which gives unrelated operators one shape, from reading as one fleet:

- **Specificity.** A template ties clusters only when it has several structural parts. A bare search through one relay has too few.
- **Chance.** Each shared template has a base rate among the clusters that send structured requests at all: its other holders, and any records outside the clusters that carry it, over those clusters. A pair is kept only when two unrelated clusters would rarely both hold the rarest template they share at that rate, corrected for how many usable templates they share (the least of several is likelier than one), and the pair survives a false-discovery-rate cut over the pairs compared; the expected number of such pairs is stated.

Records outside the clusters only ever add holders, so concatenating unrelated traffic into an analysis cannot make a shape rare. A shape one part away from a common default (a framework's shape with one setting each operator picks) is read within the default: two of its users match on that part by the shape's share of the default's senders, which is rarely rare. A shape held by more than a few senders is a common default and ties none: a large fleet on one harness and many operators on one framework look the same in the records.

A shared scaffold is a soft link ([FM-5.7](#fm-57-soft-links)). It **must not** merge clusters or raise a tier: a published harness, a tutorial or a framework default makes it without any tie between operators, and the chance model only knows the records in the analysis. The templates hold no host, path word or value, so the evidence shows how requests were built without repeating what they said. Toolkit: `scaffold_pairs` in the analysis and the `scaffold` soft link, with the settings in `[scaffold]` ([methodology](../methodology.md#descriptive-hints)).

## FM-5.15 Coordinated accounts on public platforms

Agent swarms also show up on platforms where accounts publish: many accounts opening near-identical issues or comments, creating repositories, packages or Spaces with templated names, or filing templated vulnerability reports. Here the unit is an account's public action, not a request, and the grouping is a **platform swarm candidate**: accounts acting alike beyond chance. It is a hint for review, like an interaction edge ([FM-5.12](#fm-512-interaction-edges)); it never joins a cluster and never makes a fleet or a swarm on its own.

What is read and kept **must** pass the passivity test ([FM-3.2](03-sources.md#fm-32-passivity-test)): public event archives and registry listings only, with no URL inside the text fetched and no account, repository, package or Space opened. Collection **should** keep no more personal data than grouping needs: a keyed hash in place of the login, a coarse account-age rank in place of the account id, and the text reduced to a sketch with URLs, addresses, mentions, numbers and identifiers replaced by slots.

A candidate needs all of:

- **A shared shape.** Near-duplicate text (estimated similarity of word shingles), one template once per-instance values are slots, or created items whose names follow one template with a counter or identifier. A plain name many people pick ("portfolio") is not a template.
- **Several accounts.** At least three distinct accounts, or, where the source names no account, a flood of at least five items, reported as such.
- **More than chance.** The densest burst of the accounts' first actions, weighed against the same number of actions placed at random over the window read (a scan statistic), and the share of new accounts, weighed against the accounts first seen in the same hours, combined as one test at most 1% and surviving a false-discovery-rate cut over every group weighed. The two are not multiplied as if independent: a wave of new accounts arrives in bursts, so the age share is read in the group's own hours. A burst starting on a clock hour counts a quarter, as a coincidence on the hour does for co-activity ([FM-6.9](06-timing.md#fm-69-co-activity)). Model-output residue ([FM-4.5](04-indicators.md#fm-45-artifact-families)) in at least half the members can stand in for the chance.

Benign coordination is common and **must** be ruled out before a candidate is read as a swarm: dependency and release bots, translation syncs, contribution drives and coursework, scheduled jobs, organisation-wide automation, an outage that brings many users to one project at once, and issue templates. Known automation accounts are dropped at collection and known benign templates are listed as suppressed with their kind. A burst on one owner's projects by established accounts is not reported. Each candidate lists what is left to rule out.

A registry candidate **may** be read beside its packages' build provenance, where the registry publishes it: the source repository and workflow a signed build statement names. Several packages naming one repository or workflow is a strong same-operator hint and ties a registry fleet to the code host account behind it; it remains a hint, since one monorepo publishes many packages by design. No provenance is weak context. Provenance is looked up for reported candidates' members only, within a budget, and **must not** change a candidate's chance or strength.

Toolkit: `sc_core::platform` and `swarmchase platform-swarms`; the watch's platform pass lists new and grown candidates in the digest ([methodology](../methodology.md#coordinated-accounts-on-public-platforms), [watch](../reference/watch.md#platform-swarms)).

## FM-5.16 Co-targets

Several agents of one operator often get one target list. They work it in the same hours, each at its own pace and in its own order, with their own inboxes and tags: too loose for a synchronised start ([FM-5.12](#fm-512-interaction-edges)), too unordered for a rerun ([FM-5.10](#fm-510-reruns)). A **co-target** is two clusters active on the same rare targets, host and kind of action, within an hour or so of each other, more often than chance allows.

- **Rare targets only.** A target many senders touch ties none: a news story, a disclosed flaw or a popular service sends unrelated agents to one site at once, and in an operator's own log every record names the operator's host. The holders counted include records outside the clusters.
- **Several hosts.** One shared host is a coincidence of interest; the shared targets **must** span several hosts.
- **Chance.** The chance of sharing that many targets is computed as if one cluster's targets were drawn at random from every rare target in the analysis, which leaves time aside and so overstates how often unrelated clusters meet. Pairs are kept under a false-discovery-rate cut over the pairs tested.

A co-target is a soft link and **must not** merge clusters: two operators can be handed one list by a third party, and a list can be published. Toolkit: `cotarget_pairs` in the analysis and the `co_target` soft link, with the settings in `[co_target]` ([methodology](../methodology.md#timing)).

## FM-5.17 Weighing soft links

Each kind of soft link is weighed as a likelihood ratio: how much likelier it is between two clusters of one operator than between unrelated ones. Two rules keep weak ties from adding up to a false proposal:

- **Rarity.** A value many clusters share says less than one two clusters share, and its weight falls with the share of clusters holding it.
- **Dependence.** Kinds that read one habit are not independent evidence. Encoding, header set, relay stack, scaffold, scaffold lineage, prompt echo, payload dialect, cut length, fan-out and co-groups on templates all describe one harness; shared pauses and co-activity one timeline; reruns, path sets, recon openings, co-targets, ordered co-targets, escalations and co-groups on sites one target list; captured secrets, common features, callback services and identifier generators what an operator holds. A pair **should** count only its strongest tie within each such family, and combine across families.
- **Joint dependence.** Families are not independent either: clusters running at the same time draw co-activity (timeline) and co-targets (targets) from that one fact. Where two families can fire together for one reason, their combined ratio **should** be capped at the measured ratio of the two firing together, and never fall below the stronger family alone.

The ratios **should** come from measurement: labelled fleets where they exist, and a simulator with ground truth otherwise, with a conservative bound taken rather than the point value. A kind with no measured evidence is off or weighed by stated judgment. Toolkit: `swarmchase sim calibrate` prints each kind's ratio from the simulator, and each family pair's joint ratio; the rules file says which ratios and joint caps come from it ([methodology](../methodology.md#descriptive-hints)).

## FM-5.18 Fleets across windows

An analysis covers a window of days. A slow fleet, one cluster a week, can be weak in every window and plain across several. A watch that follows clusters from run to run ([watch](../reference/watch.md#the-ledger)) follows candidate fleets too:

- **Keys.** A candidate fleet is keyed `FK-` plus 8 hex digits from its earliest member's history, so renumbering does not rename it. A key is never given to another fleet. A fleet continues the earlier one whose members it overlaps most, one to one.
- **Evidence over time.** Each pair of cluster histories keeps the weight of its soft links across runs. Overlapping windows read the same records and **must** count once: a run adds only when every record it read for the pair comes after the records counted last, and otherwise replaces that count when stronger. Old evidence decays.
- **A conservative bound.** A pair is listed as persistent only when its accumulated weight passes the upper threshold of a sequential test at a small error rate.

Persistent pairs are proposals in the admin's digest, like candidate fleets. They never merge clusters, change a tier or reach a provider, operator or public report. Toolkit: `FK-` keys and persistent pairs in the watch's ledger and digest.

## FM-5.19 Ordered co-targets

A target list is often ordered, and agents handed one list tend to work it in that order, each at its own pace. A co-target ([FM-5.16](#fm-516-co-targets)) ignores order; a rerun ([FM-5.10](#fm-510-reruns)) needs another day; a synchronised start ([FM-5.12](#fm-512-interaction-edges)) needs requests within seconds. An **ordered co-target** is two clusters, active at the same time, that first touched the rare hosts they share in the same order more often than chance allows.

- **First touches, request times only.** Each cluster's order is the order of its first request to each shared host. Capture times **must not** be read: an archive's crawl order is not the client's.
- **The statistic.** The longest run of shared hosts both clusters touched in the same order. A tie in either cluster's times **must not** count as agreement.
- **Chance.** The chance of so long a run when the shared hosts are put in a random order; exactly computed for a few dozen hosts, and bounded from above beyond that. Pairs are kept under a false-discovery-rate cut over the pairs tested.
- **Sorted lists.** A public list sorted by name or by number, or a published ranking, gives every reader one order without a shared operator. A pair whose two orders both follow the hosts' sorted order as far as they follow each other **must not** be tied.
- **Time-ordered sources.** Concurrent readers of one source that publishes hosts over time (a certificate log, newly registered domains, a trending list) touch them in the order they arrive, without a shared operator. A pair whose two orders both follow the order the shared hosts first appear in other records, outside every cluster above noise, as far as they follow each other **must not** be tied. Clusters above noise do not set that order, or one operator's other agents would explain its pairs away; readers of a source whose hosts no other record touches remain indistinguishable from one operator's list.

An ordered co-target is a soft link in the targets family and **must not** merge clusters: a list can be shared, and a ranking the toolkit does not know reads as an order. Toolkit: `ordered_cotarget_pairs` in the analysis and the `ordered_co_target` soft link, with the settings in `[co_target]` ([methodology](../methodology.md#timing)).

## FM-5.20 Scaffold lineage

An operator who upgrades a harness mid-fleet changes one part of its request structure: a parameter added or renamed, another encoding, a new payload set, another relay. Scaffold fingerprints ([FM-5.14](#fm-514-scaffold-fingerprints)) compare exact templates, so the fleet splits at the upgrade. **Scaffold lineage** compares templates one structural part apart.

- **Deletion neighbourhood.** A specific template with at least one part more than the specificity floor yields one key per structural part dropped, and its own key. Two templates differing in one part, or one a part longer than the other, share a key. A pair already sharing a template is the scaffold test's, not this one's.
- **Chance.** Each key has a base rate as a template does, with outside records counted as more holders; a key held by more than a few senders is a common default and ties none. Templates built from common parts are often one part apart by chance, so the chance **must** account for every key a cluster holds, not only those shared: the chance that an unrelated cluster holds as many of one side's keys as the other does, keys held by overlapping sets of clusters counting once. That chance **must** pass on its own; the handover only adds to it.
- **Handover.** An upgrade has a before and an after: only pairs where one cluster ends before the other starts are compared, and the chance of a gap that short under random placement of the two spans is combined with the template chance as one test.

Pairs are kept under a false-discovery-rate cut over the pairs compared. Scaffold lineage is a soft link in the harness family and **must not** merge clusters: a framework release changes every user's template the same way. Toolkit: `lineage_pairs` in the analysis and the `scaffold_lineage` soft link, read with the `[scaffold]` settings ([methodology](../methodology.md#descriptive-hints)).

## FM-5.21 Prompt echo

Agents given one prompt write their search and form text from one template, each naming its own target. A **prompt echo** is two clusters whose prose parameter values (several words of natural language) are near-duplicates once each value's per-instance parts are slots: the target's own name, numbers, URLs, addresses and identifiers.

- **Shape.** Equal slotted text, or near-duplicate word shingles (estimated similarity of at least 0.6), as for platform text ([FM-5.15](#fm-515-coordinated-accounts-on-public-platforms)).
- **Public wording.** Dork lists, benchmark prompts and tutorials give unrelated users one wording. A template matching a listed public query, each listed with its source, **must not** tie clusters; one carried by more than a few senders, records outside the clusters counted, is a common default.
- **Chance.** The base rate of the template among the clusters writing prose at all, read as the chance that an unrelated cluster meets one side in as many of its templates as the other does (templates carried by overlapping sets of clusters counting once), and a false-discovery-rate cut over the pairs compared. A prompt copied by a few unrelated operators **cannot** be told from one operator's by its wording alone.

A prompt echo is a soft link in the harness family and **must not** merge clusters. The evidence quotes only the slotted template: the target's name **must** be a slot in each form prose writes it (its labels, the parts of a hyphenated label and those parts joined, and their possessives). Toolkit: `prompt_echo_pairs` in the analysis and the `prompt_echo` soft link, with the settings in `[prompt_echo]` ([methodology](../methodology.md#descriptive-hints)).

## FM-5.22 Co-groups

A fleet larger than a few clusters escapes every pairwise target and harness test: a host or template held by more than a few senders is treated as popular, since a news story sends many unrelated agents to one site and a framework gives many operators one request shape. A **co-group** is three or more clusters all holding several features few others hold, beyond what the clusters' and features' own counts explain.

- **Features.** A rare site (its registrable domain) in one stretch of hours, a specific request template, a prose template. The hosts of one site **must** count as one feature: a story names one site, a list names many. A feature whose records always carry another, and prose templates carried by exactly the same clusters, **must** count once. Listed benchmark and practice targets **must not** count.
- **Group.** Clusters all holding the same features, and only those clusters: a closed biclique of the cluster-by-feature matrix, with a minimum of clusters and of features.
- **Null.** The matrix randomised with each cluster's number of features and each feature's number of holders kept (swap randomisation), a site moving only to a cluster active in its hours. A group's chance is the share of randomised matrices whose strongest group is as strong, which accounts for every group the analysis could have found. That chance is already familywise over the groups found, so they are not corrected again one by one: groups are kept under a false-discovery-rate cut over the matrices mined.

A co-group ties each pair of its clusters with a soft link, in the targets family for sites and the harness family for templates, and **must not** merge clusters. A large fleet on one site reads as a news spike; a story naming several sites, or a framework with several default templates, can read as a group. Toolkit: `co_groups` in the analysis and the `co_group` soft link, with the settings in `[biclique]` ([methodology](../methodology.md#descriptive-hints)).

## FM-5.23 Identifier generators

A fleet that gives each agent a fresh run tag defeats linking on the tag ([FM-5.2](#fm-52-shared-link-features)). How the tags were generated often survives: a time-based UUID carries its host's node id, a Snowflake id its worker, a time-ordered id (UUIDv7, ULID, KSUID) its generator's clock, and a counter its next number. An **identifier generator** link is two clusters whose generated identifiers decode to one generator.

- **Node ids.** A UUIDv1 or v6 node id in both. A random node id (multicast bit set) **must not** count. A node id carried by many senders (cloned images, shared builders) **must not** tie, nor one seen only in one site's own URLs.
- **Workers.** A Snowflake datacenter and worker, read only where the id's time falls near the record's.
- **Clock skew.** The embedded time minus the time the identifier was first sent, read only from identifiers the agent generates (a target site mints its own ids, and agents fetching a fresh one share the site's clock), stable over a cluster's identifiers, clear of an ordinary clock and of whole quarter hours (time-zone errors), and shared within seconds. Its chance comes from a fixed prior on skews, never from the skews seen.
- **Counters.** One stem, with numbers within a few of each other across the two clusters.
- **Chance.** Each key's chance between unrelated generators, the pair's smallest corrected for the keys it shares, and a false-discovery-rate cut over the pairs compared.

A node id is a device identifier: it **must not** be stored or shown, nor any value computed from it alone, since a hash of a 48-bit id with a known vendor prefix is reversed by trying the few candidates. It is shown as a label that means something only within one analysis (`node A`). An identifier generator link is a soft link in the identifiers family and **must not** merge clusters: a shared builder image or a published tag scheme gives unrelated operators one generator. Toolkit: `generator_pairs` in the analysis and the `generator` soft link, with the settings in `[generator]` ([methodology](../methodology.md#descriptive-hints)).

## FM-5.24 Playbook alignment

One harness runs a task script: on each host it sends its probe steps in one order, recon before traversal before injection, whatever run tag, inbox or step counter it changes between agents. Scaffold fingerprints ([FM-5.14](#fm-514-scaffold-fingerprints)) and scaffold lineage ([FM-5.20](#fm-520-scaffold-lineage)) compare the set of request templates; a **playbook** compares their order. It is read only on hosts, never on dialect, scaffold or preambles, which compare sets or an exact opening.

- **Steps.** A step is a request template ([FM-5.14](#fm-514-scaffold-fingerprints)) with the parameters that carry linking values (run tags) dropped, so a new tag style or inbox leaves it unchanged. Each cluster's steps on each host, by request and submit time (capture times **must not** be read: an archive's crawl order is not the client's), a repeat in a row dropped, are one sequence. A cluster's profile is its most common sequence, a playbook when it has several steps on several hosts.
- **Alignment.** Two profiles are aligned locally (weighted Smith-Waterman): a matched step scores by its rarity (IDF), gaps are penalised, and the statistic sums each of one cluster's host sequences aligned with the other's profile, both ways, so a playbook seen on many hosts weighs more than one seen once.
- **Chance.** The order's chance is a permutation null: each cluster's steps shuffled within each host, the share of shuffles aligning as well, which keeps every step set and asks only about order; it **must** pass on its own. The rarest aligned step has a base rate as a scaffold template does (its other holders and outside records over the comparable clusters), and its chance combines with the order's as one test, kept under a false-discovery-rate cut over the pairs compared.
- **Public orders.** A public scanner's default order and cheat-sheet orders give unrelated operators one order; a pair whose aligned steps' payload classes follow a listed common order **must not** be tied, and a step carried by more than a few senders is a common default.

A playbook is a soft link in the harness family and **must not** merge clusters. The steps hold no host, path word or value, so the evidence shows the order requests were built in without repeating what they said. Toolkit: `playbook_pairs` in the analysis and the `playbook` soft link, with the settings in `[playbook]` ([methodology](../methodology.md#descriptive-hints)).
