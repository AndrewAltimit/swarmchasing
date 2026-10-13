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

## FM-5.8 Candidate fleets, merge and split

Clusters joined by soft links form a **candidate fleet**. A candidate fleet is never merged automatically. The admin decides, and the decision is a dated entry in the case with:

- the clusters merged or split, by stable key (a name that survives renumbering, taken from the cluster's earliest record, so a record added later cannot change it);
- the evidence for the decision, by link and record;
- what would reverse it.

Merges and splits are reversible and both are logged. A fleet grows, merges with another or breaks apart as evidence arrives. This mirrors how threat-intelligence teams handle uncategorised activity clusters, which "can grow, merge with, or break off from other clusters" before they are named ([Mandiant](references.md#attribution-practice)).

Toolkit: the analysis lists soft links between clusters with a kind and a strength (shared pauses, dialect pairs, reruns, path sets, encodings, fan-out width, cut lengths, header sets, escalations, common features, captured secrets, relay stacks, callback services, shared scaffolds, co-activity), and groups strongly soft-linked clusters into candidate fleets, shown in internal reports. Candidate fleets never merge clusters or change a tier. The admin records a merge or split with `case fleet merge` / `case fleet split`, which logs the soft links behind it in the case's decision log; reports and exports then treat the merged clusters as one fleet.

## FM-5.9 Escalation sequences

An escalation sequence is the order in which tactics appear within a run, or across a fleet's runs: for example task retrieval (SC-T1), then circumvention after a block (SC-T3), then probing (SC-T4), then a callback channel (SC-T7). The sequence is evidence of intent forming during the task rather than given at its start, and of how far the agent went.

A report states the sequence with the first record of each step. It is an Inference ([FM-7.6](07-attribution.md#fm-76-claim-tags)): records can be missing, and capture times can reorder steps ([FM-6.1](06-timing.md#fm-61-timestamp-kinds)). Toolkit: route escalation (a direct request, then a relay, then a program carrier, then a remote browser, for one host and path within a set window) is reported as a hint on the clusters it touches and as a soft link between them, leaving capture-time records out ([methodology](../methodology.md#descriptive-hints)). The STIX run object lists a run's tactics in order of first appearance ([FM-12.2](12-interoperability.md#fm-122-the-x-sc-agent-run-extension)). The reviewer states the tactic sequence and its first records by hand.

## FM-5.10 Reruns

A rerun is a later run that repeats an earlier run's target hosts in nearly the same order, on another day, in a different cluster. Hosts that many runs share count for little. A rerun is a soft link between the two clusters, and is evidence that a task is scheduled or repeated, which bears on whether an incident is still active ([FM-11.3](11-notices.md#fm-113-status-lifecycle)). The toolkit's thresholds are in [methodology](../methodology.md#descriptive-hints).

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

A plant signal is informative only against its base rate. Provenance monoculture fires on every cluster built from one scan service, which is most clusters in such a collection; a signal that fires on nearly every cluster of a source tells the reviewer nothing about this one. Each signal **should** be reported with its base rate: the share of the analysis's clusters from the same source kinds that carry it. A signal carried by more than half of them is context, listed but not counted towards the plant review threshold ([FM-10.9](10-disclosure.md#fm-109-self-review-and-second-review)).

Toolkit: each plant signal carries its kind's base rate across the clusters; a kind on more than half (with at least four) is reported with that rate and does not count toward the threshold (`PlantSignal::counts()`).

Each is a prompt, never a finding, and stays out of reports to providers and operators and out of notices. Toolkit: `provenance`, `corroboration` and `plant_signals` on each cluster; provider and internal reports carry the provenance line, and case notes a *Plant review* section ([methodology](../methodology.md#provenance-and-plant-review)).

## FM-5.12 Interaction edges

An interaction edge joins two runs that may have acted on each other's output, on one of the signals in [FM-4.10](04-indicators.md#fm-410-interaction-signals). It is a hint like a soft link, with two differences: it is between runs, not clusters, and it never proposes a fleet. Edges are never scored and never merge clusters.

Hard links can hide interaction. A shared inbox joins every record that writes to it into one cluster, so two agents reporting to one sink become one cluster and their exchange is invisible at cluster level. The standard therefore splits each run into **strands** by how its records were sent (relay route, user agent, network, header set) and compares strands, inside a cluster as well as across clusters. Two strands count as different clients only when they differ on at least two of those dimensions or their encoding style, and share no user agent, network or header set.

Where a signal has a chance model it is stated with the edge: synchronized starts weigh requests lined up step by step against the shorter run placed at random over the analysis span and against its own gaps reordered, and report the larger chance, so two jobs that start together at a steady rate do not qualify; role sequences and partitions draw hosts at random from the analysis's target hosts or target family. A reviewer who accepts an edge records it in the case with what the records show; until then the grouping is a fleet ([FM-1.3](01-scope.md#fm-13-groupings)). Toolkit: thresholds are in [methodology](../methodology.md#interaction-between-runs); internal and provider reports list edges under *Possible interaction (SC-T9)*, and affected-operator reports and notices never do.

## FM-5.13 Cluster lifecycle and identifiers

Activity moves through stages, each with its own identifier and its own bar. The stages follow how threat-intelligence teams handle uncategorised activity: a cluster is created from an anchoring characteristic, can grow, merge or break off, and "graduates" into a named group only on substantial evidence ([Mandiant](references.md#attribution-practice)).

| Stage | Identifier | Who sets it | Bar to enter |
|---|---|---|---|
| **Cluster** (provisional) | Stable key `k-` plus 8 hex digits; a display number (`C1`) that changes between analyses. | The analysis. | Two flagged records joined by hard links ([FM-5.1](#fm-51-hard-and-soft-links)). |
| **Candidate fleet** | None of its own; listed by its clusters' keys. | The analysis. | Soft links between clusters above a set strength ([FM-5.8](#fm-58-candidate-fleets-merge-and-split)). |
| **Case fleet** | `fleet-<n>`, unique within one case. | The admin. | A recorded merge decision with its evidence and what would reverse it. |
| **Named fleet** | `SCF-<n>`, unique across all cases and never reused. | The admin. | Published in a notice, or seen in two cases, with the merge evidence reviewed again. |
| **Swarm** | The fleet's identifier, unchanged. | The admin. | Reviewed interaction evidence ([FM-1.3](01-scope.md#fm-13-groupings)). |

Rules for identifiers:

- **Stable from the earliest record.** A cluster key is derived from the cluster's earliest record, so later records, retries or plants cannot rename it ([FM-5.11](#fm-511-provenance-and-planted-records)).
- **Merge.** When two named fleets merge, the older identifier survives and the other becomes its alias. Notices that used the alias get a dated update naming the survivor.
- **Split.** When a fleet splits, the part holding the earliest record keeps the identifier and the other part takes a new one. Both decisions are logged with the links that changed.
- **Never reused.** A withdrawn or merged identifier is retired, never given to new activity.
- **Neutral names.** A fleet identifier carries no provider, model, country or organisation name. A name is not an attribution, and a neutral one cannot become a false one when the attribution changes.

Moving back is allowed at every stage: a swarm whose interaction record is withdrawn is a fleet again, and a named fleet whose merge evidence fails review is split, with the reason logged. Toolkit: cluster keys, candidate fleets, case fleets (`case fleet merge`, `case fleet split`) and swarm records are built ([cases](../reference/cases.md#swarms)). Named fleets, aliases and cross-case identifiers are (planned); until then a notice refers to a fleet by its case and `fleet-<n>`.

## FM-5.14 Scaffold fingerprints

A fleet built on one harness (one prompt, one tool wrapper, one request builder) can give every agent its own inbox and run tag, so no identifier joins its clusters. Its requests still share a structure. A **scaffold fingerprint** reduces each record, after unwrapping, to a template with every value replaced by its slot type:

- the relay and carrier route, outermost first;
- the path's shape: each segment's type (word, number, hex, UUID, token), with a short file extension kept;
- the parameters in the order sent, each as its name and the kind of its value (a URL, a payload, prose, a secret, or a number, word or token with a length class);
- the URL's encoding choices ([FM-5.7](#fm-57-soft-links));
- the canonical test payloads it carries, and whether it was cut off.

Two clusters are compared by their mixes of templates, each template weighted down by how many clusters hold it. Two guards keep a popular library or framework, which gives unrelated operators one shape, from reading as one fleet:

- **Specificity.** A template ties clusters only when it has several structural parts. A bare search through one relay has too few.
- **Chance.** A shape is rare only against traffic that could have shown it. Each shared template has a base rate: the share of the analysis's senders holding it, a cluster counting once and every record outside the clusters, unflagged ones included, counting as a sender of its own. A pair is kept only when two unrelated clusters would rarely both hold the rarest template they share at that rate and the pair survives a false-discovery-rate cut over every cluster pair; the expected number of such pairs is stated. A shape held by more than a set number of clusters ties none of them. With little traffic outside the clusters, a shape many clusters hold reads as popular; with much, fewer clusters suffice and a larger fleet on one shape reads as less likely by accident, not more.

A shared scaffold is a soft link ([FM-5.7](#fm-57-soft-links)). It **must not** merge clusters or raise a tier: a published harness, a tutorial or a framework default makes it without any tie between operators, and the chance model only knows the records in the analysis. The templates hold no host, path word or value, so the evidence shows how requests were built without repeating what they said. Toolkit: `scaffold_pairs` in the analysis and the `scaffold` soft link, with the settings in `[scaffold]` ([methodology](../methodology.md#descriptive-hints)).

## FM-5.15 Coordinated accounts on public platforms

Agent swarms also show up on platforms where accounts publish: many accounts opening near-identical issues or comments, creating repositories, packages or Spaces with templated names, or filing templated vulnerability reports. Here the unit is an account's public action, not a request, and the grouping is a **platform swarm candidate**: accounts acting alike beyond chance. It is a hint for review, like an interaction edge ([FM-5.12](#fm-512-interaction-edges)); it never joins a cluster and never makes a fleet or a swarm on its own.

What is read and kept **must** pass the passivity test ([FM-3.2](03-sources.md#fm-32-passivity-test)): public event archives and registry listings only, with no URL inside the text fetched and no account, repository, package or Space opened. Collection **should** keep no more personal data than grouping needs: a keyed hash in place of the login, a coarse account-age rank in place of the account id, and the text reduced to a sketch with URLs, addresses, mentions, numbers and identifiers replaced by slots.

A candidate needs all of:

- **A shared shape.** Near-duplicate text (estimated similarity of word shingles), one template once per-instance values are slots, or created items whose names follow one template with a counter or identifier. A plain name many people pick ("portfolio") is not a template.
- **Several accounts.** At least three distinct accounts, or, where the source names no account, a flood of at least five items, reported as such.
- **More than chance.** The densest burst of the accounts' first actions, weighed against the same number of actions placed at random over the window read (a scan statistic), and the share of new accounts, weighed against the window's base rate, together at most 1%. A burst starting on a clock hour counts a quarter, as a coincidence on the hour does for co-activity ([FM-6.9](06-timing.md#fm-69-co-activity)). Model-output residue ([FM-4.5](04-indicators.md#fm-45-artifact-families)) in at least half the members can stand in for the chance.

Benign coordination is common and **must** be ruled out before a candidate is read as a swarm: dependency and release bots, translation syncs, contribution drives and coursework, scheduled jobs, organisation-wide automation, an outage that brings many users to one project at once, and issue templates. Known automation accounts are dropped at collection and known benign templates are listed as suppressed with their kind. A burst on one owner's projects by established accounts is not reported. Each candidate lists what is left to rule out.

Toolkit: `sc_core::platform` and `swarmchase platform-swarms`; the watch's platform pass lists new and grown candidates in the digest ([methodology](../methodology.md#coordinated-accounts-on-public-platforms), [watch](../reference/watch.md#platform-swarms)).
