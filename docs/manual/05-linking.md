# 5. Linking

[Manual index](README.md) · Previous: [4. Indicators](04-indicators.md) · Next: [6. Timing](06-timing.md)

## FM-5.1 Hard and soft links

Linking decides which records belong to one operator. It is the step whose errors cost most: a false merge attributes one operator's activity to another, and every later claim inherits it.

| Link | Effect | Examples |
|---|---|---|
| **Hard** | Joins records into one cluster, automatically. | A shared link feature within its bounds; close timing on the same target with a rule in common; a probe chain. |
| **Soft** | Proposes that clusters may be one operator. Never joins them. | Shared pauses; shared payload dialect; reruns; the same uncommon path set or recon opening; the same hosting network. |

Only flagged records (score above zero) are linked. Ordinary traffic to the same host is never swept into a cluster. A cluster needs at least two records, and hard links are transitive: if A links to B and B to C, all three are one cluster. Each cluster lists the features and links that joined it, so a reader can check them.

## FM-5.2 Shared link features

Two records that carry the same link feature are hard-linked. A link feature is the matched text of a rule marked `link`, or the value of a parameter named as a run-tag parameter (`uqtag`, `run`, `session` and similar), at least three characters long.

The standard bounds this link two ways:

- **Time bound.** The two records fall within a set interval of each other. Beyond it, the shared feature is a soft link: an inbox reused months later may have changed hands, or the value may have been copied.
- **Commonness cap.** A feature carried by more distinct targets or clusters than a set cap, or quoted in a published report, is demoted to a soft link. Common values (`test`, `1`, a tag a report made famous) are not identifiers ([FM-14.5](14-limits.md#fm-145-tags-get-copied-after-publication)).

Toolkit: shared features link with no time bound and no commonness cap. The bound and the cap are (planned); until then, the reviewer checks each cluster's link features against both by hand.

## FM-5.3 Close timing on the same target

Consecutive flagged records to the same target host, at most a set window apart, that share at least one rule are hard-linked. The shared rule keeps two unrelated clients who happened to hit the same host in the same minutes apart, unless they also share an indicator.

Close timing is only as good as the timestamps. It **should** use request or submission times; capture times say when an archive saved a URL, not when an agent sent it ([FM-6.1](06-timing.md#fm-61-timestamp-kinds)). Toolkit: records carry their timestamp kind; restricting this link by kind is (planned). Popular targets read through popular relays are the usual false merge here ([FM-14.6](14-limits.md#fm-146-common-features-cause-giant-clusters)).

## FM-5.4 Probe chains

A probe chain is one client trying variants of one request: requests to the same host and path, each within a few minutes of the last, with at least three distinct parameter sets and at least one parameter whose value changes. The flagged requests in a chain are hard-linked even when different rules fired on each, because the chain itself is the evidence of one client.

A chain also carries description that never changes a link: its pace (median gap) and its retries after an error. A sub-second pace reads as a script or scanner; seconds to minutes is consistent with a model choosing each request; a changed request sent right after an error response suggests a reader of the error. Both are hints ([methodology](../methodology.md#linking-into-clusters)).

## FM-5.5 Runs

Within a cluster, a gap longer than a set run gap starts a new run. A run approximates one working session. Runs are the unit for rerun detection ([FM-5.10](#fm-510-reruns)), escalation sequences ([FM-5.9](#fm-59-escalation-sequences)) and concurrency ([FM-6.3](06-timing.md#fm-63-concurrency-and-fan-out)).

## FM-5.6 Cluster hygiene

Before a cluster is used in a report, the reviewer checks:

- **What joined it.** Every link feature and every timing link. A cluster held together by one weak timing link between two otherwise separate groups is two clusters with a soft link.
- **Size against spread.** A cluster that grows across many unrelated targets, sources and days usually rests on a common feature. Find it and treat it as soft.
- **Targets.** Malformed URLs (a doubled scheme, a missing colon) can yield a bogus target host, and a bogus host shared by unrelated records produces timing links. Check that each target is a real host.

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

## FM-5.8 Candidate fleets, merge and split

Clusters joined by soft links form a **candidate fleet**. A candidate fleet is never merged automatically. The admin decides, and the decision is a dated entry in the case with:

- the clusters merged or split, by stable key;
- the evidence for the decision, by link and record;
- what would reverse it.

Merges and splits are reversible and both are logged. A fleet grows, merges with another or breaks apart as evidence arrives. This mirrors how threat-intelligence teams handle uncategorised activity clusters, which "can grow, merge with, or break off from other clusters" before they are named ([Mandiant](references.md#attribution-practice)).

Toolkit: soft links appear in reports and the watch digest as leads (shared pauses, shared dialects, reruns, archive bursts). Candidate-fleet objects and a merge/split command are (planned); today the decision is recorded with a case note.

## FM-5.9 Escalation sequences

An escalation sequence is the order in which tactics appear within a run, or across a fleet's runs: for example task retrieval (SC-T1), then circumvention after a block (SC-T3), then probing (SC-T4), then a callback channel (SC-T7). The sequence is evidence of intent forming during the task rather than given at its start, and of how far the agent went.

A report states the sequence with the first record of each step. It is an Inference ([FM-7.6](07-attribution.md#fm-76-claim-tags)): records can be missing, and capture times can reorder steps ([FM-6.1](06-timing.md#fm-61-timestamp-kinds)). Toolkit support is (planned) and depends on rule tactics ([FM-4.2](04-indicators.md#fm-42-rule-anatomy)).

## FM-5.10 Reruns

A rerun is a later run that repeats an earlier run's target hosts in nearly the same order, on another day, in a different cluster. Hosts that many runs share count for little. A rerun is a soft link between the two clusters, and is evidence that a task is scheduled or repeated, which bears on whether an incident is still active ([FM-11.3](11-notices.md#fm-113-status-lifecycle)). The toolkit's thresholds are in [methodology](../methodology.md#descriptive-hints).
