# 6. Timing and concurrency

[Manual index](README.md) · Previous: [5. Linking](05-linking.md) · Next: [7. Attribution](07-attribution.md)

Timing describes clusters and suggests soft links. Apart from close timing on the same target ([FM-5.3](05-linking.md#fm-53-close-timing-on-the-same-target)), no timing feature changes a score or joins records.

## FM-6.1 Timestamp kinds

Every record states what its time measures. A timing claim names the kind it rests on, and uses only what that kind can support.

| Kind | Measures | Can support | Cannot support |
|---|---|---|---|
| **Request** | When the request reached a server (an operator's access log). | Every timing claim in this chapter. | Nothing excluded. |
| **Submit** | When a URL was submitted to a scan service. When the agent submitted it, this is the agent's own action. | Cadence, bursts, pauses, rhythm, close-timing links, clock offset. | Claims about the target's own logs, or about requests made outside the service. |
| **Capture** | When an archive saved a URL. May be the agent's own save request, or a later crawl of a link to it. | "Requested no later than"; bursts of captures as a lead ([FM-5.7](05-linking.md#fm-57-soft-links)). | Cadence, pauses, rhythm, fan-out, clock offset, close-timing links, the order of steps. |
| **Unknown** | Not stated. | Nothing beyond the record's existence. | Any timing claim. |

Toolkit: every record carries its kind (request, capture, submit, unknown), set from its source, and each cluster and probe chain states its time basis. Rhythm and fan-out skip capture times, chains timed by captures report no pace, and submit times are labelled as such. The close-timing link uses request and submit times only, and reads times of unknown kind as requests, so a source that states no kind is not cut off from it; capture times never join records by timing ([FM-5.3](05-linking.md#fm-53-close-timing-on-the-same-target)). The reviewer still checks the kind behind each timing link of an unknown-kind source.

## FM-6.2 Cadence, bursts and pauses

- **Cadence**: the median and 90th-percentile gap between consecutive records of a cluster.
- **Burst**: at least a set number of records, each within a few seconds of the last.
- **Pause**: a gap at least a set length and at least ten times the median gap, so a slow but steady cadence does not read as a string of pauses.

Cadence separates scripts (sub-second, regular) from agents choosing each step (seconds to minutes, irregular) and from people (slower, with breaks). It is a hint: a script can sleep randomly and a model can be fast.

## FM-6.3 Concurrency and fan-out

**Concurrency** is how many runs of an analysis are active at the same instant. Many concurrent runs from one fleet, each on its own target, is what a parallel fleet looks like.

**Fan-out width** is how many alike requests land in the same second, as when an agent issues tool calls in parallel. A fixed width that repeats across runs can reflect a harness setting ([FM-7.4](07-attribution.md#fm-74-harness-and-framework-layer)).

**Cross-service fan-out** is one target, compared after unwrapping, submitted to several scan services within seconds to a minute. A person checking a link uses one service, or a second one minutes later; an agent's tool loop or a script holding keys for several services sends each URL to all of them at once. It reads submit or request times only, never capture times.

A mail gateway or security product that submits every link it sees does the same, and then whoever mailed the link made the records ([FM-5.11](05-linking.md#fm-511-provenance-and-planted-records)). Its sign is ordinary links on other hosts fanned out alike around the cluster. Without that sign, cross-service fan-out counts toward L4 as a scale beyond one person ([FM-7.10](07-attribution.md#fm-710-agent-likelihood)); with it, it is a counter-signal. It never scores or links, and several services carrying one target are one submitter's act, not corroboration.

## FM-6.4 Rhythm

A rhythm is a cluster's hour-of-day profile, counted in distinct active clock hours rather than records, so one burst does not outweigh a day. It needs enough data: records on several UTC days, a minimum number of records and of active hours.

- The narrowest window of the day holding most active hours, when it is at most about half a day, reads as one time zone's working day. Placing its middle at early afternoon local time gives a guess at the operator's UTC offset.
- A window covering nearly the whole day with high entropy reads as round the clock. People sleep; unsupervised fleets need not.
- Anything else is unclear and is reported as such.

The working-day guess assumes an ordinary schedule. A fleet scheduled to a fixed UTC window gives a misleading offset.

## FM-6.5 Clock offset from date tags

Agents sometimes put "today's" date in a request (`report_date=20260704`). A tag one day ahead of the UTC date, late in the UTC day, means the clock that wrote it is east of UTC; one day behind, early in the UTC day, means west. Each tagged record narrows the range of UTC offsets consistent with all of them. The report gives that range when the records agree, and says when they do not. Tags more than a day from the UTC date are not "today" tags and are left out.

This rests on the assumption that the tag means "today" on the operator's or agent's clock. It is an Inference ([FM-7.6](07-attribution.md#fm-76-claim-tags)).

## FM-6.6 Stale dates

A stale date is a "today" tag at least a week behind the day it was observed. An agent with no clock that writes today's date writes the date it believes it is, often one from its training data. A cluster's stale dates are reported as a pattern only when there are several, they are at least half of its date tags, and most name one date or lag by about the same amount.

A shared stale date across clusters is a soft link at most. It can bear on the model-family layer ([FM-7.5](07-attribution.md#fm-75-model-family-layer)) only as one ranked input, because many models share training cut-offs.

## FM-6.7 Shared pauses

Two clusters that share no identifier but go quiet together may share a scheduler, a quota or an operator. For each pair of clusters, pauses are compared over the time both were active. Two pauses match when their starts and their ends each fall within a set tolerance.

Matches happen by chance, so each pair is tested against a chance model:

1. For each pair of pauses whose lengths are close enough to match, the chance of a match is the width of the window in which one pause's start could fall and still match, divided by the time both clusters were active.
2. The sum over all pause pairs is the number of matches expected by chance.
3. The probability of at least the observed number of matches is taken from a Poisson distribution with that mean.

A pair is reported only when that probability is small (the toolkit uses 1%) and either it has at least two matches or one matching pause is long. Pauses that start or end on a clock hour are down-weighted, because unrelated cron jobs stop and start on the hour together. A shared pause is a soft link ([FM-5.7](05-linking.md#fm-57-soft-links)). The toolkit's settings are in [methodology](../methodology.md#timing).

## FM-6.8 Stating timing claims

A timing claim in a report:

- names the timestamp kind and the source;
- gives the numbers it rests on (gaps, counts, the window), not just the reading;
- is tagged Inference, with the assumption it depends on;
- uses likelihood words from [chapter 8](08-confidence.md) when it bears on attribution.

## FM-6.9 Co-activity

Agents one dispatcher starts are busy together: a planner hands out tasks and each worker starts seconds later. Two clusters that share no identifier can show this in their request times alone.

1. Each cluster's request and submit times are put into short bins; a bin with any request is active. Capture times never count ([FM-6.1](#fm-61-timestamp-kinds)).
2. Over the time both clusters were active, count the bins where both are active, at each lag up to a few bins either way. The best lag is the statistic, and its sign says which cluster trails the other.
3. The chance model is a circular shift: one cluster's activity is rotated within that time, which keeps each cluster's own bursts and gaps and only breaks their alignment. The chance is the share of shifts that align at least as well.

Clock hours need care, as for shared pauses ([FM-6.7](#fm-67-shared-pauses)). A coincidence on a clock hour is down-weighted, and when most of either cluster's activity sits on clock hours the shifts are whole hours, so two jobs on one schedule keep their alignment under the chance model and do not qualify.

Co-activity is a soft link ([FM-5.7](05-linking.md#fm-57-soft-links)), never a merge. One scheduler driving unrelated jobs aligns them too, so a consistent lag suggests one dispatcher, not interaction: interaction needs the signals of [FM-4.10](04-indicators.md#fm-410-interaction-signals). A pair already tied by shared pauses reads the same timeline and gets no second timing link. Toolkit: `coactive_pairs` in the analysis and the `co_activity` soft link, with the settings in `[co_activity]` ([methodology](../methodology.md#timing)).
