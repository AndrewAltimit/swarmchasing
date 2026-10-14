# Evaluation

How the rules are measured, and how CI stops a rules change that costs precision. Why precision matters most, and what the numbers do and do not show, is in [methodology](../methodology.md#evaluation) and the field manual's [evaluation chapter](../manual/09-evaluation.md).

## `swarmchase eval`

`eval` scores the rules against labelled records. It reports:

- precision and recall at each tier (significant, and suggestive or above), each with its 95% Wilson interval and the count behind it, counted per record and per cluster ([units](#record-and-cluster-units));
- the same numbers over the records not marked synthetic ([synthetic and non-synthetic](#synthetic-and-non-synthetic-records)), and per provenance, per source and per label file;
- recall per agent class, and per tactic of the rules that fired;
- the false-positive rate per benign class;
- the reviewed benign baseline: progress toward its target and the false-positive bound per tier ([benign baseline](#a-reviewed-benign-baseline));
- a calibration table: the share of labelled records that are agents, per tier and per agent grade ([calibration](#calibration));
- precision per rule, with its hard negatives;
- linking against labelled runs ([cluster-level evaluation](#cluster-level-evaluation));
- agent grades against each record's actor ([agent grades by actor](#agent-grades-by-actor));
- rule coverage, in one line, or per rule with `--coverage`;
- for admin review labels, the agent labels below the labelling rule, with precision and recall without them ([agent labels below L2](#agent-labels-below-l2)).

Labels come from a `label` field on each record (`agent` or `benign`), or from `--labels` files (NDJSON or CSV, including Transluce's `reports.csv`). Later `--labels` files override earlier ones. The other label fields (`class`, `run`, `hard_negative_for`, `actor`, `synthetic`, `reconstructed`, `labeller`) are described in [samples/eval/README.md](../../samples/eval/README.md#record-fields).

```sh
swarmchase eval samples/eval/*.ndjson               # the committed set
swarmchase eval <data>/labels/reviewed.ndjson       # everything reviewed so far
```

| Option | Does |
|---|---|
| `--show-fp N` | List up to N false positives. |
| `--json <file>` | Write the full result, false-positive URLs (defanged) included. Keep it private for third-party records. |
| `--coverage` | Print the per-rule coverage table. |
| `--coverage-allow <file>`, `--require-coverage` | Read the allow-list; fail on uncovered rules ([coverage gate](#coverage-gate)). |
| `--summary-json <file>` | Write the [summary JSON](#summary-json). |
| `--save-result <file>` | Write a [saved result](#saved-results); `--allow-no-benign` for a recall-only one. |
| `--split time\|cluster`, `--seed`, `--fraction`, `--split-out` | Write a frozen held-out id list and exit ([splits](#frozen-splits)). |
| `--only-ids <file>`, `--exclude-ids <file>` | Score only the listed ids, or all but them. |
| `--before <date>` | Run the [negative control](#negative-control) on records before the date, and exit. |
| `--bench <file>`, `--predictions <file>` | Score an [SC-Bench](#sc-bench) file, and exit. |

| Subcommand | Does |
|---|---|
| `eval repro <result.json>` | Measure a saved result again and diff its numbers ([reproducing a result](#reproducing-a-result)). |
| `eval check-results [<dir>]` | Check the saved results CI can check without their inputs ([checking saved results](#checking-saved-results)). |
| `eval export-bench <input>… --out <file>` | Write an [SC-Bench](#sc-bench) file. |
| `eval pre-era` | Collect and measure the [pre-era control](#the-pre-era-control-on-archive-data). |

## Statistics

Every proportion carries a 95% Wilson score interval, which stays inside 0 to 1 and does not collapse to zero width at 100%. Tables print `value [lo–hi]` and the denominator `n`. On the committed set, 100% precision on a few dozen flagged records still has a lower bound near 90%: that is what the set can show.

Recall per tactic groups agent records by the `tactic` of the rules that fired on them. A record counts once under each tactic it touches. Rules without a `tactic` group as `untagged`, and agent records no rule fired on as `no_rule_fired`. Since a tactic is known only when a rule fired, the table shows how strongly each tactic's evidence scores, not what the rules miss; the misses are in `no_rule_fired` and the per-class table.

### Record and cluster units

The **record unit** counts every labelled record once, so a cluster of ten flagged records counts ten times. A set rich in large runs looks better per record than the reports it would produce.

The **cluster unit** counts every predicted group once: a cluster (over its labelled members) or a labelled record in no cluster. A group is flagged at a tier when its tier is at or above it: the cluster's tier, or the lone record's.

- All labelled members agent: a true positive when flagged, a false negative when not.
- All benign: a false positive when flagged, a true negative when not.
- Mixed agent and benign: wrong either way. Flagged, it is a false positive, since reporting it would misattribute the benign members; unflagged, a false negative.

Both units are printed and both are in the summary JSON. Floors read the record unit.

### Synthetic and non-synthetic records

A record marked `"synthetic": true` was written by hand to exercise a rule, and the rules catch most of them by construction. A record marked `"reconstructed": true` was rebuilt from a published incident; any other record was collected. `eval` reports every headline number twice: over all labelled records, and over the records not marked synthetic. It also breaks the record-unit numbers down by provenance (`synthetic`, `reconstructed`, `collected`), by record source, and by the label file each label came from.

Read the non-synthetic numbers first. On the committed set they are the reconstructions of published incidents and their benign look-alikes, and they are smaller and weaker than the all-records numbers.

### Calibration

The calibration table gives, for the records at each tier (`noise`, `suggestive`, `significant`, exactly that tier) and in each agent-grade column (`unflagged`, `unclustered`, `L0` to `L4`), the share of labelled records that are agents, with its interval. It says what a tier or a grade is worth as evidence on the set measured. It is reported, never gated, and on a set built to exercise the rules it says more about the set than about the world.

## The eval gate

With `--min-*` floors, `eval` exits non-zero when a floor is not met. [`eval-gate.sh`](../../scripts/ci/eval-gate.sh) runs it on [`samples/eval/`](../../samples/eval/README.md) with the floors written in the script, in CI on every pull request and push and in the pre-commit hook when `rules/`, `crates/sc-core/`, `crates/sc-sim/`, `samples/eval/` or `samples/sim/` is staged. It then runs [`eval check-results`](#checking-saved-results) on the saved results, and the [simulator bounds](#simulator-bounds).

- **Point floors**: `--min-{significant,suggestive}-{precision,recall}` on the point estimates.
- **Interval floors**: `--min-{significant,suggestive}-precision-lower` on the lower end of the precision interval. They were set at the bounds the set gave when they were added, rounded down.
- **Non-synthetic floors**: `--min-nonsynthetic-…` takes the same six floors over the records not marked synthetic. The gate sets both sets, so hand-written fixtures cannot hold a number up on their own. The non-synthetic recall and interval floors were set at the values the set gave when they were added, rounded down; the precision floors are the same 90% as the others.
- **The floors are a ratchet.** Raise one when a change improves the numbers; never lower one to land a change. Fix the rule, or argue the label in `samples/eval/` instead.
- **A rules change gives its numbers.** The commit message carries the before and after `eval` output: precision and recall at both tiers, for all and for non-synthetic records, and the changed rule's own precision ([contributing a rule](../../CONTRIBUTING.md#contributing-a-rule)).

### Coverage gate

Each rule's **positives** are the agent-labelled records it fires on, and its **hard negatives** the benign records that name it in `hard_negative_for`. The coverage table shows `fired/total` for hard negatives. A hard negative the rule fires on is not a false positive while the record stays below suggestive, but it shows how close the trap came.

With `--require-coverage`, `eval` fails when a rule has no positive and is not on the allow-list ([`coverage-allow.txt`](../../samples/eval/coverage-allow.txt)). It also fails on an allow-list entry whose rule now has a positive, names no rule, or gives no reason. Rules, tactics and artifacts are read from the rules file the analysis ran with.

## Cluster-level evaluation

Records labelled with `run` measure linking. The numbers are reported, never gated.

- **B-cubed precision, recall and F1**, over run-labelled records only. A record's predicted group is its cluster, or the record alone when it is in none.
- **False merges**: clusters whose labelled members span two or more runs, or mix agent and benign records. Each is listed by cluster key with the runs it joins.
- **Split runs**: runs whose records sit in more than one predicted group. An agent record no rule fired on is never clustered, so a run with a missed record always shows as split.

## Agent grades by actor

The agent grade ([methodology](../methodology.md#agent-likelihood)) is measured against who really sent each record. A record's `actor` field says: `agent`, `human` or `tool`. An agent-labelled record without one counts as `agent`; a benign record without one is left out of the table. `eval` prints actor by grade, one count per record: `unflagged` (no rule fired), `unclustered` (flagged, in no cluster) and the grade of the record's cluster, `L0` to `L4`. L5 is never computed, so it has no column. The table is reported, never gated; its JSON is `grades.rows` in `--json`.

A record with an `actor` and no `label` is graded but not scored for detection. A person's attack payloads are flagged by design ([known limits](../methodology.md#known-limits-and-false-positive-traps)): scoring them as benign would measure that limit, not the rules. The committed set's controls are of this kind ([samples/eval/README.md](../../samples/eval/README.md#actor-controlsndjson)).

## Negative control

No agent of the kind this toolkit looks for sent a request before late 2022. `--before <date>` analyses only the records timestamped before the date, with no labels and no floors. Every flag, every grade above L1 and every plant signal on them is a false alarm, so the rates need no labels:

- records flagged suggestive or above, and significant, of all records;
- records per agent-grade column, of all records, and clusters graded L2 or above, of all clusters;
- records and clusters graded above L0;
- per rule that fired, the records it fired on and those of them flagged suggestive or above, of all records;
- clusters carrying each plant signal, of all clusters;
- interaction edges, by kind.

Each rate has its Wilson interval. `eval` also prints the 95% upper bound on the false-alarm rate at each tier: the rule of three, `3/n`, when none of `n` records was flagged, and the Wilson upper bound otherwise. Inputs may be record files or a watch store directory, so a store of archive captures can be measured whole:

```sh
swarmchase eval <data>/store --before 2022-11-30
swarmchase eval <data>/store --before 2022-11-30 --summary-json <data>/eval/control.json
```

Old records are mostly archive captures, which stop at L2, so the control measures how often the model-written rung fires on pre-agent traffic. Run it on local data only: the records and the table stay in the data directory and are never committed.

A relay or carrier rule firing on a pre-era record of its own host is not by itself a false alarm: the record went through the relay or the echo service. The per-rule table separates the records a rule fired on from those it helped flag, and the flagged column is the one that counts.

### The pre-era control on archive data

`eval pre-era` builds the control from real captures and measures it in one step:

```sh
swarmchase eval pre-era --per-source 600
swarmchase eval pre-era --offline            # measure what is collected, fetch nothing
swarmchase eval pre-era --offline --years even   # one half of the capture years
```

1. It reads the `wayback` sources of [`watchlist.toml`](../../watchlist.toml), the relay and carrier hosts, with their patterns and filters (`--source <name>` picks some).
2. For each source it reads the Wayback index one calendar year at a time, from `--from-year` (default 2012) to the day before `--before` (default 2022-11-30), up to `--per-source` captures spread evenly over the years. Index rows only, one request per year and source, at the watchlist's request interval.
3. Each year's rows go to `<data>/controls/pre-era/<source>/<year>-n<bound>.ndjson`. A year collected once is reused, so a second run with the same arguments measures the same records without fetching, and a failed year is fetched on the next run.
4. It analyses every collected record before the date and prints the per-source counts, the [negative control](#negative-control) tables and the grade table. The same numbers, and no record content, go to `<data>/controls/pre-era/summary.json`.

`--years even` or `--years odd` measures only the captures of even or odd calendar years. The per-year bound is still set over every year, so both halves read the files a full run collected. Tune a change on one half and quote the other ([FM-9.13](../manual/09-evaluation.md#fm-913-negative-control-and-benign-baseline)).

The index is sorted by URL within a year, so a year's share is the first captures by URL in it, not a random draw. Several relays did not exist before the cut, so their sources return little or nothing; the per-source table shows how much each contributed. The records stay in the data directory; only the aggregate numbers may be quoted.

## Interaction edges

Records labelled with `swarm` measure the interaction edges ([SC-FM 5.12](../manual/05-linking.md#fm-512-interaction-edges)). The value names the interacting group a record's run belongs to, or `none` for runs known not to interact. `eval` prints the edges found by kind, how many labelled groups have an edge inside them, and how many edges touch a `none` run, by kind. Each side of an edge is placed by its first labelled record. The numbers are reported, never gated, and the committed groups are synthetic ([evaluation set](../../samples/eval/README.md#swarm-interactionndjson)). A disjoint partition on a `none` run is expected: a sharded scheduler draws one.

## Fleet proposals

Records labelled with `fleet` measure the soft links and candidate fleets as proposals of cluster pairs that one operator runs ([SC-FM 5.8](../manual/05-linking.md#fm-58-candidate-fleets-merge-and-split)). A cluster takes the most common `fleet` among its labelled members; `none` marks a cluster known to be its operator's only one, so any pair touching it is wrong.

`eval` prints, per soft-link kind, over all soft links and over the pairs inside candidate fleets: the pairs proposed between two labelled clusters, how many are in one fleet (precision, with its Wilson interval), the share of true pairs found (recall), and a few wrong pairs. Pairs touching an unlabelled cluster are not counted. The numbers are reported, never gated: the committed fleets are synthetic and few ([evaluation set](../../samples/eval/README.md#scaffold-fleetsndjson)).

## Swarm and fleet measurement

`swarmchase sim score <files>` measures the interaction edges, soft links, candidate fleets and agent grades against records labelled with `run`, `swarm` and `fleet` ([`sc-sim`](../../crates/sc-sim/README.md)). `fleet` names the operator group a run belongs to (one scheduler, one scaffold deployment); a swarm's runs share one. A run with neither is its own operator. Each file is analysed on its own and the counts are summed; `--json` writes them.

The unit is a pair of true runs. An edge side is placed on the run most of its records belong to, and a cluster on the run most of its members belong to.

- **Edges**, per kind: precision is the share of drawn run pairs that are two distinct runs in one swarm. The table also counts pairs on one run (one client changing route) and pairs with one operator that do not interact (a fleet signal). Recall is over swarm pairs both of whose runs reach a cluster above noise.
- **Soft links and candidate fleets**, per kind: precision is the share of linked cluster pairs with one operator. Recall is over operator pairs in different clusters above noise; pairs already in one cluster are counted apart.
- **Distinct runs and split runs**: a soft link between two clusters of one run counts as right in the precision above. It is also printed between distinct runs only, with same-run pairs left out of both counts, and the pairs of clusters above noise on one run (a split run) are counted with how many each kind rejoins.
- **Agent grades**: records by actor and class against the grade columns, as in [agent grades by actor](#agent-grades-by-actor). A benign record that names no actor is left out, as in `eval`. Benign and tool records in clusters graded L2 or above, and people's records at L3 or above, are counted on their own.

Every proportion has its Wilson interval. Every kind is listed with its recall denominator in every file and seed, fired or not, so summed recall counts the true pairs a kind missed where it drew nothing. `sim score` numbers are reported, never gated. The committed labelled groups are hand-written and few, so the intervals are wide and the numbers say whether a detector fires on its designed case, not how often it would on real traffic. The simulated scenarios below are gated.

### Simulated scenarios

`swarmchase sim bench samples/sim/scenarios.toml` generates labelled records for each scenario in the file, under each of its seeds, analyses each set on its own and prints the measurement above per scenario and summed. `sim write` saves the records instead, as ordinary labelled files that `eval` and `sim score` also read.

A scenario lists actors: single agents, swarms (`modes`: `sink` for one shared callback inbox, `sync` for runs one dispatcher drives step by step, each request 0 to 2 seconds after its dispatch, `roles` for a reader followed by attackers on the same hosts, `shard` for one host family split between agents, `handoff` for a gist one agent names and the others fetch within the hour, `dispatch` for a planner whose workers each send a request 40 to 85 seconds after each of its irregular dispatches).

Other actors: fleets on one scaffold with separate inboxes, schedulers sharding a list from one client, target lists (one operator's agents working one host list in the same hours, each 15 to 20 minutes after the last in its own order), planters copying another actor's identifiers from a different client, news spikes (unrelated agents sent to one family of hosts within a few hours), hubs (one unrelated agent working the target lists of the actors it `bridges`, a cluster tied to two fleets), mimics, escalators, and background: people reading through relays, mail gateways, on-the-hour jobs, crawlers, people running scanners and people pasting a chatbot's payloads. Each actor has a pace, a retry rate and a time basis (request, submit or capture).

- **Fleets.** A fleet's harness adds two parameters of its own to every request (a step counter and a per-request trace value, names drawn from a list no palette record uses), and sends its handful of records in one fixed rotation, so its agents share one request shape and one mix that unrelated agents copying the same records do not. `interval_hours` sets the hours between one agent's start and the next (26 by default; a slow fleet spreads over weeks). `upgrade_at` gives the agents from that index on an upgraded harness: one parameter and one record changed, so every request shape changes.
- **Planters** copy a swarm's run tag and inbox; with `copy_timing` they also replay its first run's request times a few seconds behind.
- **Mimics** (`bridges`, as hubs use it for target lists) send the shapes of the fleets named, with their own tags: one run of another operator that looks like several fleets at once, a hub between them.
- **Escalators** send each relay record's target directly first (unanswered), then the record as written through the relay 11 to 25 minutes later, past the linking window and within the escalation window. Each route is a separate tool with its own run tag, so the steps fall in two clusters of one run and draw escalation links.
- **Timing options.** `jitter_secs` sets how late a synchronised worker leaves after each dispatch (2 seconds by default; beyond the lockstep tolerance it is a loose swarm). `window_hours` starts single agents and background runs within that many hours instead of over the scenario's span, and `same_family` has single agents draw their hosts from one shared family: together, a news spike sending unrelated agents to one target at once.
- **Benign look-alikes**, each client its own run and operator: an uptime service (`uptime_monitor`) checking the same URLs every minute from several regions within a second of each other (a lockstep look-alike), an internet-wide scanner (`internet_scanner`) sharding one host family over consecutive addresses of one network (a partition and scaffold look-alike), link-preview bots (`link_preview`) fetching each posted link within seconds (a co-activity look-alike), and feed readers (`feed_poller`) polling the same feeds in one order through one outage (a rerun and shared-pause look-alike). Their content is the benign records of their kind that a rule fires on, so the timing and linking detectors see them.

`off_hour` moves an actor's start to a seeded 7 to 53 minutes past its hour, so a synchronized swarm does not begin on a clock hour. `palette_share` below 1 has each swarm, scheduler or single agent draw from its own seeded share of the palette.

The generator writes no request content. Each record copies a committed evaluation record and changes its target host to a reserved `.example` name, its linking identifiers and captured secrets to values of its own run (or of its swarm, for a shared inbox), and for a retry a cache-busting parameter. A hand-off adds the gist's address to the writer's requests and one fetch of it through a reader relay to each reader's run. What is simulated is the senders, their clients, the times and the order.

`fleet-traffic` puts a scaffold fleet among a day of benign crawler traffic, which must change no scaffold chance ([methodology](../methodology.md#descriptive-hints)): set beside `fleet`, it shows whether unrelated traffic dilutes the null. A fleet's own other members count toward each shared shape's base rate, so with the [multiplicity budget](../methodology.md#descriptive-hints) a fleet of three passes the scaffold test only among a few hundred comparable clusters: `fleet-crowd`, `hub-two-fleets` and `fleet-upgrade` put fleets among hundreds of single agents, while `fleet` and `fleet-traffic` among a few dozen draw none. `target-list` measures co-targets, `news-spike-list` is their hard negative, and `hub` shows whether a cluster tied to two fleets chains them into one candidate fleet.

`swarmchase sim calibrate samples/sim/scenarios.toml` switches every soft-link kind on and prints each kind's likelihood ratio over the pairs of clusters on distinct true runs: the pairs of one operator and the unrelated pairs it links, the point ratio and a conservative one (the lower Wilson bound of the first share over the upper bound of the second), beside the ratio the rules set. The bundled ratios start from the conservative values ([methodology](../methodology.md#descriptive-hints)).

It then prints the ratios stratified by scenario: a Mantel-Haenszel ratio over the scenarios where the kind fired and both kinds of pair exist, the lower bound of its Greenland-Robins interval, and each scenario's own ratio, so the unrelated pairs of a few crowded scenarios do not inflate a pooled ratio. `--check` exits non-zero when a ratio the rules set is above that stratified lower bound.

A scenario's `expect` table names the kinds it is built to produce, each with bounds on that scenario's own measurement: `expect.S3 = { min_precision = 1.0, min_recall = 0.8 }` for an edge kind (by id or name), and the same for a soft-link kind or `candidate_fleet`, which also take `min_rejoined` (the share of split-run pairs the kind rejoins). The bounds are set at or just below what the scenario measures and only go up.

A scenario marked `null = true` has only background actors and single agents, and the file checks it: no two of its runs are related, so every edge, soft link and candidate fleet it draws between different runs is false. The null scenarios run under many seeds, and `sim bench` prints what they drew.

### Simulator bounds

`sim bench` takes floors and ceilings and exits non-zero when one is not met: `--min-edge-precision`, `--min-link-precision` and `--min-fleet-precision` on interaction edges, soft links and candidate fleets of any kind, summed over every scenario, `--min-link-cross-run-precision` and `--min-fleet-cross-run-precision` on the last two between distinct runs only, and `--max-null-edges`, `--max-null-links` and `--max-null-fleet-pairs` on what the null scenarios draw between different runs, summed over their seeds.

`--max-benign-high` and `--max-human-high` cap the benign and tool records graded L2 or above and the people's records graded L3 or above, summed over every scenario. `--expect` holds each scenario's `expect` table, so a kind that stops firing in the scenario built for it fails even when the pooled precision holds; a bound on a kind that drew nothing fails. The eval gate runs the committed scenarios with the bounds written in the script. The simulator is seeded, so the numbers move only when the analysis, the rules, the generator or the scenarios do; the bounds ratchet like the eval floors, and a new scenario that lowers a pooled number is argued in its commit.

What this does not model: the variety of real request content (every actor draws from one small set of records, so habit soft links such as relay stacks and payload dialects join unrelated agents more often than they would on real traffic; `palette_share` narrows this without removing it), hand-offs through anything but a gist, headers, real address and network structure, and archive or scan-service behaviour beyond the timestamp kind. Simulator numbers say how the detectors behave on the modelled situations, not how often they are right on real records.


## Frozen splits

`--split` writes the ids of a held-out side to `--split-out` and exits. Write it to the data directory, never to the repository.

- `time`: the latest `--fraction` of labelled records by timestamp. A group (cluster or labelled run) with records on both sides of the cut is excluded from both, so every held-out record is later than every tuning record.
- `cluster`: whole groups, shuffled with `--seed`, until `--fraction` of the records is held out.

Tune with `--exclude-ids <file>` and measure with `--only-ids <file>`. Looking at held-out errors to change a rule spends the split ([FM-9.3](../manual/09-evaluation.md#fm-93-frozen-held-out-split)).

**Freezing the membership.** A split's hash is the SHA-256 of its distinct ids, sorted, one per line: it names which records are held out, whatever their content or order, so a re-fetched or re-ordered record file keeps it. `--split` prints it and writes it into the id list's header, `eval ids-hash <file>...` prints it for an id list or a record file, and `--expect-ids-sha256 sha256:<hex>` makes `eval` fail before measuring when the labelled records it would score hash otherwise. The id lists stay in the data directory; the hash can be committed, and every saved result carries the hash of the records it scored (`scored_ids`), which `eval repro` checks again.

## Saved results

`--save-result <file>` writes JSON with numbers only, for [`samples/eval/results/`](../../samples/eval/results/README.md):

| Field | Holds |
|---|---|
| `result_schema` | `2`. |
| `kind` | `regression`, `held_out` or `prospective` (`--result-kind`). |
| `description` | What was measured, in words (`--describe`). |
| `rules_version`, `rules_sha256` | The rules version, and the SHA-256 of the rules text with line endings made LF. |
| `rules_file` | The `--rules` file, when one was given; absent for the bundled rules. |
| `toolkit` | Toolkit version and git commit (`-dirty` with uncommitted changes). |
| `records`, `labels` | `path`, SHA-256 and size of each input and label file, in order. |
| `only_ids`, `exclude_ids` | The same for the id lists, when used. |
| `scored_ids` | `sha256` and `count` of the labelled records scored, by id ([freezing the membership](#frozen-splits)). |
| `counts` | `labelled`, `agents`, `benign`, `non_synthetic_labelled`, `non_synthetic_benign`. |
| `allow_no_benign` | `true` when saved with `--allow-no-benign`. |
| `summary` | The [summary JSON](#summary-json). |

A recorded `path` is the path as given when it was relative, and the file name alone when it was absolute, so a result does not say where its author keeps data.

A held-out or prospective result with no benign record has a precision that cannot be wrong, so `--save-result` refuses it unless `--allow-no-benign` is given. Such a result is quoted for recall only.

### Reproducing a result

`eval repro <result.json>` finds each input at its recorded path, or among `--input <file>` candidates by SHA-256, and checks the bundled (or `--rules`) rules carry the saved version and hash. It then measures again, reading the inputs with automatic format detection, and diffs every number in the saved summary's counts, tiers, cluster-unit tiers, non-synthetic slice, class and tactic tables and calibration. Rows are matched by name, so a new class shows as a difference rather than shifting the rest. It exits non-zero on a missing input, a rules mismatch or any difference.

```sh
swarmchase eval repro samples/eval/results/<file>.json
swarmchase eval repro samples/eval/results/<file>.json --input ~/elsewhere/holdout.csv
```

### Checking saved results

`eval check-results [<dir>]` (default `samples/eval/results`) checks what needs no inputs, and the eval gate runs it in CI. Each result must:

- name a rules version no newer than the bundled rules, so it can be measured again from the checkout;
- have a benign record if it is held out or prospective, or say it was saved with `--allow-no-benign`;
- come from committed code (a `toolkit.commit` that is known and not `-dirty`);
- hold no URL.

A result that fails is withdrawn, never edited: measure again and commit the new file.

## Summary JSON

`--summary-json <file>` writes the evaluation as one object, for the site to render. It holds numbers, rule ids, class and tactic names, run ids, cluster keys, record source names and label file names; never record ids, URLs or other record content. The same value comes from `sc_core::summarize(analysis, labels, rules_toml, allow_list_text)`, a pure function the browser build can call.

A proportion is `{"k", "n", "value", "lo", "hi"}`: `k` of `n`, the point estimate and the 95% Wilson interval. `value`, `lo` and `hi` are `null` when `n` is 0. A tier row is `tier` (`suggestive` or `significant`; at or above), `tp`, `fp`, `fn`, `tn`, and `precision` and `recall` as proportions.

| Field | Holds |
|---|---|
| `schema` | `1`. Bumped on a breaking change; added fields are not breaking. |
| `rules_version` | The rules file's `[meta] version`. |
| `labelled`, `agents`, `benign`, `unlabelled`, `missing_records` | Record counts. |
| `tiers[]` | Tier rows, record unit. |
| `cluster_tiers[]` | Tier rows, cluster unit. |
| `non_synthetic` | A slice over the records not marked synthetic. |
| `by_provenance[]`, `by_source[]`, `by_file[]` | Slices per provenance, record source and label file. `by_file` is empty when the caller did not say which file each label came from. |
| `calibration` | `by_tier[]` and `by_agent_level[]`, rows of `name` and `precision` (a proportion: agents of labelled records in the row). |
| `rules[]` | Every rule in the file: `rule_id`, `tactics`, `artifact` (when set), `tp`, `fp`, `precision`, `hard_negatives`, `hard_negatives_fired`, `covered`, `allowed` (the allow-list reason, when listed). |
| `coverage` | `rules`, `covered`, `allowed`, `uncovered` (rule ids), `with_hard_negatives`, `unknown_hard_negative_ids`. |
| `agent_classes[]`, `tactics[]` | `name`, `n`, and recall as `suggestive` and `significant` proportions. |
| `benign_classes[]` | `name`, `n`, and the false-positive rate as `suggestive` and `significant` proportions. |
| `clusters` | The [cluster-level evaluation](#cluster-level-evaluation), described below. |
| `baseline` | The [benign baseline](#a-reviewed-benign-baseline), described below; absent with no review-sample label. |

A slice is `name`, `labelled`, `agents`, `benign`, `tiers[]` (record unit) and `cluster_tiers[]` (cluster unit).

`clusters` holds `run_labelled`, `runs`, `bcubed_precision`, `bcubed_recall`, `bcubed_f1` and `false_merge_rate` (numbers or `null`). It also holds `clusters_checked`, `false_splits` (run ids) and `false_merges[]`, each with `cluster` (key), `members`, `runs` and `mixes_labels`.

`baseline` holds `target`, `reviewed`, `benign`, `agents`, `excluded` (tuned or synthetic) and `tiers[]`, each with `tier`, `fp_rate` (a proportion), `upper` (the 95% upper bound) and `method` (`rule_of_three` or `wilson`).

## SC-Bench

SC-Bench is a labelled set in a form another group can score its own detector against, with this toolkit's scorer. The format is the JSON Schema [`schemas/sc-bench-v1.json`](../../schemas/sc-bench-v1.json). A bench file has a header (`format`, `name`, `description`, `freeze_date`, `rules_version`, `rules_sha256`, `toolkit_version`) and one entry per record:

- `id`, `host` (the target host, defanged), `label` (absent for a record graded by actor only), `actor`, `class`;
- `labellers`, `split` (`regression`, `held_out`, `prospective`);
- `ts`, `ts_kind`, `source`, `provenance` (`synthetic`, `reconstructed`, `collected`), `origin` (the file or dataset to get the record from), `run`;
- the reference: `fired_rules`, `tier` and `cluster` key under the named rules.

It never holds a record's URL or other content. Records come from their source by id, under its terms ([FM-9.10](../manual/09-evaluation.md#fm-910-benchmark-publication-rules)).

```sh
swarmchase eval export-bench samples/eval/*.ndjson --out bench.json --name my-bench \
    --freeze-date 2026-01-31 --held-out-ids <data>/eval/holdout-ids.txt
swarmchase eval --bench bench.json                                  # the reference tiers
swarmchase eval --bench bench.json --predictions mine.ndjson --json score.json
```

`export-bench` puts the ids in `--held-out-ids` in the `held_out` split and the rest in `--split` (default `regression`). A row's `labeller` or `labellers` field names who labelled it, else `--labeller`. The export checks that its reference tiers score exactly as the analysis did.

Predictions are NDJSON, one line per record: `id`, then `tier` (`noise`, `suggestive`, `significant`) or `flagged` (a binary detector; flagged counts at both thresholds), and optionally `cluster`, the detector's own grouping. A labelled record with no prediction is scored unflagged and counted as missing. The score gives record-unit and cluster-unit tier rows for all records and for the non-synthetic ones, over the whole file and per split; records without a `cluster` count as their own group.

The committed example [`samples/eval/bench/sc-bench-v1-example.json`](../../samples/eval/bench/sc-bench-v1-example.json) is the committed evaluation set in this form, built from committed samples only.

## Held-out measurement

The committed set was used to tune the rules, so it is a regression floor, not an estimate of real-world precision. The held-out measurement uses Transluce's labelled urlquery release. `collect urlquery-reports` fetches the labelled reports by ID into the gitignored data directory, and `eval --labels` scores them. The steps are in [samples/eval/README.md](../../samples/eval/README.md#held-out-evaluation-on-the-transluce-release).

urlquery content is never committed or quoted: the fetched reports stay in the data directory, and only IDs, our own label notes and saved results (numbers and hashes) are committed ([configuration](configuration.md#urlquerynet)).

## Reviewed records

Records labelled with `swarmchase review` are saved with their labels in `<data>/labels/reviewed.ndjson` ([review](watch.md#reviewing-leads)). Measuring them shows how the rules do on what the watch actually finds, including the unflagged sample. The file is never committed.

### Agent labels below L2

The labelling rule gives `agent` only at an agent grade of L2 or higher ([evaluating leads](../guides/evaluating-leads.md#exceptions-to-the-labelling-rule)). The admin may still label agent below it, and `review` saves such a label with the grade it was judged against, marked `below_l2` ([label lines](watch.md#label-lines)).

When the label files hold admin review lines (lines with `reviewed_at`), `eval` prints one more block after the tables:

- how many of the admin's agent labels are below L2, split by the grade stored with the label and the grade now for an older line that stores none;
- how many older lines name a record not in the analysis, which are not judged;
- precision and recall at each tier, record unit over all records, with those labels and without them (left unlabelled).

The evaluation set's labels are not admin review labels, so for `samples/eval/` nothing is printed and the gate is unaffected.

### Two labellers

`review --labeller <name>` saves to `<data>/labels/reviewed-<name>.ndjson` instead, so a second reviewer can label the same queue without seeing the first one's answers. `review --stats` then also prints Cohen's κ for every pair of review files (the default file counts as `default`) over the records both labelled, with `n`, the count that agree, and each disagreement by record id. Settle disagreements by discussion and record the outcome in the default file.

### A reviewed benign baseline

A false-positive rate needs benign records nobody chose for looking like agents. The baseline is built from the watch store in the data directory, and only aggregate numbers from it are ever committed.

1. **Sample.** `review sample` draws a stratified, seeded sample and writes it as a queue file in the data directory:

    ```sh
    swarmchase review sample --stratify source,relay,month --n 1200 --seed 1 <data>/store
    ```

    Strata are combinations of `source`, `relay` (the first relay or carrier rule that fired, else `direct`), `month` and `ts_kind`. The sample is split over them in proportion to their size, so it is self-weighting. By default it draws from every tier; `--below suggestive` draws from the watch's noise tier only. Records already in a review file are left out (`--include-reviewed` keeps them), so a sample with a new seed tops the baseline up.

2. **Label twice.** Each labeller runs `swarmchase review <data>/labels/baseline-queue-1.ndjson --all --labeller <name>`. `--all` queues every record in the file, in its order, as `review:baseline-sample`.

3. **Agree.** `review --stats` prints κ between the labellers and lists disagreements; settle them into the default file (`review <queue> --all` with no `--labeller`).

4. **Bound.** `review --stats` prints the baseline line: the baseline-sample reviews, how many were labelled benign and agent (agents found there are misses), and the benign records flagged at review with the false-positive rate and its interval. With none of `n` benign records flagged, the 95% upper bound is `3/n` (the rule of three): 0.5% needs more than 600 benign records with none flagged, and 1,200 bounds it at 0.25%.

5. **Measure.** `swarmchase eval <data>/labels/reviewed.ndjson` scores the current rules on everything reviewed and prints the baseline line: the benign baseline records against the target of 1,000, the agents found among them, and per tier the false-positive rate with its 95% upper bound, by the rule of three when none was flagged and the Wilson bound otherwise. Run it before and after a rules change: a benign baseline record a change flags is a false positive the change introduces.

6. **Spend.** A baseline record looked at while changing a rule (a false positive from `--show-fp` that a change was made to fix) no longer tests the rules fairly. `review tuned <id>…` (ids, or files of ids) marks it `"tuned": true` in every review file, and `eval` leaves it out of the baseline and counts it as excluded.

The baseline counts only labels of class `review:baseline-sample` that are not `synthetic` and not `tuned`. Records reviewed because they were flagged, or from `review --unflagged`, are chosen by the rules and are not in it.

A sample drawn with `--below suggestive` is unflagged by the rules it was drawn under, so on those rules its false-positive rate is zero by construction. Its value is what a rules change does to it, and the misses it finds. The default every-tier sample estimates the rate over all the watch's traffic.
