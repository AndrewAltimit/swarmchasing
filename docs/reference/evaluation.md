# Evaluation

How the rules are measured, and how CI stops a rules change that costs precision. Why precision matters most, and what the numbers do and do not show, is in [methodology](../methodology.md#evaluation) and the field manual's [evaluation chapter](../manual/09-evaluation.md).

## `swarmchase eval`

`eval` scores the rules against labelled records. It reports:

- precision and recall at each tier (significant, and suggestive or above), each with its 95% Wilson interval and the count behind it, counted per record and per cluster ([units](#record-and-cluster-units));
- the same numbers over the records not marked synthetic ([synthetic and non-synthetic](#synthetic-and-non-synthetic-records)), and per provenance, per source and per label file;
- recall per agent class, and per tactic of the rules that fired;
- the false-positive rate per benign class;
- a calibration table: the share of labelled records that are agents, per tier and per agent grade ([calibration](#calibration));
- precision per rule, with its hard negatives;
- linking against labelled runs ([cluster-level evaluation](#cluster-level-evaluation));
- agent grades against each record's actor ([agent grades by actor](#agent-grades-by-actor));
- rule coverage, in one line, or per rule with `--coverage`.

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

With `--min-*` floors, `eval` exits non-zero when a floor is not met. [`eval-gate.sh`](../../scripts/ci/eval-gate.sh) runs it on [`samples/eval/`](../../samples/eval/README.md) with the floors written in the script, in CI on every pull request and push and in the pre-commit hook when `rules/`, `crates/sc-core/` or `samples/eval/` is staged. It then runs [`eval check-results`](#checking-saved-results) on the saved results.

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
- clusters carrying each plant signal, of all clusters.

Each rate has its Wilson interval. With none of `n` records flagged, the 95% upper bound is close to the rule of three, `3/n`, and `eval` prints it. Inputs may be record files or a watch store directory, so a store of archive captures can be measured whole:

```sh
swarmchase eval <data>/store --before 2022-11-30
swarmchase eval <data>/store --before 2022-11-30 --summary-json <data>/eval/control.json
```

Old records are mostly archive captures, which stop at L2, so the control measures how often the model-written rung fires on pre-agent traffic. Run it on local data only: the records and the table stay in the data directory and are never committed.

## Interaction edges

Records labelled with `swarm` measure the interaction edges ([SC-FM 5.12](../manual/05-linking.md#fm-512-interaction-edges)). The value names the interacting group a record's run belongs to, or `none` for runs known not to interact. `eval` prints the edges found by kind, how many labelled groups have an edge inside them, and how many edges touch a `none` run, by kind. Each side of an edge is placed by its first labelled record. The numbers are reported, never gated, and the committed groups are synthetic ([evaluation set](../../samples/eval/README.md#swarm-interactionndjson)). A disjoint partition on a `none` run is expected: a sharded scheduler draws one.

## Frozen splits

`--split` writes the ids of a held-out side to `--split-out` and exits. Write it to the data directory, never to the repository.

- `time`: the latest `--fraction` of labelled records by timestamp. A group (cluster or labelled run) with records on both sides of the cut is excluded from both, so every held-out record is later than every tuning record.
- `cluster`: whole groups, shuffled with `--seed`, until `--fraction` of the records is held out.

Tune with `--exclude-ids <file>` and measure with `--only-ids <file>`. Looking at held-out errors to change a rule spends the split ([FM-9.3](../manual/09-evaluation.md#fm-93-frozen-held-out-split)).

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

A slice is `name`, `labelled`, `agents`, `benign`, `tiers[]` (record unit) and `cluster_tiers[]` (cluster unit).

`clusters` holds `run_labelled`, `runs`, `bcubed_precision`, `bcubed_recall`, `bcubed_f1` and `false_merge_rate` (numbers or `null`). It also holds `clusters_checked`, `false_splits` (run ids) and `false_merges[]`, each with `cluster` (key), `members`, `runs` and `mixes_labels`.

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

### Two labellers

`review --labeller <name>` saves to `<data>/labels/reviewed-<name>.ndjson` instead, so a second reviewer can label the same queue without seeing the first one's answers. `review --stats` then also prints Cohen's κ for every pair of review files (the default file counts as `default`) over the records both labelled, with `n`, the count that agree, and each disagreement by record id. Settle disagreements by discussion and record the outcome in the default file.

### A reviewed benign baseline

A false-positive rate needs benign records nobody chose for looking like agents. The baseline is built from the watch store in the data directory, and only aggregate numbers from it are ever committed.

1. **Sample.** `review sample` draws a stratified, seeded sample and writes it as a queue file in the data directory:

    ```sh
    swarmchase review sample --stratify source,relay,month --n 1200 --seed 1 <data>/store
    ```

    Strata are combinations of `source`, `relay` (the first relay or carrier rule that fired, else `direct`), `month` and `ts_kind`. The sample is split over them in proportion to their size, so it is self-weighting. By default it draws from the records below suggestive (`--below suggestive`), the watch's noise tier; `--below all` draws from every tier.

2. **Label twice.** Each labeller runs `swarmchase review <data>/labels/baseline-queue-1.ndjson --all --labeller <name>`. `--all` queues every record in the file, in its order, as `review:baseline-sample`.

3. **Agree.** `review --stats` prints κ between the labellers and lists disagreements; settle them into the default file (`review <queue> --all` with no `--labeller`).

4. **Bound.** `review --stats` prints the baseline line: the baseline-sample reviews, how many were labelled benign and agent (agents found there are misses), and the benign records flagged at review with the false-positive rate and its interval. With none of `n` benign records flagged, the 95% upper bound is `3/n` (the rule of three): 0.5% needs more than 600 benign records with none flagged, and 1,200 bounds it at 0.25%.

5. **Measure.** `swarmchase eval <data>/labels/reviewed.ndjson` scores the current rules on everything reviewed. Run it before and after a rules change: a benign baseline record a change flags is a false positive the change introduces.

A sample from the noise tier is unflagged by the rules it was drawn under, so on those rules its false-positive rate is zero by construction. Its value is what a rules change does to it, and the misses it finds. For a rate over all the watch's benign traffic, draw with `--below all`.
