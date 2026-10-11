# Evaluation

How the rules are measured, and how CI stops a rules change that costs precision. Why precision matters most, and what the numbers do and do not show, is in [methodology](../methodology.md#evaluation) and the field manual's [evaluation chapter](../manual/09-evaluation.md).

## `swarmchase eval`

`eval` scores the rules against labelled records. It reports:

- precision and recall at each tier (significant, and suggestive or above), each with its 95% Wilson interval and the count behind it;
- recall per agent class, and per tactic of the rules that fired;
- the false-positive rate per benign class;
- precision per rule, with its hard negatives;
- linking against labelled runs ([cluster-level evaluation](#cluster-level-evaluation));
- agent grades against each record's actor ([agent grades by actor](#agent-grades-by-actor));
- rule coverage, in one line, or per rule with `--coverage`.

Labels come from a `label` field on each record (`agent` or `benign`), or from `--labels` files (NDJSON or CSV, including Transluce's `reports.csv`). Later `--labels` files override earlier ones. The other label fields (`class`, `run`, `hard_negative_for`, `actor`) are described in [samples/eval/README.md](../../samples/eval/README.md#record-fields).

The unit is the record, not the cluster: a cluster of ten flagged records counts ten times.

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
| `--save-result <file>` | Write a [saved result](#saved-results). |
| `--split time\|cluster`, `--seed`, `--fraction`, `--split-out` | Write a frozen held-out id list and exit ([splits](#frozen-splits)). |
| `--only-ids <file>`, `--exclude-ids <file>` | Score only the listed ids, or all but them. |
| `--before <date>` | Grade only records timestamped before the date, as a [negative control](#negative-control), and exit. |

## Statistics

Every proportion carries a 95% Wilson score interval, which stays inside 0 to 1 and does not collapse to zero width at 100%. Tables print `value [lo–hi]` and the denominator `n`. On the committed set, 100% precision on a few dozen flagged records still has a lower bound near 90%: that is what the set can show.

Recall per tactic groups agent records by the `tactic` of the rules that fired on them. A record counts once under each tactic it touches. Rules without a `tactic` group as `untagged`, and agent records no rule fired on as `no_rule_fired`. Since a tactic is known only when a rule fired, the table shows how strongly each tactic's evidence scores, not what the rules miss; the misses are in `no_rule_fired` and the per-class table.

## The eval gate

With `--min-*` floors, `eval` exits non-zero when a floor is not met. [`eval-gate.sh`](../../scripts/ci/eval-gate.sh) runs it on [`samples/eval/`](../../samples/eval/README.md) with the floors written in the script, in CI on every pull request and push and in the pre-commit hook when `rules/`, `crates/sc-core/` or `samples/eval/` is staged.

- **Point floors**: `--min-{significant,suggestive}-{precision,recall}` on the point estimates.
- **Interval floors**: `--min-{significant,suggestive}-precision-lower` on the lower end of the precision interval. They were set at the bounds the set gave when they were added, rounded down.
- **The floors are a ratchet.** Raise one when a change improves the numbers; never lower one to land a change. Fix the rule, or argue the label in `samples/eval/` instead.
- **A rules change gives its numbers.** The commit message carries the before and after `eval` output: precision and recall at both tiers, and the changed rule's own precision ([contributing a rule](../../CONTRIBUTING.md#contributing-a-rule)).

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

### Negative control

No agent of the kind this toolkit looks for sent a request before late 2022. `--before <date>` grades only records timestamped before the date, all as one row, with no labels and no floors:

```sh
swarmchase eval <data>/store/wayback.ndjson <data>/cases/<id>/raw/records.ndjson --before 2022-11-30
```

Any cluster at L2 or above is a false grade. Old records are mostly archive captures, which stop at L2, so the control measures how often the model-written rung fires on pre-agent traffic. Run it on local data only: the records and the table stay in the data directory and are never committed.

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
| `kind` | `regression`, `held_out` or `prospective` (`--result-kind`). |
| `description` | What was measured, in words (`--describe`). |
| `rules_version`, `toolkit` | Rules version; toolkit version and git commit (`-dirty` with uncommitted changes). |
| `records`, `labels` | SHA-256 and size of each input and label file, in order. |
| `only_ids`, `exclude_ids` | SHA-256 and size of the id lists, when used. |
| `summary` | The [summary JSON](#summary-json). |

## Summary JSON

`--summary-json <file>` writes the evaluation as one object, for the site to render. It holds numbers, rule ids, class and tactic names, run ids and cluster keys; never record ids, URLs or other record content. The same value comes from `sc_core::summarize(analysis, labels, rules_toml, allow_list_text)`, a pure function the browser build can call.

A proportion is `{"k", "n", "value", "lo", "hi"}`: `k` of `n`, the point estimate and the 95% Wilson interval. `value`, `lo` and `hi` are `null` when `n` is 0.

| Field | Holds |
|---|---|
| `schema` | `1`. Bumped on a breaking change. |
| `rules_version` | The rules file's `[meta] version`. |
| `labelled`, `agents`, `benign`, `unlabelled`, `missing_records` | Record counts. |
| `tiers[]` | `tier` (`suggestive`, `significant`; at or above), `tp`, `fp`, `fn`, `tn`, `precision` and `recall` as proportions. |
| `rules[]` | Every rule in the file: `rule_id`, `tactics`, `artifact` (when set), `tp`, `fp`, `precision`, `hard_negatives`, `hard_negatives_fired`, `covered`, `allowed` (the allow-list reason, when listed). |
| `coverage` | `rules`, `covered`, `allowed`, `uncovered` (rule ids), `with_hard_negatives`, `unknown_hard_negative_ids`. |
| `agent_classes[]`, `tactics[]` | `name`, `n`, and recall as `suggestive` and `significant` proportions. |
| `benign_classes[]` | `name`, `n`, and the false-positive rate as `suggestive` and `significant` proportions. |
| `clusters` | The [cluster-level evaluation](#cluster-level-evaluation), described below. |

`clusters` holds `run_labelled`, `runs`, `bcubed_precision`, `bcubed_recall`, `bcubed_f1` and `false_merge_rate` (numbers or `null`). It also holds `clusters_checked`, `false_splits` (run ids) and `false_merges[]`, each with `cluster` (key), `members`, `runs` and `mixes_labels`.

## Held-out measurement

The committed set was used to tune the rules, so it is a regression floor, not an estimate of real-world precision. The held-out measurement uses Transluce's labelled urlquery release. `collect urlquery-reports` fetches the labelled reports by ID into the gitignored data directory, and `eval --labels` scores them. The steps are in [samples/eval/README.md](../../samples/eval/README.md#held-out-evaluation-on-the-transluce-release).

urlquery content is never committed or quoted: the fetched reports stay in the data directory, and only IDs, our own label notes and saved results (numbers and hashes) are committed ([configuration](configuration.md#urlquerynet)).

## Reviewed records

Records labelled with `swarmchase review` are saved with their labels in `<data>/labels/reviewed.ndjson` ([review](watch.md#reviewing-leads)). Measuring them shows how the rules do on what the watch actually finds, including the unflagged sample. The file is never committed.

### Two labellers

`review --labeller <name>` saves to `<data>/labels/reviewed-<name>.ndjson` instead, so a second reviewer can label the same queue without seeing the first one's answers. `review --stats` then also prints Cohen's κ for every pair of review files (the default file counts as `default`) over the records both labelled, with `n`, the count that agree, and each disagreement by record id. Settle disagreements by discussion and record the outcome in the default file.
