# Evaluation

How the rules are measured, and how CI stops a rules change that costs precision. Why precision matters most, and what the numbers do and do not show, is in [methodology](../methodology.md#evaluation).

## `swarmchase eval`

`eval` scores the rules against labelled records. It reports:

- precision and recall at each tier (significant, and suggestive or above);
- precision per rule;
- recall per kind of activity.

Labels come from a `label` field on each record (`agent` or `benign`), or from `--labels` files (NDJSON or CSV, including Transluce's `reports.csv`). Later `--labels` files override earlier ones. `--show-fp N` lists false positives; `--json <file>` writes the full result.

The unit is the record, not the cluster: a cluster of ten flagged records counts ten times.

```sh
swarmchase eval samples/eval/*.ndjson               # the committed set
swarmchase eval <data>/labels/reviewed.ndjson       # everything reviewed so far
```

## The eval gate

With `--min-*` floors, `eval` exits non-zero when a floor is not met. [`eval-gate.sh`](../../scripts/ci/eval-gate.sh) runs it on [`samples/eval/`](../../samples/eval/README.md) with the floors written in the script, in CI on every pull request and push and in the pre-commit hook when `rules/`, `crates/sc-core/` or `samples/eval/` is staged.

- **The floors are a ratchet.** Raise one when a change improves the numbers; never lower one to land a change. Fix the rule, or argue the label in `samples/eval/` instead.
- **A rules change gives its numbers.** The commit message carries the before and after `eval` output: precision and recall at both tiers, and the changed rule's own precision ([contributing a rule](../../CONTRIBUTING.md#contributing-a-rule)).

## Held-out measurement

The committed set was used to tune the rules, so it is a regression floor, not an estimate of real-world precision. The held-out measurement uses Transluce's labelled urlquery release. `collect urlquery-reports` fetches the labelled reports by ID into the gitignored data directory, and `eval --labels` scores them. The steps are in [samples/eval/README.md](../../samples/eval/README.md#held-out-evaluation-on-the-transluce-release).

urlquery content is never committed or quoted: the fetched reports stay in the data directory, and only IDs and our own label notes are committed ([configuration](configuration.md#urlquerynet)).

## Reviewed records

Records labelled with `swarmchase review` are saved with their labels in `<data>/labels/reviewed.ndjson` ([review](watch.md#reviewing-leads)). Measuring them shows how the rules do on what the watch actually finds, including the unflagged sample. The file is never committed.
