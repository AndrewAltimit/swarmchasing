# 9. Evaluation

[Manual index](README.md) · Previous: [8. Confidence language](08-confidence.md) · Next: [10. Disclosure](10-disclosure.md)

With no embargo, a false positive is published the moment the admin acts on it. Precision therefore matters most, and every number quoted about the method says what it was measured on.

## FM-9.1 Three kinds of evaluation

| Kind | What it is | What its numbers mean |
|---|---|---|
| **Regression set** | A committed, labelled set the rules were tuned on. | A floor that stops regressions. Not an estimate of real-world precision. |
| **Frozen held-out split** | Labelled data set aside before tuning and never used for it. | An estimate of performance on data like it. |
| **Prospective** | What happens to the leads the method actually produces. | Precision in operation, as the admin experiences it. |

A claimed number names its kind. Only held-out and prospective numbers may be quoted as performance.

## FM-9.2 Regression set

The regression set holds reconstructed records from published incident reports, synthetic records for each artifact family, and benign records, including hard negatives built to trip the rules ([FM-4.7](04-indicators.md#fm-47-rule-writing-standard)). A gate runs on every change and fails when precision or recall at either tier falls below its floor. Floors only go up.

In this repository the set is [`samples/eval/`](../../samples/eval/README.md) and the gate is described in [evaluation](../reference/evaluation.md#the-eval-gate).

## FM-9.3 Frozen held-out split

A held-out split is frozen before any rule is tuned against it, and is split two ways at once:

- **By time.** Every held-out record is later than every tuning record, so the measurement includes drift: new relays, new payloads, new tags.
- **By cluster.** No cluster or fleet has records on both sides. Records of one run are near-duplicates; splitting them across sides measures memory, not detection.

A frozen split is used for measurement only. Looking at its errors to change a rule spends it: the next measurement needs a new split.

Labels from an external release are used with documented overrides, each with its reason. The [Transluce release](references.md#incident-reports) is such a source: it labels scan reports and ships report ids, not contents, so a practitioner fetches the reports under their own access and measures record by record ([held-out steps](../../samples/eval/README.md#held-out-evaluation-on-the-transluce-release)). Its labels draw on context a single record cannot show, so the per-class table matters more than the total.

Toolkit: the Transluce measurement runs record by record, and `eval --split time|cluster` freezes a split of any labelled set ([frozen splits](../reference/evaluation.md#frozen-splits)). Results are saved as numbers and hashes ([saved results](../reference/evaluation.md#saved-results)).

## FM-9.4 Prospective evaluation

The prospective measure is the **admin-confirmed share of digest leads**: of the clusters the digest reported as leads in a period, the share a reviewer labelled agent activity. To catch misses, the reviewer also labels a stable random sample of unflagged records.

Toolkit: reviewed labels are saved and can be scored ([reviewed records](../reference/evaluation.md#reviewed-records)); computing the confirmed share per period is (planned).

## FM-9.5 Detection metrics

Detection is measured as precision and recall:

- **per tier**: significant, and suggestive or above;
- **per tactic** ([FM-4.3](04-indicators.md#fm-43-the-sc-t-tactic-taxonomy)), so a strong tactic does not hide a weak one;
- **per unit**: by record and by cluster. A cluster of ten records counts ten times by record and once by cluster; give both.

Every proportion carries a 95% Wilson score interval ([Wilson 1927](references.md#statistics)), which behaves at small counts and near 0 or 1 where the plain normal interval does not. For `k` successes in `n` trials, `p = k/n` and `z = 1.96`:

```text
centre    = (p + z²/(2n)) / (1 + z²/n)
halfwidth = (z / (1 + z²/n)) · sqrt( p(1−p)/n + z²/(4n²) )
```

Toolkit: precision and recall per tier, recall per class and per tactic, and false positives per benign class, each with its Wilson interval ([statistics](../reference/evaluation.md#statistics)). Detection scored with the cluster as the unit is (planned).

## FM-9.6 Cluster metrics

Linking is measured against reference groupings (records labelled with their true operator or run).

- **B-cubed precision (purity)** and **B-cubed recall (completeness)** ([Bagga and Baldwin 1998](references.md#statistics); [Amigó et al. 2009](references.md#statistics)). For each record, precision is the share of its predicted cluster that shares its true group, and recall the share of its true group in its predicted cluster; each is averaged over records.
- **False-merge rate**: the share of predicted clusters whose records span more than one true group. This is the error that misattributes, so it is reported on its own.
- **False-split rate**: the share of true groups spread over more than one predicted cluster.

Toolkit: B-cubed precision, recall and F1, false merges and split runs, reported but not gated ([cluster-level evaluation](../reference/evaluation.md#cluster-level-evaluation)).

## FM-9.7 Attribution calibration

An attribution method is calibrated when its words match outcomes: of the attributions called "likely" (55–80%), between 55% and 80% turn out right once settled.

- Keep every attribution with its likelihood word and, later, its outcome (confirmed, refuted, unresolved).
- Publish a reliability table: for each band in [FM-8.1](08-confidence.md#fm-81-likelihood-table), the count settled and the share correct, with Wilson intervals.
- For model-family methods, publish top-1 and top-3 accuracy on a held-out set, the number of families, and the corpus size per family.

Unresolved attributions are reported as a count, not dropped. Toolkit support is (planned).

## FM-9.8 Inter-rater agreement

Labels are judgments. A sample of leads is labelled by two reviewers independently, and agreement is reported as Cohen's κ ([Cohen 1960](references.md#statistics)); with more than two reviewers, Fleiss' κ ([Fleiss 1971](references.md#statistics)). Report κ with the sample size, the label set (agent, benign, unsure) and how disagreements were settled. Low agreement on a class means its labels, and any number built on them, are weak.

Toolkit: `review --labeller <name>` keeps each reviewer's labels apart, and `review --stats` reports Cohen's κ for each pair with its disagreements ([two labellers](../reference/evaluation.md#two-labellers)). Fleiss' κ is (planned).

## FM-9.9 What to publish with a number

Any precision, recall, agreement or accuracy figure published about the method carries:

- the evaluation kind ([FM-9.1](#fm-91-three-kinds-of-evaluation)) and the period it covers;
- the unit (record or cluster) and the counts behind it, not just the ratio;
- its 95% Wilson interval;
- the rules version and toolkit version;
- the label source, and overrides with their reasons;
- the class mix, since precision depends on the base rate.

A figure without these is not quoted in reports or notices.

## FM-9.10 Benchmark publication rules

A published benchmark contains:

- record ids or links to the public records, never third-party record content;
- labels, with who labelled and how;
- derived features (rule ids that fired, tactic, timestamp kind, defanged target host) that a practitioner computed;
- the split assignment (tuning or held-out) and the freeze date.

It never contains a source's content where the source's terms forbid redistribution ([FM-3.4](03-sources.md#fm-34-terms-of-use)), captured secrets, or operator-supplied logs. Users fetch records themselves, under the source's terms.

## FM-9.11 Agent-grade evaluation

The agent-likelihood grade ([FM-7.10](07-attribution.md#fm-710-agent-likelihood)) is measured against who really sent the records, not against detection labels:

- label each record's **actor**: agent, human or tool;
- report a confusion table of actor by grade, by record and by cluster;
- include hard negatives for the grade: human-pentest runs (hand-typed payloads, repeater pace, retries) and scanner runs (tool defaults, tool pace, fan-out);
- run a **negative control**: the grade over records captured before capable agents existed, none of which an agent sent. Any grade of L2 or above there is a false grade; archive captures stop at L2, so such a control measures the model-written rung.

A grade is not quoted as performance until a held-out measurement exists ([FM-9.1](#fm-91-three-kinds-of-evaluation)). Toolkit: records may carry `actor`; `eval` prints the table by record, and `eval --before <date>` runs the control over local records ([evaluation](../reference/evaluation.md#agent-grades-by-actor)). Neither is gated.
