# 9. Evaluation

[Manual index](README.md) · Previous: [8. Confidence language](08-confidence.md) · Next: [10. Disclosure](10-disclosure.md)

With no embargo on indicators, a false positive is published within a day of the admin acting on it, and the names of affected parties follow within days. Precision therefore matters most, and every number quoted about the method says what it was measured on.

## FM-9.1 Three kinds of evaluation

| Kind | What it is | What its numbers mean |
|---|---|---|
| **Regression set** | A committed, labelled set the rules were tuned on. | A floor that stops regressions. Not an estimate of real-world precision. |
| **Frozen held-out split** | Labelled data set aside before tuning and never used for it. | An estimate of performance on data like it. |
| **Prospective** | What happens to the leads the method actually produces. | Precision in operation, as the admin experiences it. |

A claimed number names its kind. Only held-out and prospective numbers may be quoted as performance.

## FM-9.2 Regression set

The regression set holds reconstructed records from published incident reports, synthetic records for each artifact family, and benign records, including hard negatives built to trip the rules ([FM-4.7](04-indicators.md#fm-47-rule-writing-standard)). A gate runs on every change and fails when precision or recall at either tier falls below its floor. Floors only go up.

Synthetic records are written to exercise a rule, so the rules catch them by construction and they lift every number they are counted in. Every headline number is therefore given twice: over all labelled records, and over the records not marked synthetic (reconstructions and collected records). The gate holds floors on both, so hand-written fixtures cannot hold a number up on their own. Read the non-synthetic numbers first.

In this repository the set is [`samples/eval/`](../../samples/eval/README.md) and the gate is described in [evaluation](../reference/evaluation.md#the-eval-gate).

## FM-9.3 Frozen held-out split

A held-out split is frozen before any rule is tuned against it, and is split two ways at once:

- **By time.** Every held-out record is later than every tuning record, so the measurement includes drift: new relays, new payloads, new tags.
- **By cluster.** No cluster or fleet has records on both sides. Records of one run are near-duplicates; splitting them across sides measures memory, not detection.

A frozen split is used for measurement only. Looking at its errors to change a rule spends it: the next measurement needs a new split.

Labels from an external release are used with documented overrides, each with its reason. The [Transluce release](references.md#incident-reports) is such a source: it labels scan reports and ships report ids, not contents, so a practitioner fetches the reports under their own access and measures record by record ([held-out steps](../../samples/eval/README.md#held-out-evaluation-on-the-transluce-release)). Its labels draw on context a single record cannot show, so the per-class table matters more than the total.

Toolkit: the Transluce measurement runs record by record, and `eval --split time|cluster` freezes a split of any labelled set ([frozen splits](../reference/evaluation.md#frozen-splits)). Results are saved as numbers and hashes ([saved results](../reference/evaluation.md#saved-results)). `eval repro <result>` finds the inputs by hash, measures again and diffs every number ([reproducing a result](../reference/evaluation.md#reproducing-a-result)); `eval check-results`, run by the gate, checks that every saved result names committed rules and code, has a benign record when held out or prospective, and holds no URL ([checking saved results](../reference/evaluation.md#checking-saved-results)).

## FM-9.4 Prospective evaluation

The prospective measure is the **admin-confirmed share of digest leads**: of the clusters the digest reported as leads in a period, the share a reviewer labelled agent activity. To catch misses, the reviewer also labels a stable random sample of unflagged records.

Toolkit: reviewed labels are saved and can be scored ([reviewed records](../reference/evaluation.md#reviewed-records)); computing the confirmed share per period is (planned).

## FM-9.5 Detection metrics

Detection is measured as precision and recall:

- **per tier**: significant, and suggestive or above;
- **per tactic** ([FM-4.3](04-indicators.md#fm-43-the-sc-t-tactic-taxonomy)), so a strong tactic does not hide a weak one;
- **per unit**: by record and by cluster. A cluster of ten records counts ten times by record and once by cluster; give both. By cluster, a predicted group whose labelled members mix agent and benign is wrong whether flagged or not: flagged, reporting it would misattribute the benign members;
- **per provenance**: over all records and over the non-synthetic ones ([FM-9.2](#fm-92-regression-set)).

Every proportion carries a 95% Wilson score interval ([Wilson 1927](references.md#statistics)), which behaves at small counts and near 0 or 1 where the plain normal interval does not. For `k` successes in `n` trials, `p = k/n` and `z = 1.96`:

```text
centre    = (p + z²/(2n)) / (1 + z²/n)
halfwidth = (z / (1 + z²/n)) · sqrt( p(1−p)/n + z²/(4n²) )
```

**Zero errors.** With none of `n` benign records flagged, the observed false-positive rate is 0 but the 95% upper bound is not: it is close to `3/n`, the rule of three ([Hanley and Lippman-Hand 1983](references.md#statistics)). Bounding a false-positive rate at 0.5% takes more than 600 benign records with none flagged. A clean result on fewer says less than that, and is quoted with its bound.

Toolkit: precision and recall per tier, by record and by cluster, over all and non-synthetic records, recall per class and per tactic, and false positives per benign class, each with its Wilson interval; the `3/n` bound where nothing was flagged ([statistics](../reference/evaluation.md#statistics), [units](../reference/evaluation.md#record-and-cluster-units)).

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

SC-Bench is this form as a file: the JSON Schema [`schemas/sc-bench-v1.json`](../../schemas/sc-bench-v1.json) holds a header (freeze date, rules version and hash, toolkit version) and one entry per record (id, defanged host, label, labellers, split, timestamp kind, provenance, and the reference rules' fired rules, tier and cluster), never a URL. Toolkit: `eval export-bench` writes one, and `eval --bench` scores another detector's predictions against it, by record and by cluster, over all and non-synthetic records ([SC-Bench](../reference/evaluation.md#sc-bench)).

## FM-9.11 Agent-grade evaluation

The agent-likelihood grade ([FM-7.10](07-attribution.md#fm-710-agent-likelihood)) is measured against who really sent the records, not against detection labels:

- label each record's **actor**: agent, human or tool;
- report a confusion table of actor by grade, by record and by cluster;
- include hard negatives for the grade: human-pentest runs (hand-typed payloads, repeater pace, retries) and scanner runs (tool defaults, tool pace, fan-out);
- run a **negative control**: the grade over records captured before capable agents existed, none of which an agent sent. Any grade of L2 or above there is a false grade; archive captures stop at L2, so such a control measures the model-written rung.

A grade is not quoted as performance until a held-out measurement exists ([FM-9.1](#fm-91-three-kinds-of-evaluation)). Toolkit: records may carry `actor`; `eval` prints the table by record, and `eval --before <date>` runs the control over local records ([evaluation](../reference/evaluation.md#agent-grades-by-actor)). Neither is gated.

## FM-9.12 Calibrated public language

Three kinds of word reach a reader: a tier ("significant"), an agent grade ("adaptive") and an attribution label with a likelihood word ("Suspected: very likely"). Each implies a rate of being right, and each may be said in public only as strongly as a measurement supports.

**The calibration rule.** A public statement that a class of finding *is* something (agent activity, an agent, a given operator) uses a likelihood word no stronger than the lower bound of the 95% Wilson interval ([FM-9.5](#fm-95-detection-metrics)) of that class's measured precision, read against the table in [FM-8.1](08-confidence.md#fm-81-likelihood-table).

For example, a significant tier whose held-out precision has a lower bound of 83% supports "very likely agent activity" for records of that tier and kind; one at 70% supports "likely". The measurement is held-out or prospective ([FM-9.1](#fm-91-three-kinds-of-evaluation)), on the same unit as the claim (record or cluster), and on data like the case's: the same source kinds and a comparable class mix ([FM-9.9](#fm-99-what-to-publish-with-a-number)).

| Statement | Measured by | Before a measurement exists | After |
|---|---|---|---|
| Tier: "the records contain attack payloads" | Nothing: it is Observed. | Allowed, with the rule ids. | Allowed. |
| Tier as agent activity: "this is agent activity" | Held-out precision of the tier, by cluster. | Not said. The notice says what the records contain ([FM-14.7](14-limits.md#fm-147-humans-look-the-same)). | The word the lower bound allows. |
| Agent grade: "an agent sent these" | The actor-by-grade table on a held-out set ([FM-9.11](#fm-911-agent-grade-evaluation)). | Not in a notice ([FM-7.10](07-attribution.md#fm-710-agent-likelihood)). Private reports give the grade as evidence reached, with its competing hypotheses ([FM-7.12](07-attribution.md#fm-712-competing-hypotheses)). | The word the grade's lower bound allows. |
| Scope: "the agents went beyond their task" | Reviewer agreement on scope findings ([FM-9.8](#fm-98-inter-rater-agreement)). | Allowed as the reviewer's Inference, with the evidence listed ([FM-15.4](15-misalignment.md#fm-154-stating-a-scope-finding)). | As before, with the agreement figure. |
| Attribution: label and likelihood word | The reliability table of settled attributions ([FM-9.7](#fm-97-attribution-calibration)). | The label is about evidence, not probability, and may be used. The likelihood word is the analyst's judgment, capped by the label, and the report says it is not yet calibrated. | The word may not exceed what the reliability table shows for its band. |

Rules that follow:

- **The regression set calibrates nothing.** It was tuned on, and is mostly synthetic, so its precision is a floor for regressions and never a basis for a word ([FM-9.2](#fm-92-regression-set)).
- **Agreement is not calibration.** Several groups reaching the same tier with the same rules shows the rules are shared, not that they are right.
- **Per class, not overall.** A precision measured mostly on one artifact family does not support a word for another. Where per-class counts are too small for an interval, the class has no measurement.
- **Words move down as well as up.** When a new measurement lowers a bound, later notices use the lower word, and published notices are not rewritten ([FM-2.6](02-principles.md#fm-26-correct-in-public)).

Toolkit: precision with Wilson intervals per tier, per class and per tactic, and the actor-by-grade table, are reported by `eval` ([statistics](../reference/evaluation.md#statistics)). Deriving the allowed word from a saved measurement, and checking it in `notice lint`, are (planned).
