# For researchers

This page is for researchers outside the project: people studying agent behaviour on the public internet, checking this project's claims, or applying the method to their own data. It covers what the toolkit and site do, running the analysis on your own exports, the rule format and tactic taxonomy, contributing a rule, citing the method, reproducing the evaluation numbers, scoring your own detector against SC-Bench, and what data is never shared.

## What the toolkit does

The toolkit reads public records (archive indexes, scan-service results, registry and event-stream metadata, certificate logs), redacts secrets, unwraps each recorded URL into its layers, grades each record against indicator rules, links flagged records into clusters, and describes their timing. It drafts reports and notices; a person decides what is true and publishes. The steps are in [methodology](../methodology.md), and the method as a standard any group can apply is the [Field Manual](../manual/README.md).

Collection is passive: nothing fetches a URL an agent submitted, reads an agent's callback channel or probes its infrastructure ([FM-3.2](../manual/03-sources.md#fm-32-passivity-test)). Work that follows the manual keeps to the same test.

The public site carries the same analysis, compiled to WebAssembly: the notices, the docs, the rules with an editor, the evaluation summary, and the workbench ([browser toolkit](../reference/browser-toolkit.md)).

## Running the analysis on your own exports

### In the browser

The workbench (**Analyze**) analyses records you paste or load. Parsing and analysis run in the page; nothing is uploaded.

1. Paste records or use **Load file**. Accepted formats: NDJSON or JSON records, a CDX JSON export from a web archive, one URL per line, or a web server access log. Auto-detect usually picks the format.
2. If your JSON names fields differently, give a field map, for example `ts=submitted_at,url=page.url`.
3. Press **Analyze**. The views show runs, the fleet graph of hints between clusters, rules against clusters, rhythm and endpoints, each with a table view ([the workbench](../reference/browser-toolkit.md#the-workbench)).

*Try an example* loads synthetic records written to exercise the rules. To run the site locally, build it with `scripts/ci/build-site.sh` and serve `_site/`.

### With the CLI

```sh
cargo build --release
swarmchase scan export.ndjson                         # flagged records, strongest first
swarmchase clusters export.ndjson                     # linked clusters and runs
swarmchase analyze export.ndjson -o analysis.json     # the full analysis as JSON
swarmchase unwrap '<url>'                             # the layers of one URL and the rules each triggers
```

Through cargo, replace `swarmchase` with `cargo run --release -p swarmchase --`. `--format` and `--map` work as in the browser, and `--rules <file>` runs a rules file of your own. Each record's timestamp kind (request, submit, capture) decides which timing claims it can support ([FM-6.1](../manual/06-timing.md#fm-61-timestamp-kinds)); archive rows are captures, not requests.

## Rules and tactics

Indicators are data, in [`rules/default.toml`](../../rules/default.toml), compiled into the CLI and the site. Each rule has an id, a kind, a target, a pattern, a weight, optional `significant` and `link` flags, and a tactic or an artifact flag ([FM-4.2](../manual/04-indicators.md#fm-42-rule-anatomy)). The site's rules page shows one card per rule.

Tactics say what an agent was doing, independent of how a rule detected it: `SC-T1` task retrieval to `SC-T9` inter-agent coordination ([FM-4.3](../manual/04-indicators.md#fm-43-the-sc-t-tactic-taxonomy)), with a cross-walk to MITRE ATLAS and ATT&CK ([FM-4.6](../manual/04-indicators.md#fm-46-cross-walk-to-mitre-atlas-and-attck)). Artifacts are traces of how an agent was built, such as model-output residue; they score low and never link ([FM-4.5](../manual/04-indicators.md#fm-45-artifact-families)).

## Contributing a rule

A rule change needs a public reference, labelled positives and hard negatives in the evaluation set, a passing eval gate, and its before and after numbers. [Writing rules](writing-rules.md) walks through it; [CONTRIBUTING](../../CONTRIBUTING.md#contributing-a-rule) lists the requirements.

Pull requests from forks run nothing on the project's runner, so run the gates yourself and say which you ran ([CONTRIBUTING](../../CONTRIBUTING.md#the-gates)).

## Citing the method

Cite the Field Manual by version and section id: `SC-FM 1.0 §FM-5.2`. Section ids, tactic ids and attribution labels are stable within a major version; a section whose meaning changes gets a new id ([how to cite](../manual/README.md#how-to-cite)). Say which sections you follow and where you depart.

Cite a rule by its id and the rules version (`[meta] version` in the rules file), and a number by its evaluation kind and the context [FM-9.9](../manual/09-evaluation.md#fm-99-what-to-publish-with-a-number) lists. For worked examples of the method applied to published incidents, see the case studies from [FM-13.3](../manual/13-case-study.md#fm-133-reading-a-published-write-up-with-the-template) on.

## Reproducing the evaluation numbers

There are three kinds of number, and only two may be quoted as performance ([FM-9.1](../manual/09-evaluation.md#fm-91-three-kinds-of-evaluation)).

- **The regression set.** [`samples/eval/`](../../samples/eval/README.md) holds reconstructed, synthetic and benign records. `swarmchase eval samples/eval/*.ndjson` reproduces the numbers the site shows; [`eval-gate.sh`](../../scripts/ci/eval-gate.sh) adds the floors. The rules were tuned on this set, so it is a floor, not an estimate. Most of it is synthetic; read the non-synthetic numbers, which `eval` prints beside the rest ([synthetic and non-synthetic](../reference/evaluation.md#synthetic-and-non-synthetic-records)).
- **Held-out.** Transluce's labelled urlquery.net release ships report ids and labels. With your own urlquery.net key, `swarmchase collect urlquery-reports` fetches the reports into a gitignored directory and `eval --labels` scores them, with this project's label overrides and their reasons ([held-out steps](../../samples/eval/README.md#held-out-evaluation-on-the-transluce-release)).
- **Saved results.** [`samples/eval/results/`](../../samples/eval/results/README.md) holds measured results as numbers, with the path, SHA-256 and size of every input and label file, the rules version and hash, and the toolkit version and commit. Holding the same inputs, `swarmchase eval repro <result.json>` measures again and diffs every number ([reproducing a result](../reference/evaluation.md#reproducing-a-result)).

Every proportion carries a 95% Wilson interval. Precision and recall are counted per record and per cluster, since a run of ten flagged records is one report, not ten ([units](../reference/evaluation.md#record-and-cluster-units)). Run-labelled records also give B-cubed precision and recall for linking ([evaluation](../reference/evaluation.md)). To build your own held-out measurement, freeze a split by time or cluster before tuning anything ([frozen splits](../reference/evaluation.md#frozen-splits)).

## Scoring your own detector (SC-Bench)

SC-Bench is the evaluation set as a file another group can score its own detector against, with this project's scorer ([SC-Bench](../reference/evaluation.md#sc-bench)). A bench file follows [`schemas/sc-bench-v1.json`](../../schemas/sc-bench-v1.json). It names each record by id and carries its label, labellers, split, timestamp kind, source and provenance, defanged target host, and what this project's rules said at the freeze. It holds no URL or other record content.

1. Get the records. The committed example, [`sc-bench-v1-example.json`](../../samples/eval/bench/sc-bench-v1-example.json), names records in [`samples/eval/`](../../samples/eval/README.md); a bench over a third-party source names records you fetch yourself, by id, under the source's terms.
2. Run your detector and write one NDJSON line per record: `id`, then `tier` (`noise`, `suggestive`, `significant`) or `flagged` (true or false), and optionally your `cluster` for the record.
3. Score: `swarmchase eval --bench <bench.json> --predictions <yours.ndjson> --json score.json`. The score has record-unit and cluster-unit precision and recall with intervals, for all records and for the non-synthetic ones, overall and per split. `swarmchase eval --bench <bench.json>` alone scores this project's rules as frozen in the file, for comparison.

When you report a score, give the bench name and freeze date, the split, the unit, and the non-synthetic numbers beside the all-records ones.

## Negative control

No agent of the kind looked for existed before late 2022, so every flag on older records is a false alarm. `swarmchase eval <records or store> --before 2022-11-30` gives label-free false-alarm rates per tier, agent grade and plant signal, with intervals ([negative control](../reference/evaluation.md#negative-control)). Archive captures from before that date are the natural input.

## What is never shared, and why

| Never shared | Why |
|---|---|
| urlquery.net report content | Its terms forbid redistribution. The project links reports and quotes only indicators it derived. |
| Raw collector output and the watch store | Records can carry captured cookies and tokens, and name organisations before review. |
| Unreviewed leads | Nothing reaches the public before the admin reviews it. |
| Case files and reviewed labels | They hold private reports, contacts and judgments in progress. |
| Operator-supplied logs | They are the operator's, used publicly only with consent ([FM-10.7](../manual/10-disclosure.md#fm-107-operator-supplied-logs)). |
| Live channel identifiers and secrets | A reader could take over or reuse an agent's channel ([FM-11.4](../manual/11-notices.md#fm-114-what-a-notice-withholds)). |

A benchmark built from this work follows [FM-9.10](../manual/09-evaluation.md#fm-910-benchmark-publication-rules): record ids or links, labels, derived features and the split, never a source's content where its terms forbid it. You fetch the records yourself, under the source's terms.
