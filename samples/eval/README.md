# Evaluation set

Labelled records for `swarmchase eval`. CI runs [`eval-gate.sh`](../../scripts/ci/eval-gate.sh) on every `*.ndjson` here and fails when precision or recall falls below its floors.

## `published-patterns.ndjson`

Each line is a record with three extra fields: `label` (`agent` or `benign`), `class`, and `cite`.

- **Agent records (23)** reproduce request patterns quoted in two Transluce reports, [agent activity](https://transluce.org/agent-activity) and [US and Canadian government](https://transluce.org/us-canada-gov). Examples are `State_Id=1 OR 1=1`, `zz=oai<digits>`, `tok=expt3`, `CHATGPTTEST1`, `..%2F` traversal, and base64 programs sent through `httpbin.org/base64/`. Each record is marked `"reconstructed": true`. They rebuild the shape of the published request, not the original record. Where an article named a host but not a full URL, the path is illustrative.
- **Benign records (24)** are ordinary uses of the same relays and carriers, and normal requests to the same targets. They include known traps: SQL words in search text, `1=1` in a question, and reading `claude.ai` through a relay.

No urlquery content is copied here. urlquery's terms forbid redistributing it, and the Transluce release links reports rather than reproducing them.

## `llm-residue.ndjson`

Synthetic records for the language-model output residue rules (`marker.md_link`, `marker.placeholder`, `marker.tool_call_json` and the rest). Each is marked `"synthetic": true`, uses reserved `.example` hosts for targets, and was written by hand, not copied from any report.

- **Agent records (26)**, class `llm_residue`: Markdown links and code spans around URLs, unfilled placeholders (`YOUR_API_KEY`, `{{target}}`), function-call markup and tool-call JSON in parameters, JSON string tails, escaped newlines, and output cut off mid escape or with an ellipsis. Also chat reply openers in front of a URL (`Sure, here is the page: https://...`, `As an AI, I cannot open ...`), doubled, colon-less and defanged schemes (`https://https://`, `?url=https//`, `hxxps://` sent to a relay), impossible dates in date parameters (February 30, June 31, month 13), and stock example identities (`john.doe@example.com`, `test123`, `555-0142`). Most pair the residue with a relay, carrier, tag or probe, as agents do.
- **Benign records (30)** are hard negatives: JSON in the query string of ordinary GET APIs (Elasticsearch query DSL, GraphQL variables, REST filters), parentheses in page titles, backticks and Markdown in searches, `example.com` in search text and OAuth documentation links, unrendered front-end templates captured by crawlers, Windows paths, and an encoded `%` at the end of a URL. Further hard negatives cover the newer rules: searches that start like a chat reply (`here is the news`, `I'll be there for you`, `as an AI language model`), a blog slug read through a relay, a redirect parameter carrying an encoded URL, a host named `https-portal`, an analyst searching for a defanged indicator, a crawled `href` missing its colon, version and build strings shaped like impossible dates, real leap-day and month-end dates in both day/month orders, and an example address in a documentation link, a QA test login and a `123 Main St` map search. The last three match `marker.placeholder_identity` on purpose; at weight 1 they stay noise.

### What the numbers mean

The rules were tuned on this set, so it is a **regression floor, not a precision estimate**. A measurement worth quoting needs held-out data.

## Held-out evaluation on the Transluce release

Transluce's [urlquery dataset](https://transluce.org/agent-activity) labels about 38,000 urlquery reports. 6,467 are significant, 31,182 suggestive, and 79 are benign background controls. It ships report IDs and labels, not report contents. To measure against it, fetch the reports and keep them in the gitignored `data/`:

```sh
# Download and unzip the release into data/ (not committed), then:
export URLQUERY_APIKEY=...          # from a urlquery.net account
cargo run --release -p swarmchase -- collect urlquery-reports \
    data/transluce/all-reports.csv -o data/eval/transluce.ndjson --sample 1000
cargo run --release -p swarmchase -- eval data/eval/transluce.ndjson \
    --labels data/transluce/all-reports.csv \
    --labels samples/eval/overrides/transluce-labels.ndjson \
    --json data/eval/transluce-eval.json
```

Later `--labels` files override earlier ones. [`overrides/transluce-labels.ndjson`](overrides/transluce-labels.ndjson) holds our corrections to Transluce's labels, each with its reason. These are IDs and our own notes, no urlquery content. `URLQUERY_APIKEY` can live in `env.list` (run through `scripts/with-env.sh`).

`--sample 1000` fetches every benign control plus 1,000 agent reports spread evenly over the list. The fetch appends to its output and skips IDs it already has, so it can be stopped and resumed. `review_required` rows are skipped as unlabelled.

Read the per-class table, not just the overall recall. Transluce labelled many `source_request` reports suggestive because of context, such as a request to a data source tied to a known task. A rule cannot see that from one record. 79 controls are too few to estimate precision on their own, so add a sample of unflagged reports from a generic urlquery search, labelled `benign`, as a baseline.
