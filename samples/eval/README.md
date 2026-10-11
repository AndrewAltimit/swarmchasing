# Evaluation set

Labelled records for `swarmchase eval`. CI runs [`eval-gate.sh`](../../scripts/ci/eval-gate.sh) on every `*.ndjson` here and fails when precision or recall falls below its floors, or when a rule has no positive and is not on the [coverage allow-list](#coverage-allow-list).

## Record fields

Each record is an ordinary record plus label fields:

| Field | On | Meaning |
|---|---|---|
| `label` | every record | `agent` or `benign`. |
| `class` | every record | Agent records: the kind of activity (`exploit`, `llm_residue`, ...). Benign records: the kind of ordinary traffic (see below). |
| `cite` | every record | Where the pattern comes from, or `synthetic: ...`. |
| `run` | optional | The true run the record belongs to. Scored by the [cluster-level evaluation](../../docs/reference/evaluation.md#cluster-level-evaluation). |
| `hard_negative_for` | benign, optional | Rule ids the record was written to resemble and must not be flagged for. |
| `actor` | optional | Who sent it: `agent`, `human` or `tool`, for the [agent grade table](../../docs/reference/evaluation.md#agent-grades-by-actor). A record with an `actor` and no `label` is graded, not scored. |

Benign classes: `relay_reading` (a person reading a page through a relay or converter), `api_client` (ordinary API calls), `dev_tool` (developer services used as intended), `crawler` (pages and assets fetched by crawlers), `human_form` (searches, logins and other form input), `human_browse` (ordinary page views), and `scanner` (security scanners). False positives are reported per benign class.

Records get a `run` only where the grouping is clear: the published reconstructions of one incident share one, and each other incident has its own. The `llm-residue.ndjson` records are independent synthetic examples and carry none.

## `published-patterns.ndjson`

Each line is a record with three extra fields: `label` (`agent` or `benign`), `class`, and `cite`.

- **Agent records (23)** reproduce request patterns quoted in two Transluce reports, [agent activity](https://transluce.org/agent-activity) and [US and Canadian government](https://transluce.org/us-canada-gov). Examples are `State_Id=1 OR 1=1`, `zz=oai<digits>`, `tok=expt3`, `CHATGPTTEST1`, `..%2F` traversal, and base64 programs sent through `httpbin.org/base64/`. Each record is marked `"reconstructed": true`. They rebuild the shape of the published request, not the original record. Where an article named a host but not a full URL, the path is illustrative.
- **Benign records (24)** are ordinary uses of the same relays and carriers, and normal requests to the same targets. They include known traps: SQL words in search text, `1=1` in a question, and reading `claude.ai` through a relay.

No urlquery content is copied here. urlquery's terms forbid redistributing it, and the Transluce release links reports rather than reproducing them.

## `llm-residue.ndjson`

Synthetic records for the language-model output residue rules (`marker.md_link`, `marker.placeholder`, `marker.tool_call_json` and the rest). Each is marked `"synthetic": true`, uses reserved `.example` hosts for targets, and was written by hand, not copied from any report.

- **Agent records (28)**, class `llm_residue`: Markdown links and code spans around URLs, unfilled placeholders (`YOUR_API_KEY`, `{{target}}`), function-call markup and tool-call JSON in parameters, JSON string tails, escaped newlines, and output cut off mid escape or with an ellipsis. Also chat reply openers in front of a URL (`Sure, here is the page: https://...`, `As an AI, I cannot open ...`), doubled, colon-less and defanged schemes (`https://https://`, `?url=https//`, `hxxps://` sent to a relay), impossible dates in date parameters (February 30, June 31, month 13), and stock example identities (`john.doe@example.com`, `test123`, `555-0142`). Most pair the residue with a relay, carrier, tag or probe, as agents do. Two show a generation loop: one word, and one two-word phrase, repeated five or more times in a search.
- **Benign records (34)** are hard negatives: JSON in the query string of ordinary GET APIs (Elasticsearch query DSL, GraphQL variables, REST filters), parentheses in page titles, backticks and Markdown in searches, `example.com` in search text and OAuth documentation links, unrendered front-end templates captured by crawlers, Windows paths, and an encoded `%` at the end of a URL. Further hard negatives cover the newer rules: searches that start like a chat reply (`here is the news`, `I'll be there for you`, `as an AI language model`), a blog slug read through a relay, a redirect parameter carrying an encoded URL, a host named `https-portal`, an analyst searching for a defanged indicator, a crawled `href` missing its colon, version and build strings shaped like impossible dates, real leap-day and month-end dates in both day/month orders, and an example address in a documentation link, a QA test login and a `123 Main St` map search. The last three match `marker.placeholder_identity` on purpose; at weight 1 they stay noise.
- **Generation-loop hard negatives (4)** guard `marker.repeated_token`: a song search of one short syllable (`na na na ...`), a search box tested with one long run of a letter, a title repeating a word four times, and repeated numbers in an API parameter.

### What the numbers mean

The rules were tuned on this set, so it is a **regression floor, not a precision estimate**. A measurement worth quoting needs held-out data.

## `rule-coverage.ndjson`

Synthetic records that give every rule at least one labelled positive, and the significant and link rules hard negatives: benign records that look alike and must not fire. Each is marked `"synthetic": true`, uses reserved `.example` hosts (or the public service the rule names), and was written by hand. Payloads are the canonical textbook test strings. Benign records name the rule they guard in `hard_negative_for`, and records from one synthetic run share a `run` id.

## `actor-controls.ndjson`

Synthetic runs sent by people and conventional tools, for the agent grade. Each carries `actor` (`human` or `tool`) and no `label`, so detection does not score it: the rules flag their payloads by design. Each is marked `"synthetic": true`, uses reserved `.example` hosts, and was written by hand from tools' documented defaults and textbook payloads.

- **Human**: SQL injection stepped through by hand in an intercepting proxy's repeater, a minute apart with retries after errors; textbook XSS typed into a search box minutes apart; and a person pasting a chatbot's login-bypass payloads, placeholder unfilled, retrying after errors. The last reaches L3, the grade's known limit.
- **Tool**: an SQL injection tool with its default user agent at tool pace; a template scanner sending two templates per second against one parameter (fixed fan-out); a proxy's active scanner working through its insertion points whatever each response.

## `linking-negatives.ndjson`

Benign records for the cluster-level evaluation. Two readers, months apart, fetch different pages through the same relay with the same popular campaign tag (`tag=blackfriday`). They are different runs, so they must not merge. A shared feature links only within the link window, so the pair stays apart; if it merged, the cluster-level evaluation would list it as a false merge. The cluster-level numbers are reported, not gated.

## Coverage allow-list

[`coverage-allow.txt`](coverage-allow.txt) lists rules that may go without a positive: one rule id per line, then the reason. The gate fails on a rule with no agent-labelled record it fires on unless it is listed, and on an entry whose rule now has a positive. Remove the entry in the commit that adds the record.

## Saved results

[`results/`](results/README.md) holds measured results as JSON: numbers, input hashes, the rules version and the toolkit commit. Never record content.

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

To freeze a split of your own labelled data, write the held-out ids to the data directory once and score each side separately:

```sh
swarmchase eval data/eval/labelled.ndjson --split cluster --seed 1 --split-out data/eval/holdout-ids.txt
swarmchase eval data/eval/labelled.ndjson --exclude-ids data/eval/holdout-ids.txt   # tune on this
swarmchase eval data/eval/labelled.ndjson --only-ids data/eval/holdout-ids.txt \
    --save-result data/eval/holdout-result.json --result-kind held_out --describe "..."
```

Read the per-class table, not just the overall recall. Transluce labelled many `source_request` reports suggestive because of context, such as a request to a data source tied to a known task. A rule cannot see that from one record. 79 controls are too few to estimate precision on their own, so add a sample of unflagged reports from a generic urlquery search, labelled `benign`, as a baseline.
