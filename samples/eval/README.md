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
| `swarm` | optional | The interacting group (swarm) the record's run belongs to, or `none` for a run known not to interact. Scored by the [interaction-edge summary](../../docs/reference/evaluation.md#interaction-edges). |
| `synthetic` | written records | `true`: written by hand to exercise the rules. `eval` reports every number again without these ([synthetic and non-synthetic](../../docs/reference/evaluation.md#synthetic-and-non-synthetic-records)). |
| `reconstructed` | rebuilt records | `true`: rebuilt from a published incident. |
| `labeller` | optional | Who labelled the record, for [SC-Bench](../../docs/reference/evaluation.md#sc-bench) exports. |
| `tuned` | reviewed records | `true`: looked at while changing a rule, so left out of the [benign baseline](../../docs/reference/evaluation.md#a-reviewed-benign-baseline). |

Benign classes: `relay_reading` (a person reading a page through a relay or converter), `api_client` (ordinary API calls), `dev_tool` (developer services used as intended), `crawler` (pages and assets fetched by crawlers), `human_form` (searches, logins and other form input), `human_browse` (ordinary page views), `mail_gateway` (links a mail gateway or security product submits on its own), and `scanner` (security scanners). False positives are reported per benign class.

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

Synthetic records for the cluster-level evaluation, each pair or group a case linking must keep apart. If one merged, the cluster-level evaluation would list it as a false merge. The cluster-level numbers are reported, not gated; the golden test in `sc-core` fails on these merges.

- **Copied campaign tag.** Two readers, months apart, fetch different pages through the same relay with the same popular campaign tag (`tag=blackfriday`). A shared feature links only within the link window, so the pair stays apart.
- **Planted records.** Two agent runs, each two probes on one host joined by a run tag, and beside each a benign record placed two minutes after it on the same host: one read through the same relay, one sharing only a cache-busting parameter. Each shares a rule and a host with its run inside the timing window, but only a context rule, so neither joins ([methodology](../../docs/methodology.md#linking-into-clusters)).

## `swarm-interaction.ndjson`

Synthetic agent records for the interaction edges ([SC-FM 5.12](../../docs/manual/05-linking.md#fm-512-interaction-edges)), each marked `"synthetic": true`, on reserved `.example` hosts and made-up inbox and gist identifiers, and carrying a `swarm` group:

- **`none`**: one scheduler with one client splitting a host list into two shards started together. It is a fleet, and the only edge it should draw is a disjoint partition.
- **`handoff-1`**: one run names a gist as where its notes go; a different client fetches that gist 25 minutes later and probes other hosts.
- **`sink-1`**: two clients, one direct with a headless browser and one through a relay from another network, writing to one webhook.site inbox. The inbox joins them into one cluster; the shared-sink edge is between its strands.
- **`roles-1`**: one client reads five hosts; a different client attacks the same five in the same order half an hour later.

Every record is flagged significant on its own, so the file raises recall at both tiers and leaves precision unchanged.

## `cross-service.ndjson`

Synthetic records for cross-service fan-out ([methodology](../../docs/methodology.md#descriptive-hints)): one target submitted to several scan services within seconds. Each is marked `"synthetic": true`, uses reserved `.example` hosts, carries `"ts_kind": "submit"`, and was written by hand.

- **Agent run** (`xsvc-agent-1`): a tool loop probing one search with an unfilled placeholder, sending each variant to urlquery and then to urlscan 6 to 11 seconds later. It grades L4.
- **Human** (`actor`, no `label`): an analyst checking one suspicious link on two services four minutes apart, outside the window.
- **Mail gateway**: a gateway submitting every link in scanned mail to urlscan and then urlquery 3 seconds later. The ordinary links (newsletter, invoice, calendar, shared document, a click tracker with a timestamp parameter) are benign hard negatives, class `mail_gateway`, actor `tool`. Three links a person crafted in an agent's style and mailed through it are graded as `human`, with no `label`: the ordinary fan-outs around them mark an auto-submitter, so they stop at L3, the grade's known limit for a person pasting model output, instead of reaching L4.

## Coverage allow-list

[`coverage-allow.txt`](coverage-allow.txt) lists rules that may go without a positive: one rule id per line, then the reason. The gate fails on a rule with no agent-labelled record it fires on unless it is listed, and on an entry whose rule now has a positive. Remove the entry in the commit that adds the record.

## Synthetic and reconstructed records

Every record here is marked `synthetic` or `reconstructed`. The synthetic files exist to give each rule a positive and a hard negative, and the rules catch their agent records almost by construction; the reconstructions in `published-patterns.ndjson` are the closest the set comes to real traffic. `eval` prints the non-synthetic numbers beside the all-records ones, and the gate holds floors on both ([the eval gate](../../docs/reference/evaluation.md#the-eval-gate)).

## Real-data measurement

This set was used to tune the rules, so it is a regression floor, not a precision estimate. Two measurements on real data need no records committed here, and only their aggregate numbers are ever quoted:

- the [pre-era control](../../docs/reference/evaluation.md#the-pre-era-control-on-archive-data) (`swarmchase eval pre-era`): relay and carrier captures from before agents existed, where every flag is a false alarm;
- the [reviewed benign baseline](../../docs/reference/evaluation.md#a-reviewed-benign-baseline) (`swarmchase review sample`, then `swarmchase eval <data>/labels/reviewed.ndjson`): a stratified sample of the watch store, labelled by hand, with the false-positive bound per tier.

## SC-Bench example

[`bench/sc-bench-v1-example.json`](bench/sc-bench-v1-example.json) is this set as an [SC-Bench](../../docs/reference/evaluation.md#sc-bench) file: ids, labels, provenance, defanged hosts, and what the rules said when it was frozen. It is built from the files here only, with `swarmchase eval export-bench`, and every record is in the `regression` split because the rules were tuned on it. The records themselves are the lines in this directory with the same `id`.

## Saved results

[`results/`](results/README.md) holds measured results as JSON: numbers, input paths and hashes, the rules version and hash, and the toolkit version and commit. Never record content.

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
