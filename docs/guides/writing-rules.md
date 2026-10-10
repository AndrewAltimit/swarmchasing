# Writing rules

A tutorial for adding or changing an indicator rule in [`rules/default.toml`](../../rules/default.toml): what each field does, how to pick a weight, how to write the hard negatives that keep a rule honest, and how to show the eval gate the change is safe. The requirements a rule change must meet are listed in [CONTRIBUTING](../../CONTRIBUTING.md#contributing-a-rule); the standard behind them is [FM-4.7](../manual/04-indicators.md#fm-47-rule-writing-standard). This page is the how.

Every example here is synthetic and uses reserved `.example` hosts.

## Before you write anything

A rule needs a **basis**: a public write-up, advisory or incident report that documents the behaviour. A pattern seen only in unpublished data is not enough, because a reader of a notice must be able to check why the rule exists.

Then look at how the toolkit already reads the shape. Build a stand-in URL with `.example` hosts and unwrap it:

```sh
cargo run -p swarmchase -- unwrap 'https://reader.relay.example/https://stats.agency.example/table?id=7'
```

`unwrap` prints each layer (relays, URL-valued parameters, `data:` and base64 payloads) and every rule that fires, with its weight. If an existing rule already catches the shape, the change may be a pattern fix, not a new rule. The browser's Unwrap page does the same ([browser toolkit](../reference/browser-toolkit.md#pages)).

## Anatomy of a rule

```toml
[[rule]]
id = "relay.reader_example"
kind = "relay"
tactic = "T1"
target = "host"
pattern = "reader.relay.example"
weight = 2
description = "Reader relay: fetches a page server-side and returns text (synthetic example)"
```

| Field | What it does |
|---|---|
| `id` | Stable dotted name, `<kind>.<name>`. Reports, notices and eval output cite it, so never reuse one. |
| `kind` | The family: `relay`, `carrier`, `exploit`, `agent_marker`, `cache_buster`, `self_id`, `exfil`, `header`, `outcome`, `anti_bot`, `infra`. |
| `target` | What the rule reads (see below). |
| `pattern` | A host suffix for `host`; a case-insensitive regular expression otherwise. |
| `check` | A test a `param_value` match must also pass (see [checks](#checks)). |
| `weight` | What a match adds to the record's score. Defaults to 1. |
| `significant` | `true`: one match puts the record in the top tier. |
| `link` | `true`: the matched text joins records into one cluster. |
| `tactic` | What the match shows the agent doing, `T1` to `T9` ([FM-4.3](../manual/04-indicators.md#fm-43-the-sc-t-tactic-taxonomy)). |
| `artifact` | `true`: the match only shows that a model wrote the request. |
| `description` | One line a reader of a report can understand. |

A rule names a `tactic` or sets `artifact = true`; a test fails on a bundled rule with neither, and a tactic outside `T1` to `T9` stops the file loading. Each kind has a default tactic ([FM-4.4](../manual/04-indicators.md#fm-44-default-tactics-by-rule-kind)); a bundled rule on another tactic needs an entry with its reason in `TACTIC_EXCEPTIONS` ([`rules.rs`](../../crates/sc-core/src/rules.rs)). Tactics and artifacts describe; they never change a score.

### Targets

| `target` | Reads |
|---|---|
| `host` | The host of every unwrapped layer, as a suffix match. |
| `url` | Each layer's decoded text: the URL, a `data:` body, a base64 payload. |
| `param_name`, `param_value` | Query parameter names, or values. |
| `header` | Request headers as `name: value`. |
| `user_agent` | The user agent. |
| `final_url` | Where the scan ended. |

Pick the narrowest target that works. A `url` pattern also sees hosts and paths, so it fires more widely than a `param_value` pattern with the same text. `header`, `user_agent` and `final_url` rules fire only on records that carry those fields: most archive rows do not, and operator access logs often do.

The analysis module in the browser has no Unicode property classes (`\p{…}`); a pattern that uses one works in the CLI only ([edited rules](../reference/browser-toolkit.md#edited-rules)).

### Checks

Some shapes need counting, which a regular expression cannot do. A `param_value` rule can name a `check`: the pattern picks candidate values cheaply, and the rule fires only on a value the check also passes. The checks:

| `check` | Passes when |
|---|---|
| `repeated_token` | One word of three characters or more, or a phrase of two or three words, repeats five or more times in a row. |

```toml
[[rule]]
id = "marker.loop_example"
kind = "agent_marker"
artifact = true
target = "param_value"
pattern = "(\\S+\\s+){4}\\S"
check = "repeated_token"
weight = 1
description = "A word or phrase repeated in a loop (synthetic example)"
```

A check on any other target, or a name not in the table, stops the file loading. Keep the pattern loose enough to reach every value the check should see: here, any value of five words or more. A new check is code in sc-core ([`prose.rs`](../../crates/sc-core/src/prose.rs) holds `repeated_token`) with its own tests, and hard negatives in the eval set like any rule.

## Choosing a weight

A record's score is the sum of the weights of the distinct rules that fired, each counted once however many layers it matched. The `[thresholds]` table grades it: suggestive at 3, significant at 6.

- **Anything ordinary users also do stays below suggestive alone.** People read pages through relays, use echo services and add cache-busters. Relays weigh 1 or 2, so one relay hit never flags a record; it needs a second, independent indicator.
- **Artifacts stay low.** Model-output residue and self-identification come from people pasting chatbot answers too. Weight 1 or 2.
- **Weight 3** flags a record alone, at suggestive. Use it only for shapes ordinary traffic rarely has: a per-user callback inbox, a tag parameter agents add.
- **`significant = true`** is for payloads and fingerprints with no ordinary use: `UNION SELECT`, multi-step traversal to a sensitive file, a script tag in a parameter. A significant record can lead to a published notice, so a significant rule needs the strongest hard negatives.
- **A weaker form of a payload** (one `../`, a lone quote, an out-of-range id) gets a weight, not `significant`.

Raising an existing weight needs evidence that the rule's hits are agent activity, not only that it fires more.

## When a rule links

`link = true` makes the matched text a link feature: records sharing it join one cluster, within `linking.feature_link_window_secs` of each other, unless the feature spans more than `linking.feature_max_hosts` target hosts, when it is listed as common instead ([FM-5.2](../manual/05-linking.md#fm-52-shared-link-features)).

Use it only for values one operator would hold: a callback inbox id, a request-catcher subdomain, a notification topic. A string many unrelated users share must never link, or it merges their clusters and every later step inherits the error ([FM-14.6](../manual/14-limits.md#fm-146-common-features-cause-giant-clusters)). When a service has both forms, write two rules, as the OAST rules do: the per-user subdomain links, the bare service name scores but does not.

```toml
[[rule]]
id = "exfil.catcher_example"
kind = "exfil"
tactic = "T7"
target = "url"
pattern = "[a-z0-9]{8,}\\.catcher\\.example"
weight = 3
link = true
description = "Per-user request-catcher inbox (synthetic example)"
```

Run-tag parameters whose values link are listed in `linking.strong_params`, not marked per rule. A pattern that matches the same text on every record (a fixed tag prefix, say) links all of them; match the distinguishing part, or do not link.

## Benchmark and stale-knowledge entries

Two tables in the rules file describe clusters without scoring them: `[[benchmark]]` lists public practice targets and benchmark environments, and `[[stale]]` lists retired endpoints and old client versions ([FM-4.5](../manual/04-indicators.md#fm-45-artifact-families), [FM-4.9](../manual/04-indicators.md#fm-49-benchmark-targets-and-declared-testing)).

```toml
[[benchmark]]
id = "practice_shop_example"
# https://docs.practice.example/ (the vendor's page for its demo shop)
pattern = "://demo\\.practice\\.example\\b"
note = "A deliberately vulnerable demo shop (synthetic example)"

[[stale]]
id = "widgets_api_v1"
target = "user_agent"
# https://docs.widgets.example/deprecations (the retirement notice)
pattern = "\\bWidgetsClient/1\\."
note = "Widgets client 1.x, retired (synthetic example)"
```

| Field | What it does |
|---|---|
| `id` | Unique name, shown in reports and in the cluster's `benchmarks` or `stale_knowledge`. |
| `target` | `url` (the default: the request on the target host) or `user_agent`. |
| `pattern` | A case-insensitive regular expression. |
| `note` | One line saying what a match means, shown with stale entries. |

Every entry needs a source in a comment: the site's own page for a practice target, the provider's deprecation notice for a retired API. Anchor host patterns on `://` and a word boundary so a path or a search mentioning the name does not match. An entry changes no score and no tier, so it does not move the eval numbers; check it with two stand-in records through `report --audience internal` or the workbench's cluster detail instead. A stale entry is reported only when two or more members of a cluster carry it, so one old script in a cluster stays quiet.

## Writing eval records

Each new or changed rule needs labelled records in [`samples/eval/`](../../samples/eval/README.md): at least one agent record it should catch, and hard negatives. Synthetic records for coverage go in `rule-coverage.ndjson`; records rebuilt from a published request go in `published-patterns.ndjson`, marked `"reconstructed": true`.

A positive:

```json
{"id": "eval:cov-reader-probe", "source": "eval", "ts": "2026-08-05T10:00:00Z", "url": "https://reader.relay.example/https://stats.agency.example/table?id=1%27", "label": "agent", "class": "indirection", "cite": "synthetic: reader relay wrapping a quote probe", "synthetic": true, "run": "cov-run-reader"}
```

A hard negative is a benign record built to trip the rule: the same service used as intended, the same words in a search, the same syntax in an ordinary API call. It names the rule it guards:

```json
{"id": "eval:cov-reader-news", "source": "eval", "ts": "2026-08-05T11:00:00Z", "url": "https://reader.relay.example/https://www.news.example/article/42", "label": "benign", "class": "relay_reading", "cite": "synthetic: a person reading an article through the relay", "synthetic": true, "hard_negative_for": ["relay.reader_example"]}
```

Good hard negatives are the cases you would be embarrassed to publish: a search for the payload's words, documentation about the syntax, a QA login with a stock identity, a popular page read through the relay. A hard negative may fire the rule as long as the record stays below suggestive; the coverage table shows how close it came.

Rules for records: targets use `.example` hosts unless the basis names the host; `cite` says where the shape comes from or starts `synthetic:`; records from one synthetic run share a `run`, so the cluster-level numbers measure linking. Never copy scan-service content or raw collector output into the set ([configuration](../reference/configuration.md#urlquerynet)).

## Running the evaluation

Rules are compiled into the CLI, so run through `cargo run` after editing, or pass the file with `--rules`. Measure before the change on the old rules, then after:

```sh
git show HEAD:rules/default.toml > data/rules-before.toml        # data/ is gitignored
cargo run -p swarmchase -- eval samples/eval/*.ndjson --rules data/rules-before.toml
cargo run -p swarmchase -- eval samples/eval/*.ndjson \
    --coverage --coverage-allow samples/eval/coverage-allow.txt --require-coverage
scripts/ci/eval-gate.sh
```

Read, in this order:

1. **Tiers.** Precision and recall at significant and at suggestive-or-above, each as `value [lo–hi]` with its count. The interval is a 95% Wilson interval ([statistics](../reference/evaluation.md#statistics)).
2. **Your rule's row.** Its precision, its hard negatives and how many it fired on.
3. **False positives.** `--show-fp N` lists them; each one is a record that would be published.
4. **Coverage.** Every rule needs at least one agent-labelled record it fires on, unless the [allow-list](../../samples/eval/coverage-allow.txt) names it with a reason. Adding a positive for an allowed rule fails the gate until you remove its entry in the same commit.

`eval-gate.sh` runs the same evaluation with the floors written in it: point floors on precision and recall at both tiers, and floors on the lower end of each precision interval. The interval floors stop a rule from passing on a handful of records: 100% precision on a few dozen records still has a lower bound well below 100%. The floors only go up. If a change fails one, fix the rule or argue the label in `samples/eval/`; never lower the floor ([the eval gate](../reference/evaluation.md#the-eval-gate)).

The committed set is a regression floor, not a precision estimate: the rules were tuned on it. To quote a number, measure on held-out data ([FM-9.1](../manual/09-evaluation.md#fm-91-three-kinds-of-evaluation)).

### In the browser

The site's rules page edits rules in place and *Test against labelled set* scores the bundled and edited rules side by side, listing records whose tier changed ([edited rules](../reference/browser-toolkit.md#edited-rules)). It is quick for trying patterns; the numbers for the commit come from the CLI.

## Finishing the change

- Validate the file: `cargo run -p swarmchase -- rules rules/default.toml`.
- Bump `[meta] version` to the date of the change.
- Put the before and after numbers in the commit message: precision and recall at both tiers, and the rule's own precision. The why of the change goes there too, not in a rule comment ([CLAUDE.md](../../CLAUDE.md#writing-rules-for-committed-docs)).
- Fill in the rule section of the [pull request template](../../.github/PULL_REQUEST_TEMPLATE.md), including the reason for any `significant` or `link` flag.

Open cases keep the rules they were opened with, so a merged rule reaches a case only when the admin re-pins it ([pinned rules](../reference/cases.md#pinned-rules)).
