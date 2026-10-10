# sc-core

The analysis library behind the [`swarmchase`](../swarmchase/README.md) CLI and the [browser toolkit](../sc-wasm/README.md). It turns records of requests into graded, linked and timed findings, and drafts reports from them.

It has no I/O, no clock and no threads: it takes strings and returns values. The same code runs in the CLI, in CI and compiled to WebAssembly in the browser, so a result in one is the result in the others. Fetching records is [`sc-collect`](../sc-collect/README.md)'s job; reading and writing files is the CLI's.

## Use

It is a workspace crate (not published). Depend on it by path:

```toml
[dependencies]
sc-core = { path = "crates/sc-core" }
```

The usual flow is parse, analyse, then render:

```rust
use sc_core::{FieldMap, Format, ReportOptions, Rules, analyze, parse_input, render_markdown};

let rules = Rules::default_rules(); // rules/default.toml, compiled in
let parsed = parse_input(&text, Format::Auto, &FieldMap::default()); // secrets redacted here
let analysis = analyze(parsed.observations, &rules);

for r in &analysis.results {
    // r.obs (the record), r.score, r.tier, r.hits (the rules that fired)
}
for c in &analysis.clusters {
    // c.id ("C1"), c.members (indexes into results), timing and descriptive hints
}
let draft = render_markdown(&analysis, &ReportOptions::default()); // an internal draft
```

`Rules::from_toml(&text)` loads another rules file. `Analysis` serialises to JSON with serde; that JSON is what `swarmchase analyze` prints and what the browser passes around.

## Concepts

- **`Observation`**: one public record of a request: `id`, `source`, `ts`, `url`, and optionally IP, ASN, user agent, headers, status, final URL and a link to the public record.
- **Unwrapping**: relays (`r.jina.ai/https://…`, `*.translate.goog`), URL parameters, `data:` programs and base64 values are peeled into layers until the real target is found.
- **Rules**: data-driven indicators from [`rules/default.toml`](../../rules/default.toml), each with a weight. A record's score is the sum of the rules it triggers.
- **Tier**: `significant` (a rule marked significant fired, or score ≥ 6), `suggestive` (score ≥ 3) or `noise`.
- **Cluster**: records linked by shared identifiers, close timing against the same target, or a probe chain. Clusters carry timing and descriptive hints (encoding style, payload dialect, fan-out width and others). The hints are shown in reports and never change a score or a link.
- **Report**: a Markdown draft for one audience (`provider`, `affected`, `internal`, `public`). The public audience withholds what notices must not carry. Every report is a draft for a person to check.

[docs/methodology.md](../../docs/methodology.md) explains how records become tiers, clusters and claims, and the known limits.

## Modules

| Module | Covers |
|---|---|
| [`model`](src/model.rs) | `Observation`, `Tier`, `Hit` and timestamp helpers. |
| [`ingest`](src/ingest.rs) | NDJSON, JSON, CDX, urlquery, URL lists and access logs into `Observation`s; `--map` field mappings. |
| [`urlquery`](src/urlquery.rs) | urlquery.net report records into `Observation`s. |
| [`redact`](src/redact.rs) | Replaces secrets with `REDACTED-<hash>` at ingest. |
| [`extract`](src/extract.rs) | URL unwrapping, indicator matching for one record, and `defang`. |
| [`rules`](src/rules.rs) | Loading and compiling rule sets. |
| [`analyze`](src/analyze/mod.rs) | The pipeline: extract, score, link into clusters (`link`), describe each cluster (`hints`), time. Clusters have a number (`C1`) and a stable `key`. |
| [`chains`](src/chains.rs) | Probe chains: one client trying variant after variant of a request. |
| [`timing`](src/timing/mod.rs) | Cadence, bursts and pauses (`cadence`), hour-of-day profiles (`rhythm`), date tags (`dates`) and shared pauses (`pauses`). |
| [`fingerprint`](src/fingerprint.rs) | How a request was encoded, and header sets. |
| [`paths`](src/paths.rs) | Path sets per host and fabricated-looking identifiers. |
| [`dialect`](src/dialect.rs) | Payload dialect, shared dialects between clusters, repeated cut lengths. |
| [`fanout`](src/fanout.rs) | Parallel fan-out width. |
| [`recurrence`](src/recurrence.rs) | One task rerun on another day. |
| [`endpoints`](src/endpoints.rs) | Flagged activity grouped by target host. |
| [`attribution`](src/attribution.rs) | The evidence ladder and who a report may name. |
| [`report`](src/report/mod.rs) | Markdown drafts and the public notice: per-audience wording (`audience`), cluster hint lines (`hints`), attribution and endpoints (`sections`). |
| [`notice`](src/notice.rs) | What a public notice may carry: the withholding view and the leak lint. Notice files, pages and the feed are in [`sc-publish`](../sc-publish/README.md). |
| [`stamp`](src/stamp.rs) | Reproducibility stamps for evidence bundles. |
| [`eval`](src/eval.rs) | Precision and recall against labelled records. |
| [`securitytxt`](src/securitytxt.rs) | RFC 9116 `security.txt` parsing. |

## Rules

Rule changes go in `rules/default.toml`, not in code, and must pass the eval gate. See [Contributing a rule](../../CONTRIBUTING.md#contributing-a-rule).

## Tests

```sh
cargo test -p sc-core
```

`scripts/ci/check-wasm-target.sh` checks that the crate still builds for `wasm32-unknown-unknown`, so anything that needs the OS (files, network, the clock) stays out of it.
