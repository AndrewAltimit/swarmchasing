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
    // c.id ("C1"), c.key (stable), c.members (indexes into results), timing and hints
}
let draft = render_markdown(&analysis, &ReportOptions::default()); // an internal draft
```

`Rules::from_toml(&text)` loads another rules file. `Analysis` serialises to JSON with serde; that JSON is what `swarmchase analyze` prints and what the browser passes around.

## Concepts

- **`Observation`**: one public record of a request: `id`, `source`, `ts` and what it is the time of (`ts_kind`: a request, an archive capture, a scan submission), `url`, and optionally IP, the client's ASN, the target's ASN, user agent, headers, status, final URL and a link to the public record. Records stored before `ts_kind` and `target_asn` are upgraded as they are read.
- **Unwrapping**: relays (`r.jina.ai/https://…`, `*.translate.goog`), URL parameters, `data:` programs and base64 values are peeled into layers until the real target is found.
- **Rules**: data-driven indicators from [`rules/default.toml`](../../rules/default.toml), each with a weight and optionally an independence `group`. A record's score adds the weights of the rules it triggers, each group counted once at its largest weight and context kinds capped below suggestive (`Rules::score`).
- **Tier**: `significant` (a rule marked significant fired, or score ≥ 6), `suggestive` (score ≥ 3) or `noise`.
- **Cluster**: records linked by shared identifiers (`LinkFeature`, serialised as `param:<name>=<value>` or `<rule>:<text>`), close timing against the same target, or a probe chain. Each has a number by strength (`C1`), which can change between runs, and a stable `key` (`k-` and 8 hex digits) that every cluster selector also accepts. Clusters carry timing and descriptive hints (encoding style, payload dialect, fan-out width and others). The hints are shown in reports and never change a score or a link.
- **Report**: a Markdown draft for one audience (`provider`, `affected`, `internal`, `public`). The public audience withholds what notices must not carry. Every report is a draft for a person to check.

[docs/methodology.md](../../docs/methodology.md) explains how records become tiers, clusters and claims, and the known limits.

## The pipeline

`analyze` runs the passes listed in [`analyze/pipeline.rs`](src/analyze/pipeline.rs) in order over one context that holds the `Analysis` being built. Each pass names the passes whose output it reads, and a test fails when one is listed before them. A new per-cluster output is a field on `Cluster` (or in one of its groups, such as `knowledge` or `origin`, which serialise flat), a function that fills it, and one pass. The snapshot tests then show its JSON.

## Modules

| Module | Covers |
|---|---|
| [`model`](src/model.rs) | `Observation` (with what its timestamp is, `TsKind`, and the client's `asn` apart from the `target_asn`), `Tier`, `Hit`, `LinkFeature`, the known sources (`SourceKind`), `Provenance` and timestamp helpers. |
| [`ingest`](src/ingest.rs) | NDJSON, JSON, CDX, urlquery, URL lists and access logs into `Observation`s; `--map` field mappings. |
| [`urlquery`](src/urlquery.rs) | urlquery.net report records into `Observation`s. |
| [`capture`](src/capture.rs) | Wayback and Arquivo.pt captures into `Observation`s, with one id however they arrive. |
| [`redact`](src/redact.rs) | Replaces secrets with `REDACTED-<hash>` at ingest, and in every layer unwrapping decodes. |
| [`extract`](src/extract.rs) | URL unwrapping, indicator matching for one record, and `defang`. |
| [`rules`](src/rules.rs) | Loading and compiling rule sets. |
| [`analyze`](src/analyze/mod.rs) | The pipeline as ordered passes (`pipeline`): score, link into clusters (`link`), describe each cluster (`hints`), number, then cross-cluster hints. Clusters have a number (`C1`) and a stable `key`. |
| [`chains`](src/chains.rs) | Probe chains: one client trying variant after variant of a request. |
| [`seam`](src/seam.rs) | Seams in a cluster's link graph: a record or one client's records holding together two groups that differ. A plant-review prompt. |
| [`timing`](src/timing/mod.rs) | Cadence, bursts and pauses (`cadence`), hour-of-day profiles (`rhythm`), date tags (`dates`) and shared pauses (`pauses`). |
| [`fingerprint`](src/fingerprint.rs) | How a request was encoded, and header sets. |
| [`paths`](src/paths.rs) | Path sets per host and fabricated-looking identifiers. |
| [`dialect`](src/dialect.rs) | Payload dialect, shared dialects between clusters, repeated cut lengths. |
| [`fanout`](src/fanout.rs) | Parallel fan-out width. |
| [`fleets`](src/fleets.rs) | Soft links as likelihood ratios by family under joint caps, and the candidate fleets they suggest; never merges. |
| [`scaffold`](src/scaffold.rs) | Request templates with values as slot types, and cluster pairs sharing them beyond chance. |
| [`coactivity`](src/coactivity.rs) | Cluster pairs active together, or at a fixed lag, beyond a circular-shift chance model. |
| [`cotarget`](src/cotarget.rs) | Cluster pairs on the same rare targets in the same hours beyond a hypergeometric chance model, and in the same order beyond a random order. |
| [`biclique`](src/biclique.rs) | Co-groups: three or more clusters on several rarely held sites or templates, beyond a degree-preserving swap null. |
| [`generator`](src/generator.rs) | Generated identifiers decoded (UUID node ids, Snowflake workers, clock skews, counters), and cluster pairs on one generator beyond chance. |
| [`community`](src/community.rs) | Backbone filter, deterministic Leiden (CPM) and minimum cut for candidate fleets. |
| [`fleet_track`](src/fleet_track.rs) | Candidate fleets across analyses: `FK-` keys, matching, pair evidence accumulated over windows. |
| [`recurrence`](src/recurrence.rs) | One task rerun on another day, across target runs or across an analysis's clusters (`cluster_reruns`). |
| [`canary`](src/canary.rs) | Canary tokens for our own published pages: derivation from a seed, the registry, and copies found in records. |
| [`bursts`](src/bursts.rs) | Bursts of archive captures of a host the archives rarely capture. |
| [`endpoints`](src/endpoints.rs) | Flagged activity grouped by target host. |
| [`escalation`](src/escalation.rs) | Route escalation: one target requested directly, then through a relay, a program carrier, a remote browser. |
| [`attribution`](src/attribution.rs) | The evidence ladder and who a report may name. |
| [`identity`](src/identity/mod.rs) | Declared agent identity: product claims, published ranges (`ranges`), Web Bot Auth signatures (`httpsig`, `sfv`); verified, spoofed or claimed. Ed25519 checks need the `signatures` feature. |
| [`agentness`](src/agentness.rs) | Each cluster's agent grade (L0 payloads only to L4 agent likely) with its signals, counter-signals and caps; L5 only from a case decision. |
| [`swarm`](src/swarm/mod.rs) | Interaction edges between runs (SC-T9): runs and strands (`runs`), named artifacts (`artifacts`), one detector per kind (`edges`), edges against labels (`eval`); onset groups of clusters launched together (`onset`). |
| [`platform`](src/platform/mod.rs) | Coordinated-account swarm candidates on public platforms: slotted text sketches and MinHash (`text`), residue in prose (`residue`), benign automation and templates (`automation`), grouping and the chance model (`detect`), members' build provenance (`provenance`). Hints, never findings. |
| [`report`](src/report/mod.rs) | Markdown drafts and the public notice, one module per section; per-audience wording (`audience`) and cluster hint lines (`hints`). |
| [`notice`](src/notice.rs) | What a public notice may carry: the withholding view and the leak lint. Notice files, pages and the feed are in [`sc-publish`](../sc-publish/README.md). |
| [`stamp`](src/stamp.rs) | Reproducibility stamps for evidence bundles. |
| [`eval`](src/eval.rs) | Precision and recall against labelled records, per record and per cluster (`units`); agent grades by actor (`grades`); the negative control (`control`); SC-Bench (`bench`). |
| [`securitytxt`](src/securitytxt.rs) | RFC 9116 `security.txt` parsing. |
| [`sightings`](src/sightings/mod.rs) | SC-Sightings v1: an analysis as a shareable sightings file (keyed per-epoch hashes, scaffold, hours), and the matcher across parties. |
| [`sort`](src/sort.rs) | Stable sorts that share one compiled routine, so each call site does not add a copy of the standard sort to the browser module. Same order as `slice::sort_by`. |

## Rules

Rule changes go in `rules/default.toml`, not in code, and must pass the eval gate. See [Contributing a rule](../../CONTRIBUTING.md#contributing-a-rule).

## Tests

```sh
cargo test -p sc-core
```

Unit tests sit beside the code. [`tests/integration.rs`](tests/integration.rs) gathers the integration tests into one binary; [`tests/golden.rs`](tests/golden.rs) analyses the labelled set in `samples/eval/` end to end and holds the eval gate's numbers, so a change that moves them fails `cargo test` as well as the gate. [`tests/snapshot.rs`](tests/snapshot.rs) pins the full `Analysis` JSON (what the browser toolkit reads) and every audience's report over the same set to the files in `tests/snapshots/`; after an intended change, regenerate them with `UPDATE_SNAPSHOTS=1 cargo test -p sc-core --test integration snapshot::` and review the diff.

`scripts/ci/check-wasm-target.sh` checks that the crate still builds for `wasm32-unknown-unknown`, so anything that needs the OS (files, network, the clock) stays out of it.
