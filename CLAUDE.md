# CLAUDE.md

Guidance for Claude Code when working in this repository.

This file is a **map**, not the manual. The detail lives in [`docs/`](docs/README.md), the crate READMEs and the code; this file points at the right page, plus the rules that apply across the whole repo. Keep it that way: a row here is one line and a link. If a cell needs a paragraph, the paragraph belongs on the linked page.

## Mission

Find misaligned AI agent swarms in public records, link their activity into runs and fleets, and report each incident to the AI provider responsible and to the affected operators, publishing a public notice at the same time. Policies (no embargo, naming, channels, what notices withhold, retention) are in [`docs/policies.md`](docs/policies.md).

## Hard rules

- **No raw data or live secrets in git.** `data/` (watch data and case files) is gitignored; committed records are redacted at ingest. Enforced by [`check-committed-data.py`](scripts/ci/check-committed-data.py). See [CONTRIBUTING](CONTRIBUTING.md#the-one-hard-rule-no-raw-data-no-live-secrets).
- **Secrets live in `env.list`** (gitignored, loaded by [`scripts/with-env.sh`](scripts/with-env.sh)); [`env.list.example`](env.list.example) lists the names. Never print their values.
- **Passive only.** Never fetch a URL an agent submitted, never touch its callback channels, never probe its infrastructure.
- **The admin sends and publishes.** Tools and agents draft reports, find contacts and prepare notices. They never send email, file reports or publish a notice.
- **No public artifacts of unreviewed leads.** Watch output stays on the runner and reaches the admin by email only.

## Repository map

| Path | Covers |
|---|---|
| [`crates/sc-core`](crates/sc-core/README.md) | Analysis: ingest, redaction, unwrapping, rules, scoring, clustering, timing, reports. No I/O (compiles to WASM). |
| [`crates/sc-collect`](crates/sc-collect/README.md) | Passive collectors (Wayback / Arquivo CDX, urlquery.net search and reports, crt.sh, security.txt) with retry and paging. |
| [`crates/swarmchase`](crates/swarmchase/README.md) | CLI (usage in its README); [`watch.rs`](crates/swarmchase/src/watch.rs) is the incremental watch pipeline and digest; [`case.rs`](crates/swarmchase/src/case.rs) is case files, contacts, evidence bundles and send drafts; [`evidence.rs`](crates/swarmchase/src/evidence.rs) is logs operators send back; [`stix.rs`](crates/swarmchase/src/stix.rs) is the STIX 2.1 export; [`notice.rs`](crates/swarmchase/src/notice.rs) adds, updates, lints and builds public notices. |
| [`crates/sc-wasm`](crates/sc-wasm/README.md) | wasm-bindgen bindings for the browser toolkit in [`site/`](site/index.html). |
| `notices/` | Published notices (`<id>.md`, front matter + dated updates). Committing one publishes it ([notices](docs/reference/notices.md)). |
| [`rules/default.toml`](rules/default.toml) | Indicator rules, compiled into the CLI and the browser. Every change passes the eval gate. |
| [`samples/eval/`](samples/eval/README.md) | Labelled evaluation set behind the CI eval gate; the held-out Transluce steps. |
| [`watchlist.toml`](watchlist.toml) | Sources the scheduled watch pulls, each with its rationale. |
| [`scripts/`](scripts/README.md) | CI gates, helpers and the pre-commit hook; the README says what runs where. |
| [`.github/workflows/`](.github/workflows/main-ci.yml) | `main-ci.yml` (gates, then build/test, then Pages) and `watch.yml` (6-hourly watch, digest email). |
| [`.claude/skills/verify/`](.claude/skills/verify/SKILL.md) | How to verify a change: gates, eval, site build, headless browser checks. |

## Docs map

| Doc | Covers |
|---|---|
| [`docs/README.md`](docs/README.md) | Index of every doc. |
| [`guides/admin-workflow.md`](docs/guides/admin-workflow.md) | Digest → review → case → contacts → drafts → send → notice → updates. |
| [`guides/for-operators.md`](docs/guides/for-operators.md) | For a reported site: what the report means, checking logs, replies, bundles. |
| [`reference/watch.md`](docs/reference/watch.md) | Data directory, incremental collection, digest, retention, review. |
| [`reference/cases.md`](docs/reference/cases.md) | `case.toml`, every `case` subcommand, drafts, bundles, pinned rules. |
| [`reference/notices.md`](docs/reference/notices.md) | Notice lifecycle, what notices withhold, lint and build. |
| [`reference/evaluation.md`](docs/reference/evaluation.md) | `eval`, the eval gate's floors, held-out measurement. |
| [`reference/browser-toolkit.md`](docs/reference/browser-toolkit.md) | The Pages site: build, tabs, payload safety. |
| [`reference/configuration.md`](docs/reference/configuration.md) | `env.list`, environment variables, urlquery key and terms. |
| [`reference/runner.md`](docs/reference/runner.md) | Workflows, secrets and variables, caches, runner requirements. |
| [`methodology.md`](docs/methodology.md) | Tiers, clusters, hints, attribution levels, known limits. |
| [`policies.md`](docs/policies.md) | Collection, attribution, reporting and publication. |

## Scripts and gates

[`scripts/README.md`](scripts/README.md) maps every script and gate to the CI job and hook trigger that runs it. [CONTRIBUTING](CONTRIBUTING.md#the-gates) lists the commands. The four that matter before a push:

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --workspace -- -D warnings
cargo test --workspace --profile release-test
scripts/ci/eval-gate.sh
```

## Common commands

```bash
scripts/ci/install-hooks.sh                              # once per clone
cargo run -p swarmchase -- scan records.ndjson           # flagged records
cargo run -p swarmchase -- eval samples/eval/*.ndjson    # rules precision/recall
cargo run -p swarmchase -- notice lint                   # committed notices
scripts/with-env.sh cargo run -p swarmchase -- watch     # one watch run with env.list loaded
scripts/ci/build-site.sh && python -m http.server -d site 8080
python3 scripts/ci/check-md-links.py && python3 scripts/ci/check-doc-density.py
```

## Writing rules for committed docs

- Present tense. State what the code, command or policy **is**, not when or how it came to be.
- No dates of work, session notes, narrative changelogs or before/after comparisons in committed files.
- No rot-prone counts of project state (tests, rules, records, eval scores). Stable facts (a threshold, a default) are fine.
- Keep prose out of table cells. A cell is one line; a paragraph goes in a section on the linked page. [`check-doc-density.py`](scripts/ci/check-doc-density.py) enforces caps, tighter for this file. Passing is a floor, not a target.
- The why of a rule change, and its before/after `swarmchase eval` numbers, go in the commit message, not in a doc or a rule comment.
- Never cite a private planning document or agent memory from a committed file.

## Cross-cutting facts that catch people out

- **The data directory is relative by default.** `--out`/`--data`, else `SWARMCHASE_DATA`, else `data/` under the working directory. Run from the checkout root or set the variable, or a watch starts a fresh store. Details: [watch](docs/reference/watch.md#the-data-directory).
- **`eval` scores records, not clusters.** A cluster of ten flagged records counts ten times, and the committed set is a regression floor, not a precision estimate. Details: [evaluation](docs/reference/evaluation.md).
- **Cases pin rules.** A case's reports, notice, exports and bundles use the rules version it was opened with; a rules change does not reach them until `case rules <id> --update`. Details: [cases](docs/reference/cases.md#pinned-rules).
- **urlquery content is never committed or quoted.** Not in samples, fixtures, notices or eval overrides; link the report, quote only derived indicators. Details: [configuration](docs/reference/configuration.md#urlquerynet).
- **Fork PRs run nothing** on the self-hosted runner. To test a fork's change, push it to a branch of this repository. Details: [runner](docs/reference/runner.md).
- **`actions/checkout` cleans the workspace.** Anything that must persist (cargo cache, wasm-opt cache, watch data) lives outside the checkout. Details: [runner](docs/reference/runner.md#what-lives-outside-the-checkout).
- **`site/pkg/` and `site/notices/` are generated** and gitignored; build them before serving or running the XSS check. Details: [verify skill](.claude/skills/verify/SKILL.md).
- **Floors only go up.** Never lower an [`eval-gate.sh`](scripts/ci/eval-gate.sh) floor to land a change; fix the rule or argue the label.
- **Defang in every output.** Hosts print as `a[.]b`, and a record's URL is never made clickable, in reports, digests, notices and the site.

## Runner

Self-hosted, label `self-hosted`, Ubuntu arm64 (DGX Spark), shared with other workloads. Setup, secrets and caches: [`docs/reference/runner.md`](docs/reference/runner.md).
