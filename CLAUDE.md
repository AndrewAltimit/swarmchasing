# CLAUDE.md

Guidance for Claude Code when working in this repository.

This file is a **map**, not the manual. The detail lives in [`README.md`](README.md), [`docs/policies.md`](docs/policies.md) and the code; this file points at the right place, plus the rules that apply across the whole repo. Keep it that way: a row here is one line and a link.

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
| [`notices/`](README.md#notices) | Published notices (`<id>.md`, front matter + dated updates). Committing one publishes it; `notice lint` gates what they may carry. |
| [`crates/sc-wasm`](crates/sc-wasm/README.md) | wasm-bindgen bindings for the browser toolkit in [`site/`](site/index.html). |
| [`rules/default.toml`](rules/default.toml) | Indicator rules, compiled into the CLI and the browser. Every change passes the eval gate; the commit message gives the before/after eval numbers. |
| [`samples/eval/`](samples/eval/README.md) | Labelled evaluation set behind the CI eval gate; how to run the held-out Transluce measurement. |
| [`watchlist.toml`](watchlist.toml) | Sources the scheduled watch pulls. |
| [`scripts/ci/`](scripts/ci/select-ci-target-dir.sh) | CI gates and helpers; the [pre-commit hook](scripts/git-hooks/pre-commit) mirrors them. |
| [`.github/workflows/`](.github/workflows/main-ci.yml) | `main-ci.yml` (gates, lint, test, Pages) and `watch.yml` (6-hourly watch, digest email). |
| [`docs/`](docs/methodology.md) | [Methodology](docs/methodology.md), [for operators](docs/for-operators.md), and [policies](docs/policies.md) for collection, attribution, reporting and publication. |

## Gates

Run before pushing (full list in [CONTRIBUTING](CONTRIBUTING.md#the-gates)):

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --workspace -- -D warnings
cargo test --workspace --profile release-test
scripts/ci/eval-gate.sh
```

## Runner

Self-hosted, label `self-hosted`, Ubuntu arm64 (DGX Spark), shared with other workloads. Fork PRs run nothing. Cargo's cache and the watch data live outside the checkout (`~/.cache/swarmchase-ci-target`, `$SWARMCHASE_DATA`), because `actions/checkout` cleans the workspace.
