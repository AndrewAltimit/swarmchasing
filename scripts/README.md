# scripts/

Every script in the repository, and where each gate runs. Each script carries its own usage header; this page is the map. A map that leaves something out is worse than none, because a reader takes absence as evidence, so every file under `scripts/` is listed here.

Run them from the repository root. The workflows and the pre-commit hook call them by `scripts/...` path.

## Gates

A gate fails the commit or the run. CI is the authority; the hook is a fast local mirror, scoped to what is staged.

| Gate | Checks | CI job | Pre-commit hook |
|---|---|---|---|
| [`ci/check-committed-data.py`](ci/check-committed-data.py) | No raw dumps, data or case paths, local secrets files or credential-shaped values in git; self-tests its detectors. | `gates` | every commit (`--staged`) |
| [`ci/check-md-links.py`](ci/check-md-links.py) | Relative links and heading anchors in every tracked Markdown file. | `gates` | staged `*.md` (`--staged`) |
| [`ci/check-doc-density.py`](ci/check-doc-density.py) | Over-long lines and paragraphs in table cells, in docs, crate READMEs, top-level pages and this page; `--self-test`. | `gates` | staged `*.md` (`--staged`) |
| [`ci/check-site.py`](ci/check-site.py) | The site's Content-Security-Policy and no HTML sinks in its code; `--selftest`. | `gates` | staged `site/` |
| [`ci/check-published-tags.py`](ci/check-published-tags.py) | Every linking tag or marker a committed notice shows is in `[linking] published_tags`; `--self-test`. | `gates` | staged `notices/` or `rules/` |
| [`ci/deny.sh`](ci/deny.sh) | cargo-deny: advisories, licenses, sources, bans. Installs the pinned cargo-deny. | `gates` | staged `Cargo.lock` or `deny.toml`, when cargo-deny is installed |
| `cargo fmt --check` | Formatting. The hook auto-fixes and re-stages. | `ci` | staged Rust, `Cargo.*`, `rules/`, `samples/eval/` |
| `cargo clippy -D warnings` | Lints, warnings as errors. | `ci` | as above |
| `cargo test --profile release-test` | The test suite. | `ci` | not run; run it before pushing |
| [`ci/eval-gate.sh`](ci/eval-gate.sh) | Precision and recall floors on `samples/eval/`, all and non-synthetic, then `eval check-results` on the saved results ([evaluation](../docs/reference/evaluation.md#the-eval-gate)). | `ci` | staged `rules/`, `crates/sc-core/`, `samples/eval/` |
| [`ci/check-rules-schema.py`](ci/check-rules-schema.py) | `rules/default.toml` validates against [`schemas/sc-rules-v1.json`](../schemas/sc-rules-v1.json) ([SC-Rules v1](../docs/specs/rules-v1.md)). Stdlib only. | `gates` | staged `rules/` or `schemas/` |
| `swarmchase notice lint` | Committed notices carry nothing a notice withholds ([notices](../docs/reference/notices.md#lint)). | `ci` | staged `notices/` |
| [`ci/check-wasm-target.sh`](ci/check-wasm-target.sh) | Type-checks `sc-wasm` (engine and `tools` feature), `sc-rules-wasm` and `sc-case` for `wasm32-unknown-unknown`. | `ci` | staged `crates/sc-core/`, `crates/sc-wasm/`, `crates/sc-case/` |
| [`site-xss-check.mjs`](site-xss-check.mjs) | Builds the site with a hostile notice and drives every page in headless Chrome with XSS probes; fails if any runs. | `deploy-pages` | not run |

Pull requests run `gates` then `ci`; pushes to `main` run both and then `deploy-pages`. Pull requests from forks run nothing. The jobs are in [`main-ci.yml`](../.github/workflows/main-ci.yml); the runner setup is in [runner](../docs/reference/runner.md).

`site-xss-check.mjs` exits 2 when it cannot run (no Chrome, or `site/pkg` not built). CI treats that as a warning unless the repo variable `SWARMCHASE_REQUIRE_BROWSER` is `true`.

## CI helpers

| Script | Does | Used by |
|---|---|---|
| [`ci/select-ci-target-dir.sh`](ci/select-ci-target-dir.sh) | Points `CARGO_TARGET_DIR` at a per-compiler cache outside the checkout and prunes the others. | every cargo job in both workflows |
| [`ci/build-site.sh`](ci/build-site.sh) | Builds the WASM modules (wasm-opt cached by module hash, size budget enforced), then the site into `_site/`, then runs `check-site.py` on it. | `deploy-pages`; local site work |
| [`ci/send-mail.sh`](ci/send-mail.sh) | Sends a plain-text email to the admin over SMTP with `curl`, with Date and Message-ID headers; refuses header injection. | `watch.yml` digest and failure alert |
| [`ci/install-hooks.sh`](ci/install-hooks.sh) | Points `core.hooksPath` at `git-hooks/`. Run once per clone. | contributors |

## Hooks

| Hook | Does |
|---|---|
| [`git-hooks/pre-commit`](git-hooks/pre-commit) | Runs the gates above for what is staged. `SWARMCHASE_SKIP_PRECOMMIT=1` skips it for one command. |

## Local helpers

| Script | Does |
|---|---|
| [`with-env.sh`](with-env.sh) | Loads `env.list` (parsed, never executed) and runs a command, or loads it into the shell when sourced ([configuration](../docs/reference/configuration.md#local-secrets)). |
