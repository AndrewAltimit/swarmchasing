# CI on a self-hosted runner

All workflows use `runs-on: self-hosted`. The runner is Ubuntu Linux arm64 (DGX Spark), shared with other workloads. Each workflow file comments every step with why it exists; this page covers setup and what lives where. Which gate runs in which job is in [scripts/README.md](../../scripts/README.md).

## Workflows

| Workflow | Runs | Does |
|---|---|---|
| [`main-ci.yml`](../../.github/workflows/main-ci.yml) | Pull requests, pushes to `main`, manual dispatch | Repo gates, then fmt, clippy, tests, eval gate, notice lint and wasm32 type-check; on `main`, deploys the site. |
| [`watch.yml`](../../.github/workflows/watch.yml) | Every 6 hours, manual dispatch | `swarmchase watch`; emails the digest when something changed and an alert when the run fails. |
| [`watch-stale.yml`](../../.github/workflows/watch-stale.yml) | Every 3 hours, manual dispatch | Emails the admin when the newest watch run is more than 12 hours old. |

### main-ci.yml

- **Order.** The `gates` job runs first and the cargo job `ci` needs it, so a committed dump or a broken link fails in seconds. `ci` also runs `swarmchase watch --check` on the committed watchlist, reusing its test build.
- **Pull requests** run the same jobs as `main`, except the deploy. A superseded push to a PR cancels its earlier run; runs on `main` never cancel.
- **Pull requests from forks run nothing**, because a self-hosted runner would otherwise run untrusted code on the machine. Also enable *Settings → Actions → Require approval for all outside collaborators*.
- **Deploy.** On `main`, after `gates` and `ci` pass, `deploy-pages` (one at a time, in its own concurrency group) builds the site with `scripts/ci/build-site.sh` (it fails on a WASM module over budget, a page that breaks the site policy, or an input that is not committed), locates a browser and runs the site XSS check, then deploys `_site/` to Pages. Set *Settings → Pages → Source* to **GitHub Actions**.
- **Browser.** The *Locate Chromium* step hands the XSS check the first browser that starts headless as the check starts it, `$CHROME` or a system Chrome or Chromium (a snap that answers `--version` but cannot run headless is passed over). With none, the check runs against a pinned headless Chrome in a container ([`site-xss-container.sh`](../../scripts/ci/site-xss-container.sh)), which needs only Docker. Set the variable `SWARMCHASE_REQUIRE_BROWSER` to `true`, so a runner that later loses both fails the deploy instead of publishing unchecked pages ([runner requirements](#runner-requirements)).

### watch.yml

Results are not uploaded as artifacts: a public repo's artifacts are downloadable by anyone, and these are unreviewed leads. They stay in `$SWARMCHASE_DATA` on the runner and reach the admin only by email. Without the SMTP secrets, runs still write digests on the runner. One watch runs at a time, since runs share the state file and the record store.

A source failure, an unavailable host or a failed canary is a health alert, which makes the run count as changed, so the digest reporting it is mailed the same run ([health](watch.md#health)). The digest is mailed whenever the run wrote a changed one, even when the watch then exits non-zero because every source failed. The mail's subject starts with the run's priority, which the watch step writes to its outputs beside `changed` ([needs attention](watch.md#needs-attention)). The failure alert goes out when the job fails or is cancelled, with the tail of the run's log.

The Actions log of a public repository is public, and the watch's output describes unreviewed leads. The full output goes to `$RUNNER_TEMP/watch.log` on the runner and never to the log. The public log shows only the [public summary](watch.md#the-public-log) the watch writes from an allowlist: each source's name, kind, status, counts and duration, and the totals.

The watch runs on the `release-test` profile, the one `main-ci.yml` tests with, in the same cargo cache, so a run after a push reuses that build.

**First run.** The watch refuses a data directory that holds no watch data ([the data directory](watch.md#the-data-directory)). On a new runner, start the workflow by hand once with its `init` input checked; scheduled runs never pass `--init`, so a changed or unset `SWARMCHASE_DATA` fails the run (and mails the failure alert) instead of starting an empty store.

### watch-stale.yml

The watch's failure alert covers a run that fails or is cancelled, not one that never starts: a disabled schedule, an offline runner, a queue stuck behind another workload. Every 3 hours this workflow runs [`check-watch-age.sh`](../../scripts/ci/check-watch-age.sh), which reads only `LATEST` in the data directory, and emails the admin once per stale stamp when the newest run is more than 12 hours old (`.stale-alerted` holds the stamp last mailed about). Its log line says when the watch last finished, never what it found. It runs on the same runner, so it cannot report the runner itself being down.

Model triage is opt-in through the variables below: a model server the runner reaches on loopback or a private network (the watch refuses any other host before sending anything), or Claude through the runner user's Claude Code login ([model triage with Claude](#model-triage-with-claude)). The workflow holds no model API key. The job's timeout leaves room for one host's ten minutes of retries on HTTP 503: after those the run stops sending to that host, and its sources continue from their checkpoints next run.

## Secrets and variables

| Name | Kind | Used by | Purpose |
|---|---|---|---|
| `SMTP_URL` | secret | `watch.yml`, `watch-stale.yml` | SMTP server, e.g. `smtps://smtp.example.com:465`. Unset, no email is sent. |
| `SMTP_USER`, `SMTP_PASSWORD` | secret | `watch.yml`, `watch-stale.yml` | SMTP login. |
| `MAIL_FROM`, `MAIL_TO` | secret | `watch.yml`, `watch-stale.yml` | Sender and the admin's address. |
| `URLQUERY_APIKEY` | secret | `watch.yml` | Enables the urlquery sources. |
| `GITHUB_TOKEN` | automatic | `watch.yml` | The job's own read-only token; enables the GitHub search source. |

| `SWARMCHASE_DATA` | variable | `watch.yml`, `watch-stale.yml` | Data directory on the runner; default `~/swarmchase-data`. |
| `SWARMCHASE_WATCH_TRIAGE` | variable | `watch.yml` | `local` (or `true`) or `claude` turns on [model triage](watch.md#model-triage) of new leads. Unset, no model is asked. |
| `SWARMCHASE_LLM_URL`, `SWARMCHASE_LLM_MODEL` | variable | `watch.yml` | The model server local triage asks, on the runner or its private network, and the model name. |
| `SWARMCHASE_CLAUDE_MODEL`, `CLAUDE_PATH` | variable | `watch.yml` | The model Claude triage asks (default `claude-opus-5-5`) and the `claude` binary, when not on `PATH`. |
| `SWARMCHASE_CANARY_SEED` | secret | `main-ci.yml` | Seed of the site's [canary tokens](configuration.md#canary-tokens). Unset, the site carries none. |
| `SWARMCHASE_REQUIRE_BROWSER` | variable | `main-ci.yml` | `true` makes the deploy fail when the site XSS check has neither Chrome nor Docker, instead of skipping it with a warning. |

Email goes out through [`send-mail.sh`](../../scripts/ci/send-mail.sh) (`curl` over SMTP), to the admin only.

## Model triage with Claude

With `SWARMCHASE_WATCH_TRIAGE` set to `claude`, the watch runs Claude Code headless on the runner to suggest labels on each run's new leads. The credential is the runner user's own Claude Code login on the admin's subscription; the workflow holds no secret for it, and the watch removes `ANTHROPIC_API_KEY` from the call's environment so no API key is used. Claude sees only leads from the hosted sources, defanged and without IP addresses ([policies](../policies.md#evidence-and-attribution)).

Set it up once, as the user the runner service runs as:

1. Install Claude Code for that user, so `claude` is on its `PATH` or in `~/.local/bin` (otherwise set `CLAUDE_PATH`).
2. Log in with the subscription: run `claude`, then `/login`, and follow the prompts. The login is kept in `~/.claude`.
3. Check it with one headless call: `claude -p --model claude-opus-5-5 --tools "" "Reply with OK"` should print `OK`.
4. Set the repository variable `SWARMCHASE_WATCH_TRIAGE` to `claude`.

Each call runs with no tools, no MCP servers, no settings files, no CLAUDE.md, no saved session and a fixed system prompt, in an empty temporary directory, and never skips permission checks. One run makes one call for up to 25 leads. Calls count against the subscription's usage limits, which the runner's other workloads may share: when a limit is hit, the run asks no more, the digest says so, and the leads are asked again next run.

## What lives outside the checkout

`actions/checkout` cleans the workspace on every run, so anything that must persist lives elsewhere:

| Path | Holds | Managed by |
|---|---|---|
| `~/.cache/swarmchase-ci-target/` | cargo's build cache, one directory per exact compiler, shared by both workflows | [`select-ci-target-dir.sh`](../../scripts/ci/select-ci-target-dir.sh) |
| `${XDG_CACHE_HOME:-~/.cache}/swarmchase-wasm-opt/` | optimised WASM modules, keyed by the hash of the unoptimised module | [`build-site.sh`](../../scripts/ci/build-site.sh) |
| `$SWARMCHASE_DATA` (default `~/swarmchase-data`) | watch state, record store, runs, labels, cases | `swarmchase watch` |

## Runner requirements

- **rustup.** [`rust-toolchain.toml`](../../rust-toolchain.toml) pulls stable plus the `wasm32-unknown-unknown` target.
- **python3** for the repo gates, and **node** for the site XSS check.
- **Chrome, Chromium or Docker** for the site XSS check (optional unless `SWARMCHASE_REQUIRE_BROWSER` is `true`). An installed browser is used first. Otherwise [`site-xss-container.sh`](../../scripts/ci/site-xss-container.sh) runs a pinned multi-arch `chromedp/headless-shell` image (arm64 included) as the runner user, on the host network with debugging on loopback only, with the check's files mounted read-only; the container holds no state and is removed when the check ends. The runner user needs Docker access; no sudo and no system libraries are needed. [`site-xss-check.mjs`](../../scripts/site-xss-check.mjs) takes a local browser from `$CHROME`, which the step sets, or the usual install paths, and a running one from `XSS_CDP`.
- `wasm-pack` and `cargo-deny` are installed on first use by the scripts that need them; wasm-pack downloads `wasm-opt` on its first optimised build.
