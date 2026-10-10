# CI on a self-hosted runner

All workflows use `runs-on: self-hosted`. The runner is Ubuntu Linux arm64 (DGX Spark), shared with other workloads. Each workflow file comments every step with why it exists; this page covers setup and what lives where. Which gate runs in which job is in [scripts/README.md](../../scripts/README.md).

## Workflows

| Workflow | Runs | Does |
|---|---|---|
| [`main-ci.yml`](../../.github/workflows/main-ci.yml) | Pull requests, pushes to `main`, manual dispatch | Repo gates, then fmt, clippy, tests, eval gate, notice lint and wasm32 type-check; on `main`, deploys the site. |
| [`watch.yml`](../../.github/workflows/watch.yml) | Every 6 hours, manual dispatch | `swarmchase watch`; emails the digest when something changed and an alert when the run fails. |

### main-ci.yml

- **Order.** The `gates` job runs first and the cargo job `ci` needs it, so a committed dump or a broken link fails in seconds.
- **Pull requests** run the same jobs as `main`, except the deploy. A superseded push to a PR cancels its earlier run; runs on `main` never cancel.
- **Pull requests from forks run nothing**, because a self-hosted runner would otherwise run untrusted code on the machine. Also enable *Settings → Actions → Require approval for all outside collaborators*.
- **Deploy.** On `main`, after `gates` and `ci` pass, `deploy-pages` builds the site with `scripts/ci/build-site.sh` (it fails on a WASM module over budget, a page that breaks the site policy, or an input that is not committed), runs the site XSS check, then deploys `_site/` to Pages. Set *Settings → Pages → Source* to **GitHub Actions**.

### watch.yml

Results are not uploaded as artifacts: a public repo's artifacts are downloadable by anyone, and these are unreviewed leads. They stay in `$SWARMCHASE_DATA` on the runner and reach the admin only by email. Without the SMTP secrets, runs still write digests on the runner. One watch runs at a time, since runs share the state file and the record store.

## Secrets and variables

| Name | Kind | Used by | Purpose |
|---|---|---|---|
| `SMTP_URL` | secret | `watch.yml` | SMTP server, e.g. `smtps://smtp.example.com:465`. Unset, no email is sent. |
| `SMTP_USER`, `SMTP_PASSWORD` | secret | `watch.yml` | SMTP login. |
| `MAIL_FROM`, `MAIL_TO` | secret | `watch.yml` | Sender and the admin's address. |
| `URLQUERY_APIKEY` | secret | `watch.yml` | Enables the urlquery sources. |
| `SWARMCHASE_DATA` | variable | `watch.yml` | Data directory on the runner; default `~/swarmchase-data`. |
| `SWARMCHASE_REQUIRE_BROWSER` | variable | `main-ci.yml` | `true` makes the deploy fail when the site XSS check cannot find Chrome, instead of skipping it with a warning. |

Email goes out through [`send-mail.sh`](../../scripts/ci/send-mail.sh) (`curl` over SMTP), to the admin only.

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
- **Chrome or Chromium** for the site XSS check (optional unless `SWARMCHASE_REQUIRE_BROWSER` is `true`). [`site-xss-check.mjs`](../../scripts/site-xss-check.mjs) looks in the usual install paths and `$CHROME`.
- `wasm-pack` and `cargo-deny` are installed on first use by the scripts that need them; wasm-pack downloads `wasm-opt` on its first optimised build.
