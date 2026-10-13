# Contributing

This page covers the rules of engagement: what will never land, which gates a change has to pass, and the conventions that keep a change reviewable. [`CLAUDE.md`](CLAUDE.md) is the repository map, [`docs/README.md`](docs/README.md) indexes the docs, and [`scripts/README.md`](scripts/README.md) says which gate runs where.

## The one hard rule: no raw data, no live secrets

**Nothing collected goes into git unredacted, and raw collector output never goes in at all.** Records can carry exfiltrated cookies, session tokens and API keys, and a watch run names organisations before the admin has reviewed anything.

In practice:

- `data/` and `cases/` are gitignored and stay that way; case files live in `<data>/cases/`. The watch pipeline keeps its record store in `$SWARMCHASE_DATA` on the runner, outside the checkout.
- Committed records live only in `samples/` or a crate's `tests/fixtures/`, and go through `swarmchase` ingest first, which replaces secrets with `REDACTED-<hash>`.
- A deliberately fake credential in a test carries `secret-scan: fixture` on the same line.
- Your own keys and passwords go in `env.list` (gitignored; start from `env.list.example`). The gate refuses `env.list` and `.env` even if force-added.

[`check-committed-data.py`](scripts/ci/check-committed-data.py) enforces this in the pre-commit hook and in CI. It checks what is tracked, not what `.gitignore` says, because an ignore rule is one `git add -f` away from being fiction.

## Passive collection only

Collectors read public indexes. They never open URLs agents submitted, never touch agents' callback inboxes or topics, and never probe suspected agent infrastructure. A collector that needs to contact a target system does not land. See [`docs/policies.md`](docs/policies.md).

## Getting set up

```bash
cargo build --release
scripts/ci/install-hooks.sh   # once per clone
cp env.list.example env.list  # optional: API keys and SMTP settings, loaded by scripts/with-env.sh
```

The installer points `core.hooksPath` at [`scripts/git-hooks/`](scripts/git-hooks/), so the hooks stay in version control.

## The gates

CI is strict: warnings are failures. Run these before you push:

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --workspace -- -D warnings
cargo test --workspace --profile release-test
scripts/ci/check-wasm-target.sh
scripts/ci/eval-gate.sh
python3 scripts/ci/check-committed-data.py
python3 scripts/ci/check-md-links.py
python3 scripts/ci/check-doc-density.py
python3 scripts/ci/check-site.py
python3 scripts/ci/check-published-tags.py
cargo run -p swarmchase -- notice lint
cargo run -p swarmchase -- watch --check watchlist.toml
scripts/ci/deny.sh
```

`deny.sh` runs cargo-deny against [`deny.toml`](deny.toml): RustSec advisories, permissive licenses only (compatible with MIT OR Unlicense), crates.io as the only source, no wildcard versions. It installs the pinned cargo-deny if it is missing.

If you change `site/`, also build it and run the browser check, which loads records carrying XSS probes and a hostile notice into headless Chrome and fails if anything executes:

```bash
scripts/ci/build-site.sh && node scripts/site-xss-check.mjs
```

The [verify skill](.claude/skills/verify/SKILL.md) covers serving the site and checking pages in headless Chrome.

`release-test` is CI's test profile: release optimisation without fat LTO, so a relink after a small change stays fast.

CI runs the repo gates first, then fmt, clippy, the tests, the eval gate, notice lint and the wasm32 type-check, on pull requests and on pushes to `main`. Pushes to `main` then build and deploy the site. Pull requests from forks run nothing on the self-hosted runner. The jobs and runner setup are in [`docs/reference/runner.md`](docs/reference/runner.md).

`check-doc-density.py` keeps docs readable: no line over 800 characters and no table cell over 60 words (tighter in `CLAUDE.md`). Committed docs describe what is, in the present tense; the why of a change, and a rule change's eval numbers, go in the commit message.

### What the pre-commit hook runs

The hook is scoped to what you staged ([the hook](scripts/git-hooks/pre-commit) is the authority):

| Staged | Gates |
|---|---|
| every commit | `check-committed-data.py --staged` |
| any `*.md` | `check-md-links.py --staged`, `check-doc-density.py --staged` |
| anything in `site/` | `check-site.py` |
| anything in `notices/` | `swarmchase notice lint` |
| anything in `notices/` or `rules/` | `check-published-tags.py` |
| `watchlist.toml`, `crates/sc-collect/`, `crates/swarmchase/src/watch/` | `swarmchase watch --check watchlist.toml` |
| `crates/`, `Cargo.*`, `rules/`, `rust-toolchain*` | `cargo fmt --check` (auto-fixed and re-staged), `cargo clippy -D warnings` |
| `rules/`, `crates/sc-core/`, `samples/eval/` | detection eval gate (`eval-gate.sh`) |
| `crates/sc-core/`, `crates/sc-wasm/` | wasm32 type-check |
| `Cargo.lock`, `deny.toml` | `deny.sh` (skipped with a warning if cargo-deny is not installed) |

The hook does not run the tests. Set `SWARMCHASE_SKIP_PRECOMMIT=1` to bypass it in an emergency.

## Conventions

- **`sc-core` stays I/O-free.** It compiles to WASM for the browser toolkit, so anything that touches the network or the filesystem goes in `sc-collect` or the CLI.
- **Rules are data.** Indicators live in [`rules/default.toml`](rules/default.toml), not in code. A new rule needs a public reference, and bumping its weight needs evidence. Change the `version` date when the rules change, and give the before/after `swarmchase eval` numbers in the commit message. See [Contributing a rule](#contributing-a-rule).
- **Floors only go up.** The eval gate's floors in [`eval-gate.sh`](scripts/ci/eval-gate.sh) are a ratchet: raise them when a change improves the numbers, and never lower one to land a change.
- **Defang in every output.** Reports, digests and notices print hosts as `a[.]b`; a record's URL is never made clickable.
- **Test the false positive too.** A rule fix for a misfire gets a regression test for the record that misfired.

## Contributing a rule

Rules decide what gets reported and published, so a rule change needs more than a pattern that matches. [`docs/methodology.md`](docs/methodology.md#rules) explains kinds, weights, tiers and linking. [Writing rules](docs/guides/writing-rules.md) walks through a change step by step: the fields, choosing a weight, hard negatives, and running the evaluation.

A new rule, or a change to an existing rule's pattern, weight, `significant` or `link` flag, needs all of the following:

1. **A public reference.** A published incident report, advisory or write-up that documents the behaviour. Put the link in the rule's comment or `description`. A behaviour seen only in unpublished data is not enough.
2. **Labelled eval records** in [`samples/eval/`](samples/eval/README.md), one JSON object per line with `label` (`agent` or `benign`), `class` and `cite`:
   - agent records the rule should catch, marked `"reconstructed": true` when rebuilt from a published request or `"synthetic": true` when written by hand;
   - **hard negatives**: benign records built to trip the rule, such as ordinary uses of the same service, the same words in search text, or the same syntax in a normal API call. A rule with no hard negatives does not land.
   - Targets use reserved hosts (`.example`, `example.com`) unless the reference names the host. Never copy urlquery content or raw collector output into the set.
3. **A passing eval gate.** `scripts/ci/eval-gate.sh` must pass. Never lower a floor to land a rule; fix the rule or argue the label instead.
4. **Before and after numbers in the commit message.** Run `swarmchase eval samples/eval/*.ndjson` before and after the change, and give precision and recall at both tiers, plus the new rule's own precision.
5. **A new `version` date** in the `[meta]` table of [`rules/default.toml`](rules/default.toml).

Weights and flags:

- **Weight.** Anything ordinary users also do stays below the suggestive threshold on its own. Raising a weight needs evidence that the rule's hits are agent activity, not just that it fires.
- **`significant = true`** is for unambiguous attack payloads and fingerprints no ordinary client produces. One match puts a record in the top tier, which can lead to a published notice.
- **`link = true`** is for identifiers only one operator would hold, such as a per-user inbox ID. A string many unrelated users share must never link, or it merges their clusters.

The pull request template repeats this list as a checklist.

## Licensing

Contributions are accepted under the project's dual license: the [Unlicense](LICENSE) or the [MIT License](LICENSE-MIT), at the user's option. [`NOTICE`](NOTICE) covers what the licenses do not extend to.
