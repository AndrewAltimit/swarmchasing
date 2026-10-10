---
name: verify
description: How to verify changes in this repo - the gates, the detection eval gate, building the browser toolkit and notice pages, the headless-Chrome XSS check, and looking at pages headlessly.
---

# Verifying changes in swarmchasing

Which gate covers what, and where each runs, is in [`scripts/README.md`](../../../scripts/README.md). Run what your change touches; CI runs everything.

## Gates

The four before any push:

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --workspace -- -D warnings
cargo test --workspace --profile release-test
scripts/ci/eval-gate.sh --profile release-test
```

The repo gates take seconds; run them for any docs, script or site change:

```bash
python3 scripts/ci/check-committed-data.py
python3 scripts/ci/check-md-links.py
python3 scripts/ci/check-doc-density.py --self-test && python3 scripts/ci/check-doc-density.py
python3 scripts/ci/check-site.py
python3 scripts/ci/check-published-tags.py --self-test && python3 scripts/ci/check-published-tags.py
cargo run -q --profile release-test -p swarmchase -- notice lint
scripts/ci/check-wasm-target.sh          # after touching sc-core or sc-wasm
scripts/ci/deny.sh                       # after touching Cargo.lock or deny.toml
```

On Windows, `python3` may be the Store stub; use `python`. Shell scripts run under Git Bash.

## Rules and analysis changes

`scripts/ci/eval-gate.sh` fails when precision or recall falls below its floors. For the numbers the commit message needs, run the eval before and after the change:

```bash
cargo run -q --profile release-test -p swarmchase -- eval samples/eval/*.ndjson --show-fp 50
```

Give precision and recall at both tiers and the changed rule's own precision. Never lower a floor. `eval` scores records, not clusters.

## Browser toolkit

1. Build the site (all generated, all gitignored):
   ```bash
   scripts/ci/build-site.sh                # WASM modules, then every page into _site/; --dev skips wasm-opt
   scripts/ci/build-site.sh --pages-only   # pages only, after a change to site/, docs/ or sc-publish
   ```
   `build-site.sh` caches the optimised modules in `${XDG_CACHE_HOME:-~/.cache}/swarmchase-wasm-opt`, so a rebuild with unchanged Rust skips wasm-opt. It runs `check-site.py --built _site --inputs ...` itself; a new file under `site/` must be `git add`ed first, because the build may read committed inputs only.
2. Serve it: `python -m http.server -d _site 8080` (run it in the background and stop it when done).
3. Run the XSS check. It starts its own server and Chrome, so the step above is not needed for it:
   ```bash
   node scripts/site-xss-check.mjs [path/to/chrome]
   ```
   It builds its own copy of the site with a hostile notice (cargo), so it needs `site/pkg` and `site/pkg-rules` built. Exit 0 is a pass, 1 a failure, 2 means it could not run (no Chrome, no cargo, or the modules missing). Run it after any change to `site/`, `sc-wasm`, or anything that renders records or notices.

## Looking at pages headlessly

Find a browser. `site-xss-check.mjs` takes a path argument or `$CHROME`; for your own checks, use the first that exists:

| Platform | Paths |
|---|---|
| Windows | `C:/Program Files/Google/Chrome/Application/chrome.exe`, `%LOCALAPPDATA%/ms-playwright/chromium-*/chrome-win64/chrome.exe` |
| Linux | `/usr/bin/google-chrome`, `/usr/bin/chromium`, `/usr/bin/chromium-browser`, `~/.cache/ms-playwright/chromium-*/chrome-linux/chrome` |

With the site served on 8080:

```bash
chrome --headless=new --disable-gpu --user-data-dir=<scratch>/prof --virtual-time-budget=5000 \
  --dump-dom http://localhost:8080/ > dom.html
chrome --headless=new --disable-gpu --user-data-dir=<scratch>/prof --window-size=1280,900 \
  --virtual-time-budget=5000 --screenshot=<scratch>/shot.png http://localhost:8080/
```

`--virtual-time-budget` gives the WASM module time to load before the dump or screenshot. Use a throwaway `--user-data-dir` so the run does not touch a real profile. For interaction (clicking tabs, loading records), drive Chrome over the DevTools protocol as `site-xss-check.mjs` does, or with playwright-core and the cached Playwright Chromium as `executablePath`.

Keep driver scripts, profiles and screenshots in the session scratchpad, never in the repo. Load only synthetic records or `samples/` into the page; never real watch data.

## CLI changes

Run the command against synthetic input or `samples/`, from the checkout root so `watchlist.toml` and `notices/` resolve. Commands that use the data directory default to `data/` relative to the working directory; point `--out` or `SWARMCHASE_DATA` at a scratch directory so a test never writes into real watch data. Never run a collector against live sources to test a change unless that is the change.
