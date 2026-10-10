# Browser toolkit

The GitHub Pages site in [`site/`](../../site/index.html) runs the same analysis as the CLI, compiled to WASM from [`sc-wasm`](../../crates/sc-wasm/README.md). Nothing leaves the browser.

## Building and serving

```sh
scripts/ci/build-site.sh                    # sc-wasm -> site/pkg (gitignored)
python -m http.server -d site 8080          # then open http://localhost:8080
```

`site/pkg/` and `site/notices/` are generated and gitignored. CI builds both at deploy ([runner](runner.md)).

## Analyse

The page analyses pasted or loaded records entirely client-side, including an operator's own access log ([for operators](../guides/for-operators.md#check-your-own-logs)). It also unwraps single URLs, edits rules, parses security.txt and defangs URLs. *Try an example* loads synthetic records, written to exercise the rules and never collected.

Selecting a cluster shows:

- its runs, daily rhythm, clock offset from date tags and stale date tags;
- the report hints: encoding styles, recon openings, unusual path sets, fabricated identifiers, probe chains.

A separate card lists shared pauses and probe chains across the input. These are hints to check, not evidence ([methodology](../methodology.md#descriptive-hints)).

## Rules tab

The Rules tab edits the rules in place. *Test against labelled set* scores the bundled and the edited rules on the committed `samples/eval/*.ndjson` set side by side, and lists records whose tier changed and records still misclassified ([evaluation](evaluation.md)).

## Disclosure draft

The disclosure draft follows the CLI's naming gate: pick the weakest evidence that may name a developer, and paste claims from case work (the JSON `swarmchase report --claims` reads). Outside case notes, a developer below that level is not named ([attribution](../methodology.md#attribution-levels-and-the-naming-gate)).

## Notices tab

The Notices tab lists published notices by status, provider and affected host. Each notice page shows its updates, corrections and statements ([notices](notices.md)).

## Case tab

The Case tab checks an evidence bundle. Pick its four files or its folder, and the page:

1. checks each SHA-256 against the manifest;
2. re-runs the analysis with the rules in the Rules tab;
3. compares every tier and cluster with the stamp, as `case verify` does;
4. shows the stamp, a timeline of each cluster's runs, the clusters and the records, defanged.

## Safety

Records carry attack payloads, so the page treats them as inert text.

- A strict Content-Security-Policy allows only the page's own script, styles and WASM module.
- Record text is inserted as text, never as HTML, and URLs are shown defanged and never as links.
- Notices reach the page as plain blocks and spans, never as HTML.

[`check-site.py`](../../scripts/ci/check-site.py) checks the policy and the code statically, in CI and in the pre-commit hook. [`site-xss-check.mjs`](../../scripts/site-xss-check.mjs) loads XSS probes and a hostile notice into headless Chrome and fails if any of them runs; CI runs it at deploy.
