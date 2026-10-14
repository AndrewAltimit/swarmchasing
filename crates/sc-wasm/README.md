# sc-wasm

WebAssembly bindings for [`sc-core`](../sc-core/README.md), used by the [browser toolkit](../../docs/reference/browser-toolkit.md) on GitHub Pages. The pages run the same analysis as the CLI entirely in the browser: nothing a user pastes or loads leaves it.

## Build

```sh
scripts/ci/build-site.sh          # release modules into site/pkg, site/pkg/tools and site/pkg-rules, then the site
scripts/ci/build-site.sh --dev    # faster, unoptimised
python -m http.server -d _site 8080
```

The crate builds two modules, by feature:

| Feature | Module | What it carries |
|---|---|---|
| `engine` (default) | `site/pkg/sc_wasm.js` | What every analysis page loads: `analyze`, `unwrap`, `endpoints` and the helpers. |
| `tools` | `site/pkg/tools/sc_tools.js` | What a page loads on demand: `prepare` and `report`, `attribution`, `verify_bundle`, `eval_labelled`, `parse_security_txt`. |

Both carry `check_rules` and `defang`; tests build both. The build runs `wasm-pack build --target web` with size settings (opt-level `z`, one codegen unit, `panic=abort`, `wasm-opt -Oz` with `--gufa` and `--converge`) and fails a release module over its budget (the engine's is 2 MiB). The page loads a module as an ES module:

```js
import init, * as sc from "./pkg/sc_wasm.js";
await init();
const out = JSON.parse(sc.analyze(text, "auto", "", ""));
```

What keeps the module small: regex without Unicode property tables or literal prefilters (the workspace manifest); rules read as JSON, not TOML (edited rules go through [`sc-rules-wasm`](../sc-rules-wasm/README.md), and [`build.rs`](build.rs) converts the bundled rules); the labelled set and the example records served by the site, not compiled in; no deserialiser for a whole analysis; sorts through one shared routine ([`sc_core::sort`](../sc-core/src/sort.rs)) rather than one copy of the standard sort per call site.

## API

Everything crosses the boundary as strings: inputs are text or JSON, outputs are JSON (or Markdown), so the page needs nothing but `JSON.parse`. Functions that can fail throw a JS `Error` with the message. Wherever a function takes `rules_json`, it is a rules file as JSON (`sc-rules-wasm`'s `rules_json`), and an empty string means the bundled rules.

| Function | Returns |
|---|---|
| `check_rules(rules_json)` | `{"rules", "asns", "version"}`, or throws on an invalid rule set. |
| `analyze(input, format, map, rules_json)` | Engine. `{"analysis", "warnings", "redacted", "cluster_date_tags"}`, and keeps the analysis for `endpoints`. `format` is `auto`, `ndjson`, `json`, `lines` or `access_log`; `map` is a field mapping such as `ts=a.b,url=c`, or empty. Secrets are redacted before analysis. |
| `inputs_add(input, format, map)` | Engine. Parses one file of a set and keeps its records, ids prefixed with the file's number (`f2:log-17`); returns `{"file", "format", "lines", "records", "skipped", "redacted", "warnings", "warning_count"}`. |
| `inputs_analyze(rules_json)` | Engine. One analysis over every file added since the last call, as `analyze` returns it and keeps it; clears the set. `inputs_clear()` drops the set. |
| `unwrap(url, rules_json)` | Engine. The layers inside one URL and the rules that fired. |
| `prepare(input, format, map, rules_json)` | Tools. Re-runs `analyze` on the same input and keeps it for `report` and `attribution`; returns `{"clusters", "total"}`. |
| `report(opts_json)` | Tools. A Markdown draft of the prepared analysis. `opts_json` takes `audience`, `cluster` (a cluster `id` or `key`), `reporter`, `generated`, `min_named` and `claims`, as the CLI's `report` does. |
| `attribution(opts_json)` | Tools. `{"layers", "withheld"}` for one cluster of the prepared analysis; `opts_json` takes `cluster`, `claims` and `min_named`. |
| `endpoints(opts_json)` | Engine. Flagged activity per target host in the last analysis. `opts_json`: `{"min_tier", "now", "active_days"}`, or empty. |
| `evidence_levels()` | Engine. The evidence levels that may name a developer, weakest first, and the default. |
| `check_claims(claims_json)` | Engine. The claims re-serialised after validation. |
| `eval_labelled(rules_json, set)` | Tools. The eval report on the labelled NDJSON `set` (the site serves `samples/eval/*.ndjson` joined), every labelled record's tier, and the records misclassified. |
| `verify_bundle(records_ndjson, analysis_json, stamp_json, rules_json, claims_json)` | Tools. Re-runs an evidence bundle's analysis and compares it, and the bundle's own `analysis.json`, with its stamp, through [`sc-case`](../sc-case/README.md) as `swarmchase case verify` does, and adds the attribution layers. The page checks the manifest hashes itself with Web Crypto. |
| `verify_signature(manifest, signature, public_keys)` | Tools. `MANIFEST.sha256.sig` checked against the site's published keys (key file lines), through [`sc-case`](../sc-case/README.md): `status` (`signed`, `invalid`, `unsigned`, `unchecked`), `key_id`, `reason`, `line`, `published`. |
| `defang(text)` | The text with URLs defanged. |
| `parse_security_txt(text)` | Tools. The parsed `security.txt` fields. |
| `identity_catalog()` | Tools. The declared-agent catalog, with each range file's and directory's URL. |
| `identity_check(input, format, map, files_json)` | Tools. Each record's declared identity; `files_json` holds downloaded range files and directories by catalog id ([identity](../../docs/reference/identity.md#in-the-browser)). |
| `identity_check_held(files_json)` | Tools. `identity_check` on the records of the held analysis, such as a set analysed with `inputs_analyze`. |

Clusters in an analysis carry a number (`id`, `C1`) and a stable `key` (`k-3f9a2c1b`); its records may carry `ts_kind` and `target_asn` (see [`sc-core`](../sc-core/README.md#concepts)).

## Site safety

The pages build their DOM with `textContent` and never `innerHTML`, under a strict Content Security Policy, and defang every URL they show. Records are hostile input. `scripts/site-xss-check.mjs` and `scripts/ci/check-site.py` check this in CI.

## Tests

```sh
cargo test -p sc-wasm
```

The tests run natively; the functions are plain Rust behind `#[wasm_bindgen]`.
