# sc-wasm

WebAssembly bindings for [`sc-core`](../sc-core/README.md), used by the [browser toolkit](../../docs/reference/browser-toolkit.md) on GitHub Pages. The pages run the same analysis as the CLI entirely in the browser: nothing a user pastes or loads leaves it.

## Build

```sh
scripts/ci/build-site.sh          # release modules into site/pkg and site/pkg-rules, then the site
scripts/ci/build-site.sh --dev    # faster, unoptimised
python -m http.server -d _site 8080
```

The build runs `wasm-pack build --target web` with size settings (opt-level `z`, one codegen unit, `panic=abort`, `wasm-opt -Oz`), and fails a release module over 1.5 MiB. The page loads it as an ES module:

```js
import init, * as sc from "./pkg/sc_wasm.js";
await init();
const out = JSON.parse(sc.analyze(text, "auto", "", ""));
```

What keeps the module small: regex without Unicode property tables or literal prefilters (the workspace manifest); rules read as JSON, not TOML (edited rules go through [`sc-rules-wasm`](../sc-rules-wasm/README.md), and [`build.rs`](build.rs) converts the bundled rules); the labelled set and the example records served by the site, not compiled in; no deserialiser for a whole analysis.

## API

Everything crosses the boundary as strings: inputs are text or JSON, outputs are JSON (or Markdown), so the page needs nothing but `JSON.parse`. Functions that can fail throw a JS `Error` with the message. Wherever a function takes `rules_json`, it is a rules file as JSON (`sc-rules-wasm`'s `rules_json`), and an empty string means the bundled rules.

| Function | Returns |
|---|---|
| `version()` | The toolkit version. |
| `default_rules()` | The bundled `rules/default.toml` text. |
| `check_rules(rules_json)` | `{"rules", "asns", "version"}`, or throws on an invalid rule set. |
| `analyze(input, format, map, rules_json)` | `{"analysis", "warnings", "redacted", "cluster_date_tags"}`, and keeps the analysis for `report` and `endpoints`. `format` is `auto`, `ndjson`, `json`, `lines` or `access_log`; `map` is a field mapping such as `ts=a.b,url=c`, or empty. Secrets are redacted before analysis. |
| `unwrap(url, rules_json)` | The layers inside one URL and the rules that fired. |
| `report(opts_json)` | A Markdown draft of the last analysis. `opts_json` takes `audience`, `cluster` (a cluster `id` or `key`), `reporter`, `generated`, `min_named` and `claims`, as the CLI's `report` does. |
| `endpoints(opts_json)` | Flagged activity per target host in the last analysis. `opts_json`: `{"min_tier", "now", "active_days"}`, or empty. |
| `evidence_levels()` | The evidence levels that may name a developer, weakest first, and the default. |
| `check_claims(claims_json)` | The claims re-serialised after validation. |
| `eval_labelled(rules_json, set)` | The eval report on the labelled NDJSON `set` (the site serves `samples/eval/*.ndjson` joined), every labelled record's tier, and the records misclassified. |
| `verify_bundle(records_ndjson, analysis_json, stamp_json, rules_json)` | Re-runs an evidence bundle's analysis and compares it, and the bundle's own `analysis.json`, with its stamp, as `swarmchase case verify` does. The page checks the manifest hashes itself with Web Crypto. |
| `defang(text)` | The text with URLs defanged. |
| `parse_security_txt(text)` | The parsed `security.txt` fields. |

Clusters in an analysis carry a number (`id`, `C1`) and a stable `key` (`k-3f9a2c1b`); its records may carry `ts_kind` and `target_asn` (see [`sc-core`](../sc-core/README.md#concepts)).

## Site safety

The pages build their DOM with `textContent` and never `innerHTML`, under a strict Content Security Policy, and defang every URL they show. Records are hostile input. `scripts/site-xss-check.mjs` and `scripts/ci/check-site.py` check this in CI.

## Tests

```sh
cargo test -p sc-wasm
```

The tests run natively; the functions are plain Rust behind `#[wasm_bindgen]`.
