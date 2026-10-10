# sc-wasm

WebAssembly bindings for [`sc-core`](../sc-core/README.md), used by the browser toolkit in [`site/`](../../site/index.html) on GitHub Pages. The page runs the same analysis as the CLI entirely in the browser: nothing a user pastes or loads leaves it.

## Build

```sh
scripts/ci/build-site.sh          # release build into site/pkg (installs wasm-pack if missing)
scripts/ci/build-site.sh --dev    # faster, unoptimised
python -m http.server -d site 8080
```

Then open <http://localhost:8080>. The build runs `wasm-pack build --target web`, so the page loads it as an ES module:

```js
import init, * as sc from "./pkg/sc_wasm.js";
await init();
const out = JSON.parse(sc.analyze(text, "auto", "", ""));
```

[`build.rs`](build.rs) embeds every `samples/eval/*.ndjson` file, so the page can score edited rules against the labelled set. Rebuild after changing them.

## API

Everything crosses the boundary as strings: inputs are text or JSON, outputs are JSON (or Markdown), so the page needs nothing but `JSON.parse`. Functions that can fail throw a JS `Error` with the message. Wherever a function takes `rules_toml`, an empty string means the bundled rules.

| Function | Returns |
|---|---|
| `version()` | The toolkit version. |
| `default_rules()` | The bundled `rules/default.toml` text. |
| `check_rules(rules_toml)` | `{"rules", "asns", "version"}`, or throws on an invalid file. |
| `analyze(input, format, map, rules_toml)` | `{"analysis", "warnings", "redacted", "cluster_date_tags"}`. `format` is `auto`, `ndjson`, `json`, `lines` or `access_log`; `map` is a field mapping such as `ts=a.b,url=c`, or empty. Secrets are redacted before analysis. |
| `unwrap(url, rules_toml)` | The layers inside one URL and the rules that fired. |
| `report(analysis_json, opts_json)` | A Markdown draft. `opts_json` takes `audience`, `cluster` (a cluster `id` or `key`), `reporter`, `generated`, `min_named` and `claims`, as the CLI's `report` does. |
| `endpoints(analysis_json, opts_json)` | Flagged activity per target host. `opts_json`: `{"min_tier", "now", "active_days"}`, or empty. |
| `evidence_levels()` | The evidence levels that may name a developer, weakest first, and the default. |
| `check_claims(claims_json)` | The claims re-serialised after validation. |
| `eval_labelled(rules_toml)` | Precision and recall on the embedded labelled set, every record's tier, and the records misclassified. |
| `example_records()` | Synthetic example records as NDJSON, labels removed. They were written to exercise the rules, never collected. |
| `verify_bundle(records_ndjson, analysis_json, stamp_json, rules_toml)` | Re-runs an evidence bundle's analysis and compares it, and the bundle's own `analysis.json`, with its stamp, as `swarmchase case verify` does. The page checks the manifest hashes itself with Web Crypto. |
| `defang(text)` | The text with URLs defanged. |
| `parse_security_txt(text)` | The parsed `security.txt` fields. |

`analysis_json` is the `analysis` field of `analyze`'s result.

## Site safety

The page builds its DOM with `textContent` and never `innerHTML`, under a strict Content Security Policy, and defangs every URL it shows. Records are hostile input. `scripts/site-xss-check.mjs` and `scripts/ci/check-site.py` check this in CI.

## Tests

```sh
cargo test -p sc-wasm
```

The tests run natively; the functions are plain Rust behind `#[wasm_bindgen]`.
