# sc-rules-wasm

Rules files (TOML) to the JSON the [`sc-wasm`](../sc-wasm/README.md) analysis module reads. Taking rules as JSON keeps a TOML parser out of the module every analysis page downloads; the site loads this one only when a visitor has edited rules to convert.

## API

| Function | Returns |
|---|---|
| `rules_json(toml_text)` | The rules file as JSON, or throws with the TOML parse error. |

The conversion is structural: a TOML value becomes the same JSON value, and `sc-wasm` reads the rule set from it as `Rules::from_toml` reads the TOML. The tests check that on the bundled rules.

## Build and tests

`scripts/ci/build-site.sh` builds it into `site/pkg-rules`.

```sh
cargo test -p sc-rules-wasm
```
