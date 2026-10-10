#!/usr/bin/env bash
# Build the WASM package into site/pkg. Usage: scripts/ci/build-site.sh [--dev]
set -euo pipefail
cd "$(dirname "$0")/../.."
mode=--release
[[ "${1:-}" == "--dev" ]] && mode=--dev
command -v wasm-pack >/dev/null || cargo install wasm-pack --locked
wasm-pack build crates/sc-wasm --target web --out-dir ../../site/pkg --no-typescript "$mode"
rm -f site/pkg/.gitignore site/pkg/package.json site/pkg/README.md
echo "site ready: serve ./site (e.g. python -m http.server -d site 8080)"
