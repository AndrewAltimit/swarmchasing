#!/usr/bin/env bash
# Supply-chain gate: cargo-deny against deny.toml (RustSec advisories,
# permissive licenses only, crates.io as the only source, no wildcard
# versions).
#
# Installs the pinned cargo-deny with `cargo install --locked` when it is
# missing or a different version. On the self-hosted runner it stays in
# ~/.cargo/bin, so only the first run and a pin bump pay for the build.
#
# Usage:
#     scripts/ci/deny.sh                 # cargo deny check (every section)
#     scripts/ci/deny.sh advisories      # one section
#
# Fetches the RustSec advisory database (github.com/rustsec/advisory-db).

set -euo pipefail

cd "$(dirname "$0")/../.."

CARGO_DENY_VERSION=0.20.2

have="$(cargo deny --version 2>/dev/null | awk '{print $2}' || true)"
if [[ "$have" != "$CARGO_DENY_VERSION" ]]; then
    echo "[deny] installing cargo-deny $CARGO_DENY_VERSION (found: ${have:-none})"
    cargo install cargo-deny --locked --version "$CARGO_DENY_VERSION"
fi

echo "[deny] cargo deny check $*"
cargo deny check "$@"
