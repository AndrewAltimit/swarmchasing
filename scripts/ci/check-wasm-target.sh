#!/usr/bin/env bash
# Type-check the wasm32 target - the half of the browser toolkit no native
# gate compiles.
#
# `#[cfg(target_arch = "wasm32")]` code, and anything that only breaks when a
# dependency's wasm feature set is selected, is invisible to `cargo clippy
# --all-targets --workspace` and `cargo test`, which build for the host. This
# is a type-check, not a wasm-pack build, so it costs about one `cargo check`.
#
# Usage:
#     scripts/ci/check-wasm-target.sh          # sc-wasm (both modules), sc-rules-wasm, sc-case
#     scripts/ci/check-wasm-target.sh -p foo   # any other package
#
# Exits 0 with a SKIPPED notice when the wasm32 target is not installed and
# cannot be added, so a clone without it is not blocked from committing.

set -euo pipefail

cd "$(dirname "$0")/../.."

PKG_ARGS=("$@")
if [[ ${#PKG_ARGS[@]} -eq 0 ]]; then
    PKG_ARGS=(-p sc-wasm -p sc-rules-wasm -p sc-case)
fi

if ! rustup target list --installed 2>/dev/null | grep -q wasm32-unknown-unknown; then
    echo "[check-wasm-target] wasm32-unknown-unknown not installed; adding..."
    if ! rustup target add wasm32-unknown-unknown; then
        echo "[check-wasm-target] SKIPPED - could not add the wasm32 target." >&2
        echo "[check-wasm-target] This is a vacuous pass: nothing type-checked the browser toolkit." >&2
        exit 0
    fi
fi

echo "[check-wasm-target] cargo check --release --target wasm32-unknown-unknown ${PKG_ARGS[*]}"
cargo check --release --target wasm32-unknown-unknown "${PKG_ARGS[@]}"
if [[ $# -eq 0 ]]; then
    # sc-wasm's on-demand tools module is the same crate under another feature.
    echo "[check-wasm-target] cargo check --release --target wasm32-unknown-unknown -p sc-wasm --no-default-features --features tools"
    cargo check --release --target wasm32-unknown-unknown -p sc-wasm --no-default-features --features tools
fi
echo "[check-wasm-target] OK"
