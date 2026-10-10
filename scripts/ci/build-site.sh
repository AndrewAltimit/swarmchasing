#!/usr/bin/env bash
# Build the WASM package into site/pkg.
#
#     scripts/ci/build-site.sh          # release build, optimised with wasm-opt
#     scripts/ci/build-site.sh --dev    # debug build, no wasm-opt
#
# wasm-opt is the slow half of a release build (minutes on the runner, against
# seconds for the cargo build when the cache is warm), and its output depends
# only on its input module, its flags and its version. So wasm-pack builds
# with --no-opt and this script runs wasm-opt itself, caching the optimised
# module outside the checkout (actions/checkout cleans the workspace) under
# the SHA-256 of the unoptimised module, the flags and the wasm-opt version.
# A deploy that did not change the Rust reuses the cached module.
#
# The flags are read from `[package.metadata.wasm-pack.profile.release]
# wasm-opt = [...]` in crates/sc-wasm/Cargo.toml, the same list wasm-pack
# would pass, so the manifest stays the one place they are set.
#
# wasm-opt is taken from $WASM_OPT, else PATH, else the copy wasm-pack keeps
# in its own cache. When none is found (a fresh machine), the script lets
# wasm-pack optimise the module itself, uncached; that run downloads wasm-opt
# into wasm-pack's cache, so the next run finds it.
#
# Environment:
#     WASM_OPT                path to a wasm-opt binary
#     SWARMCHASE_WASM_OPT_CACHE  cache directory
#                             (default ${XDG_CACHE_HOME:-$HOME/.cache}/swarmchase-wasm-opt)
set -euo pipefail
cd "$(dirname "$0")/../.."

mode=--release
[[ "${1:-}" == "--dev" ]] && mode=--dev
command -v wasm-pack >/dev/null || cargo install wasm-pack --locked

PKG=site/pkg
WASM="$PKG/sc_wasm_bg.wasm"
CACHE="${SWARMCHASE_WASM_OPT_CACHE:-${XDG_CACHE_HOME:-$HOME/.cache}/swarmchase-wasm-opt}"
KEEP=20   # cached modules kept; older ones are pruned

pack() {
    wasm-pack build crates/sc-wasm --target web --out-dir ../../site/pkg --no-typescript "$@"
    rm -f "$PKG/.gitignore" "$PKG/package.json" "$PKG/README.md"
}

find_wasm_opt() {
    if [[ -n "${WASM_OPT:-}" && -x "$WASM_OPT" ]]; then
        echo "$WASM_OPT"
        return
    fi
    if command -v wasm-opt >/dev/null 2>&1; then
        command -v wasm-opt
        return
    fi
    # wasm-pack's download cache: dirs::cache_dir()/.wasm-pack/wasm-opt-<hash>/bin.
    local c
    for c in "${XDG_CACHE_HOME:-$HOME/.cache}"/.wasm-pack/wasm-opt-*/bin/wasm-opt \
             "$HOME/Library/Caches"/.wasm-pack/wasm-opt-*/bin/wasm-opt \
             "${LOCALAPPDATA:-/nonexistent}"/.wasm-pack/wasm-opt-*/bin/wasm-opt.exe; do
        if [[ -x "$c" ]]; then
            echo "$c"
            return
        fi
    done
}

# The flags wasm-pack would pass: the quoted items of the release profile's
# `wasm-opt = [...]` line. Empty when the manifest disables wasm-opt.
opt_flags() {
    sed -n '/^\[package\.metadata\.wasm-pack\.profile\.release\]/,/^\[/{
        s/^wasm-opt[[:space:]]*=[[:space:]]*\[\(.*\)\].*/\1/p
    }' crates/sc-wasm/Cargo.toml | tr ',' '\n' | sed -E 's/^[[:space:]]*"//; s/"[[:space:]]*$//' | sed '/^$/d'
}

sha256() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum | awk '{print $1}'
    else
        shasum -a 256 | awk '{print $1}'
    fi
}

if [[ "$mode" == --dev ]]; then
    pack --dev
    echo "site ready (dev build): serve ./site (e.g. python -m http.server -d site 8080)"
    exit 0
fi

mapfile -t FLAGS < <(opt_flags)
OPT="$(find_wasm_opt || true)"

if [[ ${#FLAGS[@]} -eq 0 ]]; then
    echo "[build-site] wasm-opt disabled in crates/sc-wasm/Cargo.toml; building unoptimised"
    pack --release --no-opt
elif [[ -z "$OPT" ]]; then
    echo "[build-site] wasm-opt not found; letting wasm-pack optimise (uncached, downloads wasm-opt for next time)"
    pack --release
else
    pack --release --no-opt
    version="$("$OPT" --version | head -n1)"
    key="$({ sha256 <"$WASM"; printf '%s\n' "${FLAGS[@]}" "$version"; } | sha256)"
    mkdir -p "$CACHE"
    hit="$CACHE/$key.wasm"
    if [[ -s "$hit" ]]; then
        echo "[build-site] wasm-opt cache hit ($key)"
        cp "$hit" "$WASM"
        touch "$hit"
    else
        echo "[build-site] wasm-opt ${FLAGS[*]} ($version); cache miss ($key)"
        start=$SECONDS
        "$OPT" "$WASM" -o "$WASM.opt" "${FLAGS[@]}"
        mv "$WASM.opt" "$WASM"
        # Write then rename, so an interrupted copy never becomes a cache hit.
        cp "$WASM" "$hit.tmp.$$"
        mv "$hit.tmp.$$" "$hit"
        echo "[build-site] wasm-opt took $((SECONDS - start))s"
    fi
    # Keep the newest $KEEP modules (a hit refreshes its mtime).
    ls -1t "$CACHE"/*.wasm 2>/dev/null | tail -n +$((KEEP + 1)) | while IFS= read -r old; do
        rm -f -- "$old"
    done
fi

size=$(wc -c <"$WASM" | tr -d ' ')
echo "[build-site] $WASM: $size bytes ($((size / 1024)) KiB; advisory target < 1536 KiB)"
echo "site ready: serve ./site (e.g. python -m http.server -d site 8080)"
