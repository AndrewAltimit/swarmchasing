#!/usr/bin/env bash
# Build the public site into _site/: the WASM modules, then every page.
#
#     scripts/ci/build-site.sh               # release module, optimised with wasm-opt
#     scripts/ci/build-site.sh --dev         # debug module, no wasm-opt, no size check
#     scripts/ci/build-site.sh --pages-only  # pages only; reuse site/pkg as built
#
# Environment:
#     SITE_OUT                output directory (default _site)
#     SITE_BASE_URL           the site's public URL, for the feed and the sitemap
#                             (default http://localhost:8080/)
#     WASM_OPT                path to a wasm-opt binary
#     SWARMCHASE_WASM_OPT_CACHE  wasm-opt cache directory
#                             (default ${XDG_CACHE_HOME:-$HOME/.cache}/swarmchase-wasm-opt)
#
# The modules: wasm-pack builds sc-wasm (the analysis engine) into site/pkg
# and sc-rules-wasm (rules TOML to JSON, loaded only for edited rules) into
# site/pkg-rules, both gitignored, on the release profile with size settings
# (opt-level "z", one codegen unit, panic=abort) passed as
# CARGO_PROFILE_RELEASE_* variables, so they apply to these builds only and
# never to native binaries. A release engine over BUDGET bytes fails the
# build.
#
# wasm-opt is the slow half of a release build (minutes on the runner, against
# seconds for the cargo build when the cache is warm), and its output depends
# only on its input module, its flags and its version. So wasm-pack builds
# with --no-opt and this script runs wasm-opt itself, caching the optimised
# module outside the checkout (actions/checkout cleans the workspace) under
# the SHA-256 of the unoptimised module, the flags and the wasm-opt version.
# The flags are read from `[package.metadata.wasm-pack.profile.release]
# wasm-opt = [...]` in crates/sc-wasm/Cargo.toml, the list wasm-pack would
# pass. wasm-opt is taken from $WASM_OPT, else PATH, else wasm-pack's own
# cache; with none found, wasm-pack optimises (uncached) and downloads it.
#
# The pages: the sc-site binary (crates/sc-publish) reads committed inputs
# only (notices/, docs/, rules/default.toml, samples/eval/, site/), refuses
# anything under data/ or $SWARMCHASE_DATA, and writes the site. Then
# check-site.py checks every generated page and that every input it read is
# tracked by git.
set -euo pipefail
cd "$(dirname "$0")/../.."

mode=--release
case "${1:-}" in
    --dev) mode=--dev ;;
    --pages-only) mode=pages ;;
    "") ;;
    *) echo "usage: $0 [--dev|--pages-only]" >&2; exit 2 ;;
esac

WASM=site/pkg/sc_wasm_bg.wasm
OUT="${SITE_OUT:-_site}"
BASE_URL="${SITE_BASE_URL:-http://localhost:8080/}"
CACHE="${SWARMCHASE_WASM_OPT_CACHE:-${XDG_CACHE_HOME:-$HOME/.cache}/swarmchase-wasm-opt}"
KEEP=20                 # cached modules kept; older ones are pruned
BUDGET=$((1536 * 1024)) # bytes: the module every analysis page downloads

python_bin() {
    local p
    for p in python3 python; do
        if command -v "$p" >/dev/null 2>&1 && "$p" -c "" >/dev/null 2>&1; then
            echo "$p"
            return
        fi
    done
    echo "[build-site] no python found" >&2
    return 1
}

# pack <crate> <out dir under site/> [wasm-pack flags]
pack() {
    local crate=$1 out=$2
    shift 2
    command -v wasm-pack >/dev/null || cargo install wasm-pack --locked
    CARGO_PROFILE_RELEASE_OPT_LEVEL=z \
    CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1 \
    CARGO_PROFILE_RELEASE_PANIC=abort \
        wasm-pack build "crates/$crate" --target web --out-dir "../../site/$out" --no-typescript "$@"
    rm -f "site/$out/.gitignore" "site/$out/package.json" "site/$out/README.md"
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
    }' "crates/$1/Cargo.toml" | tr ',' '\n' | sed -E 's/^[[:space:]]*"//; s/"[[:space:]]*$//' | sed '/^$/d'
}

sha256() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum | awk '{print $1}'
    else
        shasum -a 256 | awk '{print $1}'
    fi
}

# build_release_module <crate> <out dir under site/> <module file> <budget bytes or 0>
build_release_module() {
    local crate=$1 out=$2 WASM=$3 budget=$4
    local -a FLAGS
    mapfile -t FLAGS < <(opt_flags "$crate")
    local OPT
    OPT="$(find_wasm_opt || true)"
    if [[ ${#FLAGS[@]} -eq 0 ]]; then
        echo "[build-site] wasm-opt disabled in crates/$crate/Cargo.toml; building unoptimised"
        pack "$crate" "$out" --release --no-opt
    elif [[ -z "$OPT" ]]; then
        echo "[build-site] wasm-opt not found; letting wasm-pack optimise (uncached, downloads wasm-opt for next time)"
        pack "$crate" "$out" --release
    else
        pack "$crate" "$out" --release --no-opt
        local version key hit start
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
    local size
    size=$(wc -c <"$WASM" | tr -d ' ')
    echo "[build-site] $WASM: $size bytes ($((size / 1024)) KiB)"
    if ((budget > 0 && size > budget)); then
        echo "[build-site] $WASM is over its size budget of $((budget / 1024)) KiB; trim it before deploying" >&2
        exit 1
    fi
}

case "$mode" in
    --release)
        build_release_module sc-wasm pkg site/pkg/sc_wasm_bg.wasm "$BUDGET"
        build_release_module sc-rules-wasm pkg-rules site/pkg-rules/sc_rules_wasm_bg.wasm 0
        ;;
    --dev)
        pack sc-wasm pkg --dev
        pack sc-rules-wasm pkg-rules --dev
        ;;
    pages) [[ -s "$WASM" ]] || echo "[build-site] warning: $WASM missing; the analysis pages will not load" ;;
esac

LOG="$(mktemp)"
trap 'rm -f "$LOG"' EXIT
cargo run -q --profile release-test -p sc-publish --bin sc-site -- \
    --out "$OUT" --base-url "$BASE_URL" --inputs-log "$LOG"
"$(python_bin)" scripts/ci/check-site.py --built "$OUT" --inputs "$LOG"
echo "site ready: serve ./$OUT (e.g. python -m http.server -d $OUT 8080)"
