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
#     SWARMCHASE_CANARY_SEED  set: embed canary tokens; unset: none
#                             (docs/reference/configuration.md#canary-tokens)
#     SITE_IDENTITY_SNAPSHOT  a directory `swarmchase identity refresh` wrote
#                             (<data>/identity): the identity page embeds its
#                             providers' files with their fetch dates; unset,
#                             the page has the catalog only
#     WASM_OPT                path to a wasm-opt binary
#     SWARMCHASE_WASM_OPT_CACHE  wasm-opt cache directory
#                             (default ${XDG_CACHE_HOME:-$HOME/.cache}/swarmchase-wasm-opt)
#
# The modules, all gitignored, each with its own size budget:
#
#     site/pkg/sc_wasm_bg.wasm          sc-wasm, feature engine: the analysis
#                                       engine every analysis page loads
#     site/pkg/tools/sc_tools_bg.wasm   sc-wasm, feature tools: report drafts,
#                                       the bundle check and the labelled
#                                       eval, loaded only on demand
#     site/pkg-rules/sc_rules_wasm_bg.wasm  sc-rules-wasm: rules TOML to JSON,
#                                       loaded only for edited rules
#
# wasm-pack builds them on the release profile with size settings
# (opt-level "z", one codegen unit, panic=abort) passed as
# CARGO_PROFILE_RELEASE_* variables, so they apply to these builds only and
# never to native binaries. A release module over its budget fails the
# build; the sizes and the headroom under each budget are printed at the end.
#
# wasm-opt is the slow half of a release build (minutes on the runner, against
# seconds for the cargo build when the cache is warm), and its output depends
# only on its input module, its flags and its version. So wasm-pack builds
# with --no-opt and this script runs wasm-opt itself, caching the optimised
# module outside the checkout (actions/checkout cleans the workspace) under
# the SHA-256 of the unoptimised module, the flags and the wasm-opt version.
# The modules are built one after another, then optimised in parallel, one
# background wasm-opt per module; the build fails if any of them fails. The
# wasm-pack builds stay serial: the engine and the tools module are the same
# crate with different features, so cargo writes both to the same artifact
# path, and a second build running beside the first could hand wasm-bindgen
# the other module.
# The flags are read from `[package.metadata.wasm-pack.profile.release]
# wasm-opt = [...]` in crates/sc-wasm/Cargo.toml, the list wasm-pack would
# pass. wasm-opt is taken from $WASM_OPT, else PATH, else wasm-pack's own
# cache; with none found, wasm-pack optimises (uncached) and downloads it.
#
# The pages: the sc-site binary (crates/sc-publish) reads committed inputs
# only (notices/, docs/, rules/default.toml, samples/eval/, samples/showcase/,
# site/), refuses anything under data/ or $SWARMCHASE_DATA, and writes the
# site, including the synthetic showcase bundle the tools page checks
# (assets/showcase-bundle/, made from samples/showcase/ as `case bundle`
# makes one). The loading messages quote each module's gzip size, so build
# the modules before the pages. Then check-site.py checks every generated
# page and that every input it read is tracked by git.
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
# Budgets in bytes. The engine's is the one that matters most: every
# analysis page downloads it on arrival.
ENGINE_BUDGET=$((1536 * 1024))
TOOLS_BUDGET=$((1856 * 1024)) # loaded on demand, never on arrival
RULES_BUDGET=$((512 * 1024))
SIZES=()                # "<module> <bytes> <budget>" per release module built
BUILT=()                # "<module> <budget>" per release module built
OPT_QUEUE=()            # "<module> <crate>" per module wasm-opt is still to run on
OPT=""                  # the wasm-opt binary, when one is found

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

# pack <crate> <out dir under site/> <out name> <cargo features> [wasm-pack flags]
# Features empty means the crate's defaults. wasm-pack resolves --out-dir
# against the crate directory.
pack() {
    local crate=$1 out=$2 name=$3 features=$4
    shift 4
    local -a cargo_args=()
    if [[ -n "$features" ]]; then
        cargo_args=(-- --no-default-features --features "$features")
    fi
    command -v wasm-pack >/dev/null || cargo install wasm-pack --locked
    CARGO_PROFILE_RELEASE_OPT_LEVEL=z \
    CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1 \
    CARGO_PROFILE_RELEASE_PANIC=abort \
        wasm-pack build "crates/$crate" --target web --out-dir "../../site/$out" --out-name "$name" \
        --no-typescript "$@" "${cargo_args[@]}"
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

# pack_release <crate> <out dir under site/> <out name> <cargo features> <budget bytes>
# Builds one release module. When wasm-opt is ours to run, the module is
# queued in OPT_QUEUE for optimise_queued; otherwise wasm-pack has done all
# there is to do. Every module is queued in BUILT for check_sizes.
pack_release() {
    local crate=$1 out=$2 name=$3 features=$4 budget=$5
    local wasm="site/$out/${name}_bg.wasm"
    local -a flags
    mapfile -t flags < <(opt_flags "$crate")
    if [[ ${#flags[@]} -eq 0 ]]; then
        echo "[build-site] wasm-opt disabled in crates/$crate/Cargo.toml; building unoptimised"
        pack "$crate" "$out" "$name" "$features" --release --no-opt
    elif [[ -z "$OPT" ]]; then
        echo "[build-site] wasm-opt not found; letting wasm-pack optimise (uncached, downloads wasm-opt for next time)"
        pack "$crate" "$out" "$name" "$features" --release
    else
        pack "$crate" "$out" "$name" "$features" --release --no-opt
        OPT_QUEUE+=("$wasm $crate")
    fi
    BUILT+=("$wasm $budget")
}

# optimise <module> <crate>: wasm-opt one module in place, through the cache.
# Runs as a background job beside the other modules' passes.
optimise() {
    local wasm=$1 crate=$2
    local -a flags
    mapfile -t flags < <(opt_flags "$crate")
    local version key hit start
    version="$("$OPT" --version | head -n1)"
    key="$({ sha256 <"$wasm"; printf '%s\n' "${flags[@]}" "$version"; } | sha256)"
    hit="$CACHE/$key.wasm"
    if [[ -s "$hit" ]]; then
        echo "[build-site] $wasm: wasm-opt cache hit ($key)"
        cp "$hit" "$wasm"
        touch "$hit"
        return
    fi
    echo "[build-site] $wasm: wasm-opt ${flags[*]} ($version); cache miss ($key)"
    start=$SECONDS
    "$OPT" "$wasm" -o "$wasm.opt" "${flags[@]}"
    mv "$wasm.opt" "$wasm"
    # Write then rename, so an interrupted copy never becomes a cache hit.
    cp "$wasm" "$hit.tmp.$BASHPID"
    mv "$hit.tmp.$BASHPID" "$hit"
    echo "[build-site] $wasm: wasm-opt took $((SECONDS - start))s"
}

# Run optimise for every queued module at once, print each one's output
# when it is done, and fail if any failed.
optimise_queued() {
    ((${#OPT_QUEUE[@]})) || return 0
    mkdir -p "$CACHE"
    local logs line wasm crate i failed=0
    logs="$(mktemp -d)"
    local -a pids=()
    for i in "${!OPT_QUEUE[@]}"; do
        read -r wasm crate <<<"${OPT_QUEUE[$i]}"
        optimise "$wasm" "$crate" >"$logs/$i.log" 2>&1 &
        pids+=($!)
    done
    for i in "${!pids[@]}"; do
        if ! wait "${pids[$i]}"; then
            failed=1
            read -r wasm crate <<<"${OPT_QUEUE[$i]}"
            echo "[build-site] wasm-opt failed for $wasm" >&2
        fi
        cat "$logs/$i.log"
    done
    rm -rf "$logs"
    if ((failed)); then
        exit 1
    fi
    # Keep the newest $KEEP modules (a hit refreshes its mtime).
    ls -1t "$CACHE"/*.wasm 2>/dev/null | tail -n +$((KEEP + 1)) | while IFS= read -r line; do
        rm -f -- "$line"
    done
}

# Each built module's size, against its budget.
check_sizes() {
    local line wasm budget size over=0
    for line in "${BUILT[@]}"; do
        read -r wasm budget <<<"$line"
        size=$(wc -c <"$wasm" | tr -d ' ')
        echo "[build-site] $wasm: $size bytes ($((size / 1024)) KiB)"
        SIZES+=("$wasm $size $budget")
        if ((size > budget)); then
            echo "[build-site] $wasm is over its size budget of $((budget / 1024)) KiB; trim it before deploying" >&2
            over=1
        fi
    done
    if ((over)); then
        exit 1
    fi
}

report_sizes() {
    local line f size budget
    echo "[build-site] module sizes in bytes (size / budget, headroom):"
    for line in "${SIZES[@]}"; do
        read -r f size budget <<<"$line"
        printf '[build-site]   %-40s %9d / %9d  %+9d\n' "$f" "$size" "$budget" "$((budget - size))"
    done
}

case "$mode" in
    --release)
        OPT="$(find_wasm_opt || true)"
        # The engine first: the tools module goes in a directory under its
        # output.
        pack_release sc-wasm pkg sc_wasm "" "$ENGINE_BUDGET"
        pack_release sc-wasm pkg/tools sc_tools tools "$TOOLS_BUDGET"
        pack_release sc-rules-wasm pkg-rules sc_rules_wasm "" "$RULES_BUDGET"
        optimise_queued
        check_sizes
        report_sizes
        ;;
    --dev)
        pack sc-wasm pkg sc_wasm "" --dev
        pack sc-wasm pkg/tools sc_tools tools --dev
        pack sc-rules-wasm pkg-rules sc_rules_wasm "" --dev
        ;;
    pages) [[ -s "$WASM" ]] || echo "[build-site] warning: $WASM missing; the analysis pages will not load" ;;
esac

LOG="$(mktemp)"
trap 'rm -f "$LOG"' EXIT
SNAPSHOT=()
if [[ -n "${SITE_IDENTITY_SNAPSHOT:-}" ]]; then
    SNAPSHOT=(--identity-snapshot "$SITE_IDENTITY_SNAPSHOT")
fi
cargo run -q --profile release-test -p sc-publish --bin sc-site -- \
    --out "$OUT" --base-url "$BASE_URL" --inputs-log "$LOG" "${SNAPSHOT[@]}"
"$(python_bin)" scripts/ci/check-site.py --built "$OUT" --inputs "$LOG"
echo "site ready: serve ./$OUT (e.g. python -m http.server -d $OUT 8080)"
