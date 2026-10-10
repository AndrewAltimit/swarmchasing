#!/usr/bin/env bash
# Point CARGO_TARGET_DIR at a per-toolchain subdirectory of a persistent cargo
# cache outside the checkout, and prune every other toolchain's subdirectory.
#
# `actions/checkout` runs `git clean -ffdx`, and `-x` deletes the gitignored
# `target/`, so without this every CI run and every 6-hourly watch run would
# rebuild the whole workspace from cold. Keeping cargo's fingerprints across
# runs means a run rebuilds only what changed.
#
# The cache outlives the toolchain, though: when `stable` moves on the runner,
# the new rustc must not be handed rlibs the old one compiled (E0514 in the
# doctest pass). Keying the directory on the exact compiler makes a toolchain
# bump start cold instead of poisoned, and pruning the other keys stops the
# cache growing by a workspace build per rustc release.
#
# Usage (a workflow step):
#     scripts/ci/select-ci-target-dir.sh
#
# The cache root is $CARGO_TARGET_DIR when set, else
# ~/.cache/swarmchase-ci-target. The chosen directory is appended to
# $GITHUB_ENV so every later step of the job builds into it. Outside Actions
# it only prints the directory.

set -euo pipefail

BASE="${CARGO_TARGET_DIR:-$HOME/.cache/swarmchase-ci-target}"
BASE="${BASE%/}"

# Guard the prune below: it deletes siblings under BASE, so BASE must be the
# dedicated cache and never a checkout's own target/ or a home directory.
case "$(basename "$BASE")" in
    swarmchase-ci-target) ;;
    *)
        echo "select-ci-target-dir: refusing to manage '$BASE'" \
             "(expected a directory named swarmchase-ci-target)" >&2
        exit 1
        ;;
esac

RUSTC_VV="$(rustc -vV)"
RUSTC_V="$(rustc -V)"
RUSTDOC_V="$(rustdoc -V)"
echo "$RUSTC_VV"
echo "$RUSTDOC_V"

# A doctest runs rustdoc against rustc's rlibs, so a split toolchain on PATH
# fails here with both versions named rather than later as E0514.
if [[ "${RUSTC_V#rustc }" != "${RUSTDOC_V#rustdoc }" ]]; then
    echo "select-ci-target-dir: rustc and rustdoc disagree -" \
         "doctests would load rlibs from the wrong compiler" >&2
    exit 1
fi

HASH="$(awk '/^commit-hash:/ {print $2}' <<<"$RUSTC_VV")"
HOST="$(awk '/^host:/ {print $2}' <<<"$RUSTC_VV")"
if [[ -z "$HASH" || "$HASH" == "unknown" ]]; then
    HASH="$(awk '/^release:/ {print $2}' <<<"$RUSTC_VV")"
fi
DIR="$BASE/rustc-${HASH:0:12}-${HOST}"

mkdir -p "$DIR"
shopt -s dotglob nullglob
for entry in "$BASE"/*; do
    if [[ "$entry" != "$DIR" ]]; then
        echo "select-ci-target-dir: pruning stale $(basename "$entry")"
        rm -rf -- "$entry"
    fi
done

echo "select-ci-target-dir: CARGO_TARGET_DIR=$DIR"
if [[ -n "${GITHUB_ENV:-}" ]]; then
    echo "CARGO_TARGET_DIR=$DIR" >>"$GITHUB_ENV"
fi
