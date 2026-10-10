#!/usr/bin/env bash
# Detection regression gate: run `swarmchase eval` on the committed evaluation
# set and fail if precision or recall drops below the floors below.
#
# The floors are a ratchet. Raise them when a rules change improves the
# numbers; never lower one to land a change - fix the rule, or argue the label
# in samples/eval/ instead. Precision floors stay at 90%:
# with no embargo, a false positive is published as soon as it is acted on.
#
# This set was used to tune the rules, so it is a regression floor, not an
# estimate of real-world precision. That comes from the held-out Transluce
# data (see samples/eval/README.md).
#
# Usage:
#     scripts/ci/eval-gate.sh [extra cargo args, e.g. --profile release-test]

set -euo pipefail
cd "$(dirname "$0")/../.."

cargo run --quiet "$@" -p swarmchase -- eval samples/eval/*.ndjson \
    --show-fp 50 \
    --min-significant-precision 0.90 \
    --min-suggestive-precision 0.90 \
    --min-suggestive-recall 0.87 \
    --min-significant-recall 0.36
