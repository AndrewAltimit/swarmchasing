#!/usr/bin/env bash
# Detection regression gate: run `swarmchase eval` on the committed evaluation
# set and fail if precision or recall drops below the floors below.
#
# The floors are a ratchet. Raise them when a rules change improves the
# numbers; never lower one to land a change - fix the rule, or argue the label
# in samples/eval/ instead. Precision floors stay at 90%:
# with no embargo, a false positive is published within a day of being acted on.
#
# The `-lower` floors apply to the lower end of the 95% Wilson interval for
# precision, so a precision of 100% on a handful of records does not pass
# for more than it shows. They were set at the lower bounds the set gave
# when they were added, rounded down, and ratchet like the others.
#
# Coverage: every rule needs at least one agent-labelled record it fires on,
# unless samples/eval/coverage-allow.txt lists it with a reason.
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
    --min-significant-recall 0.36 \
    --min-significant-precision-lower 0.88 \
    --min-suggestive-precision-lower 0.94 \
    --coverage-allow samples/eval/coverage-allow.txt \
    --require-coverage
