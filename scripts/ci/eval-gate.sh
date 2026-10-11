#!/usr/bin/env bash
# Detection regression gate: run `swarmchase eval` on the committed evaluation
# set and fail if precision or recall drops below the floors below, then
# check the saved results in samples/eval/results/.
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
# Two sets of floors. The first reads every labelled record. The
# `nonsynthetic` floors read only the records not marked `synthetic`
# (reconstructions of published incidents and their benign look-alikes), so
# hand-written fixtures that every rule catches by construction cannot hold
# a number up on their own. Their recall and lower-bound floors were set at
# the values the set gave when they were added, rounded down.
#
# Coverage: every rule needs at least one agent-labelled record it fires on,
# unless samples/eval/coverage-allow.txt lists it with a reason.
#
# This set was used to tune the rules, so it is a regression floor, not an
# estimate of real-world precision. That comes from held-out data (see
# samples/eval/README.md).
#
# Saved results: every file in samples/eval/results/ must name a rules
# version no newer than the committed rules, have a benign record when it is
# held out or prospective (or say it was saved without one), come from
# committed code and hold no URL (`swarmchase eval check-results`).
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
    --min-nonsynthetic-significant-precision 0.90 \
    --min-nonsynthetic-suggestive-precision 0.90 \
    --min-nonsynthetic-suggestive-recall 0.73 \
    --min-nonsynthetic-significant-recall 0.34 \
    --min-nonsynthetic-significant-precision-lower 0.67 \
    --min-nonsynthetic-suggestive-precision-lower 0.81 \
    --coverage-allow samples/eval/coverage-allow.txt \
    --require-coverage

cargo run --quiet "$@" -p swarmchase -- eval check-results samples/eval/results
