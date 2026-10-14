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
# Simulator: `swarmchase sim bench` on samples/sim/scenarios.toml, with
# floors on interaction-edge, soft-link and candidate-fleet precision summed
# over every scenario (soft links and candidate fleets also between distinct
# runs only, since a split run rejoined counts as right in the first), ceilings
# on the edges, soft links and candidate-fleet pairs the null scenarios (no two
# runs related) draw, ceilings on benign and tool records graded L2 or above
# and on people's records graded L3 or above, and each scenario's `expect`
# table (`--expect`: every kind a scenario is built to produce must draw pairs
# and meet its bounds there, or draw at most `max_pairs` where it is built not
# to fire). Then `swarmchase sim calibrate --check`: every soft-link ratio in
# the bundled rules at or below the lower bound of that kind's ratio
# stratified by scenario, where the simulation measures it. The simulator is
# seeded, so the numbers only move when the analysis, the rules, the generator
# or the scenarios do. Floors only
# go up and ceilings only go down, as above; a new scenario that lowers a
# pooled number is argued in its commit, never landed by moving a bound.
#
# Usage:
#     scripts/ci/eval-gate.sh [extra cargo args, e.g. --profile release-test]

set -euo pipefail
cd "$(dirname "$0")/../.."

cargo run --quiet "$@" -p swarmchase -- eval samples/eval/*.ndjson \
    --show-fp 50 \
    --min-significant-precision 0.90 \
    --min-suggestive-precision 0.90 \
    --min-suggestive-recall 0.96 \
    --min-significant-recall 0.52 \
    --min-significant-precision-lower 0.95 \
    --min-suggestive-precision-lower 0.97 \
    --min-nonsynthetic-significant-precision 0.90 \
    --min-nonsynthetic-suggestive-precision 0.90 \
    --min-nonsynthetic-suggestive-recall 0.84 \
    --min-nonsynthetic-significant-recall 0.40 \
    --min-nonsynthetic-significant-precision-lower 0.78 \
    --min-nonsynthetic-suggestive-precision-lower 0.87 \
    --coverage-allow samples/eval/coverage-allow.txt \
    --require-coverage

cargo run --quiet "$@" -p swarmchase -- eval check-results samples/eval/results

cargo run --quiet "$@" -p swarmchase -- sim bench samples/sim/scenarios.toml \
    --total \
    --min-edge-precision 0.88 \
    --min-link-precision 0.29 \
    --min-fleet-precision 0.90 \
    --max-null-edges 0 \
    --max-null-links 10 \
    --max-null-fleet-pairs 3 \
    --min-link-cross-run-precision 0.27 \
    --min-fleet-cross-run-precision 0.91 \
    --max-benign-high 2429 \
    --max-human-high 10 \
    --expect \
    | sed -n '/^Null scenarios/,$p'

cargo run --quiet "$@" -p swarmchase -- sim calibrate samples/sim/scenarios.toml \
    --check \
    | sed -n '/^ok\|^FAIL/p'
