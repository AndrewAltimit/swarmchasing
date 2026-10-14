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
# Cluster floors: recall counted per cluster (a cluster, or an unclustered
# record, counts once), over every record and over the non-synthetic ones,
# and B-cubed F1 of clusters against labelled runs. They were set at the
# values the set gave when they were added, rounded down.
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
# to fire). The same pass runs the calibration check (`--calibrate-check`, as
# `swarmchase sim calibrate --check` does, on the records it generated): every
# soft-link ratio in the bundled rules at or below the lower bound of that
# kind's ratio stratified by scenario, where the simulation measures it, and
# every ratio above 1 that no scenario measures named, with a reason, in the
# scenario file's `calibration.unmeasured`. The simulator is
# seeded, so the numbers only move when the analysis, the rules, the generator
# or the scenarios do. Floors only
# go up and ceilings only go down, as above; a new scenario that lowers a
# pooled number is argued in its commit, never landed by moving a bound.
#
# Usage:
#     scripts/ci/eval-gate.sh [extra cargo args, e.g. --profile release-test]
#
# Exit status: 0 when everything passes, 3 when a floor, ceiling or bound is
# not met (`eval` and `sim bench` exit 3 then), 1 on any other error.

set -euo pipefail
cd "$(dirname "$0")/../.."

cargo run --quiet "$@" -p swarmchase -- eval samples/eval/*.ndjson \
    --show-fp 50 \
    --min-significant-precision 0.90 \
    --min-suggestive-precision 0.90 \
    --min-suggestive-recall 0.97 \
    --min-significant-recall 0.53 \
    --min-significant-precision-lower 0.96 \
    --min-suggestive-precision-lower 0.98 \
    --min-nonsynthetic-significant-precision 0.90 \
    --min-nonsynthetic-suggestive-precision 0.90 \
    --min-nonsynthetic-suggestive-recall 0.85 \
    --min-nonsynthetic-significant-recall 0.41 \
    --min-nonsynthetic-significant-precision-lower 0.78 \
    --min-nonsynthetic-suggestive-precision-lower 0.88 \
    --min-cluster-suggestive-recall 0.95 \
    --min-cluster-significant-recall 0.52 \
    --min-nonsynthetic-cluster-suggestive-recall 0.84 \
    --min-nonsynthetic-cluster-significant-recall 0.46 \
    --min-bcubed-f1 0.90 \
    --coverage-allow samples/eval/coverage-allow.txt \
    --require-coverage

cargo run --quiet "$@" -p swarmchase -- eval check-results samples/eval/results

cargo run --quiet "$@" -p swarmchase -- sim bench samples/sim/scenarios.toml \
    --total \
    --min-edge-precision 0.90 \
    --min-link-precision 0.29 \
    --min-fleet-precision 0.93 \
    --max-null-edges 0 \
    --max-null-links 8 \
    --max-null-fleet-pairs 2 \
    --min-link-cross-run-precision 0.27 \
    --min-fleet-cross-run-precision 0.92 \
    --max-benign-high 0 \
    --max-human-high 10 \
    --expect \
    --calibrate-check \
    | sed -n '/^Null scenarios/,$p'
