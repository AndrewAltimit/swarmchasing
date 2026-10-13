#!/usr/bin/env bash
# Is the newest watch run recent? Reads <data>/LATEST (the stamp of the most
# recent run, YYYYMMDDTHHMMSSZ) and compares it with the clock.
#
#     scripts/ci/check-watch-age.sh [max-hours]    # default 12
#
# The data directory is $SWARMCHASE_DATA, else ~/swarmchase-data (the
# runner's default). Prints one line: the newest run's stamp and age. Exits
# 0 when it is at most max-hours old, 1 when it is older or there is no run,
# 2 on a usage error. Reads nothing but LATEST, so the line is safe for a
# public log: it says when the watch last finished, never what it found.
set -euo pipefail

max_hours="${1:-12}"
if ! [[ "$max_hours" =~ ^[0-9]+$ ]]; then
    echo "usage: $0 [max-hours]" >&2
    exit 2
fi
data="${SWARMCHASE_DATA:-$HOME/swarmchase-data}"
latest="$data/LATEST"

if [[ ! -s "$latest" ]]; then
    echo "no watch run recorded ($latest is missing or empty)"
    exit 1
fi
stamp="$(tr -d '[:space:]' <"$latest")"
if ! [[ "$stamp" =~ ^([0-9]{8})T([0-9]{2})([0-9]{2})([0-9]{2})Z$ ]]; then
    echo "LATEST holds no run stamp: ${stamp:0:40}"
    exit 1
fi
then_s="$(date -u -d "${BASH_REMATCH[1]} ${BASH_REMATCH[2]}:${BASH_REMATCH[3]}:${BASH_REMATCH[4]}" +%s)"
now_s="$(date -u +%s)"
age_h=$(((now_s - then_s) / 3600))
echo "newest watch run $stamp, ${age_h} h old (limit ${max_hours} h)"
((now_s - then_s <= max_hours * 3600))
