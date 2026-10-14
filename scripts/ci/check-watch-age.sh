#!/usr/bin/env bash
# Is the newest watch run recent? Reads <data>/LATEST (the stamp of the most
# recent run, YYYYMMDDTHHMMSSZ) and compares it with the clock. With
# LATEST_OK as the file, it reads the newest run in which a source ran and
# not every one failed instead.
#
#     scripts/ci/check-watch-age.sh [max-hours] [LATEST|LATEST_OK]   # default 12 LATEST
#
# The data directory is $SWARMCHASE_DATA, else ~/swarmchase-data (the
# runner's default). Prints one line: the newest run's stamp and age. Exits
# 0 when it is at most max-hours old, 1 when it is older or there is no run,
# 2 on a usage error. Reads nothing but that file, so the line is safe for a
# public log: it says when the watch last finished, never what it found.
set -euo pipefail

max_hours="${1:-12}"
file="${2:-LATEST}"
if ! [[ "$max_hours" =~ ^[0-9]+$ ]] || ! [[ "$file" =~ ^LATEST(_OK)?$ ]]; then
    echo "usage: $0 [max-hours] [LATEST|LATEST_OK]" >&2
    exit 2
fi
data="${SWARMCHASE_DATA:-$HOME/swarmchase-data}"
latest="$data/$file"
what="newest watch run"
[[ "$file" == LATEST_OK ]] && what="newest watch run with a source that worked"

if [[ ! -s "$latest" ]]; then
    echo "no $what recorded ($latest is missing or empty)"
    exit 1
fi
stamp="$(tr -d '[:space:]' <"$latest")"
if ! [[ "$stamp" =~ ^([0-9]{8})T([0-9]{2})([0-9]{2})([0-9]{2})Z$ ]]; then
    echo "$file holds no run stamp: ${stamp:0:40}"
    exit 1
fi
then_s="$(date -u -d "${BASH_REMATCH[1]} ${BASH_REMATCH[2]}:${BASH_REMATCH[3]}:${BASH_REMATCH[4]}" +%s)"
now_s="$(date -u +%s)"
age_h=$(((now_s - then_s) / 3600))
echo "$what $stamp, ${age_h} h old (limit ${max_hours} h)"
((now_s - then_s <= max_hours * 3600))
