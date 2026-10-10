#!/usr/bin/env bash
# Load env.list (gitignored local secrets) and run a command, or load it into
# the current shell when sourced.
#
#     scripts/with-env.sh <command> [args...]
#     source scripts/with-env.sh
#
# env.list is KEY=value per line (see env.list.example). Values are taken
# literally - the file is parsed, never executed - and a variable already set
# in the environment is left alone, so CI secrets and one-off overrides win.
# Set SWARMCHASE_ENV_FILE to load a different file.

_sc_load_env() {
    local root file line key value n=0
    root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
    file="${SWARMCHASE_ENV_FILE:-$root/env.list}"
    if [[ ! -f "$file" ]]; then
        echo "with-env: $file not found (copy env.list.example)" >&2
        return 0
    fi
    while IFS= read -r line || [[ -n "$line" ]]; do
        line="${line%$'\r'}"
        [[ "$line" =~ ^[[:space:]]*(#|$) ]] && continue
        if [[ ! "$line" =~ ^[[:space:]]*(export[[:space:]]+)?([A-Za-z_][A-Za-z0-9_]*)=(.*)$ ]]; then
            echo "with-env: skipping malformed line in $file" >&2
            continue
        fi
        key="${BASH_REMATCH[2]}"
        value="${BASH_REMATCH[3]}"
        [[ -n "${!key+x}" ]] && continue
        export "$key=$value"
        n=$((n + 1))
    done <"$file"
    # Names only; values are secrets.
    echo "with-env: loaded $n variable(s) from $(basename "$file")" >&2
}

if [[ "${BASH_SOURCE[0]}" != "$0" ]]; then
    _sc_load_env
    unset -f _sc_load_env
    return 0
fi

set -euo pipefail
if [[ $# -eq 0 ]]; then
    echo "usage: scripts/with-env.sh <command> [args...]   (or: source scripts/with-env.sh)" >&2
    exit 2
fi
_sc_load_env
exec "$@"
