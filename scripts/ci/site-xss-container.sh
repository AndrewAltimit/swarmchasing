#!/usr/bin/env bash
# Run scripts/site-xss-check.mjs against a headless Chrome in a container, for
# a machine with Docker and no Chrome of its own (the self-hosted runner).
#
# The browser runs in a pinned multi-arch headless-shell image, holds no state
# and is removed on exit. On Linux it shares the host network and listens on
# loopback only, and the check's files are mounted read-only at their own path.
# Elsewhere (Docker Desktop) it reaches the check's server through
# host.docker.internal, which it is told to treat as a secure origin, as
# 127.0.0.1 is.
#
# Usage (after scripts/ci/build-site.sh):
#     scripts/ci/site-xss-container.sh
# Exit codes are the check's: 0 pass, 1 failure, 2 could not run (no Docker,
# no image, or the check's own reasons).
set -euo pipefail

IMAGE="${XSS_CHROME_IMAGE:-chromedp/headless-shell:151.0.7922.109}"
PORT="${XSS_PORT:-8790}"
DEBUG_PORT="${XSS_DEBUG_PORT:-9334}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"

if ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1; then
  echo "site-xss-container: no usable Docker" >&2
  exit 2
fi
if ! docker image inspect "$IMAGE" >/dev/null 2>&1 && ! docker pull -q "$IMAGE" >/dev/null; then
  echo "site-xss-container: could not pull $IMAGE" >&2
  exit 2
fi

share="$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/sc-xss-share.XXXXXX")"
name="sc-xss-chrome-$$"
cleanup() {
  docker rm -f "$name" >/dev/null 2>&1 || true
  rm -rf "$share"
}
trap cleanup EXIT

if [ "$(uname -s)" = "Linux" ]; then
  # Later switches win: debugging moves from the image's 0.0.0.0:9222 to
  # loopback on DEBUG_PORT.
  docker run -d --rm --name "$name" --network host --user "$(id -u):$(id -g)" \
    -v "$share:$share:ro" "$IMAGE" \
    --remote-debugging-address=127.0.0.1 --remote-debugging-port="$DEBUG_PORT" >/dev/null
  export XSS_PAGE_HOST=127.0.0.1
  unset XSS_SHARE_AS
else
  docker run -d --rm --name "$name" -p "127.0.0.1:$DEBUG_PORT:9222" \
    --add-host host.docker.internal:host-gateway \
    -v "$share:/share:ro" "$IMAGE" \
    --unsafely-treat-insecure-origin-as-secure="http://host.docker.internal:$PORT" >/dev/null
  export XSS_PAGE_HOST=host.docker.internal
  export XSS_SHARE_AS=/share
fi

export XSS_CDP="http://127.0.0.1:$DEBUG_PORT"
export XSS_SHARE_DIR="$share"
rc=0
node "$ROOT/scripts/site-xss-check.mjs" || rc=$?
exit "$rc"
