#!/bin/bash
# test-mac.sh — run the workspace test suite on macOS.
#
#   bin/test-mac.sh                    # full suite, log to _eval/runs/<ts>.log
#   bin/test-mac.sh -p tinker-m0 ...   # any cargo-test args pass through
#
# Brings up the dev cluster (bin/dev-db-mac.sh), a throwaway Redis on
# 127.0.0.1:16390 (no persistence; reused if already up), points the
# browser test at a Chrome for Testing build when one is installed, and
# sets DATABASE_URL so `sqlx::query!` can check queries at compile time.
set -uo pipefail

HERE="$(cd "$(dirname "$0")/.." && pwd)"
cd "$HERE"
export PATH="/opt/homebrew/opt/rustup/bin:$HOME/.cargo/bin:/opt/homebrew/bin:$PATH"

bin/dev-db-mac.sh >/dev/null || { echo "test-mac: dev-db failed" >&2; exit 1; }
eval "$(bin/dev-db-mac.sh env)"
export DATABASE_URL="$TINKER_CORE_OWNER_URL"

REDIS_PORT=16390
if ! redis-cli -p "$REDIS_PORT" ping >/dev/null 2>&1; then
  redis-server --port "$REDIS_PORT" --bind 127.0.0.1 --save "" --appendonly no --daemonize yes >/dev/null
  for _ in 1 2 3 4 5 6 7 8 9 10; do redis-cli -p "$REDIS_PORT" ping >/dev/null 2>&1 && break; sleep 0.2; done
fi
export TINKER_TEST_REDIS_URL="redis://127.0.0.1:$REDIS_PORT/"

if [ -z "${TINKER_TEST_CHROME:-}" ]; then
  CFT=$(ls -d "$HOME"/Library/Caches/ms-playwright/chromium-*/chrome-mac-arm64/"Google Chrome for Testing.app"/Contents/MacOS/"Google Chrome for Testing" 2>/dev/null | tail -1)
  [ -n "$CFT" ] && export TINKER_TEST_CHROME="$CFT"
fi

mkdir -p _eval/runs
LOG="_eval/runs/$(date +%Y%m%dT%H%M%S).log"
cargo test --workspace --no-fail-fast "$@" >"$LOG" 2>&1
STATUS=$?
grep -E "^test result:" "$LOG" | awk '{p+=$4; f+=$6; i+=$8} END {printf "test-mac: passed %d failed %d ignored %d\n", p, f, i}'
grep -E "^test .* FAILED$" "$LOG" | sed 's/^/test-mac: /'
echo "test-mac: log $HERE/$LOG (exit $STATUS)"
exit $STATUS
