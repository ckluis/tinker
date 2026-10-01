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
# ~90 test binaries with full debug info + incremental caches reached
# 22GB of target/ and filled the disk (2026-09-30). Test runs need
# neither: line tables keep panic locations, and no incremental cache.
export CARGO_INCREMENTAL=0
export CARGO_PROFILE_DEV_DEBUG=line-tables-only

REDIS_PORT=16390
if ! redis-cli -p "$REDIS_PORT" ping >/dev/null 2>&1; then
  redis-server --port "$REDIS_PORT" --bind 127.0.0.1 --save "" --appendonly no --daemonize yes >/dev/null
  for _ in 1 2 3 4 5 6 7 8 9 10; do redis-cli -p "$REDIS_PORT" ping >/dev/null 2>&1 && break; sleep 0.2; done
fi
export TINKER_TEST_REDIS_URL="redis://127.0.0.1:$REDIS_PORT/"

# Browser test: Playwright's chrome-headless-shell. The full Chrome for
# Testing app never commits a navigation in headless mode on this macOS
# (location stays about:blank, screenshots hang); the headless shell
# renders normally.
if [ -z "${TINKER_TEST_CHROME:-}" ]; then
  HS=$(ls -d "$HOME"/Library/Caches/ms-playwright/chromium_headless_shell-*/chrome-headless-shell-mac-arm64/chrome-headless-shell 2>/dev/null | tail -1)
  [ -n "$HS" ] && export TINKER_TEST_CHROME="$HS"
fi

export TINKER_TEST_PROOF_DIR="${TINKER_TEST_PROOF_DIR:-$HERE/target/browser-proofs}"

mkdir -p _eval/runs
LOG="_eval/runs/$(date +%Y%m%dT%H%M%S).log"
cargo test --workspace --no-fail-fast "$@" >"$LOG" 2>&1
STATUS=$?
grep -E "^test result:" "$LOG" | awk '{p+=$4; f+=$6; i+=$8} END {printf "test-mac: passed %d failed %d ignored %d\n", p, f, i}'
grep -E "^test .* FAILED$" "$LOG" | sed 's/^/test-mac: /'
echo "test-mac: log $HERE/$LOG (exit $STATUS)"

# The no-plaintext-PII gate (samen's `no_plaintext_pii` tier): every
# email/phone field in the database the suite just exercised must be
# vault-backed. A green suite that left plaintext PII behind still fails.
if ! cargo run -q -p tinker-m7 --bin tinker-cli -- pii verify >>"$LOG" 2>&1; then
  echo "test-mac: FAILED pii verify (plaintext email/phone fields; see log)"
  STATUS=1
else
  echo "test-mac: pii verify ok"
fi
exit $STATUS
