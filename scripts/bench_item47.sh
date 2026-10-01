#!/usr/bin/env bash
# Item 47 bench runner: single-server efficiency (measure first, then optimize).
#
# Usage: scripts/bench_item47.sh [OUT_DIR]
#
# Runs the ignored `mcp_bench` test (timing-sensitive: never part of the
# default gate) with the standard session env. Prints the report path on
# success. Run once BEFORE any optimization (baseline) and again after
# each change; diff with scripts/compare_bench.py.
#
# The bench needs a quiet VM: check `uptime` first, and never run it
# while another DB-touching cargo job is active. The load-sensitive
# m4_perf::versioned_query_tripwire threshold is NEVER weakened to make
# a bench number look better.

set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO"

OUT_DIR="${1:-/tmp/tinker-bench}"
mkdir -p "$OUT_DIR"

echo "--- pg-ensure ---"
"$REPO/bin/pg-ensure.sh" | tail -2

set -a
# shellcheck disable=SC1091
. .secrets/.env.test
set +a
export DATABASE_URL="$TINKER_CORE_OWNER_URL"
export TINKER_TEST_REDIS_URL=redis://127.0.0.1:16379/
export PATH="/usr/lib/postgresql/16/bin:$HOME/.cargo/bin:$PATH"
export TINKER_BENCH_OUT="$OUT_DIR"

echo "--- VM load before bench ---"
uptime
if pgrep -f "cargo test" >/dev/null 2>&1; then
    echo "WARNING: another 'cargo test' is running; bench numbers may be polluted."
fi

echo "--- running mcp_bench (ignored test, serial) ---"
cargo test -p tinker-mcp --test mcp_bench -- --ignored --nocapture --test-threads=1

echo "--- latest report ---"
ls -t "$OUT_DIR"/report-*.json | head -1
