# One-server efficiency — item 29 evidence

User directive 2026-09-25 02:17 EDT: make Tinker so efficient a business
runs on ONE server and never needs to scale out. This doc is the
evidence: the reference profile, the fixed workload, the measured
numbers, the budgets, the optimizations, and the MEASURED CEILING.
It does not claim unlimited scale.

## 1. Reference one-server profile ("tinker-1s")

Recorded from the machine the measurements ran on (2026-09-25):

| Component | Detail |
|---|---|
| VM | single VM, app + PostgreSQL + Redis on the same box (all 127.0.0.1) |
| vCPU | 2 (AMD EPYC 9D25, 1 thread/core) |
| RAM | 7.9 GB |
| Disk | 7.5 GB overlay |
| OS | Linux 7.0.0-38-generic (Ubuntu 24.04 cell) |
| PostgreSQL | 16.15, cluster rebuilt via `bin/pg-ensure.sh` |
| Redis | 7.0.15 (vendored debs, `--save "" --appendonly no`) |
| App | `tinker-cli` binary (MCP HTTP transport) + `tinker-web` routes; **debug build** (consistent with every existing tripwire) |
| Pool | `tinker-db` `pool_options()`: max 16 / min 1 / acquire 5s / idle 300s / lifetime 1800s |

## 2. Workload definition ("crm-10k") — fixed before measuring

A CRM SaaS tenant shape, seeded deterministically (`generate_series`,
one batched INSERT per object per org):

- **10 tenants** (orgs), each with its own actor, membership, workspace
- Per tenant: **50 companies, 1,000 contacts, 200 deals**
- **12,500 records total** across `data.crm_company` / `data.crm_contact` / `data.crm_deal`
- Org 0 additionally carries the ingest stream, the machine credential,
  and the web session; query benchmarks run against org 1 (stable —
  ingest growth on org 0 never pollutes query measurements)

Named paths (harness: `crates/tinker-m7/tests/m7_efficiency.rs`):

| Path | What it measures |
|---|---|
| `ingest_page_500` | One 500-row page through `IngestPipeline::run`: extract→land→profile→model→promote, identity resolution on email, fresh stream + fresh source ids per iteration (always the insert path) |
| `query_grid_miss` | compile + `QueryCache` miss + `QueryExecutor::execute` (filtered `crm_contact` grid, `StartsWith` filter, limit 100) + audit write; distinct filter per iteration so every run misses |
| `query_grid_hit` | plan hash + `QueryCache` get on the primed intent |
| `gateway_transform` | `ModelGateway::transform_richtext` via the fake adapter (provider-row lookup + placement enforcement, no network) |
| `mcp_http_tools_list` | `POST /mcp` `tools/list` over the item-28 HTTP transport: Bearer <redacted> verify + scope gate + wire-server dispatch, full HTTP round trip |
| `mcp_http_sse_handshake` | `GET /sse`: time to the first endpoint event |
| `auth_key_verify` | `MachineCredentialStore::verify` (prefix SELECT + best-effort `last_used_at` UPDATE) |
| `auth_session_load` | `SessionManager::load_session` (cookie token → session row) |

Throughput probes (print-only, no wall-clock asserts): 8 concurrent
workers × 100 ops on `query_grid_hit`, and 8 × 25 on
`mcp_http_tools_list`.

## 3. Baseline measurements

Measured 2026-09-25. **Load conditions:** the cell was under sustained
foreign contention during calibration — a Shell-OS `shell_pty` process
at 60–95% CPU and a Bocht `bend build` at ~40% CPU, loadavg 4–5 for the
duration. These numbers are therefore **contention-inclusive upper
bounds**, not quiet-window ideals; the tripwire budgets below hold even
under this load, which is the stronger claim. Debug build, serial
`-j1`. Each latency row: 5 warmups + 21 measured runs (7 for the SSE
handshake), p50/p99. Raw log: `~/workspace/tinker-item29-baseline.log`.

| Path | p50 | p99 | Budget (tripwire) | Headroom (p50) |
|---|---|---|---|---|
| `ingest_page_500` | 12,046 ms | 25,891 ms | 30,000 ms | 2.5× |
| `query_grid_miss` | 12 ms | 100 ms | 500 ms | 41× |
| `query_grid_hit` | 0 ms | 0 ms | 100 ms | — |
| `gateway_transform` | 0 ms | 75 ms | 500 ms | — |
| `mcp_http_tools_list` | 2 ms | 19 ms | 500 ms | 250× |
| `mcp_http_sse_handshake` | 2 ms | 4 ms | 5,000 ms | — |
| `auth_key_verify` | 2 ms | 6 ms | 100 ms | 50× |
| `auth_session_load` | 0 ms | 75 ms | 100 ms | — |

Stage breakdown for `ingest_page_500` (per-iteration, 500 rows):
`extract_land` 39–248 ms, `model` (identity resolution) 2.1–14.8 s,
`profile` 3–73 ms, `promote` (canonical writes + provenance) 1.0–2.1 s.
Identity resolution dominates: ~13 DB round trips per row (BEGIN + 3×
SET LOCAL + 2 candidate SELECTs + link SELECT/INSERT + skeleton INSERT
+ read + write + provenance + COMMIT), each inflated by CPU contention.

Throughput (sustained, 8 workers, same loaded window):

| Path | ops/sec |
|---|---|
| `query_grid_hit` | 5,141 |
| `mcp_http_tools_list` | 176 |

## 4. Budgets and tripwires

Per-path budgets are pinned by regression tripwires in
`crates/tinker-m7/tests/m7_efficiency.rs`, in the `m4_perf` style:
generous p50 asserts over 21 runs (7 for the SSE handshake), not SLAs.
Every budget is load-sensitive by construction — the lesson from items
27/28 stands: wall-clock budgets are proven in a quiet window and the
tripwire names the load condition. The one pre-existing load-sensitive
tripwire (`m4_perf::versioned_query_tripwire`) is untouched.

## 5. Optimizations (measured before/after)

Three changes, all in production code (not benchmark-only). Each
preserves semantics; each was verified by the full serial suite.

### 5a. Landing write batching — N+1 elimination

`LandingWriter::write_batch` (`crates/tinker-ingest/src/landing.rs`)
executed one `INSERT … ON CONFLICT DO UPDATE` per source record: 500
round trips for a 500-row page. It now builds one multi-row INSERT per
batch (chunked at 1,000 rows to stay under Postgres's 65,535-parameter
limit): 1 round trip per page. Same transaction, same
`ON CONFLICT (organization_id, _source_id)` upsert semantics — replay
idempotency is unchanged, and a failed batch still rolls back
atomically.

Measured on `ingest_page_500` (extract_land stage). The pre-fix
baseline (9.3 s total page) was not stage-instrumented; the structural
win is 500 sequential INSERT round trips → 1 multi-row INSERT:

| | extract_land (500 rows) |
|---|---|
| After (multi-row INSERT) | 39–248 ms per iteration (first iteration cold, rest warm) |

The 500-round-trip loop is eliminated; landing is now a negligible
fraction of the page (model/promote dominate — see §3).

### 5b. App-binary pool discipline — connection establishment

`crates/tinker-m7/src/main.rs` (`build_stack`, `build_base`) built its
pools with raw `sqlx::PgPool::connect` — sqlx's light-duty defaults
(max 10, **min 0**). Every burst of concurrent requests paid
connection-establishment latency and PG backend-fork overhead, and the
ceiling for concurrent DB work was 10 per pool. Both builders now use
`CoreDb::connect` / `OwnerDb::connect`, which apply the tuned
`tinker-db` pool (max 16, min 1 warm, acquire 5s, idle 300s, lifetime
1800s). The efficiency harness uses the same constructors, so the
tripwires measure the deployed profile.

Pool sizing for the reference profile (2 vCPU, 8 GB, PG on-box):
16 max × 2 pools = 32 PG backends worst-case; each backend ~10 MB, so
~320 MB reserved — comfortable. min 1 keeps one warm connection per
pool without pinning 32 idle backends.

### 5c. Identity-link cross-stream index — plan discipline

`IngestPipeline::find_candidates_tx` resolves each source id against
_all_ streams of the organization (the designed cross-stream
external-id match):
`WHERE organization_id=$1 AND source_id=$2`. The only index was the
unique `(organization_id, stream_id, source_id)`; without a `stream_id`
predicate the planner range-scans every link of the organization per
lookup — O(org links) per row, O(n²) per page as the link table grows.
Migration `0035` adds `(organization_id, source_id)`, turning the
designed query into an index seek. Purely additive (no rewrite, no
behavior change). Verified: `EXPLAIN` shows the planner considering the
table's indexes; on a populated link table the
`(organization_id, source_id)` prefix gives an exact seek where the
unique `(organization_id, stream_id, source_id)` could only range-scan
the org's links and filter. Wall-clock before/after on the model stage
is confounded by the loaded calibration window (§3) — the structural
improvement (O(org links) → O(log n) per lookup) is the claim, and the
tripwire guards the wall clock.

Measured on `ingest_page_500` (model stage = identity resolution):
the stage grows across iterations as the link table accumulates
(2.1 s at 0 links → 10–14.8 s at ~12.5k links under contention);
the index bounds the per-lookup scan that drives that growth.

### Considered and declined (with reasons)

- **SAVEPOINT-per-row instead of transaction-per-row in `promote`:**
  would save ~3 round trips/row (~20% of model+promote), but the
  per-row transaction is a deliberate correctness boundary —
  poisoned-record isolation — and the error path (conflict review
  queued in a *separate* transaction after the record's tx rolls back)
  is structured around it. Risk in the identity/provenance path
  outweighs a modest gain.
- **Expression index on `lower(email)`:** the candidate email lookup
  wraps the physical column in `lower()`, defeating the DDL runner's
  `(organization_id, raw_col)` btree for exact seeks (it still
  index-scans the org's rows). A functional index would need the DDL
  runner to emit per-field expression indexes for email-type fields
  plus backfill — disproportionate; the org-scoped scan is bounded and
  not the dominant cost. Noted as future work.
- **`row_to_json` micro-optimizations** (`crates/tinker-live/src/exec.rs`):
  inspected; per-cell `type_info().name()` strings are noise-level
  against DB round trips. No change.
- **Plan-cache:** already disciplined — `bind_param` is the single
  canonical Param→SQLx path with a comment naming the INT4/INT8 cache
  hazard; `QueryCache` keys on plan hash. No change needed.

## 6. Headroom margin and the MEASURED CEILING

**Headroom:** every latency path's p50 sits 2.5×–250× under its
tripwire budget (§3), measured under sustained foreign contention
(loadavg 4–5). The budgets are the regression guard; the headroom is
the operating margin.

**Measured ceiling** — concurrency ramp on `mcp_http_tools_list`
(the DB-authenticated machine-traffic path), 40 sequential requests per
worker, same loaded window:

| Workers | Throughput | p50 | p99 |
|---|---|---|---|
| 1 | 65/s | 10 ms | 56 ms |
| 2 | 200/s | 7 ms | 29 ms |
| 4 | 208/s | 9 ms | 286 ms |
| 8 | 197/s | 21 ms | 475 ms |
| 16 | 281/s | 42 ms | 173 ms |
| 32 | 409/s | 71 ms | 205 ms |

No saturation knee was observed to 32 concurrent workers: throughput
scales with concurrency (65 → 409 req/s) while p50 stays well under the
500 ms budget. The owner pool (16 max) is not the binding constraint at
this level — per-request DB time is ~2 ms (verify SELECT + last_used_at
UPDATE), so 16 connections serve 32 workers without queueing. **The
measured ceiling for machine-API traffic on the reference profile is
therefore _at least_ ~400 req/s sustained; the knee lies beyond the
measured range.** p99s are erratic (load spikes from the foreign
processes), which is why the tripwires assert p50, not p99.

What this doc does NOT claim: unlimited scale, production-readiness,
or that scale-out is never needed. The ceiling above is measured on
the reference profile under contention; a quiet box or release build
moves it up, heavier workloads move it down, and the scale-out spike
(companion directive, same day) covers the multi-instance mechanics
separately.

**Honest limits:**
- Ingest is the tightest path: ~40 rows/s sustained under contention
  (12 s/500-row page), bounded by ~13 DB round trips per row in the
  deliberate per-record transaction. A 1 M-row initial import takes
  ~7 hours at this rate — acceptable for a small business's nightly
  sync, not for a bulk-migration firehose.
- The ramp did not find the knee; the true ceiling is unmeasured.
  Do not extrapolate beyond 32 workers.
- All numbers are debug-build, single-box, contention-inclusive.
  Release build + quiet box will be faster; this doc does not guess by
  how much.

## 7. Method notes

- `cargo test -p tinker-m7 --test m7_efficiency`, serial
  `--test-threads=1` (the harness shares one database; parallel
  threads would collide).
- Quiet window (target): `uptime` loadavg < 1.0 and no foreign process
  above ~10% CPU for the duration. **Not achieved on 2026-09-25:**
  the cell carried sustained foreign work (Shell-OS `shell_pty` at
  60–95%, Bocht `bend build` at ~40%, loadavg 4–5). §3 numbers are
  labeled as contention-inclusive upper bounds; the tripwires'
  p50 budgets hold even under that load.
- The box this VM runs on is shared: foreign builds invalidate
  wall-clock comparisons across windows. Do not compare §3 numbers
  against numbers taken in a different window; re-run in one window
  before claiming an optimization moved the needle.
- If the cell rootfs rolls mid-run (PostgreSQL/Redis binaries vanish),
  `bin/pg-ensure.sh` + the vendored Redis debs rebuild the profile;
  any failure burst against a dead DB is an infra event, not a code
  regression, and is logged as such.
- Raw logs: `~/workspace/tinker-item29-baseline.log` (calibration),
  `~/workspace/tinker-item29-smoke1.log` (harness smoke),
  `~/workspace/tinker-item29-smoke-ingest.log` (ingest smoke).
