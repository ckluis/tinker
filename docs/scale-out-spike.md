# Scale-out spike (post-M8 item 30)

Date: 2026-09-25. Time-boxed spike, not a production-topology claim.
Nothing here says Tinker is production-ready; it is not.

## Spike topology

Two real `tinker` server binaries (separate OS processes, ports 18681 /
18682) sharing one PostgreSQL and one Redis:

- Postgres: the app's single database (owner URL for migrations and
  pre-tenant lookups, app-role URL for tenant queries).
- Redis: `TINKER_REDIS_URL`. Both instances ran with it set, so the
  signal fan-out bridge was live.
- Both binaries run migrations at startup. Migration ownership is
  serialized cluster-wide with Postgres advisory locks
  (`MIGRATION_LOCK_CORE` / `MIGRATION_LOCK_PII`), so N instances racing
  at deploy time apply each migration exactly once.

## What was proven (with tests)

1. **Migrations serialize across instances.**
   `crates/tinker-db/tests/migration_advisory_lock.rs` — 8 concurrent
   migrators all succeed with unique migration versions; a migrator
   blocks while another session holds `MIGRATION_LOCK_CORE` and
   completes after release. 2/2 pass.

2. **Login on A, authenticated request on B — no stickiness.**
   `crates/tinker-web/tests/scale_out_two_process.rs` — full passkey
   ceremony over HTTP against instance A, then `GET /apps` with the
   session cookie against instance B returns 200. Sessions and passkey
   challenges live in Postgres (`tinker_identity::SessionManager`), so
   there is nothing per-instance to stick to. 1/1 passes (6/6 repeat
   runs green after moving off a port squatted by a sibling campaign
   binary — see limits).

3. **Cross-instance signal fan-out.**
   `crates/tinker-live/tests/signal_fanout.rs` — 6/6 pass: `Invalidate`
   and `SchemaVersion` published on one `SignalBus` reach a second bus
   sharing only Redis; the per-org sequence (`INCR
   tinker:signals:seq:{org}`) is globally increasing across publishers;
   envelopes from the wrong org are rejected; a remote `SchemaVersion`
   invalidates the receiving instance's `QueryCache`; the publisher
   does not get a duplicate Redis echo of its own signal; an
   unreachable Redis fails closed at enable time.
   The two-process test additionally proves the full HTTP path: an SSE
   stream opened on B receives the `invalidate` event (with `seq` and
   the posted `record_ids`) for a message posted through A's API, and a
   write in org2 produces **no** event on org1's stream (tenant
   isolation).

4. **Machine credentials unchanged across instances.**
   `crates/tinker-auth/tests/apikey_credentials.rs::machine_credentials_shared_across_instances`
   — issue on A (one `MachineCredentialStore`), verify on B (an
   independently connected store), revoke on A, verify fails closed on
   B. 1/1 passes. Credentials are Postgres rows; nothing per-instance.

5. **Approvals unchanged across instances.**
   `crates/tinker-agents/tests/approvals_scale_out.rs` — request on A
   (one `ApprovalEngine`), read + approve on B (independently
   connected), approved state visible back on A. 1/1 passes. Approval
   state is Postgres; nothing per-instance.

## What survives scale-out

- Authentication sessions, passkey challenges: Postgres.
- Machine API credentials (issue/verify/revoke): Postgres.
- Approval requests and decisions: Postgres.
- Migrations: advisory-lock serialized; safe to run at every boot.
- `Invalidate` / `SchemaVersion` signals: Redis pub/sub bridge, one
  channel per org (`tinker:signals:{org}`), per-org sequence shared via
  `INCR`, envelopes carry the publishing instance id and are rejected
  cross-org.
- Ontology/query execution paths: Postgres-backed; no per-instance
  caches observed.
- The comms `installed` cache (`tinker-comms`) holds ontology object
  ids resolved from idempotent DDL — identical on every instance,
  benign.

## What does NOT survive (or only partially)

- **Redis pub/sub is lossy with no replay.** A subscriber that is not
  connected at publish time misses the signal. The current subscriber
  task exits on Redis disconnect and does not yet reconnect or
  re-subscribe automatically. Publish failure logs an error and falls
  back to local delivery, so remote nodes can silently miss that hint.
- **Row invalidations do not clear remote query caches.** Only
  `SchemaVersion` signals invalidate the remote `QueryCache`; a row
  `Invalidate` still only clears the publishing instance's cache.
  Staleness on other nodes is bounded by the existing 30-second
  row-query TTL. This is unchanged pre-existing behavior, now
  documented.
- **No Redis session store in the web auth path.** The brief referenced
  item 19's `RedisSessionStore`, but web authentication goes through
  `tinker_identity::SessionManager` (Postgres). `RedisSessionStore`
  lives in `tinker-transfer` and is not wired into Tinker web login.
  Cross-instance login works — via shared Postgres, not Redis. If a
  Redis-backed web session is wanted, that is a separate architecture
  change, not something this spike did.
- **The unit-level fan-out tests use separate `SignalBus` instances
  sharing Redis, not separate OS processes.** The HTTP SSE leg *is*
  proven across two real processes by the two-process test; the
  in-process `SignalBus` assertions are not.
- **Test-port fragility (environmental, fixed).** The two-process test
  originally used ports 18081/18082; a sibling Bocht campaign binary
  (`med_native_r38`) was observed listening on 0.0.0.0:18081 mid-run,
  causing `AddrInUse` crashes and one `IncompleteMessage` failure.
  Moved to 18681/18682 with a wait-for-port-free guard and fail-fast
  child-exit detection. 6/6 consecutive runs green afterwards.

## Minimal real deployment changes

1. Point every instance at the same Postgres and Redis.
2. Set `TINKER_REDIS_URL` on every instance (unset = single-instance
   mode, current behavior; set-but-unreachable = fail closed at boot).
3. Keep running migrations at startup (advisory lock makes it safe).
4. Do not rely on row-invalidation freshness across nodes below the
   30s TTL; use schema-version bumps for coherence-critical changes.
5. Redis becomes a hard dependency for the signal bridge: monitor it,
   and expect the reconnect gap above to be closed before any claim
   stronger than this spike.
