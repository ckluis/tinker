# Tinker production deployment package
#
# This directory is the complete, self-contained production layout for
# Tinker. NOTHING HERE DEPLOYS ANYTHING — it is configuration,
# documentation, and samples for an operator to apply on a real host.
# There is deliberately no Terraform, no cloud module, no DNS change:
# see "What you must provide for real hosting" below.

## Layout

```
deploy/
  README.md                  # this file: layout, bring-up order, operator checklist
  postgres/
    postgresql.conf          # production postgres settings (archive-ready WAL,
                             #   logging collector, tuned memory; sized for 8GB VM)
    CONFIG-DELTA.md          # exact delta vs bin/pg-ensure.sh's dev cluster
    initdb-and-bootstrap.md  # one-shot provisioning: initdb, roles, DBs,
                             #   extensions, archive spool, verification queries
    tinker-postgres.service  # sample systemd unit
  redis/
    redis.conf               # RDB snapshots + AOF everysec, loopback-only,
                             #   requirepass, dangerous commands renamed
    tinker-redis.service     # sample systemd unit (REDISCLI_AUTH via env file)
  proxy/
    nginx-tinker-mcp.conf    # TLS-terminating reverse proxy: /mcp (SSE-safe),
                             #   /healthz, security headers, rate limit.
                             #   SYNTAX-UNVALIDATED (no nginx on build VM)
  systemd/
    tinker-mcp.service       # `tinker-mcp serve` unit (loopback bind, env file)
  env/
    tinker.env.template      # EVERY variable the service reads, documented,
                             #   placeholders only — no real secrets
    SECRETS.md               # the hard rule: secrets via environment, never the repo
  logging/
    logrotate-tinker         # sample logrotate policy for all service logs
```

## Bring-up order (on the production host)

1. **Host + OS user**: provision the machine (see "What you must
   provide"), create the `tinker` and `redis` OS users, install
   PostgreSQL 18 (PGDG apt repo, apt.postgresql.org — Ubuntu 24.04 main
   ships only 16) and Redis 7 (vendored Redis debs live in
   `bin/vendor/` if the host is offline).
2. **PostgreSQL**: follow `postgres/initdb-and-bootstrap.md`
   (initdb → `postgresql.conf` → archive spool → one-shot role/DB/
   extension bootstrap). `systemctl enable --now tinker-postgres`,
   then run the archive-verification queries in step 6 of that doc.
3. **Redis**: install `redis/redis.conf` (fill `__REDIS_PASSWORD__`),
   create `/etc/tinker/redis.env` with `REDISCLI_AUTH=<same>`,
   `systemctl enable --now tinker-redis`. Smoke: `redis-cli ping`.
4. **Secrets**: copy `env/tinker.env.template` to
   `/etc/tinker/tinker-mcp.env`, fill every `__PLACEHOLDER__`,
   `chown root:tinker`, `chmod 0600`. Read `env/SECRETS.md`.
5. **Binary**: `cargo build --release -p tinker-mcp` (pin the toolchain
   per the repo's rust-toolchain file, if any), install the binary at
   `/opt/tinker/bin/tinker-mcp`. First boot runs the embedded
   migrations under a cluster-wide leader election — watch stderr for
   `tinker-mcp: listening on 127.0.0.1:8080 (http)`.
   `systemctl enable --now tinker-mcp`.
6. **Reverse proxy**: fill the `__PLACEHOLDER__`s in
   `proxy/nginx-tinker-mcp.conf`, `nginx -t`, reload. Confirm
   `https://__DOMAIN__/healthz` → `{"status":"ok","version":"..."}`.
7. **C6 key**: `tinker-cli mcp key issue --org <slug> --name <name>
   --scopes mcp:tools,mcp:resources --role member` (run with the same
   env file), then smoke an authenticated tool call through the proxy:
   `POST https://__DOMAIN__/mcp` `initialize` → `tools/list`.
8. **Logging**: install `logging/logrotate-tinker` as
   `/etc/logrotate.d/tinker`.
9. **Backups**: wire the off-host WAL copy + base-backup schedule from
   `docs/disaster-recovery.md` (R2 DR runbook — all three drills passed
   2026-09-28; evidence in `~/workspace/prodread/pg-dr/`) and re-run its
   restore drill against this exact layout before serving production
   traffic.
   schedule BEFORE serving production traffic (see below).

## Validated on the build VM (2026-09-28, R5 workstream)

| Component | Result |
|---|---|
| `GET /healthz` (new endpoint) | PASS — 200, `{"status":"ok","version":"0.1.0"}`, unauthenticated, body has exactly the two keys; covered by `http_healthz_is_unauthenticated_and_minimal` in `mcp_http.rs` |
| `tinker-mcp` test suites (incl. the new test) | PASS (`cargo test -p tinker-mcp`) |
| Full serial gate (115 suites) after the code change | PASS — 2026-09-28 22:46:49Z→23:01:25Z, `cargo test --workspace -j1 -- --skip seed_drorg_1` (seed_drorg_1 skipped exactly as in R3's gate: R4's non-idempotent seed fixture collides), CARGO_TEST_EXIT:0 with 117 "test result: ok" / 0 failures, `cargo clippy --workspace --all-targets` clean; run under the GATE_RUNNING lock with the soak paused; log at `~/workspace/prodread/closeout/r5_gate_full.log` |
| Production `postgresql.conf` | PASS — a scratch cluster was initdb'd with this file at `/var/tmp/pgdata-prodval` on port 5434 (the requested `~/workspace/prodread/pg-prodval` was unusable: the `postgres` OS user is confined from `/home/hatch`; R2 already held 5433), started, `archive_mode=on` confirmed via `SHOW`, a forced `pg_switch_wal()` landed a segment in the local archive spool, `pg_stat_archiver.failed_count=0`, tuned settings (`shared_buffers=2GB`, `checkpoint_completion_target=0.9`) confirmed live |
| Production `redis.conf` | PASS — redis-server 7.0.15 started with this file on port 6380 (dev's 16379 untouched): `PING`+AUTH ok, RDB snapshot + AOF rewrite produced files, key written → server killed -9 → restarted → key present (crash-durability smoke) |
| `tinker-mcp serve` + authenticated smoke behind the proxy config | PARTIAL — serve booted with the production-shaped env (loopback bind) and answered `/healthz` and an authenticated `initialize`+`tools/list` directly; the nginx config itself is SYNTAX-UNVALIDATED (no nginx on the build VM; `nginx -t` must be run by the operator) |
| systemd units, logrotate | PARTIAL — `systemd-analyze verify` passes on all three units (only expected note: `/opt/tinker/bin/tinker-mcp` doesn't exist on the build VM); actual PID-1 boot and logrotate runs NOT validated — no systemd as PID 1 here; operator re-verifies at install |

## What you must provide for real hosting

Nothing in this directory creates any of the following. The operator
(the user) provides all of it; this package only consumes it.

1. **Domain + DNS**: a hostname (e.g. `mcp.example.com`) with an A/AAAA
   record pointing at the host. No DNS was touched by this workstream
   (hard stop: no public deploy).
2. **Host/VM**: a Linux VM with ≥4 vCPU / 8 GB RAM / SSD as sized in
   `postgres/postgresql.conf` (re-tune for the real machine), with
   persistent block storage for `/var/lib/postgresql`,
   `/var/lib/redis`, `/opt/tinker/var/files`.
3. **Certificates**: TLS strategy is Let's Encrypt via certbot
   (`certbot --nginx -d __DOMAIN__` fills `ssl_certificate*` in the
   nginx config and renews automatically). The sample config keeps
   `/.well-known/acme-challenge/` reachable over HTTP for renewal. No
   certificate was requested or created here.
4. **Secrets provisioning**: every `__PLACEHOLDER__` in
   `env/tinker.env.template` + the redis `requirepass` + the postgres
   superuser password, from your secret store (age/Vault/hosted
   secrets manager). Generation commands:
   `openssl rand -base64 32` (passwords/KEK), and C6 keys via
   `tinker-cli mcp key issue` once the service is up.
5. **Backups (`docs/disaster-recovery.md`, R2 DR runbook — drills passed
   2026-09-28)**: this package stages WAL segments into
   `/var/lib/postgresql/wal-archive/` and keeps RDB+AOF for redis, but
   the OFF-HOST copy, the base-backup schedule (`pg_basebackup`), the
   restore drill, and the file-backend (`TINKER_FILE_ROOT`) backup live
   in that runbook — do not serve production traffic until its drill
   has passed against this exact layout.
6. **Monitoring/alerting**: at minimum, alert on
   `pg_stat_archiver.failed_count > 0`, `redis` `rdb_last_bgsave_status
   != ok`, `tinker-mcp` process down, `/healthz` non-200, and disk
   usage on the WAL spool. None is configured here.
7. **Operator runbook**: `docs/disaster-recovery.md` + this README are the
   starting set; add your incident contacts and escalation paths.
