# Config delta: dev cluster (bin/pg-ensure.sh) vs this production file
#
# The dev cluster is rebuilt from scratch by pg-ensure.sh whenever the
# VM's rootfs rolls; it is optimized for fast, unattended resurrection,
# not for durability. This document lists EVERY material difference so
# an operator can see exactly what changes in production.

## 1. Data directory — the big one
- DEV: `/var/tmp/pgdata-tinker` — a tmpfs. Survives neither a reboot nor
  a rootfs roll. That is *intentional* in dev: the database is
  disposable and test fixtures re-seed it.
- PROD: a PERSISTENT directory on real disk, e.g.
  `/var/lib/postgresql/16/prod` (see initdb-and-bootstrap.md). The
  postgres OS user must own it; it must be on a volume that survives
  reboots, and it must be included in the host backup (point at the R2
  DR runbook for the backup/restore procedure).
- WHY /var/tmp IS DEV-ONLY: it is tmpfs (RAM-backed). A power loss, a
  reboot, or a cell roll deletes the entire cluster with no recovery
  possible. Production data on tmpfs is data loss by design.

## 2. WAL archiving
- DEV: `archive_mode = off` (initdb default). Completed WAL segments are
  recycled. Point-in-time recovery is impossible; only the latest
  checkpointed state exists.
- PROD: `wal_level = replica`, `archive_mode = on`, `archive_command`
  stages every segment into `/var/lib/postgresql/wal-archive/`, and
  `archive_timeout = 3600` bounds recovery-point staleness. The R2 DR
  runbook governs the off-host copy of that spool — the local spool
  alone is not a backup.

## 3. Logging
- DEV: `logging_collector = off`; the postmaster is started with
  `-l /var/tmp/pgdata-tinker.log` — one ever-growing file on tmpfs.
- PROD: `logging_collector = on`, daily + 100MB rotation under
  `<datadir>/log/`, `log_min_duration_statement = 1000`,
  `log_checkpoints/connections/disconnections/lock_waits = on`. Logs go
  to the logrotate policy in deploy/logging/.

## 4. Network surface
- DEV: started with `-o '-p 5432 -k /var/tmp -c
  listen_addresses=127.0.0.1'` — TCP on localhost, unix socket in /var/tmp.
- PROD: `listen_addresses = 'localhost'`, `port = 5432`, unix socket in
  `/var/run/postgresql` (the Debian/Ubuntu default; matches the systemd
  unit). Same localhost-only posture; `ssl = off` stays valid ONLY
  while every client is on the same host.

## 5. Memory / planner tuning
- DEV: every initdb default (`shared_buffers = 128MB`,
  `random_page_cost = 4`, `effective_cache_size = 4GB`, …).
- PROD: `shared_buffers = 2GB`, `effective_cache_size = 6GB`,
  `work_mem = 8MB`, `maintenance_work_mem = 512MB`,
  `random_page_cost = 1.1`, `effective_io_concurrency = 200`,
  `checkpoint_completion_target = 0.9`, `max_wal_size = 4GB`.
  SIZED FOR an 8GB-RAM dedicated VM — re-tune for the real host.

## 6. Credentials & roles
- DEV: superuser password is `openssl rand -base64 32` written to
  `/var/tmp/pgdata-tinker.pw` (tmpfs, regenerated per initdb); role
  passwords come from `.secrets/.env.test` and are (re)applied on every
  pg-ensure run.
- PROD: superuser password is set ONCE at initdb from the operator's
  secret store and never written to a repo; role passwords
  (`tinker_core`, `tinker_app`, `tinker_pii`, `tinker_pii_app`) come from
  the production environment (see deploy/env/), NOT from
  `.secrets/.env.test`. The one-shot privileged bootstrap (same role
  shape as pg-ensure.sh: owners are LOGIN+CREATEROLE, app roles are plain
  LOGIN, extensions installed by the superuser) is documented in
  initdb-and-bootstrap.md.

## 7. Autovacuum
- DEV: defaults.
- PROD: `autovacuum_max_workers = 4`, naptime 30s, scale factors halved —
  the ontology tables churn and the defaults lag on them.

## 8. Timezone
- DEV: initdb default (host timezone).
- PROD: `timezone = 'UTC'` / `log_timezone = 'UTC'` — timestamps stored
  and logged in UTC; presentation happens in the app.
