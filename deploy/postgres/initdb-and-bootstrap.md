# Provisioning the production cluster: initdb + one-shot bootstrap
#
# Run ONCE per host as root (or a sudo-capable operator). Afterwards the
# systemd unit in this directory owns the postmaster.

## 0. Prerequisites (operator provides)
- PostgreSQL 18 server binaries (`postgresql-18` from the PGDG apt
  repository, apt.postgresql.org; Ubuntu 24.04's own archive stops at 16).
  Upgrading an existing 16 cluster: see §7.
- A persistent data volume mounted at `/var/lib/postgresql` (or any
  persistent path — adjust `PGDATA` below and in the systemd unit).
- The WAL archive spool directory's parent on persistent disk.
- The four role passwords in your secret store (see
  `deploy/env/tinker.env.template`): they become
  `TINKER_CORE_OWNER_URL`, `TINKER_CORE_URL`, `TINKER_PII_OWNER_URL`,
  `TINKER_PII_URL` passwords.

## 1. initdb
```sh
PGDATA=/var/lib/postgresql/18/prod
PGBIN=/usr/lib/postgresql/18/bin
install -d -o postgres -g postgres -m 0700 "$PGDATA"
su -s /bin/sh postgres -c "umask 077; $PGBIN/initdb -D '$PGDATA' -E UTF8 \
  --locale=C.UTF-8 --auth=scram-sha-256"
# PostgreSQL 18 initdb enables data checksums by default (wanted for a
# fresh cluster). An upgrade from a 16 cluster that lacks them must
# instead initdb with --no-data-checksums — see §7.
# The superuser password is set interactively or via --pwfile from the
# operator's secret store. It is NEVER committed to the repo.
```

## 2. Install the production postgresql.conf
```sh
cp deploy/postgres/postgresql.conf "$PGDATA/postgresql.conf"
chown postgres:postgres "$PGDATA/postgresql.conf"
chmod 0600 "$PGDATA/postgresql.conf"
```

## 3. WAL archive spool (the archive_command target)
```sh
install -d -o postgres -g postgres -m 0700 /var/lib/postgresql/wal-archive
```
This spool is the LOCAL staging area only. The R2 DR runbook's
off-host copy job watches this directory — without that job, archived
segments pile up here and the spool is not a backup.

## 4. One-shot privileged bootstrap (roles, databases, extensions)
Same privilege shape as `bin/pg-ensure.sh` (kept deliberately
identical so dev and prod converge):
- `tinker_core` / `tinker_pii`: LOGIN + CREATEROLE, NOSUPERUSER,
  NOCREATEDB. CREATEROLE is the minimum the app needs for
  `tinker_db::rotate_app_role_passwords` (ALTER ROLE on the app role)
  plus the frozen 0001 role-creation backstop.
- `tinker_app` / `tinker_pii_app`: plain LOGIN. No DDL, no role admin.
- Extensions (`pgcrypto`, `pg_trgm`) are installed by the superuser so
  migrations never need SUPERUSER.
- The owners hold `ADMIN OPTION` (only) on their app role, which
  PostgreSQL requires alongside CREATEROLE to ALTER another role.

Run as the `postgres` superuser over the local socket, substituting the
four passwords from the secret store. psql `:'var'` interpolation fires
at the TOP LEVEL only — it does NOT fire inside a dollar-quoted `DO`
block — so the bootstrap goes through a temp function whose arguments
are substituted at the `SELECT` call site, and the function body uses
`format(... %L ...)` (proper literal quoting, no injection):
```sh
$PGBIN/psql -h /var/run/postgresql -d postgres -v ON_ERROR_STOP=1 \
  -v core_pw="$CORE_PW" -v app_pw="$APP_PW" \
  -v pii_pw="$PII_PW" -v pii_app_pw="$PII_APP_PW" <<'EOF'
CREATE OR REPLACE FUNCTION pg_temp.bootstrap_roles(
  core_pw text, app_pw text, pii_pw text, pii_app_pw text)
RETURNS void LANGUAGE plpgsql AS $func$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='tinker_core') THEN
    EXECUTE 'CREATE ROLE tinker_core LOGIN CREATEROLE';
  END IF;
  EXECUTE format('ALTER ROLE tinker_core WITH LOGIN CREATEROLE NOSUPERUSER NOCREATEDB PASSWORD %L', core_pw);
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='tinker_app') THEN
    EXECUTE 'CREATE ROLE tinker_app LOGIN';
  END IF;
  EXECUTE format('ALTER ROLE tinker_app WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE PASSWORD %L', app_pw);
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='tinker_pii') THEN
    EXECUTE 'CREATE ROLE tinker_pii LOGIN CREATEROLE';
  END IF;
  EXECUTE format('ALTER ROLE tinker_pii WITH LOGIN CREATEROLE NOSUPERUSER NOCREATEDB PASSWORD %L', pii_pw);
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='tinker_pii_app') THEN
    EXECUTE 'CREATE ROLE tinker_pii_app LOGIN';
  END IF;
  EXECUTE format('ALTER ROLE tinker_pii_app WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE PASSWORD %L', pii_app_pw);
END
$func$;
SELECT pg_temp.bootstrap_roles(:'core_pw', :'app_pw', :'pii_pw', :'pii_app_pw');
DROP FUNCTION pg_temp.bootstrap_roles(text, text, text, text);
SELECT 'CREATE DATABASE tinker_core OWNER tinker_core'
  WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname='tinker_core')\gexec
SELECT 'CREATE DATABASE tinker_pii OWNER tinker_pii'
  WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname='tinker_pii')\gexec
GRANT tinker_app TO tinker_core WITH ADMIN OPTION;
GRANT tinker_pii_app TO tinker_pii WITH ADMIN OPTION;
EOF
for db in tinker_core tinker_pii; do
  $PGBIN/psql -h /var/run/postgresql -d "$db" -v ON_ERROR_STOP=1 -q \
    -c 'CREATE EXTENSION IF NOT EXISTS pgcrypto;'
done
$PGBIN/psql -h /var/run/postgresql -d tinker_core -v ON_ERROR_STOP=1 -q \
  -c 'CREATE EXTENSION IF NOT EXISTS pg_trgm;'
```
The block is idempotent: re-running converges passwords and grants
instead of duplicating them. Validated 2026-09-28 on a scratch PG16
cluster (re-run 2026-09-30 against PG 18.6 by bin/dev-db.sh, which
mirrors this block): all four roles created with the documented attributes
(login; CREATEROLE on owners only; NOSUPERUSER), SCRAM password login
verified over TCP for each role, wrong password rejected, and a second
run with a rotated password converged to the new password.

## 5. Migrations — none needed manually
`tinker-mcp serve` runs `owner.migrate()` at startup with a
cluster-wide leader election (exactly one instance migrates while the
rest wait). The first production boot applies the embedded migrations
itself. Verify with:
```sh
psql "$TINKER_CORE_OWNER_URL" -tAc 'SELECT count(*) FROM _sqlx_migrations'
```
and compare against the count of `*.sql` files in
`crates/tinker-db/migrations/core` (44 as of 2026-09-28) — a mismatch
means a stale binary.

## 6. Verify archiving is actually working
```sh
psql "$TINKER_CORE_OWNER_URL" -tAc "SHOW archive_mode; SHOW archive_command;"
# then force a segment and confirm it lands in the spool:
psql "$TINKER_CORE_OWNER_URL" -c 'SELECT pg_switch_wal();'
ls -l /var/lib/postgresql/wal-archive/ | tail -3
# and confirm zero failures accumulate:
psql "$TINKER_CORE_OWNER_URL" -tAc \
  "SELECT last_failed_wal FROM pg_stat_archiver;"
```
`last_failed_wal` non-empty (or `failed_count` rising) is a
page-the-operator condition — archiving is the RPO story.

## 7. Upgrading an existing PostgreSQL 16 cluster to 18
Tinker's schema needs nothing version-specific: every core and PII
migration, pgcrypto and pg_trgm apply unchanged on 18 (full workspace
suite green on 18.6, 2026-09-30). The upgrade is a cluster operation:

1. Take a fresh base backup and verify it restores (R2 runbook) — the
   upgrade's rollback is that backup.
2. Install `postgresql-18` alongside 16. Stop `tinker-mcp` (all
   instances), then `tinker-postgres`.
3. `initdb` the new cluster as in §1, adding `--no-data-checksums`
   if `pg_controldata $OLD_PGDATA | grep checksum` shows version 0 —
   pg_upgrade refuses a checksum mismatch. Copy `postgresql.conf` (§2).
4. Skip §3–§4 for the new cluster: pg_upgrade carries roles,
   databases, grants and extensions across. Run, as postgres:
   ```sh
   /usr/lib/postgresql/18/bin/pg_upgrade --check \
     -b /usr/lib/postgresql/16/bin -B /usr/lib/postgresql/18/bin \
     -d /var/lib/postgresql/16/prod -D /var/lib/postgresql/18/prod
   ```
   then the same command without `--check` (add `--link` only if the
   backup in step 1 is verified: link mode makes the old cluster
   unusable once the new one starts).
5. Point the systemd unit at the 18 paths (this repo's unit already
   does), start it, `vacuumdb --all --analyze-in-stages` (pg_upgrade
   does not carry planner statistics), then start `tinker-mcp`.
6. Verify: §5 migration count, §6 archiving, and a `/healthz` probe.

