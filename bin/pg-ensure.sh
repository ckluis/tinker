#!/bin/bash
# pg-ensure.sh — self-healing dev PostgreSQL for Tinker.
#
# WHY THIS EXISTS (2026-09-24): the cell rootfs rolls wipe /usr (binaries)
# and /var/lib/postgresql (data). Non-root users are MAC-confined to
# tmpfs (/tmp, /var/tmp) — no persistent location is writable by the
# postgres user. So dev database DATA is inherently ephemeral here.
#
# This script rebuilds everything idempotently in ~60s:
#   1. Installs postgresql-16 from the apt cache (also recorded in the
#      platform os-intent ledger, so future rolls replay the binaries).
#   2. initdb a fresh cluster in /var/tmp/pgdata-tinker (2GB tmpfs,
#      not subject to the /tmp cleaner).
#   3. Starts the postmaster on 127.0.0.1:5432 if not running.
#   4. Creates tinker roles + databases (dev passwords from
#      .secrets/.env.test).
#   5. Runs core + PII migrations.
#
# Test fixtures are seeded by the test suites themselves, so a rebuilt
# database is immediately usable. Safe to run any time; it never drops
# an existing live cluster.
set -u

PGDATA=/var/tmp/pgdata-tinker
PGBIN=/usr/lib/postgresql/16/bin
PORT=5432
HERE="$(cd "$(dirname "$0")/.." && pwd)"

# 1. Binaries (cache-first; the platform ledger replays these on rolls).
if [ ! -x "$PGBIN/initdb" ]; then
    echo "pg-ensure: installing postgresql-16 from apt cache..."
    dpkg --force-depends -i /var/cache/apt/archives/libpq5_16.15-0ubuntu0.24.04.1_amd64.deb \
        /var/cache/apt/archives/postgresql-client-common_257build1.1_all.deb \
        /var/cache/apt/archives/postgresql-common_257build1.1_all.deb \
        /var/cache/apt/archives/postgresql-client-16_16.15-0ubuntu0.24.04.1_amd64.deb \
        /var/cache/apt/archives/postgresql-16_16.15-0ubuntu0.24.04.1_amd64.deb \
        >/dev/null 2>&1 || true
fi
# Fallback: vendored debs survive rolls that wipe the apt cache (2026-09-25).
if [ ! -x "$PGBIN/initdb" ]; then
    VENDOR="$HERE/bin/vendor/pg"
    if [ -f "$VENDOR/postgresql-16_16.15-0ubuntu0.24.04.1_amd64.deb" ]; then
        echo "pg-ensure: apt cache empty, installing postgresql-16 from vendored debs..."
        dpkg --force-depends -i "$VENDOR"/libpq5_16.15-0ubuntu0.24.04.1_amd64.deb \
            "$VENDOR"/postgresql-client-common_257build1.1_all.deb \
            "$VENDOR"/postgresql-common_257build1.1_all.deb \
            "$VENDOR"/postgresql-client-16_16.15-0ubuntu0.24.04.1_amd64.deb \
            "$VENDOR"/postgresql-16_16.15-0ubuntu0.24.04.1_amd64.deb \
            >/dev/null 2>&1 || true
    fi
fi
[ -x "$PGBIN/initdb" ] || { echo "pg-ensure: FATAL: no postgres binaries" >&2; exit 1; }

# 2. Cluster.
if [ ! -f "$PGDATA/PG_VERSION" ]; then
    echo "pg-ensure: initdb fresh cluster at $PGDATA"
    rm -rf "$PGDATA" /var/tmp/pgdata-tinker.pw
    su -s /bin/sh postgres -c "umask 077; openssl rand -base64 32 > /var/tmp/pgdata-tinker.pw; mkdir -p '$PGDATA' && '$PGBIN/initdb' -D '$PGDATA' -E UTF8 --auth=scram-sha-256 --pwfile=/var/tmp/pgdata-tinker.pw" \
        || { echo "pg-ensure: FATAL: initdb failed" >&2; exit 1; }
fi

# 3. Postmaster.
if ! su -s /bin/sh postgres -c "'$PGBIN/pg_ctl' -D '$PGDATA' status" >/dev/null 2>&1; then
    echo "pg-ensure: starting postmaster on 127.0.0.1:$PORT"
    su -s /bin/sh postgres -c "'$PGBIN/pg_ctl' -D '$PGDATA' -l /var/tmp/pgdata-tinker.log -o '-p $PORT -k /var/tmp -c listen_addresses=127.0.0.1' start" \
        || { echo "pg-ensure: FATAL: pg_ctl start failed" >&2; tail -20 /var/tmp/pgdata-tinker.log >&2; exit 1; }
    sleep 2
fi

export PATH="$HOME/.cargo/bin:$PATH"

# Credentials come from .secrets/.env.test (dev-only).
set -a
# shellcheck disable=SC1091
. "$HERE/.secrets/.env.test"
set +a
pw_of() { printf '%s' "$1" | sed -n 's|.*://[^:]*:\([^@]*\)@.*|\1|p'; }
CORE_PW="$(pw_of "$TINKER_CORE_OWNER_URL")"
PII_PW="$(pw_of "$TINKER_PII_OWNER_URL")"
APP_PW="$(pw_of "$TINKER_CORE_URL")"
PII_APP_PW="$(pw_of "$TINKER_PII_URL")"

# 4. Roles + databases + extensions: the ONE-SHOT PRIVILEGED BOOTSTRAP.
# Everything in this section runs as the postgres superuser over the
# local socket, and it is idempotent: re-running it converges the
# cluster to the declared privilege shape instead of accumulating
# grants.
#
# Privilege model (post-M8 backlog item: one-shot privileged bootstrap,
# then least-privilege owners):
# - tinker_core / tinker_pii: LOGIN + CREATEROLE only. CREATEROLE is the
#   minimum for the supported app-role password rotation
#   (tinker_db::rotate_app_role_passwords runs ALTER ROLE over owner
#   handles) and for the frozen 0001 role-creation backstop. They are
#   NOT superuser and NOT createdb. SUPERUSER was previously needed for
#   CREATE EXTENSION (pgcrypto, pg_trgm); extensions are now installed
#   below, inside this bootstrap, so migrations never need it. The
#   owners also hold ADMIN OPTION (only) on their app role, which
#   PostgreSQL requires alongside CREATEROLE to ALTER another role —
#   granted below, never used for privilege inheritance.
# - tinker_app / tinker_pii_app: plain LOGIN. No DDL, no role admin.
#   App passwords are (re)set here from the environment on every run,
#   so a stale default can never survive provisioning.
SQL_FILE=/var/tmp/pg-ensure.sql
# Written by the postgres user (root-created 600 files are unreadable to
# it); passwords are expanded by this shell before the handoff.
# NOTE: /var/tmp is tmpfs shared with the postgres user; a stale
# root-owned file from a failed run must be cleared first.
rm -f "$SQL_FILE"
su -s /bin/sh postgres -c "umask 077; cat > '$SQL_FILE'" <<EOF
DO \$\$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='tinker_core') THEN
    CREATE ROLE tinker_core LOGIN CREATEROLE PASSWORD '$CORE_PW';
  ELSE
    ALTER ROLE tinker_core WITH LOGIN CREATEROLE NOSUPERUSER NOCREATEDB PASSWORD '$CORE_PW';
  END IF;
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='tinker_app') THEN
    CREATE ROLE tinker_app LOGIN PASSWORD '$APP_PW';
  ELSE
    ALTER ROLE tinker_app WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE PASSWORD '$APP_PW';
  END IF;
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='tinker_pii') THEN
    CREATE ROLE tinker_pii LOGIN CREATEROLE PASSWORD '$PII_PW';
  ELSE
    ALTER ROLE tinker_pii WITH LOGIN CREATEROLE NOSUPERUSER NOCREATEDB PASSWORD '$PII_PW';
  END IF;
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='tinker_pii_app') THEN
    CREATE ROLE tinker_pii_app LOGIN PASSWORD '$PII_APP_PW';
  ELSE
    ALTER ROLE tinker_pii_app WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE PASSWORD '$PII_APP_PW';
  END IF;
END
\$\$;
SELECT 'CREATE DATABASE tinker_core OWNER tinker_core'
  WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname='tinker_core')\gexec
SELECT 'CREATE DATABASE tinker_pii OWNER tinker_pii'
  WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname='tinker_pii')\gexec
-- ADMIN OPTION (not a privilege grant for use): lets the least-privilege
-- owners ALTER ROLE on exactly their app role (password rotation).
-- GRANT is idempotent, so re-running converges.
GRANT tinker_app TO tinker_core WITH ADMIN OPTION;
GRANT tinker_pii_app TO tinker_pii WITH ADMIN OPTION;
EOF
su -s /bin/sh postgres -c "PGPASSWORD=\$(cat /var/tmp/pgdata-tinker.pw) '$PGBIN/psql' -h /var/tmp -p '$PORT' -d postgres -v ON_ERROR_STOP=1 -q -f '$SQL_FILE'" \
    || { echo "pg-ensure: FATAL: role/db setup failed" >&2; exit 1; }
rm -f "$SQL_FILE"

# 4b. Extensions, still inside the one-shot bootstrap: CREATE EXTENSION
# needs superuser, and extensions are database-scoped, so the postgres
# superuser installs them into each database here. Migrations 0001
# (pgcrypto) and 0005 (pg_trgm) then hit IF NOT EXISTS no-ops, and the
# least-privilege owners never need SUPERUSER.
for _db in tinker_core tinker_pii; do
  su -s /bin/sh postgres -c "PGPASSWORD=\$(cat /var/tmp/pgdata-tinker.pw) '$PGBIN/psql' -h /var/tmp -p '$PORT' -d '$_db' -v ON_ERROR_STOP=1 -q -c 'CREATE EXTENSION IF NOT EXISTS pgcrypto;'" \
    || { echo "pg-ensure: FATAL: pgcrypto setup failed ($_db)" >&2; exit 1; }
done
su -s /bin/sh postgres -c "PGPASSWORD=\$(cat /var/tmp/pgdata-tinker.pw) '$PGBIN/psql' -h /var/tmp -p '$PORT' -d tinker_core -v ON_ERROR_STOP=1 -q -c 'CREATE EXTENSION IF NOT EXISTS pg_trgm;'" \
  || { echo "pg-ensure: FATAL: pg_trgm setup failed" >&2; exit 1; }

# 5. Migrations. NOTE (2026-09-24): sqlx::migrate! embeds migration
# files at compile time, and cargo did not track the migrations
# directory — a stale `migrate` example binary once skipped 0012 and
# then failed with VersionMissing(13) on a DB that already had it.
# tinker-db/build.rs now emits rerun-if-changed for the migrations
# dirs, and we verify the applied versions match the source files
# after running: a mismatch fails loudly instead of "succeeding".
export DATABASE_URL="$TINKER_CORE_OWNER_URL"
(cd "$HERE" && cargo run -q -p tinker-db --example migrate) || {
    echo "pg-ensure: FATAL: migrations failed" >&2; exit 1
}
CORE_EXPECTED=$(ls "$HERE/crates/tinker-db/migrations/core"/*.sql | wc -l)
PII_EXPECTED=$(ls "$HERE/crates/tinker-db/migrations/pii"/*.sql | wc -l)
CORE_APPLIED=$(su -s /bin/sh postgres -c "PGPASSWORD=\$(cat /var/tmp/pgdata-tinker.pw) '$PGBIN/psql' -h /var/tmp -p '$PORT' -d tinker_core -tAc 'SELECT count(*) FROM _sqlx_migrations'" 2>/dev/null)
PII_APPLIED=$(su -s /bin/sh postgres -c "PGPASSWORD=\$(cat /var/tmp/pgdata-tinker.pw) '$PGBIN/psql' -h /var/tmp -p '$PORT' -d tinker_pii -tAc 'SELECT count(*) FROM _sqlx_migrations'" 2>/dev/null)
if [ "$CORE_APPLIED" != "$CORE_EXPECTED" ] || [ "$PII_APPLIED" != "$PII_EXPECTED" ]; then
    echo "pg-ensure: FATAL: migration count mismatch (core $CORE_APPLIED/$CORE_EXPECTED, pii $PII_APPLIED/$PII_EXPECTED) — stale binary?" >&2
    exit 1
fi
# 5b. Checksum verification. Counts catch a stale binary's *missing*
# migrations, but not a migration file edited after it was applied
# (applied migrations are immutable). Compare the SHA-384 of every .sql
# file on disk against _sqlx_migrations; any drift fails closed.
(cd "$HERE" && cargo run -q -p tinker-db --example verify-migrations -- \
    "$HERE/crates/tinker-db/migrations/core" "$HERE/crates/tinker-db/migrations/pii") || {
    echo "pg-ensure: FATAL: migration checksum mismatch" >&2; exit 1
}

echo "pg-ensure: postgres ready on 127.0.0.1:$PORT (data dir $PGDATA, ephemeral)"
