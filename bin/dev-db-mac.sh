#!/bin/bash
# dev-db-mac.sh — macOS (Homebrew) dev PostgreSQL for Tinker.
#
# The macOS counterpart of bin/pg-ensure.sh (which targets the Ubuntu
# cell: apt/dpkg, `su postgres`, tmpfs). Same privilege shape, different
# plumbing:
#   1. Homebrew PostgreSQL 18 (override with TINKER_PG_BIN).
#   2. A private cluster in .pgdata/ (gitignored) on 127.0.0.1:$PORT —
#      never the machine's default cluster. Superuser `postgres` over the
#      cluster's own unix socket (trust); TCP is scram-sha-256.
#   3. .secrets/.env.test generated once with random dev passwords and a
#      random KEK; reused on every later run.
#   4. Roles, databases and extensions — the one-shot privileged
#      bootstrap, identical to pg-ensure.sh §4/§4b.
#   5. Migrations via the tinker-db `migrate` example, then the same
#      count + checksum verification as pg-ensure.sh §5.
#
# Idempotent. `bin/dev-db-mac.sh stop` stops the cluster;
# `bin/dev-db-mac.sh env` prints `export` lines for the test env.
set -euo pipefail

HERE="$(cd "$(dirname "$0")/.." && pwd)"
PGBIN="${TINKER_PG_BIN:-/opt/homebrew/opt/postgresql@18/bin}"
PGDATA="$HERE/.pgdata"
PORT="${TINKER_PG_PORT:-5440}"
SECRETS="$HERE/.secrets/.env.test"
export PATH="/opt/homebrew/opt/rustup/bin:$HOME/.cargo/bin:$PATH"

[ -x "$PGBIN/initdb" ] || { echo "dev-db: FATAL: no postgres binaries at $PGBIN" >&2; exit 1; }

case "${1:-up}" in
  stop) "$PGBIN/pg_ctl" -D "$PGDATA" stop -m fast; exit 0 ;;
  env)  sed -n 's/^\([A-Z_]*=.*\)$/export \1/p' "$SECRETS"; exit 0 ;;
  up)   ;;
  *)    echo "usage: $0 [up|stop|env]" >&2; exit 2 ;;
esac

# 3. Secrets (first run only).
if [ ! -f "$SECRETS" ]; then
  mkdir -p "$(dirname "$SECRETS")"
  pw() { openssl rand -hex 16; }
  umask 077
  cat > "$SECRETS" <<EOF
TINKER_CORE_OWNER_URL=postgres://tinker_core:$(pw)@127.0.0.1:$PORT/tinker_core
TINKER_CORE_URL=postgres://tinker_app:$(pw)@127.0.0.1:$PORT/tinker_core
TINKER_PII_OWNER_URL=postgres://tinker_pii:$(pw)@127.0.0.1:$PORT/tinker_pii
TINKER_PII_URL=postgres://tinker_pii_app:$(pw)@127.0.0.1:$PORT/tinker_pii
TINKER_KEK=$(openssl rand -hex 32)
TINKER_BLIND_INDEX_KEY=$(openssl rand -hex 32)
TINKER_FILE_ROOT=$HERE/.devfiles
EOF
  echo "dev-db: wrote $SECRETS"
fi
# Keys added after a secrets file was first written (sensitive fields:
# docs/pii-sensitive-fields.md). Appended once, never rotated here.
if ! grep -q '^TINKER_BLIND_INDEX_KEY=' "$SECRETS"; then
  echo "TINKER_BLIND_INDEX_KEY=$(openssl rand -hex 32)" >> "$SECRETS"
  echo "dev-db: added TINKER_BLIND_INDEX_KEY to $SECRETS"
fi
set -a; . "$SECRETS"; set +a
pw_of() { printf '%s' "$1" | sed -n 's|.*://[^:]*:\([^@]*\)@.*|\1|p'; }
CORE_PW="$(pw_of "$TINKER_CORE_OWNER_URL")"
PII_PW="$(pw_of "$TINKER_PII_OWNER_URL")"
APP_PW="$(pw_of "$TINKER_CORE_URL")"
PII_APP_PW="$(pw_of "$TINKER_PII_URL")"
mkdir -p "$TINKER_FILE_ROOT"

# 2. Cluster.
if [ ! -f "$PGDATA/PG_VERSION" ]; then
  echo "dev-db: initdb $PGDATA ($("$PGBIN/postgres" --version))"
  "$PGBIN/initdb" -D "$PGDATA" -U postgres -E UTF8 --locale=C \
    --auth-local=trust --auth-host=scram-sha-256 >/dev/null
fi
if ! "$PGBIN/pg_ctl" -D "$PGDATA" status >/dev/null 2>&1; then
  echo "dev-db: starting postgres on 127.0.0.1:$PORT"
  "$PGBIN/pg_ctl" -D "$PGDATA" -l "$PGDATA/server.log" -w \
    -o "-p $PORT -k '$PGDATA' -c listen_addresses=127.0.0.1 -c max_connections=400" start >/dev/null
fi
psql_su() { "$PGBIN/psql" -h "$PGDATA" -p "$PORT" -U postgres -v ON_ERROR_STOP=1 -q "$@"; }

# 4. Roles + databases + extensions (mirrors pg-ensure.sh §4/§4b).
psql_su -d postgres <<EOF
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
GRANT tinker_app TO tinker_core WITH ADMIN OPTION;
GRANT tinker_pii_app TO tinker_pii WITH ADMIN OPTION;
EOF
for db in tinker_core tinker_pii; do
  psql_su -d "$db" -c 'CREATE EXTENSION IF NOT EXISTS pgcrypto;'
done
psql_su -d tinker_core -c 'CREATE EXTENSION IF NOT EXISTS pg_trgm;'

# 5. Migrations + verification (mirrors pg-ensure.sh §5/§5b).
(cd "$HERE" && cargo run -q -p tinker-db --example migrate)
CORE_EXPECTED=$(ls "$HERE/crates/tinker-db/migrations/core"/*.sql | wc -l | tr -d ' ')
PII_EXPECTED=$(ls "$HERE/crates/tinker-db/migrations/pii"/*.sql | wc -l | tr -d ' ')
CORE_APPLIED=$(psql_su -d tinker_core -tAc 'SELECT count(*) FROM _sqlx_migrations')
PII_APPLIED=$(psql_su -d tinker_pii -tAc 'SELECT count(*) FROM _sqlx_migrations')
if [ "$CORE_APPLIED" != "$CORE_EXPECTED" ] || [ "$PII_APPLIED" != "$PII_EXPECTED" ]; then
  echo "dev-db: FATAL: migration count mismatch (core $CORE_APPLIED/$CORE_EXPECTED, pii $PII_APPLIED/$PII_EXPECTED)" >&2
  exit 1
fi
(cd "$HERE" && cargo run -q -p tinker-db --example verify-migrations -- \
  "$HERE/crates/tinker-db/migrations/core" "$HERE/crates/tinker-db/migrations/pii")

echo "dev-db: ready on 127.0.0.1:$PORT ($("$PGBIN/postgres" --version)); env: eval \"\$(bin/dev-db-mac.sh env)\""
