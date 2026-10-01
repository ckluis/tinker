# Tinker Disaster Recovery Runbook

Measured, drill-verified backup/restore procedures. All timings and
claims below come from the R2 DR drills (2026-09-28); nothing here is
theory. Drill evidence: `~/workspace/prodread/pg-dr/`.

Scope: PostgreSQL (core + PII databases), Redis, file bytes, secrets.
Out of scope: model-provider failover, DNS/TLS, multi-host replication
(no standby exists today — see Finding F5).

---

## 1. What must be backed up (the complete set)

| Component | Where it lives | In `pg_dump`? | Backup method |
|---|---|---|---|
| `tinker_core` database | PostgreSQL | — | `pg_dump -Fc` (superuser/BYPASSRLS, §2) |
| `tinker_pii` database | PostgreSQL | — | `pg_dump -Fc` (superuser/BYPASSRLS, §2) |
| WAL archive (for PITR) | **not configured today** | no | archive_command → durable off-host store (§4) |
| Base backups (for PITR) | **none taken today** | no | `pg_basebackup` on a schedule (§4) |
| File bytes | `./var/files` (or `TINKER_FILE_ROOT`) | **NO** — `stored_files` holds metadata only | filesystem snapshot / rsync to off-host |
| Secrets | `.secrets/.env.test` (DB passwords, API keys, provider keys) | **NO** | encrypted off-host copy; rotate after restore |
| Redis persistence | RDB + AOF files | n/a | Redis's own persistence (§5); RDB snapshots copied off-host |

**A database dump alone is not a backup of Tinker.** File bytes and
secrets live outside PostgreSQL. Restore all four rows or the system
does not come back.

---

## 2. Logical backup (pg_dump) — Drill A verified

### The RLS trap (Finding F1)

36 tables (e.g. `agent_attachments`, `auth_challenges`, `approval_requests`,
`spend_ledger`, `disclosure_audit`) have **FORCE ROW LEVEL SECURITY**.
`pg_dump` as the application owner role (`tinker_core`) **fails**:

```
pg_dump: error: query failed: ERROR: query would be affected by
row-level security policy for table "agent_attachments"
```

Backups **must** run as a superuser or a dedicated role with
`BYPASSRLS`. The app/owner credentials cannot produce a complete dump.

### Backup commands

```bash
# 13 MB database: core 402,871 bytes in 575 ms, pii 11,617 bytes in 225 ms (measured)
pg_dump -h <host> -U postgres tinker_core -Fc -f /backups/tinker_core-$(date +%F).dump
pg_dump -h <host> -U postgres tinker_pii  -Fc -f /backups/tinker_pii.dump
sha256sum /backups/*.dump > /backups/SHA256SUMS
```

Also back up roles (dumps reference `tinker_core`, `tinker_pii`,
`tinker_app`, `tinker_pii_app`):

```bash
pg_dumpall -h <host> -U postgres --roles-only -f /backups/roles.sql
```

### Restore commands (fresh cluster)

```bash
# 1. Pre-create roles BEFORE restore (dump assigns ownership to them)
psql -h <newhost> -U postgres -f /backups/roles.sql
for db in tinker_core tinker_pii; do
  psql -h <newhost> -U postgres -c "CREATE DATABASE $db OWNER ${db};"
done
psql -h <newhost> -U postgres -d tinker_core -c "CREATE EXTENSION pg_trgm;"
psql -h <newhost> -U postgres -d tinker_core -c "CREATE EXTENSION pgcrypto;"
psql -h <newhost> -U postgres -d tinker_pii  -c "CREATE EXTENSION pgcrypto;"

# 2. Restore with ownership/ACLs (measured: core 1063 ms, pii 127 ms, 0 errors)
pg_restore -h <newhost> -U postgres -d tinker_core /backups/tinker_core-<date>.dump
pg_restore -h <newhost> -U postgres -d tinker_pii  /backups/tinker_pii.dump
```

Do **not** use `--no-owner --no-acl` for a production restore: the app
roles need their grants or the app boots without working RLS.

### Verify the restore ("done" for Drill A)

```bash
# 1. Per-table row counts match on every table (drill: 105/105, 0 mismatches)
# 2. Content checksums match on key tables (drill: 8/8 md5 match)
for spec in "tinker_core:public:organizations" "tinker_core:public:ontology_objects" \
            "tinker_core:public:ontology_fields" "tinker_core:data:drorg_article" \
            "tinker_core:public:mutation_audit" "tinker_core:public:actors" \
            "tinker_pii:public:pii_refs"; do
  # SELECT md5(string_agg(md5(t::text),'' ORDER BY t::text)) FROM <table> t;
  # ... compare live vs restored
done

# 3. App boots against the restored DB (drill: tinker describe catalog OK,
#    drorg_article present)
TINKER_CORE_URL=<restored owner url> TINKER_APP_URL=<restored app url> \
  tinker describe --org <org-uuid> --role owner

# 4. C6 (machine credential) login works against the restored DB
#    (drill: POST /mcp -> 401 no key, 401 bad key, 200 + valid MCP
#    initialize response with good key)
tinker-cli mcp http --port <port>   # pointed at the restored DB
curl -X POST http://127.0.0.1:<port>/mcp \
  -H "Authorization: Bearer <tk_...>" -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"dr","version":"1"}}}'
```

Only API-key **hashes** are stored, so keys survive the restore; the
secret itself is never in the database.

---

## 3. Point-in-time recovery (PITR) — Drill B verified

### Exact production requirements

On the **primary** (the cluster being backed up):

```
wal_level      = replica      # minimum; 'logical' only if logical decoding is needed
archive_mode   = on
archive_command = 'test ! -f /wal-archive/%f && cp %p /wal-archive/%f'
                  # ^ must point at DURABLE OFF-HOST storage (S3/NFS), writable
                  #   by the postgres OS user. Verified: postgres cannot write
                  #   to /home/hatch on this platform (MAC confinement).
archive_timeout = 60          # bounds RPO: worst case ~60 s of WAL not yet archived
max_wal_senders = 5           # >= number of concurrent base backups + streaming
```

Replication access for `pg_basebackup`:

```sql
-- role used by the backup job (or use the superuser):
CREATE ROLE tinker_backup LOGIN REPLICATION PASSWORD '<strong>';
```

```ini
# pg_hba.conf — allow the backup role to open replication connections:
host  replication  tinker_backup  <backup-host>/32  scram-sha-256
```

On a schedule (cron/systemd):

```bash
pg_basebackup -h <primary> -U tinker_backup -D /backups/base/$(date +%F) \
  -Fp -Xs -P -c fast        # measured: 656 ms for a 46 MB cluster
```

Retain base backups + every WAL segment since the oldest base backup
you might restore from. **Archiving must be enabled before the base
backup** — segments are only archived from the moment `archive_mode`
is turned on.

### Recovery procedure (kill -9 tested)

```bash
# 1. Stop the dead primary, provision a fresh data directory.
rm -rf $PGDATA && mkdir -p $PGDATA && chmod 700 $PGDATA

# 2. Lay down the base backup (measured: 104 ms for 46 MB).
cp -a /backups/base/<date>/. $PGDATA/
rm -f $PGDATA/postmaster.pid $PGDATA/postmaster.opts

# 3. Point recovery at the WAL archive and pick the target.
cat > $PGDATA/postgresql.auto.conf <<EOF
restore_command = 'cp /wal-archive/%f %p'
recovery_target_time = '2026-09-28 21:33:37.404747+00'  # or recovery_target_name/xid/lsn
recovery_target_action = 'promote'
EOF
touch $PGDATA/recovery.signal

# 4. Start. The server replays WAL to the target, forks a new timeline,
#    and promotes itself to a writable primary.
pg_ctl -D $PGDATA -l recovery.log start
```

Drill B result: base backup + WAL traffic (100 baseline rows, then 50
"good" rows, then 50 "bad" rows, then `DROP TABLE`), kill -9, restore,
recover to the timestamp between "good" and "bad". Recovered: table
exists, 150 rows (100 baseline + 50 good), 0 bad rows. Log line:
`recovery stopping before commit of transaction 734`,
`selected new timeline ID: 2`.

### RPO / RTO (measured, this hardware)

| Metric | Value | Notes |
|---|---|---|
| RPO (PITR) | ≤ `archive_timeout` + segment fill time | every committed WAL segment archived before the kill was replayed; with `archive_timeout = 60`, worst case ~60 s |
| RTO (PITR) | base copy (~0.1 s) + WAL replay (~seconds for this size) | replay time scales with WAL volume since the base backup |
| Base backup | 656 ms / 46 MB cluster | scales with database size |

**Finding F2:** the pg-ensure dev cluster has `archive_command = (disabled)`.
PITR is impossible there today. Do not "fix" this by archiving to
`/var/tmp` — a rootfs roll wipes it, which is exactly when you need the
archive. The archive belongs off-host.

---

## 4. Redis — Drill C verified

Recommended production config (what the drill ran):

```
port 6379
appendonly yes
appendfsync everysec
save 60 1000
```

### Observed behavior (kill -9 tested)

| Persistence mode | Test | Result |
|---|---|---|
| AOF (`appendfsync everysec`) | 5,002 keys written, `kill -9` immediately after | **5,002/5,002 recovered**, recovery 72 ms |
| AOF (`appendfsync everysec`) | single SET then `kill -9` | recovered (fsync tick fired first) — loss window is real but ≤ ~1 s |
| RDB only (`save 60 1000`, `appendonly no`) | key before `BGSAVE`, key after, `kill -9` | pre-snapshot key recovered, **post-snapshot key LOST** |

### RPO / RTO (measured)

| Mode | RPO (observed) | RTO (observed) |
|---|---|---|
| AOF `everysec` | 0 lost across two kill -9s; bound = ~1 s of acknowledged writes | 72 ms for 5k keys |
| AOF `always` | 0 (every write fsynced) — costs write latency | same |
| RDB only | up to the snapshot interval (post-snapshot write provably lost) | ~1 s |

Copy RDB snapshots off-host on a schedule; the AOF alone on a single
disk is not a backup. Redis holds sessions, the signal fan-out
(`tinker:signals:{org}`, `tinker:signals:seq:{org}`) and the transform
cache — losing it logs users out and drops in-flight signals, but the
system of record (PostgreSQL) is unaffected.

### Recovery

```bash
# After kill -9 / host loss with persistence files intact:
redis-server /etc/redis/redis.conf --daemonize yes
# verify: redis-cli DBSIZE, spot-check session keys
```

---

## 5. Secrets handling

`.secrets/.env.test` (dev) — and whatever the production equivalent is —
contains database passwords, the C6 API-key issuance path, and model
provider keys. It is **not** in any database dump. Procedure:

1. Keep an encrypted off-host copy (age/sops/Vault — pick one, document it).
2. After any restore, verify every credential in it still works; **rotate**
   database passwords and provider keys after a real incident.
3. Never commit it; never put it in a dump artifact.

---

## 6. Findings (R2, 2026-09-28)

- **F1 — pg_dump fails with app credentials.** 36 force-RLS tables make
  owner-role `pg_dump` exit 1. Backups must run as superuser/BYPASSRLS.
- **F2 — No WAL archiving on the live cluster.** `archive_command` is
  `(disabled)`; PITR is impossible. Archiving to `/var/tmp` would be
  theater (rolls wipe it); the archive must be off-host.
- **F3 — No base-backup schedule.** Nothing to restore *from* for PITR.
- **F4 — File bytes and secrets are outside every DB dump.**
  `./var/files` (or `TINKER_FILE_ROOT`) and `.secrets/` need their own
  backup path or a "restored" system is missing files and credentials.
- **F5 — No standby / replication target.** RTO for total host loss is
  "rebuild from backups", not failover.
- **F6 — Backup role does not exist.** Production needs a `REPLICATION`
  backup role + `pg_hba` entry (exact DDL in §3); today only the
  superuser can take base backups.

## 7. Drill re-run checklist

- [ ] `cargo test -p tinker-m0 --test dr_seed -- --nocapture` (idempotent;
      org `drorg_1`, object `drorg_article`, 300 records)
- [ ] Drill A: dump → fresh cluster on a scratch port → counts 105/105 →
      md5 8/8 → `tinker describe` → C6 `/mcp` 401/401/200
- [ ] Drill B: throwaway cluster + archive → basebackup → traffic →
      kill -9 → recover to target → verify row sets
- [ ] Drill C: own redis, AOF+RDB → kill -9 → verify recovery + RPO spot
- [ ] Update the RPO/RTO table above with the new measurements
