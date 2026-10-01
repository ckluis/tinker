# Secrets rule: environment, never the repo

This is a hard rule, not a suggestion.

1. **All secrets arrive via environment variables** (systemd
   `EnvironmentFile=/etc/tinker/tinker-mcp.env`, mode `0600`,
   owned `root:tinker`). The template in this directory lists every
   variable; the filled-in file lives ONLY on the host.
2. **No secret ever lands in git.** Not in `deploy/`, not in
   `docs/`, not in a "temporary" script. The template's
   `__PLACEHOLDER__` values are unguessable-shaped on purpose so a
   `grep -rn "sk-\|BEGIN PRIVATE\|postgres://.*:.*@"` sweep can prove a
   tree clean. (The one exception is `bin/pg-ensure.sh`'s
   `.secrets/.env.test`, which is DEV-ONLY and git-ignored.)
3. **Rotation is designed in, not bolted on:**
   - DB app-role passwords: `tinker_db::rotate_app_role_passwords`
     (owners hold CREATEROLE + ADMIN OPTION on the app role exactly for
     this; see `deploy/postgres/initdb-and-bootstrap.md`).
   - `TINKER_KEK`: set `TINKER_KEK_PREVIOUS` to the old key during
     rotation; the vault decrypts with current-then-previous.
   - C6 machine keys (`tk_...`): `tinker-cli mcp key rotate` /
     `revoke`; revocation takes effect on the next HTTP request (the
     serve tier re-verifies the Bearer key per request).
   - Redis `requirepass`: change in `redis.conf` + `TINKER_REDIS_URL`,
     `CONFIG REWRITE` or restart.
4. **Key material is never logged.** `tinker-mcp` drops the Bearer key
   after per-request verification and logs only method names, never
   params. The nginx access log records client IPs — treat it as
   sensitive and rotate it (see `deploy/logging/`).
5. **Break-glass:** the renamed redis commands' new names and the
   postgres superuser password live in the operator's secret store
   (e.g. age-encrypted file, Vault, or the hoster's secret manager) —
   never in this repo, never in chat logs.
