# Tinker

**Build internal tools on data you can't see.**

Tinker is an ontology-driven builder for internal tools, written in Rust on PostgreSQL 18. You define an object once: its fields, types, validation, relations, row policies and lifecycle. Tinker turns it into a real Postgres table behind row-level security, a governed HTTP API and an MCP front door for agents.

Personal data is sealed by type. Every email and phone field lives in a separate encrypted vault. Every read gets a mask, automations get a stable key, and a person sees the plaintext only after a second person approves.

**[Project page →](https://ckluis.github.io/tinker/)**

[![CI](https://github.com/ckluis/tinker/actions/workflows/ci.yml/badge.svg)](https://github.com/ckluis/tinker/actions/workflows/ci.yml)
![Rust](https://img.shields.io/badge/rust-stable-orange)
![PostgreSQL](https://img.shields.io/badge/postgres-18-336791)
![License](https://img.shields.io/badge/license-MIT-blue)

---

## What makes it different

**One field, three faces.** A sealed field is never stored in the core database. The row holds a vault reference and a keyed blind index (HMAC-SHA256), and each audience gets exactly what it needs:

| Face | Who gets it | Example |
|---|---|---|
| **Mask** | every query, dashboard, cache, search result and agent | `"••••••"` |
| **Key** | automations, webhooks, run logs, `field:key` selects | `"pk_3f9a0c71e2…b84d"` |
| **Value** | one person, one field, one time, with a stated purpose and a second approver | `"ada@analytical.engine"` |

Exact-match lookups (`eq`, `ne`, `in`) still work through the blind index. Operators that would leak the value, such as `contains`, ranges and sorting, are refused.

**Every path goes through one governor.** The builder, HTTP API, CLI, live grids, search, dashboards and agents all compile through one typed query compiler. That compiler applies role projection, row policies and masking in one place.

**Tenancy is enforced by Postgres.** Every request runs in a transaction that sets `SET LOCAL app.organization_id`, on a role that cannot bypass RLS. Rows you can't see return `not_found`, the same as rows that don't exist.

**Automations on keys, not values.** Conditions compare keys, and a literal you type is turned into a key when the automation is saved. Actions resolve values only at the moment they run. `send_email` looks up the recipient from the vault at send time and never writes it back. Loops stop at depth 3, and guessing sealed values through conditions is rate-limited. Runs execute as the author's role, re-checked on every run.

**Erasure by crypto-shred.** Every record has its own data-encryption key (AES-256-GCM, wrapped by a rotating KEK). Erasing a record destroys that key, so any copy of its ciphertext becomes unreadable.

**An agent front door that teaches itself.** The MCP server (stdio and HTTP/SSE) is self-describing. An agent with nothing but a `tk_` machine key can discover the schema and the governed write paths. Five of its twelve tools (`reveal`, `request_reveal`, `approvals`, `erase` and `automation`) need their scope granted by name; a blanket `mcp:tools` scope does not cover them.

## Status

Tinker was built in gated milestones (M0–M8), then hardened in four review rounds. The full suite passes on PostgreSQL 18: **662 passed, 0 failed, 1 ignored** (a timing benchmark). That run includes a real headless-browser test, and `fmt` and `clippy -D warnings` are clean.

Every capability claim in [`STATUS.md`](STATUS.md) names the test that proves it.

It has **not** been deployed publicly and has **not** had an external security audit. See [Known limits](#known-limits).

## Quickstart

Requirements: stable Rust, PostgreSQL 18, Redis, `openssl`, and about 4 GB of free disk for a test build. A headless Chrome or Chromium is optional; it's used by the browser test.

```sh
# macOS
brew install postgresql@18 redis
# Debian/Ubuntu: install postgresql-18 from apt.postgresql.org, plus redis-server
```

Run these from the repository root:

```sh
bin/dev-db.sh                 # private PG18 cluster on 127.0.0.1:5440 in .pgdata/,
                              # random dev secrets in .secrets/.env.test, migrations
eval "$(bin/dev-db.sh env)"   # export the connection URLs and keys

bin/test.sh                   # full suite + browser test + the `pii verify` gate
# test: passed 662 failed 0 ignored 1
# test: pii verify ok

bin/test.sh -p tinker-mcp     # any cargo-test arguments pass through
bin/dev-db.sh stop            # stop the cluster
```

Everything runs as your own user. Nothing touches the machine's default Postgres cluster.

### Running the servers

```sh
cargo run -p tinker-web --bin tinker                 # web tier on 127.0.0.1:8080 (TINKER_ADDR)

cargo run -p tinker-m7 --bin tinker-cli -- \
  mcp key issue --org <slug> --name my-agent --scopes mcp:tools

TINKER_API_KEY=tk_… cargo run -p tinker-mcp          # MCP over stdio
cargo run -p tinker-mcp -- serve                     # MCP over HTTP/SSE
```

The servers start with the vault when `TINKER_KEK`, `TINKER_BLIND_INDEX_KEY` and the PII database URLs are set. If none of them are set, writes to sealed fields are refused. If only some are set, startup fails.

Other `tinker-cli` commands:
- `pii verify`: fails if any email or phone field is not vault-backed
- `pii retrofit`: seals existing plaintext
- `pii sweep`: removes orphaned vault values
- `field make-sensitive`: seals a populated text field

Production layout (Postgres, Redis, TLS proxy, systemd units) lives in [`deploy/`](deploy/README.md).

## Architecture

It's one Cargo workspace of 29 crates, layered so the data plane knows nothing about the surfaces built on it.

| Layer | Crates |
|---|---|
| **Data plane** | `tinker-core` (tenant context, ids, blind index) · `tinker-ontology` (schema → DDL, sealing, governed writes) · `tinker-query` (typed compiler) · `tinker-db` (the two stores) · `tinker-vault` (PII projector) · `tinker-search` |
| **Identity** | `tinker-auth` (WebAuthn ES256/EdDSA, OIDC code flow + PKCE, `tk_` keys) · `tinker-identity` (sessions, grants) |
| **Surfaces** | `tinker-web` · `tinker-apps` · `tinker-live` (SSE grids) · `tinker-comms` · `tinker-agents` · `tinker-ingest` · `tinker-evolve` · `tinker-durable` · `tinker-packs` · `tinker-transfer` · `tinker-automate` |
| **Front door** | `tinker-mcp` (stdio + HTTP/SSE) · `tinker describe` · `tinker-cli` |
| **Milestone suites** | `tinker-m0` … `tinker-m8`: integration tests, one gated crate per milestone |

The milestones:
- M0: ontology → tables, PII split, durable workflows
- M1: multi-tenant runtime and auth
- M2: governed reactivity
- M3: packs
- M4: schema evolution
- M5: work and communications
- M6: governed ingestion
- M7: context, agents and cost
- M8: authority transfer and hardening

See [`docs/overview.md`](docs/overview.md) for the request lifecycle in detail.

## Documentation

| Doc | What it covers |
|---|---|
| [`docs/overview.md`](docs/overview.md) | Architecture and request lifecycle |
| [`docs/pii-sensitive-fields.md`](docs/pii-sensitive-fields.md) | Sealed fields, blind index, reveal, erasure, retrofit |
| [`docs/automations.md`](docs/automations.md) | Automation keys, the engine and its guards (decisions A1–A10) |
| [`docs/threat-model.md`](docs/threat-model.md) | Threat model and the internal adversarial review |
| [`docs/disaster-recovery.md`](docs/disaster-recovery.md) | Backup, restore and PITR drills with measured RPO/RTO |
| [`docs/spec-agent-front-door.md`](docs/spec-agent-front-door.md) | The MCP front-door spec |
| [`docs/one-server-efficiency.md`](docs/one-server-efficiency.md), [`docs/scale-out-spike.md`](docs/scale-out-spike.md) | Performance measurements |
| [`STATUS.md`](STATUS.md) | Capability ledger: every claim bound to a passing test |
| [`BACKLOG.md`](BACKLOG.md) | Deferred work, each item with the reason it was deferred |
| [`docs/history/`](docs/history/README.md) | The independent evaluation and the four hardening rounds that followed |
| [`CHANGELOG.md`](CHANGELOG.md) | Notable changes |

## Known limits

- **No external security audit.** The adversarial review was internal and is labelled that way.
- **Not deployed publicly.** The `deploy/` kit has been validated locally only.
- **Email.** Automation emails are queued, but the servers ship with no real email provider configured.
- **Automation actions are not one transaction.** If a later action in a run fails, the earlier ones stand and the run is not retried.
- **Crypto-shred and backups.** A backup that also contains `wrapped_deks` still holds the key until it ages out. Back up the key table on a shorter retention than the values.
- **Legacy values.** Values sealed before per-record keys are destroyed row by row; their shared legacy key can't be shredded.
- **Search.** Semantic ranking was measured with a pseudo-embedding, and TIN full-text search is blocked upstream.

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md). To report a security issue, see [`SECURITY.md`](SECURITY.md).

## License

[MIT](LICENSE)
