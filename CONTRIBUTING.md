# Contributing

Thanks for looking. Tinker has a few house rules that keep it honest.

## Setup

```sh
bin/dev-db.sh                # private PostgreSQL 18 cluster in .pgdata/ (port 5440)
eval "$(bin/dev-db.sh env)"  # connection URLs, KEK, blind-index key
bin/test.sh                  # full suite, then the `pii verify` gate
```

You need stable Rust, PostgreSQL 18, Redis and `openssl`. A headless Chrome or Chromium is optional; it's used by the browser test. `DATABASE_URL` must point at the dev cluster when you build, because `sqlx::query!` checks queries at compile time. `bin/test.sh` sets it for you.

A full debug build of every test binary is large. `bin/test.sh` builds with `CARGO_INCREMENTAL=0` and line-table debug info, which takes about 4 GB.

## Before you open a PR

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
bin/test.sh
```

CI runs the same three steps.

## House rules

- **Every claim names its test.** A new capability gets a test that proves it, and an entry in [`STATUS.md`](STATUS.md) that names the test. For a fix, check that the test fails with the fix removed.
- **Fail closed.** A missing or misconfigured dependency produces a loud, typed error. Never fall back silently to a weaker path.
- **One governor.** Reads go through `tinker-query` and writes through the governed mutation paths in `tinker-ontology`. Don't add a side door that bypasses projection, row policy, masking or the automation outbox.
- **No plaintext PII.** Email and phone values, and any text field marked sensitive, never land in the core database, logs, audit rows, caches, run logs or webhook payloads. `pii verify` must stay green.
- **Migrations are append-only.** Applied migrations are checksum-verified. Add a new file; never edit an old one.
- **Deferred work is written down.** If you leave something out, record it in [`BACKLOG.md`](BACKLOG.md) with the reason.

## Reporting security issues

Please don't open a public issue. See [`SECURITY.md`](SECURITY.md).
