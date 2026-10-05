# Changelog

Notable changes to Tinker. Per-item detail, with gate numbers and the test behind each claim, lives in [`STATUS.md`](STATUS.md), [`BACKLOG.md`](BACKLOG.md) and [`docs/history/hardening-log.md`](docs/history/hardening-log.md).

## Unreleased: first public release

### Added
- **Automations over sealed fields** (`tinker-automate`, [docs/automations.md](docs/automations.md)):
  - automation keys (`pk_…`) and `field:key` selects
  - an outbox written in the same transaction as each create, update, publish and ingest promotion
  - keyed conditions, plus `update_record`, `send_email` (recipient resolved from the vault at send time) and `webhook` actions
  - a depth-3 loop guard, a guessing rate limit (20 sealed literals per actor per hour), and runs that execute as the author's role
  - the MCP `automation` tool and a background worker in the web and MCP servers
- **Second-person reveal.** `reveal` needs a single-use `pii.reveal` approval for exactly that (object, record, field), decided by someone other than the requester. Adds the MCP tools `request_reveal` and `approvals`.
- **Crypto-shred erasure.** Per-record data-encryption keys; erasing a record destroys its keys.
- **PII by type.** Every `email` and `phone` field is sealed; text fields opt in. Adds `tinker-cli pii verify|retrofit|sweep`, with `pii verify` run as a test gate.
- **Sealed fields:**
  - masked reads in the compiler
  - exact match through an HMAC-SHA256 blind index
  - audited `reveal` and MCP `erase`
  - ingest sealing, with the landing tables scrubbed
  - `tinker-cli field make-sensitive` to retrofit a populated field
- **Four-eyes approvals.** The requester is recorded and can never decide.
- **OIDC** authorization-code flow with PKCE (S256), single-use `state` and a required `nonce`.
- **WebAuthn**, verified properly: client data, origin, rpIdHash, UP/UV, counter, and ES256/EdDSA signatures. MFA only when UV is set; registration endpoints added.
- Portable dev scripts `bin/dev-db.sh` and `bin/test.sh` (macOS and Linux), GitHub Actions CI, and a project page.

### Changed
- **PostgreSQL 18** is now the supported version (from 16).
- Vault DEKs are per subject (record), not per organization, and `rotate_dek` is per subject.
- The MCP front door has 12 tools; 5 of them need their scope granted by name.

### Fixed
- Findings from the [2026-09-30 evaluation](docs/history/2026-09-30-evaluation.md), across four rounds; round 1 alone fixed ten. Each fix has a regression test. The list is in the [hardening log](docs/history/hardening-log.md).
- `deploy/env/tinker.env.template` documented `TINKER_KEK` as base64, but the vault only parses hex.

### Removed
- The OIDC endpoint that accepted a bare `id_token`.
- Vendored PostgreSQL 16 / Redis `.deb` packages.

## M0–M8 and production readiness (2026-09-24 → 2026-09-30)

Gated milestone build:
- ontology → real tables
- multi-tenant runtime
- governed reactivity
- packs
- schema evolution
- work and communications
- ingestion
- agents and cost
- authority transfer

Then the agent front door (items 43–49) and the production-readiness workstream:
- **R1:** 24-hour soak
- **R2:** DR drills
- **R3:** internal adversarial review
- **R4:** search backend decision
- **R5:** deployment kit

See [`STATUS.md`](STATUS.md).
