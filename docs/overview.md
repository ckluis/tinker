# Tinker — architecture overview

## What it is

Tinker is an **ontology-driven application platform** for internal tools, written in Rust and backed by PostgreSQL 18 and Redis.

You define data objects once, with their fields, types, validation, relations, row-level policies and lifecycles. Tinker then:
- materializes them as real Postgres tables
- enforces tenant isolation in the database itself
- exposes the objects through governed HTTP, CLI and agent interfaces

Think of a Directus-style data platform, but in Rust, multi-tenant by construction, designed for LLM agents first, and with personal data sealed by type.

The agent-first bet is that Tinker's APIs exist in no model's training data, so the framework has to **teach itself**. `tinker describe` and the MCP server let an agent with nothing but a credential:
- discover the schema
- learn the governed mutation paths
- do correct work without reading human docs

Three timed, independently verified experiments measured whether static skill docs add anything on top of the MCP. Every verdict was a loss or a tie, which means the MCP documents itself.

## Architecture

It's one Cargo workspace (`crates/`), in layers.

**Milestones M0–M8** (`tinker-m0` … `tinker-m8`) were built in order, and each had to pass its gate before the next began. Each crate holds that milestone's integration suite:

| Milestone | Scope |
|---|---|
| M0 | Foundation: ontology → real tables, PII separation, durable workflows |
| M1 | Multi-tenant app runtime: auth, sessions, rendering |
| M2 | Governed reactivity |
| M3 | Pack ontology |
| M4 | Schema evolution: versioned, canary, promote |
| M5 | Native work and communications |
| M6 | Governed ingestion |
| M7 | Context, agents and cost accounting |
| M8 | Authority transfer and hardening |

**Data plane:**
- `tinker-core`: tenant context, ids, errors, blind index
- `tinker-ontology`: schema → DDL, sealing, governed writes
- `tinker-query`: the typed compiler
- `tinker-db`: the two physically separate stores
- `tinker-search`

**PII:** `tinker-vault` keeps personal data in a separate encrypted store. Core SQL *cannot* join to it, and a test proves that.

**Identity:**
- `tinker-auth`: WebAuthn, OIDC code flow, `tk_` machine keys
- `tinker-identity`: sessions and grants

**Surfaces:**

| Crate | What it is |
|---|---|
| `tinker-web` | HTTP and schema builder |
| `tinker-apps` | Versioned apps rendered server-side |
| `tinker-live` | SSE grids |
| `tinker-comms` | Email outbox |
| `tinker-agents` | Context, approvals, cost |
| `tinker-ingest` | Connectors, master data, AI mapping proposals |
| `tinker-evolve` | Schema evolution |
| `tinker-durable` | DBOS-style workflows on Postgres |
| `tinker-packs` | Installable bundles |
| `tinker-transfer` | Strangler migration |
| `tinker-automate` | Automations over sealed fields |

**Agent front door:**
- `tinker-mcp`: MCP over stdio and HTTP/SSE, with 12 tools and `tinker://ontology/{slug}` resources
- `tinker describe`
- `tinker-cli`

## Request lifecycle

1. **Credential.** The caller presents a `tk_` machine key, a passkey session or an OIDC session. Keys are verified against the credential store and bound to one (organization, role). Sessions take their tenant from the credential, never from caller input.
2. **Tenant transaction.** Every request runs in a transaction on an app role that cannot bypass RLS, with `SET LOCAL app.organization_id / app.actor_id / app.purpose`. **There is no existence oracle:** unauthorized objects and rows return `not_found`, which is indistinguishable from nonexistent.
3. **Governed reads.** One typed compiler applies role projection, row policies and masking to produce the SQL. The builder, HTTP, CLI, live grids, search, dashboards and agents all go through it.
4. **Governed writes.** Writes take one of these paths:
   - validation and presets
   - lifecycle state machines (draft → review → publish)
   - four-eyes approvals bound to (action, target), where the requester can never decide
   - an automation event written to an outbox in the *same* transaction
5. **Sealed fields.**
   - **What gets sealed.** Email and phone fields are always sealed, and text fields opt in. Values are sealed into the vault before any copy is made, under a per-record DEK wrapped by a rotating KEK.
   - **What core holds.** Core keeps only a vault ref and a keyed blind index. Every read returns a mask, and exact-match lookups use the index.
   - **Keys and plaintext.** Automations see an automation key. Plaintext comes only from the audited `reveal` tool, which needs a second person's single-use approval.
   - **Erasure.** Erasing a record destroys its key (crypto-shred).

   See [pii-sensitive-fields.md](pii-sensitive-fields.md) and [automations.md](automations.md).
6. **Fail closed.** A missing extension, an unconfigured vault or embedding provider, or a dead IdP each give a loud typed error. Nothing silently falls back.

## Evidence

- [`STATUS.md`](../STATUS.md): the per-milestone capability ledger. Every claim is bound to a named passing test, with exact gate numbers.
- [`BACKLOG.md`](../BACKLOG.md): post-M8 items and the production-readiness workstream R1–R5, each with gate numbers and deviations.
  - **R1:** 24-hour soak, 4.1M operations over both MCP transports. 4 of 5 fail criteria pass; the p99 criterion failed as written (p50 stayed flat, and the spikes were VM-load noise).
  - **R2:** backup, restore and point-in-time recovery drills with measured RPO/RTO. See [disaster-recovery.md](disaster-recovery.md).
  - **R3:** internal adversarial security review. See [threat-model.md](threat-model.md). It found and fixed a real DoS.
- [`history/`](history/README.md): an independent evaluation (2026-09-30) and the four hardening rounds that answered it.

## Known limits

- No external security audit (R3 was internal, and is labelled that way).
- DR follow-ups are open: no backup role or pg_hba entry, no WAL archiving on live clusters, no off-host secrets backup, no standby, no drill schedule.
- Semantic search was measured with a pseudo-embedding and needs a real model. TIN full-text search is blocked upstream (GA only on PlanetScale/Neki).
- Single-server efficiency was measured with a micro-benchmark, not a production workload.
- Automation email has no real provider configured in the servers, and automation actions are not transactional across a failed run.
