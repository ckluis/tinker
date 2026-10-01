# Tinker — Framework Overview (for evaluators)

## What it is

Tinker is an **ontology-driven application platform** written in Rust, backed by
PostgreSQL (+ Redis). You define data objects (fields, types, validation, relations,
row-level policies, lifecycles) once in the ontology; Tinker materializes real
Postgres tables, enforces tenant isolation at the database layer, and exposes the
objects through governed HTTP, CLI, and agent interfaces. Think "Directus-style
data platform, but Rust, multi-tenant by construction, and designed LLM-first."

The LLM-first bet is the core thesis: Tinker's APIs exist in no model's training
data, so the framework must **teach itself**. `tinker describe` and the MCP server
let an agent with nothing but a credential discover the schema, learn the governed
mutation paths, and do correct work without reading human docs. Three kill-bar
experiments (fresh agents, timed, independently verified) measured whether static
skill docs add value on top of the MCP: verdicts were LOSS / TIE — the MCP is
effectively self-documenting.

## Architecture

One Cargo workspace (`crates/`), layered:

- **Milestones M0–M8** (`tinker-m0` … `tinker-m8`): built in order, each gated.
  M0 foundation (ontology → real tables, PII separation, durable workflows);
  M1 multi-tenant app runtime (auth, sessions, rendering); M2 governed reactivity;
  M3 pack ontology; M4 schema evolution (versioned, canary, promote); M5 native
  work & communications; M6 governed ingestion; M7 context, agents & cost
  accounting; M8 authority transfer & hardening.
- **Core** (`tinker-core`, `tinker-ontology`, `tinker-db`, `tinker-query`,
  `tinker-search`): the governed data plane. `tinker-vault`: PII lives in a
  separate encrypted store — core SQL *cannot* join to it (proven by test).
  `tinker-auth` / `tinker-identity`: passkey + OIDC → normalized actors.
- **App surfaces** (`tinker-web`, `tinker-apps`, `tinker-live`, `tinker-comms`,
  `tinker-agents`, `tinker-ingest`, `tinker-evolve`, `tinker-durable`,
  `tinker-packs`, `tinker-transfer`): HTTP API, app rendering, ingestion
  (incl. AI-assisted mapping proposals), schema evolution, durable workflows.
- **Agent front door** (`tinker-mcp`, `tinker describe`): MCP over stdio and
  HTTP/SSE, 7 tools + `tinker://ontology/{slug}` resources, `tk_` machine-key
  auth. Post-M8 items 43–49 added: self-describing ontology, version-matched
  skill, MCP server, HTTP/SSE transport, measured single-server efficiency,
  embedding-based semantic ranking, AI mapping proposals.

## How it works (request lifecycle)

1. Caller presents a `tk_` machine key → verified against the credential store,
   bound to (organization, role). Sessions bind to the credential's tenant —
   never caller-supplied.
2. Every read passes tenant-scoped row policies (RLS); **there is no existence
   oracle** — unauthorized objects/rows return `not_found`, indistinguishable
   from nonexistent.
3. Writes go through governed paths only: validation + presets, lifecycle
   state machines (draft → review → publish) with approvals bound to
   (action, draft_id) — approvals can't be replayed across actions.
4. PII fields are sealed into the vault (per-org DEK, KEK-wrapped); the app
   only ever sees ciphertext or masked values.
5. Fail-closed everywhere: missing TIN extension, unconfigured embedding
   provider, or dead OIDC → loud typed errors, never silent fallback.

## How it was verified (evidence, not claims)

- `STATUS.md`: per-milestone capability ledger — every claim bound to a named
  passing test, with exact gate numbers (suites/tests, fmt, clippy).
- `BACKLOG.md`: post-M8 items 19–49 + production-readiness workstream R1–R5,
  each with implementation commit, gate numbers, and deviations.
- R1: 24h soak, 4.1M ops, both MCP transports — 4/5 fail criteria pass
  (the p99 criterion failed as written; p50 flat, spikes were VM-load noise).
- R2: backup/restore + point-in-time recovery drills with measured RPO/RTO;
  `docs/disaster-recovery.md`.
- R3: internal adversarial security review (threat model in
  `docs/threat-model.md`); found and fixed a real DoS (C6 multibyte panic).
- Kill bars v1–v3: the skill-vs-MCP experiments described above.
- `deploy/`: production layout (Postgres, Redis, TLS proxy, systemd) validated
  locally; nothing ever deployed publicly.

## Known limits (honest)

- No external security audit (R3 was internal, labeled as such).
- DR follow-ups open: no backup role/pg_hba, no WAL archiving on live
  clusters, no off-host secrets backup, no standby, no drill schedule.
- Semantic search default chosen by measurement but not yet wired into the
  HTTP layer; relevance measured with a pseudo-embedding, needs a real model.
- TIN full-text search blocked externally (GA only on PlanetScale/Neki).
- Single-server efficiency measured via micro-bench, not a production workload.

## Suggested evaluation angles

1. Does the tenant-isolation model hold? (Try to construct a cross-org read
   through any tool; check `tinker-mcp/tests/mcp_front_door.rs` and
   `r3_adversarial.rs` for the existing attack surface.)
2. Is "fail closed" real? (Remove/unset optional backends and confirm loud
   errors, not silent degradation.)
3. Does the ledger culture survive scrutiny? (Pick any STATUS.md claim and
   trace it to the named test and commit.)
4. Where would *you* attack it? (Auth, approval replay, file uploads,
   PII exfiltration via search/highlight.)
5. Is the LLM-first thesis earned? (The kill-bar results are in BACKLOG.md —
   do you buy the methodology?)
