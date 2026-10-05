# Tinker Agent Front Door — Spec

Status: APPROVED FOR BUILD 2026-09-26 (user: "Do it").
Decisions: (1) MCP transport stdio-first; (2) `describe` is schema-only
in v1 — no synthetic example records; (3) kill bar ADOPTED: median
time-to-first-correct-publish, fresh agent with skill+MCP vs. raw HTTP +
human docs. If the front door doesn't win clearly, it failed its thesis.

Backlog: items 43 (Part 1), 44 (Part 3), 45 (Part 2) — build in order.

## Thesis

Tinker's APIs exist in no model's training data. Every future agent that
meets Tinker will meet it cold. So Tinker must teach itself: an agent with
nothing but a credential should be able to discover the ontology, learn the
governed mutation paths, and do correct work without ever reading a human
docs page. The ontology is the documentation; the API is the tutorial.

This is also the second-order bet from the Directus comparison: Rust plus a
governed stack should make *building with AI* easier, not just make the
server faster. That advantage has to be constructed — it doesn't fall out
of the language. This spec constructs it.

Non-goals: coupling Tinker to Diamond (explicitly deferred); replacing
human docs; a generic MCP gateway for arbitrary backends.

## Part 1 — Self-describing ontology (`tinker describe`)

The ontology answers questions about itself. Three surfaces, one source
of truth:

- **CLI:** `tinker describe [object] [--json]` — human-readable by
  default, `--json` for machines.
- **HTTP:** `GET /api/describe` (catalog: objects, API version, ontology
  version) and `GET /api/describe/{object}` (full object documentation).
- **MCP resource** (see Part 2): `tinker://ontology/{object}`.

### What `describe` returns for an object

- Fields: name, type, nullability, validation rules (item 37), write
  presets (item 37), `max_pii_class` ceiling (item 42), human `description`
  where the modeler wrote one.
- Relations: targets, cardinality.
- Row policies: *summarized* (e.g. "tenant-scoped, author-visible drafts"),
  never verbatim predicate SQL — policy internals are not documentation.
- Lifecycle (item 40): states, allowed transitions, which roles may
  submit/approve/publish, approval binding rules.
- Mutation contract: which write path to use, error taxonomy (validation
  vs Forbidden vs conflict), pagination and filtering syntax for reads.
- Every payload carries `tinker_version` and `ontology_version`.

### Design rules

1. **Describe is permission-aware.** You see what you may see. Row filters
   (item 38), field projection, and lifecycle visibility apply to describe
   output too — no schema oracle for objects/fields hidden from the caller.
2. **Read-only.** Describe never mutates, never leaks secrets, never
   evaluates user input as code.
3. **Canonical JSON** (reuse item 39's canonicalization) with stable field
   order, so agents and tests can pin expectations.
4. **Versioned and pinned.** Clients declare the version they were built
   against; the server rejects unknown-version clients with a clear error
   rather than silently drifting.

### Honest limit

Describe documents the ontology, not business meaning. It lists the values
of `deal_stage`; it does not know what "negotiation" means to the org.
Human-authored `description` fields are encouraged, never required.

## Part 2 — MCP front door (`tinker-mcp`)

A first-class MCP server over the existing machine API, authenticated with
C6 API keys (the `apikey_credentials` model). New binary in the workspace;
**stdio transport first** (that's what coding agents speak), HTTP/SSE later.

### Tools (v1)

| Tool | Does |
|---|---|
| `describe` | Ontology discovery (Part 1) — always the first call. |
| `query` | Run a query (structured filter / QueryIntent) under the caller's permissions. |
| `get_record` | Fetch one record, governed read path. |
| `create_record` / `update_record` | Governed write paths — validation, presets, file-field checks, lifecycle all apply. Never around governance. |
| `transition` | Lifecycle transitions (e.g. submit for review, publish) with approval binding. |
| `render_dashboard` | Dashboard render as the viewer (item 41 semantics). |

Explicitly **out of v1**: `apply_snapshot` (operator-level privilege, stays
out of the agent toolset), real-time subscriptions.

### Design rules

1. **Every tool executes as the calling credential.** The item-41 lesson,
   generalized: a tool never shows its caller data the caller can't see,
   and shared artifacts (dashboards, saved queries) never escalate.
2. **Fail closed.** Unknown arguments → validation error. Unauthorized →
   `Forbidden`, with identical shape for missing vs hidden (no oracles).
   Unconfigured backend → error, never silent fallback.
3. **Version handshake.** Server reports `tinker_version`; a client built
   for another version gets a clear mismatch error, not silent drift.
4. **Errors teach.** Error payloads name the rule that fired and point at
   the describe section that documents it (e.g. "transition rejected:
   see describe.widgets.lifecycle").

## Part 3 — Version-matched agent skill

A skill in the shape agents already consume (`SKILL.md`): *"Working with
Tinker."* Contents:

- The discovery-first workflow: **always `describe` before writing** —
  never guess a field name, never invent a transition.
- Auth setup: C6 key via environment, never in chat, never in files.
- The governed mutation paths and when to use each (direct write vs
  lifecycle transition vs approval).
- Error taxonomy and what to do about each class.
- Worked examples: first query, first valid write, first publish flow.

Distribution and versioning:

- Ships in the repo; installable via `tinker agent install [--global]`.
- Frontmatter pins `tinker_version`; `tinker agent verify` checks the
  installed skill against the server and fails loudly on drift.
- The skill is tested: a CI job installs the skill against a fixture
  server and runs the worked examples (the skill's own examples are its
  regression tests).

## Sequencing

1. **Part 1** (`describe`) — unlocks everything; mostly read paths, small
   blast radius.
2. **Part 3** (skill) — draftable against `describe` immediately; its
   examples become acceptance tests.
3. **Part 2** (MCP) — the front door, built on 1 and 2.

## Acceptance

The bar is behavioral, not documentary. A fresh agent — and every current
model is fresh to Tinker — given only a C6 key and the skill, must be able
to: discover the schema, query records it may see (and only those), create
a valid record, and drive it through the lifecycle to published, without
reading any human docs. If it can't, the front door isn't done.

Suggested kill bar for the whole effort: median time-to-first-correct-
publish for a fresh agent with the skill + MCP vs. the same agent with
raw HTTP + human docs. If the front door doesn't win clearly, it failed
its thesis. (Proposed, not imposed — say the word and I'll set the bar.)

## Open questions for you

1. MCP transport: stdio first is the obvious call — agree, or do you want
   HTTP/SSE from day one for hosted agents?
2. Should `describe` include *example* records (synthetic, clearly marked)
   to ground agents faster, or is schema-only the right v1?
3. Kill bar: adopt the time-to-first-correct-publish comparison, or a
   different measure?
