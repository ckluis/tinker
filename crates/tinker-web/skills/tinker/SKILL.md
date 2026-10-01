---
name: tinker
description: Working with Tinker, the governed data platform. Discovery-first: describe the ontology before reading or writing anything. Use when the task touches Tinker objects, records, queries, dashboards, files, or lifecycle publishing.
tinker_version: __TINKER_VERSION__
ontology_version: __ONTOLOGY_VERSION__
---

# Working with Tinker

Tinker is a governed data platform: every object, field, validation rule,
row policy, and lifecycle transition is defined in the ontology and
enforced by the server. The ontology documents itself — this skill teaches
you the workflow, and `tinker describe` teaches you the specific
organization you're working in.

This skill is pinned to Tinker `__TINKER_VERSION__` / ontology
`__ONTOLOGY_VERSION__`. If those don't match your server, run
`tinker agent verify` and upgrade the skill before doing anything else.
A version-mismatched skill is worse than no skill.

## Rule zero: discover before you write

**Always `describe` before writing. Never guess a field name, never invent
a transition, never assume a validation rule.** The describe output is a
read projection over the real governance sources — not a hand-written doc
that can drift. If a field isn't in describe output, you can't see it;
if a transition isn't listed, it doesn't exist for you.

```bash
# Catalog: every object you may see (permission-projected)
tinker describe --org <org-uuid> --role <your-role>

# One object: fields, validation, presets, relations, row policy,
# lifecycle, mutation and read contracts
tinker describe widgets --org <org-uuid> --role <your-role>

# Canonical JSON (keys sorted, byte-stable — safe to pin and diff)
tinker describe widgets --org <org-uuid> --role <your-role> --json
```

- `--org` and `--role` are required; `--role` is an explicit view-as and
  drives the permission projection (hidden fields are *omitted*, never
  named).
- Full usage: `tinker describe [object] [--json] --org <uuid> --role <role>`
- Needs `TINKER_CORE_URL` and `TINKER_APP_URL` in the environment.
  Describe is read-only and never runs migrations.
- Misuse (missing `--org`, unknown flag) exits 2 with usage text.

Over HTTP (same projection, session-authenticated):

```http
GET /api/describe
GET /api/describe/{slug}
```

Optional version pins — declare what you were built against; a mismatch
fails closed with 409 instead of silently drifting:

```http
GET /api/describe/widgets?client_tinker_version=__TINKER_VERSION__&client_ontology_version=__ONTOLOGY_VERSION__
```

```json
{
  "error": "version_mismatch",
  "message": "client was built against different Tinker versions; refusing to silently drift",
  "expected": { "tinker_version": "...", "ontology_version": "..." },
  "got": { "tinker_version": "...", "ontology_version": "..." },
  "hint": "re-run describe without version pins, or update the client/skill to the server versions"
}
```

### What describe tells you (per object)

- `fields[]`: `api_name`, `label`, `field_type`, `postgres_type`,
  `required`, `nullable` (always true in v1 — physical columns are
  nullable and `required` is enforced by the governed mutation layer,
  so don't infer NOT NULL), `options` (select values), `validation`
  (min/max/pattern/options rules), `preset` (forced default applied
  *before* validation — a preset can satisfy `required`),
  `max_pii_class` (ceiling for linked files), `relation_target`.
- `relations[]`: FK columns, `cardinality` is always `"many-to-one"`.
- `row_policy`: `{ applies, summary, filter_count }` — deliberately
  coarse. Field names, operators, and values never appear.
- `lifecycle` (only when `lifecycle_enabled`): states, transitions,
  who may initiate each, and which need M7 approval.
- `mutation`: `write_path` is `"governed"` or `"lifecycle"`, plus the
  error taxonomy below.
- `reads`: `query_endpoint` (`POST /api/query`), the intent shape, and
  the rules that govern reads.

Describe is schema-only: it lists the values of an enum, not what they
mean to the business. Human `description`s appear where the modeler
wrote one; they're encouraged, never required.

## Installing and verifying this skill

The skill ships with Tinker and is installed by an operator:

```bash
tinker agent install [--global]   # project ./.claude/skills, or ~/.claude/skills with --global
tinker agent verify [--global]    # fail loudly if the installed pin drifted
```

The installed `SKILL.md` pins the Tinker and ontology versions it was
built against. If `tinker agent verify` reports drift, re-install —
never work from a stale skill.

## Authentication: C6 machine credentials

Agents authenticate as machines, not users. Credentials are C6 API keys:

```bash
# Issued by an operator. The secret is printed ONCE — store it then.
tinker-cli mcp key issue --org <org-slug> --name <name> --scopes <csv> [--ttl-days <n>]

tinker-cli mcp key list --org <org-slug>
tinker-cli mcp key rotate --org <org-slug> --id <uuid>
tinker-cli mcp key revoke --org <org-slug> --id <uuid>
```

- Secret format: `tk_` + 43 base64url chars. Only its SHA-256 is stored
  server-side; the plaintext is never logged.
- Keep it in the `TINKER_API_KEY` environment variable. **Never in chat,
  never in files, never in a URL.**
- Scopes: `mcp:tools`, `mcp:resources`, `mcp:tool:<name>`. Ask for the
  narrowest scope that does the job.
- On MCP HTTP transports, present it as `Authorization: Bearer <key>`
  (the M7 `tinker-cli mcp http` transport: `GET /sse`,
  `POST /messages`, `POST /mcp`; binds 127.0.0.1 — put TLS in front).
- Every verification failure — unknown key, bad secret, revoked,
  expired — returns the same 401. There is no existence oracle; don't
  try to distinguish them.

## Reading: `POST /api/query`

Build the intent from `describe.<object>.reads.intent_shape`. The exact
shape:

```json
{
  "from": "<object id (uuid)>",
  "select": ["api_name", "relation_field.api_name"],
  "filters": [{"field": "api_name", "op": "eq|ne|lt|lte|gt|gte|in|contains|starts_with|is_null|is_not_null", "value": "<json>"}],
  "order": [{"field": "api_name", "descending": false}],
  "limit": 100,
  "schema_version": "active"
}
```

Rules (also in `reads.notes` — they are enforced, not advisory):

- `select` uses field `api_name`s; `"a.b"` traverses one declared
  relation hop.
- Filters/sorts on fields hidden from your role are rejected outright —
  a boolean oracle on a hidden column would leak its values.
- Row policies AND with the tenant predicate at compile time: policy
  before ranking.
- Query plans are cached per (organization, plan hash); the hash covers
  the row-policy SQL and actor binds, so roles never share a plan they
  shouldn't see.

## Writing: two governed paths, no third

`describe.<object>.mutation.write_path` tells you which path an object
uses. There is no ungoverned write.

### Path A — governed direct write (`write_path: "governed"`)

Every write passes the mutation connector in this order, no exceptions:

1. **Presets** are applied first (`WhenMissing` fills omitted/nulled
   fields; `Always` overwrites whatever you sent). A preset can satisfy
   `required` — don't send a value the preset already provides.
2. **Validation** rules run (min/max/pattern/options, required,
   unknown-field rejection).
3. **File-field validation**: a linked file must exist, be active,
   belong to your organization, and fit the field's `max_pii_class`.
   Missing/deleted/cross-org files all return the same opaque error —
   don't probe to distinguish them.

Notes: explicit `null` clears an optional field. If the object is
lifecycle-managed, direct writes are refused with `403
"object is lifecycle-managed; use the record lifecycle API"` — that is
not an error to work around; switch to Path B.

### Path B — lifecycle (`write_path: "lifecycle"`)

Records travel draft → review → publish. The transition table (verified
against the engine; also in `describe.<object>.lifecycle.transitions`):

| Transition | From | To | Who | Approval |
|---|---|---|---|---|
| `create_draft` | — | `draft` | any organization member | — |
| `update_draft` | `draft` | `draft` | the draft author only | — |
| `submit_for_review` | `draft`, `rejected` | `in_review` | the draft author only | bound M7 approval for `submit_for_review` on this draft |
| `publish` | `in_review` | `published` | any member with a bound M7 `publish` approval **decided by someone other than the draft author** | bound M7 approval for `publish` on this draft — no self-approval, ever |
| `reject` | `in_review` | `rejected` | reviewer, admin, or owner — never the draft author | — |
| `revise` | `rejected` | `draft` | the draft author only | — |
| `archive` | `published` | `archived` | any member with a bound M7 `archive` approval | bound M7 approval for `archive` on this record |
| `unarchive` | `archived` | `published` | any member with a bound M7 `unarchive` approval | bound M7 approval for `unarchive` on this record |

- Storage truth: `draft`, `in_review`, `rejected` live in
  `record_drafts`; `published` and `archived` live on the data row.
- Published versions are immutable — publishing snapshots; you can't
  edit a published version in place.
- Approvals bind to the exact action and record (`action_name` +
  payload): a `submit` approval never publishes, and one draft's
  approval never covers another.
- M8 retention composes: purge of stale drafts/orphaned versions is
  suspended under legal hold.

## Error taxonomy

From `describe.<object>.mutation.error_taxonomy` — what each class means
and what to do:

| Class | HTTP | Meaning | Do this |
|---|---|---|---|
| `invalid` | 400 | validation rule violated, unknown field, or illegal transition | re-read describe for the field/transition; fix the payload |
| `forbidden` | 403 | you lack permission — **indistinguishable from `not_found` for things you can't see** | don't probe; check your role's describe view |
| `not_found` | 404 | unknown object/field/record — same shape as hidden | verify the slug against the catalog |
| `conflict` | 409 | version/state conflict, or a client version-pinning mismatch | for version pins, re-run unpinned or upgrade the skill; for state, re-describe |

## Worked examples

<!-- example: first-query -->
### Example 1 — first query

1. `tinker describe --org $ORG --role $ROLE` → find the object's
   `api_slug` in the catalog.
2. `tinker describe <slug> --org $ORG --role $ROLE --json` → read
   `fields[].api_name`, `reads.intent_shape`, `row_policy`.
3. Build the intent with the object's id in `from` and only visible
   `api_name`s in `select`. `POST /api/query`.
4. If a filter is rejected, the field is hidden from your role — pick
   fields from the describe output, not from memory.

<!-- example: first-write -->
### Example 2 — first valid write (governed object)

1. Confirm `mutation.write_path == "governed"` in describe output.
2. Send only the fields you mean to set; let `WhenMissing` presets fill
   the rest (describe shows each field's `preset`).
3. If you get 400 `invalid`, the response names the rule — the field's
   `validation` in describe output is the same rule. Fix and retry.
4. File fields: link only files your organization owns, within the
   field's `max_pii_class`. Any failure here is opaque by design.

<!-- example: publish-flow -->
### Example 3 — first publish flow (lifecycle object)

1. Confirm `lifecycle_enabled` and read `lifecycle.transitions`.
2. `create_draft` with the record content (validated like a write:
   presets → validation → file checks).
3. Obtain the M7 approval for `submit_for_review` on the draft, then
   `submit_for_review` → `in_review`.
4. A reviewer (not you, if you're the author) decides the M7 `publish`
   approval bound to the draft; `publish` → `published`, immutable.
5. To change a published record: `create_draft` for a new version
   (edit flow), or `archive` with an `archive` approval.

## Honest limits of this skill (v1)

- Record writes have no generic HTTP API on the main server in v1 —
  writes go through the governed mutation connector (Rust API) and the
  MCP front door. This skill documents the *rules* all write paths
  enforce; the MCP tool names arrive with the front door.
- `describe` is schema-only: no example records, no business meaning.
- Dashboards (`/api/dashboards`) render as the viewer — shared
  dashboards never escalate your permissions.
- Snapshots (`tinker describe` doesn't cover them) are operator-level;
  not in the agent toolset.
