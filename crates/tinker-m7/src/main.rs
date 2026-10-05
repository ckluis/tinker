//! `tinker` — the M7 CLI read surface for context and agents.
//!
//! Virtual files are read-only authorized projections; this CLI exposes the
//! exact same semantic pipeline as the MCP server (Identify → Authorize →
//! Transform → Emit → Audit), so CLI reads and MCP reads can never disagree
//! on what a role may see. There is deliberately no write path here: writes
//! use typed actions from the server-generated registry, never a generic
//! database console.
//!
//! Usage:
//!   tinker-cli vfile read --org <slug> --actor <display-name>
//!                     [--attachment <name>] --path <virtual-path> [--json]
//!   tinker-cli mcp serve --org <slug> --actor <display-name>
//!                    [--attachment <name>]
//!     MCP wire transport: JSON-RPC 2.0 over stdio (newline-delimited).
//!     Identity is launch-scoped (same dev-grade authn as vfile read).
//!   tinker-cli mcp http [--port <port>]
//!     MCP HTTP+SSE transport (MCP 2024-11-05: GET /sse, POST /messages)
//!     plus single-shot JSON-RPC at POST /mcp. Every endpoint requires
//!     `Authorization: Bearer tk_...` (see `tinker-cli mcp key`). Binds
//!     127.0.0.1 only — put TLS termination in front for public ingress.
//!   tinker-cli mcp key issue --org <slug> --name <name> --scopes <csv> [--role member]
//!                         [--ttl-days <n>]
//!   tinker-cli mcp key rotate --org <slug> --id <uuid>
//!   tinker-cli mcp key revoke --org <slug> --id <uuid>
//!   tinker-cli mcp key list --org <slug>
//!     Inbound machine credentials (API keys) for the HTTP transport.
//!     Scopes: mcp:tools, mcp:resources, mcp:tool:<name>. The secret is
//!     printed exactly once at issue/rotate; only its SHA-256 is stored.
//!   tinker-cli file store --org <slug> --actor <display-name> --name <name>
//!                     --mime <mime> [--pii-class none|pii|restricted] <path>
//!   tinker-cli file get --org <slug> --actor <display-name> --id <file-id>
//!                   --out <path>
//!   tinker-cli file delete --org <slug> --actor <display-name> --id <file-id>
//!     Governed file/blob store: bytes live on the FileBackend
//!     (TINKER_FILE_ROOT, default ./var/files), metadata in
//!     stored_files, every access audit-logged.
//!   tinker-cli ingest suggest-mappings --org <slug> --actor <display-name>
//!                     --target <object-slug> --provider <name>
//!                     --source-file <schema.json>
//!     Item 49: AI-assisted mapping proposals, suggestion-only. Prints the
//!     ranked proposals as JSON. The proposer persists nothing — the only
//!     write anywhere in this CLI is the mandated M7 cost-ledger record
//!     for the model call itself. Applying a proposal goes through the
//!     governed write paths with the caller's own auth.
//!   tinker-cli field make-sensitive --object <object-slug> --field <api_name>
//!     Operator maintenance (docs/pii-sensitive-fields.md "Retrofit"):
//!     seals every existing value of a text/email/phone field into the
//!     PII vault, replaces plaintext copies in drafts, versions, the
//!     mutation audit, ingest provenance and landing, and drops the old
//!     plaintext column. Needs the owner URL plus TINKER_PII_URL,
//!     TINKER_KEK and TINKER_BLIND_INDEX_KEY. Restart servers afterwards
//!     (cached plans name the old column), then VACUUM FULL the table.
//!   tinker-cli pii verify
//!     The no-plaintext-PII gate: lists every email/phone field that is
//!     not vault-backed (PII by type) and exits 1 if there is any.
//!   tinker-cli pii retrofit
//!     Runs `field make-sensitive` for every field `pii verify` reports.
//!   tinker-cli pii sweep [--grace-minutes <n>]
//!     Deletes vault ciphertext no core pii_refs row references (left by
//!     rolled-back two-phase writes), older than the grace (default 60).
//!     Needs TINKER_PII_OWNER_URL.
//!
//! AuthN is dev-grade (actor resolved by display name within the org); the
//! authorization pipeline underneath is the real one.

use std::sync::Arc;

use tinker_agents::adapters::HttpModelAdapter;
use tinker_agents::audit::AuditWriter;
use tinker_agents::cache::TransformCache;
use tinker_agents::files::{FileStore, PiiClass};
use tinker_agents::gateway::{FakeModelAdapter, ModelGateway, UnavailableModelAdapter};
use tinker_agents::mcp_stdio::StdioMcpServer;
use tinker_agents::profiles::ProfileEngine;
use tinker_agents::transforms::TransformEngine;
use tinker_agents::vfile::VirtualFileReader;
use tinker_core::{OrganizationId, TenantContext};
use tinker_db::{CoreDb, OwnerDb};
use tinker_ontology::Ontology;
use uuid::Uuid;

mod mcp_http;

fn usage() -> ! {
    eprintln!(
        "usage:\n  tinker-cli vfile read --org <slug> --actor <display-name> [--attachment <name>] --path <virtual-path> [--json]\n  tinker-cli mcp serve --org <slug> --actor <display-name> [--attachment <name>]\n  tinker-cli mcp http [--port <port>]\n  tinker-cli mcp key issue --org <slug> --name <name> --scopes <csv> [--ttl-days <n>] [--role <role>]\n  tinker-cli mcp key rotate --org <slug> --id <uuid>\n  tinker-cli mcp key revoke --org <slug> --id <uuid>\n  tinker-cli mcp key list --org <slug>\n  tinker-cli file store --org <slug> --actor <display-name> --name <name> --mime <mime> [--pii-class none|pii|restricted] <path>\n  tinker-cli file get --org <slug> --actor <display-name> --id <file-id> --out <path>\n  tinker-cli file delete --org <slug> --actor <display-name> --id <file-id>
  tinker-cli ingest suggest-mappings --org <slug> --actor <display-name> --target <object-slug> --provider <name> --source-file <path>
  tinker-cli field make-sensitive --object <object-slug> --field <api_name>
  tinker-cli pii verify | retrofit | sweep [--grace-minutes <n>]"
    );
    std::process::exit(2);
}

struct VfileArgs {
    org: String,
    actor: String,
    attachment: Option<String>,
    path: String,
    json: bool,
}

fn parse_vfile_args(args: Vec<String>) -> VfileArgs {
    let mut it = args.into_iter();
    if it.next().as_deref() != Some("read") {
        usage();
    }
    let (mut org, mut actor, mut attachment, mut path) = (None, None, None, None);
    let mut json = false;
    while let Some(flag) = it.next() {
        match flag.as_str() {
            "--org" => org = it.next(),
            "--actor" => actor = it.next(),
            "--attachment" => attachment = it.next(),
            "--path" => path = it.next(),
            "--json" => json = true,
            _ => usage(),
        }
    }
    VfileArgs {
        org: org.unwrap_or_else(|| usage()),
        actor: actor.unwrap_or_else(|| usage()),
        attachment,
        path: path.unwrap_or_else(|| usage()),
        json,
    }
}

fn env(key: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| {
        eprintln!("error: {key} must be set");
        std::process::exit(1);
    })
}

#[tokio::main]
async fn main() {
    let mut it = std::env::args().skip(1);
    let sub = it.next();
    let rest: Vec<String> = it.collect();
    let rc = match sub.as_deref() {
        Some("vfile") => run_vfile(rest).await,
        Some("mcp") => run_mcp(rest).await,
        Some("file") => run_file(rest).await,
        Some("ingest") => run_ingest(rest).await,
        Some("field") => run_field(rest).await,
        Some("pii") => run_pii(rest).await,
        _ => usage(),
    };
    if let Err(e) = rc {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

/// Shared stack: pools, ontology, identity, gateway, pipeline pieces.
struct Stack {
    core: CoreDb,
    owner: OwnerDb,
    ontology: Ontology,
    gateway: ModelGateway,
    ctx: TenantContext,
}

async fn build_stack(org_slug: &str, actor_name: &str) -> tinker_core::Result<Stack> {
    // Production pool discipline: CoreDb::connect / OwnerDb::connect apply
    // the tuned pool (max 16, min 1 warm, bounded acquire) instead of
    // sqlx's light-duty defaults (max 10, min 0). Raw PgPool::connect here
    // used to pay connection-establishment latency on every burst.
    let core = CoreDb::connect(&env("TINKER_CORE_URL")).await?;
    let owner = OwnerDb::connect(&env("TINKER_CORE_OWNER_URL")).await?;
    let ontology = Ontology::new(core.clone(), owner.clone());

    // Resolve org + actor (owner DB holds identity).
    let org_id: Uuid = sqlx::query_scalar("SELECT id FROM organizations WHERE slug = $1")
        .bind(org_slug)
        .fetch_optional(&owner.0)
        .await
        .map_err(tinker_core::TinkerError::Db)?
        .ok_or_else(|| tinker_core::TinkerError::NotFound(format!("org {org_slug}")))?;
    let actor_id: Uuid = sqlx::query_scalar(
        "SELECT id FROM actors WHERE organization_id = $1 AND display_name = $2",
    )
    .bind(org_id)
    .bind(actor_name)
    .fetch_optional(&owner.0)
    .await
    .map_err(tinker_core::TinkerError::Db)?
    .ok_or_else(|| {
        tinker_core::TinkerError::NotFound(format!("actor {actor_name} in org {org_slug}"))
    })?;
    let ctx = TenantContext::new(OrganizationId(org_id), actor_id, "tinker-cli");

    // Gateway adapters come from the provider registry: the DB row carries
    // kind/status/placement; the process only holds adapters for kinds it
    // can actually serve. Hosted/private endpoints get a real HTTP adapter
    // when their TINKER_PROVIDER_<NAME>_* env config is complete;
    // otherwise they degrade to explicit unavailable markers rather than
    // being called half-configured.
    let mut gateway = ModelGateway::new(core.clone(), owner.clone());
    {
        let mut tx = core.tenant_tx(&ctx).await?;
        let rows: Vec<(String, String)> =
            sqlx::query_as("SELECT name, kind FROM model_providers WHERE organization_id = $1")
                .bind(org_id)
                .fetch_all(&mut *tx)
                .await
                .map_err(tinker_core::TinkerError::Db)?;
        tx.commit().await?;
        for (name, kind) in rows {
            match kind.as_str() {
                "fake" => gateway.register(&name, Arc::new(FakeModelAdapter::new(name.clone()))),
                "unavailable" => {
                    gateway.register(&name, Arc::new(UnavailableModelAdapter::new(name.clone())))
                }
                "hosted" | "private" => match HttpModelAdapter::from_env(&name) {
                    Ok(adapter) => gateway.register(&name, Arc::new(adapter)),
                    Err(e) => {
                        eprintln!("provider {name}: {e}; registering as unavailable");
                        gateway
                            .register(&name, Arc::new(UnavailableModelAdapter::new(name.clone())))
                    }
                },
                _ => {}
            }
        }
    }

    Ok(Stack {
        core,
        owner,
        ontology,
        gateway,
        ctx,
    })
}

async fn resolve_attachment_name(stack: &Stack, name: &str) -> tinker_core::Result<Uuid> {
    let mut tx = stack.core.tenant_tx(&stack.ctx).await?;
    let id: Option<Uuid> = sqlx::query_scalar(
        "SELECT id FROM agent_attachments WHERE organization_id = $1 AND name = $2 AND status = 'active'",
    )
    .bind(stack.ctx.organization_id.0)
    .bind(name)
    .fetch_optional(&mut *tx)
    .await
    .map_err(tinker_core::TinkerError::Db)?;
    tx.commit().await?;
    id.ok_or_else(|| tinker_core::TinkerError::NotFound(format!("attachment {name}")))
}

async fn run_mcp(args: Vec<String>) -> tinker_core::Result<()> {
    let mut it = args.into_iter();
    match it.next().as_deref() {
        Some("serve") => run_mcp_serve(it.collect()).await,
        Some("http") => run_mcp_http(it.collect()).await,
        Some("key") => run_mcp_key(it.collect()).await,
        _ => usage(),
    }
}

/// Pools + ontology + gateway without identity: the HTTP transport
/// authenticates per request from machine credentials.
async fn build_base() -> tinker_core::Result<mcp_http::HttpStack> {
    // Production pool discipline: CoreDb::connect / OwnerDb::connect apply
    // the tuned pool (max 16, min 1 warm, bounded acquire) instead of
    // sqlx's light-duty defaults (max 10, min 0). Raw PgPool::connect here
    // used to pay connection-establishment latency on every burst.
    let core = CoreDb::connect(&env("TINKER_CORE_URL")).await?;
    let owner = OwnerDb::connect(&env("TINKER_CORE_OWNER_URL")).await?;
    let ontology = Ontology::new(core.clone(), owner.clone());
    let gateway = ModelGateway::new(core.clone(), owner.clone());
    Ok(mcp_http::HttpStack {
        core,
        owner,
        ontology,
        gateway,
    })
}

async fn run_mcp_http(args: Vec<String>) -> tinker_core::Result<()> {
    let mut port: u16 = 8080;
    let mut it = args.into_iter();
    while let Some(flag) = it.next() {
        match flag.as_str() {
            "--port" => {
                port = it
                    .next()
                    .map(|p| p.parse().unwrap_or_else(|_| usage()))
                    .unwrap_or_else(|| usage());
            }
            _ => usage(),
        }
    }
    let stack = build_base().await?;
    let store = tinker_auth::MachineCredentialStore::new(stack.owner.clone());
    eprintln!(
        "tinker-cli mcp http: listening on 127.0.0.1:{port} (GET /sse, POST /messages, POST /mcp)"
    );
    mcp_http::serve_http(stack, store, port).await
}

async fn org_id_by_slug(owner: &OwnerDb, slug: &str) -> tinker_core::Result<Uuid> {
    sqlx::query_scalar("SELECT id FROM organizations WHERE slug = $1")
        .bind(slug)
        .fetch_optional(&owner.0)
        .await
        .map_err(tinker_core::TinkerError::Db)?
        .ok_or_else(|| tinker_core::TinkerError::NotFound(format!("org {slug}")))
}

async fn run_mcp_key(args: Vec<String>) -> tinker_core::Result<()> {
    let mut it = args.into_iter();
    let op = it.next();
    let rest: Vec<String> = it.collect();
    let mut it = rest.into_iter();
    let (mut org, mut name, mut scopes, mut ttl_days, mut id, mut role) =
        (None, None, None, None, None, None);
    while let Some(flag) = it.next() {
        match flag.as_str() {
            "--org" => org = it.next(),
            "--name" => name = it.next(),
            "--scopes" => scopes = it.next(),
            "--ttl-days" => ttl_days = it.next(),
            "--id" => id = it.next(),
            "--role" => role = it.next(),
            _ => usage(),
        }
    }
    let org = org.unwrap_or_else(|| usage());
    let stack = build_base().await?;
    let org_id = org_id_by_slug(&stack.owner, &org).await?;
    let store = tinker_auth::MachineCredentialStore::new(stack.owner.clone());

    match op.as_deref() {
        Some("issue") => {
            let name = name.unwrap_or_else(|| usage());
            let scopes: Vec<String> = scopes
                .unwrap_or_else(|| usage())
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            let ttl_days: Option<i64> = ttl_days.map(|d| d.parse().unwrap_or_else(|_| usage()));
            let issued = store.issue(org_id, &name, &scopes, ttl_days, None).await?;
            // Item 45: a machine key's *data* visibility comes from its
            // actor's membership role (distinct from its scopes, which
            // gate MCP methods). --role grants it at issuance; without
            // it the tinker-mcp front door fails closed with the fix
            // spelled out.
            if let Some(role) = role.as_deref() {
                store
                    .grant_machine_role(org_id, issued.credential.actor_id, role)
                    .await?;
            }
            println!("id:       {}", issued.credential.id);
            println!("name:     {}", issued.credential.name);
            println!("prefix:   {}", issued.credential.key_prefix);
            println!("scopes:   {}", issued.credential.scopes.join(","));
            println!("actor_id: {}", issued.credential.actor_id);
            if let Some(role) = role.as_deref() {
                println!("role:     {role}");
            }
            // The secret is printed exactly once — it is never stored.
            println!("secret:   {}", issued.secret);
            eprintln!("SAVE THE SECRET NOW — it cannot be retrieved again.");
        }
        Some("rotate") => {
            let id: Uuid = id
                .unwrap_or_else(|| usage())
                .parse()
                .unwrap_or_else(|_| usage());
            let issued = store.rotate(org_id, id).await?;
            println!("id:     {}", issued.credential.id);
            println!("prefix: {}", issued.credential.key_prefix);
            println!("secret: {}", issued.secret);
            eprintln!("SAVE THE SECRET NOW — the old one stopped working.");
        }
        Some("revoke") => {
            let id: Uuid = id
                .unwrap_or_else(|| usage())
                .parse()
                .unwrap_or_else(|_| usage());
            store.revoke(org_id, id).await?;
            println!("revoked {id}");
        }
        Some("list") => {
            for c in store.list(org_id).await? {
                let status = if c.revoked_at.is_some() {
                    "revoked"
                } else if c.expires_at.is_some_and(|e| e <= chrono::Utc::now()) {
                    "expired"
                } else {
                    "active"
                };
                println!(
                    "{}  {}  {}  [{}]  {}",
                    c.id,
                    c.key_prefix,
                    c.name,
                    c.scopes.join(","),
                    status
                );
            }
        }
        _ => usage(),
    }
    Ok(())
}

async fn run_mcp_serve(args: Vec<String>) -> tinker_core::Result<()> {
    let mut it = args.into_iter();
    let (mut org, mut actor, mut attachment) = (None, None, None);
    while let Some(flag) = it.next() {
        match flag.as_str() {
            "--org" => org = it.next(),
            "--actor" => actor = it.next(),
            "--attachment" => attachment = it.next(),
            _ => usage(),
        }
    }
    let (org, actor) = (
        org.unwrap_or_else(|| usage()),
        actor.unwrap_or_else(|| usage()),
    );
    let stack = build_stack(&org, &actor).await?;
    let attachment_id = match &attachment {
        Some(name) => Some(resolve_attachment_name(&stack, name).await?),
        None => None,
    };

    let audit = AuditWriter::new(stack.core.clone(), stack.owner.clone());
    let engine = TransformEngine::new(
        stack.core.clone(),
        stack.owner.clone(),
        stack.ontology.clone(),
        stack.gateway,
        audit,
    );
    let cache = TransformCache::new(stack.core.clone(), stack.owner.clone());
    let profiles = ProfileEngine::new(stack.core.clone(), stack.owner.clone());
    let server = StdioMcpServer::new(
        stack.ctx,
        stack.core,
        stack.owner,
        stack.ontology,
        engine,
        cache,
        profiles,
        attachment_id,
    );
    server.run_stdio().await
}

async fn run_vfile(args: Vec<String>) -> tinker_core::Result<()> {
    let args = parse_vfile_args(args);
    let stack = build_stack(&args.org, &args.actor).await?;

    // Optional attachment scope (budgets, action grants, approval policy).
    let attachment_id: Option<Uuid> = match &args.attachment {
        Some(name) => Some(resolve_attachment_name(&stack, name).await?),
        None => None,
    };

    let audit = AuditWriter::new(stack.core.clone(), stack.owner.clone());
    let engine = TransformEngine::new(
        stack.core.clone(),
        stack.owner.clone(),
        stack.ontology,
        stack.gateway,
        audit,
    );
    let cache = TransformCache::new(stack.core.clone(), stack.owner.clone());
    let reader = VirtualFileReader::new(&engine, &cache);

    let markdown = reader.read(&stack.ctx, &args.path, attachment_id).await?;
    if args.json {
        println!(
            "{}",
            serde_json::json!({"path": args.path, "content": markdown})
        );
    } else {
        print!("{markdown}");
    }
    Ok(())
}

fn parse_pii_class(s: &str) -> PiiClass {
    match s {
        "none" => PiiClass::None,
        "pii" => PiiClass::Pii,
        "restricted" => PiiClass::Restricted,
        _ => usage(),
    }
}

async fn run_file(args: Vec<String>) -> tinker_core::Result<()> {
    let mut it = args.into_iter();
    let op = it.next();
    let rest: Vec<String> = it.collect();
    let mut it = rest.into_iter();
    let (mut org, mut actor, mut name, mut mime, mut pii, mut id, mut out, mut path) =
        (None, None, None, None, None, None, None, None);
    while let Some(flag) = it.next() {
        match flag.as_str() {
            "--org" => org = it.next(),
            "--actor" => actor = it.next(),
            "--name" => name = it.next(),
            "--mime" => mime = it.next(),
            "--pii-class" => pii = it.next(),
            "--id" => id = it.next(),
            "--out" => out = it.next(),
            f if !f.starts_with("--") && path.is_none() => path = Some(f.to_string()),
            _ => usage(),
        }
    }
    let (org, actor) = (
        org.unwrap_or_else(|| usage()),
        actor.unwrap_or_else(|| usage()),
    );
    let stack = build_stack(&org, &actor).await?;
    let store = FileStore::new(
        stack.core.clone(),
        tinker_agents::files::backend_from_env()?,
    );

    match op.as_deref() {
        Some("store") => {
            let (name, mime, src) = (
                name.unwrap_or_else(|| usage()),
                mime.unwrap_or_else(|| usage()),
                path.unwrap_or_else(|| usage()),
            );
            let bytes = std::fs::read(&src)
                .map_err(|e| tinker_core::TinkerError::Internal(format!("read {src}: {e}")))?;
            let r = store
                .store(
                    &stack.ctx,
                    &name,
                    &mime,
                    parse_pii_class(pii.as_deref().unwrap_or("none")),
                    &bytes,
                )
                .await?;
            println!(
                "{}",
                serde_json::json!({
                    "id": r.id, "name": r.name, "mime": r.mime,
                    "byte_size": r.byte_size, "sha256": r.sha256,
                })
            );
        }
        Some("get") => {
            let (id, out) = (
                id.unwrap_or_else(|| usage()),
                out.unwrap_or_else(|| usage()),
            );
            let file_id: Uuid = id
                .parse()
                .map_err(|_| tinker_core::TinkerError::Validation("bad --id".into()))?;
            let (r, bytes) = store.fetch(&stack.ctx, file_id).await?;
            std::fs::write(&out, &bytes)
                .map_err(|e| tinker_core::TinkerError::Internal(format!("write {out}: {e}")))?;
            eprintln!("wrote {} bytes (sha256 {}) to {out}", r.byte_size, r.sha256);
        }
        Some("delete") => {
            let id = id.unwrap_or_else(|| usage());
            let file_id: Uuid = id
                .parse()
                .map_err(|_| tinker_core::TinkerError::Validation("bad --id".into()))?;
            store.delete(&stack.ctx, file_id).await?;
            println!("deleted {file_id}");
        }
        _ => usage(),
    }
    Ok(())
}

struct SuggestMappingsArgs {
    org: String,
    actor: String,
    target: String,
    provider: String,
    source_file: String,
}

fn parse_suggest_mappings_args(args: Vec<String>) -> SuggestMappingsArgs {
    let mut it = args.into_iter();
    if it.next().as_deref() != Some("suggest-mappings") {
        usage();
    }
    let (mut org, mut actor, mut target, mut provider, mut source_file) =
        (None, None, None, None, None);
    while let Some(flag) = it.next() {
        match flag.as_str() {
            "--org" => org = it.next(),
            "--actor" => actor = it.next(),
            "--target" => target = it.next(),
            "--provider" => provider = it.next(),
            "--source-file" => source_file = it.next(),
            _ => usage(),
        }
    }
    SuggestMappingsArgs {
        org: org.unwrap_or_else(|| usage()),
        actor: actor.unwrap_or_else(|| usage()),
        target: target.unwrap_or_else(|| usage()),
        provider: provider.unwrap_or_else(|| usage()),
        source_file: source_file.unwrap_or_else(|| usage()),
    }
}

/// Item 49: AI-assisted mapping proposals, suggestion-only.
///
/// Reads an ad-hoc source schema (field names + sample values, JSON),
/// asks the named model provider to rank mappings onto the target
/// platform object, and prints the ranked proposals as JSON. The proposer
/// persists nothing — the only write in this path is the mandated M7
/// cost-ledger record for the model call itself (guardrail: every model
/// call is accounted, fail closed). Applying a proposal goes only
/// through the governed write paths (`put_mapping` / `approve_mapping` /
/// `activate_mapping`, or `define_object` / `add_field` for ontology
/// work) with the caller's own auth; this command never writes schema
/// or records.
async fn run_ingest(args: Vec<String>) -> tinker_core::Result<()> {
    let a = parse_suggest_mappings_args(args);
    let stack = build_stack(&a.org, &a.actor).await?;
    let raw = std::fs::read_to_string(&a.source_file)
        .map_err(|e| tinker_core::TinkerError::Internal(format!("read {}: {e}", a.source_file)))?;
    let source: tinker_ingest::mapping::MappingSource =
        serde_json::from_str(&raw).map_err(|e| {
            tinker_core::TinkerError::Validation(format!(
                "source file is not a valid mapping source schema: {e}"
            ))
        })?;
    let engine =
        tinker_ingest::mapping::MappingEngine::new(stack.core.clone(), stack.owner.clone());
    let report = engine
        .suggest_mappings(&stack.ctx, &source, &a.target, &stack.gateway, &a.provider)
        .await?;
    println!(
        "{}",
        serde_json::to_string_pretty(&report).expect("suggestion report serializes")
    );
    Ok(())
}

/// `field make-sensitive`: retrofit a populated field into the vault —
/// the core half (rows, drafts, versions, mutation audit) then the ingest
/// half (provenance, landing). Fails closed without a full vault config.
async fn run_field(args: Vec<String>) -> tinker_core::Result<()> {
    let mut it = args.into_iter();
    if it.next().as_deref() != Some("make-sensitive") {
        usage();
    }
    let (mut object, mut field) = (None, None);
    while let Some(flag) = it.next() {
        match flag.as_str() {
            "--object" => object = it.next(),
            "--field" => field = it.next(),
            _ => usage(),
        }
    }
    let (object, field) = (
        object.unwrap_or_else(|| usage()),
        field.unwrap_or_else(|| usage()),
    );
    let sealer = tinker_ontology::sensitive::sealer_from_env()
        .await?
        .ok_or_else(|| {
            tinker_core::TinkerError::Validation(
                "make-sensitive needs TINKER_PII_URL, TINKER_KEK and TINKER_BLIND_INDEX_KEY".into(),
            )
        })?;
    let owner = OwnerDb::connect(&env("TINKER_CORE_OWNER_URL")).await?;
    let core = CoreDb::connect(&env("TINKER_CORE_URL")).await?;
    let object_ids: Vec<Uuid> = sqlx::query_scalar(
        "SELECT id FROM ontology_objects WHERE api_slug = $1 AND adopted_from IS NULL",
    )
    .bind(&object)
    .fetch_all(&owner.0)
    .await
    .map_err(tinker_core::TinkerError::Db)?;
    let [object_id] = object_ids[..] else {
        return Err(tinker_core::TinkerError::Validation(format!(
            "object slug '{object}' must name exactly one defining object (found {})",
            object_ids.len()
        )));
    };
    let report = sealer
        .make_field_sensitive(&owner, object_id, &field)
        .await?;
    let ingest = tinker_ingest::IngestPipeline::new(core, owner)
        .retrofit_sensitive(&sealer, &object, &field)
        .await?;
    println!(
        "{}",
        serde_json::json!({
            "object": object,
            "field": field,
            "rows_sealed": report.rows,
            "history_copies_sealed": report.history_copies,
            "ingest_copies_replaced": ingest,
            "dropped_column": report.old_column,
            "new_column": report.new_column,
            "next": format!("restart servers; VACUUM FULL data.{object}; rotate backups that predate this run"),
        })
    );
    Ok(())
}

/// Email/phone fields (PII by type) that still store plaintext:
/// (object_id, object_slug, api_name), defining objects only.
async fn plaintext_pii_fields(owner: &OwnerDb) -> tinker_core::Result<Vec<(Uuid, String, String)>> {
    sqlx::query_as(
        "SELECT o.id, o.api_slug, f.api_name FROM ontology_fields f \
         JOIN ontology_objects o ON o.id = f.object_id \
         WHERE f.state = 'active' AND o.adopted_from IS NULL \
           AND f.field_type IN ('email', 'phone') AND NOT f.sensitive \
         ORDER BY o.api_slug, f.api_name",
    )
    .fetch_all(&owner.0)
    .await
    .map_err(tinker_core::TinkerError::Db)
}

/// `pii verify` / `pii retrofit`: the no-plaintext-PII gate and its fix.
async fn run_pii(args: Vec<String>) -> tinker_core::Result<()> {
    let owner = OwnerDb::connect(&env("TINKER_CORE_OWNER_URL")).await?;
    let fields = plaintext_pii_fields(&owner).await?;
    match args.first().map(String::as_str) {
        Some("verify") => {
            for (_, slug, api) in &fields {
                println!("plaintext PII: {slug}.{api}");
            }
            if fields.is_empty() {
                println!("ok: every email/phone field is vault-backed");
                Ok(())
            } else {
                Err(tinker_core::TinkerError::Validation(format!(
                    "{} email/phone field(s) store plaintext; run `tinker-cli pii retrofit`",
                    fields.len()
                )))
            }
        }
        Some("sweep") => {
            let grace = match (args.get(1).map(String::as_str), args.get(2)) {
                (None, _) => 60,
                (Some("--grace-minutes"), Some(n)) => n.parse().unwrap_or_else(|_| usage()),
                _ => usage(),
            };
            let pii_owner = sqlx::PgPool::connect(&env("TINKER_PII_OWNER_URL"))
                .await
                .map_err(tinker_core::TinkerError::Db)?;
            let removed = tinker_ontology::sensitive::sweep_orphans(
                &owner.0,
                &pii_owner,
                chrono::Duration::minutes(grace),
            )
            .await?;
            println!("sweep: {removed} orphaned vault value(s) destroyed (grace {grace} min)");
            Ok(())
        }
        Some("retrofit") => {
            let sealer = tinker_ontology::sensitive::sealer_from_env()
                .await?
                .ok_or_else(|| {
                    tinker_core::TinkerError::Validation(
                        "pii retrofit needs TINKER_PII_URL, TINKER_KEK and TINKER_BLIND_INDEX_KEY"
                            .into(),
                    )
                })?;
            let core = CoreDb::connect(&env("TINKER_CORE_URL")).await?;
            let ingest = tinker_ingest::IngestPipeline::new(core, owner.clone());
            let (mut done, mut failed) = (0usize, 0usize);
            for (object_id, slug, api) in &fields {
                let res = async {
                    let r = sealer.make_field_sensitive(&owner, *object_id, api).await?;
                    let n = ingest.retrofit_sensitive(&sealer, slug, api).await?;
                    Ok::<_, tinker_core::TinkerError>((r, n))
                }
                .await;
                match res {
                    Ok((r, n)) => {
                        done += 1;
                        println!(
                            "sealed {slug}.{api}: {} rows, {} history copies, {n} ingest copies",
                            r.rows, r.history_copies
                        );
                    }
                    Err(e) => {
                        failed += 1;
                        eprintln!("FAILED {slug}.{api}: {e}");
                    }
                }
            }
            println!("retrofit: {done} field(s) sealed, {failed} failed");
            if failed > 0 {
                return Err(tinker_core::TinkerError::Validation(format!(
                    "{failed} field(s) could not be retrofitted"
                )));
            }
            println!("next: restart servers; VACUUM FULL the touched tables; rotate older backups");
            Ok(())
        }
        _ => usage(),
    }
}
