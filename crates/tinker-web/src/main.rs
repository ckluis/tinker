//! The Tinker binary: one process serving every organization.
//!
//! Configuration (environment):
//!
//! * `TINKER_CORE_OWNER_URL` — Postgres URL for the owner role
//!   (migrations, pre-tenant lookups).
//! * `TINKER_CORE_URL` — Postgres URL for the tenant-facing pool (app
//!   role, RLS always applies). Same names as `tinker-mcp`/`tinker-cli`.
//! * Legacy: when `TINKER_APP_URL` is set, it is the app-role URL and
//!   `TINKER_CORE_URL` is the owner URL (the old layout of this binary).
//!   Startup refuses any tenant URL whose role RLS does not bind.
//! * `TINKER_HOST` — public host name, the mandatory host context.
//! * `TINKER_ADDR` — listen address, default `127.0.0.1:8080`.
//! * `TINKER_COOKIE_SECURE` — session cookies carry `Secure` by default;
//!   set to `0` only for plain-HTTP local development.
//! * `TINKER_REDIS_URL` — optional Redis URL (e.g.
//!   `redis://127.0.0.1:6379/`). When set, the SSE signal bus fans out
//!   across instances via Redis pub/sub (item 30 scale-out spike);
//!   startup fails closed if Redis is unreachable. When unset, signals
//!   stay in-process (single-instance mode).
//! * `OIDC_ISSUER`, `OIDC_AUDIENCE`, `OIDC_RSA_PEM` — when all three are
//!   set, the OIDC adapter joins the broker. JWKS fetching is backlog;
//!   supply the provider's RSA public key as PEM.

use std::net::SocketAddr;

use tinker_auth::{AuthBroker, OidcAdapter, OidcConfig, OidcKey, PasskeyAdapter};
use tinker_db::{CoreDb, OwnerDb};
use tinker_identity::{PgOidcBindingStore, PgPasskeyStore};
use tinker_web::build_router;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Item 43: `tinker describe` — the self-describing ontology as a CLI.
    // A subcommand, not a flag: when present the server never starts.
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some("describe") {
        return run_describe_cli(&args[2..]).await;
    }
    // Item 44: `tinker agent` — install/verify the version-matched agent
    // skill. Also a subcommand; the server never starts.
    if args.get(1).map(String::as_str) == Some("agent") {
        return run_agent_cli(&args[2..]);
    }

    let (core_url, app_url) = db_urls();
    let host_name = std::env::var("TINKER_HOST").unwrap_or_else(|_| "tinker.local".into());
    let addr: SocketAddr = std::env::var("TINKER_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:8080".into())
        .parse()?;
    // Secure by default: forgetting a flag must not ship session cookies
    // over plain HTTP. Local plain-HTTP dev opts out explicitly with 0.
    let cookie_secure = std::env::var("TINKER_COOKIE_SECURE").as_deref() != Ok("0");

    let owner = OwnerDb::connect(&core_url).await?;
    // Cluster-wide advisory lock: every instance runs this at startup
    // and exactly one migrates while the rest wait.
    owner.migrate().await?;
    let tenant = CoreDb::connect(&app_url).await?;

    let tenant_pool = tenant.0.clone();
    let system_pool = owner.0.clone();

    // The broker is assembled here, once, from configuration. Everything
    // downstream (sessions, grants, rendering) only sees AuthnContext.
    let mut adapters: Vec<Box<dyn tinker_auth::AuthAdapter>> = vec![Box::new(PasskeyAdapter::new(
        PgPasskeyStore::new(tenant_pool.clone()),
    ))];
    if let (Ok(issuer), Ok(audience), Ok(pem_path)) = (
        std::env::var("OIDC_ISSUER"),
        std::env::var("OIDC_AUDIENCE"),
        std::env::var("OIDC_RSA_PEM"),
    ) {
        let pem = std::fs::read(&pem_path)?;
        adapters.push(Box::new(OidcAdapter::new(
            PgOidcBindingStore::new(system_pool.clone()),
            OidcConfig {
                issuer,
                audience,
                keys: vec![OidcKey {
                    key_id: None,
                    algorithm: jsonwebtoken::Algorithm::RS256,
                    decoding_key: jsonwebtoken::DecodingKey::from_rsa_pem(&pem)?,
                }],
            },
        )));
        eprintln!("oidc adapter enabled");
    }
    let broker = AuthBroker::new(adapters);

    // Sensitive fields: the PII vault from the environment (fails loud on
    // a partial configuration; unset disables sensitive writes).
    let pii = tinker_ontology::sensitive::sealer_from_env().await?;
    let state = tinker_web::build_state_with_pii(
        tenant_pool,
        system_pool,
        broker,
        host_name,
        cookie_secure,
        pii,
    );
    // Item 30: cross-instance SSE signal fan-out. Opt-in via
    // TINKER_REDIS_URL; unset keeps the in-process bus.
    if let Ok(redis_url) = std::env::var("TINKER_REDIS_URL") {
        if !redis_url.trim().is_empty() {
            state.signals.enable_redis_fanout(&redis_url).await?;
            eprintln!("signal fan-out enabled via redis");
        }
    }
    // M5: install the platform comms tables (owner-backed DDL, idempotent).
    state.comms.install().await?;
    let app = build_router(state);

    eprintln!("tinker listening on {addr}");
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Item 43: `tinker describe [object] [--json] --org <uuid> --role <role>`
//
// Operator introspection over the same read projection the HTTP API
// serves. `--org` selects the organization; `--role` is an explicit
// view-as: the CLI runs with direct database access, so the role picks
// which permission-projected view to render (the same projection a
// session with that role would get over HTTP).
//
// Configuration: TINKER_CORE_URL (owner pool) and TINKER_APP_URL (the
// tenant-facing app-role pool). The database must already be migrated;
// describe is read-only and never runs migrations.
fn describe_usage() -> &'static str {
    "usage: tinker describe [object] [--json] --org <uuid> --role <role>\n\
     \n\
     describe the ontology: catalog, or one object's fields, relations,\n\
     row-policy summary, lifecycle, and mutation/read contracts.\n\
     \n\
     --org <uuid>   organization to describe as (required)\n\
     --role <role>  view-as role for permission projection (required)\n\
     --json         canonical JSON output (default: human-readable text)"
}

async fn run_describe_cli(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut object: Option<String> = None;
    let mut json = false;
    let mut org: Option<String> = None;
    let mut role: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--json" => json = true,
            "--org" => {
                i += 1;
                org = args.get(i).cloned();
            }
            "--role" => {
                i += 1;
                role = args.get(i).cloned();
            }
            "--help" | "-h" => {
                println!("{}", describe_usage());
                return Ok(());
            }
            other if other.starts_with("--") => {
                eprintln!("unknown flag: {other}\n{}", describe_usage());
                std::process::exit(2);
            }
            positional => {
                if object.is_some() {
                    eprintln!("unexpected argument: {positional}\n{}", describe_usage());
                    std::process::exit(2);
                }
                object = Some(positional.to_string());
            }
        }
        i += 1;
    }
    let (Some(org), Some(role)) = (org, role) else {
        eprintln!("--org and --role are required\n{}", describe_usage());
        std::process::exit(2);
    };
    let org_id: uuid::Uuid = org
        .parse()
        .map_err(|_| "--org must be a uuid".to_string())?;
    if role.is_empty() || role.len() > 64 {
        eprintln!("--role must be 1..=64 chars");
        std::process::exit(2);
    }

    let (core_url, app_url) = db_urls();
    let owner = tinker_db::OwnerDb::connect(&core_url).await?;
    let core = tinker_db::CoreDb::connect(&app_url).await?;
    let describer = tinker_web::describe::Describer::for_cli(core, owner);
    // Nil actor: describe reads metadata only, never row data, so no
    // actor-scoped value is ever resolved. The role (not the actor)
    // drives the projection.
    let ctx = tinker_core::TenantContext::new(
        tinker_core::OrganizationId(org_id),
        uuid::Uuid::nil(),
        "tinker-describe-cli".to_string(),
    );

    if json {
        let value = match &object {
            None => {
                let c = describer.catalog(&ctx, &role).await?;
                serde_json::to_value(&c)?
            }
            Some(slug) => {
                let o = describer.object(&ctx, &role, slug).await?;
                serde_json::to_value(&o)?
            }
        };
        // Canonical bytes are the contract; print them as UTF-8.
        let bytes = tinker_web::describe::canonical_json(&value);
        println!(
            "{}",
            String::from_utf8(bytes).expect("canonical JSON is UTF-8")
        );
        return Ok(());
    }

    match &object {
        None => {
            let c = describer.catalog(&ctx, &role).await?;
            print!("{}", tinker_web::describe::render_catalog_text(&c));
        }
        Some(slug) => {
            let o = describer.object(&ctx, &role, slug).await?;
            print!("{}", tinker_web::describe::render_object_text(&o));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Item 44: `tinker agent install|verify [--global] [--dir <path>]`
//
// The version-matched agent skill. Install copies the embedded SKILL.md
// (with the binary's versions substituted) into the standard
// agent-skills location; verify reads an installed skill back and fails
// loudly on version drift. Neither touches the database — versions are
// compile-time facts about this binary.
fn agent_usage() -> &'static str {
    "usage: tinker agent <install|verify> [--global] [--dir <path>]\n\
     \n\
     install   install the version-matched agent skill\n\
     verify    check the installed skill's pinned versions against this binary\n\
     \n\
     --global  use the personal skills dir (~/.claude/skills) instead of\n\
               the project-local one (./.claude/skills)\n\
     --dir <path>\n\
               override the skills root (the skill installs to <path>/tinker/)"
}

fn run_agent_cli(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut subcommand: Option<String> = None;
    let mut global = false;
    let mut dir: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--global" => global = true,
            "--dir" => {
                i += 1;
                dir = args.get(i).cloned();
            }
            "--help" | "-h" => {
                println!("{}", agent_usage());
                return Ok(());
            }
            other if other.starts_with("--") => {
                eprintln!("unknown flag: {other}\n{}", agent_usage());
                std::process::exit(2);
            }
            positional => {
                if subcommand.is_some() {
                    eprintln!("unexpected argument: {positional}\n{}", agent_usage());
                    std::process::exit(2);
                }
                subcommand = Some(positional.to_string());
            }
        }
        i += 1;
    }
    let subcommand = match subcommand.as_deref() {
        Some("install") | Some("verify") => subcommand.unwrap(),
        _ => {
            eprintln!("expected `install` or `verify`\n{}", agent_usage());
            std::process::exit(2);
        }
    };
    if global && dir.is_some() {
        eprintln!(
            "--global and --dir are mutually exclusive\n{}",
            agent_usage()
        );
        std::process::exit(2);
    }
    let root = match dir {
        Some(d) => std::path::PathBuf::from(d),
        None => tinker_web::agent::default_skills_root(global).map_err(|e| e.to_string())?,
    };
    match subcommand.as_str() {
        "install" => {
            let path = tinker_web::agent::install_skill(&root).map_err(|e| e.to_string())?;
            let v = tinker_web::agent::current_versions();
            println!(
                "installed agent skill -> {}\nskill pins tinker {} / ontology {}",
                path.display(),
                v.tinker_version,
                v.ontology_version
            );
            Ok(())
        }
        "verify" => match tinker_web::agent::verify_skill(&root) {
            Ok(v) => {
                println!(
                    "skill OK: tinker {} / ontology {} ({})",
                    v.tinker_version,
                    v.ontology_version,
                    root.join(tinker_web::agent::SKILL_DIR_NAME).display()
                );
                Ok(())
            }
            Err(e) => {
                eprintln!("skill verify FAILED: {e}");
                std::process::exit(1);
            }
        },
        _ => unreachable!(),
    }
}

/// (owner URL, tenant app-role URL).
///
/// Canonical names match `tinker-mcp` and `tinker-cli`:
/// `TINKER_CORE_OWNER_URL` = owner, `TINKER_CORE_URL` = RLS-bound app
/// role. The legacy layout this binary used to require —
/// `TINKER_CORE_URL` = owner plus `TINKER_APP_URL` = app role — is still
/// honored whenever `TINKER_APP_URL` is set. Either way
/// `CoreDb::connect` refuses a tenant URL that names an RLS-exempt role,
/// so a swapped pair fails at startup instead of serving unisolated.
fn db_urls() -> (String, String) {
    let var = |k: &str| std::env::var(k).ok().filter(|v| !v.is_empty());
    let need = |k: &str| {
        var(k).unwrap_or_else(|| {
            eprintln!("{k} must be set");
            std::process::exit(2);
        })
    };
    match var("TINKER_APP_URL") {
        Some(app) => (need("TINKER_CORE_URL"), app),
        None => (need("TINKER_CORE_OWNER_URL"), need("TINKER_CORE_URL")),
    }
}
