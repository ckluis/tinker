//! `tinker-mcp`: the MCP front door as a stdio JSON-RPC server,
//! or — with the `serve` subcommand (item 46) — as an HTTP/SSE server.
//!
//! Configuration (environment):
//!
//! * `TINKER_CORE_OWNER_URL` — Postgres URL for the operational store
//!   (owner role; migrations, machine-credential verification, and
//!   pre-tenant lookups).
//! * `TINKER_CORE_URL` — Postgres URL for the tenant-facing pool (app
//!   role, RLS always applies).
//! * `TINKER_API_KEY` — the C6 machine credential (`tk_...`), stdio
//!   mode only. Verified once at startup; every verification failure
//!   exits non-zero with the same message — no oracle, and the key
//!   itself is never logged. Serve mode does NOT read this variable:
//!   the key arrives per request as `Authorization: Bearer`.
//! * `TINKER_FILE_ROOT` / S3 vars — the file backend (item 42), via
//!   `backend_from_env`; misconfiguration fails closed at startup.
//!
//! Protocol (stdio): newline-delimited JSON-RPC 2.0 on stdin/stdout.
//! Logging goes to stderr ONLY — stdout is the protocol.
//!
//! Serve mode: `tinker-mcp serve [--bind 127.0.0.1:8080]` —
//! `POST /mcp` (JSON-RPC, or SSE when the client asks),
//! `GET /mcp/stream` (server→client SSE), `DELETE /mcp` (session
//! teardown). See `tinker_mcp::http` for the route contract.

use tinker_auth::apikey::MachineCredentialStore;
use tinker_core::{OrganizationId, TenantContext};
use tinker_db::{CoreDb, OwnerDb};
use tinker_mcp::{build_services_with_pii, FrontDoor};

fn required_env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| {
        eprintln!("tinker-mcp: {name} must be set");
        std::process::exit(2);
    })
}

#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("tinker-mcp: fatal: {e}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), String> {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        // Item 46: server mode. Bare invocation keeps the item-45
        // stdio behavior exactly as it was.
        Some("serve") => {
            let mut bind = "127.0.0.1:8080".to_string();
            while let Some(arg) = args.next() {
                match arg.as_str() {
                    "--bind" => {
                        bind = args
                            .next()
                            .ok_or_else(|| "--bind requires a value".to_string())?;
                    }
                    other => return Err(format!("unknown argument for serve: {other}")),
                }
            }
            tinker_mcp::http::serve(&bind).await
        }
        Some(other) => Err(format!(
            "unknown subcommand {other:?}; run with no arguments for stdio, or `serve` for HTTP/SSE"
        )),
        None => run_stdio().await,
    }
}

/// The item-45 stdio server, unchanged.
async fn run_stdio() -> Result<(), String> {
    let owner_url = required_env("TINKER_CORE_OWNER_URL");
    let core_url = required_env("TINKER_CORE_URL");
    let api_key = required_env("TINKER_API_KEY");

    let owner = OwnerDb::connect(&owner_url)
        .await
        .map_err(|e| format!("owner db connect: {e}"))?;
    // Same cluster-wide migration discipline as the `tinker` server:
    // exactly one instance migrates while the rest wait.
    owner.migrate().await.map_err(|e| format!("migrate: {e}"))?;
    let core = CoreDb::connect(&core_url)
        .await
        .map_err(|e| format!("tenant db connect: {e}"))?;

    // The credential binds (organization, actor). Every failure mode —
    // unknown prefix, malformed secret, hash mismatch, revoked, expired
    // — exits the same way: no oracle, and the secret is never echoed.
    let store = MachineCredentialStore::new(owner.clone());
    let cred = store
        .verify(&api_key)
        .await
        .map_err(|_| "auth failed: invalid API key".to_string())?;
    // TINKER_API_KEY is no longer needed past this point; it is not
    // logged, not stored, and not passed anywhere else.
    drop(api_key);

    let tenant = TenantContext::new(
        OrganizationId(cred.organization_id),
        cred.actor_id,
        "tinker-mcp".to_string(),
    );
    // Sensitive fields: the PII vault from the environment. Unset → no
    // vault (sensitive writes fail closed); partially set → startup error.
    let pii = tinker_ontology::sensitive::sealer_from_env()
        .await
        .map_err(|e| format!("pii vault: {e}"))?;
    let (state, mutator, lifecycle) =
        build_services_with_pii(core.0.clone(), owner.0.clone(), pii).map_err(|e| e.to_string())?;
    // The role comes from the membership table — the same trusted
    // source the HTTP tier uses. No membership fails closed here, at
    // startup, with the fix spelled out; inventing a default role
    // would be inventing permissions.
    let role = FrontDoor::resolve_role(&state.core, &tenant)
        .await
        .map_err(|e| format!("auth failed: {e}"))?;

    let server = FrontDoor::new(state, mutator, lifecycle, cred, tenant, role);
    eprintln!("tinker-mcp: ready (stdio)");

    let stdin = tokio::io::stdin();
    let mut lines = tokio::io::AsyncBufReadExt::lines(tokio::io::BufReader::new(stdin));
    let mut stdout = tokio::io::stdout();
    loop {
        let line = lines.next_line().await.map_err(|e| format!("stdin: {e}"))?;
        let Some(line) = line else {
            break; // EOF: the client hung up; exit cleanly.
        };
        if line.trim().is_empty() {
            continue;
        }
        // Only the method name is logged — never params, which may
        // carry record content.
        if let Some(response) = server.handle(&line).await {
            use tokio::io::AsyncWriteExt;
            stdout
                .write_all(response.as_bytes())
                .await
                .map_err(|e| format!("stdout: {e}"))?;
            stdout
                .write_all(b"\n")
                .await
                .map_err(|e| format!("stdout: {e}"))?;
            stdout.flush().await.map_err(|e| format!("stdout: {e}"))?;
        }
    }
    eprintln!("tinker-mcp: stdin closed, exiting");
    Ok(())
}
