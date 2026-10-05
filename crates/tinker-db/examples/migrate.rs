//! Dev utility: run core + PII migrations against owner URLs from env,
//! then set the app-role passwords from environment-provided URLs.
//!
//! The 0001 migrations create tinker_app / tinker_pii_app with
//! repo-embedded dev passwords when the roles do not exist (frozen
//! migrations). Running this example without the env bootstrap would
//! leave those published defaults live, so the app-role password
//! rotation is mandatory here, not optional: it fails closed when the
//! app URLs are absent or carry no password segment.
//!
//! Usage: TINKER_CORE_OWNER_URL=... TINKER_PII_OWNER_URL=...
//!        TINKER_CORE_URL=... TINKER_PII_URL=...
//!        cargo run -p tinker-db --example migrate

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let core_url = std::env::var("TINKER_CORE_OWNER_URL")?;
    let pii_url = std::env::var("TINKER_PII_OWNER_URL")?;
    let core_app_url = std::env::var("TINKER_CORE_URL").map_err(|_| {
        "TINKER_CORE_URL must be set: app-role passwords are environment-provided, never defaults"
    })?;
    let pii_app_url = std::env::var("TINKER_PII_URL").map_err(|_| {
        "TINKER_PII_URL must be set: PII app-role passwords are environment-provided, never defaults"
    })?;
    let core = tinker_db::OwnerDb::connect(&core_url).await?;
    core.migrate().await?;
    println!("core migrations applied");
    let pii = tinker_db::PiiDb::connect(&pii_url).await?;
    pii.migrate().await?;
    println!("pii migrations applied");
    // Owner handles: the app roles own nothing, so only a privileged
    // role can set their passwords. Fails closed on missing passwords.
    tinker_db::rotate_app_role_passwords(&core.0, &pii.0, &core_app_url, &pii_app_url).await?;
    println!("app role passwords set from environment");
    Ok(())
}
