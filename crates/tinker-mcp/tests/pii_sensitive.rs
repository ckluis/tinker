//! Sensitive fields end to end through the MCP front door
//! (docs/pii-sensitive-fields.md).
//!
//! The contract under test:
//! - A `sensitive` field's value never lands in core in plaintext: the
//!   data row holds a vault ref (UUID) + blind index, the mutation audit
//!   holds the sealed form, and `pii_refs` tracks the ref.
//! - Every read path (`query`, `get_record`) returns the mask.
//! - Exact-match lookups work through the blind index (normalized:
//!   case/whitespace for email); plaintext-comparing operators and sorts
//!   are refused.
//! - `reveal` is the only plaintext path: owner/admin role, explicit
//!   `mcp:tool:reveal` scope, purpose required and audited (never the
//!   value), foreign records are not_found.
//! - Callers cannot smuggle a sealed form, and a server without a vault
//!   refuses sensitive writes instead of storing plaintext.

use serde_json::{json, Value};
use tinker_auth::apikey::{MachineCredentialStore, VerifiedCredential};
use tinker_core::{OrganizationId, TenantContext};
use tinker_db::{CoreDb, OwnerDb};
use tinker_mcp::{build_services, build_services_with_pii, FrontDoor};
use tinker_ontology::sensitive::{sealer_from_env, MASK};
use tinker_ontology::{FieldDef, FieldType, ObjectDef, Ontology, Scope, ValidationRules};
use tokio::sync::OnceCell;
use uuid::Uuid;

/// A `pii_values` row as a backup would hold it:
/// (id, subject_id, storage_class, ciphertext, nonce, wrapped_dek_id).
type PiiValueRow = (Uuid, Uuid, String, Vec<u8>, Vec<u8>, Uuid);

fn env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("{name} must be set"))
}

struct Env {
    core: CoreDb,
    core_owner: sqlx::PgPool,
    host_id: Uuid,
}

static MIGRATED: OnceCell<()> = OnceCell::const_new();

async fn setup() -> Env {
    std::env::set_var(
        "TINKER_FILE_ROOT",
        std::env::temp_dir().join(format!("tinker-pii-test-{}", std::process::id())),
    );
    let core_owner = sqlx::PgPool::connect(&env("TINKER_CORE_OWNER_URL"))
        .await
        .expect("core owner connect");
    MIGRATED
        .get_or_init(|| async {
            tinker_db::MIGRATOR_CORE
                .run(&core_owner)
                .await
                .expect("core migrations");
            let pii_owner = sqlx::PgPool::connect(&env("TINKER_PII_OWNER_URL"))
                .await
                .expect("pii owner connect");
            tinker_db::MIGRATOR_PII
                .run(&pii_owner)
                .await
                .expect("pii migrations");
        })
        .await;
    let core = CoreDb::connect(&env("TINKER_CORE_URL"))
        .await
        .expect("core app-role connect");
    let host_id = Uuid::from_u128(0x0);
    sqlx::query("INSERT INTO hosts (id, name) VALUES ($1,'test') ON CONFLICT (id) DO NOTHING")
        .bind(host_id)
        .execute(&core_owner)
        .await
        .expect("host upsert");
    Env {
        core,
        core_owner,
        host_id,
    }
}

fn uniq(prefix: &str) -> String {
    let s = Uuid::now_v7().simple().to_string();
    format!("{prefix}{}", &s[24..32])
}

async fn new_org(env: &Env) -> TenantContext {
    let org_id = Uuid::now_v7();
    let slug = uniq("piiorg");
    sqlx::query("INSERT INTO organizations (id, host_id, name, slug) VALUES ($1,$2,$3,$3)")
        .bind(org_id)
        .bind(env.host_id)
        .bind(&slug)
        .execute(&env.core_owner)
        .await
        .expect("org insert");
    TenantContext::new(
        OrganizationId(org_id),
        Uuid::now_v7(),
        "pii-test".to_string(),
    )
}

fn field(api_name: &str, field_type: FieldType, sensitive: bool) -> FieldDef {
    FieldDef {
        name: api_name.into(),
        api_name: api_name.into(),
        label: api_name.into(),
        field_type,
        options: json!({}),
        required: false,
        validation: ValidationRules::default(),
        preset: None,
        max_pii_class: "none".into(),
        sensitive,
    }
}

/// Org with a `contact` object: plain `name`, sensitive `email` + `phone`.
async fn contact_object(env: &Env, ctx: &TenantContext) -> (Uuid, String) {
    let ont = Ontology::new(env.core.clone(), OwnerDb(env.core_owner.clone()));
    let slug = uniq("contact");
    let meta = ont
        .define_object(
            ctx,
            &ObjectDef {
                name: slug.clone(),
                api_slug: slug.clone(),
                label: slug.clone(),
                scope: Scope::Organization,
                pack_id: None,
                pack_version: None,
            },
        )
        .await
        .unwrap();
    ont.add_field(ctx, meta.id, &field("name", FieldType::Text, false))
        .await
        .unwrap();
    ont.add_field(ctx, meta.id, &field("email", FieldType::Email, true))
        .await
        .unwrap();
    ont.add_field(ctx, meta.id, &field("phone", FieldType::Phone, true))
        .await
        .unwrap();
    (meta.id, slug)
}

async fn issue_key(env: &Env, org: Uuid, role: &str, scopes: &[&str]) -> VerifiedCredential {
    let store = MachineCredentialStore::new(OwnerDb(env.core_owner.clone()));
    let scopes: Vec<String> = scopes.iter().map(|s| s.to_string()).collect();
    let issued = store
        .issue(org, &uniq("k"), &scopes, None, None)
        .await
        .expect("key issue");
    store
        .grant_machine_role(org, issued.credential.actor_id, role)
        .await
        .expect("grant role");
    store.verify(&issued.secret).await.expect("key verify")
}

async fn door(env: &Env, cred: &VerifiedCredential, with_vault: bool) -> FrontDoor {
    let (state, mutator, lifecycle) = if with_vault {
        let pii = sealer_from_env()
            .await
            .expect("vault env")
            .expect("TINKER_PII_URL, TINKER_KEK, TINKER_BLIND_INDEX_KEY must be set");
        build_services_with_pii(env.core.0.clone(), env.core_owner.clone(), Some(pii))
    } else {
        build_services(env.core.0.clone(), env.core_owner.clone())
    }
    .expect("build_services");
    let tenant = TenantContext::new(
        OrganizationId(cred.organization_id),
        cred.actor_id,
        "pii-test".to_string(),
    );
    let role = FrontDoor::resolve_role(&state.core, &tenant).await.unwrap();
    FrontDoor::new(state, mutator, lifecycle, cred.clone(), tenant, role)
}

async fn rpc(door: &FrontDoor, method: &str, params: Value) -> Value {
    let raw = json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).to_string();
    serde_json::from_str(&door.handle(&raw).await.expect("response")).unwrap()
}

/// Ok(payload) for a successful tool call, Err(error payload) otherwise.
async fn tool(door: &FrontDoor, name: &str, args: Value) -> Result<Value, Value> {
    let resp = rpc(door, "tools/call", json!({"name": name, "arguments": args})).await;
    if let Some(e) = resp.get("error") {
        return Err(e.clone());
    }
    let r = &resp["result"];
    let text: Value = serde_json::from_str(r["content"][0]["text"].as_str().unwrap()).unwrap();
    if r["isError"] == true {
        Err(text)
    } else {
        Ok(text)
    }
}

/// The full second-person reveal: the caller files a pii.reveal request,
/// a different admin approves it, the caller reveals with its id.
async fn reveal(
    env: &Env,
    org: Uuid,
    door: &FrontDoor,
    slug: &str,
    id: &str,
    field: &str,
) -> Result<Value, Value> {
    let req = tool(
        door,
        "request_reveal",
        json!({"object": slug, "record_id": id, "field": field, "purpose": "support ticket 42"}),
    )
    .await?;
    let approver = issue_key(env, org, "admin", &["mcp:tools", "mcp:tool:approvals"]).await;
    let approver_door = door_for(env, &approver).await;
    let pending = tool(&approver_door, "approvals", json!({"action": "list"})).await?;
    let listed = pending["pending"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["id"] == req["approval_request_id"])
        .expect("the pending request is listed for the approver");
    assert_eq!(listed["action"], "pii.reveal");
    assert_eq!(listed["payload"]["field"], field);
    tool(
        &approver_door,
        "approvals",
        json!({"action": "approve", "id": req["approval_request_id"]}),
    )
    .await?;
    tool(
        door,
        "reveal",
        json!({"object": slug, "record_id": id, "field": field,
               "approval_request_id": req["approval_request_id"]}),
    )
    .await
}

async fn door_for(env: &Env, cred: &VerifiedCredential) -> FrontDoor {
    door(env, cred, true).await
}

#[tokio::test]
async fn sensitive_values_are_sealed_masked_findable_and_revealable() {
    let env = setup().await;
    let ctx = new_org(&env).await;
    let (object_id, slug) = contact_object(&env, &ctx).await;
    let admin = issue_key(
        &env,
        ctx.organization_id.0,
        "admin",
        &["mcp:tools", "mcp:tool:reveal", "mcp:tool:request_reveal"],
    )
    .await;
    let d = door(&env, &admin, true).await;

    // describe tells the agent which fields are sensitive.
    let desc = tool(&d, "describe", json!({"object": slug})).await.unwrap();
    let email_desc = desc["fields"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["api_name"] == "email")
        .unwrap();
    assert_eq!(email_desc["sensitive"], true, "{email_desc}");

    let created = tool(
        &d,
        "create_record",
        json!({"object": slug, "values": {"name": "Maya", "email": "Maya.Chen@Example.com", "phone": "+1 (555) 010-2000"}}),
    )
    .await
    .unwrap();
    let id = created["record_id"].as_str().unwrap().to_string();

    // At rest: no plaintext anywhere in core.
    let row: String = sqlx::query_scalar(&format!(
        "SELECT to_jsonb(t)::text FROM data.{slug} t WHERE id = $1::uuid"
    ))
    .bind(&id)
    .fetch_one(&env.core_owner)
    .await
    .unwrap();
    for needle in [
        // Needles long and specific enough never to occur by chance in a
        // UUID or hex digest ("555" once matched a blind-index digest).
        "maya.chen",
        "Maya.Chen",
        "Example.com",
        "5550102000",
        "010-2000",
    ] {
        assert!(
            !row.contains(needle),
            "plaintext {needle:?} in data row: {row}"
        );
    }
    let mut tx = env.core.tenant_tx(&ctx).await.unwrap();
    let audit: String = sqlx::query_scalar(
        "SELECT after_json::text FROM mutation_audit WHERE record_id = $1::uuid",
    )
    .bind(&id)
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    assert!(
        !audit.contains("Maya.Chen") && audit.contains("pii_ref"),
        "{audit}"
    );
    let refs: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM pii_refs WHERE subject_id = $1::uuid AND state = 'active'",
    )
    .bind(&id)
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(refs, 2, "one active ref per sealed value");

    // Reads mask.
    let rec = tool(&d, "get_record", json!({"object": slug, "record_id": id}))
        .await
        .unwrap();
    assert_eq!(rec["record"]["email"], MASK);
    assert_eq!(rec["record"]["phone"], MASK);
    assert_eq!(rec["record"]["name"], "Maya");
    let q = tool(
        &d,
        "query",
        json!({"object": slug, "intent": {"select": ["name", "email"]}}),
    )
    .await
    .unwrap();
    assert_eq!(q["rows"][0]["email"], MASK, "{q}");

    // Exact-match lookup through the blind index, normalized.
    let find = |email: &str| json!({"object": slug, "intent": {"select": ["name"], "filters": [{"field": "email", "op": "eq", "value": email}]}});
    let hit = tool(&d, "query", find("  maya.chen@example.COM "))
        .await
        .unwrap();
    assert_eq!(hit["rows"].as_array().unwrap().len(), 1, "{hit}");
    let miss = tool(&d, "query", find("someone@else.com")).await.unwrap();
    assert!(miss["rows"].as_array().unwrap().is_empty());
    let by_phone = tool(
        &d,
        "query",
        json!({"object": slug, "intent": {"select": ["name"], "filters": [{"field": "phone", "op": "in", "value": ["+15550102000", "+1999"]}]}}),
    )
    .await
    .unwrap();
    assert_eq!(by_phone["rows"].as_array().unwrap().len(), 1, "{by_phone}");
    // Plaintext-comparing operators and sorts are refused.
    let err = tool(
        &d,
        "query",
        json!({"object": slug, "intent": {"select": ["name"], "filters": [{"field": "email", "op": "starts_with", "value": "maya"}]}}),
    )
    .await
    .unwrap_err();
    assert!(err.to_string().contains("sensitive"), "{err}");
    let err = tool(
        &d,
        "query",
        json!({"object": slug, "intent": {"select": ["name"], "order": [{"field": "email", "descending": false}]}}),
    )
    .await
    .unwrap_err();
    assert!(err.to_string().contains("sensitive"), "{err}");

    // Reveal returns the original plaintext and audits the purpose only.
    let v = reveal(&env, ctx.organization_id.0, &d, &slug, &id, "email")
        .await
        .unwrap();
    assert_eq!(v["value"], "Maya.Chen@Example.com");
    let mut tx = env.core.tenant_tx(&ctx).await.unwrap();
    let meta: Vec<String> = sqlx::query_scalar(
        "SELECT metadata::text FROM audit_events WHERE action = 'pii.resolve' AND actor_id = $1",
    )
    .bind(admin.actor_id)
    .fetch_all(&mut *tx)
    .await
    .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(meta.len(), 1);
    assert!(
        meta[0].contains("support ticket 42") && !meta[0].contains("Maya"),
        "{}",
        meta[0]
    );

    // Update re-seals; reveal follows.
    tool(
        &d,
        "update_record",
        json!({"object": slug, "record_id": id, "values": {"email": "maya@new.example"}}),
    )
    .await
    .unwrap();
    assert_eq!(
        reveal(&env, ctx.organization_id.0, &d, &slug, &id, "email")
            .await
            .unwrap()["value"],
        "maya@new.example"
    );
    let old = tool(&d, "query", find("maya.chen@example.com"))
        .await
        .unwrap();
    assert!(
        old["rows"].as_array().unwrap().is_empty(),
        "old digest no longer matches"
    );

    // Non-sensitive fields are not revealable (they are plain reads).
    let err = reveal(&env, ctx.organization_id.0, &d, &slug, &id, "name")
        .await
        .unwrap_err();
    assert!(err.to_string().contains("not sensitive"), "{err}");

    // Erasure destroys every value the record ever sealed — including the
    // email superseded by the update — and clears the row.
    let sealer = sealer_from_env().await.unwrap().unwrap();
    let ont = Ontology::new(env.core.clone(), OwnerDb(env.core_owner.clone()));
    let desc = ont.describe_object(&ctx, object_id).await.unwrap();
    let rid: Uuid = id.parse().unwrap();
    assert_eq!(
        sealer
            .erase_record(&env.core, &ctx, &desc, rid)
            .await
            .unwrap(),
        3
    );
    let rec = tool(&d, "get_record", json!({"object": slug, "record_id": id}))
        .await
        .unwrap();
    assert_eq!(rec["record"]["email"], Value::Null);
    assert_eq!(
        rec["record"]["name"], "Maya",
        "non-sensitive data is untouched"
    );
    let mut tx = env.core.tenant_tx(&ctx).await.unwrap();
    let live: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM pii_refs WHERE subject_id = $1 AND state = 'active'",
    )
    .bind(rid)
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(live, 0, "every ref tombstoned");
}

#[tokio::test]
async fn reveal_is_gated_by_role_scope_and_tenant() {
    let env = setup().await;
    let ctx = new_org(&env).await;
    let (_, slug) = contact_object(&env, &ctx).await;
    let admin = issue_key(
        &env,
        ctx.organization_id.0,
        "admin",
        &["mcp:tools", "mcp:tool:reveal", "mcp:tool:request_reveal"],
    )
    .await;
    let d = door(&env, &admin, true).await;
    let id = tool(
        &d,
        "create_record",
        json!({"object": slug, "values": {"email": "a@b.co"}}),
    )
    .await
    .unwrap()["record_id"]
        .as_str()
        .unwrap()
        .to_string();

    // Blanket mcp:tools does not cover reveal: protocol-level scope denial.
    let no_scope = issue_key(&env, ctx.organization_id.0, "admin", &["mcp:tools"]).await;
    let err = reveal(
        &env,
        ctx.organization_id.0,
        &door(&env, &no_scope, true).await,
        &slug,
        &id,
        "email",
    )
    .await
    .unwrap_err();
    assert_eq!(err["code"], -32001, "{err}");

    // Scope without the role: forbidden.
    let member = issue_key(
        &env,
        ctx.organization_id.0,
        "member",
        &["mcp:tools", "mcp:tool:reveal", "mcp:tool:request_reveal"],
    )
    .await;
    let err = reveal(
        &env,
        ctx.organization_id.0,
        &door(&env, &member, true).await,
        &slug,
        &id,
        "email",
    )
    .await
    .unwrap_err();
    assert!(err.to_string().contains("owner or admin"), "{err}");

    // Another org's admin: the record does not exist for them.
    let ctx_b = new_org(&env).await;
    let (_, slug_b) = contact_object(&env, &ctx_b).await;
    let admin_b = issue_key(
        &env,
        ctx_b.organization_id.0,
        "admin",
        &["mcp:tools", "mcp:tool:reveal", "mcp:tool:request_reveal"],
    )
    .await;
    let d_b = door(&env, &admin_b, true).await;
    let err = reveal(&env, ctx_b.organization_id.0, &d_b, &slug_b, &id, "email")
        .await
        .unwrap_err();
    assert!(err.to_string().contains("not_found"), "{err}");

    // A purpose is mandatory.
    let err = tool(
        &d,
        "request_reveal",
        json!({"object": slug, "record_id": id, "field": "email", "purpose": ""}),
    )
    .await
    .unwrap_err();
    assert!(err.to_string().contains("purpose"), "{err}");
}

#[tokio::test]
async fn sealed_forms_cannot_be_smuggled_and_no_vault_fails_closed() {
    let env = setup().await;
    let ctx = new_org(&env).await;
    let (_, slug) = contact_object(&env, &ctx).await;
    let admin = issue_key(
        &env,
        ctx.organization_id.0,
        "admin",
        &["mcp:tools", "mcp:tool:reveal", "mcp:tool:request_reveal"],
    )
    .await;
    let d = door(&env, &admin, true).await;
    let victim = tool(
        &d,
        "create_record",
        json!({"object": slug, "values": {"email": "secret@victim.co"}}),
    )
    .await
    .unwrap()["record_id"]
        .as_str()
        .unwrap()
        .to_string();
    // Copy the victim's sealed form straight out of the row and try to
    // write it into a new record (to later reveal it via that record).
    let (r, b): (Uuid, String) = sqlx::query_as(&format!(
        "SELECT \"{0}\", \"{0}__bidx\" FROM data.{slug} WHERE id = $1::uuid",
        sqlx::query_scalar::<_, String>(
            "SELECT physical_column FROM ontology_fields f JOIN ontology_objects o ON o.id = f.object_id \
             WHERE o.api_slug = $1 AND f.api_name = 'email'"
        )
        .bind(&slug)
        .fetch_one(&env.core_owner)
        .await
        .unwrap()
    ))
    .bind(&victim)
    .fetch_one(&env.core_owner)
    .await
    .unwrap();
    let err = tool(
        &d,
        "create_record",
        json!({"object": slug, "values": {"email": {"pii_ref": r.to_string(), "bidx": b}}}),
    )
    .await
    .unwrap_err();
    assert!(err.to_string().contains("take a string"), "{err}");

    // A server without a vault refuses the write rather than storing it.
    let bare = door(&env, &admin, false).await;
    let err = tool(
        &bare,
        "create_record",
        json!({"object": slug, "values": {"email": "x@y.co"}}),
    )
    .await
    .unwrap_err();
    assert!(err.to_string().contains("no PII vault configured"), "{err}");
    // ... while non-sensitive writes still work there.
    tool(
        &bare,
        "create_record",
        json!({"object": slug, "values": {"name": "ok"}}),
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn sensitive_definitions_are_validated() {
    let env = setup().await;
    let ctx = new_org(&env).await;
    let (object_id, _) = contact_object(&env, &ctx).await;
    let ont = Ontology::new(env.core.clone(), OwnerDb(env.core_owner.clone()));
    let err = ont
        .add_field(&ctx, object_id, &field("score", FieldType::Number, true))
        .await
        .unwrap_err();
    assert!(
        err.to_string().contains("only text, email and phone"),
        "{err}"
    );
}

/// Email and phone are PII by type: declared non-sensitive, they are
/// sealed anyway (as in samen — the type decides, not the author).
#[tokio::test]
async fn email_and_phone_are_sensitive_by_type() {
    let env = setup().await;
    let ctx = new_org(&env).await;
    let ont = Ontology::new(env.core.clone(), OwnerDb(env.core_owner.clone()));
    let (object_id, _) = contact_object(&env, &ctx).await;
    ont.add_field(
        &ctx,
        object_id,
        &field("work_email", FieldType::Email, false),
    )
    .await
    .unwrap();
    ont.add_field(&ctx, object_id, &field("mobile", FieldType::Phone, false))
        .await
        .unwrap();
    let desc = ont.describe_object(&ctx, object_id).await.unwrap();
    for api in ["work_email", "mobile"] {
        let f = desc.fields.iter().find(|f| f.api_name == api).unwrap();
        assert!(f.sensitive, "{api} must be sensitive by type");
    }
}

/// Retrofit: an existing, populated plaintext field becomes sensitive.
/// Every live value and every plaintext copy in the mutation audit is
/// sealed, the plaintext column is dropped, and the field then behaves
/// exactly like one declared sensitive from the start.
#[tokio::test]
async fn populated_field_can_be_made_sensitive() {
    let env = setup().await;
    let ctx = new_org(&env).await;
    let ont = Ontology::new(env.core.clone(), OwnerDb(env.core_owner.clone()));
    let slug = uniq("legacy");
    let meta = ont
        .define_object(
            &ctx,
            &ObjectDef {
                name: slug.clone(),
                api_slug: slug.clone(),
                label: slug.clone(),
                scope: Scope::Organization,
                pack_id: None,
                pack_version: None,
            },
        )
        .await
        .unwrap();
    ont.add_field(&ctx, meta.id, &field("name", FieldType::Text, false))
        .await
        .unwrap();
    ont.add_field(&ctx, meta.id, &field("national_id", FieldType::Text, false))
        .await
        .unwrap();
    let admin = issue_key(
        &env,
        ctx.organization_id.0,
        "admin",
        &["mcp:tools", "mcp:tool:reveal", "mcp:tool:request_reveal"],
    )
    .await;
    let before = door(&env, &admin, true).await;
    let mut ids = vec![];
    for (n, e) in [("Ann", "NI-ANN-0001"), ("Bob", "NI-BOB-0002")] {
        let r = tool(
            &before,
            "create_record",
            json!({"object": slug, "values": {"name": n, "national_id": e}}),
        )
        .await
        .unwrap();
        ids.push(r["record_id"].as_str().unwrap().to_string());
    }
    tool(
        &before,
        "update_record",
        json!({"object": slug, "record_id": ids[0], "values": {"national_id": "NI-ANN-0099"}}),
    )
    .await
    .unwrap();

    let sealer = sealer_from_env().await.unwrap().unwrap();
    let report = sealer
        .make_field_sensitive(&OwnerDb(env.core_owner.clone()), meta.id, "national_id")
        .await
        .unwrap();
    assert_eq!(report.rows, 2);
    // create x2 (after) + update (before + after) = 4 audit copies.
    assert_eq!(report.history_copies, 4);

    // No plaintext anywhere for this object.
    let rows: Vec<String> =
        sqlx::query_scalar(&format!("SELECT to_jsonb(t)::text FROM data.{slug} t"))
            .fetch_all(&env.core_owner)
            .await
            .unwrap();
    let audit: Vec<String> = sqlx::query_scalar(
        "SELECT coalesce(before_json::text, '') || after_json::text FROM mutation_audit WHERE object_id = $1",
    )
    .bind(meta.id)
    .fetch_all(&env.core_owner)
    .await
    .unwrap();
    for text in rows.iter().chain(audit.iter()) {
        assert!(
            !text.contains("NI-ANN") && !text.contains("NI-BOB"),
            "{text}"
        );
    }
    assert!(
        rows.iter().all(|r| r.contains("Ann") || r.contains("Bob")),
        "other fields intact"
    );

    // Behaves like a born-sensitive field (fresh state: caches start cold).
    let after = door(&env, &admin, true).await;
    let rec = tool(
        &after,
        "get_record",
        json!({"object": slug, "record_id": ids[0]}),
    )
    .await
    .unwrap();
    assert_eq!(rec["record"]["national_id"], MASK);
    assert_eq!(
        reveal(
            &env,
            ctx.organization_id.0,
            &after,
            &slug,
            &ids[0],
            "national_id"
        )
        .await
        .unwrap()["value"],
        "NI-ANN-0099"
    );
    assert_eq!(
        reveal(
            &env,
            ctx.organization_id.0,
            &after,
            &slug,
            &ids[1],
            "national_id"
        )
        .await
        .unwrap()["value"],
        "NI-BOB-0002"
    );
    let hit = tool(
        &after,
        "query",
        json!({"object": slug, "intent": {"select": ["name"], "filters": [{"field": "national_id", "op": "eq", "value": " NI-BOB-0002 "}]}}),
    )
    .await
    .unwrap();
    assert_eq!(hit["rows"][0]["name"], "Bob", "{hit}");
    // New writes seal as usual; converting twice is refused.
    tool(
        &after,
        "create_record",
        json!({"object": slug, "values": {"national_id": "NI-CY-0003"}}),
    )
    .await
    .unwrap();
    let err = sealer
        .make_field_sensitive(&OwnerDb(env.core_owner.clone()), meta.id, "national_id")
        .await
        .unwrap_err();
    assert!(err.to_string().contains("already sensitive"), "{err}");
}

/// `erase` (right to erasure) through the front door: explicit scope,
/// owner/admin role, purpose audited, every sensitive value of the record
/// destroyed while non-sensitive data stays.
#[tokio::test]
async fn erase_tool_destroys_sensitive_values_under_the_same_gate() {
    let env = setup().await;
    let ctx = new_org(&env).await;
    let (_, slug) = contact_object(&env, &ctx).await;
    let admin = issue_key(
        &env,
        ctx.organization_id.0,
        "admin",
        &[
            "mcp:tools",
            "mcp:tool:reveal",
            "mcp:tool:request_reveal",
            "mcp:tool:erase",
        ],
    )
    .await;
    let d = door(&env, &admin, true).await;
    let id = tool(
        &d,
        "create_record",
        json!({"object": slug, "values": {"name": "Eve", "email": "eve@forget.me", "phone": "+15550100"}}),
    )
    .await
    .unwrap()["record_id"]
        .as_str()
        .unwrap()
        .to_string();
    let erase = |door: FrontDoor| {
        let (slug, id) = (slug.clone(), id.clone());
        async move {
            tool(
                &door,
                "erase",
                json!({"object": slug, "record_id": id, "purpose": "DSR-2026-17"}),
            )
            .await
        }
    };

    // Gate: blanket mcp:tools is not enough; a member is refused.
    let no_scope = issue_key(&env, ctx.organization_id.0, "admin", &["mcp:tools"]).await;
    assert_eq!(
        erase(door(&env, &no_scope, true).await).await.unwrap_err()["code"],
        -32001
    );
    let member = issue_key(
        &env,
        ctx.organization_id.0,
        "member",
        &["mcp:tools", "mcp:tool:erase"],
    )
    .await;
    let err = erase(door(&env, &member, true).await).await.unwrap_err();
    assert!(err.to_string().contains("owner or admin"), "{err}");

    let out = erase(d).await.unwrap();
    assert_eq!(out["values_destroyed"], 2);
    let d = door(&env, &admin, true).await;
    let rec = tool(&d, "get_record", json!({"object": slug, "record_id": id}))
        .await
        .unwrap();
    assert_eq!(rec["record"]["email"], Value::Null);
    assert_eq!(rec["record"]["phone"], Value::Null);
    assert_eq!(rec["record"]["name"], "Eve");
    assert_eq!(
        reveal(&env, ctx.organization_id.0, &d, &slug, &id, "email")
            .await
            .unwrap()["value"],
        Value::Null
    );
    let mut tx = env.core.tenant_tx(&ctx).await.unwrap();
    let meta: String = sqlx::query_scalar(
        "SELECT metadata::text FROM audit_events WHERE action = 'pii.erase' AND resource_id = $1",
    )
    .bind(&id)
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    tx.commit().await.unwrap();
    assert!(
        meta.contains("DSR-2026-17") && !meta.contains("forget.me"),
        "{meta}"
    );
}

/// `field:key` (docs/automations.md, A1): a sealed field can be selected
/// as its automation key — stable per value, equal for equal values,
/// never the plaintext and never the raw blind-index digest.
#[tokio::test]
async fn sensitive_fields_select_as_stable_keys() {
    let env = setup().await;
    let ctx = new_org(&env).await;
    let (_, slug) = contact_object(&env, &ctx).await;
    let admin = issue_key(&env, ctx.organization_id.0, "admin", &["mcp:tools"]).await;
    let d = door(&env, &admin, true).await;
    for (n, e) in [
        ("A", "same@x.example"),
        ("B", " SAME@x.example "),
        ("C", "other@x.example"),
    ] {
        tool(
            &d,
            "create_record",
            json!({"object": slug, "values": {"name": n, "email": e}}),
        )
        .await
        .unwrap();
    }
    let q = tool(
        &d,
        "query",
        json!({"object": slug, "intent": {"select": ["name", "email:key"], "order": [{"field": "name", "descending": false}]}}),
    )
    .await
    .unwrap();
    let rows = q["rows"].as_array().unwrap();
    let key = |i: usize| rows[i]["email:key"].as_str().unwrap().to_string();
    assert!(key(0).starts_with("pk_") && key(0).len() == 43, "{q}");
    assert_eq!(key(0), key(1), "equal values share a key (normalized)");
    assert_ne!(key(0), key(2));
    assert!(!q.to_string().contains("x.example"), "{q}");
    let err = tool(
        &d,
        "query",
        json!({"object": slug, "intent": {"select": ["name:key"]}}),
    )
    .await
    .unwrap_err();
    assert!(
        err.to_string().contains("only sensitive fields have keys"),
        "{err}"
    );
}

/// The `automation` tool end to end: explicit scope, a sealed-field
/// condition stored and listed as a key, and the run visible through
/// the same tool after the worker drains the outbox.
#[tokio::test]
async fn automation_tool_saves_keys_and_reports_runs() {
    let env = setup().await;
    let ctx = new_org(&env).await;
    let (_, slug) = contact_object(&env, &ctx).await;
    let blanket = issue_key(&env, ctx.organization_id.0, "admin", &["mcp:tools"]).await;
    let def = json!({
        "action": "save", "object": slug, "name": "flag VIP",
        "trigger": {"on": "record_created"},
        "conditions": [{"field": "email", "op": "eq", "value": "vip@corp.example"}],
        "actions": [{"type": "update_record", "values": {"name": "VIP"}}]
    });
    let err = tool(&door(&env, &blanket, true).await, "automation", def.clone())
        .await
        .unwrap_err();
    assert_eq!(
        err["code"], -32001,
        "mcp:tools does not cover automation: {err}"
    );

    let admin = issue_key(
        &env,
        ctx.organization_id.0,
        "admin",
        &["mcp:tools", "mcp:tool:automation"],
    )
    .await;
    let d = door(&env, &admin, true).await;
    let saved = tool(&d, "automation", def).await.unwrap();
    assert!(
        saved["conditions"][0]["value"]
            .as_str()
            .unwrap()
            .starts_with("pk_"),
        "{saved}"
    );
    let listed = tool(&d, "automation", json!({"action": "list", "object": slug}))
        .await
        .unwrap();
    assert!(!listed.to_string().contains("corp.example"), "{listed}");

    let rec = tool(
        &d,
        "create_record",
        json!({"object": slug, "values": {"name": "x", "email": "VIP@corp.example"}}),
    )
    .await
    .unwrap()["record_id"]
        .as_str()
        .unwrap()
        .to_string();
    let sealer = sealer_from_env().await.unwrap();
    tinker_automate::AutomationEngine::new(
        env.core.clone(),
        OwnerDb(env.core_owner.clone()),
        sealer,
    )
    .run_pending_org(ctx.organization_id.0, 100)
    .await
    .unwrap();
    let runs = tool(
        &d,
        "automation",
        json!({"action": "runs", "id": saved["id"]}),
    )
    .await
    .unwrap();
    assert_eq!(runs["runs"][0]["outcome"], "succeeded", "{runs}");
    let got = tool(&d, "get_record", json!({"object": slug, "record_id": rec}))
        .await
        .unwrap();
    assert_eq!(got["record"]["name"], "VIP");
}

async fn reveal_with(
    d: &FrontDoor,
    slug: &str,
    id: &str,
    approval: Value,
    field: &str,
) -> Result<Value, Value> {
    tool(
        d,
        "reveal",
        json!({"object": slug, "record_id": id, "field": field, "approval_request_id": approval}),
    )
    .await
}

/// Samen parity: plaintext needs a second person. No approval, a
/// self-approval, a reused approval, or one for another field never
/// reveals; an approved request reveals exactly once.
#[tokio::test]
async fn reveal_needs_a_fresh_second_person_approval_for_that_field() {
    let env = setup().await;
    let ctx = new_org(&env).await;
    let org = ctx.organization_id.0;
    let (_, slug) = contact_object(&env, &ctx).await;
    let scopes = [
        "mcp:tools",
        "mcp:tool:reveal",
        "mcp:tool:request_reveal",
        "mcp:tool:approvals",
    ];
    let alice = issue_key(&env, org, "admin", &scopes).await;
    let bob = issue_key(&env, org, "admin", &scopes).await;
    let (a, b) = (door(&env, &alice, true).await, door(&env, &bob, true).await);
    let id = tool(
        &a,
        "create_record",
        json!({"object": slug, "values": {"email": "z@q.example", "phone": "+1555"}}),
    )
    .await
    .unwrap()["record_id"]
        .as_str()
        .unwrap()
        .to_string();
    // No approval at all: a made-up id is refused.
    let err = reveal_with(&a, &slug, &id, json!(Uuid::now_v7()), "email")
        .await
        .unwrap_err();
    assert!(err.to_string().contains("approved pii.reveal"), "{err}");

    let req = tool(
        &a,
        "request_reveal",
        json!({"object": slug, "record_id": id, "field": "email", "purpose": "DSR check"}),
    )
    .await
    .unwrap();
    let rid = req["approval_request_id"].clone();
    // Pending (not yet approved) is refused; self-approval is refused.
    assert!(reveal_with(&a, &slug, &id, rid.clone(), "email")
        .await
        .is_err());
    let err = tool(&a, "approvals", json!({"action": "approve", "id": rid}))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("requester"), "{err}");
    // Bob approves. Bob cannot use Alice's approval; Alice cannot use it
    // for another field; Alice reveals the email exactly once.
    tool(&b, "approvals", json!({"action": "approve", "id": rid}))
        .await
        .unwrap();
    assert!(
        reveal_with(&b, &slug, &id, rid.clone(), "email")
            .await
            .is_err(),
        "not the requester"
    );
    assert!(
        reveal_with(&a, &slug, &id, rid.clone(), "phone")
            .await
            .is_err(),
        "other field"
    );
    let v = reveal_with(&a, &slug, &id, rid.clone(), "email")
        .await
        .unwrap();
    assert_eq!(v["value"], "z@q.example");
    let err = reveal_with(&a, &slug, &id, rid, "email").await.unwrap_err();
    assert!(
        err.to_string().contains("approved pii.reveal") || err.to_string().contains("already used"),
        "{err}"
    );
}

/// Crypto-shred (samen parity): erasure destroys the record's DEK, so a
/// copy of its ciphertext that survives elsewhere — a backup of
/// pii_values, a replica, an export — can never be decrypted again.
#[tokio::test]
async fn erasure_crypto_shreds_copies_of_the_ciphertext() {
    let env = setup().await;
    let ctx = new_org(&env).await;
    let org = ctx.organization_id.0;
    let (_, slug) = contact_object(&env, &ctx).await;
    let admin = issue_key(&env, org, "admin", &["mcp:tools", "mcp:tool:erase"]).await;
    let d = door(&env, &admin, true).await;
    let id = tool(
        &d,
        "create_record",
        json!({"object": slug, "values": {"email": "shred@me.example"}}),
    )
    .await
    .unwrap()["record_id"]
        .as_str()
        .unwrap()
        .to_string();
    let rid: Uuid = id.parse().unwrap();
    let pii_owner = sqlx::PgPool::connect(&std::env::var("TINKER_PII_OWNER_URL").unwrap())
        .await
        .unwrap();
    // "Backup": a copy of the record's ciphertext rows, taken before erasure.
    let backup: Vec<PiiValueRow> = sqlx::query_as(
        "SELECT id, subject_id, storage_class, ciphertext, nonce, wrapped_dek_id \
         FROM pii_values WHERE organization_id = $1 AND subject_id = $2",
    )
    .bind(org)
    .bind(rid)
    .fetch_all(&pii_owner)
    .await
    .unwrap();
    assert_eq!(
        backup.len(),
        1,
        "one value, sealed under the record's own DEK"
    );
    let keys_before: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM wrapped_deks WHERE organization_id = $1 AND subject_id = $2",
    )
    .bind(org)
    .bind(rid)
    .fetch_one(&pii_owner)
    .await
    .unwrap();
    assert_eq!(keys_before, 1);

    tool(
        &d,
        "erase",
        json!({"object": slug, "record_id": id, "purpose": "DSR-shred"}),
    )
    .await
    .unwrap();
    let keys_after: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM wrapped_deks WHERE organization_id = $1 AND subject_id = $2",
    )
    .bind(org)
    .bind(rid)
    .fetch_one(&pii_owner)
    .await
    .unwrap();
    assert_eq!(keys_after, 0, "the subject's DEK is destroyed");

    // Restore the "backup" of the ciphertext: the key it was sealed
    // under no longer exists anywhere — the database even refuses the
    // row (pii_values.wrapped_dek_id references wrapped_deks), and
    // outside the database the bytes are AES-GCM under a destroyed key.
    let (vid, subject, class, ct, nonce, dek) = backup[0].clone();
    let restore = sqlx::query(
        "INSERT INTO pii_values (id, organization_id, subject_id, storage_class, ciphertext, nonce, wrapped_dek_id) \
         VALUES ($1, $2, $3, $4, $5, $6, $7)",
    )
    .bind(vid)
    .bind(org)
    .bind(subject)
    .bind(&class)
    .bind(&ct)
    .bind(&nonce)
    .bind(dek)
    .execute(&pii_owner)
    .await;
    let err = restore.expect_err("a ciphertext whose DEK is shredded cannot come back");
    assert!(err.to_string().contains("wrapped_dek_id"), "{err}");
    let dek_anywhere: i64 = sqlx::query_scalar("SELECT count(*) FROM wrapped_deks WHERE id = $1")
        .bind(dek)
        .fetch_one(&pii_owner)
        .await
        .unwrap();
    assert_eq!(dek_anywhere, 0);
}
