//! Item 39 (C4) exits: signed/versioned portable schema snapshot/diff/apply.
//!
//! The contract under test:
//! - Export captures objects, fields (kind/label/required/options),
//!   item-37 validation rules and write presets, relations by target
//!   slug (never UUID — UUIDs are per-org), and item-38 row policies.
//! - The envelope is tamper-evident: any payload byte change breaks the
//!   digest; the Ed25519 signature covers the digest; the envelope's
//!   claimed public key must equal the pinned vendor key (key-swap
//!   defense).
//! - Version/vendor guards fail closed: tampered, downgraded, replayed
//!   (same version, different hash), cross-vendor, and unknown-format
//!   snapshots are all refused.
//! - Portfolio semantics: the slug namespace is shared, so applying to a
//!   fresh org ADOPTS the shared table (the adopter sees the source's
//!   base fields live) and only DEFINES a new table for a genuinely new
//!   slug. Field convergence runs against the live effective schema.
//! - Apply is additive-only through the M4 evolver (create_draft ->
//!   add_field/add_relation -> mark_preview -> promote); drift on the
//!   target's own extension fields and independent target evolution fail
//!   closed before any schema write; a dry-run plan writes nothing;
//!   reapplying the exact artifact is a safe no-op.

mod common;

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use tinker_core::{TenantContext, TinkerError};
use tinker_db::OwnerDb;
use tinker_evolve::{SchemaEvolver, VersionSel};
use tinker_ontology::{
    FieldDef, FieldType, ObjectDef, Ontology, PresetMode, PresetValue, Scope, ValidationRules,
    WritePreset,
};
use tinker_query::{
    canonical_bytes, diff_snapshots, sign_snapshot, signing_key_from_env, verify_snapshot,
    verifying_key_from_hex, FieldSnapshot, ObjectSnapshot, RowFilterDef, RowFilters,
    SignedSnapshot, SnapshotDoc, SnapshotService, SIGNING_KEY_ENV, SNAPSHOT_FORMAT,
    SNAPSHOT_FORMAT_VERSION,
};
use uuid::Uuid;

fn object_def(slug: &str) -> ObjectDef {
    ObjectDef {
        name: slug.into(),
        api_slug: slug.into(),
        label: format!("{slug} label"),
        scope: Scope::Organization,
        pack_id: None,
        pack_version: None,
    }
}

fn field(api_name: &str, field_type: FieldType) -> FieldDef {
    FieldDef {
        max_pii_class: "restricted".to_string(),
        validation: ValidationRules::default(),
        preset: None,
        name: api_name.into(),
        api_name: api_name.into(),
        label: format!("{api_name} label"),
        field_type,
        options: serde_json::json!({}),
        required: false,
    }
}

fn snap_field(api_name: &str, kind: &str) -> FieldSnapshot {
    FieldSnapshot {
        max_pii_class: "restricted".to_string(),
        api_name: api_name.into(),
        label: format!("{api_name} label"),
        kind: kind.into(),
        required: false,
        options: serde_json::json!({}),
        relation_target: None,
        validation: ValidationRules::default(),
        preset: None,
    }
}

struct World {
    ctx_a: TenantContext,
    deal: Uuid,
    person: Uuid,
    deal_slug: String,
    person_slug: String,
    vendor: String,
    signing: SigningKey,
    ontology: Ontology,
    evolver: SchemaEvolver,
    policies: RowFilters,
    svc: SnapshotService,
}

impl World {
    fn pin(&self) -> [u8; 32] {
        *self.signing.verifying_key().as_bytes()
    }

    async fn export(&self, version: u64) -> (SnapshotDoc, SignedSnapshot) {
        let doc = self
            .svc
            .build_snapshot(
                &self.ctx_a,
                &self.vendor,
                version,
                &[self.deal, self.person],
            )
            .await
            .unwrap();
        let envelope = sign_snapshot(&doc, &self.signing).unwrap();
        (doc, envelope)
    }
}

/// Org A: `deal` (name, amount w/ validation, status select, owner ->
/// person relation, created_by w/ write preset) plus a `person` target;
/// a row policy on deal for role "sales".
async fn setup_world(env: &common::Env, tag: &str) -> World {
    let ctx_a = common::new_org(env, &common::uniq(&format!("snapa{tag}"))).await;
    let ontology = Ontology::new(env.core.clone(), OwnerDb(env.core_owner.clone()));
    let evolver = SchemaEvolver::new(
        env.core.clone(),
        OwnerDb(env.core_owner.clone()),
        ontology.clone(),
    );
    let policies = RowFilters::new(env.core.clone());
    let svc = SnapshotService::new(
        env.core.clone(),
        ontology.clone(),
        evolver.clone(),
        RowFilters::new(env.core.clone()),
    );

    let deal_slug = common::uniq(&format!("deal{tag}"));
    let person_slug = common::uniq(&format!("person{tag}"));
    let person = ontology
        .define_object(&ctx_a, &object_def(&person_slug))
        .await
        .unwrap();
    ontology
        .add_field(&ctx_a, person.id, &field("name", FieldType::Text))
        .await
        .unwrap();

    let deal = ontology
        .define_object(&ctx_a, &object_def(&deal_slug))
        .await
        .unwrap();
    ontology
        .add_field(&ctx_a, deal.id, &field("name", FieldType::Text))
        .await
        .unwrap();
    let mut amount = field("amount", FieldType::Number);
    amount.validation = ValidationRules {
        min: Some(0.0),
        max: Some(1_000_000.0),
        ..Default::default()
    };
    ontology.add_field(&ctx_a, deal.id, &amount).await.unwrap();
    let mut status = field("status", FieldType::Select);
    status.options = serde_json::json!({"options": ["new", "won", "lost"]});
    ontology.add_field(&ctx_a, deal.id, &status).await.unwrap();
    ontology
        .add_field(
            &ctx_a,
            deal.id,
            &field(
                "owner",
                FieldType::Relation {
                    target_object_id: person.id,
                },
            ),
        )
        .await
        .unwrap();
    let mut created_by = field("created_by", FieldType::Text);
    created_by.preset = Some(WritePreset {
        mode: PresetMode::Always,
        value: PresetValue::ActorId,
    });
    ontology
        .add_field(&ctx_a, deal.id, &created_by)
        .await
        .unwrap();

    let desc = ontology.describe_object(&ctx_a, deal.id).await.unwrap();
    policies
        .set_filters(
            &ctx_a,
            &desc,
            "sales",
            &[RowFilterDef {
                field: "status".into(),
                op: "eq".into(),
                value: Some(serde_json::json!("won")),
            }],
        )
        .await
        .unwrap();

    World {
        ctx_a,
        deal: deal.id,
        person: person.id,
        deal_slug,
        person_slug,
        vendor: common::uniq(&format!("vendor{tag}")),
        signing: SigningKey::generate(&mut OsRng),
        ontology,
        evolver,
        policies,
        svc,
    }
}

async fn ctx_b(env: &common::Env, tag: &str) -> TenantContext {
    common::new_org(env, &common::uniq(&format!("snapb{tag}"))).await
}

fn err_string(e: &TinkerError) -> String {
    format!("{e:?}")
}

#[tokio::test]
async fn roundtrip_apply_converges() {
    let env = common::setup().await;
    let w = setup_world(&env, "rt").await;
    let (doc, envelope) = w.export(1).await;
    let ctx_b = ctx_b(&env, "rt").await;
    let pin = w.pin();

    // The dry-run plan adopts the shared tables (no field writes: the
    // adopter sees the source's base live) and writes nothing.
    let plan = w.svc.plan_apply(&ctx_b, &doc).await.unwrap();
    assert!(
        !plan.is_empty(),
        "expected a non-empty plan on empty target"
    );
    let rendered = plan.render_human();
    assert!(
        rendered.contains(&format!("adopt object {}", w.deal_slug)),
        "plan:\n{rendered}"
    );
    assert!(
        rendered.contains(&format!("adopt object {}", w.person_slug)),
        "plan:\n{rendered}"
    );
    assert!(
        !rendered.contains("add field"),
        "adoption brings the base live; no field writes expected, plan:\n{rendered}"
    );
    assert!(
        rendered.contains("set row policy"),
        "the sales policy must be planned, plan:\n{rendered}"
    );
    assert!(
        matches!(
            w.ontology
                .describe_object_by_slug(&ctx_b, &w.deal_slug)
                .await,
            Err(TinkerError::NotFound(_))
        ),
        "plan_apply must be read-only"
    );

    // Apply: both objects adopted, no fields added, policy set.
    let report = w
        .svc
        .apply_snapshot(&ctx_b, &envelope, &w.vendor, &pin)
        .await
        .unwrap();
    assert!(report.objects_created.is_empty());
    assert_eq!(
        report.objects_adopted.len(),
        2,
        "adopted: {:?}",
        report.objects_adopted
    );
    assert_eq!(report.fields_added, 0);
    assert_eq!(report.policies_set, 1);
    assert_eq!(report.snapshot_version, 1);

    // The plan is now empty: the target converges.
    let plan2 = w.svc.plan_apply(&ctx_b, &doc).await.unwrap();
    assert!(
        plan2.is_empty(),
        "plan not empty after apply:\n{}",
        plan2.render_human()
    );

    // A fresh export of the target diffs empty against the source.
    let b_deal = w
        .ontology
        .describe_object_by_slug(&ctx_b, &w.deal_slug)
        .await
        .unwrap();
    let b_person = w
        .ontology
        .describe_object_by_slug(&ctx_b, &w.person_slug)
        .await
        .unwrap();
    let doc_b = w
        .svc
        .build_snapshot(&ctx_b, &w.vendor, 1, &[b_deal.id, b_person.id])
        .await
        .unwrap();
    let d = diff_snapshots(&doc, &doc_b);
    assert!(d.is_empty(), "diff not empty:\n{}", d.render_human());

    // Relations are slug-portable: B's owner points at B's person row.
    let b_owner = b_deal
        .fields
        .iter()
        .find(|f| f.api_name == "owner")
        .unwrap();
    assert_eq!(b_owner.field_type, "relation");
    assert_eq!(b_owner.relation_target_id, Some(b_person.id));
    assert_ne!(
        b_person.id, w.person,
        "target must not leak the source UUID"
    );
    // The retargeted target is resolvable through the adopter's own
    // tenant view (RLS hides the root's row): relation hops work.
    let target = w
        .ontology
        .describe_object(&ctx_b, b_owner.relation_target_id.unwrap())
        .await
        .unwrap();
    assert_eq!(target.api_slug, w.person_slug);

    // Validation rules, write preset, and select options survived.
    let b_amount = b_deal
        .fields
        .iter()
        .find(|f| f.api_name == "amount")
        .unwrap();
    assert_eq!(b_amount.validation.min, Some(0.0));
    assert_eq!(b_amount.validation.max, Some(1_000_000.0));
    let b_cb = b_deal
        .fields
        .iter()
        .find(|f| f.api_name == "created_by")
        .unwrap();
    assert!(
        matches!(&b_cb.preset, Some(p) if p.mode == PresetMode::Always),
        "preset: {:?}",
        b_cb.preset
    );
    assert!(matches!(
        &b_cb.preset,
        Some(p) if matches!(p.value, PresetValue::ActorId)
    ));
    let b_status = b_deal
        .fields
        .iter()
        .find(|f| f.api_name == "status")
        .unwrap();
    assert_eq!(
        b_status.options_json,
        serde_json::json!({"options": ["new", "won", "lost"]})
    );

    // Row policy survived (replace semantics, data shapes only).
    let pol = w
        .policies
        .load_policy(&ctx_b, b_deal.id, "sales")
        .await
        .unwrap();
    assert_eq!(pol.filters.len(), 1);
    assert_eq!(pol.filters[0].field, "status");
    assert_eq!(pol.filters[0].op.as_str(), "eq");

    // The version guard advanced.
    assert_eq!(
        w.svc.last_applied_version(&ctx_b, &w.vendor).await.unwrap(),
        1
    );
}

#[tokio::test]
async fn define_path_for_new_slug() {
    let env = common::setup().await;
    let w = setup_world(&env, "new").await;
    let ctx_b = ctx_b(&env, "new").await;
    let pin = w.pin();

    // A hand-built snapshot for a slug no org has ever defined: apply
    // must DEFINE a new table (not adopt) and add every field via M4.
    let slug = common::uniq("brandnew");
    let mut title = snap_field("title", "text");
    title.required = true;
    let doc = SnapshotDoc {
        format: SNAPSHOT_FORMAT.into(),
        format_version: SNAPSHOT_FORMAT_VERSION,
        vendor_id: w.vendor.clone(),
        snapshot_version: 1,
        created_at: "2026-09-26T00:00:00Z".into(),
        objects: vec![ObjectSnapshot {
            api_slug: slug.clone(),
            name: slug.clone(),
            label: "Brand New".into(),
            fields: vec![title, snap_field("seq_no", "number")],
            row_policies: vec![],
            evolution_version: None,
            lifecycle_enabled: false,
        }],
    };
    let envelope = sign_snapshot(&doc, &w.signing).unwrap();

    let plan = w.svc.plan_apply(&ctx_b, &doc).await.unwrap();
    let rendered = plan.render_human();
    assert!(
        rendered.contains(&format!("create object {slug}")),
        "plan:\n{rendered}"
    );
    assert!(rendered.contains("add field"), "plan:\n{rendered}");

    let report = w
        .svc
        .apply_snapshot(&ctx_b, &envelope, &w.vendor, &pin)
        .await
        .unwrap();
    assert_eq!(report.objects_created, vec![slug.clone()]);
    assert!(report.objects_adopted.is_empty());
    assert_eq!(report.fields_added, 2);

    // M4-added fields are extension fields: read the effective schema.
    let new_id = w
        .ontology
        .describe_object_by_slug(&ctx_b, &slug)
        .await
        .unwrap()
        .id;
    let resolved = w
        .evolver
        .resolve(&ctx_b, new_id, VersionSel::Active)
        .await
        .unwrap();
    let desc = w
        .ontology
        .describe_object_with_ext(&ctx_b, new_id, &resolved.ext_fields)
        .await
        .unwrap();
    assert_eq!(desc.fields.len(), 2);
    assert!(
        desc.fields
            .iter()
            .find(|f| f.api_name == "title")
            .unwrap()
            .required
    );
    assert_eq!(
        desc.fields
            .iter()
            .find(|f| f.api_name == "seq_no")
            .unwrap()
            .field_type,
        "number"
    );
}

#[tokio::test]
async fn reapply_same_artifact_is_idempotent() {
    let env = common::setup().await;
    let w = setup_world(&env, "idm").await;
    let (_doc, envelope) = w.export(1).await;
    let ctx_b = ctx_b(&env, "idm").await;
    let pin = w.pin();

    w.svc
        .apply_snapshot(&ctx_b, &envelope, &w.vendor, &pin)
        .await
        .unwrap();
    let b_deal = w
        .ontology
        .describe_object_by_slug(&ctx_b, &w.deal_slug)
        .await
        .unwrap();
    let n_fields = b_deal.fields.len();

    // Reapplying the exact same artifact is a safe no-op.
    let r2 = w
        .svc
        .apply_snapshot(&ctx_b, &envelope, &w.vendor, &pin)
        .await
        .unwrap();
    assert!(r2.objects_created.is_empty());
    assert!(r2.objects_adopted.is_empty());
    assert_eq!(r2.fields_added, 0);
    assert_eq!(r2.policies_set, 0);
    let b_deal2 = w
        .ontology
        .describe_object_by_slug(&ctx_b, &w.deal_slug)
        .await
        .unwrap();
    assert_eq!(
        b_deal2.fields.len(),
        n_fields,
        "reapply must not duplicate fields"
    );
    assert_eq!(
        w.svc.last_applied_version(&ctx_b, &w.vendor).await.unwrap(),
        1
    );
}

#[tokio::test]
async fn tampered_snapshot_rejected() {
    let env = common::setup().await;
    let w = setup_world(&env, "tmp").await;
    let (mut doc, envelope) = w.export(1).await;
    let ctx_b = ctx_b(&env, "tmp").await;
    let pin = w.pin();

    // 1) Payload bytes changed, old digest + signature kept: digest mismatch.
    doc.objects[0].fields[0].label = "EVIL LABEL".into();
    let mut evil = envelope.clone();
    evil.payload = serde_json::to_value(&doc).unwrap();
    let e = w
        .svc
        .apply_snapshot(&ctx_b, &evil, &w.vendor, &pin)
        .await
        .unwrap_err();
    assert!(
        err_string(&e).contains("digest mismatch"),
        "tampered payload must fail closed"
    );

    // 2) Signature bytes flipped: signature verification fails.
    let (_doc2, envelope2) = w.export(1).await;
    let mut evil2 = envelope2.clone();
    let mut sig = evil2.signature.clone();
    sig.replace_range(0..1, if &sig[0..1] == "A" { "B" } else { "A" });
    evil2.signature = sig;
    let e = w
        .svc
        .apply_snapshot(&ctx_b, &evil2, &w.vendor, &pin)
        .await
        .unwrap_err();
    assert!(
        err_string(&e).contains("signature"),
        "flipped signature must fail closed"
    );

    // 3) Key swap: attacker re-signs a tampered doc with THEIR key and puts
    //    their key in the envelope. The pin rejects it.
    let attacker = SigningKey::generate(&mut OsRng);
    let evil_doc = doc.clone();
    let evil3 = sign_snapshot(&evil_doc, &attacker).unwrap();
    assert_ne!(evil3.public_key, envelope.public_key);
    let e = w
        .svc
        .apply_snapshot(&ctx_b, &evil3, &w.vendor, &pin)
        .await
        .unwrap_err();
    assert!(
        err_string(&e).contains("pinned vendor key"),
        "key-swap must fail closed"
    );

    // Nothing was applied anywhere along the way.
    assert_eq!(
        w.svc.last_applied_version(&ctx_b, &w.vendor).await.unwrap(),
        0
    );
    assert!(matches!(
        w.ontology
            .describe_object_by_slug(&ctx_b, &w.deal_slug)
            .await,
        Err(TinkerError::NotFound(_))
    ));
}

#[tokio::test]
async fn version_guard_downgrade_and_replay() {
    let env = common::setup().await;
    let w = setup_world(&env, "ver").await;
    let (_doc1, env1) = w.export(1).await;
    let ctx_b = ctx_b(&env, "ver").await;
    let pin = w.pin();

    w.svc
        .apply_snapshot(&ctx_b, &env1, &w.vendor, &pin)
        .await
        .unwrap();

    // Same version, different payload hash (a re-signed, substituted
    // artifact): rejected, not treated as idempotent.
    let (doc1b_raw, _) = w.export(1).await;
    let mut doc1b = doc1b_raw;
    doc1b.created_at = "2000-01-01T00:00:00Z".into();
    let env1b = sign_snapshot(&doc1b, &w.signing).unwrap();
    assert_ne!(env1b.payload_sha256, env1.payload_sha256);
    let e = w
        .svc
        .apply_snapshot(&ctx_b, &env1b, &w.vendor, &pin)
        .await
        .unwrap_err();
    assert!(
        err_string(&e).contains("not newer"),
        "replay must fail closed"
    );

    // v2 (source added a base field — the adopter sees it live, so the
    // apply is a version advance with no field writes).
    w.ontology
        .add_field(&w.ctx_a, w.deal, &field("notes", FieldType::Text))
        .await
        .unwrap();
    let (_doc2, env2) = w.export(2).await;
    let r = w
        .svc
        .apply_snapshot(&ctx_b, &env2, &w.vendor, &pin)
        .await
        .unwrap();
    assert_eq!(
        r.fields_added, 0,
        "adopted base resolves live from the source"
    );
    assert_eq!(
        w.svc.last_applied_version(&ctx_b, &w.vendor).await.unwrap(),
        2
    );
    let b_deal = w
        .ontology
        .describe_object_by_slug(&ctx_b, &w.deal_slug)
        .await
        .unwrap();
    assert!(b_deal.fields.iter().any(|f| f.api_name == "notes"));

    // v1 again is a downgrade: refused.
    let e = w
        .svc
        .apply_snapshot(&ctx_b, &env1, &w.vendor, &pin)
        .await
        .unwrap_err();
    assert!(
        err_string(&e).contains("not newer"),
        "downgrade must fail closed"
    );
    assert_eq!(
        w.svc.last_applied_version(&ctx_b, &w.vendor).await.unwrap(),
        2
    );
}

#[tokio::test]
async fn cross_vendor_refused() {
    let env = common::setup().await;
    let w = setup_world(&env, "ven").await;
    let (_doc, envelope) = w.export(1).await;
    let ctx_b = ctx_b(&env, "ven").await;
    let pin = w.pin();

    // Same signature, wrong expected vendor: refused.
    let e = w
        .svc
        .apply_snapshot(&ctx_b, &envelope, "some-other-vendor", &pin)
        .await
        .unwrap_err();
    assert!(
        err_string(&e).contains("does not match expected"),
        "cross-vendor apply must fail closed"
    );

    // A different vendor's own envelope is refused under our vendor pin
    // even when everything else is well-formed.
    let other = SigningKey::generate(&mut OsRng);
    let other_doc = w
        .svc
        .build_snapshot(&w.ctx_a, "rival-vendor", 1, &[w.deal, w.person])
        .await
        .unwrap();
    let other_env = sign_snapshot(&other_doc, &other).unwrap();
    let e = w
        .svc
        .apply_snapshot(&ctx_b, &other_env, &w.vendor, &pin)
        .await
        .unwrap_err();
    assert!(
        err_string(&e).contains("pinned vendor key"),
        "foreign vendor envelope must fail closed"
    );
    assert_eq!(
        w.svc.last_applied_version(&ctx_b, &w.vendor).await.unwrap(),
        0
    );
}

#[tokio::test]
async fn unknown_format_rejected() {
    let env = common::setup().await;
    let w = setup_world(&env, "fmt").await;
    let (mut doc, _envelope) = w.export(1).await;
    let ctx_b = ctx_b(&env, "fmt").await;
    let pin = w.pin();

    // A future format_version we cannot read: rejected even though the
    // signature is valid.
    doc.format_version = 999;
    let evil = sign_snapshot(&doc, &w.signing).unwrap();
    let e = w
        .svc
        .apply_snapshot(&ctx_b, &evil, &w.vendor, &pin)
        .await
        .unwrap_err();
    assert!(
        err_string(&e).contains("newer than supported"),
        "unknown format_version must fail closed"
    );

    // An unknown format marker: rejected.
    let (mut doc2, _) = w.export(1).await;
    doc2.format = "evil-format".into();
    let evil2 = sign_snapshot(&doc2, &w.signing).unwrap();
    let e = w
        .svc
        .apply_snapshot(&ctx_b, &evil2, &w.vendor, &pin)
        .await
        .unwrap_err();
    assert!(
        err_string(&e).contains("unknown format"),
        "unknown format marker must fail closed"
    );
    assert_eq!(
        w.svc.last_applied_version(&ctx_b, &w.vendor).await.unwrap(),
        0
    );
}

#[tokio::test]
async fn old_format_version_rejected_predates_lifecycle() {
    let env = common::setup().await;
    let w = setup_world(&env, "oldfmt").await;
    let (_doc, mut envelope) = w.export(1).await;
    let ctx_b = ctx_b(&env, "oldfmt").await;
    let pin = w.pin();
    assert!(!envelope.payload["objects"].as_array().unwrap().is_empty());

    // A pre-lifecycle (format_version 1) snapshot: the payload carries no
    // lifecycle_enabled flag. It must be rejected with an explicit
    // re-export instruction — never applied with the flag silently off.
    // NOTE: the signature is now stale, but the version floor fires before
    // any digest/signature check, so the asserted reason is the floor.
    envelope.payload["format_version"] = serde_json::json!(1u64);
    for o in envelope.payload["objects"].as_array_mut().unwrap() {
        o.as_object_mut().unwrap().remove("lifecycle_enabled");
    }
    let e = w
        .svc
        .apply_snapshot(&ctx_b, &envelope, &w.vendor, &pin)
        .await
        .unwrap_err();
    let msg = err_string(&e);
    assert!(
        msg.contains("predates lifecycle support") && msg.contains("re-export"),
        "v1 snapshot must fail closed with re-export guidance, got: {msg}"
    );
    assert_eq!(
        w.svc.last_applied_version(&ctx_b, &w.vendor).await.unwrap(),
        0
    );
}

#[tokio::test]
async fn missing_lifecycle_flag_rejected_as_malformed() {
    let env = common::setup().await;
    let w = setup_world(&env, "nolc").await;
    let (_doc, mut envelope) = w.export(1).await;
    let ctx_b = ctx_b(&env, "nolc").await;
    let pin = w.pin();
    assert!(!envelope.payload["objects"].as_array().unwrap().is_empty());

    // A current-version snapshot with the flag stripped from every object:
    // deserialization must fail closed instead of defaulting the flag to
    // false. (The stale signature is never reached: from_value runs first.)
    for o in envelope.payload["objects"].as_array_mut().unwrap() {
        o.as_object_mut().unwrap().remove("lifecycle_enabled");
    }
    let e = w
        .svc
        .apply_snapshot(&ctx_b, &envelope, &w.vendor, &pin)
        .await
        .unwrap_err();
    let msg = err_string(&e);
    assert!(
        msg.contains("lifecycle_enabled"),
        "missing flag must be rejected explicitly, got: {msg}"
    );
    assert_eq!(
        w.svc.last_applied_version(&ctx_b, &w.vendor).await.unwrap(),
        0
    );
}

#[tokio::test]
async fn old_format_version_rejected_predates_row_policies() {
    let env = common::setup().await;
    let w = setup_world(&env, "oldfmrp").await;
    let (_doc, mut envelope) = w.export(1).await;
    let ctx_b = ctx_b(&env, "oldfmrp").await;
    let pin = w.pin();
    assert!(!envelope.payload["objects"].as_array().unwrap().is_empty());

    // A pre-lifecycle (format_version 1) snapshot with row_policies
    // stripped: row policies predate the snapshot format (present since
    // v1), so this payload is old-shape AND policy-stripped. It must be
    // rejected outright — never applied with zero row policies. The
    // version floor fires before deserialization, so the asserted reason
    // is the floor with re-export guidance.
    envelope.payload["format_version"] = serde_json::json!(1u64);
    for o in envelope.payload["objects"].as_array_mut().unwrap() {
        o.as_object_mut().unwrap().remove("row_policies");
    }
    let e = w
        .svc
        .apply_snapshot(&ctx_b, &envelope, &w.vendor, &pin)
        .await
        .unwrap_err();
    let msg = err_string(&e);
    assert!(
        msg.contains("predates lifecycle support") && msg.contains("re-export"),
        "v1 snapshot with stripped row_policies must fail closed with re-export guidance, got: {msg}"
    );
    assert_eq!(
        w.svc.last_applied_version(&ctx_b, &w.vendor).await.unwrap(),
        0
    );
}

#[tokio::test]
async fn missing_row_policies_rejected_as_malformed() {
    let env = common::setup().await;
    let w = setup_world(&env, "norp").await;
    let (_doc, mut envelope) = w.export(1).await;
    let ctx_b = ctx_b(&env, "norp").await;
    let pin = w.pin();
    assert!(!envelope.payload["objects"].as_array().unwrap().is_empty());

    // A current-version snapshot with row_policies stripped from every
    // object: deserialization must fail closed instead of defaulting to
    // an empty policy list (which would apply the snapshot with ZERO row
    // policies — fail-open). (The stale signature is never reached:
    // from_value runs first.)
    for o in envelope.payload["objects"].as_array_mut().unwrap() {
        o.as_object_mut().unwrap().remove("row_policies");
    }
    let e = w
        .svc
        .apply_snapshot(&ctx_b, &envelope, &w.vendor, &pin)
        .await
        .unwrap_err();
    let msg = err_string(&e);
    assert!(
        msg.contains("row_policies"),
        "missing row_policies must be rejected explicitly, got: {msg}"
    );
    assert_eq!(
        w.svc.last_applied_version(&ctx_b, &w.vendor).await.unwrap(),
        0
    );
}

#[tokio::test]
async fn field_drift_fails_closed() {
    let env = common::setup().await;
    let w = setup_world(&env, "drf").await;
    let (_doc1, env1) = w.export(1).await;
    let ctx_b = ctx_b(&env, "drf").await;
    let pin = w.pin();
    w.svc
        .apply_snapshot(&ctx_b, &env1, &w.vendor, &pin)
        .await
        .unwrap();

    // The target adds its OWN extension field "score" (text) via M4...
    let b_deal = w
        .ontology
        .describe_object_by_slug(&ctx_b, &w.deal_slug)
        .await
        .unwrap();
    let draft_b = w.evolver.create_draft(&ctx_b, b_deal.id).await.unwrap();
    w.evolver
        .add_field(&ctx_b, draft_b.id, &field("score", FieldType::Text))
        .await
        .unwrap();
    w.evolver.mark_preview(&ctx_b, draft_b.id).await.unwrap();
    w.evolver.promote(&ctx_b, draft_b.id).await.unwrap();

    // ...while the source independently evolves "score" as a NUMBER.
    // The v2 snapshot conflicts with the target's extension: fail closed.
    let draft_a = w.evolver.create_draft(&w.ctx_a, w.deal).await.unwrap();
    w.evolver
        .add_field(&w.ctx_a, draft_a.id, &field("score", FieldType::Number))
        .await
        .unwrap();
    w.evolver.mark_preview(&w.ctx_a, draft_a.id).await.unwrap();
    w.evolver.promote(&w.ctx_a, draft_a.id).await.unwrap();
    let (_doc2, env2) = w.export(2).await;

    let e = w
        .svc
        .apply_snapshot(&ctx_b, &env2, &w.vendor, &pin)
        .await
        .unwrap_err();
    assert!(
        err_string(&e).contains("drifted"),
        "type drift must fail closed: {e:?}"
    );

    // The target is untouched and the version guard did not advance.
    // (Extension fields need describe_object_with_ext, not the base
    // describe.)
    let resolved = w
        .evolver
        .resolve(&ctx_b, b_deal.id, VersionSel::Active)
        .await
        .unwrap();
    let b = w
        .ontology
        .describe_object_with_ext(&ctx_b, b_deal.id, &resolved.ext_fields)
        .await
        .unwrap();
    assert_eq!(
        b.fields
            .iter()
            .find(|f| f.api_name == "score")
            .unwrap()
            .field_type,
        "text"
    );
    assert_eq!(
        w.svc.last_applied_version(&ctx_b, &w.vendor).await.unwrap(),
        1
    );
}

#[tokio::test]
async fn newer_target_evolution_refused() {
    let env = common::setup().await;
    let w = setup_world(&env, "evo").await;
    let (_doc1, env1) = w.export(1).await;
    let ctx_b = ctx_b(&env, "evo").await;
    let pin = w.pin();
    w.svc
        .apply_snapshot(&ctx_b, &env1, &w.vendor, &pin)
        .await
        .unwrap();

    // The target evolves twice, independently.
    let b_deal = w
        .ontology
        .describe_object_by_slug(&ctx_b, &w.deal_slug)
        .await
        .unwrap();
    for tag in ["x1", "x2"] {
        let d = w.evolver.create_draft(&ctx_b, b_deal.id).await.unwrap();
        w.evolver
            .add_field(
                &ctx_b,
                d.id,
                &field(&format!("evo_b_{tag}"), FieldType::Text),
            )
            .await
            .unwrap();
        w.evolver.mark_preview(&ctx_b, d.id).await.unwrap();
        w.evolver.promote(&ctx_b, d.id).await.unwrap();
    }

    // The source evolves once and exports v2 (evolution_version = 1).
    let draft = w.evolver.create_draft(&w.ctx_a, w.deal).await.unwrap();
    w.evolver
        .add_field(&w.ctx_a, draft.id, &field("evo_a", FieldType::Text))
        .await
        .unwrap();
    w.evolver.mark_preview(&w.ctx_a, draft.id).await.unwrap();
    w.evolver.promote(&w.ctx_a, draft.id).await.unwrap();
    let (doc2, env2) = w.export(2).await;
    assert_eq!(
        doc2.objects
            .iter()
            .find(|o| o.api_slug == w.deal_slug)
            .unwrap()
            .evolution_version,
        Some(1)
    );

    // The target (v2) is ahead of the snapshot's lineage (v1): refused
    // rather than merged blindly.
    let e = w
        .svc
        .apply_snapshot(&ctx_b, &env2, &w.vendor, &pin)
        .await
        .unwrap_err();
    assert!(
        err_string(&e).contains("evolved to v2"),
        "newer target evolution must fail closed: {e:?}"
    );
    assert_eq!(
        w.svc.last_applied_version(&ctx_b, &w.vendor).await.unwrap(),
        1
    );
}

#[tokio::test]
async fn build_full_snapshot_exports_org_ontology() {
    let env = common::setup().await;
    let w = setup_world(&env, "full").await;
    let doc = w
        .svc
        .build_full_snapshot(&w.ctx_a, &w.vendor, 1)
        .await
        .unwrap();
    let slugs: Vec<&str> = doc.objects.iter().map(|o| o.api_slug.as_str()).collect();
    assert!(slugs.contains(&w.deal_slug.as_str()), "slugs: {slugs:?}");
    assert!(slugs.contains(&w.person_slug.as_str()), "slugs: {slugs:?}");
    let mut sorted = slugs.clone();
    sorted.sort_unstable();
    assert_eq!(slugs, sorted, "full export must be slug-ordered");
    // It signs and verifies like any other snapshot.
    let envelope = sign_snapshot(&doc, &w.signing).unwrap();
    let back = verify_snapshot(&envelope, &w.vendor, &w.pin()).unwrap();
    assert_eq!(back.objects.len(), doc.objects.len());
}

#[tokio::test]
async fn version_out_of_range_rejected() {
    let env = common::setup().await;
    let w = setup_world(&env, "big").await;
    // A version that cannot fit the bigint log column fails closed at
    // apply time, before any schema write.
    let doc = w
        .svc
        .build_snapshot(&w.ctx_a, &w.vendor, u64::MAX, &[w.deal, w.person])
        .await
        .unwrap();
    let envelope = sign_snapshot(&doc, &w.signing).unwrap();
    let ctx_b = ctx_b(&env, "big").await;
    let e = w
        .svc
        .apply_snapshot(&ctx_b, &envelope, &w.vendor, &w.pin())
        .await
        .unwrap_err();
    assert!(err_string(&e).contains("out of range"));
    assert_eq!(
        w.svc.last_applied_version(&ctx_b, &w.vendor).await.unwrap(),
        0
    );
}

#[tokio::test]
async fn plan_flags_root_relation_divergence() {
    let env = common::setup().await;
    let w = setup_world(&env, "pln").await;
    let (mut doc, _envelope) = w.export(1).await;
    let ctx_b = ctx_b(&env, "pln").await;

    // The snapshot claims deal.owner points at the DEAL object — but the
    // live shared root points it at person. The dry-run plan must fail
    // closed on the divergence, not wave it through.
    let deal = doc
        .objects
        .iter_mut()
        .find(|o| o.api_slug == w.deal_slug)
        .unwrap();
    deal.fields
        .iter_mut()
        .find(|f| f.api_name == "owner")
        .unwrap()
        .relation_target = Some(w.deal_slug.clone());
    // (doc is re-signed by the test's trusted key: well-formed, just wrong)
    let _ = sign_snapshot(&doc, &w.signing).unwrap();

    let e = w.svc.plan_apply(&ctx_b, &doc).await.unwrap_err();
    assert!(
        err_string(&e).contains("drifted") && err_string(&e).contains("relation target"),
        "plan must flag relation divergence: {e:?}"
    );
    // And the real apply fails closed too.
    let envelope = sign_snapshot(&doc, &w.signing).unwrap();
    let e = w
        .svc
        .apply_snapshot(&ctx_b, &envelope, &w.vendor, &w.pin())
        .await
        .unwrap_err();
    assert!(err_string(&e).contains("drifted"), "apply: {e:?}");
    assert_eq!(
        w.svc.last_applied_version(&ctx_b, &w.vendor).await.unwrap(),
        0
    );
}

#[tokio::test]
async fn diff_and_human_rendering() {
    let env = common::setup().await;
    let w = setup_world(&env, "dif").await;
    let (doc_a, _) = w.export(1).await;

    // Identical snapshots diff empty.
    let d = diff_snapshots(&doc_a, &doc_a);
    assert!(d.is_empty());
    assert!(d.render_human().contains("no differences"));

    // A changed doc renders one line per change.
    let mut doc_b = doc_a.clone();
    let deal = doc_b
        .objects
        .iter_mut()
        .find(|o| o.api_slug == w.deal_slug)
        .unwrap();
    deal.fields.push(FieldSnapshot {
        api_name: "extra".into(),
        label: "extra label".into(),
        kind: "text".into(),
        required: false,
        options: serde_json::json!({}),
        relation_target: None,
        validation: ValidationRules::default(),
        preset: None,
        max_pii_class: "restricted".to_string(),
    });
    let amount = deal
        .fields
        .iter_mut()
        .find(|f| f.api_name == "amount")
        .unwrap();
    amount.kind = "text".into();
    deal.fields.retain(|f| f.api_name != "status");
    deal.row_policies.clear();
    let d2 = diff_snapshots(&doc_a, &doc_b);
    assert!(!d2.is_empty());
    let h = d2.render_human();
    assert!(
        h.contains(&format!("+ field {}.extra", w.deal_slug)),
        "render:\n{h}"
    );
    assert!(
        h.contains(&format!("~ field {}.amount", w.deal_slug)),
        "render:\n{h}"
    );
    assert!(
        h.contains(&format!("- field {}.status", w.deal_slug)),
        "render:\n{h}"
    );
    assert!(
        h.contains(&format!("- row policy {}.sales", w.deal_slug)),
        "render:\n{h}"
    );

    // The diff is machine-appliable: it carries the full field definition.
    let od = d2
        .objects
        .iter()
        .find(|o| o.api_slug == w.deal_slug)
        .unwrap();
    assert_eq!(od.added.len(), 1);
    assert_eq!(od.added[0].api_name, "extra");
    assert_eq!(od.removed, vec!["status".to_string()]);
    assert_eq!(od.changed.len(), 1);
    assert_eq!(od.changed[0].api_name, "amount");
    assert!(od.changed[0].changes.iter().any(|c| c.contains("kind")));
}

#[tokio::test]
async fn canonical_form_is_deterministic() {
    let env = common::setup().await;
    let w = setup_world(&env, "can").await;
    let (doc_a, _) = w.export(1).await;

    // Same doc, same key: byte-identical canonical form and signature
    // (Ed25519 is deterministic; no HashMap iteration leaks in).
    let c1 = canonical_bytes(&doc_a).unwrap();
    let c2 = canonical_bytes(&doc_a).unwrap();
    assert_eq!(c1, c2);
    let e1 = sign_snapshot(&doc_a, &w.signing).unwrap();
    let e2 = sign_snapshot(&doc_a, &w.signing).unwrap();
    assert_eq!(e1.signature, e2.signature);
    assert_eq!(e1.payload_sha256, e2.payload_sha256);

    // Field ARRAY order is semantic: swapping two fields changes the
    // digest (build_snapshot always emits api_name order, so two exports
    // of the same org agree).
    let mut doc_b = doc_a.clone();
    let deal = doc_b
        .objects
        .iter_mut()
        .find(|o| o.api_slug == w.deal_slug)
        .unwrap();
    deal.fields.swap(0, 1);
    assert_ne!(canonical_bytes(&doc_b).unwrap(), c1);

    // Digest helper agrees with the envelope.
    assert_eq!(tinker_query::payload_digest_hex(&c1), e1.payload_sha256);
}

#[tokio::test]
async fn signing_key_env_and_key_parsing() {
    let seed = SigningKey::generate(&mut OsRng).to_bytes();
    let hex: String = seed.iter().map(|b| format!("{b:02x}")).collect();
    std::env::set_var(SIGNING_KEY_ENV, &hex);
    let key = signing_key_from_env().unwrap();
    assert_eq!(key.to_bytes(), seed);
    std::env::remove_var(SIGNING_KEY_ENV);
    assert!(
        signing_key_from_env().is_err(),
        "missing key must fail closed"
    );

    // Verifying-key parsing: malformed hex and wrong length fail closed.
    assert!(verifying_key_from_hex("zzzz").is_err());
    assert!(verifying_key_from_hex("abcd").is_err());
    let good_hex: String = key
        .verifying_key()
        .as_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let good = verifying_key_from_hex(&good_hex).unwrap();
    assert_eq!(good, *key.verifying_key().as_bytes());

    // verify_snapshot round-trips through the public API.
    let env = common::setup().await;
    let w = setup_world(&env, "ver2").await;
    let (_doc, envelope) = w.export(1).await;
    let back = verify_snapshot(&envelope, &w.vendor, &w.pin()).unwrap();
    assert_eq!(back.snapshot_version, 1);
    assert_eq!(back.objects.len(), 2);
}
