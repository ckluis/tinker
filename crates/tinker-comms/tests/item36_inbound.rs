//! Item 36: inbound email receiving — webhook verification, tenant
//! routing, attachments, PII policy.

mod common;

use base64::Engine as _;
use common::*;
use tinker_comms::{fetch_message_attachment, receive_email, InboundConfig, ReceiveOutcome};
use uuid::Uuid;

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn attachment(name: &str, bytes: &[u8]) -> serde_json::Value {
    serde_json::json!({
        "filename": name,
        "mime": "application/octet-stream",
        "content_base64": b64(bytes),
    })
}

async fn accept(
    e: &common::Item36Env,
    config: &InboundConfig,
    org_id: Uuid,
    raw: &[u8],
    with_search: bool,
) -> ReceiveOutcome {
    let sig = sign(config, org_id, raw);
    receive_email(&deps_for(e, with_search), config, Some(&sig), raw)
        .await
        .unwrap()
}

#[tokio::test]
async fn webhook_happy_path_stores_message() {
    let e = setup().await;
    let config = test_config();
    let addr_a = unique_addr("a");
    register(&e, &e.ctx_a, &addr_a).await;

    let raw = email_payload("pid-happy-1", &addr_a, now_ts(), serde_json::json!([]));
    let outcome = accept(&e, &config, e.org_a, &raw, false).await;
    let (message_id, thread_id) = match outcome {
        ReceiveOutcome::Accepted {
            message_id,
            thread_id,
        } => (message_id, thread_id),
        ReceiveOutcome::Rejected => panic!("valid webhook was rejected"),
    };
    assert_eq!(message_count(&e, &e.ctx_a).await, 1);

    // The stored body carries the From: header and the text. Resolve the
    // physical column through the installed object map (same as the
    // writer); the body is RichText JSONB.
    let writer =
        tinker_comms::CommsWriter::new(e.core.clone(), e.ontology.clone(), e.signals.clone());
    let map = writer
        .columns(&e.ctx_a, e.installed.message_id, &e.installed.message_table)
        .await
        .unwrap();
    let body_col = map.cols.get("body").unwrap().clone();
    let mut tx = e.core.tenant_tx(&e.ctx_a).await.unwrap();
    let body: String = sqlx::query_scalar(&format!(
        "SELECT \"{body_col}\"::text FROM {} WHERE organization_id = $1 AND id = $2",
        e.installed.message_table
    ))
    .bind(e.org_a)
    .bind(message_id)
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    tx.commit().await.unwrap();
    assert!(body.contains("sender@example.com"), "body: {body}");
    assert!(body.contains("body text"), "body: {body}");

    // Thread subject came from the email subject (resolved through the
    // installed thread object map).
    let tmap = writer
        .columns(&e.ctx_a, e.installed.thread_id, &e.installed.thread_table)
        .await
        .unwrap();
    let subject_col = tmap.cols.get("subject").unwrap().clone();
    let mut tx = e.core.tenant_tx(&e.ctx_a).await.unwrap();
    let subject: String = sqlx::query_scalar(&format!(
        "SELECT \"{subject_col}\"::text FROM {} WHERE organization_id = $1 AND id = $2",
        e.installed.thread_table
    ))
    .bind(e.org_a)
    .bind(thread_id)
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    tx.commit().await.unwrap();
    // RichText JSONB arrives as a JSON string; the literal subject is
    // inside it.
    assert!(subject.contains("Hello"), "subject: {subject}");
}

#[tokio::test]
async fn webhook_rejects_bad_signature() {
    let e = setup().await;
    let config = test_config();
    let addr_a = unique_addr("a");
    register(&e, &e.ctx_a, &addr_a).await;

    let raw = email_payload("pid-bad-1", &addr_a, now_ts(), serde_json::json!([]));
    // Signed for the WRONG org (B's key over A's address).
    let sig = sign(&config, e.org_b, &raw);
    let outcome = receive_email(&deps_for(&e, false), &config, Some(&sig), &raw)
        .await
        .unwrap();
    assert_eq!(outcome, ReceiveOutcome::Rejected);
    assert_eq!(message_count(&e, &e.ctx_a).await, 0);
    assert_eq!(message_count(&e, &e.ctx_b).await, 0);
}

#[tokio::test]
async fn webhook_rejects_missing_signature() {
    let e = setup().await;
    let config = test_config();
    let addr_a = unique_addr("a");
    register(&e, &e.ctx_a, &addr_a).await;

    let raw = email_payload("pid-miss-1", &addr_a, now_ts(), serde_json::json!([]));
    let outcome = receive_email(&deps_for(&e, false), &config, None, &raw)
        .await
        .unwrap();
    assert_eq!(outcome, ReceiveOutcome::Rejected);
    assert_eq!(message_count(&e, &e.ctx_a).await, 0);
}

#[tokio::test]
async fn webhook_rejects_malformed_signature_format() {
    let e = setup().await;
    let config = test_config();
    let addr_a = unique_addr("a");
    register(&e, &e.ctx_a, &addr_a).await;

    let raw = email_payload("pid-fmt-1", &addr_a, now_ts(), serde_json::json!([]));
    // Missing sha256= prefix and non-hex are both generic rejections.
    for bad in ["deadbeef", "sha256=zzzz", "md5=abc123"] {
        let outcome = receive_email(&deps_for(&e, false), &config, Some(bad), &raw)
            .await
            .unwrap();
        assert_eq!(outcome, ReceiveOutcome::Rejected, "for {bad}");
    }
    assert_eq!(message_count(&e, &e.ctx_a).await, 0);
}

#[tokio::test]
async fn webhook_rejects_stale_timestamp() {
    let e = setup().await;
    let config = test_config();
    let addr_a = unique_addr("a");
    register(&e, &e.ctx_a, &addr_a).await;

    // Valid signature, but 10 minutes old (window is 5).
    let raw = email_payload(
        "pid-stale-1",
        &addr_a,
        now_ts() - 600,
        serde_json::json!([]),
    );
    let outcome = accept(&e, &config, e.org_a, &raw, false).await;
    assert_eq!(outcome, ReceiveOutcome::Rejected);
    assert_eq!(message_count(&e, &e.ctx_a).await, 0);
}

#[tokio::test]
async fn webhook_rejects_replay() {
    let e = setup().await;
    let config = test_config();
    let addr_a = unique_addr("a");
    register(&e, &e.ctx_a, &addr_a).await;

    let raw = email_payload("pid-replay-1", &addr_a, now_ts(), serde_json::json!([]));
    let first = accept(&e, &config, e.org_a, &raw, false).await;
    assert!(matches!(first, ReceiveOutcome::Accepted { .. }));
    // Identical bytes, identical (valid) signature: replay.
    let second = accept(&e, &config, e.org_a, &raw, false).await;
    assert_eq!(second, ReceiveOutcome::Rejected);
    assert_eq!(
        message_count(&e, &e.ctx_a).await,
        1,
        "replay must not store a second message"
    );
}

#[tokio::test]
async fn unknown_recipient_fails_closed_with_no_oracle() {
    let e = setup().await;
    let config = test_config();
    let addr_a = unique_addr("a");
    register(&e, &e.ctx_a, &addr_a).await;

    // Nobody owns this address; the signature can't verify against any
    // org key, but the rejection must be identical to a bad signature.
    let raw = email_payload(
        "pid-unk-1",
        &unique_addr("nobody"),
        now_ts(),
        serde_json::json!([]),
    );
    let sig = sign(&config, e.org_a, &raw);
    let outcome = receive_email(&deps_for(&e, false), &config, Some(&sig), &raw)
        .await
        .unwrap();
    assert_eq!(outcome, ReceiveOutcome::Rejected);
    // And with no signature at all: same outcome, no rows anywhere.
    let outcome2 = receive_email(&deps_for(&e, false), &config, None, &raw)
        .await
        .unwrap();
    assert_eq!(outcome2, ReceiveOutcome::Rejected);
    assert_eq!(message_count(&e, &e.ctx_a).await, 0);
    assert_eq!(message_count(&e, &e.ctx_b).await, 0);
    let n: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM inbound_email_log WHERE provider_id = 'pid-unk-1'",
    )
    .fetch_one(&e.owner.0)
    .await
    .unwrap();
    assert_eq!(n, 0, "unknown recipient leaves no trace");
}

#[tokio::test]
async fn tenant_isolation_on_receive() {
    let e = setup().await;
    let config = test_config();
    let addr_a = unique_addr("a");
    let addr_b = unique_addr("b");
    register(&e, &e.ctx_a, &addr_a).await;
    register(&e, &e.ctx_b, &addr_b).await;

    // Mail to B's address routes to B only.
    let raw = email_payload(
        "pid-iso-1",
        &addr_b,
        now_ts(),
        serde_json::json!([attachment("note.txt", b"for b only")]),
    );
    let outcome = accept(&e, &config, e.org_b, &raw, false).await;
    assert!(matches!(outcome, ReceiveOutcome::Accepted { .. }));
    assert_eq!(message_count(&e, &e.ctx_b).await, 1);
    assert_eq!(
        message_count(&e, &e.ctx_a).await,
        0,
        "org A must not see org B's inbound mail"
    );
    // Case-insensitive routing: the registry normalizes.
    let raw2 = email_payload(
        "pid-iso-2",
        &addr_b.to_uppercase(),
        now_ts(),
        serde_json::json!([]),
    );
    let outcome2 = accept(&e, &config, e.org_b, &raw2, false).await;
    assert!(matches!(outcome2, ReceiveOutcome::Accepted { .. }));
    assert_eq!(message_count(&e, &e.ctx_b).await, 2);

    // A's key cannot sign for B's address (cross-org confusion fails).
    let raw3 = email_payload("pid-iso-3", &addr_b, now_ts(), serde_json::json!([]));
    let outcome3 = accept(&e, &config, e.org_a, &raw3, false).await;
    assert_eq!(outcome3, ReceiveOutcome::Rejected);
    assert_eq!(message_count(&e, &e.ctx_b).await, 2);
}

#[tokio::test]
async fn attachment_dedup_and_integrity() {
    let e = setup().await;
    let config = test_config();
    let addr_a = unique_addr("a");
    register(&e, &e.ctx_a, &addr_a).await;

    // Same bytes twice (different names) dedup to one registry row.
    let raw = email_payload(
        "pid-dedup-1",
        &addr_a,
        now_ts(),
        serde_json::json!([
            attachment("a.bin", b"identical bytes"),
            attachment("b.bin", b"identical bytes"),
        ]),
    );
    let outcome = accept(&e, &config, e.org_a, &raw, false).await;
    let message_id = match outcome {
        ReceiveOutcome::Accepted { message_id, .. } => message_id,
        ReceiveOutcome::Rejected => panic!("rejected"),
    };
    assert_eq!(stored_file_count(&e, e.org_a).await, 1);

    // Both links point at the single row... except the link table
    // dedups identical content per message (unique
    // (organization_id, message_id, file_id) in migration 0037): one
    // link survives for the duplicated bytes.
    let links: Vec<Uuid> = sqlx::query_scalar(
        "SELECT file_id FROM message_attachments
         WHERE organization_id = $1 AND message_id = $2 ORDER BY position",
    )
    .bind(e.org_a)
    .bind(message_id)
    .fetch_all(&e.owner.0)
    .await
    .unwrap();
    assert_eq!(links.len(), 1);

    // Distinct bytes attach as distinct links and registry rows.
    let raw2 = email_payload(
        "pid-dedup-2",
        &addr_a,
        now_ts(),
        serde_json::json!([
            attachment("c.bin", b"bytes one"),
            attachment("d.bin", b"bytes two"),
        ]),
    );
    let outcome2 = accept(&e, &config, e.org_a, &raw2, false).await;
    let message2 = match outcome2 {
        ReceiveOutcome::Accepted { message_id, .. } => message_id,
        ReceiveOutcome::Rejected => panic!("rejected"),
    };
    assert_eq!(stored_file_count(&e, e.org_a).await, 3);
    let links2: Vec<Uuid> = sqlx::query_scalar(
        "SELECT file_id FROM message_attachments
         WHERE organization_id = $1 AND message_id = $2 ORDER BY position",
    )
    .bind(e.org_a)
    .bind(message2)
    .fetch_all(&e.owner.0)
    .await
    .unwrap();
    assert_eq!(links2.len(), 2);
    assert_ne!(links2[0], links2[1]);

    // Tamper with the backend bytes: fetch must fail closed.
    let sha: String = sqlx::query_scalar(
        "SELECT sha256 FROM stored_files WHERE organization_id = $1 AND id = $2",
    )
    .bind(e.org_a)
    .bind(links[0])
    .fetch_one(&e.owner.0)
    .await
    .unwrap();
    let path = e
        .file_root
        .join(e.org_a.to_string())
        .join(&sha[..2])
        .join(&sha);
    std::fs::write(&path, b"tampered bytes").unwrap();
    let store = file_store_for(&e);
    let err = fetch_message_attachment(
        &e.core,
        &store,
        &e.installed,
        &e.ctx_a,
        message_id,
        links[0],
    )
    .await
    .unwrap_err();
    assert!(
        matches!(err, tinker_core::TinkerError::Internal(_)),
        "tampered bytes must fail closed, got {err:?}"
    );
}

#[tokio::test]
async fn attachment_size_cap_fails_closed_before_bytes_kept() {
    let e = setup().await;
    let config = test_config(); // max_attachment_bytes = 1024
    let addr_a = unique_addr("a");
    register(&e, &e.ctx_a, &addr_a).await;

    let big = vec![0u8; 1500];
    let raw = email_payload(
        "pid-cap-1",
        &addr_a,
        now_ts(),
        serde_json::json!([attachment("big.bin", &big)]),
    );
    let sig = sign(&config, e.org_a, &raw);
    let err = receive_email(&deps_for(&e, false), &config, Some(&sig), &raw)
        .await
        .unwrap_err();
    assert!(
        matches!(err, tinker_core::TinkerError::Validation(_)),
        "oversize attachment must fail closed, got {err:?}"
    );
    assert_eq!(stored_file_count(&e, e.org_a).await, 0);
    assert_eq!(message_count(&e, &e.ctx_a).await, 0);
    // The burned provider id was released: a retry with a fixed payload
    // can proceed (no phantom replay).
    let raw2 = email_payload(
        "pid-cap-1",
        &addr_a,
        now_ts(),
        serde_json::json!([attachment("small.bin", b"tiny")]),
    );
    let outcome = accept(&e, &config, e.org_a, &raw2, false).await;
    assert!(matches!(outcome, ReceiveOutcome::Accepted { .. }));
}

#[tokio::test]
async fn attachment_count_cap_fails_closed() {
    let e = setup().await;
    let config = test_config(); // max_attachments = 3
    let addr_a = unique_addr("a");
    register(&e, &e.ctx_a, &addr_a).await;

    let atts: Vec<_> = (0..4)
        .map(|i| attachment(&format!("f{i}.bin"), b"x"))
        .collect();
    let raw = email_payload(
        "pid-cap-2",
        &addr_a,
        now_ts(),
        serde_json::Value::Array(atts),
    );
    let sig = sign(&config, e.org_a, &raw);
    let err = receive_email(&deps_for(&e, false), &config, Some(&sig), &raw)
        .await
        .unwrap_err();
    assert!(matches!(err, tinker_core::TinkerError::Validation(_)));
    assert_eq!(stored_file_count(&e, e.org_a).await, 0);
    assert_eq!(message_count(&e, &e.ctx_a).await, 0);
}

#[tokio::test]
async fn attachment_total_cap_fails_closed() {
    let e = setup().await;
    let config = test_config(); // max_total = 2048; each file <= 1024
    let addr_a = unique_addr("a");
    register(&e, &e.ctx_a, &addr_a).await;

    let chunk = vec![7u8; 900];
    let raw = email_payload(
        "pid-cap-3",
        &addr_a,
        now_ts(),
        serde_json::json!([
            attachment("c1.bin", &chunk),
            attachment("c2.bin", &chunk),
            attachment("c3.bin", &chunk),
        ]),
    );
    let sig = sign(&config, e.org_a, &raw);
    let err = receive_email(&deps_for(&e, false), &config, Some(&sig), &raw)
        .await
        .unwrap_err();
    assert!(
        matches!(err, tinker_core::TinkerError::Validation(_)),
        "total cap must fail closed, got {err:?}"
    );
    assert_eq!(stored_file_count(&e, e.org_a).await, 0);
    assert_eq!(message_count(&e, &e.ctx_a).await, 0);
}

#[tokio::test]
async fn pii_classed_body_skips_search_index() {
    let e = setup().await;
    let config = test_config();
    let addr_a = unique_addr("a");
    register(&e, &e.ctx_a, &addr_a).await;

    // pii-classed body: stored, but NEVER indexed (item-32 fail-closed).
    let mut payload = serde_json::json!({
        "provider_id": "pid-pii-1",
        "to": addr_a,
        "from": "sender@example.com",
        "subject": "SSN inside",
        "text_body": "my ssn is 123-45-6789",
        "timestamp": now_ts(),
        "pii_class": "pii",
        "attachments": [],
    });
    let raw = serde_json::to_vec(&payload).unwrap();
    let outcome = accept(&e, &config, e.org_a, &raw, true).await;
    let pii_msg = match outcome {
        ReceiveOutcome::Accepted { message_id, .. } => message_id,
        ReceiveOutcome::Rejected => panic!("rejected"),
    };
    assert_eq!(message_count(&e, &e.ctx_a).await, 1);

    // Ordinary body: indexed.
    payload["provider_id"] = serde_json::json!("pid-pii-2");
    payload["pii_class"] = serde_json::json!("none");
    payload["text_body"] = serde_json::json!("ordinary hello");
    let raw2 = serde_json::to_vec(&payload).unwrap();
    let outcome2 = accept(&e, &config, e.org_a, &raw2, true).await;
    let ok_msg = match outcome2 {
        ReceiveOutcome::Accepted { message_id, .. } => message_id,
        ReceiveOutcome::Rejected => panic!("rejected"),
    };

    let mut tx = e.core.tenant_tx(&e.ctx_a).await.unwrap();
    let pii_hits: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM search_index WHERE organization_id = $1 AND record_id = $2",
    )
    .bind(e.org_a)
    .bind(pii_msg)
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    let ok_hits: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM search_index WHERE organization_id = $1 AND record_id = $2",
    )
    .bind(e.org_a)
    .bind(ok_msg)
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(pii_hits, 0, "PII-classed body must not reach the index");
    assert_eq!(ok_hits, 1, "ordinary body is indexed");
}

#[tokio::test]
async fn attachment_fetch_mirrors_message_visibility() {
    let e = setup().await;
    let config = test_config();
    let addr_b = unique_addr("b");
    register(&e, &e.ctx_b, &addr_b).await;

    let raw = email_payload(
        "pid-fetch-1",
        &addr_b,
        now_ts(),
        serde_json::json!([attachment("secret.txt", b"org b bytes")]),
    );
    let outcome = accept(&e, &config, e.org_b, &raw, false).await;
    let message_id = match outcome {
        ReceiveOutcome::Accepted { message_id, .. } => message_id,
        ReceiveOutcome::Rejected => panic!("rejected"),
    };
    let file_id: Uuid = sqlx::query_scalar(
        "SELECT file_id FROM message_attachments
         WHERE organization_id = $1 AND message_id = $2",
    )
    .bind(e.org_b)
    .bind(message_id)
    .fetch_one(&e.owner.0)
    .await
    .unwrap();
    let store = file_store_for(&e);

    // Same org: serves bytes.
    let (_, bytes) =
        fetch_message_attachment(&e.core, &store, &e.installed, &e.ctx_b, message_id, file_id)
            .await
            .unwrap();
    assert_eq!(bytes, b"org b bytes");

    // Cross-org caller: NotFound (no oracle), even though the file id is
    // a valid UUID.
    let err =
        fetch_message_attachment(&e.core, &store, &e.installed, &e.ctx_a, message_id, file_id)
            .await
            .unwrap_err();
    assert!(matches!(err, tinker_core::TinkerError::NotFound(_)));

    // Right org, wrong message: NotFound.
    let err = fetch_message_attachment(
        &e.core,
        &store,
        &e.installed,
        &e.ctx_b,
        Uuid::now_v7(),
        file_id,
    )
    .await
    .unwrap_err();
    assert!(matches!(err, tinker_core::TinkerError::NotFound(_)));
}

#[tokio::test]
async fn bad_provider_id_is_clean_validation_before_claim() {
    let e = setup().await;
    let config = test_config();
    let addr_a = unique_addr("a");
    register(&e, &e.ctx_a, &addr_a).await;

    // Oversized provider id, validly signed: must be a clean Validation
    // error (validated before the replay claim), not a database error.
    let mut payload = serde_json::json!({
        "provider_id": "x".repeat(300),
        "to": addr_a,
        "from": "sender@example.com",
        "subject": "Hello",
        "text_body": "body",
        "timestamp": now_ts(),
        "attachments": [],
    });
    let raw = serde_json::to_vec(&payload).unwrap();
    let sig = sign(&config, e.org_a, &raw);
    let err = receive_email(&deps_for(&e, false), &config, Some(&sig), &raw)
        .await
        .unwrap_err();
    assert!(
        matches!(err, tinker_core::TinkerError::Validation(ref m) if m == "bad provider_id"),
        "got {err:?}"
    );

    // Empty provider id: same clean validation.
    payload["provider_id"] = serde_json::json!("  ");
    let raw2 = serde_json::to_vec(&payload).unwrap();
    let sig2 = sign(&config, e.org_a, &raw2);
    let err2 = receive_email(&deps_for(&e, false), &config, Some(&sig2), &raw2)
        .await
        .unwrap_err();
    assert!(matches!(err2, tinker_core::TinkerError::Validation(_)));
    assert_eq!(message_count(&e, &e.ctx_a).await, 0);
}

#[tokio::test]
async fn address_registration_has_no_oracle() {
    let e = setup().await;
    let taken = unique_addr("taken");
    register(&e, &e.ctx_a, &taken).await;
    // Org B tries to register the same address: generic "unavailable",
    // identical whether the address exists or not.
    let err = tinker_comms::register_inbound_address(
        &e.core,
        &e.ontology,
        &e.signals,
        &e.installed,
        &e.ctx_b,
        &taken,
        "Other inbox",
    )
    .await
    .unwrap_err();
    assert!(
        matches!(err, tinker_core::TinkerError::Validation(ref m) if m == "address unavailable"),
        "got {err:?}"
    );
}
