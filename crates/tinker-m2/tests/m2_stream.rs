//! M2 exit test: the row streamer.
//!
//! `QueryExecutor::execute_stream` pages a compiled plan through a
//! server-side cursor in STREAM_CHUNK fetches, so result sets stream with
//! bounded memory. This proves: every row arrives exactly once, decoding
//! matches `execute`, the tenant barrier holds mid-stream, completed
//! streams are audited with the true row count, and abandoned streams roll
//! back without an audit row.

mod common;

use tinker_db::CoreDb;
use tinker_live::{QueryExecutor, STREAM_CHUNK};
use tinker_query::{Filter, FilterOp, QueryIntent};
use tokio_stream::StreamExt;

use common::{setup, Env, OrgCtx};

/// Rows seeded per stream test: exactly MAX_LIMIT, spanning multiple
/// STREAM_CHUNK server round-trips.
const ROWS: i64 = 1000;

fn stream_intent(object_id: uuid::Uuid, prefix: &str) -> QueryIntent {
    QueryIntent {
        from: object_id,
        select: vec!["name".into(), "score".into()],
        filters: vec![Filter {
            field: "name".into(),
            op: FilterOp::StartsWith,
            value: serde_json::json!(prefix),
        }],
        order: vec![],
        limit: Some(ROWS as u32),
        schema_version: None,
    }
}

async fn seed_stream_rows(env: &Env, org: &OrgCtx, prefix: &str, n: i64) {
    let slug = format!("m2_widget_{}", env.run).replace('-', "_");
    let desc = env
        .state
        .ontology
        .describe_object(&org.tenant, env.object_id)
        .await
        .unwrap();
    let name_col = desc
        .fields
        .iter()
        .find(|f| f.api_name == "name")
        .unwrap()
        .physical_column
        .clone();
    let score_col = desc
        .fields
        .iter()
        .find(|f| f.api_name == "score")
        .unwrap()
        .physical_column
        .clone();
    let core = CoreDb(env.tenant_pool.clone());
    let mut tx = core.tenant_tx(&org.tenant).await.unwrap();
    for i in 0..n {
        // NOTE: score binds as i32, matching the fixture's insert above.
        // sqlx's prepared-statement cache is keyed by SQL text alone: this
        // INSERT text is byte-identical to the fixture's, so an i64 bind
        // here would reuse the fixture's INT4 preparation on a pooled
        // connection and die with 22P03 (proven 2026-09-24).
        let score: i32 = i.try_into().expect("seed scores fit i32");
        sqlx::query(&format!(
            "INSERT INTO data.{slug} (organization_id, id, \"{name_col}\", \"{score_col}\") \
             VALUES ($1, $2, $3, $4)"
        ))
        .bind(org.org_id)
        .bind(uuid::Uuid::now_v7())
        .bind(format!("{prefix}-{i:04}"))
        .bind(score)
        .execute(&mut *tx)
        .await
        .unwrap();
    }
    tx.commit().await.unwrap();
}

async fn audit_row_count(env: &Env, org_id: uuid::Uuid, hash: &str) -> (i64, Option<i32>) {
    let row: (i64, Option<i32>) = sqlx::query_as(
        "SELECT COUNT(*), MAX(row_count) FROM query_audit \
         WHERE organization_id = $1 AND sql_hash = $2",
    )
    .bind(org_id)
    .bind(hash)
    // Owner pool: tinker_core owns query_audit, so RLS does not apply to
    // this read. (The app pool would need tenant GUCs; without them the
    // tenant_isolation policy parses an empty setting as a uuid.)
    .fetch_one(&env.system_pool)
    .await
    .unwrap();
    row
}

/// The stream delivers every row exactly once, decodes like `execute`, and
/// the completed stream is audited with the true row count.
#[tokio::test]
async fn stream_pages_all_rows_and_audits_completion() {
    const { assert!(ROWS >= STREAM_CHUNK * 2, "test must span several fetches") };
    let env = setup().await;
    seed_stream_rows(&env, &env.org_a, "stream", ROWS).await;

    let plan = env
        .state
        .compiler
        .compile(&env.org_a.tenant, &stream_intent(env.object_id, "stream"))
        .await
        .unwrap();
    let hash = QueryExecutor::plan_hash(&plan);

    let mut stream = env.state.executor.execute_stream(&env.org_a.tenant, &plan);
    let mut names = Vec::new();
    while let Some(item) = stream.next().await {
        let row = item.expect("stream item must not error");
        names.push(row["name"].as_str().unwrap().to_string());
        // Decoding parity with `execute`: score arrives as a JSON number,
        // __id is present even though it was not selected.
        assert!(row["score"].is_number(), "score must decode as number");
        assert!(row["__id"].is_string(), "__id must be present");
    }
    names.sort();
    let want: Vec<String> = (0..ROWS).map(|i| format!("stream-{i:04}")).collect();
    assert_eq!(names, want, "every row exactly once");

    let (n, max_rows) = audit_row_count(&env, env.org_a.org_id, &hash).await;
    assert_eq!(n, 1, "exactly one audit row for the completed stream");
    assert_eq!(max_rows, Some(ROWS as i32), "audit row_count is exact");
}

/// The tenant barrier holds across chunk fetches: org B's stream of the
/// same-shaped plan sees only org B's rows.
#[tokio::test]
async fn stream_keeps_tenant_isolation_across_chunks() {
    let env = setup().await;
    seed_stream_rows(&env, &env.org_a, "stream", ROWS).await;
    // One decoy row for org B under the same prefix.
    seed_stream_rows(&env, &env.org_b, "stream", 1).await;

    let plan_b = env
        .state
        .compiler
        .compile(&env.org_b.tenant, &stream_intent(env.object_id, "stream"))
        .await
        .unwrap();
    let mut stream = env
        .state
        .executor
        .execute_stream(&env.org_b.tenant, &plan_b);
    let mut names = Vec::new();
    while let Some(item) = stream.next().await {
        names.push(item.unwrap()["name"].as_str().unwrap().to_string());
    }
    assert_eq!(names, vec!["stream-0000"], "org B sees only its own row");
}

/// A stream dropped before exhaustion rolls back: no audit row is written
/// for the abandoned execution.
///
/// Runs on the current-thread runtime so the producer task cannot outrun
/// the drop: spawned tasks only poll when this task yields, and the drop
/// below happens with no await in between — the producer's first send is
/// guaranteed to observe the closed channel.
#[tokio::test(flavor = "current_thread")]
async fn abandoned_stream_writes_no_audit_row() {
    let env = setup().await;
    // More rows than the channel buffer (STREAM_CHUNK), under a prefix
    // unique to this test. The producer can buffer at most STREAM_CHUNK
    // rows while the count query awaits; it can never finish without the
    // receiver, so dropping the stream guarantees its next send observes
    // the closed channel and it rolls back without auditing. (A filter
    // matching zero rows would let the producer exhaust and audit without
    // ever sending — the abandonment would be unobservable.)
    seed_stream_rows(&env, &env.org_a, "abandon", STREAM_CHUNK + 200).await;

    let mut intent = stream_intent(env.object_id, "abandon");
    intent.limit = Some(STREAM_CHUNK as u32 + 200);
    let plan = env
        .state
        .compiler
        .compile(&env.org_a.tenant, &intent)
        .await
        .unwrap();
    let hash = QueryExecutor::plan_hash(&plan);

    // Abandoned without consuming and without yielding: the producer
    // cannot have completed (it needs several DB round-trips first), so
    // its first channel send observes the dropped receiver and it rolls
    // back without auditing.
    {
        let _stream = env.state.executor.execute_stream(&env.org_a.tenant, &plan);
    }

    // Poll for up to ~2s: the audit row must NEVER appear.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    loop {
        let (n, _) = audit_row_count(&env, env.org_a.org_id, &hash).await;
        assert_eq!(n, 0, "abandoned stream must not be audited");
        if std::time::Instant::now() >= deadline {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
}

/// Field-aware filter coercion end to end: a JSON string on a number field
/// binds as a number; a non-numeric string is a validation error, not a
/// Postgres operator error.
#[tokio::test]
async fn field_aware_filter_coercion_through_compiler() {
    let env = setup().await;
    seed_stream_rows(&env, &env.org_a, "coerce", 10).await;

    let intent = QueryIntent {
        from: env.object_id,
        select: vec!["name".into(), "score".into()],
        filters: vec![Filter {
            field: "score".into(),
            op: FilterOp::Eq,
            value: serde_json::json!("7"),
        }],
        order: vec![],
        limit: Some(50),
        schema_version: None,
    };
    let plan = env
        .state
        .compiler
        .compile(&env.org_a.tenant, &intent)
        .await
        .unwrap();
    // The int bind carries its type in the statement text (sqlx's statement
    // cache is keyed by SQL alone).
    assert!(
        plan.sql.contains("::int8"),
        "int filter must pin the bind type: {}",
        plan.sql
    );
    let rows = env
        .state
        .executor
        .execute(&env.org_a.tenant, &plan)
        .await
        .unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["name"], serde_json::json!("coerce-0007"));

    // Same plan shape, float value: must prepare separately (::float8) and
    // return the right row — not 22P03, not a misparsed comparison. Run in
    // both orders to cover whichever preparation the pool saw first.
    let desc = env
        .state
        .ontology
        .describe_object(&env.org_a.tenant, env.object_id)
        .await
        .unwrap();
    let slug = format!("m2_widget_{}", env.run).replace('-', "_");
    let name_col = desc
        .fields
        .iter()
        .find(|f| f.api_name == "name")
        .unwrap()
        .physical_column
        .clone();
    let score_col = desc
        .fields
        .iter()
        .find(|f| f.api_name == "score")
        .unwrap()
        .physical_column
        .clone();
    {
        let core = CoreDb(env.tenant_pool.clone());
        let mut tx = core.tenant_tx(&env.org_a.tenant).await.unwrap();
        // Column order differs from the fixture's INSERT text on purpose:
        // sqlx's statement cache is keyed by SQL text alone, and the
        // fixture's text is already prepared as INT4 on pooled connections.
        sqlx::query(&format!(
            "INSERT INTO data.{slug} (id, organization_id, \"{name_col}\", \"{score_col}\") \
             VALUES ($1, $2, $3, $4)"
        ))
        .bind(uuid::Uuid::now_v7())
        .bind(env.org_a.org_id)
        .bind("coerce-float")
        .bind(7.5f64)
        .execute(&mut *tx)
        .await
        .unwrap();
        tx.commit().await.unwrap();
    }
    let float_intent = QueryIntent {
        from: env.object_id,
        select: vec!["name".into(), "score".into()],
        filters: vec![Filter {
            field: "score".into(),
            op: FilterOp::Eq,
            value: serde_json::json!(7.5),
        }],
        order: vec![],
        limit: Some(50),
        schema_version: None,
    };
    let float_plan = env
        .state
        .compiler
        .compile(&env.org_a.tenant, &float_intent)
        .await
        .unwrap();
    assert!(
        float_plan.sql.contains("::float8"),
        "float filter must pin the bind type: {}",
        float_plan.sql
    );
    // Int plan already executed above; now float, then int again: every
    // order must return exact rows — no 22P03, no misparsed comparison.
    for (p, want) in [(&float_plan, "coerce-float"), (&plan, "coerce-0007")] {
        let rows = env
            .state
            .executor
            .execute(&env.org_a.tenant, p)
            .await
            .unwrap();
        assert_eq!(rows.len(), 1, "plan {}", p.sql);
        assert_eq!(rows[0]["name"], serde_json::json!(want), "plan {}", p.sql);
    }

    let bad = QueryIntent {
        filters: vec![Filter {
            field: "score".into(),
            op: FilterOp::Eq,
            value: serde_json::json!("not-a-number"),
        }],
        ..intent
    };
    let err = env
        .state
        .compiler
        .compile(&env.org_a.tenant, &bad)
        .await
        .expect_err("non-numeric string on a number field must fail");
    assert!(
        format!("{err:?}").contains("numeric"),
        "validation error, not a PG error: {err:?}"
    );
}
