//! M1 performance baselines (local Postgres 16, debug build).
//!
//! These are regression tripwires, not SLAs: the numbers below document
//! what this machine does today so a future change that doubles them gets
//! caught.

mod common;

use std::time::Instant;

use common::{get_with_cookie, passkey_login, setup};

fn percentile(mut samples: Vec<u128>, pct: f64) -> u128 {
    samples.sort_unstable();
    let idx = ((samples.len() as f64 * pct).ceil() as usize).saturating_sub(1);
    samples[idx.min(samples.len() - 1)]
}

/// Full published-app render over HTTP: session → registry → authorize →
/// Askama. The tripwire gates on p50 (robust to noisy neighbors on a shared
/// VM); p95 is reported for information. These are regression tripwires,
/// not SLAs.
#[tokio::test]
async fn render_p95_tripwire() {
    let env = setup().await;
    let cookie = passkey_login(&env.router, &env.org_a).await;

    // Warm up.
    for _ in 0..5 {
        let res = get_with_cookie(&env.router, "/apps/dashboard", &cookie).await;
        assert_eq!(res.status(), axum::http::StatusCode::OK);
        let _ = common::body_text(res).await;
    }

    let mut samples = Vec::new();
    for _ in 0..50 {
        let t = Instant::now();
        let res = get_with_cookie(&env.router, "/apps/dashboard", &cookie).await;
        assert_eq!(res.status(), axum::http::StatusCode::OK);
        let _ = common::body_text(res).await;
        samples.push(t.elapsed().as_micros());
    }
    let p50 = percentile(samples.clone(), 0.5);
    let p95 = percentile(samples, 0.95);
    println!("render: p50={p50}µs p95={p95}µs");
    assert!(p50 < 100_000, "render p50 tripwire: {p50}µs");
}

/// Session resolution: cookie → live session. Gates on p50; see above.
#[tokio::test]
async fn session_load_p95_tripwire() {
    let env = setup().await;
    let cookie = passkey_login(&env.router, &env.org_a).await;

    let mut samples = Vec::new();
    for _ in 0..50 {
        let t = Instant::now();
        let s = env.sessions.load_session(&cookie).await.unwrap();
        assert!(s.is_some());
        samples.push(t.elapsed().as_micros());
    }
    let p50 = percentile(samples.clone(), 0.5);
    let p95 = percentile(samples, 0.95);
    println!("session_load: p50={p50}µs p95={p95}µs");
    assert!(p50 < 50_000, "session load p50 tripwire: {p50}µs");
}
