//! Rate-limiter standalone integration test against a TLS Redis
//! (`rediss://`) — exercises the production `RateLimiter::new_redis()`
//! constructor and the `check()` hot path over an encrypted wire.
//!
//! Companion to `tests/banning_redis_tls_test.rs` (which proves the
//! BAN-list path) — this one proves the **rate-limiter** itself behaves
//! identically over TLS.
//!
//! Requires a TLS Redis on `rediss://127.0.0.1:6380` and a PEM-encoded
//! CA at `KRAKENWAF_TEST_TLS_CA` (default `/tmp/krakenwaf-tls/ca.pem`).
//! Skips cleanly when either is missing.

#![allow(clippy::unwrap_used)]

use krakenwaf::waf::rate_limit::RateLimiter;
use std::path::Path;
use std::sync::Once;

const REDISS_URL: &str = "rediss://127.0.0.1:6380";

fn ensure_crypto_provider() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

fn ca_cert_path() -> String {
    std::env::var("KRAKENWAF_TEST_TLS_CA")
        .unwrap_or_else(|_| "/tmp/krakenwaf-tls/ca.pem".to_string())
}

fn unique_prefix(name: &str) -> String {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default();
    format!("krakenwaf-rl-tls-test:{name}:{nonce}")
}

async fn build_rl(limit: u32, window: u64, name: &str) -> Option<RateLimiter> {
    ensure_crypto_provider();
    let ca = ca_cert_path();
    if !Path::new(&ca).exists() {
        eprintln!("TLS CA cert not found at {ca} — skipping");
        return None;
    }
    let prefix = unique_prefix(name);
    match RateLimiter::new_redis(REDISS_URL, limit, window, &prefix, 2, Some(&ca)).await {
        Ok(rl) => Some(rl),
        Err(err) => {
            eprintln!("rediss:// rate-limiter unreachable: {err:#} — skipping");
            None
        }
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

/// The first `limit` requests are allowed; the `limit+1`-th is denied.
/// Same semantics as the plaintext `redis_allows_within_limit` lib test,
/// but the wire is encrypted with our custom CA.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rate_limit_allows_then_denies_over_rediss() {
    let Some(rl) = build_rl(3, 60, "limit").await else { return };
    let ip = "10.42.0.7";

    for n in 1..=3 {
        assert!(
            rl.check(ip).await,
            "request {n}/3 should be allowed under the rediss:// limit"
        );
    }
    assert!(
        !rl.check(ip).await,
        "request 4 must be denied after exhausting the budget over TLS"
    );
}

/// Different IPs have independent budgets. Proves the Lua key namespace
/// is per-IP, not shared, when the transport is TLS.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rate_limit_keys_are_per_ip_over_rediss() {
    let Some(rl) = build_rl(1, 60, "per-ip").await else { return };

    assert!(rl.check("10.42.0.10").await, "first request from .10 must pass");
    assert!(!rl.check("10.42.0.10").await, "second request from .10 must be denied");

    // A different IP gets its own fresh window.
    assert!(
        rl.check("10.42.0.11").await,
        "first request from .11 must pass — budgets must be per-IP over TLS"
    );
}

/// A short window resets after expiry. Confirms TTL semantics work
/// through the TLS transport (the EXPIRE in the Lua script must take
/// effect).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rate_limit_window_resets_over_rediss() {
    // 2 req / 2 s — short enough to keep the test fast.
    let Some(rl) = build_rl(2, 2, "window").await else { return };
    let ip = "10.42.0.20";

    assert!(rl.check(ip).await);
    assert!(rl.check(ip).await);
    assert!(!rl.check(ip).await, "third request must be denied within the same window");

    tokio::time::sleep(std::time::Duration::from_millis(2_200)).await;

    assert!(
        rl.check(ip).await,
        "after 2 s the window must have reset over TLS"
    );
}

/// Heavy concurrency check — 20 parallel `check()` calls against a
/// limit of 5 must produce **exactly 5** allowed responses. The Lua
/// `INCR_WITH_TTL_LUA` script must remain atomic over multiplexed TLS.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rate_limit_lua_script_is_atomic_over_rediss() {
    let Some(rl) = build_rl(5, 60, "atomic").await else { return };
    let rl = std::sync::Arc::new(rl);
    let ip = "10.42.0.30";

    let mut joins = Vec::new();
    for _ in 0..20 {
        let r = rl.clone();
        let ip = ip.to_string();
        joins.push(tokio::spawn(async move { r.check(&ip).await }));
    }

    let mut allowed = 0;
    for j in joins {
        if j.await.unwrap_or(false) {
            allowed += 1;
        }
    }
    assert_eq!(
        allowed, 5,
        "exactly 5 of 20 concurrent checks must be allowed — Lua atomicity over TLS"
    );
}
