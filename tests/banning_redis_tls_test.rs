//! TLS-backed Redis BAN list integration test.
//!
//! Identical in spirit to `banning_redis_test.rs`, but goes through the
//! **production** code path: `RateLimiter::new_redis()` enforces
//! `rediss://` (TLS) and accepts a CA-cert path used to verify the
//! self-signed server certificate. This proves the full CIS-Benchmark
//! deployment topology (encrypted Redis traffic, no plaintext) works
//! for both rate-limiting *and* the BAN list sharing the same pool.
//!
//! Test environment
//! ────────────────
//! Requires:
//!   • a Redis built with TLS support listening on
//!     `rediss://127.0.0.1:6380`
//!   • the matching CA cert at `KRAKENWAF_TEST_TLS_CA`
//!     (defaults to `/tmp/krakenwaf-tls/cert.pem`)
//!
//! When either is missing the test logs the reason and exits cleanly —
//! it is an integration test, not a unit test, so an unconfigured TLS
//! Redis must not be reported as a regression.

#![allow(clippy::unwrap_used)]

use krakenwaf::banning::{BanConfig, BanManager, BlockReason};
use krakenwaf::waf::rate_limit::RateLimiter;
use std::path::Path;
use std::sync::Once;

const REDISS_URL: &str = "rediss://127.0.0.1:6380";

/// Install the rustls ring CryptoProvider exactly once per test
/// process. The production `main()` does the same — without it, fred's
/// TLS handshake panics with "Could not automatically determine the
/// process-level CryptoProvider".
fn ensure_crypto_provider() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        // Ignore the error: if another test already installed it,
        // `install_default()` returns Err and we don't care.
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

fn ca_cert_path() -> String {
    std::env::var("KRAKENWAF_TEST_TLS_CA")
        .unwrap_or_else(|_| "/tmp/krakenwaf-tls/ca.pem".to_string())
}

/// Returns `Some(ca_path)` when both the TLS Redis and the CA cert
/// file are available; otherwise prints a reason and returns `None`.
async fn tls_ready() -> Option<String> {
    ensure_crypto_provider();
    let ca = ca_cert_path();
    if !Path::new(&ca).exists() {
        eprintln!("TLS CA cert not found at {ca} — skipping (set KRAKENWAF_TEST_TLS_CA to override)");
        return None;
    }
    // Cheap probe: build a one-connection pool against the TLS Redis,
    // give each test its own key namespace so the probe never collides
    // with previous probes in the same `cargo test` run.
    let probe_prefix = unique_prefix("probe");
    let probe = RateLimiter::new_redis(REDISS_URL, 1000, 60, &probe_prefix, 1, Some(&ca)).await;
    match probe {
        Ok(rl) => {
            if !rl.check("127.0.0.1").await {
                eprintln!("TLS Redis probe rejected the first request — skipping");
                return None;
            }
            Some(ca)
        }
        Err(err) => {
            eprintln!("TLS Redis unreachable at {REDISS_URL}: {err:#} — skipping");
            None
        }
    }
}

fn unique_prefix(name: &str) -> String {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default();
    format!("krakenwaf-tls-test:{name}:{nonce}")
}

fn cfg(tolerance: u32, security_scanners: bool) -> BanConfig {
    let yaml = format!(
        "Banning_mode: true\n\
         Ban_context:\n  \
           security_scanners: {security_scanners}\n  \
           tolerance_block_count: {tolerance}\n  \
           Ban_wait_time: 30m\n"
    );
    let parsed: krakenwaf::banning::BanConfigFile = serde_yaml::from_str(&yaml).expect("yaml");
    BanConfig::validate(parsed).expect("validate")
}

// ─── Tests ───────────────────────────────────────────────────────────────────

/// End-to-end TLS path: build a `rediss://` rate-limiter via the
/// production constructor (which enforces TLS) and reuse its pool for
/// the BAN manager. The wire is encrypted, the CA is custom, and the
/// BAN-list semantics must match the plaintext test 1:1.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn banning_over_rediss_with_custom_ca() {
    let Some(ca) = tls_ready().await else { return };

    let rl_prefix = unique_prefix("rl");
    let rl = RateLimiter::new_redis(REDISS_URL, 10, 60, &rl_prefix, 2, Some(&ca))
        .await
        .expect("rediss:// rate-limiter must connect with the custom CA");

    assert!(rl.check("10.5.0.1").await);

    let pool = rl.redis_pool().expect("rediss:// limiter must expose a fred::Pool");
    let manager = BanManager::new_redis(cfg(3, false), pool, &unique_prefix("ban"));

    let attacker = "203.0.113.111";
    assert!(manager.check(attacker).await.is_none(), "fresh IP must not be banned");

    for round in 1..=2 {
        let out = manager
            .record_block(attacker, BlockReason::RuleDetection)
            .await
            .expect("record");
        assert!(
            out.triggered_ban.is_none(),
            "round {round} should not ban yet (threshold=3)"
        );
        assert!(manager.check(attacker).await.is_none());
    }

    let out = manager
        .record_block(attacker, BlockReason::RuleDetection)
        .await
        .expect("record");
    let triggered = out.triggered_ban.expect("3rd block must trigger the ban");
    assert_eq!(triggered.ban_count, 1);
    assert!(manager.check(attacker).await.is_some());
}

/// `security_scanners: true` fast-track over TLS — proves the
/// SecurityScanner reason still short-circuits the threshold even
/// when the transport is encrypted.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn security_scanner_fast_track_over_rediss() {
    let Some(ca) = tls_ready().await else { return };

    let rl = RateLimiter::new_redis(REDISS_URL, 100, 60, &unique_prefix("rl-scan"), 2, Some(&ca))
        .await
        .expect("rediss://");
    let pool = rl.redis_pool().expect("pool");
    // Tolerance set high so the only way an IP can be banned is via
    // the fast-track.
    let manager = BanManager::new_redis(cfg(999, true), pool, &unique_prefix("ban-scan"));

    let attacker = "198.51.100.211";
    let out = manager
        .record_block(attacker, BlockReason::SecurityScanner)
        .await
        .expect("record");
    assert!(
        out.triggered_ban.is_some(),
        "scanner fast-track must trigger over TLS too"
    );
    assert!(manager.check(attacker).await.is_some());
}

/// Atomicity check on the TLS path — fred multiplexes EVAL over the
/// pool, and the script must remain atomic regardless of the
/// transport.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_records_remain_atomic_over_rediss() {
    let Some(ca) = tls_ready().await else { return };

    let rl = RateLimiter::new_redis(
        REDISS_URL,
        1000,
        60,
        &unique_prefix("rl-atomic"),
        4,
        Some(&ca),
    )
    .await
    .expect("rediss://");
    let pool = rl.redis_pool().expect("pool");
    let manager = std::sync::Arc::new(BanManager::new_redis(
        cfg(5, false),
        pool,
        &unique_prefix("ban-atomic"),
    ));

    let attacker = "203.0.113.222";
    let mut joins = Vec::new();
    for _ in 0..20 {
        let m = manager.clone();
        let ip = attacker.to_string();
        joins.push(tokio::spawn(async move {
            m.record_block(&ip, BlockReason::RuleDetection).await
        }));
    }

    let mut bans = 0;
    for j in joins {
        if let Ok(Some(out)) = j.await {
            if out.triggered_ban.is_some() {
                bans += 1;
            }
        }
    }

    assert_eq!(
        bans, 1,
        "exactly one record must report the ban-triggered event over TLS"
    );
    assert!(manager.check(attacker).await.is_some());
}

/// The production constructor must REJECT a plain `redis://` URL even
/// if you'd otherwise get a working pool — this guards the CIS
/// Benchmark requirement against regressions.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn plain_redis_url_is_rejected_by_production_constructor() {
    ensure_crypto_provider();
    let result = RateLimiter::new_redis(
        "redis://127.0.0.1:6379",
        10,
        60,
        "krakenwaf-tls-test:should-fail",
        1,
        None,
    )
    .await;

    let err = match result {
        Ok(_) => panic!("plain redis:// must be rejected by RateLimiter::new_redis"),
        Err(e) => e,
    };

    let msg = format!("{err:#}");
    assert!(
        msg.contains("rediss://"),
        "error message should mention the rediss:// requirement, got: {msg}"
    );
}
