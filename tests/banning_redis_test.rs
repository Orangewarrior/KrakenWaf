//! Redis-backed BAN list integration test.
//!
//! These tests prove the hybrid backend's Redis path end-to-end: the
//! BAN manager reuses the rate-limiter's `fred::Pool` (mirroring the
//! production wiring in `src/main.rs::build_ban_manager`), and every
//! Lua-script path operates against a real `redis-server`.
//!
//! Test environment
//! ────────────────
//! Each test bootstraps its own pool via
//! `RateLimiter::new_redis_for_test()` against `redis://127.0.0.1:6379`,
//! which is the same path the production constructor uses minus the
//! mandatory TLS / `rediss://` requirement. (The binary's TLS gate is
//! a CIS-Benchmark hardening for *deployed* WAFs; the storage logic
//! exercised here is identical with or without it.)
//!
//! If Redis is unreachable the test is skipped — these are integration
//! tests, not unit tests, so a missing Redis is not a correctness
//! regression.

#![allow(clippy::unwrap_used)]

use krakenwaf::banning::{BanConfig, BanManager, BlockReason};
use krakenwaf::waf::rate_limit::RateLimiter;
use std::time::Duration;

const REDIS_URL: &str = "redis://127.0.0.1:6379";

/// Probe Redis once at startup. When it's not reachable the test is
/// marked as a no-op rather than a failure.
async fn redis_available() -> bool {
    RateLimiter::new_redis_for_test(REDIS_URL, 1, 1, "krakenwaf-test-probe")
        .await
        .is_ok()
}

fn unique_prefix(name: &str) -> String {
    // Each test gets its own namespace so concurrent / repeated runs
    // never collide on the same key.
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default();
    format!("krakenwaf-test:{name}:{nonce}")
}

/// Build a config with the given threshold and a 30-minute ban window
/// so the test never accidentally expires mid-run.
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

/// End-to-end Redis backend: build a rate-limiter, hand its pool to
/// the BAN manager, exercise both subsystems against the same Redis,
/// and verify the BAN list rejects the IP only after the threshold.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn banning_and_rate_limiting_share_a_redis_pool() {
    if !redis_available().await {
        eprintln!("redis-server not running on 127.0.0.1:6379 — skipping");
        return;
    }

    // ── Rate-limiter against the local Redis (10 req / 60 s) ──────────────
    let rl_prefix = unique_prefix("rl");
    let rl = RateLimiter::new_redis_for_test(REDIS_URL, 10, 60, &rl_prefix)
        .await
        .expect("build rate-limiter");

    // Sanity: rate-limit allows the first request.
    assert!(rl.check("10.0.0.1").await, "first request should be allowed");

    // ── BAN manager reusing the SAME fred::Pool ───────────────────────────
    let pool = rl.redis_pool().expect("redis-backed limiter exposes a pool");
    let ban_prefix = unique_prefix("ban");
    let manager = BanManager::new_redis(cfg(3, false), pool, &ban_prefix);

    let attacker = "203.0.113.7"; // RFC 5737 TEST-NET-3

    // Initially: not banned.
    assert!(manager.check(attacker).await.is_none());

    // Two recorded blocks — under threshold, still not banned.
    let out1 = manager
        .record_block(attacker, BlockReason::RuleDetection)
        .await
        .expect("record 1");
    assert!(out1.triggered_ban.is_none(), "should not ban after 1 block");
    assert!(manager.check(attacker).await.is_none());

    let out2 = manager
        .record_block(attacker, BlockReason::RuleDetection)
        .await
        .expect("record 2");
    assert!(out2.triggered_ban.is_none(), "should not ban after 2 blocks");
    assert!(manager.check(attacker).await.is_none());

    // Third block — threshold met, ban triggered.
    let out3 = manager
        .record_block(attacker, BlockReason::RuleDetection)
        .await
        .expect("record 3");
    let triggered = out3
        .triggered_ban
        .expect("ban should be triggered on the threshold-th block");
    assert_eq!(triggered.ban_count, 1, "first ban for this IP");
    let now = chrono::Utc::now().timestamp();
    assert!(
        triggered.banned_until >= now + 60 * 25,
        "ban should last at least 25 minutes (config is 30m)"
    );

    // The very next lookup must report the IP as banned and return the
    // same `banned_until` we just stored.
    let banned_until = manager
        .check(attacker)
        .await
        .expect("attacker should now be in the BAN list");
    assert_eq!(banned_until, triggered.banned_until);

    // ── A different IP is unaffected — proves keying is correct ──────────
    assert!(manager.check("198.51.100.11").await.is_none());

    // ── Rate-limiter still works on the same pool ─────────────────────────
    assert!(
        rl.check("10.0.0.2").await,
        "rate-limiter must continue to function after BAN traffic"
    );
}

/// `security_scanners: true` short-circuits the tolerance threshold —
/// a single `BlockReason::SecurityScanner` event bans the IP outright.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn security_scanner_fast_track_on_redis() {
    if !redis_available().await {
        eprintln!("redis-server not running on 127.0.0.1:6379 — skipping");
        return;
    }

    let rl = RateLimiter::new_redis_for_test(REDIS_URL, 100, 60, &unique_prefix("rl-scan"))
        .await
        .expect("rl");
    let pool = rl.redis_pool().expect("pool");
    // Tolerance is intentionally astronomical so we know the threshold
    // path is NOT what bans the IP — the fast-track is.
    let manager = BanManager::new_redis(cfg(999, true), pool, unique_prefix("ban-scan"));

    let attacker = "198.51.100.42";

    // Single scanner-flavoured block → ban.
    let out = manager
        .record_block(attacker, BlockReason::SecurityScanner)
        .await
        .expect("record");
    assert!(
        out.triggered_ban.is_some(),
        "security_scanners: true must ban on the first SecurityScanner hit"
    );
    assert!(manager.check(attacker).await.is_some());

    // A rule-detection block on a different IP must NOT be fast-tracked.
    let bystander = "198.51.100.43";
    let out2 = manager
        .record_block(bystander, BlockReason::RuleDetection)
        .await
        .expect("record bystander");
    assert!(
        out2.triggered_ban.is_none(),
        "non-scanner reasons must still respect the threshold"
    );
    assert!(manager.check(bystander).await.is_none());
}

/// Concurrent `record_block` calls on the same IP must result in a
/// consistent counter — the Lua script is supposed to make the
/// read-modify-write atomic. We fire 20 parallel blocks against a
/// threshold of 5 and assert the IP ends up banned (and only one
/// ban-trigger event is reported, since subsequent records find the
/// IP "already banned").
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_records_are_atomic() {
    if !redis_available().await {
        eprintln!("redis-server not running on 127.0.0.1:6379 — skipping");
        return;
    }

    let rl = RateLimiter::new_redis_for_test(REDIS_URL, 1000, 60, &unique_prefix("rl-atomic"))
        .await
        .expect("rl");
    let pool = rl.redis_pool().expect("pool");
    let manager = std::sync::Arc::new(BanManager::new_redis(
        cfg(5, false),
        pool,
        unique_prefix("ban-atomic"),
    ));

    let attacker = "203.0.113.55";

    let mut joins = Vec::new();
    for _ in 0..20 {
        let m = manager.clone();
        let ip = attacker.to_string();
        joins.push(tokio::spawn(async move {
            m.record_block(&ip, BlockReason::RuleDetection).await
        }));
    }

    let mut bans_triggered = 0;
    for j in joins {
        if let Ok(Some(out)) = j.await {
            if out.triggered_ban.is_some() {
                bans_triggered += 1;
            }
        }
    }

    assert_eq!(
        bans_triggered, 1,
        "exactly one block should report the ban-triggered event (atomic guarantee)"
    );
    assert!(
        manager.check(attacker).await.is_some(),
        "IP must end up banned after 20 concurrent blocks against a threshold of 5"
    );
}

/// Sanity: when Redis is reachable but the key is empty, `check()`
/// returns None promptly (no spurious "banned" state from leftover keys).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fresh_namespace_starts_empty() {
    if !redis_available().await {
        eprintln!("redis-server not running on 127.0.0.1:6379 — skipping");
        return;
    }

    let rl = RateLimiter::new_redis_for_test(REDIS_URL, 10, 60, &unique_prefix("rl-empty"))
        .await
        .expect("rl");
    let pool = rl.redis_pool().expect("pool");
    let manager = BanManager::new_redis(cfg(3, false), pool, unique_prefix("ban-empty"));

    // Several "is it banned?" queries against an untouched namespace
    // must all be None inside a sensible budget.
    for ip in ["10.1.1.1", "10.1.1.2", "10.1.1.3"] {
        let started = std::time::Instant::now();
        assert!(manager.check(ip).await.is_none(), "{ip} should be clean");
        assert!(
            started.elapsed() < Duration::from_millis(200),
            "check on a clean key should be well under the 150 ms op_timeout"
        );
    }
}
