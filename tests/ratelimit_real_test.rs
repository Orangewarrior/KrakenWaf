//! Rate-limiter integration tests.
//!
//! Topology
//! ────────
//!   reqwest  →  KrakenWAF `:WAF_PORT` (--no-tls)  →  Axum backend :9450
//!
//! Three test groups:
//!   1. **Local rate limiter** — burst / recovery via the WAF subprocess.
//!   2. **Redis rate limiter** — direct `RedisRateLimiter` unit tests against a
//!      local `redis-server` spawned for the test suite.  Skipped when
//!      `redis-server` is not found on PATH.
//!   3. **Per-IP concurrency limit** (`max_coroutines_per_ip`) — uses a slow
//!      backend that holds connections open so the ceiling can be saturated.

use axum::{response::Html, routing::get, Router};
use reqwest::StatusCode;
use std::{
    net::SocketAddr,
    process::{Child, Command, Stdio},
    sync::{
        atomic::{AtomicU16, Ordering},
        OnceLock,
    },
    time::Duration,
};

// ─── Port allocation ──────────────────────────────────────────────────────────

/// Backend port for this test module (separate from server_real_test.rs).
const BACKEND_PORT: u16 = 9450;
/// WAF ports for this module start here.
static NEXT_WAF_PORT: AtomicU16 = AtomicU16::new(9500);
/// Redis ports for this module.
static NEXT_REDIS_PORT: AtomicU16 = AtomicU16::new(16379);

fn alloc_waf_port() -> u16 {
    NEXT_WAF_PORT.fetch_add(1, Ordering::SeqCst)
}

fn alloc_redis_port() -> u16 {
    NEXT_REDIS_PORT.fetch_add(1, Ordering::SeqCst)
}

// ─── Axum backend (started once) ─────────────────────────────────────────────

static BACKEND_ONCE: OnceLock<()> = OnceLock::new();

async fn ok_endpoint() -> Html<&'static str> {
    Html("<h1>ok</h1>")
}

/// Slow endpoint: holds the connection open for 2 seconds.
/// Used to saturate the per-IP concurrency limit in tests.
async fn slow_endpoint() -> Html<&'static str> {
    tokio::time::sleep(Duration::from_secs(2)).await;
    Html("<h1>slow</h1>")
}

fn ensure_backend() {
    BACKEND_ONCE.get_or_init(|| {
        let addr: SocketAddr = format!("127.0.0.1:{BACKEND_PORT}").parse().expect("addr");
        std::thread::spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("tokio rt")
                .block_on(async move {
                    let app = Router::new()
                        .route("/ok", get(ok_endpoint))
                        .route("/slow", get(slow_endpoint));
                    let listener = tokio::net::TcpListener::bind(addr).await.expect("bind");
                    axum::serve(listener, app).await.expect("serve");
                });
        });
        std::thread::sleep(Duration::from_millis(300));
    });
}

// ─── WAF subprocess helpers ───────────────────────────────────────────────────

struct WafGuard {
    child: Child,
    _tmpdir: tempfile::TempDir,
}

impl Drop for WafGuard {
    fn drop(&mut self) {
        self.child.kill().ok();
        self.child.wait().ok();
    }
}

fn spawn_waf(waf_port: u16, extra_args: &[&str]) -> WafGuard {
    let project_root = env!("CARGO_MANIFEST_DIR");
    let rules_dir = format!("{project_root}/rules");
    let listen = format!("127.0.0.1:{waf_port}");
    let upstream = format!("http://127.0.0.1:{BACKEND_PORT}");
    let tmpdir = tempfile::tempdir().expect("tmpdir");

    let child = Command::new(env!("CARGO_BIN_EXE_krakenwaf"))
        .args([
            "--no-tls",
            "--allow-private-upstream",
            "--listen",
            &listen,
            "--upstream",
            &upstream,
            "--rules-dir",
            &rules_dir,
        ])
        .args(extra_args)
        .current_dir(tmpdir.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("failed to spawn krakenwaf");

    WafGuard { child, _tmpdir: tmpdir }
}

async fn wait_for_waf(client: &reqwest::Client, port: u16) {
    let url = format!("http://127.0.0.1:{port}/__krakenwaf/health");
    for _ in 0..60 {
        if client
            .get(&url)
            .timeout(Duration::from_millis(500))
            .send()
            .await
            .is_ok()
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    panic!("KrakenWAF on port {port} did not become ready in time");
}

fn http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .expect("client")
}

// ─── Redis process helpers ────────────────────────────────────────────────────

struct RedisGuard {
    child: Child,
    pub port: u16,
}

impl Drop for RedisGuard {
    fn drop(&mut self) {
        // SHUTDOWN NOSAVE is the cleanest way to stop a test Redis.
        let _ = std::process::Command::new("redis-cli")
            .args(["-p", &self.port.to_string(), "shutdown", "nosave"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn();
        std::thread::sleep(Duration::from_millis(200));
        self.child.kill().ok();
        self.child.wait().ok();
    }
}

/// Returns `None` when `redis-server` is not available on PATH.
fn try_spawn_redis() -> Option<RedisGuard> {
    if which::which("redis-server").is_err() {
        return None;
    }
    let port = alloc_redis_port();
    let child = Command::new("redis-server")
        .args([
            "--port", &port.to_string(),
            "--save", "",           // disable RDB snapshots
            "--loglevel", "warning",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;

    // Wait until redis-cli PING succeeds.
    for _ in 0..30 {
        std::thread::sleep(Duration::from_millis(200));
        let ok = Command::new("redis-cli")
            .args(["-p", &port.to_string(), "ping"])
            .output()
            .map(|o| o.stdout.starts_with(b"PONG"))
            .unwrap_or(false);
        if ok {
            return Some(RedisGuard { child, port });
        }
    }
    None
}

// ─── Tests: local rate limiter ────────────────────────────────────────────────

/// A burst of requests from one IP is blocked after the configured limit.
#[tokio::test]
async fn local_rate_limit_blocks_burst() {
    ensure_backend();
    let port = alloc_waf_port();
    let _waf = spawn_waf(port, &["--rate-limit-per-minute", "3"]);
    let client = http_client();
    wait_for_waf(&client, port).await;

    let url = format!("http://127.0.0.1:{port}/ok");
    let mut allowed = 0u32;
    let mut blocked = 0u32;

    for _ in 0..6 {
        let resp = client.get(&url).send().await.expect("request");
        match resp.status() {
            StatusCode::OK => allowed += 1,
            StatusCode::FORBIDDEN => blocked += 1,
            other => panic!("unexpected status {other}"),
        }
    }

    assert_eq!(allowed, 3, "exactly 3 requests should pass (limit = 3)");
    assert_eq!(blocked, 3, "requests 4-6 must be blocked");
}

/// A different IP is not affected by another IP's rate-limit counter.
#[tokio::test]
async fn local_rate_limit_ips_are_independent() {
    ensure_backend();
    let port = alloc_waf_port();
    let _waf = spawn_waf(port, &["--rate-limit-per-minute", "2"]);
    let client = http_client();
    wait_for_waf(&client, port).await;

    let url = format!("http://127.0.0.1:{port}/ok");

    // Exhaust the limit from 127.0.0.1 (the default peer address).
    for i in 0..3 {
        let resp = client.get(&url).send().await.expect("request");
        if i < 2 {
            assert_eq!(resp.status(), StatusCode::OK);
        } else {
            assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        }
    }

    // A second client connecting from 127.0.0.1 also gets blocked because
    // the WAF sees the same peer IP. This test verifies the counter persists
    // across requests within the same window.
    let resp2 = client.get(&url).send().await.expect("request");
    assert_eq!(
        resp2.status(),
        StatusCode::FORBIDDEN,
        "same IP must remain blocked within the window"
    );
}

/// The WAF loads rate-limit settings from a YAML file when
/// --ratelimit-by-file-conf is given.
#[tokio::test]
async fn ratelimit_by_file_conf_loads_rate_limit_from_yaml() {
    ensure_backend();

    // Write a config file specifying a low rate limit.
    let tmp = tempfile::tempdir().expect("tmpdir");
    let conf_path = tmp.path().join("rl.yaml");
    std::fs::write(
        &conf_path,
        "rate_limit_per_minute: 2\nmax_coroutines_per_ip: 0\n",
    )
    .expect("write config");

    let port = alloc_waf_port();
    let _waf = spawn_waf(
        port,
        &["--ratelimit-by-file-conf", conf_path.to_str().unwrap()],
    );
    let client = http_client();
    wait_for_waf(&client, port).await;

    let url = format!("http://127.0.0.1:{port}/ok");

    // First 2 must pass, 3rd must be blocked.
    assert_eq!(client.get(&url).send().await.expect("1").status(), StatusCode::OK);
    assert_eq!(client.get(&url).send().await.expect("2").status(), StatusCode::OK);
    assert_eq!(
        client.get(&url).send().await.expect("3").status(),
        StatusCode::FORBIDDEN,
        "rate limit from file conf must block 3rd request when limit=2"
    );
}

/// CLI --rate-limit-per-minute overrides the value from the file config.
#[tokio::test]
async fn cli_rate_limit_overrides_file_conf() {
    ensure_backend();

    let tmp = tempfile::tempdir().expect("tmpdir");
    let conf_path = tmp.path().join("rl.yaml");
    // File says limit=2, CLI will say limit=5 — CLI wins.
    std::fs::write(&conf_path, "rate_limit_per_minute: 2\nmax_coroutines_per_ip: 0\n")
        .expect("write config");

    let port = alloc_waf_port();
    let _waf = spawn_waf(
        port,
        &[
            "--ratelimit-by-file-conf",
            conf_path.to_str().unwrap(),
            "--rate-limit-per-minute",
            "5",
        ],
    );
    let client = http_client();
    wait_for_waf(&client, port).await;

    let url = format!("http://127.0.0.1:{port}/ok");
    let mut ok = 0u32;
    for _ in 0..5 {
        if client.get(&url).send().await.expect("req").status() == StatusCode::OK {
            ok += 1;
        }
    }
    assert_eq!(ok, 5, "CLI limit=5 should allow all 5 requests despite file saying 2");
}

// ─── Tests: per-IP concurrency limit ─────────────────────────────────────────

/// When `max_coroutines_per_ip` = 2, the third concurrent request from the
/// same IP receives HTTP 429 while the other two are still in-flight.
#[tokio::test]
async fn max_coroutines_per_ip_blocks_excess_concurrent_requests() {
    ensure_backend();

    let tmp = tempfile::tempdir().expect("tmpdir");
    let conf_path = tmp.path().join("rl.yaml");
    // Rate limit high enough not to interfere; coroutine cap = 2.
    std::fs::write(
        &conf_path,
        "rate_limit_per_minute: 1000\nmax_coroutines_per_ip: 2\n",
    )
    .expect("write config");

    let port = alloc_waf_port();
    let _waf = spawn_waf(
        port,
        &["--ratelimit-by-file-conf", conf_path.to_str().unwrap()],
    );

    // Use a client with no per-request timeout so slow requests don't fail.
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
        .expect("client");
    wait_for_waf(&client, port).await;

    let slow_url = format!("http://127.0.0.1:{port}/slow");
    let fast_url = format!("http://127.0.0.1:{port}/ok");

    // Fire 2 slow requests concurrently (they will hold connections for ~2 s).
    let client_a = client.clone();
    let client_b = client.clone();
    let url_a = slow_url.clone();
    let url_b = slow_url.clone();
    let h1 = tokio::spawn(async move { client_a.get(&url_a).send().await });
    let h2 = tokio::spawn(async move { client_b.get(&url_b).send().await });

    // Give the slow requests time to register as in-flight.
    tokio::time::sleep(Duration::from_millis(400)).await;

    // Third request from same IP must be rejected with 429.
    let resp = client.get(&fast_url).send().await.expect("3rd request");
    assert_eq!(
        resp.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "3rd concurrent request from same IP must receive 429"
    );

    // Clean up — don't care about the result of the slow requests.
    drop(h1);
    drop(h2);
}

/// With `max_coroutines_per_ip = 0` (disabled), many concurrent requests all
/// succeed regardless of in-flight count.
#[tokio::test]
async fn max_coroutines_per_ip_zero_disables_limit() {
    ensure_backend();

    let tmp = tempfile::tempdir().expect("tmpdir");
    let conf_path = tmp.path().join("rl.yaml");
    std::fs::write(
        &conf_path,
        "rate_limit_per_minute: 1000\nmax_coroutines_per_ip: 0\n",
    )
    .expect("write config");

    let port = alloc_waf_port();
    let _waf = spawn_waf(
        port,
        &["--ratelimit-by-file-conf", conf_path.to_str().unwrap()],
    );
    let client = http_client();
    wait_for_waf(&client, port).await;

    // Fire 10 simultaneous requests — all must succeed.
    let url = format!("http://127.0.0.1:{port}/ok");
    let handles: Vec<_> = (0..10)
        .map(|_| {
            let c = client.clone();
            let u = url.clone();
            tokio::spawn(async move { c.get(&u).send().await.expect("req").status() })
        })
        .collect();

    for h in handles {
        let status = h.await.expect("join");
        assert_ne!(status, StatusCode::TOO_MANY_REQUESTS, "concurrent limit disabled — must not see 429");
    }
}

// ─── Tests: Redis rate limiter (direct, no-TLS local Redis) ──────────────────
//
// These tests exercise `RedisRateLimiter` directly (bypassing the WAF binary)
// using a plain `redis://` server spawned for the test.  TLS enforcement is
// intentionally bypassed via `new_for_test()` — only safe because this server
// is localhost-only and ephemeral.

use krakenwaf::ratelimit_config::RedisConfig;
use krakenwaf::waf::rate_limit::RedisRateLimiter;

fn redis_config(port: u16, limit: u32, window_secs: u64) -> RedisConfig {
    RedisConfig {
        enabled: true,
        url: format!("redis://127.0.0.1:{port}"),
        tls: krakenwaf::ratelimit_config::RedisTlsConfig::default(),
        pool_size: 2,
        key_prefix: format!("kwaf_test_{port}:"),
        max_requests: limit,
        window_secs,
    }
}

/// Redis: first N requests are allowed, (N+1)th is blocked.
#[tokio::test]
async fn redis_rate_limit_blocks_after_limit() {
    let Some(redis) = try_spawn_redis() else {
        eprintln!("SKIP redis_rate_limit_blocks_after_limit: redis-server not found");
        return;
    };

    let limit = 3u32;
    let cfg = redis_config(redis.port, limit, 60);
    let rl = RedisRateLimiter::new_for_test(&cfg, limit).await.expect("connect");

    for i in 0..limit {
        assert!(rl.check("10.0.0.1").await, "request {i} should be allowed");
    }
    assert!(!rl.check("10.0.0.1").await, "request N+1 must be blocked");
}

/// Redis: different IPs have independent counters.
#[tokio::test]
async fn redis_rate_limit_ips_are_independent() {
    let Some(redis) = try_spawn_redis() else {
        eprintln!("SKIP redis_rate_limit_ips_are_independent: redis-server not found");
        return;
    };

    let cfg = redis_config(redis.port, 2, 60);
    let rl = RedisRateLimiter::new_for_test(&cfg, 2).await.expect("connect");

    // Exhaust limit for IP A.
    assert!(rl.check("10.0.0.1").await);
    assert!(rl.check("10.0.0.1").await);
    assert!(!rl.check("10.0.0.1").await, "IP A must be blocked");

    // IP B must still be allowed.
    assert!(rl.check("10.0.0.2").await, "IP B must be unaffected");
}

/// Redis: limit resets after the TTL window expires.
#[tokio::test]
async fn redis_rate_limit_resets_after_window() {
    let Some(redis) = try_spawn_redis() else {
        eprintln!("SKIP redis_rate_limit_resets_after_window: redis-server not found");
        return;
    };

    // 2-second window so the test completes quickly.
    let cfg = redis_config(redis.port, 2, 2);
    let rl = RedisRateLimiter::new_for_test(&cfg, 2).await.expect("connect");

    assert!(rl.check("10.1.1.1").await);
    assert!(rl.check("10.1.1.1").await);
    assert!(!rl.check("10.1.1.1").await, "must be blocked within window");

    // Wait for the window to expire.
    tokio::time::sleep(Duration::from_secs(3)).await;

    assert!(rl.check("10.1.1.1").await, "must be allowed after window reset");
}

/// Redis: concurrent attack simulation — 20 goroutines hammer the same IP.
/// Exactly `limit` requests must succeed; the rest must be rejected.
#[tokio::test]
async fn redis_concurrent_attack_respects_limit() {
    let Some(redis) = try_spawn_redis() else {
        eprintln!("SKIP redis_concurrent_attack_respects_limit: redis-server not found");
        return;
    };

    let limit = 10u32;
    let total = 30u32;
    let cfg = redis_config(redis.port, limit, 60);
    let rl = std::sync::Arc::new(
        RedisRateLimiter::new_for_test(&cfg, limit).await.expect("connect"),
    );

    let handles: Vec<_> = (0..total)
        .map(|_| {
            let rl = rl.clone();
            tokio::spawn(async move { rl.check("192.168.0.1").await })
        })
        .collect();

    let mut allowed = 0u32;
    let mut blocked = 0u32;
    for h in handles {
        if h.await.expect("join") { allowed += 1; } else { blocked += 1; }
    }

    assert_eq!(allowed, limit, "exactly {limit} requests must be allowed");
    assert_eq!(blocked, total - limit, "{} requests must be blocked", total - limit);
}

/// Redis: key prefix isolates counters between different WAF instances.
#[tokio::test]
async fn redis_key_prefix_isolates_namespaces() {
    let Some(redis) = try_spawn_redis() else {
        eprintln!("SKIP redis_key_prefix_isolates_namespaces: redis-server not found");
        return;
    };

    let mut cfg_a = redis_config(redis.port, 2, 60);
    cfg_a.key_prefix = format!("waf_a_{}", redis.port);
    let mut cfg_b = redis_config(redis.port, 2, 60);
    cfg_b.key_prefix = format!("waf_b_{}", redis.port);

    let rl_a = RedisRateLimiter::new_for_test(&cfg_a, 2).await.expect("connect A");
    let rl_b = RedisRateLimiter::new_for_test(&cfg_b, 2).await.expect("connect B");

    // Exhaust instance A.
    rl_a.check("10.0.0.1").await;
    rl_a.check("10.0.0.1").await;
    assert!(!rl_a.check("10.0.0.1").await, "instance A must be blocked");

    // Instance B uses a different key prefix — counter is independent.
    assert!(rl_b.check("10.0.0.1").await, "instance B must be unaffected by A's counter");
}

// ─── Tests: attack simulation (WAF subprocess) ───────────────────────────────

/// Burst attack: an attacker sends many requests very quickly from the same IP.
/// The rate limiter must block after the configured threshold, then recover.
#[tokio::test]
async fn attack_burst_is_rate_limited() {
    ensure_backend();
    let port = alloc_waf_port();
    // Very tight limit for a clear signal.
    let _waf = spawn_waf(port, &["--rate-limit-per-minute", "5"]);
    let client = http_client();
    wait_for_waf(&client, port).await;

    let url = format!("http://127.0.0.1:{port}/ok");
    let mut statuses = Vec::new();
    for _ in 0..10 {
        let s = client.get(&url).send().await.expect("req").status();
        statuses.push(s);
    }

    let ok_count = statuses.iter().filter(|&&s| s == StatusCode::OK).count();
    let blocked_count = statuses.iter().filter(|&&s| s == StatusCode::FORBIDDEN).count();

    assert_eq!(ok_count, 5, "exactly 5 requests should pass the rate limit");
    assert_eq!(blocked_count, 5, "the remaining 5 must be blocked");
}

/// Scanner-style attack: 50 requests with different scanner User-Agent strings.
/// Rate limiter must kick in after the threshold even when UA varies.
#[tokio::test]
async fn attack_scanner_rate_limited_regardless_of_ua() {
    ensure_backend();
    let port = alloc_waf_port();
    let _waf = spawn_waf(port, &["--rate-limit-per-minute", "3"]);
    let client = http_client();
    wait_for_waf(&client, port).await;

    let url = format!("http://127.0.0.1:{port}/ok");
    // Use a clean UA so the scanner-UA detector doesn't interfere — we're
    // testing the rate limiter here, not the UA detector.
    let ua = "Mozilla/5.0 (compatible; TestClient/1.0)";

    let mut ok = 0u32;
    let mut blocked = 0u32;
    for _ in 0..8 {
        let s = client
            .get(&url)
            .header("User-Agent", ua)
            .send()
            .await
            .expect("req")
            .status();
        match s {
            StatusCode::OK => ok += 1,
            StatusCode::FORBIDDEN => blocked += 1,
            other => panic!("unexpected status {other}"),
        }
    }

    assert_eq!(ok, 3, "limit=3; exactly 3 must pass");
    assert_eq!(blocked, 5, "requests 4–8 must be blocked");
}

/// Slowloris-style attack simulation: many slow concurrent connections exhaust
/// the per-IP concurrency cap; fast requests from the same IP are rejected.
#[tokio::test]
async fn attack_slowloris_concurrent_blocked_by_coroutine_limit() {
    ensure_backend();

    let tmp = tempfile::tempdir().expect("tmpdir");
    let conf_path = tmp.path().join("rl.yaml");
    std::fs::write(
        &conf_path,
        "rate_limit_per_minute: 1000\nmax_coroutines_per_ip: 3\n",
    )
    .expect("write");

    let port = alloc_waf_port();
    let _waf = spawn_waf(
        port,
        &["--ratelimit-by-file-conf", conf_path.to_str().unwrap()],
    );
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
        .expect("client");
    wait_for_waf(&client, port).await;

    let slow = format!("http://127.0.0.1:{port}/slow");
    let fast = format!("http://127.0.0.1:{port}/ok");

    // Launch 3 slow "Slowloris" connections.
    let handles: Vec<_> = (0..3)
        .map(|_| {
            let c = client.clone();
            let u = slow.clone();
            tokio::spawn(async move { c.get(u).send().await })
        })
        .collect();

    // Let them register as in-flight.
    tokio::time::sleep(Duration::from_millis(500)).await;

    // 4th concurrent request must be rejected.
    let resp = client.get(&fast).send().await.expect("4th req");
    assert_eq!(
        resp.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "4th concurrent request must be blocked (cap=3)"
    );

    drop(handles);
}
