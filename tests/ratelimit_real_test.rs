//! Rate-limit and per-IP concurrency integration tests.
//!
//! Topology
//! ────────
//!   reqwest  →  `KrakenWAF` `:WAF_PORT` (--no-tls)  →  Axum backend `:BACKEND_PORT`
//!
//! Tests exercise:
//!   • Local GCRA rate limiter via WAF binary (--rate-limit-per-minute)
//!   • Config file loading (--ratelimit-by-file-conf)
//!   • Per-IP concurrency cap (`max_coroutines_per_ip`)
//!   • Attack simulations: burst, concurrent flood, slow-connection (Slowloris)
//!
//! Port isolation
//! ──────────────
//! Every test process allocates ports dynamically via the OS (bind ":0") so
//! that concurrent `cargo test` runs do not fight over fixed port numbers.
#![allow(clippy::unwrap_used)]

use axum::{routing::get, Router};
use reqwest::StatusCode;
use std::{
    net::SocketAddr,
    process::{Child, Command, Stdio},
    sync::OnceLock,
    time::Duration,
};
use tempfile::NamedTempFile;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

// ── Port allocation ───────────────────────────────────────────────────────────

/// Bind to port 0 and return the OS-allocated ephemeral port number.
/// The socket is released immediately; there is a small TOCTOU window, but
/// it is acceptable in loopback-only test infrastructure.
fn pick_free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind :0");
    listener.local_addr().expect("local_addr").port()
}

/// Allocate a free WAF port for one test.
fn alloc_waf_port() -> u16 {
    pick_free_port()
}

// ── Axum backend (started once per test process on a dynamic port) ───────────

/// The backend port for this test-process instance. Resolved once, then cached.
static BACKEND_PORT: OnceLock<u16> = OnceLock::new();
static BACKEND_ONCE: OnceLock<()> = OnceLock::new();

fn ensure_backend() -> u16 {
    // Bind first (keeps the port while we hand it to the spawned thread).
    let std_listener = BACKEND_PORT.get_or_init(|| {
        let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind backend");
        l.local_addr().expect("addr").port()
    });
    let port = *std_listener;

    BACKEND_ONCE.get_or_init(|| {
        // Bind again — the first bind above only reserved the port number.
        // We do a second bind here; the tiny race is acceptable in loopback tests.
        let addr: SocketAddr = format!("127.0.0.1:{port}").parse().expect("addr");
        std::thread::spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("test runtime")
                .block_on(async move {
                    let app = Router::new().route("/ping", get(ok_handler));
                    let listener = tokio::net::TcpListener::bind(addr).await.expect("bind");
                    axum::serve(listener, app).await.expect("serve");
                });
        });
        std::thread::sleep(Duration::from_millis(300));
    });

    port
}

fn backend_addr(port: u16) -> String {
    format!("127.0.0.1:{port}")
}

fn waf_base(port: u16) -> String {
    format!("http://127.0.0.1:{port}")
}

async fn ok_handler() -> &'static str {
    "ok"
}

// ── WAF subprocess helpers ────────────────────────────────────────────────────

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

fn spawn_waf(waf_port: u16, backend_port: u16, extra_args: &[&str]) -> WafGuard {
    let project_root = env!("CARGO_MANIFEST_DIR");
    let rules_dir = format!("{project_root}/rules");
    let tmpdir = tempfile::tempdir().expect("tempdir");
    let metrics_port = pick_free_port().to_string();

    let child = Command::new(env!("CARGO_BIN_EXE_krakenwaf"))
        .args([
            "--no-tls",
            "--allow-private-upstream",
            "--listen",
            &format!("127.0.0.1:{waf_port}"),
            "--metrics-port",
            &metrics_port,
            "--upstream",
            &format!("http://{}", backend_addr(backend_port)),
            "--rules-dir",
            &rules_dir,
        ])
        .args(extra_args)
        .current_dir(tmpdir.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("failed to spawn krakenwaf binary");

    WafGuard {
        child,
        _tmpdir: tmpdir,
    }
}

fn http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(25))
        .build()
        .expect("reqwest client")
}

async fn wait_for_waf(client: &reqwest::Client, port: u16) {
    // Use the health endpoint — it bypasses the rate limiter so readiness
    // polling does not consume rate-limit budget during tests.
    // Poll until the WAF process is ready (up to 45 s). Per-request timeout
    // for actual test requests is 25 s, controlled by `http_client()`.
    let health = format!("{}/__krakenwaf/health", waf_base(port));
    for _ in 0..150 {
        if let Ok(r) = client
            .get(&health)
            .timeout(Duration::from_millis(500))
            .send()
            .await
        {
            if r.status().is_success() {
                return;
            }
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    panic!("KrakenWAF on port {port} did not become ready");
}

// ── Local rate-limit tests ────────────────────────────────────────────────────

#[tokio::test]
async fn local_rate_limit_blocks_burst() {
    let bp = ensure_backend();
    let port = alloc_waf_port();
    let _waf = spawn_waf(port, bp, &["--rate-limit-per-minute", "3"]);
    let client = http_client();
    wait_for_waf(&client, port).await;

    let url = format!("{}/ping", waf_base(port));
    let mut allowed = 0u32;
    let mut blocked = 0u32;
    for _ in 0..6 {
        let status = client.get(&url).send().await.expect("request").status();
        if status == StatusCode::OK {
            allowed += 1;
        } else {
            blocked += 1;
        }
    }
    assert!(allowed >= 3, "at least 3 requests must pass; got {allowed}");
    assert!(
        blocked >= 1,
        "at least 1 request must be rate-limited; got {blocked}"
    );
}

#[tokio::test]
async fn local_rate_limit_ips_are_independent() {
    let bp = ensure_backend();
    let port = alloc_waf_port();
    let _waf = spawn_waf(port, bp, &["--rate-limit-per-minute", "1"]);
    let client = http_client();
    wait_for_waf(&client, port).await;

    let url = format!("{}/ping", waf_base(port));
    // First request from IP1 (localhost) — passes.
    let r1 = client.get(&url).send().await.expect("r1").status();
    // Second request from same IP — blocked with the rate-limit-specific status.
    let r2 = client.get(&url).send().await.expect("r2").status();
    assert_eq!(r1, StatusCode::OK, "first request must pass");
    assert_eq!(r2, StatusCode::TOO_MANY_REQUESTS);
}

// ── Config-file loading tests ─────────────────────────────────────────────────

#[tokio::test]
async fn ratelimit_by_file_conf_sets_rate_limit() {
    let bp = ensure_backend();
    let port = alloc_waf_port();

    let conf = NamedTempFile::new().expect("tempfile");
    std::fs::write(
        conf.path(),
        "rate_limit_per_minute: 2\nmax_coroutines_per_ip: 0\n",
    )
    .expect("write conf");

    let _waf = spawn_waf(
        port,
        bp,
        &["--ratelimit-by-file-conf", conf.path().to_str().unwrap()],
    );
    let client = http_client();
    wait_for_waf(&client, port).await;

    let url = format!("{}/ping", waf_base(port));
    assert_eq!(
        client.get(&url).send().await.unwrap().status(),
        StatusCode::OK
    );
    assert_eq!(
        client.get(&url).send().await.unwrap().status(),
        StatusCode::OK
    );
    assert_eq!(
        client.get(&url).send().await.unwrap().status(),
        StatusCode::TOO_MANY_REQUESTS,
        "3rd request must be blocked by file-configured limit of 2"
    );
}

#[tokio::test]
async fn rate_limit_is_enforced_in_detect_only_mode() {
    let backend_port = ensure_backend();
    let port = alloc_waf_port();
    let _waf = spawn_waf(
        port,
        backend_port,
        &["--rate-limit-per-minute", "1", "--mode", "detect-only"],
    );
    let client = http_client();
    wait_for_waf(&client, port).await;

    let url = format!("{}/ping", waf_base(port));
    assert_eq!(
        client.get(&url).send().await.unwrap().status(),
        StatusCode::OK
    );
    let response = client.get(&url).send().await.unwrap();
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(response.headers().contains_key("retry-after"));
}

#[tokio::test]
async fn cli_rate_limit_overrides_file_conf() {
    let bp = ensure_backend();
    let port = alloc_waf_port();

    // File says limit=1 but CLI says 5 — CLI wins.
    let conf = NamedTempFile::new().expect("tempfile");
    std::fs::write(
        conf.path(),
        "rate_limit_per_minute: 1\nmax_coroutines_per_ip: 0\n",
    )
    .expect("write conf");

    let _waf = spawn_waf(
        port,
        bp,
        &[
            "--ratelimit-by-file-conf",
            conf.path().to_str().unwrap(),
            "--rate-limit-per-minute",
            "5",
        ],
    );
    let client = http_client();
    wait_for_waf(&client, port).await;

    let url = format!("{}/ping", waf_base(port));
    for i in 0..5 {
        assert_eq!(
            client.get(&url).send().await.unwrap().status(),
            StatusCode::OK,
            "request {i} must pass when CLI overrides file limit to 5"
        );
    }
}

// ── Per-IP concurrency tests ──────────────────────────────────────────────────

#[tokio::test]
async fn max_coroutines_per_ip_blocks_excess_concurrent() {
    let bp = ensure_backend();
    let port = alloc_waf_port();

    // Set a very high rate limit so the GCRA never fires; test only concurrency.
    let conf = NamedTempFile::new().expect("tempfile");
    std::fs::write(
        conf.path(),
        "rate_limit_per_minute: 10000\nmax_coroutines_per_ip: 2\n",
    )
    .expect("write conf");

    let _waf = spawn_waf(
        port,
        bp,
        &["--ratelimit-by-file-conf", conf.path().to_str().unwrap()],
    );
    let client = http_client();
    wait_for_waf(&client, port).await;

    // Send 5 concurrent requests. With cap=2 the WAF processes at most 2 at once;
    // the rest receive 429. We relax the assertion to "at least one 429".
    let url = format!("{}/ping", waf_base(port));
    let handles: Vec<tokio::task::JoinHandle<_>> = (0..5)
        .map(|_| {
            let c = client.clone();
            let u = url.clone();
            tokio::spawn(async move { c.get(&u).send().await.map(|r| r.status()) })
        })
        .collect();

    let mut statuses = Vec::new();
    for h in handles {
        if let Ok(Ok(s)) = h.await {
            statuses.push(s);
        }
    }

    let too_many = statuses
        .iter()
        .filter(|&&s| s == StatusCode::TOO_MANY_REQUESTS)
        .count();
    assert!(
        too_many >= 1,
        "expected at least one 429 with cap=2; got {statuses:?}"
    );
}

#[tokio::test]
async fn max_coroutines_per_ip_zero_disables_limit() {
    let bp = ensure_backend();
    let port = alloc_waf_port();

    let conf = NamedTempFile::new().expect("tempfile");
    std::fs::write(
        conf.path(),
        "rate_limit_per_minute: 10000\nmax_coroutines_per_ip: 0\n",
    )
    .expect("write conf");

    let _waf = spawn_waf(
        port,
        bp,
        &["--ratelimit-by-file-conf", conf.path().to_str().unwrap()],
    );
    let client = http_client();
    wait_for_waf(&client, port).await;

    let url = format!("{}/ping", waf_base(port));
    let handles: Vec<tokio::task::JoinHandle<_>> = (0..10)
        .map(|_| {
            let c = client.clone();
            let u = url.clone();
            tokio::spawn(async move { c.get(&u).send().await.map(|r| r.status()) })
        })
        .collect();

    let mut statuses = Vec::new();
    for h in handles {
        if let Ok(Ok(s)) = h.await {
            statuses.push(s);
        }
    }

    assert!(
        statuses.iter().all(|&s| s == StatusCode::OK),
        "all requests must pass when concurrency limit is disabled; got {statuses:?}"
    );
}

// ── Attack simulation tests ───────────────────────────────────────────────────

/// Burst attack: attacker sends many requests rapidly — GCRA must absorb the
/// burst up to the configured limit and block the rest.
#[tokio::test]
async fn attack_burst_is_rate_limited() {
    let bp = ensure_backend();
    let port = alloc_waf_port();
    let _waf = spawn_waf(port, bp, &["--rate-limit-per-minute", "5"]);
    let client = http_client();
    wait_for_waf(&client, port).await;

    let url = format!("{}/ping", waf_base(port));
    let mut allowed = 0u32;
    let mut blocked = 0u32;
    for _ in 0..10 {
        match client.get(&url).send().await.map(|r| r.status()) {
            Ok(s) if s == StatusCode::OK => allowed += 1,
            _ => blocked += 1,
        }
    }
    assert!(allowed >= 5, "GCRA must allow at least 5; got {allowed}");
    assert!(
        blocked >= 1,
        "burst attack must trigger blocking; got {blocked}"
    );
}

/// Scanner attack: attacker rotates user-agents — rate-limiting is per-IP,
/// not per-UA, so rotating the user-agent must not bypass the limit.
#[tokio::test]
async fn attack_scanner_rate_limited_regardless_of_ua() {
    let bp = ensure_backend();
    let port = alloc_waf_port();
    let _waf = spawn_waf(port, bp, &["--rate-limit-per-minute", "3"]);
    let client = http_client();
    wait_for_waf(&client, port).await;

    let url = format!("{}/ping", waf_base(port));
    let user_agents = [
        "Mozilla/5.0 (compatible; Googlebot/2.1)",
        "curl/7.88.1",
        "python-requests/2.31",
        "Nikto/2.1.6",
        "sqlmap/1.7",
        "masscan/1.3",
    ];

    let mut blocked = 0u32;
    for (i, ua) in user_agents.iter().enumerate() {
        let status = client
            .get(&url)
            .header("user-agent", *ua)
            .send()
            .await
            .map_or(StatusCode::INTERNAL_SERVER_ERROR, |r| r.status());
        // GCRA is an operational control and returns 429 independently of WAF mode.
        if status != StatusCode::OK {
            blocked += 1;
        }
        if i >= 3 {
            assert!(
                blocked >= 1,
                "rate limit must fire even with varied user-agents"
            );
        }
    }
}

/// Concurrent flood: many goroutines from the same IP — the per-IP concurrency
/// cap and the rate limiter together must reduce the number of successful responses.
#[tokio::test]
async fn attack_concurrent_flood_is_throttled() {
    let bp = ensure_backend();
    let port = alloc_waf_port();

    let conf = NamedTempFile::new().expect("tempfile");
    std::fs::write(
        conf.path(),
        "rate_limit_per_minute: 5\nmax_coroutines_per_ip: 3\n",
    )
    .expect("write conf");

    let _waf = spawn_waf(
        port,
        bp,
        &["--ratelimit-by-file-conf", conf.path().to_str().unwrap()],
    );
    let client = http_client();
    wait_for_waf(&client, port).await;

    let url = format!("{}/ping", waf_base(port));
    let handles: Vec<tokio::task::JoinHandle<_>> = (0..20)
        .map(|_| {
            let c = client.clone();
            let u = url.clone();
            tokio::spawn(async move { c.get(&u).send().await.map(|r| r.status()) })
        })
        .collect();

    let mut statuses = Vec::new();
    for h in handles {
        if let Ok(Ok(s)) = h.await {
            statuses.push(s);
        }
    }

    let ok_count = statuses.iter().filter(|&&s| s == StatusCode::OK).count();
    let limited = statuses
        .iter()
        .filter(|&&s| s == StatusCode::TOO_MANY_REQUESTS)
        .count();
    assert!(
        limited >= 1,
        "flood of 20 concurrent requests must trigger throttling; ok={ok_count} limited={limited}"
    );
}

/// An incomplete header block never reaches the request handler, so it must not
/// consume the per-request IP concurrency budget. The independent header timer
/// owns this pre-request phase.
#[tokio::test]
async fn incomplete_headers_do_not_consume_request_concurrency_budget() {
    let bp = ensure_backend();
    let port = alloc_waf_port();

    let conf = NamedTempFile::new().expect("tempfile");
    std::fs::write(
        conf.path(),
        "rate_limit_per_minute: 10000\n\
         max_coroutines_per_ip: 1\n\
         http_header_read_timeout_secs: 1\n",
    )
    .expect("write conf");

    let _waf = spawn_waf(
        port,
        bp,
        &["--ratelimit-by-file-conf", conf.path().to_str().unwrap()],
    );
    let client = http_client();
    wait_for_waf(&client, port).await;

    let waf_addr = format!("127.0.0.1:{port}");

    // Open a raw TCP connection and stop before the terminating CRLF.
    let mut slow_conn = tokio::net::TcpStream::connect(&waf_addr)
        .await
        .expect("tcp connect");
    slow_conn
        .write_all(b"GET /ping HTTP/1.1\r\nHost: 127.0.0.1\r\n")
        .await
        .expect("write partial request");
    // Do NOT send the final \r\n — this keeps the connection open.

    // Give Hyper a moment to enter its HTTP/1 header-read phase.
    tokio::time::sleep(Duration::from_millis(100)).await;

    // The complete request still reaches the handler because the partial
    // connection has not consumed the request-level concurrency budget.
    let url = format!("{}/ping", waf_base(port));
    let status = client
        .get(&url)
        .send()
        .await
        .expect("complete request")
        .status();
    assert_eq!(status, StatusCode::OK);
    drop(slow_conn);
}

/// An incomplete HTTP/1 header block must be closed by Hyper's header timer,
/// before request-level rate limiting or the 30-second connection timeout.
#[tokio::test]
async fn incomplete_http1_headers_are_closed_by_header_timeout() {
    let bp = ensure_backend();
    let port = alloc_waf_port();

    let conf = NamedTempFile::new().expect("tempfile");
    std::fs::write(
        conf.path(),
        "rate_limit_per_minute: 10000\n\
         max_coroutines_per_ip: 64\n\
         connection_timeout_secs: 30\n\
         http_header_read_timeout_secs: 1\n",
    )
    .expect("write conf");

    let _waf = spawn_waf(
        port,
        bp,
        &["--ratelimit-by-file-conf", conf.path().to_str().unwrap()],
    );
    let client = http_client();
    wait_for_waf(&client, port).await;

    let mut stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .expect("tcp connect");
    stream
        .write_all(b"GET /ping HTTP/1.1\r\nHost: localhost\r\nX-Slow: ")
        .await
        .expect("write incomplete headers");

    let mut byte = [0u8; 1];
    let read = tokio::time::timeout(Duration::from_secs(4), stream.read(&mut byte))
        .await
        .expect("header timeout must close the connection within four seconds");

    match read {
        Ok(0) | Err(_) => {}
        Ok(n) => panic!("unexpected response bytes before close: {n}"),
    }
}
