//! Integration tests for the `only_addrs` IP-restriction feature in allow-paths.
//!
//! # Topology
//!
//! ```text
//!   reqwest  →  KrakenWaf (--no-tls)  →  Axum backend
//! ```
//!
//! Tests cover:
//! - Proxy-path IP restriction: `/healthz` with `only_addrs: 127.0.0.1`
//!   - Allowed when effective IP is 127.0.0.1 (loopback)
//!   - Blocked when effective IP is a "foreign" address (simulated via
//!     `X-Forwarded-For` + `--trusted-proxy-cidrs`)
//! - URI query-string restriction: foreign IP sending `?next=/healthz` is blocked
//! - Unrestricted paths still pass WAF inspection (attack payloads are blocked)
//! - Localhost access to WAF's own `/metrics` endpoint

use axum::{response::Html, routing::get, Router};
use reqwest::StatusCode;
use std::{
    net::SocketAddr,
    process::{Child, Command, Stdio},
    sync::OnceLock,
    time::Duration,
};

// ── Port helpers ──────────────────────────────────────────────────────────────

static BACKEND_PORT: OnceLock<u16> = OnceLock::new();

fn pick_free_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind :0");
    l.local_addr().expect("local_addr").port()
}

fn backend_port() -> u16 {
    *BACKEND_PORT.get_or_init(pick_free_port)
}

fn backend_addr() -> String {
    format!("127.0.0.1:{}", backend_port())
}

fn waf_base(port: u16) -> String {
    format!("http://127.0.0.1:{port}")
}

// ── Axum backend ──────────────────────────────────────────────────────────────

static BACKEND_ONCE: OnceLock<()> = OnceLock::new();

async fn healthz() -> &'static str {
    "ok"
}

async fn readyz() -> &'static str {
    "ok"
}

async fn test_page() -> Html<&'static str> {
    Html("<html><body>test</body></html>")
}

fn ensure_backend() {
    BACKEND_ONCE.get_or_init(|| {
        let addr: SocketAddr = backend_addr().parse().expect("backend addr");
        std::thread::spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("runtime")
                .block_on(async move {
                    let app = Router::new()
                        .route("/healthz", get(healthz))
                        .route("/readyz", get(readyz))
                        .route("/test", get(test_page));
                    let listener = tokio::net::TcpListener::bind(addr).await.expect("bind");
                    axum::serve(listener, app).await.expect("serve");
                });
        });
        std::thread::sleep(Duration::from_millis(300));
    });
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

/// Spawn a WAF that:
/// - Has an allow-paths YAML with `only_addrs: 127.0.0.1` for `/healthz` and `/readyz`
/// - Accepts `X-Forwarded-For` from 127.0.0.0/8 (so tests can spoof the effective IP)
fn spawn_waf_with_only_addrs(waf_port: u16) -> WafGuard {
    let project_root = env!("CARGO_MANIFEST_DIR");
    let rules_dir = format!("{project_root}/rules");
    let listen = format!("127.0.0.1:{waf_port}");
    let upstream = format!("http://{}", backend_addr());

    let tmpdir = tempfile::tempdir().expect("tmpdir");

    // Write the IP allowlist file.
    std::fs::write(
        tmpdir.path().join("allow_addrs.txt"),
        "# Only loopback may access health/metrics paths.\n127.0.0.1\n::1\n",
    )
    .expect("write allow_addrs.txt");

    // Write the allow-paths YAML that references the IP list.
    let yaml = r#"allow:
  - order: 1
    title: "Health check endpoint"
    description: "IP-restricted health probes"
    log: false
    only_addrs: allow_addrs.txt
    paths:
      - /healthz
      - /readyz
"#;
    std::fs::write(tmpdir.path().join("lists.yaml"), yaml).expect("write lists.yaml");

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
            "--allow-paths",
            "lists.yaml",
            // Trust loopback as a proxy so X-Forwarded-For is honoured.
            "--trusted-proxy-cidrs",
            "127.0.0.0/8",
            "--real-ip-header",
            "X-Forwarded-For",
        ])
        .current_dir(tmpdir.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn krakenwaf");

    WafGuard { child, _tmpdir: tmpdir }
}

/// Spawn a plain WAF (no allow-paths) for attack-blocking tests.
fn spawn_plain_waf(waf_port: u16) -> WafGuard {
    let project_root = env!("CARGO_MANIFEST_DIR");
    let rules_dir = format!("{project_root}/rules");
    let listen = format!("127.0.0.1:{waf_port}");
    let upstream = format!("http://{}", backend_addr());
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
        .current_dir(tmpdir.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn krakenwaf");

    WafGuard { child, _tmpdir: tmpdir }
}

fn http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(25))
        .build()
        .expect("client")
}

async fn wait_for_waf(client: &reqwest::Client, waf_port: u16) {
    let health_url = format!("{}/__krakenwaf/health", waf_base(waf_port));
    for _ in 0..150 {
        if client
            .get(&health_url)
            .timeout(Duration::from_millis(500))
            .send()
            .await
            .is_ok()
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    panic!("KrakenWaf on port {waf_port} did not become ready in time");
}

// ── Tests ─────────────────────────────────────────────────────────────────────

/// Localhost (127.0.0.1) can access an IP-restricted path.
#[tokio::test]
async fn test_healthz_allowed_from_localhost() {
    ensure_backend();
    let port = pick_free_port();
    let _waf = spawn_waf_with_only_addrs(port);
    let client = http_client();
    wait_for_waf(&client, port).await;

    // No X-Forwarded-For → effective IP is the TCP peer (127.0.0.1) → allowed.
    let resp = client
        .get(format!("{}/healthz", waf_base(port)))
        .send()
        .await
        .expect("request");
    assert_eq!(resp.status(), StatusCode::OK, "/healthz must be 200 for localhost");
}

/// A foreign IP (simulated via X-Forwarded-For) is blocked on an IP-restricted path.
#[tokio::test]
async fn test_healthz_blocked_from_foreign_ip() {
    ensure_backend();
    let port = pick_free_port();
    let _waf = spawn_waf_with_only_addrs(port);
    let client = http_client();
    wait_for_waf(&client, port).await;

    // 203.0.113.1 is TEST-NET-3 (RFC 5737) — documentation, not in allow_addrs.txt.
    let resp = client
        .get(format!("{}/healthz", waf_base(port)))
        .header("X-Forwarded-For", "203.0.113.1")
        .send()
        .await
        .expect("request");
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "/healthz must be 403 for a foreign IP"
    );
}

/// /readyz also IP-restricted; localhost passes, foreign IP is blocked.
#[tokio::test]
async fn test_readyz_allowed_from_localhost() {
    ensure_backend();
    let port = pick_free_port();
    let _waf = spawn_waf_with_only_addrs(port);
    let client = http_client();
    wait_for_waf(&client, port).await;

    let resp = client
        .get(format!("{}/readyz", waf_base(port)))
        .send()
        .await
        .expect("request");
    assert_eq!(resp.status(), StatusCode::OK, "/readyz must be 200 for localhost");
}

#[tokio::test]
async fn test_readyz_blocked_from_foreign_ip() {
    ensure_backend();
    let port = pick_free_port();
    let _waf = spawn_waf_with_only_addrs(port);
    let client = http_client();
    wait_for_waf(&client, port).await;

    let resp = client
        .get(format!("{}/readyz", waf_base(port)))
        .header("X-Forwarded-For", "198.51.100.5")
        .send()
        .await
        .expect("request");
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "/readyz must be 403 for a foreign IP"
    );
}

/// Unrestricted paths let any IP through WAF inspection normally.
#[tokio::test]
async fn test_unrestricted_path_any_ip_passes() {
    ensure_backend();
    let port = pick_free_port();
    let _waf = spawn_waf_with_only_addrs(port);
    let client = http_client();
    wait_for_waf(&client, port).await;

    // /test is not in the allow-paths config → IP restriction does not apply.
    let resp = client
        .get(format!("{}/test", waf_base(port)))
        .header("X-Forwarded-For", "203.0.113.99")
        .send()
        .await
        .expect("request");
    // WAF forwards to backend (no attack payload) → 200.
    assert_eq!(resp.status(), StatusCode::OK, "/test must be 200 for any IP (no IP restriction)");
}

/// A foreign IP with the restricted path appearing in a query string is blocked.
#[tokio::test]
async fn test_uri_query_string_blocked_foreign_ip() {
    ensure_backend();
    let port = pick_free_port();
    let _waf = spawn_waf_with_only_addrs(port);
    let client = http_client();
    wait_for_waf(&client, port).await;

    // The actual path (/test) is not restricted, but the URI contains /healthz.
    let resp = client
        .get(format!("{}/test?next=/healthz", waf_base(port)))
        .header("X-Forwarded-For", "203.0.113.2")
        .send()
        .await
        .expect("request");
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "URI with restricted path in query string must be blocked for foreign IP"
    );
}

/// Same URI is allowed when effective IP is localhost.
#[tokio::test]
async fn test_uri_query_string_allowed_localhost() {
    ensure_backend();
    let port = pick_free_port();
    let _waf = spawn_waf_with_only_addrs(port);
    let client = http_client();
    wait_for_waf(&client, port).await;

    let resp = client
        .get(format!("{}/test?next=/healthz", waf_base(port)))
        .send()
        .await
        .expect("request");
    // Localhost is in allow_addrs.txt → allowed. WAF would forward to /test on backend → 200.
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "URI with restricted path in query string must be 200 for localhost"
    );
}

/// WAF still blocks real attack payloads on unrestricted paths.
#[tokio::test]
async fn test_attack_blocked_on_unrestricted_path() {
    ensure_backend();
    let port = pick_free_port();
    let _waf = spawn_plain_waf(port);
    let client = http_client();
    wait_for_waf(&client, port).await;

    // Classic XSS in GET query — should be blocked by WAF keyword rules.
    let resp = client
        .get(format!("{}/test?payload=<script>alert(1)</script>", waf_base(port)))
        .send()
        .await
        .expect("request");
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "XSS payload must be blocked by WAF on unrestricted paths"
    );
}

/// `SQLi` payload is blocked on unrestricted paths (WAF inspection still runs).
#[tokio::test]
async fn test_sqli_blocked_on_unrestricted_path() {
    ensure_backend();
    let port = pick_free_port();
    let _waf = spawn_plain_waf(port);
    let client = http_client();
    wait_for_waf(&client, port).await;

    let resp = client
        .get(format!("{}/test?id=' OR 1=1--", waf_base(port)))
        .send()
        .await
        .expect("request");
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "SQLi payload must be blocked by WAF"
    );
}

/// WAF's own /metrics endpoint is accessible from localhost.
#[tokio::test]
async fn test_waf_metrics_accessible_from_localhost() {
    ensure_backend();
    let port = pick_free_port();
    let _waf = spawn_plain_waf(port);
    let client = http_client();
    wait_for_waf(&client, port).await;

    let resp = client
        .get(format!("{}/metrics", waf_base(port)))
        .send()
        .await
        .expect("request");
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "/metrics must be 200 from localhost with no allowlist configured"
    );

    let body = resp.text().await.expect("body");
    assert!(
        body.contains("krakenwaf_requests_inspected_total"),
        "/metrics must return Prometheus counters"
    );
}

/// Path traversal attempts on restricted paths are normalised and still blocked.
#[tokio::test]
async fn test_path_traversal_on_restricted_path_blocked() {
    ensure_backend();
    let port = pick_free_port();
    let _waf = spawn_waf_with_only_addrs(port);
    let client = http_client();
    wait_for_waf(&client, port).await;

    // After normalisation /foo/../healthz → /healthz → matches the restricted entry.
    let resp = client
        .get(format!("{}/foo/../healthz", waf_base(port)))
        .header("X-Forwarded-For", "203.0.113.10")
        .send()
        .await
        .expect("request");
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "path traversal to restricted path must be blocked for foreign IP"
    );
}

/// Localhost can access the restricted path even after traversal normalisation.
#[tokio::test]
async fn test_path_traversal_on_restricted_path_allowed_localhost() {
    ensure_backend();
    let port = pick_free_port();
    let _waf = spawn_waf_with_only_addrs(port);
    let client = http_client();
    wait_for_waf(&client, port).await;

    let resp = client
        .get(format!("{}/foo/../healthz", waf_base(port)))
        .send()
        .await
        .expect("request");
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "localhost must access /healthz even via traversal-normalised path"
    );
}
