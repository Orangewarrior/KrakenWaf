
//! End-to-end integration tests: Axum micro-backend + KrakenWAF (--no-tls).
//!
//! Topology
//! --------
//!   reqwest  →  KrakenWAF :WAF_PORT (--no-tls)  →  Axum backend :9077
//!
//! The backend is started once for the whole test binary via `BACKEND_ONCE`.
//! Each test gets its own WAF port (atomically allocated) so tests can run
//! without port collisions even when the OS puts a closed socket in TIME_WAIT.
//!
//! Backend routes
//! --------------
//!   GET  /test_one   → HTML form (GET → /test_get)
//!   GET  /test_get   → renders `payload_test` query param unsanitised in <h1>
//!   GET  /test_two   → HTML form (POST → /test_post)
//!   POST /test_post  → renders `payload_test` form field unsanitised in <h1>

use axum::{
    extract::{Form, Query},
    response::Html,
    routing::{get, post},
    Router,
};
use reqwest::StatusCode;
use serde::Deserialize;
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

const BACKEND_PORT: u16 = 9077;
static NEXT_WAF_PORT: AtomicU16 = AtomicU16::new(9090);

fn alloc_waf_port() -> u16 {
    NEXT_WAF_PORT.fetch_add(1, Ordering::SeqCst)
}

fn backend_addr() -> String {
    format!("127.0.0.1:{BACKEND_PORT}")
}

fn waf_base(port: u16) -> String {
    format!("http://127.0.0.1:{port}")
}

// ─── Axum backend (started once) ─────────────────────────────────────────────

static BACKEND_ONCE: OnceLock<()> = OnceLock::new();

#[derive(Deserialize)]
struct Payload {
    #[serde(default)]
    payload_test: String,
}

async fn test_one() -> Html<&'static str> {
    Html(
        r#"<html><body>
           <form method="GET" action="/test_get">
             <input name="payload_test"/><input type="submit" value="Go"/>
           </form></body></html>"#,
    )
}

async fn test_get(Query(p): Query<Payload>) -> Html<String> {
    Html(format!("<h1>{}</h1>", p.payload_test))
}

async fn test_two() -> Html<&'static str> {
    Html(
        r#"<html><body>
           <form method="POST" action="/test_post">
             <input name="payload_test"/><input type="submit" value="Go"/>
           </form></body></html>"#,
    )
}

async fn test_post(Form(p): Form<Payload>) -> Html<String> {
    Html(format!("<h1>{}</h1>", p.payload_test))
}

fn ensure_backend() {
    BACKEND_ONCE.get_or_init(|| {
        let addr: SocketAddr = backend_addr().parse().unwrap();
        std::thread::spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async move {
                    let app = Router::new()
                        .route("/test_one", get(test_one))
                        .route("/test_get", get(test_get))
                        .route("/test_two", get(test_two))
                        .route("/test_post", post(test_post));
                    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
                    axum::serve(listener, app).await.unwrap();
                });
        });
        // Allow the listener to bind before any WAF is pointed at it.
        std::thread::sleep(Duration::from_millis(300));
    });
}

// ─── WAF subprocess helpers ───────────────────────────────────────────────────

struct WafGuard(Child);

impl Drop for WafGuard {
    fn drop(&mut self) {
        self.0.kill().ok();
        self.0.wait().ok();
    }
}

fn spawn_waf(waf_port: u16, extra_args: &[&str]) -> WafGuard {
    let project_root = env!("CARGO_MANIFEST_DIR");
    let rules_dir = format!("{project_root}/rules");
    let listen = format!("127.0.0.1:{waf_port}");
    let upstream = format!("http://{}", backend_addr());

    let child = Command::new(env!("CARGO_BIN_EXE_krakenwaf"))
        .args([
            "--no-tls",
            "--listen",
            &listen,
            "--upstream",
            &upstream,
            "--rules-dir",
            &rules_dir,
        ])
        .args(extra_args)
        .current_dir(project_root)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("failed to spawn krakenwaf binary");

    WafGuard(child)
}

/// Poll the WAF health endpoint until it responds (or timeout).
async fn wait_for_waf(client: &reqwest::Client, waf_port: u16) {
    let health_url = format!("{}/__krakenwaf/health", waf_base(waf_port));
    for _ in 0..40 {
        if client
            .get(&health_url)
            .timeout(Duration::from_millis(300))
            .send()
            .await
            .is_ok()
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(150)).await;
    }
    panic!("KrakenWAF on port {waf_port} did not become ready in time");
}

fn http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap()
}

// ─── Tests ────────────────────────────────────────────────────────────────────

/// POST body containing an XSS payload (`<script`) is blocked with HTTP 403.
#[tokio::test]
async fn post_xss_is_blocked() {
    ensure_backend();
    let port = alloc_waf_port();
    let _waf = spawn_waf(port, &[]);
    let client = http_client();
    wait_for_waf(&client, port).await;

    let resp = client
        .post(format!("{}/test_post", waf_base(port)))
        .form(&[("payload_test", "<script>alert(1)</script>")])
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

/// GET query containing a SQLi payload is blocked with HTTP 403.
#[tokio::test]
async fn get_sqli_is_blocked() {
    ensure_backend();
    let port = alloc_waf_port();
    let _waf = spawn_waf(port, &[]);
    let client = http_client();
    wait_for_waf(&client, port).await;

    let resp = client
        .get(format!("{}/test_get", waf_base(port)))
        .query(&[("payload_test", "' or '1'='1")])
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

/// A request carrying a known scanner User-Agent (`nikto`) is blocked (403).
#[tokio::test]
async fn scanner_ua_is_blocked() {
    ensure_backend();
    let port = alloc_waf_port();
    let _waf = spawn_waf(port, &[]);
    let client = http_client();
    wait_for_waf(&client, port).await;

    let resp = client
        .get(format!("{}/test_one", waf_base(port)))
        .header("User-Agent", "nikto/2.1.6")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

/// A request from a blocklisted IP (via X-Real-IP + trusted proxy CIDR) is
/// blocked with HTTP 403.  The IP `10.10.10.1` is present in
/// `rules/addr/blocklist.txt`; we configure the WAF to trust the loopback
/// as a proxy so the X-Real-IP header is honoured.
#[tokio::test]
async fn blocklisted_ip_is_blocked() {
    ensure_backend();
    let port = alloc_waf_port();
    let _waf = spawn_waf(
        port,
        &[
            "--real-ip-header",
            "X-Real-IP",
            "--trusted-proxy-cidrs",
            "127.0.0.1/32",
        ],
    );
    let client = http_client();
    wait_for_waf(&client, port).await;

    let resp = client
        .get(format!("{}/test_one", waf_base(port)))
        .header("X-Real-IP", "10.10.10.1")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

/// Clean traffic with an innocuous payload passes through and reaches the
/// backend (HTTP 200).
#[tokio::test]
async fn clean_get_passes_through() {
    ensure_backend();
    let port = alloc_waf_port();
    let _waf = spawn_waf(port, &[]);
    let client = http_client();
    wait_for_waf(&client, port).await;

    let resp = client
        .get(format!("{}/test_get", waf_base(port)))
        .query(&[("payload_test", "hello world")])
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
}

/// Clean POST passes through and reaches the backend (HTTP 200).
#[tokio::test]
async fn clean_post_passes_through() {
    ensure_backend();
    let port = alloc_waf_port();
    let _waf = spawn_waf(port, &[]);
    let client = http_client();
    wait_for_waf(&client, port).await;

    let resp = client
        .post(format!("{}/test_post", waf_base(port)))
        .form(&[("payload_test", "safe value")])
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
}
