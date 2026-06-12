//! Integration tests for the dedicated observability port's
//! `Authorization: Bearer <token>` gate and its IP allowlist.
//!
//! # Topology
//!
//! ```text
//!   reqwest / attack  →  KrakenWaf observability port (--no-tls, plain HTTP)
//! ```
//!
//! A real WAF subprocess is booted with:
//!   * `--metrics-port <p>` — the dedicated observability listener,
//!   * `--allow-paths lists.yaml` — an allow-paths file scoped to that port
//!     (`port: <p>`) whose `only_addrs` permits loopback only,
//!   * `KRAKENWAF_METRICS_TOKEN=<token>` in the environment — the bearer secret.
//!
//! The tests assert the full matrix the feature promises:
//!   * no token            → 401
//!   * wrong token         → 401
//!   * valid token         → 200 + Prometheus body
//!   * foreign IP (via XFF) → 403 (IP gate runs before the token gate)
//!
//! The final test drives the in-tree `attack` binary in `--metrics-only` mode
//! against the same port, proving the operator-facing tool reports the gate as
//! healthy (exit code 0).

#![allow(clippy::unwrap_used)]

use axum::{routing::get, Router};
use reqwest::StatusCode;
use std::{
    net::SocketAddr,
    process::{Child, Command, Stdio},
    sync::OnceLock,
    time::Duration,
};
use tempfile::TempDir;

const TOKEN: &str = "s3cr3t-observability-token-DoNotShare-9f2c1a7e4b";

// ── Port + backend helpers ──────────────────────────────────────────────────

fn pick_free_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind :0");
    l.local_addr().expect("local_addr").port()
}

static BACKEND_PORT: OnceLock<u16> = OnceLock::new();
fn backend_port() -> u16 {
    *BACKEND_PORT.get_or_init(pick_free_port)
}
fn backend_addr() -> String {
    format!("127.0.0.1:{}", backend_port())
}

static BACKEND_ONCE: OnceLock<()> = OnceLock::new();
fn ensure_backend() {
    BACKEND_ONCE.get_or_init(|| {
        let addr: SocketAddr = backend_addr().parse().expect("backend addr");
        std::thread::spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("runtime")
                .block_on(async move {
                    let app = Router::new().route("/", get(|| async { "backend" }));
                    let listener = tokio::net::TcpListener::bind(addr).await.expect("bind");
                    axum::serve(listener, app).await.expect("serve");
                });
        });
        std::thread::sleep(Duration::from_millis(300));
    });
}

// ── WAF subprocess ──────────────────────────────────────────────────────────

struct WafGuard {
    child: Child,
    _tmpdir: TempDir,
    metrics_port: u16,
}

impl Drop for WafGuard {
    fn drop(&mut self) {
        self.child.kill().ok();
        self.child.wait().ok();
    }
}

/// Boot a plain-HTTP WAF whose observability port is bearer-protected and
/// IP-restricted to loopback. Returns the guard plus the data-plane port.
fn spawn_protected_waf() -> (WafGuard, u16) {
    let project_root = env!("CARGO_MANIFEST_DIR");
    let rules_dir = format!("{project_root}/rules");
    let waf_port = pick_free_port();
    let metrics_port = pick_free_port();
    let listen = format!("127.0.0.1:{waf_port}");
    let upstream = format!("http://{}", backend_addr());

    let tmpdir = tempfile::tempdir().expect("tmpdir");

    // IP allowlist: loopback only.
    std::fs::write(
        tmpdir.path().join("allow_addrs_metrics_n_ui.txt"),
        "# loopback only\n127.0.0.1\n::1\n",
    )
    .expect("write allow_addrs_metrics_n_ui.txt");

    // Allow-paths YAML scoped to the dedicated observability port via `port:`.
    let yaml = format!(
        r#"allow:
  - order: 2
    title: "Health check and UI endpoint"
    description: "Observability + kraken-ui, restricted to allowed IPs"
    log: false
    port: {metrics_port}
    only_addrs: allow_addrs_metrics_n_ui.txt
    paths:
      - /metrics
      - /healthz
      - /readyz
      - /livez
"#
    );
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
            "--metrics-port",
            &metrics_port.to_string(),
            // Honour X-Forwarded-For from loopback so tests can spoof a foreign IP.
            "--trusted-proxy-cidrs",
            "127.0.0.0/8",
            "--real-ip-header",
            "X-Forwarded-For",
        ])
        .env("KRAKENWAF_METRICS_TOKEN", TOKEN)
        .current_dir(tmpdir.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn krakenwaf");

    (
        WafGuard {
            child,
            _tmpdir: tmpdir,
            metrics_port,
        },
        waf_port,
    )
}

fn http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
        .expect("client")
}

/// Wait until the data-plane health probe answers (the WAF is fully up).
async fn wait_for_waf(client: &reqwest::Client, waf_port: u16) {
    let url = format!("http://127.0.0.1:{waf_port}/__krakenwaf/health");
    for _ in 0..200 {
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
    panic!("WAF on data-plane port {waf_port} did not become ready in time");
}

fn metrics_url(port: u16) -> String {
    format!("http://127.0.0.1:{port}/metrics")
}

// ── Tests ───────────────────────────────────────────────────────────────────

/// No `Authorization` header → 401, and the body must not leak metrics.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn metrics_without_token_is_unauthorized() {
    ensure_backend();
    let (waf, waf_port) = spawn_protected_waf();
    let client = http_client();
    wait_for_waf(&client, waf_port).await;

    let resp = client
        .get(metrics_url(waf.metrics_port))
        .send()
        .await
        .expect("request");
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "missing bearer token must yield 401"
    );
    let body = resp.text().await.unwrap_or_default();
    assert!(
        !body.contains("krakenwaf_requests_inspected_total"),
        "401 response must not leak Prometheus metrics, got: {body}"
    );
}

/// Wrong token → 401.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn metrics_with_wrong_token_is_unauthorized() {
    ensure_backend();
    let (waf, waf_port) = spawn_protected_waf();
    let client = http_client();
    wait_for_waf(&client, waf_port).await;

    let resp = client
        .get(metrics_url(waf.metrics_port))
        .header("Authorization", "Bearer definitely-not-the-token")
        .send()
        .await
        .expect("request");
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "an invalid bearer token must yield 401"
    );
}

/// Valid token → 200 with a Prometheus body.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn metrics_with_valid_token_succeeds() {
    ensure_backend();
    let (waf, waf_port) = spawn_protected_waf();
    let client = http_client();
    wait_for_waf(&client, waf_port).await;

    let resp = client
        .get(metrics_url(waf.metrics_port))
        .header("Authorization", format!("Bearer {TOKEN}"))
        .send()
        .await
        .expect("request");
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "the correct bearer token must be accepted"
    );
    let body = resp.text().await.unwrap_or_default();
    assert!(
        body.contains("krakenwaf_requests_inspected_total"),
        "authorised /metrics must return the Prometheus exposition body"
    );
}

/// A foreign source IP (spoofed via X-Forwarded-For) is rejected with 403 by
/// the IP allowlist BEFORE the bearer gate — even when it presents a valid
/// token. Proves the IP gate runs first.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn foreign_ip_is_forbidden_even_with_valid_token() {
    ensure_backend();
    let (waf, waf_port) = spawn_protected_waf();
    let client = http_client();
    wait_for_waf(&client, waf_port).await;

    let resp = client
        .get(metrics_url(waf.metrics_port))
        .header("X-Forwarded-For", "203.0.113.9")
        .header("Authorization", format!("Bearer {TOKEN}"))
        .send()
        .await
        .expect("request");
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "a source IP outside the allowlist must get 403, regardless of token"
    );
}

/// The in-tree `attack` binary, in `--metrics-only` mode, validates the gate
/// end-to-end and exits 0 when the WAF behaves correctly.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn attack_binary_metrics_probe_passes_against_protected_port() {
    ensure_backend();
    let (waf, waf_port) = spawn_protected_waf();
    let client = http_client();
    wait_for_waf(&client, waf_port).await;

    let attack_bin = env!("CARGO_BIN_EXE_attack");
    let metrics_target = format!("http://127.0.0.1:{}", waf.metrics_port);

    let output = tokio::task::spawn_blocking(move || {
        Command::new(attack_bin)
            .args([
                "--metrics-target",
                &metrics_target,
                "--metrics-token",
                TOKEN,
                "--metrics-only",
            ])
            .output()
            .expect("run attack binary")
    })
    .await
    .expect("join");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "attack --metrics-only must exit 0 against a correctly-protected port — output:\n{stdout}"
    );
    assert!(
        stdout.contains("ALL CHECKS PASSED"),
        "attack output must report the gate as healthy — output:\n{stdout}"
    );
    // The token must never appear in the tool's output — only the mask.
    assert!(
        !stdout.contains(TOKEN),
        "attack output must never print the bearer token"
    );
}
