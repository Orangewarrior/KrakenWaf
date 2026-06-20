//! End-to-end coverage for the file-driven configuration inputs added for the
//! automatically discovered `conf/proxy.yaml`, `conf/filter.yaml`, and
//! `conf/ratelimit.yaml` inputs.
//!
//! Topology
//! --------
//!   reqwest  →  `KrakenWAF` (`:WAF_PORT`)  →  Axum backend (`:BACKEND_PORT`)
//!
//! The WAF is spawned **without** `--listen`, `--upstream`, `--no-tls`,
//! `--allow-private-upstream`, `--header-protection-injection`, or `--blockmsg`
//! on the command line. Every one of those must come from `conf/proxy.yaml`
//! so a successful proxied request proves the automatically discovered file was
//! honoured. The body-size cap likewise comes only from the automatically
//! loaded `conf/ratelimit.yaml` file.

use axum::{routing::get, routing::post, Router};
use reqwest::StatusCode;
use std::{
    fs,
    net::SocketAddr,
    path::Path,
    process::{Child, Command, Stdio},
    time::Duration,
};

const BACKEND_MARKER: &str = "BACKEND_OK_MARKER_8F3A";
const BLOCK_PAGE_MARKER: &str = "KRAKEN_BLOCK_PAGE_MARKER_42";
/// `conf/ratelimit.yaml :: max_body_bytes` used by the test — deliberately tiny.
const MAX_BODY_BYTES: usize = 100;

fn pick_free_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind :0");
    l.local_addr().expect("local_addr").port()
}

// ─── Backend ──────────────────────────────────────────────────────────────────

async fn clean() -> &'static str {
    BACKEND_MARKER
}

async fn sink() -> &'static str {
    "ok"
}

fn spawn_backend(port: u16) {
    std::thread::spawn(move || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("backend runtime")
            .block_on(async move {
                let app = Router::new()
                    .route("/clean", get(clean))
                    .route("/sink", post(sink));
                let addr: SocketAddr = format!("127.0.0.1:{port}").parse().expect("addr");
                let listener = tokio::net::TcpListener::bind(addr).await.expect("bind backend");
                axum::serve(listener, app).await.expect("serve backend");
            });
    });
    std::thread::sleep(Duration::from_millis(300));
}

// ─── WAF subprocess ───────────────────────────────────────────────────────────

/// Owns the spawned WAF process and kills it on drop. The workdir `TempDir` is
/// owned by the caller and declared *before* this guard so it is dropped after
/// the child has been reaped.
struct WafGuard {
    child: Child,
}

impl Drop for WafGuard {
    fn drop(&mut self) {
        self.child.kill().ok();
        self.child.wait().ok();
    }
}

/// Write the two config files into `<tmp>/conf/` and spawn the WAF pointing at
/// them. Crucially, the proxy-level flags are **not** on the command line.
fn spawn_waf_from_files(workdir: &Path, waf_port: u16, backend_port: u16) -> WafGuard {
    let project_root = env!("CARGO_MANIFEST_DIR");
    let rules_dir = format!("{project_root}/rules");

    fs::create_dir_all(workdir.join("conf")).expect("mkdir conf");

    // Response-header policy + custom block page live inside the workdir so the
    // WAF (cwd == workdir) resolves the relative paths and the block-page
    // canonicalisation stays within root.
    fs::write(workdir.join("headers.txt"), "X-Frame-Options: DENY\n").expect("write headers");
    fs::write(
        workdir.join("block.html"),
        format!("<html><body>{BLOCK_PAGE_MARKER}</body></html>"),
    )
    .expect("write block page");

    // conf/proxy.yaml — exercises the documented format: `key : value` spacing,
    // inline `# comments`, an empty field (upstream-timeout-secs), booleans, and
    // a CIDR list. None of these are passed on the command line.
    let proxy_yaml = format!(
        "# proxy config under test\n\
         listen : 127.0.0.1:{waf_port}\n\
         upstream : http://127.0.0.1:{backend_port} # backend\n\
         upstream-timeout-secs: # empty -> WAF default\n\
         allow-private-upstream: true # loopback backend\n\
         internal-header-name: X-Kraken-Internal\n\
         real-ip-header: X-Forwarded-For\n\
         trusted-proxy-cidrs: 127.0.0.1/32\n\
         no-tls: true # plain HTTP for the test\n\
         header-protection-injection: headers.txt\n\
         blockmsg: block.html\n"
    );
    fs::write(workdir.join("conf/proxy.yaml"), proxy_yaml).expect("write proxy.yaml");

    // conf/ratelimit.yaml — tiny max_body_bytes so the cap is observable; a high
    // request budget so the rate limiter never interferes with the test.
    let ratelimit_yaml = format!(
        "rate_limit_per_minute: 100000\n\
         connection_timeout_secs: 25\n\
         http_header_read_timeout_secs: 8\n\
         max_connections: 256\n\
         max_body_bytes: {MAX_BODY_BYTES}\n\
         max_upstream_response_bytes: 4194304\n"
    );
    fs::write(workdir.join("conf/ratelimit.yaml"), ratelimit_yaml).expect("write ratelimit.yaml");

    // conf/filter.yaml is also auto-loaded. Vectorscan is deliberately enabled
    // so non-Vectorscan builds exercise the required startup diagnostic sink.
    fs::write(
        workdir.join("conf/filter.yaml"),
        format!(
            "libinjection-sqli: true\n\
             libinjection-xss: true\n\
             vectorscan: true\n\
             cmc-modules: false\n\
             rules-dir: {rules_dir}\n\
             allowpaths: ''\n\
             verbose: false\n"
        ),
    )
    .expect("write filter.yaml");

    let child = Command::new(env!("CARGO_BIN_EXE_krakenwaf"))
        .current_dir(workdir)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn krakenwaf");

    WafGuard { child }
}

fn http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(25))
        .build()
        .expect("client")
}

async fn wait_for_waf(client: &reqwest::Client, waf_port: u16) {
    let health = format!("http://127.0.0.1:{waf_port}/__krakenwaf/health");
    for _ in 0..150 {
        if client
            .get(&health)
            .timeout(Duration::from_millis(500))
            .send()
            .await
            .is_ok()
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    panic!("WAF on :{waf_port} did not become ready");
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn proxy_and_ratelimit_files_drive_behavior() {
    let backend_port = pick_free_port();
    let waf_port = pick_free_port();
    spawn_backend(backend_port);

    let tmp = tempfile::tempdir().expect("tempdir");
    let _waf = spawn_waf_from_files(tmp.path(), waf_port, backend_port);

    let client = http_client();
    wait_for_waf(&client, waf_port).await;

    if !cfg!(feature = "vectorscan-engine") {
        let error_log = tmp.path().join("log/console/error.jsonl");
        for _ in 0..50 {
            if fs::read_to_string(&error_log)
                .is_ok_and(|content| content.contains("compiled without the 'vectorscan-engine' feature"))
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        let content = fs::read_to_string(&error_log).expect("read Vectorscan error log");
        assert!(
            content.contains("compiled without the 'vectorscan-engine' feature"),
            "missing Vectorscan build-mismatch diagnostic: {content}"
        );
    }

    let base = format!("http://127.0.0.1:{waf_port}");

    // 1) Clean request proxies to the backend. This only works if `upstream`,
    //    `listen`, `no-tls`, and `allow-private-upstream` all came from
    //    conf/proxy.yaml — none were passed on the command line.
    let resp = client
        .get(format!("{base}/clean"))
        .send()
        .await
        .expect("clean request");
    assert_eq!(resp.status(), StatusCode::OK, "clean GET should proxy to backend");
    // The header-protection-injection file was applied to the response.
    assert_eq!(
        resp.headers()
            .get("x-frame-options")
            .and_then(|v| v.to_str().ok()),
        Some("DENY"),
        "header-protection-injection from proxy.yaml should be applied"
    );
    let body = resp.text().await.expect("body");
    assert!(
        body.contains(BACKEND_MARKER),
        "clean response should carry the backend marker, got: {body}"
    );

    // 2) Attack request is blocked with the custom block page from proxy.yaml.
    let resp = client
        .get(format!("{base}/clean?x=union%20select%201%20from%20users"))
        .send()
        .await
        .expect("attack request");
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "SQLi URI keyword should be blocked"
    );
    let body = resp.text().await.expect("block body");
    assert!(
        body.contains(BLOCK_PAGE_MARKER),
        "blocked response should serve the blockmsg page from proxy.yaml, got: {body}"
    );

    // 3) A clean body larger than conf/ratelimit.yaml :: max_body_bytes is
    //    rejected with 413 — proving the cap was loaded from the file.
    let big_clean_body = "a".repeat(MAX_BODY_BYTES * 4);
    let resp = client
        .post(format!("{base}/sink"))
        .body(big_clean_body)
        .send()
        .await
        .expect("oversized post");
    assert_eq!(
        resp.status(),
        StatusCode::PAYLOAD_TOO_LARGE,
        "body over max_body_bytes (from ratelimit.yaml) should be 413"
    );

    // 4) A small clean body under the cap passes through to the backend.
    let resp = client
        .post(format!("{base}/sink"))
        .body("a".repeat(10))
        .send()
        .await
        .expect("small post");
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "small clean body should proxy successfully"
    );
}

/// A malformed proxy config must abort startup (the validator rejects it), so
/// the health endpoint never comes up.
#[tokio::test]
async fn invalid_proxy_config_aborts_startup() {
    let tmp = tempfile::tempdir().expect("tempdir");
    fs::create_dir_all(tmp.path().join("conf")).expect("mkdir conf");
    // `listen` is not a socket address → validation failure.
    fs::write(
        tmp.path().join("conf/proxy.yaml"),
        "listen: not-a-socket-addr\nno-tls: true\n",
    )
    .expect("write bad proxy.yaml");

    let mut child = Command::new(env!("CARGO_BIN_EXE_krakenwaf"))
        .current_dir(tmp.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn krakenwaf");

    // The process should exit (non-zero) rather than bind a listener.
    for _ in 0..50 {
        if let Some(status) = child.try_wait().expect("try_wait") {
            assert!(!status.success(), "invalid proxy config should fail startup");
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    child.kill().ok();
    child.wait().ok();
    panic!("WAF did not exit on invalid proxy config");
}
