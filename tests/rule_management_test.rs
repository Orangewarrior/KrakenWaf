//! End-to-end integration tests for the **rule-management control plane**.
//!
//! Topology
//! --------
//!   reqwest ─┬─► KrakenWAF data plane  :WAF_PORT  (--no-tls) ─► demo_server :BACKEND
//!            └─► KrakenWAF rule-mgmt    :RM_PORT   (--no-tls)
//!
//! The tests act as the Rorschach *client*: they sign tokens with the exact same
//! `krakenwaf::rorschach::sign_token` code path the WAF verifies against, using
//! the same even/odd secrets handed to the WAF through its environment. This
//! mirrors how kraken-ui (in a separate repo) will talk to the control plane.
//!
//! Covered (matches the feature spec):
//!   * list reflects live state; partial update toggles only the sent modules
//!   * disabling HPP_detect stops HPP detection; re-enabling restores it
//!   * attacks are detected identically across 3 enable/disable cycles
//!   * missing / wrong token, replayed nonce, altered path/body/method,
//!     future step → 401
//!   * IP outside the allowlist → 403
//!   * unknown JSON field → 400
//!   * invalid secret → WAF refuses to start
//!   * empty allowlist → control plane refuses to start

// Test prose names product identifiers (KrakenWAF, HPP_detect, SQLite, …); the
// API-doc backtick lint is noise here.
#![allow(clippy::doc_markdown)]

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use krakenwaf::rorschach::{self, RorschachSecrets};
use reqwest::StatusCode;
use std::{
    net::TcpListener,
    process::{Child, Command, Stdio},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

// ─── Secrets (shared between the test client and the WAF under test) ──────────

fn even_b64() -> String {
    URL_SAFE_NO_PAD.encode([0xA1u8; 64])
}
fn odd_b64() -> String {
    URL_SAFE_NO_PAD.encode([0xB2u8; 64])
}
fn secrets() -> RorschachSecrets {
    RorschachSecrets::from_base64(&even_b64(), &odd_b64()).expect("valid test secrets")
}

fn now_unix() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_secs(),
    )
    .expect("fits i64")
}
fn current_step() -> u64 {
    u64::try_from(now_unix() / rorschach::STEP_SECONDS).expect("step fits u64")
}

// ─── Ports / process helpers ──────────────────────────────────────────────────

fn pick_free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("bind :0")
        .local_addr()
        .expect("local_addr")
        .port()
}

struct ChildGuard(Child);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        self.0.kill().ok();
        self.0.wait().ok();
    }
}

struct WafGuard {
    child: Child,
    _tmp: tempfile::TempDir,
}
impl Drop for WafGuard {
    fn drop(&mut self) {
        self.child.kill().ok();
        self.child.wait().ok();
    }
}

fn spawn_backend(port: u16) -> ChildGuard {
    let child = Command::new(env!("CARGO_BIN_EXE_demo_server"))
        .arg(port.to_string())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn demo_server");
    ChildGuard(child)
}

/// Spawn the WAF with the rule-management control plane enabled.
fn spawn_waf_rm(
    waf_port: u16,
    rm_port: u16,
    backend_port: u16,
    even_env: &str,
    odd_env: &str,
    allowlist_override: Option<&str>,
) -> WafGuard {
    let root = env!("CARGO_MANIFEST_DIR");
    let rules_dir = format!("{root}/rules");
    let cmc = format!("{root}/conf/filter.yaml");
    let listen = format!("127.0.0.1:{waf_port}");
    let upstream = format!("http://127.0.0.1:{backend_port}");
    let rm_port_s = rm_port.to_string();
    // A unique metrics port avoids the fixed-4343 bind collision across parallel
    // test processes (the metrics listener is irrelevant to these tests).
    let metrics_port_s = pick_free_port().to_string();

    let tmp = tempfile::tempdir().expect("waf tempdir");
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_krakenwaf"));
    cmd.args([
        "--no-tls",
        "--allow-private-upstream",
        "--listen",
        &listen,
        "--upstream",
        &upstream,
        "--rules-dir",
        &rules_dir,
        "--cmc-load",
        &cmc,
        "--rule-management-port",
        &rm_port_s,
        "--metrics-port",
        &metrics_port_s,
    ]);
    if let Some(path) = allowlist_override {
        cmd.args(["--rule-management-allowlist", path]);
    }
    cmd.env("RORSCHACH_SECRET_EVEN", even_env)
        .env("RORSCHACH_SECRET_ODD", odd_env)
        .current_dir(tmp.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null());

    let child = cmd.spawn().expect("spawn krakenwaf");
    WafGuard { child, _tmp: tmp }
}

fn http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(20))
        .build()
        .expect("client")
}

async fn wait_for_health(client: &reqwest::Client, port: u16, max_iters: u32) -> bool {
    let url = format!("http://127.0.0.1:{port}/__krakenwaf/health");
    for _ in 0..max_iters {
        if client
            .get(&url)
            .timeout(Duration::from_millis(500))
            .send()
            .await
            .is_ok()
        {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    false
}

/// Outcome of observing a WAF that is expected to fail closed at startup.
#[derive(Debug, PartialEq, Eq)]
enum StartupOutcome {
    Exited,
    Healthy,
    TimedOut,
}

/// Poll until the WAF either exits (fail-closed) or serves health, whichever
/// comes first. Startup does a lot of work (SQLite store, rate limiter, engine
/// build) before the fail-closed checks, so this must allow ample time.
async fn await_startup_outcome(
    waf: &mut WafGuard,
    client: &reqwest::Client,
    port: u16,
    max_iters: u32,
) -> StartupOutcome {
    let url = format!("http://127.0.0.1:{port}/__krakenwaf/health");
    for _ in 0..max_iters {
        if waf.child.try_wait().expect("try_wait").is_some() {
            return StartupOutcome::Exited;
        }
        if client
            .get(&url)
            .timeout(Duration::from_millis(500))
            .send()
            .await
            .is_ok()
        {
            return StartupOutcome::Healthy;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    StartupOutcome::TimedOut
}

async fn wait_for_backend(client: &reqwest::Client, port: u16) {
    let url = format!("http://127.0.0.1:{port}/");
    for _ in 0..120 {
        if client
            .get(&url)
            .timeout(Duration::from_millis(500))
            .send()
            .await
            .is_ok()
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    panic!("demo_server on :{port} never became ready");
}

// ─── Rorschach client helpers ─────────────────────────────────────────────────

fn rm_url(port: u16, path: &str) -> String {
    format!("http://127.0.0.1:{port}{path}")
}

/// Build an `Authorization: Bearer <rorschach>` header for the current step.
fn auth(client_id: &str, method: &str, path: &str, body: &[u8]) -> String {
    let step = current_step();
    let nonce = rorschach::random_nonce_b64().expect("nonce");
    let token = rorschach::sign_token(&secrets(), client_id, step, &nonce, method, path, body)
        .expect("sign");
    format!("Bearer {token}")
}

/// Like [`auth`] but with an explicit step (for the future-step rejection test).
fn auth_step(client_id: &str, step: u64, method: &str, path: &str, body: &[u8]) -> String {
    let nonce = rorschach::random_nonce_b64().expect("nonce");
    let token = rorschach::sign_token(&secrets(), client_id, step, &nonce, method, path, body)
        .expect("sign");
    format!("Bearer {token}")
}

/// Send the HPP attack (duplicate `dup` query parameter) through the data plane.
async fn hpp_status(client: &reqwest::Client, waf_port: u16) -> StatusCode {
    client
        .get(format!(
            "http://127.0.0.1:{waf_port}/test_get?payload_test=hi&dup=1&dup=2"
        ))
        .send()
        .await
        .expect("hpp request")
        .status()
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cmc_real_time_toggle_and_attack_detection() {
    let backend_port = pick_free_port();
    let waf_port = pick_free_port();
    let rm_port = pick_free_port();
    let _backend = spawn_backend(backend_port);
    let _waf = spawn_waf_rm(
        waf_port,
        rm_port,
        backend_port,
        &even_b64(),
        &odd_b64(),
        None,
    );

    let client = http_client();
    wait_for_backend(&client, backend_port).await;
    assert!(
        wait_for_health(&client, waf_port, 180).await,
        "WAF did not become ready"
    );

    // 1. list: all 18 modules enabled initially.
    let list_path = "/rule/control/cmc/list";
    let resp = client
        .get(rm_url(rm_port, list_path))
        .header("Authorization", auth("kraken-ui", "GET", list_path, b""))
        .send()
        .await
        .expect("list");
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.text().await.expect("list body");
    assert!(body.contains("\"status\":\"ok\""), "body={body}");
    assert!(body.contains("\"HPP_detect\":true"), "body={body}");
    assert!(body.contains("\"Silent_sql_errors\":true"), "body={body}");

    // 2. HPP attack is blocked while HPP_detect is on (run 3× for determinism).
    for _ in 0..3 {
        assert_eq!(hpp_status(&client, waf_port).await, StatusCode::FORBIDDEN);
    }

    // 3. Partial update: disable HPP_detect + Silent_sql_errors only.
    let update_path = "/rule/control/cmc/update";
    let patch = br#"{"modules":{"CMC-Rules":{"HPP_detect":false,"Silent_sql_errors":false}}}"#;
    let resp = client
        .post(rm_url(rm_port, update_path))
        .header(
            "Authorization",
            auth("kraken-ui", "POST", update_path, patch),
        )
        .body(patch.to_vec())
        .send()
        .await
        .expect("update");
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.text().await.expect("update body");
    assert!(body.contains("\"context\":\"cmc_update\""), "body={body}");
    assert!(
        body.contains("\"disabled\":[\"Silent_sql_errors\",\"HPP_detect\"]"),
        "body={body}"
    );
    assert!(body.contains("\"enabled\":[]"), "body={body}");

    // 4. list now reflects the new state; untouched modules are unchanged.
    let resp = client
        .get(rm_url(rm_port, list_path))
        .header("Authorization", auth("kraken-ui", "GET", list_path, b""))
        .send()
        .await
        .expect("list2");
    let body = resp.text().await.expect("list2 body");
    assert!(body.contains("\"HPP_detect\":false"), "body={body}");
    assert!(body.contains("\"Silent_sql_errors\":false"), "body={body}");
    // A module that was never part of the patch stays enabled.
    assert!(
        body.contains("\"SQLi_comments_detect\":true"),
        "body={body}"
    );

    // 5. With HPP_detect disabled the same attack now passes (3× for determinism).
    for _ in 0..3 {
        assert_eq!(hpp_status(&client, waf_port).await, StatusCode::OK);
    }

    // 6. Re-enable HPP_detect — detection is restored, again deterministically.
    let patch = br#"{"modules":{"CMC-Rules":{"HPP_detect":true}}}"#;
    let resp = client
        .post(rm_url(rm_port, update_path))
        .header(
            "Authorization",
            auth("kraken-ui", "POST", update_path, patch),
        )
        .body(patch.to_vec())
        .send()
        .await
        .expect("re-enable");
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.text().await.expect("body");
    assert!(body.contains("\"enabled\":[\"HPP_detect\"]"), "body={body}");

    for _ in 0..3 {
        assert_eq!(hpp_status(&client, waf_port).await, StatusCode::FORBIDDEN);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rule_management_auth_and_input_validation() {
    let backend_port = pick_free_port();
    let waf_port = pick_free_port();
    let rm_port = pick_free_port();
    let _backend = spawn_backend(backend_port);
    let _waf = spawn_waf_rm(
        waf_port,
        rm_port,
        backend_port,
        &even_b64(),
        &odd_b64(),
        None,
    );

    let client = http_client();
    assert!(
        wait_for_health(&client, waf_port, 180).await,
        "WAF not ready"
    );

    let list_path = "/rule/control/cmc/list";
    let update_path = "/rule/control/cmc/update";

    // Missing token → 401.
    let resp = client
        .get(rm_url(rm_port, list_path))
        .send()
        .await
        .expect("no-token");
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // Token signed with the WRONG secrets → 401.
    let wrong = RorschachSecrets::from_base64(
        &URL_SAFE_NO_PAD.encode([0x11u8; 64]),
        &URL_SAFE_NO_PAD.encode([0x22u8; 64]),
    )
    .expect("wrong secrets");
    let nonce = rorschach::random_nonce_b64().expect("test");
    let bad = rorschach::sign_token(&wrong, "c", current_step(), &nonce, "GET", list_path, b"")
        .expect("sign wrong");
    let resp = client
        .get(rm_url(rm_port, list_path))
        .header("Authorization", format!("Bearer {bad}"))
        .send()
        .await
        .expect("wrong-token");
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // Replayed nonce → 401 (first use consumes it, second is rejected).
    let header = auth("c", "GET", list_path, b"");
    let first = client
        .get(rm_url(rm_port, list_path))
        .header("Authorization", header.clone())
        .send()
        .await
        .expect("replay-1");
    assert_eq!(first.status(), StatusCode::OK);
    let second = client
        .get(rm_url(rm_port, list_path))
        .header("Authorization", header)
        .send()
        .await
        .expect("replay-2");
    assert_eq!(second.status(), StatusCode::UNAUTHORIZED);

    // Altered path: signed for list, sent to a different path → 401.
    let resp = client
        .get(rm_url(rm_port, "/rule/control/cmc/other"))
        .header("Authorization", auth("c", "GET", list_path, b""))
        .send()
        .await
        .expect("altered-path");
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // Altered body: token bound to b"{}" but a different body is sent → 401.
    let resp = client
        .post(rm_url(rm_port, update_path))
        .header("Authorization", auth("c", "POST", update_path, b"{}"))
        .body(br#"{"modules":{"CMC-Rules":{"HPP_detect":false}}}"#.to_vec())
        .send()
        .await
        .expect("altered-body");
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // Altered method: signed GET, sent POST → 401.
    let resp = client
        .post(rm_url(rm_port, list_path))
        .header("Authorization", auth("c", "GET", list_path, b""))
        .send()
        .await
        .expect("altered-method");
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // Future step → 401.
    let resp = client
        .get(rm_url(rm_port, list_path))
        .header(
            "Authorization",
            auth_step("c", current_step() + 10, "GET", list_path, b""),
        )
        .send()
        .await
        .expect("future-step");
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // Unknown JSON field with an otherwise-valid token → 400.
    let patch = br#"{"modules":{"CMC-Rules":{"Bogus_module":true}}}"#;
    let resp = client
        .post(rm_url(rm_port, update_path))
        .header("Authorization", auth("c", "POST", update_path, patch))
        .body(patch.to_vec())
        .send()
        .await
        .expect("unknown-field");
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = resp.text().await.expect("test");
    assert!(body.contains("expected format"), "body={body}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rule_management_ip_outside_allowlist_is_forbidden() {
    let backend_port = pick_free_port();
    let waf_port = pick_free_port();
    let rm_port = pick_free_port();

    // Restrict the allowlist to a network that does NOT contain 127.0.0.1.
    let allow_dir = tempfile::tempdir().expect("allow dir");
    let allow_path = allow_dir.path().join("allow.txt");
    std::fs::write(&allow_path, "10.0.0.0/8\n").expect("write allowlist");

    let _backend = spawn_backend(backend_port);
    let _waf = spawn_waf_rm(
        waf_port,
        rm_port,
        backend_port,
        &even_b64(),
        &odd_b64(),
        Some(allow_path.to_str().expect("test")),
    );

    let client = http_client();
    assert!(
        wait_for_health(&client, waf_port, 180).await,
        "WAF not ready"
    );

    let list_path = "/rule/control/cmc/list";
    // Even WITH a valid token, a loopback caller outside the allowlist → 403.
    let resp = client
        .get(rm_url(rm_port, list_path))
        .header("Authorization", auth("c", "GET", list_path, b""))
        .send()
        .await
        .expect("forbidden");
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    // And with no token at all it is still 403 (allowlist is checked first).
    let resp = client
        .get(rm_url(rm_port, list_path))
        .send()
        .await
        .expect("forbidden-no-token");
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn waf_refuses_to_start_with_invalid_secret() {
    let backend_port = pick_free_port();
    let waf_port = pick_free_port();
    let rm_port = pick_free_port();

    // `even` is set but far too short (and not 64 bytes) → fatal startup error.
    let mut waf = spawn_waf_rm(
        waf_port,
        rm_port,
        backend_port,
        "too-short",
        &odd_b64(),
        None,
    );

    let client = http_client();
    // The WAF must fail closed: exit on its own, never serving health.
    assert_eq!(
        await_startup_outcome(&mut waf, &client, waf_port, 160).await,
        StartupOutcome::Exited,
        "WAF must refuse to start with an invalid Rorschach secret"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rule_management_refuses_empty_allowlist() {
    let backend_port = pick_free_port();
    let waf_port = pick_free_port();
    let rm_port = pick_free_port();

    let allow_dir = tempfile::tempdir().expect("allow dir");
    let allow_path = allow_dir.path().join("empty.txt");
    std::fs::write(&allow_path, "# no entries here\n\n").expect("write empty allowlist");

    let mut waf = spawn_waf_rm(
        waf_port,
        rm_port,
        backend_port,
        &even_b64(),
        &odd_b64(),
        Some(allow_path.to_str().expect("test")),
    );

    let client = http_client();
    assert_eq!(
        await_startup_outcome(&mut waf, &client, waf_port, 160).await,
        StartupOutcome::Exited,
        "rule-management control plane must refuse to start with an empty allowlist"
    );
}
