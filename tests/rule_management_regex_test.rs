//! End-to-end integration tests for the **regex rule-management endpoints**.
//!
//! Topology
//! --------
//!   reqwest ─┬─► KrakenWAF data plane  :WAF_PORT  (--no-tls) ─► demo_server :BACKEND
//!            └─► KrakenWAF rule-mgmt    :RM_PORT   (--no-tls)
//!
//! These cover the `POST /rule/control/regex/view` and
//! `POST /rule/control/regex/update/<name>` endpoints added on top of the CMC
//! control plane. The test acts as the Rorschach *client*, signing tokens with
//! the same `krakenwaf::rorschach::sign_token` code path the WAF verifies.
//!
//! Every WAF instance runs against a **private copy** of the repository `rules/`
//! tree (made in a tempdir), so the update tests — which rewrite rule files on
//! disk — never mutate the checked-in rule set.
//!
//! Covered (matches the feature spec):
//!   * view returns the file content for each of the five managed names
//!   * view / update reject a name outside the managed allowlist (incl. a real
//!     repository file, `rules.json`, that must stay untouched)
//!   * update replaces a context's rules, hot-reloads, and the new rule blocks
//!     a live request immediately
//!   * update of the scanner line-list and the vectorscan keyword bundle
//!   * empty / malformed rule documents are rejected with 400
//!   * missing token → 401

#![allow(clippy::doc_markdown)]

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use krakenwaf::rorschach::{self, RorschachSecrets};
use reqwest::StatusCode;
use std::{
    net::TcpListener,
    path::Path,
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
    rules_dir: std::path::PathBuf,
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

/// Recursively copy a directory tree (used to clone the repo `rules/` into a
/// writable tempdir so update tests never touch the checked-in files).
fn copy_dir_all(src: &Path, dst: &Path) {
    std::fs::create_dir_all(dst).expect("create dst dir");
    for entry in std::fs::read_dir(src).expect("read_dir") {
        let entry = entry.expect("dir entry");
        let file_type = entry.file_type().expect("file_type");
        let from = entry.path();
        let to = dst.join(entry.file_name());
        if file_type.is_dir() {
            copy_dir_all(&from, &to);
        } else if file_type.is_file() {
            std::fs::copy(&from, &to).expect("copy file");
        }
    }
}

/// Spawn the WAF against a private copy of the repository rules tree, with the
/// rule-management control plane enabled. Returns the guard plus the path of the
/// writable rules copy so tests can assert against on-disk files.
fn spawn_waf_rm(waf_port: u16, rm_port: u16, backend_port: u16) -> WafGuard {
    let root = env!("CARGO_MANIFEST_DIR");
    let tmp = tempfile::tempdir().expect("waf tempdir");
    let rules_dir = tmp.path().join("rules");
    copy_dir_all(Path::new(&format!("{root}/rules")), &rules_dir);

    let listen = format!("127.0.0.1:{waf_port}");
    let upstream = format!("http://127.0.0.1:{backend_port}");
    let rm_port_s = rm_port.to_string();
    let metrics_port_s = pick_free_port().to_string();
    let cmc = format!("{root}/conf/filter.yaml");
    let rules_dir_s = rules_dir.to_string_lossy().to_string();

    let mut cmd = Command::new(env!("CARGO_BIN_EXE_krakenwaf"));
    cmd.args([
        "--no-tls",
        "--allow-private-upstream",
        "--listen",
        &listen,
        "--upstream",
        &upstream,
        "--rules-dir",
        &rules_dir_s,
        "--cmc-load",
        &cmc,
        "--rule-management-port",
        &rm_port_s,
        "--metrics-port",
        &metrics_port_s,
    ]);
    cmd.env("RORSCHACH_SECRET_EVEN", even_b64())
        .env("RORSCHACH_SECRET_ODD", odd_b64())
        .current_dir(tmp.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null());

    let child = cmd.spawn().expect("spawn krakenwaf");
    WafGuard {
        child,
        rules_dir,
        _tmp: tmp,
    }
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

/// Build an `Authorization: Bearer <rorschach>` header for the current step,
/// bound to the given method, path and body.
fn auth(method: &str, path: &str, body: &[u8]) -> String {
    let step = current_step();
    let nonce = rorschach::random_nonce_b64().expect("nonce");
    let token = rorschach::sign_token(&secrets(), "kraken-ui", step, &nonce, method, path, body)
        .expect("sign");
    format!("Bearer {token}")
}

async fn post_rm(
    client: &reqwest::Client,
    rm_port: u16,
    path: &str,
    body: &[u8],
) -> reqwest::Response {
    client
        .post(rm_url(rm_port, path))
        .header("Authorization", auth("POST", path, body))
        .body(body.to_vec())
        .send()
        .await
        .expect("rule-management POST")
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn regex_view_returns_each_managed_file() {
    let backend_port = pick_free_port();
    let waf_port = pick_free_port();
    let rm_port = pick_free_port();
    let _backend = spawn_backend(backend_port);
    let _waf = spawn_waf_rm(waf_port, rm_port, backend_port);

    let client = http_client();
    wait_for_backend(&client, backend_port).await;
    assert!(wait_for_health(&client, waf_port, 180).await, "WAF not ready");

    let view = "/rule/control/regex/view";

    // body_regex carries the documented "Command injection separators body" rule.
    let resp = post_rm(&client, rm_port, view, br#"{"rule_view":"body_regex"}"#).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.text().await.expect("body");
    assert!(body.contains("\"context\":\"regex_view\""), "body={body}");
    assert!(
        body.contains("Command injection separators body"),
        "body={body}"
    );

    // The other four managed names all resolve and return content.
    for name in ["header_regex", "path_regex", "vectorscan_list", "scanners"] {
        let payload = format!("{{\"rule_view\":\"{name}\"}}");
        let resp = post_rm(&client, rm_port, view, payload.as_bytes()).await;
        assert_eq!(resp.status(), StatusCode::OK, "name={name}");
        let body = resp.text().await.expect("body");
        assert!(body.contains("\"status\":\"ok\""), "name={name} body={body}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn regex_view_requires_token_and_rejects_unknown_name() {
    let backend_port = pick_free_port();
    let waf_port = pick_free_port();
    let rm_port = pick_free_port();
    let _backend = spawn_backend(backend_port);
    let _waf = spawn_waf_rm(waf_port, rm_port, backend_port);

    let client = http_client();
    assert!(wait_for_health(&client, waf_port, 180).await, "WAF not ready");

    let view = "/rule/control/regex/view";

    // No token → 401.
    let resp = client
        .post(rm_url(rm_port, view))
        .body(br#"{"rule_view":"body_regex"}"#.to_vec())
        .send()
        .await
        .expect("no-token");
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // A name outside the managed allowlist → 400 unknown_rule.
    let resp = post_rm(&client, rm_port, view, br#"{"rule_view":"rules"}"#).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = resp.text().await.expect("body");
    assert!(body.contains("unknown_rule"), "body={body}");

    // An unknown JSON field → generic 400.
    let resp = post_rm(&client, rm_port, view, br#"{"rule_view":"body_regex","x":1}"#).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn regex_update_replaces_rules_and_blocks_in_real_time() {
    let backend_port = pick_free_port();
    let waf_port = pick_free_port();
    let rm_port = pick_free_port();
    let _backend = spawn_backend(backend_port);
    let waf = spawn_waf_rm(waf_port, rm_port, backend_port);

    let client = http_client();
    wait_for_backend(&client, backend_port).await;
    assert!(wait_for_health(&client, waf_port, 180).await, "WAF not ready");

    // A distinctive payload that no shipped rule matches.
    let marker = "zzkrakenregexmarkerzz";
    let attack_url = format!("http://127.0.0.1:{waf_port}/test_post");

    // Baseline: the marker is allowed before any rule update.
    let resp = client
        .post(&attack_url)
        .form(&[("payload_test", marker)])
        .send()
        .await
        .expect("baseline");
    assert_eq!(resp.status(), StatusCode::OK, "marker must pass initially");

    // Replace ALL body_regex rules with a single rule matching the marker.
    let new_rules = format!(
        r#"{{"rules":[{{"enable":1,"http_action":"Request","title":"marker rule","severity":"critical","cwe":"CWE-77","description":"test marker","url":"https://example.com","rule_match":"{marker}","id":"90001","score":1000}}]}}"#
    );
    let update = "/rule/control/regex/update/body_regex";
    let resp = post_rm(&client, rm_port, update, new_rules.as_bytes()).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.text().await.expect("body");
    assert!(body.contains("\"context\":\"regex_update\""), "body={body}");
    assert!(body.contains("\"rules_written\":1"), "body={body}");

    // The on-disk copy was rewritten with the new rule (old rules discarded).
    let on_disk =
        std::fs::read_to_string(waf.rules_dir.join("regex/body_regex.json")).expect("read file");
    assert!(on_disk.contains(marker), "on-disk file must contain new rule");
    assert!(
        !on_disk.contains("Command injection separators body"),
        "old rules must be gone"
    );

    // Hot-reload took effect: the marker is now blocked immediately (3× for
    // determinism).
    for _ in 0..3 {
        let resp = client
            .post(&attack_url)
            .form(&[("payload_test", marker)])
            .send()
            .await
            .expect("blocked");
        assert_eq!(
            resp.status(),
            StatusCode::FORBIDDEN,
            "marker must be blocked after update"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn regex_update_scanners_and_vectorscan() {
    let backend_port = pick_free_port();
    let waf_port = pick_free_port();
    let rm_port = pick_free_port();
    let _backend = spawn_backend(backend_port);
    let waf = spawn_waf_rm(waf_port, rm_port, backend_port);

    let client = http_client();
    assert!(wait_for_health(&client, waf_port, 180).await, "WAF not ready");

    // scanners.txt uses the line-list shape `{ "lines": [...] }`.
    let scanners = "/rule/control/regex/update/scanners";
    let resp = post_rm(
        &client,
        rm_port,
        scanners,
        br#"{"lines":["evilscanner","anotherbot"]}"#,
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.text().await.expect("body");
    assert!(body.contains("\"rules_written\":2"), "body={body}");
    let on_disk =
        std::fs::read_to_string(waf.rules_dir.join("user_agents/scanners.txt")).expect("read");
    assert_eq!(on_disk, "evilscanner\nanotherbot\n");

    // vectorscan_list uses the keyword `{ "rules": [...] }` shape.
    let vectorscan = "/rule/control/regex/update/vectorscan_list";
    let body = br#"{"rules":[{"enable":1,"http_action":"Request","title":"kw","severity":"critical","cwe":"CWE-89","description":"d","url":"https://example.com","rule_match":"union select","id":"00001","score":1000}]}"#;
    let resp = post_rm(&client, rm_port, vectorscan, body).await;
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn regex_update_rejects_empty_malformed_and_out_of_scope() {
    let backend_port = pick_free_port();
    let waf_port = pick_free_port();
    let rm_port = pick_free_port();
    let _backend = spawn_backend(backend_port);
    let waf = spawn_waf_rm(waf_port, rm_port, backend_port);

    let client = http_client();
    assert!(wait_for_health(&client, waf_port, 180).await, "WAF not ready");

    // Empty rule set → 400 invalid_rules, file untouched.
    let update = "/rule/control/regex/update/body_regex";
    let before =
        std::fs::read_to_string(waf.rules_dir.join("regex/body_regex.json")).expect("read");
    let resp = post_rm(&client, rm_port, update, br#"{"rules":[]}"#).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = resp.text().await.expect("body");
    assert!(body.contains("invalid_rules"), "body={body}");

    // Malformed / out-of-shape JSON → 400.
    let resp = post_rm(&client, rm_port, update, br#"{"rules":[{"foo":1}]}"#).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    // A rule with an invalid regex → 400.
    let bad_regex = br#"{"rules":[{"enable":1,"http_action":"Request","title":"t","severity":"high","cwe":"CWE-77","description":"d","url":"https://example.com","rule_match":"(unclosed","id":"1","score":1000}]}"#;
    let resp = post_rm(&client, rm_port, update, bad_regex).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    let after =
        std::fs::read_to_string(waf.rules_dir.join("regex/body_regex.json")).expect("read");
    assert_eq!(before, after, "rejected updates must not modify the file");

    // Out-of-scope name: `rules` maps to the real, unmanaged rules.json → 400,
    // and the on-disk rules.json must be untouched.
    let rules_json_before =
        std::fs::read_to_string(waf.rules_dir.join("rules.json")).expect("read rules.json");
    let out_of_scope = "/rule/control/regex/update/rules";
    let valid_doc = br#"{"rules":[{"enable":1,"http_action":"Request","title":"t","severity":"high","cwe":"CWE-77","description":"d","url":"https://example.com","rule_match":"abc","id":"1","score":1000}]}"#;
    let resp = post_rm(&client, rm_port, out_of_scope, valid_doc).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = resp.text().await.expect("body");
    assert!(body.contains("unknown_rule"), "body={body}");
    let rules_json_after =
        std::fs::read_to_string(waf.rules_dir.join("rules.json")).expect("read rules.json");
    assert_eq!(
        rules_json_before, rules_json_after,
        "an out-of-scope file must never be modified"
    );
}
