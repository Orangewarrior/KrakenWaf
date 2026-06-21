//! End-to-end test for the BAN-list subsystem.
//!
//! Topology
//! ────────
//!   reqwest (X-Forwarded-For: <fake attacker IP>)
//!       │
//!       ▼
//!   `KrakenWAF` :`WAF_PORT`  (--no-tls, --trusted-proxy-cidrs 127.0.0.0/8,
//!                         --real-ip-header x-forwarded-for, --cmc-load …,
//!                         conf/banning.yaml in cwd)
//!       │
//!       ▼
//!   Axum backend :`BACKEND_PORT`  (GET /ok → 200)
//!
//! Why a forged `X-Forwarded-For`?
//! ────────────────────────────────
//! All reqwest connections originate from 127.0.0.1; we cannot use raw client
//! IPs to differentiate one attacker from another in a hermetic test. By
//! marking loopback as a trusted proxy and reading the client IP from
//! `X-Forwarded-For`, the WAF treats every request as coming from whatever
//! IP we put in the header — exactly the same code path that runs in
//! production when `KrakenWAF` sits behind nginx/HAProxy. The "fake attacker"
//! is therefore a stand-in for a real free-proxy / VPN exit IP.
//!
//! Scenarios exercised
//! ───────────────────
//! 1. `security_scanners: true` fast-track. A single GET with
//!    `User-Agent: nikto/2.1.6` is blocked by the `Detect_bots_n_scanners`
//!    CMC module. The attacker IP is added to the BAN list immediately.
//!    A second request from the same attacker IP — even with a *clean*
//!    User-Agent — returns 403 from the BAN-list short-circuit at the
//!    server layer (no inspection at all).
//! 2. `tolerance_block_count: 3`. Three blocked requests trigger the ban
//!    on the fourth request.

#![allow(clippy::unwrap_used)]

use axum::{routing::get, Router};
use reqwest::StatusCode;
use std::{
    fs,
    net::SocketAddr,
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::OnceLock,
    time::Duration,
};
use tempfile::TempDir;

static BAN_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

// ─── Port helpers ────────────────────────────────────────────────────────────

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

fn waf_base(port: u16) -> String {
    format!("http://127.0.0.1:{port}")
}

// ─── Axum backend ────────────────────────────────────────────────────────────

static BACKEND_ONCE: OnceLock<()> = OnceLock::new();

fn ensure_backend() {
    BACKEND_ONCE.get_or_init(|| {
        let port = backend_port();
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .expect("rt");
            rt.block_on(async move {
                let app = Router::new().route("/ok", get(|| async { "ok" }));
                let addr: SocketAddr = ([127, 0, 0, 1], port).into();
                let listener = tokio::net::TcpListener::bind(addr).await.expect("bind");
                axum::serve(listener, app).await.expect("serve");
            });
        });
        // Give the listener a moment to come up. The WAF launch + health
        // poll will absorb any residual gap.
        std::thread::sleep(Duration::from_millis(200));
    });
}

// ─── WAF guard ───────────────────────────────────────────────────────────────

struct WafGuard {
    child: Child,
    tmpdir: TempDir,
}

impl Drop for WafGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Start a WAF instance backed by `--cmc-load` + a banning.yaml in `cwd`.
fn spawn_waf(waf_port: u16, banning_yaml: &str) -> WafGuard {
    let project_root = env!("CARGO_MANIFEST_DIR");
    let rules_dir = format!("{project_root}/rules");
    let cmc_config = format!("{project_root}/conf/filter.yaml");
    let listen = format!("127.0.0.1:{waf_port}");
    let metrics_port = pick_free_port().to_string();
    let upstream = format!("http://{}", backend_addr());

    let tmpdir = tempfile::tempdir().expect("tempdir");
    // The WAF auto-loads `conf/banning.yaml` from the current working
    // directory at startup.
    fs::create_dir_all(tmpdir.path().join("conf")).expect("mkdir conf");
    fs::write(tmpdir.path().join("conf/banning.yaml"), banning_yaml).expect("write banning.yaml");
    let allowpaths_file = tmpdir.path().join("allowpaths.yaml");
    fs::write(&allowpaths_file, "allow: []\n").expect("write allowpaths.yaml");
    let allowpaths = allowpaths_file.to_string_lossy().into_owned();

    let child = Command::new(env!("CARGO_BIN_EXE_krakenwaf"))
        .args([
            "--no-tls",
            "--allow-private-upstream",
            "--listen",
            &listen,
            "--metrics-port",
            &metrics_port,
            "--upstream",
            &upstream,
            "--rules-dir",
            &rules_dir,
            "--cmc-load",
            &cmc_config,
            "--allow-paths",
            &allowpaths,
            "--trusted-proxy-cidrs",
            "127.0.0.0/8",
            "--real-ip-header",
            "x-forwarded-for",
        ])
        .current_dir(tmpdir.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn krakenwaf");

    WafGuard { child, tmpdir }
}

async fn wait_for_waf(client: &reqwest::Client, waf_port: u16) {
    let health_url = format!("{}/__krakenwaf/health", waf_base(waf_port));
    for _ in 0..180 {
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
    panic!("KrakenWAF on port {waf_port} did not become ready in time");
}

fn dump_logs(tmpdir: &std::path::Path) {
    let logs = tmpdir.join("logs");
    if !logs.exists() {
        eprintln!("=== no logs/ in {}", tmpdir.display());
        return;
    }
    for entry in fs::read_dir(&logs).into_iter().flatten().flatten() {
        let p = entry.path();
        if p.is_file() {
            eprintln!("--- {} ---", p.display());
            if let Ok(content) = fs::read_to_string(&p) {
                eprintln!("{content}");
            }
        }
    }
}

fn http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .expect("client")
}

// ─── Banning.yaml fixtures ───────────────────────────────────────────────────

/// `security_scanners: true` + threshold high so it cannot trigger by accident.
fn yaml_fast_track() -> &'static str {
    r"Banning_mode: true
Ban_context:
  security_scanners: true
  tolerance_block_count: 99
  Ban_wait_time: 30m
"
}

/// `security_scanners: false` + low tolerance so cumulative blocks ban.
fn yaml_threshold() -> &'static str {
    r"Banning_mode: true
Ban_context:
  security_scanners: false
  tolerance_block_count: 3
  Ban_wait_time: 30m
"
}

// ─── Tests ───────────────────────────────────────────────────────────────────

/// Scenario 1 — scanner UA fast-track.
///
/// A single request with `User-Agent: nikto/2.1.6` is blocked by the
/// `Detect_bots_n_scanners` CMC module. Because `security_scanners: true`,
/// the BAN-list manager fast-tracks the attacker IP to the BAN list. A
/// second request from the same IP with a *clean* User-Agent is rejected
/// by the BAN-list short-circuit at the server layer with HTTP 403.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn nikto_request_then_clean_request_is_banned() {
    let _serial = BAN_TEST_LOCK.lock().await;
    ensure_backend();
    let port = pick_free_port();
    let waf = spawn_waf(port, yaml_fast_track());
    let client = http_client();
    // Health-poll up front; on timeout dump the WAF logs from tmpdir.
    let health_url = format!("{}/__krakenwaf/health", waf_base(port));
    let mut ready = false;
    for _ in 0..180 {
        if client
            .get(&health_url)
            .timeout(Duration::from_millis(500))
            .send()
            .await
            .is_ok()
        {
            ready = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    if !ready {
        dump_logs(waf.tmpdir.path());
        panic!("WAF not ready on port {port}");
    }
    let _waf = waf;

    // RFC 5737 TEST-NET-2 — guaranteed not to collide with any real
    // public IP if this test ever leaked into a routable network.
    let attacker_ip = "198.51.100.7";

    // 1. Scanner request — blocked by the CMC, IP enters BAN list.
    let url = format!("{}/ok", waf_base(port));
    let resp = client
        .get(&url)
        .header("User-Agent", "Mozilla/5.0 nikto/2.1.6")
        .header("X-Forwarded-For", attacker_ip)
        .send()
        .await
        .expect("first request");
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "scanner UA should be blocked by Detect_bots_n_scanners"
    );

    // The proxy fires-and-forgets the BAN record (tokio::spawn). Wait a
    // little so the SQLite write completes before the second probe.
    tokio::time::sleep(Duration::from_millis(400)).await;

    // 2. Second request, this time with a CLEAN User-Agent. If the BAN
    //    list works, the server short-circuits before the WAF engine ever
    //    inspects the request and returns 403 with our "Banned" body.
    let resp2 = client
        .get(&url)
        .header(
            "User-Agent",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
        )
        .header("X-Forwarded-For", attacker_ip)
        .send()
        .await
        .expect("second request");
    assert_eq!(
        resp2.status(),
        StatusCode::FORBIDDEN,
        "banned IP must be rejected at the server layer"
    );
    let body = resp2.text().await.unwrap_or_default();
    assert!(
        body.contains("Banned"),
        "expected the 'Banned by KrakenWaf' response body, got: {body}"
    );
}

/// Scenario 2 — cumulative tolerance threshold.
///
/// `security_scanners: false` + `tolerance_block_count: 3`. The first
/// three `SQLi` requests must each return 403 (block, not ban). The
/// fourth request — same attacker IP, this time with a clean payload —
/// must be rejected by the BAN-list short-circuit (the prior three
/// blocks reached the tolerance threshold).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn three_blocks_triggers_ban_on_fourth_request() {
    let _serial = BAN_TEST_LOCK.lock().await;
    ensure_backend();
    let port = pick_free_port();
    let _waf = spawn_waf(port, yaml_threshold());
    let client = http_client();
    wait_for_waf(&client, port).await;

    let attacker_ip = "203.0.113.42"; // RFC 5737 TEST-NET-3
    let base = waf_base(port);

    // Three SQLi-style requests, each blocked by the regex/libinjection
    // engines. Spaced out a touch so the async BAN record finishes
    // between rounds.
    for n in 1..=3 {
        let payload = format!("' OR {n}={n}-- ");
        let resp = client
            .get(format!("{base}/ok"))
            .query(&[("q", payload.as_str())])
            .header("X-Forwarded-For", attacker_ip)
            .send()
            .await
            .expect("sqli request");
        assert_eq!(
            resp.status(),
            StatusCode::FORBIDDEN,
            "SQLi-style request #{n} should be blocked"
        );
        tokio::time::sleep(Duration::from_millis(300)).await;
    }

    // Wait once more so the third ban-record finishes.
    tokio::time::sleep(Duration::from_millis(400)).await;

    // Fourth request — totally clean payload + clean UA. Must still be
    // 403 because the attacker IP is now in the BAN list.
    let resp = client
        .get(format!("{base}/ok"))
        .header(
            "User-Agent",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
        )
        .header("X-Forwarded-For", attacker_ip)
        .send()
        .await
        .expect("post-ban request");
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "IP should be banned after {} blocks reached the tolerance threshold",
        3
    );
    let body = resp.text().await.unwrap_or_default();
    assert!(
        body.contains("Banned"),
        "expected the 'Banned by KrakenWaf' response body, got: {body}"
    );
}

/// Sanity check — a different X-Forwarded-For IP is unaffected by another
/// attacker's BAN. Proves the ban is keyed on the effective client IP and
/// not on the loopback peer address.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn banning_is_per_ip_other_clients_unaffected() {
    let _serial = BAN_TEST_LOCK.lock().await;
    ensure_backend();
    let port = pick_free_port();
    let _waf = spawn_waf(port, yaml_fast_track());
    let client = http_client();
    wait_for_waf(&client, port).await;

    let attacker = "198.51.100.99";
    let bystander = "192.0.2.55"; // RFC 5737 TEST-NET-1
    let url = format!("{}/ok", waf_base(port));

    // Ban the attacker.
    let _ = client
        .get(&url)
        .header("User-Agent", "nikto/2.1.6")
        .header("X-Forwarded-For", attacker)
        .send()
        .await
        .expect("ban-trigger request");
    tokio::time::sleep(Duration::from_millis(400)).await;

    // The bystander sends a perfectly clean request with the SAME loopback
    // peer (every reqwest connection is 127.0.0.1) but a DIFFERENT
    // X-Forwarded-For. It must pass through to the backend.
    let resp = client
        .get(&url)
        .header(
            "User-Agent",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
        )
        .header("X-Forwarded-For", bystander)
        .send()
        .await
        .expect("bystander request");
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "bystander IP must NOT be affected by another IP's ban"
    );
}

#[test]
fn fixtures_compile_into_valid_files() {
    // Belt-and-braces sanity: every YAML fixture used in this file must
    // produce a non-empty buffer. Catches future copy/paste regressions.
    let _: PathBuf = PathBuf::from("tests/banning_real_test.rs");
    assert!(!yaml_fast_track().is_empty());
    assert!(!yaml_threshold().is_empty());
}
