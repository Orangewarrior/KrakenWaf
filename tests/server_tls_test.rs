//! End-to-end TLS test: the WAF binary terminates TLS itself (loads its
//! own cert/key via an SNI map) and serves traffic over HTTPS to a
//! reqwest client + the `attack` binary, both verifying the cert
//! against a custom CA.
//!
//! Topology
//! ────────
//!   reqwest  (HTTPS, custom CA root)
//!       │
//!       ▼
//!   krakenwaf  --listen 127.0.0.1:N  (TLS termination, `sni_map.csv` →
//!       │     /tmp/krakenwaf-tls/waf.pem + waf.key, signed by ca.pem)
//!       ▼
//!   Axum backend (plain HTTP)
//!
//! Requires `/tmp/krakenwaf-tls/{ca,waf}.pem` + `waf.key` — generated
//! by the openssl recipe in `docs/banning.md`. Skips when missing.

#![allow(clippy::unwrap_used)]

use axum::{routing::get, Router};
use reqwest::StatusCode;
use std::{
    fs,
    net::SocketAddr,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::OnceLock,
    time::Duration,
};
use std::error::Error as _;
use tempfile::TempDir;

// ─── Cert + Redis discovery ──────────────────────────────────────────────────

fn tls_root() -> PathBuf {
    PathBuf::from(std::env::var("KRAKENWAF_TEST_TLS_DIR").unwrap_or_else(|_| "/tmp/krakenwaf-tls".to_string()))
}

fn ca_path() -> PathBuf { tls_root().join("ca.pem") }
fn waf_cert_path() -> PathBuf { tls_root().join("waf.pem") }
fn waf_key_path() -> PathBuf { tls_root().join("waf.key") }

fn tls_assets_present() -> bool {
    let ok = ca_path().exists() && waf_cert_path().exists() && waf_key_path().exists();
    if !ok {
        eprintln!(
            "TLS assets missing in {} (need ca.pem, waf.pem, waf.key) — skipping. \
             See docs/banning.md for the openssl recipe.",
            tls_root().display()
        );
    }
    ok
}

// ─── Free ports + Axum backend ───────────────────────────────────────────────

fn pick_free_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind :0");
    l.local_addr().expect("addr").port()
}

static BACKEND_PORT: OnceLock<u16> = OnceLock::new();
fn backend_port() -> u16 { *BACKEND_PORT.get_or_init(pick_free_port) }
fn backend_addr() -> String { format!("127.0.0.1:{}", backend_port()) }

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
                let app = Router::new()
                    .route("/ok", get(|| async { "ok" }))
                    .route("/echo", get(|axum::extract::Query(q): axum::extract::Query<std::collections::HashMap<String, String>>| async move {
                        format!("echo:{}", q.get("q").cloned().unwrap_or_default())
                    }));
                let addr: SocketAddr = ([127, 0, 0, 1], port).into();
                let listener = tokio::net::TcpListener::bind(addr).await.expect("bind");
                axum::serve(listener, app).await.expect("serve");
            });
        });
        std::thread::sleep(Duration::from_millis(200));
    });
}

// ─── WAF guard (TLS termination ON) ──────────────────────────────────────────

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

/// Spawn a krakenwaf instance with TLS termination ENABLED. Writes a
/// minimal `sni_map.csv` into `tmpdir/rules/tls/` so the WAF loads the
/// test CA-signed cert/key instead of the repo's default.
fn spawn_waf_tls(waf_port: u16) -> WafGuard {
    let project_root = env!("CARGO_MANIFEST_DIR");
    let rules_dir = format!("{project_root}/rules");
    let listen = format!("127.0.0.1:{waf_port}");
    let upstream = format!("http://{}", backend_addr());

    let tmpdir = tempfile::tempdir().expect("tempdir");

    // Custom SNI map: tell the WAF where its cert + key live. rustls'
    // ResolvesServerCertUsingSni rejects IP literals — SNI is for DNS
    // names only. The single `localhost` entry is also the default,
    // which is what gets served to clients connecting via the literal
    // IP (no SNI in the ClientHello).
    let tls_dir = tmpdir.path().join("rules/tls");
    fs::create_dir_all(&tls_dir).expect("mkdir rules/tls");
    let sni_csv = tls_dir.join("sni_map.csv");
    fs::write(
        &sni_csv,
        format!(
            "localhost,{cert},{key},true\n",
            cert = waf_cert_path().display(),
            key = waf_key_path().display(),
        ),
    )
    .expect("write sni_map.csv");

    let child = Command::new(env!("CARGO_BIN_EXE_krakenwaf"))
        .args([
            "--allow-private-upstream",
            "--listen", &listen,
            "--upstream", &upstream,
            "--rules-dir", &rules_dir,
            "--sni-map", sni_csv.to_str().unwrap(),
        ])
        .current_dir(tmpdir.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn krakenwaf with TLS");

    WafGuard { child, tmpdir }
}

fn dump_logs(tmpdir: &Path) {
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

fn https_client_with_ca() -> reqwest::Client {
    let pem = fs::read(ca_path()).expect("read ca.pem");
    let cert = reqwest::Certificate::from_pem(&pem).expect("parse ca.pem");
    reqwest::Client::builder()
        .add_root_certificate(cert)
        .timeout(Duration::from_secs(15))
        .build()
        .expect("client")
}

async fn wait_for_https_waf(client: &reqwest::Client, port: u16) -> Result<(), &'static str> {
    let url = format!("https://127.0.0.1:{port}/__krakenwaf/health");
    // 60 s ceiling — debug builds of krakenwaf load ~600 CMC patterns,
    // ~280 SQL-error regexes, the addr lists, the rules tree, etc.
    // The release build is much faster; this budget exists for CI.
    for _ in 0..200 {
        if client
            .get(&url)
            .timeout(Duration::from_millis(500))
            .send()
            .await
            .is_ok()
        {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    Err("WAF (TLS) did not become ready in 60 s")
}

// ─── Tests ───────────────────────────────────────────────────────────────────

/// The WAF loads its own self-signed (CA-signed) cert via the SNI map
/// and terminates TLS. A reqwest client validating against the same CA
/// successfully reaches the backend over HTTPS, and a XSS-payload
/// query is blocked with 403 — proving the WAF inspection runs on
/// post-TLS-handshake plaintext.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn waf_terminates_tls_and_blocks_inside_the_session() {
    if !tls_assets_present() { return }
    ensure_backend();
    let port = pick_free_port();
    let waf = spawn_waf_tls(port);
    let client = https_client_with_ca();

    if let Err(reason) = wait_for_https_waf(&client, port).await {
        dump_logs(waf.tmpdir.path());
        panic!("{reason} on port {port}");
    }
    let _waf = waf;

    let base = format!("https://127.0.0.1:{port}");

    // Clean request — must pass through.
    let resp = client
        .get(format!("{base}/ok"))
        .send()
        .await
        .expect("clean HTTPS request");
    assert_eq!(resp.status(), StatusCode::OK, "clean request must reach backend over TLS");
    assert_eq!(resp.text().await.unwrap_or_default(), "ok");

    // XSS payload — WAF must inspect the decrypted request and block it.
    let resp = client
        .get(format!("{base}/echo"))
        .query(&[("q", "<script>alert(1)</script>")])
        .send()
        .await
        .expect("xss HTTPS request");
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "XSS payload over HTTPS must be blocked by the WAF inside the TLS session"
    );
}

/// reqwest WITHOUT the custom CA must FAIL the handshake — proves the
/// WAF is genuinely doing TLS, not silently falling back to plaintext.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reqwest_without_ca_fails_handshake_against_tls_waf() {
    use std::fmt::Write as _;
    if !tls_assets_present() { return }
    ensure_backend();
    let port = pick_free_port();
    let waf = spawn_waf_tls(port);
    let trusted = https_client_with_ca();
    if let Err(reason) = wait_for_https_waf(&trusted, port).await {
        dump_logs(waf.tmpdir.path());
        panic!("{reason} on port {port}");
    }
    let _waf = waf;

    let strict = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("strict client");

    let err = strict
        .get(format!("https://127.0.0.1:{port}/__krakenwaf/health"))
        .send()
        .await
        .expect_err("untrusted CA must reject the WAF's self-signed cert");

    // Walk the std::error::Error source chain — reqwest wraps the
    // underlying rustls/hyper error in a thin transport error whose
    // Display does not always mention TLS specifics.
    let mut chain = format!("{err}");
    let mut cause: Option<&dyn std::error::Error> = err.source();
    while let Some(c) = cause {
        write!(chain, " | {c}").expect("write to String is infallible");
        cause = c.source();
    }
    let chain_lc = chain.to_lowercase();
    assert!(
        chain_lc.contains("certificate")
            || chain_lc.contains("unknown")     // rustls "unknown issuer"
            || chain_lc.contains("tls")
            || chain_lc.contains("invalid")
            || chain_lc.contains("ca"),
        "error chain should evidence a TLS rejection, got: {chain}"
    );
}

/// Run the in-tree `attack` binary against the TLS WAF using its
/// freshly-added `--cacert` flag. Proves attack.rs can audit a real
/// HTTPS deployment end-to-end and that the WAF blocks the canonical
/// XSS/SQLi sweep over TLS just as well as plaintext.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn attack_binary_runs_against_tls_waf_with_custom_ca() {
    if !tls_assets_present() { return }
    ensure_backend();
    let port = pick_free_port();
    let waf = spawn_waf_tls(port);
    let client = https_client_with_ca();
    if let Err(reason) = wait_for_https_waf(&client, port).await {
        dump_logs(waf.tmpdir.path());
        panic!("{reason} on port {port}");
    }
    let _waf = waf;

    // Resolve the `attack` binary that cargo just built.
    let attack_bin = env!("CARGO_BIN_EXE_attack");
    let target = format!("https://127.0.0.1:{port}");

    let output = tokio::task::spawn_blocking(move || {
        Command::new(attack_bin)
            .args([
                "--target", &target,
                "--cacert", ca_path().to_str().unwrap(),
                "--concurrency", "10",
            ])
            .output()
            .expect("run attack binary")
    })
    .await
    .expect("join");

    let stdout = String::from_utf8_lossy(&output.stdout);

    // The attack binary's exit code includes score-engine response-side
    // expectations that depend on the backend echoing specific payloads
    // — out of scope for a TLS test. The TLS-relevant signals are:
    //
    //   1. The WAF blocked plenty of payloads over the encrypted wire.
    //   2. No request hit a TLS / cert-validation error.
    //   3. The session reached the backend (404s prove the request was
    //      decrypted, inspected, allowed, and proxied through).
    // Per-sweep summary lines look like "→ 50 blocked | 0 bypassed | 0 errors".
    // We need at least one sweep where the WAF blocked something over
    // TLS — XSS/SQLi sweeps will produce 50/50 when the WAF is healthy.
    let has_summary_block = stdout
        .lines()
        .any(|l| l.contains("blocked") && !l.contains("0 blocked"));
    assert!(
        has_summary_block,
        "attack run must show at least one sweep with `blocked > 0` over TLS — output:\n{stdout}"
    );
    assert!(
        !stdout.to_lowercase().contains("unknownissuer")
            && !stdout.to_lowercase().contains("certificate verify failed")
            && !stdout.to_lowercase().contains("invalid certificate"),
        "attack run must not hit cert-validation errors when --cacert is supplied:\n{stdout}"
    );
    // 404 from the upstream stub proves the WAF terminated TLS, the
    // request reached the backend, and a response came back.
    assert!(
        stdout.contains("404"),
        "expected at least one 404 backend response over TLS — output:\n{stdout}"
    );
}

/// `--insecure-skip-verify` also works against the WAF (debug-mode
/// fallback). Mirrors the cacert test but proves the bypass flag is
/// wired up.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn attack_binary_runs_against_tls_waf_with_insecure_skip_verify() {
    if !tls_assets_present() { return }
    ensure_backend();
    let port = pick_free_port();
    let waf = spawn_waf_tls(port);
    let client = https_client_with_ca();
    if let Err(reason) = wait_for_https_waf(&client, port).await {
        dump_logs(waf.tmpdir.path());
        panic!("{reason} on port {port}");
    }
    let _waf = waf;

    let attack_bin = env!("CARGO_BIN_EXE_attack");
    let target = format!("https://127.0.0.1:{port}");

    let output = tokio::task::spawn_blocking(move || {
        Command::new(attack_bin)
            .args([
                "--target", &target,
                "--insecure-skip-verify",
                "--concurrency", "10",
            ])
            .output()
            .expect("run attack binary")
    })
    .await
    .expect("join");

    let stdout = String::from_utf8_lossy(&output.stdout);
    // See the rationale on the --cacert variant above — exit code
    // covers expectations unrelated to TLS. We assert on the signals
    // that prove the TLS round-trip succeeded.
    let has_block = stdout
        .lines()
        .any(|l| l.contains("blocked") && !l.contains("0 blocked"));
    assert!(has_block, "expected at least one sweep with `blocked > 0` over TLS:\n{stdout}");
    assert!(
        !stdout.to_lowercase().contains("unknownissuer"),
        "--insecure-skip-verify must mute cert validation errors"
    );
}
