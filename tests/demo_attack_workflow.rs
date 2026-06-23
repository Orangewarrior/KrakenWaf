//! End-to-end smoke test for the shipped `demo_server` and `attack` binaries.

use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    path::Path,
    process::{Child, Command, Stdio},
    thread,
    time::Duration,
};

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("bind an ephemeral port")
        .local_addr()
        .expect("read ephemeral port")
        .port()
}

struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        self.0.kill().ok();
        self.0.wait().ok();
    }
}

fn wait_for_http(port: u16) {
    for _ in 0..100 {
        if let Ok(mut stream) = TcpStream::connect(("127.0.0.1", port)) {
            stream
                .write_all(b"GET /__krakenwaf/health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                .expect("write health request");
            let mut response = String::new();
            stream.read_to_string(&mut response).ok();
            if response.starts_with("HTTP/1.1 200") {
                return;
            }
        }
        thread::sleep(Duration::from_millis(100));
    }
    panic!("KrakenWAF did not become ready on port {port}");
}

fn wait_for_hpp_token_row(root: &Path) -> (String, String, String, String) {
    let db_path = root.join("logs/db/vulns_alert.db");
    for _ in 0..100 {
        if db_path.exists() {
            let conn = rusqlite::Connection::open(&db_path).expect("open alerts db");
            let row = {
                let mut stmt = match conn.prepare(
                    "SELECT request_uri, request_uri_masked, request_payload, request_payload_masked \
                     FROM vulnerabilities \
                     WHERE request_uri LIKE '%token=abc%' OR request_payload LIKE '%token=abc%' \
                     ORDER BY id DESC LIMIT 1;",
                ) {
                    Ok(stmt) => stmt,
                    Err(_) => {
                        thread::sleep(Duration::from_millis(100));
                        continue;
                    }
                };
                stmt.query_row([], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                    ))
                })
                .ok()
            };
            if let Some(row) = row {
                return row;
            }
        }
        thread::sleep(Duration::from_millis(100));
    }
    panic!(
        "no HPP token attack row was persisted in {}",
        db_path.display()
    );
}

#[test]
fn demo_server_is_protected_against_the_attack_sweep() {
    let root = env!("CARGO_MANIFEST_DIR");
    let backend_port = free_port();
    let waf_port = free_port();
    let metrics_port = free_port();

    let demo = Command::new(env!("CARGO_BIN_EXE_demo_server"))
        .arg(backend_port.to_string())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("start demo_server");
    let _demo = ChildGuard(demo);

    let waf = Command::new(env!("CARGO_BIN_EXE_krakenwaf"))
        .args([
            "--no-tls",
            "--allow-private-upstream",
            "--listen",
            &format!("127.0.0.1:{waf_port}"),
            "--metrics-port",
            &metrics_port.to_string(),
            "--upstream",
            &format!("http://127.0.0.1:{backend_port}"),
            "--rate-limit-per-minute",
            "100000",
        ])
        .current_dir(root)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("start KrakenWAF");
    let _waf = ChildGuard(waf);
    wait_for_http(waf_port);

    let output = Command::new(env!("CARGO_BIN_EXE_attack"))
        .args([
            "--target",
            &format!("http://127.0.0.1:{waf_port}"),
            "--concurrency",
            "50",
        ])
        .output()
        .expect("run attack sweep");

    assert!(
        output.status.success(),
        "attack sweep failed:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("ALL PAYLOADS BLOCKED"),
        "attack sweep did not report the expected protected result"
    );
}

#[test]
fn demo_attack_sweep_persists_masked_sensitive_values() {
    let project_root = env!("CARGO_MANIFEST_DIR");
    let runtime = tempfile::tempdir().expect("runtime tempdir");
    let filter_path = runtime.path().join("filter.yaml");
    let filter_yaml = std::fs::read_to_string(Path::new(project_root).join("conf/filter.yaml"))
        .expect("read shipped filter config")
        .lines()
        .filter(|line| !line.trim_start().starts_with("allowpaths:"))
        .collect::<Vec<_>>()
        .join("\n");
    std::fs::write(&filter_path, filter_yaml).expect("write runtime filter config");
    let backend_port = free_port();
    let waf_port = free_port();
    let metrics_port = free_port();

    let demo = Command::new(env!("CARGO_BIN_EXE_demo_server"))
        .arg(backend_port.to_string())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("start demo_server");
    let _demo = ChildGuard(demo);

    let waf = Command::new(env!("CARGO_BIN_EXE_krakenwaf"))
        .args([
            "--no-tls",
            "--allow-private-upstream",
            "--listen",
            &format!("127.0.0.1:{waf_port}"),
            "--metrics-port",
            &metrics_port.to_string(),
            "--upstream",
            &format!("http://127.0.0.1:{backend_port}"),
            "--rate-limit-per-minute",
            "100000",
            "--rules-dir",
            &format!("{project_root}/rules"),
            "--cmc-load",
            filter_path.to_str().expect("filter path utf8"),
        ])
        .current_dir(runtime.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("start KrakenWAF");
    let _waf = ChildGuard(waf);
    wait_for_http(waf_port);

    let output = Command::new(env!("CARGO_BIN_EXE_attack"))
        .args([
            "--target",
            &format!("http://127.0.0.1:{waf_port}"),
            "--concurrency",
            "50",
        ])
        .output()
        .expect("run attack sweep");

    assert!(
        output.status.success(),
        "attack sweep failed:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let (request_uri, request_uri_masked, request_payload, request_payload_masked) =
        wait_for_hpp_token_row(runtime.path());
    let raw = format!("{request_uri}\n{request_payload}");
    let masked = format!("{request_uri_masked}\n{request_payload_masked}");

    assert!(
        raw.contains("token=abc"),
        "raw admin evidence should preserve the attack token value: {raw}"
    );
    assert!(
        masked.contains("token=+++++") || masked.contains("TOKEN=+++++"),
        "masked UI evidence should hide the token value: {masked}"
    );
    assert!(
        !masked.contains("token=abc") && !masked.contains("TOKEN=def"),
        "masked evidence leaked a sensitive token value: {masked}"
    );
}
