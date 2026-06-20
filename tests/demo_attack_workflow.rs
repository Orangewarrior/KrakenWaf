//! End-to-end smoke test for the shipped `demo_server` and `attack` binaries.

use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
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

#[test]
fn demo_server_is_protected_against_the_attack_sweep() {
    let root = env!("CARGO_MANIFEST_DIR");
    let backend_port = free_port();
    let waf_port = free_port();

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
