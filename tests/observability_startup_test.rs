//! Startup policy tests for externally-bound observability.

#![allow(clippy::unwrap_used)]

use std::{
    fs,
    io::Read,
    net::TcpListener,
    path::Path,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

fn pick_free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("bind ephemeral port")
        .local_addr()
        .expect("local address")
        .port()
}

fn write_minimal_rules(root: &Path) {
    fs::create_dir_all(root.join("addr")).expect("create addr");
    fs::create_dir_all(root.join("regex")).expect("create regex");
    fs::create_dir_all(root.join("Vectorscan")).expect("create vectorscan");
    fs::write(root.join("rules.json"), "{}\n").expect("write rules");
    fs::write(root.join("addr/allowlist.txt"), "").expect("write allowlist");
    fs::write(root.join("addr/blocklist.txt"), "").expect("write blocklist");
    for path in [
        "regex/path_regex.json",
        "regex/body_regex.json",
        "regex/header_regex.json",
        "Vectorscan/strings2block.json",
    ] {
        fs::write(root.join(path), "{\"rules\":[]}\n").expect("write empty rules");
    }
}

fn command(workdir: &Path, rules: &Path, token: Option<&str>) -> Command {
    let listen_port = pick_free_port();
    let metrics_port = pick_free_port();
    let mut command = Command::new(env!("CARGO_BIN_EXE_krakenwaf"));
    command
        .args([
            "--no-tls",
            "--allow-private-upstream",
            "--listen",
            &format!("0.0.0.0:{listen_port}"),
            "--metrics-port",
            &metrics_port.to_string(),
            "--upstream",
            "http://127.0.0.1:9",
            "--rules-dir",
            rules.to_str().expect("rules path"),
        ])
        .current_dir(workdir)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .env_remove("BEARER_PASSWORD")
        .env_remove("BEARER_PASSWORD_FILE");
    if let Some(token) = token {
        command.env("BEARER_PASSWORD", token);
    }
    command
}

fn wait_for_exit(child: &mut Child, timeout: Duration) -> Option<std::process::ExitStatus> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if let Some(status) = child.try_wait().expect("poll child") {
            return Some(status);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    None
}

#[test]
fn public_metrics_without_protection_fails_startup() {
    let temp = tempfile::tempdir().expect("tempdir");
    let rules = temp.path().join("rules");
    write_minimal_rules(&rules);

    let mut child = command(temp.path(), &rules, None)
        .spawn()
        .expect("spawn KrakenWaf");
    let status = wait_for_exit(&mut child, Duration::from_secs(5));
    if status.is_none() {
        child.kill().ok();
        child.wait().ok();
        panic!("unprotected public bind did not fail startup");
    }
    assert!(
        !status.expect("status").success(),
        "unprotected public bind must fail"
    );
    let mut stderr = String::new();
    child
        .stderr
        .take()
        .expect("stderr pipe")
        .read_to_string(&mut stderr)
        .expect("read stderr");
    assert!(
        stderr.contains("refusing to expose observability"),
        "unexpected startup error: {stderr}"
    );
}

#[test]
fn public_metrics_with_bearer_passes_startup_policy() {
    let temp = tempfile::tempdir().expect("tempdir");
    let rules = temp.path().join("rules");
    write_minimal_rules(&rules);

    let mut child = command(
        temp.path(),
        &rules,
        Some("test-only-observability-token-7d8f31"),
    )
    .spawn()
    .expect("spawn KrakenWaf");

    let early_exit = wait_for_exit(&mut child, Duration::from_secs(2));
    child.kill().ok();
    child.wait().ok();
    assert!(
        early_exit.is_none(),
        "bearer-protected public bind exited during startup: {early_exit:?}"
    );
}
