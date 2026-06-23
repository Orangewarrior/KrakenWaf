use axum::{
    body::Bytes,
    http::{
        header::{CONTENT_LENGTH, TRANSFER_ENCODING},
        HeaderMap,
    },
    response::IntoResponse,
    routing::post,
    Router,
};
use reqwest::StatusCode;
use std::{
    net::SocketAddr,
    process::{Child, Command, Stdio},
    sync::OnceLock,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

static BACKEND_PORT: OnceLock<u16> = OnceLock::new();
static BACKEND_ONCE: OnceLock<()> = OnceLock::new();

fn pick_free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind :0");
    listener.local_addr().expect("local_addr").port()
}

fn backend_port() -> u16 {
    *BACKEND_PORT.get_or_init(pick_free_port)
}

fn backend_addr() -> String {
    format!("127.0.0.1:{}", backend_port())
}

fn waf_base(port: u16) -> String {
    format!("http://127.0.0.1:{port}")
}

async fn echo(headers: HeaderMap, body: Bytes) -> impl IntoResponse {
    let content_length = headers
        .get(CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("none");
    let transfer_encoding = headers
        .get(TRANSFER_ENCODING)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("none");
    let body_text = String::from_utf8_lossy(&body);
    (
        [("content-type", "text/plain; charset=utf-8")],
        format!(
            "len={}\ncontent-length={content_length}\ntransfer-encoding={transfer_encoding}\nbody={body_text}",
            body.len()
        ),
    )
}

fn ensure_backend() {
    BACKEND_ONCE.get_or_init(|| {
        let addr: SocketAddr = backend_addr().parse().expect("backend addr");
        std::thread::spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("runtime")
                .block_on(async move {
                    let app = Router::new()
                        .route("/echo", post(echo))
                        .route("/allow/echo", post(echo));
                    let listener = tokio::net::TcpListener::bind(addr).await.expect("bind");
                    axum::serve(listener, app).await.expect("serve");
                });
        });
        std::thread::sleep(Duration::from_millis(300));
    });
}

struct WafGuard {
    child: Child,
    _tmpdir: tempfile::TempDir,
}

impl Drop for WafGuard {
    fn drop(&mut self) {
        self.child.kill().ok();
        self.child.wait().ok();
    }
}

fn spawn_waf(waf_port: u16, extra_args: &[&str], allowpaths_yaml: &str) -> WafGuard {
    let project_root = env!("CARGO_MANIFEST_DIR");
    let rules_dir = format!("{project_root}/rules");
    let listen = format!("127.0.0.1:{waf_port}");
    let metrics_port = pick_free_port().to_string();
    let upstream = format!("http://{}", backend_addr());
    let tmpdir = tempfile::tempdir().expect("tmpdir");
    std::fs::write(tmpdir.path().join("allowpaths.yaml"), allowpaths_yaml)
        .expect("write allowpaths");

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
            "--allow-paths",
            "allowpaths.yaml",
        ])
        .args(extra_args)
        .current_dir(tmpdir.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn krakenwaf");

    WafGuard {
        child,
        _tmpdir: tmpdir,
    }
}

fn http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(25))
        .build()
        .expect("client")
}

async fn wait_for_waf(client: &reqwest::Client, waf_port: u16) {
    let health_url = format!("{}/__krakenwaf/health", waf_base(waf_port));
    for _ in 0..150 {
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

fn assert_echoed_body(echo: &str, expected: &str) {
    assert!(
        echo.contains(&format!("len={}", expected.len())),
        "unexpected echo response: {echo}"
    );
    assert!(
        echo.contains(&format!("content-length={}", expected.len())),
        "upstream Content-Length must match body length: {echo}"
    );
    assert!(
        echo.contains("transfer-encoding=none"),
        "proxy should not forward hop-by-hop transfer encoding: {echo}"
    );
    assert!(
        echo.ends_with(&format!("body={expected}")),
        "upstream body changed or was truncated: {echo}"
    );
}

#[derive(Debug)]
struct RawResponse {
    status: u16,
    body: Vec<u8>,
}

async fn raw_chunked_post(waf_port: u16, path: &str, chunks: &[&[u8]]) -> RawResponse {
    let mut stream = TcpStream::connect(("127.0.0.1", waf_port))
        .await
        .expect("connect WAF");
    let mut request = format!(
        "POST {path} HTTP/1.1\r\nHost: 127.0.0.1:{waf_port}\r\nTransfer-Encoding: chunked\r\nContent-Type: application/octet-stream\r\nConnection: close\r\n\r\n"
    )
    .into_bytes();
    for chunk in chunks {
        request.extend_from_slice(format!("{:x}\r\n", chunk.len()).as_bytes());
        request.extend_from_slice(chunk);
        request.extend_from_slice(b"\r\n");
    }
    request.extend_from_slice(b"0\r\n\r\n");

    stream.write_all(&request).await.expect("write request");

    let mut raw = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), stream.read_to_end(&mut raw))
        .await
        .expect("read response timeout")
        .expect("read response");
    parse_raw_response(&raw)
}

fn parse_raw_response(raw: &[u8]) -> RawResponse {
    let header_end = raw
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .unwrap_or_else(|| {
            panic!(
                "response header terminator; raw_len={} raw={:?}",
                raw.len(),
                String::from_utf8_lossy(raw)
            )
        });
    let header_text = String::from_utf8_lossy(&raw[..header_end]);
    let mut lines = header_text.split("\r\n");
    let status = lines
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .expect("status code")
        .parse()
        .expect("numeric status");

    let mut is_chunked = false;
    let mut content_length = None;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.eq_ignore_ascii_case("transfer-encoding")
            && value.to_ascii_lowercase().contains("chunked")
        {
            is_chunked = true;
        }
        if name.eq_ignore_ascii_case("content-length") {
            content_length = value.trim().parse::<usize>().ok();
        }
    }

    let wire_body = &raw[header_end + 4..];
    let body = if is_chunked {
        decode_chunked(wire_body)
    } else if let Some(length) = content_length {
        wire_body[..length.min(wire_body.len())].to_vec()
    } else {
        wire_body.to_vec()
    };
    RawResponse { status, body }
}

fn decode_chunked(wire_body: &[u8]) -> Vec<u8> {
    let mut pos = 0usize;
    let mut decoded = Vec::new();
    loop {
        let line_end = wire_body[pos..]
            .windows(2)
            .position(|window| window == b"\r\n")
            .expect("chunk size line")
            + pos;
        let size_line = std::str::from_utf8(&wire_body[pos..line_end]).expect("chunk size utf8");
        let size_hex = size_line.split(';').next().unwrap_or(size_line).trim();
        let size = usize::from_str_radix(size_hex, 16).expect("chunk size hex");
        pos = line_end + 2;
        if size == 0 {
            break;
        }
        decoded.extend_from_slice(&wire_body[pos..pos + size]);
        pos += size + 2;
    }
    decoded
}

#[tokio::test]
async fn fixed_length_allowed_body_reaches_upstream_unchanged() {
    ensure_backend();
    let port = pick_free_port();
    let _waf = spawn_waf(port, &[], "allow: []\n");
    let client = http_client();
    wait_for_waf(&client, port).await;

    let body = "field=safe&tail=fixed-length";
    let response = client
        .post(format!("{}/echo", waf_base(port)))
        .header("content-type", "application/x-www-form-urlencoded")
        .body(body.to_string())
        .send()
        .await
        .expect("fixed body request");

    assert_eq!(response.status(), StatusCode::OK);
    let echo = response.text().await.expect("echo body");
    assert_echoed_body(&echo, body);
}

#[tokio::test]
async fn chunked_allowed_body_reaches_upstream_unchanged() {
    ensure_backend();
    let port = pick_free_port();
    let _waf = spawn_waf(port, &[], "allow: []\n");
    let client = http_client();
    wait_for_waf(&client, port).await;

    let expected = "field=safe&tail=chunked";
    let response = raw_chunked_post(
        port,
        "/echo",
        &[
            b"field=".as_slice(),
            b"safe".as_slice(),
            b"&tail=chunked".as_slice(),
        ],
    )
    .await;

    assert_eq!(response.status, 200);
    let echo = String::from_utf8(response.body).expect("utf8 echo");
    assert_echoed_body(&echo, expected);
}

#[tokio::test]
async fn allowlisted_body_bypasses_signatures_and_keeps_raw_body() {
    ensure_backend();
    let port = pick_free_port();
    let allowpaths = r#"allow:
  - order: 1
    title: "Allow body echo"
    description: "signature bypass for body transparency test"
    log: false
    paths:
      - /allow
"#;
    let _waf = spawn_waf(port, &[], allowpaths);
    let client = http_client();
    wait_for_waf(&client, port).await;

    let body = "field=<script>alert(1)</script>&tail=allowlisted";
    let response = client
        .post(format!("{}/allow/echo", waf_base(port)))
        .header("content-type", "application/x-www-form-urlencoded")
        .header("content-encoding", "gzip")
        .body(body.to_string())
        .send()
        .await
        .expect("allowlisted body request");

    assert_eq!(response.status(), StatusCode::OK);
    let echo = response.text().await.expect("echo body");
    assert_echoed_body(&echo, body);
}

#[tokio::test]
async fn block_mode_rejects_detected_body() {
    ensure_backend();
    let port = pick_free_port();
    let _waf = spawn_waf(port, &[], "allow: []\n");
    let client = http_client();
    wait_for_waf(&client, port).await;

    let response = client
        .post(format!("{}/echo", waf_base(port)))
        .header("content-type", "application/x-www-form-urlencoded")
        .body("field=<script>alert(1)</script>&tail=must-not-arrive")
        .send()
        .await
        .expect("blocked body request");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn detect_only_forwards_complete_detected_body() {
    ensure_backend();
    let port = pick_free_port();
    let _waf = spawn_waf(port, &["--mode", "detect-only"], "allow: []\n");
    let client = http_client();
    wait_for_waf(&client, port).await;

    let body = "field=<script>alert(1)</script>&tail=detect-only-complete";
    let response = client
        .post(format!("{}/echo", waf_base(port)))
        .header("content-type", "application/x-www-form-urlencoded")
        .body(body.to_string())
        .send()
        .await
        .expect("detect-only request");

    assert_eq!(response.status(), StatusCode::OK);
    let echo = response.text().await.expect("echo body");
    assert_echoed_body(&echo, body);
}
