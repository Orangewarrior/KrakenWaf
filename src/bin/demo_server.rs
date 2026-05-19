//! Intentionally vulnerable demo backend — used to demonstrate `KrakenWAF`.
//!
//! Usage
//! -----
//!   cargo run --bin `demo_server`            # listens on 0.0.0.0:9077
//!   cargo run --bin `demo_server` -- 9999    # custom port
//!
//! Then start `KrakenWAF` in front of it:
//!   cargo run -- --no-tls --allow-private-upstream \
//!                --listen 0.0.0.0:8080    \
//!                --upstream <http://127.0.0.1:9077>
//!
//! Finally run the attack tool against the WAF:
//!   cargo run --bin attack -- --target <http://127.0.0.1:8080>

use axum::{
    extract::{Form, Path, Query},
    response::Html,
    routing::{get, post},
    Router,
};
use serde::Deserialize;
use std::net::SocketAddr;

#[derive(Deserialize)]
struct Payload {
    #[serde(default)]
    payload_test: String,
}

async fn index() -> Html<&'static str> {
    Html(
        r#"<!DOCTYPE html>
<html><head><title>KrakenWAF Demo Backend</title></head><body>
<h1>KrakenWAF Demo Backend</h1>
<p>This server is intentionally vulnerable. Place KrakenWAF in front of it.</p>
<h2>GET form (XSS / SQLi via query param)</h2>
<form method="GET" action="/test_get">
  <input name="payload_test" placeholder="enter payload" size="60"/>
  <input type="submit" value="Send GET"/>
</form>
<h2>POST form (XSS / SQLi via form body)</h2>
<form method="POST" action="/test_post">
  <input name="payload_test" placeholder="enter payload" size="60"/>
  <input type="submit" value="Send POST"/>
</form>
<h2>Score engine probes</h2>
<p>GET chain: kwaf-score-get-a kwaf-score-get-b kwaf-score-get-c</p>
<p>POST chain: kwaf-score-post-a kwaf-score-post-b kwaf-score-post-c kwaf-score-post-d</p>
<p>Response chain: kwaf-score-response-a kwaf-score-response-b kwaf-score-response-c</p>
</body></html>"#,
    )
}

async fn test_get(Query(p): Query<Payload>) -> Html<String> {
    Html(format!(
        "<!DOCTYPE html><html><body>\
         <h1>GET result</h1>\
         <p>payload_test = <b>{}</b></p>\
         </body></html>",
        p.payload_test
    ))
}

async fn test_post(Form(p): Form<Payload>) -> Html<String> {
    Html(format!(
        "<!DOCTYPE html><html><body>\
         <h1>POST result</h1>\
         <p>payload_test = <b>{}</b></p>\
         </body></html>",
        p.payload_test
    ))
}

/// Endpoint that accepts any POST body — used by the Java deserialization
/// attack sweep as a target that would normally deserialize data. Returns 200
/// regardless of payload; the WAF must intercept the malicious request first.
async fn java_deser_endpoint() -> Html<&'static str> {
    Html("<html><body><h1>java-deser: received</h1></body></html>")
}

/// Simulates a server leaking /etc/passwd content in the response body.
/// Used by the attack sweep to verify that `Anti_passwd_leak` blocks the
/// response before it reaches the attacker.
async fn leak_passwd() -> &'static str {
    "root:x:0:0:root:/root:/bin/bash\n\
     daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n\
     bin:x:2:2:bin:/bin:/usr/sbin/nologin\n\
     nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n"
}

/// Simulates a server leaking /etc/shadow content in the response body.
async fn leak_shadow() -> &'static str {
    "root:$6$salt$longhash:19000:0:99999:7:::\n\
     daemon:*:18858:0:99999:7:::\n\
     nobody:*:18858:0:99999:7:::\n"
}

/// Simulates a server leaking database error messages — used by
/// `Detect_db_errors` sweep to verify that error-based injection responses
/// are intercepted before they reach the attacker.
async fn leak_db_error_mysql() -> &'static str {
    "You have an error in your SQL syntax; check the manual that corresponds \
     to your MySQL server version for the right syntax to use near '\"' at line 1"
}

async fn leak_db_error_pgsql() -> &'static str {
    "PostgreSQL query failed: ERROR: syntax error at or near \"'\" at character 10"
}

async fn leak_db_error_oracle() -> &'static str {
    "ORA-00933: SQL command not properly ended"
}

async fn leak_db_error_mssql() -> &'static str {
    "Unclosed quotation mark after the character string 'admin'."
}

async fn leak_db_error_mongo() -> &'static str {
    r#"{"error":"MongoServerError","code":2,"message":"E11000 duplicate key error collection"}"#
}

/// Catch-all GET handler used by the backup-file sweep in the attack tool.
/// Returns 200 so that the attack tool can distinguish a WAF bypass (200) from
/// a WAF block (403).  In a real deployment these paths would never exist on a
/// hardened server; here we deliberately expose them so the demo is meaningful.
async fn backup_file(Path(path): Path<String>) -> Html<String> {
    Html(format!(
        "<!DOCTYPE html><html><body>\
         <h1>EXPOSED: /{path}</h1>\
         <p>This file should have been blocked by the WAF.</p>\
         </body></html>"
    ))
}

#[tokio::main]
async fn main() {
    let port: u16 = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(9077);

    let app = Router::new()
        .route("/", get(index))
        .route("/test_get", get(test_get))
        .route("/test_post", post(test_post))
        // passwd/shadow leak routes — used by Anti_passwd_leak sweep.
        .route("/leak/passwd", get(leak_passwd))
        .route("/leak/shadow", get(leak_shadow))
        // DB error leak routes — used by Detect_db_errors sweep.
        .route("/leak/db-error/mysql", get(leak_db_error_mysql))
        .route("/leak/db-error/pgsql", get(leak_db_error_pgsql))
        .route("/leak/db-error/oracle", get(leak_db_error_oracle))
        .route("/leak/db-error/mssql", get(leak_db_error_mssql))
        .route("/leak/db-error/mongo", get(leak_db_error_mongo))
        // Java deserialization target — accepts POST with any body so the
        // attack tool can test Java deserialization payloads against the WAF.
        .route("/java-deser", post(java_deser_endpoint))
        // Wildcard route for the backup-file sweep: returns 200 so the attack
        // tool can distinguish a WAF bypass from a WAF block (403).
        // Axum 0.8+ requires the `{*name}` syntax for wildcard capture.
        .route("/{*path}", get(backup_file));

    let addr: SocketAddr = format!("0.0.0.0:{port}").parse().expect("valid socket addr");
    println!("Demo backend listening on http://{addr}");
    println!("Routes: GET /test_get?payload_test=...  |  POST /test_post (form)");
    println!("Start KrakenWAF: cargo run -- --no-tls --allow-private-upstream \\");
    println!("                   --listen 0.0.0.0:8080 --upstream http://127.0.0.1:{port}");

    let listener = tokio::net::TcpListener::bind(addr).await.expect("bind");
    axum::serve(listener, app).await.expect("serve");
}
