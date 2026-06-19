//! Intentionally vulnerable demo backend — used to demonstrate `KrakenWAF`.
//!
//! Usage
//! -----
//!   cargo run --bin `demo_server`            # listens on 0.0.0.0:9077
//!   cargo run --bin `demo_server` -- 9999    # custom port
//!
//! Then start `KrakenWAF` in front of it:
//!   cargo run -- --no-tls --allow-private-upstream \
//!                --listen 0.0.0.0:8080 \
//!                --upstream <http://127.0.0.1:9077> \
//!                --cmc-load rules/cmc/config.yaml \
//!                --enable-libinjection-sqli --enable-libinjection-xss \
//!                --rate-limit-per-minute 100000
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

// ─── Silent_sql_errors static fingerprint leak routes ─────────────────────────
//
// Each route emits a verbose DBMS error string drawn from the OWASP CRS
// `sql-errors.data` list. Used by the `silent_sql_errors` integration tests to
// verify the scrubber/blocker pipeline; the wrapping HTML preserves a realistic
// "rendered error page" layout so the Content-Length update after a scrub can
// be observed end-to-end.
async fn leak_static_mysql_client() -> &'static str {
    "<html><body><p>MySqlClient. could not connect</p></body></html>"
}
async fn leak_static_sql_client_exception() -> &'static str {
    "<html><body>System.Data.SqlClient.SqlException raised at line 42</body></html>"
}
async fn leak_static_ole_db_sql_server() -> &'static str {
    "<html><body>Microsoft OLE DB Provider for SQL Server returned 0x80040E14</body></html>"
}
async fn leak_static_db2_cli_driver() -> &'static str {
    "<html><body>[IBM][CLI Driver][DB2/6000] SQL0204N undefined name</body></html>"
}
async fn leak_static_psql_exception() -> &'static str {
    "<html><body>org.postgresql.util.PSQLException: ERROR relation does not exist</body></html>"
}
async fn leak_static_sybase_msg() -> &'static str {
    "<html><body>Sybase message: malformed identifier in line 1</body></html>"
}
async fn leak_static_npgsql() -> &'static str {
    "<html><body>Npgsql.PostgresException: connection terminated</body></html>"
}
async fn leak_static_sqlite_exception() -> &'static str {
    "<html><body>SQLiteException at offset 17 unrecognized token</body></html>"
}
async fn leak_static_zend_mysqli() -> &'static str {
    "<html><body>Zend_Db_Adapter_Mysqli_Exception: Access denied for user</body></html>"
}
async fn leak_static_oracle_exception() -> &'static str {
    "<html><body>OracleException ORA-00942: table or view does not exist</body></html>"
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

// ─── Detect_bad_artifacts demo routes ────────────────────────────────────────
//
// Each route serves a realistic "leaked" response at a URI that matches a
// known-sensitive artifact pattern.  The WAF must block the REQUEST at the URI
// phase before the handler is ever invoked.  At `untrust >= 60` all of these
// must return 403 from the WAF; at `untrust < 60` they return 200.

async fn handle_env_leak() -> &'static str {
    "DB_PASSWORD=secret123\nAPI_KEY=abc"
}

async fn handle_git_config_leak() -> &'static str {
    "[core]\n  repositoryformatversion = 0"
}

async fn handle_wp_config_leak() -> &'static str {
    "<?php define('DB_PASSWORD','secret');"
}

async fn handle_proc_cpuinfo_leak() -> &'static str {
    "processor : 0\nmodel name : Intel(R) Core(TM) i7"
}

async fn handle_aws_credentials_leak() -> &'static str {
    "[default]\naws_access_key_id = AKIAIOSFODNN7"
}

async fn handle_config_json_leak() -> &'static str {
    r#"{"db_password":"secret","api_key":"abc"}"#
}

async fn handle_ssh_id_rsa_leak() -> &'static str {
    "-----BEGIN RSA PRIVATE KEY-----"
}

async fn handle_debug_log_leak() -> &'static str {
    "[ERROR] Connection failed"
}

async fn handle_composer_json_leak() -> &'static str {
    r#"{"name":"app/app","require":{}}"#
}

async fn handle_htpasswd_leak() -> &'static str {
    "admin:$apr1$xyz$hash"
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
        // Static DBMS error fingerprint leak routes — used by
        // Silent_sql_errors integration tests + attack sweep.
        .route("/leak/static/mysql-client", get(leak_static_mysql_client))
        .route("/leak/static/sql-client-exception", get(leak_static_sql_client_exception))
        .route("/leak/static/ole-db-sql-server", get(leak_static_ole_db_sql_server))
        .route("/leak/static/db2-cli-driver", get(leak_static_db2_cli_driver))
        .route("/leak/static/psql-exception", get(leak_static_psql_exception))
        .route("/leak/static/sybase-msg", get(leak_static_sybase_msg))
        .route("/leak/static/npgsql", get(leak_static_npgsql))
        .route("/leak/static/sqlite-exception", get(leak_static_sqlite_exception))
        .route("/leak/static/zend-mysqli", get(leak_static_zend_mysqli))
        .route("/leak/static/oracle-exception", get(leak_static_oracle_exception))
        // Java deserialization target — accepts POST with any body so the
        // attack tool can test Java deserialization payloads against the WAF.
        .route("/java-deser", post(java_deser_endpoint))
        // Detect_bad_artifacts demo routes — these serve "leaked" content at
        // sensitive URIs; the WAF must block the request before reaching here.
        .route("/.env", get(handle_env_leak))
        .route("/.git/config", get(handle_git_config_leak))
        .route("/wp-config.php", get(handle_wp_config_leak))
        .route("/proc/cpuinfo", get(handle_proc_cpuinfo_leak))
        .route("/.aws/credentials", get(handle_aws_credentials_leak))
        .route("/config.json", get(handle_config_json_leak))
        .route("/.ssh/id_rsa", get(handle_ssh_id_rsa_leak))
        .route("/debug.log", get(handle_debug_log_leak))
        .route("/composer.json", get(handle_composer_json_leak))
        .route("/.htpasswd", get(handle_htpasswd_leak))
        // Wildcard route for the backup-file sweep: returns 200 so the attack
        // tool can distinguish a WAF bypass from a WAF block (403).
        // Axum 0.8+ requires the `{*name}` syntax for wildcard capture.
        .route("/{*path}", get(backup_file));

    let addr: SocketAddr = format!("0.0.0.0:{port}").parse().expect("valid socket addr");
    println!("Demo backend listening on http://{addr}");
    println!("Routes: GET /test_get?payload_test=...  |  POST /test_post (form)");
    println!("Start KrakenWAF: cargo run -- --no-tls --allow-private-upstream \\");
    println!("                   --listen 0.0.0.0:8080 \\");
    println!("                   --upstream http://127.0.0.1:{port} \\");
    println!("                   --cmc-load rules/cmc/config.yaml \\");
    println!("                   --enable-libinjection-sqli --enable-libinjection-xss \\");
    println!("                   --rate-limit-per-minute 100000");

    let listener = tokio::net::TcpListener::bind(addr).await.expect("bind");
    axum::serve(listener, app).await.expect("serve");
}
