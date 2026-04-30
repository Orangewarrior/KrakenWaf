//! Intentionally vulnerable demo backend — used to demonstrate KrakenWAF.
//!
//! Usage
//! -----
//!   cargo run --bin demo_server            # listens on 0.0.0.0:9077
//!   cargo run --bin demo_server -- 9999    # custom port
//!
//! Then start KrakenWAF in front of it:
//!   cargo run -- --no-tls --allow-private-upstream \
//!                --listen 0.0.0.0:8080    \
//!                --upstream http://127.0.0.1:9077
//!
//! Finally run the attack tool against the WAF:
//!   cargo run --bin attack -- --target http://127.0.0.1:8080

use axum::{
    extract::{Form, Query},
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
    Html(r#"<!DOCTYPE html>
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
</body></html>"#)
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

#[tokio::main]
async fn main() {
    let port: u16 = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(9077);

    let app = Router::new()
        .route("/", get(index))
        .route("/test_get", get(test_get))
        .route("/test_post", post(test_post));

    let addr: SocketAddr = format!("0.0.0.0:{port}").parse().unwrap();
    println!("Demo backend listening on http://{addr}");
    println!("Routes: GET /test_get?payload_test=...  |  POST /test_post (form)");
    println!("Start KrakenWAF: cargo run -- --no-tls --allow-private-upstream \\");
    println!("                   --listen 0.0.0.0:8080 --upstream http://127.0.0.1:{port}");

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
