//! Rule-management control plane — a dedicated, isolated HTTP listener that lets
//! an operator inspect and **modify detection rules in real time** without
//! restarting the WAF.
//!
//! Topology mirrors the observability (`/metrics`) listener: a separate port
//! (default 4342, `rule_management_port` in `conf/proxy.yaml`) bound to the same
//! IP as `--listen`, reusing the listener's TLS certificates (plain HTTP only
//! under `--no-tls`). It is **not** a reverse proxy — it serves only the control
//! endpoints and answers everything else with 404.
//!
//! # Access control (two independent gates)
//!
//! 1. **IP allowlist → 403.** The effective client IP (honouring trusted-proxy
//!    CIDRs / `X-Forwarded-For`) must be contained by an entry in
//!    `rules/addr/allowlist/allow_rule_management.txt` (CIDR-aware). Checked
//!    first so an off-allowlist caller never reaches authentication.
//! 2. **Rorschach bearer token → 401.** A rotating, body-bound bearer
//!    credential (see [`crate::rorschach`]) verified in constant time, with
//!    anti-replay. A missing or invalid token is 401. The token is never logged
//!    — only [`crate::rorschach::REDACTED_TOKEN`].
//!
//! # Endpoints
//!
//! CMC module toggles (see [`cmc`]):
//! * `GET  /rule/control/cmc/list`   — JSON overview of every CMC module's state.
//! * `POST /rule/control/cmc/update` — partial patch; only the modules present
//!   in the body change.
//!
//! Regex / keyword / scanner rule editing (see [`regex_rules`]):
//! * `POST /rule/control/regex/view`          — return a managed rule file's content.
//! * `POST /rule/control/regex/update/<name>` — replace a managed rule file and
//!   hot-reload the live engine.
//!
//! All user input is strictly validated: every JSON document is typed with
//! `deny_unknown_fields`, and any parse/validation failure returns a generic
//! "JSON not in the expected format" 400 that leaks no internal detail.

mod cmc;
mod factory;
mod regex_rules;

use std::{net::SocketAddr, path::Path, sync::Arc};

use anyhow::{bail, Context, Result};
use bytes::Bytes;
use chrono::Utc;
use http::{Request, Response, StatusCode};
use http_body_util::{BodyExt, Limited};
use hyper::{body::Incoming, service::service_fn};
use hyper_util::rt::TokioIo;
use ipnet::IpNet;
use serde::Serialize;
use tokio::{net::TcpListener, task, time::timeout};
use tracing::{error, info, warn};

use crate::{
    app::AppState,
    proxy::{effective_client_ip, full_body, plain_response, WafResponse},
    rorschach::{RorschachCredential, RorschachValidator, REDACTED_TOKEN},
    server::{connection_builder, cope_with_accept_error, wait_for_shutdown_signal},
    tls::TlsConfigStore,
};
use std::time::Duration;

/// Hard cap on a rule-management request body. The control documents are tiny
/// JSON; anything larger is a misuse and is rejected with 400.
const MAX_RULE_MGMT_BODY: usize = 64 * 1024;

/// Resolved access-control state for the rule-management control plane. Present
/// in [`AppState`] only when the Rorschach secrets were provisioned.
#[derive(Debug)]
pub struct RuleManagementGate {
    /// Verifies Rorschach bearer tokens (constant-time, with anti-replay).
    pub validator: RorschachValidator,
    /// CIDR-aware IP allowlist; a caller outside every entry receives 403.
    pub allowlist: Vec<IpNet>,
}

/// Default allowlist path, relative to the rules directory.
#[must_use]
pub fn default_allowlist_path(rules_dir: &Path) -> std::path::PathBuf {
    rules_dir.join("addr/allowlist/allow_rule_management.txt")
}

/// Load and validate the rule-management IP allowlist.
///
/// Accepts one bare IP or CIDR per line; blank lines and `#` comments are
/// ignored. Reuses [`crate::proxy::parse_trusted_proxy_cidr`] so the rule-
/// management allowlist and the trusted-proxy parser accept exactly the same
/// notation.
///
/// # Errors
/// Returns an error when the file is unreadable, contains a malformed entry, or
/// yields no valid entries (an empty allowlist is fail-closed — the control
/// plane must not start).
pub fn load_allowlist(path: &Path) -> Result<Vec<IpNet>> {
    let raw = std::fs::read_to_string(path).with_context(|| {
        format!(
            "failed to read rule-management allowlist '{}'",
            path.display()
        )
    })?;
    let mut nets = Vec::new();
    for (idx, line) in raw.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let net = crate::proxy::parse_trusted_proxy_cidr(trimmed).with_context(|| {
            format!(
                "rule-management allowlist '{}' line {}: invalid entry '{trimmed}'",
                path.display(),
                idx + 1
            )
        })?;
        nets.push(net);
    }
    if nets.is_empty() {
        bail!(
            "rule-management allowlist '{}' contains no valid IP/CIDR entries; the control plane \
             refuses to start with an empty allowlist (fail-closed)",
            path.display()
        );
    }
    Ok(nets)
}

/// True when `ip` (a string) parses and is contained by any allowlist network.
fn ip_allowed(allowlist: &[IpNet], ip: &str) -> bool {
    match ip.parse::<std::net::IpAddr>() {
        Ok(addr) => allowlist.iter().any(|net| net.contains(&addr)),
        Err(_) => false,
    }
}

// ── Response helpers (shared by the cmc and regex_rules submodules) ───────────

fn json_response<T: Serialize>(state: &Arc<AppState>, status: StatusCode, body: &T) -> WafResponse {
    let bytes = match serde_json::to_vec(body) {
        Ok(bytes) => bytes,
        Err(e) => {
            error!(target: "krakenwaf", error = %e, "failed to serialize control-plane JSON response body");
            Vec::new()
        }
    };
    let mut resp = Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(full_body(Bytes::from(bytes)))
        .unwrap_or_else(|_| plain_response(status, ""));
    state
        .response_header_policy
        .apply(resp.headers_mut(), false);
    resp
}

/// A generic 400 that never leaks parser internals.
fn bad_request_json(state: &Arc<AppState>) -> WafResponse {
    #[derive(Serialize)]
    struct Err {
        status: &'static str,
        error: &'static str,
        message: &'static str,
    }
    json_response(
        state,
        StatusCode::BAD_REQUEST,
        &Err {
            status: "error",
            error: "invalid_request",
            message: "JSON is not in the expected format",
        },
    )
}

fn unauthorized(state: &Arc<AppState>) -> WafResponse {
    let mut resp = plain_response(StatusCode::UNAUTHORIZED, "Unauthorized");
    resp.headers_mut().insert(
        http::header::WWW_AUTHENTICATE,
        http::HeaderValue::from_static("Bearer realm=\"krakenwaf-rule-management\""),
    );
    state
        .response_header_policy
        .apply(resp.headers_mut(), false);
    resp
}

fn forbidden(state: &Arc<AppState>) -> WafResponse {
    let mut resp = plain_response(StatusCode::FORBIDDEN, "Access denied");
    state
        .response_header_policy
        .apply(resp.headers_mut(), false);
    resp
}

fn not_found(state: &Arc<AppState>) -> WafResponse {
    let mut resp = plain_response(StatusCode::NOT_FOUND, "Not found");
    state
        .response_header_policy
        .apply(resp.headers_mut(), false);
    resp
}

/// Extract the bearer credential from `Authorization: Bearer <token>`.
fn extract_bearer(headers: &http::HeaderMap) -> Option<&str> {
    let value = headers.get(http::header::AUTHORIZATION)?.to_str().ok()?;
    let (scheme, token) = value.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("bearer") {
        return None;
    }
    let token = token.trim();
    (!token.is_empty()).then_some(token)
}

// ── Request handling ──────────────────────────────────────────────────────────

#[allow(clippy::too_many_lines)]
async fn handle_rule_management(
    req: Request<Incoming>,
    state: Arc<AppState>,
    peer_ip: String,
) -> WafResponse {
    let Some(gate) = state.rule_management.as_ref() else {
        // The listener is only ever started when the gate exists; treat a
        // missing gate defensively as "no such service".
        return not_found(&state);
    };

    let bearer_raw = extract_bearer(req.headers()).map(str::to_string);
    let effective_ip = effective_client_ip(&peer_ip, req.headers(), &state);
    let (parts, body) = req.into_parts();
    let method = parts.method;
    let path = parts.uri.path().to_string();

    // ── Gate 1: IP allowlist (403) ────────────────────────────────────────────
    if !ip_allowed(&gate.allowlist, &effective_ip) {
        warn!(
            target: "krakenwaf",
            ip = %effective_ip,
            %method,
            %path,
            "rule-management: client IP not in allowlist; rejected with 403"
        );
        return forbidden(&state);
    }

    let Some(cred) = bearer_raw.as_deref().and_then(RorschachCredential::parse) else {
        warn!(
            target: "krakenwaf",
            ip = %effective_ip,
            token = REDACTED_TOKEN,
            present = bearer_raw.is_some(),
            "rule-management: missing or malformed bearer token; rejected with 401"
        );
        return unauthorized(&state);
    };

    // Read the (bounded) body after structural token validation: the Rorschach
    // MAC binds a hash of the body, so the exact bytes are still required for
    // authentication, but unauthenticated callers cannot force body buffering.
    let Ok(collected) = Limited::new(body, MAX_RULE_MGMT_BODY).collect().await else {
        warn!(
            target: "krakenwaf",
            ip = %effective_ip,
            "rule-management: request body exceeded limit or failed to read; rejected"
        );
        return bad_request_json(&state);
    };
    let body_bytes = collected.to_bytes();

    // ── Gate 2: Rorschach bearer token (401) ──────────────────────────────────
    let now = Utc::now().timestamp();
    if let Err(err) = gate
        .validator
        .verify(&cred, method.as_str(), &path, &body_bytes, now)
        .await
    {
        warn!(
            target: "krakenwaf",
            ip = %effective_ip,
            client_id = %cred.client_id,
            token = REDACTED_TOKEN,
            reason = err.reason(),
            "rule-management: bearer token rejected; 401"
        );
        return unauthorized(&state);
    }

    info!(
        target: "krakenwaf",
        ip = %effective_ip,
        client_id = %cred.client_id,
        token = REDACTED_TOKEN,
        %method,
        %path,
        "rule-management: request authorized"
    );

    // ── Routing ───────────────────────────────────────────────────────────────
    match (method.as_str(), path.as_str()) {
        ("GET", "/rule/control/cmc/list") => cmc::handle_list(&state),
        ("POST", "/rule/control/cmc/update") => cmc::handle_update(&state, &body_bytes),
        ("POST", "/rule/control/regex/view") => regex_rules::handle_view(&state, &body_bytes),
        ("POST", update_path) if update_path.starts_with(regex_rules::UPDATE_PREFIX) => {
            regex_rules::handle_update(&state, update_path, &body_bytes).await
        }
        _ => not_found(&state),
    }
}

// ── Listeners (TLS + plain) — mirror the observability listener ────────────────

async fn serve_conn<I>(io: I, peer: SocketAddr, state: Arc<AppState>)
where
    I: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
{
    let timeout_secs = state.connection_timeout_secs;
    let client_ip = peer.ip().to_string();
    let state_for_service = Arc::clone(&state);
    let builder = connection_builder(state.http_header_read_timeout_secs);
    let service = service_fn(move |req: Request<Incoming>| {
        let state = Arc::clone(&state_for_service);
        let client_ip = client_ip.clone();
        async move {
            Ok::<_, std::convert::Infallible>(handle_rule_management(req, state, client_ip).await)
        }
    });
    let conn = builder.serve_connection(io, service);
    match timeout(Duration::from_secs(timeout_secs), conn).await {
        Ok(Ok(())) => {}
        Ok(Err(err)) => error!(target: "krakenwaf", "rule-management connection error: {err}"),
        Err(_) => error!(target: "krakenwaf", "rule-management connection timed out"),
    }
}

/// Start the dedicated **TLS** rule-management listener.
///
/// # Errors
/// Returns an error if the TCP listener cannot bind to `listener_addr`.
pub async fn run(
    listener_addr: SocketAddr,
    tls_store: TlsConfigStore,
    state: Arc<AppState>,
) -> Result<()> {
    let listener = TcpListener::bind(listener_addr).await?;
    info!(target: "krakenwaf", addr=%listener_addr, tls=true, "KrakenWaf rule-management listener started");

    let shutdown = wait_for_shutdown_signal();
    tokio::pin!(shutdown);

    loop {
        let (stream, peer) = tokio::select! {
            result = listener.accept() => match result {
                Ok(pair) => pair,
                Err(err) => {
                    cope_with_accept_error(&err).await;
                    continue;
                }
            },
            () = &mut shutdown => break,
        };

        let acceptor = tls_store.acceptor();
        let state = state.clone();
        task::spawn(async move {
            let handshake_secs = state.tls_handshake_timeout_secs;
            let accepted = if handshake_secs > 0 {
                match timeout(Duration::from_secs(handshake_secs), acceptor.accept(stream)).await {
                    Ok(Ok(tls_stream)) => Some(tls_stream),
                    _ => None,
                }
            } else {
                acceptor.accept(stream).await.ok()
            };
            let Some(tls_stream) = accepted else {
                warn!(
                    target: "krakenwaf",
                    peer = %peer,
                    "rule-management TLS handshake failed or timed out; dropping connection"
                );
                return;
            };
            serve_conn(TokioIo::new(tls_stream), peer, state).await;
        });
    }

    info!(target: "krakenwaf", "rule-management listener shutting down");
    Ok(())
}

/// Start the dedicated **plain-HTTP** rule-management listener (`--no-tls`).
///
/// # Errors
/// Returns an error if the TCP listener cannot bind to `listener_addr`.
pub async fn run_plain(listener_addr: SocketAddr, state: Arc<AppState>) -> Result<()> {
    let listener = TcpListener::bind(listener_addr).await?;
    info!(target: "krakenwaf", addr=%listener_addr, tls=false, "KrakenWaf rule-management listener started (plain HTTP)");

    let shutdown = wait_for_shutdown_signal();
    tokio::pin!(shutdown);

    loop {
        let (stream, peer) = tokio::select! {
            result = listener.accept() => match result {
                Ok(pair) => pair,
                Err(err) => {
                    cope_with_accept_error(&err).await;
                    continue;
                }
            },
            () = &mut shutdown => break,
        };

        let state = state.clone();
        task::spawn(async move {
            serve_conn(TokioIo::new(stream), peer, state).await;
        });
    }

    info!(target: "krakenwaf", "rule-management listener shutting down");
    Ok(())
}

/// Spawn a periodic janitor that prunes expired Rorschach nonces so the replay
/// table cannot grow without bound.
pub fn spawn_nonce_janitor(state: &Arc<AppState>) {
    let Some(gate) = state.rule_management.clone() else {
        return;
    };
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(crate::rorschach::NONCE_SWEEP_INTERVAL);
        ticker.tick().await; // skip the immediate first tick
        loop {
            ticker.tick().await;
            gate.validator.sweep(Utc::now().timestamp());
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ip_allowed_matches_cidr_and_host() {
        let allow = vec![
            "127.0.0.1/32".parse::<IpNet>().expect("test"),
            "10.0.0.0/8".parse::<IpNet>().expect("test"),
        ];
        assert!(ip_allowed(&allow, "127.0.0.1"));
        assert!(ip_allowed(&allow, "10.1.2.3"));
        assert!(!ip_allowed(&allow, "192.168.1.1"));
        assert!(!ip_allowed(&allow, "not-an-ip"));
    }

    #[test]
    fn empty_allowlist_is_rejected() {
        let dir = tempfile::tempdir().expect("test");
        let path = dir.path().join("empty.txt");
        std::fs::write(&path, "# only comments\n\n").expect("test");
        assert!(load_allowlist(&path).is_err());
    }

    #[test]
    fn allowlist_parses_cidr_and_comments() {
        let dir = tempfile::tempdir().expect("test");
        let path = dir.path().join("a.txt");
        std::fs::write(&path, "127.0.0.1\n# comment\n10.0.0.0/8\n").expect("test");
        let nets = load_allowlist(&path).expect("valid");
        assert_eq!(nets.len(), 2);
    }
}
