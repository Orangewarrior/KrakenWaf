//! Rule-management control plane — a dedicated, isolated HTTP listener that lets
//! an operator inspect and **toggle CMC detection modules in real time** without
//! restarting the WAF.
//!
//! Topology mirrors the observability (`/metrics`) listener: a separate port
//! (default 4342, `rule_management_port` in `conf/proxy.yaml`) bound to the same
//! IP as `--listen`, reusing the listener's TLS certificates (plain HTTP only
//! under `--no-tls`). It is **not** a reverse proxy — it serves only the two
//! control endpoints and answers everything else with 404.
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
//! * `GET  /rule/control/cmc/list`   — JSON overview of every CMC module's state.
//! * `POST /rule/control/cmc/update` — partial patch; only the modules present
//!   in the body change. Unknown fields → 400; absent fields → unchanged.
//!
//! All user input is strictly validated: every JSON document is typed with
//! `deny_unknown_fields`, and any parse/validation failure returns a generic
//! "JSON not in the expected format" 400 that leaks no internal detail.

use std::{net::SocketAddr, path::Path, sync::Arc};

use anyhow::{bail, Context, Result};
use bytes::Bytes;
use chrono::Utc;
use http::{Request, Response, StatusCode};
use http_body_util::{BodyExt, Limited};
use hyper::{body::Incoming, service::service_fn};
use hyper_util::rt::TokioIo;
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use tokio::{net::TcpListener, task, time::timeout};
use tracing::{error, info, warn};

use crate::{
    app::AppState,
    cmc::CmcUpdateOutcome,
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

// ── JSON contracts (all strictly typed with deny_unknown_fields) ──────────────

/// `GET /rule/control/cmc/list` response envelope.
#[derive(Debug, Serialize)]
struct ListResponse {
    status: &'static str,
    modules: ListModules,
}

#[derive(Debug, Serialize)]
struct ListModules {
    #[serde(rename = "CMC-Rules")]
    cmc_rules: CmcRulesView,
}

/// The 18 toggleable CMC modules, in canonical order, as booleans.
#[derive(Debug, Serialize)]
#[allow(clippy::struct_excessive_bools)]
struct CmcRulesView {
    #[serde(rename = "SQLi_comments_detect")]
    sqli_comments_detect: bool,
    #[serde(rename = "Overflow_detect")]
    overflow_detect: bool,
    #[serde(rename = "SSTI_detect")]
    ssti_detect: bool,
    #[serde(rename = "SSI_injection_detect")]
    ssi_injection_detect: bool,
    #[serde(rename = "ESI_injection_detect")]
    esi_injection_detect: bool,
    #[serde(rename = "CRLF_injection_detect")]
    crlf_injection_detect: bool,
    #[serde(rename = "Request_Smuggling_detect")]
    request_smuggling_detect: bool,
    #[serde(rename = "NOSQL_injection_detect")]
    nosql_injection_detect: bool,
    #[serde(rename = "XXE_attack_detect")]
    xxe_attack_detect: bool,
    #[serde(rename = "Anti_exposed_backup")]
    anti_exposed_backup: bool,
    #[serde(rename = "Anti_passwd_leak")]
    anti_passwd_leak: bool,
    #[serde(rename = "Java_deserialize_detect")]
    java_deserialize_detect: bool,
    #[serde(rename = "Detect_db_errors")]
    detect_db_errors: bool,
    #[serde(rename = "Silent_sql_errors")]
    silent_sql_errors: bool,
    #[serde(rename = "Detect_bad_artifacts")]
    detect_bad_artifacts: bool,
    #[serde(rename = "Detect_bots_n_scanners")]
    detect_bots_n_scanners: bool,
    #[serde(rename = "HPP_detect")]
    hpp_detect: bool,
    #[serde(rename = "Open_redirect_n_RFI_detect")]
    open_redirect_n_rfi_detect: bool,
}

impl CmcRulesView {
    fn from_states(states: &[(&'static str, bool)]) -> Self {
        let get = |key: &str| {
            states
                .iter()
                .find(|(k, _)| *k == key)
                .is_some_and(|(_, v)| *v)
        };
        Self {
            sqli_comments_detect: get("SQLi_comments_detect"),
            overflow_detect: get("Overflow_detect"),
            ssti_detect: get("SSTI_detect"),
            ssi_injection_detect: get("SSI_injection_detect"),
            esi_injection_detect: get("ESI_injection_detect"),
            crlf_injection_detect: get("CRLF_injection_detect"),
            request_smuggling_detect: get("Request_Smuggling_detect"),
            nosql_injection_detect: get("NOSQL_injection_detect"),
            xxe_attack_detect: get("XXE_attack_detect"),
            anti_exposed_backup: get("Anti_exposed_backup"),
            anti_passwd_leak: get("Anti_passwd_leak"),
            java_deserialize_detect: get("Java_deserialize_detect"),
            detect_db_errors: get("Detect_db_errors"),
            silent_sql_errors: get("Silent_sql_errors"),
            detect_bad_artifacts: get("Detect_bad_artifacts"),
            detect_bots_n_scanners: get("Detect_bots_n_scanners"),
            hpp_detect: get("HPP_detect"),
            open_redirect_n_rfi_detect: get("Open_redirect_n_RFI_detect"),
        }
    }
}

/// `POST /rule/control/cmc/update` request body.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct UpdateRequest {
    modules: UpdateModules,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct UpdateModules {
    #[serde(rename = "CMC-Rules")]
    cmc_rules: CmcRulesPatch,
}

/// Partial patch: every module is optional. An absent field leaves the module
/// unchanged; `deny_unknown_fields` turns any unrecognised module name into a
/// deserialization error → HTTP 400.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct CmcRulesPatch {
    #[serde(rename = "SQLi_comments_detect")]
    sqli_comments_detect: Option<bool>,
    #[serde(rename = "Overflow_detect")]
    overflow_detect: Option<bool>,
    #[serde(rename = "SSTI_detect")]
    ssti_detect: Option<bool>,
    #[serde(rename = "SSI_injection_detect")]
    ssi_injection_detect: Option<bool>,
    #[serde(rename = "ESI_injection_detect")]
    esi_injection_detect: Option<bool>,
    #[serde(rename = "CRLF_injection_detect")]
    crlf_injection_detect: Option<bool>,
    #[serde(rename = "Request_Smuggling_detect")]
    request_smuggling_detect: Option<bool>,
    #[serde(rename = "NOSQL_injection_detect")]
    nosql_injection_detect: Option<bool>,
    #[serde(rename = "XXE_attack_detect")]
    xxe_attack_detect: Option<bool>,
    #[serde(rename = "Anti_exposed_backup")]
    anti_exposed_backup: Option<bool>,
    #[serde(rename = "Anti_passwd_leak")]
    anti_passwd_leak: Option<bool>,
    #[serde(rename = "Java_deserialize_detect")]
    java_deserialize_detect: Option<bool>,
    #[serde(rename = "Detect_db_errors")]
    detect_db_errors: Option<bool>,
    #[serde(rename = "Silent_sql_errors")]
    silent_sql_errors: Option<bool>,
    #[serde(rename = "Detect_bad_artifacts")]
    detect_bad_artifacts: Option<bool>,
    #[serde(rename = "Detect_bots_n_scanners")]
    detect_bots_n_scanners: Option<bool>,
    #[serde(rename = "HPP_detect")]
    hpp_detect: Option<bool>,
    #[serde(rename = "Open_redirect_n_RFI_detect")]
    open_redirect_n_rfi_detect: Option<bool>,
}

impl CmcRulesPatch {
    /// Flatten the present fields into `(module_key, value)` pairs in canonical order.
    fn pairs(&self) -> Vec<(String, bool)> {
        let mut pairs = Vec::new();
        let mut push = |key: &str, v: Option<bool>| {
            if let Some(v) = v {
                pairs.push((key.to_string(), v));
            }
        };
        push("SQLi_comments_detect", self.sqli_comments_detect);
        push("Overflow_detect", self.overflow_detect);
        push("SSTI_detect", self.ssti_detect);
        push("SSI_injection_detect", self.ssi_injection_detect);
        push("ESI_injection_detect", self.esi_injection_detect);
        push("CRLF_injection_detect", self.crlf_injection_detect);
        push("Request_Smuggling_detect", self.request_smuggling_detect);
        push("NOSQL_injection_detect", self.nosql_injection_detect);
        push("XXE_attack_detect", self.xxe_attack_detect);
        push("Anti_exposed_backup", self.anti_exposed_backup);
        push("Anti_passwd_leak", self.anti_passwd_leak);
        push("Java_deserialize_detect", self.java_deserialize_detect);
        push("Detect_db_errors", self.detect_db_errors);
        push("Silent_sql_errors", self.silent_sql_errors);
        push("Detect_bad_artifacts", self.detect_bad_artifacts);
        push("Detect_bots_n_scanners", self.detect_bots_n_scanners);
        push("HPP_detect", self.hpp_detect);
        push(
            "Open_redirect_n_RFI_detect",
            self.open_redirect_n_rfi_detect,
        );
        pairs
    }
}

/// `POST /rule/control/cmc/update` response envelope.
#[derive(Debug, Serialize)]
struct UpdateResponse {
    status: &'static str,
    context: &'static str,
    updated: UpdatedModules,
}

#[derive(Debug, Serialize)]
struct UpdatedModules {
    disabled: Vec<String>,
    enabled: Vec<String>,
}

// ── Response helpers ──────────────────────────────────────────────────────────

fn json_response<T: Serialize>(state: &Arc<AppState>, status: StatusCode, body: &T) -> WafResponse {
    let bytes = serde_json::to_vec(body).unwrap_or_default();
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

    // Read the (bounded) body before authentication: the Rorschach token binds a
    // hash of the body, so we must have the exact bytes to verify it.
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
    let now = Utc::now().timestamp();
    if let Err(err) = gate
        .validator
        .verify(&cred, method.as_str(), &path, &body_bytes, now)
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
        ("GET", "/rule/control/cmc/list") => handle_list(&state),
        ("POST", "/rule/control/cmc/update") => handle_update(&state, &body_bytes),
        _ => not_found(&state),
    }
}

fn handle_list(state: &Arc<AppState>) -> WafResponse {
    let states = state.waf.cmc_module_states();
    let body = ListResponse {
        status: "ok",
        modules: ListModules {
            cmc_rules: CmcRulesView::from_states(&states),
        },
    };
    json_response(state, StatusCode::OK, &body)
}

fn handle_update(state: &Arc<AppState>, body: &[u8]) -> WafResponse {
    let request: UpdateRequest = match serde_json::from_slice(body) {
        Ok(req) => req,
        Err(_) => return bad_request_json(state),
    };
    let pairs = request.modules.cmc_rules.pairs();
    match state.waf.cmc_apply_update(&pairs) {
        Ok(CmcUpdateOutcome { enabled, disabled }) => {
            info!(
                target: "krakenwaf",
                enabled = ?enabled,
                disabled = ?disabled,
                "rule-management: CMC module table updated in real time"
            );
            let body = UpdateResponse {
                status: "ok",
                context: "cmc_update",
                updated: UpdatedModules { disabled, enabled },
            };
            json_response(state, StatusCode::OK, &body)
        }
        // Unknown module key. `deny_unknown_fields` normally turns this into a
        // deserialization error above; this is the defensive belt-and-braces case.
        Err(_unknown_key) => bad_request_json(state),
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

    #[test]
    fn update_rejects_unknown_module_field() {
        let body = br#"{"modules":{"CMC-Rules":{"Bogus_module":true}}}"#;
        let parsed: Result<UpdateRequest, _> = serde_json::from_slice(body);
        assert!(
            parsed.is_err(),
            "unknown module key must fail deny_unknown_fields"
        );
    }

    #[test]
    fn update_accepts_partial_patch() {
        let body = br#"{"modules":{"CMC-Rules":{"HPP_detect":false,"Silent_sql_errors":false}}}"#;
        let parsed: UpdateRequest = serde_json::from_slice(body).expect("valid partial patch");
        let pairs = parsed.modules.cmc_rules.pairs();
        assert_eq!(
            pairs,
            vec![
                ("Silent_sql_errors".to_string(), false),
                ("HPP_detect".to_string(), false),
            ]
        );
    }

    #[test]
    fn update_rejects_unknown_top_level_field() {
        let body = br#"{"modules":{"CMC-Rules":{}},"extra":1}"#;
        let parsed: Result<UpdateRequest, _> = serde_json::from_slice(body);
        assert!(parsed.is_err());
    }
}
