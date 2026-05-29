use crate::{
    app::AppState,
    logging::{write_critical, SecurityEvent},
    proxy::{effective_client_ip, plain_response},
    rules::Severity,
    tls::TlsConfigStore,
};
use anyhow::Result;
use bytes::Bytes;
use chrono::Utc;
use http::{Request, Response, StatusCode};
use http_body_util::Full;
use hyper::{body::Incoming, service::service_fn};
use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    server::conn::auto::Builder,
};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use std::time::Duration;
use tokio::{net::TcpListener, sync::Notify, task, time::timeout};
use tracing::{error, info, warn};

/// Compact request-correlation ID matching the WAF engine's format
/// (32-char lowercase hex, no hyphens). Used by BAN-list short-circuit
/// rejections so the log entry is consistent with full-WAF blocks.
fn request_id() -> String {
    uuid::Uuid::new_v4().simple().to_string()
}

/// Emit the Low-severity "Banned IP — request rejected" log entry.
///
/// The same `SecurityEvent` is persisted to the JSON log, the critical
/// log, and the `SQLite` security store so dashboards keep a single source
/// of truth for blocked requests (including those that never reach the
/// inspection pipeline).
fn log_banned_request(
    state: &AppState,
    client_ip: &str,
    method: &str,
    uri: &str,
    banned_until: i64,
) {
    let event = SecurityEvent {
        timestamp: Utc::now().to_rfc3339(),
        request_id: request_id(),
        client_ip: client_ip.to_string(),
        country: String::new(),
        continent_name: String::new(),
        method: method.to_string(),
        uri: uri.to_string(),
        fullpath_evidence: uri.to_string(),
        engine: "banning".to_string(),
        rule_id: "00000".to_string(),
        title: "Banned IP — request rejected".to_string(),
        severity: Severity::Low,
        cwe: "CWE-693".to_string(),
        description: format!(
            "Client IP is in the BAN list (banned_until={banned_until}); request rejected without inspection."
        ),
        reference_url: "https://github.com/Orangewarrior/KrakenWaf/blob/main/docs/banning.md".to_string(),
        rule_match: "banning::active_ban".to_string(),
        rule_line_match: format!("banned_until={banned_until}"),
        request_payload: String::new(),
    };

    info!(
        target: "krakenwaf",
        request_id = %event.request_id,
        ip = %event.client_ip,
        method = %event.method,
        uri = %event.uri,
        banned_until,
        title = %event.title,
        severity = %event.severity,
        "banned IP rejected"
    );
    write_critical(&state.logging, &event);
    state.store.enqueue(event);
    state.metrics.inc_blocked();
    state.metrics.inc_blocked_by_label("banning:active_ban");
}

/// Maximum time the listener waits for in-flight connections to drain after
/// receiving SIGINT/SIGTERM before forcibly returning.
const SHUTDOWN_DRAIN_TIMEOUT: Duration = Duration::from_secs(30);

/// RAII guard that decrements the per-IP in-flight counter when dropped.
struct ConnGuard(Arc<AtomicUsize>);

impl Drop for ConnGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Resolves when the process receives SIGINT or, on Unix, SIGTERM.
async fn wait_for_shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut sigterm = match signal(SignalKind::terminate()) {
            Ok(sig) => sig,
            Err(err) => {
                warn!(target: "krakenwaf", "failed to install SIGTERM handler: {err}");
                let _ = tokio::signal::ctrl_c().await;
                return;
            }
        };
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = sigterm.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

/// Wait up to `SHUTDOWN_DRAIN_TIMEOUT` for the in-flight connection counter to
/// reach zero. Logs a warning and returns when the deadline passes.
async fn wait_for_drain(in_flight: &AtomicUsize, notify: &Notify) {
    let deadline = tokio::time::Instant::now() + SHUTDOWN_DRAIN_TIMEOUT;
    loop {
        let pending = in_flight.load(Ordering::Acquire);
        if pending == 0 {
            return;
        }
        let now = tokio::time::Instant::now();
        if now >= deadline {
            warn!(
                target: "krakenwaf",
                pending,
                "shutdown drain deadline reached; abandoning in-flight connections"
            );
            return;
        }
        let _ = tokio::time::timeout(deadline - now, notify.notified()).await;
    }
}

/// Start the TLS listener (normal production mode).
///
/// # Errors
/// Returns an error if the TCP listener cannot bind to the given address.
pub async fn run(
    listener_addr: std::net::SocketAddr,
    tls_store: TlsConfigStore,
    state: Arc<AppState>,
) -> Result<()> {
    let listener = TcpListener::bind(listener_addr).await?;
    let semaphore = Arc::new(tokio::sync::Semaphore::new(state.cli.max_connections));
    let in_flight = Arc::new(AtomicUsize::new(0));
    let drain_notify = Arc::new(Notify::new());
    info!(target: "krakenwaf", addr=%listener_addr, tls=true, "KrakenWaf listener started");

    let shutdown = wait_for_shutdown_signal();
    tokio::pin!(shutdown);

    loop {
        let permit = tokio::select! {
            result = semaphore.clone().acquire_owned() => match result {
                Ok(p) => p,
                Err(_) => return Err(anyhow::anyhow!("connection semaphore closed")),
            },
            () = &mut shutdown => break,
        };

        let (stream, peer) = tokio::select! {
            result = listener.accept() => result?,
            () = &mut shutdown => break,
        };

        let acceptor = tls_store.acceptor();
        let state = state.clone();
        let in_flight = in_flight.clone();
        let drain_notify = drain_notify.clone();

        in_flight.fetch_add(1, Ordering::AcqRel);
        task::spawn(async move {
            let _permit = permit;
            match acceptor.accept(stream).await {
                Ok(tls_stream) => {
                    let io = TokioIo::new(tls_stream);
                    let timeout_secs = state.cli.connection_timeout_secs;
                    let state_for_service = Arc::clone(&state);
                    let client_ip = peer.ip().to_string();
                    let builder = Builder::new(TokioExecutor::new());
                    let service = service_fn(move |req: Request<Incoming>| {
                        let state = Arc::clone(&state_for_service);
                        let client_ip = client_ip.clone();
                        async move {
                            Ok::<_, std::convert::Infallible>(handle(req, state, client_ip).await)
                        }
                    });
                    let conn = builder.serve_connection(io, service);
                    match timeout(Duration::from_secs(timeout_secs), conn).await {
                        Ok(Ok(())) => {}
                        Ok(Err(err)) => error!(target: "krakenwaf", "connection error: {err}"),
                        Err(_) => error!(target: "krakenwaf", "connection timed out"),
                    }
                }
                Err(err) => {
                    error!(target: "krakenwaf", "TLS handshake failed for {}: {}", peer, err);
                }
            }
            if in_flight.fetch_sub(1, Ordering::AcqRel) == 1 {
                drain_notify.notify_waiters();
            }
        });
    }

    info!(target: "krakenwaf", "shutdown signal received; draining in-flight connections (up to 30 s)");
    wait_for_drain(&in_flight, &drain_notify).await;
    info!(target: "krakenwaf", "drain complete, exiting");
    Ok(())
}

/// Start the plain-HTTP listener (--no-tls mode — for testing or load-balancer deployments).
///
/// # Errors
/// Returns an error if the TCP listener cannot bind to the given address.
pub async fn run_plain(listener_addr: std::net::SocketAddr, state: Arc<AppState>) -> Result<()> {
    let listener = TcpListener::bind(listener_addr).await?;
    let semaphore = Arc::new(tokio::sync::Semaphore::new(state.cli.max_connections));
    let in_flight = Arc::new(AtomicUsize::new(0));
    let drain_notify = Arc::new(Notify::new());
    info!(target: "krakenwaf", addr=%listener_addr, tls=false, "KrakenWaf listener started (plain HTTP)");

    let shutdown = wait_for_shutdown_signal();
    tokio::pin!(shutdown);

    loop {
        let permit = tokio::select! {
            result = semaphore.clone().acquire_owned() => match result {
                Ok(p) => p,
                Err(_) => return Err(anyhow::anyhow!("connection semaphore closed")),
            },
            () = &mut shutdown => break,
        };

        let (stream, peer) = tokio::select! {
            result = listener.accept() => result?,
            () = &mut shutdown => break,
        };

        let state = state.clone();
        let in_flight = in_flight.clone();
        let drain_notify = drain_notify.clone();

        in_flight.fetch_add(1, Ordering::AcqRel);
        task::spawn(async move {
            let _permit = permit;
            let io = TokioIo::new(stream);
            let timeout_secs = state.cli.connection_timeout_secs;
            let state_for_service = Arc::clone(&state);
            let client_ip = peer.ip().to_string();
            let builder = Builder::new(TokioExecutor::new());
            let service = service_fn(move |req: Request<Incoming>| {
                let state = Arc::clone(&state_for_service);
                let client_ip = client_ip.clone();
                async move { Ok::<_, std::convert::Infallible>(handle(req, state, client_ip).await) }
            });
            let conn = builder.serve_connection(io, service);
            match timeout(Duration::from_secs(timeout_secs), conn).await {
                Ok(Ok(())) => {}
                Ok(Err(err)) => error!(target: "krakenwaf", "connection error: {err}"),
                Err(_) => error!(target: "krakenwaf", "connection timed out"),
            }
            if in_flight.fetch_sub(1, Ordering::AcqRel) == 1 {
                drain_notify.notify_waiters();
            }
        });
        let _ = peer;
    }

    info!(target: "krakenwaf", "shutdown signal received; draining in-flight connections (up to 30 s)");
    wait_for_drain(&in_flight, &drain_notify).await;
    info!(target: "krakenwaf", "drain complete, exiting");
    Ok(())
}

#[allow(clippy::too_many_lines)]
async fn handle(
    req: Request<Incoming>,
    state: Arc<AppState>,
    client_ip: String,
) -> Response<Full<Bytes>> {
    let path = req.uri().path();

    // Health and metrics endpoints bypass per-IP concurrency and backpressure gates.
    // Root-level /livez and /readyz are aliases for the namespaced paths.
    if path == "/__krakenwaf/health"
        || path == "/__krakenwaf/livez"
        || path == "/__krakenwaf/readyz"
        || path == "/livez"
        || path == "/readyz"
        || path == "/metrics"
    {
        // Resolve the effective IP (honours X-Forwarded-For + trusted proxy CIDRs)
        // so that IP restrictions apply correctly behind a load balancer.
        let effective_ip = effective_client_ip(&client_ip, req.headers(), &state);

        // Check YAML-based only_addrs restriction first (if configured).
        if let Some(config) = &state.allow_path_config {
            use crate::allowpaths::PathDecision;
            if matches!(config.check(path, path, &effective_ip), PathDecision::Block) {
                let mut resp = plain_response(StatusCode::FORBIDDEN, "Access denied");
                state.response_header_policy.apply(resp.headers_mut(), false);
                return resp;
            }
        }
        // Fallback: allowlist.txt-based restriction (rules/addr/allowlist.txt).
        let snap = state.waf.rules_snapshot();
        if !snap.is_ip_allowed(&client_ip) {
            let mut resp = plain_response(StatusCode::FORBIDDEN, "Access denied");
            state.response_header_policy.apply(resp.headers_mut(), false);
            return resp;
        }
        if path == "/__krakenwaf/livez" || path == "/livez" {
            let mut response = plain_response(StatusCode::OK, "ok");
            state.response_header_policy.apply(response.headers_mut(), false);
            return response;
        }
        if path == "/__krakenwaf/health" || path == "/__krakenwaf/readyz" || path == "/readyz" {
            // Readiness: WAF must have at least one rule loaded.
            let ready = !snap.uri_keywords.is_empty()
                || !snap.header_keywords.is_empty()
                || !snap.body_keywords.is_empty()
                || !snap.path_regex.is_empty()
                || !snap.blocked_ips.is_empty()
                || !snap.blocked_ip_prefixes.is_empty();
            if ready {
                let mut response = plain_response(StatusCode::OK, "KrakenWaf OK");
                state.response_header_policy.apply(response.headers_mut(), false);
                return response;
            }
            let mut response =
                plain_response(StatusCode::SERVICE_UNAVAILABLE, "KrakenWaf not ready");
            state.response_header_policy.apply(response.headers_mut(), false);
            return response;
        }
        // /metrics
        let mut response = Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "text/plain; version=0.0.4; charset=utf-8")
            .body(Full::new(Bytes::from(state.metrics.render_prometheus())))
            .unwrap_or_else(|_| plain_response(StatusCode::OK, ""));
        state.response_header_policy.apply(response.headers_mut(), false);
        return response;
    }

    // ── BAN-list short-circuit ────────────────────────────────────────────────
    // Resolve the effective client IP honouring X-Forwarded-For + trusted
    // proxies, then reject *any* request from a currently-banned IP before
    // touching concurrency gates, backpressure accounting, the WAF engine,
    // or the upstream. The block is logged at Low severity.
    if state.ban_manager.enabled() {
        let effective_ip = effective_client_ip(&client_ip, req.headers(), &state);
        if let Some(banned_until) = state.ban_manager.check(&effective_ip).await {
            log_banned_request(
                &state,
                &effective_ip,
                req.method().as_str(),
                &req.uri().to_string(),
                banned_until,
            );
            let mut resp = plain_response(StatusCode::FORBIDDEN, "Banned by KrakenWaf");
            state.response_header_policy.apply(resp.headers_mut(), false);
            return resp;
        }
    }

    // Per-IP concurrency gate — enforced before any WAF inspection.
    let _conn_guard = if state.max_coroutines_per_ip > 0 {
        let counter = state
            .ip_connections
            .entry(client_ip.clone())
            .or_insert_with(|| Arc::new(AtomicUsize::new(0)))
            .clone();

        let prev = counter.fetch_add(1, Ordering::Relaxed);
        if prev >= state.max_coroutines_per_ip {
            counter.fetch_sub(1, Ordering::Relaxed);
            warn!(
                target: "krakenwaf",
                ip = %client_ip,
                limit = state.max_coroutines_per_ip,
                "per-IP concurrency limit exceeded"
            );
            state.metrics.inc_rate_limit_hits();
            let mut resp = plain_response(
                StatusCode::TOO_MANY_REQUESTS,
                "Too many simultaneous connections from this IP address",
            );
            resp.headers_mut()
                .insert("Retry-After", http::HeaderValue::from_static("5"));
            state.response_header_policy.apply(resp.headers_mut(), false);
            return resp;
        }
        Some(ConnGuard(counter))
    } else {
        None
    };

    // Memory backpressure gate (global).
    if state.max_inflight_body_bytes > 0 {
        let current = state.inflight_body_bytes.load(Ordering::Relaxed);
        if current >= state.max_inflight_body_bytes {
            warn!(
                target: "krakenwaf",
                current_bytes = current,
                limit = state.max_inflight_body_bytes,
                ip = %client_ip,
                "global body-bytes backpressure limit reached"
            );
            state.metrics.inc_rate_limit_hits();
            let mut resp = plain_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "KrakenWaf is under load, please retry",
            );
            resp.headers_mut()
                .insert("Retry-After", http::HeaderValue::from_static("5"));
            state.response_header_policy.apply(resp.headers_mut(), false);
            return resp;
        }
    }

    // Memory backpressure gate (per-IP).
    if state.max_per_ip_body_bytes > 0 {
        let ip_current = state
            .ip_body_bytes
            .get(&client_ip)
            .map_or(0, |v| v.load(Ordering::Relaxed));
        if ip_current >= state.max_per_ip_body_bytes {
            warn!(
                target: "krakenwaf",
                current_bytes = ip_current,
                limit = state.max_per_ip_body_bytes,
                ip = %client_ip,
                "per-IP body-bytes backpressure limit reached"
            );
            state.metrics.inc_rate_limit_hits();
            let mut resp = plain_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "KrakenWaf per-IP limit reached, please retry",
            );
            resp.headers_mut()
                .insert("Retry-After", http::HeaderValue::from_static("5"));
            state.response_header_policy.apply(resp.headers_mut(), false);
            return resp;
        }
    }

    state.proxy.handle(&state, req, client_ip).await
}
