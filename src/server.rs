use crate::{
    allowpaths::AllowPathConfig,
    app::AppState,
    logging::{write_critical, SecurityEvent},
    proxy::{effective_client_ip, full_body, plain_response, WafResponse},
    rules::{RuleSet, Severity},
    tls::TlsConfigStore,
};
use anyhow::Result;
use bytes::Bytes;
use chrono::Utc;
use http::{Request, Response, StatusCode};
use hyper::{body::Incoming, service::service_fn};
use hyper_util::{
    rt::{TokioExecutor, TokioIo, TokioTimer},
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

/// Outcome of a (timeout-bounded) TLS handshake. Distinguishes a genuine
/// handshake failure from a Slowloris-style stall so the two are logged at
/// different levels and can be separated on a dashboard.
enum TlsAcceptOutcome {
    Timeout,
    Failed(std::io::Error),
}

/// Interval at which idle per-IP counter entries are reaped from the
/// concurrency and body-byte maps.
const IP_MAP_SWEEP_INTERVAL: Duration = Duration::from_secs(30);

/// Reject an externally-bound observability listener unless at least one
/// access-control mechanism is active before the socket is opened.
///
/// TLS server authentication alone is not mTLS and does not satisfy this
/// policy. `KrakenWaf` currently accepts bearer authentication and either the
/// port-scoped allow-path restriction or the legacy rules allowlist.
///
/// # Errors
/// Returns an error when a non-loopback bind has no effective bearer token or
/// IP allowlist.
pub fn validate_observability_exposure(
    metrics_addr: std::net::SocketAddr,
    bearer_configured: bool,
    allow_paths: Option<&AllowPathConfig>,
    rules: &RuleSet,
) -> Result<()> {
    if metrics_addr.ip().is_loopback() {
        return Ok(());
    }

    let allow_paths_protected = allow_paths
        .is_some_and(|config| config.has_ip_restriction_for("/metrics", metrics_addr.port()));
    let legacy_allowlist_protected = !rules.allowed_ips.is_empty();

    if bearer_configured || allow_paths_protected || legacy_allowlist_protected {
        return Ok(());
    }

    anyhow::bail!(
        "refusing to expose observability on {metrics_addr}: a non-loopback metrics bind requires \
         BEARER_PASSWORD or an explicit IP allowlist for /metrics; ordinary TLS is not mTLS"
    )
}

fn connection_builder(header_read_timeout_secs: u64) -> Builder<TokioExecutor> {
    let mut builder = Builder::new(TokioExecutor::new());
    let mut http1 = builder.http1();
    http1.timer(TokioTimer::default());
    if header_read_timeout_secs == 0 {
        http1.header_read_timeout(None);
    } else {
        http1.header_read_timeout(Duration::from_secs(header_read_timeout_secs));
    }
    builder
}

/// Periodically evict zero-valued entries from the per-IP concurrency
/// (`ip_connections`) and per-IP body-byte (`ip_body_bytes`) maps.
///
/// Without this sweep those `DashMap`s grow without bound — one entry per
/// distinct source IP, never removed — so a client rotating source addresses
/// (trivial across an IPv6 /64) drives a slow memory-exhaustion `DoS`. An entry
/// is removed **only when its counter is zero**, i.e. the IP has no in-flight
/// connection and no buffered body at that instant, so a live request is never
/// disturbed (a racing increment simply re-creates the entry). This mirrors the
/// GCRA rate-limiter's existing shard sweep.
pub fn spawn_ip_map_janitor(state: Arc<AppState>) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(IP_MAP_SWEEP_INTERVAL);
        // The first tick fires immediately; skip it so we do not sweep empty maps.
        ticker.tick().await;
        loop {
            ticker.tick().await;
            state
                .ip_connections
                .retain(|_, counter| counter.load(Ordering::Relaxed) > 0);
            state
                .ip_body_bytes
                .retain(|_, counter| counter.load(Ordering::Relaxed) > 0);
            // Reap per-IP WebSocket session counters the same way, so a client
            // rotating source addresses cannot grow the map without bound.
            state.ws_control.sweep_idle();
        }
    });
}

/// True if `ip` parses to a loopback address (127.0.0.0/8 or `::1`).
fn ip_is_loopback(ip: &str) -> bool {
    ip.parse::<std::net::IpAddr>()
        .is_ok_and(|addr| addr.is_loopback())
}

/// Placeholder substituted for the bearer token in every log line so the secret
/// never reaches disk, a log shipper, or a crash dump.
const REDACTED_TOKEN: &str = "****";

/// Constant-time byte-slice equality. The comparison time depends only on the
/// length of `a`, not on where (or whether) the two slices first differ, so an
/// attacker cannot recover the expected token byte-by-byte by timing the
/// response. Length mismatch short-circuits — token length is not itself a
/// secret.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Extract the credential from an `Authorization: Bearer <token>` header.
/// Returns `None` when the header is absent, non-UTF-8, not a `Bearer` scheme,
/// or carries an empty token. The scheme name is matched case-insensitively per
/// RFC 7235; the token itself is returned verbatim.
fn extract_bearer(headers: &http::HeaderMap) -> Option<&str> {
    let value = headers.get(http::header::AUTHORIZATION)?.to_str().ok()?;
    let (scheme, token) = value.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("bearer") {
        return None;
    }
    let token = token.trim();
    if token.is_empty() {
        None
    } else {
        Some(token)
    }
}

/// Enforce the `Authorization: Bearer <token>` gate on the dedicated
/// observability listener. Returns `Some(401)` when the token is missing or
/// does not match the configured secret, and `None` when the request is
/// authorised (or when no token is configured, leaving the endpoint open as
/// before). The presented token is never logged — only [`REDACTED_TOKEN`].
fn enforce_bearer_auth(
    req: &Request<Incoming>,
    state: &Arc<AppState>,
    effective_ip: &str,
) -> Option<WafResponse> {
    // No token configured ⇒ the bearer gate is disabled (a startup warning is
    // emitted in this case). This keeps deployments that have not provisioned a
    // secret working exactly as before.
    let expected = state.metrics_auth_token.as_deref()?;

    let presented = extract_bearer(req.headers());
    let authorised = presented.is_some_and(|t| constant_time_eq(t.as_bytes(), expected.as_bytes()));
    if authorised {
        return None;
    }

    warn!(
        target: "krakenwaf",
        ip = %effective_ip,
        token = REDACTED_TOKEN,
        present = presented.is_some(),
        "rejected observability request: missing or invalid bearer token"
    );
    let mut resp = plain_response(StatusCode::UNAUTHORIZED, "Unauthorized");
    resp.headers_mut().insert(
        http::header::WWW_AUTHENTICATE,
        http::HeaderValue::from_static("Bearer realm=\"krakenwaf-observability\""),
    );
    state.response_header_policy.apply(resp.headers_mut(), false);
    Some(resp)
}

/// Decide whether `/metrics` may be served to this client.
///
/// The Prometheus endpoint exposes operational intelligence (per-module block
/// counts, latency, which engines fire) and must not be world-readable by
/// default. When an IP allowlist **is** configured the caller has already
/// passed [`RuleSet::is_ip_allowed`], so remote scraping is an explicit opt-in
/// and is permitted. When **no** allowlist is configured we restrict `/metrics`
/// to loopback (node-local / sidecar scrapers) instead of failing open.
fn metrics_access_allowed(snap: &RuleSet, effective_ip: &str, peer_ip: &str) -> bool {
    if !snap.allowed_ips.is_empty() {
        return true;
    }
    ip_is_loopback(effective_ip) || ip_is_loopback(peer_ip)
}

/// Serve the observability endpoints — `/livez`, `/readyz`,
/// `/__krakenwaf/{health,livez,readyz}`, and (when `include_metrics`) `/metrics`.
///
/// Returns `Some(response)` when `req` targets an endpoint this function owns
/// (including access-denied responses), and `None` otherwise so the caller can
/// continue down its own pipeline. Shared by the data-plane listener (which sets
/// `include_metrics = false`, keeping liveness/readiness inline but delegating
/// `/metrics` to the dedicated port) and the observability listener (which sets
/// `include_metrics = true`).
fn serve_observability(
    req: &Request<Incoming>,
    state: &Arc<AppState>,
    client_ip: &str,
    include_metrics: bool,
    listener_port: u16,
) -> Option<WafResponse> {
    let path = req.uri().path();
    let is_health = path == "/__krakenwaf/health"
        || path == "/__krakenwaf/livez"
        || path == "/__krakenwaf/readyz"
        || path == "/livez"
        || path == "/readyz";
    let is_metrics = include_metrics && path == "/metrics";
    if !(is_health || is_metrics) {
        return None;
    }

    // Resolve the effective IP (honours X-Forwarded-For + trusted proxy CIDRs)
    // so that IP restrictions apply correctly behind a load balancer.
    let effective_ip = effective_client_ip(client_ip, req.headers(), state);

    // Check YAML-based only_addrs restriction first (if configured).
    if let Some(config) = &state.allow_path_config {
        use crate::allowpaths::PathDecision;
        if matches!(
            config.check(path, path, &effective_ip, listener_port),
            PathDecision::Block
        ) {
            let mut resp = plain_response(StatusCode::FORBIDDEN, "Access denied");
            state.response_header_policy.apply(resp.headers_mut(), false);
            return Some(resp);
        }
    }
    // Fallback: allowlist.txt-based restriction (rules/addr/allowlist.txt).
    let snap = state.waf.rules_snapshot();
    if !snap.is_ip_allowed(client_ip) {
        let mut resp = plain_response(StatusCode::FORBIDDEN, "Access denied");
        state.response_header_policy.apply(resp.headers_mut(), false);
        return Some(resp);
    }
    // Bearer-token gate. Only the dedicated observability listener
    // (`include_metrics`) is protected: every endpoint it serves — `/metrics`,
    // the health probes, and the kraken-ui proxy surface — requires a valid
    // `Authorization: Bearer <token>` once a token is configured. The IP
    // allowlist (403, above) is checked first; an authorised IP that omits or
    // mis-presents the token gets 401 here. Loopback/data-plane probes
    // (`include_metrics == false`) are unaffected.
    if include_metrics {
        if let Some(resp) = enforce_bearer_auth(req, state, &effective_ip) {
            return Some(resp);
        }
    }
    if path == "/__krakenwaf/livez" || path == "/livez" {
        let mut response = plain_response(StatusCode::OK, "ok");
        state.response_header_policy.apply(response.headers_mut(), false);
        return Some(response);
    }
    if path == "/__krakenwaf/health" || path == "/__krakenwaf/readyz" || path == "/readyz" {
        // Readiness: WAF must have at least one rule loaded.
        let ready = !snap.uri_keywords.is_empty()
            || !snap.header_keywords.is_empty()
            || !snap.body_keywords.is_empty()
            || !snap.path_regex.is_empty()
            || !snap.blocked_ips.is_empty()
            || !snap.blocked_ip_prefixes.is_empty();
        let mut response = if ready {
            plain_response(StatusCode::OK, "KrakenWaf OK")
        } else {
            plain_response(StatusCode::SERVICE_UNAVAILABLE, "KrakenWaf not ready")
        };
        state.response_header_policy.apply(response.headers_mut(), false);
        return Some(response);
    }
    // /metrics exposes operational intelligence (per-module block counts,
    // latency, which engines fire). Unlike liveness/readiness it must not be
    // world-readable by default: with no allowlist configured, restrict it to
    // loopback. Remote scraping is opt-in via rules/addr/allowlist.txt (or the
    // allow-paths YAML), both already enforced above.
    if !metrics_access_allowed(&snap, &effective_ip, client_ip) {
        warn!(
            target: "krakenwaf",
            ip = %effective_ip,
            "denied /metrics from non-loopback client with no allowlist configured; \
             add the scraper IP to rules/addr/allowlist.txt to permit remote scraping"
        );
        let mut resp = plain_response(StatusCode::FORBIDDEN, "Access denied");
        state.response_header_policy.apply(resp.headers_mut(), false);
        return Some(resp);
    }
    let mut response = Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "text/plain; version=0.0.4; charset=utf-8")
        .body(full_body(Bytes::from(state.metrics.render_prometheus())))
        .unwrap_or_else(|_| plain_response(StatusCode::OK, ""));
    state.response_header_policy.apply(response.headers_mut(), false);
    Some(response)
}

/// Drive a single accepted observability connection to completion, bounded by
/// the same connection timeout as the data plane. Shared by the TLS and plain
/// observability listeners. Serves the full observability surface (health probes
/// + `/metrics`) and answers any other path with 404 — it is not a reverse proxy.
async fn serve_observability_conn<I>(
    io: I,
    peer: std::net::SocketAddr,
    state: Arc<AppState>,
    listener_port: u16,
) where
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
            let resp = serve_observability(&req, &state, &client_ip, true, listener_port)
                .unwrap_or_else(|| {
                let mut resp = plain_response(StatusCode::NOT_FOUND, "Not found");
                state.response_header_policy.apply(resp.headers_mut(), false);
                resp
            });
            Ok::<_, std::convert::Infallible>(resp)
        }
    });
    let conn = builder.serve_connection(io, service);
    match timeout(Duration::from_secs(timeout_secs), conn).await {
        Ok(Ok(())) => {}
        Ok(Err(err)) => error!(target: "krakenwaf", "observability connection error: {err}"),
        Err(_) => error!(target: "krakenwaf", "observability connection timed out"),
    }
}

/// Start the dedicated **TLS** observability listener on its own port.
///
/// Serves `/metrics` and the health probes, reusing the data-plane
/// [`TlsConfigStore`] so the same certificates (and SNI map) back both ports —
/// only the port differs, giving operators an isolated, independently
/// routable/firewallable observability surface.
///
/// # Errors
/// Returns an error if the TCP listener cannot bind to `listener_addr`.
pub async fn run_metrics(
    listener_addr: std::net::SocketAddr,
    tls_store: TlsConfigStore,
    state: Arc<AppState>,
) -> Result<()> {
    let listener = TcpListener::bind(listener_addr).await?;
    let listener_port = listener_addr.port();
    info!(target: "krakenwaf", addr=%listener_addr, tls=true, "KrakenWaf observability listener started");

    let shutdown = wait_for_shutdown_signal();
    tokio::pin!(shutdown);

    loop {
        let (stream, peer) = tokio::select! {
            result = listener.accept() => result?,
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
                    "observability TLS handshake failed or timed out; dropping connection"
                );
                return;
            };
            serve_observability_conn(TokioIo::new(tls_stream), peer, state, listener_port).await;
        });
    }

    info!(target: "krakenwaf", "observability listener shutting down");
    Ok(())
}

/// Start the dedicated **plain-HTTP** observability listener (used only when the
/// whole WAF runs with `--no-tls`, e.g. integration tests or LB-terminated TLS).
///
/// # Errors
/// Returns an error if the TCP listener cannot bind to `listener_addr`.
pub async fn run_metrics_plain(
    listener_addr: std::net::SocketAddr,
    state: Arc<AppState>,
) -> Result<()> {
    let listener = TcpListener::bind(listener_addr).await?;
    let listener_port = listener_addr.port();
    info!(target: "krakenwaf", addr=%listener_addr, tls=false, "KrakenWaf observability listener started (plain HTTP)");

    let shutdown = wait_for_shutdown_signal();
    tokio::pin!(shutdown);

    loop {
        let (stream, peer) = tokio::select! {
            result = listener.accept() => result?,
            () = &mut shutdown => break,
        };

        let state = state.clone();
        task::spawn(async move {
            serve_observability_conn(TokioIo::new(stream), peer, state, listener_port).await;
        });
    }

    info!(target: "krakenwaf", "observability listener shutting down");
    Ok(())
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
            // Anti-Slowloris: bound the TLS handshake. A client that opens the
            // socket but never finishes the handshake would otherwise pin this
            // task — and its semaphore permit — indefinitely, letting a handful
            // of stalled sockets exhaust `--max-connections`.
            let handshake_secs = state.tls_handshake_timeout_secs;
            let accepted = if handshake_secs > 0 {
                timeout(Duration::from_secs(handshake_secs), acceptor.accept(stream))
                    .await
                    .map_or_else(
                        |_elapsed| Err(TlsAcceptOutcome::Timeout),
                        |res| res.map_err(TlsAcceptOutcome::Failed),
                    )
            } else {
                acceptor.accept(stream).await.map_err(TlsAcceptOutcome::Failed)
            };
            match accepted {
                Ok(tls_stream) => {
                    let io = TokioIo::new(tls_stream);
                    let timeout_secs = state.connection_timeout_secs;
                    let state_for_service = Arc::clone(&state);
                    let client_ip = peer.ip().to_string();
                    let builder = connection_builder(state.http_header_read_timeout_secs);
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
                Err(TlsAcceptOutcome::Timeout) => warn!(
                    target: "krakenwaf",
                    peer = %peer,
                    timeout_secs = handshake_secs,
                    "TLS handshake timed out; dropping connection (anti-Slowloris)"
                ),
                Err(TlsAcceptOutcome::Failed(err)) => {
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
            let timeout_secs = state.connection_timeout_secs;
            let state_for_service = Arc::clone(&state);
            let client_ip = peer.ip().to_string();
            let builder = connection_builder(state.http_header_read_timeout_secs);
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
) -> WafResponse {
    // Liveness/readiness probes bypass per-IP concurrency and backpressure gates
    // and are still answered inline on the data-plane port (load balancers and
    // k8s probe the serving port). `/metrics`, however, is *not* served here: it
    // moved to the dedicated observability listener (see `run_metrics`) so the
    // Prometheus surface can be firewalled/routed in isolation — hence
    // `include_metrics = false`.
    if let Some(resp) = serve_observability(&req, &state, &client_ip, false, state.cli.listen.port())
    {
        return resp;
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

#[cfg(test)]
mod tests {
    use super::{
        constant_time_eq, extract_bearer, validate_observability_exposure,
    };
    use crate::{allowpaths::AllowPathConfig, rules::RuleSet};
    use http::header::{HeaderMap, HeaderValue, AUTHORIZATION};

    fn headers_with_auth(value: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(AUTHORIZATION, HeaderValue::from_str(value).expect("header value"));
        h
    }

    #[test]
    fn constant_time_eq_matches_identical() {
        assert!(constant_time_eq(b"hunter2", b"hunter2"));
    }

    #[test]
    fn constant_time_eq_rejects_different_content() {
        assert!(!constant_time_eq(b"hunter2", b"hunter3"));
    }

    #[test]
    fn constant_time_eq_rejects_different_length() {
        assert!(!constant_time_eq(b"short", b"longer-token"));
        assert!(!constant_time_eq(b"", b"x"));
    }

    #[test]
    fn extract_bearer_reads_token() {
        let h = headers_with_auth("Bearer my-secret-token");
        assert_eq!(extract_bearer(&h), Some("my-secret-token"));
    }

    #[test]
    fn extract_bearer_is_scheme_case_insensitive() {
        let h = headers_with_auth("bEaReR my-secret-token");
        assert_eq!(extract_bearer(&h), Some("my-secret-token"));
    }

    #[test]
    fn extract_bearer_trims_surrounding_whitespace() {
        let h = headers_with_auth("Bearer   spaced-token  ");
        assert_eq!(extract_bearer(&h), Some("spaced-token"));
    }

    #[test]
    fn extract_bearer_rejects_other_schemes() {
        let h = headers_with_auth("Basic dXNlcjpwYXNz");
        assert_eq!(extract_bearer(&h), None);
    }

    #[test]
    fn extract_bearer_rejects_empty_token() {
        let h = headers_with_auth("Bearer    ");
        assert_eq!(extract_bearer(&h), None);
    }

    #[test]
    fn extract_bearer_absent_header_is_none() {
        let h = HeaderMap::new();
        assert_eq!(extract_bearer(&h), None);
    }

    #[test]
    fn public_observability_bind_without_protection_is_rejected() {
        let addr = "0.0.0.0:4343".parse().expect("socket address");
        let error = validate_observability_exposure(addr, false, None, &RuleSet::default())
            .expect_err("public unprotected metrics must fail");
        assert!(error.to_string().contains("refusing to expose observability"));
    }

    #[test]
    fn loopback_observability_bind_needs_no_extra_gate() {
        for addr in ["127.0.0.1:4343", "[::1]:4343"] {
            validate_observability_exposure(
                addr.parse().expect("socket address"),
                false,
                None,
                &RuleSet::default(),
            )
            .expect("loopback bind");
        }
    }

    #[test]
    fn bearer_or_legacy_allowlist_protects_public_bind() {
        let addr = "0.0.0.0:4343".parse().expect("socket address");
        validate_observability_exposure(addr, true, None, &RuleSet::default())
            .expect("bearer protection");

        let mut rules = RuleSet::default();
        rules.allowed_ips.push("127.0.0.1".to_string());
        validate_observability_exposure(addr, false, None, &rules)
            .expect("legacy allowlist protection");
    }

    #[test]
    fn port_scoped_only_addrs_protects_public_bind() {
        let temp = tempfile::tempdir().expect("tempdir");
        std::fs::write(temp.path().join("metrics.txt"), "127.0.0.1\n")
            .expect("write allowlist");
        std::fs::write(
            temp.path().join("lists.yaml"),
            r"allow:
  - order: 1
    title: Metrics
    log: false
    port: 4343
    only_addrs: metrics.txt
    paths: [/metrics]
",
        )
        .expect("write allow paths");
        let allow_paths =
            AllowPathConfig::from_file(&temp.path().join("lists.yaml"), temp.path())
                .expect("load allow paths");

        validate_observability_exposure(
            "0.0.0.0:4343".parse().expect("socket address"),
            false,
            Some(&allow_paths),
            &RuleSet::default(),
        )
        .expect("port-scoped allowlist protection");
    }
}
