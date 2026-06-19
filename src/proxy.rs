use crate::{
    allowpaths::PathDecision,
    app::AppState,
    body_decode::{decompress_body_for_inspection, parse_content_encoding},
    cli::WafMode,
    error::KrakenError,
    geo::GeoIpResult,
    logging::{write_critical, SecurityEvent},
    multipart_extract::{extract_boundary, parse_parts, MultipartPart},
    waf::{Decision, Finding, InspectionContext, ResponseContext},
};
use anyhow::{Context, Result};
use bytes::{Bytes, BytesMut};
use chrono::Utc;
use http::{
    header::{CONNECTION, COOKIE, HOST, LOCATION, UPGRADE},
    HeaderMap, HeaderName, HeaderValue, Method, Request, Response, StatusCode, Uri,
};
use http_body_util::{combinators::UnsyncBoxBody, BodyExt, Full};
use hyper::{
    body::{Body, Frame, Incoming, SizeHint},
    upgrade,
};
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::{
    client::legacy::{connect::HttpConnector, Client},
    rt::{TokioExecutor, TokioIo},
};
use rustls::{ClientConfig, RootCertStore};
use rustls_pki_types::{pem::PemObject, CertificateDer};
use std::{
    collections::VecDeque,
    convert::Infallible,
    fs::{self, OpenOptions},
    io::Write as _,
    path::Path,
    pin::Pin,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    task::{Context as TaskContext, Poll},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{error, info, warn};
use url::{Host, Url};
use uuid::Uuid;

const PROXY_ERROR_DEV_LOG: &str = "logs/proxy_errors_dev/proxy_errors.jsonl";

/// RAII guard that tracks bytes buffered during body inspection and releases
/// the global + per-IP in-flight byte counters on drop.
struct BodyTracker {
    global: Arc<AtomicUsize>,
    ip: Arc<AtomicUsize>,
    bytes: usize,
}

impl BodyTracker {
    fn new(global: Arc<AtomicUsize>, ip: Arc<AtomicUsize>) -> Self {
        Self {
            global,
            ip,
            bytes: 0,
        }
    }

    /// Atomically reserve `n` bytes against the global and per-IP counters.
    ///
    /// Replaces the previous load-then-add pattern, which was a TOCTOU race:
    /// concurrent requests could each observe the counter below the cap, then
    /// all add, overshooting it. Here each counter is bumped with a single
    /// `fetch_add`; if the post-increment total exceeds its cap the reservation
    /// is rolled back (and the global is rolled back too if the per-IP check
    /// fails after the global one passed). `0` means the corresponding cap is
    /// disabled. Returns `Err(limit)` identifying the cap that was hit.
    fn try_reserve(&mut self, n: usize, global_max: usize, ip_max: usize) -> Result<(), usize> {
        let prev_global = self.global.fetch_add(n, Ordering::Relaxed);
        if global_max > 0 && prev_global.saturating_add(n) > global_max {
            self.global.fetch_sub(n, Ordering::Relaxed);
            return Err(global_max);
        }
        let prev_ip = self.ip.fetch_add(n, Ordering::Relaxed);
        if ip_max > 0 && prev_ip.saturating_add(n) > ip_max {
            self.ip.fetch_sub(n, Ordering::Relaxed);
            self.global.fetch_sub(n, Ordering::Relaxed);
            return Err(ip_max);
        }
        self.bytes += n;
        Ok(())
    }
}

impl Drop for BodyTracker {
    fn drop(&mut self) {
        if self.bytes > 0 {
            self.global.fetch_sub(self.bytes, Ordering::Relaxed);
            self.ip.fetch_sub(self.bytes, Ordering::Relaxed);
        }
    }
}

/// Hard ceiling on the number of headers forwarded upstream and embedded into the
/// inspection prefix. Defends against header-amplification `DoS` and request smuggling
/// surface. Browsers send ~20-30 headers in practice.
const MAX_FORWARDED_HEADERS: usize = 100;

/// Hard ceiling on the cumulative bytes of forwarded headers (name + value sum).
const MAX_FORWARDED_HEADER_BYTES: usize = 32 * 1024;

/// Maximum wall-clock time we wait for a single body frame from the client. Bounds the
/// memory + connection cost of a slowloris-style streaming body that trickles bytes to
/// keep the inspection loop alive indefinitely.
const BODY_FRAME_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

type UpstreamConnector = hyper_rustls::HttpsConnector<HttpConnector>;
type UpstreamClient = Client<UpstreamConnector, Full<Bytes>>;
type BoxError = Box<dyn std::error::Error + Send + Sync>;
pub type WafBody = UnsyncBoxBody<Bytes, BoxError>;
pub type WafResponse = Response<WafBody>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseMode {
    InspectBuffered {
        max_bytes: usize,
    },
    StreamOnly {
        max_bytes: usize,
    },
    TeePrefix {
        inspect_prefix_bytes: usize,
        max_bytes: usize,
    },
}

struct LimitedResponseBody {
    initial: VecDeque<Frame<Bytes>>,
    inner: Pin<Box<Incoming>>,
    seen: usize,
    max_bytes: usize,
    done: bool,
}

impl LimitedResponseBody {
    fn new(
        initial: VecDeque<Frame<Bytes>>,
        inner: Incoming,
        seen: usize,
        max_bytes: usize,
    ) -> Self {
        Self {
            initial,
            inner: Box::pin(inner),
            seen,
            max_bytes,
            done: false,
        }
    }
}

impl Body for LimitedResponseBody {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();
        if this.done {
            return Poll::Ready(None);
        }
        if let Some(frame) = this.initial.pop_front() {
            return Poll::Ready(Some(Ok(frame)));
        }
        match this.inner.as_mut().poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref() {
                    let Some(total) = this.seen.checked_add(data.len()) else {
                        this.done = true;
                        return Poll::Ready(Some(Err(response_limit_error(this.max_bytes))));
                    };
                    if total > this.max_bytes {
                        this.done = true;
                        return Poll::Ready(Some(Err(response_limit_error(this.max_bytes))));
                    }
                    this.seen = total;
                }
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(Some(Err(error))) => {
                this.done = true;
                Poll::Ready(Some(Err(Box::new(error))))
            }
            Poll::Ready(None) => {
                this.done = true;
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.done || (self.initial.is_empty() && self.inner.is_end_stream())
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::default()
    }
}

fn response_limit_error(max_bytes: usize) -> BoxError {
    Box::new(std::io::Error::other(format!(
        "upstream response exceeded streaming limit of {max_bytes} bytes"
    )))
}

pub(crate) fn full_body(bytes: Bytes) -> WafBody {
    Full::new(bytes)
        .map_err(|never: Infallible| match never {})
        .boxed_unsync()
}

fn limited_body(
    initial: VecDeque<Frame<Bytes>>,
    inner: Incoming,
    seen: usize,
    max_bytes: usize,
) -> WafBody {
    LimitedResponseBody::new(initial, inner, seen, max_bytes).boxed_unsync()
}

pub struct ProxyClient {
    client: UpstreamClient,
    upstream: Url,
    upstream_timeout: std::time::Duration,
    internal_header_name: Option<HeaderName>,
}

#[derive(Debug, Clone)]
struct ForwardedOrigin {
    proto: String,
    host: String,
    port: Option<u16>,
}

impl ForwardedOrigin {
    fn from_headers(headers: &HeaderMap, state: &AppState) -> Self {
        let proto = if state.cli.no_tls { "http" } else { "https" }.to_string();
        let host = headers
            .get(HOST)
            .and_then(|value| value.to_str().ok())
            .filter(|value| !value.trim().is_empty())
            .map_or_else(|| state.cli.listen.to_string(), str::to_owned);
        let port = host_port(&host).or_else(|| Some(state.cli.listen.port()));
        Self { proto, host, port }
    }

    fn host_without_port(&self) -> &str {
        let trimmed = self.host.trim();
        if let Some(rest) = trimmed.strip_prefix('[') {
            if let Some((addr, _)) = rest.rsplit_once("]:") {
                return addr;
            }
            return trimmed;
        }
        trimmed.rsplit_once(':').map_or(trimmed, |(host, _)| host)
    }

    fn public_port_for_url(&self) -> Option<u16> {
        let default = (self.proto == "http" && self.port == Some(80))
            || (self.proto == "https" && self.port == Some(443));
        if default {
            None
        } else {
            self.port
        }
    }
}

#[derive(Debug)]
enum BodyInspectionError {
    TooLarge {
        limit: usize,
    },
    Blocked {
        finding: Box<Finding>,
        partial_body: Bytes,
    },
    Timeout,
    Other(anyhow::Error),
}

impl std::fmt::Display for BodyInspectionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooLarge { limit } => {
                write!(f, "request body exceeded route limit of {limit} bytes")
            }
            Self::Blocked { .. } => write!(f, "request blocked during streaming inspection"),
            Self::Timeout => write!(
                f,
                "request body frame did not arrive within {} seconds",
                BODY_FRAME_TIMEOUT.as_secs()
            ),
            Self::Other(err) => write!(f, "{err}"),
        }
    }
}

impl std::error::Error for BodyInspectionError {}

fn build_upstream_client(upstream_ca: Option<&str>) -> Result<UpstreamClient> {
    let tls_config = build_upstream_tls_config(upstream_ca)?;
    let connector = HttpsConnectorBuilder::new()
        .with_tls_config(tls_config)
        .https_or_http()
        .enable_http1()
        .enable_http2()
        .build();
    Ok(Client::builder(TokioExecutor::new()).build(connector))
}

fn build_upstream_tls_config(upstream_ca: Option<&str>) -> Result<ClientConfig> {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    if let Some(ca_path) = upstream_ca {
        let pem = std::fs::read(ca_path)
            .with_context(|| format!("--upstream-ca: failed to read '{ca_path}'"))?;
        let mut added = 0usize;
        for cert in CertificateDer::pem_slice_iter(&pem) {
            let cert = cert.with_context(|| {
                format!("--upstream-ca: '{ca_path}' is not a valid PEM certificate bundle")
            })?;
            roots.add(cert).with_context(|| {
                format!("--upstream-ca: failed to parse certificate in '{ca_path}'")
            })?;
            added += 1;
        }
        anyhow::ensure!(
            added > 0,
            "--upstream-ca: '{ca_path}' contained no certificates"
        );
    }

    Ok(
        ClientConfig::builder_with_provider(rustls::crypto::aws_lc_rs::default_provider().into())
            .with_safe_default_protocol_versions()
            .context("failed to build upstream TLS protocol configuration")?
            .with_root_certificates(roots)
            .with_no_client_auth(),
    )
}

impl ProxyClient {
    /// # Errors
    /// Returns an error if the upstream URL is invalid or the HTTP client cannot be built.
    pub fn new(
        upstream: &str,
        timeout_secs: u64,
        allow_private_upstream: bool,
        internal_header_name: Option<String>,
        upstream_ca: Option<&str>,
    ) -> Result<Self> {
        let upstream =
            Url::parse(upstream).with_context(|| format!("invalid upstream URL: {upstream}"))?;
        validate_upstream(&upstream, allow_private_upstream)?;

        let client = build_upstream_client(upstream_ca)?;

        let internal_header_name = internal_header_name.and_then(|value| {
            if value.trim().is_empty() {
                None
            } else {
                value.parse().ok()
            }
        });

        Ok(Self {
            client,
            upstream,
            upstream_timeout: std::time::Duration::from_secs(timeout_secs),
            internal_header_name,
        })
    }

    /// Handle a request. `client_ip` is the TCP peer address; the effective
    /// client IP (honouring trusted-proxy `Forwarded:` / `X-Forwarded-For` /
    /// `X-Real-IP`) is derived from it in `dispatch` and used as the key for
    /// every per-IP subsystem (rate limit, body-byte backpressure, engine), so
    /// they all share one identity. The peer is retained so the upstream
    /// `X-Forwarded-For` can be sanitised based on whether the peer is trusted.
    pub async fn handle(
        &self,
        state: &AppState,
        req: Request<Incoming>,
        client_ip: String,
    ) -> WafResponse {
        // Generate a compact UUID v4 (32 lowercase hex chars, no hyphens) once per
        // request. Threaded through all log events, SQLite rows, and the upstream
        // X-Request-Id header so a WAF alert can be correlated with upstream access logs.
        let request_id = Uuid::new_v4().simple().to_string();

        // Build or propagate a W3C traceparent.
        // Format: "00-{trace_id_32hex}-{parent_id_16hex}-01"
        // - Incoming valid traceparent → preserve trace-id, generate fresh parent-id span.
        // - No incoming traceparent → generate both trace-id and parent-id from UUID.
        let traceparent = build_traceparent(
            req.headers()
                .get("traceparent")
                .and_then(|v| v.to_str().ok()),
            &state.metrics,
        );

        let started = std::time::Instant::now();
        let mut resp = self
            .dispatch(state, req, client_ip, &request_id, &traceparent)
            .await;
        state
            .metrics
            .observe_latency_ms(u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX));
        // Stamp every response (blocked or forwarded) with the correlation IDs.
        if let Ok(val) = http::header::HeaderValue::from_str(&request_id) {
            resp.headers_mut()
                .insert(http::header::HeaderName::from_static("x-request-id"), val);
        }
        if let Ok(val) = http::header::HeaderValue::from_str(&traceparent) {
            resp.headers_mut()
                .insert(http::header::HeaderName::from_static("traceparent"), val);
        }
        resp
    }

    #[allow(clippy::too_many_lines)]
    async fn dispatch(
        &self,
        state: &AppState,
        mut req: Request<Incoming>,
        client_ip: String,
        request_id: &str,
        traceparent: &str,
    ) -> WafResponse {
        let method = req.method().clone();
        let effective_ip = effective_client_ip(&client_ip, req.headers(), state);
        // The peer is a trusted reverse proxy when its address falls inside a
        // configured trusted-proxy CIDR. This gates whether an inbound
        // `X-Forwarded-For` chain may be preserved when forwarding upstream.
        let peer_is_trusted = client_ip
            .parse::<std::net::IpAddr>()
            .is_ok_and(|peer| state.trusted_proxy_nets.iter().any(|net| net.contains(&peer)));
        let uri = req.uri().clone();
        let path = crate::rules::normalize_url_path(uri.path());
        // Reject oversize header sets BEFORE materialising any flattened representation
        // so an attacker cannot force the WAF to allocate the full string just to learn
        // the request will be denied.
        if exceeds_header_limits(req.headers()) {
            return block_content_response(
                state,
                StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
                "KrakenWaf rejected the request header set",
            );
        }
        let headers_flat = flatten_headers(req.headers());
        // A-2: per-route rule limit is further bounded by the operator-configured hard cap.
        let body_limit = state
            .waf
            .body_limit_for_path(&path)
            .min(state.cli.max_body_bytes);

        let geo = state
            .geo_reader
            .as_ref()
            .map_or_else(GeoIpResult::empty, |r| r.lookup(&effective_ip));

        let context = InspectionContext {
            client_ip: effective_ip.clone(),
            method: method.to_string(),
            uri: uri.to_string(),
            path: path.clone(),
            headers: headers_flat.clone(),
            body_limit,
            request_id: request_id.to_string(),
            country: geo.country_name,
            continent_name: geo.continent_name,
        };

        // Per-IP rate limit — enforced for EVERY request, BEFORE the allow-paths
        // decision and independent of CMC/regex/keyword inspection. An
        // allow-listed path skips signature inspection but must still be
        // rate-limited; otherwise an allow-listed route is an unbounded request
        // sink. Routed through the same finding + `log_and_enforce` path the
        // engine used before, so Block/Silent/DetectOnly semantics, the ban
        // attribution, and the metrics are all unchanged.
        if let Some(finding) = state.waf.rate_limit_finding(&context).await {
            let event = build_event(&context, &finding, None);
            if let Some(response) = self.log_and_enforce(state, event).await {
                return response;
            }
        }

        // Check allow-paths: IP-restricted entries block non-allowed IPs; matched entries
        // without IP restriction skip WAF inspection entirely.
        let (skip_inspection, block_by_ip) = if let Some(config) = &state.allow_path_config {
            match config.check(
                &path,
                &uri.to_string(),
                &effective_ip,
                state.cli.listen.port(),
            ) {
                PathDecision::Allow(entry) => {
                    if entry.log {
                        info!(
                            target: "krakenwaf",
                            uri = %context.uri,
                            title = %entry.title,
                            "allow-paths match: skipping WAF inspection"
                        );
                    }
                    (true, false)
                }
                PathDecision::Block => (false, true),
                PathDecision::NoMatch => (false, false),
            }
        } else {
            (false, false)
        };

        if block_by_ip {
            return block_content_response(
                state,
                StatusCode::FORBIDDEN,
                "Access denied by KrakenWaf IP restriction",
            );
        }

        if !skip_inspection {
            match state.waf.inspect_early(&context).await {
                Decision::Allow | Decision::Monitor(_) | Decision::SilentReplace { .. } => {}
                Decision::Block(finding) => {
                    let event = build_event(&context, &finding, None);
                    if let Some(response) = self.log_and_enforce(state, event).await {
                        return response;
                    }
                }
            }
        }

        if is_websocket_upgrade(req.headers()) {
            // ── WebSocket control policy (conf/websocket.yaml) ────────────────
            // When enable_ws_control is true the handshake is subject to the
            // path allow-list, optional handshake inspection, and the per-IP
            // simultaneous-session cap *before* any upstream tunnel is opened.
            // The acquired guard is threaded into the tunnel task so the per-IP
            // counter is released exactly when the session ends.
            let ws = &state.ws_control;
            let ws_guard = if ws.enabled() {
                if !ws.path_allowed(&path) {
                    warn!(
                        target: "krakenwaf",
                        ip = %effective_ip,
                        path = %path,
                        "websocket upgrade rejected: path not in allowed_paths"
                    );
                    return block_content_response(
                        state,
                        StatusCode::FORBIDDEN,
                        "WebSocket path not permitted by KrakenWaf",
                    );
                }
                if ws.inspect_handshake() && !skip_inspection {
                    let handshake = format_request_prefix_bytes(&context);
                    if let Decision::Block(finding) = state
                        .waf
                        .inspect_complete_payload_with_context(&handshake, Some(&context.method))
                    {
                        let event = build_event(&context, &finding, None);
                        if let Some(response) = self.log_and_enforce(state, event).await {
                            return response;
                        }
                    }
                }
                let Some(guard) = ws.try_acquire(&effective_ip) else {
                    warn!(
                        target: "krakenwaf",
                        ip = %effective_ip,
                        limit = ws.config().max_connections_per_ip,
                        "websocket upgrade rejected: per-IP session cap reached"
                    );
                    state.metrics.inc_rate_limit_hits();
                    let mut resp = plain_response(
                        StatusCode::TOO_MANY_REQUESTS,
                        "Too many simultaneous WebSocket sessions from this IP address",
                    );
                    resp.headers_mut()
                        .insert("Retry-After", HeaderValue::from_static("5"));
                    apply_response_policy(state, &mut resp);
                    return resp;
                };
                Some(guard)
            } else {
                None
            };

            let forwarded_origin = ForwardedOrigin::from_headers(req.headers(), state);
            return self
                .handle_websocket_upgrade(
                    state,
                    req,
                    request_id,
                    traceparent,
                    &forwarded_origin,
                    ws_guard,
                )
                .await;
        }

        // Single body pipeline: buffer the body (with backpressure accounting
        // keyed on the effective client IP), then — unless this is an
        // allow-listed path — decode any `Content-Encoding`, and run multipart,
        // HPP, Open-Redirect/RFI and the full-request signature inspection
        // **once** on the decoded view. Allow-listed paths skip all inspection
        // here (they already returned before `inspect_early`), so they no longer
        // pay the cost of an inspection whose verdict was discarded.
        let body_bytes = match consume_and_inspect_body(
            state,
            &context,
            req.body_mut(),
            &effective_ip,
            skip_inspection,
        )
        .await
        {
            Ok(bytes) => bytes,
            Err(BodyInspectionError::TooLarge { limit: _ }) => {
                return block_content_response(
                    state,
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "KrakenWaf blocked the request body",
                );
            }
            Err(BodyInspectionError::Blocked {
                finding,
                partial_body,
            }) => {
                // `consume_and_inspect_body` only inspects when `!skip_inspection`,
                // so a `Blocked` outcome always warrants enforcement.
                let event = build_event(&context, &finding, Some(&partial_body));
                if let Some(response) = self.log_and_enforce(state, event).await {
                    return response;
                }
                // Silent / DetectOnly mode: forward whatever body was accumulated.
                partial_body
            }
            Err(BodyInspectionError::Timeout) => {
                return block_content_response(
                    state,
                    StatusCode::REQUEST_TIMEOUT,
                    "KrakenWaf timed out waiting for the request body",
                );
            }
            Err(BodyInspectionError::Other(err)) => {
                warn!(target: "krakenwaf", error=%err, method=%context.method, uri=%context.uri, fullpath_evidence=%context.uri, "body inspection failed");
                write_proxy_critical(
                    "dispatch",
                    "body_inspection_failed",
                    "request body could not be inspected; rejected with 400",
                    &serde_json::json!({
                        "request_id": context.request_id,
                        "method": context.method,
                        "uri": context.uri,
                        "error": err.to_string(),
                    }),
                );
                return block_content_response(
                    state,
                    StatusCode::BAD_REQUEST,
                    "KrakenWaf could not inspect the request body",
                );
            }
        };

        let forwarded_origin = ForwardedOrigin::from_headers(req.headers(), state);

        match self
            .forward_request(
                state,
                method,
                uri,
                req.headers(),
                body_bytes,
                request_id,
                traceparent,
                &forwarded_origin,
                &effective_ip,
                peer_is_trusted,
            )
            .await
        {
            Ok(response) => response,
            Err(err) => {
                error!(target: "krakenwaf", "upstream proxy failure: {err:#}");
                write_proxy_critical(
                    "dispatch",
                    "upstream_failure",
                    "upstream request failed; returned 502 to client",
                    &serde_json::json!({
                        "request_id": request_id,
                        "error": format!("{err:#}"),
                    }),
                );
                let mut response =
                    plain_response(StatusCode::BAD_GATEWAY, "KrakenWaf upstream failure");
                apply_response_policy(state, &mut response);
                response
            }
        }
    }

    async fn handle_websocket_upgrade(
        &self,
        state: &AppState,
        mut req: Request<Incoming>,
        request_id: &str,
        traceparent: &str,
        forwarded_origin: &ForwardedOrigin,
        ws_guard: Option<crate::websocket::WsConnGuard>,
    ) -> WafResponse {
        // Resolve the tunnel idle / session bounds from the control policy. When
        // the policy is disabled the tunnel is unbounded (transparent proxy).
        let (idle, max_session) = if state.ws_control.enabled() {
            (
                state.ws_control.config().idle_timeout(),
                state.ws_control.config().max_session(),
            )
        } else {
            (None, None)
        };
        match self
            .open_upstream_websocket(&req, request_id, traceparent, forwarded_origin)
            .await
        {
            Ok((upstream, response, leftover)) => {
                let on_upgrade = upgrade::on(&mut req);
                tokio::spawn(async move {
                    match on_upgrade.await {
                        Ok(upgraded) => {
                            let mut downstream = TokioIo::new(upgraded);
                            let upstream = upstream;
                            if !leftover.is_empty()
                                && downstream.write_all(&leftover).await.is_err()
                            {
                                return;
                            }
                            // Bounded bidirectional pump: closes on idle timeout
                            // or session-lifetime cap; `ws_guard` releases the
                            // per-IP session slot when the tunnel ends.
                            crate::websocket::tunnel(
                                downstream,
                                upstream,
                                idle,
                                max_session,
                                ws_guard,
                            )
                            .await;
                        }
                        Err(err) => {
                            warn!(target: "krakenwaf", error=%err, "websocket client upgrade failed");
                        }
                    }
                });

                let mut response = response;
                apply_response_policy(state, &mut response);
                response
            }
            Err(err) => {
                warn!(target: "krakenwaf", error=%err, "websocket upstream upgrade failed");
                let mut response = plain_response(
                    StatusCode::BAD_GATEWAY,
                    "KrakenWaf websocket upstream failure",
                );
                apply_response_policy(state, &mut response);
                response
            }
        }
    }

    async fn open_upstream_websocket(
        &self,
        req: &Request<Incoming>,
        request_id: &str,
        traceparent: &str,
        forwarded_origin: &ForwardedOrigin,
    ) -> Result<(tokio::net::TcpStream, WafResponse, Bytes)> {
        anyhow::ensure!(
            self.upstream.scheme() == "http",
            "websocket tunneling currently supports http:// upstreams"
        );

        let host = self
            .upstream
            .host_str()
            .ok_or_else(|| anyhow::anyhow!("upstream host is missing"))?;
        let port = self
            .upstream
            .port_or_known_default()
            .ok_or_else(|| anyhow::anyhow!("upstream port is missing"))?;
        let mut stream = tokio::net::TcpStream::connect((host, port)).await?;

        let request = build_upstream_websocket_request(
            &self.upstream,
            req,
            request_id,
            traceparent,
            forwarded_origin,
        )?;
        stream.write_all(&request).await?;

        let (response, leftover) = read_upstream_websocket_response(&mut stream).await?;
        Ok((stream, response, leftover))
    }

    /// Log the detection event and, in `Block` mode, return a 403 response.
    /// Returns `None` in `Silent` or `DetectOnly` mode so the caller continues forwarding.
    #[allow(clippy::unused_async)]
    async fn log_and_enforce(&self, state: &AppState, event: SecurityEvent) -> Option<WafResponse> {
        state.metrics.inc_blocked();
        // Per-engine:module counter derived from the security event label.
        let module_label = derive_module_label(&event.engine, &event.rule_match);
        state.metrics.inc_blocked_by_label(&module_label);

        info!(
            target: "krakenwaf",
            request_id=%event.request_id,
            rule_id=%event.rule_id,
            title=%event.title,
            severity=%event.severity,
            cwe=%event.cwe,
            engine=%event.engine,
            ip=%event.client_ip,
            method=%event.method,
            uri=%event.uri,
            fullpath_evidence=%event.fullpath_evidence,
            rule=%event.rule_match,
            rule_source=%event.rule_line_match,
            reference_url=%event.reference_url,
            mode=?state.mode,
            "request detected"
        );
        write_critical(&state.logging, &event);

        // Feed the BAN-list manager *before* we move `event` into the
        // SQLite queue. Counting only happens when the WAF is going to
        // actually return 403 (Block mode); Silent / DetectOnly are
        // observe-only modes and must not poison the ban list.
        if state.mode == crate::cli::WafMode::Block && state.ban_manager.enabled() {
            let reason = derive_block_reason(&event);
            let ip = event.client_ip.clone();
            let manager = state.ban_manager.clone();
            // Spawn so we never delay the response on a slow Redis call.
            // The outcome is interesting for the structured log only; the
            // actual ban (if newly triggered) becomes effective on the
            // *next* request from this IP — by which point the BAN-list
            // check at the server layer will short-circuit it.
            tokio::spawn(async move {
                let _ = manager.record_block(&ip, reason).await;
            });
        }

        state.store.enqueue(event);

        if state.mode == WafMode::Silent || state.mode == WafMode::DetectOnly {
            return None;
        }

        Some(block_content_response(
            state,
            StatusCode::FORBIDDEN,
            "Blocked by KrakenWaf",
        ))
    }

    #[allow(clippy::too_many_lines, clippy::too_many_arguments)]
    async fn forward_request(
        &self,
        state: &AppState,
        method: Method,
        uri: Uri,
        headers: &HeaderMap,
        body: Bytes,
        request_id: &str,
        traceparent: &str,
        forwarded_origin: &ForwardedOrigin,
        effective_ip: &str,
        peer_is_trusted: bool,
    ) -> Result<WafResponse> {
        // Build the upstream URL by overlaying ONLY the request path and query on top of the
        // configured upstream. Never `Url::join` an attacker-controlled string: an absolute-form
        // request URI (RFC 7230 §5.3.2) such as `http://attacker.tld/x` would otherwise
        // *replace* the upstream base entirely (SSRF / upstream hijack).
        let target = build_upstream_target(&self.upstream, &uri);
        let method_str = method.as_str().to_string();
        let target_uri: Uri = target
            .as_str()
            .parse()
            .with_context(|| format!("failed to build upstream URI from {target}"))?;
        let mut request_builder = Request::builder().method(method).uri(target_uri);

        // RFC 9110 §7.6.1 / RFC 7230 §6.1: every token listed in Connection:
        // is hop-by-hop and must be removed before forwarding.
        let connection_hop = connection_listed_headers(headers);

        let mut forwarded_count: usize = 0;
        let mut forwarded_bytes: usize = 0;
        let cookie_header = combine_request_cookie_headers(headers);
        for (name, value) in headers {
            // `x-forwarded-for` is always dropped here and re-emitted below as a
            // sanitised value. An inbound RFC 7239 `Forwarded:` header is dropped
            // when the peer is NOT a trusted proxy, since a direct client could
            // otherwise spoof a proxy chain the backend would trust.
            let is_xff = name.as_str().eq_ignore_ascii_case("x-forwarded-for");
            let is_forwarded = name.as_str().eq_ignore_ascii_case("forwarded");
            if is_hop_by_hop(name)
                || name == HOST
                || name == COOKIE
                || is_xff
                || (is_forwarded && !peer_is_trusted)
                || connection_hop.iter().any(|hop| hop == name)
            {
                continue;
            }
            forwarded_count += 1;
            forwarded_bytes += name.as_str().len() + value.as_bytes().len();
            if forwarded_count > MAX_FORWARDED_HEADERS
                || forwarded_bytes > MAX_FORWARDED_HEADER_BYTES
            {
                anyhow::bail!(
                    "request rejected: forwarded headers exceed limits (count<={MAX_FORWARDED_HEADERS}, bytes<={MAX_FORWARDED_HEADER_BYTES})"
                );
            }
            request_builder = request_builder.header(name, value);
        }
        if let Some(cookie_header) = cookie_header {
            forwarded_count += 1;
            forwarded_bytes += COOKIE.as_str().len() + cookie_header.as_bytes().len();
            if forwarded_count > MAX_FORWARDED_HEADERS
                || forwarded_bytes > MAX_FORWARDED_HEADER_BYTES
            {
                anyhow::bail!(
                    "request rejected: forwarded headers exceed limits (count<={MAX_FORWARDED_HEADERS}, bytes<={MAX_FORWARDED_HEADER_BYTES})"
                );
            }
            request_builder = request_builder.header(COOKIE, cookie_header);
        }

        request_builder =
            request_builder.header("x-forwarded-proto", forwarded_origin.proto.as_str());
        request_builder =
            request_builder.header("x-forwarded-host", forwarded_origin.host.as_str());
        if let Some(port) = forwarded_origin.port {
            request_builder = request_builder.header("x-forwarded-port", port.to_string());
        }
        // Sanitised `X-Forwarded-For`: a trusted-proxy chain is preserved and the
        // effective client IP appended; an untrusted (direct) client's spoofed
        // chain is discarded and replaced with the effective IP alone.
        if let Some(xff) = build_forwarded_for(headers, effective_ip, peer_is_trusted) {
            forwarded_count += 1;
            forwarded_bytes += "x-forwarded-for".len() + xff.as_bytes().len();
            if forwarded_count > MAX_FORWARDED_HEADERS || forwarded_bytes > MAX_FORWARDED_HEADER_BYTES
            {
                anyhow::bail!(
                    "request rejected: forwarded headers exceed limits (count<={MAX_FORWARDED_HEADERS}, bytes<={MAX_FORWARDED_HEADER_BYTES})"
                );
            }
            request_builder = request_builder.header("x-forwarded-for", xff);
        }
        request_builder = request_builder.header("x-request-id", request_id);
        request_builder = request_builder.header("traceparent", traceparent);
        if let Some(header_name) = &self.internal_header_name {
            request_builder = request_builder.header(header_name, "1");
        }

        let request = request_builder
            .body(Full::new(body))
            .map_err(|err| KrakenError::Upstream(err.to_string()))?;

        let response = tokio::time::timeout(self.upstream_timeout, self.client.request(request))
            .await
            .map_err(|_| KrakenError::Upstream("upstream request timed out".to_string()))?
            .map_err(|err| KrakenError::Upstream(err.to_string()))?;

        let status = response.status();
        let mut response_builder = Response::builder().status(status);
        for (name, value) in response.headers() {
            if !is_hop_by_hop(name) {
                if name == LOCATION {
                    let value = rewrite_upstream_location(value, &self.upstream, forwarded_origin)
                        .unwrap_or_else(|| value.clone());
                    response_builder = response_builder.header(name, value);
                } else {
                    response_builder = response_builder.header(name, value);
                }
            }
        }
        let resp_headers_map = match response_builder.headers_ref() {
            Some(headers) => headers.clone(),
            None => HeaderMap::new(),
        };
        let mode = response_mode(
            &resp_headers_map,
            state.cli.max_upstream_response_bytes,
            state.memory_limits.max_streamed_response_bytes,
            state.memory_limits.response_inspect_prefix_bytes,
        );
        let advertised_length = content_length(&resp_headers_map);
        let response_body = response.into_body();

        match mode {
            ResponseMode::InspectBuffered { max_bytes } => {
                ensure_advertised_length_within_limit(advertised_length, max_bytes)?;
                let mut body_buf = BytesMut::new();
                let mut response_body = response_body;
                while let Some(frame) = response_body
                    .frame()
                    .await
                    .transpose()
                    .map_err(|err| KrakenError::Upstream(err.to_string()))?
                {
                    if let Some(chunk) = frame.data_ref() {
                        body_buf.extend_from_slice(chunk);
                        if body_buf.len() > max_bytes {
                            anyhow::bail!(
                                "buffered upstream response exceeds limit of {max_bytes} bytes"
                            );
                        }
                    }
                }
                let mut bytes = body_buf.freeze();
                if let Some(response) = self
                    .inspect_upstream_response(
                        state,
                        status,
                        &resp_headers_map,
                        &mut response_builder,
                        &mut bytes,
                        true,
                        &method_str,
                        &uri,
                        request_id,
                    )
                    .await
                {
                    return Ok(response);
                }
                let mut built = response_builder.body(full_body(bytes)).map_err(|err| {
                    anyhow::anyhow!("failed to assemble upstream response: {err}")
                })?;
                apply_response_policy(state, &mut built);
                Ok(built)
            }
            ResponseMode::StreamOnly { max_bytes } => {
                ensure_advertised_length_within_limit(advertised_length, max_bytes)?;
                let mut empty = Bytes::new();
                if let Some(response) = self
                    .inspect_upstream_response(
                        state,
                        status,
                        &resp_headers_map,
                        &mut response_builder,
                        &mut empty,
                        false,
                        &method_str,
                        &uri,
                        request_id,
                    )
                    .await
                {
                    return Ok(response);
                }
                let mut built = response_builder
                    .body(limited_body(VecDeque::new(), response_body, 0, max_bytes))
                    .map_err(|err| {
                        anyhow::anyhow!("failed to assemble upstream response: {err}")
                    })?;
                apply_response_policy(state, &mut built);
                Ok(built)
            }
            ResponseMode::TeePrefix {
                inspect_prefix_bytes,
                max_bytes,
            } => {
                ensure_advertised_length_within_limit(advertised_length, max_bytes)?;
                let (mut prefix, remainder, response_body, seen) =
                    read_response_prefix(response_body, inspect_prefix_bytes, max_bytes).await?;
                let original_prefix_len = prefix.len();
                if let Some(response) = self
                    .inspect_upstream_response(
                        state,
                        status,
                        &resp_headers_map,
                        &mut response_builder,
                        &mut prefix,
                        false,
                        &method_str,
                        &uri,
                        request_id,
                    )
                    .await
                {
                    return Ok(response);
                }
                adjust_streaming_content_length(
                    &mut response_builder,
                    advertised_length,
                    original_prefix_len,
                    prefix.len(),
                );
                let mut initial = VecDeque::with_capacity(remainder.len() + 1);
                if !prefix.is_empty() {
                    initial.push_back(Frame::data(prefix));
                }
                initial.extend(remainder);
                let mut built = response_builder
                    .body(limited_body(initial, response_body, seen, max_bytes))
                    .map_err(|err| {
                        anyhow::anyhow!("failed to assemble upstream response: {err}")
                    })?;
                apply_response_policy(state, &mut built);
                Ok(built)
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn inspect_upstream_response(
        &self,
        state: &AppState,
        status: StatusCode,
        response_headers: &HeaderMap,
        response_builder: &mut http::response::Builder,
        bytes: &mut Bytes,
        complete_body: bool,
        method: &str,
        uri: &Uri,
        request_id: &str,
    ) -> Option<WafResponse> {
        let resp_ctx = ResponseContext {
            status: status.as_u16(),
            headers: flatten_headers(response_headers),
            body: bytes.clone(),
        };
        match state.waf.inspect_response(&resp_ctx) {
            Decision::Block(finding) => {
                let event = build_response_event(&finding, method, uri, request_id);
                if let Some(response) = self.log_and_enforce(state, event).await {
                    return Some(response);
                }
            }
            Decision::Monitor(finding) => {
                // Log to all security outputs but forward the upstream response.
                let event = build_response_event(&finding, method, uri, request_id);
                info!(
                    target: "krakenwaf",
                    request_id=%event.request_id,
                    rule_id=%event.rule_id,
                    title=%event.title,
                    severity=%event.severity,
                    cwe=%event.cwe,
                    engine=%event.engine,
                    method=%event.method,
                    uri=%event.uri,
                    rule=%event.rule_match,
                    mode="monitor",
                    "response finding — log only (untrust_level < 60)"
                );
                write_critical(&state.logging, &event);
                state.store.enqueue(event);
                // Do NOT block — fall through and return the upstream response.
            }
            Decision::SilentReplace {
                finding,
                body: modified,
            } => {
                // Log finding (low severity by construction) to ALL outputs.
                let event = build_response_event(&finding, method, uri, request_id);
                info!(
                    target: "krakenwaf",
                    request_id=%event.request_id,
                    rule_id=%event.rule_id,
                    title=%event.title,
                    severity=%event.severity,
                    cwe=%event.cwe,
                    engine=%event.engine,
                    method=%event.method,
                    uri=%event.uri,
                    rule=%event.rule_match,
                    mode="silent-replace",
                    original_len=bytes.len(),
                    scrubbed_len=modified.len(),
                    "response DBMS error fingerprint scrubbed (untrust_level < 80)"
                );
                write_critical(&state.logging, &event);
                state.store.enqueue(event);
                *bytes = modified;
                if complete_body {
                    if let Some(headers) = response_builder.headers_mut() {
                        if let Ok(value) = HeaderValue::from_str(&bytes.len().to_string()) {
                            headers.insert(http::header::CONTENT_LENGTH, value);
                        }
                    }
                }
            }
            Decision::Allow => {}
        }
        None
    }
}

/// Buffer the request body up to `ctx.body_limit`, then inspect it **once**.
///
/// 2.24.0 collapses the previous chunk-by-chunk inspection loop. The old model
/// ran every detection engine on every overlap-prefixed window, turning a
/// 100 MiB body into 12 500 redundant passes over the same payload — an
/// amplification-vector that this refactor closes. The new shape is:
///
/// 1. Read frames until EOF or `body_limit` is exceeded (frame-level
///    `BODY_FRAME_TIMEOUT` still guards against slowloris).
/// 2. Apply `Content-Encoding` decoders (gzip / br / deflate / zstd) with
///    a zip-bomb expansion-ratio guard.
/// 3. If `Content-Type` is `multipart/form-data`, inspect each text part plus
///    every part's metadata. Binary file bodies are excluded from textual
///    matching to avoid random image/video bytes firing string rules.
/// 4. Run a single inspection pass on the (possibly decoded) textual view.
///
/// The function returns the **original** (still-compressed) bytes — the
/// upstream sees what the client sent. The decoded view is used only for
/// inspection.
/// Reads frames from `body` into a contiguous buffer, enforcing per-request,
/// global-inflight, and per-IP size limits, plus a per-frame timeout.
/// The RAII `BodyTracker` releases both counters on return in all paths.
async fn accumulate_body_frames(
    state: &AppState,
    ctx: &InspectionContext,
    body: &mut Incoming,
    client_ip: &str,
) -> std::result::Result<Bytes, BodyInspectionError> {
    let ip_counter: Arc<AtomicUsize> = state
        .ip_body_bytes
        .entry(client_ip.to_string())
        .or_insert_with(|| Arc::new(AtomicUsize::new(0)))
        .clone();
    let mut tracker = BodyTracker::new(Arc::clone(&state.inflight_body_bytes), ip_counter);
    let frame_timeout = if state.body_frame_timeout_secs > 0 {
        std::time::Duration::from_secs(state.body_frame_timeout_secs)
    } else {
        BODY_FRAME_TIMEOUT
    };
    let mut acc = BytesMut::new();
    loop {
        let frame = match tokio::time::timeout(frame_timeout, body.frame()).await {
            Ok(Some(frame)) => frame.map_err(|err| BodyInspectionError::Other(err.into()))?,
            Ok(None) => break,
            Err(_) => return Err(BodyInspectionError::Timeout),
        };
        if let Some(chunk) = frame.data_ref() {
            // Per-request cap: this loop owns `acc`, so a plain check is race-free.
            if acc.len() + chunk.len() > ctx.body_limit {
                return Err(BodyInspectionError::TooLarge {
                    limit: ctx.body_limit,
                });
            }
            // Global + per-IP caps: reserve atomically so concurrent requests
            // cannot each pass a stale read and collectively overshoot the cap.
            tracker
                .try_reserve(
                    chunk.len(),
                    state.max_inflight_body_bytes,
                    state.max_per_ip_body_bytes,
                )
                .map_err(|limit| BodyInspectionError::TooLarge { limit })?;
            acc.extend_from_slice(chunk);
        }
    }
    Ok(acc.freeze())
}

async fn consume_and_inspect_body(
    state: &AppState,
    ctx: &InspectionContext,
    body: &mut Incoming,
    client_ip: &str,
    skip_inspection: bool,
) -> std::result::Result<Bytes, BodyInspectionError> {
    let raw_body = accumulate_body_frames(state, ctx, body, client_ip).await?;
    // Allow-listed paths buffered the body for backpressure accounting only.
    if skip_inspection {
        return Ok(raw_body);
    }

    // Decode `Content-Encoding` only when there are bytes to decode; an empty
    // body still flows through `inspect_decoded_body` so query-string HPP /
    // Open-Redirect-RFI run for bodyless (GET) requests.
    let decoded_body = if raw_body.is_empty() {
        raw_body.clone()
    } else {
        let decoded = decode_body_for_inspection(state, ctx, &raw_body)?;
        inspect_multipart_parts(state, ctx, &decoded, &raw_body)?;
        decoded
    };
    inspect_decoded_body(state, ctx, &decoded_body, raw_body)
}

fn decode_body_for_inspection(
    state: &AppState,
    ctx: &InspectionContext,
    raw_body: &Bytes,
) -> std::result::Result<Bytes, BodyInspectionError> {
    let encodings = match ctx_header(ctx, "content-encoding") {
        Some(v) => parse_content_encoding(&v),
        None => Vec::new(),
    };
    if encodings.is_empty() {
        return Ok(raw_body.clone());
    }

    decompress_body_for_inspection(
        raw_body,
        &encodings,
        ctx.body_limit,
        state.memory_limits.max_decompress_ratio,
    )
    .map_err(|err| {
        tracing::warn!(
            target: "krakenwaf",
            request_id = %ctx.request_id,
            error = %err,
            "request body decompression failed; rejecting"
        );
        BodyInspectionError::Other(anyhow::anyhow!("body decompression rejected: {err}"))
    })
}

fn inspect_multipart_parts(
    state: &AppState,
    ctx: &InspectionContext,
    decoded_body: &Bytes,
    raw_body: &Bytes,
) -> std::result::Result<(), BodyInspectionError> {
    // Multipart extraction: scan each part's inspectable view independently.
    if let Some(ct) = ctx_header(ctx, "content-type") {
        if let Some(boundary) = extract_boundary(&ct) {
            let parts = parse_parts(decoded_body, &boundary);
            for part in &parts {
                let part_view = multipart_part_for_text_inspection(part);
                if part_view.is_empty() {
                    continue;
                }
                let part_payload = format_full_request_bytes(ctx, Some(&part_view));
                match state
                    .waf
                    .inspect_complete_payload_with_context(&part_payload, Some(&ctx.method))
                {
                    Decision::Allow | Decision::Monitor(_) | Decision::SilentReplace { .. } => {}
                    Decision::Block(finding) => {
                        return Err(BodyInspectionError::Blocked {
                            finding,
                            partial_body: raw_body.clone(),
                        });
                    }
                }
            }
        }
    }
    Ok(())
}

fn inspect_decoded_body(
    state: &AppState,
    ctx: &InspectionContext,
    decoded_body: &Bytes,
    raw_body: Bytes,
) -> std::result::Result<Bytes, BodyInspectionError> {
    let body_for_inspection = request_body_for_text_inspection(ctx, decoded_body);

    // HPP and Open-Redirect/RFI inspect the query string AND the *decoded* body
    // text. Running them on the decoded view closes the evasion where a
    // `Content-Encoding: gzip|br|deflate|zstd` wrapper hid a duplicated
    // parameter or a hot redirect/inclusion value from these CMC modules. The
    // query is always inspected, so bodyless GET requests are still covered.
    let query = ctx.uri.split_once('?').map_or("", |(_, q)| q);
    let body_text = String::from_utf8_lossy(&body_for_inspection);
    if let Decision::Block(finding) = state.waf.inspect_hpp(query, &body_text) {
        return Err(BodyInspectionError::Blocked {
            finding,
            partial_body: raw_body,
        });
    }
    if let Decision::Block(finding) = state.waf.inspect_open_redirect_rfi(query, &body_text) {
        return Err(BodyInspectionError::Blocked {
            finding,
            partial_body: raw_body,
        });
    }
    drop(body_text);

    // The full-request signature pass is only meaningful when there is a body:
    // the bodyless request prefix was already inspected by `inspect_early`, so
    // re-running it here would double-inspect every request.
    if body_for_inspection.is_empty() {
        return Ok(raw_body);
    }
    let full = format_full_request_bytes(ctx, Some(&body_for_inspection));
    match state
        .waf
        .inspect_complete_payload_with_context(&full, Some(&ctx.method))
    {
        Decision::Allow | Decision::Monitor(_) | Decision::SilentReplace { .. } => Ok(raw_body),
        Decision::Block(finding) => Err(BodyInspectionError::Blocked {
            finding,
            partial_body: raw_body,
        }),
    }
}

/// Convenience accessor used only by `consume_and_inspect_body` to pull a
/// header value out of the flattened headers stored on the context.
/// The flattened representation is one `Name: value` per line.
fn ctx_header(ctx: &InspectionContext, target: &str) -> Option<String> {
    for line in ctx.headers.lines() {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.trim().eq_ignore_ascii_case(target) {
            return Some(value.trim().to_string());
        }
    }
    None
}

fn request_body_for_text_inspection(ctx: &InspectionContext, body: &Bytes) -> Bytes {
    let Some(ct) = ctx_header(ctx, "content-type") else {
        return body.clone();
    };
    let Some(boundary) = extract_boundary(&ct) else {
        return body.clone();
    };
    let parts = parse_parts(body, &boundary);
    if parts.is_empty() {
        return body.clone();
    }

    let mut out = Vec::with_capacity(body.len().min(64 * 1024));
    for part in &parts {
        out.extend_from_slice(&part.headers);
        out.extend_from_slice(b"\n\n");
        if multipart_part_body_should_be_inspected(part) {
            out.extend_from_slice(&part.body);
        }
        out.push(b'\n');
    }
    Bytes::from(out)
}

fn multipart_part_for_text_inspection(part: &MultipartPart) -> Bytes {
    let mut out = Vec::with_capacity(part.headers.len() + part.body.len().min(8 * 1024) + 2);
    out.extend_from_slice(&part.headers);
    out.extend_from_slice(b"\n\n");
    if multipart_part_body_should_be_inspected(part) {
        out.extend_from_slice(&part.body);
    }
    Bytes::from(out)
}

fn multipart_part_body_should_be_inspected(part: &MultipartPart) -> bool {
    if part.body.is_empty() {
        return false;
    }
    if let Some(content_type) = &part.content_type {
        if media_type_is_textual(content_type) {
            return true;
        }
        if media_type_is_binary(content_type) {
            return false;
        }
    }
    looks_like_text(&part.body)
}

fn media_type_is_textual(value: &str) -> bool {
    let media_type = value
        .split(';')
        .next()
        .unwrap_or(value)
        .trim()
        .to_ascii_lowercase();
    media_type.starts_with("text/")
        || media_type == "application/json"
        || media_type == "application/xml"
        || media_type == "application/xhtml+xml"
        || media_type == "application/javascript"
        || media_type == "application/x-javascript"
        || media_type == "application/x-www-form-urlencoded"
        || media_type == "application/yaml"
        || media_type == "application/graphql"
        || media_type.ends_with("+json")
        || media_type.ends_with("+xml")
        || media_type == "image/svg+xml"
}

fn media_type_is_binary(value: &str) -> bool {
    let media_type = value
        .split(';')
        .next()
        .unwrap_or(value)
        .trim()
        .to_ascii_lowercase();
    media_type.starts_with("image/")
        || media_type.starts_with("video/")
        || media_type.starts_with("audio/")
        || media_type == "application/octet-stream"
        || media_type == "application/pdf"
        || media_type == "application/zip"
        || media_type == "application/gzip"
        || media_type == "application/x-7z-compressed"
        || media_type == "application/x-rar-compressed"
}

fn looks_like_text(bytes: &[u8]) -> bool {
    let sample_len = bytes.len().min(4096);
    if sample_len == 0 {
        return false;
    }
    let sample = &bytes[..sample_len];
    if sample.contains(&0) {
        return false;
    }
    let suspicious = sample
        .iter()
        .filter(|&&b| !(b == b'\n' || b == b'\r' || b == b'\t' || (0x20..=0x7e).contains(&b)))
        .count();
    suspicious * 100 <= sample_len * 10
}

fn build_event(ctx: &InspectionContext, finding: &Finding, body: Option<&Bytes>) -> SecurityEvent {
    let request_payload = format_full_request(ctx, body, &finding.request_payload);
    SecurityEvent::from_finding(finding, ctx, request_payload)
}

/// Build a `SecurityEvent` for a **response-phase** finding (rules with
/// `http_action: Response`). The response pipeline has no request
/// `InspectionContext`, so it synthesises a minimal one carrying just the
/// method, URI, and request-id for correlation. Shared by the `Block`,
/// `Monitor`, and `SilentReplace` arms of `inspect_upstream_response`.
fn build_response_event(
    finding: &Finding,
    method: &str,
    uri: &Uri,
    request_id: &str,
) -> SecurityEvent {
    let ctx = InspectionContext {
        client_ip: String::new(),
        method: method.to_string(),
        uri: uri.to_string(),
        path: uri.path().to_string(),
        headers: String::new(),
        body_limit: 0,
        request_id: request_id.to_string(),
        country: String::new(),
        continent_name: String::new(),
    };
    SecurityEvent::from_finding(finding, &ctx, finding.request_payload.clone())
}

pub(crate) fn format_request_prefix_bytes(ctx: &InspectionContext) -> Vec<u8> {
    let mut out =
        Vec::with_capacity(ctx.method.len() + 1 + ctx.uri.len() + 10 + ctx.headers.len() + 4);
    out.extend_from_slice(ctx.method.as_bytes());
    out.push(b' ');
    out.extend_from_slice(ctx.uri.as_bytes());
    out.extend_from_slice(b" HTTP/1.1\n");
    if !ctx.headers.is_empty() {
        out.extend_from_slice(ctx.headers.as_bytes());
        if !ctx.headers.ends_with('\n') {
            out.push(b'\n');
        }
    }
    out.push(b'\n');
    out
}

fn format_full_request_bytes(ctx: &InspectionContext, body: Option<&Bytes>) -> Vec<u8> {
    let mut out = format_request_prefix_bytes(ctx);
    if let Some(bytes) = body {
        out.extend_from_slice(bytes);
    }
    out
}

fn format_full_request(
    ctx: &InspectionContext,
    body: Option<&Bytes>,
    matched_payload: &str,
) -> String {
    let mut out = String::new();
    out.push_str(&ctx.method);
    out.push(' ');
    out.push_str(&ctx.uri);
    out.push_str(" HTTP/1.1\n");
    if !ctx.headers.is_empty() {
        out.push_str(&ctx.headers);
        if !ctx.headers.ends_with('\n') {
            out.push('\n');
        }
    }
    out.push('\n');
    match body {
        Some(bytes) if !bytes.is_empty() => out.push_str(&String::from_utf8_lossy(bytes)),
        _ if !matched_payload.is_empty() => out.push_str(matched_payload),
        _ => {}
    }
    out
}

/// Parse a single `--trusted-proxy-cidrs` / `proxy.yaml` entry. Accepts either
/// CIDR notation (`10.0.0.0/8`, `2001:db8::/32`) or a bare IP literal
/// (`192.0.2.1`, treated as a `/32`; `2001:db8::1` as a `/128`). Surrounding
/// whitespace is trimmed.
///
/// # Errors
/// Returns an error when `entry` is neither a valid IP nor a valid CIDR.
pub fn parse_trusted_proxy_cidr(entry: &str) -> Result<ipnet::IpNet> {
    let trimmed = entry.trim();
    if let Ok(net) = trimmed.parse::<ipnet::IpNet>() {
        return Ok(net);
    }
    let ip = trimmed.parse::<std::net::IpAddr>().map_err(|_| {
        anyhow::anyhow!(
            "'{entry}' is not a valid IP address or CIDR (e.g. 10.0.0.0/8 or 192.0.2.1)"
        )
    })?;
    let prefix = if ip.is_ipv4() { 32 } else { 128 };
    ipnet::IpNet::new(ip, prefix)
        .with_context(|| format!("failed to build a host network for '{entry}'"))
}

/// Parse every trusted-proxy entry once, failing on the first malformed value.
/// Empty entries are skipped. Done eagerly at startup so a typo fails fast
/// instead of being silently dropped on every request — a dropped entry would
/// make the proxy's own IP look like the client and break rate-limit, ban, and
/// blocklist keying.
///
/// # Errors
/// Returns an error if any entry is neither a valid IP nor a valid CIDR.
pub fn parse_trusted_proxy_cidrs(entries: &[String]) -> Result<Vec<ipnet::IpNet>> {
    entries
        .iter()
        .map(|entry| entry.trim())
        .filter(|entry| !entry.is_empty())
        .map(parse_trusted_proxy_cidr)
        .collect()
}

#[cfg(test)]
mod trusted_proxy_cidr_tests {
    use super::{parse_trusted_proxy_cidr, parse_trusted_proxy_cidrs};

    #[test]
    fn accepts_cidr_and_bare_ip() {
        // CIDR notation passes through unchanged.
        assert_eq!(
            parse_trusted_proxy_cidr("10.0.0.0/8").expect("cidr").to_string(),
            "10.0.0.0/8"
        );
        // A bare IPv4 becomes a /32 host network.
        assert_eq!(
            parse_trusted_proxy_cidr("192.0.2.1").expect("v4 host").to_string(),
            "192.0.2.1/32"
        );
        // A bare IPv6 becomes a /128 host network.
        assert_eq!(
            parse_trusted_proxy_cidr("2001:db8::1").expect("v6 host").to_string(),
            "2001:db8::1/128"
        );
        // Surrounding whitespace is tolerated.
        assert!(parse_trusted_proxy_cidr("  127.0.0.1/32  ").is_ok());
    }

    #[test]
    fn rejects_malformed_entry() {
        // A typo no longer fails silently — it is a hard error at parse time.
        assert!(parse_trusted_proxy_cidr("999.0.0.0/8").is_err());
        assert!(parse_trusted_proxy_cidr("not-an-ip").is_err());
        assert!(parse_trusted_proxy_cidr("10.0.0.0/40").is_err());
    }

    #[test]
    fn parses_list_skipping_blanks_and_fails_on_first_bad() {
        let nets = parse_trusted_proxy_cidrs(&[
            "127.0.0.1/32".to_string(),
            "  ".to_string(),
            "10.0.0.0/8".to_string(),
        ])
        .expect("all valid");
        assert_eq!(nets.len(), 2, "blank entries are skipped");

        let err = parse_trusted_proxy_cidrs(&[
            "127.0.0.1/32".to_string(),
            "bogus".to_string(),
        ]);
        assert!(err.is_err(), "one malformed entry fails the whole parse");
    }
}

fn validate_upstream(upstream: &Url, allow_private_upstream: bool) -> Result<()> {
    if !matches!(upstream.scheme(), "http" | "https") {
        anyhow::bail!("upstream must use http or https");
    }

    if allow_private_upstream {
        return Ok(());
    }

    if let Some(host) = upstream.host() {
        match host {
            Host::Ipv4(ip) => {
                if ip.is_private() || ip.is_loopback() || ip.is_link_local() || ip.is_unspecified()
                {
                    anyhow::bail!("private or local upstreams require --allow-private-upstream");
                }
            }
            Host::Ipv6(ip) => {
                if ip.is_loopback() || ip.is_unspecified() || ip.is_unique_local() {
                    anyhow::bail!("private or local upstreams require --allow-private-upstream");
                }
            }
            Host::Domain(domain) => {
                // Eager DNS resolution at startup mitigates DNS-rebinding by giving the
                // operator visibility into which IPs the upstream resolves to before any
                // request is forwarded. We do NOT pin the IP at the connection layer;
                // operators that need hard pinning should configure the upstream as an
                // explicit IP literal.
                let port = upstream.port_or_known_default().unwrap_or(0);
                let host_port = format!("{domain}:{port}");
                match std::net::ToSocketAddrs::to_socket_addrs(&host_port.as_str()) {
                    Ok(iter) => {
                        let resolved: Vec<std::net::IpAddr> = iter.map(|sa| sa.ip()).collect();
                        for ip in &resolved {
                            let is_local = match ip {
                                std::net::IpAddr::V4(v4) => {
                                    v4.is_private()
                                        || v4.is_loopback()
                                        || v4.is_link_local()
                                        || v4.is_unspecified()
                                }
                                std::net::IpAddr::V6(v6) => {
                                    v6.is_loopback() || v6.is_unspecified() || v6.is_unique_local()
                                }
                            };
                            if is_local {
                                anyhow::bail!(
                                    "upstream {domain} resolved to private/local address {ip}; \
                                     refuse to start without --allow-private-upstream"
                                );
                            }
                        }
                        info!(
                            target: "krakenwaf",
                            upstream_host = %domain,
                            resolved = ?resolved,
                            "resolved upstream hostname at startup (DNS-rebinding visibility)"
                        );
                    }
                    Err(err) => {
                        warn!(
                            target: "krakenwaf",
                            upstream_host = %domain,
                            error = %err,
                            "failed to resolve upstream hostname at startup; continuing — \
                             the connection layer will retry at request time"
                        );
                    }
                }
            }
        }
    }

    Ok(())
}

/// Returns true when the inbound header set exceeds the configured count or byte limits.
/// Counted with raw `name + value` byte sums so the check does not depend on materialised
/// strings.
fn exceeds_header_limits(headers: &HeaderMap) -> bool {
    let mut count = 0usize;
    let mut bytes = 0usize;
    for (name, value) in headers {
        count += 1;
        bytes += name.as_str().len() + value.as_bytes().len();
        if count > MAX_FORWARDED_HEADERS || bytes > MAX_FORWARDED_HEADER_BYTES {
            return true;
        }
    }
    false
}

fn flatten_headers(headers: &HeaderMap) -> String {
    // Inspection-side: keep raw bytes intact. A binary header value previously
    // collapsed to the literal "<binary>" placeholder, which hid SQLi/XSS
    // payloads encoded in non-UTF-8 form. We now base our inspection string on
    // the value bytes directly (lossy decode preserves every ASCII byte).
    let mut out = String::new();
    let mut count = 0usize;
    let mut total = 0usize;
    for (name, value) in headers {
        count += 1;
        total += name.as_str().len() + value.as_bytes().len();
        if count > MAX_FORWARDED_HEADERS || total > MAX_FORWARDED_HEADER_BYTES {
            out.push_str("\n<truncated: header limit reached>");
            break;
        }
        if !out.is_empty() {
            out.push('\n');
        }
        out.push_str(name.as_str());
        out.push_str(": ");
        // `from_utf8_lossy` keeps every ASCII byte verbatim; non-UTF-8 bytes
        // become U+FFFD. Critically it never drops a payload to "<binary>".
        out.push_str(&String::from_utf8_lossy(value.as_bytes()));
    }
    out
}

/// Build the upstream URL by overlaying the request path and query on top of the
/// configured upstream base URL. Never accepts the user-supplied authority/scheme.
/// Leading `//` segments are collapsed to a single `/` to defeat protocol-relative
/// reinterpretation by downstream HTTP libraries.
fn build_upstream_target(upstream: &Url, uri: &Uri) -> Url {
    let mut target = upstream.clone();
    let raw_path = uri.path();
    let trimmed = raw_path.trim_start_matches('/');
    let safe_path = format!("/{trimmed}");
    target.set_path(&safe_path);
    target.set_query(uri.query());
    target.set_fragment(None);
    target
}

fn host_port(host: &str) -> Option<u16> {
    let trimmed = host.trim();
    if trimmed.is_empty() {
        return None;
    }
    if let Some(rest) = trimmed.strip_prefix('[') {
        let (_, port) = rest.rsplit_once("]:")?;
        return port.parse().ok();
    }
    let (_, port) = trimmed.rsplit_once(':')?;
    port.parse().ok()
}

fn upstream_authority_matches(location: &Url, upstream: &Url) -> bool {
    location.scheme() == upstream.scheme()
        && location.host_str() == upstream.host_str()
        && location.port_or_known_default() == upstream.port_or_known_default()
}

fn rewrite_upstream_location(
    value: &HeaderValue,
    upstream: &Url,
    origin: &ForwardedOrigin,
) -> Option<HeaderValue> {
    let text = value.to_str().ok()?;
    let mut parsed = Url::parse(text).ok()?;
    if !upstream_authority_matches(&parsed, upstream) {
        return None;
    }
    parsed.set_scheme(&origin.proto).ok()?;
    parsed.set_host(Some(origin.host_without_port())).ok()?;
    parsed.set_port(origin.public_port_for_url()).ok()?;
    HeaderValue::from_str(parsed.as_str()).ok()
}

fn is_websocket_upgrade(headers: &HeaderMap) -> bool {
    headers
        .get(UPGRADE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.eq_ignore_ascii_case("websocket"))
        && headers
            .get(CONNECTION)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| {
                value
                    .split(',')
                    .any(|token| token.trim().eq_ignore_ascii_case("upgrade"))
            })
}

fn build_upstream_websocket_request(
    upstream: &Url,
    req: &Request<Incoming>,
    request_id: &str,
    traceparent: &str,
    origin: &ForwardedOrigin,
) -> Result<Vec<u8>> {
    let target = build_upstream_target(upstream, req.uri());
    let path = if let Some(query) = target.query() {
        format!("{}?{}", target.path(), query)
    } else {
        target.path().to_string()
    };

    let authority = target
        .host_str()
        .map(|host| match target.port() {
            Some(port) => format!("{host}:{port}"),
            None => host.to_string(),
        })
        .ok_or_else(|| anyhow::anyhow!("upstream host is missing"))?;

    let mut out = Vec::with_capacity(1024);
    out.extend_from_slice(req.method().as_str().as_bytes());
    out.push(b' ');
    out.extend_from_slice(path.as_bytes());
    out.extend_from_slice(b" HTTP/1.1\r\n");
    out.extend_from_slice(b"Host: ");
    out.extend_from_slice(authority.as_bytes());
    out.extend_from_slice(b"\r\n");

    let connection_hop = connection_listed_headers(req.headers());
    for (name, value) in req.headers() {
        if name == HOST
            || connection_hop
                .iter()
                .any(|hop| hop == name && hop != UPGRADE)
        {
            continue;
        }
        // Defence-in-depth: this request line is serialised by hand into a raw
        // byte buffer, so a header value carrying a bare CR/LF would inject
        // additional headers (or a smuggled request) into the upstream
        // handshake. hyper's HeaderValue rejects CR/LF on construction, but we
        // re-check here so the manual serialiser cannot be the weak link if that
        // invariant ever changes. A value that violates it is dropped.
        if header_value_has_control_break(value.as_bytes()) {
            continue;
        }
        out.extend_from_slice(name.as_str().as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(value.as_bytes());
        out.extend_from_slice(b"\r\n");
    }

    append_header_line(&mut out, "x-forwarded-proto", origin.proto.as_str());
    append_header_line(&mut out, "x-forwarded-host", origin.host.as_str());
    if let Some(port) = origin.port {
        append_header_line(&mut out, "x-forwarded-port", &port.to_string());
    }
    append_header_line(&mut out, "x-request-id", request_id);
    append_header_line(&mut out, "traceparent", traceparent);
    out.extend_from_slice(b"\r\n");
    Ok(out)
}

/// True when `value` contains a raw CR or LF byte. Such a value must never be
/// written into a hand-serialised HTTP header block: it would terminate the
/// current header line early and let the remainder be parsed as a separate
/// header (CRLF / header injection).
fn header_value_has_control_break(value: &[u8]) -> bool {
    value.iter().any(|&b| b == b'\r' || b == b'\n')
}

fn append_header_line(out: &mut Vec<u8>, name: &str, value: &str) {
    out.extend_from_slice(name.as_bytes());
    out.extend_from_slice(b": ");
    out.extend_from_slice(value.as_bytes());
    out.extend_from_slice(b"\r\n");
}

async fn read_upstream_websocket_response(
    stream: &mut tokio::net::TcpStream,
) -> Result<(WafResponse, Bytes)> {
    const MAX_WS_HANDSHAKE_BYTES: usize = 32 * 1024;

    let mut buf = Vec::with_capacity(1024);
    let header_end = loop {
        if buf.len() > MAX_WS_HANDSHAKE_BYTES {
            anyhow::bail!("upstream websocket handshake exceeded {MAX_WS_HANDSHAKE_BYTES} bytes");
        }

        let mut chunk = [0u8; 1024];
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            anyhow::bail!("upstream closed during websocket handshake");
        }
        buf.extend_from_slice(&chunk[..n]);

        if let Some(idx) = find_header_terminator(&buf) {
            break idx;
        }
    };

    let headers = &buf[..header_end];
    let leftover = Bytes::copy_from_slice(&buf[header_end + 4..]);
    let text = std::str::from_utf8(headers)?;
    let mut lines = text.split("\r\n");
    let status_line = lines
        .next()
        .ok_or_else(|| anyhow::anyhow!("upstream websocket response missing status line"))?;
    let status = parse_http_status(status_line)?;
    let mut builder = Response::builder().status(status);

    for line in lines {
        if line.is_empty() {
            continue;
        }
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        builder = builder.header(name.trim(), value.trim());
    }

    let response = builder
        .body(full_body(Bytes::new()))
        .map_err(|err| anyhow::anyhow!("failed to build websocket response: {err}"))?;
    Ok((response, leftover))
}

fn find_header_terminator(bytes: &[u8]) -> Option<usize> {
    bytes.windows(4).position(|window| window == b"\r\n\r\n")
}

fn parse_http_status(status_line: &str) -> Result<StatusCode> {
    let code = status_line
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| anyhow::anyhow!("bad upstream websocket status line: {status_line}"))?
        .parse::<u16>()?;
    StatusCode::from_u16(code)
        .map_err(|err| anyhow::anyhow!("bad upstream websocket status code {code}: {err}"))
}

fn response_mode(
    headers: &HeaderMap,
    buffered_max_bytes: usize,
    streamed_max_bytes: usize,
    inspect_prefix_bytes: usize,
) -> ResponseMode {
    let inspect_prefix_bytes = inspect_prefix_bytes.min(streamed_max_bytes);
    let content_type = headers
        .get(http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(|value| {
            value
                .split(';')
                .next()
                .unwrap_or(value)
                .trim()
                .to_ascii_lowercase()
        });

    let Some(content_type) = content_type else {
        return ResponseMode::TeePrefix {
            inspect_prefix_bytes,
            max_bytes: streamed_max_bytes,
        };
    };

    if content_type.starts_with("text/")
        || content_type == "application/json"
        || content_type.ends_with("+json")
        || content_type == "application/xml"
        || content_type.ends_with("+xml")
        || content_type == "application/xhtml+xml"
        || content_type == "application/javascript"
        || content_type == "application/x-www-form-urlencoded"
        || content_type == "application/yaml"
        || content_type == "application/graphql"
    {
        return ResponseMode::InspectBuffered {
            max_bytes: buffered_max_bytes,
        };
    }

    if content_type.starts_with("image/")
        || content_type.starts_with("video/")
        || content_type.starts_with("audio/")
        || content_type.starts_with("font/")
        || matches!(
            content_type.as_str(),
            "application/pdf"
                | "application/zip"
                | "application/x-zip-compressed"
                | "application/gzip"
                | "application/x-gzip"
                | "application/x-7z-compressed"
                | "application/vnd.rar"
                | "application/x-rar-compressed"
                | "application/wasm"
        )
    {
        return ResponseMode::StreamOnly {
            max_bytes: streamed_max_bytes,
        };
    }

    ResponseMode::TeePrefix {
        inspect_prefix_bytes,
        max_bytes: streamed_max_bytes,
    }
}

#[cfg(test)]
mod response_mode_tests {
    use super::{response_mode, ResponseMode};
    use http::{header::CONTENT_TYPE, HeaderMap, HeaderValue};

    const BUFFERED_MAX: usize = 8 * 1024 * 1024;
    const STREAMED_MAX: usize = 1024 * 1024 * 1024;
    const PREFIX: usize = 64 * 1024;

    fn headers(content_type: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_str(content_type).expect("valid content type"),
        );
        headers
    }

    #[test]
    fn text_and_structured_text_are_buffered_for_complete_inspection() {
        for content_type in [
            "text/html; charset=utf-8",
            "application/json",
            "application/problem+json",
            "application/xml",
        ] {
            assert_eq!(
                response_mode(&headers(content_type), BUFFERED_MAX, STREAMED_MAX, PREFIX),
                ResponseMode::InspectBuffered {
                    max_bytes: BUFFERED_MAX
                },
                "{content_type}"
            );
        }
    }

    #[test]
    fn known_binary_media_are_streamed_without_buffering() {
        for content_type in [
            "image/png",
            "video/mp4",
            "application/pdf",
            "application/zip",
        ] {
            assert_eq!(
                response_mode(&headers(content_type), BUFFERED_MAX, STREAMED_MAX, PREFIX),
                ResponseMode::StreamOnly {
                    max_bytes: STREAMED_MAX
                },
                "{content_type}"
            );
        }
    }

    #[test]
    fn generic_binary_and_missing_content_type_use_prefix_inspection() {
        let expected = ResponseMode::TeePrefix {
            inspect_prefix_bytes: PREFIX,
            max_bytes: STREAMED_MAX,
        };
        assert_eq!(
            response_mode(
                &headers("application/octet-stream"),
                BUFFERED_MAX,
                STREAMED_MAX,
                PREFIX
            ),
            expected
        );
        assert_eq!(
            response_mode(&HeaderMap::new(), BUFFERED_MAX, STREAMED_MAX, PREFIX),
            expected
        );
    }

    #[test]
    fn prefix_never_exceeds_the_total_stream_limit() {
        assert_eq!(
            response_mode(
                &headers("application/octet-stream"),
                BUFFERED_MAX,
                1024,
                PREFIX
            ),
            ResponseMode::TeePrefix {
                inspect_prefix_bytes: 1024,
                max_bytes: 1024
            }
        );
    }
}

fn content_length(headers: &HeaderMap) -> Option<usize> {
    headers
        .get(http::header::CONTENT_LENGTH)?
        .to_str()
        .ok()?
        .parse()
        .ok()
}

fn ensure_advertised_length_within_limit(
    advertised_length: Option<usize>,
    max_bytes: usize,
) -> Result<()> {
    if advertised_length.is_some_and(|length| length > max_bytes) {
        anyhow::bail!("upstream response Content-Length exceeds limit of {max_bytes} bytes");
    }
    Ok(())
}

async fn read_response_prefix(
    mut body: Incoming,
    prefix_limit: usize,
    max_bytes: usize,
) -> Result<(Bytes, VecDeque<Frame<Bytes>>, Incoming, usize)> {
    let mut prefix = BytesMut::with_capacity(prefix_limit.min(64 * 1024));
    let mut remainder = VecDeque::new();
    let mut seen = 0usize;

    while prefix.len() < prefix_limit {
        let Some(frame) = body
            .frame()
            .await
            .transpose()
            .map_err(|error| KrakenError::Upstream(error.to_string()))?
        else {
            break;
        };
        match frame.into_data() {
            Ok(mut chunk) => {
                seen = seen
                    .checked_add(chunk.len())
                    .ok_or_else(|| anyhow::anyhow!("upstream response byte counter overflow"))?;
                if seen > max_bytes {
                    return Err(anyhow::anyhow!(
                        "upstream response exceeded streaming limit of {max_bytes} bytes"
                    ));
                }
                let needed = prefix_limit - prefix.len();
                if chunk.len() <= needed {
                    prefix.extend_from_slice(&chunk);
                } else {
                    let inspected = chunk.split_to(needed);
                    prefix.extend_from_slice(&inspected);
                    remainder.push_back(Frame::data(chunk));
                }
            }
            Err(frame) => {
                remainder.push_back(frame);
                break;
            }
        }
    }

    Ok((prefix.freeze(), remainder, body, seen))
}

fn adjust_streaming_content_length(
    response_builder: &mut http::response::Builder,
    advertised_length: Option<usize>,
    original_prefix_len: usize,
    forwarded_prefix_len: usize,
) {
    if original_prefix_len == forwarded_prefix_len {
        return;
    }
    let Some(headers) = response_builder.headers_mut() else {
        return;
    };
    let Some(original_length) = advertised_length else {
        headers.remove(http::header::CONTENT_LENGTH);
        return;
    };
    let adjusted = original_length
        .saturating_sub(original_prefix_len)
        .saturating_add(forwarded_prefix_len);
    if let Ok(value) = HeaderValue::from_str(&adjusted.to_string()) {
        headers.insert(http::header::CONTENT_LENGTH, value);
    } else {
        headers.remove(http::header::CONTENT_LENGTH);
    }
}

fn is_hop_by_hop(name: &HeaderName) -> bool {
    matches!(
        name.as_str().to_ascii_lowercase().as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailers"
            | "transfer-encoding"
            | "upgrade"
    )
}

/// Collect every header name listed in `Connection:` so the forwarding loop
/// can strip them.
///
/// RFC 9110 §7.6.1 (formerly RFC 7230 §6.1) requires intermediaries to
/// treat any token in the `Connection:` header as hop-by-hop and *delete*
/// it before forwarding the message. The fixed-name list above is not
/// enough on its own: a request like
///
/// ```text
/// Connection: X-Auth-Internal
/// X-Auth-Internal: admin
/// ```
///
/// expects every well-behaved proxy to delete `X-Auth-Internal` before
/// reaching the backend. Without that step a backend that trusts
/// `X-Auth-Internal` for SSO can be smuggled an injected value through any
/// WAF that only knows the fixed list. Added in 2.24.0.
fn connection_listed_headers(headers: &HeaderMap) -> Vec<HeaderName> {
    let mut out = Vec::new();
    for value in headers.get_all(CONNECTION) {
        let Ok(text) = value.to_str() else { continue };
        for raw in text.split(',') {
            let token = raw.trim();
            // Skip the two RFC-defined options that are not header names.
            if token.is_empty()
                || token.eq_ignore_ascii_case("close")
                || token.eq_ignore_ascii_case("keep-alive")
            {
                continue;
            }
            if let Ok(name) = HeaderName::try_from(token) {
                out.push(name);
            }
        }
    }
    out
}

fn combine_request_cookie_headers(headers: &HeaderMap) -> Option<HeaderValue> {
    let mut combined = String::new();
    for value in headers.get_all(COOKIE) {
        let Ok(raw) = value.to_str() else {
            continue;
        };
        let raw = raw.trim();
        if raw.is_empty() {
            continue;
        }
        if !combined.is_empty() {
            combined.push_str("; ");
        }
        combined.push_str(raw);
    }
    if combined.is_empty() {
        return None;
    }
    HeaderValue::from_str(&combined).ok()
}

/// Build the sanitised `X-Forwarded-For` value forwarded upstream.
///
/// * When the peer is a **trusted proxy**, its inbound `X-Forwarded-For` chain
///   is legitimate, so it is preserved and the effective client IP appended
///   (standard reverse-proxy append semantics).
/// * When the peer is **untrusted** (a direct client), any inbound chain is
///   attacker-controlled and is discarded; the value becomes the effective IP
///   alone (which equals the peer in this case).
///
/// Returns `None` only if the resulting value cannot be encoded as a header
/// (e.g. a non-ASCII effective IP, which cannot happen for a parsed `IpAddr`).
fn build_forwarded_for(
    headers: &HeaderMap,
    effective_ip: &str,
    peer_is_trusted: bool,
) -> Option<HeaderValue> {
    let mut chain = String::new();
    if peer_is_trusted {
        for value in headers.get_all("x-forwarded-for") {
            let Ok(raw) = value.to_str() else {
                continue;
            };
            let raw = raw.trim();
            if raw.is_empty() {
                continue;
            }
            if !chain.is_empty() {
                chain.push_str(", ");
            }
            chain.push_str(raw);
        }
    }
    if !chain.is_empty() {
        chain.push_str(", ");
    }
    chain.push_str(effective_ip);
    HeaderValue::from_str(&chain).ok()
}

fn apply_response_policy<B>(state: &AppState, response: &mut Response<B>) {
    let is_websocket_upgrade = response.status() == StatusCode::SWITCHING_PROTOCOLS
        || response.headers().contains_key(UPGRADE)
        || response
            .headers()
            .get(CONNECTION)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.to_ascii_lowercase().contains("upgrade"));
    state
        .response_header_policy
        .apply(response.headers_mut(), is_websocket_upgrade);
}

fn block_content_response(
    state: &AppState,
    status: StatusCode,
    fallback_message: &str,
) -> WafResponse {
    let mut response = if let Some(body) = &state.block_response_body {
        Response::builder()
            .status(status)
            .header("content-type", state.block_response_content_type.as_str())
            .header("x-content-type-options", "nosniff")
            .body(full_body(body.clone()))
            .unwrap_or_else(|_| plain_response(status, fallback_message))
    } else {
        plain_response(status, fallback_message)
    };
    apply_response_policy(state, &mut response);
    response
}

#[must_use]
pub fn plain_response(status: StatusCode, message: &str) -> WafResponse {
    // All header names/values are static literals so the builder cannot actually fail.
    // Falling back to a bare Response::new keeps the request path infallible if the
    // http crate ever tightens its validation.
    Response::builder()
        .status(status)
        .header("content-type", "text/plain; charset=utf-8")
        .header("x-content-type-options", "nosniff")
        .body(full_body(Bytes::copy_from_slice(message.as_bytes())))
        .unwrap_or_else(|_| {
            let mut resp = Response::new(full_body(Bytes::copy_from_slice(message.as_bytes())));
            *resp.status_mut() = status;
            resp
        })
}

fn header_value_case_insensitive(headers: &http::HeaderMap, name: &str) -> Option<String> {
    headers
        .iter()
        .find(|(k, _)| k.as_str().eq_ignore_ascii_case(name))
        .and_then(|(_, v)| v.to_str().ok())
        .map(str::to_owned)
}

#[track_caller]
fn write_proxy_error_dev(
    debug_proxy_dev: bool,
    always_save: bool,
    function: &str,
    code: &str,
    message: &str,
    fields: &serde_json::Value,
) {
    let severity = if always_save { "critical" } else { "diagnostic" };
    if !debug_proxy_dev && !always_save {
        tracing::debug!(
            target: "krakenwaf",
            function,
            code,
            message,
            "diagnostic proxy dev event suppressed; enable debug-proxy-dev to persist it"
        );
        return;
    }

    let location = std::panic::Location::caller();
    let event = serde_json::json!({
        "timestamp": Utc::now().to_rfc3339(),
        "severity": severity,
        "debug_proxy_dev": debug_proxy_dev,
        "function": function,
        "file": location.file(),
        "line": location.line(),
        "code": code,
        "message": message,
        "fields": fields,
    });
    if let Err(err) = append_proxy_error_dev_event(&event) {
        warn!(
            target: "krakenwaf",
            error = %err,
            path = PROXY_ERROR_DEV_LOG,
            function,
            code,
            "failed to write proxy error dev event"
        );
    }
}

fn append_proxy_error_dev_event(event: &serde_json::Value) -> std::io::Result<()> {
    let path = Path::new(PROXY_ERROR_DEV_LOG);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    writeln!(file, "{event}")
}

const PROXY_CRITICAL_LOG: &str = "logs/proxy/critical.jsonl";

/// Persist a critical proxy event to `logs/proxy/critical.jsonl`, creating the
/// directory if it does not exist. Unlike [`write_proxy_error_dev`] (which is
/// gated behind `--debug-proxy-dev`), these events are always persisted: they
/// represent failures that produced an error response to the client (upstream
/// failure, un-inspectable body) and must be auditable even if the tracing sink
/// is unavailable.
fn write_proxy_critical(function: &str, code: &str, message: &str, fields: &serde_json::Value) {
    let event = serde_json::json!({
        "timestamp": Utc::now().to_rfc3339(),
        "severity": "critical",
        "component": "proxy",
        "function": function,
        "code": code,
        "message": message,
        "fields": fields,
    });
    let path = Path::new(PROXY_CRITICAL_LOG);
    let result = (|| -> std::io::Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut file = OpenOptions::new().create(true).append(true).open(path)?;
        writeln!(file, "{event}")
    })();
    if let Err(err) = result {
        warn!(
            target: "krakenwaf",
            error = %err,
            path = PROXY_CRITICAL_LOG,
            function,
            code,
            "failed to persist critical proxy event"
        );
    }
}

/// Parse the RFC 7239 `Forwarded:` header chain and return the rightmost
/// `for=` value whose IP does **not** belong to a trusted proxy CIDR.
///
/// Browsers / users do not send `Forwarded:` directly; only intermediaries
/// do. The rightmost untrusted value is therefore the real client. Returns
/// `None` when the header is absent, malformed, or every value resolves to
/// a trusted hop.
fn forwarded_header_real_ip(
    headers: &http::HeaderMap,
    trusted: &[ipnet::IpNet],
    debug_proxy_dev: bool,
) -> Option<String> {
    use std::net::IpAddr;
    let raw = header_value_case_insensitive(headers, "forwarded")?;
    let elements: Vec<&str> = raw.split(',').collect();
    for element in elements.iter().rev() {
        for kv in element.split(';') {
            let kv = kv.trim();
            let Some((k, v)) = kv.split_once('=') else {
                continue;
            };
            if !k.eq_ignore_ascii_case("for") {
                continue;
            }
            // Allowed forms: `for=192.0.2.1`, `for="192.0.2.1:4711"`,
            // `for="[2001:db8::1]"`, `for="_obfuscated"`.
            let stripped = v.trim().trim_matches('"');
            // Strip an optional port and surrounding `[]` for IPv6.
            let host_only = if let Some(rest) = stripped.strip_prefix('[') {
                let Some((host, _suffix)) = rest.split_once(']') else {
                    write_proxy_error_dev(
                        debug_proxy_dev,
                        false,
                        "forwarded_header_real_ip",
                        "malformed_forwarded_ipv6",
                        "Forwarded for= value starts with '[' but has no closing ']'",
                        &serde_json::json!({
                            "raw_header": raw,
                            "element": element,
                            "value": stripped,
                        }),
                    );
                    continue;
                };
                host
            } else if stripped.matches(':').count() == 1 {
                // `host:port` for IPv4.
                if let Some((host, _port)) = stripped.split_once(':') {
                    host
                } else {
                    stripped
                }
            } else {
                stripped
            };
            let Ok(parsed) = host_only.parse::<IpAddr>() else {
                if !host_only.starts_with('_') {
                    write_proxy_error_dev(
                        debug_proxy_dev,
                        false,
                        "forwarded_header_real_ip",
                        "invalid_forwarded_for_ip",
                        "Forwarded for= value could not be parsed as an IP address",
                        &serde_json::json!({
                            "raw_header": raw,
                            "element": element,
                            "value": stripped,
                            "host_only": host_only,
                        }),
                    );
                }
                continue;
            };
            if !trusted.iter().any(|net| net.contains(&parsed)) {
                return Some(host_only.to_string());
            }
        }
    }
    None
}

pub(crate) fn effective_client_ip(
    peer_ip: &str,
    headers: &http::HeaderMap,
    state: &AppState,
) -> String {
    use std::net::IpAddr;
    let Ok(peer) = peer_ip.parse::<IpAddr>() else {
        return peer_ip.to_string();
    };
    // Trusted-proxy CIDRs are parsed and validated once at startup
    // (see `parse_trusted_proxy_cidrs`), so the request path is a cheap slice
    // scan instead of re-parsing strings — and a malformed entry can no longer
    // be silently dropped here (it fails the process at boot instead).
    let trusted_nets = state.trusted_proxy_nets.as_slice();
    if !trusted_nets.iter().any(|net| net.contains(&peer)) {
        return peer_ip.to_string();
    }

    // RFC 7239 `Forwarded:` header takes precedence when present — modern
    // proxies (HAProxy 2.x, recent nginx with the realip module) emit it
    // instead of `X-Forwarded-For`. We walk the chain right-to-left and pick
    // the first `for=` value whose IP is *not* one of our trusted proxies.
    if let Some(ip) = forwarded_header_real_ip(headers, trusted_nets, state.cli.debug_proxy_dev) {
        return ip;
    }

    let header_name = match state.cli.real_ip_header.as_deref() {
        Some(h) if !h.trim().is_empty() => h.trim(),
        // Even without an explicit --real-ip-header we still honour the
        // de-facto standard `X-Real-IP` if the peer is a trusted proxy.
        _ => "x-real-ip",
    };
    let Some(raw) = header_value_case_insensitive(headers, header_name) else {
        return peer_ip.to_string();
    };
    let candidate = if header_name.eq_ignore_ascii_case("x-forwarded-for") {
        // Rightmost-trusted algorithm (RFC 7239 §5.3): walk right-to-left, skip IPs that
        // belong to a trusted proxy CIDR, and pick the first one that does not. Using the
        // leftmost value (split(',').next()) is client-controlled and trivially bypassable —
        // an attacker can prepend any IP to spoof past blocklist and rate-limit checks.
        raw.split(',')
            .rev()
            .map(str::trim)
            .find(|s| {
                !s.parse::<IpAddr>()
                    .ok()
                    .is_some_and(|ip| trusted_nets.iter().any(|net| net.contains(&ip)))
            })
            .unwrap_or(peer_ip)
            .to_string()
    } else {
        raw.trim().to_string()
    };
    if candidate.parse::<IpAddr>().is_ok() {
        candidate
    } else {
        peer_ip.to_string()
    }
}

/// Build or propagate a W3C traceparent header value.
///
/// Rules:
/// - If the incoming value is present and has a valid 32-hex trace-id in field[1],
///   the trace-id is preserved and a new parent-id span is generated.
/// - Otherwise (absent or malformed) both trace-id and parent-id are freshly
///   generated from UUID v4.
fn build_traceparent(incoming: Option<&str>, metrics: &crate::metrics::WafMetrics) -> String {
    fn new_parent_id() -> String {
        let parent_bytes = *Uuid::new_v4().as_bytes();
        format!(
            "{:016x}",
            u64::from_be_bytes([
                parent_bytes[0],
                parent_bytes[1],
                parent_bytes[2],
                parent_bytes[3],
                parent_bytes[4],
                parent_bytes[5],
                parent_bytes[6],
                parent_bytes[7],
            ])
        )
    }

    if let Some(tp) = incoming {
        let parts: Vec<&str> = tp.splitn(4, '-').collect();
        if parts.len() >= 3
            && parts[1].len() == 32
            && parts[1].chars().all(|c| c.is_ascii_hexdigit())
        {
            let trace_id = parts[1];
            metrics.inc_traceparent_forwarded();
            return format!("00-{trace_id}-{}-01", new_parent_id());
        }
    }
    // No valid incoming — generate fresh traceparent.
    let trace_id = format!("{:032x}", Uuid::new_v4().as_u128());
    metrics.inc_traceparent_generated();
    format!("00-{trace_id}-{}-01", new_parent_id())
}

/// Classify a block event so the BAN-list manager knows whether the
/// `security_scanners` fast-track applies (User-Agent scanner hit) or whether
/// the event must roll into the normal `tolerance_block_count` threshold.
fn derive_block_reason(event: &SecurityEvent) -> crate::banning::BlockReason {
    use crate::banning::BlockReason;

    // Detect_bots_n_scanners CMC module → potential fast-track.
    if event.rule_match.starts_with("cmc::detect_bots_n_scanners") {
        return BlockReason::SecurityScanner;
    }

    // Rate-limit / per-IP concurrency exhaustion.
    if event.rule_match == "rate_limiter"
        || event.rule_match.starts_with("rate_limit")
        || event.rule_line_match == "window_exceeded"
    {
        return BlockReason::RateLimit;
    }

    // IP-reputation blocks (Spamhaus, Firehol, blocklist/allowlist, DQS).
    if event.rule_line_match.starts_with("addr/")
        || event.rule_line_match.starts_with("rules/addr/")
        || event.rule_match.starts_with("Spamhaus")
        || event.title.starts_with("Blocked source IP")
        || event.title.starts_with("Blocked IP range")
        || event.title.starts_with("Spamhaus")
    {
        return BlockReason::IpReputation;
    }

    BlockReason::RuleDetection
}

/// Derive an `"engine:module"` label for the per-module Prometheus counter.
/// For CMC findings the `rule_match` is `"cmc::module_name:..."`, so we extract
/// the module name. For other engines we use a sensible short label.
///
/// Custom regex rules arrive here with an already-enriched engine label of the
/// form `"<title>, ID <id>:Regex rule"` (see `logging::derive_engine_label`),
/// which is forwarded as-is so the metrics identify the exact rule that
/// blocked instead of the old blind `unknown:regex`.
fn derive_module_label(engine: &str, rule_match: &str) -> String {
    if engine == "cmc" {
        // rule_match format: "cmc::sqli_comments_detect:evidence"
        let module = rule_match
            .strip_prefix("cmc::")
            .and_then(|s| s.split(':').next())
            .unwrap_or("unknown");
        format!("cmc:{module}")
    } else if engine == "libinjection" {
        // rule_match format: "libinjection::sqli:fingerprint"
        let variant = rule_match
            .strip_prefix("libinjection::")
            .and_then(|s| s.split(':').next())
            .unwrap_or("unknown");
        format!("libinjection:{variant}")
    } else {
        engine.to_string()
    }
}

#[cfg(test)]
mod module_label_tests {
    use super::derive_module_label;

    #[test]
    fn cmc_label_extracts_module_name() {
        assert_eq!(
            derive_module_label("cmc", "cmc::sqli_comments_detect:evidence"),
            "cmc:sqli_comments_detect"
        );
    }

    #[test]
    fn libinjection_label_extracts_variant() {
        assert_eq!(
            derive_module_label("libinjection", "libinjection::sqli:s&1c"),
            "libinjection:sqli"
        );
    }

    /// The enriched regex engine label ("<title>, ID <id>:Regex rule") must
    /// flow through untouched so the metrics name the exact rule that blocked.
    #[test]
    fn regex_rule_label_passes_through() {
        assert_eq!(
            derive_module_label(
                "Shell downloader body, ID 00003:Regex rule",
                r"(?i)wget\s+https?://"
            ),
            "Shell downloader body, ID 00003:Regex rule"
        );
    }
}

#[cfg(test)]
mod forwarded_for_tests {
    use super::build_forwarded_for;
    use http::{HeaderMap, HeaderValue};

    fn headers_with_xff(values: &[&str]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for v in values {
            headers.append("x-forwarded-for", HeaderValue::from_str(v).expect("valid"));
        }
        headers
    }

    #[test]
    fn untrusted_peer_discards_inbound_chain_and_uses_effective_ip() {
        // A direct (untrusted) client could spoof the chain; it must be dropped
        // and replaced with the effective IP alone.
        let headers = headers_with_xff(&["1.1.1.1", "2.2.2.2"]);
        let xff = build_forwarded_for(&headers, "203.0.113.7", false).expect("value");
        assert_eq!(xff, HeaderValue::from_static("203.0.113.7"));
    }

    #[test]
    fn trusted_peer_preserves_chain_and_appends_effective_ip() {
        let headers = headers_with_xff(&["1.1.1.1", "2.2.2.2"]);
        let xff = build_forwarded_for(&headers, "203.0.113.7", true).expect("value");
        assert_eq!(
            xff,
            HeaderValue::from_static("1.1.1.1, 2.2.2.2, 203.0.113.7")
        );
    }

    #[test]
    fn no_inbound_chain_yields_just_effective_ip() {
        let headers = HeaderMap::new();
        let xff = build_forwarded_for(&headers, "198.51.100.9", true).expect("value");
        assert_eq!(xff, HeaderValue::from_static("198.51.100.9"));
    }
}

#[cfg(test)]
mod redirect_tests {
    use super::{combine_request_cookie_headers, rewrite_upstream_location, ForwardedOrigin};
    use http::{header::COOKIE, HeaderMap, HeaderValue};
    use url::Url;

    #[test]
    fn header_value_control_break_guard_flags_crlf() {
        assert!(super::header_value_has_control_break(
            b"value\r\nset-cookie: x"
        ));
        assert!(super::header_value_has_control_break(b"value\ninjected"));
        assert!(super::header_value_has_control_break(b"value\rinjected"));
        assert!(!super::header_value_has_control_break(b"normal-value 123"));
        assert!(!super::header_value_has_control_break(b""));
    }

    #[test]
    fn rewrites_absolute_upstream_location_to_public_origin() {
        let upstream = Url::parse("http://127.0.0.1:8080").expect("url");
        let origin = ForwardedOrigin {
            proto: "https".to_string(),
            host: "dvwa.local:8444".to_string(),
            port: Some(8444),
        };
        let rewritten = rewrite_upstream_location(
            &HeaderValue::from_static("http://127.0.0.1:8080/index.php"),
            &upstream,
            &origin,
        )
        .expect("rewrite");
        assert_eq!(
            rewritten,
            HeaderValue::from_static("https://dvwa.local:8444/index.php")
        );
    }

    #[test]
    fn leaves_relative_location_untouched() {
        let upstream = Url::parse("http://127.0.0.1:8080").expect("url");
        let origin = ForwardedOrigin {
            proto: "https".to_string(),
            host: "dvwa.local:8444".to_string(),
            port: Some(8444),
        };
        assert!(rewrite_upstream_location(
            &HeaderValue::from_static("index.php"),
            &upstream,
            &origin,
        )
        .is_none());
    }

    #[test]
    fn leaves_external_location_untouched() {
        let upstream = Url::parse("http://127.0.0.1:8080").expect("url");
        let origin = ForwardedOrigin {
            proto: "https".to_string(),
            host: "dvwa.local:8444".to_string(),
            port: Some(8444),
        };
        assert!(rewrite_upstream_location(
            &HeaderValue::from_static("https://example.test/login"),
            &upstream,
            &origin,
        )
        .is_none());
    }

    #[test]
    fn combines_split_http2_cookie_headers_with_semicolons() {
        let mut headers = HeaderMap::new();
        headers.append(COOKIE, HeaderValue::from_static("PHPSESSID=abc"));
        headers.append(COOKIE, HeaderValue::from_static("security=low"));

        let combined = combine_request_cookie_headers(&headers).expect("cookie");

        assert_eq!(
            combined,
            HeaderValue::from_static("PHPSESSID=abc; security=low")
        );
    }
}

#[cfg(test)]
mod multipart_request_inspection_tests {
    use super::{looks_like_text, media_type_is_textual, request_body_for_text_inspection};
    use crate::waf::InspectionContext;
    use bytes::Bytes;

    fn ctx(boundary: &str) -> InspectionContext {
        InspectionContext {
            client_ip: "127.0.0.1".into(),
            method: "POST".into(),
            uri: "/profile/image/file".into(),
            path: "/profile/image/file".into(),
            headers: format!(
                "host: localhost\ncontent-type: multipart/form-data; boundary={boundary}"
            ),
            body_limit: 1024 * 1024,
            request_id: "test".into(),
            country: String::new(),
            continent_name: String::new(),
        }
    }

    #[test]
    fn multipart_image_body_is_removed_from_textual_inspection_view() {
        let boundary = "kw-boundary";
        let mut body = format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"avatar.png\"\r\nContent-Type: image/png\r\n\r\n"
        )
        .into_bytes();
        body.extend_from_slice(b"\x89PNG\r\n../<script onload=alert(1)>\r\n");
        body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
        let body = Bytes::from(body);

        let view = request_body_for_text_inspection(&ctx(boundary), &body);
        let text = String::from_utf8_lossy(&view);

        assert!(text.contains("filename=\"avatar.png\""));
        assert!(text.contains("Content-Type: image/png"));
        assert!(!text.contains("../<script"));
    }

    #[test]
    fn multipart_text_field_stays_in_textual_inspection_view() {
        let boundary = "kw-boundary";
        let body = Bytes::from(format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"comment\"\r\n\r\n<script>alert(1)</script>\r\n--{boundary}--\r\n"
        ));

        let view = request_body_for_text_inspection(&ctx(boundary), &body);
        let text = String::from_utf8_lossy(&view);

        assert!(text.contains("name=\"comment\""));
        assert!(text.contains("<script>alert(1)</script>"));
    }

    #[test]
    fn svg_file_body_is_still_textually_inspected() {
        assert!(media_type_is_textual("image/svg+xml"));
        assert!(looks_like_text(br#"<svg onload="alert(1)"></svg>"#));
    }
}

#[cfg(test)]
mod upstream_ca_tests {
    use super::ProxyClient;

    // A self-signed PEM certificate used only to exercise the --upstream-ca
    // read → parse → add_root_certificate path. Parsing/adding a root does not
    // check validity dates, so this fixture never expires for test purposes.
    const TEST_CA_PEM: &str = "\
-----BEGIN CERTIFICATE-----
MIIDKzCCAhOgAwIBAgIUWM/CFwcu86vwBQy7C19brEL/N/IwDQYJKoZIhvcNAQEL
BQAwJTEjMCEGA1UEAwwaS3Jha2VuV2FmIFRlc3QgVXBzdHJlYW0gQ0EwHhcNMjYw
NTMwMDUxMDQ5WhcNMzYwNTI3MDUxMDQ5WjAlMSMwIQYDVQQDDBpLcmFrZW5XYWYg
VGVzdCBVcHN0cmVhbSBDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
AJsujj8dWDQl9WDdrXuUc8h53M6O5FrlymiIbnWn9DG0L1xKE1PW+z/RcN/Q7XJ7
LycERqR3KL97ghagJaNcqpLJJ3wzBEwISTT/XNAEmoe5S3pFmTH2x/Zw6/RGQwQt
MnURylzsYoYjOvLniC19BoW0wwgrMtkdKAxk/xCz6qLlGbaMuEzUFGHXGcYg5LWV
6u13ByNA2Oa/XRpFjdJ9cBzecJroG1moeN3etaWNxSiDt84/xLypftl5jzqZ2IwB
MyAWJRISddft1YDLvv912dR5zEhgitM+pOjn+l9QXYaD5XoTT2McQLS8eufrHMy6
Ey0GANLEsvBT+DsVRgGmV4kCAwEAAaNTMFEwHQYDVR0OBBYEFCfp5HMuCFf+PRHX
7d9lNcJXS9XoMB8GA1UdIwQYMBaAFCfp5HMuCFf+PRHX7d9lNcJXS9XoMA8GA1Ud
EwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBAD6HaL5VUp5qKNJ2b2my5Nop
TXMXzPQSg2BorYoMgn0pa168pBlpnyvXI+on7GwMVvrRc6JyuFe3roqitIA0WRk6
yM3pyfMGvT3QWdNXPI5Y0qEma5FwM3wKnbVKE3JsHoKftBy+N/1yplPZKI+3qcXC
AmqeEDUoNgmz+Monytn7lU6F4z66/IHqDJ3QLi4+gbt8kwnlNiQsRL11yYJ+Y718
FQ4585CILyePGe5gAS8evj5aaS66iEvFhpRYpsF3eeEkpEZgBocAAE5R+yvMXUMe
mHdKNWay9Hq1obnN0UbFuBnzT2hA/Uy6D0/Yekg5c30Xo8dpW79qYl4l0gdOnZk=
-----END CERTIFICATE-----
";

    // A loopback upstream with allow_private_upstream=true keeps the constructor
    // fully offline (no DNS), isolating the --upstream-ca behaviour under test.
    const UPSTREAM: &str = "https://127.0.0.1:9443";

    #[test]
    fn valid_upstream_ca_builds_client() {
        let dir = tempfile::tempdir().expect("tempdir");
        let ca = dir.path().join("ca.pem");
        std::fs::write(&ca, TEST_CA_PEM).expect("write ca");
        let client = ProxyClient::new(UPSTREAM, 5, true, None, ca.to_str());
        assert!(
            client.is_ok(),
            "valid upstream CA should build the client: {:?}",
            client.err()
        );
    }

    #[test]
    fn missing_upstream_ca_file_errors() {
        let client = ProxyClient::new(UPSTREAM, 5, true, None, Some("/no/such/upstream-ca.pem"));
        assert!(client.is_err(), "missing CA file must be a hard error");
    }

    #[test]
    fn non_pem_upstream_ca_errors() {
        let dir = tempfile::tempdir().expect("tempdir");
        let bad = dir.path().join("bad.pem");
        std::fs::write(&bad, b"this is not a certificate").expect("write");
        let client = ProxyClient::new(UPSTREAM, 5, true, None, bad.to_str());
        assert!(client.is_err(), "garbage CA file must be rejected");
    }

    #[test]
    fn no_upstream_ca_still_builds() {
        let client = ProxyClient::new(UPSTREAM, 5, true, None, None);
        assert!(client.is_ok(), "no CA should build with public roots only");
    }
}
