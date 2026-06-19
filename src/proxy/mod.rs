use crate::{
    allowpaths::PathDecision,
    app::AppState,
    cli::WafMode,
    error::KrakenError,
    geo::GeoIpResult,
    logging::{write_critical, SecurityEvent},
    waf::{Decision, InspectionContext, ResponseContext},
};
use anyhow::{Context, Result};
use bytes::{Bytes, BytesMut};
use http::{
    header::{CONNECTION, COOKIE, HOST, LOCATION, UPGRADE},
    HeaderMap, HeaderName, HeaderValue, Method, Request, Response, StatusCode, Uri,
};
use http_body_util::{combinators::UnsyncBoxBody, BodyExt, Full};
use hyper::{
    body::{Frame, Incoming},
    upgrade,
};
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::{
    client::legacy::{connect::HttpConnector, Client},
    rt::{TokioExecutor, TokioIo},
};
use rustls::{ClientConfig, RootCertStore};
use rustls_pki_types::{pem::PemObject, CertificateDer};
use std::collections::VecDeque;
use tokio::io::AsyncWriteExt;
use tracing::{error, info, warn};
use url::{Host, Url};
use uuid::Uuid;

mod body;
mod client_ip;
mod diagnostics;
mod response;
mod websocket;

pub use client_ip::{parse_trusted_proxy_cidr, parse_trusted_proxy_cidrs};
pub(crate) use body::format_request_prefix_bytes;
pub(crate) use client_ip::effective_client_ip;
pub(crate) use response::full_body;
use body::{build_event, build_response_event, consume_and_inspect_body, BodyInspectionError};
use client_ip::{build_traceparent, host_port};
use diagnostics::write_proxy_critical;
use response::{
    adjust_streaming_content_length, content_length, ensure_advertised_length_within_limit,
    limited_body, read_response_prefix, response_mode, ResponseMode,
};
use websocket::{
    build_upstream_websocket_request, is_websocket_upgrade, read_upstream_websocket_response,
};

/// Hard ceiling on the number of headers forwarded upstream and embedded into the
/// inspection prefix. Defends against header-amplification `DoS` and request smuggling
/// surface. Browsers send ~20-30 headers in practice.
const MAX_FORWARDED_HEADERS: usize = 100;

/// Hard ceiling on the cumulative bytes of forwarded headers (name + value sum).
const MAX_FORWARDED_HEADER_BYTES: usize = 32 * 1024;

type UpstreamConnector = hyper_rustls::HttpsConnector<HttpConnector>;
type UpstreamClient = Client<UpstreamConnector, Full<Bytes>>;
type BoxError = Box<dyn std::error::Error + Send + Sync>;
pub type WafBody = UnsyncBoxBody<Bytes, BoxError>;
pub type WafResponse = Response<WafBody>;

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
