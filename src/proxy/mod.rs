mod body;
mod builder;
mod enforcement;
mod real_ip;
mod trace_context;
mod trusted_proxy;

pub(crate) use body::full_body;
pub use body::WafBody;
use body::{limited_body, BodyReservationError, BodyTracker};
pub use builder::ProxyClientBuilder;
use enforcement::{derive_block_reason, derive_module_label};
pub(crate) use real_ip::effective_client_ip;
use trace_context::build_traceparent;
pub use trusted_proxy::{parse_trusted_proxy_cidr, parse_trusted_proxy_cidrs};

use crate::{
    allowpaths::PathDecision,
    app::AppState,
    body_decode::{decompress_body_for_inspection, parse_content_encoding},
    cli::WafMode,
    error::KrakenError,
    geo::GeoIpResult,
    logging::{write_critical, SecurityEvent},
    multipart_extract::{extract_boundary, parse_parts, MultipartPart},
    waf::{Decision, Finding, InspectionContext, InspectionDeadline, ResponseContext},
};
use anyhow::{Context, Result};
use bytes::{Bytes, BytesMut};
use http::{
    header::{CONNECTION, CONTENT_LENGTH, COOKIE, HOST, LOCATION, TRANSFER_ENCODING, UPGRADE},
    HeaderMap, HeaderName, HeaderValue, Method, Request, Response, StatusCode, Uri,
};
use http_body_util::{BodyExt, Full};
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
use std::{
    collections::VecDeque,
    sync::{atomic::AtomicUsize, Arc},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{error, info, warn};
use url::{Host, Url};
use uuid::Uuid;

/// Bytes carried between adjacent body chunks when streaming-inspecting the body.
/// Sized to be larger than any realistic detection pattern so attackers cannot
/// reliably split a payload across TCP frames to evade the keyword/regex matchers.
/// 2.24.0: the body pipeline now buffers and inspects once, so this constant
/// is only a fallback for the (legacy) per-chunk streaming path. It remains
/// here as a lower bound on the streaming-inspection-window cap.
#[allow(dead_code)]
const STREAM_OVERLAP_BYTES: usize = 16 * 1024;

/// Hard ceiling on the number of headers forwarded upstream and embedded into the
/// inspection prefix. Defends against header-amplification `DoS` and request smuggling
/// surface. Browsers send ~20-30 headers in practice.
const MAX_FORWARDED_HEADERS: usize = 100;

/// Hard ceiling on the cumulative bytes of forwarded headers (name + value sum).
const MAX_FORWARDED_HEADER_BYTES: usize = 32 * 1024;

type UpstreamConnector = hyper_rustls::HttpsConnector<HttpConnector>;
type UpstreamClient = Client<UpstreamConnector, Full<Bytes>>;
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

pub struct ProxyClient {
    client: UpstreamClient,
    upstream: Url,
    upstream_timeout: std::time::Duration,
    allow_private_upstream: bool,
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
    TooLarge { limit: usize },
    Timeout { timeout_secs: u64 },
    Other(anyhow::Error),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InspectionPolicy {
    Bypass,
    DetectOnly,
    Block,
}

#[derive(Debug)]
enum BodyOutcome {
    Complete {
        body: Bytes,
        body_for_text_inspection: Bytes,
        findings: Vec<Finding>,
    },
    Rejected {
        finding: Box<Finding>,
        captured_prefix: Bytes,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct AllowInspectionDecision {
    skip_inspection: bool,
    block_by_ip: bool,
}

#[derive(Debug)]
struct RequestHead {
    method: Method,
    uri: Uri,
    context: InspectionContext,
}

enum RequestHeadPhase {
    Continue(RequestHead),
    Respond(WafResponse),
}

#[derive(Debug, Clone, Copy)]
struct RequestTrace<'a> {
    request_id: &'a str,
    traceparent: &'a str,
}

#[derive(Debug, Clone, Copy)]
enum EnforcementPolicy {
    WafMode,
    RateLimit { retry_after: std::time::Duration },
}

impl std::fmt::Display for BodyInspectionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooLarge { limit } => {
                write!(f, "request body exceeded route limit of {limit} bytes")
            }
            Self::Timeout { timeout_secs } => write!(
                f,
                "request body frame did not arrive within {timeout_secs} seconds"
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

        let internal_header_name = match internal_header_name {
            Some(value) if !value.trim().is_empty() => Some(
                value
                    .parse()
                    .with_context(|| format!("invalid internal header name: {value}"))?,
            ),
            _ => None,
        };

        Ok(Self {
            client,
            upstream,
            upstream_timeout: std::time::Duration::from_secs(timeout_secs),
            allow_private_upstream,
            internal_header_name,
        })
    }

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

    async fn dispatch(
        &self,
        state: &AppState,
        mut req: Request<Incoming>,
        client_ip: String,
        request_id: &str,
        traceparent: &str,
    ) -> WafResponse {
        let trace = RequestTrace {
            request_id,
            traceparent,
        };
        let RequestHead {
            method,
            uri,
            context,
        } = match Self::request_head_phase(state, &req, &client_ip, trace) {
            RequestHeadPhase::Continue(head) => head,
            RequestHeadPhase::Respond(response) => return response,
        };

        if let Some(response) = Self::rate_limit_phase(state, &context).await {
            return response;
        }

        let allow_decision = Self::allow_paths_phase(state, &context);

        if allow_decision.block_by_ip {
            return block_content_response(
                state,
                StatusCode::FORBIDDEN,
                "Access denied by KrakenWaf IP restriction",
            );
        }

        let inspection_deadline = if allow_decision.skip_inspection {
            None
        } else {
            state.waf.inspection_deadline()
        };

        if !allow_decision.skip_inspection {
            if let Some(response) =
                Self::early_inspection_phase(state, &context, inspection_deadline).await
            {
                return response;
            }
        }

        if is_websocket_upgrade(req.headers()) {
            return self
                .websocket_phase(
                    state,
                    req,
                    &context,
                    allow_decision.skip_inspection,
                    inspection_deadline,
                    trace,
                )
                .await;
        }

        let body_policy = Self::body_inspection_policy(state, allow_decision.skip_inspection);
        let (body_bytes, body_for_text_inspection) = match Self::body_phase(
            state,
            &context,
            req.body_mut(),
            &client_ip,
            body_policy,
            inspection_deadline,
        )
        .await
        {
            Ok(body) => body,
            Err(response) => return response,
        };

        if !allow_decision.skip_inspection {
            if let Some(response) = Self::inspect_buffered_request_body(
                state,
                &context,
                &body_bytes,
                &body_for_text_inspection,
                inspection_deadline,
            ) {
                return response;
            }
        }

        self.forward_phase(state, &req, method, uri, body_bytes, trace)
            .await
    }

    fn request_head_phase(
        state: &AppState,
        req: &Request<Incoming>,
        client_ip: &str,
        trace: RequestTrace<'_>,
    ) -> RequestHeadPhase {
        let method = req.method().clone();
        let effective_ip = effective_client_ip(client_ip, req.headers(), state);
        let uri = req.uri().clone();
        let path = crate::rules::normalize_url_path(uri.path());

        // Reject oversize header sets BEFORE materialising any flattened
        // representation so an attacker cannot force the WAF to allocate the
        // full string just to learn the request will be denied.
        if exceeds_header_limits(req.headers()) {
            return RequestHeadPhase::Respond(block_content_response(
                state,
                StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
                "KrakenWaf rejected the request header set",
            ));
        }

        // A-2: per-route rule limit is further bounded by the
        // operator-configured hard cap.
        let body_limit = state
            .waf
            .body_limit_for_path(&path)
            .min(state.cli.max_body_bytes);
        let geo = state
            .geo_reader
            .as_ref()
            .map_or_else(GeoIpResult::empty, |r| r.lookup(&effective_ip));
        let context = InspectionContext {
            client_ip: effective_ip,
            method: method.to_string(),
            uri: uri.to_string(),
            path,
            headers: flatten_headers(req.headers()),
            body_limit,
            request_id: trace.request_id.to_string(),
            country: geo.country_name,
            continent_name: geo.continent_name,
        };

        RequestHeadPhase::Continue(RequestHead {
            method,
            uri,
            context,
        })
    }

    // Per-IP rate limit — enforced for EVERY request, BEFORE the allow-paths
    // decision and independent of CMC/regex/keyword inspection. An allow-listed
    // path skips signature inspection but must still be rate-limited; otherwise
    // an allow-listed route is an unbounded request sink. Rate limiting is an
    // operational control, so it is enforced in every WAF inspection mode and
    // returns HTTP 429 with `Retry-After`.
    async fn rate_limit_phase(
        state: &AppState,
        context: &InspectionContext,
    ) -> Option<WafResponse> {
        let rejection = state.waf.rate_limit_finding(context).await?;
        let event = build_event(context, &rejection.finding, None);
        Self::log_and_enforce_with(
            state,
            event,
            EnforcementPolicy::RateLimit {
                retry_after: rejection
                    .decision
                    .retry_after()
                    .unwrap_or(std::time::Duration::from_secs(1)),
            },
        )
    }

    // Check allow-paths: IP-restricted entries block non-allowed IPs; matched
    // entries without IP restriction skip WAF inspection entirely.
    fn allow_paths_phase(state: &AppState, context: &InspectionContext) -> AllowInspectionDecision {
        let Some(config) = &state.allow_path_config else {
            return AllowInspectionDecision {
                skip_inspection: false,
                block_by_ip: false,
            };
        };

        match config.check(
            &context.path,
            &context.uri,
            &context.client_ip,
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
                AllowInspectionDecision {
                    skip_inspection: true,
                    block_by_ip: false,
                }
            }
            PathDecision::Block => AllowInspectionDecision {
                skip_inspection: false,
                block_by_ip: true,
            },
            PathDecision::NoMatch => AllowInspectionDecision {
                skip_inspection: false,
                block_by_ip: false,
            },
        }
    }

    async fn early_inspection_phase(
        state: &AppState,
        context: &InspectionContext,
        deadline: Option<InspectionDeadline>,
    ) -> Option<WafResponse> {
        match state
            .waf
            .inspect_early_with_deadline(context, deadline)
            .await
        {
            Decision::Allow | Decision::Monitor(_) | Decision::SilentReplace { .. } => None,
            Decision::Block(finding) => {
                let event = build_event(context, &finding, None);
                Self::log_and_enforce(state, event)
            }
        }
    }

    fn body_inspection_policy(state: &AppState, skip_inspection: bool) -> InspectionPolicy {
        if skip_inspection {
            InspectionPolicy::Bypass
        } else if state.mode == WafMode::Block {
            InspectionPolicy::Block
        } else {
            InspectionPolicy::DetectOnly
        }
    }

    // ── WebSocket control policy (conf/websocket.yaml) ────────────────
    // When enable_ws_control is true the handshake is subject to the path
    // allow-list, optional handshake inspection, and the per-IP
    // simultaneous-session cap *before* any upstream tunnel is opened.
    // The acquired guard is threaded into the tunnel task so the per-IP counter
    // is released exactly when the session ends.
    async fn websocket_phase(
        &self,
        state: &AppState,
        req: Request<Incoming>,
        context: &InspectionContext,
        skip_inspection: bool,
        deadline: Option<InspectionDeadline>,
        trace: RequestTrace<'_>,
    ) -> WafResponse {
        let ws = &state.ws_control;
        let ws_guard = if ws.enabled() {
            if !ws.path_allowed(&context.path) {
                warn!(
                    target: "krakenwaf",
                    ip = %context.client_ip,
                    path = %context.path,
                    "websocket upgrade rejected: path not in allowed_paths"
                );
                return block_content_response(
                    state,
                    StatusCode::FORBIDDEN,
                    "WebSocket path not permitted by KrakenWaf",
                );
            }
            if ws.inspect_handshake() && !skip_inspection {
                let handshake = format_request_prefix_bytes(context);
                if let Decision::Block(finding) =
                    state.waf.inspect_complete_payload_with_context_deadline(
                        &handshake,
                        Some(&context.method),
                        deadline,
                    )
                {
                    let event = build_event(context, &finding, None);
                    if let Some(response) = Self::log_and_enforce(state, event) {
                        return response;
                    }
                }
            }
            let Some(guard) = ws.try_acquire(&context.client_ip) else {
                warn!(
                    target: "krakenwaf",
                    ip = %context.client_ip,
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
        self.handle_websocket_upgrade(
            state,
            req,
            trace.request_id,
            trace.traceparent,
            &forwarded_origin,
            ws_guard,
        )
        .await
    }

    async fn body_phase(
        state: &AppState,
        context: &InspectionContext,
        body: &mut Incoming,
        client_ip: &str,
        policy: InspectionPolicy,
        deadline: Option<InspectionDeadline>,
    ) -> Result<(Bytes, Bytes), WafResponse> {
        match consume_and_inspect_body(state, context, body, client_ip, policy, deadline).await {
            Ok(BodyOutcome::Complete {
                body,
                body_for_text_inspection,
                findings,
            }) => {
                for finding in findings {
                    let event = build_event(context, &finding, Some(&body));
                    if let Some(response) = Self::log_and_enforce(state, event) {
                        return Err(response);
                    }
                }
                Ok((body, body_for_text_inspection))
            }
            Ok(BodyOutcome::Rejected {
                finding,
                captured_prefix,
            }) => {
                let event = build_event(context, &finding, Some(&captured_prefix));
                if let Some(response) = Self::log_and_enforce(state, event) {
                    return Err(response);
                }
                // A rejected body is evidence only. If enforcement policy ever
                // changes under us, fail closed instead of forwarding it.
                Err(block_content_response(
                    state,
                    StatusCode::FORBIDDEN,
                    "Blocked by KrakenWaf",
                ))
            }
            Err(BodyInspectionError::TooLarge { limit: _ }) => Err(block_content_response(
                state,
                StatusCode::PAYLOAD_TOO_LARGE,
                "KrakenWaf blocked the request body",
            )),
            Err(BodyInspectionError::Timeout { .. }) => Err(block_content_response(
                state,
                StatusCode::REQUEST_TIMEOUT,
                "KrakenWaf timed out waiting for the request body",
            )),
            Err(BodyInspectionError::Other(err)) => {
                warn!(target: "krakenwaf", error=%err, method=%context.method, uri=%context.uri, fullpath_evidence=%context.uri, "body inspection failed");
                Err(block_content_response(
                    state,
                    StatusCode::BAD_REQUEST,
                    "KrakenWaf could not inspect the request body",
                ))
            }
        }
    }

    async fn forward_phase(
        &self,
        state: &AppState,
        req: &Request<Incoming>,
        method: Method,
        uri: Uri,
        body_bytes: Bytes,
        trace: RequestTrace<'_>,
    ) -> WafResponse {
        let forwarded_origin = ForwardedOrigin::from_headers(req.headers(), state);
        match self
            .forward_request(
                state,
                method,
                uri,
                req.headers(),
                body_bytes,
                trace.request_id,
                trace.traceparent,
                &forwarded_origin,
            )
            .await
        {
            Ok(response) => response,
            Err(err) => {
                error!(target: "krakenwaf", "upstream proxy failure: {err:#}");
                let mut response =
                    plain_response(StatusCode::BAD_GATEWAY, "KrakenWaf upstream failure");
                apply_response_policy(state, &mut response);
                response
            }
        }
    }

    fn inspect_buffered_request_body(
        state: &AppState,
        context: &InspectionContext,
        body_bytes: &Bytes,
        body_for_inspection: &Bytes,
        deadline: Option<InspectionDeadline>,
    ) -> Option<WafResponse> {
        // HTTP Parameter Pollution check (HPP_detect CMC module): inspect the
        // raw query string and the request body for a duplicated parameter
        // name. Runs once the body is available so both locations are covered.
        let query = context.uri.split_once('?').map_or("", |(_, q)| q);
        let body_text = String::from_utf8_lossy(body_for_inspection);
        if let Decision::Block(finding) = state
            .waf
            .inspect_hpp_with_deadline(query, &body_text, deadline)
        {
            let event = build_event(context, &finding, Some(body_bytes));
            if let Some(response) = Self::log_and_enforce(state, event) {
                return Some(response);
            }
        }

        // Open Redirect / RFI check (Open_redirect_n_RFI_detect CMC module):
        // inspect the raw query string (GET) and request body (POST) for a
        // hot redirect/inclusion parameter whose value resolves to an external
        // URL, dangerous scheme, or inclusion wrapper.
        if let Decision::Block(finding) = state
            .waf
            .inspect_open_redirect_rfi_with_deadline(query, &body_text, deadline)
        {
            let event = build_event(context, &finding, Some(body_bytes));
            if let Some(response) = Self::log_and_enforce(state, event) {
                return Some(response);
            }
        }

        None
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
        validate_upstream_for_request(&self.upstream, self.allow_private_upstream).await?;
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
    fn log_and_enforce(state: &AppState, event: SecurityEvent) -> Option<WafResponse> {
        Self::log_and_enforce_with(state, event, EnforcementPolicy::WafMode)
    }

    fn log_and_enforce_with(
        state: &AppState,
        event: SecurityEvent,
        enforcement: EnforcementPolicy,
    ) -> Option<WafResponse> {
        // Per-engine:module counter derived from the security event label.
        let module_label = derive_module_label(&event.engine, &event.rule_match);
        state.metrics.inc_detected();
        state.metrics.inc_detected_by_label(&module_label);

        let actually_blocked = matches!(enforcement, EnforcementPolicy::RateLimit { .. })
            || state.mode == crate::cli::WafMode::Block;
        if actually_blocked {
            state.metrics.inc_blocked();
            state.metrics.inc_blocked_by_label(&module_label);
        }

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
        if actually_blocked && state.ban_manager.enabled() {
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

        if matches!(enforcement, EnforcementPolicy::WafMode)
            && (state.mode == WafMode::Silent || state.mode == WafMode::DetectOnly)
        {
            return None;
        }

        let (status, retry_after) = match enforcement {
            EnforcementPolicy::WafMode => (StatusCode::FORBIDDEN, None),
            EnforcementPolicy::RateLimit { retry_after } => {
                (StatusCode::TOO_MANY_REQUESTS, Some(retry_after))
            }
        };
        let mut response = block_content_response(state, status, "Blocked by KrakenWaf");
        if let Some(delay) = retry_after {
            let seconds = delay
                .as_secs()
                .saturating_add(u64::from(delay.subsec_nanos() > 0))
                .max(1)
                .to_string();
            if let Ok(value) = HeaderValue::from_str(&seconds) {
                response.headers_mut().insert("Retry-After", value);
            }
        }
        Some(response)
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
    ) -> Result<WafResponse> {
        validate_upstream_for_request(&self.upstream, self.allow_private_upstream).await?;

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
            if is_hop_by_hop(name)
                || name == HOST
                || name == COOKIE
                || name == CONTENT_LENGTH
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
        request_builder = request_builder.header("x-request-id", request_id);
        request_builder = request_builder.header("traceparent", traceparent);
        if let Some(header_name) = &self.internal_header_name {
            request_builder = request_builder.header(header_name, "1");
        }
        if !body.is_empty() || headers.contains_key(CONTENT_LENGTH) {
            request_builder = request_builder.header(CONTENT_LENGTH, body.len().to_string());
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
                if let Some(response) = Self::inspect_upstream_response(
                    state,
                    status,
                    &resp_headers_map,
                    &mut response_builder,
                    &mut bytes,
                    true,
                    &method_str,
                    &uri,
                    request_id,
                ) {
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
                if let Some(response) = Self::inspect_upstream_response(
                    state,
                    status,
                    &resp_headers_map,
                    &mut response_builder,
                    &mut empty,
                    false,
                    &method_str,
                    &uri,
                    request_id,
                ) {
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
                let (mut prefix, remainder, response_body, seen, prefix_is_complete_body) =
                    read_response_prefix(response_body, inspect_prefix_bytes, max_bytes).await?;
                let original_prefix_len = prefix.len();
                if let Some(response) = Self::inspect_upstream_response(
                    state,
                    status,
                    &resp_headers_map,
                    &mut response_builder,
                    &mut prefix,
                    prefix_is_complete_body
                        || (remainder.is_empty()
                            && advertised_length.is_some_and(|length| length == seen)),
                    &method_str,
                    &uri,
                    request_id,
                ) {
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
    fn inspect_upstream_response(
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
                if let Some(response) = Self::log_and_enforce(state, event) {
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
                if !complete_body {
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
                        original_len=bytes.len(),
                        "response DBMS error fingerprint detected in prefix; not rewriting partial body"
                    );
                    write_critical(&state.logging, &event);
                    state.store.enqueue(event);
                    return None;
                }
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
/// 1. Read frames until EOF or `body_limit` is exceeded. The startup-resolved
///    frame timeout still guards against slowloris.
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
    // Resource accounting intentionally keys on the direct TCP peer instead of
    // `ctx.client_ip` (`effective_ip`). Rate-limit/GeoIP use trusted-proxy
    // identity, while body-buffer pressure is bounded by the connection that is
    // actually consuming memory on this listener.
    let ip_counter: Arc<AtomicUsize> = state
        .ip_body_bytes
        .entry(client_ip.to_string())
        .or_insert_with(|| Arc::new(AtomicUsize::new(0)))
        .clone();
    let mut tracker = BodyTracker::new(Arc::clone(&state.inflight_body_bytes), ip_counter);
    let frame_timeout = std::time::Duration::from_secs(state.body_frame_timeout_secs);
    let mut acc = BytesMut::new();
    loop {
        let frame = match tokio::time::timeout(frame_timeout, body.frame()).await {
            Ok(Some(frame)) => frame.map_err(|err| BodyInspectionError::Other(err.into()))?,
            Ok(None) => break,
            Err(_) => {
                return Err(BodyInspectionError::Timeout {
                    timeout_secs: state.body_frame_timeout_secs,
                });
            }
        };
        if let Some(chunk) = frame.data_ref() {
            if acc.len() + chunk.len() > ctx.body_limit {
                return Err(BodyInspectionError::TooLarge {
                    limit: ctx.body_limit,
                });
            }
            match tracker.try_add(
                chunk.len(),
                state.max_inflight_body_bytes,
                state.max_per_ip_body_bytes,
            ) {
                Ok(()) => {}
                Err(BodyReservationError::Global) => {
                    return Err(BodyInspectionError::TooLarge {
                        limit: state.max_inflight_body_bytes,
                    });
                }
                Err(BodyReservationError::Ip) => {
                    return Err(BodyInspectionError::TooLarge {
                        limit: state.max_per_ip_body_bytes,
                    });
                }
            }
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
    policy: InspectionPolicy,
    deadline: Option<InspectionDeadline>,
) -> std::result::Result<BodyOutcome, BodyInspectionError> {
    let raw_body = accumulate_body_frames(state, ctx, body, client_ip).await?;
    if raw_body.is_empty() || policy == InspectionPolicy::Bypass {
        return Ok(BodyOutcome::Complete {
            body_for_text_inspection: raw_body.clone(),
            body: raw_body,
            findings: Vec::new(),
        });
    }

    let decoded_body = decode_body_for_inspection(state, ctx, &raw_body)?;
    let mut findings = Vec::new();
    let multipart_parts = multipart_parts_for_text_inspection(ctx, &decoded_body);
    if let Some(outcome) = inspect_multipart_parts(
        state,
        ctx,
        multipart_parts.as_deref(),
        &raw_body,
        policy,
        deadline,
        &mut findings,
    ) {
        return Ok(outcome);
    }
    let body_for_text_inspection =
        request_body_for_text_inspection_with_parts(&decoded_body, multipart_parts.as_deref());
    if let Some(outcome) = inspect_decoded_body(
        state,
        ctx,
        &body_for_text_inspection,
        &raw_body,
        policy,
        deadline,
        &mut findings,
    ) {
        return Ok(outcome);
    }
    Ok(BodyOutcome::Complete {
        body_for_text_inspection,
        body: raw_body,
        findings,
    })
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
    parts: Option<&[MultipartPart]>,
    raw_body: &Bytes,
    policy: InspectionPolicy,
    deadline: Option<InspectionDeadline>,
    findings: &mut Vec<Finding>,
) -> Option<BodyOutcome> {
    // Multipart extraction: scan each part's inspectable view independently.
    let parts = parts?;
    for part in parts {
        let part_view = multipart_part_for_text_inspection(part);
        if part_view.is_empty() {
            continue;
        }
        let part_payload = format_full_request_bytes(ctx, Some(&part_view));
        match state.waf.inspect_complete_payload_with_context_deadline(
            &part_payload,
            Some(&ctx.method),
            deadline,
        ) {
            Decision::Allow | Decision::Monitor(_) | Decision::SilentReplace { .. } => {}
            Decision::Block(finding) => {
                if policy == InspectionPolicy::Block {
                    return Some(BodyOutcome::Rejected {
                        finding,
                        captured_prefix: raw_body.clone(),
                    });
                }
                findings.push(*finding);
            }
        }
    }
    None
}

fn inspect_decoded_body(
    state: &AppState,
    ctx: &InspectionContext,
    body_for_inspection: &Bytes,
    raw_body: &Bytes,
    policy: InspectionPolicy,
    deadline: Option<InspectionDeadline>,
    findings: &mut Vec<Finding>,
) -> Option<BodyOutcome> {
    // Single full-body inspection on the cleartext view.
    let full = format_full_request_bytes(ctx, Some(body_for_inspection));
    match state.waf.inspect_complete_payload_with_context_deadline(
        &full,
        Some(&ctx.method),
        deadline,
    ) {
        Decision::Allow | Decision::Monitor(_) | Decision::SilentReplace { .. } => None,
        Decision::Block(finding) => {
            if policy == InspectionPolicy::Block {
                Some(BodyOutcome::Rejected {
                    finding,
                    captured_prefix: raw_body.clone(),
                })
            } else {
                findings.push(*finding);
                None
            }
        }
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

#[cfg(test)]
fn request_body_for_text_inspection(ctx: &InspectionContext, body: &Bytes) -> Bytes {
    let parts = multipart_parts_for_text_inspection(ctx, body);
    request_body_for_text_inspection_with_parts(body, parts.as_deref())
}

fn multipart_parts_for_text_inspection(
    ctx: &InspectionContext,
    body: &Bytes,
) -> Option<Vec<MultipartPart>> {
    let ct = ctx_header(ctx, "content-type")?;
    let boundary = extract_boundary(&ct)?;
    Some(parse_parts(body, &boundary))
}

fn request_body_for_text_inspection_with_parts(
    body: &Bytes,
    parts: Option<&[MultipartPart]>,
) -> Bytes {
    let Some(parts) = parts else {
        return body.clone();
    };
    if parts.is_empty() {
        return body.clone();
    }

    let mut out = Vec::with_capacity(body.len().min(64 * 1024));
    for part in parts {
        out.extend_from_slice(&part.headers);
        out.extend_from_slice(b"\n\n");
        out.extend_from_slice(multipart_part_inspect_bytes(part));
        out.push(b'\n');
    }
    Bytes::from(out)
}

fn multipart_part_for_text_inspection(part: &MultipartPart) -> Bytes {
    let mut out = Vec::with_capacity(part.headers.len() + part.body.len().min(8 * 1024) + 2);
    out.extend_from_slice(&part.headers);
    out.extend_from_slice(b"\n\n");
    out.extend_from_slice(multipart_part_inspect_bytes(part));
    Bytes::from(out)
}

/// Bounded prefix scanned from a binary part body. A polyglot upload — a text
/// attack payload smuggled under an `image/png` (or other binary) content type —
/// would otherwise be skipped entirely; inspecting a capped prefix catches the
/// common case (payloads sit near the start) without paying to scan megabytes of
/// genuine binary on every upload.
const BINARY_PART_INSPECT_PREFIX: usize = 8 * 1024;

/// Return the slice of a part's body that should be fed to the textual matchers.
///
/// * Declared-textual parts (`text/*`, JSON, XML, form-urlencoded, …) — full body.
/// * Declared-binary parts (`image/*`, `application/octet-stream`, …) — a bounded
///   prefix, so a polyglot still trips the matchers without unbounded scanning.
/// * Unknown content type — full body when it sniffs as text, otherwise a bounded
///   prefix (the same polyglot defence as the declared-binary case).
///
/// Full inspection of a textual or text-sniffing part is intentional: such a
/// body is what the upstream will parse, so inspecting less than the whole would
/// open a false-negative window. It is **not** unbounded — the per-route request
/// `body_limit` is enforced in `accumulate_body_frames` *before* the body is
/// parsed into parts, so no single part can exceed that cap. Only declared- or
/// sniffed-binary parts are additionally trimmed to [`BINARY_PART_INSPECT_PREFIX`].
fn multipart_part_inspect_bytes(part: &MultipartPart) -> &[u8] {
    if part.body.is_empty() {
        return &[];
    }
    let prefix = &part.body[..part.body.len().min(BINARY_PART_INSPECT_PREFIX)];
    if let Some(content_type) = &part.content_type {
        if media_type_is_textual(content_type) {
            return &part.body;
        }
        if media_type_is_binary(content_type) {
            return prefix;
        }
    }
    if looks_like_text(&part.body) {
        &part.body
    } else {
        prefix
    }
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

#[allow(dead_code)]
fn format_full_request_window_bytes(ctx: &InspectionContext, body_window: &[u8]) -> Vec<u8> {
    let mut out = format_request_prefix_bytes(ctx);
    out.extend_from_slice(body_window);
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

fn validate_upstream(upstream: &Url, allow_private_upstream: bool) -> Result<()> {
    if !matches!(upstream.scheme(), "http" | "https") {
        anyhow::bail!("upstream must use http or https");
    }

    if allow_private_upstream {
        return Ok(());
    }

    reject_private_upstream_resolution(upstream, true)
}

async fn validate_upstream_for_request(upstream: &Url, allow_private_upstream: bool) -> Result<()> {
    if allow_private_upstream {
        return Ok(());
    }
    let upstream = upstream.clone();
    tokio::task::spawn_blocking(move || reject_private_upstream_resolution(&upstream, false))
        .await
        .context("upstream DNS validation task failed")?
}

fn reject_private_upstream_resolution(upstream: &Url, log_success: bool) -> Result<()> {
    if let Some(host) = upstream.host() {
        match host {
            Host::Ipv4(ip) => {
                if ip_is_private_or_local(&std::net::IpAddr::V4(ip)) {
                    anyhow::bail!("private or local upstreams require --allow-private-upstream");
                }
            }
            Host::Ipv6(ip) => {
                if ip_is_private_or_local(&std::net::IpAddr::V6(ip)) {
                    anyhow::bail!("private or local upstreams require --allow-private-upstream");
                }
            }
            Host::Domain(domain) => {
                let resolved = resolve_upstream_addrs(upstream, domain)?;
                for ip in &resolved {
                    if ip_is_private_or_local(ip) {
                        anyhow::bail!(
                            "upstream {domain} resolved to private/local address {ip}; \
                             refuse without --allow-private-upstream"
                        );
                    }
                }
                if log_success {
                    info!(
                        target: "krakenwaf",
                        upstream_host = %domain,
                        resolved = ?resolved,
                        "resolved upstream hostname at startup (DNS-rebinding visibility)"
                    );
                }
            }
        }
    } else {
        anyhow::bail!("upstream host is missing");
    }

    Ok(())
}

fn resolve_upstream_addrs(upstream: &Url, domain: &str) -> Result<Vec<std::net::IpAddr>> {
    let port = upstream
        .port_or_known_default()
        .ok_or_else(|| anyhow::anyhow!("upstream port is missing"))?;
    let host_port = format!("{domain}:{port}");
    let resolved = std::net::ToSocketAddrs::to_socket_addrs(&host_port.as_str())
        .with_context(|| format!("failed to resolve upstream hostname {domain}"))?
        .map(|sa| sa.ip())
        .collect::<Vec<_>>();
    anyhow::ensure!(
        !resolved.is_empty(),
        "upstream hostname {domain} resolved to no addresses"
    );
    Ok(resolved)
}

fn ip_is_private_or_local(ip: &std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => {
            v4.is_private() || v4.is_loopback() || v4.is_link_local() || v4.is_unspecified()
        }
        std::net::IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_unique_local()
                || v6.is_unicast_link_local()
        }
    }
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
        if name == TRANSFER_ENCODING
            && !headers.contains_key(CONTENT_LENGTH)
            && value
                .to_str()
                .ok()
                .is_some_and(|value| value.trim().eq_ignore_ascii_case("chunked"))
        {
            continue;
        }
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
) -> Result<(Bytes, VecDeque<Frame<Bytes>>, Incoming, usize, bool)> {
    let mut prefix = BytesMut::with_capacity(prefix_limit.min(64 * 1024));
    let mut remainder = VecDeque::new();
    let mut seen = 0usize;
    let mut complete_body = false;

    while prefix.len() < prefix_limit {
        let Some(frame) = body
            .frame()
            .await
            .transpose()
            .map_err(|error| KrakenError::Upstream(error.to_string()))?
        else {
            complete_body = true;
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

    Ok((prefix.freeze(), remainder, body, seen, complete_body))
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
    fn multipart_image_polyglot_prefix_is_inspected() {
        // A text attack payload smuggled into the head of an image/png part is a
        // classic polyglot. The bounded prefix is now inspected (AppSec finding
        // #3) so the payload — and the part metadata — both appear in the view.
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
        // The smuggled payload sits within the bounded prefix, so it is caught.
        assert!(text.contains("../<script"));
    }

    #[test]
    fn multipart_large_binary_body_is_capped_to_prefix() {
        // A genuinely large binary part must not be scanned in full: only the
        // bounded prefix is inspected, so a multi-MB upload is cheap to handle.
        use super::BINARY_PART_INSPECT_PREFIX;
        let boundary = "kw-boundary";
        let mut body = format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"big.bin\"\r\nContent-Type: application/octet-stream\r\n\r\n"
        )
        .into_bytes();
        // A marker far past the prefix boundary must NOT appear in the view.
        body.extend_from_slice(&vec![b'A'; BINARY_PART_INSPECT_PREFIX + 4096]);
        body.extend_from_slice(b"PAST_PREFIX_MARKER");
        body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
        let body = Bytes::from(body);

        let view = request_body_for_text_inspection(&ctx(boundary), &body);
        let text = String::from_utf8_lossy(&view);
        assert!(!text.contains("PAST_PREFIX_MARKER"));
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

#[cfg(test)]
mod multipart_inspect_tests {
    use super::{multipart_part_inspect_bytes, BINARY_PART_INSPECT_PREFIX};
    use crate::multipart_extract::MultipartPart;
    use bytes::Bytes;

    fn part(content_type: Option<&str>, body: &[u8]) -> MultipartPart {
        MultipartPart {
            name: None,
            filename: None,
            content_type: content_type.map(ToString::to_string),
            headers: Bytes::new(),
            body: Bytes::copy_from_slice(body),
        }
    }

    #[test]
    fn textual_part_is_inspected_in_full() {
        let p = part(Some("application/json"), b"{\"q\":\"<script>\"}");
        assert_eq!(multipart_part_inspect_bytes(&p), p.body.as_ref());
    }

    #[test]
    fn binary_polyglot_prefix_is_still_inspected() {
        // A text attack payload smuggled under image/png must NOT be skipped
        // entirely — the bounded prefix is scanned so the matcher can fire.
        let p = part(Some("image/png"), b"<script>alert(1)</script>");
        assert_eq!(
            multipart_part_inspect_bytes(&p),
            b"<script>alert(1)</script>"
        );
    }

    #[test]
    fn binary_body_is_capped_at_prefix() {
        let mut body = vec![b'A'; BINARY_PART_INSPECT_PREFIX + 4096];
        body[0] = b'<';
        let p = part(Some("application/octet-stream"), &body);
        let inspected = multipart_part_inspect_bytes(&p);
        assert_eq!(inspected.len(), BINARY_PART_INSPECT_PREFIX);
        assert_eq!(inspected, &body[..BINARY_PART_INSPECT_PREFIX]);
    }

    #[test]
    fn unknown_type_that_sniffs_binary_uses_prefix() {
        let mut body = vec![0u8; BINARY_PART_INSPECT_PREFIX + 100];
        body[10] = b'X';
        let p = part(None, &body);
        assert_eq!(
            multipart_part_inspect_bytes(&p).len(),
            BINARY_PART_INSPECT_PREFIX
        );
    }

    #[test]
    fn unknown_type_that_sniffs_text_is_inspected_in_full() {
        // No Content-Type but the body sniffs as text → inspected in full, even
        // when larger than the binary prefix. This is the documented tradeoff:
        // a text-like body is what the upstream parses, so trimming it would open
        // a false-negative window; the per-route request body_limit (enforced
        // before parsing) is what bounds the overall size.
        let mut body = vec![b'a'; BINARY_PART_INSPECT_PREFIX + 4096];
        body.extend_from_slice(b"<script>alert(1)</script>");
        let p = part(None, &body);
        let inspected = multipart_part_inspect_bytes(&p);
        assert_eq!(
            inspected.len(),
            body.len(),
            "text-sniffing part is inspected in full"
        );
        assert!(inspected.ends_with(b"<script>alert(1)</script>"));
    }

    #[test]
    fn empty_body_is_empty() {
        let p = part(Some("image/png"), b"");
        assert!(multipart_part_inspect_bytes(&p).is_empty());
    }
}
