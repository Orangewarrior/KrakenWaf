use crate::{
    allowpaths::PathDecision,
    app::AppState,
    body_decode::{decompress_body_for_inspection, parse_content_encoding},
    cli::WafMode,
    error::KrakenError,
    geo::GeoIpResult,
    logging::{write_critical, SecurityEvent},
    multipart_extract::{extract_boundary, parse_parts},
    waf::{Decision, Finding, InspectionContext, ResponseContext},
};
use anyhow::{Context, Result};
use bytes::{Bytes, BytesMut};
use http::{
    header::{CONNECTION, HOST, UPGRADE},
    HeaderMap, HeaderName, Method, Request, Response, StatusCode, Uri,
};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use reqwest::{redirect::Policy, Client};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use tracing::{error, info, warn};
use url::{Host, Url};
use uuid::Uuid;

/// RAII guard that tracks bytes buffered during body inspection and releases
/// the global + per-IP in-flight byte counters on drop.
struct BodyTracker {
    global: Arc<AtomicUsize>,
    ip: Arc<AtomicUsize>,
    bytes: usize,
}

impl BodyTracker {
    fn new(global: Arc<AtomicUsize>, ip: Arc<AtomicUsize>) -> Self {
        Self { global, ip, bytes: 0 }
    }

    fn add(&mut self, n: usize) {
        self.global.fetch_add(n, Ordering::Relaxed);
        self.ip.fetch_add(n, Ordering::Relaxed);
        self.bytes += n;
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

/// Maximum wall-clock time we wait for a single body frame from the client. Bounds the
/// memory + connection cost of a slowloris-style streaming body that trickles bytes to
/// keep the inspection loop alive indefinitely.
const BODY_FRAME_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

pub struct ProxyClient {
    client: Client,
    upstream: Url,
    internal_header_name: Option<HeaderName>,
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

        let mut builder = Client::builder()
            .use_rustls_tls()
            .redirect(Policy::none())
            .timeout(std::time::Duration::from_secs(timeout_secs));

        // Optionally trust a private / custom CA for the upstream TLS handshake.
        // The certificate(s) are *added* to the built-in public webpki roots —
        // full chain verification is still enforced (this is NOT an
        // "accept any certificate" switch) — so a backend that presents a
        // private-PKI / internal-CA certificate can be fronted without
        // weakening validation, while public upstreams keep working.
        if let Some(ca_path) = upstream_ca {
            let pem = std::fs::read(ca_path)
                .with_context(|| format!("--upstream-ca: failed to read '{ca_path}'"))?;
            let certs = reqwest::Certificate::from_pem_bundle(&pem).with_context(|| {
                format!("--upstream-ca: '{ca_path}' is not a valid PEM certificate bundle")
            })?;
            anyhow::ensure!(
                !certs.is_empty(),
                "--upstream-ca: '{ca_path}' contained no certificates"
            );
            for cert in certs {
                builder = builder.add_root_certificate(cert);
            }
        }

        let client = builder.build()?;

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
            internal_header_name,
        })
    }

    pub async fn handle(
        &self,
        state: &AppState,
        req: Request<Incoming>,
        client_ip: String,
    ) -> Response<Full<Bytes>> {
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
        let mut resp = self.dispatch(state, req, client_ip, &request_id, &traceparent).await;
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
    ) -> Response<Full<Bytes>> {
        let method = req.method().clone();
        let effective_ip = effective_client_ip(&client_ip, req.headers(), state);
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
            .as_ref().map_or_else(GeoIpResult::empty, |r| r.lookup(&effective_ip));

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

        // Check allow-paths: IP-restricted entries block non-allowed IPs; matched entries
        // without IP restriction skip WAF inspection entirely.
        let (skip_inspection, block_by_ip) = if let Some(config) = &state.allow_path_config {
            match config.check(&path, &uri.to_string(), &effective_ip) {
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
                Decision::Allow
                | Decision::Monitor(_)
                | Decision::SilentReplace { .. } => {}
                Decision::Block(finding) => {
                    let event = build_event(&context, &finding, None);
                    if let Some(response) = self.log_and_enforce(state, event).await {
                        return response;
                    }
                }
            }
        }

        let body_bytes = match consume_and_inspect_body(state, &context, req.body_mut(), &client_ip).await {
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
                if !skip_inspection {
                    let event = build_event(&context, &finding, Some(&partial_body));
                    if let Some(response) = self.log_and_enforce(state, event).await {
                        return response;
                    }
                }
                // Silent mode or allowlisted path: forward whatever body was accumulated.
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
                return block_content_response(
                    state,
                    StatusCode::BAD_REQUEST,
                    "KrakenWaf could not inspect the request body",
                );
            }
        };

        if !skip_inspection {
            let full_request = format_full_request_bytes(&context, Some(&body_bytes));
            match state
                .waf
                .inspect_complete_payload_with_context(&full_request, Some(&context.method))
            {
                Decision::Allow
                | Decision::Monitor(_)
                | Decision::SilentReplace { .. } => {}
                Decision::Block(finding) => {
                    let event = build_event(&context, &finding, Some(&body_bytes));
                    if let Some(response) = self.log_and_enforce(state, event).await {
                        return response;
                    }
                }
            }
        }

        match self
            .forward_request(state, method, uri, req.headers(), body_bytes, request_id, traceparent)
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

    /// Log the detection event and, in `Block` mode, return a 403 response.
    /// Returns `None` in `Silent` or `DetectOnly` mode so the caller continues forwarding.
    #[allow(clippy::unused_async)]
    async fn log_and_enforce(
        &self,
        state: &AppState,
        event: SecurityEvent,
    ) -> Option<Response<Full<Bytes>>> {
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
    ) -> Result<Response<Full<Bytes>>> {
        // Build the upstream URL by overlaying ONLY the request path and query on top of the
        // configured upstream. Never `Url::join` an attacker-controlled string: an absolute-form
        // request URI (RFC 7230 §5.3.2) such as `http://attacker.tld/x` would otherwise
        // *replace* the upstream base entirely (SSRF / upstream hijack).
        let target = build_upstream_target(&self.upstream, &uri);
        let method_str = method.as_str().to_string();
        let mut builder = self.client.request(method, target);

        // RFC 9110 §7.6.1 / RFC 7230 §6.1: every token listed in Connection:
        // is hop-by-hop and must be removed before forwarding.
        let connection_hop = connection_listed_headers(headers);

        let mut forwarded_count: usize = 0;
        let mut forwarded_bytes: usize = 0;
        for (name, value) in headers {
            if is_hop_by_hop(name)
                || name == HOST
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
            builder = builder.header(name, value);
        }

        builder = builder.header("x-forwarded-proto", "https");
        builder = builder.header("x-request-id", request_id);
        builder = builder.header("traceparent", traceparent);
        if let Some(header_name) = &self.internal_header_name {
            builder = builder.header(header_name, "1");
        }

        let response = builder
            .body(body)
            .send()
            .await
            .map_err(|err| KrakenError::Upstream(err.to_string()))?;

        let status =
            StatusCode::from_u16(response.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
        let mut response_builder = Response::builder().status(status);
        for (name, value) in response.headers() {
            if !is_hop_by_hop(name) {
                response_builder = response_builder.header(name, value);
            }
        }
        // Stream the upstream body in chunks so an oversized response cannot
        // exhaust WAF heap. The cap is operator-configurable (8 MiB default
        // in 2.24.0, down from 100 MiB).
        let max_response = state.cli.max_upstream_response_bytes;

        // 2.24.0: when the upstream advertises a binary content-type the
        // body bytes are useless to the keyword / regex / libinjection
        // engines, so we inspect headers only and stream the body without
        // any further allocation pressure. This protects WAF latency on
        // file downloads (PDF, mp4, large JPEGs, …) while still scanning
        // text/html, application/json, and friends.
        let resp_headers_map = response_builder
            .headers_ref()
            .cloned()
            .unwrap_or_default();
        let inspect_body = response_body_should_be_inspected(&resp_headers_map);

        let mut body_buf = BytesMut::new();
        let mut response = response;
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|err| KrakenError::Upstream(err.to_string()))?
        {
            body_buf.extend_from_slice(&chunk);
            if body_buf.len() > max_response {
                anyhow::bail!(
                    "upstream response body exceeds limit of {max_response} bytes; \
                     increase --max-upstream-response-bytes if the upstream legitimately returns large responses"
                );
            }
        }
        let mut bytes = body_buf.freeze();

        // Inspect the upstream response (rules with http_action: Response).
        let resp_headers = flatten_headers(&resp_headers_map);
        let resp_ctx = ResponseContext {
            status: status.as_u16(),
            headers: resp_headers,
            body: if inspect_body { bytes.clone() } else { Bytes::new() },
        };
        let resp_decision = state.waf.inspect_response(&resp_ctx);
        match resp_decision {
            Decision::Block(finding) => {
                let event = crate::logging::SecurityEvent::from_finding(
                    &finding,
                    &InspectionContext {
                        client_ip: String::new(),
                        method: method_str.clone(),
                        uri: uri.to_string(),
                        path: uri.path().to_string(),
                        headers: String::new(),
                        body_limit: 0,
                        request_id: request_id.to_string(),
                        country: String::new(),
                        continent_name: String::new(),
                    },
                    finding.request_payload.clone(),
                );
                if let Some(response) = self.log_and_enforce(state, event).await {
                    return Ok(response);
                }
            }
            Decision::Monitor(finding) => {
                // Log to all security outputs but forward the upstream response.
                let event = crate::logging::SecurityEvent::from_finding(
                    &finding,
                    &InspectionContext {
                        client_ip: String::new(),
                        method: method_str.clone(),
                        uri: uri.to_string(),
                        path: uri.path().to_string(),
                        headers: String::new(),
                        body_limit: 0,
                        request_id: request_id.to_string(),
                        country: String::new(),
                        continent_name: String::new(),
                    },
                    finding.request_payload.clone(),
                );
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
                let event = crate::logging::SecurityEvent::from_finding(
                    &finding,
                    &InspectionContext {
                        client_ip: String::new(),
                        method: method_str.clone(),
                        uri: uri.to_string(),
                        path: uri.path().to_string(),
                        headers: String::new(),
                        body_limit: 0,
                        request_id: request_id.to_string(),
                        country: String::new(),
                        continent_name: String::new(),
                    },
                    finding.request_payload.clone(),
                );
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
                // Replace the body the client will receive with the scrubbed copy.
                bytes = modified;
                // Update Content-Length so the client does not see a truncated
                // payload (or wait for bytes that will never arrive).
                if let Some(headers) = response_builder.headers_mut() {
                    if let Ok(val) = http::HeaderValue::from_str(&bytes.len().to_string()) {
                        headers.insert(http::header::CONTENT_LENGTH, val);
                    }
                }
            }
            Decision::Allow => {}
        }

        let mut built = response_builder
            .body(Full::new(bytes))
            .map_err(|err| anyhow::anyhow!("failed to assemble upstream response: {err}"))?;
        apply_response_policy(state, &mut built);
        Ok(built)
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
/// 3. If `Content-Type` is `multipart/form-data`, extract each part's
///    cleartext payload and run inspection on each.
/// 4. Run a single inspection pass on the (possibly decoded) body.
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
            if acc.len() + chunk.len() > ctx.body_limit {
                return Err(BodyInspectionError::TooLarge { limit: ctx.body_limit });
            }
            if state.max_inflight_body_bytes > 0
                && state.inflight_body_bytes.load(Ordering::Relaxed) + chunk.len()
                    > state.max_inflight_body_bytes
            {
                return Err(BodyInspectionError::TooLarge { limit: state.max_inflight_body_bytes });
            }
            if state.max_per_ip_body_bytes > 0
                && tracker.ip.load(Ordering::Relaxed) + chunk.len() > state.max_per_ip_body_bytes
            {
                return Err(BodyInspectionError::TooLarge { limit: state.max_per_ip_body_bytes });
            }
            tracker.add(chunk.len());
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
) -> std::result::Result<Bytes, BodyInspectionError> {
    let raw_body = accumulate_body_frames(state, ctx, body, client_ip).await?;
    if raw_body.is_empty() {
        return Ok(raw_body);
    }

    let limits = &state.memory_limits;

    // Build the cleartext view used by every detection engine.
    let encodings = ctx_header(ctx, "content-encoding")
        .map(|v| parse_content_encoding(&v))
        .unwrap_or_default();

    let decoded_body: Bytes = if encodings.is_empty() {
        raw_body.clone()
    } else {
        match decompress_body_for_inspection(
            &raw_body,
            &encodings,
            ctx.body_limit,
            limits.max_decompress_ratio,
        ) {
            Ok(out) => out,
            Err(err) => {
                tracing::warn!(
                    target: "krakenwaf",
                    request_id = %ctx.request_id,
                    error = %err,
                    "request body decompression failed; rejecting"
                );
                return Err(BodyInspectionError::Other(anyhow::anyhow!(
                    "body decompression rejected: {err}"
                )));
            }
        }
    };

    // Multipart extraction: scan each part's payload independently.
    if let Some(ct) = ctx_header(ctx, "content-type") {
        if let Some(boundary) = extract_boundary(&ct) {
            let parts = parse_parts(&decoded_body, &boundary);
            for part in &parts {
                if part.body.is_empty() {
                    continue;
                }
                let part_payload =
                    format_full_request_bytes(ctx, Some(&part.body));
                match state
                    .waf
                    .inspect_complete_payload_with_context(&part_payload, Some(&ctx.method))
                {
                    Decision::Allow
                    | Decision::Monitor(_)
                    | Decision::SilentReplace { .. } => {}
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

    // Single full-body inspection on the cleartext view.
    let full = format_full_request_bytes(ctx, Some(&decoded_body));
    match state
        .waf
        .inspect_complete_payload_with_context(&full, Some(&ctx.method))
    {
        Decision::Allow
        | Decision::Monitor(_)
        | Decision::SilentReplace { .. } => Ok(raw_body),
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
        let Some((name, value)) = line.split_once(':') else { continue };
        if name.trim().eq_ignore_ascii_case(target) {
            return Some(value.trim().to_string());
        }
    }
    None
}

fn build_event(ctx: &InspectionContext, finding: &Finding, body: Option<&Bytes>) -> SecurityEvent {
    let request_payload = format_full_request(ctx, body, &finding.request_payload);
    SecurityEvent::from_finding(finding, ctx, request_payload)
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
                // request is forwarded. We do NOT pin the IP at the connection layer
                // (would require a custom resolver inside reqwest); operators that need
                // hard pinning should configure the upstream as an explicit IP literal.
                let port = upstream.port_or_known_default().unwrap_or(0);
                let host_port = format!("{domain}:{port}");
                match std::net::ToSocketAddrs::to_socket_addrs(&host_port.as_str()) {
                    Ok(iter) => {
                        let resolved: Vec<std::net::IpAddr> =
                            iter.map(|sa| sa.ip()).collect();
                        for ip in &resolved {
                            let is_local = match ip {
                                std::net::IpAddr::V4(v4) => {
                                    v4.is_private()
                                        || v4.is_loopback()
                                        || v4.is_link_local()
                                        || v4.is_unspecified()
                                }
                                std::net::IpAddr::V6(v6) => {
                                    v6.is_loopback()
                                        || v6.is_unspecified()
                                        || v6.is_unique_local()
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

/// Decide whether the upstream response body should be fed to the
/// detection engines. Binary types (images, video, audio, generic
/// `application/octet-stream`) contain no text the WAF can reason about,
/// so we skip body inspection — headers and status are still scanned.
fn response_body_should_be_inspected(headers: &http::HeaderMap) -> bool {
    let Some(value) = headers.get("content-type") else {
        return true;
    };
    let Ok(text) = value.to_str() else { return true };
    let normalised = text.split(';').next().unwrap_or(text).trim().to_ascii_lowercase();
    // Allow-list of "text-ish" prefixes — everything else is treated as binary.
    
    normalised.starts_with("text/")
        || normalised.starts_with("application/json")
        || normalised.starts_with("application/xml")
        || normalised.starts_with("application/xhtml")
        || normalised.starts_with("application/javascript")
        || normalised.starts_with("application/x-www-form-urlencoded")
        || normalised.starts_with("application/yaml")
        || normalised.starts_with("application/graphql")
        || normalised.starts_with("application/vnd.api+json")
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

fn apply_response_policy(state: &AppState, response: &mut Response<Full<Bytes>>) {
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
) -> Response<Full<Bytes>> {
    let mut response = if let Some(body) = &state.block_response_body {
        Response::builder()
            .status(status)
            .header("content-type", state.block_response_content_type.as_str())
            .header("x-content-type-options", "nosniff")
            .body(Full::new(body.clone()))
            .unwrap_or_else(|_| plain_response(status, fallback_message))
    } else {
        plain_response(status, fallback_message)
    };
    apply_response_policy(state, &mut response);
    response
}

#[must_use] 
pub fn plain_response(status: StatusCode, message: &str) -> Response<Full<Bytes>> {
    // All header names/values are static literals so the builder cannot actually fail.
    // Falling back to a bare Response::new keeps the request path infallible if the
    // http crate ever tightens its validation.
    Response::builder()
        .status(status)
        .header("content-type", "text/plain; charset=utf-8")
        .header("x-content-type-options", "nosniff")
        .body(Full::new(Bytes::copy_from_slice(message.as_bytes())))
        .unwrap_or_else(|_| {
            let mut resp = Response::new(Full::new(Bytes::copy_from_slice(message.as_bytes())));
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
) -> Option<String> {
    use std::net::IpAddr;
    let raw = header_value_case_insensitive(headers, "forwarded")?;
    let elements: Vec<&str> = raw.split(',').collect();
    for element in elements.iter().rev() {
        for kv in element.split(';') {
            let kv = kv.trim();
            let Some((k, v)) = kv.split_once('=') else { continue };
            if !k.eq_ignore_ascii_case("for") {
                continue;
            }
            // Allowed forms: `for=192.0.2.1`, `for="192.0.2.1:4711"`,
            // `for="[2001:db8::1]"`, `for="_obfuscated"`.
            let stripped = v.trim().trim_matches('"');
            // Strip an optional port and surrounding `[]` for IPv6.
            let host_only = if let Some(rest) = stripped.strip_prefix('[') {
                rest.split(']').next().unwrap_or("")
            } else if stripped.matches(':').count() == 1 {
                // `host:port` for IPv4.
                stripped.split(':').next().unwrap_or(stripped)
            } else {
                stripped
            };
            let Ok(parsed) = host_only.parse::<IpAddr>() else {
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
    let trusted_nets: Vec<ipnet::IpNet> = state
        .cli
        .trusted_proxy_cidrs
        .iter()
        .filter_map(|cidr| cidr.parse().ok())
        .collect();
    if !trusted_nets.iter().any(|net| net.contains(&peer)) {
        return peer_ip.to_string();
    }

    // RFC 7239 `Forwarded:` header takes precedence when present — modern
    // proxies (HAProxy 2.x, recent nginx with the realip module) emit it
    // instead of `X-Forwarded-For`. We walk the chain right-to-left and pick
    // the first `for=` value whose IP is *not* one of our trusted proxies.
    if let Some(ip) = forwarded_header_real_ip(headers, &trusted_nets) {
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
