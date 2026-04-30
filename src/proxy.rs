use crate::{
    app::AppState,
    cli::WafMode,
    error::KrakenError,
    logging::{write_critical, SecurityEvent},
    waf::{Decision, Finding, InspectionContext, ResponseContext},
};
use anyhow::{Context, Result};
use bytes::{Bytes, BytesMut};
use http::{header::{HOST, CONNECTION, UPGRADE}, HeaderMap, HeaderName, Method, Request, Response, StatusCode, Uri};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use reqwest::{redirect::Policy, Client};
use tracing::{error, info, warn};
use url::{Host, Url};

/// Bytes carried between adjacent body chunks when streaming-inspecting the body.
/// Sized to be larger than any realistic detection pattern so attackers cannot
/// reliably split a payload across TCP frames to evade the keyword/regex matchers.
const STREAM_OVERLAP_BYTES: usize = 16 * 1024;

/// Hard ceiling on the number of headers forwarded upstream and embedded into the
/// inspection prefix. Defends against header-amplification DoS and request smuggling
/// surface. Browsers send ~20-30 headers in practice.
const MAX_FORWARDED_HEADERS: usize = 100;

/// Hard ceiling on the cumulative bytes of forwarded headers (name + value sum).
const MAX_FORWARDED_HEADER_BYTES: usize = 32 * 1024;

pub struct ProxyClient {
    client: Client,
    upstream: Url,
    internal_header_name: Option<HeaderName>,
}

#[derive(Debug)]
enum BodyInspectionError {
    TooLarge { limit: usize },
    Blocked { finding: Finding, partial_body: Bytes },
    Other(anyhow::Error),
}

impl std::fmt::Display for BodyInspectionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooLarge { limit } => write!(f, "request body exceeded route limit of {} bytes", limit),
            Self::Blocked { .. } => write!(f, "request blocked during streaming inspection"),
            Self::Other(err) => write!(f, "{err}"),
        }
    }
}

impl std::error::Error for BodyInspectionError {}

impl ProxyClient {
    pub fn new(upstream: &str, timeout_secs: u64, allow_private_upstream: bool, internal_header_name: Option<String>) -> Result<Self> {
        let upstream = Url::parse(upstream).with_context(|| format!("invalid upstream URL: {upstream}"))?;
        validate_upstream(&upstream, allow_private_upstream)?;

        let client = Client::builder()
            .use_rustls_tls()
            .redirect(Policy::none())
            .timeout(std::time::Duration::from_secs(timeout_secs))
            .build()?;

        let internal_header_name = internal_header_name
            .and_then(|value| if value.trim().is_empty() { None } else { value.parse().ok() });

        Ok(Self { client, upstream, internal_header_name })
    }

    pub async fn handle(&self, state: &AppState, mut req: Request<Incoming>, client_ip: String) -> Response<Full<Bytes>> {
        let method = req.method().clone();
        let effective_ip = effective_client_ip(&client_ip, req.headers(), state);
        let uri = req.uri().clone();
        let path = crate::rules::normalize_url_path(uri.path());
        let headers_flat = flatten_headers(req.headers());
        let body_limit = state.waf.body_limit_for_path(&path);

        let context = InspectionContext {
            client_ip: effective_ip.clone(),
            method: method.to_string(),
            uri: uri.to_string(),
            path: path.clone(),
            headers: headers_flat.clone(),
            body_limit,
        };

        // Check allow-paths: if the URI is explicitly allowed, skip WAF inspection entirely.
        let skip_inspection = state.allow_path_config.as_ref().and_then(|c| c.is_allowed(&path)).map(|entry| {
            if entry.log {
                info!(target: "krakenwaf", uri=%context.uri, title=%entry.title, "allow-paths match: skipping WAF inspection");
            }
        }).is_some();

        if !skip_inspection {
            match state.waf.inspect_early(&context).await {
                Decision::Allow => {}
                Decision::Block(finding) => {
                    let event = build_event(&context, &finding, None);
                    if let Some(response) = self.log_and_enforce(state, event).await {
                        return response;
                    }
                }
            }
        }

        let body_bytes = match consume_and_inspect_body(state, &context, req.body_mut()).await {
            Ok(bytes) => bytes,
            Err(BodyInspectionError::TooLarge { limit: _ }) => {
                return block_content_response(state, StatusCode::PAYLOAD_TOO_LARGE, "KrakenWaf blocked the request body");
            }
            Err(BodyInspectionError::Blocked { finding, partial_body }) => {
                if skip_inspection {
                    partial_body
                } else {
                    let event = build_event(&context, &finding, Some(&partial_body));
                    if let Some(response) = self.log_and_enforce(state, event).await {
                        return response;
                    }
                    // Silent mode: forward whatever body we accumulated before detection.
                    partial_body
                }
            }
            Err(BodyInspectionError::Other(err)) => {
                warn!(target: "krakenwaf", error=%err, method=%context.method, uri=%context.uri, fullpath_evidence=%context.uri, "body inspection failed");
                return block_content_response(state, StatusCode::BAD_REQUEST, "KrakenWaf could not inspect the request body");
            }
        };

        if !skip_inspection {
            let full_request = format_full_request_bytes(&context, Some(&body_bytes));
            match state.waf.inspect_complete_payload_with_context(&full_request, Some(&context.method)) {
                Decision::Allow => {}
                Decision::Block(finding) => {
                    let event = build_event(&context, &finding, Some(&body_bytes));
                    if let Some(response) = self.log_and_enforce(state, event).await {
                        return response;
                    }
                }
            }
        }

        match self.forward_request(state, method, uri, req.headers(), body_bytes).await {
            Ok(response) => response,
            Err(err) => {
                error!(target: "krakenwaf", "upstream proxy failure: {err:#}");
                let mut response = plain_response(StatusCode::BAD_GATEWAY, "KrakenWaf upstream failure");
                apply_response_policy(state, &mut response);
                response
            }
        }
    }

    /// Log the detection event and, in `Block` mode, return a 403 response.
    /// Returns `None` in `Silent` mode so the caller can continue forwarding the request.
    async fn log_and_enforce(&self, state: &AppState, event: SecurityEvent) -> Option<Response<Full<Bytes>>> {
        state.metrics.inc_blocked();

        info!(
            target: "krakenwaf",
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
        state.store.enqueue(event.clone());

        if state.mode == WafMode::Silent {
            return None;
        }

        Some(block_content_response(state, StatusCode::FORBIDDEN, "Blocked by KrakenWaf"))
    }

    async fn forward_request(
        &self,
        state: &AppState,
        method: Method,
        uri: Uri,
        headers: &HeaderMap,
        body: Bytes,
    ) -> Result<Response<Full<Bytes>>> {
        // Build the upstream URL by overlaying ONLY the request path and query on top of the
        // configured upstream. Never `Url::join` an attacker-controlled string: an absolute-form
        // request URI (RFC 7230 §5.3.2) such as `http://attacker.tld/x` would otherwise
        // *replace* the upstream base entirely (SSRF / upstream hijack).
        let target = build_upstream_target(&self.upstream, &uri);
        let method_str = method.as_str().to_string();
        let mut builder = self.client.request(method, target);

        let mut forwarded_count: usize = 0;
        let mut forwarded_bytes: usize = 0;
        for (name, value) in headers.iter() {
            if is_hop_by_hop(name) || name == HOST {
                continue;
            }
            forwarded_count += 1;
            forwarded_bytes += name.as_str().len() + value.as_bytes().len();
            if forwarded_count > MAX_FORWARDED_HEADERS || forwarded_bytes > MAX_FORWARDED_HEADER_BYTES {
                anyhow::bail!(
                    "request rejected: forwarded headers exceed limits (count<={MAX_FORWARDED_HEADERS}, bytes<={MAX_FORWARDED_HEADER_BYTES})"
                );
            }
            builder = builder.header(name, value);
        }

        builder = builder.header("x-forwarded-proto", "https");
        if let Some(header_name) = &self.internal_header_name {
            builder = builder.header(header_name, "1");
        }

        let response = builder
            .body(body)
            .send()
            .await
            .map_err(|err| KrakenError::Upstream(err.to_string()))?;

        let status = StatusCode::from_u16(response.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
        let mut response_builder = Response::builder().status(status);
        for (name, value) in response.headers().iter() {
            if !is_hop_by_hop(name) {
                response_builder = response_builder.header(name, value);
            }
        }
        // Stream the upstream body in chunks so an oversized response (e.g. 1 GB from a
        // compromised upstream) cannot exhaust WAF heap. Limit is operator-configurable.
        let max_response = state.cli.max_upstream_response_bytes;
        let mut body_buf = BytesMut::new();
        let mut response = response;
        while let Some(chunk) = response.chunk().await.map_err(|err| KrakenError::Upstream(err.to_string()))? {
            body_buf.extend_from_slice(&chunk);
            if body_buf.len() > max_response {
                anyhow::bail!(
                    "upstream response body exceeds limit of {max_response} bytes; \
                     increase --max-upstream-response-bytes if the upstream legitimately returns large responses"
                );
            }
        }
        let bytes = body_buf.freeze();

        // Inspect the upstream response (rules with http_action: Response).
        let resp_headers = flatten_headers(
            response_builder
                .headers_ref()
                .unwrap_or(&http::HeaderMap::new())
        );
        let resp_ctx = ResponseContext { status: status.as_u16(), headers: resp_headers, body: bytes.clone() };
        if let Decision::Block(finding) = state.waf.inspect_response(&resp_ctx) {
            let event = crate::logging::SecurityEvent::from_finding(
                &finding,
                &InspectionContext {
                    client_ip: String::new(),
                    method: method_str,
                    uri: uri.to_string(),
                    path: uri.path().to_string(),
                    headers: String::new(),
                    body_limit: 0,
                },
                finding.request_payload.clone(),
            );
            state.metrics.inc_blocked();
            tracing::info!(
                target: "krakenwaf",
                rule_id=%event.rule_id,
                title=%event.title,
                severity=%event.severity,
                engine=%event.engine,
                uri=%event.uri,
                rule=%event.rule_match,
                "response blocked"
            );
            write_critical(&state.logging, &event);
            state.store.enqueue(event);
            anyhow::bail!("upstream response blocked by WAF response rule");
        }

        let mut built = response_builder
            .body(Full::new(bytes))
            .map_err(|err| anyhow::anyhow!("failed to assemble upstream response: {err}"))?;
        apply_response_policy(state, &mut built);
        Ok(built)
    }
}

async fn consume_and_inspect_body(
    state: &AppState,
    ctx: &InspectionContext,
    body: &mut Incoming,
) -> std::result::Result<Bytes, BodyInspectionError> {
    let mut acc = BytesMut::new();
    let mut overlap = Vec::new();

    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|err| BodyInspectionError::Other(err.into()))?;
        if let Some(chunk) = frame.data_ref() {
            if acc.len() + chunk.len() > ctx.body_limit {
                return Err(BodyInspectionError::TooLarge { limit: ctx.body_limit });
            }

            let mut inspection_buf = BytesMut::with_capacity(overlap.len() + chunk.len());
            inspection_buf.extend_from_slice(&overlap);
            inspection_buf.extend_from_slice(chunk);

            let request_window = format_full_request_window_bytes(ctx, &inspection_buf);
            match state.waf.inspect_complete_payload_with_context(&request_window, Some(&ctx.method)) {
                Decision::Allow => {
                    acc.extend_from_slice(chunk);
                    overlap = inspection_buf[inspection_buf.len().saturating_sub(STREAM_OVERLAP_BYTES)..].to_vec();
                }
                Decision::Block(finding) => {
                    let mut partial = BytesMut::with_capacity(acc.len() + chunk.len());
                    partial.extend_from_slice(&acc);
                    partial.extend_from_slice(chunk);
                    return Err(BodyInspectionError::Blocked { finding, partial_body: partial.freeze() });
                }
            }
        }
    }

    Ok(acc.freeze())
}

fn build_event(ctx: &InspectionContext, finding: &Finding, body: Option<&Bytes>) -> SecurityEvent {
    let request_payload = format_full_request(ctx, body, &finding.request_payload);
    SecurityEvent::from_finding(finding, ctx, request_payload)
}

pub(crate) fn format_request_prefix_bytes(ctx: &InspectionContext) -> Vec<u8> {
    let mut out = Vec::with_capacity(
        ctx.method.len() + 1 + ctx.uri.len() + 10 + ctx.headers.len() + 4
    );
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

fn format_full_request(ctx: &InspectionContext, body: Option<&Bytes>, matched_payload: &str) -> String {
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
                if ip.is_private() || ip.is_loopback() || ip.is_link_local() || ip.is_unspecified() {
                    anyhow::bail!("private or local upstreams require --allow-private-upstream");
                }
            }
            Host::Ipv6(ip) => {
                if ip.is_loopback() || ip.is_unspecified() || ip.is_unique_local() {
                    anyhow::bail!("private or local upstreams require --allow-private-upstream");
                }
            }
            Host::Domain(_) => {}
        }
    }

    Ok(())
}

fn flatten_headers(headers: &HeaderMap) -> String {
    let mut out = String::new();
    let mut count = 0usize;
    let mut bytes = 0usize;
    for (name, value) in headers.iter() {
        count += 1;
        bytes += name.as_str().len() + value.as_bytes().len();
        if count > MAX_FORWARDED_HEADERS || bytes > MAX_FORWARDED_HEADER_BYTES {
            out.push_str("\n<truncated: header limit reached>");
            break;
        }
        if !out.is_empty() {
            out.push('\n');
        }
        out.push_str(name.as_str());
        out.push_str(": ");
        out.push_str(value.to_str().unwrap_or("<binary>"));
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
    let safe_path = format!("/{}", trimmed);
    target.set_path(&safe_path);
    target.set_query(uri.query());
    target.set_fragment(None);
    target
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


fn apply_response_policy(state: &AppState, response: &mut Response<Full<Bytes>>) {
    let is_websocket_upgrade = response.status() == StatusCode::SWITCHING_PROTOCOLS
        || response.headers().contains_key(UPGRADE)
        || response
            .headers()
            .get(CONNECTION)
            .and_then(|v| v.to_str().ok())
            .map(|v| v.to_ascii_lowercase().contains("upgrade"))
            .unwrap_or(false);
    state.response_header_policy.apply(response.headers_mut(), is_websocket_upgrade);
}

fn block_content_response(state: &AppState, status: StatusCode, fallback_message: &str) -> Response<Full<Bytes>> {
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

pub fn plain_response(status: StatusCode, message: &str) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header("content-type", "text/plain; charset=utf-8")
        .header("x-content-type-options", "nosniff")
        .body(Full::new(Bytes::copy_from_slice(message.as_bytes())))
        .unwrap()
}


fn header_value_case_insensitive(headers: &http::HeaderMap, name: &str) -> Option<String> {
    headers
        .iter()
        .find(|(k, _)| k.as_str().eq_ignore_ascii_case(name))
        .and_then(|(_, v)| v.to_str().ok())
        .map(str::to_owned)
}

fn effective_client_ip(peer_ip: &str, headers: &http::HeaderMap, state: &AppState) -> String {
    use std::net::IpAddr;
    let peer = match peer_ip.parse::<IpAddr>() {
        Ok(ip) => ip,
        Err(_) => return peer_ip.to_string(),
    };
    let trusted_nets: Vec<ipnet::IpNet> = state.cli.trusted_proxy_cidrs
        .iter()
        .filter_map(|cidr| cidr.parse().ok())
        .collect();
    if !trusted_nets.iter().any(|net| net.contains(&peer)) {
        return peer_ip.to_string();
    }
    let header_name = match state.cli.real_ip_header.as_deref() {
        Some(h) if !h.trim().is_empty() => h.trim(),
        _ => return peer_ip.to_string(),
    };
    let raw = match header_value_case_insensitive(headers, header_name) {
        Some(v) => v,
        None => return peer_ip.to_string(),
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
                s.parse::<IpAddr>()
                    .ok()
                    .map_or(true, |ip| !trusted_nets.iter().any(|net| net.contains(&ip)))
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
