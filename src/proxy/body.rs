//! Request-body buffering and inspection pipeline.
//!
//! Buffers the client body under per-request, global and per-IP byte caps (with
//! an atomic reserve to avoid TOCTOU overshoot), decodes `Content-Encoding`,
//! splits `multipart/form-data`, and runs the CMC / signature inspection once on
//! the decoded view. Also builds the `SecurityEvent`s emitted for findings.

use bytes::{Bytes, BytesMut};
use http_body_util::BodyExt as _;
use hyper::body::Incoming;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

use crate::app::AppState;
use crate::body_decode::{decompress_body_for_inspection, parse_content_encoding};
use crate::logging::SecurityEvent;
use crate::multipart_extract::{extract_boundary, parse_parts, MultipartPart};
use crate::waf::{Decision, Finding, InspectionContext};
use http::Uri;

#[derive(Debug)]
pub(crate) enum BodyInspectionError {
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


/// Maximum wall-clock time we wait for a single body frame from the client. Bounds the
/// memory + connection cost of a slowloris-style streaming body that trickles bytes to
/// keep the inspection loop alive indefinitely.
const BODY_FRAME_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);


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

pub(crate) async fn consume_and_inspect_body(
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

pub(crate) fn build_event(ctx: &InspectionContext, finding: &Finding, body: Option<&Bytes>) -> SecurityEvent {
    let request_payload = format_full_request(ctx, body, &finding.request_payload);
    SecurityEvent::from_finding(finding, ctx, request_payload)
}

/// Build a `SecurityEvent` for a **response-phase** finding (rules with
/// `http_action: Response`). The response pipeline has no request
/// `InspectionContext`, so it synthesises a minimal one carrying just the
/// method, URI, and request-id for correlation. Shared by the `Block`,
/// `Monitor`, and `SilentReplace` arms of `inspect_upstream_response`.
pub(crate) fn build_response_event(
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
