//! WebSocket upgrade handling: detecting the upgrade, serialising the upstream
//! handshake request by hand (with a CR/LF injection guard), and parsing the
//! upstream handshake response.

use anyhow::Result;
use bytes::Bytes;
use http::header::{CONNECTION, HOST, UPGRADE};
use http::{HeaderMap, Request, Response, StatusCode};
use hyper::body::Incoming;
use tokio::io::AsyncReadExt as _;
use url::Url;

use super::{
    build_upstream_target, connection_listed_headers, full_body, ForwardedOrigin, WafResponse,
};

pub(crate) fn is_websocket_upgrade(headers: &HeaderMap) -> bool {
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

pub(crate) fn build_upstream_websocket_request(
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

pub(crate) async fn read_upstream_websocket_response(
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


#[cfg(test)]
mod tests {
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
}
