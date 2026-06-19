//! Upstream response body handling: streaming-limit enforcement, the
//! buffered/stream/tee mode selection, prefix reading for inspection, and
//! `Content-Length` adjustment when the inspected prefix is rewritten.

use anyhow::Result;
use bytes::{Bytes, BytesMut};
use http::{HeaderMap, HeaderValue};
use http_body_util::{BodyExt, Full};
use hyper::body::{Body, Frame, Incoming, SizeHint};
use std::{
    collections::VecDeque,
    convert::Infallible,
    pin::Pin,
    task::{Context as TaskContext, Poll},
};

use crate::error::KrakenError;

use super::{BoxError, WafBody};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ResponseMode {
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

pub(crate) fn limited_body(
    initial: VecDeque<Frame<Bytes>>,
    inner: Incoming,
    seen: usize,
    max_bytes: usize,
) -> WafBody {
    LimitedResponseBody::new(initial, inner, seen, max_bytes).boxed_unsync()
}

pub(crate) fn response_mode(
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

pub(crate) fn content_length(headers: &HeaderMap) -> Option<usize> {
    headers
        .get(http::header::CONTENT_LENGTH)?
        .to_str()
        .ok()?
        .parse()
        .ok()
}

pub(crate) fn ensure_advertised_length_within_limit(
    advertised_length: Option<usize>,
    max_bytes: usize,
) -> Result<()> {
    if advertised_length.is_some_and(|length| length > max_bytes) {
        anyhow::bail!("upstream response Content-Length exceeds limit of {max_bytes} bytes");
    }
    Ok(())
}

pub(crate) async fn read_response_prefix(
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

pub(crate) fn adjust_streaming_content_length(
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
