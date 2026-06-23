use bytes::Bytes;
use http_body_util::{combinators::UnsyncBoxBody, BodyExt, Full};
use hyper::body::{Body, Frame, Incoming, SizeHint};
use std::{
    collections::VecDeque,
    convert::Infallible,
    pin::Pin,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    task::{Context, Poll},
};

pub(super) type BoxError = Box<dyn std::error::Error + Send + Sync>;
pub type WafBody = UnsyncBoxBody<Bytes, BoxError>;

/// RAII accounting for request bytes currently buffered for inspection.
pub(super) struct BodyTracker {
    global: Arc<AtomicUsize>,
    pub(super) ip: Arc<AtomicUsize>,
    bytes: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum BodyReservationError {
    Global,
    Ip,
}

impl BodyTracker {
    pub(super) fn new(global: Arc<AtomicUsize>, ip: Arc<AtomicUsize>) -> Self {
        Self {
            global,
            ip,
            bytes: 0,
        }
    }

    pub(super) fn try_add(
        &mut self,
        bytes: usize,
        global_limit: usize,
        ip_limit: usize,
    ) -> Result<(), BodyReservationError> {
        let global_before = self.global.fetch_add(bytes, Ordering::AcqRel);
        if limit_exceeded(global_before, bytes, global_limit) {
            self.global.fetch_sub(bytes, Ordering::AcqRel);
            return Err(BodyReservationError::Global);
        }

        let ip_before = self.ip.fetch_add(bytes, Ordering::AcqRel);
        if limit_exceeded(ip_before, bytes, ip_limit) {
            self.ip.fetch_sub(bytes, Ordering::AcqRel);
            self.global.fetch_sub(bytes, Ordering::AcqRel);
            return Err(BodyReservationError::Ip);
        }

        self.bytes += bytes;
        Ok(())
    }
}

impl Drop for BodyTracker {
    fn drop(&mut self) {
        if self.bytes > 0 {
            self.global.fetch_sub(self.bytes, Ordering::AcqRel);
            self.ip.fetch_sub(self.bytes, Ordering::AcqRel);
        }
    }
}

fn limit_exceeded(current: usize, added: usize, limit: usize) -> bool {
    let Some(total) = current.checked_add(added) else {
        return true;
    };
    limit > 0 && total > limit
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
        cx: &mut Context<'_>,
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

pub(super) fn limited_body(
    initial: VecDeque<Frame<Bytes>>,
    inner: Incoming,
    seen: usize,
    max_bytes: usize,
) -> WafBody {
    LimitedResponseBody::new(initial, inner, seen, max_bytes).boxed_unsync()
}
